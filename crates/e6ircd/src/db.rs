//! Database worker: owns the PostgreSQL pool. Consumes [`DbRequest`]s
//! from its queue and answers by pushing [`Input::DbReply`] into the
//! core queue — the core never touches the database directly.

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use e6irc_proto::casemap::CaseMapping;
use sqlx::PgPool;
use sqlx::Row;
use std::sync::Arc;
use std::time::Instant;

use crate::core::{DbReply, DbRequest, Input};
use crate::observability::Telemetry;
use e6irc_queue::{Receiver, Sender};

/// Migrations are compiled into the binary; startup refuses to run on
/// checksum drift (sqlx's default) rather than guessing.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

#[derive(Debug)]
pub enum DbError {
    Connect(sqlx::Error),
    Migrate(sqlx::migrate::MigrateError),
    Query(sqlx::Error),
    Hash(argon2::password_hash::Error),
    DuplicateAccount(String),
    /// A network of that name already exists for the owner.
    DuplicateNetwork(String),
    /// A persisted BNC network kind is outside the closed driver-kind set.
    InvalidNetworkKind(String),
    /// Persisted server settings do not decode into the closed typed schema.
    InvalidServerSettings(String),
    /// A console write was based on an older settings revision.
    StaleServerSettings,
    /// Unknown account or wrong password (indistinguishable on purpose).
    BadCredentials,
    /// A write resolved to no account row for the given name.
    UnknownAccount(String),
    ReplayedLogoutToken,
    /// The account already holds the maximum number of app passwords / PATs.
    TooManyCredentials,
    /// The account already holds the maximum number of BNC networks.
    TooManyNetworks,
    /// The channel already holds the maximum number of access entries.
    TooManyAccessEntries,
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "database connect failed: {e}"),
            Self::Migrate(e) => write!(f, "database migration failed: {e}"),
            Self::Query(e) => write!(f, "database query failed: {e}"),
            Self::Hash(e) => write!(f, "password hashing failed: {e}"),
            Self::DuplicateAccount(n) => write!(f, "account already exists: {n}"),
            Self::DuplicateNetwork(n) => write!(f, "network already exists: {n}"),
            Self::InvalidNetworkKind(kind) => {
                write!(f, "invalid persisted BNC network kind: {kind}")
            }
            Self::InvalidServerSettings(error) => {
                write!(f, "invalid persisted server settings: {error}")
            }
            Self::StaleServerSettings => write!(f, "server settings changed concurrently"),
            Self::BadCredentials => write!(f, "invalid account or password"),
            Self::UnknownAccount(n) => write!(f, "no such account: {n}"),
            Self::ReplayedLogoutToken => write!(f, "OpenID Connect logout token was replayed"),
            Self::TooManyCredentials => write!(f, "account holds too many app passwords"),
            Self::TooManyNetworks => write!(f, "account holds too many networks"),
            Self::TooManyAccessEntries => write!(f, "channel holds too many access entries"),
        }
    }
}

impl std::error::Error for DbError {}

pub async fn connect_and_migrate(url: &str) -> Result<PgPool, DbError> {
    let pool = PgPool::connect(url).await.map_err(DbError::Connect)?;
    MIGRATOR.run(&pool).await.map_err(DbError::Migrate)?;
    Ok(pool)
}

pub(crate) async fn store_observability_sample(
    pool: &PgPool,
    snapshot: &crate::observability::Snapshot,
    retention_hours: u64,
) -> Result<(), DbError> {
    let value = serde_json::to_value(snapshot)
        .map_err(|error| DbError::InvalidServerSettings(error.to_string()))?;
    let retention_ms = retention_hours
        .saturating_mul(60)
        .saturating_mul(60)
        .saturating_mul(1_000);
    let cutoff = snapshot.sampled_at_ms.saturating_sub(retention_ms);
    let sampled_at = i64::try_from(snapshot.sampled_at_ms)
        .map_err(|_| DbError::InvalidServerSettings("sample timestamp exceeds BIGINT".into()))?;
    let cutoff = i64::try_from(cutoff)
        .map_err(|_| DbError::InvalidServerSettings("retention cutoff exceeds BIGINT".into()))?;
    let mut transaction = pool.begin().await.map_err(DbError::Query)?;
    sqlx::query(
        "INSERT INTO observability_samples (sampled_at_ms, snapshot)
         VALUES ($1, $2)
         ON CONFLICT (sampled_at_ms) DO UPDATE SET snapshot = EXCLUDED.snapshot",
    )
    .bind(sampled_at)
    .bind(value)
    .execute(&mut *transaction)
    .await
    .map_err(DbError::Query)?;
    sqlx::query("DELETE FROM observability_samples WHERE sampled_at_ms < $1")
        .bind(cutoff)
        .execute(&mut *transaction)
        .await
        .map_err(DbError::Query)?;
    transaction.commit().await.map_err(DbError::Query)?;
    Ok(())
}

pub(crate) async fn list_observability_samples(
    pool: &PgPool,
    since_ms: u64,
    until_ms: u64,
    limit: usize,
) -> Result<Vec<crate::observability::Snapshot>, DbError> {
    let since_ms = i64::try_from(since_ms)
        .map_err(|_| DbError::InvalidServerSettings("history timestamp exceeds BIGINT".into()))?;
    let until_ms = i64::try_from(until_ms)
        .map_err(|_| DbError::InvalidServerSettings("history timestamp exceeds BIGINT".into()))?;
    let limit = i64::try_from(limit)
        .map_err(|_| DbError::InvalidServerSettings("history limit exceeds BIGINT".into()))?;
    let rows = sqlx::query(
        "WITH params AS (
             SELECT GREATEST(1, (($2 - $1) + $3 - 2) / ($3 - 1)) AS bucket_ms
         ),
         sampled AS (
             SELECT DISTINCT ON ((sampled_at_ms - $1) / params.bucket_ms)
                    sampled_at_ms, snapshot
               FROM observability_samples, params
              WHERE sampled_at_ms BETWEEN $1 AND $2
              ORDER BY ((sampled_at_ms - $1) / params.bucket_ms), sampled_at_ms DESC
         )
         SELECT snapshot FROM sampled ORDER BY sampled_at_ms LIMIT $3",
    )
    .bind(since_ms)
    .bind(until_ms)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;
    rows.into_iter()
        .map(|row| {
            serde_json::from_value(row.get("snapshot"))
                .map_err(|error| DbError::InvalidServerSettings(error.to_string()))
        })
        .collect()
}

/// One immutable view of the settings row. Callers must present `revision` on a
/// write, making lost updates impossible instead of relying on timing.
#[derive(Debug, Clone)]
pub struct ManagedConfigSnapshot {
    pub revision: i64,
    pub settings: crate::config::ManagedConfig,
    pub updated_by: String,
    pub updated_at: String,
}

fn decode_managed_settings(
    value: serde_json::Value,
) -> Result<crate::config::ManagedConfig, DbError> {
    serde_json::from_value(value).map_err(|error| DbError::InvalidServerSettings(error.to_string()))
}

/// Load the control-plane row, importing the validated bootstrap values exactly
/// once when a deployment first gains this migration.
pub async fn load_or_initialize_managed_config(
    pool: &PgPool,
    bootstrap: &crate::config::ManagedConfig,
) -> Result<ManagedConfigSnapshot, DbError> {
    let value = serde_json::to_value(bootstrap)
        .map_err(|error| DbError::InvalidServerSettings(error.to_string()))?;
    sqlx::query(
        "INSERT INTO server_settings (singleton, revision, settings, updated_by)
         VALUES (TRUE, 1, $1, 'bootstrap')
         ON CONFLICT (singleton) DO NOTHING",
    )
    .bind(value)
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    load_managed_config(pool).await
}

pub async fn load_managed_config(pool: &PgPool) -> Result<ManagedConfigSnapshot, DbError> {
    use sqlx::Row;
    let row = sqlx::query(
        "SELECT revision, settings, updated_by,
                to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS \"UTC\"') AS updated_at
         FROM server_settings WHERE singleton",
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)?
    .ok_or_else(|| DbError::InvalidServerSettings("settings row is missing".into()))?;
    Ok(ManagedConfigSnapshot {
        revision: row.get("revision"),
        settings: decode_managed_settings(row.get("settings"))?,
        updated_by: row.get("updated_by"),
        updated_at: row.get("updated_at"),
    })
}

/// Store a complete typed settings revision and its redacted audit description
/// in the same transaction. A stale revision changes no rows and emits no audit
/// entry.
pub async fn save_managed_config(
    pool: &PgPool,
    expected_revision: i64,
    settings: &crate::config::ManagedConfig,
    actor: &str,
    audit_detail: &str,
) -> Result<ManagedConfigSnapshot, DbError> {
    let value = serde_json::to_value(settings)
        .map_err(|error| DbError::InvalidServerSettings(error.to_string()))?;
    let mut tx = pool.begin().await.map_err(DbError::Query)?;
    let next: Option<(i64, String)> = sqlx::query_as(
        "UPDATE server_settings
         SET revision = revision + 1, settings = $2, updated_by = $3, updated_at = now()
         WHERE singleton AND revision = $1
         RETURNING revision,
                   to_char(updated_at AT TIME ZONE 'UTC',
                           'YYYY-MM-DD HH24:MI:SS \"UTC\"')",
    )
    .bind(expected_revision)
    .bind(value)
    .bind(actor)
    .fetch_optional(&mut *tx)
    .await
    .map_err(DbError::Query)?;
    let Some((revision, updated_at)) = next else {
        return Err(DbError::StaleServerSettings);
    };
    insert_audit_log_with(&mut *tx, actor, "CONFIG", "server", audit_detail).await?;
    tx.commit().await.map_err(DbError::Query)?;
    Ok(ManagedConfigSnapshot {
        revision,
        settings: settings.clone(),
        updated_by: actor.to_string(),
        updated_at,
    })
}

/// Create an account with a local password. Used by NickServ REGISTER
/// and by tests/admin tooling.
pub async fn create_account(pool: &PgPool, name: &str, password: &str) -> Result<i64, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(name);
    let hash = hash_password(password.to_string()).await?;
    let mut tx = pool.begin().await.map_err(DbError::Query)?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO accounts (name, name_folded) VALUES ($1, $2)
         ON CONFLICT (name_folded) DO NOTHING RETURNING id",
    )
    .bind(name)
    .bind(&folded)
    .fetch_optional(&mut *tx)
    .await
    .map_err(DbError::Query)?
    .ok_or_else(|| DbError::DuplicateAccount(name.to_string()))?;
    sqlx::query(
        "INSERT INTO account_credentials (account_id, kind, argon2_hash)
         VALUES ($1, 'local_password', $2)",
    )
    .bind(id)
    .bind(&hash)
    .execute(&mut *tx)
    .await
    .map_err(DbError::Query)?;
    tx.commit().await.map_err(DbError::Query)?;
    Ok(id)
}

/// The single Argon2 configuration used for every password hash and verify,
/// so credential hardening lives in one choke point rather than scattered
/// `Argon2::default()` calls. These are the argon2 0.5.3 defaults — Argon2id,
/// v19, m=19456 KiB (~19 MiB), t=2, p=1 — which meet the OWASP minimum.
/// Documented in DESIGN §15; change here to change it everywhere.
fn hasher() -> Argon2<'static> {
    Argon2::default()
}

/// Concurrent argon2 operations allowed in flight across the WHOLE process.
/// Each argon2 costs ~19 MiB, so this bounds the memory any burst of hashing
/// can pin. It is deliberately global: hashing and verification happen on three
/// paths — the DB worker (`VerifyPassword`/`CreateAccount`), SASL, and the REST
/// credential endpoints (`create_app_password`, which calls `issue_app_password`
/// directly, *not* through the worker) — and a per-path bound leaves any path
/// that forgets it able to spawn unbounded argon2 and exhaust memory (tokio's
/// blocking pool is ~512 threads ⇒ ~10 GiB). Enforced at the two choke points
/// below (`hash_password`, `verify_credentials`) so no caller can bypass it.
const MAX_CONCURRENT_ARGON2: usize = 4;

/// The single gate every argon2 op passes through (see [`MAX_CONCURRENT_ARGON2`]).
static ARGON2_PERMITS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(MAX_CONCURRENT_ARGON2);

/// argon2id via the blocking pool — hashing is deliberately slow and
/// must not stall the async runtime. Bounded by [`ARGON2_PERMITS`].
async fn hash_password(password: String) -> Result<String, DbError> {
    let _permit = ARGON2_PERMITS
        .acquire()
        .await
        .expect("argon2 semaphore never closed");
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        hasher()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(DbError::Hash)
    })
    .await
    .expect("hashing task panicked")
}

/// Most app passwords one account may hold, matching the REST layer's
/// `MAX_CREDENTIALS_PER_ACCOUNT`. Bounds authenticated storage growth.
const MAX_APP_PASSWORDS_PER_ACCOUNT: i64 = 32;

/// Verify an account password, then mint a fresh app password: 32
/// random bytes, base64-shown once, argon2id hash stored.
pub async fn issue_app_password(
    pool: &PgPool,
    account: &str,
    password: &str,
    label: &str,
) -> Result<String, DbError> {
    match handle_verify(pool, account, password).await {
        VerifyOutcome::Verified(_) => {}
        VerifyOutcome::Rejected => return Err(DbError::BadCredentials),
        VerifyOutcome::Unavailable => return Err(DbError::Query(sqlx::Error::PoolClosed)),
    }
    issue_app_password_for_account(pool, account, label).await
}

/// Mint an app password for an account whose browser session has already been
/// authenticated. The HTTP console exposes this only after cookie
/// authentication and body-CSRF verification; keeping the minting primitive
/// here lets the password-verified REST path and session-verified UI path share
/// the same cap, lock, hashing, and storage transaction.
pub async fn issue_app_password_for_account(
    pool: &PgPool,
    account: &str,
    label: &str,
) -> Result<String, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let mut secret_bytes = [0u8; 32];
    use argon2::password_hash::rand_core::RngCore;
    OsRng.fill_bytes(&mut secret_bytes);
    let secret = e6irc_proto::base64::encode(&secret_bytes);
    // Hash before the transaction: argon2 takes ~100ms and must not extend the
    // account-row lock below.
    let hash = hash_password(secret.clone()).await?;
    // Cap per-account app passwords so an authenticated account can't flood the
    // credential table (mirrors the network cap). `local_password` is excluded —
    // this bounds only the app passwords a user mints. The count and the insert
    // run inside one transaction with the account row locked FOR UPDATE:
    // separate pool statements would each see a pre-insert snapshot, so two
    // concurrent requests reading cap-1 would both insert and overshoot the
    // cap the comment promises (this endpoint runs on the concurrent REST
    // layer, not the serial worker).
    let mut tx = pool.begin().await.map_err(DbError::Query)?;
    let account_id: Option<i64> =
        sqlx::query_scalar("SELECT id FROM accounts WHERE name_folded = $1 FOR UPDATE")
            .bind(&folded)
            .fetch_optional(&mut *tx)
            .await
            .map_err(DbError::Query)?;
    // The account row was gone (deleted since authentication): reject rather
    // than hand back an app password that was never stored.
    let Some(account_id) = account_id else {
        return Err(DbError::BadCredentials);
    };
    let app_pw_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM account_credentials
         WHERE account_id = $1 AND kind = 'app_password'",
    )
    .bind(account_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(DbError::Query)?;
    if app_pw_count >= MAX_APP_PASSWORDS_PER_ACCOUNT {
        return Err(DbError::TooManyCredentials);
    }
    sqlx::query(
        "INSERT INTO account_credentials (account_id, kind, argon2_hash, label)
         VALUES ($1, 'app_password', $2, $3)",
    )
    .bind(account_id)
    .bind(&hash)
    .bind(label)
    .execute(&mut *tx)
    .await
    .map_err(DbError::Query)?;
    tx.commit().await.map_err(DbError::Query)?;
    Ok(secret)
}

/// One worker loop; run as a task. Replies always reach the core (or
/// the core is gone and the server is shutting down).
pub async fn run_worker(pool: PgPool, mut rx: Receiver<DbRequest>, core_tx: Sender<Input>) {
    run_worker_inner(pool, &mut rx, core_tx, None).await;
}

pub(crate) async fn run_worker_observed(
    pool: PgPool,
    mut rx: Receiver<DbRequest>,
    core_tx: Sender<Input>,
    telemetry: Arc<Telemetry>,
) {
    run_worker_inner(pool, &mut rx, core_tx, Some(telemetry)).await;
}

async fn run_worker_inner(
    pool: PgPool,
    rx: &mut Receiver<DbRequest>,
    core_tx: Sender<Input>,
    telemetry: Option<Arc<Telemetry>>,
) {
    let mut log_batch: Vec<DbRequest> = Vec::new();
    while let Some(envelope) = rx.pop().await {
        let mut next = Some(envelope.payload);
        while let Some(request) = next.take() {
            match request {
                DbRequest::LogMessage { .. } => log_batch.push(request),
                // Password verification is a pure read of the accounts/credential
                // tables (never `messages`) with no ordering dependency on any
                // other request, and its argon2 verify is ~tens of ms. Run it off
                // the worker loop so a burst of logins can't head-of-line-block
                // CHATHISTORY reads and account lookups behind one serial argon2 at
                // a time. The argon2 memory bound lives at the choke point
                // (`verify_credentials`, gated by `ARGON2_PERMITS`), so no
                // per-caller semaphore is needed here. No flush is needed (it reads
                // no messages).
                DbRequest::VerifyPassword {
                    conn,
                    account,
                    password,
                    origin,
                } => {
                    let pool = pool.clone();
                    let core_tx = core_tx.clone();
                    let telemetry = telemetry.clone();
                    tokio::spawn(async move {
                        let started = Instant::now();
                        let outcome = handle_verify(&pool, &account, &password).await;
                        let unavailable = matches!(&outcome, VerifyOutcome::Unavailable);
                        let reply = outcome.into_reply(origin);
                        if let Some(telemetry) = telemetry {
                            telemetry.record_database_request(started.elapsed());
                            if unavailable {
                                telemetry.record_error(crate::observability::ErrorKind::Database);
                            }
                        }
                        // The core being gone (push fails) just means shutdown.
                        let _ = core_tx.push(Input::DbReply { conn, reply }).await;
                    });
                }
                // Account creation carries the same ~100ms argon2 hash as a
                // verify; offload it (its `hash_password` is gated by the same
                // `ARGON2_PERMITS` choke point) so a cheap one-line REGISTER can't
                // monopolize the single worker for the full hash and stall every
                // queued read/login behind it. It writes only the accounts table
                // (never `messages`), so — like VerifyPassword — no log-batch
                // flush is needed for *table* consistency.
                //
                // Reply *ordering* is a subtler matter: because this reply is
                // produced off the serial loop, a CHATHISTORY the same client
                // pipelined right after (answered on the serial loop in ~ms) can
                // resolve before this ~100ms hash does, so the two deferred
                // replies release in completion order, not issue order. That is
                // deliberately tolerated — see the `deferred_replies` invariant
                // in `core::state`: only self-identifying replies (a REGISTER
                // SUCCESS/FAIL vs. a chathistory BATCH) can swap, ambiguous sync
                // output never overtakes either, and a labeled-response client
                // correlates each by its own label regardless of arrival order.
                DbRequest::CreateAccount {
                    conn,
                    name,
                    password,
                    origin,
                } => {
                    let pool = pool.clone();
                    let core_tx = core_tx.clone();
                    let telemetry = telemetry.clone();
                    tokio::spawn(async move {
                        let started = Instant::now();
                        let reply = handle_create_account(&pool, name, &password, origin).await;
                        let unavailable =
                            matches!(&reply, DbReply::AccountRegisterUnavailable { .. });
                        if let Some(telemetry) = telemetry {
                            telemetry.record_database_request(started.elapsed());
                            if unavailable {
                                telemetry.record_error(crate::observability::ErrorKind::Database);
                            }
                        }
                        let _ = core_tx.push(Input::DbReply { conn, reply }).await;
                    });
                }
                request => {
                    // Any other request may *read* the messages table, so the
                    // writes queued ahead of it must land first. Without this a
                    // client that sends a message and immediately asks for its
                    // history queries a database that does not contain it yet —
                    // the buffered rows would still be sitting in `log_batch`.
                    // Consecutive messages still batch; only a read forces the
                    // flush, which is exactly the ordering the queue promises.
                    if !log_batch.is_empty() {
                        let started = Instant::now();
                        let succeeded =
                            flush_log_batch(&pool, std::mem::take(&mut log_batch)).await;
                        if let Some(telemetry) = &telemetry {
                            telemetry.record_database_request(started.elapsed());
                            if !succeeded {
                                telemetry.record_error(crate::observability::ErrorKind::Database);
                            }
                        }
                    }
                    let started = Instant::now();
                    let keep_running =
                        handle_request(&pool, &core_tx, request, telemetry.as_deref()).await;
                    if let Some(telemetry) = &telemetry {
                        telemetry.record_database_request(started.elapsed());
                    }
                    if !keep_running {
                        return;
                    }
                }
            }
            next = rx.try_pop().map(|e| e.payload);
        }
        // Queue drained: flush accumulated history in one statement.
        if !log_batch.is_empty() {
            let started = Instant::now();
            let succeeded = flush_log_batch(&pool, std::mem::take(&mut log_batch)).await;
            if let Some(telemetry) = &telemetry {
                telemetry.record_database_request(started.elapsed());
                if !succeeded {
                    telemetry.record_error(crate::observability::ErrorKind::Database);
                }
            }
        }
    }
}

/// Group-insert buffered LogMessage rows. Persistence is best-effort:
/// chat delivery already happened, so a failed flush is logged loudly and
/// dropped rather than retried into duplicate rows.
async fn flush_log_batch(pool: &PgPool, batch: Vec<DbRequest>) -> bool {
    let n = batch.len();
    let (mut msgids, mut targets, mut prefixes, mut accounts, mut kinds, mut bodies, mut tss) = (
        Vec::with_capacity(n),
        Vec::with_capacity(n),
        Vec::with_capacity(n),
        Vec::with_capacity(n),
        Vec::with_capacity(n),
        Vec::with_capacity(n),
        Vec::with_capacity(n),
    );
    // A channel message stores NULL here; a direct message stores its
    // casefolded participants, which is what CHATHISTORY TARGETS searches.
    // Bound as the joined form and split back into an array in SQL: a
    // conversation has one or two participants, and Postgres arrays passed
    // through UNNEST must be rectangular, which a ragged nesting is not.
    let mut peers: Vec<Option<String>> = Vec::with_capacity(n);
    let mut bots: Vec<bool> = Vec::with_capacity(n);
    // NULL for an ordinary message; the encoded lines for a draft/multiline one
    // (see `core::handler::message::encode_multiline`), authoritative on replay.
    let mut multilines: Vec<Option<String>> = Vec::with_capacity(n);
    for request in batch {
        let DbRequest::LogMessage {
            msgid,
            target,
            dm_peers,
            sender_prefix,
            sender_account,
            kind,
            body,
            sender_is_bot,
            multiline,
            ts,
        } = request
        else {
            unreachable!("caller batches only LogMessage");
        };
        msgids.push(msgid);
        targets.push(target);
        peers.push((!dm_peers.is_empty()).then(|| dm_peers.join("!")));
        prefixes.push(sender_prefix);
        accounts.push(sender_account);
        kinds.push(kind.db().to_string());
        bodies.push(body);
        bots.push(sender_is_bot);
        multilines.push(multiline);
        tss.push(ts.as_millis() as i64);
    }
    let result = sqlx::query(
        "INSERT INTO messages (msgid, target, sender_prefix, sender_account, kind, body, ts, dm_peers, sender_is_bot, multiline)
         SELECT m, t, p, a, k, b, at,
                CASE WHEN d IS NULL THEN NULL ELSE string_to_array(d, '!') END,
                bot, ml
         FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[],
                     ARRAY(SELECT to_timestamp(x / 1000.0) FROM UNNEST($7::bigint[]) x),
                     $8::text[], $9::bool[], $10::text[]) AS u(m, t, p, a, k, b, at, d, bot, ml)
         ON CONFLICT (msgid) DO NOTHING",
    )
    .bind(&msgids)
    .bind(&targets)
    .bind(&prefixes)
    .bind(&accounts)
    .bind(&kinds)
    .bind(&bodies)
    .bind(&tss)
    .bind(&peers)
    .bind(&bots)
    .bind(&multilines)
    .execute(pool)
    .await;
    if let Err(e) = result {
        eprintln!("db: history flush of {n} messages failed: {e}");
        // Best-effort persistence (see the doc above): the messages were
        // delivered live but not stored. No ring is marked incomplete here — a
        // DB-backed ring is *already* created `complete = false` (a target may
        // have older rows in `messages`), so CHATHISTORY always has Postgres as
        // its backstop and never presents the hot ring as a gap-free record.
        false
    } else {
        true
    }
}

fn record_database_error(telemetry: Option<&Telemetry>) {
    if let Some(telemetry) = telemetry {
        telemetry.record_error(crate::observability::ErrorKind::Database);
    }
}

/// Handle one non-history request; false = core gone, stop the worker.
async fn handle_request(
    pool: &PgPool,
    core_tx: &Sender<Input>,
    request: DbRequest,
    telemetry: Option<&Telemetry>,
) -> bool {
    match request {
        // `run_worker` intercepts VerifyPassword and spawns it off the loop before
        // ever reaching here (like LogMessage's batching). A duplicate inline path
        // would silently lose the off-loop latency decoupling (the argon2 memory
        // bound lives at the `ARGON2_PERMITS` choke point regardless), so make the
        // invariant load-bearing rather than shipping a second copy of the logic.
        DbRequest::VerifyPassword { .. } => unreachable!("offloaded by run_worker"),
        DbRequest::VerifyToken { conn, token } => {
            // A bearer token is only ever presented by SASL OAUTHBEARER.
            let origin = crate::core::CredentialOrigin::Sasl;
            let outcome = match api_token_account(pool, &token).await {
                Ok(Some(account)) => VerifyOutcome::Verified(account),
                Ok(None) => VerifyOutcome::Rejected,
                Err(e) => {
                    record_database_error(telemetry);
                    eprintln!("db: token lookup failed: {e}");
                    VerifyOutcome::Unavailable
                }
            };
            let reply = outcome.into_reply(origin);
            core_tx.push(Input::DbReply { conn, reply }).await.is_ok()
        }
        // `run_worker` intercepts CreateAccount and spawns it off the loop (like
        // VerifyPassword) so its argon2 hash never runs on the serial worker loop.
        // A duplicate inline path would silently lose that off-loop decoupling.
        DbRequest::CreateAccount { .. } => unreachable!("offloaded by run_worker"),
        DbRequest::RegisterChannel {
            conn,
            channel,
            founder_account,
            topic,
            label,
        } => {
            let reply =
                handle_register_channel(pool, &channel, &founder_account, topic, label).await;
            if matches!(&reply, DbReply::ChannelRegisterUnavailable { .. }) {
                record_database_error(telemetry);
            }
            core_tx.push(Input::DbReply { conn, reply }).await.is_ok()
        }
        DbRequest::RegisterOwnedChannel {
            request_id,
            channel,
            founder_account,
            topic,
        } => {
            let result = match persist_channel_registration(
                pool,
                &channel,
                &founder_account,
                &topic,
            )
            .await
            {
                Ok(result) => result,
                Err(error) => {
                    record_database_error(telemetry);
                    eprintln!("db: owner channel registration failed: {error}");
                    crate::core::ChannelRegistrationResult::Unavailable
                }
            };
            core_tx
                .push(Input::OwnedChannelRegistrationResult {
                    request_id,
                    channel,
                    founder_account,
                    topic,
                    result,
                })
                .await
                .is_ok()
        }
        DbRequest::DropChannel { channel, requester } => {
            let dropped = match &requester {
                crate::core::ChannelDropRequester::Admin { actor, .. } => {
                    drop_channel_audited(pool, &channel, actor).await
                }
                crate::core::ChannelDropRequester::ChanServ { .. } => {
                    drop_channel(pool, &channel).await
                }
            };
            let result = match dropped {
                Ok(true) => crate::core::ChannelDropResult::Dropped,
                Ok(false) => crate::core::ChannelDropResult::Missing,
                Err(e) => {
                    record_database_error(telemetry);
                    eprintln!("db: channel drop failed: {e}");
                    crate::core::ChannelDropResult::Unavailable
                }
            };
            core_tx
                .push(Input::ChannelDropResult {
                    channel,
                    requester,
                    result,
                })
                .await
                .is_ok()
        }
        DbRequest::SetChannelFounder {
            conn,
            channel,
            new_founder,
        } => {
            let reply = match set_channel_founder(pool, &channel, &new_founder).await {
                Ok(true) => DbReply::FounderChanged {
                    channel,
                    account: new_founder,
                },
                Ok(false) => DbReply::FounderChangeFailed { channel },
                Err(e) => {
                    record_database_error(telemetry);
                    eprintln!("db: founder transfer failed: {e}");
                    DbReply::FounderChangeUnavailable { channel }
                }
            };
            core_tx.push(Input::DbReply { conn, reply }).await.is_ok()
        }
        DbRequest::QueryHistory {
            conn,
            targets,
            display,
            batch_ref,
            query,
            label,
        } => {
            let rows = async {
                let effective = resolve_history_target(pool, targets).await?;
                query_history(pool, &effective, query).await
            }
            .await
            .map_err(|e| {
                record_database_error(telemetry);
                // The error string is logged here; the core only needs to know
                // it failed so it can FAIL the CHATHISTORY rather than reply
                // with a misleading empty page.
                eprintln!("db: history query failed: {e}");
            });
            core_tx
                .push(Input::HistoryPage {
                    conn,
                    display,
                    batch_ref,
                    rows,
                    label,
                })
                .await
                .is_ok()
        }
        DbRequest::QueryTargets {
            conn,
            channels,
            me,
            min_ts,
            max_ts,
            limit,
            batch_ref,
            label,
        } => {
            let targets = query_targets(pool, &channels, &me, min_ts, max_ts, limit)
                .await
                .map_err(|e| {
                    record_database_error(telemetry);
                    eprintln!("db: targets query failed: {e}");
                });
            core_tx
                .push(Input::TargetsPage {
                    conn,
                    batch_ref,
                    targets,
                    label,
                })
                .await
                .is_ok()
        }
        DbRequest::SetReadMarker {
            conn,
            account,
            target,
            display,
            marker_ms,
            label,
        } => {
            let reply = match set_read_marker(pool, &account, &target, marker_ms).await {
                Ok(marker_ms) => crate::core::DbReply::ReadMarkerStored {
                    account,
                    target,
                    display,
                    marker_ms,
                    label,
                },
                Err(e) => {
                    record_database_error(telemetry);
                    eprintln!("db: read marker persistence failed: {e}");
                    crate::core::DbReply::ReadMarkerUnavailable {
                        account,
                        target,
                        display,
                        label,
                    }
                }
            };
            core_tx.push(Input::DbReply { conn, reply }).await.is_ok()
        }
        DbRequest::SetChannelTopic {
            conn,
            channel,
            display,
            prefix,
            topic,
            revision,
            label,
        } => {
            let reply = match set_channel_topic(pool, &channel, topic.clone()).await {
                Ok(Some(retained)) => DbReply::ChannelTopicSet {
                    channel,
                    display,
                    prefix,
                    topic,
                    revision,
                    retained,
                    label,
                },
                Ok(None) => DbReply::ChannelTopicFailed {
                    channel,
                    display,
                    revision,
                    label,
                    failure: crate::core::ChannelTopicFailure::MissingRegistration,
                },
                Err(e) => {
                    record_database_error(telemetry);
                    eprintln!("db: channel topic persistence failed: {e}");
                    DbReply::ChannelTopicFailed {
                        channel,
                        display,
                        revision,
                        label,
                        failure: crate::core::ChannelTopicFailure::PersistenceUnavailable,
                    }
                }
            };
            core_tx.push(Input::DbReply { conn, reply }).await.is_ok()
        }
        DbRequest::SetChannelKeeptopic {
            conn,
            channel,
            display,
            keeptopic,
            topic,
            label,
        } => {
            let reply = match set_channel_keeptopic(pool, &channel, keeptopic, topic.clone()).await
            {
                Ok(applied) => DbReply::ChannelKeeptopicSet {
                    channel,
                    display,
                    keeptopic,
                    topic,
                    applied,
                    label,
                },
                Err(e) => {
                    record_database_error(telemetry);
                    eprintln!("db: channel keeptopic persistence failed: {e}");
                    DbReply::ChannelKeeptopicUnavailable { display, label }
                }
            };
            core_tx.push(Input::DbReply { conn, reply }).await.is_ok()
        }
        DbRequest::SetChannelMlock {
            conn,
            channel,
            display,
            mlock,
            label,
        } => {
            let reply = match set_channel_mlock(pool, &channel, mlock.clone()).await {
                Ok(applied) => DbReply::ChannelMlockSet {
                    channel,
                    display,
                    mlock,
                    applied,
                    label,
                },
                Err(e) => {
                    record_database_error(telemetry);
                    eprintln!("db: channel mlock persistence failed: {e}");
                    DbReply::ChannelMlockUnavailable { display, label }
                }
            };
            core_tx.push(Input::DbReply { conn, reply }).await.is_ok()
        }
        DbRequest::SetChannelAccess {
            conn,
            channel,
            account,
            flags,
        } => {
            // A store fault is not "account is not registered" — those are
            // different replies, so the operator is never told a definitive
            // negative that was really a transient DB failure.
            let reply = match set_channel_access(pool, &channel, &account, flags.clone()).await {
                Ok(applied) => DbReply::ChannelAccessSet {
                    channel,
                    account,
                    flags,
                    applied,
                },
                Err(DbError::TooManyAccessEntries) => {
                    DbReply::ChannelAccessLimitReached { channel }
                }
                Err(e) => {
                    record_database_error(telemetry);
                    eprintln!("db: channel access persistence failed: {e}");
                    DbReply::ChannelAccessUnavailable { channel }
                }
            };
            core_tx.push(Input::DbReply { conn, reply }).await.is_ok()
        }
        DbRequest::MutateOwnedChannel {
            request_id,
            channel,
            actor,
            mutation,
        } => {
            let result =
                match persist_owned_channel_mutation(pool, &channel, &actor, &mutation).await {
                    Ok(result) => result,
                    Err(e) => {
                        record_database_error(telemetry);
                        eprintln!("db: owner channel mutation failed: {e}");
                        crate::core::ChannelControlResult::Unavailable
                    }
                };
            core_tx
                .push(Input::ChannelControlResult {
                    request_id,
                    channel,
                    mutation,
                    result,
                })
                .await
                .is_ok()
        }
        DbRequest::MutateServerBan {
            mutation,
            requester,
        } => {
            let result = match mutate_server_ban_audited(pool, &mutation).await {
                Ok(()) => crate::core::ServerBanResult::Stored,
                Err(e) => {
                    record_database_error(telemetry);
                    eprintln!("db: audited server-ban mutation failed: {e}");
                    crate::core::ServerBanResult::Unavailable
                }
            };
            core_tx
                .push(Input::ServerBanResult {
                    mutation,
                    requester,
                    result,
                })
                .await
                .is_ok()
        }
        DbRequest::AuditLog {
            actor,
            action,
            target,
            detail,
        } => {
            if let Err(e) = insert_audit_log(pool, &actor, &action, &target, &detail).await {
                record_database_error(telemetry);
                eprintln!("db: audit log write failed: {e}");
            }
            true
        }
        DbRequest::LogMessage { .. } => unreachable!("batched by the caller"),
    }
}

/// Every read marker for `account` as `(target, iso8601-with-millis UTC)`,
/// ordered by target — for the self-service REST read.
pub async fn list_read_markers(
    pool: &PgPool,
    account: &str,
) -> Result<Vec<(String, String)>, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    sqlx::query_as(
        "SELECT r.target,
                to_char(r.marker_ts AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')
         FROM read_markers r JOIN accounts a ON a.id = r.account_id
         WHERE a.name_folded = $1 ORDER BY r.target",
    )
    .bind(&folded)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}

/// Every stored read marker as (account display name, target, epoch-millis),
/// for the core's boot-time preload of its hot mirror of the `read_markers`
/// table. Without this the mirror starts empty after a restart and MARKREAD
/// queries wrongly report `*` for markers that are in fact persisted.
pub async fn list_all_read_markers(pool: &PgPool) -> Result<Vec<(String, String, i64)>, DbError> {
    sqlx::query_as(
        "SELECT a.name, r.target, (EXTRACT(EPOCH FROM r.marker_ts) * 1000)::bigint
         FROM read_markers r JOIN accounts a ON a.id = r.account_id",
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}

async fn set_read_marker(
    pool: &PgPool,
    account: &str,
    target: &str,
    marker_ms: e6irc_proto::time::Millis,
) -> Result<e6irc_proto::time::Millis, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let stored: Option<i64> = sqlx::query_scalar(
        "INSERT INTO read_markers (account_id, target, marker_ts)
         SELECT a.id, $1, to_timestamp($2::double precision / 1000)
         FROM accounts a WHERE a.name_folded = $3
         ON CONFLICT (account_id, target)
         DO UPDATE SET marker_ts = GREATEST(read_markers.marker_ts, EXCLUDED.marker_ts)
         RETURNING (EXTRACT(EPOCH FROM marker_ts) * 1000)::bigint",
    )
    .bind(target)
    .bind(marker_ms.as_millis() as i64)
    .bind(&folded)
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)?;
    // The SELECT matches no row if the account name no longer resolves.
    // Surface that as an unavailable verdict rather than a false success.
    let Some(stored) = stored else {
        return Err(DbError::UnknownAccount(account.to_string()));
    };
    Ok(e6irc_proto::time::Millis::from_millis(stored as u64))
}

/// Outcome of linking an OIDC identity to an account.
#[derive(Debug, PartialEq, Eq)]
pub enum LinkOutcome {
    /// The identity was newly attached to the account.
    Linked,
    /// The identity was already attached to this same account.
    AlreadyYours,
    /// The identity belongs to a different account — refused.
    Conflict,
}

/// One linked OIDC identity: `(id, issuer, subject, created_at RFC3339)`.
pub type OidcIdentityRow = (i64, String, String, String);

/// Every OIDC identity linked to `account`, ordered for stable listing.
pub async fn list_oidc_identities(
    pool: &PgPool,
    account: &str,
) -> Result<Vec<OidcIdentityRow>, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    sqlx::query_as(
        "SELECT o.id, o.issuer, o.subject,
                to_char(o.created_at AT TIME ZONE 'UTC',
                        'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')
         FROM oidc_identities o JOIN accounts a ON a.id = o.account_id
         WHERE a.name_folded = $1 ORDER BY o.issuer, o.subject, o.id",
    )
    .bind(&folded)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}

#[derive(Debug, PartialEq, Eq)]
pub enum UnlinkIdentityOutcome {
    Unlinked,
    LastIdentity,
    NotFound,
}

/// Remove one linked identity owned by `account`, refusing to remove the last
/// browser-login path. The account row serializes concurrent unlinks, so two
/// requests cannot both observe a count of two and remove both identities.
/// Sessions asserted by the removed identity are revoked in the same
/// transaction; unlinking cannot leave an already-authenticated back door.
pub async fn unlink_oidc_identity(
    pool: &PgPool,
    account: &str,
    identity_id: i64,
) -> Result<UnlinkIdentityOutcome, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let mut tx = pool.begin().await.map_err(DbError::Query)?;
    let account_id: Option<i64> =
        sqlx::query_scalar("SELECT id FROM accounts WHERE name_folded = $1 FOR UPDATE")
            .bind(&folded)
            .fetch_optional(&mut *tx)
            .await
            .map_err(DbError::Query)?;
    let Some(account_id) = account_id else {
        return Ok(UnlinkIdentityOutcome::NotFound);
    };
    let identity: Option<(String, String)> = sqlx::query_as(
        "SELECT issuer, subject FROM oidc_identities
         WHERE id = $1 AND account_id = $2",
    )
    .bind(identity_id)
    .bind(account_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(DbError::Query)?;
    let Some((issuer, subject)) = identity else {
        return Ok(UnlinkIdentityOutcome::NotFound);
    };
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oidc_identities WHERE account_id = $1")
            .bind(account_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(DbError::Query)?;
    if count <= 1 {
        return Ok(UnlinkIdentityOutcome::LastIdentity);
    }
    sqlx::query("DELETE FROM oidc_identities WHERE id = $1 AND account_id = $2")
        .bind(identity_id)
        .bind(account_id)
        .execute(&mut *tx)
        .await
        .map_err(DbError::Query)?;
    sqlx::query(
        "DELETE FROM web_sessions
         WHERE account_id = $1 AND oidc_issuer = $2 AND oidc_subject = $3",
    )
    .bind(account_id)
    .bind(issuer)
    .bind(subject)
    .execute(&mut *tx)
    .await
    .map_err(DbError::Query)?;
    tx.commit().await.map_err(DbError::Query)?;
    Ok(UnlinkIdentityOutcome::Unlinked)
}

/// Attach an OIDC `(issuer, subject)` to `account`. Because the pair is
/// globally unique, an identity already owned by another account is a hard
/// [`LinkOutcome::Conflict`], never a silent move.
pub async fn link_oidc_identity(
    pool: &PgPool,
    account: &str,
    issuer: &str,
    subject: &str,
) -> Result<LinkOutcome, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let account_id: i64 = sqlx::query_scalar("SELECT id FROM accounts WHERE name_folded = $1")
        .bind(&folded)
        .fetch_optional(pool)
        .await
        .map_err(DbError::Query)?
        .ok_or(DbError::BadCredentials)?;
    let inserted: Option<i64> = sqlx::query_scalar(
        "INSERT INTO oidc_identities (account_id, issuer, subject) VALUES ($1, $2, $3)
         ON CONFLICT (issuer, subject) DO NOTHING RETURNING id",
    )
    .bind(account_id)
    .bind(issuer)
    .bind(subject)
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)?;
    if inserted.is_some() {
        return Ok(LinkOutcome::Linked);
    }
    // The pair already exists; whose is it?
    let owner: i64 = sqlx::query_scalar(
        "SELECT account_id FROM oidc_identities WHERE issuer = $1 AND subject = $2",
    )
    .bind(issuer)
    .bind(subject)
    .fetch_one(pool)
    .await
    .map_err(DbError::Query)?;
    if owner == account_id {
        Ok(LinkOutcome::AlreadyYours)
    } else {
        Ok(LinkOutcome::Conflict)
    }
}

/// Persist (or clear, when `topic` is `None`) a registered channel's
/// retained topic on its `channels` row.
pub async fn set_channel_topic(
    pool: &PgPool,
    channel_folded: &str,
    topic: Option<(String, String, u64)>,
) -> Result<Option<bool>, DbError> {
    let (text, setter, set_at) = match topic {
        Some((text, setter, set_at)) => (Some(text), Some(setter), Some(set_at as f64)),
        None => (None, None, None),
    };
    sqlx::query_scalar(
        "UPDATE channels
         SET topic = CASE WHEN keeptopic THEN $2 ELSE NULL END,
             topic_setter = CASE WHEN keeptopic THEN $3 ELSE NULL END,
             topic_set_at = CASE
                 WHEN keeptopic AND $4::double precision IS NOT NULL
                 THEN to_timestamp($4::double precision)
                 ELSE NULL
             END
         WHERE name_folded = $1
         RETURNING keeptopic",
    )
    .bind(channel_folded)
    .bind(text)
    .bind(setter)
    .bind(set_at)
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)
}

/// One history row decoded from PostgreSQL. `#[derive(sqlx::FromRow)]` binds
/// each field to the column of the **same name**, not by position — so the
/// SELECT column order no longer has to line up with a positional tuple. Four
/// of these are `String` (`msgid`/`sender_prefix`/`kind`/`body`); as a 7-tuple
/// a transposition of any two compiled cleanly and silently mis-mapped (a
/// replayed message showing its body as the source prefix, etc.). Keyed by
/// name, a reordered or mis-typed column fails to bind instead. `ts_millis` is
/// the `(EXTRACT(EPOCH FROM ts) * 1000)` bigint, aliased in the SELECT so it has
/// a name to bind to.
#[derive(sqlx::FromRow)]
struct HistoryDbRow {
    msgid: String,
    ts_millis: i64,
    sender_prefix: String,
    sender_account: Option<String>,
    kind: String,
    body: String,
    sender_is_bot: bool,
    /// Encoded draft/multiline lines, or NULL for an ordinary message.
    multiline: Option<String>,
}

/// A CHATHISTORY statement: the column list, then whatever narrows it.
///
/// The column list is a contract between eleven query variants and one row
/// type. When the timestamp moved from seconds to milliseconds every copy had
/// to be edited by hand, and the one that was missed stayed wrong for six
/// sweeps — so it is written once here.
///
/// `concat!` rather than `format!`: `sqlx::query_as` borrows its `&str`, and
/// this keeps every statement a single `&'static str` with no runtime work and
/// no temporary to outlive the query. The SQL also stays greppable, which an
/// interpolated string would not.
macro_rules! history_select {
    ($rest:literal) => {
        concat!(
            "SELECT msgid, (EXTRACT(EPOCH FROM ts) * 1000)::bigint AS ts_millis, sender_prefix, \
             sender_account, kind, body, sender_is_bot, multiline FROM messages ",
            $rest
        )
    };
}

/// The windowed form: two bounded halves unioned, then ordered as one. The
/// inner select aliases the timestamp so the outer query can order by it, and
/// carries `ts`/`id` for that ordering.
macro_rules! history_window {
    ($older:literal, $newer:literal) => {
        concat!(
            "SELECT msgid, ts_millis, sender_prefix, sender_account, kind, body, sender_is_bot, multiline FROM ( (SELECT msgid, \
             (EXTRACT(EPOCH FROM ts) * 1000)::bigint AS ts_millis, sender_prefix, sender_account, kind, \
             body, sender_is_bot, multiline, ts, id FROM messages ",
            $older,
            ") UNION ALL (SELECT msgid, (EXTRACT(EPOCH FROM ts) * 1000)::bigint AS ts_millis, \
             sender_prefix, sender_account, kind, body, sender_is_bot, multiline, ts, id FROM messages ",
            $newer,
            ") ) w ORDER BY ts ASC, id ASC"
        )
    };
}

/// Resolve the stored target for an exact or offline-ambiguous history request.
async fn resolve_history_target(
    pool: &PgPool,
    targets: crate::core::HistoryTargets,
) -> Result<String, sqlx::Error> {
    let (primary, fallback) = match targets {
        crate::core::HistoryTargets::Exact(target) => return Ok(target),
        crate::core::HistoryTargets::PreferExisting { primary, fallback } => (primary, fallback),
    };
    let primary_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM messages WHERE target = $1)")
            .bind(&primary)
            .fetch_one(pool)
            .await?;
    Ok(if primary_exists { primary } else { fallback })
}

pub async fn query_history(
    pool: &PgPool,
    target: &str,
    query: crate::core::HistoryQuery,
) -> Result<Vec<crate::core::HistoryRow>, sqlx::Error> {
    use crate::core::HistoryQuery;
    // BETWEEN resolves each pivot's `(ts, id)` in the DB and derives its own
    // direction, so it produces its final oldest-first order itself rather than
    // going through the shared newest-first reversal below.
    if let HistoryQuery::BetweenSelectors {
        first,
        second,
        limit,
    } = query
    {
        return query_between_selectors(pool, target, &first, &second, limit).await;
    }
    // LATEST/BEFORE (and its msgid pivot) select newest-first and get reversed
    // below; the rest are already oldest-first. Computed before the match
    // consumes `query`.
    let newest_first = matches!(
        query,
        HistoryQuery::Latest { .. }
            | HistoryQuery::LatestAfter { .. }
            | HistoryQuery::LatestAfterMsgid { .. }
            | HistoryQuery::Before { .. }
            | HistoryQuery::BeforeMsgid { .. }
    );
    // Each branch selects a window, then we return it oldest-first.
    let rows: Result<Vec<HistoryDbRow>, sqlx::Error> = match query {
        HistoryQuery::Latest { limit } => {
            sqlx::query_as(history_select!(
                    "WHERE target = $1 ORDER BY ts DESC, id DESC LIMIT $2"
                ))
            .bind(target)
            .bind(limit as i64)
            .fetch_all(pool)
            .await
        }
        HistoryQuery::Before { before_ts, limit } => {
            sqlx::query_as(history_select!(
                    "WHERE target = $1 AND ts < to_timestamp($2::double precision / 1000) ORDER BY ts DESC, id DESC LIMIT $3"
                ))
            .bind(target)
            .bind(before_ts.as_millis() as i64)
            .bind(limit as i64)
            .fetch_all(pool)
            .await
        }
        // Bounded LATEST: newest-first within the bound, reversed below, so a
        // limit smaller than the number of messages after the bound keeps the
        // most recent ones rather than the oldest.
        HistoryQuery::LatestAfter { after_ts, limit } => {
            sqlx::query_as(history_select!(
                    "WHERE target = $1 AND ts > to_timestamp($2::double precision / 1000) ORDER BY ts DESC, id DESC LIMIT $3"
                ))
            .bind(target)
            .bind(after_ts.as_millis() as i64)
            .bind(limit as i64)
            .fetch_all(pool)
            .await
        }
        HistoryQuery::LatestAfterMsgid { msgid, limit } => {
            sqlx::query_as(history_select!(
                    "WHERE target = $1 AND (ts, id) > (SELECT ts, id FROM messages WHERE msgid = $2 AND target = $1) ORDER BY ts DESC, id DESC LIMIT $3"
                ))
            .bind(target)
            .bind(&msgid)
            .bind(limit as i64)
            .fetch_all(pool)
            .await
        }
        HistoryQuery::After { after_ts, limit } => {
            sqlx::query_as(history_select!(
                    "WHERE target = $1 AND ts > to_timestamp($2::double precision / 1000) ORDER BY ts ASC, id ASC LIMIT $3"
                ))
            .bind(target)
            .bind(after_ts.as_millis() as i64)
            .bind(limit as i64)
            .fetch_all(pool)
            .await
        }
        HistoryQuery::Around { around_ts, limit } => {
            // Half older than the point, half at/after it, then oldest-first.
            let before = (limit / 2) as i64;
            let after = (limit - limit / 2) as i64;
            sqlx::query_as(history_window!(
                    "WHERE target = $1 AND ts < to_timestamp($2::double precision / 1000) ORDER BY ts DESC, id DESC LIMIT $3",
                    "WHERE target = $1 AND ts >= to_timestamp($2::double precision / 1000) ORDER BY ts ASC, id ASC LIMIT $4"
                ))
            .bind(target)
            .bind(around_ts.as_millis() as i64)
            .bind(before)
            .bind(after)
            .fetch_all(pool)
            .await
        }
        // Msgid pivots: page on the composite (ts, id) relative to the pivot
        // row so messages sharing the pivot's timestamp are not skipped.
        //
        // The pivot is looked up *within the same target*. Globally, a msgid
        // that belongs to some other buffer is not "unknown", so an unscoped
        // lookup would silently position the query from a message the caller
        // may never have been able to see — answering a request to page from a
        // position that does not exist in this buffer with a plausible result
        // instead of an empty one, and turning any known msgid into an oracle
        // for when it was sent. Scoped, an unknown-here msgid makes the
        // subquery NULL and the result empty, which is what the caller asked
        // about.
        HistoryQuery::BeforeMsgid { msgid, limit } => {
            sqlx::query_as(history_select!(
                    "WHERE target = $1 AND (ts, id) < (SELECT ts, id FROM messages WHERE msgid = $2 AND target = $1) ORDER BY ts DESC, id DESC LIMIT $3"
                ))
            .bind(target)
            .bind(&msgid)
            .bind(limit as i64)
            .fetch_all(pool)
            .await
        }
        HistoryQuery::AfterMsgid { msgid, limit } => {
            sqlx::query_as(history_select!(
                    "WHERE target = $1 AND (ts, id) > (SELECT ts, id FROM messages WHERE msgid = $2 AND target = $1) ORDER BY ts ASC, id ASC LIMIT $3"
                ))
            .bind(target)
            .bind(&msgid)
            .bind(limit as i64)
            .fetch_all(pool)
            .await
        }
        HistoryQuery::AroundMsgid { msgid, limit } => {
            let before = (limit / 2) as i64;
            let after = (limit - limit / 2) as i64;
            sqlx::query_as(history_window!(
                    "WHERE target = $1 AND (ts, id) < (SELECT ts, id FROM messages WHERE msgid = $2 AND target = $1) ORDER BY ts DESC, id DESC LIMIT $3",
                    "WHERE target = $1 AND (ts, id) >= (SELECT ts, id FROM messages WHERE msgid = $2 AND target = $1) ORDER BY ts ASC, id ASC LIMIT $4"
                ))
            .bind(target)
            .bind(&msgid)
            .bind(before)
            .bind(after)
            .fetch_all(pool)
            .await
        }
        // Returned early above.
        HistoryQuery::BetweenSelectors { .. } => unreachable!("handled before the match"),
    };
    let mut rows = rows?;
    if newest_first {
        rows.reverse();
    }
    Ok(rows.into_iter().map(history_row_from_db).collect())
}

/// Map a raw history row to a [`HistoryRow`].
fn history_row_from_db(row: HistoryDbRow) -> crate::core::HistoryRow {
    crate::core::HistoryRow {
        msgid: row.msgid,
        ts: e6irc_proto::time::Millis::from_millis(row.ts_millis as u64),
        sender_prefix: row.sender_prefix,
        sender_account: row.sender_account,
        // The `kind` column is written only from `MessageKind::db`, so an
        // unrecognized value is a corrupt row — fall back to PRIVMSG (the louder
        // kind) rather than drop the message.
        kind: crate::core::MessageKind::from_db(&row.kind)
            .unwrap_or(crate::core::MessageKind::Privmsg),
        body: row.body,
        sender_is_bot: row.sender_is_bot,
        multiline: row.multiline,
    }
}

/// The BETWEEN query with each endpoint resolved to a `(ts, id)` position *in the
/// database*, so the span and the paging direction are correct even when a
/// `msgid=` pivot has scrolled out of the in-memory ring. A `msgid=` pivot is
/// looked up within this target (an unknown-here msgid yields an empty result,
/// like the other msgid pivots); a `timestamp=` bound has no id, so it uses id
/// sentinels that make its comparison ts-only. Returns rows oldest-first.
async fn query_between_selectors(
    pool: &PgPool,
    target: &str,
    first: &crate::core::SelectorBound,
    second: &crate::core::SelectorBound,
    limit: usize,
) -> Result<Vec<crate::core::HistoryRow>, sqlx::Error> {
    use crate::core::SelectorBound;
    // Resolve a selector to `(ts_ms, ordering_id, is_timestamp)`. A missing msgid
    // is `None` → the whole window is empty.
    async fn marker(
        pool: &PgPool,
        target: &str,
        b: &SelectorBound,
    ) -> Result<Option<(i64, i64, bool)>, sqlx::Error> {
        match b {
            SelectorBound::Timestamp(t) => Ok(Some((t.as_millis() as i64, 0, true))),
            SelectorBound::Msgid(m) => {
                let row: Option<(i64, i64)> = sqlx::query_as(
                    "SELECT (EXTRACT(EPOCH FROM ts) * 1000)::bigint, id \
                     FROM messages WHERE msgid = $1 AND target = $2",
                )
                .bind(m)
                .bind(target)
                .fetch_optional(pool)
                .await?;
                Ok(row.map(|(ts, id)| (ts, id, false)))
            }
        }
    }
    let (m1, m2) = match (
        marker(pool, target, first).await,
        marker(pool, target, second).await,
    ) {
        (Ok(Some(a)), Ok(Some(b))) => (a, b),
        // A DB fault is surfaced (Err), never folded into an empty page — the
        // caller distinguishes "no such window" from "the store failed".
        (Err(e), _) | (_, Err(e)) => return Err(e),
        // A pivot msgid that is not in this buffer → genuinely empty (as for the
        // other msgid pivots), not a plausible-but-wrong window, and not a fault.
        _ => return Ok(Vec::new()),
    };
    // Order the two pivots; the first selector being the newer bound means the
    // `limit` cuts from the newest end (CHATHISTORY walks first → second).
    let newest_first = (m1.0, m1.1) > (m2.0, m2.1);
    let (older, newer) = if newest_first { (m2, m1) } else { (m1, m2) };
    // Lower bound (strictly after the older pivot): a timestamp uses id = MAX so
    // `(ts,id) > (T, MAX)` is `ts > T`. Upper bound (strictly before the newer
    // pivot): a timestamp uses id = MIN so `(ts,id) < (T, MIN)` is `ts < T`.
    let (lo_ts, lo_id) = (older.0, if older.2 { i64::MAX } else { older.1 });
    let (hi_ts, hi_id) = (newer.0, if newer.2 { i64::MIN } else { newer.1 });
    let sql = if newest_first {
        history_select!(
            "WHERE target = $1 \
             AND (ts, id) > (to_timestamp($2::double precision / 1000), $3::bigint) \
             AND (ts, id) < (to_timestamp($4::double precision / 1000), $5::bigint) \
             ORDER BY ts DESC, id DESC LIMIT $6"
        )
    } else {
        history_select!(
            "WHERE target = $1 \
             AND (ts, id) > (to_timestamp($2::double precision / 1000), $3::bigint) \
             AND (ts, id) < (to_timestamp($4::double precision / 1000), $5::bigint) \
             ORDER BY ts ASC, id ASC LIMIT $6"
        )
    };
    let rows: Result<Vec<HistoryDbRow>, sqlx::Error> = sqlx::query_as(sql)
        .bind(target)
        .bind(lo_ts)
        .bind(lo_id)
        .bind(hi_ts)
        .bind(hi_id)
        .bind(limit as i64)
        .fetch_all(pool)
        .await;
    let mut rows = rows?;
    if newest_first {
        rows.reverse(); // the batch replays oldest-first
    }
    Ok(rows.into_iter().map(history_row_from_db).collect())
}

/// CHATHISTORY TARGETS: buffers whose latest message falls strictly between
/// `min_ts` and `max_ts` — among the `channels` (casefolded) the requester can
/// see, plus every direct-message conversation `me` takes part in, reported as
/// the correspondent's casefolded nick. Oldest activity first, so a `limit` keeps
/// the oldest buffers. Empty on a query error (logged loudly).
pub async fn query_targets(
    pool: &PgPool,
    channels: &[String],
    me: &str,
    min_ts: e6irc_proto::time::Millis,
    max_ts: e6irc_proto::time::Millis,
    limit: usize,
) -> Result<Vec<(String, e6irc_proto::time::Millis)>, sqlx::Error> {
    // A conversation is keyed by both participants, so it is reported under the
    // *other* one — and under `me` for a conversation with oneself, whose key
    // has only the single participant.
    // The window is tested against each buffer's *latest* message, not against
    // any message it happens to contain: a buffer whose newest activity is
    // outside the window has already been read past, so reporting it would
    // hand a reconnecting client backlog it does not need.
    let rows: Result<Vec<(String, i64)>, sqlx::Error> = sqlx::query_as(
        "SELECT name, (EXTRACT(EPOCH FROM MAX(latest)) * 1000)::bigint AS latest FROM (
             SELECT target AS name, MAX(ts) AS latest
             FROM messages
             WHERE target = ANY($1)
             GROUP BY target
             UNION ALL
             SELECT COALESCE(
                        (SELECT p FROM UNNEST(dm_peers) p WHERE p <> $5 LIMIT 1),
                        $5
                    ) AS name,
                    MAX(ts) AS latest
             FROM messages
             WHERE dm_peers @> ARRAY[$5::text]
             GROUP BY name
         ) buffers
         GROUP BY name
         HAVING MAX(latest) > to_timestamp($2::double precision / 1000)
            AND MAX(latest) < to_timestamp($3::double precision / 1000)
         ORDER BY latest ASC
         LIMIT $4",
    )
    .bind(channels)
    .bind(min_ts.as_millis() as f64)
    .bind(max_ts.as_millis() as f64)
    .bind(limit as i64)
    .bind(me)
    .fetch_all(pool)
    .await;
    Ok(rows?
        .into_iter()
        .map(|(t, ts)| (t, e6irc_proto::time::Millis::from_millis(ts as u64)))
        .collect())
}

/// Most access entries (auto-op/voice grants) one channel may hold. Bounds both
/// the persisted `channel_access` rows and the in-core map they preload into.
const MAX_ACCESS_ENTRIES_PER_CHANNEL: i64 = 256;

/// Upsert (`flags = Some`) or remove (`flags = None`) one channel-access entry.
/// Returns whether the change was *applied to a real account*: the grant INSERT
/// affects no rows when no `accounts` row matches (the account isn't
/// registered), so the caller can refuse to record a phantom grant in its hot
/// map. A removal is always considered applied — dropping a (possibly stale)
/// entry is idempotent cleanup.
pub async fn set_channel_access(
    pool: &PgPool,
    channel: &str,
    account: &str,
    flags: Option<String>,
) -> Result<bool, DbError> {
    let channel_folded = CaseMapping::Rfc1459.casefold(channel);
    let account_folded = CaseMapping::Rfc1459.casefold(account);
    match flags {
        Some(flags) => {
            // Cap the access list per channel, like every sibling grant collection
            // (app passwords, PATs, BNC networks): count + insert in one
            // transaction with the channel row locked FOR UPDATE, so two founders
            // granting concurrently can't both slip past the cap. Without it the
            // map — and its persisted rows, re-loaded into RAM on every boot by
            // `preload_access` — grow without bound. Only a *new* (channel,
            // account) pair counts against the cap; re-flagging an existing entry
            // is always allowed (it replaces, it doesn't grow).
            let mut tx = pool.begin().await.map_err(DbError::Query)?;
            let ids: Option<(i64, i64)> = sqlx::query_as(
                "SELECT c.id, a.id FROM channels c, accounts a
                 WHERE c.name_folded = $1 AND a.name_folded = $2
                 FOR UPDATE OF c",
            )
            .bind(&channel_folded)
            .bind(&account_folded)
            .fetch_optional(&mut *tx)
            .await
            .map_err(DbError::Query)?;
            // No match → the account isn't registered (or the channel is gone);
            // nothing granted, same as before.
            let Some((channel_id, account_id)) = ids else {
                return Ok(false);
            };
            let already: Option<i64> = sqlx::query_scalar(
                "SELECT account_id FROM channel_access WHERE channel_id = $1 AND account_id = $2",
            )
            .bind(channel_id)
            .bind(account_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(DbError::Query)?;
            if already.is_none() {
                let count: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM channel_access WHERE channel_id = $1")
                        .bind(channel_id)
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(DbError::Query)?;
                if count >= MAX_ACCESS_ENTRIES_PER_CHANNEL {
                    return Err(DbError::TooManyAccessEntries);
                }
            }
            sqlx::query(
                "INSERT INTO channel_access (channel_id, account_id, flags)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (channel_id, account_id) DO UPDATE SET flags = EXCLUDED.flags",
            )
            .bind(channel_id)
            .bind(account_id)
            .bind(flags)
            .execute(&mut *tx)
            .await
            .map_err(DbError::Query)?;
            tx.commit().await.map_err(DbError::Query)?;
            Ok(true)
        }
        None => {
            sqlx::query(
                "DELETE FROM channel_access ca USING channels c, accounts a
                 WHERE ca.channel_id = c.id AND ca.account_id = a.id
                   AND c.name_folded = $1 AND a.name_folded = $2",
            )
            .bind(&channel_folded)
            .bind(&account_folded)
            .execute(pool)
            .await
            .map_err(DbError::Query)?;
            Ok(true)
        }
    }
}

/// Persist and audit one founder-owned channel mutation in a transaction.
/// Locking the channel row makes ownership authorization, the write, and its
/// audit record one indivisible transition.
pub async fn persist_owned_channel_mutation(
    pool: &PgPool,
    channel: &str,
    actor: &str,
    mutation: &crate::core::PersistedChannelMutation,
) -> Result<crate::core::ChannelControlResult, DbError> {
    use crate::core::{ChannelControlResult, PersistedChannelMutation};

    let channel_folded = CaseMapping::Rfc1459.casefold(channel);
    let actor_folded = CaseMapping::Rfc1459.casefold(actor);
    let mut transaction = pool.begin().await.map_err(DbError::Query)?;
    let row: Option<(i64, String, bool)> = sqlx::query_as(
        "SELECT c.id, a.name_folded, c.keeptopic
         FROM channels c JOIN accounts a ON a.id = c.founder_account_id
         WHERE c.name_folded = $1
         FOR UPDATE OF c",
    )
    .bind(&channel_folded)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(DbError::Query)?;
    let Some((channel_id, founder, keeptopic)) = row else {
        return Ok(ChannelControlResult::MissingOrNotOwner);
    };
    if founder != actor_folded {
        return Ok(ChannelControlResult::MissingOrNotOwner);
    }

    let (action, detail) = match mutation {
        PersistedChannelMutation::SetTopic { topic } => {
            if !keeptopic {
                return Ok(ChannelControlResult::KeeptopicDisabled);
            }
            let (text, setter, set_at) = match topic {
                Some((text, setter, set_at)) => (Some(text), Some(setter), Some(*set_at as f64)),
                None => (None, None, None),
            };
            sqlx::query(
                "UPDATE channels
                 SET topic = $2,
                     topic_setter = $3,
                     topic_set_at = CASE
                         WHEN $4::double precision IS NULL THEN NULL
                         ELSE to_timestamp($4::double precision)
                     END
                 WHERE id = $1",
            )
            .bind(channel_id)
            .bind(text)
            .bind(setter)
            .bind(set_at)
            .execute(&mut *transaction)
            .await
            .map_err(DbError::Query)?;
            (
                "CHANNEL_TOPIC",
                if topic.is_some() { "set" } else { "cleared" }.to_string(),
            )
        }
        PersistedChannelMutation::SetKeeptopic { enabled, topic } => {
            let (text, setter, set_at) = match topic {
                Some((text, setter, set_at)) if *enabled => {
                    (Some(text), Some(setter), Some(*set_at as f64))
                }
                _ => (None, None, None),
            };
            sqlx::query(
                "UPDATE channels
                 SET keeptopic = $2,
                     topic = $3,
                     topic_setter = $4,
                     topic_set_at = CASE
                         WHEN $5::double precision IS NULL THEN NULL
                         ELSE to_timestamp($5::double precision)
                     END
                 WHERE id = $1",
            )
            .bind(channel_id)
            .bind(enabled)
            .bind(text)
            .bind(setter)
            .bind(set_at)
            .execute(&mut *transaction)
            .await
            .map_err(DbError::Query)?;
            (
                "CHANNEL_KEEPTOPIC",
                if *enabled { "on" } else { "off" }.to_string(),
            )
        }
        PersistedChannelMutation::SetMlock { mlock } => {
            sqlx::query("UPDATE channels SET mlock = $2 WHERE id = $1")
                .bind(channel_id)
                .bind(mlock)
                .execute(&mut *transaction)
                .await
                .map_err(DbError::Query)?;
            (
                "CHANNEL_MLOCK",
                mlock.as_deref().unwrap_or("cleared").to_string(),
            )
        }
        PersistedChannelMutation::SetAccess { account, flags } => {
            let account_folded = CaseMapping::Rfc1459.casefold(account);
            if let Some(flags) = flags {
                let account_id: Option<i64> =
                    sqlx::query_scalar("SELECT id FROM accounts WHERE name_folded = $1")
                        .bind(&account_folded)
                        .fetch_optional(&mut *transaction)
                        .await
                        .map_err(DbError::Query)?;
                let Some(account_id) = account_id else {
                    return Ok(ChannelControlResult::AccountMissing);
                };
                let already: Option<i64> = sqlx::query_scalar(
                    "SELECT account_id FROM channel_access
                     WHERE channel_id = $1 AND account_id = $2",
                )
                .bind(channel_id)
                .bind(account_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(DbError::Query)?;
                if already.is_none() {
                    let count: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM channel_access WHERE channel_id = $1",
                    )
                    .bind(channel_id)
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(DbError::Query)?;
                    if count >= MAX_ACCESS_ENTRIES_PER_CHANNEL {
                        return Ok(ChannelControlResult::AccessLimitReached);
                    }
                }
                sqlx::query(
                    "INSERT INTO channel_access (channel_id, account_id, flags)
                     VALUES ($1, $2, $3)
                     ON CONFLICT (channel_id, account_id)
                     DO UPDATE SET flags = EXCLUDED.flags",
                )
                .bind(channel_id)
                .bind(account_id)
                .bind(flags)
                .execute(&mut *transaction)
                .await
                .map_err(DbError::Query)?;
            } else {
                sqlx::query(
                    "DELETE FROM channel_access ca USING accounts a
                     WHERE ca.channel_id = $1 AND ca.account_id = a.id
                       AND a.name_folded = $2",
                )
                .bind(channel_id)
                .bind(&account_folded)
                .execute(&mut *transaction)
                .await
                .map_err(DbError::Query)?;
            }
            (
                "CHANNEL_ACCESS",
                format!(
                    "account={account_folded} flags={}",
                    flags.as_deref().unwrap_or("-")
                ),
            )
        }
        PersistedChannelMutation::TransferFounder { account } => {
            let account_id: Option<i64> =
                sqlx::query_scalar("SELECT id FROM accounts WHERE name_folded = $1")
                    .bind(account)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(DbError::Query)?;
            let Some(account_id) = account_id else {
                return Ok(ChannelControlResult::AccountMissing);
            };
            sqlx::query("UPDATE channels SET founder_account_id = $2 WHERE id = $1")
                .bind(channel_id)
                .bind(account_id)
                .execute(&mut *transaction)
                .await
                .map_err(DbError::Query)?;
            ("CHANNEL_FOUNDER", account.clone())
        }
        PersistedChannelMutation::Drop => {
            sqlx::query("DELETE FROM channels WHERE id = $1")
                .bind(channel_id)
                .execute(&mut *transaction)
                .await
                .map_err(DbError::Query)?;
            ("CHANNEL_DROP", String::new())
        }
    };
    insert_audit_log_with(
        &mut *transaction,
        &actor_folded,
        action,
        &channel_folded,
        &detail,
    )
    .await?;
    transaction.commit().await.map_err(DbError::Query)?;
    Ok(ChannelControlResult::Applied)
}

/// Whether `account` holds a registered relationship with `channel` — its
/// founder, or an access-flag entry. Used to authorize the REST history read,
/// which (unlike IRC `CHATHISTORY`) has no view of live channel membership, so
/// it must fail closed rather than expose any channel's history to any account.
pub async fn account_may_read_channel(
    pool: &PgPool,
    channel_folded: &str,
    account_folded: &str,
) -> Result<bool, DbError> {
    let found: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM channels c
         JOIN accounts a ON a.name_folded = $2
         WHERE c.name_folded = $1
           AND (c.founder_account_id = a.id
                OR EXISTS (SELECT 1 FROM channel_access ca
                           WHERE ca.channel_id = c.id AND ca.account_id = a.id))
         LIMIT 1",
    )
    .bind(channel_folded)
    .bind(account_folded)
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(found.is_some())
}

/// Every channel access entry, as `(channel_folded, account_folded,
/// flags)` — boot-loaded into the hot access map.
pub async fn list_channel_access(pool: &PgPool) -> Result<Vec<(String, String, String)>, DbError> {
    sqlx::query_as(
        "SELECT c.name_folded, a.name_folded, ca.flags
         FROM channel_access ca
         JOIN channels c ON c.id = ca.channel_id
         JOIN accounts a ON a.id = ca.account_id",
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}

/// Transfer a channel's founder to `new_founder_folded`. Returns whether
/// a row was updated (false = no such channel or account).
/// Transfer a channel's founder. `Ok(true)` = a row was updated, `Ok(false)` =
/// no such channel/account (a definitive negative), `Err` = the store failed.
/// The caller must keep these distinct: reporting a DB fault as "no such
/// account" would tell the founder a lie they might act on.
pub async fn set_channel_founder(
    pool: &PgPool,
    channel: &str,
    new_founder_folded: &str,
) -> Result<bool, DbError> {
    let channel_folded = CaseMapping::Rfc1459.casefold(channel);
    let res = sqlx::query(
        "UPDATE channels SET founder_account_id = a.id
         FROM accounts a
         WHERE channels.name_folded = $1 AND a.name_folded = $2",
    )
    .bind(&channel_folded)
    .bind(new_founder_folded)
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(res.rows_affected() > 0)
}

/// Persist a server ban (KLINE/DLINE/XLINE). Upserts on `(mask, kind)` so
/// re-banning an existing mask of the same kind refreshes its reason/setter.
pub async fn add_server_ban(
    pool: &PgPool,
    mask: &str,
    mask_display: &str,
    reason: &str,
    set_by: &str,
    kind: &str,
) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO server_bans (mask, mask_display, reason, set_by, kind) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (mask, kind) DO UPDATE
            SET mask_display = EXCLUDED.mask_display, reason = EXCLUDED.reason, set_by = EXCLUDED.set_by",
    )
    .bind(mask)
    .bind(mask_display)
    .bind(reason)
    .bind(set_by)
    .bind(kind)
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(())
}

/// Remove a server ban by `(mask, kind)` (UN*LINE).
pub async fn remove_server_ban(pool: &PgPool, mask: &str, kind: &str) -> Result<(), DbError> {
    sqlx::query("DELETE FROM server_bans WHERE mask = $1 AND kind = $2")
        .bind(mask)
        .bind(kind)
        .execute(pool)
        .await
        .map_err(DbError::Query)?;
    Ok(())
}

async fn mutate_server_ban_audited(
    pool: &PgPool,
    mutation: &crate::core::ServerBanMutation,
) -> Result<(), DbError> {
    let mut transaction = pool.begin().await.map_err(DbError::Query)?;
    let (actor, action, target, detail) = match mutation {
        crate::core::ServerBanMutation::Add {
            mask,
            mask_display,
            reason,
            set_by,
            kind,
        } => {
            sqlx::query(
                "INSERT INTO server_bans (mask, mask_display, reason, set_by, kind)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (mask, kind) DO UPDATE
                    SET mask_display = EXCLUDED.mask_display,
                        reason = EXCLUDED.reason,
                        set_by = EXCLUDED.set_by",
            )
            .bind(mask)
            .bind(mask_display)
            .bind(reason)
            .bind(set_by)
            .bind(kind)
            .execute(&mut *transaction)
            .await
            .map_err(DbError::Query)?;
            (
                set_by.as_str(),
                kind.to_ascii_uppercase(),
                mask_display.as_str(),
                reason.as_str(),
            )
        }
        crate::core::ServerBanMutation::Remove {
            mask,
            mask_display,
            kind,
            actor,
        } => {
            sqlx::query("DELETE FROM server_bans WHERE mask = $1 AND kind = $2")
                .bind(mask)
                .bind(kind)
                .execute(&mut *transaction)
                .await
                .map_err(DbError::Query)?;
            (
                actor.as_str(),
                format!("UN{}", kind.to_ascii_uppercase()),
                mask_display.as_str(),
                "",
            )
        }
    };
    insert_audit_log_with(&mut *transaction, actor, &action, target, detail).await?;
    transaction.commit().await.map_err(DbError::Query)
}

async fn insert_audit_log_with<'executor>(
    executor: impl sqlx::Executor<'executor, Database = sqlx::Postgres>,
    actor: &str,
    action: &str,
    target: &str,
    detail: &str,
) -> Result<(), DbError> {
    sqlx::query("INSERT INTO audit_log (actor, action, target, detail) VALUES ($1, $2, $3, $4)")
        .bind(actor)
        .bind(action)
        .bind(target)
        .bind(detail)
        .execute(executor)
        .await
        .map_err(DbError::Query)?;
    Ok(())
}

/// Record one privileged action in the audit trail.
pub async fn insert_audit_log(
    pool: &PgPool,
    actor: &str,
    action: &str,
    target: &str,
    detail: &str,
) -> Result<(), DbError> {
    insert_audit_log_with(pool, actor, action, target, detail).await
}

/// The most recent `limit` audit entries as `(actor, action, target,
/// detail, created_at RFC3339)`, newest first — for the admin API.
pub async fn list_audit_log(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<(String, String, String, String, String)>, DbError> {
    sqlx::query_as(
        "SELECT actor, action, target, detail,
                to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')
         FROM audit_log ORDER BY id DESC LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}

/// Every server ban as `(mask_display, reason, set_by, kind)` — boot-loaded
/// into the hot server-ban list. The first field is the display casing
/// (`COALESCE(mask_display, mask)` so a row predating the display column falls
/// back to its folded mask); `MaskKey::new` re-derives the fold for comparison.
pub async fn list_server_bans(
    pool: &PgPool,
) -> Result<Vec<(String, String, String, String)>, DbError> {
    sqlx::query_as(
        "SELECT COALESCE(mask_display, mask), reason, set_by, kind FROM server_bans ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}

/// Unregister a channel by its casefolded name (ChanServ DROP).
pub async fn drop_channel(pool: &PgPool, channel_folded: &str) -> Result<bool, DbError> {
    sqlx::query("DELETE FROM channels WHERE name_folded = $1")
        .bind(channel_folded)
        .execute(pool)
        .await
        .map(|result| result.rows_affected() == 1)
        .map_err(DbError::Query)
}

async fn drop_channel_audited(
    pool: &PgPool,
    channel_folded: &str,
    actor: &str,
) -> Result<bool, DbError> {
    let mut transaction = pool.begin().await.map_err(DbError::Query)?;
    let deleted = sqlx::query("DELETE FROM channels WHERE name_folded = $1")
        .bind(channel_folded)
        .execute(&mut *transaction)
        .await
        .map_err(DbError::Query)?
        .rows_affected()
        == 1;
    if deleted {
        insert_audit_log_with(&mut *transaction, actor, "DROPCHAN", channel_folded, "").await?;
    }
    transaction.commit().await.map_err(DbError::Query)?;
    Ok(deleted)
}

async fn handle_register_channel(
    pool: &PgPool,
    channel: &str,
    founder: &str,
    topic: Option<(String, String, u64)>,
    label: Option<String>,
) -> DbReply {
    use crate::core::ChannelRegistrationResult;

    match persist_channel_registration(pool, channel, founder, &topic).await {
        Ok(ChannelRegistrationResult::Registered) => DbReply::ChannelRegistered {
            channel: channel.to_string(),
            founder_account: founder.to_string(),
            topic,
            label,
        },
        Ok(ChannelRegistrationResult::Exists) => DbReply::ChannelExists {
            channel: channel.to_string(),
            label,
        },
        Ok(ChannelRegistrationResult::AccountMissing) => {
            eprintln!("db: founder account {founder} missing during channel registration");
            DbReply::ChannelRegisterUnavailable {
                channel: channel.to_string(),
                label,
            }
        }
        Ok(ChannelRegistrationResult::Unavailable) => DbReply::ChannelRegisterUnavailable {
            channel: channel.to_string(),
            label,
        },
        Err(error) => {
            eprintln!("db: channel registration failed: {error}");
            DbReply::ChannelRegisterUnavailable {
                channel: channel.to_string(),
                label,
            }
        }
    }
}

/// Insert one registered channel with its initial retained topic and audit
/// record as one transition. Both ChanServ and the owner HTTP control plane use
/// this function; only their authorization and response transports differ.
async fn persist_channel_registration(
    pool: &PgPool,
    channel: &str,
    founder: &str,
    topic: &Option<(String, String, u64)>,
) -> Result<crate::core::ChannelRegistrationResult, DbError> {
    use crate::core::ChannelRegistrationResult;

    let chan_folded = CaseMapping::Rfc1459.casefold(channel);
    let founder_folded = CaseMapping::Rfc1459.casefold(founder);
    let (topic_text, topic_setter, topic_set_at) = match topic {
        Some((text, setter, set_at)) => (
            Some(text.as_str()),
            Some(setter.as_str()),
            Some(*set_at as f64),
        ),
        None => (None, None, None),
    };
    let mut transaction = pool.begin().await.map_err(DbError::Query)?;
    let inserted: Option<i64> = sqlx::query_scalar(
        "INSERT INTO channels (
             name, name_folded, founder_account_id,
             topic, topic_setter, topic_set_at
         )
         SELECT $1, $2, a.id, $4, $5,
                CASE WHEN $6::double precision IS NULL
                     THEN NULL
                     ELSE to_timestamp($6::double precision)
                END
         FROM accounts a WHERE a.name_folded = $3
         ON CONFLICT (name_folded) DO NOTHING RETURNING id",
    )
    .bind(channel)
    .bind(&chan_folded)
    .bind(&founder_folded)
    .bind(topic_text)
    .bind(topic_setter)
    .bind(topic_set_at)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(DbError::Query)?;
    let result = if inserted.is_some() {
        insert_audit_log_with(
            &mut *transaction,
            &founder_folded,
            "CHANNEL_REGISTER",
            &chan_folded,
            "",
        )
        .await?;
        ChannelRegistrationResult::Registered
    } else {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM channels WHERE name_folded = $1)")
                .bind(&chan_folded)
                .fetch_one(&mut *transaction)
                .await
                .map_err(DbError::Query)?;
        if exists {
            ChannelRegistrationResult::Exists
        } else {
            ChannelRegistrationResult::AccountMissing
        }
    };
    transaction.commit().await.map_err(DbError::Query)?;
    Ok(result)
}

/// The three outcomes of a credential check, before an origin is attached.
/// Kept distinct from [`DbReply`] so `handle_verify` can be reused by callers
/// that are not a SASL/IDENTIFY round trip (e.g. `issue_app_password`) without
/// inventing a bogus [`CredentialOrigin`]; the worker maps it to the
/// origin-carrying reply at the one place that knows which command asked.
enum VerifyOutcome {
    Verified(String),
    Rejected,
    Unavailable,
}

impl VerifyOutcome {
    fn into_reply(self, origin: crate::core::CredentialOrigin) -> DbReply {
        match self {
            Self::Verified(account) => DbReply::PasswordVerified { account, origin },
            Self::Rejected => DbReply::PasswordRejected { origin },
            Self::Unavailable => DbReply::Unavailable { origin },
        }
    }
}

/// Create an account (hashing its password with argon2) and build the
/// origin-carrying reply. Runs off the serial worker loop (spawned by
/// `run_worker`) so its ~100ms hash can't head-of-line-block CHATHISTORY reads
/// and other logins — the same treatment `handle_verify` gets,
/// closing the "an argon2 op runs on the serial worker" class for the write path
/// too. A create writes only the accounts table (never `messages`), so it needs
/// no log-batch flush and has no ordering dependency on buffered history.
async fn handle_create_account(
    pool: &PgPool,
    name: String,
    password: &str,
    origin: crate::core::AccountOrigin,
) -> DbReply {
    match create_account(pool, &name, password).await {
        Ok(_) => DbReply::AccountCreated {
            account: name,
            origin,
        },
        Err(DbError::DuplicateAccount(_)) => DbReply::AccountExists { origin },
        Err(e) => {
            eprintln!("db: account creation failed: {e}");
            // Origin-carrying failure so the handler answers the way the client
            // asked (NickServ notice vs REGISTER FAIL) instead of dropping a
            // bare Unavailable it can't attribute.
            DbReply::AccountRegisterUnavailable { origin }
        }
    }
}

async fn handle_verify(pool: &PgPool, account: &str, password: &str) -> VerifyOutcome {
    match verify_credentials(pool, account, password).await {
        Ok(Some(account)) => VerifyOutcome::Verified(account),
        Ok(None) => VerifyOutcome::Rejected,
        Err(e) => {
            eprintln!("db: credential lookup failed: {e}");
            VerifyOutcome::Unavailable
        }
    }
}

// ---- device authorization grant (RFC 8628) ------------------------------

/// State of a device grant when polled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceStatus {
    /// Not yet approved by a user.
    Pending,
    /// Approved; the grant is consumed and a freshly-minted API token returned.
    /// Consuming the grant and minting the token happen in one transaction, so
    /// an approved grant is never destroyed by a token-mint failure.
    Approved(String),
    /// The grant window elapsed.
    Expired,
    /// No such grant (bad or already-consumed device code).
    Unknown,
}

/// Start a device grant: a secret `device_code` the client polls with and
/// a short `user_code` the user enters to approve. Valid for 10 minutes.
pub async fn create_device_grant(pool: &PgPool) -> Result<(String, String), DbError> {
    use argon2::password_hash::rand_core::RngCore;
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let device_code = e6irc_proto::base64::encode(&bytes);
    // 8 chars from an unambiguous alphabet (no 0/O/1/I/L). The length (31) does
    // not divide 256, so a plain `byte % len` would make the first `256 % 31`
    // characters more likely — a small but real bias in a human-entered
    // approval secret for an unauthenticated flow (RFC 8628 §6.1). Reject bytes
    // at or above the largest multiple of the length and redraw, so every
    // character is equiprobable.
    const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let unbiased_max = 256 - (256 % ALPHABET.len());
    let mut user_code = String::with_capacity(8);
    let mut byte = [0u8; 1];
    while user_code.len() < 8 {
        OsRng.fill_bytes(&mut byte);
        if (byte[0] as usize) < unbiased_max {
            user_code.push(ALPHABET[byte[0] as usize % ALPHABET.len()] as char);
        }
    }
    // Prune expired grants on write: `/device/start` is unauthenticated and a
    // grant is otherwise only removed when it is approved and polled, so a
    // flood of never-approved starts would grow the table without bound.
    sqlx::query("DELETE FROM device_grants WHERE expires_at <= now()")
        .execute(pool)
        .await
        .map_err(DbError::Query)?;
    sqlx::query(
        "INSERT INTO device_grants (device_code, user_code, expires_at)
         VALUES ($1, $2, now() + interval '10 minutes')",
    )
    .bind(&device_code)
    .bind(&user_code)
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    Ok((device_code, user_code))
}

/// Approve a pending grant by its `user_code`, binding it to `account`.
/// Returns whether a pending, unexpired grant was approved.
pub async fn approve_device_grant(
    pool: &PgPool,
    user_code: &str,
    account: &str,
) -> Result<bool, DbError> {
    let res = sqlx::query(
        "UPDATE device_grants SET account = $2
         WHERE user_code = $1 AND account IS NULL AND expires_at > now()",
    )
    .bind(user_code)
    .bind(account)
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(res.rows_affected() > 0)
}

/// Poll a grant; if approved and valid, atomically consume it and mint the
/// caller's API token (labelled `token_label`) in the same transaction,
/// returning the token in [`DeviceStatus::Approved`].
///
/// Consume-and-mint is one transaction on purpose: if the mint fails (a
/// transient DB error, or the account having been deleted between approval and
/// poll), the transaction rolls back and the approved grant is left intact, so
/// the client's next poll retries rather than being forced to restart the whole
/// device flow. The `DELETE ... RETURNING` row lock still guarantees only one
/// concurrent poll can win, so there is no double-mint.
pub async fn poll_device_grant(
    pool: &PgPool,
    device_code: &str,
    token_label: &str,
) -> Result<DeviceStatus, DbError> {
    let mut tx = pool.begin().await.map_err(DbError::Query)?;
    let approved: Option<String> = sqlx::query_scalar(
        "DELETE FROM device_grants
         WHERE device_code = $1 AND account IS NOT NULL AND expires_at > now()
         RETURNING account",
    )
    .bind(device_code)
    .fetch_optional(&mut *tx)
    .await
    .map_err(DbError::Query)?;
    if let Some(account) = approved {
        // Mint in the same transaction: on any error `tx` drops without commit,
        // rolling the DELETE back so the grant survives for the next poll.
        let token = insert_api_token(&mut *tx, &account, token_label).await?;
        tx.commit().await.map_err(DbError::Query)?;
        return Ok(DeviceStatus::Approved(token));
    }
    let row: Option<(bool,)> =
        sqlx::query_as("SELECT expires_at > now() FROM device_grants WHERE device_code = $1")
            .bind(device_code)
            .fetch_optional(&mut *tx)
            .await
            .map_err(DbError::Query)?;
    tx.commit().await.map_err(DbError::Query)?;
    Ok(match row {
        Some((true,)) => DeviceStatus::Pending,
        Some((false,)) => DeviceStatus::Expired,
        None => DeviceStatus::Unknown,
    })
}

/// Aggregate server counts for the admin API: `(accounts, registered
/// channels, server bans)`.
pub async fn server_stats(pool: &PgPool) -> Result<(i64, i64, i64), DbError> {
    sqlx::query_as(
        "SELECT (SELECT count(*) FROM accounts),
                (SELECT count(*) FROM channels),
                (SELECT count(*) FROM server_bans)",
    )
    .fetch_one(pool)
    .await
    .map_err(DbError::Query)
}

/// Every account's display name, ordered — for the admin API.
pub async fn list_accounts(pool: &PgPool) -> Result<Vec<String>, DbError> {
    sqlx::query_scalar("SELECT name FROM accounts ORDER BY name")
        .fetch_all(pool)
        .await
        .map_err(DbError::Query)
}

/// A fixed argon2id hash used only to spend a verification's worth of CPU on
/// the no-such-account path of [`verify_credentials`], so that account
/// existence is not a timing oracle. Computed once with the same parameters
/// as real hashes; the password it encodes is irrelevant and never matches.
fn dummy_verify_hash() -> &'static str {
    static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HASH.get_or_init(|| {
        let salt =
            SaltString::from_b64("YWJjZGVmZ2hpamtsbW5vcA").expect("static salt is valid B64");
        hasher()
            .hash_password(b"e6irc/no-such-account", &salt)
            .expect("dummy hash computes")
            .to_string()
    })
}

/// Verify `password` against `account`'s stored credentials (account
/// password or app password — both are argon2id rows under the same
/// account). Returns the account's canonical display name on success and
/// `None` on rejection (no account/nick-existence oracle). A database
/// failure is an `Err` — callers must not treat it as a rejection.
pub async fn verify_credentials(
    pool: &PgPool,
    account: &str,
    password: &str,
) -> Result<Option<String>, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT a.name, c.argon2_hash, c.id FROM accounts a
         JOIN account_credentials c ON c.account_id = a.id
         WHERE a.name_folded = $1",
    )
    .bind(&folded)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;
    if rows.is_empty() {
        // No such account. Still spend one argon2 verification against a fixed
        // throwaway hash, so a non-existent account is indistinguishable from a
        // single-credential account being rejected. (An account with extra app
        // passwords costs proportionally more argon2 to reject — an accepted,
        // minor timing signal of "has app passwords", inherent to checking each
        // stored credential; it never reveals the password itself.)
        let password = password.to_string();
        let _permit = ARGON2_PERMITS
            .acquire()
            .await
            .expect("argon2 semaphore never closed");
        tokio::task::spawn_blocking(move || {
            let parsed = PasswordHash::new(dummy_verify_hash()).expect("dummy hash parses");
            // Always fails (the password never matches); we run it only to
            // spend the argon2 time, so the result is deliberately discarded.
            let _ = hasher().verify_password(password.as_bytes(), &parsed);
        })
        .await
        .expect("verification task panicked");
        return Ok(None);
    }
    let display_name = rows[0].0.clone();
    let creds: Vec<(i64, String)> = rows.into_iter().map(|(_, h, id)| (id, h)).collect();
    let password = password.to_string();
    // Returns the id of the credential that matched, if any — evaluated over
    // every credential so the reject time is uniform (the id is only recorded,
    // never short-circuited on).
    let _permit = ARGON2_PERMITS
        .acquire()
        .await
        .expect("argon2 semaphore never closed");
    let matched_id = tokio::task::spawn_blocking(move || {
        // Evaluate every credential (not a short-circuiting any()) so the reject
        // time doesn't reveal which credential matched or how early.
        let mut matched_id: Option<i64> = None;
        for (id, hash) in &creds {
            let ok = PasswordHash::new(hash).is_ok_and(|parsed| {
                hasher()
                    .verify_password(password.as_bytes(), &parsed)
                    .is_ok()
            });
            if ok {
                matched_id = Some(*id);
            }
        }
        matched_id
    })
    .await
    .expect("verification task panicked");
    if let Some(id) = matched_id {
        // Record the use so the credential list can show it. Best-effort: a
        // failure here must not fail an otherwise-successful authentication, so
        // it is logged, not propagated.
        if let Err(e) =
            sqlx::query("UPDATE account_credentials SET last_used_at = now() WHERE id = $1")
                .bind(id)
                .execute(pool)
                .await
        {
            eprintln!("db: failed to record credential last-used time: {e}");
        }
    }
    Ok(matched_id.map(|_| display_name))
}

// ---- per-account BNC networks (DESIGN §10.3) ----------------------------

/// A stored per-account BNC network. `sasl_password_sealed` is an
/// `enc:v1:` blob (or `None`); the caller decrypts it with the master
/// key before starting the driver.
#[derive(Debug, Clone)]
pub struct BncNetworkRow {
    /// Which driver backs this network (`irc` for a plain upstream, or a
    /// `matrix`/`discord`/`slack` bridge).
    pub kind: crate::config::NetworkKind,
    pub name: String,
    pub addr: String,
    pub tls: bool,
    pub nick: String,
    pub realname: Option<String>,
    pub autojoin: Vec<String>,
    pub sasl_account: Option<String>,
    pub sasl_password_sealed: Option<String>,
    /// Whether an always-on driver runs for this network. A disabled
    /// network keeps its config/buffers but is skipped at boot.
    pub enabled: bool,
}

fn stored_network_kind(kind: &str) -> Result<crate::config::NetworkKind, DbError> {
    match crate::config::NetworkKind::from_db_str(kind) {
        Some(parsed) if parsed != crate::config::NetworkKind::Local => Ok(parsed),
        _ => Err(DbError::InvalidNetworkKind(kind.to_string())),
    }
}

fn bnc_row(row: &sqlx::postgres::PgRow) -> Result<BncNetworkRow, DbError> {
    use sqlx::Row;
    let kind = row.get::<String, _>("kind");
    Ok(BncNetworkRow {
        kind: stored_network_kind(&kind)?,
        name: row.get("name"),
        addr: row.get("addr"),
        tls: row.get("tls"),
        nick: row.get("nick"),
        realname: row.get("realname"),
        enabled: row.get("enabled"),
        autojoin: row.get("autojoin"),
        sasl_account: row.get("sasl_account"),
        sasl_password_sealed: row.get("sasl_password_sealed"),
    })
}

/// Create a network owned by `account`. Errors with `DuplicateNetwork`
/// on a name collision for that owner, `BadCredentials` if the account
/// is unknown.
pub async fn create_bnc_network(
    pool: &PgPool,
    account: &str,
    net: &BncNetworkRow,
) -> Result<i64, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    // Cap the count and insert in one transaction with the account row locked
    // FOR UPDATE. A count-then-insert across two pool statements (which is what
    // the REST handler used to do) lets two concurrent creates each read cap-1
    // and both insert, overshooting the cap — and each network spawns an
    // always-on outbound driver, the very amplifier this cap exists to bound.
    let mut tx = pool.begin().await.map_err(DbError::Query)?;
    let account_id: i64 =
        sqlx::query_scalar("SELECT id FROM accounts WHERE name_folded = $1 FOR UPDATE")
            .bind(&folded)
            .fetch_optional(&mut *tx)
            .await
            .map_err(DbError::Query)?
            .ok_or(DbError::BadCredentials)?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM bnc_networks WHERE account_id = $1")
        .bind(account_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(DbError::Query)?;
    if count >= MAX_BNC_NETWORKS_PER_ACCOUNT {
        return Err(DbError::TooManyNetworks);
    }
    let id = sqlx::query_scalar(
        "INSERT INTO bnc_networks
           (account_id, name, addr, tls, nick, realname, autojoin,
            sasl_account, sasl_password_sealed, kind, enabled)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         ON CONFLICT (account_id, lower(name)) DO NOTHING
         RETURNING id",
    )
    .bind(account_id)
    .bind(&net.name)
    .bind(&net.addr)
    .bind(net.tls)
    .bind(&net.nick)
    .bind(&net.realname)
    .bind(&net.autojoin)
    .bind(&net.sasl_account)
    .bind(&net.sasl_password_sealed)
    .bind(net.kind.as_db_str())
    .bind(net.enabled)
    .fetch_optional(&mut *tx)
    .await
    .map_err(DbError::Query)?
    .ok_or_else(|| DbError::DuplicateNetwork(net.name.clone()))?;
    tx.commit().await.map_err(DbError::Query)?;
    Ok(id)
}

/// Most BNC networks one account may hold, matching the REST layer's
/// `MAX_NETWORKS_PER_ACCOUNT`. Each network runs an always-on outbound driver,
/// so this bounds an account's outbound-connection amplification.
const MAX_BNC_NETWORKS_PER_ACCOUNT: i64 = 32;

/// List the networks owned by `account`, ordered by name.
pub async fn list_bnc_networks(
    pool: &PgPool,
    account: &str,
) -> Result<Vec<BncNetworkRow>, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let rows = sqlx::query(
        "SELECT n.name, n.addr, n.tls, n.nick, n.realname, n.autojoin,
                n.sasl_account, n.sasl_password_sealed, n.enabled, n.kind
         FROM bnc_networks n JOIN accounts a ON a.id = n.account_id
         WHERE a.name_folded = $1 ORDER BY n.name",
    )
    .bind(&folded)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;
    rows.iter().map(bnc_row).collect()
}

/// One stored BNC network paired with its display owner for admin inventory.
pub struct OwnedBncNetworkRow {
    pub owner: String,
    pub network: BncNetworkRow,
}

/// Every account-owned network, ordered by owner and name. This is consumed
/// only behind the HTTP administrator gate.
pub async fn list_bnc_network_inventory(pool: &PgPool) -> Result<Vec<OwnedBncNetworkRow>, DbError> {
    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT a.name AS owner, n.name, n.addr, n.tls, n.nick, n.realname, n.autojoin,
                n.sasl_account, n.sasl_password_sealed, n.enabled, n.kind
         FROM bnc_networks n JOIN accounts a ON a.id = n.account_id
         ORDER BY a.name_folded, lower(n.name)",
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;
    rows.iter()
        .map(|row| {
            Ok(OwnedBncNetworkRow {
                owner: row.get("owner"),
                network: bnc_row(row)?,
            })
        })
        .collect()
}

/// One network owned by `account`, by name — used to rebuild a driver
/// when a paused network is re-enabled. `None` if the caller owns no
/// network of that name.
pub async fn get_bnc_network(
    pool: &PgPool,
    account: &str,
    name: &str,
) -> Result<Option<BncNetworkRow>, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let row = sqlx::query(
        "SELECT n.name, n.addr, n.tls, n.nick, n.realname, n.autojoin,
                n.sasl_account, n.sasl_password_sealed, n.enabled, n.kind
         FROM bnc_networks n JOIN accounts a ON a.id = n.account_id
         WHERE a.name_folded = $1 AND lower(n.name) = lower($2)",
    )
    .bind(&folded)
    .bind(name)
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)?;
    row.as_ref().map(bnc_row).transpose()
}

/// Enable or disable `account`'s network `name`. Returns whether a row
/// matched (false ⇒ no such network for that owner).
pub async fn set_bnc_network_enabled(
    pool: &PgPool,
    account: &str,
    name: &str,
    enabled: bool,
) -> Result<bool, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let done = sqlx::query(
        "UPDATE bnc_networks n SET enabled = $3
         FROM accounts a
         WHERE n.account_id = a.id AND a.name_folded = $1 AND lower(n.name) = lower($2)",
    )
    .bind(&folded)
    .bind(name)
    .bind(enabled)
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(done.rows_affected() > 0)
}

/// Update `account`'s network `name` connection/identity fields (addr, tls,
/// nick, realname, autojoin). The SASL credentials and `kind` are deliberately
/// left unchanged — a credential/kind change goes through delete+recreate, so
/// this never has to preserve-or-replace a sealed secret. Returns whether a row
/// matched (false ⇒ no such network for that owner).
#[allow(clippy::too_many_arguments)] // one column per parameter; a struct would just re-list them
pub async fn update_bnc_network(
    pool: &PgPool,
    account: &str,
    name: &str,
    addr: &str,
    tls: bool,
    nick: &str,
    realname: Option<&str>,
    autojoin: &[String],
) -> Result<bool, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let done = sqlx::query(
        "UPDATE bnc_networks n
         SET addr = $3, tls = $4, nick = $5, realname = $6, autojoin = $7
         FROM accounts a
         WHERE n.account_id = a.id AND a.name_folded = $1 AND lower(n.name) = lower($2)",
    )
    .bind(&folded)
    .bind(name)
    .bind(addr)
    .bind(tls)
    .bind(nick)
    .bind(realname)
    .bind(autojoin)
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(done.rows_affected() > 0)
}

/// Every *enabled* network across all accounts, paired with its owner's
/// display name — used to start always-on drivers at boot. Disabled
/// networks are intentionally skipped: they run no driver.
pub async fn list_all_bnc_networks(pool: &PgPool) -> Result<Vec<(String, BncNetworkRow)>, DbError> {
    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT a.name AS owner, n.name, n.addr, n.tls, n.nick, n.realname,
                n.autojoin, n.sasl_account, n.sasl_password_sealed, n.enabled, n.kind
         FROM bnc_networks n JOIN accounts a ON a.id = n.account_id
         WHERE n.enabled",
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;
    rows.iter()
        .map(|r| Ok((r.get::<String, _>("owner"), bnc_row(r)?)))
        .collect()
}

/// Every registered channel with its founder, as `(name_folded,
/// founder_name_folded)` — boot-loaded into the core's hot ownership map.
pub async fn list_registered_channels(pool: &PgPool) -> Result<Vec<(String, String)>, DbError> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT c.name_folded, a.name_folded
         FROM channels c JOIN accounts a ON a.id = c.founder_account_id",
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(rows)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelAccessEntry {
    pub account: String,
    pub flags: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedChannel {
    pub name: String,
    pub founder: String,
    pub keeptopic: bool,
    pub topic: Option<String>,
    pub topic_setter: Option<String>,
    pub topic_set_at_millis: Option<i64>,
    pub mlock: Option<String>,
    pub access: Vec<ChannelAccessEntry>,
}

#[derive(sqlx::FromRow)]
struct OwnedChannelRow {
    name: String,
    founder: String,
    keeptopic: bool,
    topic: Option<String>,
    topic_setter: Option<String>,
    topic_set_at_millis: Option<i64>,
    mlock: Option<String>,
    access_account: Option<String>,
    access_flags: Option<String>,
}

/// Every registered channel founded by `account`, including its complete
/// persisted control-plane configuration. One ordered join produces a
/// statement-consistent view; callers never need to stitch channel rows and
/// access grants from independently changing queries.
pub async fn list_owned_channels(
    pool: &PgPool,
    account: &str,
) -> Result<Vec<OwnedChannel>, DbError> {
    let account_folded = CaseMapping::Rfc1459.casefold(account);
    let rows: Vec<OwnedChannelRow> = sqlx::query_as(
        "SELECT c.name,
                founder.name AS founder,
                c.keeptopic,
                c.topic,
                c.topic_setter,
                (EXTRACT(EPOCH FROM c.topic_set_at) * 1000)::bigint
                    AS topic_set_at_millis,
                c.mlock,
                access_account.name AS access_account,
                ca.flags AS access_flags
         FROM channels c
         JOIN accounts founder ON founder.id = c.founder_account_id
         LEFT JOIN channel_access ca ON ca.channel_id = c.id
         LEFT JOIN accounts access_account ON access_account.id = ca.account_id
         WHERE founder.name_folded = $1
         ORDER BY c.name_folded, access_account.name_folded",
    )
    .bind(account_folded)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;

    let mut channels: Vec<OwnedChannel> = Vec::new();
    for row in rows {
        let is_new = channels
            .last()
            .is_none_or(|channel| channel.name != row.name);
        if is_new {
            channels.push(OwnedChannel {
                name: row.name.clone(),
                founder: row.founder,
                keeptopic: row.keeptopic,
                topic: row.topic,
                topic_setter: row.topic_setter,
                topic_set_at_millis: row.topic_set_at_millis,
                mlock: row.mlock,
                access: Vec::new(),
            });
        }
        match (row.access_account, row.access_flags) {
            (Some(account), Some(flags)) => channels
                .last_mut()
                .expect("channel row inserted")
                .access
                .push(ChannelAccessEntry { account, flags }),
            (None, None) => {}
            _ => {
                return Err(DbError::Query(sqlx::Error::Protocol(
                    "channel access row has only one nullable field".into(),
                )));
            }
        }
    }
    Ok(channels)
}

/// Every registered channel that has a retained topic, as `(name_folded,
/// text, setter, set_at_secs)` — boot-loaded into the hot topic map.
pub async fn list_channel_topics(
    pool: &PgPool,
) -> Result<Vec<(String, String, String, u64)>, DbError> {
    let rows: Vec<(String, String, String, i64)> = sqlx::query_as(
        "SELECT name_folded, topic, topic_setter,
                EXTRACT(EPOCH FROM topic_set_at)::bigint
         FROM channels
         WHERE topic IS NOT NULL AND topic_setter IS NOT NULL AND topic_set_at IS NOT NULL",
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(rows
        .into_iter()
        .map(|(n, t, s, ts)| (n, t, s, ts as u64))
        .collect())
}

/// Persist a registered channel's KEEPTOPIC option on its `channels` row.
pub async fn set_channel_keeptopic(
    pool: &PgPool,
    channel_folded: &str,
    keeptopic: bool,
    topic: Option<(String, String, u64)>,
) -> Result<bool, DbError> {
    let (text, setter, set_at) = match topic {
        Some((text, setter, set_at)) if keeptopic => {
            (Some(text), Some(setter), Some(set_at as f64))
        }
        _ => (None, None, None),
    };
    sqlx::query(
        "UPDATE channels
         SET keeptopic = $2,
             topic = $3,
             topic_setter = $4,
             topic_set_at = CASE
                 WHEN $5::double precision IS NULL
                 THEN NULL
                 ELSE to_timestamp($5::double precision)
             END
         WHERE name_folded = $1",
    )
    .bind(channel_folded)
    .bind(keeptopic)
    .bind(text)
    .bind(setter)
    .bind(set_at)
    .execute(pool)
    .await
    .map(|result| result.rows_affected() == 1)
    .map_err(DbError::Query)
}

/// The folded names of registered channels whose KEEPTOPIC is OFF — the
/// exceptions boot-loaded into the hot set (default is on).
pub async fn list_keeptopic_off(pool: &PgPool) -> Result<Vec<String>, DbError> {
    sqlx::query_scalar("SELECT name_folded FROM channels WHERE NOT keeptopic")
        .fetch_all(pool)
        .await
        .map_err(DbError::Query)
}

/// Persist a registered channel's mode lock on its `channels` row (`None`
/// clears it).
pub async fn set_channel_mlock(
    pool: &PgPool,
    channel_folded: &str,
    mlock: Option<String>,
) -> Result<bool, DbError> {
    sqlx::query("UPDATE channels SET mlock = $2 WHERE name_folded = $1")
        .bind(channel_folded)
        .bind(mlock)
        .execute(pool)
        .await
        .map(|result| result.rows_affected() == 1)
        .map_err(DbError::Query)
}

/// Registered channels with a mode lock, as `(name_folded, spec)` —
/// boot-loaded into the hot lock map.
pub async fn list_channel_mlock(pool: &PgPool) -> Result<Vec<(String, String)>, DbError> {
    sqlx::query_as("SELECT name_folded, mlock FROM channels WHERE mlock IS NOT NULL")
        .fetch_all(pool)
        .await
        .map_err(DbError::Query)
}

/// Delete `account`'s network `name`. Returns whether a row was removed.
///
/// The network row and its buffer rows are removed in one transaction: they
/// commit or roll back together. Done as two standalone statements, a failure
/// (or a crash) after the network delete committed would orphan the buffer
/// rows — and because a later same-named network for the same owner replays
/// `recent_bnc_lines`, that stale backlog would surface in the new network. The
/// caller would also have seen the network vanish yet gotten an `Err`, so a
/// retry returns `Ok(false)` ("no such network") while the cleanup limped along
/// as a side effect. One transaction removes both hazards.
pub async fn delete_bnc_network(pool: &PgPool, account: &str, name: &str) -> Result<bool, DbError> {
    let key = BncBufferKey::new(account, name);
    let mut tx = pool.begin().await.map_err(DbError::Query)?;
    let res = sqlx::query(
        "DELETE FROM bnc_networks n USING accounts a
         WHERE n.account_id = a.id AND a.name_folded = $1 AND lower(n.name) = lower($2)",
    )
    .bind(&key.owner)
    .bind(name)
    .execute(&mut *tx)
    .await
    .map_err(DbError::Query)?;
    // `bnc_buffer` has no FK to `bnc_networks`; use the same canonical composite
    // key as every buffer read/write so a case-variant delete cannot orphan rows
    // that a later same-named network would replay.
    sqlx::query("DELETE FROM bnc_buffer WHERE owner = $1 AND network = $2")
        .bind(&key.owner)
        .bind(&key.network)
        .execute(&mut *tx)
        .await
        .map_err(DbError::Query)?;
    tx.commit().await.map_err(DbError::Query)?;
    Ok(res.rows_affected() > 0)
}

/// Rows to retain per (owner, network) in `bnc_buffer`. Only the newest are
/// ever replayed (see `PRELOAD_LIMIT`); the rest are dead weight.
const BNC_BUFFER_CAP: i64 = 5000;

/// Lines one network may append before [`trim_bnc_buffer`] is due for it.
///
/// The trim is amortized rather than run per insert, and the count belongs to
/// the caller — there is one persistence task per network, so each network
/// reaches the interval on its own traffic. Keying it off the table's `id`
/// instead does not work, however cheap it looks: `id` is a single sequence
/// shared by every network, so which network gets trimmed depends on the
/// interleaving. Two networks alternating is enough for one of them to never
/// land on a multiple of the interval and never be trimmed at all.
pub const BNC_TRIM_INTERVAL: u64 = 1000;

/// Canonical storage key for one persisted BNC buffer.
///
/// The live registry folds both account and network selectors. Constructing the
/// database key here as well means no buffer API can accidentally bind a
/// display/request spelling and miss rows written by the registry.
struct BncBufferKey {
    owner: String,
    network: String,
}

impl BncBufferKey {
    fn new(owner: &str, network: &str) -> Self {
        let casemap = CaseMapping::Rfc1459;
        Self {
            owner: casemap.casefold(owner),
            network: casemap.casefold(network),
        }
    }
}

/// Append one upstream line to a network's persisted buffer.
pub async fn persist_bnc_line(
    pool: &PgPool,
    owner: &str,
    network: &str,
    line: &str,
) -> Result<(), DbError> {
    let key = BncBufferKey::new(owner, network);
    sqlx::query("INSERT INTO bnc_buffer (owner, network, line) VALUES ($1, $2, $3)")
        .bind(&key.owner)
        .bind(&key.network)
        .bind(line)
        .execute(pool)
        .await
        .map_err(DbError::Query)?;
    Ok(())
}

/// Drop all but the newest [`BNC_BUFFER_CAP`] lines of one network's buffer,
/// so an always-on network cannot grow the table forever.
pub async fn trim_bnc_buffer(pool: &PgPool, owner: &str, network: &str) -> Result<(), DbError> {
    let key = BncBufferKey::new(owner, network);
    sqlx::query(
        "DELETE FROM bnc_buffer
         WHERE owner = $1 AND network = $2 AND id < (
             SELECT min(id) FROM (
                 SELECT id FROM bnc_buffer
                 WHERE owner = $1 AND network = $2
                 ORDER BY id DESC LIMIT $3
             ) keep
         )",
    )
    .bind(&key.owner)
    .bind(&key.network)
    .bind(BNC_BUFFER_CAP)
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(())
}

/// The most recent `limit` persisted lines for `(owner, network)`,
/// returned oldest-first for replay.
pub async fn recent_bnc_lines(
    pool: &PgPool,
    owner: &str,
    network: &str,
    limit: i64,
) -> Result<Vec<String>, DbError> {
    let key = BncBufferKey::new(owner, network);
    let mut rows: Vec<String> = sqlx::query_scalar(
        "SELECT line FROM bnc_buffer
         WHERE owner = $1 AND network = $2
         ORDER BY id DESC LIMIT $3",
    )
    .bind(&key.owner)
    .bind(&key.network)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;
    rows.reverse(); // DESC fetch -> oldest-first for playback
    Ok(rows)
}

/// Stored backlog size and activity bounds for one network.
pub struct BncBufferSummary {
    pub lines: i64,
    pub oldest_at: Option<e6irc_proto::time::Millis>,
    pub newest_at: Option<e6irc_proto::time::Millis>,
}

/// Summarize one canonical owner/network buffer without loading its contents.
pub async fn bnc_buffer_summary(
    pool: &PgPool,
    owner: &str,
    network: &str,
) -> Result<BncBufferSummary, DbError> {
    let key = BncBufferKey::new(owner, network);
    let (lines, oldest_at, newest_at): (i64, Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT count(*)::bigint,
                floor(extract(epoch FROM min(created_at)) * 1000)::bigint,
                floor(extract(epoch FROM max(created_at)) * 1000)::bigint
         FROM bnc_buffer WHERE owner = $1 AND network = $2",
    )
    .bind(&key.owner)
    .bind(&key.network)
    .fetch_one(pool)
    .await
    .map_err(DbError::Query)?;
    let timestamp = |value: Option<i64>| {
        value.map(|millis| e6irc_proto::time::Millis::from_millis(millis.max(0) as u64))
    };
    Ok(BncBufferSummary {
        lines,
        oldest_at: timestamp(oldest_at),
        newest_at: timestamp(newest_at),
    })
}

// ---- web auth (OIDC identities + sessions) ------------------------------

/// Find the account linked to (issuer, subject), or provision one named
/// after the OIDC profile. Name collisions auto-suffix (-2, -3, …) —
/// interactive nick-picking arrives with the web UI.
pub async fn find_or_create_oidc_account(
    pool: &PgPool,
    issuer: &str,
    subject: &str,
    preferred_name: &str,
) -> Result<String, DbError> {
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT a.name FROM accounts a
         JOIN oidc_identities o ON o.account_id = a.id
         WHERE o.issuer = $1 AND o.subject = $2",
    )
    .bind(issuer)
    .bind(subject)
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)?;
    if let Some(name) = existing {
        return Ok(name);
    }

    let base: String = preferred_name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        .take(24)
        .collect();
    let base = if base.is_empty() {
        "user".to_string()
    } else {
        base
    };
    let mut tx = pool.begin().await.map_err(DbError::Query)?;
    let mut chosen = None;
    for i in 0..50u32 {
        let candidate = if i == 0 {
            base.clone()
        } else {
            format!("{base}-{}", i + 1)
        };
        let folded = CaseMapping::Rfc1459.casefold(&candidate);
        let id: Option<i64> = sqlx::query_scalar(
            "INSERT INTO accounts (name, name_folded) VALUES ($1, $2)
             ON CONFLICT (name_folded) DO NOTHING RETURNING id",
        )
        .bind(&candidate)
        .bind(&folded)
        .fetch_optional(&mut *tx)
        .await
        .map_err(DbError::Query)?;
        if let Some(id) = id {
            chosen = Some((id, candidate));
            break;
        }
    }
    let Some((account_id, name)) = chosen else {
        return Err(DbError::DuplicateAccount(base));
    };
    let inserted = sqlx::query(
        "INSERT INTO oidc_identities (account_id, issuer, subject) VALUES ($1, $2, $3)
         ON CONFLICT (issuer, subject) DO NOTHING",
    )
    .bind(account_id)
    .bind(issuer)
    .bind(subject)
    .execute(&mut *tx)
    .await
    .map_err(DbError::Query)?;
    if inserted.rows_affected() == 0 {
        // A concurrent first-login for the same (issuer, subject) committed
        // first. Return the winner's account rather than a spurious 503, and do
        // NOT commit our transaction — dropping it rolls back the extra account
        // this racer just created, so the identity is provisioned exactly once.
        // (PostgreSQL blocks our ON CONFLICT until the winner's tx resolves, so
        // by here the winner is committed and visible on a fresh connection.)
        let winner: String = sqlx::query_scalar(
            "SELECT a.name FROM oidc_identities o JOIN accounts a ON a.id = o.account_id
             WHERE o.issuer = $1 AND o.subject = $2",
        )
        .bind(issuer)
        .bind(subject)
        .fetch_one(pool)
        .await
        .map_err(DbError::Query)?;
        return Ok(winner);
    }
    tx.commit().await.map_err(DbError::Query)?;
    Ok(name)
}

fn token_hash(token: &str) -> Vec<u8> {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, token.as_bytes())
        .as_ref()
        .to_vec()
}

/// The upstream identity a single-sign-on web session was minted from.
///
/// These travel together and are all `Option<&str>` on the wire, so passing
/// them positionally makes transposing two of them — recording an email as a
/// role, say — a mistake the compiler cannot catch. Naming each field makes
/// that class of error unrepresentable.
#[derive(Debug, Clone, Copy, Default)]
pub struct OidcSessionIdentity<'a> {
    /// The provider's ID token, retained so logout can end the upstream SSO
    /// session (RP-initiated logout).
    pub id_token: Option<&'a str>,
    /// Configured provider name the identity came from.
    pub provider: Option<&'a str>,
    /// Issuer that asserted the identity.
    pub issuer: Option<&'a str>,
    /// Subject claim identifying the user at the issuer.
    pub subject: Option<&'a str>,
    /// Provider session identifier, used to correlate back-channel logout.
    pub sid: Option<&'a str>,
    pub email: Option<&'a str>,
    pub role: Option<&'a str>,
}

/// Mint a web session for an account: opaque 32-byte token returned to
/// the caller; only its SHA-256 is stored. 14-day expiry.
pub async fn create_web_session(pool: &PgPool, account: &str) -> Result<String, DbError> {
    create_web_session_full(pool, account, OidcSessionIdentity::default()).await
}

/// Like [`create_web_session`], but records the upstream identity so logout can
/// end the provider's SSO session and the account page can show who is signed
/// in.
pub async fn create_oidc_web_session(
    pool: &PgPool,
    account: &str,
    identity: OidcSessionIdentity<'_>,
) -> Result<String, DbError> {
    create_web_session_full(pool, account, identity).await
}

async fn create_web_session_full(
    pool: &PgPool,
    account: &str,
    identity: OidcSessionIdentity<'_>,
) -> Result<String, DbError> {
    let OidcSessionIdentity {
        id_token,
        provider,
        issuer,
        subject,
        sid,
        email,
        role,
    } = identity;
    use argon2::password_hash::rand_core::RngCore;
    let mut bytes = [0u8; 32];
    argon2::password_hash::rand_core::OsRng.fill_bytes(&mut bytes);
    let token = e6irc_proto::base64::encode(&bytes).replace(['+', '/'], "-");
    let folded = CaseMapping::Rfc1459.casefold(account);
    // Prune expired sessions on write: lookups already filter on `expires_at`,
    // but nothing else deletes them, so every login otherwise leaks a dead row.
    sqlx::query("DELETE FROM web_sessions WHERE expires_at <= now()")
        .execute(pool)
        .await
        .map_err(DbError::Query)?;
    let inserted = sqlx::query(
        "INSERT INTO web_sessions (token_hash, account_id, expires_at, id_token, oidc_provider,
                                   oidc_issuer, oidc_subject, oidc_sid, oidc_email, oidc_role)
         SELECT $1, a.id, now() + interval '14 days', $3, $4, $5, $6, $7, $8, $9
         FROM accounts a WHERE a.name_folded = $2",
    )
    .bind(token_hash(&token))
    .bind(&folded)
    .bind(id_token)
    .bind(provider)
    .bind(issuer)
    .bind(subject)
    .bind(sid)
    .bind(email)
    .bind(role)
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    if inserted.rows_affected() == 0 {
        return Err(DbError::BadCredentials);
    }
    Ok(token)
}

#[derive(Debug, PartialEq, Eq)]
pub struct WebSessionIdentity {
    pub account: String,
    pub email: Option<String>,
    pub role: Option<String>,
    pub provider: Option<String>,
}

/// Resolve the complete durable browser identity. Personal access tokens do
/// not enter this path and cannot impersonate a Shauth browser session.
pub async fn session_identity(
    pool: &PgPool,
    token: &str,
) -> Result<Option<WebSessionIdentity>, DbError> {
    // (account name, email, role, provider) as selected below.
    type IdentityRow = (String, Option<String>, Option<String>, Option<String>);
    let row: Option<IdentityRow> = sqlx::query_as(
        "SELECT a.name, s.oidc_email, s.oidc_role, s.oidc_provider FROM web_sessions s
         JOIN accounts a ON a.id = s.account_id
         WHERE s.token_hash = $1 AND s.expires_at > now()",
    )
    .bind(token_hash(token))
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(
        row.map(|(account, email, role, provider)| WebSessionIdentity {
            account,
            email,
            role,
            provider,
        }),
    )
}

/// Atomically consumes a signed back-channel logout token and revokes only
/// the sessions correlated by its issuer plus `sid`/`sub` claims.
pub async fn consume_oidc_backchannel_logout(
    pool: &PgPool,
    issuer: &str,
    subject: Option<&str>,
    sid: Option<&str>,
    jti: &str,
    expires_at: i64,
) -> Result<u64, DbError> {
    let mut tx = pool.begin().await.map_err(DbError::Query)?;
    sqlx::query("DELETE FROM oidc_logout_tokens WHERE expires_at <= now()")
        .execute(&mut *tx)
        .await
        .map_err(DbError::Query)?;
    let inserted = sqlx::query(
        "INSERT INTO oidc_logout_tokens (issuer, jti, expires_at)
         VALUES ($1, $2, to_timestamp($3)) ON CONFLICT DO NOTHING",
    )
    .bind(issuer)
    .bind(jti)
    .bind(expires_at)
    .execute(&mut *tx)
    .await
    .map_err(DbError::Query)?;
    if inserted.rows_affected() != 1 {
        return Err(DbError::ReplayedLogoutToken);
    }
    let deleted = match sid {
        Some(sid) => sqlx::query(
            "DELETE FROM web_sessions
                 WHERE oidc_issuer = $1 AND oidc_sid = $2
                   AND ($3::text IS NULL OR oidc_subject = $3)",
        )
        .bind(issuer)
        .bind(sid)
        .bind(subject)
        .execute(&mut *tx)
        .await
        .map_err(DbError::Query)?,
        None => {
            sqlx::query("DELETE FROM web_sessions WHERE oidc_issuer = $1 AND oidc_subject = $2")
                .bind(issuer)
                .bind(subject.expect("validated logout token has sid or sub"))
                .execute(&mut *tx)
                .await
                .map_err(DbError::Query)?
        }
    };
    tx.commit().await.map_err(DbError::Query)?;
    Ok(deleted.rows_affected())
}

/// Revoke sessions named by a verified front-channel issuer/session pair.
pub async fn revoke_oidc_frontchannel_sessions(
    pool: &PgPool,
    issuer: &str,
    sid: &str,
) -> Result<u64, DbError> {
    let deleted = sqlx::query("DELETE FROM web_sessions WHERE oidc_issuer = $1 AND oidc_sid = $2")
        .bind(issuer)
        .bind(sid)
        .execute(pool)
        .await
        .map_err(DbError::Query)?;
    Ok(deleted.rows_affected())
}

/// The OIDC `(id_token, provider)` recorded with a session, for RP-initiated
/// logout. `(None, None)` for a password/PAT session or an unknown/expired
/// token — logout stays local in that case.
pub async fn session_logout_hint(
    pool: &PgPool,
    token: &str,
) -> Result<(Option<String>, Option<String>), DbError> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT id_token, oidc_provider FROM web_sessions
         WHERE token_hash = $1 AND expires_at > now()",
    )
    .bind(token_hash(token))
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(row.unwrap_or((None, None)))
}

/// Resolve a session token to its account name, if valid and unexpired.
pub async fn session_account(pool: &PgPool, token: &str) -> Result<Option<String>, DbError> {
    sqlx::query_scalar(
        "SELECT a.name FROM web_sessions s
         JOIN accounts a ON a.id = s.account_id
         WHERE s.token_hash = $1 AND s.expires_at > now()",
    )
    .bind(token_hash(token))
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)
}

/// Delete a session (logout). Deleting an unknown token is not an
/// error: logout must be idempotent.
pub async fn delete_web_session(pool: &PgPool, token: &str) -> Result<(), DbError> {
    sqlx::query("DELETE FROM web_sessions WHERE token_hash = $1")
        .bind(token_hash(token))
        .execute(pool)
        .await
        .map_err(DbError::Query)?;
    Ok(())
}

// ---- personal access tokens ---------------------------------------------

/// Mint a PAT for an account. `e6p_`-prefixed opaque token shown once;
/// SHA-256 stored. No expiry until scoped tokens land.
/// Most PATs one account may hold via the REST create endpoint, matching the
/// REST layer's `MAX_CREDENTIALS_PER_ACCOUNT`. Bounds authenticated storage
/// growth. (The device-grant login path mints through `insert_api_token`
/// directly; each of those requires an interactive approval, so it is not a
/// flood vector and is intentionally not gated here.)
const MAX_API_TOKENS_PER_ACCOUNT: i64 = 32;

pub async fn issue_api_token(pool: &PgPool, account: &str, label: &str) -> Result<String, DbError> {
    // Cap and insert in one transaction with the account row locked FOR UPDATE.
    // A count-then-insert across two pool statements (which is what the REST
    // handler used to do) lets two concurrent requests each read cap-1 and both
    // insert, overshooting the cap — the same TOCTOU `issue_app_password` closes.
    let folded = CaseMapping::Rfc1459.casefold(account);
    let mut tx = pool.begin().await.map_err(DbError::Query)?;
    let account_id: Option<i64> =
        sqlx::query_scalar("SELECT id FROM accounts WHERE name_folded = $1 FOR UPDATE")
            .bind(&folded)
            .fetch_optional(&mut *tx)
            .await
            .map_err(DbError::Query)?;
    let Some(account_id) = account_id else {
        return Err(DbError::BadCredentials);
    };
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_tokens WHERE account_id = $1")
        .bind(account_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(DbError::Query)?;
    if count >= MAX_API_TOKENS_PER_ACCOUNT {
        return Err(DbError::TooManyCredentials);
    }
    // The account row is locked in this tx, so `insert_api_token`'s own
    // name-folded lookup resolves the same row under the lock.
    let token = insert_api_token(&mut *tx, account, label).await?;
    tx.commit().await.map_err(DbError::Query)?;
    Ok(token)
}

/// Mint a fresh PAT for `account` on the given executor and return the
/// plaintext token. Executor-generic so it can run either standalone against a
/// pool or *inside a transaction* — the device-grant path mints here in the
/// same transaction that consumes the grant, so consume and mint commit or roll
/// back together.
async fn insert_api_token<'e, E>(executor: E, account: &str, label: &str) -> Result<String, DbError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    use argon2::password_hash::rand_core::RngCore;
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let token = format!(
        "e6p_{}",
        e6irc_proto::base64::encode(&bytes).replace(['+', '/'], "-")
    );
    let folded = CaseMapping::Rfc1459.casefold(account);
    let inserted = sqlx::query(
        "INSERT INTO api_tokens (token_hash, account_id, label)
         SELECT $1, a.id, $2 FROM accounts a WHERE a.name_folded = $3",
    )
    .bind(token_hash(&token))
    .bind(label)
    .bind(&folded)
    .execute(executor)
    .await
    .map_err(DbError::Query)?;
    if inserted.rows_affected() == 0 {
        return Err(DbError::BadCredentials);
    }
    Ok(token)
}

/// Resolve a PAT to its account, if valid and unexpired.
pub async fn api_token_account(pool: &PgPool, token: &str) -> Result<Option<String>, DbError> {
    sqlx::query_scalar(
        "SELECT a.name FROM api_tokens t
         JOIN accounts a ON a.id = t.account_id
         WHERE t.token_hash = $1
           AND (t.expires_at IS NULL OR t.expires_at > now())",
    )
    .bind(token_hash(token))
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)
}

/// List an account's PATs as `(id, label, created_at RFC3339, expires_at
/// RFC3339|null)` — never the token or its hash.
pub async fn list_api_tokens(
    pool: &PgPool,
    account: &str,
) -> Result<Vec<(i64, String, String, Option<String>)>, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    sqlx::query_as(
        "SELECT t.id, t.label,
                to_char(t.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
                to_char(t.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')
         FROM api_tokens t JOIN accounts a ON a.id = t.account_id
         WHERE a.name_folded = $1
         ORDER BY t.id",
    )
    .bind(&folded)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}

/// Revoke one of `account`'s PATs by id. Returns whether a row was deleted
/// (false = not found / not owned).
pub async fn delete_api_token(pool: &PgPool, account: &str, id: i64) -> Result<bool, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let result = sqlx::query(
        "DELETE FROM api_tokens t USING accounts a
         WHERE t.account_id = a.id AND a.name_folded = $1 AND t.id = $2",
    )
    .bind(&folded)
    .bind(id)
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(result.rows_affected() > 0)
}

// ---- credential management ----------------------------------------------

/// (id, kind, label, created_at RFC3339, last_used RFC3339|null).
pub type CredentialRow = (i64, String, Option<String>, String, Option<String>);

/// List an account's credentials (never the hashes).
pub async fn list_credentials(pool: &PgPool, account: &str) -> Result<Vec<CredentialRow>, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    sqlx::query_as(
        "SELECT c.id, c.kind, c.label,
                to_char(c.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
                to_char(c.last_used_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')
         FROM account_credentials c
         JOIN accounts a ON a.id = c.account_id
         WHERE a.name_folded = $1
         ORDER BY c.id",
    )
    .bind(&folded)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}

/// Revoke one *app password* owned by `account`. Returns whether a row was
/// deleted (false = not found / not owned / not an app password).
///
/// Scoped to `kind = 'app_password'` so the endpoint cannot delete the
/// account's primary `local_password` — that would silently remove password
/// login (a self-lockout), and this endpoint is documented as revoking app
/// passwords only. `list_credentials` still shows the primary for display, but
/// it is not revocable here.
pub async fn revoke_credential(pool: &PgPool, account: &str, id: i64) -> Result<bool, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let result = sqlx::query(
        "DELETE FROM account_credentials c
         USING accounts a
         WHERE c.account_id = a.id AND a.name_folded = $1 AND c.id = $2
           AND c.kind = 'app_password'",
    )
    .bind(&folded)
    .bind(id)
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(result.rows_affected() > 0)
}

#[cfg(test)]
mod history_sql_tests {
    use super::{DbError, stored_network_kind};

    #[test]
    fn unknown_persisted_network_kind_is_an_error() {
        for invalid in ["smtp", "local"] {
            assert!(matches!(
                stored_network_kind(invalid),
                Err(DbError::InvalidNetworkKind(kind)) if kind == invalid
            ));
        }
    }

    /// The macro must produce exactly the statement the queries used to spell
    /// out. `HistoryDbRow` now binds by column *name* (`sqlx::FromRow`), so the
    /// `ts_millis` alias is load-bearing — the computed column needs a name to
    /// bind to. A silent change here would be a runtime bind failure on every
    /// history read, so it is pinned rather than trusted.
    #[test]
    fn history_select_expands_to_the_expected_statement() {
        assert_eq!(
            history_select!("WHERE target = $1 ORDER BY ts DESC, id DESC LIMIT $2"),
            "SELECT msgid, (EXTRACT(EPOCH FROM ts) * 1000)::bigint AS ts_millis, sender_prefix, \
             sender_account, kind, body, sender_is_bot, multiline FROM messages WHERE target = $1 ORDER BY ts \
             DESC, id DESC LIMIT $2"
        );
    }

    /// The windowed form keeps the alias and the ordering columns the outer
    /// query depends on.
    #[test]
    fn history_window_keeps_alias_and_ordering_columns() {
        let sql = history_window!("WHERE a", "WHERE b");
        assert!(
            sql.contains("AS ts_millis"),
            "the millis column is aliased so FromRow can bind it by name: {sql}"
        );
        assert_eq!(
            sql.matches("ts, id").count(),
            2,
            "both halves carry ordering columns"
        );
        assert!(sql.trim_end().ends_with("ORDER BY ts ASC, id ASC"));
        assert!(sql.contains("UNION ALL"));
    }
}
