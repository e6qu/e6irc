//! Database worker: owns the PostgreSQL pool. Consumes [`DbRequest`]s
//! from its queue and answers by pushing [`Input::DbReply`] into the
//! core queue — the core never touches the database directly.

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use e6irc_proto::casemap::CaseMapping;
use sqlx::PgPool;

use crate::core::{DbReply, DbRequest, Input};
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
    /// Unknown account or wrong password (indistinguishable on purpose).
    BadCredentials,
    /// A write resolved to no account row for the given name.
    UnknownAccount(String),
    ReplayedLogoutToken,
    /// The account already holds the maximum number of app passwords.
    TooManyCredentials,
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
            Self::BadCredentials => write!(f, "invalid account or password"),
            Self::UnknownAccount(n) => write!(f, "no such account: {n}"),
            Self::ReplayedLogoutToken => write!(f, "OpenID Connect logout token was replayed"),
            Self::TooManyCredentials => write!(f, "account holds too many app passwords"),
        }
    }
}

impl std::error::Error for DbError {}

pub async fn connect_and_migrate(url: &str) -> Result<PgPool, DbError> {
    let pool = PgPool::connect(url).await.map_err(DbError::Connect)?;
    MIGRATOR.run(&pool).await.map_err(DbError::Migrate)?;
    Ok(pool)
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

/// argon2id via the blocking pool — hashing is deliberately slow and
/// must not stall the async runtime.
async fn hash_password(password: String) -> Result<String, DbError> {
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
        DbReply::PasswordVerified { .. } => {}
        DbReply::PasswordRejected => return Err(DbError::BadCredentials),
        _ => return Err(DbError::Query(sqlx::Error::PoolClosed)),
    }
    let folded = CaseMapping::Rfc1459.casefold(account);
    // Cap per-account app passwords so an authenticated account can't flood the
    // credential table (mirrors the network cap). `local_password` is excluded —
    // this bounds only the app passwords a user mints.
    let app_pw_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM account_credentials c
         JOIN accounts a ON a.id = c.account_id
         WHERE a.name_folded = $1 AND c.kind = 'app_password'",
    )
    .bind(&folded)
    .fetch_one(pool)
    .await
    .map_err(DbError::Query)?;
    if app_pw_count >= MAX_APP_PASSWORDS_PER_ACCOUNT {
        return Err(DbError::TooManyCredentials);
    }
    let mut secret_bytes = [0u8; 32];
    use argon2::password_hash::rand_core::RngCore;
    OsRng.fill_bytes(&mut secret_bytes);
    let secret = e6irc_proto::base64::encode(&secret_bytes);
    let hash = hash_password(secret.clone()).await?;
    let inserted = sqlx::query(
        "INSERT INTO account_credentials (account_id, kind, argon2_hash, label)
         SELECT a.id, 'app_password', $1, $2 FROM accounts a WHERE a.name_folded = $3",
    )
    .bind(&hash)
    .bind(label)
    .bind(&folded)
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    // Guard the SELECT-INSERT like its siblings (issue_api_token,
    // create_web_session_full): if the account row was gone, insert nothing and
    // reject rather than hand back an app password that was never stored.
    if inserted.rows_affected() == 0 {
        return Err(DbError::BadCredentials);
    }
    Ok(secret)
}

/// Concurrent argon2 password verifications the worker allows in flight at once.
/// Each argon2 costs ~19 MiB, so this bounds the memory a burst of `AUTHENTICATE`
/// can pin while still decoupling auth latency from the worker's serial loop
/// (an unbounded spawn would turn a latency issue into a memory DoS).
const MAX_CONCURRENT_VERIFY: usize = 4;

/// One worker loop; run as a task. Replies always reach the core (or
/// the core is gone and the server is shutting down).
pub async fn run_worker(pool: PgPool, mut rx: Receiver<DbRequest>, core_tx: Sender<Input>) {
    let mut log_batch: Vec<DbRequest> = Vec::new();
    let verify_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_VERIFY));
    while let Some(envelope) = rx.pop().await {
        let mut next = Some(envelope.payload);
        while let Some(request) = next.take() {
            match request {
                DbRequest::LogMessage { .. } => log_batch.push(request),
                // Password verification is a pure read of the accounts/credential
                // tables (never `messages`) with no ordering dependency on any
                // other request, and its argon2 verify is ~tens of ms. Run it off
                // the worker loop — bounded by `verify_sem` — so a burst of
                // logins can't head-of-line-block CHATHISTORY reads and account
                // lookups behind one serial argon2 at a time. No flush is needed
                // (it reads no messages).
                DbRequest::VerifyPassword {
                    conn,
                    account,
                    password,
                } => {
                    let pool = pool.clone();
                    let core_tx = core_tx.clone();
                    let sem = verify_sem.clone();
                    tokio::spawn(async move {
                        let _permit = sem
                            .acquire_owned()
                            .await
                            .expect("verify semaphore never closed");
                        let reply = handle_verify(&pool, &account, &password).await;
                        // The core being gone (push fails) just means shutdown.
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
                        flush_log_batch(&pool, std::mem::take(&mut log_batch)).await;
                    }
                    if !handle_request(&pool, &core_tx, request).await {
                        return;
                    }
                }
            }
            next = rx.try_pop().map(|e| e.payload);
        }
        // Queue drained: flush accumulated history in one statement.
        if !log_batch.is_empty() {
            flush_log_batch(&pool, std::mem::take(&mut log_batch)).await;
        }
    }
}

/// Group-insert buffered LogMessage rows. Persistence is best-effort:
/// chat delivery already happened, so a failed flush is logged loudly and
/// dropped rather than retried into duplicate rows.
async fn flush_log_batch(pool: &PgPool, batch: Vec<DbRequest>) {
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
    for request in batch {
        let DbRequest::LogMessage {
            msgid,
            target,
            dm_peers,
            sender_prefix,
            sender_account,
            kind,
            body,
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
        tss.push(ts.as_millis() as i64);
    }
    let result = sqlx::query(
        "INSERT INTO messages (msgid, target, sender_prefix, sender_account, kind, body, ts, dm_peers)
         SELECT m, t, p, a, k, b, at,
                CASE WHEN d IS NULL THEN NULL ELSE string_to_array(d, '!') END
         FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[],
                     ARRAY(SELECT to_timestamp(x / 1000.0) FROM UNNEST($7::bigint[]) x),
                     $8::text[]) AS u(m, t, p, a, k, b, at, d)
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
    .execute(pool)
    .await;
    if let Err(e) = result {
        eprintln!("db: history flush of {n} messages failed: {e}");
    }
}

/// Handle one non-history request; false = core gone, stop the worker.
async fn handle_request(pool: &PgPool, core_tx: &Sender<Input>, request: DbRequest) -> bool {
    match request {
        // `run_worker` intercepts VerifyPassword and spawns it under the verify
        // semaphore before ever reaching here (like LogMessage's batching). A
        // duplicate inline path would silently lose that concurrency bound and
        // the off-loop latency decoupling, so make the invariant load-bearing
        // rather than shipping a second, unbounded copy of the logic.
        DbRequest::VerifyPassword { .. } => unreachable!("offloaded by run_worker"),
        DbRequest::VerifyToken { conn, token } => {
            let reply = match api_token_account(pool, &token).await {
                Ok(Some(account)) => DbReply::PasswordVerified { account },
                Ok(None) => DbReply::PasswordRejected,
                Err(e) => {
                    eprintln!("db: token lookup failed: {e}");
                    DbReply::Unavailable
                }
            };
            core_tx.push(Input::DbReply { conn, reply }).await.is_ok()
        }
        DbRequest::CreateAccount {
            conn,
            name,
            password,
            origin,
        } => {
            let reply = match create_account(pool, &name, &password).await {
                Ok(_) => DbReply::AccountCreated {
                    account: name,
                    origin,
                },
                Err(DbError::DuplicateAccount(_)) => DbReply::AccountExists { origin },
                Err(e) => {
                    eprintln!("db: account creation failed: {e}");
                    // Origin-carrying failure so the handler answers the way the
                    // client asked (NickServ notice vs REGISTER FAIL) instead of
                    // dropping a bare Unavailable it can't attribute.
                    DbReply::AccountRegisterUnavailable { origin }
                }
            };
            core_tx.push(Input::DbReply { conn, reply }).await.is_ok()
        }
        DbRequest::RegisterChannel {
            conn,
            channel,
            founder_account,
        } => {
            let reply = handle_register_channel(pool, &channel, &founder_account).await;
            core_tx.push(Input::DbReply { conn, reply }).await.is_ok()
        }
        DbRequest::DropChannel { channel } => {
            if let Err(e) = drop_channel(pool, &channel).await {
                eprintln!("db: channel drop failed: {e}");
            }
            true
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
                    eprintln!("db: founder transfer failed: {e}");
                    DbReply::FounderChangeUnavailable { channel }
                }
            };
            core_tx.push(Input::DbReply { conn, reply }).await.is_ok()
        }
        DbRequest::QueryHistory {
            conn,
            target,
            display,
            batch_ref,
            query,
            label,
        } => {
            let rows = query_history(pool, &target, query).await.map_err(|e| {
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
            account,
            target,
            marker_ms,
        } => {
            if let Err(e) = set_read_marker(pool, &account, &target, marker_ms).await {
                eprintln!("db: read marker persistence failed: {e}");
            }
            true
        }
        DbRequest::SetChannelTopic { channel, topic } => {
            if let Err(e) = set_channel_topic(pool, &channel, topic).await {
                eprintln!("db: channel topic persistence failed: {e}");
            }
            true
        }
        DbRequest::SetChannelKeeptopic { channel, keeptopic } => {
            if let Err(e) = set_channel_keeptopic(pool, &channel, keeptopic).await {
                eprintln!("db: channel keeptopic persistence failed: {e}");
            }
            true
        }
        DbRequest::SetChannelMlock { channel, mlock } => {
            if let Err(e) = set_channel_mlock(pool, &channel, mlock).await {
                eprintln!("db: channel mlock persistence failed: {e}");
            }
            true
        }
        DbRequest::SetChannelAccess {
            conn,
            channel,
            account,
            flags,
        } => {
            let applied = match set_channel_access(pool, &channel, &account, flags.clone()).await {
                Ok(applied) => applied,
                Err(e) => {
                    eprintln!("db: channel access persistence failed: {e}");
                    false
                }
            };
            let reply = DbReply::ChannelAccessSet {
                channel,
                account,
                flags,
                applied,
            };
            core_tx.push(Input::DbReply { conn, reply }).await.is_ok()
        }
        DbRequest::AddServerBan {
            mask,
            reason,
            set_by,
            kind,
        } => {
            if let Err(e) = add_server_ban(pool, &mask, &reason, &set_by, &kind).await {
                eprintln!("db: server-ban persistence failed: {e}");
            }
            true
        }
        DbRequest::RemoveServerBan { mask, kind } => {
            if let Err(e) = remove_server_ban(pool, &mask, &kind).await {
                eprintln!("db: server-ban removal failed: {e}");
            }
            true
        }
        DbRequest::AuditLog {
            actor,
            action,
            target,
            detail,
        } => {
            if let Err(e) = insert_audit_log(pool, &actor, &action, &target, &detail).await {
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
) -> Result<(), DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let result = sqlx::query(
        "INSERT INTO read_markers (account_id, target, marker_ts)
         SELECT a.id, $1, to_timestamp($2::double precision / 1000)
         FROM accounts a WHERE a.name_folded = $3
         ON CONFLICT (account_id, target)
         DO UPDATE SET marker_ts = GREATEST(read_markers.marker_ts, EXCLUDED.marker_ts)",
    )
    .bind(target)
    .bind(marker_ms.as_millis() as i64)
    .bind(&folded)
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    // The SELECT matches no row if the account name doesn't resolve; that
    // persists nothing while the in-core mirror already moved, silently
    // diverging the two. Surface it instead.
    if result.rows_affected() == 0 {
        return Err(DbError::UnknownAccount(account.to_string()));
    }
    Ok(())
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

/// Every OIDC identity linked to `account` as `(issuer, subject)`, ordered
/// for stable listing.
pub async fn list_oidc_identities(
    pool: &PgPool,
    account: &str,
) -> Result<Vec<(String, String)>, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    sqlx::query_as(
        "SELECT o.issuer, o.subject
         FROM oidc_identities o JOIN accounts a ON a.id = o.account_id
         WHERE a.name_folded = $1 ORDER BY o.issuer, o.subject",
    )
    .bind(&folded)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
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
) -> Result<(), DbError> {
    match topic {
        Some((text, setter, set_at)) => sqlx::query(
            "UPDATE channels
             SET topic = $2, topic_setter = $3,
                 topic_set_at = to_timestamp($4::double precision)
             WHERE name_folded = $1",
        )
        .bind(channel_folded)
        .bind(text)
        .bind(setter)
        .bind(set_at as f64),
        None => sqlx::query(
            "UPDATE channels
             SET topic = NULL, topic_setter = NULL, topic_set_at = NULL
             WHERE name_folded = $1",
        )
        .bind(channel_folded),
    }
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(())
}

/// (msgid, epoch **milliseconds**, sender prefix, kind, body) as stored.
type HistoryDbRow = (String, i64, String, String, String);

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
            "SELECT msgid, (EXTRACT(EPOCH FROM ts) * 1000)::bigint, sender_prefix, kind, body \
             FROM messages ",
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
            "SELECT msgid, e, sender_prefix, kind, body FROM ( (SELECT msgid, \
             (EXTRACT(EPOCH FROM ts) * 1000)::bigint AS e, sender_prefix, kind, body, ts, id \
             FROM messages ",
            $older,
            ") UNION ALL (SELECT msgid, (EXTRACT(EPOCH FROM ts) * 1000)::bigint AS e, \
             sender_prefix, kind, body, ts, id FROM messages ",
            $newer,
            ") ) w ORDER BY ts ASC, id ASC"
        )
    };
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
    let (msgid, ts, sender_prefix, kind, body) = row;
    crate::core::HistoryRow {
        msgid,
        ts: e6irc_proto::time::Millis::from_millis(ts as u64),
        sender_prefix,
        // The `kind` column is written only from `MessageKind::db`, so an
        // unrecognized value is a corrupt row — fall back to PRIVMSG (the louder
        // kind) rather than drop the message.
        kind: crate::core::MessageKind::from_db(&kind).unwrap_or(crate::core::MessageKind::Privmsg),
        body,
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

/// CHATHISTORY TARGETS: among `channels` (casefolded), the buffers with a
/// message in `[min_ts, max_ts]`, each with its most recent message time,
/// most-recent first. Empty on a query error (logged loudly).
/// Buffers with activity strictly between `min_ts` and `max_ts`: the
/// `channels` the requester
/// can see, plus every direct-message conversation `me` takes part in, reported
/// as the correspondent's casefolded nick. Oldest activity first, so a `limit`
/// keeps the oldest buffers.
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

/// Upsert (or remove, when `flags` is `None`) one channel access entry by
/// casefolded channel + account names.
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
            let res = sqlx::query(
                "INSERT INTO channel_access (channel_id, account_id, flags)
                 SELECT c.id, a.id, $3 FROM channels c, accounts a
                 WHERE c.name_folded = $1 AND a.name_folded = $2
                 ON CONFLICT (channel_id, account_id) DO UPDATE SET flags = EXCLUDED.flags",
            )
            .bind(&channel_folded)
            .bind(&account_folded)
            .bind(flags)
            .execute(pool)
            .await
            .map_err(DbError::Query)?;
            // No rows → the (channel, account) join matched nothing, i.e. the
            // account is not registered; nothing was granted.
            Ok(res.rows_affected() > 0)
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
    reason: &str,
    set_by: &str,
    kind: &str,
) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO server_bans (mask, reason, set_by, kind) VALUES ($1, $2, $3, $4)
         ON CONFLICT (mask, kind) DO UPDATE SET reason = EXCLUDED.reason, set_by = EXCLUDED.set_by",
    )
    .bind(mask)
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

/// Record one privileged action in the audit trail.
pub async fn insert_audit_log(
    pool: &PgPool,
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
        .execute(pool)
        .await
        .map_err(DbError::Query)?;
    Ok(())
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

/// Every server ban as `(mask, reason, set_by, kind)` — boot-loaded into
/// the hot server-ban list.
pub async fn list_server_bans(
    pool: &PgPool,
) -> Result<Vec<(String, String, String, String)>, DbError> {
    sqlx::query_as("SELECT mask, reason, set_by, kind FROM server_bans ORDER BY id")
        .fetch_all(pool)
        .await
        .map_err(DbError::Query)
}

/// Unregister a channel by its casefolded name (ChanServ DROP).
pub async fn drop_channel(pool: &PgPool, channel_folded: &str) -> Result<(), DbError> {
    sqlx::query("DELETE FROM channels WHERE name_folded = $1")
        .bind(channel_folded)
        .execute(pool)
        .await
        .map_err(DbError::Query)?;
    Ok(())
}

async fn handle_register_channel(pool: &PgPool, channel: &str, founder: &str) -> DbReply {
    let chan_folded = CaseMapping::Rfc1459.casefold(channel);
    let founder_folded = CaseMapping::Rfc1459.casefold(founder);
    let inserted: Result<Option<i64>, sqlx::Error> = sqlx::query_scalar(
        "INSERT INTO channels (name, name_folded, founder_account_id)
         SELECT $1, $2, a.id FROM accounts a WHERE a.name_folded = $3
         ON CONFLICT (name_folded) DO NOTHING RETURNING id",
    )
    .bind(channel)
    .bind(&chan_folded)
    .bind(&founder_folded)
    .fetch_optional(pool)
    .await;
    match inserted {
        Ok(Some(_)) => DbReply::ChannelRegistered {
            channel: channel.to_string(),
            // Echo the founder the row was actually written with, so the hot
            // map is seeded from the persisted value rather than the session's
            // possibly-since-changed account.
            founder_account: founder.to_string(),
        },
        // No row: either the channel exists or the founder account
        // vanished; both leave nothing registered. Distinguish them.
        Ok(None) => {
            let exists: Result<Option<i64>, _> =
                sqlx::query_scalar("SELECT id FROM channels WHERE name_folded = $1")
                    .bind(&chan_folded)
                    .fetch_optional(pool)
                    .await;
            match exists {
                Ok(Some(_)) => DbReply::ChannelExists,
                Ok(None) => {
                    eprintln!("db: founder account {founder} missing during channel registration");
                    DbReply::ChannelRegisterUnavailable
                }
                Err(e) => {
                    eprintln!("db: channel existence check failed: {e}");
                    DbReply::ChannelRegisterUnavailable
                }
            }
        }
        Err(e) => {
            eprintln!("db: channel registration failed: {e}");
            DbReply::ChannelRegisterUnavailable
        }
    }
}

async fn handle_verify(pool: &PgPool, account: &str, password: &str) -> DbReply {
    match verify_credentials(pool, account, password).await {
        Ok(Some(account)) => DbReply::PasswordVerified { account },
        Ok(None) => DbReply::PasswordRejected,
        Err(e) => {
            eprintln!("db: credential lookup failed: {e}");
            DbReply::Unavailable
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

fn bnc_row(row: &sqlx::postgres::PgRow) -> BncNetworkRow {
    use sqlx::Row;
    BncNetworkRow {
        name: row.get("name"),
        addr: row.get("addr"),
        tls: row.get("tls"),
        nick: row.get("nick"),
        realname: row.get("realname"),
        enabled: row.get("enabled"),
        autojoin: row.get("autojoin"),
        sasl_account: row.get("sasl_account"),
        sasl_password_sealed: row.get("sasl_password_sealed"),
    }
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
    let account_id: i64 = sqlx::query_scalar("SELECT id FROM accounts WHERE name_folded = $1")
        .bind(&folded)
        .fetch_optional(pool)
        .await
        .map_err(DbError::Query)?
        .ok_or(DbError::BadCredentials)?;
    sqlx::query_scalar(
        "INSERT INTO bnc_networks
           (account_id, name, addr, tls, nick, realname, autojoin,
            sasl_account, sasl_password_sealed)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (account_id, name) DO NOTHING
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
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)?
    .ok_or_else(|| DbError::DuplicateNetwork(net.name.clone()))
}

/// List the networks owned by `account`, ordered by name.
pub async fn list_bnc_networks(
    pool: &PgPool,
    account: &str,
) -> Result<Vec<BncNetworkRow>, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let rows = sqlx::query(
        "SELECT n.name, n.addr, n.tls, n.nick, n.realname, n.autojoin,
                n.sasl_account, n.sasl_password_sealed, n.enabled
         FROM bnc_networks n JOIN accounts a ON a.id = n.account_id
         WHERE a.name_folded = $1 ORDER BY n.name",
    )
    .bind(&folded)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(rows.iter().map(bnc_row).collect())
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
                n.sasl_account, n.sasl_password_sealed, n.enabled
         FROM bnc_networks n JOIN accounts a ON a.id = n.account_id
         WHERE a.name_folded = $1 AND n.name = $2",
    )
    .bind(&folded)
    .bind(name)
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(row.as_ref().map(bnc_row))
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
         WHERE n.account_id = a.id AND a.name_folded = $1 AND n.name = $2",
    )
    .bind(&folded)
    .bind(name)
    .bind(enabled)
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
                n.autojoin, n.sasl_account, n.sasl_password_sealed, n.enabled
         FROM bnc_networks n JOIN accounts a ON a.id = n.account_id
         WHERE n.enabled",
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(rows
        .iter()
        .map(|r| (r.get::<String, _>("owner"), bnc_row(r)))
        .collect())
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
) -> Result<(), DbError> {
    sqlx::query("UPDATE channels SET keeptopic = $2 WHERE name_folded = $1")
        .bind(channel_folded)
        .bind(keeptopic)
        .execute(pool)
        .await
        .map_err(DbError::Query)?;
    Ok(())
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
) -> Result<(), DbError> {
    sqlx::query("UPDATE channels SET mlock = $2 WHERE name_folded = $1")
        .bind(channel_folded)
        .bind(mlock)
        .execute(pool)
        .await
        .map_err(DbError::Query)?;
    Ok(())
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
    let folded = CaseMapping::Rfc1459.casefold(account);
    let mut tx = pool.begin().await.map_err(DbError::Query)?;
    let res = sqlx::query(
        "DELETE FROM bnc_networks n USING accounts a
         WHERE n.account_id = a.id AND a.name_folded = $1 AND n.name = $2",
    )
    .bind(&folded)
    .bind(name)
    .execute(&mut *tx)
    .await
    .map_err(DbError::Query)?;
    // bnc_buffer has no FK to bnc_networks (owner/network are plain text), so
    // its rows would otherwise be orphaned forever on delete. The persistence
    // task keys the buffer by the *casefolded* owner (NetworkKey folds it, and
    // spawn_persistence writes/reads under that), so the delete must match the
    // folded form too — binding the raw account here removed zero buffer rows,
    // leaking backlog that a same-named network would later replay.
    sqlx::query("DELETE FROM bnc_buffer WHERE owner = $1 AND network = $2")
        .bind(&folded)
        .bind(name)
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

/// Append one upstream line to a network's persisted buffer.
pub async fn persist_bnc_line(
    pool: &PgPool,
    owner: &str,
    network: &str,
    line: &str,
) -> Result<(), DbError> {
    sqlx::query("INSERT INTO bnc_buffer (owner, network, line) VALUES ($1, $2, $3)")
        .bind(owner)
        .bind(network)
        .bind(line)
        .execute(pool)
        .await
        .map_err(DbError::Query)?;
    Ok(())
}

/// Drop all but the newest [`BNC_BUFFER_CAP`] lines of one network's buffer,
/// so an always-on network cannot grow the table forever.
pub async fn trim_bnc_buffer(pool: &PgPool, owner: &str, network: &str) -> Result<(), DbError> {
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
    .bind(owner)
    .bind(network)
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
    let mut rows: Vec<String> = sqlx::query_scalar(
        "SELECT line FROM bnc_buffer
         WHERE owner = $1 AND network = $2
         ORDER BY id DESC LIMIT $3",
    )
    .bind(owner)
    .bind(network)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;
    rows.reverse(); // DESC fetch -> oldest-first for playback
    Ok(rows)
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
    sqlx::query("INSERT INTO oidc_identities (account_id, issuer, subject) VALUES ($1, $2, $3)")
        .bind(account_id)
        .bind(issuer)
        .bind(subject)
        .execute(&mut *tx)
        .await
        .map_err(DbError::Query)?;
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
pub async fn issue_api_token(pool: &PgPool, account: &str, label: &str) -> Result<String, DbError> {
    insert_api_token(pool, account, label).await
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
    /// The macro must produce exactly the statement the queries used to spell
    /// out, in the column order `HistoryDbRow` destructures. A silent change
    /// here would be a runtime column-mismatch on every history read, so it is
    /// pinned rather than trusted.
    #[test]
    fn history_select_expands_to_the_expected_statement() {
        assert_eq!(
            history_select!("WHERE target = $1 ORDER BY ts DESC, id DESC LIMIT $2"),
            "SELECT msgid, (EXTRACT(EPOCH FROM ts) * 1000)::bigint, sender_prefix, kind, body \
             FROM messages WHERE target = $1 ORDER BY ts DESC, id DESC LIMIT $2"
        );
    }

    /// The windowed form keeps the alias and the ordering columns the outer
    /// query depends on.
    #[test]
    fn history_window_keeps_alias_and_ordering_columns() {
        let sql = history_window!("WHERE a", "WHERE b");
        assert!(
            sql.contains("AS e"),
            "outer query orders by the alias: {sql}"
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
