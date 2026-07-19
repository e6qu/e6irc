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

/// argon2id via the blocking pool — hashing is deliberately slow and
/// must not stall the async runtime.
async fn hash_password(password: String) -> Result<String, DbError> {
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(DbError::Hash)
    })
    .await
    .expect("hashing task panicked")
}

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
    let mut secret_bytes = [0u8; 32];
    use argon2::password_hash::rand_core::RngCore;
    OsRng.fill_bytes(&mut secret_bytes);
    let secret = e6irc_proto::base64::encode(&secret_bytes);
    let hash = hash_password(secret.clone()).await?;
    sqlx::query(
        "INSERT INTO account_credentials (account_id, kind, argon2_hash, label)
         SELECT a.id, 'app_password', $1, $2 FROM accounts a WHERE a.name_folded = $3",
    )
    .bind(&hash)
    .bind(label)
    .bind(&folded)
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(secret)
}

/// One worker loop; run as a task. Replies always reach the core (or
/// the core is gone and the server is shutting down).
pub async fn run_worker(pool: PgPool, mut rx: Receiver<DbRequest>, core_tx: Sender<Input>) {
    let mut log_batch: Vec<DbRequest> = Vec::new();
    while let Some(envelope) = rx.pop().await {
        let mut next = Some(envelope.payload);
        while let Some(request) = next.take() {
            if let DbRequest::LogMessage { .. } = request {
                log_batch.push(request);
            } else if !handle_request(&pool, &core_tx, request).await {
                return;
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
    for request in batch {
        let DbRequest::LogMessage {
            msgid,
            target,
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
        prefixes.push(sender_prefix);
        accounts.push(sender_account);
        kinds.push(kind.to_string());
        bodies.push(body);
        tss.push(ts as i64);
    }
    let result = sqlx::query(
        "INSERT INTO messages (msgid, target, sender_prefix, sender_account, kind, body, ts)
         SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[], $5::text[],
                              $6::text[], ARRAY(SELECT to_timestamp(x) FROM UNNEST($7::bigint[]) x))",
    )
    .bind(&msgids)
    .bind(&targets)
    .bind(&prefixes)
    .bind(&accounts)
    .bind(&kinds)
    .bind(&bodies)
    .bind(&tss)
    .execute(pool)
    .await;
    if let Err(e) = result {
        eprintln!("db: history flush of {n} messages failed: {e}");
    }
}

/// Handle one non-history request; false = core gone, stop the worker.
async fn handle_request(pool: &PgPool, core_tx: &Sender<Input>, request: DbRequest) -> bool {
    match request {
        DbRequest::VerifyPassword {
            conn,
            account,
            password,
        } => {
            let reply = handle_verify(pool, &account, &password).await;
            core_tx.push(Input::DbReply { conn, reply }).await.is_ok()
        }
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
        } => {
            let reply = match create_account(pool, &name, &password).await {
                Ok(_) => DbReply::AccountCreated { account: name },
                Err(DbError::DuplicateAccount(_)) => DbReply::AccountExists,
                Err(e) => {
                    eprintln!("db: account creation failed: {e}");
                    DbReply::Unavailable
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
            let reply = if set_channel_founder(pool, &channel, &new_founder).await {
                DbReply::FounderChanged {
                    channel,
                    account: new_founder,
                }
            } else {
                DbReply::FounderChangeFailed { channel }
            };
            core_tx.push(Input::DbReply { conn, reply }).await.is_ok()
        }
        DbRequest::QueryHistory {
            conn,
            target,
            display,
            batch_ref,
            query,
        } => {
            let rows = query_history(pool, &target, query).await;
            core_tx
                .push(Input::HistoryPage {
                    conn,
                    display,
                    batch_ref,
                    rows,
                })
                .await
                .is_ok()
        }
        DbRequest::QueryTargets {
            conn,
            channels,
            min_ts,
            max_ts,
            limit,
            batch_ref,
        } => {
            let targets = query_targets(pool, &channels, min_ts, max_ts, limit).await;
            core_tx
                .push(Input::TargetsPage {
                    conn,
                    batch_ref,
                    targets,
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
            channel,
            account,
            flags,
        } => {
            if let Err(e) = set_channel_access(pool, &channel, &account, flags).await {
                eprintln!("db: channel access persistence failed: {e}");
            }
            true
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

async fn set_read_marker(
    pool: &PgPool,
    account: &str,
    target: &str,
    marker_ms: u64,
) -> Result<(), DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    sqlx::query(
        "INSERT INTO read_markers (account_id, target, marker_ts)
         SELECT a.id, $1, to_timestamp($2::double precision / 1000)
         FROM accounts a WHERE a.name_folded = $3
         ON CONFLICT (account_id, target)
         DO UPDATE SET marker_ts = GREATEST(read_markers.marker_ts, EXCLUDED.marker_ts)",
    )
    .bind(target)
    .bind(marker_ms as i64)
    .bind(&folded)
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
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

/// (msgid, epoch seconds, sender prefix, kind, body) as stored.
type HistoryDbRow = (String, i64, String, String, String);

pub async fn query_history(
    pool: &PgPool,
    target: &str,
    query: crate::core::HistoryQuery,
) -> Vec<crate::core::HistoryRow> {
    use crate::core::HistoryQuery;
    // Each branch selects a window, then we return it oldest-first.
    let rows: Result<Vec<HistoryDbRow>, sqlx::Error> = match query {
        HistoryQuery::Latest { limit } => {
            sqlx::query_as(
                "SELECT msgid, EXTRACT(EPOCH FROM ts)::bigint, sender_prefix, kind, body
                 FROM messages WHERE target = $1 ORDER BY ts DESC, id DESC LIMIT $2",
            )
            .bind(target)
            .bind(limit as i64)
            .fetch_all(pool)
            .await
        }
        HistoryQuery::Before { before_ts, limit } => {
            sqlx::query_as(
                "SELECT msgid, EXTRACT(EPOCH FROM ts)::bigint, sender_prefix, kind, body
                 FROM messages WHERE target = $1 AND ts < to_timestamp($2)
                 ORDER BY ts DESC, id DESC LIMIT $3",
            )
            .bind(target)
            .bind(before_ts as i64)
            .bind(limit as i64)
            .fetch_all(pool)
            .await
        }
        HistoryQuery::After { after_ts, limit } => {
            sqlx::query_as(
                "SELECT msgid, EXTRACT(EPOCH FROM ts)::bigint, sender_prefix, kind, body
                 FROM messages WHERE target = $1 AND ts > to_timestamp($2)
                 ORDER BY ts ASC, id ASC LIMIT $3",
            )
            .bind(target)
            .bind(after_ts as i64)
            .bind(limit as i64)
            .fetch_all(pool)
            .await
        }
        HistoryQuery::Around { around_ts, limit } => {
            // Half older than the point, half at/after it, then oldest-first.
            let before = (limit / 2) as i64;
            let after = (limit - limit / 2) as i64;
            sqlx::query_as(
                "SELECT msgid, e, sender_prefix, kind, body FROM (
                     (SELECT msgid, EXTRACT(EPOCH FROM ts)::bigint AS e, sender_prefix,
                             kind, body, ts, id
                      FROM messages WHERE target = $1 AND ts < to_timestamp($2)
                      ORDER BY ts DESC, id DESC LIMIT $3)
                     UNION ALL
                     (SELECT msgid, EXTRACT(EPOCH FROM ts)::bigint AS e, sender_prefix,
                             kind, body, ts, id
                      FROM messages WHERE target = $1 AND ts >= to_timestamp($2)
                      ORDER BY ts ASC, id ASC LIMIT $4)
                 ) w ORDER BY ts ASC, id ASC",
            )
            .bind(target)
            .bind(around_ts as i64)
            .bind(before)
            .bind(after)
            .fetch_all(pool)
            .await
        }
        HistoryQuery::Between {
            after_ts,
            before_ts,
            limit,
        } => {
            sqlx::query_as(
                "SELECT msgid, EXTRACT(EPOCH FROM ts)::bigint, sender_prefix, kind, body
                 FROM messages
                 WHERE target = $1 AND ts > to_timestamp($2) AND ts < to_timestamp($3)
                 ORDER BY ts ASC, id ASC LIMIT $4",
            )
            .bind(target)
            .bind(after_ts as i64)
            .bind(before_ts as i64)
            .bind(limit as i64)
            .fetch_all(pool)
            .await
        }
    };
    let mut rows = match rows {
        Ok(r) => r,
        Err(e) => {
            eprintln!("db: history query failed: {e}");
            return Vec::new();
        }
    };
    // LATEST/BEFORE selected newest-first; the rest are already oldest-first.
    if matches!(
        query,
        HistoryQuery::Latest { .. } | HistoryQuery::Before { .. }
    ) {
        rows.reverse();
    }
    rows.into_iter()
        .map(
            |(msgid, ts, sender_prefix, kind, body)| crate::core::HistoryRow {
                msgid,
                ts: ts as u64,
                sender_prefix,
                kind,
                body,
            },
        )
        .collect()
}

/// CHATHISTORY TARGETS: among `channels` (casefolded), the buffers with a
/// message in `[min_ts, max_ts]`, each with its most recent message time,
/// most-recent first. Empty on a query error (logged loudly).
pub async fn query_targets(
    pool: &PgPool,
    channels: &[String],
    min_ts: u64,
    max_ts: u64,
    limit: usize,
) -> Vec<(String, u64)> {
    let rows: Result<Vec<(String, i64)>, sqlx::Error> = sqlx::query_as(
        "SELECT target, EXTRACT(EPOCH FROM MAX(ts))::bigint AS latest
         FROM messages
         WHERE target = ANY($1)
           AND ts >= to_timestamp($2::double precision)
           AND ts <= to_timestamp($3::double precision)
         GROUP BY target
         ORDER BY latest DESC
         LIMIT $4",
    )
    .bind(channels)
    .bind(min_ts as f64)
    .bind(max_ts as f64)
    .bind(limit as i64)
    .fetch_all(pool)
    .await;
    match rows {
        Ok(rows) => rows.into_iter().map(|(t, ts)| (t, ts as u64)).collect(),
        Err(e) => {
            eprintln!("db: targets query failed: {e}");
            Vec::new()
        }
    }
}

/// Upsert (or remove, when `flags` is `None`) one channel access entry by
/// casefolded channel + account names.
pub async fn set_channel_access(
    pool: &PgPool,
    channel_folded: &str,
    account_folded: &str,
    flags: Option<String>,
) -> Result<(), DbError> {
    match flags {
        Some(flags) => sqlx::query(
            "INSERT INTO channel_access (channel_id, account_id, flags)
             SELECT c.id, a.id, $3 FROM channels c, accounts a
             WHERE c.name_folded = $1 AND a.name_folded = $2
             ON CONFLICT (channel_id, account_id) DO UPDATE SET flags = EXCLUDED.flags",
        )
        .bind(channel_folded)
        .bind(account_folded)
        .bind(flags),
        None => sqlx::query(
            "DELETE FROM channel_access ca USING channels c, accounts a
             WHERE ca.channel_id = c.id AND ca.account_id = a.id
               AND c.name_folded = $1 AND a.name_folded = $2",
        )
        .bind(channel_folded)
        .bind(account_folded),
    }
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(())
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
pub async fn set_channel_founder(pool: &PgPool, channel: &str, new_founder_folded: &str) -> bool {
    let channel_folded = CaseMapping::Rfc1459.casefold(channel);
    let res = sqlx::query(
        "UPDATE channels SET founder_account_id = a.id
         FROM accounts a
         WHERE channels.name_folded = $1 AND a.name_folded = $2",
    )
    .bind(&channel_folded)
    .bind(new_founder_folded)
    .execute(pool)
    .await;
    match res {
        Ok(r) => r.rows_affected() > 0,
        Err(e) => {
            eprintln!("db: founder transfer failed: {e}");
            false
        }
    }
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
                    DbReply::Unavailable
                }
                Err(e) => {
                    eprintln!("db: channel existence check failed: {e}");
                    DbReply::Unavailable
                }
            }
        }
        Err(e) => {
            eprintln!("db: channel registration failed: {e}");
            DbReply::Unavailable
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
    /// Approved; the grant is consumed and the account returned.
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
    // 8 chars from an unambiguous alphabet (no 0/O/1/I/L).
    const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let mut ub = [0u8; 8];
    OsRng.fill_bytes(&mut ub);
    let user_code: String = ub
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect();
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

/// Poll a grant; if approved and valid, consume it and return the account.
pub async fn poll_device_grant(pool: &PgPool, device_code: &str) -> Result<DeviceStatus, DbError> {
    let approved: Option<String> = sqlx::query_scalar(
        "DELETE FROM device_grants
         WHERE device_code = $1 AND account IS NOT NULL AND expires_at > now()
         RETURNING account",
    )
    .bind(device_code)
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)?;
    if let Some(account) = approved {
        return Ok(DeviceStatus::Approved(account));
    }
    let row: Option<(bool,)> =
        sqlx::query_as("SELECT expires_at > now() FROM device_grants WHERE device_code = $1")
            .bind(device_code)
            .fetch_optional(pool)
            .await
            .map_err(DbError::Query)?;
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
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT a.name, c.argon2_hash FROM accounts a
         JOIN account_credentials c ON c.account_id = a.id
         WHERE a.name_folded = $1",
    )
    .bind(&folded)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;
    if rows.is_empty() {
        return Ok(None);
    }
    let display_name = rows[0].0.clone();
    let hashes: Vec<String> = rows.into_iter().map(|(_, h)| h).collect();
    let password = password.to_string();
    let verified = tokio::task::spawn_blocking(move || {
        hashes.iter().any(|hash| {
            PasswordHash::new(hash).is_ok_and(|parsed| {
                Argon2::default()
                    .verify_password(password.as_bytes(), &parsed)
                    .is_ok()
            })
        })
    })
    .await
    .expect("verification task panicked");
    Ok(verified.then_some(display_name))
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
pub async fn delete_bnc_network(pool: &PgPool, account: &str, name: &str) -> Result<bool, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let res = sqlx::query(
        "DELETE FROM bnc_networks n USING accounts a
         WHERE n.account_id = a.id AND a.name_folded = $1 AND n.name = $2",
    )
    .bind(&folded)
    .bind(name)
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(res.rows_affected() > 0)
}

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

/// Mint a web session for an account: opaque 32-byte token returned to
/// the caller; only its SHA-256 is stored. 14-day expiry.
pub async fn create_web_session(pool: &PgPool, account: &str) -> Result<String, DbError> {
    use argon2::password_hash::rand_core::RngCore;
    let mut bytes = [0u8; 32];
    argon2::password_hash::rand_core::OsRng.fill_bytes(&mut bytes);
    let token = e6irc_proto::base64::encode(&bytes).replace(['+', '/'], "-");
    let folded = CaseMapping::Rfc1459.casefold(account);
    let inserted = sqlx::query(
        "INSERT INTO web_sessions (token_hash, account_id, expires_at)
         SELECT $1, a.id, now() + interval '14 days'
         FROM accounts a WHERE a.name_folded = $2",
    )
    .bind(token_hash(&token))
    .bind(&folded)
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    if inserted.rows_affected() == 0 {
        return Err(DbError::BadCredentials);
    }
    Ok(token)
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
    .execute(pool)
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

/// Revoke one credential owned by `account`. Returns whether a row was
/// deleted (false = not found / not owned).
pub async fn revoke_credential(pool: &PgPool, account: &str, id: i64) -> Result<bool, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let result = sqlx::query(
        "DELETE FROM account_credentials c
         USING accounts a
         WHERE c.account_id = a.id AND a.name_folded = $1 AND c.id = $2",
    )
    .bind(&folded)
    .bind(id)
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(result.rows_affected() > 0)
}
