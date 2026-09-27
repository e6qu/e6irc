//! One serving process per database (DESIGN §18).
//!
//! The process that serves a database — its core, its bouncer drivers, its
//! database worker and maintenance, its listeners — holds the one row of
//! `serving_lease` (migration 0098) and renews it every [`RENEW_INTERVAL`].
//! Another process started against the same database finds the lease held and
//! stands by; it takes the lease when the holder releases it (the last step of
//! a graceful shutdown) or when the holder's last renewal is older than
//! [`LEASE_TTL`] (a crash). Every lease comparison is PostgreSQL's `now()`, so
//! host clocks never have to agree.
//!
//! The holder fences itself: when no renewal has been confirmed for
//! [`FENCE_AFTER`] — less than the TTL, counted on the monotonic clock from
//! when the confirmed renewal's request started — it is fenced before anyone
//! can have taken the lease over: not ready, its database errors naming the
//! unconfirmed lease, and still serving its clients from hot state. It keeps
//! renewing: a renewal that reaches the database and finds the lease still
//! its own (the same holder and epoch) lifts the fence, and one that finds it
//! another's ends the serving (the bounded drain). What the process writes
//! meanwhile is fenced by the database: every connection of the serving pool
//! is checked against the lease as it is made
//! (`serving_lease_register_backend`), and a new holder ends every connection
//! the previous one recorded, so nothing a fenced process had in flight
//! commits after the takeover.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU8, Ordering};
use std::time::Duration;

use sqlx::Connection;
use tokio::time::Instant;

use crate::db::{AuditPrincipal, DatabaseUrl, DbError};

/// How long a lease stands after its last renewal before another process may
/// take it.
pub const LEASE_TTL: Duration = Duration::from_secs(15);
/// How often the holder renews.
pub const RENEW_INTERVAL: Duration = Duration::from_secs(3);
/// How long after its last confirmed renewal the holder is fenced (not
/// ready), until a renewal is confirmed again or finds the lease taken.
pub const FENCE_AFTER: Duration = Duration::from_secs(10);
/// How often a standby tries the lease between the holder's announcements.
pub const STANDBY_POLL: Duration = Duration::from_secs(5);
const _: () = assert!(
    RENEW_INTERVAL.as_millis() * 3 <= FENCE_AFTER.as_millis()
        && FENCE_AFTER.as_millis() < LEASE_TTL.as_millis()
        && STANDBY_POLL.as_millis() * 3 == LEASE_TTL.as_millis(),
    "several renewals fit before the fence, the fence falls before the lease expires, \
     and a standby polls three times per lease"
);

/// How long a lease statement waits for the lease row's lock before it fails
/// and is tried again at the next interval.
const LEASE_LOCK_TIMEOUT: Duration = Duration::from_secs(2);
/// A lease statement's bound; ending a previous holder's connections waits for
/// each ([`TERMINATION_WAIT`]).
const LEASE_STATEMENT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long taking the lease waits for each of the previous holder's
/// connections to end.
const TERMINATION_WAIT: Duration = Duration::from_secs(5);

/// A process's identity as a lease holder: a random UUID drawn once, when the
/// process starts serving or migrating.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HolderId(String);

impl HolderId {
    /// A fresh random (version 4) UUID.
    pub fn generate() -> Self {
        use aws_lc_rs::rand::SecureRandom;
        let mut bytes = [0u8; 16];
        aws_lc_rs::rand::SystemRandom::new()
            .fill(&mut bytes)
            .expect("system RNG for the serving-lease holder identity");
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        Self(format!(
            "{}-{}-{}-{}-{}",
            &hex[0..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..32]
        ))
    }

    /// The UUID's text, as the lease row's `holder` is bound and compared.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The lease is held by another process: who, and when it last renewed (the
/// database's time).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseHeld {
    pub label: String,
    pub renewed_at: String,
}

impl fmt::Display for LeaseHeld {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} (last renewed {})",
            self.label, self.renewed_at
        )
    }
}

/// Why the lease was not taken.
#[derive(Debug)]
pub enum AcquireRefusal {
    /// Another process holds it.
    Held(LeaseHeld),
    /// The database could not be asked, or refused the takeover.
    Database(DbError),
}

impl fmt::Display for AcquireRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Held(held) => write!(formatter, "the serving lease is held by {held}"),
            Self::Database(error) => write!(formatter, "the serving lease was not taken: {error}"),
        }
    }
}

impl From<DbError> for AcquireRefusal {
    fn from(error: DbError) -> Self {
        Self::Database(error)
    }
}

/// How a held lease ended while its holder was serving. An unconfirmed
/// renewal does not end it: the holder is fenced ([`LeaseStanding::Unconfirmed`])
/// until a renewal is confirmed, or finds the lease taken.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeaseEnd {
    /// A renewal found the lease in another holder's hands (or released by
    /// someone else): `by` is who holds it now, when that could be read.
    Taken { by: Option<LeaseHeld> },
    /// The renewal task stopped without saying why (it panicked).
    RenewalsStopped,
}

impl LeaseEnd {
    /// Why this process can no longer use the database, as its database
    /// errors say from now on ([`crate::db::DbError::NotServing`]).
    fn fence_reason(&self) -> String {
        match self {
            Self::Taken { by: Some(held) } => format!("held by {held}"),
            Self::Taken { by: None } => "taken over by another process".to_owned(),
            Self::RenewalsStopped => "its renewals stopped".to_owned(),
        }
    }
}

impl fmt::Display for LeaseEnd {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Taken { by: Some(held) } => write!(
                formatter,
                "the serving lease was taken over by {held}; this process no longer serves the \
                 database"
            ),
            Self::Taken { by: None } => write!(
                formatter,
                "the serving lease is no longer this process's; it no longer serves the database"
            ),
            Self::RenewalsStopped => {
                write!(
                    formatter,
                    "the serving-lease renewal task stopped unexpectedly"
                )
            }
        }
    }
}

/// Where a lease this process took stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LeaseStanding {
    /// Held, with a renewal confirmed within [`FENCE_AFTER`].
    Held,
    /// No renewal confirmed for [`FENCE_AFTER`]: the process is not ready and
    /// serves its clients from hot state until one is, or a renewal finds the
    /// lease taken.
    Unconfirmed,
    /// Released, or taken over: this process no longer holds it.
    Ended,
}

impl LeaseStanding {
    const fn code(self) -> u8 {
        match self {
            Self::Held => 0,
            Self::Unconfirmed => 1,
            Self::Ended => 2,
        }
    }

    const fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Held,
            1 => Self::Unconfirmed,
            _ => Self::Ended,
        }
    }

    /// As `/readyz` names it.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::Unconfirmed => "unconfirmed",
            Self::Ended => "ended",
        }
    }
}

/// Where the lease stands and at which epoch, as `/readyz` and the telemetry
/// report it (`e6irc_serving_lease_held` is 1 only while [`LeaseStanding::Held`],
/// `e6irc_serving_lease_epoch`).
#[derive(Debug)]
pub(crate) struct LeaseStatus {
    standing: AtomicU8,
    epoch: AtomicI64,
}

impl LeaseStatus {
    fn new(standing: LeaseStanding, epoch: i64) -> Self {
        Self {
            standing: AtomicU8::new(standing.code()),
            epoch: AtomicI64::new(epoch),
        }
    }

    pub(crate) fn standing(&self) -> LeaseStanding {
        LeaseStanding::from_code(self.standing.load(Ordering::Relaxed))
    }

    fn set(&self, standing: LeaseStanding) {
        self.standing.store(standing.code(), Ordering::Relaxed);
    }

    pub(crate) fn held(&self) -> bool {
        self.standing() == LeaseStanding::Held
    }

    pub(crate) fn epoch(&self) -> i64 {
        self.epoch.load(Ordering::Relaxed)
    }

    /// A lease held at `epoch`, as the telemetry tests observe one.
    #[cfg(test)]
    pub(crate) fn held_at(epoch: i64) -> Arc<Self> {
        Arc::new(Self::new(LeaseStanding::Held, epoch))
    }

    /// The lease is no longer held.
    #[cfg(test)]
    pub(crate) fn lose(&self) {
        self.set(LeaseStanding::Ended);
    }
}

/// The lease, held. Renewed by a task of its own until it is released or
/// ends. Dropping the handle detaches that task, as dropping a server's
/// shutdown handle leaves the server running: only [`ServingLease::release`]
/// gives the lease up.
pub struct ServingLease {
    url: DatabaseUrl,
    holder: HolderId,
    epoch: i64,
    label: String,
    status: Arc<LeaseStatus>,
    renewals: tokio::task::JoinHandle<()>,
    ended: tokio::sync::watch::Receiver<Option<LeaseEnd>>,
}

/// Waits for a held lease to end; see [`ServingLease::end_watch`].
pub(crate) struct LeaseEndWatch(tokio::sync::watch::Receiver<Option<LeaseEnd>>);

impl LeaseEndWatch {
    /// How the lease ended, once it has.
    pub(crate) async fn ended(mut self) -> LeaseEnd {
        loop {
            if let Some(end) = self.0.borrow_and_update().clone() {
                return end;
            }
            if self.0.changed().await.is_err() {
                // The renewal task ended without recording why: a panic.
                return self.0.borrow().clone().unwrap_or(LeaseEnd::RenewalsStopped);
            }
        }
    }
}

impl ServingLease {
    pub fn holder(&self) -> &HolderId {
        &self.holder
    }

    pub fn epoch(&self) -> i64 {
        self.epoch
    }

    /// Who holds it, as the lease row names this process.
    pub fn label(&self) -> &str {
        &self.label
    }

    pub(crate) fn status(&self) -> Arc<LeaseStatus> {
        self.status.clone()
    }

    /// Resolves when the lease ends while held: taken over. An unconfirmed
    /// renewal fences the process but does not end the lease.
    pub(crate) fn end_watch(&self) -> LeaseEndWatch {
        LeaseEndWatch(self.ended.clone())
    }

    /// Stop renewing and give the lease up, within `within`, announcing the
    /// release to a standby. `Ok(false)`: it was no longer this process's to
    /// give (taken over). The holder's fence is forgotten with the lease.
    pub async fn release(mut self, within: Duration) -> Result<bool, DbError> {
        self.renewals.abort();
        if let Err(error) = (&mut self.renewals).await
            && !error.is_cancelled()
        {
            eprintln!("e6ircd: the serving-lease renewal task failed: {error}");
        }
        self.status.set(LeaseStanding::Ended);
        crate::db::set_lease_fence(&self.holder, None);
        let released =
            tokio::time::timeout(within, release_row(&self.url, &self.holder, self.epoch))
                .await
                .map_err(|_| {
                    DbError::Connect(sqlx::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("no answer within {}s", within.as_secs()),
                    )))
                })??;
        Ok(released)
    }
}

/// A connection of the lease's own: not the pool's (which the lease fences),
/// and bounded so a held row lock or a wedged server fails a statement rather
/// than parking it.
async fn lease_connection(url: &DatabaseUrl) -> Result<sqlx::PgConnection, DbError> {
    let mut connection = crate::db::connect_directly(url).await?;
    for (setting, value) in [
        ("lock_timeout", LEASE_LOCK_TIMEOUT),
        ("statement_timeout", LEASE_STATEMENT_TIMEOUT),
    ] {
        sqlx::query("SELECT set_config($1, $2, false)")
            .bind(setting)
            .bind(value.as_millis().to_string())
            .execute(&mut connection)
            .await
            .map_err(DbError::Connect)?;
    }
    Ok(connection)
}

/// Who holds the lease now, or `None` when nobody does (or it has expired).
pub async fn current_holder(url: &DatabaseUrl) -> Result<Option<LeaseHeld>, DbError> {
    let mut connection = lease_connection(url).await?;
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT holder_label, renewed_at::text FROM serving_lease
         WHERE id = 1 AND holder IS NOT NULL
           AND renewed_at + ttl_ms * interval '1 millisecond' >= now()",
    )
    .fetch_optional(&mut connection)
    .await
    .map_err(crate::db::query_error)?;
    Ok(row.map(|(label, renewed_at)| LeaseHeld { label, renewed_at }))
}

/// Take the lease for `holder` if nobody holds it or its holder's last renewal
/// is older than its TTL, and renew it from then on. `purpose` completes the
/// label an operator reads (who, from where, running what). Taking it ends
/// every connection a previous holder recorded, and is audited.
pub async fn acquire(
    url: &DatabaseUrl,
    holder: &HolderId,
    purpose: &str,
) -> Result<ServingLease, AcquireRefusal> {
    let started = Instant::now();
    let mut connection = lease_connection(url).await?;
    let mut transaction = connection.begin().await.map_err(crate::db::query_error)?;
    let (previous_label, renewed_at, free): (Option<String>, Option<String>, bool) =
        sqlx::query_as(
            "SELECT holder_label, renewed_at::text,
                    holder IS NULL OR renewed_at + ttl_ms * interval '1 millisecond' < now()
             FROM serving_lease WHERE id = 1 FOR UPDATE",
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(crate::db::query_error)?;
    if !free {
        return Err(AcquireRefusal::Held(LeaseHeld {
            label: previous_label.unwrap_or_default(),
            renewed_at: renewed_at.unwrap_or_default(),
        }));
    }
    let label: String = sqlx::query_scalar(
        "SELECT format('%s pid %s, %s',
                       COALESCE(host(inet_client_addr()), 'a local socket'), $1::int, $2::text)",
    )
    .bind(i32::try_from(std::process::id()).unwrap_or(i32::MAX))
    .bind(purpose)
    .fetch_one(&mut *transaction)
    .await
    .map_err(crate::db::query_error)?;
    let epoch: i64 = sqlx::query_scalar(
        "UPDATE serving_lease
         SET holder = $1::uuid, holder_label = $2, epoch = epoch + 1,
             acquired_at = now(), renewed_at = now(), ttl_ms = $3
         WHERE id = 1 RETURNING epoch",
    )
    .bind(holder.as_str())
    .bind(&label)
    .bind(i32::try_from(LEASE_TTL.as_millis()).expect("the lease TTL fits a PostgreSQL integer"))
    .fetch_one(&mut *transaction)
    .await
    .map_err(crate::db::query_error)?;
    // End every connection the previous holders opened, before this takeover
    // commits: nothing they had in flight can commit after it. A connection
    // is named by process id and start time together, since a process id is
    // reused. One PostgreSQL does not show this role (another role's session)
    // cannot be matched, and is said.
    let (hidden, survived): (i64, i64) = sqlx::query_as(
        "WITH previous AS (
             SELECT a.pid IS NOT NULL AND a.backend_start IS NULL AS hidden,
                    CASE WHEN a.backend_start = b.backend_start
                         THEN pg_terminate_backend(b.pid, $2) END AS ended
             FROM serving_lease_backends b
             LEFT JOIN pg_stat_activity a ON a.pid = b.pid
             WHERE b.holder <> $1::uuid
         )
         SELECT count(*) FILTER (WHERE hidden), count(*) FILTER (WHERE ended IS FALSE)
         FROM previous",
    )
    .bind(holder.as_str())
    .bind(i64::try_from(TERMINATION_WAIT.as_millis()).expect("the wait fits a bigint"))
    .fetch_one(&mut *transaction)
    .await
    .map_err(crate::db::query_error)?;
    if survived > 0 {
        return Err(AcquireRefusal::Database(DbError::PreviousHolderLingers(
            survived,
        )));
    }
    if hidden > 0 {
        eprintln!(
            "e6ircd: serving lease: {hidden} connection(s) recorded for a previous holder belong \
             to a session this database role cannot see; if the processes serving this database \
             connect as different roles, a previous holder's open connections cannot be ended — \
             connect every process as the same role"
        );
    }
    sqlx::query("DELETE FROM serving_lease_backends WHERE holder <> $1::uuid")
        .bind(holder.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(crate::db::query_error)?;
    let previous = match (&previous_label, &renewed_at) {
        (Some(label), Some(renewed)) => format!("{label} (lease expired; last renewed {renewed})"),
        _ => "nobody (released)".to_owned(),
    };
    crate::db::insert_audit_log_with(
        &mut *transaction,
        &AuditPrincipal::host("serving lease"),
        "SERVING_LEASE_ACQUIRE",
        &AuditPrincipal::server(),
        &format!("epoch {epoch}: {label}; previously {previous}"),
    )
    .await?;
    transaction.commit().await.map_err(crate::db::query_error)?;
    let status = Arc::new(LeaseStatus::new(LeaseStanding::Held, epoch));
    let (ended_tx, ended) = tokio::sync::watch::channel(None);
    let renewals = tokio::spawn(renew(Renewal {
        url: url.clone(),
        holder: holder.clone(),
        epoch,
        confirmed: started,
        connection: Some(connection),
        status: status.clone(),
        ended: ended_tx,
    }));
    Ok(ServingLease {
        url: url.clone(),
        holder: holder.clone(),
        epoch,
        label,
        status,
        renewals,
        ended,
    })
}

struct Renewal {
    url: DatabaseUrl,
    holder: HolderId,
    epoch: i64,
    /// When the last confirmed renewal's request started.
    confirmed: Instant,
    connection: Option<sqlx::PgConnection>,
    status: Arc<LeaseStatus>,
    ended: tokio::sync::watch::Sender<Option<LeaseEnd>>,
}

/// Renew every [`RENEW_INTERVAL`] until a renewal finds the lease no longer
/// this holder's. A renewal counts from when its request started. When none
/// has been confirmed for [`FENCE_AFTER`] the holder is fenced — its database
/// errors say so ([`crate::db::set_lease_fence`]), and so does its status —
/// and it keeps trying; a confirmed renewal lifts the fence. No request
/// outlives the fence, or, once fenced, [`FENCE_AFTER`] of its own.
async fn renew(mut renewal: Renewal) {
    let mut next = renewal.confirmed + RENEW_INTERVAL;
    let mut unconfirmed = false;
    let end = loop {
        let fence_at = renewal.confirmed + FENCE_AFTER;
        tokio::time::sleep_until(if unconfirmed {
            next
        } else {
            next.min(fence_at)
        })
        .await;
        if !unconfirmed && Instant::now() >= fence_at {
            unconfirmed = true;
            renewal.fence();
        }
        let started = Instant::now();
        next = started + RENEW_INTERVAL;
        let deadline = if unconfirmed {
            started + FENCE_AFTER
        } else {
            fence_at
        };
        match tokio::time::timeout_at(deadline, renew_once(&mut renewal)).await {
            Ok(Ok(true)) => {
                renewal.confirmed = started;
                if unconfirmed {
                    unconfirmed = false;
                    renewal.resume();
                }
            }
            Ok(Ok(false)) => {
                break LeaseEnd::Taken {
                    by: current_holder(&renewal.url).await.ok().flatten(),
                };
            }
            Ok(Err(error)) => {
                renewal.connection = None;
                // Once fenced, the fence's own line has said it; every
                // failed attempt of an outage would repeat it.
                if !unconfirmed {
                    eprintln!(
                        "e6ircd: serving lease: a renewal failed ({error}); this process is \
                         fenced {}s after its last confirmed renewal unless one succeeds",
                        FENCE_AFTER.as_secs()
                    );
                }
            }
            Err(_deadline) => renewal.connection = None,
        }
    };
    renewal.status.set(LeaseStanding::Ended);
    crate::db::set_lease_fence(
        &renewal.holder,
        Some(crate::db::LeaseFence::Lost(end.fence_reason())),
    );
    renewal.ended.send_replace(Some(end));
}

impl Renewal {
    /// No renewal confirmed for [`FENCE_AFTER`]: not ready, clients served
    /// from hot state, and said.
    fn fence(&self) {
        crate::db::set_lease_fence(
            &self.holder,
            Some(crate::db::LeaseFence::Unconfirmed {
                since: self.confirmed,
            }),
        );
        self.status.set(LeaseStanding::Unconfirmed);
        eprintln!(
            "e6ircd: serving lease: no renewal was confirmed for {}s; this process is not \
             ready, keeps its clients and keeps renewing: it resumes if the lease is still its \
             own when the database answers, and stops serving if another process has taken it",
            FENCE_AFTER.as_secs()
        );
    }

    /// A renewal confirmed the lease still this holder's (epoch unchanged):
    /// ready again. What was announced while fenced is read again by each
    /// follower as its listener reconnects.
    fn resume(&self) {
        self.status.set(LeaseStanding::Held);
        crate::db::set_lease_fence(&self.holder, None);
        eprintln!(
            "e6ircd: serving lease: a renewal was confirmed again (epoch {}); this process \
             serves as the holder again",
            self.epoch
        );
    }
}

async fn renew_once(renewal: &mut Renewal) -> Result<bool, DbError> {
    let connection = match &mut renewal.connection {
        Some(connection) => connection,
        None => renewal
            .connection
            .insert(lease_connection(&renewal.url).await?),
    };
    let renewed = sqlx::query(
        "UPDATE serving_lease SET renewed_at = now()
         WHERE id = 1 AND holder = $1::uuid AND epoch = $2",
    )
    .bind(renewal.holder.as_str())
    .bind(renewal.epoch)
    .execute(connection)
    .await
    .map_err(crate::db::query_error)?
    .rows_affected();
    Ok(renewed == 1)
}

/// Give the lease up if `holder` still holds `epoch` of it; the trigger
/// announces it. Whether it was still held.
async fn release_row(url: &DatabaseUrl, holder: &HolderId, epoch: i64) -> Result<bool, DbError> {
    let mut connection = lease_connection(url).await?;
    let released = sqlx::query(
        "UPDATE serving_lease SET holder = NULL, holder_label = NULL
         WHERE id = 1 AND holder = $1::uuid AND epoch = $2",
    )
    .bind(holder.as_str())
    .bind(epoch)
    .execute(&mut connection)
    .await
    .map_err(crate::db::query_error)?
    .rows_affected();
    Ok(released == 1)
}

/// The label a process of this binary gives itself when it takes the lease to
/// serve; a command-line migration names itself instead.
pub(crate) fn serving_purpose() -> String {
    format!(
        "e6ircd {} (revision {})",
        env!("CARGO_PKG_VERSION"),
        crate::BUILD_REVISION
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_holder_identity_is_a_version_four_uuid() {
        let id = HolderId::generate();
        let text = id.as_str();
        let groups: Vec<&str> = text.split('-').collect();
        assert_eq!(
            groups.iter().map(|group| group.len()).collect::<Vec<_>>(),
            [8, 4, 4, 4, 12],
            "{text}"
        );
        assert!(text.bytes().all(|b| b == b'-' || b.is_ascii_hexdigit()));
        assert_eq!(&groups[2][..1], "4", "{text}");
        assert!(matches!(&groups[3][..1], "8" | "9" | "a" | "b"), "{text}");
        assert_ne!(HolderId::generate(), id);
    }

    #[test]
    fn a_lease_end_says_what_happened() {
        let taken = LeaseEnd::Taken {
            by: Some(LeaseHeld {
                label: "10.0.0.2 pid 7, e6ircd".into(),
                renewed_at: "now".into(),
            }),
        };
        assert!(taken.to_string().contains("10.0.0.2 pid 7"), "{taken}");
    }
}
