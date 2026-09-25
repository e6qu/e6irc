//! Database worker: owns the PostgreSQL pool. Consumes [`DbRequest`]s
//! from its queue and answers by pushing [`Input::DbReply`] into the
//! core queue — the core never touches the database directly.

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use e6irc_proto::casemap::CaseMapping;
use sqlx::PgPool;
use sqlx::Row;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use crate::core::{DbReply, DbRequest, Input};
use crate::observability::Telemetry;
use e6irc_queue::Receiver;

mod credential_change;
mod secret_rotation;
pub use credential_change::{
    CredentialChange, CredentialChangeListener, RevocableCredential, credential_remaining,
};
pub use secret_rotation::{SecretRotationReport, rotate_database_secrets};

/// Migrations are compiled into the binary; startup refuses to run on
/// checksum drift (sqlx's default) rather than guessing.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

const DATABASE_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(2);
const DATABASE_STATEMENT_TIMEOUT_MS: i64 = 15_000;
const DATABASE_LOCK_TIMEOUT_MS: i64 = 5_000;
const ACCOUNT_FLAG_ADMIN: i64 = 1;
const ACCOUNT_FLAG_SUSPENDED: i64 = 2;
/// The largest millisecond value that a PostgreSQL `double precision`
/// seconds binding can represent without losing a millisecond.
const MAX_DATABASE_MILLIS: u64 = 1 << 53;

#[derive(Debug)]
pub enum DbError {
    Connect(sqlx::Error),
    /// Startup kept retrying the initial connection for its whole wait and
    /// PostgreSQL never accepted one; `last` is the final attempt's error.
    StartupWaitExhausted {
        attempts: u32,
        waited: std::time::Duration,
        last: Box<DbError>,
    },
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
    /// A database-wide secret re-seal could not prove every value readable.
    SecretRotation(String),
    /// Persisted token scopes are outside the closed authorization model.
    InvalidApiTokenScopes(String),
    /// A persisted or outbound timestamp cannot preserve its epoch-millisecond value.
    InvalidDatabaseTimestamp(String),
    /// A console write was based on an older settings revision.
    StaleServerSettings,
    /// Unknown account or wrong password (indistinguishable on purpose).
    BadCredentials,
    /// The account name has used every password attempt its window allows;
    /// nothing was verified. Retry after the given interval.
    LoginThrottled(LoginRetryAfter),
    /// An authenticated caller tried to create a primary password where one
    /// already exists and therefore must be rotated with the current password.
    LocalPasswordExists,
    /// A write resolved to no account row for the given name.
    UnknownAccount(String),
    ReplayedLogoutToken,
    /// The account already holds the maximum number of app passwords / PATs.
    TooManyCredentials,
    /// The account already holds the maximum number of BNC networks.
    TooManyNetworks,
    /// Browser bootstrap is permanently closed once any account exists.
    AlreadyInitialized,
    /// An administrator attempted to suspend the account authenticating the
    /// request.
    CannotSuspendSelf,
    /// Host-side administrator recovery named a suspended account. Recovery
    /// does not undo a suspension as a side effect; the operator names another.
    RecoveryOfSuspendedAccount(String),
    /// An administrator attempted to remove its own durable authority.
    CannotDemoteSelf,
    /// At least one active effective durable-or-configured administrator must remain.
    LastAdministrator,
    /// An account must transfer every founded channel that has no successor
    /// before deletion.
    AccountOwnsChannels(usize),
    /// Passing these channels (folded names) to their successors would take a
    /// successor past [`CHANNEL_FOUNDER_LIMIT`]; nothing was deleted.
    SuccessorChannelLimit(Vec<String>),
    /// An administrator already holds the maximum number of live invitations.
    TooManyInvitations,
    /// A bearer invitation is unknown, expired, revoked, or already consumed —
    /// or grants administrator authority its issuer no longer holds.
    InvitationUnavailable,
    /// A stored network named by owner and name has no row: its backlog has
    /// nothing to belong to.
    UnknownNetwork(String),
    /// One or more storage-maintenance collections failed; the others
    /// committed their batches (`completed`).
    MaintenanceFailed {
        completed: Box<StorageMaintenanceReport>,
        failures: Vec<MaintenanceFailure>,
    },
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "database connect failed: {e}"),
            Self::StartupWaitExhausted {
                attempts,
                waited,
                last,
            } => write!(
                f,
                "database did not accept a connection in {attempts} attempts over {}s; last \
                 error: {last}",
                waited.as_secs()
            ),
            Self::Migrate(e) => write!(f, "database migration failed: {e}"),
            Self::Query(e) => write!(f, "database query failed: {e}"),
            Self::Hash(e) => write!(f, "password hash operation failed: {e}"),
            Self::DuplicateAccount(n) => write!(f, "account already exists: {n}"),
            Self::DuplicateNetwork(n) => write!(f, "network already exists: {n}"),
            Self::InvalidNetworkKind(kind) => {
                write!(f, "invalid persisted BNC network kind: {kind}")
            }
            Self::InvalidServerSettings(error) => {
                write!(f, "invalid persisted server settings: {error}")
            }
            Self::SecretRotation(error) => write!(f, "secret rotation failed: {error}"),
            Self::InvalidApiTokenScopes(error) => {
                write!(f, "invalid persisted personal access token scopes: {error}")
            }
            Self::InvalidDatabaseTimestamp(error) => {
                write!(f, "invalid database timestamp: {error}")
            }
            Self::StaleServerSettings => write!(f, "server settings changed concurrently"),
            Self::BadCredentials => write!(f, "invalid account or password"),
            Self::LoginThrottled(retry) => write!(
                f,
                "too many password attempts for this account; retry in {}s",
                retry.seconds()
            ),
            Self::LocalPasswordExists => write!(f, "account already has a primary password"),
            Self::UnknownAccount(n) => write!(f, "no such account: {n}"),
            Self::ReplayedLogoutToken => write!(f, "OpenID Connect logout token was replayed"),
            Self::TooManyCredentials => write!(f, "account holds too many app passwords"),
            Self::TooManyNetworks => write!(f, "account holds too many networks"),
            Self::AlreadyInitialized => write!(f, "server account bootstrap is already complete"),
            Self::CannotSuspendSelf => write!(f, "an administrator cannot suspend itself"),
            Self::RecoveryOfSuspendedAccount(n) => write!(
                f,
                "account {n} is suspended; recovery does not lift a suspension — name an active account"
            ),
            Self::CannotDemoteSelf => {
                write!(f, "an administrator cannot remove its own authority")
            }
            Self::LastAdministrator => {
                write!(f, "at least one active administrator must remain")
            }
            Self::AccountOwnsChannels(count) => {
                write!(
                    f,
                    "account still founds {count} channel(s) with no successor; transfer them, \
                     name a successor, or unregister them first"
                )
            }
            Self::SuccessorChannelLimit(channels) => write!(
                f,
                "the successor of {} already founds the maximum of {CHANNEL_FOUNDER_LIMIT} \
                 channels; name another successor, transfer, or unregister {} first",
                channels.join(", "),
                if channels.len() == 1 { "it" } else { "them" }
            ),
            Self::TooManyInvitations => {
                write!(
                    f,
                    "administrator holds too many pending account invitations"
                )
            }
            Self::InvitationUnavailable => {
                write!(f, "account invitation is unavailable")
            }
            Self::UnknownNetwork(network) => write!(f, "no such stored network: {network}"),
            Self::MaintenanceFailed {
                completed: _,
                failures,
            } => {
                write!(f, "storage maintenance failed for")?;
                for (index, failure) in failures.iter().enumerate() {
                    let separator = if index == 0 { " " } else { "; " };
                    write!(
                        f,
                        "{separator}{} ({})",
                        failure.collection.table(),
                        failure.error
                    )?;
                }
                write!(f, "; every other collection committed its batch")
            }
        }
    }
}

impl std::error::Error for DbError {}

/// Acquires from the shared pool that waited the whole acquire timeout for a
/// connection and gave up — the pool was exhausted for that long. Read by
/// telemetry as `e6irc_database_pool_acquire_timeouts_total`.
static POOL_ACQUIRE_TIMEOUTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Every query failure in this module passes through here on its way into a
/// [`DbError`], so an exhausted pool is counted wherever it is met.
fn query_error(error: sqlx::Error) -> DbError {
    if matches!(error, sqlx::Error::PoolTimedOut) {
        POOL_ACQUIRE_TIMEOUTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    DbError::Query(error)
}

pub(crate) fn pool_acquire_timeouts() -> u64 {
    POOL_ACQUIRE_TIMEOUTS.load(std::sync::atomic::Ordering::Relaxed)
}

fn millis_from_database(value: i64, column: &str) -> Result<e6irc_proto::time::Millis, DbError> {
    let value = u64::try_from(value).map_err(|_| {
        DbError::InvalidDatabaseTimestamp(format!("{column} is before the Unix epoch: {value}"))
    })?;
    if value > MAX_DATABASE_MILLIS {
        return Err(DbError::InvalidDatabaseTimestamp(format!(
            "{column} exceeds exact millisecond range: {value}"
        )));
    }
    Ok(e6irc_proto::time::Millis::from_millis(value))
}

fn millis_for_database(value: e6irc_proto::time::Millis, column: &str) -> Result<i64, DbError> {
    let value = value.as_millis();
    if value > MAX_DATABASE_MILLIS {
        return Err(DbError::InvalidDatabaseTimestamp(format!(
            "{column} exceeds exact millisecond range: {value}"
        )));
    }
    Ok(value as i64)
}

fn seconds_for_database(value: u64, column: &str) -> Result<f64, DbError> {
    let millis = value.checked_mul(1000).ok_or_else(|| {
        DbError::InvalidDatabaseTimestamp(format!("{column} overflows milliseconds: {value}"))
    })?;
    Ok(
        millis_for_database(e6irc_proto::time::Millis::from_millis(millis), column)? as f64
            / 1000.0,
    )
}

/// How long a pooled session may sit inside an open transaction without
/// sending anything before PostgreSQL ends it. A transaction left open by a
/// stalled task holds its row locks and pins the xmin horizon (so vacuum
/// cannot reclaim anything newer); this bounds both instead of leaving them to
/// whoever notices.
const DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS: i64 = 60_000;

/// How long one migration statement may wait for a lock (the migrator's own
/// advisory lock included — another replica migrating — or a table lock held
/// by a live server) before the attempt is abandoned and retried.
const MIGRATION_LOCK_TIMEOUT: Duration = Duration::from_secs(10);
/// Attempts [`run_migrations`] makes when a migration keeps timing out on a
/// lock; the pause between two of them doubles from one second.
const MIGRATION_LOCK_ATTEMPTS: u32 = 6;

/// How many connections the shared pool may open. Constructed only through
/// [`DatabasePoolSize::new`] (the configured value, bounded) or
/// [`DatabasePoolSize::for_this_host`] (the default), so the pool can never be
/// asked for zero connections or for more than a PostgreSQL server's default
/// `max_connections` can serve alongside anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(try_from = "u32")]
pub struct DatabasePoolSize(u32);

impl DatabasePoolSize {
    pub const MIN: u32 = 2;
    pub const MAX: u32 = 200;

    pub fn new(value: u32) -> Result<Self, String> {
        if (Self::MIN..=Self::MAX).contains(&value) {
            Ok(Self(value))
        } else {
            Err(format!(
                "database.max_connections must be between {} and {} (got {value})",
                Self::MIN,
                Self::MAX
            ))
        }
    }

    /// The default, sized to what can hold a connection at once: the serial
    /// database worker (one), every Argon2 verification or hash offloaded from
    /// it ([`MAX_CONCURRENT_ARGON2`]), and two per runtime worker thread for
    /// the tasks that run on them — HTTP handlers, bouncer persistence tasks,
    /// maintenance — one running and one about to. Bounded to
    /// [`Self::MIN`]`..=`[`Self::MAX`].
    pub fn for_this_host() -> Self {
        let threads = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        Self::for_runtime_threads(threads)
    }

    fn for_runtime_threads(threads: usize) -> Self {
        let wanted = 1 + MAX_CONCURRENT_ARGON2 + threads.saturating_mul(2);
        Self(
            u32::try_from(wanted)
                .unwrap_or(Self::MAX)
                .clamp(Self::MIN, Self::MAX),
        )
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for DatabasePoolSize {
    type Error = String;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// One plain connection, bounded by [`DATABASE_ACQUIRE_TIMEOUT`]. The pool's
/// own `connect` retries inside its acquire timeout and then reports only
/// "pool timed out", which hides the reason — refused, wrong password, "the
/// database system is starting up" — that the operator (and the startup retry)
/// must see. This fails at once with that reason, and the bound keeps an
/// unroutable address from hanging startup on the operating system's connect
/// timeout.
async fn connect_directly(url: &str) -> Result<sqlx::PgConnection, DbError> {
    tokio::time::timeout(
        DATABASE_ACQUIRE_TIMEOUT,
        <sqlx::PgConnection as sqlx::Connection>::connect(url),
    )
    .await
    .map_err(|_| {
        DbError::Connect(sqlx::Error::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("no answer within {}s", DATABASE_ACQUIRE_TIMEOUT.as_secs()),
        )))
    })?
    .map_err(DbError::Connect)
}

/// Whether a migration failed because a statement waited out
/// [`MIGRATION_LOCK_TIMEOUT`] (SQLSTATE 55P03, `lock_not_available`).
fn migration_waited_on_a_lock(error: &sqlx::migrate::MigrateError) -> bool {
    let (sqlx::migrate::MigrateError::Execute(error)
    | sqlx::migrate::MigrateError::ExecuteMigration(error, _)) = error
    else {
        return false;
    };
    error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| code == "55P03")
}

/// Apply `migrator` on a connection of its own.
///
/// Not a pooled connection: the pool's 15-second statement timeout is right for
/// a request and wrong for a migration, which may rewrite or index a table
/// that has grown for months — a deployment that large would crash-loop on
/// every upgrade. Here there is no statement timeout, and a bounded lock
/// timeout instead: a migration stuck behind a lock (another replica
/// migrating, a long transaction on a live server) gives up after
/// [`MIGRATION_LOCK_TIMEOUT`], says so on stderr, and is retried on a fresh
/// connection with a doubling pause, [`MIGRATION_LOCK_ATTEMPTS`] times in all.
/// Every other migration failure is a fact about the schema and is returned at
/// once.
pub async fn run_migrations(url: &str, migrator: &sqlx::migrate::Migrator) -> Result<(), DbError> {
    let mut pause = Duration::from_secs(1);
    for attempt in 1..=MIGRATION_LOCK_ATTEMPTS {
        let mut connection = connect_directly(url).await?;
        sqlx::query("SET statement_timeout = 0")
            .execute(&mut connection)
            .await
            .map_err(DbError::Connect)?;
        sqlx::query("SELECT set_config('lock_timeout', $1, false)")
            .bind(MIGRATION_LOCK_TIMEOUT.as_millis().to_string())
            .execute(&mut connection)
            .await
            .map_err(DbError::Connect)?;
        let outcome = migrator.run(&mut connection).await;
        // Closing ends the session, which releases the migrator's advisory
        // lock whatever state a failed attempt left it in.
        <sqlx::PgConnection as sqlx::Connection>::close(connection)
            .await
            .map_err(DbError::Connect)?;
        match outcome {
            Ok(()) => return Ok(()),
            Err(error)
                if migration_waited_on_a_lock(&error) && attempt < MIGRATION_LOCK_ATTEMPTS =>
            {
                eprintln!(
                    "db: migration attempt {attempt} of {MIGRATION_LOCK_ATTEMPTS} waited more \
                     than {}s for a lock ({error}); retrying in {}s",
                    MIGRATION_LOCK_TIMEOUT.as_secs(),
                    pause.as_secs()
                );
                tokio::time::sleep(pause).await;
                pause *= 2;
            }
            Err(error) => return Err(DbError::Migrate(error)),
        }
    }
    unreachable!("the final attempt returns its outcome")
}

/// Migrate, then open a pool of the default size — for a one-shot command
/// (`recover-administrator`, secret rotation), which opens connections only as
/// it uses them. The daemon opens its pool through
/// [`connect_and_migrate_with_retry`], at its configured size.
pub async fn connect_and_migrate(url: &str) -> Result<PgPool, DbError> {
    connect_and_migrate_sized(url, DatabasePoolSize::for_this_host()).await
}

async fn connect_and_migrate_sized(url: &str, size: DatabasePoolSize) -> Result<PgPool, DbError> {
    run_migrations(url, &MIGRATOR).await?;
    // Every caller shares this pool, including HTTP handlers and the database
    // worker. A dependency interruption must therefore produce a bounded,
    // typed query failure instead of parking unrelated requests on SQLx's
    // longer default acquisition timeout.
    PgPoolOptions::new()
        .max_connections(size.get())
        .acquire_timeout(DATABASE_ACQUIRE_TIMEOUT)
        .after_connect(|connection, _metadata| {
            Box::pin(async move {
                for (setting, value) in [
                    ("statement_timeout", DATABASE_STATEMENT_TIMEOUT_MS),
                    ("lock_timeout", DATABASE_LOCK_TIMEOUT_MS),
                    (
                        "idle_in_transaction_session_timeout",
                        DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS,
                    ),
                ] {
                    sqlx::query("SELECT set_config($1, $2, false)")
                        .bind(setting)
                        .bind(value.to_string())
                        .execute(&mut *connection)
                        .await?;
                }
                Ok(())
            })
        })
        .connect(url)
        .await
        .map_err(DbError::Connect)
}

/// How long startup keeps retrying the first database connection before the
/// process gives up and exits non-zero. Constructed only through
/// [`StartupDatabaseWait::from_seconds`], so the bound the configuration
/// documents ([`StartupDatabaseWait::MAX_SECONDS`]) cannot be exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartupDatabaseWait(std::time::Duration);

impl StartupDatabaseWait {
    /// One hour: past that a supervisor's own restart policy is the right tool.
    pub const MAX_SECONDS: u64 = 3_600;
    /// The longest pause between two attempts; the backoff doubles up to it.
    const MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(30);
    const FIRST_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1);

    /// `0` means a single attempt and no waiting.
    pub fn from_seconds(seconds: u64) -> Result<Self, String> {
        if seconds > Self::MAX_SECONDS {
            return Err(format!(
                "database.startup_wait_seconds must be at most {} (got {seconds})",
                Self::MAX_SECONDS
            ));
        }
        Ok(Self(std::time::Duration::from_secs(seconds)))
    }

    pub const fn duration(self) -> std::time::Duration {
        self.0
    }
}

/// One failed startup connection attempt, handed to the caller's reporter so
/// every attempt is a visible line wherever the process logs.
#[derive(Debug)]
pub struct StartupDatabaseAttempt<'a> {
    /// 1-based.
    pub attempt: u32,
    pub error: &'a DbError,
    /// Time already spent waiting, including this attempt.
    pub waited: std::time::Duration,
    /// The pause before the next attempt; `None` means this was the last one.
    pub retry_in: Option<std::time::Duration>,
}

/// [`connect_and_migrate`] for process startup: a refused or not-yet-listening
/// PostgreSQL (a container that starts a few seconds after this one, a
/// restarting server) is retried with a doubling, capped backoff until `wait`
/// is spent, and every failed attempt is reported. Only connection failures
/// are retried: a migration failure is a fact about the schema that waiting
/// cannot change, and is returned at once.
pub async fn connect_and_migrate_with_retry(
    url: &str,
    wait: StartupDatabaseWait,
    size: DatabasePoolSize,
    mut report: impl FnMut(StartupDatabaseAttempt<'_>),
) -> Result<PgPool, DbError> {
    let started = std::time::Instant::now();
    let mut backoff = StartupDatabaseWait::FIRST_BACKOFF;
    let mut attempts: u32 = 0;
    loop {
        attempts = attempts.saturating_add(1);
        let error = match connect_and_migrate_sized(url, size).await {
            Ok(pool) => return Ok(pool),
            Err(error @ DbError::Connect(_)) => error,
            Err(error) => return Err(error),
        };
        let waited = started.elapsed();
        let retry_in = wait
            .duration()
            .checked_sub(waited)
            .filter(|remaining| !remaining.is_zero())
            .map(|remaining| backoff.min(remaining));
        report(StartupDatabaseAttempt {
            attempt: attempts,
            error: &error,
            waited,
            retry_in,
        });
        let Some(pause) = retry_in else {
            return Err(DbError::StartupWaitExhausted {
                attempts,
                waited,
                last: Box::new(error),
            });
        };
        tokio::time::sleep(pause).await;
        backoff = (backoff * 2).min(StartupDatabaseWait::MAX_BACKOFF);
    }
}

const STORAGE_MAINTENANCE_BATCH: u64 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StorageMaintenanceReport {
    pub messages: u64,
    /// Bouncer history (`bnc_buffer`, every network's external lines, direct
    /// messages included) under the same history retention as `messages`.
    pub bnc_buffer: u64,
    pub audit_events: u64,
    pub web_sessions: u64,
    pub api_tokens: u64,
    pub device_grants: u64,
    pub logout_tokens: u64,
    pub account_invitations: u64,
    /// Historical monitoring samples past `observability.retention_hours`,
    /// pruned here whether or not sampling is currently on.
    pub observability_samples: u64,
    /// Read markers -- core (`read_markers`) and bouncer (`bnc_read_markers`)
    /// together -- that point older than the history retention, where no
    /// message they could resume from is kept any more.
    pub read_markers: u64,
    /// The core's (`read_markers`) rows among them, each as deleted. Every
    /// core shard mirrors that table and counts it toward the per-account cap,
    /// so the caller hands these to the core: the database's delete is the one
    /// source of what expired.
    pub expired_read_markers: Vec<crate::core::ExpiredReadMarker>,
    /// At least one collection filled its bounded batch and may have more
    /// expired rows. [`drain_storage_maintenance`] keeps going while this is
    /// set, up to its batch budget.
    pub saturated: bool,
}

impl StorageMaintenanceReport {
    /// Destructures `other` exhaustively, so a counter added to the report
    /// fails to compile here until it is summed too.
    fn add(&mut self, other: Self) {
        let Self {
            messages,
            bnc_buffer,
            audit_events,
            web_sessions,
            api_tokens,
            device_grants,
            logout_tokens,
            account_invitations,
            observability_samples,
            read_markers,
            expired_read_markers,
            saturated,
        } = other;
        self.messages += messages;
        self.bnc_buffer += bnc_buffer;
        self.audit_events += audit_events;
        self.web_sessions += web_sessions;
        self.api_tokens += api_tokens;
        self.device_grants += device_grants;
        self.logout_tokens += logout_tokens;
        self.account_invitations += account_invitations;
        self.observability_samples += observability_samples;
        self.read_markers += read_markers;
        self.expired_read_markers.extend(expired_read_markers);
        self.saturated = saturated;
    }

    fn slot(&mut self, collection: MaintenanceCollection) -> &mut u64 {
        match collection {
            MaintenanceCollection::Messages => &mut self.messages,
            MaintenanceCollection::BncBuffer => &mut self.bnc_buffer,
            MaintenanceCollection::AuditLog => &mut self.audit_events,
            MaintenanceCollection::WebSessions => &mut self.web_sessions,
            MaintenanceCollection::ApiTokens => &mut self.api_tokens,
            MaintenanceCollection::DeviceGrants => &mut self.device_grants,
            MaintenanceCollection::LogoutTokens => &mut self.logout_tokens,
            MaintenanceCollection::AccountInvitations => &mut self.account_invitations,
            MaintenanceCollection::ObservabilitySamples => &mut self.observability_samples,
            MaintenanceCollection::ReadMarkers | MaintenanceCollection::BncReadMarkers => {
                &mut self.read_markers
            }
        }
    }
}

/// The time bounds maintenance applies, taken from the managed configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageRetention {
    /// `messages` and `bnc_buffer` rows older than this are deleted.
    pub history_days: u64,
    pub audit_days: u64,
    /// `observability_samples` older than this are deleted.
    pub observability_hours: u64,
}

/// How far one maintenance tick may go when a batch fills: `batches` in total
/// (the first included), `pause` between two of them so a large backlog is
/// drained in bounded steps rather than one long lock-holding sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaintenanceDrainPlan {
    pub batches: std::num::NonZeroUsize,
    pub pause: std::time::Duration,
}

/// What one tick of [`drain_storage_maintenance`] did in total.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageMaintenanceDrain {
    /// Rows deleted across every batch; `saturated` is the last batch's.
    pub totals: StorageMaintenanceReport,
    pub batches_run: usize,
}

/// The per-statement retention bound, bound before the batch limit.
#[derive(Debug, Clone, Copy)]
enum RetentionBound {
    Days(i32),
    Seconds(i32),
    Millis(i64),
    None,
}

/// One table storage maintenance keeps bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaintenanceCollection {
    Messages,
    BncBuffer,
    AuditLog,
    WebSessions,
    ApiTokens,
    DeviceGrants,
    LogoutTokens,
    AccountInvitations,
    ObservabilitySamples,
    ReadMarkers,
    BncReadMarkers,
}

impl MaintenanceCollection {
    const ALL: [Self; 11] = [
        Self::Messages,
        Self::BncBuffer,
        Self::AuditLog,
        Self::WebSessions,
        Self::ApiTokens,
        Self::DeviceGrants,
        Self::LogoutTokens,
        Self::AccountInvitations,
        Self::ObservabilitySamples,
        Self::ReadMarkers,
        Self::BncReadMarkers,
    ];

    pub fn table(self) -> &'static str {
        match self {
            Self::Messages => "messages",
            Self::BncBuffer => "bnc_buffer",
            Self::AuditLog => "audit_log",
            Self::WebSessions => "web_sessions",
            Self::ApiTokens => "api_tokens",
            Self::DeviceGrants => "device_grants",
            Self::LogoutTokens => "oidc_logout_tokens",
            Self::AccountInvitations => "account_invitations",
            Self::ObservabilitySamples => "observability_samples",
            Self::ReadMarkers => "read_markers",
            Self::BncReadMarkers => "bnc_read_markers",
        }
    }

    /// One bounded, oldest-first batch. Each statement names the rows it
    /// deletes by primary key (`= ANY(ARRAY(...))`): the candidate set comes
    /// from the time-ordered index, and the delete itself is a primary-key
    /// probe per row — never a hash join over the whole table, which is what
    /// `DELETE ... USING (candidates)` planned into.
    fn statement(self) -> &'static str {
        match self {
            Self::Messages => {
                "DELETE FROM messages WHERE id = ANY(ARRAY(
                     SELECT id FROM messages
                     WHERE ts < now() - make_interval(days => $1)
                     ORDER BY ts, id LIMIT $2))"
            }
            // Storage age (`created_at`), not the upstream's `sent_at`, which a
            // peer controls and may omit: the bound is on what this server
            // keeps, and the index from migration 0060 is on that column.
            Self::BncBuffer => {
                "DELETE FROM bnc_buffer WHERE id = ANY(ARRAY(
                     SELECT id FROM bnc_buffer
                     WHERE created_at < now() - make_interval(days => $1)
                     ORDER BY created_at, id LIMIT $2))"
            }
            Self::AuditLog => {
                "DELETE FROM audit_log WHERE id = ANY(ARRAY(
                     SELECT id FROM audit_log
                     WHERE created_at < now() - make_interval(days => $1)
                     ORDER BY created_at, id LIMIT $2))"
            }
            Self::WebSessions => {
                "DELETE FROM web_sessions WHERE token_hash = ANY(ARRAY(
                     SELECT token_hash FROM web_sessions
                     WHERE expires_at <= now()
                     ORDER BY expires_at LIMIT $1))"
            }
            Self::ApiTokens => {
                "DELETE FROM api_tokens WHERE token_hash = ANY(ARRAY(
                     SELECT token_hash FROM api_tokens
                     WHERE expires_at <= now()
                     ORDER BY expires_at LIMIT $1))"
            }
            // Kept past expiry for a grace period, so a late poll is still
            // answered `expired_token` (see
            // `DEVICE_GRANT_EXPIRED_RETENTION_SECONDS`).
            Self::DeviceGrants => {
                "DELETE FROM device_grants WHERE id = ANY(ARRAY(
                     SELECT id FROM device_grants
                     WHERE expires_at <= now() - make_interval(secs => $1)
                     ORDER BY expires_at, id LIMIT $2))"
            }
            // A composite key: the candidates are named by their row
            // position, which the same statement's snapshot keeps valid.
            Self::LogoutTokens => {
                "DELETE FROM oidc_logout_tokens WHERE ctid = ANY(ARRAY(
                     SELECT ctid FROM oidc_logout_tokens
                     WHERE expires_at <= now()
                     ORDER BY expires_at, issuer, jti LIMIT $1))"
            }
            Self::AccountInvitations => {
                "DELETE FROM account_invitations WHERE id = ANY(ARRAY(
                     SELECT id FROM account_invitations
                     WHERE consumed_at IS NOT NULL OR expires_at <= now()
                     ORDER BY COALESCE(consumed_at, expires_at), id LIMIT $1))"
            }
            Self::ObservabilitySamples => {
                "DELETE FROM observability_samples WHERE sampled_at_ms = ANY(ARRAY(
                     SELECT sampled_at_ms FROM observability_samples
                     WHERE sampled_at_ms < $1
                     ORDER BY sampled_at_ms LIMIT $2))"
            }
            // A marker names a position in history. Past the history
            // retention, nothing it could resume from is stored any more, so
            // the marker is a row about messages that no longer exist -- and
            // this table feeds the per-shard mirror built at boot, so its size
            // is start-up cost too. Composite keys, named by `ctid` within the
            // statement's own snapshot, as the logout-token sweep does.
            //
            // The deleted rows are returned, as `list_all_read_markers` reads
            // them, for the core's mirror.
            Self::ReadMarkers => {
                "WITH expired AS (
                     DELETE FROM read_markers WHERE ctid = ANY(ARRAY(
                         SELECT ctid FROM read_markers
                         WHERE marker_ts < now() - make_interval(days => $1)
                         ORDER BY marker_ts LIMIT $2))
                     RETURNING account_id, target, marker_ts)
                 SELECT a.name, e.target, (EXTRACT(EPOCH FROM e.marker_ts) * 1000)::bigint
                 FROM expired e JOIN accounts a ON a.id = e.account_id"
            }
            // The bouncer's markers store the same instant as ISO-8601 UTC
            // text, which sorts and compares lexically -- the ordering the
            // attach layer's own queries are built on.
            Self::BncReadMarkers => {
                r#"DELETE FROM bnc_read_markers WHERE ctid = ANY(ARRAY(
                     SELECT ctid FROM bnc_read_markers
                     WHERE timestamp < to_char(
                         (now() - make_interval(days => $1)) AT TIME ZONE 'UTC',
                         'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
                     ORDER BY timestamp LIMIT $2))"#
            }
        }
    }
}

/// A collection whose batch failed during one [`run_storage_maintenance`].
#[derive(Debug)]
pub struct MaintenanceFailure {
    pub collection: MaintenanceCollection,
    pub error: Box<DbError>,
}

/// Run [`run_storage_maintenance`] until a batch comes back unsaturated or
/// the plan's batch budget is spent. A saturated single batch every five
/// minutes could never catch up with a large backlog (a retention lowered by
/// months, say) and would log the same warning forever; this drains it in the
/// same tick, bounded.
pub async fn drain_storage_maintenance(
    pool: &PgPool,
    retention: StorageRetention,
    plan: MaintenanceDrainPlan,
) -> Result<StorageMaintenanceDrain, DbError> {
    let mut totals = StorageMaintenanceReport::default();
    let mut batches_run = 0;
    loop {
        let report = match run_storage_maintenance(pool, retention).await {
            Ok(report) => report,
            // What earlier batches committed is part of what this tick did:
            // the failure carries it, so the caller can still act on it.
            Err(DbError::MaintenanceFailed {
                completed,
                failures,
            }) => {
                totals.add(*completed);
                return Err(DbError::MaintenanceFailed {
                    completed: Box::new(totals),
                    failures,
                });
            }
            Err(error) => return Err(error),
        };
        let saturated = report.saturated;
        totals.add(report);
        batches_run += 1;
        if !saturated || batches_run >= plan.batches.get() {
            return Ok(StorageMaintenanceDrain {
                totals,
                batches_run,
            });
        }
        tokio::time::sleep(plan.pause).await;
    }
}

/// Delete one bounded batch from every time-retained/expiring collection.
///
/// Each collection is its own statement and its own transaction: nothing
/// needs the collections to disappear together, and one transaction across
/// all of them took each table's row locks in a fixed order that no other
/// writer shares, holding every one until the slowest finished. A collection
/// that fails is reported (by table, with its error) after the others have
/// committed their batches; the call then fails so the failure is counted and
/// logged, never absorbed.
pub async fn run_storage_maintenance(
    pool: &PgPool,
    retention: StorageRetention,
) -> Result<StorageMaintenanceReport, DbError> {
    let history_days = i32::try_from(retention.history_days)
        .map_err(|_| DbError::InvalidServerSettings("history retention exceeds INT".into()))?;
    let audit_days = i32::try_from(retention.audit_days)
        .map_err(|_| DbError::InvalidServerSettings("audit retention exceeds INT".into()))?;
    let observability_cutoff_ms = i64::try_from(
        crate::observability::epoch_millis().saturating_sub(
            retention
                .observability_hours
                .saturating_mul(60 * 60 * 1_000),
        ),
    )
    .map_err(|_| DbError::InvalidServerSettings("sample retention cutoff exceeds BIGINT".into()))?;
    let limit = STORAGE_MAINTENANCE_BATCH as i64;
    let mut report = StorageMaintenanceReport::default();
    let mut failures = Vec::new();
    for collection in MaintenanceCollection::ALL {
        let bound = match collection {
            MaintenanceCollection::Messages
            | MaintenanceCollection::BncBuffer
            | MaintenanceCollection::ReadMarkers
            | MaintenanceCollection::BncReadMarkers => RetentionBound::Days(history_days),
            MaintenanceCollection::AuditLog => RetentionBound::Days(audit_days),
            MaintenanceCollection::DeviceGrants => {
                RetentionBound::Seconds(DEVICE_GRANT_EXPIRED_RETENTION_SECONDS)
            }
            MaintenanceCollection::ObservabilitySamples => {
                RetentionBound::Millis(observability_cutoff_ms)
            }
            _ => RetentionBound::None,
        };
        let outcome = if collection == MaintenanceCollection::ReadMarkers {
            expire_read_markers(pool, history_days, limit, &mut report.expired_read_markers).await
        } else {
            let query = sqlx::query(collection.statement());
            let query = match bound {
                RetentionBound::Days(days) => query.bind(days).bind(limit),
                RetentionBound::Seconds(seconds) => query.bind(seconds).bind(limit),
                RetentionBound::Millis(millis) => query.bind(millis).bind(limit),
                RetentionBound::None => query.bind(limit),
            };
            query
                .execute(pool)
                .await
                .map(|result| result.rows_affected())
                .map_err(query_error)
        };
        match outcome {
            Ok(deleted) => {
                // Added, not assigned: the two marker tables report through one
                // counter, and the second would otherwise overwrite the first.
                *report.slot(collection) += deleted;
                report.saturated |= deleted == STORAGE_MAINTENANCE_BATCH;
            }
            Err(error) => failures.push(MaintenanceFailure {
                collection,
                error: Box::new(error),
            }),
        }
    }
    if failures.is_empty() {
        Ok(report)
    } else {
        Err(DbError::MaintenanceFailed {
            completed: Box::new(report),
            failures,
        })
    }
}

/// One batch of [`MaintenanceCollection::ReadMarkers`], appending each deleted
/// marker to `expired`; returns how many rows were deleted.
async fn expire_read_markers(
    pool: &PgPool,
    history_days: i32,
    limit: i64,
    expired: &mut Vec<crate::core::ExpiredReadMarker>,
) -> Result<u64, DbError> {
    let rows: Vec<(String, String, i64)> =
        sqlx::query_as(MaintenanceCollection::ReadMarkers.statement())
            .bind(history_days)
            .bind(limit)
            .fetch_all(pool)
            .await
            .map_err(query_error)?;
    let deleted = rows.len() as u64;
    for (account, target, millis) in rows {
        expired.push(crate::core::ExpiredReadMarker {
            account,
            target,
            marker_ms: millis_from_database(millis, "read_markers.marker_ts")?,
        });
    }
    Ok(deleted)
}

/// Where the backlog-cap sweep resumes: the last (owner, network) buffer it
/// checked. Held by the maintenance task across ticks, so every buffer is
/// visited in turn however many there are.
#[derive(Debug, Default)]
pub struct BncCapSweep {
    after: Option<(String, String)>,
}

/// Buffers one sweep step checks against [`BNC_BUFFER_CAP`].
const BNC_CAP_SWEEP_BUFFERS: usize = 64;

/// Trim buffers that exceed [`BNC_BUFFER_CAP`], [`BNC_CAP_SWEEP_BUFFERS`] of
/// them per call, resuming where the previous call stopped and wrapping around
/// at the end. Each buffer loses at most one bounded batch per call. A running
/// network trims itself (at start and every [`BNC_TRIM_INTERVAL`] lines); this
/// catches whatever that leaves over — a buffer written before a restart that
/// never reached the interval, lines from a stopped network — without a whole
/// table `GROUP BY`: each step is an index probe for the next buffer key and
/// one for its cap boundary. Returns the rows deleted.
pub async fn trim_bnc_buffers_over_cap(
    pool: &PgPool,
    sweep: &mut BncCapSweep,
) -> Result<u64, DbError> {
    let mut deleted = 0;
    for _ in 0..BNC_CAP_SWEEP_BUFFERS {
        let next: Option<(String, String)> = match &sweep.after {
            None => sqlx::query_as(
                "SELECT owner, network FROM bnc_buffer ORDER BY owner, network LIMIT 1",
            )
            .fetch_optional(pool)
            .await
            .map_err(query_error)?,
            Some((owner, network)) => sqlx::query_as(
                "SELECT owner, network FROM bnc_buffer
                 WHERE (owner, network) > ($1, $2)
                 ORDER BY owner, network LIMIT 1",
            )
            .bind(owner)
            .bind(network)
            .fetch_optional(pool)
            .await
            .map_err(query_error)?,
        };
        let Some((owner, network)) = next else {
            // The end of the key space: the next call starts over.
            sweep.after = None;
            break;
        };
        deleted += trim_bnc_buffer_batch(pool, &owner, &network, STORAGE_MAINTENANCE_BATCH).await?;
        sweep.after = Some((owner, network));
    }
    Ok(deleted)
}

/// Persist one monitoring sample. Expired samples are pruned by storage
/// maintenance (whether or not sampling is on), not here: a prune that only
/// ran while sampling was enabled left the table frozen at whatever it held
/// when sampling was turned off.
pub(crate) async fn store_observability_sample(
    pool: &PgPool,
    snapshot: &crate::observability::Snapshot,
) -> Result<(), DbError> {
    let value = serde_json::to_value(snapshot)
        .map_err(|error| DbError::InvalidServerSettings(error.to_string()))?;
    let sampled_at = i64::try_from(snapshot.sampled_at_ms)
        .map_err(|_| DbError::InvalidServerSettings("sample timestamp exceeds BIGINT".into()))?;
    sqlx::query(
        "INSERT INTO observability_samples (sampled_at_ms, snapshot)
         VALUES ($1, $2)
         ON CONFLICT (sampled_at_ms) DO UPDATE SET snapshot = EXCLUDED.snapshot",
    )
    .bind(sampled_at)
    .bind(value)
    .execute(pool)
    .await
    .map_err(query_error)?;
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
    .map_err(query_error)?;
    rows.into_iter()
        .map(|row| {
            serde_json::from_value(row.get("snapshot"))
                .map_err(|error| DbError::InvalidServerSettings(error.to_string()))
        })
        .collect()
}

/// Immutable settings with its write revision.
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
    .map_err(query_error)?;
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
    .map_err(query_error)?
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
    actor: &AuditPrincipal,
    audit_detail: &str,
) -> Result<ManagedConfigSnapshot, DbError> {
    let value = serde_json::to_value(settings)
        .map_err(|error| DbError::InvalidServerSettings(error.to_string()))?;
    let mut tx = pool.begin().await.map_err(query_error)?;
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
    .bind(actor.name())
    .fetch_optional(&mut *tx)
    .await
    .map_err(query_error)?;
    let Some((revision, updated_at)) = next else {
        return Err(DbError::StaleServerSettings);
    };
    insert_audit_log_with(
        &mut *tx,
        actor,
        "CONFIG",
        &AuditPrincipal::server(),
        audit_detail,
    )
    .await?;
    tx.commit().await.map_err(query_error)?;
    Ok(ManagedConfigSnapshot {
        revision,
        settings: settings.clone(),
        updated_by: actor.name().to_string(),
        updated_at,
    })
}

async fn insert_primary_password(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: i64,
    hash: &str,
) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO account_credentials (account_id, kind, argon2_hash)
         VALUES ($1, 'local_password', $2)",
    )
    .bind(account_id)
    .bind(hash)
    .execute(&mut **transaction)
    .await
    .map(|_| ())
    .map_err(query_error)
}

/// Insert the account row inside a transaction, returning its id — or `None`
/// when the folded name is already taken (`ON CONFLICT DO NOTHING`). Shared by
/// direct registration and invitation acceptance so the flags/insert shape
/// cannot drift between the two ways an account comes into being.
async fn insert_account(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    name: &str,
    folded: &str,
    contact_email: Option<&str>,
    administrator: bool,
) -> Result<Option<i64>, DbError> {
    let flags = if administrator { ACCOUNT_FLAG_ADMIN } else { 0 };
    sqlx::query_scalar(
        "INSERT INTO accounts (name, name_folded, contact_email, flags)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (name_folded) DO NOTHING
         RETURNING id",
    )
    .bind(name)
    .bind(folded)
    .bind(contact_email)
    .bind(flags)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(query_error)
}

const ACCOUNT_NAME_ADVISORY_LOCK_NAMESPACE: i64 = 0x6536_6972_6300_0001;

async fn lock_account_name(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    folded: &str,
) -> Result<(), DbError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, $2))")
        .bind(folded)
        .bind(ACCOUNT_NAME_ADVISORY_LOCK_NAMESPACE)
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(query_error)
}

/// Whether a new account may not take `folded`: the name is retired, it is
/// a nick grouped to another account (migration 0075's storage triggers refuse
/// both; this answers first, so the refusal is a duplicate, not a fault), or
/// it is a services pseudo-client's nick, which no session could ever use.
/// Every creation path — OpenID Connect provisioning included — asks this.
/// The caller holds the name's lock.
async fn account_name_is_unavailable(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    folded: &str,
) -> Result<bool, DbError> {
    if crate::identity::SERVICE_NICKS.contains(&folded) {
        return Ok(true);
    }
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM retired_account_names WHERE name_folded = $1)
             OR EXISTS (SELECT 1 FROM account_nicks WHERE nick_folded = $1)",
    )
    .bind(folded)
    .fetch_one(&mut **transaction)
    .await
    .map_err(query_error)
}

/// The entries of `names` no account holds, in the order and spelling given.
/// Startup names each configured administrator that is still unclaimed.
pub async fn unclaimed_account_names(
    pool: &PgPool,
    names: &[String],
) -> Result<Vec<String>, DbError> {
    let folded: Vec<String> = names
        .iter()
        .map(|name| CaseMapping::Rfc1459.casefold(name))
        .collect();
    let held: Vec<String> =
        sqlx::query_scalar("SELECT name_folded FROM accounts WHERE name_folded = ANY($1)")
            .bind(&folded)
            .fetch_all(pool)
            .await
            .map_err(query_error)?;
    Ok(names
        .iter()
        .zip(folded)
        .filter(|(_, folded)| !held.contains(folded))
        .map(|(name, _)| name.clone())
        .collect())
}

/// Create an account with an optional validated contact email.
pub async fn create_account_with_contact(
    pool: &PgPool,
    name: &str,
    password: &str,
    contact_email: Option<&crate::identity::ContactEmail>,
) -> Result<i64, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(name);
    let hash = hash_password(password.to_string()).await?;
    let mut tx = pool.begin().await.map_err(query_error)?;
    lock_account_name(&mut tx, &folded).await?;
    if account_name_is_unavailable(&mut tx, &folded).await? {
        return Err(DbError::DuplicateAccount(name.to_string()));
    }
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO accounts (name, name_folded, contact_email) VALUES ($1, $2, $3)
         ON CONFLICT (name_folded) DO NOTHING RETURNING id",
    )
    .bind(name)
    .bind(&folded)
    .bind(contact_email.map(crate::identity::ContactEmail::as_str))
    .fetch_optional(&mut *tx)
    .await
    .map_err(query_error)?
    .ok_or_else(|| DbError::DuplicateAccount(name.to_string()))?;
    insert_primary_password(&mut tx, id, &hash).await?;
    // Self-service creation is audited like every other way an account comes
    // to exist (administrator, invitation, bootstrap); the actor is the account.
    insert_audit_log_with(
        &mut *tx,
        &AuditPrincipal::account(&folded),
        "ACCOUNT_CREATE",
        &AuditPrincipal::account(&folded),
        "self-registered over IRC",
    )
    .await?;
    tx.commit().await.map_err(query_error)?;
    Ok(id)
}

/// Create an administrator-provisioned local account and its audit row as one
/// transaction. The optional authority grant is durable and immediately
/// visible through the account directory after the HTTP boundary reconciles
/// its live administrator registry.
pub async fn create_account_by_administrator(
    pool: &PgPool,
    name: &str,
    password: &str,
    contact_email: Option<&crate::identity::ContactEmail>,
    administrator: bool,
    actor: &str,
) -> Result<i64, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(name);
    let actor_folded = CaseMapping::Rfc1459.casefold(actor);
    let hash = hash_password(password.to_string()).await?;
    let mut transaction = pool.begin().await.map_err(query_error)?;
    lock_account_name(&mut transaction, &folded).await?;
    if account_name_is_unavailable(&mut transaction, &folded).await? {
        return Err(DbError::DuplicateAccount(name.to_string()));
    }
    let account_id: i64 = insert_account(
        &mut transaction,
        name,
        &folded,
        contact_email.map(crate::identity::ContactEmail::as_str),
        administrator,
    )
    .await?
    .ok_or_else(|| DbError::DuplicateAccount(name.to_string()))?;
    insert_primary_password(&mut transaction, account_id, &hash).await?;
    insert_audit_log_with(
        &mut *transaction,
        &AuditPrincipal::account(&actor_folded),
        "ACCOUNT_CREATE",
        &AuditPrincipal::account(&folded),
        if administrator {
            "local account created with durable administrator authority"
        } else {
            "local account created"
        },
    )
    .await?;
    transaction.commit().await.map_err(query_error)?;
    Ok(account_id)
}

/// Maximum live invitations one administrator may retain. Issuance and the
/// count are serialized per actor, so concurrent requests cannot cross it.
pub const MAX_PENDING_ACCOUNT_INVITATIONS_PER_ADMINISTRATOR: i64 = 100;
const INVITATION_ACTOR_ADVISORY_LOCK_NAMESPACE: i64 = 0x6536_6972_6300_0002;

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct AccountInvitationRow {
    pub id: i64,
    pub account_name: String,
    pub contact_email: Option<String>,
    pub administrator: bool,
    pub created_by: String,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct AccountInvitationPreview {
    pub account_name: String,
    pub administrator: bool,
    pub expires_at: String,
}

/// A non-zero invitation-directory page size capped at the public API maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountInvitationPageSize(usize);

impl AccountInvitationPageSize {
    pub const MAX: usize = 1_000;

    pub fn new(value: usize) -> Option<Self> {
        (1..=Self::MAX).contains(&value).then_some(Self(value))
    }

    pub fn value(self) -> usize {
        self.0
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct AccountInvitationPage {
    pub entries: Vec<AccountInvitationRow>,
    pub next_before_id: Option<i64>,
}

/// Issue one opaque, single-use account invitation. Only the digest is
/// persisted; the plaintext value is returned once.
pub async fn issue_account_invitation(
    pool: &PgPool,
    name: &str,
    contact_email: Option<&crate::identity::ContactEmail>,
    administrator: bool,
    lifetime: crate::identity::AccountInvitationLifetimeDays,
    actor: &str,
) -> Result<String, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(name);
    let actor_folded = CaseMapping::Rfc1459.casefold(actor);
    let token = format!("e6i_{}", crate::secret::random_url_safe_token());
    let mut transaction = pool.begin().await.map_err(query_error)?;
    lock_account_name(&mut transaction, &folded).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, $2))")
        .bind(&actor_folded)
        .bind(INVITATION_ACTOR_ADVISORY_LOCK_NAMESPACE)
        .execute(&mut *transaction)
        .await
        .map_err(query_error)?;
    sqlx::query(
        "UPDATE account_invitations
         SET consumed_at = expires_at
         WHERE name_folded = $1
           AND consumed_at IS NULL AND expires_at <= now()",
    )
    .bind(&folded)
    .execute(&mut *transaction)
    .await
    .map_err(query_error)?;
    if account_name_is_unavailable(&mut transaction, &folded).await? {
        return Err(DbError::DuplicateAccount(name.to_string()));
    }
    let unavailable: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM accounts WHERE name_folded = $1)
             OR EXISTS (
                 SELECT 1 FROM account_invitations
                 WHERE name_folded = $1 AND consumed_at IS NULL
             )",
    )
    .bind(&folded)
    .fetch_one(&mut *transaction)
    .await
    .map_err(query_error)?;
    if unavailable {
        return Err(DbError::DuplicateAccount(name.to_string()));
    }
    let pending: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM account_invitations
         WHERE created_by = $1 AND consumed_at IS NULL AND expires_at > now()",
    )
    .bind(&actor_folded)
    .fetch_one(&mut *transaction)
    .await
    .map_err(query_error)?;
    if pending >= MAX_PENDING_ACCOUNT_INVITATIONS_PER_ADMINISTRATOR {
        return Err(DbError::TooManyInvitations);
    }
    sqlx::query(
        "INSERT INTO account_invitations
            (token_hash, account_name, name_folded, contact_email,
             administrator, created_by, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(days => $7))",
    )
    .bind(token_hash(&token))
    .bind(name)
    .bind(&folded)
    .bind(contact_email.map(crate::identity::ContactEmail::as_str))
    .bind(administrator)
    .bind(&actor_folded)
    .bind(i32::from(lifetime.value()))
    .execute(&mut *transaction)
    .await
    .map_err(query_error)?;
    insert_audit_log_with(
        &mut *transaction,
        &AuditPrincipal::account(&actor_folded),
        "ACCOUNT_INVITATION_CREATE",
        &AuditPrincipal::invitation(&folded),
        if administrator {
            "single-use local account invitation issued with durable administrator authority"
        } else {
            "single-use local account invitation issued"
        },
    )
    .await?;
    transaction.commit().await.map_err(query_error)?;
    Ok(token)
}

/// Page live account invitations newest-first without exposing bearer digests.
pub async fn list_account_invitations(
    pool: &PgPool,
    before_id: Option<i64>,
    page_size: AccountInvitationPageSize,
) -> Result<AccountInvitationPage, DbError> {
    let fetch_limit = page_size.value() + 1;
    let mut entries: Vec<AccountInvitationRow> = sqlx::query_as(
        "SELECT id, account_name, contact_email, administrator, created_by,
                to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')
                    AS created_at,
                to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')
                    AS expires_at
         FROM account_invitations
         WHERE consumed_at IS NULL AND expires_at > now()
           AND ($1::bigint IS NULL OR id < $1)
         ORDER BY id DESC
         LIMIT $2",
    )
    .bind(before_id)
    .bind(fetch_limit as i64)
    .fetch_all(pool)
    .await
    .map_err(query_error)?;
    let next_before_id =
        (entries.len() > page_size.value()).then(|| entries[page_size.value() - 1].id);
    entries.truncate(page_size.value());
    Ok(AccountInvitationPage {
        entries,
        next_before_id,
    })
}

/// Revoke one pending invitation and record the action atomically.
pub async fn revoke_account_invitation(
    pool: &PgPool,
    invitation_id: i64,
    actor: &str,
) -> Result<bool, DbError> {
    let actor_folded = CaseMapping::Rfc1459.casefold(actor);
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let target: Option<String> = sqlx::query_scalar(
        "UPDATE account_invitations
         SET consumed_at = now()
         WHERE id = $1 AND consumed_at IS NULL AND expires_at > now()
         RETURNING name_folded",
    )
    .bind(invitation_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(query_error)?;
    let Some(target) = target else {
        return Ok(false);
    };
    insert_audit_log_with(
        &mut *transaction,
        &AuditPrincipal::account(&actor_folded),
        "ACCOUNT_INVITATION_REVOKE",
        &AuditPrincipal::invitation(&target),
        "",
    )
    .await?;
    transaction.commit().await.map_err(query_error)?;
    Ok(true)
}

/// Resolve public, non-secret invitation display data.
pub async fn account_invitation_preview(
    pool: &PgPool,
    token: &str,
) -> Result<Option<AccountInvitationPreview>, DbError> {
    sqlx::query_as(
        "SELECT account_name, administrator,
                to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS expires_at
         FROM account_invitations
         WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now()",
    )
    .bind(token_hash(token))
    .fetch_optional(pool)
    .await
    .map_err(query_error)
}

/// Consume an invitation and create its account/password in one transaction.
///
/// An invitation that grants administrator authority is honoured only while
/// its issuer still holds that authority — durably, or through
/// `configured_administrators` — and is not suspended. Suspension, demotion,
/// and host recovery revoke the issuer's invitations as they happen; this
/// re-check covers authority removed by any other path, so an invitation can
/// never confer more than its issuer holds at the moment it is used.
pub async fn accept_account_invitation(
    pool: &PgPool,
    token: &str,
    password: &str,
    configured_administrators: &[String],
) -> Result<String, DbError> {
    let hash = hash_password(password.to_string()).await?;
    let mut transaction = pool.begin().await.map_err(query_error)?;
    #[derive(sqlx::FromRow)]
    struct Invitation {
        id: i64,
        name: String,
        folded: String,
        contact_email: Option<String>,
        administrator: bool,
        issuer: String,
    }

    let invitation: Option<Invitation> = sqlx::query_as(
        "SELECT id, account_name AS name, name_folded AS folded, contact_email, administrator,
                created_by AS issuer
         FROM account_invitations
         WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now()
         FOR UPDATE",
    )
    .bind(token_hash(token))
    .fetch_optional(&mut *transaction)
    .await
    .map_err(query_error)?;
    let Some(Invitation {
        id: invitation_id,
        name,
        folded,
        contact_email,
        administrator,
        issuer,
    }) = invitation
    else {
        return Err(DbError::InvitationUnavailable);
    };
    // A configured administrator's name is created only by OIDC provisioning
    // or the bootstrap/recovery flows; an invitation issued for it before the
    // name was configured cannot claim it now.
    if configured_administrators.contains(&folded) {
        return Err(DbError::InvitationUnavailable);
    }
    if administrator {
        let issuer_is_active_administrator: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1 FROM accounts
                 WHERE name_folded = $1
                   AND (flags & $3) = 0
                   AND ((flags & $2) = $2 OR name_folded = ANY($4))
             )",
        )
        .bind(&issuer)
        .bind(ACCOUNT_FLAG_ADMIN)
        .bind(ACCOUNT_FLAG_SUSPENDED)
        .bind(configured_administrators)
        .fetch_one(&mut *transaction)
        .await
        .map_err(query_error)?;
        if !issuer_is_active_administrator {
            return Err(DbError::InvitationUnavailable);
        }
    }
    lock_account_name(&mut transaction, &folded).await?;
    if account_name_is_unavailable(&mut transaction, &folded).await? {
        return Err(DbError::InvitationUnavailable);
    }
    let account_id: i64 = insert_account(
        &mut transaction,
        &name,
        &folded,
        contact_email.as_deref(),
        administrator,
    )
    .await?
    .ok_or(DbError::InvitationUnavailable)?;
    insert_primary_password(&mut transaction, account_id, &hash).await?;
    sqlx::query("UPDATE account_invitations SET consumed_at = now() WHERE id = $1")
        .bind(invitation_id)
        .execute(&mut *transaction)
        .await
        .map_err(query_error)?;
    insert_audit_log_with(
        &mut *transaction,
        &AuditPrincipal::account(&folded),
        "ACCOUNT_INVITATION_ACCEPT",
        &AuditPrincipal::account(&folded),
        if administrator {
            "local account created from invitation with durable administrator authority"
        } else {
            "local account created from invitation"
        },
    )
    .await?;
    transaction.commit().await.map_err(query_error)?;
    Ok(name)
}

/// Read the authenticated account's private contact email.
pub async fn account_contact_email(
    pool: &PgPool,
    account: &str,
) -> Result<Option<String>, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT contact_email FROM accounts WHERE name_folded = $1")
            .bind(folded)
            .fetch_optional(pool)
            .await
            .map_err(query_error)?;
    Ok(row.and_then(|(email,)| email))
}

/// Replace or remove an account's private contact email and write a redacted
/// security event in the same transaction.
pub async fn set_account_contact_email(
    pool: &PgPool,
    account: &str,
    contact_email: Option<&crate::identity::ContactEmail>,
) -> Result<(), DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let updated = sqlx::query(
        "UPDATE accounts SET contact_email = $2
         WHERE name_folded = $1 AND (flags & $3) = 0",
    )
    .bind(&folded)
    .bind(contact_email.map(crate::identity::ContactEmail::as_str))
    .bind(ACCOUNT_FLAG_SUSPENDED)
    .execute(&mut *transaction)
    .await
    .map_err(query_error)?;
    if updated.rows_affected() == 0 {
        return Err(DbError::UnknownAccount(account.to_string()));
    }
    insert_audit_log_with(
        &mut *transaction,
        &AuditPrincipal::account(&folded),
        "ACCOUNT_CONTACT_UPDATE",
        &AuditPrincipal::account(&folded),
        if contact_email.is_some() {
            "contact email replaced"
        } else {
            "contact email removed"
        },
    )
    .await?;
    transaction.commit().await.map_err(query_error)
}

/// Whether the one-time first-account bootstrap has already been consumed.
pub async fn has_accounts(pool: &PgPool) -> Result<bool, DbError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM accounts)
             OR EXISTS (SELECT 1 FROM retired_account_names)",
    )
    .fetch_one(pool)
    .await
    .map_err(query_error)
}

/// Create the only possible first account and make it an administrator in the
/// same transaction. The table lock serializes this with every ordinary
/// account INSERT, so browser bootstrap and IRC registration cannot both
/// observe an empty store and mint separate "first" accounts.
pub async fn bootstrap_first_admin(
    pool: &PgPool,
    name: &str,
    password: &str,
) -> Result<i64, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(name);
    if crate::identity::SERVICE_NICKS.contains(&folded.as_str()) {
        return Err(DbError::DuplicateAccount(name.to_string()));
    }
    let hash = hash_password(password.to_string()).await?;
    let mut transaction = pool.begin().await.map_err(query_error)?;
    sqlx::query("LOCK TABLE accounts IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *transaction)
        .await
        .map_err(query_error)?;
    let initialized: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM accounts)
             OR EXISTS (SELECT 1 FROM retired_account_names)",
    )
    .fetch_one(&mut *transaction)
    .await
    .map_err(query_error)?;
    if initialized {
        return Err(DbError::AlreadyInitialized);
    }
    let account_id: i64 = sqlx::query_scalar(
        "INSERT INTO accounts (name, name_folded, flags)
         VALUES ($1, $2, $3)
         RETURNING id",
    )
    .bind(name)
    .bind(&folded)
    .bind(ACCOUNT_FLAG_ADMIN)
    .fetch_one(&mut *transaction)
    .await
    .map_err(query_error)?;
    insert_primary_password(&mut transaction, account_id, &hash).await?;
    insert_audit_log_with(
        &mut *transaction,
        &AuditPrincipal::account(&folded),
        "ACCOUNT_BOOTSTRAP",
        &AuditPrincipal::account(&folded),
        "first administrator created through one-time browser bootstrap",
    )
    .await?;
    transaction.commit().await.map_err(query_error)?;
    Ok(account_id)
}

/// The account an operator recovered from the host, and the one-time password
/// that now opens it. The password is wiped from memory when this is dropped.
#[derive(Debug)]
pub struct AdministratorRecovery {
    /// The account's stored name, which may differ in case from the one typed.
    pub account: String,
    pub password: String,
}

impl Drop for AdministratorRecovery {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
    }
}

/// Who the audit log records for a recovery: not an account, because the point
/// is that no account could act.
const ADMINISTRATOR_RECOVERY_ACTOR: &str = "host:recover-administrator";

/// Give an operator who holds the host — and so the database — a way back in
/// when every administrator credential is lost or the identity provider that
/// backed them is broken (`e6ircd recover-administrator`).
///
/// It acts on one existing, active account the operator names, in one
/// transaction: every credential the account held is revoked — the local
/// password and every app password, every personal access token, every device
/// grant, every browser session — exactly as suspension revokes them, because
/// the premise of a recovery is that the account's credentials are lost, and a
/// lost credential may be in someone else's hands. A generated local password
/// is installed and returned once, durable administrator authority is granted,
/// and the audit log records it. Nothing is guessed: an unknown name or a
/// suspended account is refused. Nothing stays open afterwards: unlike the
/// first-run browser bootstrap there is no token or page for anyone else to
/// reach.
pub async fn recover_administrator(
    pool: &PgPool,
    account: &str,
) -> Result<AdministratorRecovery, DbError> {
    use argon2::password_hash::rand_core::RngCore;
    let folded = CaseMapping::Rfc1459.casefold(account);
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let password = e6irc_proto::base64::encode(&secret);
    // Hashed before the transaction, so the account row is not locked for it.
    let hash = hash_password(password.clone()).await?;
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let row: Option<(i64, String, i64)> = sqlx::query_as(
        "SELECT id, name, flags FROM accounts WHERE name_folded = $1 FOR NO KEY UPDATE",
    )
    .bind(&folded)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(query_error)?;
    let Some((account_id, name, flags)) = row else {
        return Err(DbError::UnknownAccount(account.to_string()));
    };
    if flags & ACCOUNT_FLAG_SUSPENDED != 0 {
        return Err(DbError::RecoveryOfSuspendedAccount(name));
    }
    sqlx::query("DELETE FROM account_credentials WHERE account_id = $1")
        .bind(account_id)
        .execute(&mut *transaction)
        .await
        .map_err(query_error)?;
    revoke_account_bearers(&mut transaction, account_id).await?;
    revoke_issued_invitations(
        &mut transaction,
        &folded,
        &AuditPrincipal::host(ADMINISTRATOR_RECOVERY_ACTOR),
        "issuer's credentials were recovered from the host",
    )
    .await?;
    insert_primary_password(&mut transaction, account_id, &hash).await?;
    sqlx::query("UPDATE accounts SET flags = flags | $2 WHERE id = $1")
        .bind(account_id)
        .bind(ACCOUNT_FLAG_ADMIN)
        .execute(&mut *transaction)
        .await
        .map_err(query_error)?;
    insert_audit_log_with(
        &mut *transaction,
        &AuditPrincipal::host(ADMINISTRATOR_RECOVERY_ACTOR),
        "ADMINISTRATOR_RECOVERY",
        &AuditPrincipal::account(&folded),
        "every credential revoked (local and app passwords, personal access tokens, device grants, browser sessions) with every invitation the account issued, local password replaced, and administrator authority granted from the host",
    )
    .await?;
    transaction.commit().await.map_err(query_error)?;
    Ok(AdministratorRecovery {
        account: name,
        password,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountDeletionTarget {
    pub id: i64,
    pub name: String,
    pub folded: String,
    /// Suspended before the deletion began: a deletion that does not commit
    /// must leave the live suspension gate up rather than lift it.
    pub suspended: bool,
}

#[derive(sqlx::FromRow)]
struct AccountDeletionTargetRow {
    name: String,
    folded: String,
    flags: i64,
    founded_channels: i64,
}

/// One registered channel an account deletion passed to its successor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelSuccession {
    /// Folded channel name.
    pub channel: String,
    /// The successor, now founder: folded account name.
    pub founder: String,
}

/// An account permanently deleted, with the channels it passed on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedAccount {
    pub name: String,
    pub successions: Vec<ChannelSuccession>,
}

/// Resolve a deletion target before the core authentication gate.
pub async fn account_deletion_target(
    pool: &PgPool,
    account_id: i64,
    configured_administrators: &[String],
) -> Result<Option<AccountDeletionTarget>, DbError> {
    let row: Option<AccountDeletionTargetRow> = sqlx::query_as(
        "SELECT a.name, a.name_folded AS folded, a.flags,
                (SELECT count(*) FROM channels c
                 WHERE c.founder_account_id = a.id
                   AND c.successor_account_id IS NULL) AS founded_channels
         FROM accounts a WHERE a.id = $1",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await
    .map_err(query_error)?;
    let Some(AccountDeletionTargetRow {
        name,
        folded,
        flags,
        founded_channels,
    }) = row
    else {
        return Ok(None);
    };
    if founded_channels != 0 {
        return Err(DbError::AccountOwnsChannels(
            usize::try_from(founded_channels).unwrap_or(usize::MAX),
        ));
    }
    // What the deletion's succession would give each successor, so a refusal
    // the transaction would reach anyway is answered before the account is
    // gated and its networks stopped. The transaction re-checks under locks.
    let over_limit: Vec<String> = sqlx::query_scalar(
        "SELECT c.name_folded FROM channels c
         WHERE c.founder_account_id = $1 AND c.successor_account_id IS NOT NULL
           AND (SELECT count(*) FROM channels founded
                WHERE founded.founder_account_id = c.successor_account_id
                   OR (founded.founder_account_id = $1
                       AND founded.successor_account_id = c.successor_account_id)) > $2
         ORDER BY c.name_folded",
    )
    .bind(account_id)
    .bind(CHANNEL_FOUNDER_LIMIT)
    .fetch_all(pool)
    .await
    .map_err(query_error)?;
    if !over_limit.is_empty() {
        return Err(DbError::SuccessorChannelLimit(over_limit));
    }
    if flags & ACCOUNT_FLAG_ADMIN != 0 || configured_administrators.contains(&folded) {
        require_other_active_administrator(pool, account_id, configured_administrators).await?;
    }
    Ok(Some(AccountDeletionTarget {
        id: account_id,
        name,
        folded,
        suspended: flags & ACCOUNT_FLAG_SUSPENDED != 0,
    }))
}

/// The messages that are an account's: `$1` is its folded name, `$2` its
/// display name. `sender_account` holds the account as the sender's session
/// named it — the display name — while `dm_peers` holds casefolded identities.
/// An account's name never changes and no other account can fold to it, so the
/// two spellings together are exactly this account's messages. Each half has
/// its own index (`messages_sender_account_idx`, `messages_dm_peers_idx`), so
/// the predicate is a BitmapOr of two index scans. Deletion and export both
/// select with it; it is written once.
macro_rules! account_messages_predicate {
    () => {
        "(sender_account IN ($1, $2) OR dm_peers @> ARRAY[$1::text])"
    };
}

/// [`account_messages_predicate!`], for callers outside this module that plan
/// or inspect the same selection.
pub const ACCOUNT_MESSAGES_PREDICATE: &str = account_messages_predicate!();

/// Messages one account-deletion statement removes: each batch is a bounded
/// statement under the pool's statement timeout, however much history the
/// account has.
const ACCOUNT_PURGE_BATCH: i64 = 5_000;

/// Permanently remove one account after the live core has denied new
/// authentication. The retired-name reservation, privacy purge, account
/// cascade, and durable audit event commit together.
pub async fn delete_account_permanently(
    pool: &PgPool,
    account_id: i64,
    actor: &str,
    configured_administrators: &[String],
) -> Result<Option<DeletedAccount>, DbError> {
    let actor_folded = CaseMapping::Rfc1459.casefold(actor);
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let Some(LockedAccountState {
        name,
        folded,
        flags,
    }) = lock_account_state(
        &mut transaction,
        account_id,
        AccountStateChangeKind::Deletion,
    )
    .await?
    else {
        return Ok(None);
    };
    lock_account_name(&mut transaction, &folded).await?;
    // Every founded channel with a successor passes to it (ChanServ SET
    // SUCCESSOR, Atheme's succession); only one without a successor holds the
    // deletion up. The successor stops being one as it becomes founder
    // (migration 0075's trigger).
    let successions: Vec<(String, String)> = sqlx::query_as(
        "UPDATE channels c SET founder_account_id = c.successor_account_id
         FROM accounts successor
         WHERE c.founder_account_id = $1 AND successor.id = c.successor_account_id
         RETURNING c.name_folded, successor.name_folded",
    )
    .bind(account_id)
    .fetch_all(&mut *transaction)
    .await
    .map_err(query_error)?;
    // A succession is a founder transfer, so it is held to the same cap under
    // the same lock: each successor's row is locked (in id order, after the
    // channel rows, the order a transfer takes them in) and its founded
    // channels — the ones it just received included — counted. A successor
    // the deletion would take past the cap refuses the deletion, naming the
    // channels, as an unsuccessored channel does.
    let passed: Vec<&str> = successions
        .iter()
        .map(|(channel, _)| channel.as_str())
        .collect();
    // Locked by its own statement: the count must be read by a later one,
    // whose snapshot includes whatever committed while this one waited.
    sqlx::query(
        "SELECT a.id FROM accounts a
         WHERE a.id IN (SELECT founder_account_id FROM channels WHERE name_folded = ANY($1))
         ORDER BY a.id
         FOR NO KEY UPDATE",
    )
    .bind(&passed)
    .execute(&mut *transaction)
    .await
    .map_err(query_error)?;
    let over_limit: Vec<String> = sqlx::query_scalar(
        "SELECT c.name_folded FROM channels c
         WHERE c.name_folded = ANY($1)
           AND (SELECT count(*) FROM channels founded
                WHERE founded.founder_account_id = c.founder_account_id) > $2
         ORDER BY c.name_folded",
    )
    .bind(&passed)
    .bind(CHANNEL_FOUNDER_LIMIT)
    .fetch_all(&mut *transaction)
    .await
    .map_err(query_error)?;
    if !over_limit.is_empty() {
        return Err(DbError::SuccessorChannelLimit(over_limit));
    }
    let founded_channels: i64 =
        sqlx::query_scalar("SELECT count(*) FROM channels WHERE founder_account_id = $1")
            .bind(account_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(query_error)?;
    if founded_channels != 0 {
        return Err(DbError::AccountOwnsChannels(
            usize::try_from(founded_channels).unwrap_or(usize::MAX),
        ));
    }
    if flags & ACCOUNT_FLAG_ADMIN != 0 || configured_administrators.contains(&folded) {
        require_other_active_administrator(
            &mut *transaction,
            account_id,
            configured_administrators,
        )
        .await?;
    }
    sqlx::query(
        "INSERT INTO retired_account_names (name_folded) VALUES ($1)
         ON CONFLICT (name_folded) DO NOTHING",
    )
    .bind(&folded)
    .execute(&mut *transaction)
    .await
    .map_err(query_error)?;
    // Account-owned rows go in one fixed table order — messages, bouncer
    // backlog, device grants, invitations, then the account (whose cascade
    // takes the rest) — the order every other multi-table writer uses, so two
    // of them can never each hold a lock the other waits for.
    loop {
        let deleted = sqlx::query(concat!(
            "DELETE FROM messages WHERE id = ANY(ARRAY(SELECT id FROM messages WHERE ",
            account_messages_predicate!(),
            " LIMIT $3))"
        ))
        .bind(&folded)
        .bind(&name)
        .bind(ACCOUNT_PURGE_BATCH)
        .execute(&mut *transaction)
        .await
        .map_err(query_error)?
        .rows_affected();
        if deleted < ACCOUNT_PURGE_BATCH as u64 {
            break;
        }
    }
    sqlx::query("DELETE FROM bnc_buffer WHERE owner = $1")
        .bind(&folded)
        .execute(&mut *transaction)
        .await
        .map_err(query_error)?;
    sqlx::query("DELETE FROM device_grants WHERE account_id = $1")
        .bind(account_id)
        .execute(&mut *transaction)
        .await
        .map_err(query_error)?;
    sqlx::query(
        "DELETE FROM account_invitations
         WHERE name_folded = $1 OR created_by = $1",
    )
    .bind(&folded)
    .execute(&mut *transaction)
    .await
    .map_err(query_error)?;
    for (channel, successor) in &successions {
        insert_audit_log_with(
            &mut *transaction,
            &AuditPrincipal::account(&actor_folded),
            "CHANNEL_SUCCESSION",
            &AuditPrincipal::channel(channel),
            &format!("founder={folded} successor={successor}"),
        )
        .await?;
    }
    insert_audit_log_with(
        &mut *transaction,
        &AuditPrincipal::account(&actor_folded),
        "ACCOUNT_DELETE",
        &AuditPrincipal::account(&folded),
        "account and account-owned data permanently removed; name retired",
    )
    .await?;
    sqlx::query("DELETE FROM accounts WHERE id = $1")
        .bind(account_id)
        .execute(&mut *transaction)
        .await
        .map_err(query_error)?;
    transaction.commit().await.map_err(query_error)?;
    Ok(Some(DeletedAccount {
        name,
        successions: successions
            .into_iter()
            .map(|(channel, founder)| ChannelSuccession { channel, founder })
            .collect(),
    }))
}

/// Durable account posture used by authentication and administrator gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountFlags(i64);

impl AccountFlags {
    pub fn is_admin(self) -> bool {
        self.0 & ACCOUNT_FLAG_ADMIN != 0
    }

    pub fn is_suspended(self) -> bool {
        self.0 & ACCOUNT_FLAG_SUSPENDED != 0
    }
}

pub async fn account_flags(pool: &PgPool, account: &str) -> Result<Option<AccountFlags>, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    sqlx::query_scalar("SELECT flags FROM accounts WHERE name_folded = $1")
        .bind(folded)
        .fetch_optional(pool)
        .await
        .map(|flags| flags.map(AccountFlags))
        .map_err(query_error)
}

pub async fn account_id_by_name(pool: &PgPool, account: &str) -> Result<Option<i64>, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    sqlx::query_scalar("SELECT id FROM accounts WHERE name_folded = $1")
        .bind(folded)
        .fetch_optional(pool)
        .await
        .map_err(query_error)
}

/// Folded account keys whose durable suspension must be seeded into the core
/// before it accepts an authentication verdict.
pub async fn list_suspended_accounts(pool: &PgPool) -> Result<Vec<String>, DbError> {
    sqlx::query_scalar("SELECT name_folded FROM accounts WHERE (flags & $1) = $1 ORDER BY id")
        .bind(ACCOUNT_FLAG_SUSPENDED)
        .fetch_all(pool)
        .await
        .map_err(query_error)
}

pub async fn account_name_by_id(pool: &PgPool, account_id: i64) -> Result<Option<String>, DbError> {
    sqlx::query_scalar("SELECT name FROM accounts WHERE id = $1")
        .bind(account_id)
        .fetch_optional(pool)
        .await
        .map_err(query_error)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountStateChange {
    pub name: String,
    pub folded: String,
    pub suspended: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountAuthorityChange {
    pub name: String,
    pub folded: String,
    pub administrator: bool,
}

#[derive(sqlx::FromRow)]
struct LockedAccountState {
    name: String,
    folded: String,
    flags: i64,
}

const ACCOUNT_AUTHORITY_ADVISORY_LOCK_KEY: i64 = 0x6536_6972_6300_0003;

/// Lock one account for a change to its authority: administrator rights,
/// suspension, or deletion.
///
/// The row lock alone is not enough. Whether a change may go ahead depends on
/// *other* rows — is another active administrator left? — and two transactions
/// that each lock a different account both answer yes from their own snapshot,
/// then both commit, leaving none. So every authority change first takes one
/// transaction-scoped advisory lock: they run one at a time, and each counts
/// the administrators the previous one left behind.
async fn lock_account_state(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: i64,
    change: AccountStateChangeKind,
) -> Result<Option<LockedAccountState>, DbError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(ACCOUNT_AUTHORITY_ADVISORY_LOCK_KEY)
        .execute(&mut **transaction)
        .await
        .map_err(query_error)?;
    sqlx::query_as(match change {
        AccountStateChangeKind::Flags => {
            "SELECT name, name_folded AS folded, flags FROM accounts WHERE id = $1
             FOR NO KEY UPDATE"
        }
        AccountStateChangeKind::Deletion => {
            "SELECT name, name_folded AS folded, flags FROM accounts WHERE id = $1
             FOR UPDATE"
        }
    })
    .bind(account_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(query_error)
}

/// What an authority change will do to the account row, which decides how
/// strongly [`lock_account_state`] locks it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccountStateChangeKind {
    /// Rewrites `flags` only; rows referencing the account are unaffected, so
    /// `FOR NO KEY UPDATE` leaves foreign-key checks (`FOR KEY SHARE`) free.
    Flags,
    /// Deletes the row, after counting what still refers to it (founded
    /// channels) and purging what names it (messages). Every insert or update
    /// that references the account takes `FOR KEY SHARE` on its row -- a
    /// foreign-key check, or the `messages` deleted-account trigger (migration
    /// 0072) -- and only `FOR UPDATE` conflicts with that. So such a write
    /// either commits before deletion counts and purges, or meets the lock
    /// (a foreign key waits and then fails; the trigger drops the row); it
    /// can never land between count and delete.
    Deletion,
}

/// Preserve the system-wide invariant that an account mutation cannot remove
/// the final active administrator, regardless of whether that authority came
/// from durable flags or configuration.
async fn require_other_active_administrator<'e, E>(
    executor: E,
    account_id: i64,
    configured_administrators: &[String],
) -> Result<(), DbError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let other_active_administrators: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM accounts
         WHERE id <> $1
           AND (flags & $3) = 0
           AND ((flags & $2) = $2 OR name_folded = ANY($4))",
    )
    .bind(account_id)
    .bind(ACCOUNT_FLAG_ADMIN)
    .bind(ACCOUNT_FLAG_SUSPENDED)
    .bind(configured_administrators)
    .fetch_one(executor)
    .await
    .map_err(query_error)?;
    if other_active_administrators == 0 {
        return Err(DbError::LastAdministrator);
    }
    Ok(())
}

async fn write_account_flags(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: i64,
    flags: i64,
) -> Result<(), DbError> {
    sqlx::query("UPDATE accounts SET flags = $1 WHERE id = $2")
        .bind(flags)
        .bind(account_id)
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(query_error)
}

/// Lock one active account row for a credential/session issuance transaction.
/// Every issuance path must reject deleted and suspended accounts under the
/// same lock before it counts or inserts account-owned authority.
async fn lock_active_account_id(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    folded: &str,
) -> Result<i64, DbError> {
    let account_id: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM accounts
         WHERE name_folded = $1 AND (flags & $2) = 0
         FOR NO KEY UPDATE",
    )
    .bind(folded)
    .bind(ACCOUNT_FLAG_SUSPENDED)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(query_error)?;
    account_id.ok_or(DbError::BadCredentials)
}

/// Grant or revoke durable administrator authority by immutable account ID.
/// The actor cannot demote itself and the final active effective
/// durable-or-configured administrator cannot be removed, so every committed
/// state retains a recovery path.
pub async fn set_account_administrator(
    pool: &PgPool,
    account_id: i64,
    administrator: bool,
    actor: &str,
    configured_administrators: &[String],
) -> Result<Option<AccountAuthorityChange>, DbError> {
    let actor_folded = CaseMapping::Rfc1459.casefold(actor);
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let Some(LockedAccountState {
        name,
        folded,
        flags,
    }) = lock_account_state(&mut transaction, account_id, AccountStateChangeKind::Flags).await?
    else {
        return Ok(None);
    };
    if !administrator && folded == actor_folded {
        return Err(DbError::CannotDemoteSelf);
    }
    if !administrator
        && flags & ACCOUNT_FLAG_ADMIN != 0
        && !configured_administrators.contains(&folded)
    {
        require_other_active_administrator(
            &mut *transaction,
            account_id,
            configured_administrators,
        )
        .await?;
    }
    let next_flags = if administrator {
        flags | ACCOUNT_FLAG_ADMIN
    } else {
        flags & !ACCOUNT_FLAG_ADMIN
    };
    write_account_flags(&mut transaction, account_id, next_flags).await?;
    // Invitations are issued on administrator authority; losing it ends them,
    // unless configuration still grants the account that authority.
    if !administrator && !configured_administrators.contains(&folded) {
        revoke_issued_invitations(
            &mut transaction,
            &folded,
            &AuditPrincipal::account(&actor_folded),
            "issuer's administrator authority was revoked",
        )
        .await?;
    }
    let action = if administrator {
        "ACCOUNT_ADMIN_GRANT"
    } else {
        "ACCOUNT_ADMIN_REVOKE"
    };
    insert_audit_log_with(
        &mut *transaction,
        &AuditPrincipal::account(&actor_folded),
        action,
        &AuditPrincipal::account(&folded),
        "",
    )
    .await?;
    transaction.commit().await.map_err(query_error)?;
    Ok(Some(AccountAuthorityChange {
        name,
        folded,
        administrator,
    }))
}

/// Suspend or reactivate one account by immutable id. Suspension, credential
/// revocation, and its audit record commit together; no request can observe a
/// suspended flag while retaining an older browser/PAT/device grant.
pub async fn set_account_suspended(
    pool: &PgPool,
    account_id: i64,
    suspended: bool,
    actor: &str,
    configured_administrators: &[String],
) -> Result<Option<AccountStateChange>, DbError> {
    let actor_folded = CaseMapping::Rfc1459.casefold(actor);
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let Some(LockedAccountState {
        name,
        folded,
        flags,
    }) = lock_account_state(&mut transaction, account_id, AccountStateChangeKind::Flags).await?
    else {
        return Ok(None);
    };
    if suspended && folded == actor_folded {
        return Err(DbError::CannotSuspendSelf);
    }
    if suspended && (flags & ACCOUNT_FLAG_ADMIN != 0 || configured_administrators.contains(&folded))
    {
        require_other_active_administrator(
            &mut *transaction,
            account_id,
            configured_administrators,
        )
        .await?;
    }
    let next_flags = if suspended {
        flags | ACCOUNT_FLAG_SUSPENDED
    } else {
        flags & !ACCOUNT_FLAG_SUSPENDED
    };
    write_account_flags(&mut transaction, account_id, next_flags).await?;
    if suspended {
        revoke_account_bearers(&mut transaction, account_id).await?;
        revoke_issued_invitations(
            &mut transaction,
            &folded,
            &AuditPrincipal::account(&actor_folded),
            "issuer was suspended",
        )
        .await?;
    }
    let action = if suspended {
        "ACCOUNT_SUSPEND"
    } else {
        "ACCOUNT_REACTIVATE"
    };
    insert_audit_log_with(
        &mut *transaction,
        &AuditPrincipal::account(&actor_folded),
        action,
        &AuditPrincipal::account(&folded),
        "",
    )
    .await?;
    transaction.commit().await.map_err(query_error)?;
    Ok(Some(AccountStateChange {
        name,
        folded,
        suspended,
    }))
}

/// Revoke every bearer of an account's authority that is not a password: its
/// browser sessions, personal access tokens, and device grants. Suspension and
/// administrator recovery both end an account's existing access, and they must
/// end the same set — a revocation that forgets one table leaves a live
/// credential behind.
async fn revoke_account_bearers(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: i64,
) -> Result<(), DbError> {
    sqlx::query("DELETE FROM web_sessions WHERE account_id = $1")
        .bind(account_id)
        .execute(&mut **transaction)
        .await
        .map_err(query_error)?;
    sqlx::query("DELETE FROM api_tokens WHERE account_id = $1")
        .bind(account_id)
        .execute(&mut **transaction)
        .await
        .map_err(query_error)?;
    sqlx::query("DELETE FROM device_grants WHERE account_id = $1")
        .bind(account_id)
        .execute(&mut **transaction)
        .await
        .map_err(query_error)?;
    Ok(())
}

/// End every live invitation `issuer` minted, inside the caller's
/// transaction, with one `ACCOUNT_INVITATION_REVOKE` audit row each naming
/// `actor` and `reason`. An invitation is a deferred use of its issuer's
/// administrator authority; when that authority ends — suspension, demotion,
/// or a recovery that presumes the issuer's credentials were in someone else's
/// hands — so do they.
async fn revoke_issued_invitations(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    issuer: &str,
    actor: &AuditPrincipal,
    reason: &str,
) -> Result<(), DbError> {
    let revoked: Vec<String> = sqlx::query_scalar(
        "UPDATE account_invitations
         SET consumed_at = now()
         WHERE created_by = $1 AND consumed_at IS NULL AND expires_at > now()
         RETURNING name_folded",
    )
    .bind(issuer)
    .fetch_all(&mut **transaction)
    .await
    .map_err(query_error)?;
    for invited in revoked {
        insert_audit_log_with(
            &mut **transaction,
            actor,
            "ACCOUNT_INVITATION_REVOKE",
            &AuditPrincipal::invitation(&invited),
            reason,
        )
        .await?;
    }
    Ok(())
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
/// blocking pool is ~512 threads ⇒ ~10 GiB). Enforced at the only three
/// functions that compute Argon2 — `hash_password`, `matching_credential_id`,
/// and `spend_dummy_verification` — so no caller can bypass it. A permit covers
/// a bounded amount of work: a login attempt is two computations (see
/// `plan_credential_verification`), everything else is one.
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

struct CredentialHash {
    credential_id: i64,
    argon2_hash: String,
}

/// One of an account's stored credentials, as a login attempt sees it.
#[derive(Clone, sqlx::FromRow)]
struct StoredCredential {
    credential_id: i64,
    argon2_hash: String,
    /// [`app_password_lookup`] of the secret. Exactly the app passwords carry
    /// one (a CHECK constraint says so), so its absence is what marks the
    /// primary password.
    app_password_lookup: Option<Vec<u8>>,
}

/// What names an app password's row. The secret is 32 random bytes, so its
/// SHA-256 identifies it without helping anyone guess it — the way personal
/// access tokens and browser sessions are already found.
fn app_password_lookup(secret: &str) -> Vec<u8> {
    token_hash(secret)
}

/// The Argon2 work one login attempt will do.
struct CredentialVerificationPlan {
    /// Stored hashes the presented password could match.
    candidates: Vec<CredentialHash>,
    /// Verifications against the dummy hash, spent so the attempt costs the
    /// same whatever the account holds.
    dummies: usize,
}

/// Decide what to verify `presented` against.
///
/// Trying every stored hash made one guess cost up to 33 Argon2 computations
/// under a single permit of the four the whole process has, and made the time
/// an attempt took a count of the account's credentials — zero for an account
/// that does not exist. Instead an attempt verifies the primary password, and
/// the one app password whose lookup `presented` hashes to; whichever of the
/// two is missing is replaced by a dummy. Every attempt therefore costs exactly
/// two computations.
fn plan_credential_verification(
    stored: Vec<StoredCredential>,
    presented: &str,
) -> CredentialVerificationPlan {
    let lookup = app_password_lookup(presented);
    let (mut primary, mut named) = (None, None);
    for credential in stored {
        match &credential.app_password_lookup {
            None => primary = Some(credential),
            Some(stored_lookup) if *stored_lookup == lookup => named = Some(credential),
            Some(_) => {}
        }
    }
    let dummies = usize::from(primary.is_none()) + usize::from(named.is_none());
    let candidates = primary
        .into_iter()
        .chain(named)
        .map(|credential| CredentialHash {
            credential_id: credential.credential_id,
            argon2_hash: credential.argon2_hash,
        })
        .collect();
    CredentialVerificationPlan {
        candidates,
        dummies,
    }
}

/// Verify every supplied credential without short-circuiting.
///
/// A stored hash that does not parse is damaged data, not a wrong password:
/// it can never verify, and answering "rejected" would hide the damage behind
/// what looks like a typo. It is logged by credential id — never the hash —
/// and, unless another credential matches, the verification fails as a store
/// fault so every caller's error path reports and counts it. The login still
/// fails closed either way.
async fn matching_credential_id(
    credentials: Vec<CredentialHash>,
    dummies: usize,
    password: String,
) -> Result<Option<i64>, DbError> {
    let _permit = ARGON2_PERMITS
        .acquire()
        .await
        .expect("argon2 semaphore never closed");
    tokio::task::spawn_blocking(move || {
        let mut matched_id = None;
        let mut unreadable = None;
        for _ in 0..dummies {
            let parsed = PasswordHash::new(dummy_verify_hash()).expect("dummy hash parses");
            let _ = hasher().verify_password(password.as_bytes(), &parsed);
        }
        for credential in &credentials {
            match PasswordHash::new(&credential.argon2_hash) {
                Ok(parsed) => {
                    if hasher()
                        .verify_password(password.as_bytes(), &parsed)
                        .is_ok()
                    {
                        matched_id = Some(credential.credential_id);
                    }
                }
                Err(error) => {
                    eprintln!(
                        "db: stored password hash of credential {} is unreadable ({error}); \
                         it can never verify until it is reset",
                        credential.credential_id
                    );
                    unreadable = Some(error);
                }
            }
        }
        match (matched_id, unreadable) {
            (None, Some(error)) => Err(DbError::Hash(error)),
            (matched_id, _) => Ok(matched_id),
        }
    })
    .await
    .expect("verification task panicked")
}

async fn spend_dummy_verification(password: String) {
    let _permit = ARGON2_PERMITS
        .acquire()
        .await
        .expect("argon2 semaphore never closed");
    tokio::task::spawn_blocking(move || {
        let parsed = PasswordHash::new(dummy_verify_hash()).expect("dummy hash parses");
        let _ = hasher().verify_password(password.as_bytes(), &parsed);
    })
    .await
    .expect("verification task panicked");
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
    if verify_local_password(pool, account, password)
        .await?
        .is_none()
    {
        return Err(DbError::BadCredentials);
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
    // run inside one transaction with the account row locked (FOR NO KEY
    // UPDATE: it serializes the cap without blocking foreign-key inserts):
    // separate pool statements would each see a pre-insert snapshot, so two
    // concurrent requests reading cap-1 would both insert and overshoot the
    // cap the comment promises (this endpoint runs on the concurrent REST
    // layer, not the serial worker).
    let mut tx = pool.begin().await.map_err(query_error)?;
    // The account row was gone (deleted since authentication): reject rather
    // than hand back an app password that was never stored.
    let account_id = lock_active_account_id(&mut tx, &folded).await?;
    let app_pw_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM account_credentials
         WHERE account_id = $1 AND kind = 'app_password'",
    )
    .bind(account_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(query_error)?;
    if app_pw_count >= MAX_APP_PASSWORDS_PER_ACCOUNT {
        return Err(DbError::TooManyCredentials);
    }
    sqlx::query(
        "INSERT INTO account_credentials (account_id, kind, argon2_hash, label, secret_lookup)
         VALUES ($1, 'app_password', $2, $3, $4)",
    )
    .bind(account_id)
    .bind(&hash)
    .bind(label)
    .bind(app_password_lookup(&secret))
    .execute(&mut *tx)
    .await
    .map_err(query_error)?;
    insert_audit_log_with(
        &mut *tx,
        &AuditPrincipal::account(&folded),
        "ACCOUNT_APP_PASSWORD_CREATE",
        &AuditPrincipal::account(&folded),
        "app password created",
    )
    .await?;
    tx.commit().await.map_err(query_error)?;
    Ok(secret)
}

/// One worker loop; run as a task. Replies always reach the core (or
/// the core is gone and the server is shutting down).
// dead-pub-allow: integration tests drive the real worker loop with `DbRequest`s; the server's entry point, `run_worker_observed`, takes the crate-private `Telemetry` and cannot be called from a test crate.
pub async fn run_worker(
    pool: PgPool,
    mut rx: Receiver<DbRequest>,
    core_tx: crate::core::CoreIngress,
) {
    run_worker_inner(pool, &mut rx, core_tx, None, None).await;
}

/// Spawn one offloaded DB request: run `work` against the pool, time it into
/// telemetry (recording an error when the reply reports the store
/// unavailable), and push the reply to the core. Offloaded requests (argon2
/// verify/hash) run off the serial worker loop so a burst can't
/// head-of-line-block queued reads behind one serial argon2 at a time.
fn spawn_db_offload<F>(
    pool: &PgPool,
    core_tx: &crate::core::CoreIngress,
    telemetry: &Option<std::sync::Arc<Telemetry>>,
    conn: crate::core::ConnId,
    work: impl FnOnce(PgPool) -> F + Send + 'static,
) where
    F: std::future::Future<Output = (DbReply, bool)> + Send + 'static,
{
    let pool = pool.clone();
    let core_tx = core_tx.clone();
    let telemetry = telemetry.clone();
    tokio::spawn(async move {
        let started = Instant::now();
        let (reply, unavailable) = work(pool).await;
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

/// The server's database worker. `account_deletion` carries out NickServ DROP;
/// it exists whenever the database does (the network registry is built with
/// it).
pub(crate) async fn run_worker_observed(
    pool: PgPool,
    mut rx: Receiver<DbRequest>,
    core_tx: crate::core::CoreIngress,
    telemetry: Arc<Telemetry>,
    account_deletion: crate::account_deletion::AccountDeletion,
) {
    run_worker_inner(
        pool,
        &mut rx,
        core_tx,
        Some(telemetry),
        Some(account_deletion),
    )
    .await;
}

async fn run_worker_inner(
    pool: PgPool,
    rx: &mut Receiver<DbRequest>,
    core_tx: crate::core::CoreIngress,
    telemetry: Option<Arc<Telemetry>>,
    account_deletion: Option<crate::account_deletion::AccountDeletion>,
) {
    let mut log_batch: Vec<DbRequest> = Vec::new();
    while let Some(envelope) = rx.pop().await {
        let mut next = Some(envelope.payload);
        while let Some(request) = next.take() {
            match request {
                DbRequest::LogMessage { .. } => {
                    log_batch.push(request);
                    // A drain of nothing but messages contains no await at all,
                    // so the batch grew for as long as producers kept the queue
                    // non-empty — one INSERT sized to the burst, and no yield to
                    // the runtime meanwhile. A full batch is written here.
                    if log_batch.len() >= MAX_LOG_BATCH {
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
                }
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
                    spawn_db_offload(&pool, &core_tx, &telemetry, conn, move |pool| async move {
                        let outcome = handle_verify(&pool, &account, &password).await;
                        let unavailable = matches!(&outcome, VerifyOutcome::Unavailable);
                        (outcome.into_reply(origin), unavailable)
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
                    contact_email,
                    password,
                    origin,
                } => {
                    spawn_db_offload(&pool, &core_tx, &telemetry, conn, move |pool| async move {
                        let reply = handle_create_account(
                            &pool,
                            name,
                            contact_email.as_ref(),
                            &password,
                            origin,
                        )
                        .await;
                        let unavailable =
                            matches!(&reply, DbReply::AccountRegisterUnavailable { .. });
                        (reply, unavailable)
                    });
                }
                // A drop verifies a password (argon2) and then runs the whole
                // deletion — gate, network stop, purge, core broadcast — whose
                // core round trips must not stall this loop: offloaded like a
                // verify.
                DbRequest::DropAccount {
                    conn,
                    account,
                    password,
                    label,
                } => {
                    let deletion = account_deletion.clone();
                    spawn_db_offload(&pool, &core_tx, &telemetry, conn, move |pool| async move {
                        let outcome = crate::account_deletion::nickserv_drop(
                            &pool,
                            deletion.as_ref(),
                            &account,
                            &password,
                        )
                        .await;
                        let unavailable =
                            matches!(outcome, crate::core::AccountDropOutcome::Unavailable);
                        let reply = DbReply::AccountDrop {
                            account,
                            outcome,
                            label,
                        };
                        (reply, unavailable)
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
/// Messages written in one `INSERT … UNNEST`. The drain writes at this size
/// rather than at whatever a burst accumulated: it bounds the statement and
/// the vectors built for it, and gives the worker a yield point under load.
const MAX_LOG_BATCH: usize = 1_024;

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
    // casefolded participants, from which the `dm_conversations` triggers keep
    // the summary CHATHISTORY TARGETS reads.
    // Bound as the joined form and split back into an array in SQL: a
    // conversation has one or two participants, and Postgres arrays passed
    // through UNNEST must be rectangular, which a ragged nesting is not.
    let mut peers: Vec<Option<String>> = Vec::with_capacity(n);
    let mut bots: Vec<bool> = Vec::with_capacity(n);
    // NULL for an ordinary message; the encoded lines for a draft/multiline one
    // (see `core::handler::message::encode_multiline`), authoritative on replay.
    let mut multilines: Vec<Option<String>> = Vec::with_capacity(n);
    let mut client_tags_column: Vec<String> = Vec::with_capacity(n);
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
            client_tags,
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
        client_tags_column.push(client_tags);
        let Ok(ts) = millis_for_database(ts, "messages.ts") else {
            eprintln!("db: message logging skipped: timestamp exceeds exact database range");
            return false;
        };
        tss.push(ts);
    }
    let result = sqlx::query(
        "INSERT INTO messages (msgid, target, sender_prefix, sender_account, kind, body, ts, dm_peers, sender_is_bot, multiline, client_tags)
         SELECT m, t, p, a, k, b, at,
                CASE WHEN d IS NULL THEN NULL ELSE string_to_array(d, '!') END,
                bot, ml, ct
         FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[],
                     ARRAY(SELECT to_timestamp(x / 1000.0) FROM UNNEST($7::bigint[]) x),
                     $8::text[], $9::bool[], $10::text[], $11::text[])
              AS u(m, t, p, a, k, b, at, d, bot, ml, ct)
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
    .bind(&client_tags_column)
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

async fn push_channel_service_persisted(
    core_tx: &crate::core::CoreIngress,
    owner: crate::core::ChannelOwner,
    session: crate::core::SessionOwner,
    result: crate::core::ChannelServicePersistence,
) -> bool {
    core_tx
        .push(Input::ChannelServicePersisted {
            owner,
            session,
            result,
        })
        .await
        .is_ok()
}

/// Handle one non-history request; false = core gone, stop the worker.
async fn handle_request(
    pool: &PgPool,
    core_tx: &crate::core::CoreIngress,
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
            owner,
            session,
            channel,
            founder_account,
            topic,
            label,
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
                    eprintln!("db: channel registration failed: {error}");
                    crate::core::ChannelRegistrationResult::Unavailable
                }
            };
            // Counted here, once, for both ways of being unavailable: the
            // error arm above used to count it too, so every failed
            // registration was recorded as two database errors.
            if matches!(result, crate::core::ChannelRegistrationResult::Unavailable) {
                record_database_error(telemetry);
            }
            core_tx
                .push(Input::ChannelRegistrationPersisted {
                    owner,
                    session,
                    channel,
                    founder_account,
                    topic,
                    label,
                    result,
                })
                .await
                .is_ok()
        }
        DbRequest::RegisterOwnedChannel {
            owner,
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
                    owner,
                    request_id,
                    result,
                })
                .await
                .is_ok()
        }
        DbRequest::DropChannel {
            owner,
            channel,
            requester,
        } => {
            let dropped = match &requester {
                crate::core::ChannelDropRequester::Admin { actor, .. } => {
                    drop_channel(pool, &channel, ChannelDropper::Administrator(actor)).await
                }
                crate::core::ChannelDropRequester::ChanServ { actor, .. } => {
                    drop_channel(pool, &channel, ChannelDropper::Founder(actor)).await
                }
            };
            let result = match dropped {
                Ok(Ok(())) => crate::core::ChannelDropResult::Dropped,
                Ok(Err(ChannelRefusal::ChannelMissing)) => crate::core::ChannelDropResult::Missing,
                Ok(Err(ChannelRefusal::NotFounder)) => crate::core::ChannelDropResult::NotFounder,
                Err(e) => {
                    record_database_error(telemetry);
                    eprintln!("db: channel drop failed: {e}");
                    crate::core::ChannelDropResult::Unavailable
                }
            };
            core_tx
                .push(Input::ChannelDropResult {
                    owner,
                    channel,
                    requester,
                    result,
                })
                .await
                .is_ok()
        }
        DbRequest::SetChannelFounder {
            owner,
            session,
            channel,
            new_founder,
            label,
            actor,
        } => {
            let display = channel.clone();
            let result = match set_channel_founder(pool, &channel, &new_founder, &actor).await {
                Ok(FounderTransfer::Transferred { founder }) => {
                    crate::core::ChannelServicePersistence::FounderChanged {
                        channel,
                        account: founder,
                        display,
                        label,
                    }
                }
                Ok(FounderTransfer::AccountMissing) => {
                    crate::core::ChannelServicePersistence::FounderMissing {
                        channel,
                        display,
                        label,
                    }
                }
                Ok(FounderTransfer::LimitReached) => {
                    crate::core::ChannelServicePersistence::FounderLimitReached { display, label }
                }
                Ok(FounderTransfer::Refused(refusal)) => {
                    crate::core::ChannelServicePersistence::Refused {
                        display,
                        refusal,
                        label,
                    }
                }
                Err(e) => {
                    record_database_error(telemetry);
                    eprintln!("db: founder transfer failed: {e}");
                    crate::core::ChannelServicePersistence::FounderUnavailable {
                        channel,
                        display,
                        label,
                    }
                }
            };
            push_channel_service_persisted(core_tx, owner, session, result).await
        }
        DbRequest::QueryHistory {
            conn,
            target,
            floor,
            display,
            batch_ref,
            caps,
            query,
            label,
        } => {
            let rows = async {
                let scope = crate::core::HistoryScope::from(caps);
                let rows =
                    query_history_in_scope(pool, &target, floor, query.clone(), scope).await?;
                if rows.is_empty()
                    && positioned_by_unknown_msgid(pool, &target, floor, &query).await?
                {
                    return Ok(Err(crate::core::HistoryFault::UnknownMsgid {
                        subcommand: query.subcommand(),
                    }));
                }
                Ok(Ok(rows))
            }
            .await
            .unwrap_or_else(|e: DbError| {
                record_database_error(telemetry);
                // The error string is logged here; the core only needs to know
                // it failed so it can FAIL the CHATHISTORY rather than reply
                // with a misleading empty page.
                eprintln!("db: history query failed: {e}");
                Err(crate::core::HistoryFault::Unavailable {
                    subcommand: query.subcommand(),
                })
            });
            core_tx
                .push(Input::HistoryPage {
                    conn,
                    display,
                    batch_ref,
                    caps,
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
            session_only,
            min_ts,
            max_ts,
            limit,
            batch_ref,
            caps,
            label,
        } => {
            let scope = crate::core::HistoryScope::from(caps);
            let targets =
                query_targets(pool, &channels, me.as_deref(), scope, min_ts, max_ts, limit)
                    .await
                    .map(|mut targets| {
                        // Same order and bound as the query: oldest activity first.
                        targets.extend(session_only);
                        targets.sort_by_key(|(_, latest)| *latest);
                        targets.truncate(limit);
                        targets
                    })
                    .map_err(|e| {
                        record_database_error(telemetry);
                        eprintln!("db: targets query failed: {e}");
                    });
            core_tx
                .push(Input::TargetsPage {
                    conn,
                    batch_ref,
                    caps,
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
                Ok(ReadMarkerWrite::Stored(marker_ms)) => crate::core::DbReply::ReadMarkerStored {
                    account,
                    target,
                    display,
                    marker_ms,
                    label,
                },
                Ok(ReadMarkerWrite::LimitReached) => crate::core::DbReply::ReadMarkerLimitReached {
                    account,
                    target,
                    display,
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
            owner,
            session,
            channel,
            display,
            prefix,
            origin,
            topic,
            revision,
            label,
        } => {
            let result = match set_channel_topic(pool, &channel, topic.clone()).await {
                Ok(Some(retained)) => crate::core::ChannelTopicPersistence::Set {
                    channel,
                    display,
                    prefix,
                    origin,
                    topic,
                    revision,
                    retained,
                    label,
                },
                Ok(None) => crate::core::ChannelTopicPersistence::Failed {
                    channel,
                    display,
                    revision,
                    label,
                    failure: crate::core::ChannelTopicFailure::MissingRegistration,
                },
                Err(e) => {
                    record_database_error(telemetry);
                    eprintln!("db: channel topic persistence failed: {e}");
                    crate::core::ChannelTopicPersistence::Failed {
                        channel,
                        display,
                        revision,
                        label,
                        failure: crate::core::ChannelTopicFailure::PersistenceUnavailable,
                    }
                }
            };
            core_tx
                .push(Input::ChannelTopicPersisted {
                    owner,
                    conn: session.conn(),
                    session: Some(session),
                    result,
                })
                .await
                .is_ok()
        }
        DbRequest::SetChannelKeeptopic {
            owner,
            session,
            channel,
            display,
            keeptopic,
            topic,
            label,
            actor,
        } => {
            let result =
                match set_channel_keeptopic(pool, &channel, keeptopic, topic.clone(), &actor).await
                {
                    Ok(Ok(())) => crate::core::ChannelServicePersistence::KeeptopicSet {
                        channel,
                        display,
                        keeptopic,
                        topic,
                        label,
                    },
                    Ok(Err(refusal)) => crate::core::ChannelServicePersistence::Refused {
                        display,
                        refusal,
                        label,
                    },
                    Err(e) => {
                        record_database_error(telemetry);
                        eprintln!("db: channel keeptopic persistence failed: {e}");
                        crate::core::ChannelServicePersistence::KeeptopicUnavailable {
                            channel,
                            display,
                            label,
                        }
                    }
                };
            push_channel_service_persisted(core_tx, owner, session, result).await
        }
        DbRequest::SetChannelMlock {
            owner,
            session,
            channel,
            display,
            mlock,
            label,
            actor,
        } => {
            let result = match set_channel_mlock(pool, &channel, mlock.clone(), &actor).await {
                Ok(Ok(())) => crate::core::ChannelServicePersistence::MlockSet {
                    channel,
                    display,
                    mlock,
                    label,
                },
                Ok(Err(refusal)) => crate::core::ChannelServicePersistence::Refused {
                    display,
                    refusal,
                    label,
                },
                Err(e) => {
                    record_database_error(telemetry);
                    eprintln!("db: channel mlock persistence failed: {e}");
                    crate::core::ChannelServicePersistence::MlockUnavailable {
                        channel,
                        display,
                        label,
                    }
                }
            };
            push_channel_service_persisted(core_tx, owner, session, result).await
        }
        DbRequest::SetChannelAccess {
            owner,
            session,
            channel,
            display,
            account,
            flags,
            frontend,
            label,
            actor,
        } => {
            // A store fault is not "account is not registered" — those are
            // different replies, so the operator is never told a definitive
            // negative that was really a transient DB failure.
            let result =
                match set_channel_access(pool, &channel, &account, flags.clone(), &actor).await {
                    Ok(AccessChange::Applied { account, previous }) => {
                        crate::core::ChannelServicePersistence::AccessSet {
                            channel,
                            display,
                            account,
                            flags,
                            previous,
                            frontend,
                            label,
                        }
                    }
                    Ok(AccessChange::AccountMissing) => {
                        crate::core::ChannelServicePersistence::AccessAccountMissing {
                            display,
                            account,
                            frontend,
                            label,
                        }
                    }
                    Ok(AccessChange::LimitReached) => {
                        crate::core::ChannelServicePersistence::AccessLimitReached {
                            channel,
                            display,
                            label,
                        }
                    }
                    Ok(AccessChange::Refused(refusal)) => {
                        crate::core::ChannelServicePersistence::Refused {
                            display,
                            refusal,
                            label,
                        }
                    }
                    Err(e) => {
                        record_database_error(telemetry);
                        eprintln!("db: channel access persistence failed: {e}");
                        crate::core::ChannelServicePersistence::AccessUnavailable {
                            channel,
                            display,
                            label,
                        }
                    }
                };
            push_channel_service_persisted(core_tx, owner, session, result).await
        }
        DbRequest::SetChannelSuccessor {
            owner,
            session,
            channel,
            successor,
            label,
            actor,
        } => {
            let outcome = set_channel_successor(pool, &channel, successor.as_deref(), &actor)
                .await
                .map_err(|e| {
                    record_database_error(telemetry);
                    eprintln!("db: channel successor persistence failed: {e}");
                })
                .ok();
            let result = crate::core::ChannelServicePersistence::SuccessorSet {
                display: channel,
                successor,
                outcome,
                label,
            };
            push_channel_service_persisted(core_tx, owner, session, result).await
        }
        DbRequest::GroupNick {
            conn,
            account,
            nick,
            label,
        } => {
            let outcome = group_nick(pool, &account, &nick)
                .await
                .map_err(|e| {
                    record_database_error(telemetry);
                    eprintln!("db: nick grouping failed: {e}");
                })
                .ok();
            let reply = DbReply::NickGroup {
                account,
                nick,
                outcome,
                label,
            };
            core_tx.push(Input::DbReply { conn, reply }).await.is_ok()
        }
        DbRequest::UngroupNick {
            conn,
            account,
            nick,
            label,
        } => {
            let removed = ungroup_nick(pool, &account, &nick)
                .await
                .map_err(|e| {
                    record_database_error(telemetry);
                    eprintln!("db: nick ungrouping failed: {e}");
                })
                .ok();
            let reply = DbReply::NickUngroup {
                account,
                nick,
                removed,
                label,
            };
            core_tx.push(Input::DbReply { conn, reply }).await.is_ok()
        }
        DbRequest::SetNickEnforce {
            conn,
            account,
            enforce,
            label,
        } => {
            let outcome = set_nick_enforce(pool, &account, enforce)
                .await
                .map_err(|e| {
                    record_database_error(telemetry);
                    eprintln!("db: nick protection change failed: {e}");
                })
                .ok();
            let reply = DbReply::NickEnforce {
                account,
                enforce,
                outcome,
                label,
            };
            core_tx.push(Input::DbReply { conn, reply }).await.is_ok()
        }
        DbRequest::AccountInfo {
            conn,
            target,
            label,
        } => {
            let info = nickserv_account_info(pool, &target).await.map_err(|e| {
                record_database_error(telemetry);
                eprintln!("db: account information lookup failed: {e}");
            });
            let reply = DbReply::AccountInfo {
                target,
                info,
                label,
            };
            core_tx.push(Input::DbReply { conn, reply }).await.is_ok()
        }
        DbRequest::DropAccount { .. } => unreachable!("offloaded by run_worker"),
        DbRequest::MutateOwnedChannel {
            owner,
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
                    owner,
                    request_id,
                    result,
                })
                .await
                .is_ok()
        }
        DbRequest::MutateServerBan {
            mutation,
            requester,
        } => {
            let result =
                match mutate_server_ban_audited(pool, &mutation, &requester.audit_actor()).await {
                    Ok(true) => crate::core::ServerBanResult::Stored,
                    Ok(false) => crate::core::ServerBanResult::Missing,
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
    .map_err(query_error)
}

/// Every stored read marker as (account display name, target, epoch-millis),
/// for the core's boot-time preload of its hot mirror of the `read_markers`
/// table. Without this the mirror starts empty after a restart and MARKREAD
/// queries wrongly report `*` for markers that are in fact persisted.
pub async fn list_all_read_markers(
    pool: &PgPool,
) -> Result<Vec<(String, String, e6irc_proto::time::Millis)>, DbError> {
    let rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT a.name, r.target, (EXTRACT(EPOCH FROM r.marker_ts) * 1000)::bigint
         FROM read_markers r JOIN accounts a ON a.id = r.account_id",
    )
    .fetch_all(pool)
    .await
    .map_err(query_error)?;
    rows.into_iter()
        .map(|(account, target, millis)| {
            Ok((
                account,
                target,
                millis_from_database(millis, "read_markers.marker_ts")?,
            ))
        })
        .collect()
}

/// Most durable read markers one account may hold. Each core shard also keeps
/// the count in memory, but a shard only sees its own sessions' writes: with
/// several shards, only the database — where every write lands — can hold an
/// account to one cap.
pub const READ_MARKER_LIMIT: i64 = 256;

/// What became of one read-marker write.
enum ReadMarkerWrite {
    /// The marker PostgreSQL holds after the monotonic `GREATEST`.
    Stored(e6irc_proto::time::Millis),
    /// A new target, and the account already holds [`READ_MARKER_LIMIT`].
    LimitReached,
}

async fn set_read_marker(
    pool: &PgPool,
    account: &str,
    target: &str,
    marker_ms: e6irc_proto::time::Millis,
) -> Result<ReadMarkerWrite, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let marker = millis_for_database(marker_ms, "read_markers.marker_ts")?;
    let mut transaction = pool.begin().await.map_err(query_error)?;
    // The account row lock serializes this account's writers across shards, so
    // two cannot both count 255 and both insert. NO KEY UPDATE: the marker's
    // own foreign-key check (and any other account-referencing insert) takes
    // a KEY SHARE lock, which this does not block.
    let Some(account_id) = lock_account_id(&mut transaction, &folded).await? else {
        // The account name no longer resolves: an unavailable verdict, never a
        // false success.
        return Err(DbError::UnknownAccount(account.to_string()));
    };
    let (held, count): (bool, i64) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM read_markers WHERE account_id = $1 AND target = $2),
                (SELECT count(*) FROM read_markers WHERE account_id = $1)",
    )
    .bind(account_id)
    .bind(target)
    .fetch_one(&mut *transaction)
    .await
    .map_err(query_error)?;
    if !held && count >= READ_MARKER_LIMIT {
        return Ok(ReadMarkerWrite::LimitReached);
    }
    let stored: i64 = sqlx::query_scalar(
        "INSERT INTO read_markers (account_id, target, marker_ts)
         VALUES ($1, $2, to_timestamp($3::double precision / 1000))
         ON CONFLICT (account_id, target)
         DO UPDATE SET marker_ts = GREATEST(read_markers.marker_ts, EXCLUDED.marker_ts)
         RETURNING (EXTRACT(EPOCH FROM marker_ts) * 1000)::bigint",
    )
    .bind(account_id)
    .bind(target)
    .bind(marker)
    .fetch_one(&mut *transaction)
    .await
    .map_err(query_error)?;
    transaction.commit().await.map_err(query_error)?;
    millis_from_database(stored, "read_markers.marker_ts").map(ReadMarkerWrite::Stored)
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

#[derive(Debug, sqlx::FromRow)]
pub struct OidcIdentityRow {
    pub id: i64,
    pub issuer: String,
    pub subject: String,
    pub created_at: String,
}

/// Every OIDC identity linked to `account`, ordered for stable listing.
pub async fn list_oidc_identities(
    pool: &PgPool,
    account: &str,
) -> Result<Vec<OidcIdentityRow>, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    sqlx::query_as(
        "SELECT o.id, o.issuer, o.subject,
                to_char(o.created_at AT TIME ZONE 'UTC',
                        'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS created_at
         FROM oidc_identities o JOIN accounts a ON a.id = o.account_id
         WHERE a.name_folded = $1 ORDER BY o.issuer, o.subject, o.id",
    )
    .bind(&folded)
    .fetch_all(pool)
    .await
    .map_err(query_error)
}

#[derive(Debug, PartialEq, Eq)]
pub enum UnlinkIdentityOutcome {
    Unlinked,
    LastLoginMethod,
    NotFound,
}

#[derive(sqlx::FromRow)]
struct OidcIdentityReference {
    issuer: String,
    subject: String,
}

#[derive(sqlx::FromRow)]
struct LoginMethodCounts {
    identity_count: i64,
    has_local_password: bool,
}

/// Remove one linked identity without removing the last login method.
pub async fn unlink_oidc_identity(
    pool: &PgPool,
    account: &str,
    identity_id: i64,
) -> Result<UnlinkIdentityOutcome, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let mut tx = pool.begin().await.map_err(query_error)?;
    let account_id: Option<i64> =
        sqlx::query_scalar("SELECT id FROM accounts WHERE name_folded = $1 FOR NO KEY UPDATE")
            .bind(&folded)
            .fetch_optional(&mut *tx)
            .await
            .map_err(query_error)?;
    let Some(account_id) = account_id else {
        return Ok(UnlinkIdentityOutcome::NotFound);
    };
    let identity: Option<OidcIdentityReference> = sqlx::query_as(
        "SELECT issuer, subject FROM oidc_identities
         WHERE id = $1 AND account_id = $2",
    )
    .bind(identity_id)
    .bind(account_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(query_error)?;
    let Some(OidcIdentityReference { issuer, subject }) = identity else {
        return Ok(UnlinkIdentityOutcome::NotFound);
    };
    let LoginMethodCounts {
        identity_count,
        has_local_password,
    } = sqlx::query_as(
        "SELECT
             (SELECT count(*) FROM oidc_identities WHERE account_id = $1) AS identity_count,
             EXISTS(
                 SELECT 1 FROM account_credentials
                 WHERE account_id = $1 AND kind = 'local_password'
             ) AS has_local_password",
    )
    .bind(account_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(query_error)?;
    if identity_count <= 1 && !has_local_password {
        return Ok(UnlinkIdentityOutcome::LastLoginMethod);
    }
    sqlx::query("DELETE FROM oidc_identities WHERE id = $1 AND account_id = $2")
        .bind(identity_id)
        .bind(account_id)
        .execute(&mut *tx)
        .await
        .map_err(query_error)?;
    sqlx::query(
        "DELETE FROM web_sessions
         WHERE account_id = $1 AND oidc_issuer = $2 AND oidc_subject = $3",
    )
    .bind(account_id)
    .bind(issuer)
    .bind(subject)
    .execute(&mut *tx)
    .await
    .map_err(query_error)?;
    insert_audit_log_with(
        &mut *tx,
        &AuditPrincipal::account(&folded),
        "ACCOUNT_IDENTITY_UNLINK",
        &AuditPrincipal::account(&folded),
        "OpenID Connect identity unlinked and correlated sessions revoked",
    )
    .await?;
    tx.commit().await.map_err(query_error)?;
    Ok(UnlinkIdentityOutcome::Unlinked)
}

/// Attach an OIDC `(issuer, subject)` to `account`. Because the pair is
/// globally unique, an identity already owned by another account is a hard
/// [`LinkOutcome::Conflict`], never a silent move. A suspended account cannot
/// gain a login identity: the account is resolved through the same active-only
/// lock every other credential mutation uses.
pub async fn link_oidc_identity(
    pool: &PgPool,
    account: &str,
    issuer: &str,
    subject: &str,
) -> Result<LinkOutcome, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let account_id = lock_active_account_id(&mut transaction, &folded).await?;
    let inserted: Option<i64> = sqlx::query_scalar(
        "INSERT INTO oidc_identities (account_id, issuer, subject) VALUES ($1, $2, $3)
         ON CONFLICT (issuer, subject) DO NOTHING RETURNING id",
    )
    .bind(account_id)
    .bind(issuer)
    .bind(subject)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(query_error)?;
    if inserted.is_some() {
        insert_audit_log_with(
            &mut *transaction,
            &AuditPrincipal::account(&folded),
            "ACCOUNT_IDENTITY_LINK",
            &AuditPrincipal::account(&folded),
            "OpenID Connect identity linked",
        )
        .await?;
        transaction.commit().await.map_err(query_error)?;
        return Ok(LinkOutcome::Linked);
    }
    // The pair already exists; whose is it?
    let owner: i64 = sqlx::query_scalar(
        "SELECT account_id FROM oidc_identities WHERE issuer = $1 AND subject = $2",
    )
    .bind(issuer)
    .bind(subject)
    .fetch_one(&mut *transaction)
    .await
    .map_err(query_error)?;
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
        Some((text, setter, set_at)) => (
            Some(text),
            Some(setter),
            Some(seconds_for_database(set_at, "channels.topic_set_at")?),
        ),
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
    .map_err(query_error)
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
    client_tags: String,
}

/// Expand `$build!(@ <kind predicate>, <dm_conversations column>; ...)` once
/// per [`crate::core::HistoryScope`] and pick the statement for `$scope`.
///
/// What a scope means in SQL is written here and nowhere else: a reader that
/// cannot receive a TAGMSG has `messages` rows of that kind cut (before any
/// `LIMIT`, so it counts only rows the reader is sent), and reads the
/// `dm_conversations` time that ignores them (migration 0085). Every
/// scope-dependent statement is built through this, so a page, a window and
/// TARGETS cannot disagree about what a scope admits.
macro_rules! by_history_scope {
    ($scope:expr, $build:ident ! ( $($args:tt)* )) => {
        match $scope {
            crate::core::HistoryScope::TextAndTags => $build!(@ "", "latest_ts"; $($args)*),
            crate::core::HistoryScope::Text => {
                $build!(@ "AND kind <> 'tagmsg' ", "latest_text_ts"; $($args)*)
            }
        }
    };
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
    ($scope:expr, $rest:literal) => {
        by_history_scope!($scope, history_select!($rest))
    };
    (@ $kind:literal, $dm_latest:literal; $rest:literal) => {
        concat!(
            "SELECT msgid, (EXTRACT(EPOCH FROM ts) * 1000)::bigint AS ts_millis, sender_prefix, \
             sender_account, kind, body, sender_is_bot, multiline, client_tags FROM messages ",
            history_where!($kind),
            $rest
        )
    };
}

/// The predicate every history statement starts with: the target (`$1`), the
/// reader's floor (`$2`), and the scope's kind predicate.
macro_rules! history_where {
    ($kind:literal) => {
        concat!(
            "WHERE target = $1 AND ts >= to_timestamp($2::double precision / 1000) ",
            $kind
        )
    };
}

/// The windowed form: two bounded halves unioned, then ordered as one. The
/// inner select aliases the timestamp so the outer query can order by it, and
/// carries `ts`/`id` for that ordering.
macro_rules! history_window {
    ($scope:expr, $older:literal, $newer:literal) => {
        by_history_scope!($scope, history_window!($older, $newer))
    };
    (@ $kind:literal, $dm_latest:literal; $older:literal, $newer:literal) => {
        concat!(
            "SELECT msgid, ts_millis, sender_prefix, sender_account, kind, body, sender_is_bot, multiline, \
             client_tags FROM ( (SELECT msgid, \
             (EXTRACT(EPOCH FROM ts) * 1000)::bigint AS ts_millis, sender_prefix, sender_account, kind, \
             body, sender_is_bot, multiline, client_tags, ts, id FROM messages ",
            history_where!($kind),
            $older,
            ") UNION ALL (SELECT msgid, (EXTRACT(EPOCH FROM ts) * 1000)::bigint AS ts_millis, \
             sender_prefix, sender_account, kind, body, sender_is_bot, multiline, client_tags, ts, id \
             FROM messages ",
            history_where!($kind),
            $newer,
            ") ) w ORDER BY ts ASC, id ASC"
        )
    };
}

/// Whether `query` is positioned by a msgid that `target` holds no message for.
///
/// An unknown pivot makes the window's position NULL and the page empty — which
/// is also what a known pivot with nothing beyond it looks like. So an empty
/// page is only an answer once this says the pivot exists; when it returns
/// `true` the caller must fail loudly (`unknown msgid`) instead of serving the
/// empty page, or a client resuming from a vanished msgid reads "nothing newer"
/// as "up to date".
///
/// This asks the `messages` table, so it is authoritative exactly when the
/// database is the record for `target`: every REST read, and an IRC read whose
/// in-memory ring is incomplete. A caller answering from a *complete* ring (no
/// database, or a ring that still holds the target's whole history) must ask
/// the ring instead — a message may be in it and not yet flushed here. The
/// pivot is looked up within `target`, never globally: a msgid from another
/// buffer is unknown *here*. `target` is the stored key (a casefolded channel
/// name, or the conversation key of two accounts). Call it only after
/// [`query_history`] came back empty; a timestamp-positioned query has no
/// pivots and always yields `false`.
pub(crate) async fn positioned_by_unknown_msgid(
    pool: &PgPool,
    target: &str,
    floor: crate::core::HistoryFloor,
    query: &crate::core::HistoryQuery,
) -> Result<bool, DbError> {
    let floor = millis_for_database(floor.millis(), "history floor")?;
    for msgid in query.msgid_pivots() {
        let known: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM messages WHERE msgid = $1 AND target = $2
                           AND ts >= to_timestamp($3::double precision / 1000))",
        )
        .bind(msgid)
        .bind(target)
        .bind(floor)
        .fetch_one(pool)
        .await
        .map_err(query_error)?;
        if !known {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A page of `target`'s text messages — what the REST API serves, which has no
/// way to present a TAGMSG.
pub async fn query_history(
    pool: &PgPool,
    target: &str,
    floor: crate::core::HistoryFloor,
    query: crate::core::HistoryQuery,
) -> Result<Vec<crate::core::HistoryRow>, DbError> {
    query_history_in_scope(pool, target, floor, query, crate::core::HistoryScope::Text).await
}

/// A page of `target`'s history cut in the reader's `scope`.
pub(crate) async fn query_history_in_scope(
    pool: &PgPool,
    target: &str,
    floor: crate::core::HistoryFloor,
    query: crate::core::HistoryQuery,
    scope: crate::core::HistoryScope,
) -> Result<Vec<crate::core::HistoryRow>, DbError> {
    use crate::core::HistoryQuery;
    // Every statement below binds the target as `$1` and the floor as `$2`,
    // and reads only rows at or above it — pivots included, so a msgid from
    // before the floor is as unknown here as one from another buffer.
    let floor = millis_for_database(floor.millis(), "history floor")?;
    // BETWEEN resolves each pivot's `(ts, id)` in the DB and derives its own
    // direction, so it produces its final oldest-first order itself rather than
    // going through the shared newest-first reversal below.
    if let HistoryQuery::BetweenSelectors {
        first,
        second,
        limit,
    } = query
    {
        return query_between_selectors(pool, target, floor, &first, &second, limit, scope).await;
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
    // The one value, beside the target and floor, that positions a window.
    enum Position {
        Millis(i64),
        Msgid(String),
    }
    // Each branch names its statement, its position (`$3`) and its limits
    // (`$3` for LATEST, else `$4`, and `$5` for a window's newer half); the
    // statement is run once below, then returned oldest-first.
    let (sql, position, limit, newer_limit): (
        &'static str,
        Option<Position>,
        usize,
        Option<usize>,
    ) = match query {
        HistoryQuery::Latest { limit } => (
            history_select!(scope, "ORDER BY ts DESC, id DESC LIMIT $3"),
            None,
            limit,
            None,
        ),
        HistoryQuery::Before { before_ts, limit } => (
            history_select!(
                scope,
                "AND ts < to_timestamp($3::double precision / 1000) ORDER BY ts DESC, id DESC LIMIT $4"
            ),
            Some(Position::Millis(millis_for_database(
                before_ts,
                "history before selector",
            )?)),
            limit,
            None,
        ),
        // Bounded LATEST: newest-first within the bound, reversed below, so
        // a limit smaller than the number of messages after the bound keeps
        // the most recent ones rather than the oldest.
        HistoryQuery::LatestAfter { after_ts, limit } => (
            history_select!(
                scope,
                "AND ts > to_timestamp($3::double precision / 1000) ORDER BY ts DESC, id DESC LIMIT $4"
            ),
            Some(Position::Millis(millis_for_database(
                after_ts,
                "history after selector",
            )?)),
            limit,
            None,
        ),
        HistoryQuery::LatestAfterMsgid { msgid, limit } => (
            history_select!(
                scope,
                "AND (ts, id) > (SELECT ts, id FROM messages WHERE msgid = $3 AND target = $1 AND ts >= to_timestamp($2::double precision / 1000)) ORDER BY ts DESC, id DESC LIMIT $4"
            ),
            Some(Position::Msgid(msgid)),
            limit,
            None,
        ),
        HistoryQuery::After { after_ts, limit } => (
            history_select!(
                scope,
                "AND ts > to_timestamp($3::double precision / 1000) ORDER BY ts ASC, id ASC LIMIT $4"
            ),
            Some(Position::Millis(millis_for_database(
                after_ts,
                "history after selector",
            )?)),
            limit,
            None,
        ),
        // Half older than the point, half at/after it, then oldest-first.
        HistoryQuery::Around { around_ts, limit } => (
            history_window!(
                scope,
                "AND ts < to_timestamp($3::double precision / 1000) ORDER BY ts DESC, id DESC LIMIT $4",
                "AND ts >= to_timestamp($3::double precision / 1000) ORDER BY ts ASC, id ASC LIMIT $5"
            ),
            Some(Position::Millis(millis_for_database(
                around_ts,
                "history around selector",
            )?)),
            limit / 2,
            Some(limit - limit / 2),
        ),
        // Msgid pivots: page on the composite (ts, id) relative to the
        // pivot row so messages sharing the pivot's timestamp are not
        // skipped.
        //
        // The pivot is looked up *within the same target*. Globally, a
        // msgid that belongs to some other buffer is not "unknown", so an
        // unscoped lookup would silently position the query from a message
        // the caller may never have been able to see — answering a request
        // to page from a position that does not exist in this buffer with a
        // plausible result instead of an empty one, and turning any known
        // msgid into an oracle for when it was sent. Scoped, an
        // unknown-here msgid makes the subquery NULL and the result empty,
        // which is what the caller asked about.
        HistoryQuery::BeforeMsgid { msgid, limit } => (
            history_select!(
                scope,
                "AND (ts, id) < (SELECT ts, id FROM messages WHERE msgid = $3 AND target = $1 AND ts >= to_timestamp($2::double precision / 1000)) ORDER BY ts DESC, id DESC LIMIT $4"
            ),
            Some(Position::Msgid(msgid)),
            limit,
            None,
        ),
        HistoryQuery::AfterMsgid { msgid, limit } => (
            history_select!(
                scope,
                "AND (ts, id) > (SELECT ts, id FROM messages WHERE msgid = $3 AND target = $1 AND ts >= to_timestamp($2::double precision / 1000)) ORDER BY ts ASC, id ASC LIMIT $4"
            ),
            Some(Position::Msgid(msgid)),
            limit,
            None,
        ),
        HistoryQuery::AroundMsgid { msgid, limit } => (
            history_window!(
                scope,
                "AND (ts, id) < (SELECT ts, id FROM messages WHERE msgid = $3 AND target = $1 AND ts >= to_timestamp($2::double precision / 1000)) ORDER BY ts DESC, id DESC LIMIT $4",
                "AND (ts, id) >= (SELECT ts, id FROM messages WHERE msgid = $3 AND target = $1 AND ts >= to_timestamp($2::double precision / 1000)) ORDER BY ts ASC, id ASC LIMIT $5"
            ),
            Some(Position::Msgid(msgid)),
            limit / 2,
            Some(limit - limit / 2),
        ),
        // Returned early above.
        HistoryQuery::BetweenSelectors { .. } => unreachable!("handled before the match"),
    };
    let mut statement = sqlx::query_as::<_, HistoryDbRow>(sql)
        .bind(target)
        .bind(floor);
    statement = match position {
        Some(Position::Millis(millis)) => statement.bind(millis),
        Some(Position::Msgid(msgid)) => statement.bind(msgid),
        None => statement,
    };
    statement = statement.bind(limit as i64);
    if let Some(newer_limit) = newer_limit {
        statement = statement.bind(newer_limit as i64);
    }
    let rows = statement.fetch_all(pool).await;
    let mut rows = rows.map_err(query_error)?;
    if newest_first {
        rows.reverse();
    }
    rows.into_iter().map(history_row_from_db).collect()
}

/// Map a raw history row to a [`HistoryRow`].
fn history_row_from_db(row: HistoryDbRow) -> Result<crate::core::HistoryRow, DbError> {
    Ok(crate::core::HistoryRow {
        msgid: row.msgid,
        ts: millis_from_database(row.ts_millis, "messages.ts")?,
        sender_prefix: row.sender_prefix,
        sender_account: row.sender_account,
        kind: crate::core::HistoryKind::from_db(&row.kind)
            .expect("messages.kind is constrained to known message kinds"),
        body: row.body,
        sender_is_bot: row.sender_is_bot,
        multiline: row.multiline,
        client_tags: row.client_tags,
    })
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
    floor: i64,
    first: &crate::core::SelectorBound,
    second: &crate::core::SelectorBound,
    limit: usize,
    scope: crate::core::HistoryScope,
) -> Result<Vec<crate::core::HistoryRow>, DbError> {
    use crate::core::SelectorBound;
    struct HistoryMarker {
        ts_millis: i64,
        id: i64,
        is_timestamp: bool,
    }

    #[derive(sqlx::FromRow)]
    struct HistoryMarkerRow {
        ts_millis: i64,
        id: i64,
    }

    async fn marker(
        pool: &PgPool,
        target: &str,
        floor: i64,
        b: &SelectorBound,
    ) -> Result<Option<HistoryMarker>, DbError> {
        match b {
            SelectorBound::Timestamp(t) => Ok(Some(HistoryMarker {
                ts_millis: millis_for_database(*t, "history selector")?,
                id: 0,
                is_timestamp: true,
            })),
            SelectorBound::Msgid(m) => {
                let row: Option<HistoryMarkerRow> = sqlx::query_as(
                    "SELECT (EXTRACT(EPOCH FROM ts) * 1000)::bigint AS ts_millis, id \
                     FROM messages WHERE msgid = $1 AND target = $2 \
                     AND ts >= to_timestamp($3::double precision / 1000)",
                )
                .bind(m)
                .bind(target)
                .bind(floor)
                .fetch_optional(pool)
                .await
                .map_err(query_error)?;
                Ok(row.map(|row| HistoryMarker {
                    ts_millis: row.ts_millis,
                    id: row.id,
                    is_timestamp: false,
                }))
            }
        }
    }
    let (m1, m2) = match (
        marker(pool, target, floor, first).await,
        marker(pool, target, floor, second).await,
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
    let newest_first = (m1.ts_millis, m1.id) > (m2.ts_millis, m2.id);
    let (older, newer) = if newest_first { (m2, m1) } else { (m1, m2) };
    // Lower bound (strictly after the older pivot): a timestamp uses id = MAX so
    // `(ts,id) > (T, MAX)` is `ts > T`. Upper bound (strictly before the newer
    // pivot): a timestamp uses id = MIN so `(ts,id) < (T, MIN)` is `ts < T`.
    let (lo_ts, lo_id) = (
        older.ts_millis,
        if older.is_timestamp {
            i64::MAX
        } else {
            older.id
        },
    );
    let (hi_ts, hi_id) = (
        newer.ts_millis,
        if newer.is_timestamp {
            i64::MIN
        } else {
            newer.id
        },
    );
    let sql = if newest_first {
        history_select!(
            scope,
            "\
             AND (ts, id) > (to_timestamp($3::double precision / 1000), $4::bigint) \
             AND (ts, id) < (to_timestamp($5::double precision / 1000), $6::bigint) \
             ORDER BY ts DESC, id DESC LIMIT $7"
        )
    } else {
        history_select!(
            scope,
            "\
             AND (ts, id) > (to_timestamp($3::double precision / 1000), $4::bigint) \
             AND (ts, id) < (to_timestamp($5::double precision / 1000), $6::bigint) \
             ORDER BY ts ASC, id ASC LIMIT $7"
        )
    };
    let rows: Result<Vec<HistoryDbRow>, sqlx::Error> = sqlx::query_as(sql)
        .bind(target)
        .bind(floor)
        .bind(lo_ts)
        .bind(lo_id)
        .bind(hi_ts)
        .bind(hi_id)
        .bind(limit as i64)
        .fetch_all(pool)
        .await;
    let mut rows = rows.map_err(query_error)?;
    if newest_first {
        rows.reverse();
    }
    rows.into_iter().map(history_row_from_db).collect()
}

#[derive(sqlx::FromRow)]
struct HistoryTargetRow {
    name: String,
    latest: i64,
}

/// The CHATHISTORY TARGETS statement, in a scope's fragments.
///
/// A channel's newest entry in scope is one backward scan of
/// `messages_target_ts_id_idx` per requested channel (a LATERAL `max(ts)`
/// becomes `Index Scan Backward ... Limit 1`, stepping over the TAGMSG rows a
/// text-scope reader cannot be sent); grouping
/// `WHERE target = ANY(..)` instead read every row of every joined channel to
/// find each maximum. A direct-message conversation's newest entry in each
/// scope is kept in `dm_conversations` by triggers on `messages` (migrations
/// 0080 and 0085), so that half reads at most `limit` rows of the index on
/// the scope's column.
macro_rules! targets_select {
    ($scope:expr) => {
        by_history_scope!($scope, targets_select!())
    };
    (@ $kind:literal, $dm_latest:literal;) => {
        concat!(
            "SELECT name, (EXTRACT(EPOCH FROM MAX(latest)) * 1000)::bigint AS latest FROM (
                 SELECT requested.name, newest.latest
                 FROM unnest($1::text[], $6::bigint[]) AS requested(name, floor)
                 CROSS JOIN LATERAL (
                     SELECT max(ts) AS latest FROM messages
                     WHERE target = requested.name
                       AND ts >= to_timestamp(requested.floor::double precision / 1000) ",
            $kind,
            ") newest
                 WHERE newest.latest IS NOT NULL
                 UNION ALL
                 (SELECT peer AS name, ",
            $dm_latest,
            " AS latest
                  FROM dm_conversations
                  WHERE account = $5
                    AND ",
            $dm_latest,
            " > to_timestamp($2::double precision / 1000)
                    AND ",
            $dm_latest,
            " < to_timestamp($3::double precision / 1000)
                  ORDER BY ",
            $dm_latest,
            " ASC
                  LIMIT $4)
             ) buffers
             GROUP BY name
             HAVING MAX(latest) > to_timestamp($2::double precision / 1000)
                AND MAX(latest) < to_timestamp($3::double precision / 1000)
             ORDER BY latest ASC
             LIMIT $4"
        )
    };
}

/// Return visible targets whose latest activity in the reader's `scope` falls
/// in the requested window, dated by that activity: a buffer whose only
/// activity is entries the reader cannot be sent (TAGMSGs, for a reader
/// without `message-tags`) is not its buffer.
pub async fn query_targets(
    pool: &PgPool,
    channels: &[(String, crate::core::HistoryFloor)],
    me: Option<&str>,
    scope: crate::core::HistoryScope,
    min_ts: e6irc_proto::time::Millis,
    max_ts: e6irc_proto::time::Millis,
    limit: usize,
) -> Result<Vec<(String, e6irc_proto::time::Millis)>, DbError> {
    let min_ts = millis_for_database(min_ts, "history target minimum")?;
    let max_ts = millis_for_database(max_ts, "history target maximum")?;
    let (names, floors): (Vec<&str>, Vec<i64>) = channels
        .iter()
        .map(|(name, floor)| {
            millis_for_database(floor.millis(), "history target floor")
                .map(|floor| (name.as_str(), floor))
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .unzip();
    let rows: Result<Vec<HistoryTargetRow>, sqlx::Error> = sqlx::query_as(targets_select!(scope))
        .bind(names)
        .bind(min_ts as f64)
        .bind(max_ts as f64)
        .bind(limit as i64)
        .bind(me)
        .bind(floors)
        .fetch_all(pool)
        .await;
    rows.map_err(query_error)?
        .into_iter()
        .map(|row| {
            Ok((
                row.name,
                millis_from_database(row.latest, "history target latest")?,
            ))
        })
        .collect()
}

/// Most access entries (auto-op/voice grants) one channel may hold. Bounds both
/// the persisted `channel_access` rows and the in-core map they preload into.
const MAX_ACCESS_ENTRIES_PER_CHANNEL: i64 = 256;

/// Why a founder-only ChanServ change to a registered channel did not apply,
/// found with the channel row locked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelRefusal {
    /// The channel is not registered.
    ChannelMissing,
    /// The actor no longer founds the channel: a transfer committed between
    /// the core's founder check and this write (a pipelined `SET FOUNDER`).
    NotFounder,
}

/// Lock the registered channel `channel_folded` (`FOR NO KEY UPDATE`, which
/// a concurrent founder transfer also takes) and check, inside the caller's
/// transaction, that `actor` still founds it. Every founder-only mutation —
/// ChanServ's and the owner console's — starts here, so none can be applied by
/// someone the core still believed was founder when it queued the request.
async fn lock_channel_as_founder(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    channel_folded: &str,
    actor: &str,
) -> Result<Result<ChannelMutationOwnerRow, ChannelRefusal>, DbError> {
    let row: Option<ChannelMutationOwnerRow> = sqlx::query_as(
        "SELECT c.id AS channel_id, c.founder_account_id AS founder_id,
                a.name_folded AS founder, c.keeptopic
         FROM channels c JOIN accounts a ON a.id = c.founder_account_id
         WHERE c.name_folded = $1
         FOR NO KEY UPDATE OF c",
    )
    .bind(channel_folded)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(query_error)?;
    let Some(row) = row else {
        return Ok(Err(ChannelRefusal::ChannelMissing));
    };
    if row.founder != CaseMapping::Rfc1459.casefold(actor) {
        return Ok(Err(ChannelRefusal::NotFounder));
    }
    Ok(Ok(row))
}

/// An account a name resolves to.
#[derive(sqlx::FromRow)]
struct ResolvedAccount {
    id: i64,
    /// Display name.
    name: String,
    name_folded: String,
}

/// The account `name` names: the account of that name, or the account a nick
/// of that name is grouped to (NickServ GROUP; Atheme resolves any of an
/// account's nicks to it). The one resolution login, NickServ INFO and every
/// ChanServ account argument share.
async fn resolve_account<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    name: &str,
) -> Result<Option<ResolvedAccount>, DbError> {
    sqlx::query_as(
        "SELECT a.id, a.name, a.name_folded
         FROM accounts a
         WHERE a.name_folded = $1
            OR a.id = (SELECT account_id FROM account_nicks WHERE nick_folded = $1)",
    )
    .bind(CaseMapping::Rfc1459.casefold(name))
    .fetch_optional(executor)
    .await
    .map_err(query_error)
}

/// What writing one channel access entry did.
enum AccessEntryWrite {
    /// The entry holds the flags asked for; `previous` is what it held before
    /// (`None`: it is new).
    Written { previous: Option<String> },
    /// A new entry would exceed [`MAX_ACCESS_ENTRIES_PER_CHANNEL`].
    LimitReached,
}

/// Upsert `account_id`'s access entry on the locked channel `channel_id`.
/// Only a *new* entry counts against the cap; re-flagging an existing one is
/// always allowed. The caller holds the channel row lock, so two grants
/// cannot both slip past the cap.
async fn write_access_entry(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    channel_id: i64,
    account_id: i64,
    flags: &str,
) -> Result<AccessEntryWrite, DbError> {
    let previous: Option<String> = sqlx::query_scalar(
        "SELECT flags FROM channel_access WHERE channel_id = $1 AND account_id = $2",
    )
    .bind(channel_id)
    .bind(account_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(query_error)?;
    if previous.is_none() {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM channel_access WHERE channel_id = $1")
                .bind(channel_id)
                .fetch_one(&mut **transaction)
                .await
                .map_err(query_error)?;
        if count >= MAX_ACCESS_ENTRIES_PER_CHANNEL {
            return Ok(AccessEntryWrite::LimitReached);
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
    .execute(&mut **transaction)
    .await
    .map_err(query_error)?;
    Ok(AccessEntryWrite::Written { previous })
}

/// What a ChanServ access change (FLAGS, ACCESS ADD/DEL) did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessChange {
    /// The entry now holds the flags asked for (`None`: it is gone).
    Applied {
        /// The account the name resolved to, as its display name.
        account: String,
        /// The flags the entry held before (`None`: there was no entry).
        previous: Option<String>,
    },
    /// No account has that name or nick.
    AccountMissing,
    /// A new entry would exceed the per-channel cap.
    LimitReached,
    Refused(ChannelRefusal),
}

/// Set (`flags = Some`) or remove (`flags = None`) the access entry of the
/// account `account` names (its name, or a nick grouped to it) on a registered
/// channel `actor` founds — checked with the channel row locked. A change is
/// audited (`CHANNEL_ACCESS`, as the owner console records it) in the same
/// transaction.
pub async fn set_channel_access(
    pool: &PgPool,
    channel: &str,
    account: &str,
    flags: Option<String>,
    actor: &str,
) -> Result<AccessChange, DbError> {
    let channel_folded = CaseMapping::Rfc1459.casefold(channel);
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let channel = match lock_channel_as_founder(&mut transaction, &channel_folded, actor).await? {
        Ok(channel) => channel,
        Err(refusal) => return Ok(AccessChange::Refused(refusal)),
    };
    let Some(target) = resolve_account(&mut *transaction, account).await? else {
        return Ok(AccessChange::AccountMissing);
    };
    let previous = match flags.as_deref() {
        Some(flags) => {
            match write_access_entry(&mut transaction, channel.channel_id, target.id, flags).await?
            {
                AccessEntryWrite::Written { previous } => previous,
                AccessEntryWrite::LimitReached => return Ok(AccessChange::LimitReached),
            }
        }
        None => sqlx::query_scalar(
            "DELETE FROM channel_access WHERE channel_id = $1 AND account_id = $2
             RETURNING flags",
        )
        .bind(channel.channel_id)
        .bind(target.id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(query_error)?,
    };
    if previous != flags {
        let detail = format!(
            "account={} flags={}",
            target.name_folded,
            flags.as_deref().unwrap_or("-")
        );
        audit_channel_service(
            &mut transaction,
            actor,
            "CHANNEL_ACCESS",
            &channel_folded,
            &detail,
        )
        .await?;
    }
    transaction.commit().await.map_err(query_error)?;
    Ok(AccessChange::Applied {
        account: target.name,
        previous,
    })
}

/// Record one change of a registered channel inside its transaction — target
/// the folded channel, actor the acting account folded. ChanServ's changes use
/// the vocabulary the owner console's use (`CHANNEL_*`).
async fn audit_channel_service(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor: &str,
    action: &str,
    channel_folded: &str,
    detail: &str,
) -> Result<(), DbError> {
    insert_audit_log_with(
        &mut **transaction,
        &AuditPrincipal::account(&CaseMapping::Rfc1459.casefold(actor)),
        action,
        &AuditPrincipal::channel(channel_folded),
        detail,
    )
    .await
}

/// A registered channel row locked for a founder-only change (see
/// [`lock_channel_as_founder`]).
#[derive(sqlx::FromRow)]
struct ChannelMutationOwnerRow {
    channel_id: i64,
    founder_id: i64,
    /// The founder's folded account name.
    founder: String,
    keeptopic: bool,
}

/// Persist and audit one founder-owned channel mutation.
pub async fn persist_owned_channel_mutation(
    pool: &PgPool,
    channel: &str,
    actor: &str,
    mutation: &crate::core::PersistedChannelMutation,
) -> Result<crate::core::ChannelControlResult, DbError> {
    use crate::core::{ChannelControlResult, PersistedChannelMutation};

    let channel_folded = CaseMapping::Rfc1459.casefold(channel);
    let actor_folded = CaseMapping::Rfc1459.casefold(actor);
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let Ok(owner) = lock_channel_as_founder(&mut transaction, &channel_folded, actor).await? else {
        return Ok(ChannelControlResult::MissingOrNotOwner);
    };
    let (channel_id, keeptopic) = (owner.channel_id, owner.keeptopic);
    // The account an access change or transfer named, as resolved.
    let mut resolved = None;

    let (action, detail) = match mutation {
        PersistedChannelMutation::SetTopic { topic } => {
            if !keeptopic {
                return Ok(ChannelControlResult::KeeptopicDisabled);
            }
            let (text, setter, set_at) = match topic {
                Some((text, setter, set_at)) => (
                    Some(text),
                    Some(setter),
                    Some(seconds_for_database(*set_at, "channels.topic_set_at")?),
                ),
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
            .map_err(query_error)?;
            (
                "CHANNEL_TOPIC",
                if topic.is_some() { "set" } else { "cleared" }.to_string(),
            )
        }
        PersistedChannelMutation::SetKeeptopic { enabled, topic } => {
            let (text, setter, set_at) = match topic {
                Some((text, setter, set_at)) if *enabled => (
                    Some(text),
                    Some(setter),
                    Some(seconds_for_database(*set_at, "channels.topic_set_at")?),
                ),
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
            .map_err(query_error)?;
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
                .map_err(query_error)?;
            (
                "CHANNEL_MLOCK",
                mlock.as_deref().unwrap_or("cleared").to_string(),
            )
        }
        PersistedChannelMutation::SetAccess { account, flags } => {
            let Some(target) = resolve_account(&mut *transaction, account).await? else {
                return Ok(ChannelControlResult::AccountMissing);
            };
            if let Some(flags) = flags {
                if let AccessEntryWrite::LimitReached =
                    write_access_entry(&mut transaction, channel_id, target.id, flags).await?
                {
                    return Ok(ChannelControlResult::AccessLimitReached);
                }
            } else {
                sqlx::query("DELETE FROM channel_access WHERE channel_id = $1 AND account_id = $2")
                    .bind(channel_id)
                    .bind(target.id)
                    .execute(&mut *transaction)
                    .await
                    .map_err(query_error)?;
            }
            let detail = format!(
                "account={} flags={}",
                target.name_folded,
                flags.as_deref().unwrap_or("-")
            );
            resolved = Some(target.name);
            ("CHANNEL_ACCESS", detail)
        }
        PersistedChannelMutation::TransferFounder { account } => {
            let Some(founder) = resolve_account(&mut *transaction, account).await? else {
                return Ok(ChannelControlResult::AccountMissing);
            };
            match transfer_channel_founder(&mut transaction, &owner, founder.id).await? {
                FounderWrite::Transferred => {}
                FounderWrite::AccountMissing => return Ok(ChannelControlResult::AccountMissing),
                FounderWrite::LimitReached => {
                    return Ok(ChannelControlResult::FounderLimitReached);
                }
            }
            resolved = Some(founder.name);
            ("CHANNEL_FOUNDER", founder.name_folded)
        }
        PersistedChannelMutation::Drop => {
            sqlx::query("DELETE FROM channels WHERE id = $1")
                .bind(channel_id)
                .execute(&mut *transaction)
                .await
                .map_err(query_error)?;
            ("CHANNEL_DROP", String::new())
        }
    };
    insert_audit_log_with(
        &mut *transaction,
        &AuditPrincipal::account(&actor_folded),
        action,
        &AuditPrincipal::channel(&channel_folded),
        &detail,
    )
    .await?;
    transaction.commit().await.map_err(query_error)?;
    Ok(ChannelControlResult::Applied { account: resolved })
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
    .map_err(query_error)?;
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
    .map_err(query_error)
}

/// What a founder transfer on a locked channel did.
enum FounderWrite {
    Transferred,
    /// The receiving account was deleted after its name was resolved.
    AccountMissing,
    /// The receiving account already founds [`CHANNEL_FOUNDER_LIMIT`] channels.
    LimitReached,
}

/// Make `founder_id` the founder of the locked channel `channel`: the one
/// founder transfer both ChanServ and the owner console run. The receiving
/// account's row is locked and its founded channels counted first, as a
/// registration does, so no transfer can take an account past
/// [`CHANNEL_FOUNDER_LIMIT`]. A transfer clears the successor — the outgoing
/// founder picked the heir, and the new founder names their own (maintainer
/// decision; succession by account deletion clears it too, through migration
/// 0075's trigger). A transfer to the founder the channel already has changes
/// nothing.
async fn transfer_channel_founder(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    channel: &ChannelMutationOwnerRow,
    founder_id: i64,
) -> Result<FounderWrite, DbError> {
    if channel.founder_id == founder_id {
        return Ok(FounderWrite::Transferred);
    }
    let locked: Option<i64> =
        sqlx::query_scalar("SELECT id FROM accounts WHERE id = $1 FOR NO KEY UPDATE")
            .bind(founder_id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(query_error)?;
    if locked.is_none() {
        return Ok(FounderWrite::AccountMissing);
    }
    if let FounderCapacity::LimitReached = founder_capacity(transaction, founder_id).await? {
        return Ok(FounderWrite::LimitReached);
    }
    sqlx::query(
        "UPDATE channels SET founder_account_id = $2, successor_account_id = NULL WHERE id = $1",
    )
    .bind(channel.channel_id)
    .bind(founder_id)
    .execute(&mut **transaction)
    .await
    .map_err(query_error)?;
    Ok(FounderWrite::Transferred)
}

/// What ChanServ `SET FOUNDER` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FounderTransfer {
    /// The channel now belongs to `founder` (the account's display name).
    Transferred {
        founder: String,
    },
    /// No account has that name or nick.
    AccountMissing,
    /// That account already founds [`CHANNEL_FOUNDER_LIMIT`] channels.
    LimitReached,
    Refused(ChannelRefusal),
}

/// Transfer a channel `actor` founds — checked with its row locked — to the
/// account `new_founder` names (its name, or a nick grouped to it). Audited
/// (`CHANNEL_FOUNDER`) in the same transaction, with the outgoing founder
/// `actor`. A store failure is an `Err`, never "no such account": that would
/// tell the founder a lie they might act on.
pub async fn set_channel_founder(
    pool: &PgPool,
    channel: &str,
    new_founder: &str,
    actor: &str,
) -> Result<FounderTransfer, DbError> {
    let channel_folded = CaseMapping::Rfc1459.casefold(channel);
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let channel = match lock_channel_as_founder(&mut transaction, &channel_folded, actor).await? {
        Ok(channel) => channel,
        Err(refusal) => return Ok(FounderTransfer::Refused(refusal)),
    };
    let Some(founder) = resolve_account(&mut *transaction, new_founder).await? else {
        return Ok(FounderTransfer::AccountMissing);
    };
    match transfer_channel_founder(&mut transaction, &channel, founder.id).await? {
        FounderWrite::Transferred => {}
        FounderWrite::AccountMissing => return Ok(FounderTransfer::AccountMissing),
        FounderWrite::LimitReached => return Ok(FounderTransfer::LimitReached),
    }
    audit_channel_service(
        &mut transaction,
        actor,
        "CHANNEL_FOUNDER",
        &channel_folded,
        &founder.name_folded,
    )
    .await?;
    transaction.commit().await.map_err(query_error)?;
    Ok(FounderTransfer::Transferred {
        founder: founder.name,
    })
}

/// What naming a channel's successor did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuccessorChange {
    /// The successor was set as asked: the account's display name, or `None`
    /// once cleared.
    Applied {
        successor: Option<String>,
    },
    /// No account has the successor's name or nick.
    AccountMissing,
    /// The named account founds the channel; a founder cannot also succeed it.
    IsFounder,
    Refused(ChannelRefusal),
}

/// Name the account `successor` names (its name, or a nick grouped to it) as
/// the one a registered channel passes to when its founder's account is
/// deleted (ChanServ SET SUCCESSOR), or clear it with `None`. The channel row
/// is locked and `actor` checked to still found it first, so a founder
/// transfer committed after the core's check refuses this rather than let a
/// former founder pick the heir. Audited (`CHANNEL_SUCCESSOR`) with `actor` in
/// the same transaction.
pub async fn set_channel_successor(
    pool: &PgPool,
    channel: &str,
    successor: Option<&str>,
    actor: &str,
) -> Result<SuccessorChange, DbError> {
    let channel_folded = CaseMapping::Rfc1459.casefold(channel);
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let channel = match lock_channel_as_founder(&mut transaction, &channel_folded, actor).await? {
        Ok(channel) => channel,
        Err(refusal) => return Ok(SuccessorChange::Refused(refusal)),
    };
    let successor = match successor {
        Some(successor) => match resolve_account(&mut *transaction, successor).await? {
            None => return Ok(SuccessorChange::AccountMissing),
            Some(account) if account.id == channel.founder_id => {
                return Ok(SuccessorChange::IsFounder);
            }
            Some(account) => Some(account),
        },
        None => None,
    };
    sqlx::query("UPDATE channels SET successor_account_id = $2 WHERE id = $1")
        .bind(channel.channel_id)
        .bind(successor.as_ref().map(|account| account.id))
        .execute(&mut *transaction)
        .await
        .map_err(query_error)?;
    audit_channel_service(
        &mut transaction,
        actor,
        "CHANNEL_SUCCESSOR",
        &channel_folded,
        successor
            .as_ref()
            .map_or("-", |account| account.name_folded.as_str()),
    )
    .await?;
    transaction.commit().await.map_err(query_error)?;
    Ok(SuccessorChange::Applied {
        successor: successor.map(|account| account.name),
    })
}

/// Every registered channel's successor, as `(channel name_folded, successor
/// name_folded)` — boot-loaded into the founder mirror.
pub async fn list_channel_successors(pool: &PgPool) -> Result<Vec<(String, String)>, DbError> {
    sqlx::query_as(
        "SELECT c.name_folded, a.name_folded
         FROM channels c JOIN accounts a ON a.id = c.successor_account_id",
    )
    .fetch_all(pool)
    .await
    .map_err(query_error)
}

/// Most nicks one account may hold, its own name included (Atheme's
/// `maxnicks`, default 5): GROUP refuses a nick beyond it.
pub const MAX_NICKS_PER_ACCOUNT: i64 = 5;

/// What NickServ GROUP did with a nick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NickGroupOutcome {
    Grouped,
    /// The nick already belongs to this account (its name, or grouped).
    AlreadyYours,
    /// Another account holds the nick, as its name or grouped — or it is a
    /// retired account name.
    Taken,
    /// The account already holds [`MAX_NICKS_PER_ACCOUNT`] nicks.
    TooMany,
    /// The account no longer exists.
    AccountMissing,
}

/// Group `nick` to `account` (NickServ GROUP). The nick's name lock — the one
/// account creation and deletion take — and the account row are held while the
/// checks and the insert run, so a racing registration of the same name or a
/// second GROUP for the account cannot slip past them. Audited (`NICK_GROUP`).
pub async fn group_nick(
    pool: &PgPool,
    account: &str,
    nick: &str,
) -> Result<NickGroupOutcome, DbError> {
    let account_folded = CaseMapping::Rfc1459.casefold(account);
    let nick_folded = CaseMapping::Rfc1459.casefold(nick);
    let mut transaction = pool.begin().await.map_err(query_error)?;
    lock_account_name(&mut transaction, &nick_folded).await?;
    let Some(account_id) = lock_account_id(&mut transaction, &account_folded).await? else {
        return Ok(NickGroupOutcome::AccountMissing);
    };
    if nick_folded == account_folded {
        return Ok(NickGroupOutcome::AlreadyYours);
    }
    let holder: Option<i64> =
        sqlx::query_scalar("SELECT account_id FROM account_nicks WHERE nick_folded = $1")
            .bind(&nick_folded)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(query_error)?;
    match holder {
        Some(holder) if holder == account_id => return Ok(NickGroupOutcome::AlreadyYours),
        Some(_) => return Ok(NickGroupOutcome::Taken),
        None => {}
    }
    let is_account_name: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM accounts WHERE name_folded = $1)
             OR EXISTS (SELECT 1 FROM retired_account_names WHERE name_folded = $1)",
    )
    .bind(&nick_folded)
    .fetch_one(&mut *transaction)
    .await
    .map_err(query_error)?;
    if is_account_name {
        return Ok(NickGroupOutcome::Taken);
    }
    let grouped: i64 =
        sqlx::query_scalar("SELECT count(*) FROM account_nicks WHERE account_id = $1")
            .bind(account_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(query_error)?;
    // The account's own name is one of its nicks.
    if grouped + 1 >= MAX_NICKS_PER_ACCOUNT {
        return Ok(NickGroupOutcome::TooMany);
    }
    sqlx::query("INSERT INTO account_nicks (nick_folded, nick, account_id) VALUES ($1, $2, $3)")
        .bind(&nick_folded)
        .bind(nick)
        .bind(account_id)
        .execute(&mut *transaction)
        .await
        .map_err(query_error)?;
    insert_audit_log_with(
        &mut *transaction,
        &AuditPrincipal::account(&account_folded),
        "NICK_GROUP",
        &AuditPrincipal::account(&account_folded),
        &nick_folded,
    )
    .await?;
    transaction.commit().await.map_err(query_error)?;
    Ok(NickGroupOutcome::Grouped)
}

/// Remove a grouped nick from `account` (NickServ UNGROUP). Returns whether
/// the account held it. Audited (`NICK_UNGROUP`) when it did.
pub async fn ungroup_nick(pool: &PgPool, account: &str, nick: &str) -> Result<bool, DbError> {
    let account_folded = CaseMapping::Rfc1459.casefold(account);
    let nick_folded = CaseMapping::Rfc1459.casefold(nick);
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let removed = sqlx::query(
        "DELETE FROM account_nicks n USING accounts a
         WHERE n.account_id = a.id AND a.name_folded = $1 AND n.nick_folded = $2",
    )
    .bind(&account_folded)
    .bind(&nick_folded)
    .execute(&mut *transaction)
    .await
    .map_err(query_error)?
    .rows_affected()
        != 0;
    if removed {
        insert_audit_log_with(
            &mut *transaction,
            &AuditPrincipal::account(&account_folded),
            "NICK_UNGROUP",
            &AuditPrincipal::account(&account_folded),
            &nick_folded,
        )
        .await?;
    }
    transaction.commit().await.map_err(query_error)?;
    Ok(removed)
}

/// What NickServ SET ENFORCE did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NickEnforceChange {
    Changed,
    /// The flag already had the requested value.
    Unchanged,
    AccountMissing,
}

/// Turn nick protection on or off for `account` (NickServ SET ENFORCE).
/// Audited (`NICK_ENFORCE`) when it changes.
pub async fn set_nick_enforce(
    pool: &PgPool,
    account: &str,
    enforce: bool,
) -> Result<NickEnforceChange, DbError> {
    let account_folded = CaseMapping::Rfc1459.casefold(account);
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let current: Option<bool> = sqlx::query_scalar(
        "SELECT nick_enforce FROM accounts WHERE name_folded = $1 FOR NO KEY UPDATE",
    )
    .bind(&account_folded)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(query_error)?;
    match current {
        None => return Ok(NickEnforceChange::AccountMissing),
        Some(current) if current == enforce => return Ok(NickEnforceChange::Unchanged),
        Some(_) => {}
    }
    sqlx::query("UPDATE accounts SET nick_enforce = $2 WHERE name_folded = $1")
        .bind(&account_folded)
        .bind(enforce)
        .execute(&mut *transaction)
        .await
        .map_err(query_error)?;
    insert_audit_log_with(
        &mut *transaction,
        &AuditPrincipal::account(&account_folded),
        "NICK_ENFORCE",
        &AuditPrincipal::account(&account_folded),
        if enforce { "on" } else { "off" },
    )
    .await?;
    transaction.commit().await.map_err(query_error)?;
    Ok(NickEnforceChange::Changed)
}

/// Every nick registration the core mirrors: grouped nicks as
/// `(nick, account)`, and the accounts with nick protection on — all folded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NickRegistrations {
    pub grouped: Vec<(String, String)>,
    pub enforced: Vec<String>,
}

pub async fn list_nick_registrations(pool: &PgPool) -> Result<NickRegistrations, DbError> {
    let grouped = sqlx::query_as(
        "SELECT n.nick_folded, a.name_folded FROM account_nicks n
         JOIN accounts a ON a.id = n.account_id ORDER BY n.nick_folded",
    )
    .fetch_all(pool)
    .await
    .map_err(query_error)?;
    let enforced =
        sqlx::query_scalar("SELECT name_folded FROM accounts WHERE nick_enforce ORDER BY id")
            .fetch_all(pool)
            .await
            .map_err(query_error)?;
    Ok(NickRegistrations { grouped, enforced })
}

/// What NickServ INFO reports about an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NickServAccountInfo {
    /// Display name.
    pub name: String,
    pub registered_at: e6irc_proto::time::Millis,
    /// Every nick the account holds, its name first, as registered.
    pub nicks: Vec<String>,
    pub enforce: bool,
}

#[derive(sqlx::FromRow)]
struct NickServAccountRow {
    id: i64,
    name: String,
    registered_ms: i64,
    nick_enforce: bool,
}

/// The account `target` names — as its account name or a grouped nick — for
/// NickServ INFO.
pub async fn nickserv_account_info(
    pool: &PgPool,
    target: &str,
) -> Result<Option<NickServAccountInfo>, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(target);
    let row: Option<NickServAccountRow> = sqlx::query_as(
        "SELECT a.id, a.name, a.nick_enforce,
                (extract(epoch FROM a.created_at) * 1000)::bigint AS registered_ms
         FROM accounts a
         WHERE a.name_folded = $1
            OR a.id = (SELECT account_id FROM account_nicks WHERE nick_folded = $1)",
    )
    .bind(&folded)
    .fetch_optional(pool)
    .await
    .map_err(query_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let grouped: Vec<String> = sqlx::query_scalar(
        "SELECT nick FROM account_nicks WHERE account_id = $1 ORDER BY registered_at, nick_folded",
    )
    .bind(row.id)
    .fetch_all(pool)
    .await
    .map_err(query_error)?;
    let mut nicks = vec![row.name.clone()];
    nicks.extend(grouped);
    Ok(Some(NickServAccountInfo {
        name: row.name,
        registered_at: millis_from_database(row.registered_ms, "account registration")?,
        nicks,
        enforce: row.nick_enforce,
    }))
}

/// Add or remove a server ban (KLINE/DLINE/XLINE) together with its audit
/// record, in one transaction: a ban nobody is on record for cannot exist. An
/// add upserts on `(mask, kind)`, so re-banning a mask of the same kind
/// refreshes its reason and setter. Returns whether anything changed — `false`
/// when the ban to remove was not there.
pub async fn mutate_server_ban_audited(
    pool: &PgPool,
    mutation: &crate::core::ServerBanMutation,
    actor: &AuditPrincipal,
) -> Result<bool, DbError> {
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let (action, target, detail) = match mutation {
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
            .map_err(query_error)?;
            (
                kind.to_ascii_uppercase(),
                mask_display.as_str(),
                reason.as_str(),
            )
        }
        crate::core::ServerBanMutation::Remove {
            expected_id,
            mask,
            mask_display,
            kind,
            ..
        } => {
            let mut delete =
                sqlx::QueryBuilder::<sqlx::Postgres>::new("DELETE FROM server_bans WHERE mask = ");
            delete.push_bind(mask).push(" AND kind = ").push_bind(kind);
            if let Some(expected_id) = expected_id {
                delete.push(" AND id = ").push_bind(expected_id);
            }
            let deleted = delete
                .build()
                .execute(&mut *transaction)
                .await
                .map_err(query_error)?;
            if deleted.rows_affected() == 0 {
                transaction.rollback().await.map_err(query_error)?;
                return Ok(false);
            }
            (
                format!("UN{}", kind.to_ascii_uppercase()),
                mask_display.as_str(),
                "",
            )
        }
    };
    insert_audit_log_with(
        &mut *transaction,
        actor,
        &action,
        &AuditPrincipal::mask(target),
        detail,
    )
    .await?;
    transaction.commit().await.map_err(query_error)?;
    Ok(true)
}

/// What kind of name an audit row's actor or target is. Account names,
/// operator names, nicknames, channels, and masks are different namespaces
/// that can hold the same spelling — an operator block named `root` beside an
/// account named `root`, a nick `eve` beside the account `eve` — so a row
/// records which one it means, and an account's own view selects only rows
/// that name it *as an account*.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuditPrincipalKind {
    /// A folded account name.
    Account,
    /// A configured IRC operator name (the `OPER` block), not an account.
    Operator,
    /// An IRC nickname, which any connection may hold.
    Nick,
    Channel,
    /// An account's network, as `owner/network`.
    Network,
    /// A server-ban mask.
    Mask,
    /// The server itself (its configuration and keys).
    Server,
    /// An identity provider, as `oidc:<issuer>`.
    Provider,
    /// A command run on the host (`host:recover-administrator`, the secret
    /// rotation, the bootstrap import), which no account performed.
    Host,
    /// A name reserved by an invitation, which no account holds yet.
    Invitation,
}

impl AuditPrincipalKind {
    /// The stored spelling, constrained by migration 0078.
    const fn as_db_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Operator => "operator",
            Self::Nick => "nick",
            Self::Channel => "channel",
            Self::Network => "network",
            Self::Mask => "mask",
            Self::Server => "server",
            Self::Provider => "provider",
            Self::Host => "host",
            Self::Invitation => "invitation",
        }
    }
}

/// An audit row's actor or target: a name and the namespace it belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditPrincipal {
    kind: AuditPrincipalKind,
    name: String,
}

impl AuditPrincipal {
    fn new(kind: AuditPrincipalKind, name: &str) -> Self {
        Self {
            kind,
            name: name.to_owned(),
        }
    }

    /// An account, by its folded name — the account namespace's key, so an
    /// account's own view matches it whatever spelling the caller held.
    pub fn account(name: &str) -> Self {
        Self::new(
            AuditPrincipalKind::Account,
            &CaseMapping::Rfc1459.casefold(name),
        )
    }

    pub fn operator(name: &str) -> Self {
        Self::new(AuditPrincipalKind::Operator, name)
    }

    pub fn nick(name: &str) -> Self {
        Self::new(AuditPrincipalKind::Nick, name)
    }

    pub fn channel(name: &str) -> Self {
        Self::new(AuditPrincipalKind::Channel, name)
    }

    pub fn network(name: &str) -> Self {
        Self::new(AuditPrincipalKind::Network, name)
    }

    pub fn mask(name: &str) -> Self {
        Self::new(AuditPrincipalKind::Mask, name)
    }

    pub fn server() -> Self {
        Self::new(AuditPrincipalKind::Server, "server")
    }

    pub fn provider(name: &str) -> Self {
        Self::new(AuditPrincipalKind::Provider, name)
    }

    pub fn host(name: &str) -> Self {
        Self::new(AuditPrincipalKind::Host, name)
    }

    pub fn invitation(name: &str) -> Self {
        Self::new(AuditPrincipalKind::Invitation, name)
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

async fn insert_audit_log_with<'executor>(
    executor: impl sqlx::Executor<'executor, Database = sqlx::Postgres>,
    actor: &AuditPrincipal,
    action: &str,
    target: &AuditPrincipal,
    detail: &str,
) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO audit_log (actor, actor_kind, action, target, target_kind, detail)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&actor.name)
    .bind(actor.kind.as_db_str())
    .bind(action)
    .bind(&target.name)
    .bind(target.kind.as_db_str())
    .bind(detail)
    .execute(executor)
    .await
    .map_err(query_error)?;
    Ok(())
}

/// Record one privileged action in the audit trail.
pub async fn insert_audit_log(
    pool: &PgPool,
    actor: &AuditPrincipal,
    action: &str,
    target: &AuditPrincipal,
    detail: &str,
) -> Result<(), DbError> {
    insert_audit_log_with(pool, actor, action, target, detail).await
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct AuditLogRow {
    pub id: i64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy)]
pub struct AuditLogFilter<'a> {
    pub before_id: Option<i64>,
    pub actor: Option<&'a str>,
    pub action: Option<&'a str>,
    pub target: Option<&'a str>,
    pub page_size: AuditLogPageSize,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AuditLogPage {
    pub entries: Vec<AuditLogRow>,
    pub next_before_id: Option<i64>,
}

macro_rules! bounded_page_size {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name(usize);

        impl $name {
            pub const MAX: usize = 1_000;

            pub fn new(value: usize) -> Option<Self> {
                (1..=Self::MAX).contains(&value).then_some(Self(value))
            }

            pub fn value(self) -> usize {
                self.0
            }
        }
    };
}

bounded_page_size!(
    AuditLogPageSize,
    "A non-zero audit page size capped at the public API maximum."
);

fn keyset_page<T>(
    mut entries: Vec<T>,
    page_size: usize,
    stable_id: impl Fn(&T) -> i64,
) -> (Vec<T>, Option<i64>) {
    let next_before_id = (entries.len() > page_size).then(|| stable_id(&entries[page_size - 1]));
    entries.truncate(page_size);
    (entries, next_before_id)
}

macro_rules! fetch_keyset_page {
    ($pool:expr, $query:expr, $row:ty, $page_size:expr) => {{
        let entries: Vec<$row> = $query
            .build_query_as()
            .fetch_all($pool)
            .await
            .map_err(query_error)?;
        keyset_page(entries, $page_size, |entry| entry.id)
    }};
}

/// Query the privileged-action audit trail newest-first. Exact filters and the
/// stable identity cursor are applied in PostgreSQL, so pagination neither
/// duplicates nor skips rows when a concurrent action is appended.
pub async fn query_audit_log(
    pool: &PgPool,
    filter: AuditLogFilter<'_>,
) -> Result<AuditLogPage, DbError> {
    let page_size = filter.page_size.value();
    let fetch_limit = page_size + 1;
    let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT id, actor, action, target, detail,
                to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')
                    AS created_at
         FROM audit_log WHERE TRUE",
    );
    if let Some(before_id) = filter.before_id {
        query.push(" AND id < ").push_bind(before_id);
    }
    if let Some(actor) = filter.actor {
        query.push(" AND actor = ").push_bind(actor);
    }
    if let Some(action) = filter.action {
        query.push(" AND action = ").push_bind(action);
    }
    if let Some(target) = filter.target {
        query.push(" AND target = ").push_bind(target);
    }
    query
        .push(" ORDER BY id DESC LIMIT ")
        .push_bind(fetch_limit as i64);
    let (entries, next_before_id) = fetch_keyset_page!(pool, query, AuditLogRow, page_size);
    Ok(AuditLogPage {
        entries,
        next_before_id,
    })
}

/// The SQL condition selecting the audit rows (alias `log`) an account sees as
/// its own activity, the account's folded name being the SQL expression
/// `name`: the rows naming it *as an account*, as actor (its own mutations) or
/// target (administrator actions taken against it). An operator, nick, or
/// reserved name spelled like the account is another principal, and its rows
/// are not the account's. The account's view and its export share this one
/// predicate so they cannot select different rows.
fn account_audit_predicate(log: &str, name: &str) -> String {
    format!(
        "(({log}.actor_kind = 'account' AND {log}.actor = {name}) \
         OR ({log}.target_kind = 'account' AND {log}.target = {name}))"
    )
}

/// Query the security-relevant activity visible to one account
/// ([`account_audit_predicate`]). Exact RFC1459 folding prevents one account
/// from observing a similarly named account's events.
pub async fn query_account_security_activity(
    pool: &PgPool,
    account: &str,
    before_id: Option<i64>,
    page_size: AuditLogPageSize,
) -> Result<AuditLogPage, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let fetch_limit = page_size.value() + 1;
    let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new("WITH me AS (SELECT ");
    query.push_bind(&folded).push(
        "::text AS name)
         SELECT log.id, log.actor, log.action, log.target, log.detail,
                to_char(log.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')
                    AS created_at
         FROM audit_log log, me
         WHERE ",
    );
    query.push(account_audit_predicate("log", "me.name"));
    if let Some(before_id) = before_id {
        query.push(" AND log.id < ").push_bind(before_id);
    }
    query
        .push(" ORDER BY id DESC LIMIT ")
        .push_bind(fetch_limit as i64);
    let (entries, next_before_id) = fetch_keyset_page!(pool, query, AuditLogRow, page_size.value());
    Ok(AuditLogPage {
        entries,
        next_before_id,
    })
}

/// Rows one export page fetches from a section's cursor.
macro_rules! export_page {
    () => {
        "500"
    };
}

/// A versioned JSON export of one account's retained data, produced a page at
/// a time. Secret digests, password hashes, sealed upstream passwords, session
/// identity tokens, device codes, and invitation bearers are deliberately
/// absent.
///
/// Every section observes one snapshot: the export runs in a
/// `REPEATABLE READ READ ONLY` transaction. The bounded sections are built in
/// one statement; the two that grow with the account's history — its messages
/// and its bouncer backlog — are read through server-side cursors,
/// [`export_page!`] rows at a time, so neither the database nor this process
/// ever holds the whole of either as one value. The transaction is held for as
/// long as the reader keeps reading; a reader that stalls past the pool's idle
/// transaction timeout ends it, and the export fails loudly.
pub struct AccountExport {
    transaction: sqlx::Transaction<'static, sqlx::Postgres>,
    stage: AccountExportStage,
}

enum AccountExportStage {
    /// The bounded sections, as one JSON object's text.
    Head(String),
    Messages {
        first: bool,
    },
    Backlog {
        first: bool,
    },
    Done,
}

/// Open an account's export, or `None` when no such account exists. The first
/// [`AccountExport::next_chunk`] is the start of the document.
pub async fn begin_account_export(
    pool: &PgPool,
    account: &str,
) -> Result<Option<AccountExport>, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let mut transaction = pool.begin().await.map_err(query_error)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *transaction)
        .await
        .map_err(query_error)?;
    // Every interpolated piece is built from constants of this module.
    let account_activity = account_audit_predicate("log", "a.name_folded");
    let head: Option<(String, String)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        r#"
        WITH owner AS (
            SELECT id, name, name_folded, contact_email, flags, created_at
            FROM accounts WHERE name_folded = $1
        )
        SELECT a.name, jsonb_build_object(
            'schema_version', 1,
            'exported_at', to_char(now() AT TIME ZONE 'UTC',
                'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
            'account', jsonb_build_object(
                'name', a.name,
                'contact_email', a.contact_email,
                'created_at', to_char(a.created_at AT TIME ZONE 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                'administrator', (a.flags & 1) = 1,
                'suspended', (a.flags & 2) = 2
            ),
            'credentials', COALESCE((
                SELECT jsonb_agg(jsonb_build_object(
                    'kind', c.kind,
                    'label', c.label,
                    'created_at', to_char(c.created_at AT TIME ZONE 'UTC',
                        'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                    'last_used_at', to_char(c.last_used_at AT TIME ZONE 'UTC',
                        'YYYY-MM-DD"T"HH24:MI:SS"Z"')
                ) ORDER BY c.id)
                FROM account_credentials c WHERE c.account_id = a.id
            ), '[]'::jsonb),
            'personal_access_tokens', COALESCE((
                SELECT jsonb_agg(jsonb_build_object(
                    'label', t.label,
                    'scopes', t.scopes,
                    'created_at', to_char(t.created_at AT TIME ZONE 'UTC',
                        'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                    'expires_at', to_char(t.expires_at AT TIME ZONE 'UTC',
                        'YYYY-MM-DD"T"HH24:MI:SS"Z"')
                ) ORDER BY t.id)
                FROM api_tokens t WHERE t.account_id = a.id
            ), '[]'::jsonb),
            'login_identities', COALESCE((
                SELECT jsonb_agg(jsonb_build_object(
                    'issuer', o.issuer,
                    'subject', o.subject,
                    'created_at', to_char(o.created_at AT TIME ZONE 'UTC',
                        'YYYY-MM-DD"T"HH24:MI:SS"Z"')
                ) ORDER BY o.id)
                FROM oidc_identities o WHERE o.account_id = a.id
            ), '[]'::jsonb),
            'browser_sessions', COALESCE((
                SELECT jsonb_agg(jsonb_build_object(
                    'provider', s.oidc_provider,
                    'email', s.oidc_email,
                    'role', s.oidc_role,
                    'user_agent', s.user_agent,
                    'created_at', to_char(s.created_at AT TIME ZONE 'UTC',
                        'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                    'expires_at', to_char(s.expires_at AT TIME ZONE 'UTC',
                        'YYYY-MM-DD"T"HH24:MI:SS"Z"')
                ) ORDER BY s.created_at, s.id)
                FROM web_sessions s WHERE s.account_id = a.id
            ), '[]'::jsonb),
            'networks', COALESCE((
                SELECT jsonb_agg(jsonb_build_object(
                    'kind', n.kind,
                    'name', n.name,
                    'address', n.addr,
                    'tls', n.tls,
                    'nick', n.nick,
                    'username', n.username,
                    'realname', n.realname,
                    'autojoin', n.autojoin,
                    'sasl_account', n.sasl_account,
                    'has_sasl_password', n.sasl_password_sealed IS NOT NULL,
                    'has_server_password', n.server_password_sealed IS NOT NULL,
                    'enabled', n.enabled,
                    'created_at', to_char(n.created_at AT TIME ZONE 'UTC',
                        'YYYY-MM-DD"T"HH24:MI:SS"Z"')
                ) ORDER BY n.id)
                FROM bnc_networks n WHERE n.account_id = a.id
            ), '[]'::jsonb),
            'read_markers', COALESCE((
                SELECT jsonb_agg(jsonb_build_object(
                    'target', r.target,
                    'timestamp', to_char(r.marker_ts AT TIME ZONE 'UTC',
                        'YYYY-MM-DD"T"HH24:MI:SS"Z"')
                ) ORDER BY r.target)
                FROM read_markers r WHERE r.account_id = a.id
            ), '[]'::jsonb),
            'bouncer_read_markers', COALESCE((
                SELECT jsonb_agg(jsonb_build_object(
                    'network', r.network,
                    'target', r.target,
                    'timestamp', r.timestamp
                ) ORDER BY r.network, r.target)
                FROM bnc_read_markers r WHERE r.account_id = a.id
            ), '[]'::jsonb),
            'founded_channels', COALESCE((
                SELECT jsonb_agg(jsonb_build_object(
                    'name', c.name,
                    'topic', c.topic,
                    'topic_setter', c.topic_setter,
                    'topic_set_at', to_char(c.topic_set_at AT TIME ZONE 'UTC',
                        'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                    'keep_topic', c.keeptopic,
                    'mode_lock', c.mlock,
                    'created_at', to_char(c.created_at AT TIME ZONE 'UTC',
                        'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                    'access', COALESCE((
                        SELECT jsonb_agg(jsonb_build_object(
                            'account', member.name,
                            'flags', access.flags
                        ) ORDER BY member.name_folded)
                        FROM channel_access access
                        JOIN accounts member ON member.id = access.account_id
                        WHERE access.channel_id = c.id
                    ), '[]'::jsonb)
                ) ORDER BY c.id)
                FROM channels c WHERE c.founder_account_id = a.id
            ), '[]'::jsonb),
            'security_activity', COALESCE((
                SELECT jsonb_agg(jsonb_build_object(
                    'id', log.id,
                    'actor', log.actor,
                    'action', log.action,
                    'target', log.target,
                    'detail', log.detail,
                    'created_at', to_char(log.created_at AT TIME ZONE 'UTC',
                        'YYYY-MM-DD"T"HH24:MI:SS"Z"')
                ) ORDER BY log.id)
                FROM audit_log log
                WHERE {account_activity}
            ), '[]'::jsonb)
        )::text
        FROM owner a
        "#,
    )))
    .bind(&folded)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(query_error)?;
    let Some((name, head)) = head else {
        return Ok(None);
    };
    // Built from the one predicate deletion uses, so the two can never select
    // different rows. Every interpolated piece is a constant of this module.
    let predicate = ACCOUNT_MESSAGES_PREDICATE;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DECLARE export_messages NO SCROLL CURSOR FOR
         SELECT jsonb_build_object(
             'message_id', m.msgid,
             'target', m.target,
             'sender_prefix', m.sender_prefix,
             'sender_account', m.sender_account,
             'kind', m.kind,
             'body', m.body,
             'timestamp', to_char(m.ts AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
             'direct_message_peers', m.dm_peers,
             'sender_is_bot', m.sender_is_bot,
             'multiline', m.multiline,
             'client_tags', m.client_tags
         )::text
         FROM messages m WHERE {predicate} ORDER BY m.id"
    )))
    .bind(&folded)
    .bind(&name)
    .execute(&mut *transaction)
    .await
    .map_err(query_error)?;
    sqlx::query(
        "DECLARE export_backlog NO SCROLL CURSOR FOR
         SELECT jsonb_build_object(
             'network', b.network,
             'line', b.line,
             'created_at', to_char(b.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')
         )::text
         FROM bnc_buffer b WHERE b.owner = $1 ORDER BY b.id",
    )
    .bind(&folded)
    .execute(&mut *transaction)
    .await
    .map_err(query_error)?;
    Ok(Some(AccountExport {
        transaction,
        stage: AccountExportStage::Head(head),
    }))
}

impl AccountExport {
    /// The next piece of the document, or `None` once it is complete. Pieces
    /// concatenate into one JSON object: the bounded sections, then
    /// `"messages"` and `"bouncer_buffer"` arrays filled page by page.
    pub async fn next_chunk(&mut self) -> Result<Option<String>, DbError> {
        let (chunk, next) = match std::mem::replace(&mut self.stage, AccountExportStage::Done) {
            AccountExportStage::Head(head) => {
                let Some(open) = head.strip_suffix('}') else {
                    return Err(DbError::Query(sqlx::Error::Protocol(
                        "account export head is not a JSON object".into(),
                    )));
                };
                (
                    format!("{open}, \"messages\": ["),
                    AccountExportStage::Messages { first: true },
                )
            }
            AccountExportStage::Messages { first } => {
                let page = self
                    .fetch(concat!("FETCH ", export_page!(), " FROM export_messages"))
                    .await?;
                if page.is_empty() {
                    (
                        "], \"bouncer_buffer\": [".to_string(),
                        AccountExportStage::Backlog { first: true },
                    )
                } else {
                    (
                        join_page(first, &page),
                        AccountExportStage::Messages { first: false },
                    )
                }
            }
            AccountExportStage::Backlog { first } => {
                let page = self
                    .fetch(concat!("FETCH ", export_page!(), " FROM export_backlog"))
                    .await?;
                if page.is_empty() {
                    ("]}".to_string(), AccountExportStage::Done)
                } else {
                    (
                        join_page(first, &page),
                        AccountExportStage::Backlog { first: false },
                    )
                }
            }
            AccountExportStage::Done => return Ok(None),
        };
        self.stage = next;
        Ok(Some(chunk))
    }

    async fn fetch(&mut self, statement: &'static str) -> Result<Vec<String>, DbError> {
        sqlx::query_scalar(statement)
            .fetch_all(&mut *self.transaction)
            .await
            .map_err(query_error)
    }
}

/// One page of JSON array elements, comma-separated from the page before.
fn join_page(first: bool, page: &[String]) -> String {
    let body = page.join(", ");
    if first { body } else { format!(", {body}") }
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
    .map_err(query_error)
}

/// Who unregisters a channel, which names the audit row's vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelDropper<'a> {
    /// The founder, through ChanServ DROP: `CHANNEL_DROP`, as the owner
    /// console records the same change.
    Founder(&'a str),
    /// An administrator, through the console: `DROPCHAN`.
    Administrator(&'a str),
}

/// Unregister a channel by its casefolded name, audited in the same
/// transaction with the dropping account as the actor. A founder's drop is
/// refused unless the founder still founds the channel, checked with its row
/// locked; nothing is recorded when nothing was removed.
pub async fn drop_channel(
    pool: &PgPool,
    channel_folded: &str,
    dropper: ChannelDropper<'_>,
) -> Result<Result<(), ChannelRefusal>, DbError> {
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let (actor, action, dropped) = match dropper {
        ChannelDropper::Founder(actor) => {
            let channel =
                match lock_channel_as_founder(&mut transaction, channel_folded, actor).await? {
                    Ok(channel) => channel,
                    Err(refusal) => return Ok(Err(refusal)),
                };
            let dropped = sqlx::query("DELETE FROM channels WHERE id = $1")
                .bind(channel.channel_id)
                .execute(&mut *transaction)
                .await
                .map_err(query_error)?
                .rows_affected();
            (actor, "CHANNEL_DROP", dropped)
        }
        ChannelDropper::Administrator(actor) => {
            let dropped = sqlx::query("DELETE FROM channels WHERE name_folded = $1")
                .bind(channel_folded)
                .execute(&mut *transaction)
                .await
                .map_err(query_error)?
                .rows_affected();
            (actor, "DROPCHAN", dropped)
        }
    };
    if dropped != 1 {
        return Ok(Err(ChannelRefusal::ChannelMissing));
    }
    audit_channel_service(&mut transaction, actor, action, channel_folded, "").await?;
    transaction.commit().await.map_err(query_error)?;
    Ok(Ok(()))
}

/// Insert one registered channel with its initial retained topic and audit
/// record as one transition. Both ChanServ and the owner HTTP control plane use
/// this function; only their authorization and response transports differ.
pub async fn persist_channel_registration(
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
            Some(seconds_for_database(*set_at, "channels.topic_set_at")?),
        ),
        None => (None, None, None),
    };
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let Some(founder_id) = lock_account_id(&mut transaction, &founder_folded).await? else {
        return Ok(ChannelRegistrationResult::AccountMissing);
    };
    if let FounderCapacity::LimitReached = founder_capacity(&mut transaction, founder_id).await? {
        return Ok(ChannelRegistrationResult::LimitReached);
    }
    let inserted: Option<i64> = sqlx::query_scalar(
        "INSERT INTO channels (
             name, name_folded, founder_account_id,
             topic, topic_setter, topic_set_at
         )
         VALUES ($1, $2, $3, $4, $5,
                 CASE WHEN $6::double precision IS NULL
                      THEN NULL
                      ELSE to_timestamp($6::double precision)
                 END)
         ON CONFLICT (name_folded) DO NOTHING RETURNING id",
    )
    .bind(channel)
    .bind(&chan_folded)
    .bind(founder_id)
    .bind(topic_text)
    .bind(topic_setter)
    .bind(topic_set_at)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(query_error)?;
    if inserted.is_none() {
        return Ok(ChannelRegistrationResult::Exists);
    }
    insert_audit_log_with(
        &mut *transaction,
        &AuditPrincipal::account(&founder_folded),
        "CHANNEL_REGISTER",
        &AuditPrincipal::channel(&chan_folded),
        "",
    )
    .await?;
    transaction.commit().await.map_err(query_error)?;
    Ok(ChannelRegistrationResult::Registered)
}

/// Most registered channels one account may found. A registered channel is a
/// permanent `registered_founders` (and possibly `registered_topics`) entry
/// every core shard reloads at boot, and registering one runs no Argon2, so
/// without a cap one account could grow those maps without bound. Each core
/// shard checks it as a fast path, but a shard sees only its own in-flight
/// registrations and no shard sees a founder transfer's receiving side: the
/// database, where every registration and transfer lands, holds the cap, under
/// the receiving account's row lock.
pub const CHANNEL_FOUNDER_LIMIT: i64 = 200;

/// Whether the account whose row the caller has locked (`FOR NO KEY UPDATE`)
/// may found one more channel.
enum FounderCapacity {
    Available,
    LimitReached,
}

/// Count the channels `account_id` founds. The caller holds that account's row
/// lock, which every registration and founder transfer to the account also
/// takes first, so two of them cannot both pass a count of one below the cap.
async fn founder_capacity(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: i64,
) -> Result<FounderCapacity, DbError> {
    let founded: i64 =
        sqlx::query_scalar("SELECT count(*) FROM channels WHERE founder_account_id = $1")
            .bind(account_id)
            .fetch_one(&mut **transaction)
            .await
            .map_err(query_error)?;
    Ok(if founded >= CHANNEL_FOUNDER_LIMIT {
        FounderCapacity::LimitReached
    } else {
        FounderCapacity::Available
    })
}

/// The three outcomes of a credential check, before an origin is attached.
/// Kept distinct from [`DbReply`] so `handle_verify` can be reused by callers
/// that are not a SASL/IDENTIFY round trip (e.g. `issue_app_password`) without
/// inventing a bogus [`CredentialOrigin`]; the worker maps it to the
/// origin-carrying reply at the one place that knows which command asked.
enum VerifyOutcome {
    Verified(String),
    Rejected,
    Throttled(LoginRetryAfter),
    Unavailable,
}

impl VerifyOutcome {
    fn into_reply(self, origin: crate::core::CredentialOrigin) -> DbReply {
        match self {
            Self::Verified(account) => DbReply::PasswordVerified { account, origin },
            Self::Rejected => DbReply::PasswordRejected { origin },
            Self::Throttled(retry_after) => DbReply::PasswordThrottled {
                origin,
                retry_after,
            },
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
    contact_email: Option<&crate::identity::ContactEmail>,
    password: &str,
    origin: crate::core::AccountOrigin,
) -> DbReply {
    match create_account_with_contact(pool, &name, password, contact_email).await {
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
        Err(DbError::LoginThrottled(retry_after)) => VerifyOutcome::Throttled(retry_after),
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
    /// The grant was approved, but its account can no longer be given a token:
    /// it is at the per-account cap, or was suspended or deleted since. The
    /// grant is consumed, so the device is told once (`access_denied`) instead
    /// of polling to expiry.
    Denied,
    /// The grant window elapsed.
    Expired,
    /// No such grant (bad or already-consumed device code).
    Unknown,
}

/// How long a device grant may be approved and polled: RFC 8628 `expires_in`,
/// advertised by `/device/start` from this same value.
pub const DEVICE_GRANT_LIFETIME_SECONDS: u16 = 600;

/// How long an expired device grant is kept before it is pruned. A device keeps
/// polling until it is told the grant expired; pruned at expiry, the row would
/// be gone and the device told `invalid_grant` (an unknown code) instead of RFC
/// 8628's `expired_token`, which is what tells it to start over.
const DEVICE_GRANT_EXPIRED_RETENTION_SECONDS: i32 = 600;

/// Start a device grant: a secret `device_code` the client polls with and
/// a short `user_code` the user enters to approve. Valid for
/// [`DEVICE_GRANT_LIFETIME_SECONDS`].
pub async fn create_device_grant(pool: &PgPool) -> Result<(String, String), DbError> {
    use argon2::password_hash::rand_core::RngCore;
    // URL-safe: a device code in a form body spelled with `+` would arrive as
    // a space from any client that does not percent-encode it.
    let device_code = crate::secret::random_url_safe_token();
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
    // flood of never-approved starts would grow the table without bound. The
    // same bounded batch storage maintenance runs, past the same grace.
    sqlx::query(MaintenanceCollection::DeviceGrants.statement())
        .bind(DEVICE_GRANT_EXPIRED_RETENTION_SECONDS)
        .bind(STORAGE_MAINTENANCE_BATCH as i64)
        .execute(pool)
        .await
        .map_err(query_error)?;
    sqlx::query(
        "INSERT INTO device_grants (device_code, user_code, expires_at)
         VALUES ($1, $2, now() + make_interval(secs => $3))",
    )
    .bind(&device_code)
    .bind(&user_code)
    .bind(i32::from(DEVICE_GRANT_LIFETIME_SECONDS))
    .execute(pool)
    .await
    .map_err(query_error)?;
    Ok((device_code, user_code))
}

/// What became of an attempt to approve a device grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceApproval {
    Approved,
    /// No pending, unexpired grant has that user code.
    NoPendingGrant,
    /// The approving account already holds [`MAX_API_TOKENS_PER_ACCOUNT`]
    /// tokens. The grant is left pending: the person reading this can revoke a
    /// token and approve again.
    TokenLimitReached,
}

/// Approve a pending grant by its `user_code`, binding it to `account`.
///
/// The cap is checked here so the person approving is the one told about it,
/// while they can act on it. It is *enforced* where the token is minted
/// ([`poll_device_grant`]); a slot taken between the two surfaces there.
pub async fn approve_device_grant(
    pool: &PgPool,
    user_code: &str,
    account: &str,
) -> Result<DeviceApproval, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let mut tx = pool.begin().await.map_err(query_error)?;
    let account_id = lock_active_account_id(&mut tx, &folded).await?;
    if api_token_count(&mut tx, account_id).await? >= MAX_API_TOKENS_PER_ACCOUNT {
        return Ok(DeviceApproval::TokenLimitReached);
    }
    let res = sqlx::query(
        "UPDATE device_grants SET account_id = $2
         WHERE user_code = $1 AND account_id IS NULL AND expires_at > now()",
    )
    .bind(user_code)
    .bind(account_id)
    .execute(&mut *tx)
    .await
    .map_err(query_error)?;
    tx.commit().await.map_err(query_error)?;
    Ok(if res.rows_affected() > 0 {
        DeviceApproval::Approved
    } else {
        DeviceApproval::NoPendingGrant
    })
}

/// Poll a grant; if approved and valid, atomically consume it and mint the
/// caller's API token (labelled `token_label`) in the same transaction,
/// returning the token in [`DeviceStatus::Approved`].
///
/// Consume-and-mint is one transaction on purpose: if the mint fails for a
/// transient reason (a database error), the transaction rolls back and the
/// approved grant is left intact, so the client's next poll retries rather than
/// being forced to restart the whole device flow. A mint that can never succeed
/// — the account is at its token cap, or is suspended or gone — is different:
/// the grant is consumed, the denial is audited, and the device is answered
/// [`DeviceStatus::Denied`] once, because retrying would only poll to expiry.
/// The `DELETE ... RETURNING` row lock still guarantees only one concurrent
/// poll can win, so there is no double-mint.
pub async fn poll_device_grant(
    pool: &PgPool,
    device_code: &str,
    token_label: &str,
) -> Result<DeviceStatus, DbError> {
    let mut tx = pool.begin().await.map_err(query_error)?;
    let approved: Option<String> = sqlx::query_scalar(
        "DELETE FROM device_grants g USING accounts a
         WHERE g.device_code = $1 AND g.account_id = a.id AND g.expires_at > now()
         RETURNING a.name",
    )
    .bind(device_code)
    .fetch_optional(&mut *tx)
    .await
    .map_err(query_error)?;
    if let Some(account) = approved {
        let folded = CaseMapping::Rfc1459.casefold(&account);
        // Mint in the same transaction: on a transient error `tx` drops without
        // commit, rolling the DELETE back so the grant survives for the next poll.
        let token = match mint_api_token_under_cap(
            &mut tx,
            &account,
            token_label,
            crate::identity::ApiTokenScopes::device_access(),
            crate::identity::ApiTokenLifetimeDays::DEFAULT,
        )
        .await
        {
            Ok(token) => token,
            Err(refusal @ (DbError::TooManyCredentials | DbError::BadCredentials)) => {
                insert_audit_log_with(
                    &mut *tx,
                    &AuditPrincipal::account(&folded),
                    "ACCOUNT_DEVICE_TOKEN_DENIED",
                    &AuditPrincipal::account(&folded),
                    match refusal {
                        DbError::TooManyCredentials => {
                            "approved device grant denied: personal access token limit reached"
                        }
                        _ => "approved device grant denied: account is suspended or gone",
                    },
                )
                .await?;
                tx.commit().await.map_err(query_error)?;
                return Ok(DeviceStatus::Denied);
            }
            Err(error) => return Err(error),
        };
        insert_audit_log_with(
            &mut *tx,
            &AuditPrincipal::account(&folded),
            "ACCOUNT_DEVICE_TOKEN_CREATE",
            &AuditPrincipal::account(&folded),
            "personal access token created from an approved device grant",
        )
        .await?;
        tx.commit().await.map_err(query_error)?;
        return Ok(DeviceStatus::Approved(token));
    }
    let row: Option<(bool,)> =
        sqlx::query_as("SELECT expires_at > now() FROM device_grants WHERE device_code = $1")
            .bind(device_code)
            .fetch_optional(&mut *tx)
            .await
            .map_err(query_error)?;
    tx.commit().await.map_err(query_error)?;
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
    .map_err(query_error)
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct AccountDirectoryRow {
    pub id: i64,
    pub name: String,
    pub created_at: String,
    pub has_local_password: bool,
    pub app_passwords: i64,
    pub api_tokens: i64,
    pub oidc_identities: i64,
    pub browser_sessions: i64,
    pub networks: i64,
    pub founded_channels: i64,
    pub administrator: bool,
    pub suspended: bool,
    /// Presentation-only marker set by the authenticated console boundary.
    /// The database query always returns false because "current" is relative
    /// to the request actor, not durable account state.
    pub current: bool,
    /// Presentation-only authority source set by the HTTP boundary.
    pub configured_administrator: bool,
    /// Presentation-only union of durable and configured authority.
    pub effective_administrator: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct AccountDirectoryFilter<'a> {
    pub before_id: Option<i64>,
    pub exact_name: Option<&'a str>,
    pub page_size: AccountDirectoryPageSize,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AccountDirectoryPage {
    pub entries: Vec<AccountDirectoryRow>,
    pub next_before_id: Option<i64>,
}

bounded_page_size!(
    AccountDirectoryPageSize,
    "A non-zero account-directory page size capped at the public API maximum."
);

/// Query administrator-safe account posture newest-first. No credential hash,
/// bearer token, session hash, OIDC subject, or sealed network secret crosses
/// this boundary.
pub async fn query_account_directory(
    pool: &PgPool,
    filter: AccountDirectoryFilter<'_>,
) -> Result<AccountDirectoryPage, DbError> {
    let page_size = filter.page_size.value();
    let fetch_limit = page_size + 1;
    let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT a.id, a.name,
                to_char(a.created_at AT TIME ZONE 'UTC',
                        'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS created_at,
                EXISTS (
                    SELECT 1 FROM account_credentials c
                    WHERE c.account_id = a.id AND c.kind = 'local_password'
                ) AS has_local_password,
                (SELECT count(*) FROM account_credentials c
                 WHERE c.account_id = a.id AND c.kind = 'app_password') AS app_passwords,
                (SELECT count(*) FROM api_tokens t
                 WHERE t.account_id = a.id
                   AND t.expires_at > now()) AS api_tokens,
                (SELECT count(*) FROM oidc_identities i
                 WHERE i.account_id = a.id) AS oidc_identities,
                (SELECT count(*) FROM web_sessions s
                 WHERE s.account_id = a.id AND s.expires_at > now()) AS browser_sessions,
                (SELECT count(*) FROM bnc_networks n
                 WHERE n.account_id = a.id) AS networks,
                (SELECT count(*) FROM channels ch
                 WHERE ch.founder_account_id = a.id) AS founded_channels,
                (a.flags & 1) = 1 AS administrator,
                (a.flags & 2) = 2 AS suspended,
                FALSE AS current,
                FALSE AS configured_administrator,
                FALSE AS effective_administrator
         FROM accounts a WHERE TRUE",
    );
    if let Some(before_id) = filter.before_id {
        query.push(" AND a.id < ").push_bind(before_id);
    }
    if let Some(exact_name) = filter.exact_name {
        let folded = CaseMapping::Rfc1459.casefold(exact_name);
        query.push(" AND a.name_folded = ").push_bind(folded);
    }
    query
        .push(" ORDER BY a.id DESC LIMIT ")
        .push_bind(fetch_limit as i64);
    let (entries, next_before_id) = fetch_keyset_page!(pool, query, AccountDirectoryRow, page_size);
    Ok(AccountDirectoryPage {
        entries,
        next_before_id,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct RegisteredChannelDirectoryRow {
    pub id: i64,
    pub name: String,
    pub founder: String,
    /// The account the channel passes to if the founder's is deleted.
    pub successor: Option<String>,
    pub created_at: String,
    pub keeptopic: bool,
    pub topic_retained: bool,
    pub mlock: Option<String>,
    pub access_entries: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct RegisteredChannelDirectoryFilter<'a> {
    pub before_id: Option<i64>,
    pub exact_name: Option<&'a str>,
    pub exact_founder: Option<&'a str>,
    pub page_size: RegisteredChannelDirectoryPageSize,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RegisteredChannelDirectoryPage {
    pub entries: Vec<RegisteredChannelDirectoryRow>,
    pub next_before_id: Option<i64>,
}

bounded_page_size!(
    RegisteredChannelDirectoryPageSize,
    "A non-zero registered-channel directory page size capped at the public API maximum."
);

/// Query administrator-safe registered-channel posture newest-first. Exact
/// channel and founder filters use the same RFC1459 folding keys as live
/// ownership and authentication.
pub async fn query_registered_channel_directory(
    pool: &PgPool,
    filter: RegisteredChannelDirectoryFilter<'_>,
) -> Result<RegisteredChannelDirectoryPage, DbError> {
    let page_size = filter.page_size.value();
    let fetch_limit = page_size + 1;
    let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT c.id, c.name, a.name AS founder, successor.name AS successor,
                to_char(c.created_at AT TIME ZONE 'UTC',
                        'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS created_at,
                c.keeptopic, c.topic IS NOT NULL AS topic_retained, c.mlock,
                (SELECT count(*) FROM channel_access ca
                 WHERE ca.channel_id = c.id) AS access_entries
         FROM channels c
         JOIN accounts a ON a.id = c.founder_account_id
         LEFT JOIN accounts successor ON successor.id = c.successor_account_id
         WHERE TRUE",
    );
    if let Some(before_id) = filter.before_id {
        query.push(" AND c.id < ").push_bind(before_id);
    }
    if let Some(exact_name) = filter.exact_name {
        let folded = CaseMapping::Rfc1459.casefold(exact_name);
        query.push(" AND c.name_folded = ").push_bind(folded);
    }
    if let Some(exact_founder) = filter.exact_founder {
        let folded = CaseMapping::Rfc1459.casefold(exact_founder);
        query.push(" AND a.name_folded = ").push_bind(folded);
    }
    query
        .push(" ORDER BY c.id DESC LIMIT ")
        .push_bind(fetch_limit as i64);
    let (entries, next_before_id) =
        fetch_keyset_page!(pool, query, RegisteredChannelDirectoryRow, page_size);
    Ok(RegisteredChannelDirectoryPage {
        entries,
        next_before_id,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct ServerBanDirectoryRow {
    pub id: i64,
    pub kind: String,
    pub mask: String,
    pub reason: String,
    pub set_by: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy)]
pub struct ServerBanDirectoryFilter<'a> {
    pub before_id: Option<i64>,
    pub exact_kind: Option<&'a str>,
    pub exact_mask: Option<&'a str>,
    pub page_size: ServerBanDirectoryPageSize,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ServerBanDirectoryPage {
    pub entries: Vec<ServerBanDirectoryRow>,
    pub next_before_id: Option<i64>,
}

/// Look up one immutable administrator policy resource. Its ID is resolved
/// before the core receives the mutation, preventing a stale client from
/// deleting a later ban that reused the same visible mask.
pub async fn server_ban_directory_entry(
    pool: &PgPool,
    id: i64,
) -> Result<Option<ServerBanDirectoryRow>, DbError> {
    sqlx::query_as(
        "SELECT b.id, b.kind, COALESCE(b.mask_display, b.mask) AS mask,
                b.reason, b.set_by,
                to_char(b.created_at AT TIME ZONE 'UTC',
                        'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS created_at
         FROM server_bans b WHERE b.id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(query_error)
}

bounded_page_size!(
    ServerBanDirectoryPageSize,
    "A non-zero server-ban directory page size capped at the public API maximum."
);

/// Query persisted server policy bans newest-first. Display casing is returned
/// while exact mask matching uses the same folded key as enforcement and
/// removal.
pub async fn query_server_ban_directory(
    pool: &PgPool,
    filter: ServerBanDirectoryFilter<'_>,
) -> Result<ServerBanDirectoryPage, DbError> {
    let page_size = filter.page_size.value();
    let fetch_limit = page_size + 1;
    let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT b.id, b.kind, COALESCE(b.mask_display, b.mask) AS mask,
                b.reason, b.set_by,
                to_char(b.created_at AT TIME ZONE 'UTC',
                        'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS created_at
         FROM server_bans b WHERE TRUE",
    );
    if let Some(before_id) = filter.before_id {
        query.push(" AND b.id < ").push_bind(before_id);
    }
    if let Some(exact_kind) = filter.exact_kind {
        query.push(" AND b.kind = ").push_bind(exact_kind);
    }
    if let Some(exact_mask) = filter.exact_mask {
        let folded = CaseMapping::Rfc1459.casefold(exact_mask);
        query.push(" AND b.mask = ").push_bind(folded);
    }
    query
        .push(" ORDER BY b.id DESC LIMIT ")
        .push_bind(fetch_limit as i64);
    let (entries, next_before_id) =
        fetch_keyset_page!(pool, query, ServerBanDirectoryRow, page_size);
    Ok(ServerBanDirectoryPage {
        entries,
        next_before_id,
    })
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

/// Password attempts one account name may use in a window before further
/// attempts are refused unverified.
pub const LOGIN_ATTEMPT_LIMIT: i32 = 10;
/// The window [`LOGIN_ATTEMPT_LIMIT`] counts within, from its first attempt.
pub const LOGIN_ATTEMPT_WINDOW: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// Whole seconds until an account name's password attempts are admitted again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginRetryAfter(u64);

impl LoginRetryAfter {
    /// A wait of `seconds`, never less than one: a refusal always asks the
    /// client to wait.
    pub fn new(seconds: u64) -> Self {
        Self(seconds.max(1))
    }

    pub fn seconds(self) -> u64 {
        self.0
    }

    /// What a refused attempt is told, on every surface that checks a
    /// password: the IRC core's SASL 904 and NickServ notice, the attach
    /// listener's 904, and the HTTP 429's detail.
    pub fn explanation(self) -> String {
        format!(
            "Too many failed login attempts for this account; try again in {} seconds",
            self.0
        )
    }
}

/// Reserve one password attempt for `folded`, or refuse it when the name's
/// window is spent. The reservation is taken *before* the password is checked
/// and in one statement, so concurrent attempts cannot all pass a count read
/// before any of them was recorded. Keyed by name whether or not an account
/// holds it, so a refusal is not an existence oracle.
async fn reserve_login_attempt(pool: &PgPool, folded: &str) -> Result<(), DbError> {
    let window = LOGIN_ATTEMPT_WINDOW.as_secs_f64();
    sqlx::query(
        "DELETE FROM login_attempts
         WHERE window_started_at <= now() - make_interval(secs => $1)",
    )
    .bind(window)
    .execute(pool)
    .await
    .map_err(query_error)?;
    let (attempts, retry_after): (i32, i64) = sqlx::query_as(
        "INSERT INTO login_attempts (name_folded, attempts) VALUES ($1, 1)
         ON CONFLICT (name_folded) DO UPDATE
             SET attempts = LEAST(login_attempts.attempts, $3) + 1
         RETURNING attempts,
                   CEIL(EXTRACT(EPOCH FROM
                       window_started_at + make_interval(secs => $2) - now()))::bigint",
    )
    .bind(folded)
    .bind(window)
    .bind(LOGIN_ATTEMPT_LIMIT)
    .fetch_one(pool)
    .await
    .map_err(query_error)?;
    if attempts > LOGIN_ATTEMPT_LIMIT {
        return Err(DbError::LoginThrottled(LoginRetryAfter::new(
            u64::try_from(retry_after).unwrap_or(0),
        )));
    }
    Ok(())
}

/// A verified password ends the name's attempt window.
async fn clear_login_attempts(pool: &PgPool, folded: &str) -> Result<(), DbError> {
    sqlx::query("DELETE FROM login_attempts WHERE name_folded = $1")
        .bind(folded)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(query_error)
}

/// The one gate every password check passes: reserve an attempt for the
/// account name, run `verify`, and clear the window when it verified.
async fn throttled_password_check<T>(
    pool: &PgPool,
    account: &str,
    verify: impl std::future::Future<Output = Result<Option<T>, DbError>>,
) -> Result<Option<T>, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    reserve_login_attempt(pool, &folded).await?;
    let verdict = verify.await?;
    if verdict.is_some() {
        clear_login_attempts(pool, &folded).await?;
    }
    Ok(verdict)
}

/// The folded account a login name signs in to: the account a grouped nick
/// belongs to (NickServ GROUP — Atheme lets any of an account's nicks
/// identify), or the name itself. Resolved before the attempt is reserved, so
/// every nick of an account spends the one budget its name has.
async fn login_account_folded(pool: &PgPool, login: &str) -> Result<String, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(login);
    sqlx::query_scalar(
        "SELECT COALESCE(
             (SELECT a.name_folded FROM account_nicks n JOIN accounts a ON a.id = n.account_id
              WHERE n.nick_folded = $1),
             $1)",
    )
    .bind(&folded)
    .fetch_one(pool)
    .await
    .map_err(query_error)
}

#[derive(sqlx::FromRow)]
struct CredentialVerificationRow {
    display_name: String,
    argon2_hash: String,
    credential_id: i64,
}

/// Verify an account password or app password.
///
/// Every attempt costs two Argon2 computations under one permit, whether or
/// not the account exists (see [`plan_credential_verification`]), and first
/// reserves one of the name's [`LOGIN_ATTEMPT_LIMIT`] attempts: past it the
/// answer is [`DbError::LoginThrottled`] and nothing is verified.
pub async fn verify_credentials(
    pool: &PgPool,
    account: &str,
    password: &str,
) -> Result<Option<String>, DbError> {
    let account = &login_account_folded(pool, account).await?;
    throttled_password_check(
        pool,
        account,
        verify_any_credential(pool, account, password),
    )
    .await
}

async fn verify_any_credential(
    pool: &PgPool,
    account: &str,
    password: &str,
) -> Result<Option<String>, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let display_name: Option<String> =
        sqlx::query_scalar("SELECT name FROM accounts WHERE name_folded = $1 AND (flags & $2) = 0")
            .bind(&folded)
            .bind(ACCOUNT_FLAG_SUSPENDED)
            .fetch_optional(pool)
            .await
            .map_err(query_error)?;
    let stored: Vec<StoredCredential> = sqlx::query_as(
        "SELECT c.id AS credential_id, c.argon2_hash,
                c.secret_lookup AS app_password_lookup
         FROM accounts a
         JOIN account_credentials c ON c.account_id = a.id
         WHERE a.name_folded = $1 AND (a.flags & $2) = 0
         ORDER BY c.id",
    )
    .bind(&folded)
    .bind(ACCOUNT_FLAG_SUSPENDED)
    .fetch_all(pool)
    .await
    .map_err(query_error)?;
    let plan = plan_credential_verification(stored, password);
    let matched_id =
        matching_credential_id(plan.candidates, plan.dummies, password.to_string()).await?;
    let (Some(display_name), Some(id)) = (display_name, matched_id) else {
        return Ok(None);
    };
    record_credential_use(pool, id).await?;
    Ok(Some(display_name))
}

/// Record that credential `credential_id` just verified, for the credential
/// list's "last used". Both password checks end here. A failure is the
/// verification's failure: the database that could not record the use is the
/// one the login is about to depend on, and a success reported past a failed
/// write is the "log and continue" DESIGN §2 rules out.
async fn record_credential_use(pool: &PgPool, credential_id: i64) -> Result<(), DbError> {
    sqlx::query("UPDATE account_credentials SET last_used_at = now() WHERE id = $1")
        .bind(credential_id)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(query_error)
}

/// Verify only an account's primary password.
pub async fn verify_local_password(
    pool: &PgPool,
    account: &str,
    password: &str,
) -> Result<Option<String>, DbError> {
    let account = &login_account_folded(pool, account).await?;
    throttled_password_check(
        pool,
        account,
        verify_primary_password(pool, account, password),
    )
    .await
}

async fn verify_primary_password(
    pool: &PgPool,
    account: &str,
    password: &str,
) -> Result<Option<String>, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let row: Option<CredentialVerificationRow> = sqlx::query_as(
        "SELECT a.name AS display_name, c.argon2_hash, c.id AS credential_id FROM accounts a
         JOIN account_credentials c ON c.account_id = a.id
         WHERE a.name_folded = $1
           AND c.kind = 'local_password'
           AND (a.flags & $2) = 0",
    )
    .bind(&folded)
    .bind(ACCOUNT_FLAG_SUSPENDED)
    .fetch_optional(pool)
    .await
    .map_err(query_error)?;
    let Some(CredentialVerificationRow {
        display_name,
        argon2_hash,
        credential_id,
    }) = row
    else {
        spend_dummy_verification(password.to_string()).await;
        return Ok(None);
    };
    let matched = matching_credential_id(
        vec![CredentialHash {
            credential_id,
            argon2_hash,
        }],
        0,
        password.to_string(),
    )
    .await?;
    if matched.is_some() {
        record_credential_use(pool, credential_id).await?;
        Ok(Some(display_name))
    } else {
        Ok(None)
    }
}

async fn lock_account_id(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    folded_account: &str,
) -> Result<Option<i64>, DbError> {
    sqlx::query_scalar("SELECT id FROM accounts WHERE name_folded = $1 FOR NO KEY UPDATE")
        .bind(folded_account)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(query_error)
}

struct PasswordMutation<'a> {
    transaction: sqlx::Transaction<'a, sqlx::Postgres>,
    folded: String,
    new_hash: String,
    account_id: Option<i64>,
}

/// Start a locked password-mutation transaction.
async fn begin_password_mutation<'a>(
    pool: &'a PgPool,
    account: &str,
    new_password: &str,
) -> Result<PasswordMutation<'a>, DbError> {
    let new_hash = hash_password(new_password.to_string()).await?;
    let folded = CaseMapping::Rfc1459.casefold(account);
    let mut tx = pool.begin().await.map_err(query_error)?;
    let account_id = lock_account_id(&mut tx, &folded).await?;
    Ok(PasswordMutation {
        transaction: tx,
        folded,
        new_hash,
        account_id,
    })
}

#[derive(sqlx::FromRow)]
struct LocalCredentialRow {
    credential_id: i64,
    argon2_hash: String,
}

/// Replace an account's primary password after verifying the current primary
/// credential.
///
/// Both Argon2 computations — verifying the current password, hashing the new
/// one — run before any transaction begins: each may wait for one of the few
/// process-wide Argon2 permits, and a row lock held across that wait blocked
/// every foreign-key insert that referenced the account (a read marker, a
/// session) for as long as the queue took. The commit is instead a
/// compare-and-swap on the hash that was verified: a concurrent rotation that
/// committed first leaves no row matching it, and this one fails as
/// [`DbError::BadCredentials`] rather than overwriting a password it never
/// authorized against.
///
/// Every browser session other than `current_session` — the one that made the
/// change — ends in the same transaction: a password is changed because the old
/// one may be known to someone else, and that someone may be signed in. App
/// passwords and personal access tokens are separately managed credentials and
/// are left alone; the response says so.
pub async fn change_local_password(
    pool: &PgPool,
    account: &str,
    current_password: &str,
    new_password: &str,
    current_session: &str,
) -> Result<(), DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let row: Option<LocalCredentialRow> = sqlx::query_as(
        "SELECT c.id AS credential_id, c.argon2_hash
         FROM account_credentials c JOIN accounts a ON a.id = c.account_id
         WHERE a.name_folded = $1 AND c.kind = 'local_password'",
    )
    .bind(&folded)
    .fetch_optional(pool)
    .await
    .map_err(query_error)?;
    let verified = throttled_password_check(pool, account, async {
        let Some(LocalCredentialRow {
            credential_id,
            argon2_hash,
        }) = row
        else {
            spend_dummy_verification(current_password.to_string()).await;
            return Ok(None);
        };
        let matched = matching_credential_id(
            vec![CredentialHash {
                credential_id,
                argon2_hash: argon2_hash.clone(),
            }],
            0,
            current_password.to_string(),
        )
        .await?;
        Ok(matched.map(|_| (credential_id, argon2_hash)))
    })
    .await?;
    let Some((credential_id, argon2_hash)) = verified else {
        return Err(DbError::BadCredentials);
    };
    let new_hash = hash_password(new_password.to_string()).await?;
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let swapped = sqlx::query(
        "UPDATE account_credentials
         SET argon2_hash = $1, last_used_at = now()
         WHERE id = $2 AND argon2_hash = $3",
    )
    .bind(new_hash)
    .bind(credential_id)
    .bind(&argon2_hash)
    .execute(&mut *transaction)
    .await
    .map_err(query_error)?;
    if swapped.rows_affected() == 0 {
        return Err(DbError::BadCredentials);
    }
    delete_other_web_sessions_in(&mut transaction, &folded, current_session).await?;
    insert_audit_log_with(
        &mut *transaction,
        &AuditPrincipal::account(&folded),
        "ACCOUNT_PASSWORD_CHANGE",
        &AuditPrincipal::account(&folded),
        "primary password changed; other browser sessions ended",
    )
    .await?;
    transaction.commit().await.map_err(query_error)?;
    Ok(())
}

/// Add the first primary password to an authenticated account provisioned by
/// OIDC. The account-row lock plus the partial unique index serialize and
/// enforce the absent-to-present transition. Other browser sessions end as they
/// do for [`change_local_password`]: a new way into the account is a
/// credential change, and whoever else is signed in does not get to keep
/// riding a session opened before it existed.
pub async fn set_local_password(
    pool: &PgPool,
    account: &str,
    new_password: &str,
    current_session: &str,
) -> Result<(), DbError> {
    let PasswordMutation {
        mut transaction,
        folded,
        new_hash,
        account_id,
    } = begin_password_mutation(pool, account, new_password).await?;
    let Some(account_id) = account_id else {
        return Err(DbError::BadCredentials);
    };
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM account_credentials
             WHERE account_id = $1 AND kind = 'local_password'
         )",
    )
    .bind(account_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(query_error)?;
    if exists {
        return Err(DbError::LocalPasswordExists);
    }
    insert_primary_password(&mut transaction, account_id, &new_hash).await?;
    delete_other_web_sessions_in(&mut transaction, &folded, current_session).await?;
    insert_audit_log_with(
        &mut *transaction,
        &AuditPrincipal::account(&folded),
        "ACCOUNT_PASSWORD_ADD",
        &AuditPrincipal::account(&folded),
        "primary password added; other browser sessions ended",
    )
    .await?;
    transaction.commit().await.map_err(query_error)?;
    Ok(())
}

// ---- per-account BNC networks (DESIGN §10.3) ----------------------------

/// A stored per-account BNC network. `sasl_password_sealed` and
/// `server_password_sealed` are sealed blobs (or `None`); the caller opens
/// them with the master key before starting the driver.
#[derive(Debug, Clone)]
pub struct BncNetworkRow {
    /// Which driver backs this network (`irc` for a plain upstream, or a
    /// `matrix`/`discord`/`slack` bridge).
    pub kind: crate::config::NetworkKind,
    pub name: String,
    pub addr: String,
    pub tls: bool,
    pub nick: String,
    /// The IRC `USER` name. Present exactly for `kind = irc` (a table CHECK).
    pub username: Option<String>,
    pub realname: Option<String>,
    pub autojoin: Vec<String>,
    pub sasl_account: Option<String>,
    pub sasl_password_sealed: Option<String>,
    /// The sealed IRC server password (`PASS`). Only `kind = irc` carries one
    /// (a table CHECK).
    pub server_password_sealed: Option<String>,
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
        username: row.get("username"),
        realname: row.get("realname"),
        enabled: row.get("enabled"),
        autojoin: row.get("autojoin"),
        sasl_account: row.get("sasl_account"),
        sasl_password_sealed: row.get("sasl_password_sealed"),
        server_password_sealed: row.get("server_password_sealed"),
    })
}

/// The columns [`bnc_row`] decodes, qualified by the `n` alias every network
/// query gives `bnc_networks`. One list, so a column added to the row cannot
/// be read by one query and missed by another.
macro_rules! bnc_network_columns {
    () => {
        "n.name, n.addr, n.tls, n.nick, n.username, n.realname, n.autojoin, \
         n.sasl_account, n.sasl_password_sealed, n.server_password_sealed, n.enabled, n.kind"
    };
}

/// Who changed a network, and what the audit row says about it. The audit row
/// is written inside the mutation's own transaction: a network change nobody
/// is on record for cannot commit, and a recorded change always happened.
#[derive(Debug, Clone, Copy)]
pub struct NetworkAudit<'a> {
    /// The account that acted (folded before it is recorded) — the owner, or
    /// an administrator acting on the owner's network.
    pub actor: &'a str,
    pub detail: &'a str,
}

/// Record one network mutation inside its transaction, targeting
/// `owner/network` by the owner's folded name and the stored network name.
async fn audit_network_mutation(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    audit: NetworkAudit<'_>,
    action: &str,
    owner_folded: &str,
    network: &str,
) -> Result<(), DbError> {
    insert_audit_log_with(
        &mut **transaction,
        &AuditPrincipal::account(&CaseMapping::Rfc1459.casefold(audit.actor)),
        action,
        &AuditPrincipal::network(&format!("{owner_folded}/{network}")),
        audit.detail,
    )
    .await
}

/// Create a network owned by `account`. Errors with `DuplicateNetwork`
/// on a name collision for that owner, `BadCredentials` if the account
/// is unknown.
pub async fn create_bnc_network(
    pool: &PgPool,
    account: &str,
    net: &BncNetworkRow,
    audit: NetworkAudit<'_>,
) -> Result<i64, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    // Cap the count and insert in one transaction with the account row locked
    // FOR NO KEY UPDATE. A count-then-insert across two pool statements (which is what
    // the REST handler used to do) lets two concurrent creates each read cap-1
    // and both insert, overshooting the cap — and each network spawns an
    // always-on outbound driver, the very amplifier this cap exists to bound.
    let mut tx = pool.begin().await.map_err(query_error)?;
    let account_id: i64 =
        sqlx::query_scalar("SELECT id FROM accounts WHERE name_folded = $1 FOR NO KEY UPDATE")
            .bind(&folded)
            .fetch_optional(&mut *tx)
            .await
            .map_err(query_error)?
            .ok_or(DbError::BadCredentials)?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM bnc_networks WHERE account_id = $1")
        .bind(account_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(query_error)?;
    if count >= MAX_BNC_NETWORKS_PER_ACCOUNT {
        return Err(DbError::TooManyNetworks);
    }
    let id = sqlx::query_scalar(
        "INSERT INTO bnc_networks
           (account_id, name, addr, tls, nick, realname, autojoin,
            sasl_account, sasl_password_sealed, kind, enabled, username,
            server_password_sealed)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
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
    .bind(&net.username)
    .bind(&net.server_password_sealed)
    .fetch_optional(&mut *tx)
    .await
    .map_err(query_error)?
    .ok_or_else(|| DbError::DuplicateNetwork(net.name.clone()))?;
    audit_network_mutation(&mut tx, audit, "NETWORK_CREATE", &folded, &net.name).await?;
    tx.commit().await.map_err(query_error)?;
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
    let rows = sqlx::query(concat!(
        "SELECT ",
        bnc_network_columns!(),
        " FROM bnc_networks n JOIN accounts a ON a.id = n.account_id
         WHERE a.name_folded = $1 ORDER BY n.name"
    ))
    .bind(&folded)
    .fetch_all(pool)
    .await
    .map_err(query_error)?;
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
    let rows = sqlx::query(concat!(
        "SELECT a.name AS owner, ",
        bnc_network_columns!(),
        " FROM bnc_networks n JOIN accounts a ON a.id = n.account_id
         ORDER BY a.name_folded, lower(n.name)"
    ))
    .fetch_all(pool)
    .await
    .map_err(query_error)?;
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
    let row = sqlx::query(concat!(
        "SELECT ",
        bnc_network_columns!(),
        " FROM bnc_networks n JOIN accounts a ON a.id = n.account_id
         WHERE a.name_folded = $1 AND lower(n.name) = lower($2)"
    ))
    .bind(&folded)
    .bind(name)
    .fetch_optional(pool)
    .await
    .map_err(query_error)?;
    row.as_ref().map(bnc_row).transpose()
}

/// Enable or disable `account`'s network `name`, audited in the same
/// transaction. Returns whether a row matched (false ⇒ no such network for
/// that owner, and nothing is recorded).
pub async fn set_bnc_network_enabled(
    pool: &PgPool,
    account: &str,
    name: &str,
    enabled: bool,
    audit: NetworkAudit<'_>,
) -> Result<bool, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let stored: Option<String> = sqlx::query_scalar(
        "UPDATE bnc_networks n SET enabled = $3
         FROM accounts a
         WHERE n.account_id = a.id AND a.name_folded = $1 AND lower(n.name) = lower($2)
         RETURNING n.name",
    )
    .bind(&folded)
    .bind(name)
    .bind(enabled)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(query_error)?;
    let Some(stored) = stored else {
        return Ok(false);
    };
    audit_network_mutation(&mut transaction, audit, "NETWORK_TOGGLE", &folded, &stored).await?;
    transaction.commit().await.map_err(query_error)?;
    Ok(true)
}

/// Update all mutable fields of `account`'s network `name`. Secret values in
/// `network` are already sealed; this storage edge never receives plaintext.
/// The kind, stable name, and enabled state are deliberately immutable here.
/// Returns whether a row matched (false ⇒ no such network for that owner, and
/// nothing is recorded); the audit row commits with the change.
pub async fn update_bnc_network(
    pool: &PgPool,
    account: &str,
    name: &str,
    network: &BncNetworkRow,
    audit: NetworkAudit<'_>,
) -> Result<bool, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let stored: Option<String> = sqlx::query_scalar(
        "UPDATE bnc_networks n
         SET addr = $3, tls = $4, nick = $5, realname = $6, autojoin = $7,
             sasl_account = $8, sasl_password_sealed = $9, username = $10,
             server_password_sealed = $11
         FROM accounts a
         WHERE n.account_id = a.id AND a.name_folded = $1 AND lower(n.name) = lower($2)
         RETURNING n.name",
    )
    .bind(&folded)
    .bind(name)
    .bind(&network.addr)
    .bind(network.tls)
    .bind(&network.nick)
    .bind(&network.realname)
    .bind(&network.autojoin)
    .bind(&network.sasl_account)
    .bind(&network.sasl_password_sealed)
    .bind(&network.username)
    .bind(&network.server_password_sealed)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(query_error)?;
    let Some(stored) = stored else {
        return Ok(false);
    };
    audit_network_mutation(&mut transaction, audit, "NETWORK_UPDATE", &folded, &stored).await?;
    transaction.commit().await.map_err(query_error)?;
    Ok(true)
}

/// Every network whose driver runs at boot, paired with its owner's display
/// name: enabled, and owned by an account that is not suspended. Suspension
/// leaves `enabled` set so reactivation can restore the owner's networks, so
/// the flag alone would restart every suspended account's upstream sessions —
/// with their stored credentials — on the next process start.
pub async fn list_startable_bnc_networks(
    pool: &PgPool,
) -> Result<Vec<(String, BncNetworkRow)>, DbError> {
    use sqlx::Row;
    let rows = sqlx::query(concat!(
        "SELECT a.name AS owner, ",
        bnc_network_columns!(),
        " FROM bnc_networks n JOIN accounts a ON a.id = n.account_id
         WHERE n.enabled AND (a.flags & $1) = 0"
    ))
    .bind(ACCOUNT_FLAG_SUSPENDED)
    .fetch_all(pool)
    .await
    .map_err(query_error)?;
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
    .map_err(query_error)?;
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
    /// The account the channel passes to if the founder's is deleted.
    pub successor: Option<String>,
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
    successor: Option<String>,
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
                successor.name AS successor,
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
         LEFT JOIN accounts successor ON successor.id = c.successor_account_id
         LEFT JOIN channel_access ca ON ca.channel_id = c.id
         LEFT JOIN accounts access_account ON access_account.id = ca.account_id
         WHERE founder.name_folded = $1
         ORDER BY c.name_folded, access_account.name_folded",
    )
    .bind(account_folded)
    .fetch_all(pool)
    .await
    .map_err(query_error)?;

    let mut channels: Vec<OwnedChannel> = Vec::new();
    for row in rows {
        let is_new = channels
            .last()
            .is_none_or(|channel| channel.name != row.name);
        if is_new {
            channels.push(OwnedChannel {
                name: row.name.clone(),
                founder: row.founder,
                successor: row.successor,
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
    .map_err(query_error)?;
    rows.into_iter()
        .map(|(name, topic, setter, seconds)| {
            let millis = seconds.checked_mul(1000).ok_or_else(|| {
                DbError::InvalidDatabaseTimestamp(format!(
                    "channels.topic_set_at overflows milliseconds: {seconds}"
                ))
            })?;
            Ok((
                name,
                topic,
                setter,
                millis_from_database(millis, "channels.topic_set_at")?.as_secs(),
            ))
        })
        .collect()
}

/// Persist the KEEPTOPIC option of a registered channel `actor` founds —
/// checked with its row locked — on its `channels` row.
///
/// An applied change is audited (`CHANNEL_KEEPTOPIC`) in the same transaction
/// with the founder `actor`.
pub async fn set_channel_keeptopic(
    pool: &PgPool,
    channel_folded: &str,
    keeptopic: bool,
    topic: Option<(String, String, u64)>,
    actor: &str,
) -> Result<Result<(), ChannelRefusal>, DbError> {
    let (text, setter, set_at) = match topic {
        Some((text, setter, set_at)) if keeptopic => (
            Some(text),
            Some(setter),
            Some(seconds_for_database(set_at, "channels.topic_set_at")?),
        ),
        _ => (None, None, None),
    };
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let channel = match lock_channel_as_founder(&mut transaction, channel_folded, actor).await? {
        Ok(channel) => channel,
        Err(refusal) => return Ok(Err(refusal)),
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
         WHERE id = $1",
    )
    .bind(channel.channel_id)
    .bind(keeptopic)
    .bind(text)
    .bind(setter)
    .bind(set_at)
    .execute(&mut *transaction)
    .await
    .map_err(query_error)?;
    audit_channel_service(
        &mut transaction,
        actor,
        "CHANNEL_KEEPTOPIC",
        channel_folded,
        if keeptopic { "on" } else { "off" },
    )
    .await?;
    transaction.commit().await.map_err(query_error)?;
    Ok(Ok(()))
}

/// The folded names of registered channels whose KEEPTOPIC is OFF — the
/// exceptions boot-loaded into the hot set (default is on).
pub async fn list_keeptopic_off(pool: &PgPool) -> Result<Vec<String>, DbError> {
    sqlx::query_scalar("SELECT name_folded FROM channels WHERE NOT keeptopic")
        .fetch_all(pool)
        .await
        .map_err(query_error)
}

/// Persist the mode lock of a registered channel `actor` founds — checked
/// with its row locked — on its `channels` row (`None` clears it), audited
/// (`CHANNEL_MLOCK`) in the same transaction with the founder `actor`.
pub async fn set_channel_mlock(
    pool: &PgPool,
    channel_folded: &str,
    mlock: Option<String>,
    actor: &str,
) -> Result<Result<(), ChannelRefusal>, DbError> {
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let channel = match lock_channel_as_founder(&mut transaction, channel_folded, actor).await? {
        Ok(channel) => channel,
        Err(refusal) => return Ok(Err(refusal)),
    };
    sqlx::query("UPDATE channels SET mlock = $2 WHERE id = $1")
        .bind(channel.channel_id)
        .bind(&mlock)
        .execute(&mut *transaction)
        .await
        .map_err(query_error)?;
    audit_channel_service(
        &mut transaction,
        actor,
        "CHANNEL_MLOCK",
        channel_folded,
        mlock.as_deref().unwrap_or("cleared"),
    )
    .await?;
    transaction.commit().await.map_err(query_error)?;
    Ok(Ok(()))
}

/// Registered channels with a mode lock, as `(name_folded, spec)` —
/// boot-loaded into the hot lock map.
pub async fn list_channel_mlock(pool: &PgPool) -> Result<Vec<(String, String)>, DbError> {
    sqlx::query_as("SELECT name_folded, mlock FROM channels WHERE mlock IS NOT NULL")
        .fetch_all(pool)
        .await
        .map_err(query_error)
}

/// Delete `account`'s network `name`, audited in the same transaction.
/// Returns whether a row was removed.
///
/// The caller stops the network's driver — and with it the persistence task —
/// first. The backlog goes with the row by the `bnc_buffer.network_id`
/// cascade (migration 0062), so a late line cannot outlive it: an insert that
/// still names the deleted row fails its foreign key. Rows stored under the
/// same (owner, network) key without an id — a configuration network of that
/// name — are removed too, so a later network of the same name never replays
/// them. Read markers go in the same transaction.
pub async fn delete_bnc_network(
    pool: &PgPool,
    account: &str,
    name: &str,
    audit: NetworkAudit<'_>,
) -> Result<bool, DbError> {
    let key = BncBufferKey::new(account, name);
    let mut tx = pool.begin().await.map_err(query_error)?;
    let stored: Option<String> = sqlx::query_scalar(
        "DELETE FROM bnc_networks n USING accounts a
         WHERE n.account_id = a.id AND a.name_folded = $1 AND lower(n.name) = lower($2)
         RETURNING n.name",
    )
    .bind(&key.owner)
    .bind(name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(query_error)?;
    let Some(stored) = stored else {
        return Ok(false);
    };
    sqlx::query("DELETE FROM bnc_buffer WHERE owner = $1 AND network = $2")
        .bind(&key.owner)
        .bind(&key.network)
        .execute(&mut *tx)
        .await
        .map_err(query_error)?;
    sqlx::query(
        "DELETE FROM bnc_read_markers
         WHERE account_id = (SELECT id FROM accounts WHERE name_folded = $1)
           AND network = $2",
    )
    .bind(&key.owner)
    .bind(&key.network)
    .execute(&mut *tx)
    .await
    .map_err(query_error)?;
    audit_network_mutation(&mut tx, audit, "NETWORK_DELETE", &key.owner, &stored).await?;
    tx.commit().await.map_err(query_error)?;
    Ok(true)
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
#[derive(Debug, Clone)]
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

/// Where a network's backlog is defined, which decides what its stored lines
/// may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BncNetworkDefinition {
    /// A `[[network]]` in the configuration file: no `bnc_networks` row.
    Configured,
    /// A `bnc_networks` row an account created.
    Stored,
}

/// The backlog one persistence task writes: its canonical key and, for a
/// stored network, the row id resolved once when the task started. Every line
/// the task writes names that id, so a line written after the network was
/// deleted fails its foreign key instead of outliving it — and cannot slip into
/// a network re-created under the same name, which has a different id.
/// Constructed only by [`open_bnc_buffer`].
#[derive(Debug, Clone)]
pub struct BncBuffer {
    key: BncBufferKey,
    network_id: Option<i64>,
}

/// Resolve the backlog of `(owner, network)`. A stored network must have its
/// row — [`DbError::UnknownNetwork`] otherwise, never a line stored without
/// one — and is always account-owned; a configured one carries no row.
pub async fn open_bnc_buffer(
    pool: &PgPool,
    owner: Option<&str>,
    network: &str,
    definition: BncNetworkDefinition,
) -> Result<BncBuffer, DbError> {
    let key = BncBufferKey::new(owner.unwrap_or("*"), network);
    let network_id = match (definition, owner) {
        (BncNetworkDefinition::Configured, _) => None,
        (BncNetworkDefinition::Stored, None) => {
            return Err(DbError::UnknownNetwork(format!(
                "*/{network}: a stored network always has an owner"
            )));
        }
        (BncNetworkDefinition::Stored, Some(_)) => Some(
            sqlx::query_scalar(
                "SELECT n.id FROM bnc_networks n JOIN accounts a ON a.id = n.account_id
                 WHERE a.name_folded = $1 AND lower(n.name) = $2",
            )
            .bind(&key.owner)
            .bind(&key.network)
            .fetch_optional(pool)
            .await
            .map_err(query_error)?
            .ok_or_else(|| DbError::UnknownNetwork(format!("{}/{}", key.owner, key.network)))?,
        ),
    };
    Ok(BncBuffer { key, network_id })
}

/// Append one upstream line to a network's persisted buffer, extracting the
/// conversation target for CHATHISTORY queries: classified and keyed by the
/// network's own naming rules (`names`), with its name kept as the network
/// spelled it.
pub async fn persist_bnc_line(
    pool: &PgPool,
    buffer: &BncBuffer,
    own_nick: Option<&str>,
    line: &str,
    names: &e6irc_client::NetworkNames,
) -> Result<(), DbError> {
    let display = bnc_line_target(line, own_nick, names);
    let target = display.as_deref().map(|display| names.fold(display));
    let msgid = bnc_line_msgid(line);
    let sent_at = bnc_line_sent_at(line);
    sqlx::query(
        "INSERT INTO bnc_buffer (owner, network, network_id, line, target, msgid, sent_at,
                                 target_display, target_casemapping)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(&buffer.key.owner)
    .bind(&buffer.key.network)
    .bind(buffer.network_id)
    .bind(line)
    .bind(target)
    .bind(msgid)
    .bind(sent_at)
    .bind(display)
    .bind(names.casemapping().isupport_token())
    .execute(pool)
    .await
    .map_err(query_error)?;
    Ok(())
}

/// Re-key every stored conversation of one buffer that was folded under
/// another case mapping than `casemapping` — rows stored before the network
/// said how it compares names, or before it changed — from the name as the
/// network spelled it, so what was stored is found under the keys the network
/// now uses. Returns how many rows were re-keyed.
pub async fn rekey_bnc_targets(
    pool: &PgPool,
    buffer: &BncBuffer,
    casemapping: CaseMapping,
) -> Result<u64, DbError> {
    // The fold as a `translate()`: every byte the mapping lowers, and what to.
    let (upper, lower): (String, String) = (0u8..128)
        .filter(|byte| casemapping.lower(*byte) != *byte)
        .map(|byte| (char::from(byte), char::from(casemapping.lower(byte))))
        .unzip();
    sqlx::query(
        "UPDATE bnc_buffer
         SET target = translate(target_display, $3, $4), target_casemapping = $5
         WHERE owner = $1 AND network = $2
           AND target_display IS NOT NULL AND target_casemapping <> $5",
    )
    .bind(&buffer.key.owner)
    .bind(&buffer.key.network)
    .bind(upper)
    .bind(lower)
    .bind(casemapping.isupport_token())
    .execute(pool)
    .await
    .map(|result| result.rows_affected())
    .map_err(query_error)
}

/// The case mapping the newest stored conversation of `(owner, network)` was
/// keyed under: what the network last said, remembered across a restart
/// until it says it again.
pub async fn bnc_buffer_casemapping(
    pool: &PgPool,
    owner: &str,
    network: &str,
) -> Result<Option<CaseMapping>, DbError> {
    let key = BncBufferKey::new(owner, network);
    let stored: Option<String> = sqlx::query_scalar(
        "SELECT target_casemapping FROM bnc_buffer
         WHERE id = (SELECT max(id) FROM bnc_buffer
                     WHERE owner = $1 AND network = $2 AND target IS NOT NULL)",
    )
    .bind(&key.owner)
    .bind(&key.network)
    .fetch_optional(pool)
    .await
    .map_err(query_error)?;
    Ok(stored.as_deref().and_then(CaseMapping::from_isupport_token))
}

/// The conversation a stored raw IRC line belongs to, for CHATHISTORY paging,
/// as the network spelled it: the channel a PRIVMSG/NOTICE/TAGMSG was
/// addressed to (a STATUSMSG's channel), or for a direct message the other
/// party — so both directions share one conversation. What is a channel, a
/// STATUSMSG and the same nick is the network's to say (`names`). A line
/// addressed to several targets at once is no one conversation, and
/// non-message lines (JOIN, NICK, numerics) have none: `None` keeps them out
/// of target-filtered history without an extra predicate.
pub(crate) fn bnc_line_target(
    line: &str,
    own_nick: Option<&str>,
    names: &e6irc_client::NetworkNames,
) -> Option<String> {
    let msg = e6irc_proto::message::Message::parse(line).ok()?;
    match msg.command.to_ascii_uppercase().as_str() {
        "PRIVMSG" | "NOTICE" | "TAGMSG" => {
            let addressed = names.conversation(msg.params.first()?);
            if addressed.is_empty() || addressed.contains(',') {
                return None;
            }
            if names.is_channel(addressed) {
                return Some(addressed.to_string());
            }
            let source = msg.source.as_ref()?;
            let own_nick = own_nick?;
            if names.eq(source.name, own_nick) {
                Some(addressed.to_string())
            } else if source.user.is_some() || source.host.is_some() {
                Some(source.name.to_string())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// The `msgid` tag of a stored raw IRC line, for CHATHISTORY selector paging
/// (`CHATHISTORY BEFORE #chan msgid=X limit`). Only a tag-carrying line can
/// have one, and then only if the upstream sent it; lines without one return
/// `None` so they store NULL.
fn bnc_line_msgid(line: &str) -> Option<String> {
    let message = e6irc_proto::message::Message::parse(line).ok()?;
    let value = message
        .tags
        .into_iter()
        .rev()
        .find(|tag| tag.key == "msgid")?
        .value?;
    e6irc_proto::message::valid_message_id(&value).then(|| value.into_owned())
}

/// The effective message timestamp of a stored raw IRC line: a valid `time=`
/// tag canonicalized to millisecond precision, else the bouncer's arrival
/// time. Stored values therefore share one lexically sortable representation,
/// which CHATHISTORY timestamp selectors and MARKREAD positions rely on.
fn bnc_line_sent_at(line: &str) -> String {
    if let Ok(message) = e6irc_proto::message::Message::parse(line)
        && let Some(timestamp) = message
            .tags
            .into_iter()
            .rev()
            .find(|tag| tag.key == "time")
            .and_then(|tag| tag.value)
        && let Some(millis) = e6irc_proto::time::parse_server_time_millis(&timestamp)
    {
        return e6irc_proto::time::server_time(millis);
    }
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_millis()
        .min(u64::MAX as u128) as u64;
    e6irc_proto::time::server_time(e6irc_proto::time::Millis::from_millis(millis))
}

/// Drop all but the newest [`BNC_BUFFER_CAP`] lines of one network's buffer,
/// so an always-on network cannot grow the table forever. The persistence task
/// calls this once when it starts (after restoring the backlog) and every
/// [`BNC_TRIM_INTERVAL`] lines after; maintenance sweeps whatever that leaves
/// ([`trim_bnc_buffers_over_cap`]). Deletes in bounded batches until the
/// buffer is within the cap.
pub async fn trim_bnc_buffer(pool: &PgPool, buffer: &BncBuffer) -> Result<(), DbError> {
    let key = &buffer.key;
    while trim_bnc_buffer_batch(pool, &key.owner, &key.network, STORAGE_MAINTENANCE_BATCH).await?
        == STORAGE_MAINTENANCE_BATCH
    {}
    Ok(())
}

/// Delete up to `limit` of the oldest lines beyond the cap of one canonical
/// (owner, network) buffer; returns how many went. The cap boundary is one
/// index probe (`OFFSET cap` into `bnc_buffer_lookup_idx`, newest first) and
/// the batch is named by primary key.
async fn trim_bnc_buffer_batch(
    pool: &PgPool,
    owner: &str,
    network: &str,
    limit: u64,
) -> Result<u64, DbError> {
    sqlx::query(
        "DELETE FROM bnc_buffer WHERE id = ANY(ARRAY(
             SELECT id FROM bnc_buffer
             WHERE owner = $1 AND network = $2 AND id <= (
                 SELECT id FROM bnc_buffer
                 WHERE owner = $1 AND network = $2
                 ORDER BY id DESC OFFSET $3 LIMIT 1
             )
             ORDER BY id LIMIT $4))",
    )
    .bind(owner)
    .bind(network)
    .bind(BNC_BUFFER_CAP)
    .bind(limit as i64)
    .execute(pool)
    .await
    .map(|result| result.rows_affected())
    .map_err(query_error)
}

/// The most recent `limit` persisted lines for `(owner, network)`,
/// returned oldest-first for replay.
pub async fn recent_bnc_lines(
    pool: &PgPool,
    owner: &str,
    network: &str,
    limit: i64,
) -> Result<Vec<String>, DbError> {
    Ok(recent_bnc_backlog(pool, owner, network, limit)
        .await?
        .into_iter()
        .map(|(line, _)| line)
        .collect())
}

/// [`recent_bnc_lines`], each with the time it was stored under (its `time`
/// tag, or its arrival), for a ring restored from storage.
pub async fn recent_bnc_backlog(
    pool: &PgPool,
    owner: &str,
    network: &str,
    limit: i64,
) -> Result<Vec<(String, String)>, DbError> {
    let key = BncBufferKey::new(owner, network);
    // The ids come from an index-only probe of `bnc_buffer_lookup_idx`. Written
    // as one `ORDER BY id DESC LIMIT`, the planner walks the primary key
    // backward and filters out every other buffer's newer lines, so a quiet
    // buffer's replay cost grew with everyone else's traffic. A row from
    // before `sent_at` existed has its arrival.
    sqlx::query_as(
        "SELECT line,
                coalesce(sent_at,
                         to_char(created_at AT TIME ZONE 'UTC',
                                 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'))
         FROM bnc_buffer
         WHERE id = ANY(ARRAY(
             SELECT id FROM bnc_buffer
             WHERE owner = $1 AND network = $2
             ORDER BY id DESC LIMIT $3))
         ORDER BY id",
    )
    .bind(&key.owner)
    .bind(&key.network)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(query_error)
}

// ---- BNC CHATHISTORY queries ---------------------------------------------

/// One stored backlog line and its ordering metadata, for CHATHISTORY paging.
#[derive(sqlx::FromRow)]
pub struct BncHistoryLine {
    pub id: i64,
    pub line: String,
    pub msgid: Option<String>,
    pub sent_at: String,
}

/// A CHATHISTORY position on the attach listener: `*`, a message id, or a
/// canonical timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BncHistorySelector {
    Star,
    Msgid(String),
    Timestamp(String),
}

/// Which stored lines a paging client can be sent. A `TAGMSG` is nothing but
/// tags, so a client that did not negotiate `message-tags` cannot receive one
/// at all -- dropping those rows after the SQL `LIMIT` is what made a page
/// come back shorter than it asked for, indistinguishable from the end of the
/// buffer. The scope goes into the query instead, so the `LIMIT` counts only
/// lines that will reach the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BncHistoryScope {
    /// The client negotiated `message-tags`: every stored line reaches it.
    EveryLine,
    /// The client did not: a tag-only message has nothing left to send.
    ExceptTagOnly,
}

impl BncHistoryScope {
    /// From the one capability that decides it, so no call site can pass the
    /// scope that disagrees with the client's caps.
    pub fn for_message_tags(message_tags: bool) -> Self {
        if message_tags {
            Self::EveryLine
        } else {
            Self::ExceptTagOnly
        }
    }

    /// The predicate that keeps only deliverable rows, if any is needed.
    /// `IS DISTINCT FROM` because `command` is null for a line the frame
    /// regex cannot read, and such a row is not a TAGMSG.
    fn sql_predicate(self) -> &'static str {
        match self {
            Self::EveryLine => "",
            Self::ExceptTagOnly => " AND command IS DISTINCT FROM 'TAGMSG'",
        }
    }
}

/// Which window a CHATHISTORY subcommand asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BncHistoryPaging {
    Latest,
    Before,
    After,
    Around,
    Between,
}

/// A `msgid=` selector that names no message in the buffer being paged.
#[derive(Debug, PartialEq, Eq)]
pub struct UnknownBncMsgid;

/// A position in a target's `(sent_at, id)` order.
type BncPosition = (String, i64);

/// One target's lines in a `(sent_at, id)` range, at most `limit` of them:
/// the oldest when `newest` is false, the newest otherwise — returned
/// oldest-first either way. `after` is exclusive unless its flag says
/// inclusive; `before` is exclusive. Served by `bnc_buffer_sent_at_idx`
/// `(owner, network, target, sent_at, id)` as an index range scan under the
/// LIMIT.
#[allow(clippy::too_many_arguments)]
async fn bnc_history_range(
    pool: &PgPool,
    key: &BncBufferKey,
    target: &str,
    scope: BncHistoryScope,
    after: Option<(&BncPosition, bool)>,
    before: Option<&BncPosition>,
    newest: bool,
    limit: i64,
) -> Result<Vec<BncHistoryLine>, DbError> {
    let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT id, line, msgid, sent_at FROM bnc_buffer WHERE owner = ",
    );
    query
        .push_bind(&key.owner)
        .push(" AND network = ")
        .push_bind(&key.network)
        .push(" AND target = ")
        .push_bind(target)
        .push(scope.sql_predicate());
    if let Some(((sent_at, id), inclusive)) = after {
        query
            .push(if inclusive {
                " AND (sent_at, id) >= ("
            } else {
                " AND (sent_at, id) > ("
            })
            .push_bind(sent_at)
            .push(", ")
            .push_bind(*id)
            .push(")");
    }
    if let Some((sent_at, id)) = before {
        query
            .push(" AND (sent_at, id) < (")
            .push_bind(sent_at)
            .push(", ")
            .push_bind(*id)
            .push(")");
    }
    query
        .push(if newest {
            " ORDER BY sent_at DESC, id DESC LIMIT "
        } else {
            " ORDER BY sent_at ASC, id ASC LIMIT "
        })
        .push_bind(limit);
    let mut rows: Vec<BncHistoryLine> = query
        .build_query_as()
        .fetch_all(pool)
        .await
        .map_err(query_error)?;
    if newest {
        rows.reverse();
    }
    Ok(rows)
}

/// One CHATHISTORY window of one target on the attach listener, resolved in
/// PostgreSQL under a LIMIT — never a load of every retained line for the
/// target. Boundaries follow the draft/chathistory specification: a msgid
/// selector names its message (exclusive, except AROUND's pivot); a timestamp
/// names the gap before the first message at or after it. `*` is valid only for
/// an unbounded LATEST (the caller refuses it elsewhere). A msgid the target
/// does not hold is [`UnknownBncMsgid`], not an empty page.
#[allow(clippy::too_many_arguments)]
pub async fn bnc_history_window(
    pool: &PgPool,
    owner: &str,
    network: &str,
    target: &str,
    casemapping: CaseMapping,
    paging: BncHistoryPaging,
    scope: BncHistoryScope,
    first: &BncHistorySelector,
    second: &BncHistorySelector,
    limit: i64,
) -> Result<Result<Vec<BncHistoryLine>, UnknownBncMsgid>, DbError> {
    let key = BncBufferKey::new(owner, network);
    let target = casemapping.casefold(target);
    // Where a selector sits: `after` bounds the lines strictly after it,
    // `before` the lines strictly before it. A message id names one row; a
    // timestamp sorts before (`before`) or after (`after`) every row carrying
    // exactly that timestamp, whatever its id. `*` bounds nothing.
    struct Bounds {
        after: Option<BncPosition>,
        before: Option<BncPosition>,
    }
    async fn bounds(
        pool: &PgPool,
        key: &BncBufferKey,
        target: &str,
        selector: &BncHistorySelector,
    ) -> Result<Result<Bounds, UnknownBncMsgid>, DbError> {
        Ok(Ok(match selector {
            BncHistorySelector::Star => Bounds {
                after: None,
                before: None,
            },
            BncHistorySelector::Timestamp(timestamp) => Bounds {
                after: Some((timestamp.clone(), i64::MAX)),
                before: Some((timestamp.clone(), i64::MIN)),
            },
            BncHistorySelector::Msgid(msgid) => {
                let pivot: Option<BncPosition> = sqlx::query_as(
                    "SELECT sent_at, id FROM bnc_buffer
                     WHERE owner = $1 AND network = $2 AND target = $3 AND msgid = $4
                     ORDER BY sent_at, id LIMIT 1",
                )
                .bind(&key.owner)
                .bind(&key.network)
                .bind(target)
                .bind(msgid)
                .fetch_optional(pool)
                .await
                .map_err(query_error)?;
                let Some(pivot) = pivot else {
                    return Ok(Err(UnknownBncMsgid));
                };
                Bounds {
                    after: Some(pivot.clone()),
                    before: Some(pivot),
                }
            }
        }))
    }
    let first = match bounds(pool, &key, &target, first).await? {
        Ok(bounds) => bounds,
        Err(unknown) => return Ok(Err(unknown)),
    };
    let (key, target) = (&key, target.as_str());
    let rows = match paging {
        BncHistoryPaging::Latest => {
            let after = first.after.as_ref().map(|p| (p, false));
            bnc_history_range(pool, key, target, scope, after, None, true, limit).await?
        }
        BncHistoryPaging::Before => {
            bnc_history_range(
                pool,
                key,
                target,
                scope,
                None,
                first.before.as_ref(),
                true,
                limit,
            )
            .await?
        }
        BncHistoryPaging::After => {
            let after = first.after.as_ref().map(|p| (p, false));
            bnc_history_range(pool, key, target, scope, after, None, false, limit).await?
        }
        BncHistoryPaging::Around => {
            let older = limit / 2;
            let mut rows = if older > 0 {
                bnc_history_range(
                    pool,
                    key,
                    target,
                    scope,
                    None,
                    first.before.as_ref(),
                    true,
                    older,
                )
                .await?
            } else {
                Vec::new()
            };
            let from_pivot = first.before.as_ref().map(|p| (p, true));
            rows.extend(
                bnc_history_range(
                    pool,
                    key,
                    target,
                    scope,
                    from_pivot,
                    None,
                    false,
                    limit - older,
                )
                .await?,
            );
            rows
        }
        BncHistoryPaging::Between => {
            let second = match bounds(pool, key, target, second).await? {
                Ok(bounds) => bounds,
                Err(unknown) => return Ok(Err(unknown)),
            };
            // The older endpoint bounds from below, the newer from above; the
            // LIMIT cuts from the end the first selector names.
            let first_is_newer = first.before > second.before;
            let (older, newer) = if first_is_newer {
                (&second, &first)
            } else {
                (&first, &second)
            };
            bnc_history_range(
                pool,
                key,
                target,
                scope,
                older.after.as_ref().map(|p| (p, false)),
                newer.before.as_ref(),
                first_is_newer,
                limit,
            )
            .await?
        }
    };
    Ok(Ok(rows))
}

/// The distinct conversation targets that still have backlog for one network,
/// oldest-active first, each named as the network last spelled it, with its
/// newest `sent_at` (CHATHISTORY TARGETS; the timestamp lets a client resume
/// each target from its end). The name is never the folded key: on another
/// network's case mapping that key can be a different conversation. Both
/// bounds are exclusive, matching draft/chathistory's BETWEEN semantics.
pub async fn bnc_history_targets(
    pool: &PgPool,
    owner: &str,
    network: &str,
    scope: BncHistoryScope,
    min_timestamp: &str,
    max_timestamp: &str,
    limit: i64,
) -> Result<Vec<(String, String)>, DbError> {
    let key = BncBufferKey::new(owner, network);
    // Same scope as a page: a target whose only backlog is tag-only messages
    // has nothing to replay to this client, so naming it here would promise a
    // page that comes back empty. Built with a `QueryBuilder` because the
    // scope varies the text and sqlx accepts only literal SQL otherwise --
    // the varying part is a constant of this module, never input.
    let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT (array_agg(coalesce(target_display, target) ORDER BY id DESC))[1], max(sent_at)
         FROM bnc_buffer WHERE owner = ",
    );
    query
        .push_bind(&key.owner)
        .push(" AND network = ")
        .push_bind(&key.network)
        .push(" AND target IS NOT NULL")
        .push(scope.sql_predicate())
        .push(" GROUP BY target HAVING max(sent_at) > ")
        .push_bind(min_timestamp)
        .push(" AND max(sent_at) < ")
        .push_bind(max_timestamp)
        .push(" ORDER BY max(sent_at) ASC, max(id) ASC LIMIT ")
        .push_bind(limit);
    query
        .build_query_as()
        .fetch_all(pool)
        .await
        .map_err(query_error)
}

// ---- BNC read markers -----------------------------------------------------

/// Get one per-network, per-target read marker, or `None` if unset.
///
/// `target` is folded under the network's `casemapping`, as its backlog is.
pub async fn get_bnc_read_marker(
    pool: &PgPool,
    account: &str,
    network: &str,
    target: &str,
    casemapping: CaseMapping,
) -> Result<Option<String>, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let net_folded = CaseMapping::Rfc1459.casefold(network);
    let target_folded = casemapping.casefold(target);
    sqlx::query_scalar(
        "SELECT timestamp FROM bnc_read_markers
         WHERE account_id = (SELECT id FROM accounts WHERE name_folded = $1)
           AND network = $2 AND target = $3",
    )
    .bind(&folded)
    .bind(&net_folded)
    .bind(&target_folded)
    .fetch_optional(pool)
    .await
    .map_err(query_error)
}

/// Every read marker `account` keeps on `network`, as (folded target,
/// timestamp): where an attaching client's replay of each conversation starts.
pub async fn bnc_read_markers(
    pool: &PgPool,
    account: &str,
    network: &str,
) -> Result<Vec<(String, String)>, DbError> {
    sqlx::query_as(
        "SELECT target, timestamp FROM bnc_read_markers
         WHERE account_id = (SELECT id FROM accounts WHERE name_folded = $1)
           AND network = $2",
    )
    .bind(CaseMapping::Rfc1459.casefold(account))
    .bind(CaseMapping::Rfc1459.casefold(network))
    .fetch_all(pool)
    .await
    .map_err(query_error)
}

/// Set (upsert) one per-network, per-target read marker.
pub enum BncReadMarkerWrite {
    Stored(String),
    LimitReached,
}

/// Maximum durable BNC marker targets one account may retain across networks.
/// Markers outlive attachments and memberships, so the database boundary must
/// enforce the cap atomically across concurrent clients.
pub const BNC_READ_MARKER_LIMIT: i64 = 256;

pub async fn set_bnc_read_marker(
    pool: &PgPool,
    account: &str,
    network: &str,
    target: &str,
    casemapping: CaseMapping,
    timestamp: &str,
) -> Result<BncReadMarkerWrite, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let net_folded = CaseMapping::Rfc1459.casefold(network);
    let target_folded = casemapping.casefold(target);
    let mut tx = pool.begin().await.map_err(query_error)?;
    // Lock the durable account row while checking and consuming marker
    // capacity. This both serializes concurrent writers for the same account
    // and keeps the identifier at its schema-native BIGINT width.
    let account_id: Option<i64> =
        sqlx::query_scalar("SELECT id FROM accounts WHERE name_folded = $1 FOR NO KEY UPDATE")
            .bind(&folded)
            .fetch_optional(&mut *tx)
            .await
            .map_err(query_error)?;
    let Some(account_id) = account_id else {
        return Err(DbError::UnknownAccount(account.to_string()));
    };
    // Without the account row lock above, two attaches can both see 255 rows
    // and commit the 256th/257th concurrently.
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM bnc_read_markers
             WHERE account_id = $1 AND network = $2 AND target = $3
         )",
    )
    .bind(account_id)
    .bind(&net_folded)
    .bind(&target_folded)
    .fetch_one(&mut *tx)
    .await
    .map_err(query_error)?;
    if !exists {
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM bnc_read_markers WHERE account_id = $1")
                .bind(account_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(query_error)?;
        if count >= BNC_READ_MARKER_LIMIT {
            return Ok(BncReadMarkerWrite::LimitReached);
        }
    }
    let stored: String = sqlx::query_scalar(
        "INSERT INTO bnc_read_markers (account_id, network, target, timestamp)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (account_id, network, target)
         DO UPDATE SET timestamp = GREATEST(bnc_read_markers.timestamp, EXCLUDED.timestamp)
         RETURNING timestamp",
    )
    .bind(account_id)
    .bind(&net_folded)
    .bind(&target_folded)
    .bind(timestamp)
    .fetch_one(&mut *tx)
    .await
    .map_err(query_error)?;
    tx.commit().await.map_err(query_error)?;
    Ok(BncReadMarkerWrite::Stored(stored))
}
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
    .map_err(query_error)?;
    let timestamp = |value: Option<i64>| {
        value
            .map(|millis| millis_from_database(millis, "bnc_buffer.created_at"))
            .transpose()
    };
    Ok(BncBufferSummary {
        lines,
        oldest_at: timestamp(oldest_at)?,
        newest_at: timestamp(newest_at)?,
    })
}

// ---- web auth (OIDC identities + sessions) ------------------------------

/// The account an OpenID Connect identity is linked to, if any.
pub async fn oidc_linked_account(
    pool: &PgPool,
    issuer: &str,
    subject: &str,
) -> Result<Option<String>, DbError> {
    sqlx::query_scalar(OIDC_LINKED_ACCOUNT)
        .bind(issuer)
        .bind(subject)
        .fetch_optional(pool)
        .await
        .map_err(query_error)
}

/// The account (`name`) linked to the identity (`$1` issuer, `$2` subject).
const OIDC_LINKED_ACCOUNT: &str = "SELECT a.name FROM accounts a
     JOIN oidc_identities o ON o.account_id = a.id
     WHERE o.issuer = $1 AND o.subject = $2";

/// Find the account linked to (issuer, subject), or provision one named
/// exactly `account_name`, the name the provider's configured claim carries.
/// A name that is already an account's or retired is refused with
/// [`DbError::DuplicateAccount`] naming it — the server never invents a
/// different name for a person, and the caller reports the conflict.
pub async fn find_or_create_oidc_account(
    pool: &PgPool,
    issuer: &str,
    subject: &str,
    account_name: &str,
) -> Result<String, DbError> {
    const LINKED_ACCOUNT: &str = OIDC_LINKED_ACCOUNT;
    if let Some(name) = oidc_linked_account(pool, issuer, subject).await? {
        return Ok(name);
    }

    let folded = CaseMapping::Rfc1459.casefold(account_name);
    let mut tx = pool.begin().await.map_err(query_error)?;
    lock_account_name(&mut tx, &folded).await?;
    // A concurrent first login for the same person claims the same name, so it
    // waited on that lock and the winner has committed by now: look again
    // before the name reads as taken, or the loser is refused its own account.
    let linked: Option<String> = sqlx::query_scalar(LINKED_ACCOUNT)
        .bind(issuer)
        .bind(subject)
        .fetch_optional(&mut *tx)
        .await
        .map_err(query_error)?;
    if let Some(name) = linked {
        return Ok(name);
    }
    if account_name_is_unavailable(&mut tx, &folded).await? {
        return Err(DbError::DuplicateAccount(account_name.to_string()));
    }
    let account_id: i64 = sqlx::query_scalar(
        "INSERT INTO accounts (name, name_folded) VALUES ($1, $2)
         ON CONFLICT (name_folded) DO NOTHING RETURNING id",
    )
    .bind(account_name)
    .bind(&folded)
    .fetch_optional(&mut *tx)
    .await
    .map_err(query_error)?
    .ok_or_else(|| DbError::DuplicateAccount(account_name.to_string()))?;
    let name = account_name.to_string();
    let inserted = sqlx::query(
        "INSERT INTO oidc_identities (account_id, issuer, subject) VALUES ($1, $2, $3)
         ON CONFLICT (issuer, subject) DO NOTHING",
    )
    .bind(account_id)
    .bind(issuer)
    .bind(subject)
    .execute(&mut *tx)
    .await
    .map_err(query_error)?;
    if inserted.rows_affected() == 0 {
        // A concurrent first login for the same (issuer, subject) that claimed
        // a different name (the provider's claim changed between the two), so
        // the name lock above did not serialize it, committed first. Return the winner's account rather than a spurious 503, and do
        // NOT commit our transaction — dropping it rolls back the extra account
        // this racer just created, so the identity is provisioned exactly once.
        // (PostgreSQL blocks our ON CONFLICT until the winner's tx resolves, so
        // by here the winner is committed and visible on a fresh connection.)
        let winner: String = sqlx::query_scalar(LINKED_ACCOUNT)
            .bind(issuer)
            .bind(subject)
            .fetch_one(pool)
            .await
            .map_err(query_error)?;
        return Ok(winner);
    }
    insert_audit_log_with(
        &mut *tx,
        &AuditPrincipal::provider(&format!("oidc:{issuer}")),
        "ACCOUNT_CREATE",
        &AuditPrincipal::account(&folded),
        "provisioned from OpenID Connect",
    )
    .await?;
    tx.commit().await.map_err(query_error)?;
    Ok(name)
}

fn token_hash(token: &str) -> Vec<u8> {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, token.as_bytes())
        .as_ref()
        .to_vec()
}

/// The `FROM web_sessions s JOIN accounts a ... WHERE s.token_hash = $1 AND
/// s.expires_at > now()` fragment shared by the session-token lookups; the
/// argument is the SELECT column list (`history_select!` precedent).
macro_rules! session_lookup {
    ($cols:literal) => {
        concat!(
            "SELECT ",
            $cols,
            " FROM web_sessions s JOIN accounts a ON a.id = s.account_id \
             WHERE s.token_hash = $1 AND s.expires_at > now()"
        )
    };
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

/// A bounded, display-safe HTTP User-Agent value recorded as browser-session
/// provenance. Constructing it once at ingress prevents raw control characters
/// or an unbounded header from reaching storage, JSON, or the console.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionUserAgent(String);

impl SessionUserAgent {
    pub fn from_header(value: &str) -> Option<Self> {
        let normalized: String = value
            .chars()
            .map(|character| {
                if character.is_control() {
                    '\u{fffd}'
                } else {
                    character
                }
            })
            .take(512)
            .collect();
        let normalized = normalized.trim();
        (!normalized.is_empty()).then(|| Self(normalized.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Maximum unexpired durable browser logins retained for one account.
pub const MAX_BROWSER_SESSIONS_PER_ACCOUNT: usize = 32;

/// Mint a web session for an account: opaque 32-byte token returned to the
/// caller; only its SHA-256 is stored. The session expires after 14 days.
pub async fn create_web_session(
    pool: &PgPool,
    account: &str,
    user_agent: Option<&SessionUserAgent>,
) -> Result<String, DbError> {
    create_web_session_with_identity(pool, account, OidcSessionIdentity::default(), user_agent)
        .await
}

/// Like [`create_web_session`], but records the upstream identity so logout can
/// end the provider's SSO session and the account page can show who is signed
/// in.
pub async fn create_web_session_with_identity(
    pool: &PgPool,
    account: &str,
    identity: OidcSessionIdentity<'_>,
    user_agent: Option<&SessionUserAgent>,
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
    let token = crate::secret::random_url_safe_token();
    let folded = CaseMapping::Rfc1459.casefold(account);
    let mut tx = pool.begin().await.map_err(query_error)?;
    // Serialize issuance per account, then retain only the newest cap-1 active
    // rows before inserting. A count followed by an insert without this lock
    // lets concurrent logins exceed the cap. Rolling out the oldest login keeps
    // a credential-owning user able to sign in and recover the account instead
    // of letting a filled session set permanently lock out the login surface.
    let account_id = lock_active_account_id(&mut tx, &folded).await?;
    sqlx::query("DELETE FROM web_sessions WHERE account_id = $1 AND expires_at <= now()")
        .bind(account_id)
        .execute(&mut *tx)
        .await
        .map_err(query_error)?;
    sqlx::query(
        "DELETE FROM web_sessions
         WHERE account_id = $1 AND id IN (
             SELECT id FROM web_sessions
             WHERE account_id = $1 AND expires_at > now()
             ORDER BY created_at DESC, id DESC
             OFFSET $2
         )",
    )
    .bind(account_id)
    .bind((MAX_BROWSER_SESSIONS_PER_ACCOUNT - 1) as i64)
    .execute(&mut *tx)
    .await
    .map_err(query_error)?;
    sqlx::query(
        "INSERT INTO web_sessions (token_hash, account_id, expires_at, id_token, oidc_provider,
                                   oidc_issuer, oidc_subject, oidc_sid, oidc_email, oidc_role,
                                   user_agent)
         VALUES ($1, $2, now() + interval '14 days', $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(token_hash(&token))
    .bind(account_id)
    .bind(id_token)
    .bind(provider)
    .bind(issuer)
    .bind(subject)
    .bind(sid)
    .bind(email)
    .bind(role)
    .bind(user_agent.map(SessionUserAgent::as_str))
    .execute(&mut *tx)
    .await
    .map_err(query_error)?;
    insert_audit_log_with(
        &mut *tx,
        &AuditPrincipal::account(&folded),
        "ACCOUNT_LOGIN",
        &AuditPrincipal::account(&folded),
        if provider.is_some() {
            "browser session created through OpenID Connect"
        } else {
            "browser session created with local credentials"
        },
    )
    .await?;
    tx.commit().await.map_err(query_error)?;
    Ok(token)
}

#[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
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
    sqlx::query_as(session_lookup!(
        "a.name AS account, s.oidc_email AS email, s.oidc_role AS role, s.oidc_provider AS provider"
    ))
    .bind(token_hash(token))
    .fetch_optional(pool)
    .await
    .map_err(query_error)
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
    let mut tx = pool.begin().await.map_err(query_error)?;
    sqlx::query("DELETE FROM oidc_logout_tokens WHERE expires_at <= now()")
        .execute(&mut *tx)
        .await
        .map_err(query_error)?;
    let inserted = sqlx::query(
        "INSERT INTO oidc_logout_tokens (issuer, jti, expires_at)
         VALUES ($1, $2, to_timestamp($3)) ON CONFLICT DO NOTHING",
    )
    .bind(issuer)
    .bind(jti)
    .bind(expires_at)
    .execute(&mut *tx)
    .await
    .map_err(query_error)?;
    if inserted.rows_affected() != 1 {
        return Err(DbError::ReplayedLogoutToken);
    }
    let affected_accounts: Vec<String> = match sid {
        Some(sid) => sqlx::query_scalar(
            "SELECT DISTINCT a.name_folded
             FROM web_sessions s JOIN accounts a ON a.id = s.account_id
             WHERE s.oidc_issuer = $1 AND s.oidc_sid = $2
               AND ($3::text IS NULL OR s.oidc_subject = $3)",
        )
        .bind(issuer)
        .bind(sid)
        .bind(subject)
        .fetch_all(&mut *tx)
        .await
        .map_err(query_error)?,
        None => sqlx::query_scalar(
            "SELECT DISTINCT a.name_folded
             FROM web_sessions s JOIN accounts a ON a.id = s.account_id
             WHERE s.oidc_issuer = $1 AND s.oidc_subject = $2",
        )
        .bind(issuer)
        .bind(subject.expect("validated logout token has sid or sub"))
        .fetch_all(&mut *tx)
        .await
        .map_err(query_error)?,
    };
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
        .map_err(query_error)?,
        None => {
            sqlx::query("DELETE FROM web_sessions WHERE oidc_issuer = $1 AND oidc_subject = $2")
                .bind(issuer)
                .bind(subject.expect("validated logout token has sid or sub"))
                .execute(&mut *tx)
                .await
                .map_err(query_error)?
        }
    };
    for account in affected_accounts {
        insert_audit_log_with(
            &mut *tx,
            &AuditPrincipal::account(&account),
            "ACCOUNT_OIDC_LOGOUT",
            &AuditPrincipal::account(&account),
            "browser sessions revoked by OpenID Connect back-channel logout",
        )
        .await?;
    }
    tx.commit().await.map_err(query_error)?;
    Ok(deleted.rows_affected())
}

/// What a front-channel logout revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrontchannelRevocation {
    /// Browser sessions deleted.
    pub revoked: u64,
    /// Whether the session the request itself presented was one of them. Only
    /// then may the answer clear the browser's session cookie: anyone can make
    /// a browser load the logout URL with some `sid`, and clearing the cookie
    /// regardless would sign every such visitor out (logout CSRF).
    pub presented_session_revoked: bool,
}

/// Revoke sessions named by a verified front-channel issuer/session pair, and
/// say whether `presented` (the request's own session token) was among them.
pub async fn revoke_oidc_frontchannel_sessions(
    pool: &PgPool,
    issuer: &str,
    sid: &str,
    presented: Option<&str>,
) -> Result<FrontchannelRevocation, DbError> {
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let affected_accounts: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT a.name_folded
         FROM web_sessions s JOIN accounts a ON a.id = s.account_id
         WHERE s.oidc_issuer = $1 AND s.oidc_sid = $2",
    )
    .bind(issuer)
    .bind(sid)
    .fetch_all(&mut *transaction)
    .await
    .map_err(query_error)?;
    let deleted: Vec<Vec<u8>> = sqlx::query_scalar(
        "DELETE FROM web_sessions WHERE oidc_issuer = $1 AND oidc_sid = $2 RETURNING token_hash",
    )
    .bind(issuer)
    .bind(sid)
    .fetch_all(&mut *transaction)
    .await
    .map_err(query_error)?;
    for account in affected_accounts {
        insert_audit_log_with(
            &mut *transaction,
            &AuditPrincipal::account(&account),
            "ACCOUNT_OIDC_LOGOUT",
            &AuditPrincipal::account(&account),
            "browser sessions revoked by OpenID Connect front-channel logout",
        )
        .await?;
    }
    transaction.commit().await.map_err(query_error)?;
    let presented = presented.map(token_hash);
    Ok(FrontchannelRevocation {
        revoked: deleted.len() as u64,
        presented_session_revoked: presented.is_some_and(|hash| deleted.contains(&hash)),
    })
}

#[derive(sqlx::FromRow, Debug, PartialEq, Eq)]
pub struct SessionLogoutHint {
    pub id_token: Option<String>,
    pub provider: Option<String>,
}

/// Return the OpenID Connect logout hint for a valid session.
pub async fn session_logout_hint(pool: &PgPool, token: &str) -> Result<SessionLogoutHint, DbError> {
    let row: Option<SessionLogoutHint> = sqlx::query_as(
        "SELECT id_token, oidc_provider AS provider FROM web_sessions
         WHERE token_hash = $1 AND expires_at > now()",
    )
    .bind(token_hash(token))
    .fetch_optional(pool)
    .await
    .map_err(query_error)?;
    Ok(row.unwrap_or(SessionLogoutHint {
        id_token: None,
        provider: None,
    }))
}

/// Resolve a session token to its account name, if valid and unexpired.
pub async fn session_account(pool: &PgPool, token: &str) -> Result<Option<String>, DbError> {
    sqlx::query_scalar(session_lookup!("a.name"))
        .bind(token_hash(token))
        .fetch_optional(pool)
        .await
        .map_err(query_error)
}

/// How recently a browser session's person must have proved themselves
/// (signed in, or re-authenticated) for an operation that mints or redirects
/// lasting authority over the account (DESIGN §9.4).
pub const STEP_UP_WINDOW: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// Whether the browser session `token` proved its person within
/// [`STEP_UP_WINDOW`].
pub async fn session_recently_authenticated(pool: &PgPool, token: &str) -> Result<bool, DbError> {
    sqlx::query_scalar(
        "SELECT authenticated_at > now() - make_interval(secs => $2)
         FROM web_sessions WHERE token_hash = $1 AND expires_at > now()",
    )
    .bind(token_hash(token))
    .bind(STEP_UP_WINDOW.as_secs_f64())
    .fetch_optional(pool)
    .await
    .map_err(query_error)
    .map(|recent| recent.unwrap_or(false))
}

/// How a browser session's person proved themselves again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reauthentication {
    /// The account's primary password.
    Password,
    /// A fresh sign-in at a linked identity provider.
    IdentityProvider,
}

/// Record that the person behind `account`'s browser session `token` has just
/// proved themselves ([`Reauthentication`]), with an audit row. `false` when
/// the session is not `account`'s (or has ended).
pub async fn mark_session_reauthenticated(
    pool: &PgPool,
    account: &str,
    token: &str,
    how: Reauthentication,
) -> Result<bool, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let updated = sqlx::query(
        "UPDATE web_sessions s SET authenticated_at = now()
         FROM accounts a
         WHERE s.token_hash = $1 AND s.expires_at > now()
           AND a.id = s.account_id AND a.name_folded = $2",
    )
    .bind(token_hash(token))
    .bind(&folded)
    .execute(&mut *transaction)
    .await
    .map_err(query_error)?;
    if updated.rows_affected() == 0 {
        return Ok(false);
    }
    insert_audit_log_with(
        &mut *transaction,
        &AuditPrincipal::account(&folded),
        "ACCOUNT_REAUTHENTICATE",
        &AuditPrincipal::account(&folded),
        match how {
            Reauthentication::Password => {
                "browser session re-authenticated with the primary password"
            }
            Reauthentication::IdentityProvider => {
                "browser session re-authenticated through OpenID Connect"
            }
        },
    )
    .await?;
    transaction.commit().await.map_err(query_error)?;
    Ok(true)
}

/// Delete a session (logout). Deleting an unknown token is not an
/// error: logout must be idempotent.
pub async fn delete_web_session(pool: &PgPool, token: &str) -> Result<(), DbError> {
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let owner: Option<String> = sqlx::query_scalar(
        "SELECT a.name_folded
         FROM web_sessions s JOIN accounts a ON a.id = s.account_id
         WHERE s.token_hash = $1",
    )
    .bind(token_hash(token))
    .fetch_optional(&mut *transaction)
    .await
    .map_err(query_error)?;
    sqlx::query("DELETE FROM web_sessions WHERE token_hash = $1")
        .bind(token_hash(token))
        .execute(&mut *transaction)
        .await
        .map_err(query_error)?;
    if let Some(owner) = owner {
        insert_audit_log_with(
            &mut *transaction,
            &AuditPrincipal::account(&owner),
            "ACCOUNT_LOGOUT",
            &AuditPrincipal::account(&owner),
            "browser session ended",
        )
        .await?;
    }
    transaction.commit().await.map_err(query_error)?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
pub struct WebSessionRow {
    pub id: i64,
    pub created_at: String,
    pub expires_at: String,
    pub provider: Option<String>,
    pub user_agent: Option<String>,
    pub current: bool,
}

/// List one account's unexpired browser sessions without exposing their token
/// hashes. `current_token` only marks the matching row; it never changes the
/// owner predicate.
pub async fn list_web_sessions(
    pool: &PgPool,
    account: &str,
    current_token: Option<&str>,
) -> Result<Vec<WebSessionRow>, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let current_hash = current_token.map(token_hash);
    sqlx::query_as(
        "SELECT s.id,
                to_char(s.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')
                    AS created_at,
                to_char(s.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')
                    AS expires_at,
                s.oidc_provider AS provider,
                s.user_agent,
                CASE WHEN $2::bytea IS NULL THEN FALSE ELSE s.token_hash = $2 END AS current
         FROM web_sessions s
         JOIN accounts a ON a.id = s.account_id
         WHERE a.name_folded = $1 AND s.expires_at > now()
         ORDER BY current DESC, s.created_at DESC, s.id DESC
         LIMIT $3",
    )
    .bind(folded)
    .bind(current_hash)
    .bind(MAX_BROWSER_SESSIONS_PER_ACCOUNT as i64)
    .fetch_all(pool)
    .await
    .map_err(query_error)
}

/// Revoke one owner-scoped browser session. The returned boolean says whether
/// the deleted row was the request's current cookie session.
pub async fn delete_web_session_by_id(
    pool: &PgPool,
    account: &str,
    id: i64,
    current_token: Option<&str>,
) -> Result<Option<bool>, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let current_hash = current_token.map(token_hash);
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let deleted = sqlx::query_scalar(
        "DELETE FROM web_sessions s USING accounts a
         WHERE s.account_id = a.id AND a.name_folded = $1 AND s.id = $2
         RETURNING CASE
             WHEN $3::bytea IS NULL THEN FALSE
             ELSE s.token_hash = $3
         END",
    )
    .bind(folded)
    .bind(id)
    .bind(current_hash)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(query_error)?;
    if deleted.is_some() {
        let folded = CaseMapping::Rfc1459.casefold(account);
        insert_audit_log_with(
            &mut *transaction,
            &AuditPrincipal::account(&folded),
            "ACCOUNT_SESSION_REVOKE",
            &AuditPrincipal::account(&folded),
            "browser session revoked",
        )
        .await?;
    }
    transaction.commit().await.map_err(query_error)?;
    Ok(deleted)
}

/// Delete every browser session of the account `folded` except the one whose
/// token is `current_token`, inside the caller's transaction; the number
/// deleted is returned.
async fn delete_other_web_sessions_in(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    folded: &str,
    current_token: &str,
) -> Result<u64, DbError> {
    sqlx::query(
        "DELETE FROM web_sessions s USING accounts a
         WHERE s.account_id = a.id AND a.name_folded = $1 AND s.token_hash <> $2",
    )
    .bind(folded)
    .bind(token_hash(current_token))
    .execute(&mut **transaction)
    .await
    .map(|result| result.rows_affected())
    .map_err(query_error)
}

/// Revoke every other browser session owned by `account`, preserving the
/// supplied current cookie session.
pub async fn delete_other_web_sessions(
    pool: &PgPool,
    account: &str,
    current_token: &str,
) -> Result<u64, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let deleted = delete_other_web_sessions_in(&mut transaction, &folded, current_token).await?;
    if deleted != 0 {
        insert_audit_log_with(
            &mut *transaction,
            &AuditPrincipal::account(&folded),
            "ACCOUNT_SESSIONS_REVOKE",
            &AuditPrincipal::account(&folded),
            "other browser sessions revoked",
        )
        .await?;
    }
    transaction.commit().await.map_err(query_error)?;
    Ok(deleted)
}

// ---- personal access tokens ---------------------------------------------

/// Most personal access tokens one account may hold, matching the REST layer's
/// `MAX_CREDENTIALS_PER_ACCOUNT`. Bounds authenticated storage growth. Every
/// token is minted by [`mint_api_token_under_cap`] — the REST endpoint and an
/// approved device grant alike — so the cap has no exception.
const MAX_API_TOKENS_PER_ACCOUNT: i64 = 32;

pub async fn issue_scoped_api_token(
    pool: &PgPool,
    account: &str,
    label: &str,
    scopes: crate::identity::ApiTokenScopes,
    lifetime: crate::identity::ApiTokenLifetimeDays,
) -> Result<String, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let mut tx = pool.begin().await.map_err(query_error)?;
    let token = mint_api_token_under_cap(&mut tx, account, label, scopes, lifetime).await?;
    insert_audit_log_with(
        &mut *tx,
        &AuditPrincipal::account(&folded),
        "ACCOUNT_TOKEN_CREATE",
        &AuditPrincipal::account(&folded),
        "personal access token created",
    )
    .await?;
    tx.commit().await.map_err(query_error)?;
    Ok(token)
}

/// How many unexpired personal access tokens `account_id` holds. Meaningful as
/// a cap check only while the caller's transaction holds the account row's
/// lock. An expired token authenticates nothing and the account directory does
/// not count it, so it does not hold a slot while it waits for maintenance to
/// delete it.
async fn api_token_count(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: i64,
) -> Result<i64, DbError> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM api_tokens WHERE account_id = $1 AND expires_at > now()",
    )
    .bind(account_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(query_error)
}

/// The one way a personal access token comes to exist: mint it for `account`
/// inside the caller's transaction and return the plaintext, shown once.
///
/// The cap and the insert run with the account row locked `FOR NO KEY UPDATE`. A
/// count-then-insert across two pool statements lets two concurrent requests
/// each read cap-1 and both insert, overshooting the cap — the same race
/// `issue_app_password` closes. Taking the caller's transaction lets the
/// device-grant path consume its grant and mint together. A suspended or
/// missing account is [`DbError::BadCredentials`]; an account at the cap is
/// [`DbError::TooManyCredentials`].
async fn mint_api_token_under_cap(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account: &str,
    label: &str,
    scopes: crate::identity::ApiTokenScopes,
    lifetime: crate::identity::ApiTokenLifetimeDays,
) -> Result<String, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let account_id = lock_active_account_id(transaction, &folded).await?;
    if api_token_count(transaction, account_id).await? >= MAX_API_TOKENS_PER_ACCOUNT {
        return Err(DbError::TooManyCredentials);
    }
    let token = format!("e6p_{}", crate::secret::random_url_safe_token());
    sqlx::query(
        "INSERT INTO api_tokens (token_hash, account_id, label, scopes, expires_at)
         VALUES ($1, $2, $3, $4, now() + make_interval(days => $5))",
    )
    .bind(token_hash(&token))
    .bind(account_id)
    .bind(label)
    .bind(scopes.database_values())
    .bind(i32::from(lifetime.value()))
    .execute(&mut **transaction)
    .await
    .map_err(query_error)?;
    Ok(token)
}

/// Resolve a PAT to its account, if valid and unexpired.
pub async fn api_token_account(pool: &PgPool, token: &str) -> Result<Option<String>, DbError> {
    sqlx::query_scalar(
        "SELECT a.name FROM api_tokens t
         JOIN accounts a ON a.id = t.account_id
         WHERE t.token_hash = $1
           AND t.expires_at > now()
           AND 'irc' = ANY(t.scopes)
           AND (a.flags & $2) = 0",
    )
    .bind(token_hash(token))
    .bind(ACCOUNT_FLAG_SUSPENDED)
    .fetch_optional(pool)
    .await
    .map_err(query_error)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiTokenPrincipal {
    pub account: String,
    pub scopes: crate::identity::ApiTokenScopes,
}

#[derive(sqlx::FromRow)]
struct ApiTokenPrincipalRow {
    account: String,
    scopes: Vec<String>,
}

/// Resolve an unexpired token into its account and closed permission set.
pub async fn api_token_principal(
    pool: &PgPool,
    token: &str,
) -> Result<Option<ApiTokenPrincipal>, DbError> {
    let row: Option<ApiTokenPrincipalRow> = sqlx::query_as(
        "SELECT a.name AS account, t.scopes
         FROM api_tokens t
         JOIN accounts a ON a.id = t.account_id
         WHERE t.token_hash = $1
           AND t.expires_at > now()
           AND (a.flags & $2) = 0",
    )
    .bind(token_hash(token))
    .bind(ACCOUNT_FLAG_SUSPENDED)
    .fetch_optional(pool)
    .await
    .map_err(query_error)?;
    row.map(|row| {
        Ok(ApiTokenPrincipal {
            account: row.account,
            scopes: crate::identity::ApiTokenScopes::from_database(row.scopes)
                .map_err(|error| DbError::InvalidApiTokenScopes(error.to_string()))?,
        })
    })
    .transpose()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiTokenMetadata {
    pub id: i64,
    pub label: String,
    pub created_at: String,
    pub expires_at: String,
    pub scopes: crate::identity::ApiTokenScopes,
}

#[derive(sqlx::FromRow)]
struct ApiTokenMetadataRow {
    id: i64,
    label: String,
    created_at: String,
    expires_at: String,
    scopes: Vec<String>,
}

/// List an account's bounded PAT grants — never the token or its hash.
pub async fn list_api_tokens(
    pool: &PgPool,
    account: &str,
) -> Result<Vec<ApiTokenMetadata>, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let rows: Vec<ApiTokenMetadataRow> = sqlx::query_as(
        "SELECT t.id, t.label,
                to_char(t.created_at AT TIME ZONE 'UTC',
                        'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS created_at,
                to_char(t.expires_at AT TIME ZONE 'UTC',
                        'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS expires_at,
                t.scopes
         FROM api_tokens t JOIN accounts a ON a.id = t.account_id
         WHERE a.name_folded = $1
         ORDER BY t.id",
    )
    .bind(&folded)
    .fetch_all(pool)
    .await
    .map_err(query_error)?;
    rows.into_iter()
        .map(|row| {
            Ok(ApiTokenMetadata {
                id: row.id,
                label: row.label,
                created_at: row.created_at,
                expires_at: row.expires_at,
                scopes: crate::identity::ApiTokenScopes::from_database(row.scopes)
                    .map_err(|error| DbError::InvalidApiTokenScopes(error.to_string()))?,
            })
        })
        .collect()
}

/// Finish an owner-scoped credential revocation with its durable audit record
/// in the same transaction. App-password and personal-access-token deletion
/// differ only in their target table and audit vocabulary.
async fn commit_credential_revocation(
    mut transaction: sqlx::Transaction<'_, sqlx::Postgres>,
    folded: &str,
    result: sqlx::postgres::PgQueryResult,
    action: &str,
    detail: &str,
) -> Result<bool, DbError> {
    if result.rows_affected() == 0 {
        return Ok(false);
    }
    insert_audit_log_with(
        &mut *transaction,
        &AuditPrincipal::account(folded),
        action,
        &AuditPrincipal::account(folded),
        detail,
    )
    .await?;
    transaction.commit().await.map_err(query_error)?;
    Ok(true)
}

/// Revoke one of `account`'s PATs by id. Returns whether a row was deleted
/// (false = not found / not owned).
pub async fn delete_api_token(pool: &PgPool, account: &str, id: i64) -> Result<bool, DbError> {
    delete_scoped_credential(
        pool,
        account,
        id,
        "DELETE FROM api_tokens t USING accounts a
         WHERE t.account_id = a.id AND a.name_folded = $1 AND t.id = $2",
        "ACCOUNT_TOKEN_REVOKE",
        "personal access token revoked",
    )
    .await
}

/// Delete one account-scoped credential row (by folded account + row id) and
/// commit the revocation with its audit entry. `delete_sql` scopes the DELETE
/// itself (the token table, the app-password kind), so the two revocation
/// paths share the transaction/audit shape but cannot widen each other's
/// scope.
async fn delete_scoped_credential(
    pool: &PgPool,
    account: &str,
    id: i64,
    delete_sql: &'static str,
    action: &str,
    message: &str,
) -> Result<bool, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    let mut transaction = pool.begin().await.map_err(query_error)?;
    let result = sqlx::query(delete_sql)
        .bind(&folded)
        .bind(id)
        .execute(&mut *transaction)
        .await
        .map_err(query_error)?;
    commit_credential_revocation(transaction, &folded, result, action, message).await
}

// ---- credential management ----------------------------------------------

#[derive(Debug, sqlx::FromRow)]
pub struct CredentialRow {
    pub id: i64,
    pub kind: String,
    pub label: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

/// List an account's credentials (never the hashes).
pub async fn list_credentials(pool: &PgPool, account: &str) -> Result<Vec<CredentialRow>, DbError> {
    let folded = CaseMapping::Rfc1459.casefold(account);
    sqlx::query_as(
        "SELECT c.id, c.kind, c.label,
                to_char(c.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS created_at,
                to_char(c.last_used_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS last_used_at
         FROM account_credentials c
         JOIN accounts a ON a.id = c.account_id
         WHERE a.name_folded = $1
         ORDER BY c.id",
    )
    .bind(&folded)
    .fetch_all(pool)
    .await
    .map_err(query_error)
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
    delete_scoped_credential(
        pool,
        account,
        id,
        "DELETE FROM account_credentials c
         USING accounts a
         WHERE c.account_id = a.id AND a.name_folded = $1 AND c.id = $2
           AND c.kind = 'app_password'",
        "ACCOUNT_APP_PASSWORD_REVOKE",
        "app password revoked",
    )
    .await
}

#[cfg(test)]
mod pool_size_tests {
    use super::{DatabasePoolSize, MAX_CONCURRENT_ARGON2};

    #[test]
    fn the_pool_size_is_bounded_and_defaults_to_the_host() {
        assert!(DatabasePoolSize::new(1).is_err());
        assert!(DatabasePoolSize::new(201).is_err());
        assert_eq!(DatabasePoolSize::new(2).map(DatabasePoolSize::get), Ok(2));
        assert_eq!(
            DatabasePoolSize::new(200).map(DatabasePoolSize::get),
            Ok(200)
        );
        // One serial worker, the Argon2 offloads, two per runtime thread.
        assert_eq!(
            DatabasePoolSize::for_runtime_threads(8).get() as usize,
            1 + MAX_CONCURRENT_ARGON2 + 16
        );
        assert_eq!(DatabasePoolSize::for_runtime_threads(1_000).get(), 200);
        let parsed: DatabasePoolSize = serde_json::from_str("48").expect("in bounds");
        assert_eq!(parsed.get(), 48);
        assert!(serde_json::from_str::<DatabasePoolSize>("0").is_err());
    }
}

#[cfg(test)]
mod startup_budget_tests {
    use super::{MIGRATION_LOCK_ATTEMPTS, MIGRATION_LOCK_TIMEOUT};

    /// The image's `HEALTHCHECK` start period covers the longest a default
    /// start can spend before `/healthz` is bound: the default database wait,
    /// then every migration attempt waiting out its lock timeout with the
    /// doubling pauses between them. A shorter period marked a container that
    /// was starting as it should unhealthy.
    #[test]
    fn the_container_start_period_outlasts_the_startup_database_budget() {
        let pauses = (1u64 << (MIGRATION_LOCK_ATTEMPTS - 1)) - 1;
        let budget = crate::config::DEFAULT_STARTUP_WAIT_SECONDS
            + u64::from(MIGRATION_LOCK_ATTEMPTS) * MIGRATION_LOCK_TIMEOUT.as_secs()
            + pauses;
        let dockerfile =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Dockerfile"))
                .expect("read the Dockerfile");
        let period: u64 = dockerfile
            .split("--start-period=")
            .nth(1)
            .and_then(|rest| rest.split_once('s'))
            .and_then(|(seconds, _)| seconds.parse().ok())
            .expect("the HEALTHCHECK states --start-period=<seconds>s");
        assert!(
            period > budget,
            "--start-period={period}s must exceed the {budget}s startup database budget"
        );
    }
}

#[cfg(test)]
mod credential_verification_plan_tests {
    use super::{StoredCredential, app_password_lookup, plan_credential_verification};

    fn local(id: i64) -> StoredCredential {
        StoredCredential {
            credential_id: id,
            argon2_hash: format!("local-{id}"),
            app_password_lookup: None,
        }
    }

    fn app(id: i64, secret: &str) -> StoredCredential {
        StoredCredential {
            credential_id: id,
            argon2_hash: format!("app-{id}"),
            app_password_lookup: Some(app_password_lookup(secret)),
        }
    }

    /// One login attempt costs the same Argon2 work whether the account
    /// exists, has no app passwords, or has all 32 — so an account's app
    /// passwords are neither a multiplier on an attacker's guesses nor a
    /// timing signal that the account exists.
    #[test]
    fn one_attempt_costs_two_computations_however_many_app_passwords_exist() {
        let many: Vec<_> = std::iter::once(local(1))
            .chain((2..=33).map(|id| app(id, &format!("secret-{id}"))))
            .collect();
        for (stored, presented, expect_ids) in [
            (Vec::new(), "anything", vec![]),
            (vec![local(1)], "anything", vec![1]),
            (many.clone(), "not an app password", vec![1]),
            (many.clone(), "secret-17", vec![1, 17]),
            (vec![app(2, "secret-2")], "secret-2", vec![2]),
        ] {
            let plan = plan_credential_verification(stored, presented);
            let ids: Vec<i64> = plan.candidates.iter().map(|c| c.credential_id).collect();
            assert_eq!(ids, expect_ids, "{presented}");
            assert_eq!(plan.candidates.len() + plan.dummies, 2, "{presented}");
        }
    }
}

#[cfg(test)]
mod history_sql_tests {
    use super::{
        DbError, MAX_DATABASE_MILLIS, bnc_line_msgid, bnc_line_sent_at, bnc_line_target,
        millis_for_database, millis_from_database, stored_network_kind,
    };
    use e6irc_proto::time::Millis;

    #[test]
    fn database_millis_rejects_values_that_would_wrap_or_lose_precision() {
        for value in [-1, i64::MAX] {
            assert!(matches!(
                millis_from_database(value, "test timestamp"),
                Err(DbError::InvalidDatabaseTimestamp(_))
            ));
        }
        assert!(matches!(
            millis_for_database(
                Millis::from_millis(MAX_DATABASE_MILLIS + 1),
                "test timestamp"
            ),
            Err(DbError::InvalidDatabaseTimestamp(_))
        ));
    }

    #[test]
    fn database_millis_preserves_the_exact_boundary() {
        let millis = Millis::from_millis(MAX_DATABASE_MILLIS);
        assert_eq!(
            millis_from_database(MAX_DATABASE_MILLIS as i64, "test timestamp").unwrap(),
            millis
        );
        assert_eq!(
            millis_for_database(millis, "test timestamp").unwrap(),
            MAX_DATABASE_MILLIS as i64
        );
    }

    #[test]
    fn unknown_persisted_network_kind_is_an_error() {
        for invalid in ["smtp", "local"] {
            assert!(matches!(
                stored_network_kind(invalid),
                Err(DbError::InvalidNetworkKind(kind)) if kind == invalid
            ));
        }
    }

    /// The naming rules of a network that says `tokens`.
    fn network(tokens: &[&str]) -> e6irc_client::NetworkNames {
        let mut names = e6irc_client::NetworkNames::default();
        names.adopt_tokens(tokens.iter().copied());
        names
    }

    #[test]
    fn bnc_direct_messages_share_the_peer_target_in_both_directions() {
        let names = network(&[]);
        assert_eq!(
            bnc_line_target(":alice!u@h PRIVMSG Bob :outbound", Some("ALICE"), &names),
            Some("Bob".to_string())
        );
        assert_eq!(
            bnc_line_target(":Bob!u@h PRIVMSG alice :inbound", Some("Alice"), &names),
            Some("Bob".to_string())
        );
        assert_eq!(
            bnc_line_target(
                ":server.example NOTICE alice :maintenance",
                Some("alice"),
                &names
            ),
            None,
            "server notices are not direct-message conversations"
        );
        assert_eq!(
            bnc_line_target(":Bob!u@h PRIVMSG #Room :channel", Some("alice"), &names),
            Some("#Room".to_string())
        );
    }

    /// A STATUSMSG is channel conversation with a narrower audience. Filed
    /// under its sender it became a direct message from someone who never sent
    /// one, and vanished from the channel history it belongs to. Which sigils
    /// and channel types exist is the network's to say: Ergo's halfops get a
    /// `%#dev`, IRCnet has `!` channels.
    #[test]
    fn bnc_statusmsg_lines_belong_to_their_channel() {
        let names = network(&["STATUSMSG=~&@%+", "CHANTYPES=#&!"]);
        for (addressed, channel) in [
            ("@#Room", "#Room"),
            ("+#Room", "#Room"),
            ("@&local", "&local"),
            ("%#dev", "#dev"),
            ("&#dev", "#dev"),
            ("!ABCDEchan", "!ABCDEchan"),
        ] {
            assert_eq!(
                bnc_line_target(
                    &format!(":Bob!u@h PRIVMSG {addressed} :ops only"),
                    Some("alice"),
                    &names
                ),
                Some(channel.to_string()),
                "{addressed}"
            );
        }
        assert_eq!(
            bnc_line_target(":alice!u@h NOTICE @#Room :from us", Some("alice"), &names),
            Some("#Room".to_string())
        );
        assert_eq!(
            bnc_line_target(
                ":Bob!u@h PRIVMSG +alice :a nick, not a STATUSMSG",
                Some("+alice"),
                &names
            ),
            Some("Bob".to_string())
        );
        assert_eq!(
            bnc_line_target(":alice!u@h PRIVMSG #a,#b :to both", Some("alice"), &names),
            None,
            "a target list is no one conversation"
        );
    }

    /// On an `ascii` network `dev[m]` is not `dev{m}`: a message from one is
    /// not ours when we are the other.
    #[test]
    fn bnc_own_nick_is_compared_the_networks_way() {
        let names = network(&["CASEMAPPING=ascii"]);
        assert_eq!(
            bnc_line_target(":dev{m}!u@h PRIVMSG dev[m] :hi", Some("dev[m]"), &names),
            Some("dev{m}".to_string())
        );
    }

    #[test]
    fn bnc_history_metadata_is_validated_and_canonicalized() {
        assert_eq!(
            bnc_line_msgid("@msgid=abc :s PRIVMSG #x :message"),
            Some("abc".into())
        );
        assert_eq!(
            bnc_line_msgid("@msgid=abc\\sdef :s PRIVMSG #x :message"),
            None
        );
        assert_eq!(bnc_line_msgid("@msgid= :s PRIVMSG #x :message"), None);
        assert_eq!(bnc_line_msgid("@msgid :s PRIVMSG #x :message"), None);
        assert_eq!(
            bnc_line_msgid("@msgid=old;msgid=new :s PRIVMSG #x :message"),
            Some("new".into()),
            "IRC duplicate tags use the final occurrence"
        );
        assert_eq!(
            bnc_line_sent_at("@time=2026-01-02T03:04:05.6Z :s PRIVMSG #x :message"),
            "2026-01-02T03:04:05.600Z"
        );
        assert_eq!(
            bnc_line_sent_at(
                "@time=2020-01-01T00:00:00.000Z;time=2026-01-02T03:04:05.6Z :s PRIVMSG #x :message"
            ),
            "2026-01-02T03:04:05.600Z",
            "history ordering must use the same final duplicate tag clients see"
        );
        let fallback = bnc_line_sent_at("@time=not-a-timestamp :s PRIVMSG #x :message");
        assert!(
            e6irc_proto::time::parse_server_time_millis(&fallback).is_some(),
            "invalid upstream time must be replaced by a sortable arrival timestamp: {fallback}"
        );
    }

    /// The macro must produce exactly the statement the queries used to spell
    /// out. `HistoryDbRow` now binds by column *name* (`sqlx::FromRow`), so the
    /// `ts_millis` alias is load-bearing — the computed column needs a name to
    /// bind to. A silent change here would be a runtime bind failure on every
    /// history read, so it is pinned rather than trusted.
    #[test]
    fn history_select_expands_to_the_expected_statement() {
        let prefix = "SELECT msgid, (EXTRACT(EPOCH FROM ts) * 1000)::bigint AS ts_millis, \
                      sender_prefix, sender_account, kind, body, sender_is_bot, multiline, \
                      client_tags FROM messages WHERE target = $1 AND ts >= \
                      to_timestamp($2::double precision / 1000) ";
        assert_eq!(
            history_select!(
                crate::core::HistoryScope::TextAndTags,
                "ORDER BY ts DESC, id DESC LIMIT $3"
            ),
            format!("{prefix}ORDER BY ts DESC, id DESC LIMIT $3")
        );
        // A reader that cannot receive a TAGMSG has them cut before the LIMIT.
        assert_eq!(
            history_select!(
                crate::core::HistoryScope::Text,
                "ORDER BY ts DESC, id DESC LIMIT $3"
            ),
            format!("{prefix}AND kind <> 'tagmsg' ORDER BY ts DESC, id DESC LIMIT $3")
        );
    }

    /// The windowed form keeps the alias and the ordering columns the outer
    /// query depends on, and cuts both halves in the reader's scope.
    #[test]
    fn history_window_keeps_alias_and_ordering_columns() {
        for (scope, cuts) in [
            (crate::core::HistoryScope::TextAndTags, 0),
            (crate::core::HistoryScope::Text, 2),
        ] {
            let sql = history_window!(scope, "AND a", "AND b");
            assert!(
                sql.contains("AS ts_millis"),
                "the millis column is aliased so FromRow can bind it by name: {sql}"
            );
            assert_eq!(
                sql.matches("ts, id").count(),
                2,
                "both halves carry ordering columns"
            );
            assert_eq!(sql.matches("kind <> 'tagmsg'").count(), cuts, "{sql}");
            assert_eq!(sql.matches("client_tags").count(), 3, "{sql}");
            assert!(sql.trim_end().ends_with("ORDER BY ts ASC, id ASC"));
            assert!(sql.contains("UNION ALL"));
        }
    }
}
