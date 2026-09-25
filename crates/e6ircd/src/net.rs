//! Socket layer: listeners and per-connection I/O tasks. This is the
//! only module that touches the network; everything inward is queues.
//!
//! Data flow per connection:
//!   socket reads → LineBuffer → `push().await` into the core queue
//!     (await = backpressure: a full core stops socket reads)
//!   core → per-connection SendQ → writer half → socket
//!     (SendQ overflow = core dooms the connection)

#![deny(clippy::let_underscore_must_use)]

use std::io;
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::certificate::CertificateReloads;
use crate::config::{BncConfig, Config};
use crate::core::{
    ConnId, ConnectionIdAllocator, Core, CoreConfig, CoreIngress, CoreShardId, CoreWorker, Input,
    Output, TimerWheel,
};
use crate::observability::{ErrorKind, Telemetry};
use e6irc_proto::framing::LineBuffer;
use e6irc_queue::{Policy, Receiver, queue};

/// Traditional 512-byte line minus CRLF, plus the 4096-byte client tag
/// allowance (message-tags spec); the body-only limit is enforced in
/// the core after the tag section is split off.
const LINE_LIMIT: usize = e6irc_proto::message::MAX_CLIENT_FRAME_LEN;
const READ_BUF: usize = 4096;
const ACCEPT_BATCH: usize = 64;
/// How often the liveness reaper tick fires (seconds); the reaper's own
/// deadlines are coarse minutes, so a fine tick isn't needed.
const REAP_TICK_MILLIS: u64 = 15_000;
const TIMER_WHEEL_RESOLUTION_MILLIS: u64 = 1_000;
const TIMER_WHEEL_SLOTS: usize = 64;

fn random_connection_id_start() -> io::Result<NonZeroU64> {
    use aws_lc_rs::rand::SecureRandom;

    let mut bytes = [0u8; 8];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| io::Error::other("system RNG failed while seeding connection identifiers"))?;
    // Keep the top two bits clear: cursor input is parsed as signed SQL-style
    // int64 at the HTTP boundary, while the remaining 62 random/counter bits
    // still leave more connection identifiers than one process can consume.
    let value = (u64::from_le_bytes(bytes) & (u64::MAX >> 2)) | 1;
    NonZeroU64::new(value)
        .ok_or_else(|| io::Error::other("connection identifier seed was unexpectedly zero"))
}

/// Cap on the TLS handshake. `Input::Open` only reaches the core — and thus the
/// liveness reaper — *after* the handshake completes, so a peer that finishes
/// the TCP connect but never sends (or dribbles) a ClientHello would otherwise
/// hold a task, an fd, and its per-IP slot indefinitely, invisible to the
/// reaper. A plaintext peer has no such window (it hits `serve_conn` at once).
/// A real handshake completes in well under a second; 30s matches the
/// registration budget a plaintext peer already gets.
const TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 30;

/// How long a client may take to send one request's complete header block.
/// hyper starts the same timer the moment a kept-alive connection goes idle
/// (waiting for the next request's headers), so this is also the idle
/// keep-alive timeout: a connection that sends nothing for this long is closed.
const HTTP_HEADER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// HTTP connections one address may hold open at once. A browser opens a
/// handful per origin; this leaves room for many behind one address. A
/// trusted reverse proxy is exempt — every client behind it shares its
/// address — and its clients are bounded per request, by forwarded address.
const MAX_HTTP_CONNECTIONS_PER_IP: usize = 128;

/// Requests one client address may have in the HTTP service at once (see
/// `http::RequestAdmission`). A browser opens a handful of connections per
/// origin; this leaves room for several behind one address while keeping any
/// one address from holding the service-wide permits with requests it never
/// finishes.
pub const MAX_HTTP_REQUESTS_IN_FLIGHT_PER_IP: usize = 32;

/// How long graceful shutdown waits for the DB worker to drain and flush its
/// buffered history before giving up. A healthy flush is a single batched
/// INSERT (milliseconds); this bound only bites if PostgreSQL is wedged, in
/// which case we exit with a non-success code rather than hang a service
/// restart forever.
const SHUTDOWN_DB_FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long graceful shutdown waits for every core shard to stop. Stopping is
/// a drain — each shard serves the others until nothing is passing between
/// them — and normally takes milliseconds.
const SHUTDOWN_CORE_STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How long graceful shutdown waits for every bouncer driver to say goodbye
/// and release its upstream, and then for its persistence task to write the
/// backlog lines it still holds. The networks stop concurrently, so this is the
/// slowest one's budget, not a sum: a healthy IRC driver needs one bounded
/// write (`QUIT`, 2 s at most); a Matrix driver logs its device out; the
/// backlog write is a few INSERTs. Without
/// this step a restart met its own ghost on every network (433, then the
/// refusal schedule). `tools/check-systemd-unit.sh` sums it with the core and
/// database budgets for the unit's stop timeout.
const SHUTDOWN_DRIVER_STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

fn core_queue_name(index: usize) -> &'static str {
    Box::leak(format!("core-{index}").into_boxed_str())
}

pub struct Running {
    /// Bound IRC addresses, in listener-config order (useful with port 0).
    pub addrs: Vec<SocketAddr>,
    /// Bound HTTP address, when the http listener is configured.
    pub http_addr: Option<SocketAddr>,
    /// Bound BNC listener address, when configured.
    pub bnc_addr: Option<SocketAddr>,
    /// Drives the graceful-shutdown sequence (stop accepting, notify clients,
    /// flush the PG write queue). Held by `main` and consumed on a signal.
    pub shutdown: ShutdownHandle,
}

/// A task whose unexpected exit invalidates the process. The daemon reports
/// the exact task and join outcome, performs the same bounded graceful drain
/// as a signal-triggered shutdown, and exits non-zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriticalTaskFailure {
    pub task: &'static str,
    pub reason: String,
}

impl std::fmt::Display for CriticalTaskFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "critical task {} stopped: {}",
            self.task, self.reason
        )
    }
}

/// Everything `main` needs to shut the server down cleanly on SIGTERM/SIGINT.
/// Built by [`start`]; see [`ShutdownHandle::run`] for the sequence.
pub struct ShutdownHandle {
    /// Accept-loop tasks (IRC listeners, the HTTP server, the BNC listener).
    /// Aborted first so no new connection is admitted mid-shutdown.
    listeners: Vec<tokio::task::AbortHandle>,
    /// The core worker's input sender. Pushing [`Input::Shutdown`] makes the
    /// core notify clients and then stop, which drops the DB request sender.
    core_tx: Option<CoreIngress>,
    /// Every core shard is authoritative for its owned state. Main watches the
    /// supervised exits while serving and joins every shard on shutdown.
    core_workers: tokio::task::JoinSet<()>,
    /// The DB worker task, awaited (bounded) so its buffered `log_batch` reaches
    /// PostgreSQL before exit. `None` when no `[database]` is configured (there
    /// is then no worker and nothing buffered to lose).
    db_worker: Option<tokio::task::JoinHandle<()>>,
    /// Listener handles are supervised in detached join-watchers because the
    /// shutdown path only needs their abort handles.
    critical_failures: tokio::sync::mpsc::UnboundedReceiver<CriticalTaskFailure>,
    /// Runtime-managed BNC listener. Unlike the bootstrap listeners, this can
    /// be replaced from the console, so shutdown must address the controller
    /// rather than only the task that happened to exist at startup.
    bnc_listener: Option<Arc<BncListenerController>>,
    /// The bouncer drivers, stopped after the listeners so each says goodbye
    /// to its upstream before the process exits. `None` when no network can
    /// exist (no database and no configured network).
    bnc_registry: Option<Arc<crate::bouncer::Registry>>,
}

/// How graceful shutdown ended, so `main` can pick an honest exit code.
#[derive(Debug, PartialEq, Eq)]
pub enum ShutdownOutcome {
    /// The DB worker drained and flushed (or there was no database).
    Flushed,
    /// The flush did not finish within [`SHUTDOWN_DB_FLUSH_TIMEOUT`]; buffered
    /// history may have been lost, so the caller must not report success.
    FlushTimedOut,
    /// The DB worker task panicked while draining.
    WorkerPanicked,
    /// The core did not stop within the bounded shutdown interval.
    CoreTimedOut,
    /// The core task panicked while processing live state.
    CorePanicked,
}

impl ShutdownHandle {
    /// Wait until a critical task exits before shutdown was requested.
    pub async fn wait_for_critical_failure(&mut self) -> CriticalTaskFailure {
        if let Some(db_worker) = self.db_worker.as_mut() {
            tokio::select! {
                result = db_worker => {
                    self.db_worker = None;
                    critical_join_failure("PostgreSQL worker", result)
                }
                failure = next_core_failure(&mut self.core_workers) => failure,
                failure = self.critical_failures.recv() => {
                    failure.expect("listener supervisors remain alive while serving")
                }
            }
        } else {
            tokio::select! {
                failure = next_core_failure(&mut self.core_workers) => failure,
                failure = self.critical_failures.recv() => {
                    failure.expect("core and listener supervisors remain alive while serving")
                }
            }
        }
    }

    /// Run the graceful-shutdown sequence (DESIGN §18): stop accepting new
    /// connections, stop every bouncer driver (each says `QUIT` upstream),
    /// ask the core to notify clients and stop, then wait for the DB worker to
    /// flush its buffered history. Returns once the worker has drained or the
    /// bounded timeout elapses.
    pub async fn run(self) -> ShutdownOutcome {
        self.run_within(SHUTDOWN_CORE_STOP_TIMEOUT, SHUTDOWN_DRIVER_STOP_TIMEOUT)
            .await
    }

    async fn run_within(
        mut self,
        core_stop_timeout: std::time::Duration,
        driver_stop_timeout: std::time::Duration,
    ) -> ShutdownOutcome {
        // 1. Stop accepting: abort every listener task up front so nothing new
        //    is admitted while we drain.
        for listener in &self.listeners {
            listener.abort();
        }
        if let Some(listener) = &self.bnc_listener {
            listener.stop().await;
        }
        // 2. Stop the bouncer drivers, all at once, before the core: an
        //    attached client is told the network went away by its driver, and
        //    the upstream hears a goodbye instead of a reset. The drivers'
        //    own bounded writes make this finite; the deadline only bounds a
        //    wedged one, and the stop stands either way.
        if let Some(registry) = self.bnc_registry.take() {
            let stops = registry.stop_all_within(driver_stop_timeout).await;
            if stops.released < stops.running {
                eprintln!(
                    "e6ircd: {} of {} bouncer drivers did not release their upstream \
                     within {}s of the stop; proceeding without them",
                    stops.running - stops.released,
                    stops.running,
                    driver_stop_timeout.as_secs()
                );
            }
            if stops.backlog_written < stops.running {
                eprintln!(
                    "e6ircd: {} of {} bouncer networks did not finish writing their last \
                     backlog lines within {}s of the stop; those lines are lost",
                    stops.running - stops.backlog_written,
                    stops.running,
                    driver_stop_timeout.as_secs()
                );
            }
        }
        // 3. Tell the core to notify clients (terminal ERROR) and stop. A push
        //    failure can only mean the core queue is already closed, i.e. the
        //    core is already gone — nothing more to ask of it.
        // Queue closure means the core already stopped, which is the requested
        // shutdown state.
        let core_tx = self.core_tx.take().expect("shutdown core ingress present");
        if core_tx.broadcast_shutdown().await.is_err() {
            eprintln!("e6ircd: core ingress closed before shutdown broadcast");
        }
        // Drop our own sender clone so it isn't left keeping the core queue's
        // producer count up. (The core breaks on the Shutdown event regardless;
        // this just keeps the shutdown intent honest.)
        drop(core_tx);
        // Every shard is joined, whatever happens to one of them. A shard that
        // failed has lost its own state, but the database worker still holds
        // buffered history that is good — and it can only flush once *every*
        // core has dropped its end of the database queue. So a failure here is
        // remembered and reported after the flush, never instead of it.
        let mut core_failure = None;
        let deadline = tokio::time::Instant::now() + core_stop_timeout;
        loop {
            match tokio::time::timeout_at(deadline, self.core_workers.join_next()).await {
                Ok(Some(Ok(()))) => {}
                Ok(Some(Err(_join_error))) => {
                    core_failure.get_or_insert(ShutdownOutcome::CorePanicked);
                }
                Ok(None) => break,
                Err(_elapsed) => {
                    core_failure.get_or_insert(ShutdownOutcome::CoreTimedOut);
                    // A shard that will not stop (a failed shard's peers wait
                    // for traffic it will never settle) is ended here, which
                    // drops its core and with it its hold on the database queue.
                    self.core_workers.shutdown().await;
                    break;
                }
            }
        }
        // 4. Wait for the DB worker to observe its now-dropped sender, drain,
        //    and flush. Bounded so a wedged database can't hang the shutdown.
        let flush = match self.db_worker.take() {
            None => ShutdownOutcome::Flushed,
            Some(worker) => match tokio::time::timeout(SHUTDOWN_DB_FLUSH_TIMEOUT, worker).await {
                Ok(Ok(())) => ShutdownOutcome::Flushed,
                Ok(Err(_join_err)) => ShutdownOutcome::WorkerPanicked,
                Err(_elapsed) => ShutdownOutcome::FlushTimedOut,
            },
        };
        core_failure.unwrap_or(flush)
    }
}

impl Drop for ShutdownHandle {
    fn drop(&mut self) {
        self.core_workers.detach_all();
    }
}

fn critical_join_failure(
    task: &'static str,
    result: Result<(), tokio::task::JoinError>,
) -> CriticalTaskFailure {
    let reason = match result {
        Ok(()) => "exited unexpectedly".to_string(),
        Err(error) if error.is_panic() => format!("panicked: {error}"),
        Err(error) if error.is_cancelled() => format!("was cancelled: {error}"),
        Err(error) => format!("failed: {error}"),
    };
    CriticalTaskFailure { task, reason }
}

async fn next_core_failure(workers: &mut tokio::task::JoinSet<()>) -> CriticalTaskFailure {
    critical_join_failure(
        "IRC core shard",
        workers
            .join_next()
            .await
            .expect("core shards remain supervised"),
    )
}

fn supervise_listener(
    name: &'static str,
    task: tokio::task::JoinHandle<()>,
    failures: tokio::sync::mpsc::UnboundedSender<CriticalTaskFailure>,
) -> tokio::task::AbortHandle {
    let abort = task.abort_handle();
    tokio::spawn(async move {
        let failure = critical_join_failure(name, task.await);
        drop(failures.send(failure));
    });
    abort
}

#[derive(Debug)]
struct BncListenerState {
    requested: BncConfig,
    bound: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

/// Owns the attach listener as a replaceable runtime resource.
///
/// Reconfiguration binds the replacement before stopping the current listener,
/// so an invalid or occupied address cannot take a working endpoint down. The
/// controller is the one choke point for start, replace, disable, status, and
/// shutdown; a console write therefore cannot drift from the socket actually
/// accepting clients.
pub struct BncListenerController {
    state: tokio::sync::Mutex<Option<BncListenerState>>,
    registry: Arc<crate::bouncer::Registry>,
    pool: sqlx::PgPool,
    server_name: String,
    limiter: ConnLimiter,
    telemetry: Arc<Telemetry>,
    certificates: CertificateReloads,
}

impl BncListenerController {
    fn new(
        registry: Arc<crate::bouncer::Registry>,
        pool: sqlx::PgPool,
        server_name: String,
        limiter: ConnLimiter,
        telemetry: Arc<Telemetry>,
        certificates: CertificateReloads,
    ) -> Self {
        Self {
            state: tokio::sync::Mutex::new(None),
            registry,
            pool,
            server_name,
            limiter,
            telemetry,
            certificates,
        }
    }

    /// The configured listener and its effective address, when enabled.
    pub async fn status(&self) -> Option<(BncConfig, SocketAddr)> {
        self.state
            .lock()
            .await
            .as_ref()
            .map(|state| (state.requested.clone(), state.bound))
    }

    /// Enable or atomically replace the listener. The old listener remains
    /// active when the new address cannot be bound or its certificate cannot
    /// be read.
    pub async fn enable(&self, requested: &BncConfig) -> io::Result<SocketAddr> {
        let acceptor = match &requested.tls {
            Some(tls) => Some(self.certificates.acceptor(tls).inspect_err(|_error| {
                self.telemetry.record_error(ErrorKind::TlsHandshake);
            })?),
            None => None,
        };
        let listener = bind_listener(requested.addr).inspect_err(|_error| {
            self.telemetry.record_error(ErrorKind::Bouncer);
        })?;
        let bound = listener.local_addr().inspect_err(|_error| {
            self.telemetry.record_error(ErrorKind::ConnectionSetup);
        })?;
        let task = spawn_bnc_listener(
            listener,
            acceptor,
            self.registry.clone(),
            self.pool.clone(),
            self.server_name.clone(),
            self.limiter.clone(),
            self.telemetry.clone(),
        );
        let replacement = BncListenerState {
            requested: requested.clone(),
            bound,
            task,
        };
        let previous = self.state.lock().await.replace(replacement);
        if let Some(previous) = previous {
            previous.task.abort();
            drop(previous.task.await);
        }
        Ok(bound)
    }

    /// Disable the listener and wait until its accept task has been cancelled.
    pub async fn stop(&self) {
        if let Some(previous) = self.state.lock().await.take() {
            previous.task.abort();
            drop(previous.task.await);
        }
    }
}

fn spawn_bnc_listener(
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    registry: Arc<crate::bouncer::Registry>,
    pool: sqlx::PgPool,
    server_name: String,
    limiter: ConnLimiter,
    telemetry: Arc<Telemetry>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let client = ClientIp::new(peer.ip());
                    let Some(guard) = limiter.try_acquire(client) else {
                        telemetry.record_connection_rejected();
                        limiter
                            .refusals()
                            .note(client, PeerRefusal::PerIpLimit, None);
                        continue;
                    };
                    let registry = registry.clone();
                    let server_name = server_name.clone();
                    let pool = pool.clone();
                    let telemetry = telemetry.clone();
                    let refusals = limiter.refusals().clone();
                    let tls = tls.clone();
                    tokio::spawn(async move {
                        let _guard = guard;
                        if let Err(e) = stream.set_nodelay(true) {
                            telemetry.record_error(ErrorKind::ConnectionSetup);
                            refusals.note(client, PeerRefusal::SocketSetup, Some(&e));
                            return;
                        }
                        let served = match tls {
                            // Attaching clients authenticate with their account
                            // password; off loopback that only ever travels
                            // inside TLS (config refuses anything else).
                            Some(acceptor) => {
                                let handshake = tokio::time::timeout(
                                    std::time::Duration::from_secs(TLS_HANDSHAKE_TIMEOUT_SECS),
                                    acceptor.accept(stream),
                                )
                                .await;
                                match handshake {
                                    Ok(Ok(stream)) => {
                                        crate::bouncer::bnc_serve(
                                            stream,
                                            registry,
                                            &pool,
                                            &server_name,
                                            &peer.ip().to_string(),
                                        )
                                        .await
                                    }
                                    Ok(Err(e)) => {
                                        telemetry.record_error(ErrorKind::TlsHandshake);
                                        refusals.note(
                                            client,
                                            PeerRefusal::TlsHandshakeFailed,
                                            Some(&e),
                                        );
                                        return;
                                    }
                                    Err(_) => {
                                        telemetry.record_error(ErrorKind::TlsHandshake);
                                        refusals.note(
                                            client,
                                            PeerRefusal::TlsHandshakeTimedOut,
                                            None,
                                        );
                                        return;
                                    }
                                }
                            }
                            None => {
                                crate::bouncer::bnc_serve(
                                    stream,
                                    registry,
                                    &pool,
                                    &server_name,
                                    &peer.ip().to_string(),
                                )
                                .await
                            }
                        };
                        if let Err(e) = served {
                            telemetry.record_error(ErrorKind::Bouncer);
                            eprintln!("bnc connection from {peer} failed: {e}");
                        }
                    });
                }
                Err(e) => {
                    telemetry.record_error(ErrorKind::Accept);
                    eprintln!("bnc accept error: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    })
}

/// Unix-epoch milliseconds. Message timestamps are stamped from this, and
/// `server-time` is specified to millisecond precision — a whole-second clock
/// would give every message in the same second an identical `time=` tag,
/// which CHATHISTORY cannot page through.
fn wall_clock() -> e6irc_proto::time::Millis {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_millis() as u64;
    e6irc_proto::time::Millis::from_millis(ms)
}

/// Monotonic milliseconds since the process started, for timer decisions (the
/// reaper deadlines and flood-bucket refill). Unlike [`wall_clock`] this never
/// steps — an NTP correction or a VM resume cannot move it — so a reaper keyed
/// on it can neither mass-close live connections on a forward jump nor freeze
/// on a backward one. The epoch is arbitrary (process start); only differences
/// are meaningful, which is all the timers ever take.
fn mono_clock() -> e6irc_proto::time::MonoMillis {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    let ms = START.get_or_init(Instant::now).elapsed().as_millis() as u64;
    e6irc_proto::time::MonoMillis::from_millis(ms)
}

/// Select aws-lc-rs as the process-wide rustls provider exactly once.
/// Anything in the dependency tree may enable rustls's `ring` feature
/// (test HTTP clients did), which breaks auto-selection — pinning here
/// makes that whole failure class impossible.
pub fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("no other rustls provider installed before e6ircd");
    });
}

/// Whether the process serves HTTP: the `[http]` listener, or a WebSocket IRC
/// listener, which is served by the same application state.
fn serves_http(config: &Config) -> bool {
    config.http.is_some() || config.listeners.iter().any(|listener| listener.websocket)
}

/// What [`start`] reads from outside the configuration document that needs
/// neither the network nor the database, judged by the very functions `start`
/// uses: the monitoring token from the environment and every TLS certificate
/// and key pair the configuration names. `e6ircd check-config` runs this after
/// the parse-and-validate [`Config::load`] does, so a configuration it passes
/// cannot fail `start` over a malformed variable or an unreadable key file.
/// (With a database, the listeners and `[bnc]` in force come from the stored
/// revision once one exists; this judges the configuration as stated. Whether
/// the console-owned settings it states agree with that revision needs the
/// database, so only `start` can judge it — [`ManagedConfig::bootstrap_drift`]
/// — and `check-config` says so rather than implying it passed.)
///
/// [`ManagedConfig::bootstrap_drift`]: crate::config::ManagedConfig::bootstrap_drift
pub fn check_offline(config: &Config) -> io::Result<()> {
    if serves_http(config) {
        crate::http::monitoring_token_digest_from_env().map_err(io::Error::other)?;
    }
    let listener_files = config.listeners.iter().filter_map(|l| l.tls.as_ref());
    let bnc_files = config.bnc.iter().filter_map(|bnc| bnc.tls.as_ref());
    for files in listener_files.chain(bnc_files) {
        crate::certificate::ReloadingCertificate::load(files)?;
    }
    Ok(())
}

/// Bind listeners, spawn core workers, and start acceptors.
pub async fn start(mut config: Config) -> io::Result<Running> {
    // First, before anything that can wait: a SIGHUP sent to reload
    // certificates during the database wait must not be the default action,
    // which terminates the process.
    let hangups = crate::certificate::Hangups::install()?;
    install_crypto_provider();
    // Resolve once and reuse for the control-plane import plus BNC secrets.
    // UI-managed OIDC/operator credentials are always sealed in PostgreSQL.
    let secret_key = config
        .secret_keyring()
        .map_err(io::Error::other)?
        .map(Arc::new);
    // Load persisted settings before constructing anything that consumes
    // them. In particular, a queue's capacity cannot be changed after the
    // queue exists; loading `core_queue` later would make that console setting
    // a permanent no-op.
    let (pool, managed_config) = match config
        .database
        .as_ref()
        .map(|db| (db.url.clone(), db.startup_wait_seconds, db.pool_size()))
    {
        Some((database_url, startup_wait_seconds, pool_size)) => {
            let wait = crate::db::StartupDatabaseWait::from_seconds(startup_wait_seconds)
                .map_err(io::Error::other)?;
            eprintln!(
                "e6ircd: database pool holds at most {} connections",
                pool_size.get()
            );
            let pool = crate::db::connect_and_migrate_with_retry(
                &database_url,
                wait,
                pool_size,
                |attempt| match attempt.retry_in {
                    Some(pause) => eprintln!(
                        "e6ircd: database connection attempt {} failed after {:.1}s: {}; retrying \
                         in {:.1}s (giving up after {}s)",
                        attempt.attempt,
                        attempt.waited.as_secs_f64(),
                        attempt.error,
                        pause.as_secs_f64(),
                        wait.duration().as_secs(),
                    ),
                    None => eprintln!(
                        "e6ircd: database connection attempt {} failed after {:.1}s: {}; giving up",
                        attempt.attempt,
                        attempt.waited.as_secs_f64(),
                        attempt.error,
                    ),
                },
            )
            .await
            .map_err(io::Error::other)?;
            let imported =
                crate::config::ManagedConfig::from_config(&config, secret_key.as_deref())
                    .map_err(io::Error::other)?;
            let mut snapshot = crate::db::load_or_initialize_managed_config(&pool, &imported)
                .await
                .map_err(io::Error::other)?;
            // The console owns every setting in the stored revision. One the
            // configuration also states must agree with it: applying the
            // revision over a different stated value would ignore that value
            // without a word (a name removed from the administrator list that
            // kept its authority, a rotated client secret never used).
            let conflicting = snapshot
                .settings
                .bootstrap_drift(&config, secret_key.as_deref())
                .map_err(io::Error::other)?;
            if !conflicting.is_empty() {
                return Err(io::Error::other(crate::config::ManagedSettingsConflict {
                    settings: conflicting,
                    revision: snapshot.revision,
                    updated_by: snapshot.updated_by,
                    updated_at: snapshot.updated_at,
                }));
            }
            // A legacy plaintext deployment cannot be copied into PostgreSQL
            // safely without a key. Once a key is supplied, import the still-
            // authoritative bootstrap credentials as sealed values in one
            // revision before applying the database snapshot.
            if snapshot.settings.credentials_from_bootstrap && !imported.credentials_from_bootstrap
            {
                let mut upgraded = snapshot.settings.clone();
                upgraded.oidc_providers = imported.oidc_providers;
                upgraded.opers = imported.opers;
                upgraded.networks = imported.networks;
                upgraded.credentials_from_bootstrap = false;
                snapshot = crate::db::save_managed_config(
                    &pool,
                    snapshot.revision,
                    &upgraded,
                    "bootstrap",
                    "sealed credential import after master key became available",
                )
                .await
                .map_err(io::Error::other)?;
            }
            snapshot.settings.apply_to(&mut config);
            config
                .resolve_secrets_with_key(secret_key.as_deref())
                .map_err(io::Error::other)?;
            config.validate().map_err(io::Error::other)?;
            config.validate_secrets().map_err(io::Error::other)?;
            (Some(pool), Some(snapshot))
        }
        None => (None, None),
    };

    let mut core_receivers = Vec::with_capacity(config.core_workers);
    let (first_core_sender, first_core_receiver) = queue::<Input>(e6irc_queue::Config {
        name: core_queue_name(0),
        capacity: config.core_queue,
        policy: Policy::Fifo,
    });
    core_receivers.push(first_core_receiver);
    let mut remaining_core_senders = Vec::with_capacity(config.core_workers.saturating_sub(1));
    for index in 1..config.core_workers {
        let (sender, receiver) = queue::<Input>(e6irc_queue::Config {
            name: core_queue_name(index),
            capacity: config.core_queue,
            policy: Policy::Fifo,
        });
        remaining_core_senders.push(sender);
        core_receivers.push(receiver);
    }
    let core_tx = CoreIngress::with_shards(first_core_sender, remaining_core_senders);
    let (db_tx, db_rx) = queue::<crate::core::DbRequest>(e6irc_queue::Config {
        name: "db",
        capacity: 1024,
        policy: Policy::Fifo,
    });
    let telemetry = Arc::new(Telemetry::observing_queues(
        core_tx.monitors(),
        db_tx.monitor(),
    ));
    if let (Some(pool), Some(database)) = (&pool, &config.database) {
        telemetry.observe_database_pool(pool.clone(), database.pool_size());
    }
    let (critical_tx, critical_rx) = tokio::sync::mpsc::unbounded_channel();
    let managed_config =
        managed_config.map(|snapshot| Arc::new(tokio::sync::RwLock::new(snapshot)));
    // SASL is only advertised when a database exists to answer verification
    // requests.
    let sasl_enabled = pool.is_some();

    // Accept-loop tasks, collected so shutdown can stop admitting connections.
    let mut listeners: Vec<tokio::task::AbortHandle> = Vec::new();

    let next_conn = Arc::new(ConnectionIdAllocator::new(random_connection_id_start()?));

    // The BNC registry is shared between the HTTP management API (which
    // adds/removes networks) and the BNC listener (which attaches to
    // them). Server-level [[network]]s start first, then each account's
    // persisted networks are loaded and started.
    let bnc_registry = if pool.is_some() || !config.networks.is_empty() {
        let reg = Arc::new(
            crate::bouncer::Registry::start_observed(
                &config.networks,
                pool.clone(),
                crate::bouncer::CoreHandles {
                    core_tx: core_tx.clone(),
                    next_conn: next_conn.clone(),
                    sendq: config.sendq,
                },
                telemetry.clone(),
                config.internal_upstreams,
            )
            .map_err(io::Error::other)?,
        );
        if let Some(pool) = &pool {
            for (owner, row) in crate::db::list_startable_bnc_networks(pool)
                .await
                .map_err(io::Error::other)?
            {
                // One tenant's un-buildable network must not abort the whole
                // server's boot: a row can become un-buildable after a binary
                // swap (a bridge kind whose feature was dropped) or a master-key
                // rotation (its sealed secret no longer opens). Skip it loudly —
                // that one network is down until fixed — rather than brick the
                // shared daemon for every user. Config-file networks still fail
                // hard (they are the operator's own, checked at start).
                match crate::bouncer::driver_from_row(
                    &row,
                    secret_key.as_deref(),
                    &owner,
                    config.internal_upstreams,
                    crate::bouncer::FirstDial::Staggered,
                ) {
                    Ok(driver) => {
                        // A configuration-file network may already hold this
                        // key. The operator's own entry wins; say so rather
                        // than abort the boot or run two upstream sessions.
                        if let Err(error) = reg.add(
                            Some(&owner),
                            &row.name,
                            crate::db::BncNetworkDefinition::Stored,
                            driver,
                        ) {
                            telemetry.record_error(ErrorKind::Bouncer);
                            eprintln!("bnc: skipping stored network: {error}");
                        }
                    }
                    Err(e) => {
                        telemetry.record_error(ErrorKind::Bouncer);
                        eprintln!(
                            "bnc: not starting network {owner}/{} at boot: {e}",
                            row.name
                        );
                    }
                }
            }
        }
        Some(reg)
    } else {
        None
    };

    // The configured administrators, once: the core refuses their names as
    // accounts, the HTTP state grants their authority, and account deletion
    // keeps the last of them.
    let configured_administrators = crate::identity::ReservedAccountNames::new(
        config
            .http
            .iter()
            .flat_map(|http| http.admin_accounts.iter().map(String::as_str)),
    );
    // The database worker carries out NickServ DROP through the same deletion
    // procedure as the console, so it starts once the network registry that
    // procedure stops an account's networks through exists. Keep the worker
    // handle so graceful shutdown can guarantee its buffered `log_batch` is
    // flushed before the process exits (DESIGN §18).
    let db_worker = match (&pool, &bnc_registry) {
        (Some(pool), Some(registry)) => {
            let account_deletion = crate::account_deletion::AccountDeletion {
                pool: pool.clone(),
                core_tx: core_tx.clone(),
                registry: registry.clone(),
                secret_key: secret_key.clone(),
                internal_upstreams: config.internal_upstreams,
                configured_administrators: configured_administrators.clone(),
            };
            Some(tokio::spawn(crate::db::run_worker_observed(
                pool.clone(),
                db_rx,
                core_tx.clone(),
                telemetry.clone(),
                account_deletion,
            )))
        }
        (Some(_), None) => unreachable!("the network registry exists whenever the database does"),
        (None, _) => {
            drop(db_rx);
            None
        }
    };

    // One per-IP connection cap shared by the TCP IRC listeners and the
    // IRC-over-WebSocket path, so a client can't sidestep the cap by opening
    // its sessions through /ws/irc instead of the raw port.
    let limiter = ConnLimiter::new(config.limits.max_connections_per_ip);

    // Database-backed network management and the attach listener are separate
    // capabilities. The registry exists as soon as persistence does; the
    // listener can then be enabled or rebound from the console without
    // reconstructing every always-on upstream.
    // Every TLS certificate the process serves, reloaded on SIGHUP and when
    // its files change.
    let certificates = CertificateReloads::default();
    listeners.push(supervise_listener(
        "TLS certificate reloader",
        tokio::spawn(certificates.clone().run(hangups)),
        critical_tx.clone(),
    ));
    let bnc_listener = match (&pool, &bnc_registry) {
        (Some(pool), Some(registry)) => Some(Arc::new(BncListenerController::new(
            registry.clone(),
            pool.clone(),
            config.server_name.clone(),
            limiter.clone(),
            telemetry.clone(),
            certificates.clone(),
        ))),
        _ => None,
    };
    let mut bnc_addr = None;
    if let Some(bnc) = &config.bnc {
        let controller = bnc_listener
            .as_ref()
            .expect("config validation guarantees [database] when [bnc] is set");
        bnc_addr = Some(controller.enable(bnc).await?);
    }
    if let (Some(pool), Some(settings)) = (&pool, &managed_config) {
        let sampler = tokio::spawn(crate::observability::run_sampler(
            pool.clone(),
            telemetry.clone(),
            bnc_registry.clone(),
            settings.clone(),
        ));
        listeners.push(supervise_listener(
            "observability sampler",
            sampler,
            critical_tx.clone(),
        ));
        let maintenance = tokio::spawn(crate::observability::run_storage_maintenance(
            pool.clone(),
            telemetry.clone(),
            settings.clone(),
            core_tx.clone(),
        ));
        listeners.push(supervise_listener(
            "storage maintenance",
            maintenance,
            critical_tx.clone(),
        ));
    }

    // One shared HTTP `AppState`, built when either the HTTP server or any
    // dedicated websocket-IRC listener needs it, so both serve against the same
    // core, per-IP limiter and sendq. A websocket listener with no `[http]`
    // section still gets a state (with HTTP-UI fields defaulted — they are
    // unused by the WS-IRC router).
    let app_state: Option<Arc<crate::http::AppState>> = if serves_http(&config) {
        let bootstrap_available = if config.bootstrap.is_some() {
            let pool = pool
                .as_ref()
                .expect("config validation requires database for browser bootstrap");
            !crate::db::has_accounts(pool)
                .await
                .map_err(io::Error::other)?
        } else {
            false
        };
        let trusted_proxies = config
            .limits
            .trusted_proxies
            .iter()
            .map(|s| {
                s.parse::<ipnet::IpNet>().map_err(|e| {
                    io::Error::other(format!("invalid trusted_proxies CIDR {s:?}: {e}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (public_url, secure_cookies) = match &config.http {
            Some(h) => (h.public_url.clone(), h.secure_cookies),
            None => (None, false),
        };
        let monitoring_token_digest =
            crate::http::monitoring_token_digest_from_env().map_err(io::Error::other)?;
        Some(Arc::new(crate::http::AppState {
            server_name: config.server_name.clone(),
            network_name: config.network_name.clone(),
            pool: pool.clone(),
            public_url,
            http_bind: config.http.as_ref().map(|http| http.addr),
            hsts_include_subdomains: config
                .http
                .as_ref()
                .is_some_and(|http| http.hsts_include_subdomains),
            secure_cookies,
            internal_upstreams: config.internal_upstreams,
            oidc_providers: config.oidc_providers.clone(),
            application_release_revision: config.application_release_revision.clone(),
            monitoring_token_digest,
            oidc_flow_key: crate::secret::SecretKey::generate(),
            core_tx: core_tx.clone(),
            next_conn: next_conn.clone(),
            sendq: config.sendq,
            bnc_registry: bnc_registry.clone(),
            bnc_listener: bnc_listener.clone(),
            managed_config: managed_config.clone(),
            telemetry: telemetry.clone(),
            secret_key: secret_key.clone(),
            configured_admin_accounts: configured_administrators.clone(),
            csrf_key: {
                use aws_lc_rs::rand::SecureRandom;
                let mut k = [0u8; 32];
                aws_lc_rs::rand::SystemRandom::new()
                    .fill(&mut k)
                    .expect("system RNG for CSRF key");
                k
            },
            trusted_proxies: trusted_proxies.clone(),
            auth_rate_burst: config.limits.auth_rate_burst,
            auth_buckets: std::sync::Mutex::new(std::collections::HashMap::new()),
            api_rate_burst: config.limits.api_rate_burst,
            administrator_api_rate_burst: config.limits.administrator_api_rate_burst,
            api_buckets: std::sync::Mutex::new(std::collections::HashMap::new()),
            preflight_limiter: crate::http::PreflightLimiter::new(),
            ui_sockets: crate::http::UiSocketLimiter::new(),
            account_exports: crate::http::AccountExportSlots::new(),
            conn_limiter: limiter.clone(),
            database_readiness: crate::http::DatabaseReadiness::default(),
            request_admission: Arc::new(crate::http::RequestAdmission::new(
                trusted_proxies.clone(),
                MAX_HTTP_REQUESTS_IN_FLIGHT_PER_IP,
            )),
            observation: Arc::new(crate::http::RequestObservation::new(
                telemetry.clone(),
                {
                    use aws_lc_rs::rand::SecureRandom;
                    let mut bytes = [0u8; 8];
                    aws_lc_rs::rand::SystemRandom::new()
                        .fill(&mut bytes)
                        .map_err(|_| io::Error::other("system RNG for HTTP request identifiers"))?;
                    u64::from_le_bytes(bytes)
                },
                match &config.http {
                    Some(http)
                        if http
                            .public_url
                            .as_deref()
                            .is_some_and(|url| url.starts_with("https://")) =>
                    {
                        if http.hsts_include_subdomains {
                            crate::http::Hsts::WithSubdomains
                        } else {
                            crate::http::Hsts::ThisOrigin
                        }
                    }
                    _ => crate::http::Hsts::Off,
                },
            )),
            bootstrap_token_digest: config
                .bootstrap
                .as_ref()
                .map(|bootstrap| crate::http::bootstrap_token_digest(&bootstrap.token)),
            bootstrap_available: std::sync::atomic::AtomicBool::new(bootstrap_available),
        }))
    } else {
        None
    };

    let http_addr = match &config.http {
        Some(http_config) => {
            let listener = bind_listener(http_config.addr)?;
            let bound = listener.local_addr()?;
            let state = app_state
                .clone()
                .expect("app_state is built whenever [http] is set");
            let http_task = tokio::spawn(serve_http(
                listener,
                crate::http::router(state.clone()),
                HttpAdmission::for_state(&state),
                telemetry.clone(),
            ));
            listeners.push(supervise_listener(
                "HTTP listener",
                http_task,
                critical_tx.clone(),
            ));
            Some(bound)
        }
        None => None,
    };

    let core_config = CoreConfig {
        server_name: config.server_name.clone(),
        network_name: config.network_name.clone(),
        description: config.description.clone(),
        registration_before_connect: config.registration.before_connect,
        registration_require_email: config.registration.require_email,
        sendq: config.sendq,
        motd: config.motd.clone(),
        nicklen: config.nicklen,
        sasl_enabled,
        max_hot_channels: config.max_hot_channels,
        opers: config
            .opers
            .iter()
            .map(|o| (o.name.clone(), o.password.clone()))
            .collect(),
        clock: wall_clock,
        mono_clock,
        command_flood: Some(
            crate::core::CommandFlood::new(config.limits.command_burst, config.limits.command_rate)
                .map_err(io::Error::other)?,
        ),
        registration_burst: config.limits.registration_burst,
        reserved_account_names: configured_administrators.clone(),
    };
    let shard_count = core_tx.shard_count();
    let mut cores = (0..shard_count.len())
        .map(|index| {
            Core::on_shard(
                core_config.clone(),
                db_tx.clone(),
                telemetry.clone(),
                CoreShardId::new(index),
                shard_count,
                core_tx.directories(),
            )
        })
        .collect::<Vec<_>>();
    // Seed registered-channel ownership and retained topics so a founder
    // is re-opped and the topic restored on join after a restart, not only
    // within the run that registered them.
    if let Some(pool) = &pool {
        let founders = crate::db::list_registered_channels(pool)
            .await
            .map_err(io::Error::other)?;
        let successors = crate::db::list_channel_successors(pool)
            .await
            .map_err(io::Error::other)?;
        let topics = crate::db::list_channel_topics(pool)
            .await
            .map_err(io::Error::other)?;
        let keeptopic_off = crate::db::list_keeptopic_off(pool)
            .await
            .map_err(io::Error::other)?;
        let mlock = crate::db::list_channel_mlock(pool)
            .await
            .map_err(io::Error::other)?;
        let access = crate::db::list_channel_access(pool)
            .await
            .map_err(io::Error::other)?;
        let bans = crate::db::list_server_bans(pool)
            .await
            .map_err(io::Error::other)?;
        // The read-marker mirror must be seeded too, or MARKREAD queries report
        // `*` after a restart and a stale set could move a marker backwards.
        let read_markers = crate::db::list_all_read_markers(pool)
            .await
            .map_err(io::Error::other)?
            .into_iter()
            .collect::<Vec<_>>();
        let suspended = crate::db::list_suspended_accounts(pool)
            .await
            .map_err(io::Error::other)?;
        let nick_registrations = crate::db::list_nick_registrations(pool)
            .await
            .map_err(io::Error::other)?;
        for name in
            crate::db::unclaimed_account_names(pool, &configured_administrators.folded_names())
                .await
                .map_err(io::Error::other)?
        {
            eprintln!(
                "e6ircd: configured administrator {name:?} has no account yet; only OIDC sign-in \
                 or the bootstrap/recovery flows can create it (NickServ REGISTER and GROUP, \
                 IRCv3 REGISTER and invitations refuse the name)"
            );
        }
        for core in &mut cores {
            core.preload_founders(founders.clone());
            core.preload_successors(successors.clone());
            core.preload_topics(topics.clone());
            core.preload_keeptopic_off(keeptopic_off.clone());
            core.preload_mlock(mlock.clone())
                .map_err(io::Error::other)?;
            core.preload_access(access.clone());
            core.preload_server_bans(bans.clone())
                .map_err(io::Error::other)?;
            core.preload_read_markers(read_markers.clone());
            core.preload_suspended_accounts(suspended.clone());
            core.preload_nick_registrations(nick_registrations.clone());
        }
    }
    drop(db_tx);
    let mut core_workers = tokio::task::JoinSet::new();
    let mut core_ready = Vec::with_capacity(shard_count.len());
    for (core, receiver) in cores.into_iter().zip(core_receivers) {
        let (ready, received) = tokio::sync::oneshot::channel();
        core_workers.spawn(core_worker(core, receiver, core_tx.clone(), ready));
        core_ready.push(received);
    }
    for ready in core_ready {
        ready
            .await
            .map_err(|_| io::Error::other("core worker stopped during startup"))?;
    }

    // Liveness reaper tick: drives the core's registration deadline and idle
    // PING/PONG timeout so a silent connection can't hold a session forever.
    {
        let core_tx = core_tx.clone();
        let reaper = tokio::spawn(async move {
            let now = mono_clock();
            let mut wheel = TimerWheel::new(
                now,
                NonZeroU64::new(TIMER_WHEEL_RESOLUTION_MILLIS)
                    .expect("timer resolution is nonzero"),
                std::num::NonZeroUsize::new(TIMER_WHEEL_SLOTS).expect("timer wheel has slots"),
            );
            wheel.schedule(now, ());
            let mut ticker = tokio::time::interval(std::time::Duration::from_millis(
                TIMER_WHEEL_RESOLUTION_MILLIS,
            ));
            loop {
                ticker.tick().await;
                let now = mono_clock();
                for () in wheel.advance(now) {
                    wheel.schedule(now.saturating_add_millis(REAP_TICK_MILLIS), ());
                    if core_tx.broadcast_tick(now).await.is_err() {
                        return;
                    }
                }
            }
        });
        listeners.push(supervise_listener(
            "connection reaper",
            reaper,
            critical_tx.clone(),
        ));
    }

    let mut addrs = Vec::new();
    for listener_config in &config.listeners {
        let listener = bind_listener(listener_config.addr)?;
        addrs.push(listener.local_addr()?);
        if listener_config.websocket {
            // A dedicated WS-IRC listener: serve the ws-irc router at the root
            // path (`ws://addr/`) against the shared core, instead of the raw
            // TCP accept loop. Same per-IP cap (it lives in the shared state).
            let state = app_state
                .clone()
                .expect("app_state is built whenever a websocket listener is set");
            let ws_task = tokio::spawn(serve_http(
                listener,
                crate::http::ws_irc_router(state.clone()),
                HttpAdmission::for_state(&state),
                telemetry.clone(),
            ));
            listeners.push(supervise_listener(
                "WebSocket IRC listener",
                ws_task,
                critical_tx.clone(),
            ));
            continue;
        }
        let acceptor = match &listener_config.tls {
            Some(tls) => Some(certificates.acceptor(tls)?),
            None => None,
        };
        let accept_task = tokio::spawn(accept_loop(
            listener,
            acceptor,
            core_tx.clone(),
            next_conn.clone(),
            config.sendq,
            limiter.clone(),
            telemetry.clone(),
        ));
        listeners.push(supervise_listener(
            "IRC listener",
            accept_task,
            critical_tx.clone(),
        ));
    }
    drop(critical_tx);
    Ok(Running {
        addrs,
        http_addr,
        bnc_addr,
        shutdown: ShutdownHandle {
            listeners,
            core_tx: Some(core_tx),
            core_workers,
            db_worker,
            critical_failures: critical_rx,
            bnc_listener,
            bnc_registry,
        },
    })
}

/// Bind a listening socket as `tokio::net::TcpListener::bind` does (address
/// reuse off Windows, backlog 1024), except that the IPv6 wildcard `[::]` is
/// dual-stack on every platform. Linux defaults a v6 socket to dual-stack,
/// Windows and several BSDs to v6-only, so the same configuration refused IPv4
/// clients on some hosts and not others.
fn bind_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    if let SocketAddr::V6(v6) = addr
        && v6.ip().is_unspecified()
    {
        socket.set_only_v6(false)?;
    }
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

/// Who may open an HTTP connection: at most [`MAX_HTTP_CONNECTIONS_PER_IP`]
/// from one address, except a trusted reverse proxy. One instance per
/// listener — an HTTP connection is not an IRC session, and must not spend the
/// IRC listeners' per-address budget.
struct HttpAdmission {
    connections: ConnLimiter,
    trusted_proxies: Vec<ipnet::IpNet>,
}

impl HttpAdmission {
    fn for_state(state: &crate::http::AppState) -> Self {
        Self {
            connections: ConnLimiter::new(Some(MAX_HTTP_CONNECTIONS_PER_IP)),
            trusted_proxies: state.trusted_proxies.clone(),
        }
    }
}

/// Serve HTTP/1.1 (with WebSocket upgrades) on `listener`.
///
/// Written out rather than `axum::serve`, which builds its connection builder
/// without a timer: hyper then silently drops its header-read timeout, and a
/// peer that sends half a header block — or holds a kept-alive connection idle
/// — keeps its socket and task forever. Here every connection has a timer and
/// [`HTTP_HEADER_READ_TIMEOUT`], its writes are bounded by
/// [`crate::peer_write::PEER_WRITE_DEADLINE`] (so a client that asks for a
/// large response and stops reading loses the connection instead of holding
/// it), and the per-address connection cap is applied at accept, before any
/// work is spent on the peer.
async fn serve_http(
    listener: TcpListener,
    router: axum::Router,
    admission: HttpAdmission,
    telemetry: Arc<Telemetry>,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                // Transient accept errors (EMFILE etc.) must not kill the
                // listener; retrying is the correct handling.
                telemetry.record_error(ErrorKind::Accept);
                eprintln!("http accept error: {error}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let client = ClientIp::new(peer.ip());
        let guard = if admission
            .trusted_proxies
            .iter()
            .any(|net| net.contains(&client.ip()))
        {
            None
        } else {
            match admission.connections.try_acquire(client) {
                Some(guard) => Some(guard),
                None => {
                    telemetry.record_connection_rejected();
                    admission
                        .connections
                        .refusals()
                        .note(client, PeerRefusal::PerIpLimit, None);
                    continue;
                }
            }
        };
        let refusals = admission.connections.refusals().clone();
        tokio::spawn(serve_http_connection(
            stream,
            peer,
            router.clone(),
            guard,
            refusals,
            telemetry.clone(),
            crate::peer_write::PEER_WRITE_DEADLINE,
        ));
    }
}

async fn serve_http_connection(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    router: axum::Router,
    _guard: Option<ConnGuard>,
    refusals: Arc<PeerRefusalLog>,
    telemetry: Arc<Telemetry>,
    write_deadline: std::time::Duration,
) {
    use tower::ServiceExt;
    let client = ClientIp::new(peer.ip());
    if let Err(error) = stream.set_nodelay(true) {
        telemetry.record_error(ErrorKind::ConnectionSetup);
        refusals.note(client, PeerRefusal::SocketSetup, Some(&error));
        return;
    }
    // Whether this connection has carried a request: hyper reports the same
    // header timeout for a peer that never finished its first request and for
    // a kept-alive connection that sat idle after one, and only the first is a
    // refusal. A reverse proxy holding idle upstream connections hit the second
    // every ten seconds and filled the log with "refused" lines.
    let served_a_request = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let served_flag = served_a_request.clone();
    // `ConnectInfo` so handlers see the socket peer (rate limiting, and the
    // forwarded-address resolution behind a trusted proxy).
    let service = router.map_request(move |mut request: axum::http::Request<_>| {
        served_flag.store(true, std::sync::atomic::Ordering::Relaxed);
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(peer));
        request
    });
    let served = hyper::server::conn::http1::Builder::new()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HTTP_HEADER_READ_TIMEOUT)
        .serve_connection(
            // Every write — a response body, an upgraded WebSocket's frames —
            // fails once the peer has taken nothing for `write_deadline`,
            // which ends the connection ([`crate::peer_write`]).
            hyper_util::rt::TokioIo::new(crate::peer_write::DeadlineWriter::new(
                stream,
                write_deadline,
            )),
            hyper_util::service::TowerToHyperService::new(service),
        )
        .with_upgrades()
        .await;
    match served {
        Ok(()) => {}
        // An idle kept-alive connection closed at the bound: ordinary.
        Err(error)
            if error.is_timeout()
                && served_a_request.load(std::sync::atomic::Ordering::Relaxed) => {}
        Err(error) if error.is_timeout() => {
            refusals.note(client, PeerRefusal::HttpHeaderTimedOut, None);
        }
        // A peer that resets or abandons its connection mid-request: counted,
        // not logged per occurrence.
        Err(_) => telemetry.record_error(ErrorKind::Http),
    }
}

async fn core_worker(
    core: Core,
    rx: Receiver<Input>,
    ingress: CoreIngress,
    ready: tokio::sync::oneshot::Sender<()>,
) {
    if ready.send(()).is_err() {
        return;
    }
    let exit = CoreWorker::new(core, rx, ingress).run().await;
    if exit != crate::core::CoreWorkerExit::Stopped {
        // Whoever supervises this task treats its end as the failure it is;
        // this says which.
        eprintln!("e6ircd: IRC core shard stopped without a shutdown request: {exit:?}");
    }
}

/// A client's address as every per-client decision keys it: a limiter slot, a
/// refusal summary, a rate bucket, a trusted-proxy match, a session's host
/// (what WHOIS shows and a DLINE or KLINE matches). A dual-stack (`[::]`)
/// listener presents every IPv4 client as IPv4-mapped IPv6
/// (`::ffff:a.b.c.d`); the constructor canonicalizes that to the IPv4 form, so
/// one address can never be split between two spellings — two limiter
/// budgets, a ban written in natural IPv4 notation that silently misses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ClientIp(std::net::IpAddr);

impl ClientIp {
    pub(crate) fn new(address: std::net::IpAddr) -> Self {
        Self(address.to_canonical())
    }

    pub(crate) fn ip(self) -> std::net::IpAddr {
        self.0
    }

    /// The slot every per-address limiter charges this client to; see
    /// [`PeerLimitKey`].
    pub(crate) fn limit_key(self) -> PeerLimitKey {
        PeerLimitKey::of(self.0)
    }
}

impl std::fmt::Display for ClientIp {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

/// What a per-address limit counts against: an IPv4 address, or the IPv6
/// `/64` an address belongs to. One subscriber is routinely handed a whole
/// `/64` (and SLAAC privacy addresses rotate through it), so a limiter keyed by
/// the full 128 bits gives each client 2^64 fresh budgets for the asking. Every
/// limiter — the per-address connection cap, the in-flight HTTP request bound,
/// the HTTP authentication bucket, and the core's account-creation bucket —
/// takes this type, and its only constructor applies the prefix, so no limiter
/// can be keyed by a raw address. The raw [`ClientIp`] stays what is logged,
/// shown, and matched by bans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PeerLimitKey(std::net::IpAddr);

impl PeerLimitKey {
    /// Leading IPv6 bits a limiter treats as one client.
    pub(crate) const IPV6_PREFIX_BITS: u32 = 64;

    fn of(address: std::net::IpAddr) -> Self {
        match address.to_canonical() {
            std::net::IpAddr::V4(v4) => Self(std::net::IpAddr::V4(v4)),
            std::net::IpAddr::V6(v6) => {
                let mask = u128::MAX << (128 - Self::IPV6_PREFIX_BITS);
                Self(std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                    u128::from(v6) & mask,
                )))
            }
        }
    }

    /// The key for a session opened with `host`: the host is the canonical
    /// address text the listeners pass the core ([`ClientIp`]'s spelling), or
    /// a name for an in-process session, which has no address and is counted
    /// under its name.
    pub(crate) fn for_session_host(host: &str) -> SessionLimitKey {
        match host.parse::<std::net::IpAddr>() {
            Ok(address) => SessionLimitKey::Address(Self::of(address)),
            Err(_) => SessionLimitKey::InProcess(host.to_string()),
        }
    }
}

/// Where a core session's per-address limits are charged, fixed when it opens:
/// a later `SETHOST` changes what the session shows, never what it is counted
/// against.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum SessionLimitKey {
    Address(PeerLimitKey),
    /// A session opened in-process (the bouncer's `local` driver) under a name
    /// rather than an address.
    InProcess(String),
}

/// Per-IP concurrent-connection cap. When `max_per_ip` is `None` the
/// limiter is a no-op; otherwise it refuses connections beyond the cap
/// and releases the slot when the connection's guard drops.
/// A refused or failed connection attempt from one peer, by class; each class
/// is summarised separately so a TLS scanner and an over-limit client from the
/// same address are two stories, not one count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PeerRefusal {
    PerIpLimit,
    ConnectionIdExhausted,
    SocketSetup,
    TlsHandshakeFailed,
    TlsHandshakeTimedOut,
    HttpHeaderTimedOut,
}

impl PeerRefusal {
    const fn label(self) -> &'static str {
        match self {
            Self::HttpHeaderTimedOut => "HTTP request headers not received in time",
            Self::PerIpLimit => "per-IP connection limit reached",
            Self::ConnectionIdExhausted => "no connection identifier available",
            Self::SocketSetup => "socket setup failed",
            Self::TlsHandshakeFailed => "TLS handshake failed",
            Self::TlsHandshakeTimedOut => "TLS handshake timed out",
        }
    }
}

/// After the first line for a (peer, class), further occurrences are counted
/// and reported once per window.
const PEER_REFUSAL_LOG_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
/// Distinct (peer, class) pairs remembered at once; past it the oldest quiet
/// entries are evicted, and an entry that cannot be remembered is logged
/// immediately rather than dropped.
const PEER_REFUSAL_LOG_CAPACITY: usize = 4_096;

/// Per-peer, per-class log summariser for connection refusals. The first
/// occurrence is logged at once; within the following window the rest are only
/// counted, and the next occurrence after the window logs again with the count
/// it stands for. A scanner or a stuck client therefore costs one line per
/// minute per class, never one per attempt, while the counters the metrics
/// export are unchanged (they are incremented by the caller, not here).
pub(crate) struct PeerRefusalLog {
    window: std::time::Duration,
    entries:
        std::sync::Mutex<std::collections::HashMap<(ClientIp, PeerRefusal), PeerRefusalWindow>>,
}

#[derive(Debug, Clone, Copy)]
struct PeerRefusalWindow {
    last_logged: std::time::Instant,
    /// Occurrences since `last_logged` that were not logged.
    suppressed: u64,
}

impl PeerRefusalLog {
    pub(crate) fn new(window: std::time::Duration) -> Self {
        Self {
            window,
            entries: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Log one occurrence now, if it is this window's line.
    pub(crate) fn note(
        &self,
        peer: ClientIp,
        refusal: PeerRefusal,
        detail: Option<&dyn std::fmt::Display>,
    ) {
        if let Some(line) = self.line_at(std::time::Instant::now(), peer, refusal, detail) {
            eprintln!("{line}");
        }
    }

    /// The line to log for one occurrence at `now`, or `None` when it is
    /// counted into the open window instead.
    pub(crate) fn line_at(
        &self,
        now: std::time::Instant,
        peer: ClientIp,
        refusal: PeerRefusal,
        detail: Option<&dyn std::fmt::Display>,
    ) -> Option<String> {
        let describe = |suppressed: u64| {
            let mut line = format!("refused {peer}: {}", refusal.label());
            if let Some(detail) = detail {
                line.push_str(&format!(": {detail}"));
            }
            if suppressed > 0 {
                line.push_str(&format!(
                    " ({suppressed} more from this peer in the last {}s not logged)",
                    self.window.as_secs()
                ));
            }
            line
        };
        let mut entries = self.entries.lock().expect("peer refusal log poisoned");
        if let Some(entry) = entries.get_mut(&(peer, refusal)) {
            if now.duration_since(entry.last_logged) < self.window {
                entry.suppressed += 1;
                return None;
            }
            let suppressed = entry.suppressed;
            *entry = PeerRefusalWindow {
                last_logged: now,
                suppressed: 0,
            };
            return Some(describe(suppressed));
        }
        if entries.len() >= PEER_REFUSAL_LOG_CAPACITY {
            let window = self.window;
            entries.retain(|_, entry| now.duration_since(entry.last_logged) < window);
        }
        if entries.len() < PEER_REFUSAL_LOG_CAPACITY {
            entries.insert(
                (peer, refusal),
                PeerRefusalWindow {
                    last_logged: now,
                    suppressed: 0,
                },
            );
        }
        Some(describe(0))
    }
}

#[derive(Clone)]
pub(crate) struct ConnLimiter {
    counts: Arc<std::sync::Mutex<std::collections::HashMap<PeerLimitKey, usize>>>,
    max_per_ip: Option<usize>,
    /// Per-peer admission failures are summarised here rather than logged one
    /// line per attempt; it travels with the limiter because every listener
    /// that admits peers (IRC, WS-IRC, BNC) already shares this one value.
    refusals: Arc<PeerRefusalLog>,
}

impl ConnLimiter {
    pub(crate) fn new(max_per_ip: Option<usize>) -> Self {
        Self {
            counts: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            max_per_ip,
            refusals: Arc::new(PeerRefusalLog::new(PEER_REFUSAL_LOG_WINDOW)),
        }
    }

    /// The shared per-peer refusal summariser.
    pub(crate) fn refusals(&self) -> &Arc<PeerRefusalLog> {
        &self.refusals
    }

    /// Reserve a slot for `client`'s [`PeerLimitKey`], or `None` if that key
    /// is already at the cap.
    pub(crate) fn try_acquire(&self, client: ClientIp) -> Option<ConnGuard> {
        let ip = client.limit_key();
        let Some(max) = self.max_per_ip else {
            return Some(ConnGuard { limiter: None, ip });
        };
        let mut counts = self.counts.lock().expect("conn limiter poisoned");
        let count = counts.entry(ip).or_insert(0);
        if *count >= max {
            return None;
        }
        *count += 1;
        Some(ConnGuard {
            limiter: Some(self.clone()),
            ip,
        })
    }

    fn release(&self, ip: PeerLimitKey) {
        let mut counts = self.counts.lock().expect("conn limiter poisoned");
        if let Some(c) = counts.get_mut(&ip) {
            *c -= 1;
            if *c == 0 {
                counts.remove(&ip);
            }
        }
    }
}

/// Releases its per-IP slot when the connection ends (on drop).
pub(crate) struct ConnGuard {
    limiter: Option<ConnLimiter>,
    ip: PeerLimitKey,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if let Some(limiter) = &self.limiter {
            limiter.release(self.ip);
        }
    }
}

async fn accept_loop(
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    core_tx: CoreIngress,
    next_conn: Arc<ConnectionIdAllocator>,
    sendq: usize,
    limiter: ConnLimiter,
    telemetry: Arc<Telemetry>,
) {
    let context = AcceptContext {
        tls: &tls,
        core_tx: &core_tx,
        next_conn: &next_conn,
        sendq,
        limiter: &limiter,
        telemetry: &telemetry,
    };
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                // Transient accept errors (EMFILE etc.) must not kill
                // the listener; retrying is the correct handling.
                eprintln!("accept error: {e}");
                telemetry.record_error(ErrorKind::Accept);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        spawn_accepted(stream, peer, &context);

        for _ in 1..ACCEPT_BATCH {
            let accepted = std::future::poll_fn(|context| match listener.poll_accept(context) {
                std::task::Poll::Ready(result) => std::task::Poll::Ready(Some(result)),
                std::task::Poll::Pending => std::task::Poll::Ready(None),
            })
            .await;
            match accepted {
                Some(Ok((stream, peer))) => spawn_accepted(stream, peer, &context),
                None => break,
                Some(Err(e)) => {
                    eprintln!("accept error: {e}");
                    telemetry.record_error(ErrorKind::Accept);
                    break;
                }
            }
        }
    }
}

struct AcceptContext<'a> {
    tls: &'a Option<TlsAcceptor>,
    core_tx: &'a CoreIngress,
    next_conn: &'a Arc<ConnectionIdAllocator>,
    sendq: usize,
    limiter: &'a ConnLimiter,
    telemetry: &'a Arc<Telemetry>,
}

fn spawn_accepted(stream: tokio::net::TcpStream, peer: SocketAddr, context: &AcceptContext<'_>) {
    let refusals = context.limiter.refusals().clone();
    let client = ClientIp::new(peer.ip());
    let Some(guard) = context.limiter.try_acquire(client) else {
        refusals.note(client, PeerRefusal::PerIpLimit, None);
        context.telemetry.record_connection_rejected();
        return;
    };
    let conn = match context.next_conn.allocate() {
        Ok(conn) => conn,
        Err(error) => {
            refusals.note(client, PeerRefusal::ConnectionIdExhausted, Some(&error));
            context.telemetry.record_error(ErrorKind::ConnectionSetup);
            return;
        }
    };
    let core_tx = context.core_tx.clone();
    let tls = context.tls.clone();
    let telemetry = context.telemetry.clone();
    let sendq = context.sendq;
    tokio::spawn(async move {
        let _guard = guard;
        if let Err(e) = stream.set_nodelay(true) {
            refusals.note(client, PeerRefusal::SocketSetup, Some(&e));
            telemetry.record_error(ErrorKind::ConnectionSetup);
            return;
        }
        match tls {
            Some(acceptor) => {
                let handshake = tokio::time::timeout(
                    std::time::Duration::from_secs(TLS_HANDSHAKE_TIMEOUT_SECS),
                    acceptor.accept(stream),
                )
                .await;
                match handshake {
                    Ok(Ok(tls_stream)) => {
                        serve_conn(
                            tls_stream,
                            conn,
                            peer,
                            crate::core::ConnectionTransport::Tls,
                            core_tx,
                            Outbound::with_sendq(sendq),
                            telemetry,
                        )
                        .await
                    }
                    Ok(Err(e)) => {
                        telemetry.record_error(ErrorKind::TlsHandshake);
                        refusals.note(client, PeerRefusal::TlsHandshakeFailed, Some(&e));
                    }
                    Err(_) => {
                        telemetry.record_error(ErrorKind::TlsHandshake);
                        refusals.note(client, PeerRefusal::TlsHandshakeTimedOut, None);
                    }
                }
            }
            None => {
                serve_conn(
                    stream,
                    conn,
                    peer,
                    crate::core::ConnectionTransport::Tcp,
                    core_tx,
                    Outbound::with_sendq(sendq),
                    telemetry,
                )
                .await
            }
        }
    });
}

/// The bounds on what a connection is sent: its SendQ capacity, and how long
/// one write may wait for a client that has stopped reading.
struct Outbound {
    sendq: usize,
    write_deadline: std::time::Duration,
}

impl Outbound {
    fn with_sendq(sendq: usize) -> Self {
        Self {
            sendq,
            write_deadline: crate::peer_write::PEER_WRITE_DEADLINE,
        }
    }
}

async fn serve_conn<S>(
    stream: S,
    conn: ConnId,
    peer: SocketAddr,
    transport: crate::core::ConnectionTransport,
    core_tx: CoreIngress,
    outbound: Outbound,
    telemetry: Arc<Telemetry>,
) where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (read_half, write_half) = tokio::io::split(stream);
    let (out_tx, out_rx) = queue::<Output>(e6irc_queue::Config {
        name: "sendq",
        capacity: outbound.sendq,
        policy: Policy::Fifo,
    });
    if core_tx
        .push(Input::Open {
            conn,
            tx: out_tx,
            // The canonical IPv4 spelling of a mapped peer (`ClientIp`): the
            // subject `ban_match` tests and WHOIS shows.
            host: ClientIp::new(peer.ip()).to_string(),
            transport,
        })
        .await
        .is_err()
    {
        return; // core gone: shutting down
    }
    let write_half = crate::peer_write::DeadlineWriter::new(write_half, outbound.write_deadline);
    let mut writer = tokio::spawn(write_loop(write_half, out_rx, telemetry.clone()));
    let reason = tokio::select! {
        // The client closed its sending side (or errored), or the core queue is
        // gone. `read_loop` has told the core, which answers what the client
        // sent before closing — a pipelined `NICK`/`USER`/`QUIT` from a
        // half-closing client is owed its welcome and its `ERROR` — and then
        // drops this session's sendq. The writer delivers all of that and
        // returns; it is aborted only if that takes longer than
        // `HALF_CLOSE_DRAIN`.
        () = read_loop(read_half, conn, &core_tx, &telemetry) => {
            if tokio::time::timeout(HALF_CLOSE_DRAIN, &mut writer).await.is_err() {
                writer.abort();
            }
            return;
        }
        // The writer returned. Two causes: the core dropped this session's
        // `Sender<Output>` (session already gone core-side), OR a write error
        // or stall on a still-present session. Cancelling the read future frees
        // the peer's read task and per-IP ConnGuard now, so the core must be
        // told here; `close` is idempotent, so the already-gone case is a
        // harmless no-op.
        reason = &mut writer => reason.unwrap_or("Write task panicked"),
    };
    // Queue closure means the core has already removed all connection state,
    // so there is no remaining observer for this close event.
    drop(
        core_tx
            .push(Input::Closed {
                conn,
                reason: reason.to_string(),
            })
            .await,
    );
}

/// How long a client that closed its sending side waits for the replies to
/// what it sent before its connection is torn down regardless.
const HALF_CLOSE_DRAIN: std::time::Duration = std::time::Duration::from_secs(5);

async fn read_loop<R>(mut read_half: R, conn: ConnId, core_tx: &CoreIngress, telemetry: &Telemetry)
where
    R: AsyncRead + Unpin,
{
    let mut framing = LineBuffer::new(LINE_LIMIT);
    let mut buf = [0u8; READ_BUF];
    let mut events = Vec::new();
    let reason = loop {
        match read_half.read(&mut buf).await {
            Ok(0) => break "Connection closed".to_string(),
            Ok(n) => {
                framing.feed(&buf[..n], &mut events);
                if !crate::core::push_framed(core_tx, conn, &mut events).await {
                    return; // core gone
                }
            }
            Err(e) => {
                telemetry.record_error(ErrorKind::Read);
                break format!("Read error: {e}");
            }
        }
    };
    // Queue closure means the core has already removed all connection state.
    drop(core_tx.push(Input::Closed { conn, reason }).await);
}

/// Drain the sendq to the socket. Returns the reason it stopped, which the
/// caller turns into the session's `Input::Closed` — distinguishing a core-side
/// close (sender dropped) from a write error (peer gone) so neither is conflated
/// nor silently skipped.
async fn write_loop<W>(
    mut write_half: W,
    mut rx: Receiver<Output>,
    telemetry: Arc<Telemetry>,
) -> &'static str
where
    W: AsyncWrite + Unpin,
{
    let mut batch = Vec::new();
    loop {
        let Some(envelope) = rx.pop().await else {
            // Core dropped the session (sender gone): flush and close.
            drop(write_half.shutdown().await);
            return "Connection closed";
        };
        // Drain everything currently queued and present the shared Bytes as
        // vectored slices. Fan-out already serialized each capability variant
        // once; concatenating here copied every recipient's wire bytes again.
        batch.clear();
        batch.push(envelope.payload.0);
        while let Some(e) = rx.try_pop() {
            batch.push(e.payload.0);
        }
        let written = match write_all_vectored(&mut write_half, &batch).await {
            Ok(()) => write_half.flush().await,
            Err(error) => Err(error),
        };
        if let Err(error) = written {
            telemetry.record_error(ErrorKind::Write);
            // The session is still live core-side: a broken pipe / RST, or a
            // peer that stopped reading while output was queued for it.
            return if crate::peer_write::is_stalled(&error) {
                "Write timeout"
            } else {
                "Write error"
            };
        }
    }
}

/// Write every byte from `chunks`, correctly advancing across partial vectored
/// writes. At most 64 slices are offered per call, staying below every
/// supported platform's scatter/gather limit while still amortizing a full
/// SendQ drain. Writers without native vectored support consume the first slice
/// through their default implementation and remain correct.
async fn write_all_vectored<W>(writer: &mut W, chunks: &[bytes::Bytes]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    const MAX_SLICES: usize = 64;
    let mut index = 0usize;
    let mut offset = 0usize;
    while index < chunks.len() {
        if offset == chunks[index].len() {
            index += 1;
            offset = 0;
            continue;
        }
        let slices: Vec<std::io::IoSlice<'_>> =
            std::iter::once(std::io::IoSlice::new(&chunks[index][offset..]))
                .chain(
                    chunks[index + 1..]
                        .iter()
                        .take(MAX_SLICES - 1)
                        .map(|chunk| std::io::IoSlice::new(chunk)),
                )
                .collect();
        let written = writer.write_vectored(&slices).await?;
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to write queued IRC output",
            ));
        }
        let mut remaining = written;
        while index < chunks.len() {
            let available = chunks[index].len() - offset;
            if remaining < available {
                offset += remaining;
                break;
            }
            remaining -= available;
            index += 1;
            offset = 0;
            if remaining == 0 {
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::ReloadingCertificate;
    use crate::config::TlsConfig;
    use crate::core::Input;
    use e6irc_queue::Sender;
    use std::pin::Pin;

    /// One subscriber's IPv6 `/64` is one client to every per-address limit;
    /// IPv4 addresses, and an IPv4 client however the listener spells it, are
    /// counted one address each.
    #[test]
    fn per_address_limits_count_an_ipv6_slash_64_as_one_client() {
        let client = |text: &str| ClientIp::new(text.parse().unwrap());
        let limiter = ConnLimiter::new(Some(1));
        let _held = limiter
            .try_acquire(client("2001:db8:1:2::1"))
            .expect("the first connection");
        assert!(
            limiter
                .try_acquire(client("2001:db8:1:2:ffff::2"))
                .is_none(),
            "another address in the same /64 shares the budget"
        );
        let _other = limiter
            .try_acquire(client("2001:db8:1:3::1"))
            .expect("the next /64 is another client");
        let _v4 = limiter
            .try_acquire(client("192.0.2.1"))
            .expect("an IPv4 client");
        assert!(limiter.try_acquire(client("::ffff:192.0.2.1")).is_none());
        let _neighbour = limiter
            .try_acquire(client("192.0.2.2"))
            .expect("each IPv4 address is its own client");
        assert_eq!(
            client("2001:db8:1:2:aaaa:bbbb:cccc:dddd").limit_key(),
            client("2001:db8:1:2::").limit_key()
        );
        assert_eq!(
            PeerLimitKey::for_session_host("2001:db8:1:2::9"),
            SessionLimitKey::Address(client("2001:db8:1:2::1").limit_key())
        );
        assert_eq!(
            PeerLimitKey::for_session_host("local"),
            SessionLimitKey::InProcess("local".to_string())
        );
    }

    #[test]
    fn peer_refusals_log_once_per_window_with_the_suppressed_count() {
        use std::time::{Duration, Instant};
        let log = PeerRefusalLog::new(Duration::from_secs(60));
        let peer = ClientIp::new("203.0.113.9".parse().unwrap());
        let other = ClientIp::new("203.0.113.10".parse().unwrap());
        let start = Instant::now();
        let first = log
            .line_at(start, peer, PeerRefusal::PerIpLimit, None)
            .expect("the first occurrence is logged at once");
        assert_eq!(
            first,
            "refused 203.0.113.9: per-IP connection limit reached"
        );
        for i in 1..=500u64 {
            assert!(
                log.line_at(
                    start + Duration::from_millis(i),
                    peer,
                    PeerRefusal::PerIpLimit,
                    None,
                )
                .is_none(),
                "occurrence {i} inside the window must only be counted"
            );
        }
        // Another class from the same peer, and the same class from another
        // peer, are their own windows.
        let error = std::io::Error::other("bad record mac");
        assert_eq!(
            log.line_at(start, peer, PeerRefusal::TlsHandshakeFailed, Some(&error))
                .as_deref(),
            Some("refused 203.0.113.9: TLS handshake failed: bad record mac")
        );
        assert!(
            log.line_at(start, other, PeerRefusal::PerIpLimit, None)
                .is_some()
        );
        let later = log
            .line_at(
                start + Duration::from_secs(60),
                peer,
                PeerRefusal::PerIpLimit,
                None,
            )
            .expect("the window has passed");
        assert_eq!(
            later,
            "refused 203.0.113.9: per-IP connection limit reached (500 more from this peer in \
             the last 60s not logged)"
        );
        assert!(
            log.line_at(
                start + Duration::from_secs(61),
                peer,
                PeerRefusal::PerIpLimit,
                None,
            )
            .is_none(),
            "a new window opened at the second line"
        );
    }

    #[test]
    fn peer_refusal_log_is_bounded_and_never_drops_a_first_line() {
        use std::time::{Duration, Instant};
        let log = PeerRefusalLog::new(Duration::from_secs(60));
        let start = Instant::now();
        for i in 0..PEER_REFUSAL_LOG_CAPACITY as u32 {
            let peer = ClientIp::new(std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                0x0A00_0000 + i,
            )));
            assert!(
                log.line_at(start, peer, PeerRefusal::PerIpLimit, None)
                    .is_some()
            );
        }
        // Full, and every entry's window is still open: the newcomer is logged
        // (not remembered), and logged again on its next attempt.
        let newcomer = ClientIp::new("198.51.100.1".parse().unwrap());
        assert!(
            log.line_at(start, newcomer, PeerRefusal::PerIpLimit, None)
                .is_some()
        );
        assert!(
            log.line_at(start, newcomer, PeerRefusal::PerIpLimit, None)
                .is_some(),
            "an entry the bound could not remember must not be silently dropped"
        );
        assert!(log.entries.lock().unwrap().len() <= PEER_REFUSAL_LOG_CAPACITY);
        // Once the windows have passed, the quiet entries are evicted for it.
        assert!(
            log.line_at(
                start + Duration::from_secs(61),
                newcomer,
                PeerRefusal::PerIpLimit,
                None,
            )
            .is_some()
        );
        assert!(
            log.entries
                .lock()
                .unwrap()
                .contains_key(&(newcomer, PeerRefusal::PerIpLimit))
        );
    }
    use std::task::{Context, Poll};

    #[derive(Default)]
    struct PartialVectoredSink {
        bytes: Vec<u8>,
        maximum_per_write: usize,
        vectored_calls: usize,
    }

    impl AsyncWrite for PartialVectoredSink {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            let amount = buffer.len().min(self.maximum_per_write);
            self.bytes.extend_from_slice(&buffer[..amount]);
            Poll::Ready(Ok(amount))
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffers: &[std::io::IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            self.vectored_calls += 1;
            let mut remaining = self.maximum_per_write;
            let mut written = 0usize;
            for buffer in buffers {
                let amount = buffer.len().min(remaining);
                self.bytes.extend_from_slice(&buffer[..amount]);
                written += amount;
                remaining -= amount;
                if remaining == 0 {
                    break;
                }
            }
            Poll::Ready(Ok(written))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A self-signed certificate for `localhost` written to `dir`, and its DER
    /// form for a client to trust.
    fn write_certificate(
        dir: &std::path::Path,
    ) -> (TlsConfig, rustls_pki_types::CertificateDer<'static>) {
        let files = TlsConfig {
            cert_path: dir.join("cert.pem"),
            key_path: dir.join("key.pem"),
        };
        let trusted = crate::certificate::write_self_signed(&files);
        (files, trusted)
    }

    /// The certificate a TLS client is shown by `acceptor`.
    async fn presented_certificate(
        acceptor: &TlsAcceptor,
        trusted: &rustls_pki_types::CertificateDer<'static>,
    ) -> Result<rustls_pki_types::CertificateDer<'static>, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("address");
        let acceptor = acceptor.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            drop(acceptor.accept(stream).await);
        });
        let mut roots = rustls::RootCertStore::empty();
        roots.add(trusted.clone()).expect("root");
        let connector = tokio_rustls::TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let tls = connector
            .connect("localhost".try_into().expect("name"), stream)
            .await?;
        let presented = tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first())
            .expect("a certificate")
            .clone()
            .into_owned();
        drop(tls);
        drop(server.await);
        Ok(presented)
    }

    /// A renewed certificate is served without a restart: after the files are
    /// rewritten and a reload runs, the next handshake presents the new one.
    /// A file that does not parse keeps the certificate being served.
    #[tokio::test]
    async fn a_reloaded_certificate_is_presented_to_the_next_handshake() {
        install_crypto_provider();
        let dir = std::env::temp_dir().join(format!(
            "e6irc-certificate-reload-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).expect("directory");
        let (files, first) = write_certificate(&dir);
        let certificate = Arc::new(ReloadingCertificate::load(&files).expect("load"));
        let acceptor = TlsAcceptor::from(Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(certificate.clone()),
        ));
        assert_eq!(
            presented_certificate(&acceptor, &first)
                .await
                .expect("handshake"),
            first
        );

        let (_, second) = write_certificate(&dir);
        assert_ne!(first, second);
        certificate.reload().expect("the renewed files parse");
        assert_eq!(
            presented_certificate(&acceptor, &second)
                .await
                .expect("handshake with the renewed certificate"),
            second
        );

        std::fs::write(&files.cert_path, "not a certificate").expect("corrupt the file");
        assert!(certificate.reload().is_err(), "a broken file is refused");
        assert_eq!(
            presented_certificate(&acceptor, &second)
                .await
                .expect("the last good certificate is still served"),
            second
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A client that asks for a large response and never reads it held its
    /// connection (and a slot of its address's connection cap) for as long as
    /// it liked: nothing bounded a stalled body write. The connection now ends
    /// once the client has taken nothing for the write deadline.
    #[tokio::test]
    async fn an_http_client_that_stops_reading_a_large_response_loses_the_connection() {
        use std::time::Duration;
        use tokio::io::AsyncWriteExt;
        const BODY: usize = 32 * 1024 * 1024;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let client = tokio::net::TcpSocket::new_v4().expect("socket");
        client.set_recv_buffer_size(4096).expect("receive buffer");
        let mut client = client.connect(address).await.expect("connect");
        let (stream, peer) = listener.accept().await.expect("accept");
        socket2::SockRef::from(&stream)
            .set_send_buffer_size(4096)
            .expect("send buffer");
        let router =
            axum::Router::new().route("/large", axum::routing::get(|| async { vec![b'x'; BODY] }));
        let telemetry = Arc::new(Telemetry::new());
        let served = tokio::spawn(serve_http_connection(
            stream,
            peer,
            router,
            None,
            Arc::new(PeerRefusalLog::new(Duration::from_secs(60))),
            telemetry,
            Duration::from_millis(200),
        ));
        client
            .write_all(b"GET /large HTTP/1.1\r\nhost: test\r\n\r\n")
            .await
            .expect("request");
        // The client never reads; the server's write stalls within the first
        // few hundred kilobytes and must give up.
        tokio::time::timeout(Duration::from_secs(20), served)
            .await
            .expect("a stalled response write ends the connection")
            .expect("the connection task");
        drop(client);
    }

    #[tokio::test]
    async fn vectored_writer_advances_across_partial_chunk_boundaries() {
        let mut writer = PartialVectoredSink {
            maximum_per_write: 5,
            ..PartialVectoredSink::default()
        };
        write_all_vectored(
            &mut writer,
            &[
                bytes::Bytes::from_static(b"abc"),
                bytes::Bytes::from_static(b"defg"),
                bytes::Bytes::from_static(b"h"),
            ],
        )
        .await
        .expect("vectored write");
        assert_eq!(writer.bytes, b"abcdefgh");
        assert_eq!(
            writer.vectored_calls, 2,
            "partial progress should resume at the exact byte, not rewrite a chunk"
        );
    }

    #[tokio::test]
    async fn critical_task_outcomes_preserve_exit_and_panic_provenance() {
        let exited = tokio::spawn(async {}).await;
        let failure = critical_join_failure("test worker", exited);
        assert_eq!(failure.task, "test worker");
        assert_eq!(failure.reason, "exited unexpectedly");

        let panicked = tokio::spawn(async {
            panic!("intentional supervised-task test panic");
        })
        .await;
        let failure = critical_join_failure("test worker", panicked);
        assert_eq!(failure.task, "test worker");
        assert!(failure.reason.starts_with("panicked:"));
    }

    /// A stream whose read never completes (a partitioned/dead peer) and whose
    /// writes are silently accepted — so the connection can only end if the
    /// core closes it, not by the peer.
    struct DeadPeer;

    impl AsyncRead for DeadPeer {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending // never yields — the peer is silent
        }
    }
    impl AsyncWrite for DeadPeer {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct FlushFails;

    impl AsyncWrite for FlushFails {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "flush failed",
            )))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A small bounded `Input` channel for the `serve_conn` wiring tests.
    fn test_core_channel() -> (Sender<Input>, Receiver<Input>) {
        queue::<Input>(e6irc_queue::Config {
            name: "t-core",
            capacity: 8,
            policy: Policy::Fifo,
        })
    }

    /// Spawn `serve_conn` against a `DeadPeer` with the standard test wiring —
    /// the channel, connection id, transport, backlog, and telemetry every
    /// wiring test shares.
    fn spawn_dead_peer(peer: &str) -> (Receiver<Input>, tokio::task::JoinHandle<()>) {
        let (core_tx, core_rx) = test_core_channel();
        let peer: SocketAddr = peer.parse().unwrap();
        let served = tokio::spawn(serve_conn(
            DeadPeer,
            ConnId(1),
            peer,
            crate::core::ConnectionTransport::Tcp,
            CoreIngress::single(core_tx),
            Outbound::with_sendq(8),
            Arc::new(Telemetry::new()),
        ));
        (core_rx, served)
    }

    /// A client whose receive window is shut — it never reads — and whose
    /// session the core has already ended (SendQ, KILL, KLINE) is torn down at
    /// the write deadline. The writer used to park in the socket write forever,
    /// never seeing its sendq close, and the socket, the task and the per-IP
    /// slot leaked with it.
    #[tokio::test]
    async fn a_client_that_never_reads_is_torn_down_after_the_core_drops_it() {
        // Fixed small buffers (an explicit size also stops the kernel growing
        // them), inherited by the accepted socket.
        let listening = tokio::net::TcpSocket::new_v4().expect("socket");
        listening
            .set_send_buffer_size(1024)
            .expect("small send buffer");
        listening
            .bind("127.0.0.1:0".parse().unwrap())
            .expect("bind");
        let listener = listening.listen(1).expect("listen");
        let socket = tokio::net::TcpSocket::new_v4().expect("socket");
        socket.set_recv_buffer_size(1024).expect("small window");
        let client = socket
            .connect(listener.local_addr().expect("address"))
            .await
            .expect("connect");
        let (server, peer) = listener.accept().await.expect("accept");
        let (core_tx, mut core_rx) = test_core_channel();
        let served = tokio::spawn(serve_conn(
            server,
            ConnId(1),
            peer,
            crate::core::ConnectionTransport::Tcp,
            CoreIngress::single(core_tx),
            Outbound {
                sendq: 4096,
                write_deadline: std::time::Duration::from_millis(300),
            },
            Arc::new(Telemetry::new()),
        ));
        let Input::Open { tx, .. } = core_rx.pop().await.expect("Open event").payload else {
            panic!("expected Open");
        };
        // Far more than both kernel buffers hold: the writer parks mid-write.
        let line = bytes::Bytes::from(format!("NOTICE * :{}\r\n", "x".repeat(400)));
        for _ in 0..4096 {
            if tx.try_push(Output(line.clone())).is_err() {
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // The core ends the session: its sender goes.
        drop(tx);
        tokio::time::timeout(std::time::Duration::from_secs(5), served)
            .await
            .expect("a connection the core dropped must not outlive the write deadline")
            .expect("serve_conn task");
        let Input::Closed { reason, .. } = core_rx.pop().await.expect("Closed event").payload
        else {
            panic!("expected Closed");
        };
        assert_eq!(reason, "Write timeout");
        drop(client);
    }

    #[tokio::test]
    async fn flush_failure_is_a_connection_write_error() {
        let (tx, rx) = queue(e6irc_queue::Config {
            name: "t-sendq",
            capacity: 1,
            policy: Policy::Fifo,
        });
        tx.push(Output(bytes::Bytes::from_static(b"NOTICE * :hello\r\n")))
            .await
            .expect("test output");

        assert_eq!(
            write_loop(FlushFails, rx, Arc::new(Telemetry::new())).await,
            "Write error"
        );
    }

    #[tokio::test]
    async fn core_close_cancels_a_parked_read() {
        let (mut core_rx, served) = spawn_dead_peer("127.0.0.1:5000");

        // The connection registered its sendq via Open; take that sender.
        let env = core_rx.pop().await.expect("Open event");
        let Input::Open { tx, .. } = env.payload else {
            panic!("expected Open");
        };
        // Simulate the core closing the session: dropping the last Sender closes
        // the sendq, so write_loop returns — and serve_conn must then cancel the
        // parked read and finish, rather than hang until an OS TCP timeout.
        drop(tx);
        tokio::time::timeout(std::time::Duration::from_secs(2), served)
            .await
            .expect("serve_conn must return promptly after the core closes the session")
            .expect("serve_conn task panicked");
    }

    #[tokio::test]
    async fn mapped_ipv4_peer_is_canonicalized_in_the_open_host() {
        // A dual-stack (`[::]`) listener presents an IPv4 client as its
        // IPv4-mapped IPv6 form (`::ffff:a.b.c.d`). The session host that
        // `Input::Open` carries — the string `ban_match` tests DLINE/KLINE
        // against and WHOIS shows — must be the canonical IPv4, or an operator's
        // `DLINE 203.0.113.7` in natural notation would silently not match.
        let (mut core_rx, served) = spawn_dead_peer("[::ffff:203.0.113.7]:5000");
        let env = core_rx.pop().await.expect("Open event");
        let Input::Open { host, tx, .. } = env.payload else {
            panic!("expected Open");
        };
        assert_eq!(
            host, "203.0.113.7",
            "a mapped IPv4 peer must be canonicalized to its IPv4 host"
        );
        drop(tx);
        tokio::time::timeout(std::time::Duration::from_secs(2), served)
            .await
            .expect("serve_conn must return after its sendq closes")
            .expect("serve_conn task");
    }

    /// Minimal core config for the shutdown wiring test — no PostgreSQL needed.
    fn test_core_config() -> CoreConfig {
        CoreConfig {
            server_name: "irc.test".into(),
            network_name: "TestNet".into(),
            description: "test".into(),
            registration_before_connect: false,
            registration_require_email: false,
            sendq: 64,
            motd: vec!["hi".into()],
            nicklen: 30,
            sasl_enabled: false,
            max_hot_channels: 64,
            opers: Vec::new(),
            clock: wall_clock,
            mono_clock,
            command_flood: None,
            registration_burst: None,
            reserved_account_names: crate::identity::ReservedAccountNames::default(),
        }
    }

    fn shutdown_handle(
        core_workers: tokio::task::JoinSet<()>,
        flushed: Arc<std::sync::atomic::AtomicBool>,
    ) -> ShutdownHandle {
        let (core_tx, _core_rx) = queue::<Input>(e6irc_queue::Config {
            name: "t-shutdown-core",
            capacity: 4,
            policy: Policy::Fifo,
        });
        let (_failures_tx, critical_failures) = tokio::sync::mpsc::unbounded_channel();
        ShutdownHandle {
            listeners: Vec::new(),
            core_tx: Some(CoreIngress::single(core_tx)),
            core_workers,
            // Stands in for the database worker's final flush.
            db_worker: Some(tokio::spawn(async move {
                // Longer than any wait below: only a caller that awaits the
                // flush sees it happen.
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                flushed.store(true, std::sync::atomic::Ordering::SeqCst);
            })),
            critical_failures,
            bnc_listener: None,
            bnc_registry: None,
        }
    }

    /// A process restart used to leave every upstream with a ghost of the old
    /// session: nothing stopped the drivers, so no `QUIT` was sent, and the
    /// restarted daemon met the ghost as a 433. Shutdown stops the drivers,
    /// and each says goodbye before its socket closes -- before `run` returns,
    /// because the process exits right after. The registry is held by the HTTP
    /// state and the attach listener in production, so a stop that relied on
    /// the last `Arc` dropping would not happen; the test holds a clone for the
    /// same reason.
    #[tokio::test(flavor = "multi_thread")]
    async fn shutdown_stops_the_bouncer_drivers_with_a_goodbye() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        let (heard_tx, mut heard_rx) = tokio::sync::mpsc::channel::<Option<String>>(16);
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = socket.into_split();
            let mut lines = tokio::io::BufReader::new(reader).lines();
            while let Some(line) = lines.next_line().await.unwrap() {
                if line.starts_with("CAP LS") {
                    writer.write_all(b":up CAP * LS :\r\n").await.unwrap();
                } else if line.starts_with("USER ") {
                    writer
                        .write_all(b":up 001 bncbot :welcome\r\n")
                        .await
                        .unwrap();
                    heard_tx.send(Some("registered".into())).await.unwrap();
                } else if line.starts_with("QUIT") {
                    heard_tx.send(Some(line)).await.unwrap();
                }
            }
            heard_tx.send(None).await.unwrap();
        });
        let (core_tx, _core_rx) = queue::<Input>(e6irc_queue::Config {
            name: "t-shutdown-bnc-core",
            capacity: 4,
            policy: Policy::Fifo,
        });
        let registry = Arc::new(
            crate::bouncer::Registry::start_observed(
                &[crate::config::NetworkEntry {
                    kind: crate::config::NetworkKind::Irc,
                    name: "up".into(),
                    owner: None,
                    addr: upstream_addr.to_string(),
                    tls: false,
                    nick: "bncbot".into(),
                    username: Some("bncbot".into()),
                    realname: Some("bnc".into()),
                    autojoin: vec![],
                    buffer_cap: 16,
                    sasl_account: None,
                    sasl_password: None,
                    server_password: None,
                }],
                None,
                crate::bouncer::CoreHandles {
                    core_tx: CoreIngress::single(core_tx),
                    next_conn: Arc::new(ConnectionIdAllocator::new(
                        std::num::NonZeroU64::new(1).unwrap(),
                    )),
                    sendq: 64,
                },
                Arc::new(Telemetry::new()),
                crate::egress::InternalUpstreams::Allow,
            )
            .expect("registry"),
        );
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(10), heard_rx.recv())
                .await
                .expect("the driver never registered"),
            Some(Some("registered".into()))
        );
        let flushed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut handle = shutdown_handle(tokio::task::JoinSet::new(), flushed);
        handle.bnc_registry = Some(registry.clone());
        assert_eq!(handle.run().await, ShutdownOutcome::Flushed);
        // What the upstream had read by the time `run` returned.
        let mut heard = Vec::new();
        while let Ok(line) = heard_rx.try_recv() {
            heard.push(line);
        }
        assert_eq!(
            heard,
            vec![Some("QUIT :e6irc bouncer stopping".to_string()), None],
            "the upstream reads the goodbye, then end of stream, before shutdown completes"
        );
        drop(registry);
    }

    /// A shard that panicked has lost its own state; what the database worker
    /// has buffered is still good, and leaving without flushing it turns one
    /// shard's failure into lost history for every channel.
    #[tokio::test]
    async fn a_core_panic_is_reported_after_the_database_flush_not_instead_of_it() {
        let flushed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut core_workers = tokio::task::JoinSet::new();
        core_workers.spawn(async { panic!("shard failure under test") });
        core_workers.spawn(async {});
        let outcome = shutdown_handle(core_workers, flushed.clone()).run().await;
        assert_eq!(outcome, ShutdownOutcome::CorePanicked);
        assert!(flushed.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// A shard that will not stop holds the database queue open. It is ended,
    /// so the flush can still happen, and the timeout is what gets reported.
    #[tokio::test]
    async fn a_core_shard_that_will_not_stop_is_ended_so_the_database_can_flush() {
        let flushed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut core_workers = tokio::task::JoinSet::new();
        core_workers.spawn(std::future::pending());
        let outcome = shutdown_handle(core_workers, flushed.clone())
            .run_within(
                std::time::Duration::from_millis(100),
                SHUTDOWN_DRIVER_STOP_TIMEOUT,
            )
            .await;
        assert_eq!(outcome, ShutdownOutcome::CoreTimedOut);
        assert!(flushed.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// The graceful-shutdown chain that guarantees no buffered history is lost:
    /// an `Input::Shutdown` must (1) end the core worker so the `Core` is
    /// dropped, which (2) drops the sole `Sender<DbRequest>` and closes the DB
    /// worker's queue (its cue to drain and flush), and (3) delivers a terminal
    /// `ERROR` to every connected client on the way out.
    #[tokio::test]
    async fn shutdown_stops_core_notifies_clients_and_closes_db_queue() {
        let (core_tx, core_rx) = queue::<Input>(e6irc_queue::Config {
            name: "t-core",
            capacity: 16,
            policy: Policy::Fifo,
        });
        let (db_tx, mut db_rx) = queue::<crate::core::DbRequest>(e6irc_queue::Config {
            name: "t-db",
            capacity: 16,
            policy: Policy::Fifo,
        });
        let core = Core::new(test_core_config(), db_tx);
        let (ready, received) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(core_worker(
            core,
            core_rx,
            CoreIngress::single(core_tx.clone()),
            ready,
        ));
        received.await.expect("core worker ready");

        // Register one client so there is a session to notify. Its send queue's
        // receiver is held here to observe the ERROR.
        let (out_tx, mut out_rx) = queue::<Output>(e6irc_queue::Config {
            name: "t-sendq",
            capacity: 64,
            policy: Policy::Fifo,
        });
        core_tx
            .push(Input::Open {
                conn: ConnId(1),
                tx: out_tx,
                host: "host.test".into(),
                transport: crate::core::ConnectionTransport::Tcp,
            })
            .await
            .expect("open");
        core_tx
            .push(Input::Line {
                conn: ConnId(1),
                line: b"NICK alice".to_vec(),
            })
            .await
            .expect("nick");
        core_tx
            .push(Input::Line {
                conn: ConnId(1),
                line: b"USER alice 0 * :Alice".to_vec(),
            })
            .await
            .expect("user");

        core_tx.push(Input::Shutdown).await.expect("shutdown");

        // The worker must return promptly (dropping the Core, hence db_tx).
        tokio::time::timeout(std::time::Duration::from_secs(2), worker)
            .await
            .expect("core worker exits on Shutdown")
            .expect("core worker task");

        // db_tx dropped with the Core → the DB worker's queue is now closed,
        // which is precisely the "receiver closed → drain → flush" trigger.
        assert!(
            db_rx.pop().await.is_none(),
            "dropping the core must close the DB queue so the worker can flush"
        );

        // The client received a terminal ERROR line.
        let mut saw_error = false;
        while let Some(env) = out_rx.try_pop() {
            let line = String::from_utf8_lossy(&env.payload.0);
            if line.starts_with("ERROR :Closing Link:") {
                saw_error = true;
            }
        }
        assert!(
            saw_error,
            "every client must be notified with an ERROR on shutdown"
        );
    }
}
