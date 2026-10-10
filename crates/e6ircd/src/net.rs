//! The process: its listeners, the core shards, the database and the
//! bouncer, started, served and shut down together. What touches a client
//! connection — accept, TLS, framing, the reader and writer — is the edge's
//! (`e6irc_edge`), served here with the core behind its `CorePort`.

#![deny(clippy::let_underscore_must_use)]

use std::io;
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::config::{BncConfig, Config};
use crate::core::{
    ConnectionIdAllocator, Core, CoreConfig, CoreIngress, CoreShardId, CoreWorker, Input,
    TimerWheel,
};
use crate::observability::{ErrorKind, Telemetry};
use crate::serving_lease::{self, AcquireRefusal, HolderId, ServingLease};
use e6irc_edge::address::ConnLimiter;
use e6irc_edge::certificate::{CertificateReloads, Hangups, install_crypto_provider};
use e6irc_edge::connection::{
    AcceptContext, CLOSING_DRAIN, ConnectionTasks, accept_loop, bind_listener,
};
use e6irc_edge::http::{HttpAdmission, serve_http};
pub(crate) use e6irc_edge::http::{HttpStreamReclaim, UpgradedStream};
use e6irc_queue::{Policy, Receiver, queue};

/// How often the liveness reaper tick fires (seconds); the reaper's own
/// deadlines are coarse minutes, so a fine tick isn't needed.
const REAP_TICK_MILLIS: u64 = 15_000;
const TIMER_WHEEL_RESOLUTION_MILLIS: u64 = 1_000;
const TIMER_WHEEL_SLOTS: usize = 64;

/// This process's own connection identifiers, from a random start. In edge
/// mode the edges allocate theirs within the slots the core gives them
/// (DESIGN §19.2), so the core's own sessions (the `local` driver's) count
/// within slot 0, which no edge is ever given: the two cannot collide.
fn connection_ids(edge_mode: bool) -> io::Result<ConnectionIdAllocator> {
    use aws_lc_rs::rand::SecureRandom;

    let mut bytes = [0u8; 8];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| io::Error::other("system RNG failed while seeding connection identifiers"))?;
    let random = u64::from_le_bytes(bytes);
    if edge_mode {
        // Slot 0 ends where slot 1 begins; the start is in its lower half, so
        // the upper half is left to count through.
        let end = e6irc_link::Slot::new(1).expect("slot 1").first_id();
        let first = NonZeroU64::new((random & (end / 2 - 1)) | 1).expect("an odd start");
        let ids = ConnectionIdAllocator::new(first);
        ids.restart_at((first, end));
        return Ok(ids);
    }
    // Keep the top two bits clear: cursor input is parsed as signed SQL-style
    // int64 at the HTTP boundary, while the remaining 62 random/counter bits
    // still leave more connection identifiers than one process can consume.
    let value = (random & (u64::MAX >> 2)) | 1;
    let first = NonZeroU64::new(value)
        .ok_or_else(|| io::Error::other("connection identifier seed was unexpectedly zero"))?;
    Ok(ConnectionIdAllocator::new(first))
}

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
/// How long the last shutdown step waits to give the serving lease back. A
/// release that does not finish leaves the lease to expire, which delays a
/// standby's takeover by at most the lease's TTL.
const SHUTDOWN_LEASE_RELEASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How long graceful shutdown waits, once it has aborted every listener task,
/// for the tasks to end and so close their sockets: a core started in this
/// process on the same address once shutdown returns finds it free. Ending
/// an aborted task takes the runtime microseconds.
const SHUTDOWN_LISTENER_CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

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
/// refusal schedule). `tools/check-systemd-unit.sh` sums it with the core,
/// connection and database budgets for the unit's stop timeout.
const SHUTDOWN_DRIVER_STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// How long graceful shutdown waits, once the core has stopped, for the client
/// connections to deliver their closing `ERROR` and close: each has
/// [`CLOSING_DRAIN`] to write what it is still owed, then a lingering close
/// ([`e6irc_edge::lingering_close::LINGER_CLOSE_BOUND`]), all of them at once.
/// `tools/check-systemd-unit.sh` sums it into the unit's stop budget.
const SHUTDOWN_CONNECTION_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);
const _: () = assert!(
    SHUTDOWN_CONNECTION_DRAIN_TIMEOUT.as_secs()
        >= CLOSING_DRAIN.as_secs() + e6irc_edge::lingering_close::LINGER_CLOSE_BOUND.as_secs()
);

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
    /// In edge mode, the bound address edges link to.
    pub edge_link_addr: Option<SocketAddr>,
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
    /// Every client connection's task, waited for once the core has stopped.
    connections: ConnectionTasks,
    /// In edge mode, the links to the edges, ended once the core has stopped
    /// so each sends what its sessions were last given.
    edge_links: Option<Arc<crate::edge_link::LinkServer>>,
    /// The serving lease, given back last — after the flush, so nothing this
    /// process writes can land after a standby has taken over. `None` without
    /// a database.
    lease: Option<ServingLease>,
}

/// What a stop asks for (DESIGN §19.3, D16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopMode {
    /// Hand the clients over: in edge mode the core cuts its links and the
    /// edges hold every session for the next core. A process with no edge
    /// holds its own clients, and closes them.
    Handover,
    /// Close every client, with the core's own `ERROR`.
    Final,
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
    /// ask the core to notify clients and stop, wait for the connections to
    /// deliver that and close, then wait for the DB worker to flush its
    /// buffered history, and last give the serving lease back. Every step is
    /// bounded; returns once the lease is given back or its timeout elapses.
    ///
    /// A [`StopMode::Handover`] in edge mode cuts the links first (DESIGN
    /// §19.3): the edges hold every session, and the core tells no client
    /// anything; the drivers, the core, the flush and the lease follow as
    /// ever.
    pub async fn run(self, mode: StopMode) -> ShutdownOutcome {
        self.run_within(
            mode,
            ShutdownBudget {
                core_stop: SHUTDOWN_CORE_STOP_TIMEOUT,
                driver_stop: SHUTDOWN_DRIVER_STOP_TIMEOUT,
                connection_drain: SHUTDOWN_CONNECTION_DRAIN_TIMEOUT,
            },
        )
        .await
    }

    /// Whether a handover hands anything over: the process is in edge mode.
    pub fn hands_over(&self) -> bool {
        self.edge_links.is_some()
    }

    async fn run_within(mut self, mode: StopMode, budget: ShutdownBudget) -> ShutdownOutcome {
        let ShutdownBudget {
            core_stop: core_stop_timeout,
            driver_stop: driver_stop_timeout,
            connection_drain: connection_drain_timeout,
        } = budget;
        // 1. Stop accepting: abort every listener task up front so nothing new
        //    is admitted while we drain.
        for listener in &self.listeners {
            listener.abort();
        }
        let closing = tokio::time::Instant::now() + SHUTDOWN_LISTENER_CLOSE_TIMEOUT;
        while self
            .listeners
            .iter()
            .any(|listener| !listener.is_finished())
        {
            if tokio::time::Instant::now() >= closing {
                eprintln!(
                    "e6ircd: a listener task did not end within {}s of being aborted; its \
                     socket may stay bound until the process exits",
                    SHUTDOWN_LISTENER_CLOSE_TIMEOUT.as_secs()
                );
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        if let Some(listener) = &self.bnc_listener {
            listener.stop().await;
        }
        // 1b. A handover cuts the links now, before anything tells a client
        //     goodbye: the edges hold every session for the next core, and
        //     nothing the core does from here reaches them.
        let handed_over = match (&self.edge_links, mode) {
            (Some(links), StopMode::Handover) => {
                let cut = new_cut();
                let epoch = self
                    .lease
                    .as_ref()
                    .map_or(0, |lease| u64::try_from(lease.epoch()).unwrap_or(0));
                let handover = links.cut(cut, epoch).await;
                eprintln!(
                    "e6ircd: handed over to the next core: cut {:#x}, {} edges hold the \
                     sessions, {} of the core's own homed on one ({} closed as unsettled, {} \
                     that no edge holds closed)",
                    cut.get(),
                    handover.edges.len(),
                    handover.homed,
                    handover.unsettled,
                    handover.unheld
                );
                true
            }
            _ => false,
        };
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
        // 3. Tell the core to notify clients (terminal ERROR) and stop, within
        //    the core's stop budget: a shard whose queue is full and that no
        //    longer takes from it would otherwise hold the telling itself
        //    forever. A push failure can only mean the core queue is already
        //    closed, i.e. the core is already gone — nothing more to ask of it.
        // Every shard is joined, whatever happens to one of them. A shard that
        // failed has lost its own state, but the database worker still holds
        // buffered history that is good — and it can only flush once *every*
        // core has dropped its end of the database queue. So a failure here is
        // remembered and reported after the flush, never instead of it.
        let mut core_failure = None;
        let deadline = tokio::time::Instant::now() + core_stop_timeout;
        let core_tx = self.core_tx.take().expect("shutdown core ingress present");
        match tokio::time::timeout_at(deadline, core_tx.broadcast_shutdown()).await {
            Ok(Ok(())) => {}
            Ok(Err(())) => eprintln!("e6ircd: core ingress closed before shutdown broadcast"),
            Err(_elapsed) => {
                eprintln!(
                    "e6ircd: a core shard did not take the shutdown request within {}s",
                    core_stop_timeout.as_secs()
                );
                core_failure = Some(ShutdownOutcome::CoreTimedOut);
            }
        }
        // Drop our own sender clone so it isn't left keeping the core queue's
        // producer count up. (The core breaks on the Shutdown event regardless;
        // this just keeps the shutdown intent honest.)
        drop(core_tx);
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
        // 4. The core is gone, and with it every session's send queue: each
        //    connection now delivers what it is still owed — its closing
        //    ERROR — and closes. Wait for that, bounded, or dropping the
        //    runtime would cancel the writes. In edge mode each link is one
        //    of these: it sends what its sessions were last given, then
        //    closes, and the edge delivers it.
        if let Some(links) = self.edge_links.take()
            && !handed_over
        {
            links.end_links();
        }
        let unclosed = self
            .connections
            .drained_within(connection_drain_timeout)
            .await;
        if unclosed > 0 {
            eprintln!(
                "e6ircd: {unclosed} client connections had not closed {}s after the core \
                 stopped; they may not have received their closing ERROR",
                connection_drain_timeout.as_secs()
            );
        }
        // 5. Wait for the DB worker to observe its now-dropped sender, drain,
        //    and flush. Bounded so a wedged database can't hang the shutdown.
        let flush = match self.db_worker.take() {
            None => ShutdownOutcome::Flushed,
            Some(worker) => match tokio::time::timeout(SHUTDOWN_DB_FLUSH_TIMEOUT, worker).await {
                Ok(Ok(())) => ShutdownOutcome::Flushed,
                Ok(Err(_join_err)) => ShutdownOutcome::WorkerPanicked,
                Err(_elapsed) => ShutdownOutcome::FlushTimedOut,
            },
        };
        // 6. Give the serving lease back. Its release is announced, so a
        //    standby takes over at once instead of after the lease's TTL; this
        //    process has written its last by now.
        if let Some(lease) = self.lease.take() {
            give_back_lease(lease, "shutting down").await;
        }
        core_failure.unwrap_or(flush)
    }
}

/// A cut's identifier: random, so no two cuts share one.
fn new_cut() -> e6irc_link::CutId {
    use aws_lc_rs::rand::SecureRandom;
    loop {
        let mut bytes = [0u8; 8];
        aws_lc_rs::rand::SystemRandom::new()
            .fill(&mut bytes)
            .expect("the system random number generator");
        if let Some(cut) = e6irc_link::CutId::new(u64::from_le_bytes(bytes)) {
            return cut;
        }
    }
}

/// The bounds of the shutdown steps [`ShutdownHandle::run_within`] waits on.
struct ShutdownBudget {
    core_stop: std::time::Duration,
    driver_stop: std::time::Duration,
    connection_drain: std::time::Duration,
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
    attach: BncAttachContext,
    telemetry: Arc<Telemetry>,
    certificates: CertificateReloads,
}

impl BncListenerController {
    fn new(attach: BncAttachContext, certificates: CertificateReloads) -> Self {
        Self {
            state: tokio::sync::Mutex::new(None),
            telemetry: attach.telemetry.clone(),
            attach,
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
                self.telemetry.record_error(ErrorKind::Configuration);
            })?),
            None => None,
        };
        let listener = bind_listener(requested.addr).inspect_err(|_error| {
            self.telemetry.record_error(ErrorKind::Bouncer);
        })?;
        let bound = listener.local_addr().inspect_err(|_error| {
            self.telemetry.record_error(ErrorKind::ConnectionSetup);
        })?;
        let task = spawn_bnc_listener(listener, acceptor, self.attach.clone());
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

/// What every attach connection is served with.
#[derive(Clone)]
struct BncAttachContext {
    registry: Arc<crate::bouncer::Registry>,
    pool: sqlx::PgPool,
    server_name: String,
    limiter: ConnLimiter,
    telemetry: Arc<Telemetry>,
    connections: ConnectionTasks,
    /// Attach sessions draw identifiers from the one allocator every session
    /// does, so a session's identifier names one session of any kind.
    next_conn: Arc<ConnectionIdAllocator>,
    sendq_bytes: usize,
}

/// Accept attaching clients on `listener` as the edge accepts every client
/// (`e6irc_edge::connection::accept_loop`), each served as a session of the
/// core link whose other end is the attach logic (`bouncer::bnc_serve`,
/// through an `AttachPort`).
fn spawn_bnc_listener(
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    context: BncAttachContext,
) -> tokio::task::JoinHandle<()> {
    let BncAttachContext {
        registry,
        pool,
        server_name,
        limiter,
        telemetry,
        connections,
        next_conn,
        sendq_bytes,
    } = context;
    let port = attach_port(registry, pool, server_name, telemetry.clone());
    tokio::spawn(accept_loop(
        listener,
        AcceptContext {
            tls,
            core_tx: port,
            next_conn,
            sendq_bytes,
            limiter,
            telemetry,
            connections,
            proxy_protocol: None,
        },
    ))
}

/// The attach logic as a session of the core link reaches it: each session
/// opened is served by `bouncer::bnc_serve`, whichever edge accepted it, and
/// each a rebuild resumes by `bouncer::bnc_resume`.
fn attach_port(
    registry: Arc<crate::bouncer::Registry>,
    pool: sqlx::PgPool,
    server_name: String,
    telemetry: Arc<Telemetry>,
) -> crate::bouncer::AttachPort {
    let resume = {
        let (registry, server_name, telemetry) =
            (registry.clone(), server_name.clone(), telemetry.clone());
        move |link, client, record| {
            let registry = registry.clone();
            let server_name = server_name.clone();
            let telemetry = telemetry.clone();
            tokio::spawn(async move {
                match crate::bouncer::bnc_resume(link, registry, &server_name, client, record).await
                {
                    Ok(()) => {}
                    // A cut, or a link that ended: the edge holds it, or said
                    // so.
                    Err(e) if e6irc_edge::link::EdgeGone::is(&e) => {}
                    Err(e) => {
                        telemetry.record_error(ErrorKind::Bouncer);
                        eprintln!("bnc attachment of {client} failed after a restart: {e}");
                    }
                }
            });
        }
    };
    crate::bouncer::AttachPort::new(
        move |link, client| {
            let registry = registry.clone();
            let pool = pool.clone();
            let server_name = server_name.clone();
            let telemetry = telemetry.clone();
            tokio::spawn(async move {
                match crate::bouncer::bnc_serve(link, registry, &pool, &server_name, client).await {
                    Ok(()) => {}
                    // A cut, or a link that ended: the edge holds it, or said
                    // so.
                    Err(e) if e6irc_edge::link::EdgeGone::is(&e) => {}
                    Err(e) => {
                        telemetry.record_error(ErrorKind::Bouncer);
                        eprintln!("bnc connection from {client} failed: {e}");
                    }
                }
            });
        },
        resume,
    )
}

/// Unix-epoch milliseconds. Message timestamps are stamped from this, and
/// `server-time` is specified to millisecond precision — a whole-second clock
/// would give every message in the same second an identical `time=` tag,
/// which CHATHISTORY cannot page through.
pub(crate) fn wall_clock() -> e6irc_proto::time::Millis {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_millis() as u64;
    e6irc_proto::time::Millis::from_millis(ms)
}

/// Monotonic milliseconds since the process started, for timer decisions (the
/// reaper deadlines and flood-bucket refill). Unlike [`wall_clock`] this never
/// steps — an NTP correction or a virtual-machine resume cannot move it — so a reaper keyed
/// on it can neither mass-close live connections on a forward jump nor freeze
/// on a backward one. The epoch is arbitrary (process start); only differences
/// are meaningful, which is all the timers ever take.
pub(crate) fn mono_clock() -> e6irc_proto::time::MonoMillis {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    let ms = START.get_or_init(Instant::now).elapsed().as_millis() as u64;
    e6irc_proto::time::MonoMillis::from_millis(ms)
}

/// Whether the process serves HTTP: the `[http]` listener, or a WebSocket IRC
/// listener, which is served by the same application state.
fn serves_http(config: &Config) -> bool {
    config.http.is_some()
        || config.edge_link.is_some()
        || config.listeners.iter().any(|listener| listener.websocket)
}

/// What [`start`] reads from outside the configuration document that needs
/// neither the network nor the database, judged by the very functions `start`
/// uses: the monitoring token from the environment, every TLS certificate
/// and key pair the configuration names, and the core-link credentials of
/// `[edge_link]`. `e6ircd check-config` runs this after
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
    if config.database.is_some() {
        crate::db::refuse_libpq_process_environment().map_err(io::Error::other)?;
    }
    if serves_http(config) {
        crate::http::monitoring_token_digest_from_env().map_err(io::Error::other)?;
    }
    if let Some(edge_link) = &config.edge_link {
        e6irc_edge::core_link::tls::LinkCredentials::load(&edge_link.credentials)?
            .core_acceptor()?;
    }
    crate::config::load_configured_certificates(config)
}

/// How [`start_unless`] ended.
pub enum Started {
    /// This process serves: it holds the serving lease (when it has a
    /// database) and its listeners are bound.
    Serving(Box<Running>),
    /// The stop came first, while the process was still waiting for the
    /// database or standing by; it had taken nothing that needs giving back.
    StoppedWhileWaiting,
}

/// [`start_unless`] with nothing to stop it: bind listeners, spawn core
/// workers, and start acceptors once this process holds the serving lease —
/// standing by as long as another process holds it.
pub async fn start(config: Config) -> io::Result<Running> {
    match start_unless(config, std::future::pending()).await? {
        Started::Serving(running) => Ok(*running),
        Started::StoppedWhileWaiting => unreachable!("a pending stop never resolves"),
    }
}

/// Start serving: wait for the database, take the serving lease — standing by
/// while another process holds it (DESIGN §18) — migrate, then build and bind
/// everything. `stop` is raced against the waiting only: before the lease is
/// held there is nothing to drain, so a shutdown signal then ends the wait
/// ([`Started::StoppedWhileWaiting`]); once it is held, the boot completes and
/// the caller shuts the server down as usual. A boot that fails after the
/// lease is held gives it back before returning the failure.
pub async fn start_unless(
    config: Config,
    stop: impl std::future::Future<Output = ()>,
) -> io::Result<Started> {
    // First, before anything that can wait: a SIGHUP sent to reload
    // certificates during the database wait must not be the default action,
    // which terminates the process.
    let hangups = Hangups::install()?;
    install_crypto_provider();
    // Resolve once and reuse for the control-plane import plus BNC secrets.
    // UI-managed OIDC/operator credentials are always sealed in PostgreSQL.
    let secret_key = config
        .secret_keyring()
        .map_err(io::Error::other)?
        .map(Arc::new);
    let mut lease = match &config.database {
        Some(database) => {
            let waiting = wait_and_acquire(database, &config);
            tokio::select! {
                lease = waiting => Some(lease?),
                () = stop => return Ok(Started::StoppedWhileWaiting),
            }
        }
        None => None,
    };
    match serve(config, hangups, secret_key, &mut lease).await {
        Ok(running) => Ok(Started::Serving(Box::new(running))),
        Err(error) => {
            if let Some(lease) = lease.take() {
                give_back_lease(lease, "the boot failed").await;
            }
            Err(error)
        }
    }
}

/// Wait for the database ([`crate::db::wait_for_database`]), then take the
/// serving lease or stand by until it can be taken.
async fn wait_and_acquire(
    database: &crate::config::DatabaseConfig,
    config: &Config,
) -> io::Result<ServingLease> {
    crate::db::refuse_libpq_process_environment().map_err(io::Error::other)?;
    let wait = crate::db::StartupDatabaseWait::from_seconds(database.startup_wait_seconds)
        .map_err(io::Error::other)?;
    crate::db::wait_for_database(&database.url, wait, |attempt| match attempt.retry_in {
        Some(pause) => eprintln!(
            "e6ircd: database connection attempt {} failed after {:.1}s: {}; retrying in {:.1}s \
             (giving up after {}s)",
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
    })
    .await
    .map_err(io::Error::other)?;
    acquire_or_stand_by(&database.url, &HolderId::generate(), config).await
}

/// Take the serving lease, or stand by until it can be taken: say so on
/// stderr, answer `/healthz` 200 and `/readyz` 503 naming the holder on the
/// HTTP address (when there is one), and try again whenever the lease's holder
/// changes (its announcement) and every [`serving_lease::STANDBY_POLL`]. A
/// schema a later release migrated ends the wait: this binary could not serve
/// it. The health listener is closed before this returns, so the server can
/// bind the address itself.
async fn acquire_or_stand_by(
    url: &crate::db::DatabaseUrl,
    holder: &HolderId,
    config: &Config,
) -> io::Result<ServingLease> {
    let purpose = serving_lease::serving_purpose();
    let held = match serving_lease::acquire(url, holder, &purpose).await {
        Ok(lease) => return Ok(lease),
        Err(AcquireRefusal::Held(held)) => held,
        Err(AcquireRefusal::Database(error)) => return Err(io::Error::other(error)),
    };
    eprintln!(
        "e6ircd: standing by: the serving lease is held by {held}; this process serves once it is \
         released, or {}s after its last renewal",
        serving_lease::LEASE_TTL.as_secs()
    );
    let (holder_now, holder_watch) = tokio::sync::watch::channel(held);
    let health = match &config.http {
        Some(http) => Some(StandbyHealth::bind(
            http.addr,
            holder_watch,
            config.limits.trusted_proxies.clone(),
        )?),
        None => None,
    };
    let wake = Arc::new(tokio::sync::Notify::new());
    let follower = AbortOnDrop(tokio::spawn(crate::db::follow_announcements(
        url.clone(),
        crate::db::SERVING_LEASE_CHANNEL,
        "e6ircd: standby: serving-lease listener",
        None,
        LeaseWaker(wake.clone()),
    )));
    loop {
        tokio::select! {
            () = wake.notified() => {}
            () = tokio::time::sleep(serving_lease::STANDBY_POLL) => {}
        }
        match crate::db::refuse_newer_schema(url).await {
            Ok(()) => {}
            Err(error @ crate::db::DbError::Connect(_)) => {
                eprintln!("e6ircd: standby: the database could not be reached: {error}");
                continue;
            }
            Err(error) => return Err(io::Error::other(error)),
        }
        match serving_lease::acquire(url, holder, &purpose).await {
            Ok(lease) => {
                drop(follower);
                if let Some(health) = health {
                    health.close().await;
                }
                eprintln!(
                    "e6ircd: took the serving lease (epoch {}); starting to serve",
                    lease.epoch()
                );
                return Ok(lease);
            }
            Err(AcquireRefusal::Held(held)) => {
                if holder_now.borrow().label != held.label {
                    eprintln!("e6ircd: standing by: the serving lease is now held by {held}");
                }
                holder_now.send_replace(held);
            }
            Err(AcquireRefusal::Database(error)) => {
                eprintln!("e6ircd: standby: the serving lease could not be tried: {error}");
            }
        }
    }
}

/// Wakes a standby to try the lease: on every announced change of holder, and
/// after a re-established connection, which may have missed one.
struct LeaseWaker(Arc<tokio::sync::Notify>);

impl crate::db::Follower for LeaseWaker {
    async fn on_change(&mut self, _: crate::db::Announcement) -> Result<(), String> {
        self.0.notify_one();
        Ok(())
    }
}

/// A task aborted when this is dropped.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A standby's HTTP listener: `/healthz` answers 200 (the process is alive),
/// `/readyz` 503 with its role and the lease's holder, anything else 503. Each
/// answer closes its connection, so a load balancer's kept-alive health check
/// cannot outlive the listener into the serving process's.
struct StandbyHealth(AbortOnDrop);

#[derive(serde::Serialize)]
struct StandbyReadiness {
    ready: bool,
    role: &'static str,
    holder: String,
    holder_renewed_at: String,
}

impl StandbyHealth {
    fn bind(
        addr: SocketAddr,
        holder: tokio::sync::watch::Receiver<serving_lease::LeaseHeld>,
        trusted_proxies: Vec<ipnet::IpNet>,
    ) -> io::Result<Self> {
        use axum::http::{StatusCode, header};
        let listener = bind_listener(addr)?;
        let close = || [(header::CONNECTION, "close")];
        let router = axum::Router::new()
            .route(
                "/healthz",
                axum::routing::get(move || async move { (close(), "ok") }),
            )
            .route(
                "/readyz",
                axum::routing::get(move || {
                    let held = holder.borrow().clone();
                    async move {
                        (
                            StatusCode::SERVICE_UNAVAILABLE,
                            close(),
                            axum::Json(StandbyReadiness {
                                ready: false,
                                role: "standby",
                                holder: held.label,
                                holder_renewed_at: held.renewed_at,
                            }),
                        )
                    }
                }),
            )
            .fallback(move || async move {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    close(),
                    "this e6ircd process is a standby; another process serves the database\n",
                )
            });
        Ok(Self(AbortOnDrop(tokio::spawn(serve_http(
            listener,
            router,
            HttpAdmission::new(e6irc_edge::address::TrustedProxies::new(trusted_proxies)),
            Arc::new(Telemetry::new()),
        )))))
    }

    /// Stop answering and release the address.
    async fn close(mut self) {
        self.0.0.abort();
        if let Err(error) = (&mut self.0.0).await
            && !error.is_cancelled()
        {
            eprintln!("e6ircd: the standby health listener failed: {error}");
        }
    }
}

/// Give the lease back on a path that will not serve with it, saying how that
/// went.
async fn give_back_lease(lease: ServingLease, why: &str) {
    let epoch = lease.epoch();
    match lease.release(SHUTDOWN_LEASE_RELEASE_TIMEOUT).await {
        Ok(true) => eprintln!("e6ircd: released the serving lease (epoch {epoch}): {why}"),
        Ok(false) => eprintln!(
            "e6ircd: the serving lease (epoch {epoch}) was no longer this process's to release"
        ),
        Err(error) => eprintln!(
            "e6ircd: the serving lease (epoch {epoch}) could not be released ({why}); a standby \
             takes over {}s after its last renewal: {error}",
            serving_lease::LEASE_TTL.as_secs()
        ),
    }
}

/// Everything [`start_unless`] does once the lease is held (or there is no
/// database): migrate, load the stored settings, build the core, the bouncer
/// registry and the listeners. On success the lease moves into the returned
/// shutdown handle, which gives it back last.
async fn serve(
    mut config: Config,
    hangups: Hangups,
    secret_key: Option<Arc<crate::secret::SecretKeyring>>,
    lease: &mut Option<ServingLease>,
) -> io::Result<Running> {
    // Load persisted settings before constructing anything that consumes
    // them. In particular, a queue's capacity cannot be changed after the
    // queue exists; loading `core_queue` later would make that console setting
    // a permanent no-op.
    let (pool, managed_config) = match config
        .database
        .as_ref()
        .map(|db| (db.url.clone(), db.pool_size()))
    {
        Some((database_url, pool_size)) => {
            let holder = lease
                .as_ref()
                .expect("a database-backed start holds the serving lease")
                .holder()
                .clone();
            // Only the lease's holder migrates, so no process changes the
            // schema under a serving one.
            crate::db::migrate(&database_url)
                .await
                .map_err(io::Error::other)?;
            eprintln!(
                "e6ircd: database pool holds at most {} connections",
                pool_size.get()
            );
            let pool = crate::db::connect_pool(&database_url, pool_size, Some(&holder))
                .await
                .map_err(io::Error::other)?;
            let imported =
                crate::config::ManagedConfig::from_config(&config, secret_key.as_deref())
                    .map_err(io::Error::other)?;
            // A document that leaves a required setting to the console can
            // take it only from a stored revision; importing its absence as the
            // first one would store a server with no name.
            let mut snapshot = if config.left_to_stored_settings.is_empty() {
                crate::db::load_or_initialize_managed_config(&pool, &imported)
                    .await
                    .map_err(io::Error::other)?
            } else {
                crate::db::stored_managed_config(&pool)
                    .await
                    .map_err(io::Error::other)?
                    .ok_or_else(|| {
                        io::Error::other(format!(
                            "the configuration does not state {} and the database holds no \
                             stored settings to take it from: the first start needs each \
                             stated (the console owns them afterwards)",
                            config.left_to_stored_settings.join(", "),
                        ))
                    })?
            };
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
                    &crate::db::AuditPrincipal::host("bootstrap"),
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
    // Every connection's lines are metered where they enter the core: an
    // empty bucket stops its reader, not the connection (DESIGN §7.2).
    let command_flood =
        crate::core::CommandFlood::new(config.limits.command_burst, config.limits.command_rate)
            .map_err(io::Error::other)?;
    let core_tx = CoreIngress::with_shards(first_core_sender, remaining_core_senders)
        .with_command_flood(command_flood);
    // In edge mode the edges may hold sessions for this core to rebuild: the
    // core's own sessions wait until the link server knows (DESIGN §19.3).
    // Its own sessions — the `local` driver's — are homed on an edge across
    // a cut (D13).
    if config.edge_link.is_some() {
        let held = core_tx.directories().held;
        held.rebuilt.pending();
        held.homes.enable();
    }
    // Followed live from here on (`CoreIngress::adopt_live_settings`).
    core_tx
        .set_anti_spam_exit_message_time_seconds(config.limits.anti_spam_exit_message_time_seconds);
    core_tx
        .password_policy()
        .set_minimum_chars(config.registration.minimum_password_length);
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

    // A lease that ends while serving — a renewal found it taken over, at
    // once or when the database answered again after a fence — ends the
    // serving: the same bounded drain as a signal, and a non-zero exit. A
    // fence alone (no renewal confirmed) keeps serving clients from hot state
    // without the database (`serving_lease::renew`).
    if let Some(lease) = lease.as_ref() {
        telemetry.observe_serving_lease(lease.status());
        let ended = lease.end_watch();
        let critical_tx = critical_tx.clone();
        let watcher = tokio::spawn(async move {
            let end = ended.ended().await;
            drop(critical_tx.send(CriticalTaskFailure {
                task: "serving lease",
                reason: end.to_string(),
            }));
        });
        listeners.push(watcher.abort_handle());
    }

    let next_conn = Arc::new(connection_ids(config.edge_link.is_some())?);

    // The body format the shards write for their edges (D11): the stored
    // one, followed live, so `e6ircd records advance` takes effect at once;
    // without a database, the configured one.
    if let (Some(edge_link), None) = (&config.edge_link, &config.database) {
        core_tx
            .directories()
            .held
            .format
            .set(edge_link.record_format().map_err(io::Error::other)?);
    }
    if let (Some(pool), Some(database)) = (&pool, &config.database) {
        let format = core_tx.directories().held.format;
        format.set(read_record_format(pool).await?);
        listeners.push(supervise_listener(
            "record-format follower",
            tokio::spawn(crate::db::follow_announcements(
                database.url.clone(),
                crate::db::RECORD_FORMAT_CHANNEL,
                "e6ircd: record-format follower",
                None,
                RecordFormatFollower {
                    pool: pool.clone(),
                    format,
                },
            )),
            critical_tx.clone(),
        ));
    }

    // An account's authority changed by another process (`e6ircd
    // recover-administrator`, a hand-written row) is followed here (DESIGN
    // §9.1); this process's own changes are applied where they are made. The
    // follower's baseline is read before this boot reads which accounts are
    // suspended (the registry's holds, the core's gate), so a change committed
    // while it boots is announced after the baseline and applied once the core
    // runs.
    let authority_baseline = match (&pool, &config.database) {
        (Some(pool), Some(database)) => Some(
            crate::account_authority::listen(&database.url, pool)
                .await
                .map_err(io::Error::other)?,
        ),
        _ => None,
    };

    // The BNC registry is shared between the HTTP management API (which
    // adds/removes networks) and the BNC listener (which attaches to
    // them). Server-level [[network]]s start first, then each account's
    // persisted networks are loaded and started.
    let bnc_registry = if pool.is_some() || !config.networks.is_empty() {
        // A configured network whose owner is suspended or deleted starts
        // held, as the account lifecycle left it.
        let mut holds = std::collections::HashMap::new();
        if let Some(pool) = &pool {
            let owners: Vec<String> = config
                .networks
                .iter()
                .filter_map(|entry| entry.owner.as_deref())
                .map(|owner| e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(owner))
                .collect();
            for (owner, standing) in crate::db::inactive_network_owners(pool, &owners)
                .await
                .map_err(io::Error::other)?
            {
                let hold = match standing {
                    crate::db::OwnerStanding::Suspended => crate::bouncer::OwnerHold::Suspended,
                    crate::db::OwnerStanding::Deleted => crate::bouncer::OwnerHold::Deleted,
                };
                holds.insert(owner, hold);
            }
        }
        // What the configured IRC networks remembered when the process last
        // stopped; the rows of networks the configuration no longer defines go.
        let configured_channels = match &pool {
            Some(pool) => crate::bouncer::configured_remembered_channels(
                pool,
                &config.networks,
                secret_key.as_deref(),
            )
            .await
            .map_err(io::Error::other)?,
            None => Default::default(),
        };
        let reg = Arc::new(
            crate::bouncer::Registry::start_observed(
                &config.networks,
                &holds,
                crate::bouncer::RegistryStorage {
                    pool: pool.clone(),
                    secret_keys: secret_key.clone(),
                    configured_channels,
                },
                crate::bouncer::CoreHandles {
                    core_tx: core_tx.clone(),
                    next_conn: next_conn.clone(),
                    sendq_bytes: config.sendq_bytes,
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
                        if let Err(error) = reg
                            .start_stored(owner.clone(), row.name.clone(), driver)
                            .await
                        {
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
                        // Its owner is told why when they attach, rather than
                        // that an enabled network is disabled.
                        reg.record_unstartable(&owner, &row.name, e);
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
    // Every client connection's task, whichever listener accepted it, so
    // shutdown can wait for their closing ERRORs.
    let connections = ConnectionTasks::default();

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
    // In edge mode the attach listener is the edges' (their own
    // configuration); the core serves the attach sessions they open.
    let bnc_listener = match (&pool, &bnc_registry, &config.edge_link) {
        (Some(pool), Some(registry), None) => Some(Arc::new(BncListenerController::new(
            BncAttachContext {
                registry: registry.clone(),
                pool: pool.clone(),
                server_name: config.server_name.clone(),
                limiter: limiter.clone(),
                telemetry: telemetry.clone(),
                connections: connections.clone(),
                next_conn: next_conn.clone(),
                sendq_bytes: config.sendq_bytes,
            },
            certificates.clone(),
        ))),
        _ => None,
    };
    let mut bnc_addr = None;
    if let Some(bnc) = &config.bnc {
        match &bnc_listener {
            Some(controller) => bnc_addr = Some(controller.enable(bnc).await?),
            None => eprintln!(
                "e6ircd: the stored attach listener ({}) applies to single-process mode; in \
                 edge mode each edge's own configuration names its attach listener",
                bnc.addr
            ),
        }
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
        if let Some(database) = &config.database {
            let watcher = tokio::spawn(crate::settings_watch::run(
                database.url.clone(),
                pool.clone(),
                settings.clone(),
                bnc_listener.clone(),
                core_tx.clone(),
            ));
            listeners.push(supervise_listener(
                "settings-change listener",
                watcher,
                critical_tx.clone(),
            ));
        }
    }

    // Edge mode's shared state: the upgrades the core authorizes for its edges
    // to complete, and the edges linked now.
    let edge_mode = config.edge_link.as_ref().map(|_| EdgeModeState {
        upgrades: Arc::default(),
        edges: Arc::default(),
    });

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
        let trusted_proxies = config.limits.trusted_proxies.clone();
        if let Some(warning) = config.shared_authentication_budget() {
            eprintln!("e6ircd: warning: {warning}");
        }
        let (public_url, secure_cookies) = match &config.http {
            Some(h) => (h.public_url.clone(), h.secure_cookies),
            None => (None, false),
        };
        let monitoring_token_digest =
            crate::http::monitoring_token_digest_from_env().map_err(io::Error::other)?;
        // Live chat sockets end with the credential that opened them; the
        // store announces every revocation on a dedicated connection.
        let credential_watch = crate::http::CredentialWatch::new();
        if let (Some(pool), Some(database)) = (&pool, &config.database) {
            let watcher = tokio::spawn(
                credential_watch
                    .clone()
                    .run(database.url.clone(), pool.clone()),
            );
            listeners.push(supervise_listener(
                "credential-change listener",
                watcher,
                critical_tx.clone(),
            ));
        }
        let (browser_keys, browser_keys_warning) =
            crate::http::BrowserStateKeys::for_keyring(secret_key.as_deref());
        if let Some(warning) = browser_keys_warning {
            eprintln!("{warning}");
        }
        Some(Arc::new(crate::http::AppState {
            server_name: config.server_name.clone(),
            network_name: config.network_name.clone(),
            backing: crate::http::Backing::new(pool.clone(), bnc_registry.clone())
                .map_err(io::Error::other)?,
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
            oidc_flow_key: browser_keys.oidc_flow,
            core_tx: core_tx.clone(),
            next_conn: next_conn.clone(),
            sendq_bytes: config.sendq_bytes,
            bnc_listener: bnc_listener.clone(),
            managed_config: managed_config.clone(),
            telemetry: telemetry.clone(),
            secret_key: secret_key.clone(),
            configured_admin_accounts: configured_administrators.clone(),
            csrf_keys: browser_keys.csrf,
            trusted_proxies: trusted_proxies.clone(),
            auth_rate_burst: config.limits.auth_rate_burst.burst(),
            auth_buckets: std::sync::Mutex::new(std::collections::HashMap::new()),
            api_rate_burst: config.limits.api_rate_burst,
            administrator_api_rate_burst: config.limits.administrator_api_rate_burst,
            api_buckets: std::sync::Mutex::new(std::collections::HashMap::new()),
            preflight_limiter: crate::http::PreflightLimiter::new(),
            ui_sockets: crate::http::UiSocketLimiter::new(),
            credential_watch: credential_watch.clone(),
            account_exports: crate::http::AccountExportSlots::new(),
            conn_limiter: limiter.clone(),
            connections: connections.clone(),
            database_readiness: crate::http::DatabaseReadiness::default(),
            request_admission: Arc::new(crate::http::RequestAdmission::new(
                trusted_proxies.clone(),
                MAX_HTTP_REQUESTS_IN_FLIGHT_PER_IP,
                limiter.refusals().clone(),
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
            edge_upgrades: edge_mode.as_ref().map(|mode| mode.upgrades.clone()),
            linked_edges: edge_mode.as_ref().map(|mode| mode.edges.clone()),
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
                HttpAdmission::new(e6irc_edge::address::TrustedProxies::new(
                    state.trusted_proxies.clone(),
                )),
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
        sendq_bytes: config.sendq_bytes,
        motd: config.motd.clone(),
        nicklen: config.nicklen,
        sasl_enabled,
        max_hot_channels: config.max_hot_channels,
        max_history_ring_bytes: config.max_history_ring_bytes,
        max_hot_history_bytes: config.max_hot_history_bytes,
        opers: config
            .opers
            .iter()
            .map(|o| (o.name.clone(), o.password.clone()))
            .collect(),
        clock: wall_clock,
        mono_clock,
        registration_burst: config.limits.registration_burst,
        sasl_requirement: config.limits.sasl_requirement(),
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
        for name in unjoinable_registered_channels(&founders) {
            eprintln!(
                "e6ircd: registered channel {name:?} has a name JOIN refuses (a control \
                 character, a space-like character or over CHANNELLEN), so nobody can join it; \
                 drop it with DELETE /api/v1/admin/channels/{{name}} or from its owner's console"
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

    if let (Some(baseline), Some(pool), Some(registry), Some(database)) =
        (authority_baseline, &pool, &bnc_registry, &config.database)
    {
        let watcher = crate::account_authority::AccountAuthorityWatcher {
            url: database.url.clone(),
            pool: pool.clone(),
            core_tx: core_tx.clone(),
            registry: registry.clone(),
            secret_key: secret_key.clone(),
            internal_upstreams: config.internal_upstreams,
        };
        listeners.push(supervise_listener(
            "account-authority listener",
            tokio::spawn(watcher.run(baseline)),
            critical_tx.clone(),
        ));
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
    let mut edge_links = None;
    let mut edge_link_addr = None;
    if let (Some(edge_link), Some(mode)) = (&config.edge_link, &edge_mode) {
        let credentials =
            e6irc_edge::core_link::tls::LinkCredentials::load(&edge_link.credentials)?;
        let listener = bind_listener(edge_link.addr)?;
        edge_link_addr = Some(listener.local_addr()?);
        let flood =
            crate::core::CommandFlood::new(config.limits.command_burst, config.limits.command_rate)
                .map_err(io::Error::other)?;
        let server = Arc::new(crate::edge_link::LinkServer::new(
            crate::edge_link::LinkServerParts {
                acceptor: credentials.core_acceptor()?,
                epoch: lease.as_ref().map_or(0, ServingLease::epoch),
                terms: e6irc_link::EdgeTerms {
                    trusted_proxies: config
                        .limits
                        .trusted_proxies
                        .iter()
                        .map(|network| (network.network(), network.prefix_len()))
                        .collect(),
                    max_connections_per_ip: config
                        .limits
                        .max_connections_per_ip
                        .map(|limit| u32::try_from(limit).unwrap_or(u32::MAX)),
                    sendq_bytes: u32::try_from(config.sendq_bytes).map_err(|_| {
                        io::Error::other("sendq_bytes is past what a core link carries")
                    })?,
                    command_flood: Some(e6irc_link::CommandFloodTerms {
                        burst: flood.burst(),
                        rate: flood.rate(),
                    }),
                    line_credit: crate::edge_link::line_credit(config.core_queue),
                },
                sendq_bytes: config.sendq_bytes,
                core_tx: core_tx.clone(),
                next_conn: next_conn.clone(),
                attach: match (&pool, &bnc_registry) {
                    (Some(pool), Some(registry)) => Some(attach_port(
                        registry.clone(),
                        pool.clone(),
                        config.server_name.clone(),
                        telemetry.clone(),
                    )),
                    _ => None,
                },
                upgrades: mode.upgrades.clone(),
                limiter: limiter.clone(),
                telemetry: telemetry.clone(),
                connections: connections.clone(),
                edges: mode.edges.clone(),
                pool: pool.clone(),
                http: app_state.as_ref().map(crate::http::LinkRouters::for_state),
                pending_cut: match &pool {
                    Some(pool) => pending_cut(pool).await?,
                    None => None,
                },
            },
        ));
        // The shards' replicas reach the edges hosting each channel's members.
        let routes: Arc<dyn crate::core::ReplicaSink> =
            Arc::new(crate::edge_link::ReplicaRoutes(mode.edges.clone()));
        if core_tx.directories().held.replicas.set(routes).is_err() {
            unreachable!("one link server routes the replicas");
        }
        // The edges holding the last core's sessions are rebuilt once they
        // have uploaded, or once the wait is over.
        tokio::spawn(server.clone().wait_for_rebuild());
        eprintln!(
            "e6ircd: edge mode: edges link at {}",
            edge_link_addr.expect("bound above")
        );
        listeners.push(supervise_listener(
            "core link listener",
            tokio::spawn(crate::edge_link::serve(listener, server.clone())),
            critical_tx.clone(),
        ));
        edge_links = Some(server);
    }
    for listener_config in config
        .listeners
        .iter()
        .filter(|_| config.edge_link.is_none())
    {
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
                HttpAdmission::new(e6irc_edge::address::TrustedProxies::new(
                    state.trusted_proxies.clone(),
                )),
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
            AcceptContext {
                tls: acceptor,
                core_tx: core_tx.clone(),
                next_conn: next_conn.clone(),
                sendq_bytes: config.sendq_bytes,
                limiter: limiter.clone(),
                telemetry: telemetry.clone(),
                connections: connections.clone(),
                proxy_protocol: None,
            },
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
        edge_link_addr,
        shutdown: ShutdownHandle {
            listeners,
            core_tx: Some(core_tx),
            core_workers,
            db_worker,
            critical_failures: critical_rx,
            bnc_listener,
            bnc_registry,
            connections,
            edge_links,
            lease: lease.take(),
        },
    })
}

/// The body format the stored settings say the cores write, when this release
/// writes it; one this release does not write refuses the start, loudly: a
/// format advanced past this release's is one it cannot read back.
async fn read_record_format(pool: &sqlx::PgPool) -> io::Result<crate::core::record::RecordFormat> {
    let number = crate::db::roster::written_record_format(pool)
        .await
        .map_err(io::Error::other)?;
    crate::core::record::RecordFormat::read(number).ok_or_else(|| {
        io::Error::other(format!(
            "the stored record format is {number}, which this release does not write (it \
             writes {} and {}); run the release that advanced it",
            crate::core::record::RecordFormat::PREVIOUS.number(),
            crate::core::record::RecordFormat::NEWEST.number()
        ))
    })
}

/// Follows the stored record format, so every core writes the one advanced to.
struct RecordFormatFollower {
    pool: sqlx::PgPool,
    format: crate::core::RecordFormatCell,
}

impl crate::db::Follower for RecordFormatFollower {
    async fn on_change(&mut self, _: crate::db::Announcement) -> Result<(), String> {
        let format = read_record_format(&self.pool)
            .await
            .map_err(|error| error.to_string())?;
        if format != self.format.get() {
            eprintln!(
                "e6ircd: writing record format {} from now on",
                format.number()
            );
        }
        self.format.set(format);
        Ok(())
    }
}

/// The cut the roster says the edges hold, which this core rebuilds.
async fn pending_cut(pool: &sqlx::PgPool) -> io::Result<Option<crate::edge_link::PendingCut>> {
    let Some((cut, edges)) = crate::db::roster::pending_cut(pool)
        .await
        .map_err(io::Error::other)?
    else {
        return Ok(None);
    };
    let cut = e6irc_link::CutId::new(cut)
        .ok_or_else(|| io::Error::other("the roster names cut 0, which no core makes"))?;
    let edges = edges
        .iter()
        .map(|edge| e6irc_link::EdgeName::new(edge).map_err(io::Error::other))
        .collect::<io::Result<Vec<_>>>()?;
    eprintln!(
        "e6ircd: the roster says {} edges hold cut {:#x}; this core rebuilds their sessions",
        edges.len(),
        cut.get()
    );
    Ok(Some(crate::edge_link::PendingCut { cut, edges }))
}

/// Edge mode's state shared by the HTTP service and the link listener.
struct EdgeModeState {
    upgrades: Arc<crate::edge_link::EdgeUpgrades>,
    edges: Arc<crate::edge_link::LinkedEdges>,
}

/// The registered channels (`(name_folded, founder)` rows) whose names JOIN
/// refuses: registered while an older build still let such a name be created,
/// they can never become live again, so startup names each for its operator.
fn unjoinable_registered_channels(founders: &[(String, String)]) -> Vec<&str> {
    founders
        .iter()
        .map(|(name, _)| name.as_str())
        .filter(|name| crate::sanitize::ChannelName::parse(name).is_err())
        .collect()
}

async fn core_worker(
    core: Core,
    rx: Receiver<Input>,
    ingress: CoreIngress,
    ready: tokio::sync::oneshot::Sender<()>,
) {
    // Built before startup is told this shard is ready, so the shard is heard
    // (its first heartbeat) before anything can probe its liveness.
    let worker = CoreWorker::new(core, rx, ingress);
    if ready.send(()).is_err() {
        return;
    }
    let exit = worker.run().await;
    if exit != crate::core::CoreWorkerExit::Stopped {
        // Whoever supervises this task treats its end as the failure it is;
        // this says which.
        eprintln!("e6ircd: IRC core shard stopped without a shutdown request: {exit:?}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{ConnId, Output};
    use e6irc_edge::connection::{AcceptedConnection, Outbound, read_loop, serve_conn};
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    /// In edge mode the core's own sessions count within slot 0, which no
    /// edge is given, so they cannot take an identifier an edge allocates.
    #[test]
    fn an_edge_mode_core_counts_its_own_sessions_in_slot_zero() {
        let slot_one = e6irc_link::Slot::new(1).expect("slot 1").first_id();
        for _ in 0..64 {
            let id = connection_ids(true)
                .expect("identifiers")
                .allocate()
                .expect("an identifier");
            assert!(id.0 < slot_one / 2, "{} is in slot 0's lower half", id.0);
        }
        let id = connection_ids(false)
            .expect("identifiers")
            .allocate()
            .expect("an identifier");
        assert!(
            id.0 < 1 << 62,
            "the single process keeps the top two bits clear"
        );
    }

    /// A channel registered under a name the channel-name rule now refuses
    /// (a formatting control, say) is named at startup rather than preloaded
    /// silently as a registration no one can use.
    #[test]
    fn registered_channels_join_refuses_are_named_at_startup() {
        let founders = vec![
            ("#libera".to_string(), "alice".to_string()),
            ("#lib\x0fera".to_string(), "mallory".to_string()),
            ("#a\u{a0}b".to_string(), "mallory".to_string()),
        ];
        assert_eq!(
            unjoinable_registered_channels(&founders),
            ["#lib\x0fera", "#a\u{a0}b"]
        );
    }
    use crate::config::TlsConfig;
    use crate::core::Input;
    use e6irc_queue::Sender;
    use std::pin::Pin;

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

    /// An accepted plaintext connection from `peer`, as connection 1.
    fn accepted(peer: SocketAddr) -> AcceptedConnection {
        AcceptedConnection {
            conn: ConnId(1),
            peer,
            transport: crate::core::ConnectionTransport::Tcp,
            tls: None,
            task: ConnectionTasks::default().task(),
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
            accepted(peer),
            CoreIngress::single(core_tx),
            Outbound::with_sendq(4096),
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
            accepted(peer),
            CoreIngress::single(core_tx),
            Outbound {
                sendq_bytes: 4096 * 512,
                write_deadline: std::time::Duration::from_millis(300),
                closing_drain: CLOSING_DRAIN,
            },
            Arc::new(Telemetry::new()),
        ));
        let Input::Open { mut tx, .. } = core_rx.pop().await.expect("Open event").payload else {
            panic!("expected Open");
        };
        // Far more than both kernel buffers hold: the writer parks mid-write.
        let line = bytes::Bytes::from(format!("NOTICE * :{}\r\n", "x".repeat(400)));
        for _ in 0..4096 {
            if tx.0.output(Output(line.clone())).is_err() {
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
        // A silent peer is lingered on for its bound before the close.
        tokio::time::timeout(
            e6irc_edge::lingering_close::LINGER_CLOSE_BOUND + std::time::Duration::from_secs(2),
            served,
        )
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
        tokio::time::timeout(
            e6irc_edge::lingering_close::LINGER_CLOSE_BOUND + std::time::Duration::from_secs(2),
            served,
        )
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
            sendq_bytes: 64 * 512,
            motd: vec!["hi".into()],
            nicklen: 30,
            sasl_enabled: false,
            max_hot_channels: 64,
            max_history_ring_bytes: crate::config::DEFAULT_HISTORY_RING_BYTES,
            max_hot_history_bytes: crate::config::DEFAULT_HOT_HISTORY_BYTES,
            opers: Vec::new(),
            clock: wall_clock,
            mono_clock,
            registration_burst: None,
            sasl_requirement: Default::default(),
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
            connections: ConnectionTasks::default(),
            edge_links: None,
            lease: None,
        }
    }

    /// The shutdown budget with the core's stop bounded by `core_stop`.
    fn budget_with_core_stop(core_stop: std::time::Duration) -> ShutdownBudget {
        ShutdownBudget {
            core_stop,
            driver_stop: SHUTDOWN_DRIVER_STOP_TIMEOUT,
            connection_drain: SHUTDOWN_CONNECTION_DRAIN_TIMEOUT,
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
                    // As a server does: answer the goodbye and close. The
                    // driver reads to that close (`say_goodbye`), so both are
                    // heard before shutdown completes, whatever the platform's
                    // scheduling; an upstream that never answers is bounded by
                    // the goodbye deadline instead.
                    heard_tx.send(Some(line)).await.unwrap();
                    writer
                        .write_all(b"ERROR :Closing Link: bncbot (Quit)\r\n")
                        .await
                        .unwrap();
                    writer.shutdown().await.unwrap();
                }
            }
            // End of stream: the driver closed its socket.
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
                    client_certificate: None,
                }],
                &std::collections::HashMap::new(),
                crate::bouncer::RegistryStorage::default(),
                crate::bouncer::CoreHandles {
                    core_tx: CoreIngress::single(core_tx),
                    next_conn: Arc::new(ConnectionIdAllocator::new(
                        std::num::NonZeroU64::new(1).unwrap(),
                    )),
                    sendq_bytes: 64 * 512,
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
        assert_eq!(handle.run(StopMode::Final).await, ShutdownOutcome::Flushed);
        // The goodbye was sent before `run` returned; the upstream may see
        // the close a moment later on its own task, so wait for it (bounded).
        // The test still holds the registry, so only the driver closing its
        // socket can end the upstream's stream.
        let mut heard = Vec::new();
        while heard.last() != Some(&None) {
            let line = tokio::time::timeout(std::time::Duration::from_secs(5), heard_rx.recv())
                .await
                .expect("the driver closed its socket during shutdown")
                .expect("the upstream reports what it read");
            heard.push(line);
        }
        assert_eq!(
            heard,
            vec![Some("QUIT :e6irc bouncer stopping".to_string()), None],
            "the upstream reads the goodbye, then the driver's close"
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
        let outcome = shutdown_handle(core_workers, flushed.clone())
            .run(StopMode::Final)
            .await;
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
                StopMode::Final,
                budget_with_core_stop(std::time::Duration::from_millis(100)),
            )
            .await;
        assert_eq!(outcome, ShutdownOutcome::CoreTimedOut);
        assert!(flushed.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// A shard whose queue is full and that takes nothing from it used to
    /// hold the shutdown request itself forever, before the core's stop
    /// budget had even started. The request is made within that budget; on
    /// its expiry the shards are ended and the database still flushes.
    #[tokio::test]
    async fn a_shard_that_will_not_take_the_shutdown_request_is_bounded_too() {
        let flushed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut core_workers = tokio::task::JoinSet::new();
        core_workers.spawn(std::future::pending());
        let mut handle = shutdown_handle(core_workers, flushed.clone());
        // A live shard queue, full, that nothing drains.
        let (core_tx, core_rx) = queue::<Input>(e6irc_queue::Config {
            name: "t-stuck-core",
            capacity: 1,
            policy: Policy::Fifo,
        });
        core_tx.try_push(Input::Shutdown).expect("room for one");
        handle.core_tx = Some(CoreIngress::single(core_tx));
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            handle.run_within(
                StopMode::Final,
                budget_with_core_stop(std::time::Duration::from_millis(100)),
            ),
        )
        .await
        .expect("shutdown must not wait on a shard that takes nothing");
        assert_eq!(outcome, ShutdownOutcome::CoreTimedOut);
        assert!(flushed.load(std::sync::atomic::Ordering::SeqCst));
        drop(core_rx);
    }

    /// Once the core has stopped, shutdown waits — bounded — for every
    /// connection task: returning while they still write would let the
    /// runtime's end cancel the clients' closing ERROR.
    #[tokio::test]
    async fn shutdown_waits_for_the_connection_tasks_within_its_bound() {
        let flushed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handle = shutdown_handle(tokio::task::JoinSet::new(), flushed);
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let task = handle.connections.task();
        let marker = finished.clone();
        tokio::spawn(async move {
            let _task = task;
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            marker.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        assert_eq!(handle.run(StopMode::Final).await, ShutdownOutcome::Flushed);
        assert!(finished.load(std::sync::atomic::Ordering::SeqCst));
        // One that never ends costs the bound, not forever.
        let flushed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handle = shutdown_handle(tokio::task::JoinSet::new(), flushed);
        let stuck = handle.connections.task();
        let started = tokio::time::Instant::now();
        let outcome = handle
            .run_within(
                StopMode::Final,
                ShutdownBudget {
                    connection_drain: std::time::Duration::from_millis(100),
                    ..budget_with_core_stop(SHUTDOWN_CORE_STOP_TIMEOUT)
                },
            )
            .await;
        assert_eq!(outcome, ShutdownOutcome::Flushed);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        drop(stuck);
    }

    /// A certificate the attach listener cannot load is the operator's
    /// configuration, not a client's failed handshake, and is counted so.
    #[tokio::test]
    async fn an_unloadable_attach_certificate_is_a_configuration_error() {
        install_crypto_provider();
        let telemetry = Arc::new(Telemetry::new());
        let (core_tx, _core_rx) = queue::<Input>(e6irc_queue::Config {
            name: "t-bnc-cert-core",
            capacity: 4,
            policy: Policy::Fifo,
        });
        let registry = Arc::new(
            crate::bouncer::Registry::start_observed(
                &[],
                &std::collections::HashMap::new(),
                crate::bouncer::RegistryStorage::default(),
                crate::bouncer::CoreHandles {
                    core_tx: CoreIngress::single(core_tx),
                    next_conn: Arc::new(ConnectionIdAllocator::new(
                        std::num::NonZeroU64::new(1).unwrap(),
                    )),
                    sendq_bytes: 64 * 512,
                },
                telemetry.clone(),
                crate::egress::InternalUpstreams::Allow,
            )
            .expect("registry"),
        );
        let controller = BncListenerController::new(
            BncAttachContext {
                registry,
                pool: sqlx::postgres::PgPoolOptions::new()
                    .connect_lazy("postgres://unused:unused@127.0.0.1/unused")
                    .expect("lazy pool"),
                server_name: "bnc.test".into(),
                limiter: ConnLimiter::new(None),
                telemetry: telemetry.clone(),
                connections: ConnectionTasks::default(),
                next_conn: Arc::new(ConnectionIdAllocator::new(std::num::NonZeroU64::MIN)),
                sendq_bytes: 64 * 512,
            },
            CertificateReloads::default(),
        );
        let missing = std::env::temp_dir().join(format!("e6irc-missing-{}", std::process::id()));
        let requested = BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: Some(TlsConfig {
                cert_path: missing.join("cert.pem"),
                key_path: missing.join("key.pem"),
            }),
        };
        assert!(controller.enable(&requested).await.is_err());
        let errors = telemetry.snapshot(0, 0).errors;
        assert_eq!(errors["configuration"], 1, "{errors:?}");
        assert_eq!(errors["tls_handshake"], 0, "{errors:?}");
    }

    /// A client still sending when its session ends — its input unread in
    /// the server's socket — reads its closing ERROR and an orderly end of
    /// stream. Closing a socket with unread input sends a reset instead, and
    /// a reset reaches the client as "connection reset" in place of the end
    /// (on some stacks in place of the ERROR itself).
    #[tokio::test]
    async fn a_client_still_sending_reads_its_error_and_an_orderly_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .expect("connect");
        let (server, peer) = listener.accept().await.expect("accept");
        // Nothing takes from the core queue: once it is full the reader stops
        // taking input, which piles up unread.
        let (core_tx, mut core_rx) = test_core_channel();
        let served = tokio::spawn(serve_conn(
            server,
            accepted(peer),
            CoreIngress::single(core_tx),
            Outbound::with_sendq(64 * 512),
            Arc::new(Telemetry::new()),
        ));
        let Input::Open { mut tx, .. } = core_rx.pop().await.expect("Open event").payload else {
            panic!("expected Open");
        };
        let (mut client_read, mut client_write) = client.into_split();
        let sender = tokio::spawn(async move {
            let junk = "PING :x\r\n".repeat(8 * 1024).into_bytes();
            for _ in 0..16 {
                if client_write.write_all(&junk).await.is_err() {
                    return;
                }
            }
            drop(client_write.shutdown().await);
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        tx.0.output(Output(bytes::Bytes::from_static(
            b"ERROR :Closing Link: 127.0.0.1 (Killed)\r\n",
        )))
        .expect("room");
        drop(tx);
        let mut received = Vec::new();
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client_read.read_to_end(&mut received),
        )
        .await
        .expect("the connection closes");
        assert_eq!(received, b"ERROR :Closing Link: 127.0.0.1 (Killed)\r\n");
        read.expect("an orderly end of stream, not a reset");
        served.await.expect("serve_conn task");
        drop(sender);
    }

    /// A reader that takes one byte every 10 ms, forever.
    async fn trickle(mut from: impl AsyncRead + Unpin) {
        let mut byte = [0u8; 1];
        while matches!(from.read(&mut byte).await, Ok(1)) {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// A session the core has ended is torn down within the closing drain,
    /// however slowly its client reads: the write deadline counts only a
    /// stall, and a client taking a byte every few milliseconds used to keep a
    /// killed session's socket, task and per-IP slot for as long as a full
    /// SendQ took it. Its reader stops at once, so nothing more it sends is
    /// pushed for — or counted against — a session the core has forgotten.
    #[tokio::test(start_paused = true)]
    async fn a_session_the_core_ended_stops_reading_and_drains_within_its_bound() {
        let (client, server) = tokio::io::duplex(64);
        let (client_read, mut client_write) = tokio::io::split(client);
        let (core_tx, mut core_rx) = queue::<Input>(e6irc_queue::Config {
            name: "t-closing-core",
            capacity: 65_536,
            policy: Policy::Fifo,
        });
        let closing_drain = std::time::Duration::from_secs(1);
        let served = tokio::spawn(serve_conn(
            server,
            accepted("127.0.0.1:5000".parse().unwrap()),
            CoreIngress::single(core_tx),
            Outbound {
                sendq_bytes: 4096 * 512,
                write_deadline: e6irc_edge::peer_write::PEER_WRITE_DEADLINE,
                closing_drain,
            },
            Arc::new(Telemetry::new()),
        ));
        let Input::Open { mut tx, .. } = core_rx.pop().await.expect("Open event").payload else {
            panic!("expected Open");
        };
        tokio::spawn(trickle(client_read));
        // The client keeps sending lines.
        tokio::spawn(async move {
            while client_write.write_all(b"PING :x\r\n").await.is_ok() {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        });
        let line = bytes::Bytes::from(format!("NOTICE * :{}\r\n", "x".repeat(400)));
        for _ in 0..100 {
            tx.0.output(Output(line.clone())).expect("room");
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        drop(tx);
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        while core_rx.try_pop().is_some() {}
        let ended = tokio::time::Instant::now();
        tokio::time::timeout(std::time::Duration::from_secs(60), served)
            .await
            .expect("the drain of an ended session is bounded as a whole")
            .expect("serve_conn task");
        assert!(ended.elapsed() <= closing_drain + std::time::Duration::from_millis(100));
        let pushed_after = std::iter::from_fn(|| core_rx.try_pop())
            .filter(|event| matches!(event.payload, Input::Line { .. }))
            .count();
        assert_eq!(pushed_after, 0, "the reader stopped with the session");
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
        let (out_tx, mut out_rx) = crate::core::send_queue("t-sendq", 64 * 512);
        core_tx
            .push(Input::Open {
                conn: ConnId(1),
                tx: out_tx,
                host: "host.test".into(),
                transport: crate::core::ConnectionTransport::Tcp,
                tls: None,
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

    /// The credit a line waits for is room in the core's queue, granted first
    /// come first served (DESIGN §19.2): a session streaming lines into a
    /// full core waits in line like any other, so a quiet session's one line
    /// is taken after at most the noisy session's line that was already
    /// waiting — one session cannot starve the rest.
    #[tokio::test]
    async fn a_noisy_session_cannot_starve_a_quiet_one_of_credit() {
        let (core_tx, mut core_rx) = queue::<Input>(e6irc_queue::Config {
            name: "t-credit",
            capacity: 1,
            policy: Policy::Fifo,
        });
        let ingress = CoreIngress::single(core_tx);
        let telemetry = Arc::new(Telemetry::new());
        let unmetered = || {
            e6irc_edge::meter::LineMeter::new(
                None,
                e6irc_edge::meter::FloodExemption::default(),
                tokio::time::Instant::now(),
            )
        };
        let (mut noisy_client, noisy_server) = tokio::io::duplex(1024 * 1024);
        noisy_client
            .write_all("PING :noise\r\n".repeat(1000).as_bytes())
            .await
            .expect("write");
        let noisy = {
            let (ingress, telemetry) = (ingress.clone(), telemetry.clone());
            let meter = unmetered();
            tokio::spawn(async move {
                read_loop(noisy_server, ConnId(1), &ingress, meter, &*telemetry).await;
            })
        };
        // The noisy session has filled the queue and waits for room.
        while core_rx.depth() == 0 {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let (mut quiet_client, quiet_server) = tokio::io::duplex(1024);
        quiet_client
            .write_all(b"PING :quiet\r\n")
            .await
            .expect("write");
        let quiet = {
            let (ingress, telemetry) = (ingress.clone(), telemetry.clone());
            let meter = unmetered();
            tokio::spawn(async move {
                read_loop(quiet_server, ConnId(2), &ingress, meter, &*telemetry).await;
            })
        };
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let mut before_quiet = 0;
        loop {
            let event = tokio::time::timeout(std::time::Duration::from_secs(5), core_rx.pop())
                .await
                .expect("an event")
                .expect("ingress open");
            match event.payload {
                Input::Line {
                    conn: ConnId(2), ..
                } => break,
                Input::Line {
                    conn: ConnId(1), ..
                } => before_quiet += 1,
                other => panic!("{other:?}"),
            }
        }
        assert!(
            before_quiet <= 2,
            "{before_quiet} noisy lines were admitted ahead of the quiet one"
        );
        noisy.abort();
        quiet.abort();
        drop((noisy_client, quiet_client));
    }

    /// A client streaming lines — PONGs, before it has even registered — gets
    /// no more of them into the core's queue than its command allowance: past
    /// its bucket its reader stops reading the socket until a token is back,
    /// and the rest wait in the client's own socket buffers.
    #[tokio::test(start_paused = true)]
    async fn a_client_streaming_pongs_gets_only_its_allowance_into_the_core_queue() {
        let (core_tx, mut core_rx) = queue::<Input>(e6irc_queue::Config {
            name: "t-core",
            capacity: 65536,
            policy: Policy::Fifo,
        });
        let ingress = CoreIngress::single(core_tx)
            .with_command_flood(crate::core::CommandFlood::new(40, 20).expect("valid bucket"));
        let (mut client, server) = tokio::io::duplex(1024 * 1024);
        client
            .write_all("PONG :x\r\n".repeat(5000).as_bytes())
            .await
            .expect("write");
        let telemetry = Telemetry::new();
        let meter = e6irc_edge::meter::LineMeter::new(
            e6irc_edge::connection::CorePort::command_flood(&ingress),
            e6irc_edge::meter::FloodExemption::default(),
            tokio::time::Instant::now(),
        );
        let reader = read_loop(server, ConnId(1), &ingress, meter, &telemetry);
        tokio::pin!(reader);
        let queued = |rx: &mut Receiver<Input>| {
            std::iter::from_fn(|| rx.try_pop())
                .filter(|envelope| matches!(envelope.payload, Input::Line { .. }))
                .count()
        };
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), &mut reader)
                .await
                .is_err(),
            "the reader is still reading"
        );
        assert_eq!(queued(&mut core_rx), 40, "one burst at once");
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), &mut reader)
                .await
                .is_err(),
            "the reader is still reading"
        );
        let second = queued(&mut core_rx);
        assert!(
            (19..=21).contains(&second),
            "then twenty a second, not {second}"
        );
    }
}
