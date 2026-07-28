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
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::config::{Config, TlsConfig};
use crate::core::{ConnId, Core, CoreConfig, Input, Output};
use crate::observability::{ErrorKind, Telemetry};
use e6irc_proto::framing::{LineBuffer, LineEvent};
use e6irc_queue::{Policy, Receiver, Sender, queue};

/// Traditional 512-byte line minus CRLF, plus the 4096-byte client tag
/// allowance (message-tags spec); the body-only limit is enforced in
/// the core after the tag section is split off.
const LINE_LIMIT: usize = e6irc_proto::message::MAX_CLIENT_FRAME_LEN;
const READ_BUF: usize = 4096;
/// How often the liveness reaper tick fires (seconds); the reaper's own
/// deadlines are coarse minutes, so a fine tick isn't needed.
const REAP_TICK_SECS: u64 = 15;

/// Cap on the TLS handshake. `Input::Open` only reaches the core — and thus the
/// liveness reaper — *after* the handshake completes, so a peer that finishes
/// the TCP connect but never sends (or dribbles) a ClientHello would otherwise
/// hold a task, an fd, and its per-IP slot indefinitely, invisible to the
/// reaper. A plaintext peer has no such window (it hits `serve_conn` at once).
/// A real handshake completes in well under a second; 30s matches the
/// registration budget a plaintext peer already gets.
const TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 30;

/// How long graceful shutdown waits for the DB worker to drain and flush its
/// buffered history before giving up. A healthy flush is a single batched
/// INSERT (milliseconds); this bound only bites if PostgreSQL is wedged, in
/// which case we exit with a non-success code rather than hang a service
/// restart forever.
const SHUTDOWN_DB_FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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

/// Everything `main` needs to shut the server down cleanly on SIGTERM/SIGINT.
/// Built by [`start`]; see [`ShutdownHandle::run`] for the sequence.
pub struct ShutdownHandle {
    /// Accept-loop tasks (IRC listeners, the HTTP server, the BNC listener).
    /// Aborted first so no new connection is admitted mid-shutdown.
    listeners: Vec<tokio::task::AbortHandle>,
    /// The core worker's input sender. Pushing [`Input::Shutdown`] makes the
    /// core notify clients and then stop, which drops the DB request sender.
    core_tx: Sender<Input>,
    /// The DB worker task, awaited (bounded) so its buffered `log_batch` reaches
    /// PostgreSQL before exit. `None` when no `[database]` is configured (there
    /// is then no worker and nothing buffered to lose).
    db_worker: Option<tokio::task::JoinHandle<()>>,
    /// Runtime-managed BNC listener. Unlike the bootstrap listeners, this can
    /// be replaced from the console, so shutdown must address the controller
    /// rather than only the task that happened to exist at startup.
    bnc_listener: Option<Arc<BncListenerController>>,
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
}

impl ShutdownHandle {
    /// Run the graceful-shutdown sequence (DESIGN §18): stop accepting new
    /// connections, ask the core to notify clients and stop, then wait for the
    /// DB worker to flush its buffered history. Returns once the worker has
    /// drained or the bounded timeout elapses.
    pub async fn run(self) -> ShutdownOutcome {
        // 1. Stop accepting: abort every listener task up front so nothing new
        //    is admitted while we drain.
        for listener in &self.listeners {
            listener.abort();
        }
        if let Some(listener) = &self.bnc_listener {
            listener.stop().await;
        }
        // 2. Tell the core to notify clients (terminal ERROR) and stop. A push
        //    failure can only mean the core queue is already closed, i.e. the
        //    core is already gone — nothing more to ask of it.
        // Queue closure means the core already stopped, which is the requested
        // shutdown state.
        drop(self.core_tx.push(Input::Shutdown).await);
        // Drop our own sender clone so it isn't left keeping the core queue's
        // producer count up. (The core breaks on the Shutdown event regardless;
        // this just keeps the shutdown intent honest.)
        drop(self.core_tx);
        // 3. Wait for the DB worker to observe its now-dropped sender, drain,
        //    and flush. Bounded so a wedged database can't hang the shutdown.
        let Some(worker) = self.db_worker else {
            return ShutdownOutcome::Flushed;
        };
        match tokio::time::timeout(SHUTDOWN_DB_FLUSH_TIMEOUT, worker).await {
            Ok(Ok(())) => ShutdownOutcome::Flushed,
            Ok(Err(_join_err)) => ShutdownOutcome::WorkerPanicked,
            Err(_elapsed) => ShutdownOutcome::FlushTimedOut,
        }
    }
}

#[derive(Debug)]
struct BncListenerState {
    requested: SocketAddr,
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
}

impl BncListenerController {
    fn new(
        registry: Arc<crate::bouncer::Registry>,
        pool: sqlx::PgPool,
        server_name: String,
        limiter: ConnLimiter,
        telemetry: Arc<Telemetry>,
    ) -> Self {
        Self {
            state: tokio::sync::Mutex::new(None),
            registry,
            pool,
            server_name,
            limiter,
            telemetry,
        }
    }

    /// The configured and effective listener addresses, when enabled.
    pub async fn status(&self) -> Option<(SocketAddr, SocketAddr)> {
        self.state
            .lock()
            .await
            .as_ref()
            .map(|state| (state.requested, state.bound))
    }

    /// Enable or atomically replace the listener. The old listener remains
    /// active when the new address cannot be bound.
    pub async fn enable(&self, requested: SocketAddr) -> io::Result<SocketAddr> {
        let listener = TcpListener::bind(requested).await.inspect_err(|_error| {
            self.telemetry.record_error(ErrorKind::Bouncer);
        })?;
        let bound = listener.local_addr().inspect_err(|_error| {
            self.telemetry.record_error(ErrorKind::ConnectionSetup);
        })?;
        let task = spawn_bnc_listener(
            listener,
            self.registry.clone(),
            self.pool.clone(),
            self.server_name.clone(),
            self.limiter.clone(),
            self.telemetry.clone(),
        );
        let replacement = BncListenerState {
            requested,
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
                    let Some(guard) = limiter.try_acquire(peer.ip()) else {
                        telemetry.record_connection_rejected();
                        eprintln!("bnc refused {peer}: per-IP connection limit reached");
                        continue;
                    };
                    let registry = registry.clone();
                    let server_name = server_name.clone();
                    let pool = pool.clone();
                    let telemetry = telemetry.clone();
                    tokio::spawn(async move {
                        let _guard = guard;
                        let _observed_connection = telemetry.observe_bnc_client();
                        if let Err(e) = stream.set_nodelay(true) {
                            telemetry.record_error(ErrorKind::ConnectionSetup);
                            eprintln!("bnc socket setup failed for {peer}: {e}");
                            return;
                        }
                        if let Err(e) =
                            crate::bouncer::bnc_serve(stream, registry, &pool, &server_name).await
                        {
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

/// Bind all listeners, spawn the core worker and acceptor tasks.
pub async fn start(mut config: Config) -> io::Result<Running> {
    install_crypto_provider();
    // Resolve once and reuse for the control-plane import plus BNC secrets.
    // UI-managed OIDC/operator credentials are always sealed in PostgreSQL.
    let secret_key = config.secret_key().map_err(io::Error::other)?.map(Arc::new);
    // Load persisted settings before constructing anything that consumes
    // them. In particular, a queue's capacity cannot be changed after the
    // queue exists; loading `core_queue` later would make that console setting
    // a permanent no-op.
    let (pool, managed_config) = match config.database.as_ref().map(|db| db.url.clone()) {
        Some(database_url) => {
            let pool = crate::db::connect_and_migrate(&database_url)
                .await
                .map_err(io::Error::other)?;
            let imported =
                crate::config::ManagedConfig::from_config(&config, secret_key.as_deref())
                    .map_err(io::Error::other)?;
            let mut snapshot = crate::db::load_or_initialize_managed_config(&pool, &imported)
                .await
                .map_err(io::Error::other)?;
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
            (Some(pool), Some(snapshot))
        }
        None => (None, None),
    };

    let (core_tx, core_rx) = queue::<Input>(e6irc_queue::Config {
        name: "core",
        capacity: config.core_queue,
        policy: Policy::Fifo,
    });
    let (db_tx, db_rx) = queue::<crate::core::DbRequest>(e6irc_queue::Config {
        name: "db",
        capacity: 1024,
        policy: Policy::Fifo,
    });
    let telemetry = Arc::new(Telemetry::new());
    let managed_config =
        managed_config.map(|snapshot| Arc::new(tokio::sync::RwLock::new(snapshot)));
    // SASL is only advertised when a database exists to answer verification
    // requests. Keep the worker handle so graceful shutdown can guarantee its
    // buffered `log_batch` is flushed before the process exits (DESIGN §18).
    let sasl_enabled = pool.is_some();
    let db_worker = match &pool {
        Some(pool) => Some(tokio::spawn(crate::db::run_worker_observed(
            pool.clone(),
            db_rx,
            core_tx.clone(),
            telemetry.clone(),
        ))),
        None => {
            drop(db_rx);
            None
        }
    };

    // Accept-loop tasks, collected so shutdown can stop admitting connections.
    let mut listeners: Vec<tokio::task::AbortHandle> = Vec::new();

    let next_conn = Arc::new(AtomicU64::new(1));

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
            )
            .map_err(io::Error::other)?,
        );
        if let Some(pool) = &pool {
            for (owner, row) in crate::db::list_all_bnc_networks(pool)
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
                match crate::bouncer::driver_from_row(&row, secret_key.as_deref(), &owner) {
                    Ok(driver) => reg.add(Some(&owner), &row.name, driver),
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

    // One per-IP connection cap shared by the TCP IRC listeners and the
    // IRC-over-WebSocket path, so a client can't sidestep the cap by opening
    // its sessions through /ws/irc instead of the raw port.
    let limiter = ConnLimiter::new(config.limits.max_connections_per_ip);

    // Database-backed network management and the attach listener are separate
    // capabilities. The registry exists as soon as persistence does; the
    // listener can then be enabled or rebound from the console without
    // reconstructing every always-on upstream.
    let bnc_listener = match (&pool, &bnc_registry) {
        (Some(pool), Some(registry)) => Some(Arc::new(BncListenerController::new(
            registry.clone(),
            pool.clone(),
            config.server_name.clone(),
            limiter.clone(),
            telemetry.clone(),
        ))),
        _ => None,
    };
    let mut bnc_addr = None;
    if let Some(bnc) = &config.bnc {
        let controller = bnc_listener
            .as_ref()
            .expect("config validation guarantees [database] when [bnc] is set");
        bnc_addr = Some(controller.enable(bnc.addr).await?);
    }
    if let (Some(pool), Some(settings)) = (&pool, &managed_config) {
        tokio::spawn(crate::observability::run_sampler(
            pool.clone(),
            telemetry.clone(),
            bnc_registry.clone(),
            settings.clone(),
        ));
    }

    // One shared HTTP `AppState`, built when either the HTTP server or any
    // dedicated websocket-IRC listener needs it, so both serve against the same
    // core, per-IP limiter and sendq. A websocket listener with no `[http]`
    // section still gets a state (with HTTP-UI fields defaulted — they are
    // unused by the WS-IRC router).
    let any_ws_listener = config.listeners.iter().any(|l| l.websocket);
    let app_state: Option<Arc<crate::http::AppState>> = if config.http.is_some() || any_ws_listener
    {
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
        let (public_url, secure_cookies, admin_accounts) = match &config.http {
            Some(h) => (
                h.public_url.clone(),
                h.secure_cookies,
                h.admin_accounts
                    .iter()
                    .map(|a| e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(a))
                    .collect(),
            ),
            None => (None, false, std::collections::HashSet::new()),
        };
        Some(Arc::new(crate::http::AppState {
            server_name: config.server_name.clone(),
            network_name: config.network_name.clone(),
            pool: pool.clone(),
            public_url,
            http_bind: config.http.as_ref().map(|http| http.addr),
            secure_cookies,
            oidc_providers: config.oidc_providers.clone(),
            application_release_revision: config.application_release_revision.clone(),
            pending_auth: crate::http::AppState::no_pending_auth(),
            core_tx: core_tx.clone(),
            next_conn: next_conn.clone(),
            sendq: config.sendq,
            bnc_registry: bnc_registry.clone(),
            bnc_listener: bnc_listener.clone(),
            managed_config: managed_config.clone(),
            telemetry: telemetry.clone(),
            secret_key: secret_key.clone(),
            admin_accounts,
            csrf_key: {
                use aws_lc_rs::rand::SecureRandom;
                let mut k = [0u8; 32];
                aws_lc_rs::rand::SystemRandom::new()
                    .fill(&mut k)
                    .expect("system RNG for CSRF key");
                k
            },
            trusted_proxies,
            auth_rate_burst: config.limits.auth_rate_burst,
            auth_buckets: std::sync::Mutex::new(std::collections::HashMap::new()),
            conn_limiter: limiter.clone(),
        }))
    } else {
        None
    };

    let http_addr = match &config.http {
        Some(http_config) => {
            let listener = TcpListener::bind(http_config.addr).await?;
            let bound = listener.local_addr()?;
            let state = app_state
                .clone()
                .expect("app_state is built whenever [http] is set");
            let http_task = tokio::spawn(async move {
                // `ConnectInfo<SocketAddr>` so handlers can see the socket peer
                // (for rate limiting / X-Forwarded-For client-IP resolution).
                let service = crate::http::router(state)
                    .into_make_service_with_connect_info::<std::net::SocketAddr>();
                if let Err(e) = axum::serve(listener, service).await {
                    eprintln!("http server exited: {e}");
                }
            });
            listeners.push(http_task.abort_handle());
            Some(bound)
        }
        None => None,
    };

    let mut core = Core::with_telemetry(
        CoreConfig {
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
            command_burst: config.limits.command_burst,
            registration_burst: config.limits.registration_burst,
        },
        db_tx,
        telemetry.clone(),
    );
    // Seed registered-channel ownership and retained topics so a founder
    // is re-opped and the topic restored on join after a restart, not only
    // within the run that registered them.
    if let Some(pool) = &pool {
        core.preload_founders(
            crate::db::list_registered_channels(pool)
                .await
                .map_err(io::Error::other)?,
        );
        core.preload_topics(
            crate::db::list_channel_topics(pool)
                .await
                .map_err(io::Error::other)?,
        );
        core.preload_keeptopic_off(
            crate::db::list_keeptopic_off(pool)
                .await
                .map_err(io::Error::other)?,
        );
        core.preload_mlock(
            crate::db::list_channel_mlock(pool)
                .await
                .map_err(io::Error::other)?,
        );
        core.preload_access(
            crate::db::list_channel_access(pool)
                .await
                .map_err(io::Error::other)?,
        );
        core.preload_server_bans(
            crate::db::list_server_bans(pool)
                .await
                .map_err(io::Error::other)?,
        );
        // The read-marker mirror must be seeded too, or MARKREAD queries report
        // `*` after a restart and a stale set could move a marker backwards.
        core.preload_read_markers(
            crate::db::list_all_read_markers(pool)
                .await
                .map_err(io::Error::other)?
                .into_iter()
                .map(|(account, target, ms)| {
                    (
                        account,
                        target,
                        e6irc_proto::time::Millis::from_millis(ms.max(0) as u64),
                    )
                })
                .collect(),
        );
    }
    tokio::spawn(core_worker(core, core_rx));

    // Liveness reaper tick: drives the core's registration deadline and idle
    // PING/PONG timeout so a silent connection can't hold a session forever.
    {
        let core_tx = core_tx.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(REAP_TICK_SECS));
            loop {
                ticker.tick().await;
                if core_tx
                    .push(Input::Tick { now: mono_clock() })
                    .await
                    .is_err()
                {
                    break; // core gone
                }
            }
        });
    }

    let mut addrs = Vec::new();
    for listener_config in &config.listeners {
        let listener = TcpListener::bind(listener_config.addr).await?;
        addrs.push(listener.local_addr()?);
        if listener_config.websocket {
            // A dedicated WS-IRC listener: serve the ws-irc router at the root
            // path (`ws://addr/`) against the shared core, instead of the raw
            // TCP accept loop. Same per-IP cap (it lives in the shared state).
            let state = app_state
                .clone()
                .expect("app_state is built whenever a websocket listener is set");
            let ws_task = tokio::spawn(async move {
                let service = crate::http::ws_irc_router(state)
                    .into_make_service_with_connect_info::<std::net::SocketAddr>();
                if let Err(e) = axum::serve(listener, service).await {
                    eprintln!("ws-irc listener exited: {e}");
                }
            });
            listeners.push(ws_task.abort_handle());
            continue;
        }
        let acceptor = match &listener_config.tls {
            Some(tls) => Some(tls_acceptor(tls)?),
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
        listeners.push(accept_task.abort_handle());
    }
    Ok(Running {
        addrs,
        http_addr,
        bnc_addr,
        shutdown: ShutdownHandle {
            listeners,
            core_tx,
            db_worker,
            bnc_listener,
        },
    })
}

fn tls_acceptor(tls: &TlsConfig) -> io::Result<TlsAcceptor> {
    use rustls_pki_types::pem::PemObject;
    let certs: Vec<_> = rustls_pki_types::CertificateDer::pem_file_iter(&tls.cert_path)
        .map_err(pem_err)?
        .collect::<Result<_, _>>()
        .map_err(pem_err)?;
    let key = rustls_pki_types::PrivateKeyDer::from_pem_file(&tls.key_path).map_err(pem_err)?;
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

fn pem_err(e: rustls_pki_types::pem::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("TLS PEM: {e}"))
}

async fn core_worker(mut core: Core, mut rx: Receiver<Input>) {
    while let Some(envelope) = rx.pop().await {
        // `Shutdown` is handled (clients are notified) and then ends the loop.
        // Returning drops `core` — and with it the sole `Sender<DbRequest>` and
        // every session's `Sender<Output>` — which is what lets the DB worker
        // drain/flush and the write tasks deliver the ERROR before we exit.
        let stop = matches!(envelope.payload, Input::Shutdown);
        core.handle(envelope.payload);
        if stop {
            return;
        }
    }
}

/// Per-IP concurrent-connection cap. When `max_per_ip` is `None` the
/// limiter is a no-op; otherwise it refuses connections beyond the cap
/// and releases the slot when the connection's guard drops.
#[derive(Clone)]
pub(crate) struct ConnLimiter {
    counts: Arc<std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, usize>>>,
    max_per_ip: Option<usize>,
}

impl ConnLimiter {
    pub(crate) fn new(max_per_ip: Option<usize>) -> Self {
        Self {
            counts: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            max_per_ip,
        }
    }

    /// Reserve a slot for `ip`, or `None` if it is already at the cap.
    pub(crate) fn try_acquire(&self, ip: std::net::IpAddr) -> Option<ConnGuard> {
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

    fn release(&self, ip: std::net::IpAddr) {
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
    ip: std::net::IpAddr,
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
    core_tx: Sender<Input>,
    next_conn: Arc<AtomicU64>,
    sendq: usize,
    limiter: ConnLimiter,
    telemetry: Arc<Telemetry>,
) {
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
        // Enforce the per-IP cap before spending a ConnId or a task. The
        // guard is held for the connection's lifetime and frees the slot
        // on drop.
        let Some(guard) = limiter.try_acquire(peer.ip()) else {
            eprintln!("refused {peer}: per-IP connection limit reached");
            telemetry.record_connection_rejected();
            drop(stream); // closes the socket; the client sees EOF
            continue;
        };
        let conn = ConnId(next_conn.fetch_add(1, Ordering::Relaxed));
        let core_tx = core_tx.clone();
        let tls = tls.clone();
        let telemetry = telemetry.clone();
        tokio::spawn(async move {
            let _guard = guard; // released when this task ends
            if let Err(e) = stream.set_nodelay(true) {
                eprintln!("socket setup failed for {peer}: {e}");
                telemetry.record_error(ErrorKind::ConnectionSetup);
                return;
            }
            match tls {
                Some(acceptor) => {
                    // Bound the handshake so a stalled TLS peer can't hold this
                    // task/fd/slot forever below the reaper's line of sight.
                    let handshake = tokio::time::timeout(
                        std::time::Duration::from_secs(TLS_HANDSHAKE_TIMEOUT_SECS),
                        acceptor.accept(stream),
                    )
                    .await;
                    match handshake {
                        Ok(Ok(tls_stream)) => {
                            serve_conn(tls_stream, conn, peer, core_tx, sendq, telemetry).await
                        }
                        Ok(Err(e)) => {
                            telemetry.record_error(ErrorKind::TlsHandshake);
                            eprintln!("TLS handshake failed from {peer}: {e}");
                        }
                        Err(_) => {
                            telemetry.record_error(ErrorKind::TlsHandshake);
                            eprintln!("TLS handshake from {peer} timed out");
                        }
                    }
                }
                None => serve_conn(stream, conn, peer, core_tx, sendq, telemetry).await,
            }
        });
    }
}

async fn serve_conn<S>(
    stream: S,
    conn: ConnId,
    peer: SocketAddr,
    core_tx: Sender<Input>,
    sendq: usize,
    telemetry: Arc<Telemetry>,
) where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (read_half, write_half) = tokio::io::split(stream);
    let (out_tx, out_rx) = queue::<Output>(e6irc_queue::Config {
        name: "sendq",
        capacity: sendq,
        policy: Policy::Fifo,
    });
    if core_tx
        .push(Input::Open {
            conn,
            tx: out_tx,
            // Canonicalize an IPv4-mapped IPv6 peer (`::ffff:1.2.3.4`) to its IPv4
            // form at this single ingress point. A dual-stack (`[::]`) listener
            // presents every IPv4 client mapped, so without this a `DLINE
            // 1.2.3.4` (or `KLINE *@1.2.3.4`) an operator writes in natural IPv4
            // notation would not match the `::ffff:1.2.3.4` subject `ban_match`
            // tests — a silent ban evasion — and WHOIS would show the mapped
            // spelling. Mirrors the outbound SSRF canonicalization in `networks`.
            host: peer.ip().to_canonical().to_string(),
        })
        .await
        .is_err()
    {
        return; // core gone: shutting down
    }
    let mut writer = tokio::spawn(write_loop(write_half, out_rx, telemetry.clone()));
    tokio::select! {
        // The client closed/errored, or the core queue is gone: the read side
        // is done — stop the (possibly parked) writer.
        () = read_loop(read_half, conn, &core_tx, &telemetry) => writer.abort(),
        // The writer returned. Two causes: the core dropped this session's
        // `Sender<Output>` (session already gone core-side), OR a *write error*
        // on a still-present session (broken pipe / RST while output was queued).
        // Cancelling the read future frees a dead peer's read task and per-IP
        // ConnGuard now rather than at the OS TCP timeout — but it also cancels
        // the only other path that would push `Input::Closed`, so we must push it
        // here. `close` is idempotent, so the already-gone case is a harmless
        // no-op; the write-error case is cleaned up now instead of lingering as a
        // ghost session (silently black-holing messages sent to it) until the
        // reaper collects it ~180s later.
        reason = &mut writer => {
            let reason = reason.unwrap_or("Write task panicked");
            // Queue closure means the core has already removed all connection
            // state, so there is no remaining observer for this close event.
            drop(
                core_tx
                    .push(Input::Closed {
                        conn,
                        reason: reason.to_string(),
                    })
                    .await,
            );
        }
    }
}

async fn read_loop<R>(
    mut read_half: R,
    conn: ConnId,
    core_tx: &Sender<Input>,
    telemetry: &Telemetry,
) where
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
                for event in events.drain(..) {
                    let input = match event {
                        LineEvent::Line(line) => Input::Line { conn, line },
                        LineEvent::TooLong => Input::OverlongLine { conn },
                    };
                    if core_tx.push(input).await.is_err() {
                        return; // core gone
                    }
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
    loop {
        let Some(envelope) = rx.pop().await else {
            // Core dropped the session (sender gone): flush and close.
            drop(write_half.shutdown().await);
            return "Connection closed";
        };
        // Coalesce everything currently queued into one syscall.
        let mut batch: Vec<u8> = Vec::new();
        batch.extend_from_slice(&envelope.payload.0);
        while let Some(e) = rx.try_pop() {
            batch.extend_from_slice(&e.payload.0);
        }
        if write_half.write_all(&batch).await.is_err() {
            telemetry.record_error(ErrorKind::Write);
            return "Write error"; // broken pipe / RST: the session is still live
        }
        if write_half.flush().await.is_err() {
            telemetry.record_error(ErrorKind::Write);
            return "Write error";
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Input;
    use std::pin::Pin;
    use std::task::{Context, Poll};

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
        let (core_tx, mut core_rx) = test_core_channel();
        let peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let served = tokio::spawn(serve_conn(
            DeadPeer,
            ConnId(1),
            peer,
            core_tx,
            8,
            Arc::new(Telemetry::new()),
        ));

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
        let (core_tx, mut core_rx) = test_core_channel();
        let peer: SocketAddr = "[::ffff:203.0.113.7]:5000".parse().unwrap();
        let served = tokio::spawn(serve_conn(
            DeadPeer,
            ConnId(1),
            peer,
            core_tx,
            8,
            Arc::new(Telemetry::new()),
        ));
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
            command_burst: None,
            registration_burst: None,
        }
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
        let worker = tokio::spawn(core_worker(core, core_rx));

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
