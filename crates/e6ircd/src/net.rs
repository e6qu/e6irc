//! Socket layer: listeners and per-connection I/O tasks. This is the
//! only module that touches the network; everything inward is queues.
//!
//! Data flow per connection:
//!   socket reads → LineBuffer → `push().await` into the core queue
//!     (await = backpressure: a full core stops socket reads)
//!   core → per-connection SendQ → writer half → socket
//!     (SendQ overflow = core dooms the connection)

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::config::{Config, TlsConfig};
use crate::core::{ConnId, Core, CoreConfig, Input, Output};
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

pub struct Running {
    /// Bound IRC addresses, in listener-config order (useful with port 0).
    pub addrs: Vec<SocketAddr>,
    /// Bound HTTP address, when the http listener is configured.
    pub http_addr: Option<SocketAddr>,
    /// Bound BNC listener address, when configured.
    pub bnc_addr: Option<SocketAddr>,
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
pub async fn start(config: Config) -> io::Result<Running> {
    install_crypto_provider();
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
    // SASL is only advertised when a database exists to answer
    // verification requests.
    let mut pool = None;
    let sasl_enabled = match &config.database {
        Some(db_config) => {
            let p = crate::db::connect_and_migrate(&db_config.url)
                .await
                .map_err(io::Error::other)?;
            tokio::spawn(crate::db::run_worker(p.clone(), db_rx, core_tx.clone()));
            pool = Some(p);
            true
        }
        None => {
            drop(db_rx);
            false
        }
    };

    let next_conn = Arc::new(AtomicU64::new(1));

    // Master key for sealing/opening BNC upstream secrets, resolved once.
    let secret_key = config.secret_key().map_err(io::Error::other)?.map(Arc::new);

    // The BNC registry is shared between the HTTP management API (which
    // adds/removes networks) and the BNC listener (which attaches to
    // them). Server-level [[network]]s start first, then each account's
    // persisted networks are loaded and started.
    let bnc_registry = if config.bnc.is_some() {
        let reg = Arc::new(
            crate::bouncer::Registry::start(
                &config.networks,
                pool.clone(),
                crate::bouncer::CoreHandles {
                    core_tx: core_tx.clone(),
                    next_conn: next_conn.clone(),
                    sendq: config.sendq,
                },
            )
            .map_err(io::Error::other)?,
        );
        if let Some(pool) = &pool {
            for (owner, row) in crate::db::list_all_bnc_networks(pool)
                .await
                .map_err(io::Error::other)?
            {
                let cfg = crate::bouncer::network_config_from_row(&row, secret_key.as_deref())
                    .map_err(io::Error::other)?;
                reg.add(
                    Some(&owner),
                    &row.name,
                    Box::new(crate::bouncer::IrcDriver::new(cfg)),
                );
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

    let http_addr = match &config.http {
        Some(http_config) => {
            let listener = TcpListener::bind(http_config.addr).await?;
            let bound = listener.local_addr()?;
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
            let router = crate::http::router(crate::http::AppState {
                server_name: config.server_name.clone(),
                network_name: config.network_name.clone(),
                pool: pool.clone(),
                public_url: http_config.public_url.clone(),
                secure_cookies: http_config.secure_cookies,
                oidc_providers: config.oidc_providers.clone(),
                application_release_revision: config.application_release_revision.clone(),
                pending_auth: crate::http::AppState::no_pending_auth(),
                core_tx: core_tx.clone(),
                next_conn: next_conn.clone(),
                sendq: config.sendq,
                bnc_registry: bnc_registry.clone(),
                secret_key: secret_key.clone(),
                admin_accounts: http_config
                    .admin_accounts
                    .iter()
                    .map(|a| e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(a))
                    .collect(),
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
            });
            tokio::spawn(async move {
                // `ConnectInfo<SocketAddr>` so handlers can see the socket peer
                // (for rate limiting / X-Forwarded-For client-IP resolution).
                let service = router.into_make_service_with_connect_info::<std::net::SocketAddr>();
                if let Err(e) = axum::serve(listener, service).await {
                    eprintln!("http server exited: {e}");
                }
            });
            Some(bound)
        }
        None => None,
    };

    let mut core = Core::new(
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
            command_burst: config.limits.command_burst,
        },
        db_tx,
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
                    .push(Input::Tick { now: wall_clock() })
                    .await
                    .is_err()
                {
                    break; // core gone
                }
            }
        });
    }

    // BNC listener: clients attach to always-on upstream networks.
    let mut bnc_addr = None;
    if let Some(bnc) = &config.bnc {
        // The BNC authenticates attaching clients against the account
        // store, so a database is required (enforced by config::validate).
        let pool = pool
            .clone()
            .expect("config validation guarantees [database] when [bnc] is set");
        let registry = bnc_registry
            .clone()
            .expect("registry is built whenever [bnc] is set");
        let listener = TcpListener::bind(bnc.addr).await?;
        bnc_addr = Some(listener.local_addr()?);
        let server_name = config.server_name.clone();
        // Same per-IP cap the IRC listeners apply, so an unauthenticated peer
        // can't open unbounded BNC connections.
        let bnc_limiter = ConnLimiter::new(config.limits.max_connections_per_ip);
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let Some(guard) = bnc_limiter.try_acquire(peer.ip()) else {
                            // At the per-IP cap: drop it, logging like the IRC
                            // accept loop rather than dropping silently.
                            eprintln!("bnc refused {peer}: per-IP connection limit reached");
                            continue;
                        };
                        let registry = registry.clone();
                        let server_name = server_name.clone();
                        let pool = pool.clone();
                        tokio::spawn(async move {
                            let _guard = guard; // released when the connection ends
                            let _ = stream.set_nodelay(true);
                            let _ =
                                crate::bouncer::bnc_serve(stream, registry, &pool, &server_name)
                                    .await;
                        });
                    }
                    Err(e) => {
                        eprintln!("bnc accept error: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        });
    }

    let mut addrs = Vec::new();
    for listener_config in &config.listeners {
        let listener = TcpListener::bind(listener_config.addr).await?;
        addrs.push(listener.local_addr()?);
        let acceptor = match &listener_config.tls {
            Some(tls) => Some(tls_acceptor(tls)?),
            None => None,
        };
        tokio::spawn(accept_loop(
            listener,
            acceptor,
            core_tx.clone(),
            next_conn.clone(),
            config.sendq,
            limiter.clone(),
        ));
    }
    Ok(Running {
        addrs,
        http_addr,
        bnc_addr,
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
        core.handle(envelope.payload);
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
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                // Transient accept errors (EMFILE etc.) must not kill
                // the listener; retrying is the correct handling.
                eprintln!("accept error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        // Enforce the per-IP cap before spending a ConnId or a task. The
        // guard is held for the connection's lifetime and frees the slot
        // on drop.
        let Some(guard) = limiter.try_acquire(peer.ip()) else {
            eprintln!("refused {peer}: per-IP connection limit reached");
            drop(stream); // closes the socket; the client sees EOF
            continue;
        };
        let conn = ConnId(next_conn.fetch_add(1, Ordering::Relaxed));
        let core_tx = core_tx.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let _guard = guard; // released when this task ends
            let _ = stream.set_nodelay(true);
            match tls {
                Some(acceptor) => match acceptor.accept(stream).await {
                    Ok(tls_stream) => serve_conn(tls_stream, conn, peer, core_tx, sendq).await,
                    Err(e) => eprintln!("TLS handshake failed from {peer}: {e}"),
                },
                None => serve_conn(stream, conn, peer, core_tx, sendq).await,
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
            host: peer.ip().to_string(),
        })
        .await
        .is_err()
    {
        return; // core gone: shutting down
    }
    let mut writer = tokio::spawn(write_loop(write_half, out_rx));
    tokio::select! {
        // The client closed/errored, or the core queue is gone: the read side
        // is done — stop the (possibly parked) writer.
        () = read_loop(read_half, conn, &core_tx) => writer.abort(),
        // The core closed this session (its `Sender<Output>` dropped, so the
        // sendq closed and write_loop returned). Cancel the read future so a
        // dead or partitioned peer's read task — and its per-IP ConnGuard — are
        // freed now, not only when the OS TCP timeout eventually fires. The
        // session is already gone core-side, so no Input::Closed is needed.
        _ = &mut writer => {}
    }
}

async fn read_loop<R>(mut read_half: R, conn: ConnId, core_tx: &Sender<Input>)
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
            Err(e) => break format!("Read error: {e}"),
        }
    };
    let _ = core_tx.push(Input::Closed { conn, reason }).await;
}

async fn write_loop<W>(mut write_half: W, mut rx: Receiver<Output>)
where
    W: AsyncWrite + Unpin,
{
    loop {
        let Some(envelope) = rx.pop().await else {
            // Core dropped the session (sender gone): flush and close.
            let _ = write_half.shutdown().await;
            return;
        };
        // Coalesce everything currently queued into one syscall.
        let mut batch: Vec<u8> = Vec::new();
        batch.extend_from_slice(&envelope.payload.0);
        while let Some(e) = rx.try_pop() {
            batch.extend_from_slice(&e.payload.0);
        }
        if write_half.write_all(&batch).await.is_err() {
            return; // broken pipe: reader half will surface the close
        }
        let _ = write_half.flush().await;
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

    #[tokio::test]
    async fn core_close_cancels_a_parked_read() {
        let (core_tx, mut core_rx) = queue::<Input>(e6irc_queue::Config {
            name: "t-core",
            capacity: 8,
            policy: Policy::Fifo,
        });
        let peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let served = tokio::spawn(serve_conn(DeadPeer, ConnId(1), peer, core_tx, 8));

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
}
