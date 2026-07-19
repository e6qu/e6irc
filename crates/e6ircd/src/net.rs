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
const LINE_LIMIT: usize = 4096 + 510;
const READ_BUF: usize = 4096;

pub struct Running {
    /// Bound IRC addresses, in listener-config order (useful with port 0).
    pub addrs: Vec<SocketAddr>,
    /// Bound HTTP address, when the http listener is configured.
    pub http_addr: Option<SocketAddr>,
    /// Bound BNC listener address, when configured.
    pub bnc_addr: Option<SocketAddr>,
}

fn wall_clock() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs()
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
        let reg = Arc::new(crate::bouncer::Registry::start(
            &config.networks,
            pool.clone(),
            crate::bouncer::CoreHandles {
                core_tx: core_tx.clone(),
                next_conn: next_conn.clone(),
                sendq: config.sendq,
            },
        ));
        if let Some(pool) = &pool {
            for (owner, row) in crate::db::list_all_bnc_networks(pool)
                .await
                .map_err(io::Error::other)?
            {
                let cfg = crate::bouncer::network_config_from_row(&row, secret_key.as_deref())
                    .map_err(io::Error::other)?;
                reg.add(
                    Some(owner),
                    row.name.clone(),
                    Box::new(crate::bouncer::IrcDriver::new(cfg)),
                );
            }
        }
        Some(reg)
    } else {
        None
    };

    let http_addr = match &config.http {
        Some(http_config) => {
            let listener = TcpListener::bind(http_config.addr).await?;
            let bound = listener.local_addr()?;
            let router = crate::http::router(crate::http::AppState {
                server_name: config.server_name.clone(),
                network_name: config.network_name.clone(),
                pool: pool.clone(),
                public_url: http_config.public_url.clone(),
                secure_cookies: http_config.secure_cookies,
                oidc_providers: config.oidc_providers.clone(),
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
            });
            tokio::spawn(async move {
                if let Err(e) = axum::serve(listener, router).await {
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
        core.preload_access(
            crate::db::list_channel_access(pool)
                .await
                .map_err(io::Error::other)?,
        );
    }
    tokio::spawn(core_worker(core, core_rx));

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
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _peer)) => {
                        let registry = registry.clone();
                        let server_name = server_name.clone();
                        let pool = pool.clone();
                        tokio::spawn(async move {
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

    let limiter = ConnLimiter::new(config.limits.max_connections_per_ip);
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
struct ConnLimiter {
    counts: Arc<std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, usize>>>,
    max_per_ip: Option<usize>,
}

impl ConnLimiter {
    fn new(max_per_ip: Option<usize>) -> Self {
        Self {
            counts: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            max_per_ip,
        }
    }

    /// Reserve a slot for `ip`, or `None` if it is already at the cap.
    fn try_acquire(&self, ip: std::net::IpAddr) -> Option<ConnGuard> {
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
struct ConnGuard {
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
    let writer = tokio::spawn(write_loop(write_half, out_rx));
    read_loop(read_half, conn, &core_tx).await;
    writer.abort(); // reader done ⇒ session closed; writer may be parked
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
