//! `e6ircd edge` (DESIGN §19.1, decision D1): a process holding client
//! connections for a core in another process.
//!
//! Its configuration is its own (decision D9): who it is and how it reaches
//! the core ([`EdgeSection`]), and its listeners and their certificates — IRC
//! over TCP or TLS, IRC over WebSocket, the web port, the bouncer attach
//! listener — each optionally behind a load balancer speaking the PROXY
//! protocol. Everything else it follows is the core's, given at each link
//! (`Welcome`): the trusted proxies, the per-address connection limit it
//! pre-filters by, each session's send-queue bound and command-flood shape.
//! It binds its listeners at once, and accepts on them once it has first
//! linked: a connection identifier needs the slot, and a session the terms,
//! that only a core gives.

use std::io;
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use e6irc_link::{EdgeName, ListenerKind, ListenerReport, SessionKind};
use serde::Deserialize;
use tokio::sync::mpsc;

use crate::address::{ConnLimiter, TrustedProxies};
use crate::certificate::{CertificateReloads, Hangups, TlsConfig, install_crypto_provider};
use crate::connection::{
    AcceptContext, ConnectionIdAllocator, ConnectionTasks, TransportError, TransportTelemetry,
    accept_loop, bind_listener,
};
use crate::core_link::remote::{Dialing, Link, RemoteCore};
use crate::core_link::tls::{LinkCredentialFiles, LinkCredentials};
use crate::core_link::web::EdgeWeb;
use crate::http::{HttpAdmission, serve_http};

/// How long a stopping edge waits for its clients to be sent their closing
/// line and closed.
const STOP_DRAIN: std::time::Duration = std::time::Duration::from_secs(8);

/// How often the edge says what failed since it last said so.
const TELEMETRY_REPORT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// An edge's configuration file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeConfig {
    pub edge: EdgeSection,
    #[serde(default)]
    pub listeners: Vec<EdgeListener>,
    /// The web port: the application, `/ws/irc` and `/ws/ui`.
    #[serde(default)]
    pub http: Option<EdgeHttp>,
    /// The bouncer attach listener.
    #[serde(default)]
    pub attach: Option<EdgeAttach>,
}

/// Who the edge is and how it reaches the core.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeSection {
    /// The name its certificate is issued for (`e6ircd edge-credentials
    /// issue`): one DNS label.
    pub name: String,
    /// Where the core is: each a `host:port` whose every address is tried in
    /// turn — a name listing every core host, a service address, or a load
    /// balancer health-checked on the cores' `/readyz`. Only the core holding
    /// the serving lease listens.
    pub core: Vec<String>,
    /// The deployment's certificate authority, and this edge's certificate and
    /// key.
    #[serde(flatten)]
    pub credentials: LinkCredentialFiles,
}

/// An IRC listener.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeListener {
    pub addr: SocketAddr,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// IRC over WebSocket at every path, rather than over TCP.
    #[serde(default)]
    pub websocket: bool,
    #[serde(default)]
    pub proxy_protocol: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeHttp {
    pub addr: SocketAddr,
    #[serde(default)]
    pub proxy_protocol: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeAttach {
    pub addr: SocketAddr,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub proxy_protocol: bool,
}

/// Why an edge's configuration cannot run.
fn invalid(what: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, what.to_string())
}

impl EdgeConfig {
    /// The edge's name, and a refusal of what cannot run.
    pub fn validate(&self) -> io::Result<EdgeName> {
        let name = EdgeName::new(&self.edge.name).map_err(invalid)?;
        if self.edge.core.is_empty() {
            return Err(invalid("[edge] core names no address to reach the core at"));
        }
        if self.listeners.is_empty() && self.http.is_none() && self.attach.is_none() {
            return Err(invalid(
                "the edge has no listener: state [[listeners]], [http] or [attach]",
            ));
        }
        if self
            .listeners
            .iter()
            .any(|listener| listener.websocket && listener.tls.is_some())
        {
            return Err(invalid(
                "a [[listeners]] with websocket = true cannot also set tls (terminate TLS at a \
                 proxy)",
            ));
        }
        Ok(name)
    }
}

/// What the edge counts, said every [`TELEMETRY_REPORT_INTERVAL`] when any
/// of it changed: the edge serves no metrics of its own.
#[derive(Default)]
struct EdgeTelemetry {
    errors: [AtomicU64; ERROR_KINDS],
    rejected: AtomicU64,
}

fn error_index(kind: TransportError) -> usize {
    match kind {
        TransportError::Accept => 0,
        TransportError::ConnectionSetup => 1,
        TransportError::TlsHandshake => 2,
        TransportError::Read => 3,
        TransportError::Write => 4,
        TransportError::Http => 5,
    }
}

const ERROR_KINDS: usize = 6;

const ERROR_LABELS: [&str; ERROR_KINDS] = [
    "accept",
    "connection setup",
    "TLS handshake",
    "read",
    "write",
    "HTTP",
];

impl TransportTelemetry for EdgeTelemetry {
    fn record_error(&self, kind: TransportError) {
        self.errors[error_index(kind)].fetch_add(1, Ordering::Relaxed);
    }

    fn record_connection_rejected(&self) {
        self.rejected.fetch_add(1, Ordering::Relaxed);
    }
}

impl EdgeTelemetry {
    async fn report(self: Arc<Self>, name: EdgeName) {
        // Each error kind's count, then the connections refused by limit.
        let mut said = [0u64; ERROR_KINDS + 1];
        let mut interval = tokio::time::interval(TELEMETRY_REPORT_INTERVAL);
        interval.tick().await;
        loop {
            interval.tick().await;
            let mut now = [0u64; ERROR_KINDS + 1];
            for (index, count) in self.errors.iter().enumerate() {
                now[index] = count.load(Ordering::Relaxed);
            }
            now[ERROR_KINDS] = self.rejected.load(Ordering::Relaxed);
            if now == said {
                continue;
            }
            let mut parts: Vec<String> = ERROR_LABELS
                .iter()
                .enumerate()
                .filter(|(index, _)| now[*index] > said[*index])
                .map(|(index, label)| format!("{} {label} errors", now[index] - said[index]))
                .collect();
            if now[ERROR_KINDS] > said[ERROR_KINDS] {
                parts.push(format!(
                    "{} connections refused by limit",
                    now[ERROR_KINDS] - said[ERROR_KINDS]
                ));
            }
            eprintln!(
                "e6ircd edge {name}: in the last {}s: {}",
                TELEMETRY_REPORT_INTERVAL.as_secs(),
                parts.join(", ")
            );
            said = now;
        }
    }
}

/// The networks a `Welcome` trusts, as the edge matches them.
fn trusted_networks(link: &Link) -> Vec<ipnet::IpNet> {
    link.welcome()
        .terms
        .trusted_proxies
        .iter()
        .filter_map(|(network, prefix)| ipnet::IpNet::new(*network, *prefix).ok())
        .collect()
}

/// Follow a link's terms: its trusted proxies and connection limit.
fn follow(link: &Link, trusted: &TrustedProxies, limiter: &ConnLimiter) {
    trusted.set(trusted_networks(link));
    limiter.set_max(
        link.welcome()
            .terms
            .max_connections_per_ip
            .map(|limit| limit as usize),
    );
}

/// One bound listener and what it serves.
enum Bound {
    Irc(tokio::net::TcpListener, EdgeListener),
    WebSocketIrc(tokio::net::TcpListener, EdgeListener),
    Http(tokio::net::TcpListener, EdgeHttp),
    Attach(tokio::net::TcpListener, EdgeAttach),
}

/// Run an edge until `stop` resolves, then close its clients, loudly, and
/// return.
pub async fn run(config: EdgeConfig, stop: impl Future<Output = ()>) -> io::Result<()> {
    let name = config.validate()?;
    let hangups = Hangups::install()?;
    install_crypto_provider();
    let credentials = LinkCredentials::load(&config.edge.credentials)?;
    let certificates = CertificateReloads::default();
    let mut bound = Vec::new();
    let mut reports = Vec::new();
    // Each bound address is said as the core says its own (`listening on`
    // for an IRC listener), so a supervisor or a test can find a port it
    // left to the system.
    let mut report = |listener: &tokio::net::TcpListener,
                      kind: ListenerKind,
                      tls: bool,
                      proxy_protocol: bool|
     -> io::Result<()> {
        let addr = listener.local_addr()?;
        println!(
            "{}listening on {addr}",
            match kind {
                ListenerKind::Irc => "",
                ListenerKind::WebSocketIrc => "websocket ",
                ListenerKind::Http => "http ",
                ListenerKind::Attach => "attach ",
            }
        );
        reports.push(ListenerReport {
            kind,
            addr,
            tls,
            proxy_protocol,
        });
        Ok(())
    };
    for listener in &config.listeners {
        let socket = bind_listener(listener.addr)?;
        if listener.websocket {
            report(
                &socket,
                ListenerKind::WebSocketIrc,
                false,
                listener.proxy_protocol,
            )?;
            bound.push(Bound::WebSocketIrc(socket, listener.clone()));
        } else {
            report(
                &socket,
                ListenerKind::Irc,
                listener.tls.is_some(),
                listener.proxy_protocol,
            )?;
            bound.push(Bound::Irc(socket, listener.clone()));
        }
    }
    if let Some(http) = &config.http {
        let socket = bind_listener(http.addr)?;
        report(&socket, ListenerKind::Http, false, http.proxy_protocol)?;
        bound.push(Bound::Http(socket, http.clone()));
    }
    if let Some(attach) = &config.attach {
        let socket = bind_listener(attach.addr)?;
        report(
            &socket,
            ListenerKind::Attach,
            attach.tls.is_some(),
            attach.proxy_protocol,
        )?;
        bound.push(Bound::Attach(socket, attach.clone()));
    }
    // Certificates are read now, so a missing file refuses the start.
    let mut acceptors = Vec::with_capacity(bound.len());
    for listener in &bound {
        let tls = match listener {
            Bound::Irc(_, listener) => listener.tls.as_ref(),
            Bound::Attach(_, attach) => attach.tls.as_ref(),
            Bound::WebSocketIrc(..) | Bound::Http(..) => None,
        };
        acceptors.push(match tls {
            Some(tls) => Some(certificates.acceptor(tls)?),
            None => None,
        });
    }
    let telemetry = Arc::new(EdgeTelemetry::default());
    let reporting = tokio::spawn(telemetry.clone().report(name.clone()));
    let reloading = tokio::spawn(certificates.clone().run(hangups));
    let ids = Arc::new(ConnectionIdAllocator::new(NonZeroU64::MIN));
    let core = RemoteCore::new(telemetry.clone(), ids.clone());
    let (linked, mut links) = mpsc::unbounded_channel();
    let maintaining = tokio::spawn(core.clone().maintain(
        Dialing {
            edge: name.clone(),
            core: config.edge.core.clone(),
            connector: credentials.edge_connector()?,
            listeners: reports,
        },
        linked,
    ));
    tokio::pin!(stop);
    let first = tokio::select! {
        link = links.recv() => link.expect("the link keeper runs as long as the edge"),
        () = &mut stop => {
            maintaining.abort();
            reporting.abort();
            reloading.abort();
            eprintln!("e6ircd edge {name}: stopping before it first linked");
            return Ok(());
        }
    };
    let trusted = TrustedProxies::default();
    let limiter = ConnLimiter::new(None);
    follow(&first, &trusted, &limiter);
    let following = {
        let (trusted, limiter) = (trusted.clone(), limiter.clone());
        tokio::spawn(async move {
            while let Some(link) = links.recv().await {
                follow(&link, &trusted, &limiter);
            }
        })
    };
    let connections = ConnectionTasks::default();
    let dyn_telemetry: Arc<dyn TransportTelemetry> = telemetry.clone();
    let sendq_bytes = first.welcome().terms.sendq_bytes as usize;
    let mut accepting = Vec::new();
    for (listener, tls) in bound.into_iter().zip(acceptors) {
        let proxy = |on: bool| on.then(|| trusted.clone());
        let task = match listener {
            Bound::Irc(socket, listener) => tokio::spawn(accept_loop(
                socket,
                AcceptContext {
                    tls,
                    core_tx: core.port(SessionKind::Irc),
                    next_conn: ids.clone(),
                    sendq_bytes,
                    limiter: limiter.clone(),
                    telemetry: dyn_telemetry.clone(),
                    connections: connections.clone(),
                    proxy_protocol: proxy(listener.proxy_protocol),
                },
            )),
            Bound::Attach(socket, attach) => tokio::spawn(accept_loop(
                socket,
                AcceptContext {
                    tls,
                    core_tx: core.port(SessionKind::Attach),
                    next_conn: ids.clone(),
                    sendq_bytes,
                    limiter: limiter.clone(),
                    telemetry: dyn_telemetry.clone(),
                    connections: connections.clone(),
                    proxy_protocol: proxy(attach.proxy_protocol),
                },
            )),
            Bound::WebSocketIrc(socket, listener) => {
                let web = EdgeWeb::new(
                    core.clone(),
                    ids.clone(),
                    dyn_telemetry.clone(),
                    connections.clone(),
                    true,
                );
                let mut admission = HttpAdmission::new(trusted.clone());
                if listener.proxy_protocol {
                    admission = admission.with_proxy_protocol();
                }
                tokio::spawn(serve_http(
                    socket,
                    web.router(),
                    admission,
                    dyn_telemetry.clone(),
                ))
            }
            Bound::Http(socket, http) => {
                let web = EdgeWeb::new(
                    core.clone(),
                    ids.clone(),
                    dyn_telemetry.clone(),
                    connections.clone(),
                    false,
                );
                let mut admission = HttpAdmission::new(trusted.clone());
                if http.proxy_protocol {
                    admission = admission.with_proxy_protocol();
                }
                tokio::spawn(serve_http(
                    socket,
                    web.router(),
                    admission,
                    dyn_telemetry.clone(),
                ))
            }
        };
        accepting.push(task);
    }
    eprintln!("e6ircd edge {name}: accepting clients");
    stop.await;
    eprintln!("e6ircd edge {name}: stopping; closing every client as the edge shutting down");
    for task in &accepting {
        task.abort();
    }
    maintaining.abort();
    following.abort();
    core.shut_down();
    let unclosed = connections.drained_within(STOP_DRAIN).await;
    if unclosed > 0 {
        eprintln!(
            "e6ircd edge {name}: {unclosed} client connections had not closed {}s after the \
             stop",
            STOP_DRAIN.as_secs()
        );
    }
    reporting.abort();
    reloading.abort();
    Ok(())
}
