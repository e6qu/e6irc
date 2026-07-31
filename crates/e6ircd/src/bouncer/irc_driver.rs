//! The `irc` network driver: a persistent outbound IRCv3 client
//! connection to an external network, reusing `e6irc-client`. Runs on
//! its own task with auto-reconnect (exponential backoff + jitter);
//! emits [`DriverEvent`]s and accepts raw command lines.

use std::time::Duration;
use std::time::Instant;

use e6irc_client::{Connection, RelayEvent};

use super::{ConnectionEvent, DriverEnds, NetworkHandle};

/// Static configuration for one upstream network.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Upstream address (host:port).
    pub addr: String,
    /// Use TLS to the upstream.
    pub tls: bool,
    pub nick: String,
    pub realname: String,
    /// Channels to auto-join after registering.
    pub autojoin: Vec<String>,
    /// Detached buffer capacity.
    pub buffer_cap: usize,
    /// SASL PLAIN credentials for the upstream, when it requires auth.
    pub sasl: Option<(String, String)>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            addr: String::new(),
            tls: false,
            nick: "e6bnc".into(),
            realname: "e6irc bouncer".into(),
            autojoin: Vec::new(),
            buffer_cap: 1000,
            sasl: None,
        }
    }
}

/// A started `irc` network. Dropping the returned [`NetworkHandle`]
/// (its command sender) tells the driver task to stop.
pub struct IrcNetwork;

impl IrcNetwork {
    /// Start the driver task and return a handle to it.
    pub fn start(config: NetworkConfig) -> NetworkHandle {
        let (handle, ends) = NetworkHandle::channels(config.buffer_cap);
        tokio::spawn(run(config, ends));
        handle
    }
}

/// A successful, side-effect-free IRC upstream qualification. The connection
/// is closed after registration and no channels are joined. Timings are split
/// at the same boundaries operators must diagnose: name resolution, transport
/// establishment (including TLS), and IRC registration (including SASL).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IrcPreflight {
    pub resolved_addresses: usize,
    pub dns_ms: u64,
    pub connect_ms: u64,
    pub registration_ms: u64,
    pub confirmed_nick: String,
}

/// Closed failure taxonomy for an IRC preflight. Raw resolver, TLS, and server
/// errors stay in the server log; the API exposes only these actionable,
/// non-secret stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrcPreflightFailure {
    InvalidAddress,
    NameResolutionFailed,
    AddressBlocked,
    ConnectionFailed,
    SecureConnectionFailed,
    ConnectionTimedOut,
    AuthenticationRejected,
    RegistrationRejected,
    RegistrationFailed,
    RegistrationTimedOut,
}

impl IrcPreflightFailure {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidAddress => "invalid_address",
            Self::NameResolutionFailed => "name_resolution_failed",
            Self::AddressBlocked => "address_blocked",
            Self::ConnectionFailed => "connection_failed",
            Self::SecureConnectionFailed => "secure_connection_failed",
            Self::ConnectionTimedOut => "connection_timed_out",
            Self::AuthenticationRejected => "authentication_rejected",
            Self::RegistrationRejected => "registration_rejected",
            Self::RegistrationFailed => "registration_failed",
            Self::RegistrationTimedOut => "registration_timed_out",
        }
    }

    pub const fn summary(self) -> &'static str {
        match self {
            Self::InvalidAddress => "The upstream address is not a valid host and port.",
            Self::NameResolutionFailed => "The upstream hostname could not be resolved.",
            Self::AddressBlocked => {
                "The hostname resolves only to addresses blocked by the upstream safety policy."
            }
            Self::ConnectionFailed => "A TCP connection to the upstream could not be established.",
            Self::SecureConnectionFailed => {
                "The TLS connection or certificate verification failed."
            }
            Self::ConnectionTimedOut => "Connecting to the upstream timed out.",
            Self::AuthenticationRejected => "The upstream rejected the SASL credentials.",
            Self::RegistrationRejected => "The upstream rejected IRC registration.",
            Self::RegistrationFailed => "IRC registration failed before a welcome was received.",
            Self::RegistrationTimedOut => "IRC registration timed out.",
        }
    }
}

/// Resolve, connect, and register exactly as the always-on IRC driver does,
/// without persisting configuration or starting a reconnect loop.
pub async fn preflight_irc(config: &NetworkConfig) -> Result<IrcPreflight, IrcPreflightFailure> {
    if upstream_host(&config.addr).is_err() {
        return Err(IrcPreflightFailure::InvalidAddress);
    }

    let dns_started = Instant::now();
    let addresses = tokio::time::timeout(Duration::from_secs(10), resolve_vetted(&config.addr))
        .await
        .map_err(|_| IrcPreflightFailure::ConnectionTimedOut)?
        .map_err(|error| {
            eprintln!("irc preflight: name resolution failed: {error}");
            IrcPreflightFailure::NameResolutionFailed
        })?;
    if addresses.is_empty() {
        return Err(IrcPreflightFailure::AddressBlocked);
    }
    let dns_ms = elapsed_millis(dns_started.elapsed());
    let resolved_addresses = addresses.len();

    let connect_started = Instant::now();
    let mut connection =
        tokio::time::timeout(Duration::from_secs(30), connect_resolved(config, addresses))
            .await
            .map_err(|_| IrcPreflightFailure::ConnectionTimedOut)?
            .map_err(|error| {
                eprintln!("irc preflight: transport failed: {error}");
                if config.tls {
                    IrcPreflightFailure::SecureConnectionFailed
                } else {
                    IrcPreflightFailure::ConnectionFailed
                }
            })?;
    let connect_ms = elapsed_millis(connect_started.elapsed());

    let registration_started = Instant::now();
    let registration = async {
        match &config.sasl {
            Some((account, password)) => {
                connection
                    .register_sasl(&config.nick, &config.realname, account, password)
                    .await
            }
            None => connection.register(&config.nick, &config.realname).await,
        }
    };
    let confirmed_nick = match tokio::time::timeout(Duration::from_secs(30), registration).await {
        Ok(Ok(confirmed_nick)) => confirmed_nick,
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(IrcPreflightFailure::AuthenticationRejected);
        }
        Ok(Err(error))
            if matches!(
                error.kind(),
                std::io::ErrorKind::AlreadyExists
                    | std::io::ErrorKind::Other
                    | std::io::ErrorKind::Unsupported
            ) =>
        {
            return Err(IrcPreflightFailure::RegistrationRejected);
        }
        Ok(Err(error)) => {
            eprintln!("irc preflight: registration failed: {error}");
            return Err(IrcPreflightFailure::RegistrationFailed);
        }
        Err(_) => return Err(IrcPreflightFailure::RegistrationTimedOut),
    };

    Ok(IrcPreflight {
        resolved_addresses,
        dns_ms,
        connect_ms,
        registration_ms: elapsed_millis(registration_started.elapsed()),
        confirmed_nick,
    })
}

fn elapsed_millis(elapsed: Duration) -> u64 {
    elapsed.as_millis().min(u64::MAX as u128) as u64
}

async fn run(config: NetworkConfig, mut ends: DriverEnds) {
    // Clean stop: the command channel closed (handle dropped).
    super::run_with_backoff(config, &mut ends, |config, ends| {
        Box::pin(connect_once(config, ends))
    })
    .await;
}

async fn connect_once(config: &NetworkConfig, ends: &mut DriverEnds) -> super::SessionOutcome {
    // Bound connect + registration: an upstream that accepts the TCP handshake
    // but never sends 001 (firewall dropping data, half-open peer) must not
    // wedge the driver forever — that would starve the reconnect loop, the
    // same failure the Matrix driver's timeout guards against.
    let connect_fut = connect(config);
    let mut conn = match tokio::time::timeout(Duration::from_secs(30), connect_fut).await {
        Ok(Ok(c)) => c,
        Ok(Err(_)) => {
            let failure = if config.tls {
                super::NetworkFailure::SecureConnectionFailed
            } else {
                super::NetworkFailure::ConnectionFailed
            };
            return dropped(failure);
        }
        Err(_) => return dropped(super::NetworkFailure::ConnectionTimedOut),
    };
    let register_fut = async {
        match &config.sasl {
            Some((account, password)) => {
                conn.register_sasl(&config.nick, &config.realname, account, password)
                    .await
            }
            None => conn.register(&config.nick, &config.realname).await,
        }
    };
    match tokio::time::timeout(Duration::from_secs(30), register_fut).await {
        Ok(Ok(_)) => {}
        // A terminal auth/registration refusal (bad password, banned) surfaces
        // as `PermissionDenied` from the client — distinct from a transient
        // connection error, so the reconnect loop can stop re-dialing rather
        // than hammer the upstream with the same rejected credentials forever.
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return super::SessionOutcome::AuthRejected;
        }
        Ok(Err(e))
            if matches!(
                e.kind(),
                std::io::ErrorKind::AlreadyExists
                    | std::io::ErrorKind::Other
                    | std::io::ErrorKind::Unsupported
            ) =>
        {
            return super::SessionOutcome::RegistrationRejected;
        }
        Ok(Err(_)) => return dropped(super::NetworkFailure::RegistrationFailed),
        Err(_) => return dropped(super::NetworkFailure::RegistrationTimedOut),
    }
    for chan in &config.autojoin {
        if conn.send_line(&format!("JOIN {chan}")).await.is_err() {
            return dropped(super::NetworkFailure::AutojoinFailed);
        }
    }
    ends.emit(ConnectionEvent::Connected);

    // Keepalive: `connect_once` bounds connect + registration, but the
    // steady-state read below would otherwise block forever on a half-open
    // upstream (firewall silently drops the link, peer vanishes without RST),
    // starving the reconnect loop while `is_connected()` stays true — the exact
    // wedge the registration timeout guards against, just relocated. On an idle
    // gap we send our own PING; if the next gap passes with still no traffic,
    // the link is dead — drop and reconnect. A live server's own PINGs (which
    // we answer) keep a quiet-but-alive connection from ever tripping this.
    let mut awaiting_keepalive = false;
    loop {
        tokio::select! {
            // Upstream -> buffer + event.
            msg = tokio::time::timeout(KEEPALIVE_IDLE, conn.next_line_relayable()) => match msg {
                Ok(Ok(Some(RelayEvent::Line { message: parsed, raw }))) => {
                    awaiting_keepalive = false;
                    // Keepalive filtering applies only to lines we could parse;
                    // a line that didn't parse (a non-UTF-8 body, say) is never
                    // a PING and is simply relayed. A bad line must not drop the
                    // link — it is delivered, not fatal.
                    if let Some(m) = &parsed {
                        // Answer PINGs transparently (keepalive is the
                        // driver's job, not the attached client's).
                        if m.command == "PING" {
                            let token = m.params.first().cloned().unwrap_or_default();
                            if conn.send_line(&format!("PONG :{token}")).await.is_err() {
                                return dropped(super::NetworkFailure::UpstreamWriteFailed);
                            }
                            continue;
                        }
                        // The reply to our *own* keepalive PING is internal
                        // bookkeeping, not conversation — drop it so it doesn't
                        // fill the backlog (one junk line per idle interval,
                        // evicting real messages) and reach attached clients.
                        // Mirrors the local driver's keepalive discipline.
                        if m.command == "PONG"
                            && m.params.last().map(String::as_str) == Some("e6bnc-keepalive")
                        {
                            continue;
                        }
                    }
                    // The upstream's own line: attached clients and the detached
                    // buffer get what the network sent, tags and all. `attach`
                    // strips the tags a client did not negotiate.
                    //
                    // A send with zero subscribers is fine — the driver
                    // is always-on regardless of attach.
                    ends.emit_line(raw);
                }
                Ok(Ok(Some(RelayEvent::Rejected(rejected)))) => {
                    awaiting_keepalive = false;
                    // Keep the upstream connection alive, but make the whole-line
                    // loss visible to attached clients and the detached buffer.
                    // A syntactically valid local NOTICE is bounded independently
                    // of the rejected payload and cannot itself be discarded.
                    ends.emit_line(format!(
                        ":e6irc NOTICE * :upstream input rejected: {rejected}"
                    ));
                }
                // Only a genuine EOF or a real I/O error ends the session.
                Ok(Ok(None)) | Ok(Err(_)) => {
                    return dropped(super::NetworkFailure::ConnectionLost);
                }
                Err(_) => {
                    // Idle past the keepalive window.
                    if awaiting_keepalive {
                        return dropped(super::NetworkFailure::KeepaliveTimedOut);
                    }
                    awaiting_keepalive = true;
                    if conn.send_line("PING :e6bnc-keepalive").await.is_err() {
                        return dropped(super::NetworkFailure::UpstreamWriteFailed);
                    }
                }
            },
            // Downstream command -> upstream.
            cmd = ends.next_command() => match cmd {
                Some(line) => {
                    if conn.send_line(&line).await.is_err() {
                        return dropped(super::NetworkFailure::UpstreamWriteFailed);
                    }
                }
                None => return super::SessionOutcome::Stopped, // handle dropped
            },
        }
    }
}

fn dropped(failure: super::NetworkFailure) -> super::SessionOutcome {
    super::SessionOutcome::Dropped(failure)
}

/// Idle gap before the driver sends a keepalive PING (and again before it
/// declares a silent upstream dead). A live server PINGs well within this, so a
/// quiet-but-alive connection never trips it; a half-open one is caught within
/// `2 × KEEPALIVE_IDLE`.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(120);

async fn connect(config: &NetworkConfig) -> std::io::Result<Connection> {
    // SSRF control: resolve the upstream address ourselves and dial a *vetted*
    // resolved IP directly, rather than handing the hostname to the OS resolver
    // inside `TcpStream::connect`. The creation-time literal check
    // (`upstream_addr_is_internal`) can't see where a *hostname* resolves, and a
    // bare `TcpStream::connect(host)` re-resolves — so a hostname pointing at
    // `169.254.169.254` (or a DNS rebind between creation and now) would reach an
    // internal target. Connecting to the specific vetted socket address closes
    // both: resolution can't differ between the check and the connect.
    let vetted = resolve_vetted(&config.addr).await?;
    if vetted.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "upstream address resolves only to blocked/internal targets",
        ));
    }
    connect_resolved(config, vetted).await
}

async fn resolve_vetted(addr: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
    Ok(interleave_address_families(
        tokio::net::lookup_host(addr)
            .await?
            .filter(|address| !crate::http::networks::is_blocked_upstream_ip(address.ip()))
            .collect(),
    ))
}

async fn connect_resolved(
    config: &NetworkConfig,
    vetted: Vec<std::net::SocketAddr>,
) -> std::io::Result<Connection> {
    // Try every vetted result. Public round robins commonly return both IPv6
    // and IPv4; selecting only the first made a host without working IPv6 retry
    // the same unreachable address forever instead of reaching the IPv4 peer.
    // Each concrete dial is bounded so one black-holed address cannot consume
    // the entire outer connection deadline.
    let server_name = upstream_host(&config.addr)?;
    let mut last_error = std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "upstream resolved addresses were exhausted",
    );
    for address in vetted {
        let stream = match tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(address),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                last_error = error;
                continue;
            }
            Err(_) => {
                last_error = std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "concrete upstream address timed out",
                );
                continue;
            }
        };
        let connected = if config.tls {
            match tokio::time::timeout(
                Duration::from_secs(5),
                Connection::from_tcp_tls(stream, server_name, e6irc_client::webpki_root_store()),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "TLS handshake to concrete upstream address timed out",
                )),
            }
        } else {
            Connection::from_tcp(stream)
        };
        match connected {
            Ok(connection) => return Ok(connection),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

fn interleave_address_families(addresses: Vec<std::net::SocketAddr>) -> Vec<std::net::SocketAddr> {
    let start_with_ipv6 = addresses.first().is_some_and(std::net::SocketAddr::is_ipv6);
    let (ipv6, ipv4): (std::collections::VecDeque<_>, std::collections::VecDeque<_>) = addresses
        .into_iter()
        .partition(std::net::SocketAddr::is_ipv6);
    let (mut first, mut second) = if start_with_ipv6 {
        (ipv6, ipv4)
    } else {
        (ipv4, ipv6)
    };
    let mut ordered = Vec::with_capacity(first.len() + second.len());
    while !first.is_empty() || !second.is_empty() {
        if let Some(address) = first.pop_front() {
            ordered.push(address);
        }
        if let Some(address) = second.pop_front() {
            ordered.push(address);
        }
    }
    ordered
}

fn upstream_host(addr: &str) -> std::io::Result<&str> {
    let (host, port) = if let Some(bracketed) = addr.strip_prefix('[') {
        let (host, suffix) = bracketed
            .split_once(']')
            .ok_or_else(invalid_upstream_addr)?;
        let port = suffix
            .strip_prefix(':')
            .filter(|port| !port.is_empty())
            .ok_or_else(invalid_upstream_addr)?;
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(invalid_upstream_addr());
        }
        (host, port)
    } else {
        let (host, port) = addr.rsplit_once(':').ok_or_else(invalid_upstream_addr)?;
        if host.contains(':') {
            return Err(invalid_upstream_addr());
        }
        (host, port)
    };
    if host.is_empty()
        || host
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'/' | b'[' | b']'))
        || port.parse::<u16>().ok().filter(|port| *port != 0).is_none()
    {
        return Err(invalid_upstream_addr());
    }
    Ok(host)
}

fn invalid_upstream_addr() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "upstream address must be host:port with a nonzero numeric port",
    )
}

/// Syntactic IRC upstream validation shared by configuration and HTTP mutation
/// paths. DNS and SSRF checks remain dial-time concerns.
pub(crate) fn validate_irc_upstream_addr(addr: &str) -> bool {
    upstream_host(addr).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_tls_host_handles_dns_and_bracketed_ipv6() {
        assert_eq!(
            upstream_host("irc.libera.chat:6697").expect("DNS host"),
            "irc.libera.chat"
        );
        assert_eq!(
            upstream_host("[2001:db8::1]:6697").expect("IPv6"),
            "2001:db8::1"
        );
        assert!(upstream_host("missing-port").is_err());
        assert!(upstream_host("irc.example:not-a-port").is_err());
        assert!(upstream_host("irc.example:0").is_err());
        assert!(upstream_host("2001:db8::1:6697").is_err());
        assert!(upstream_host("[irc.example]:6697").is_err());
    }

    #[test]
    fn resolved_addresses_alternate_families_without_reordering_each_family() {
        let v6a = "[2001:db8::1]:6697".parse().unwrap();
        let v6b = "[2001:db8::2]:6697".parse().unwrap();
        let v4a = "192.0.2.1:6697".parse().unwrap();
        let v4b = "192.0.2.2:6697".parse().unwrap();
        assert_eq!(
            interleave_address_families(vec![v6a, v6b, v4a, v4b]),
            [v6a, v4a, v6b, v4b]
        );
        assert_eq!(
            interleave_address_families(vec![v4a, v4b, v6a, v6b]),
            [v4a, v6a, v4b, v6b]
        );
    }

    /// Exercises the actual always-on driver path (DNS vetting, pinned-IP TLS
    /// with hostname verification, IRC registration, and lifecycle reporting),
    /// not only the lower-level client probe in `tests/live_compat.rs`.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "live network: briefly connects the BNC driver to Libera.Chat"]
    async fn live_driver_connects_to_libera() {
        let nick = format!("e6b{:05}", std::process::id() % 100000);
        let handle = IrcNetwork::start(NetworkConfig {
            addr: "irc.libera.chat:6697".into(),
            tls: true,
            nick,
            realname: "e6irc BNC interop probe".into(),
            buffer_cap: 32,
            ..NetworkConfig::default()
        });

        let connected = tokio::time::timeout(Duration::from_secs(35), async {
            loop {
                let runtime = handle.runtime_snapshot();
                if runtime.lifecycle == super::super::NetworkLifecycle::Connected {
                    break runtime;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "Libera driver did not connect: {:?}",
                handle.runtime_snapshot()
            )
        });
        assert!(connected.connect_latency_ms.is_some());
        assert!(connected.lines_in > 0, "{connected:?}");
        assert_eq!(connected.last_error, None, "{connected:?}");

        handle.shutdown();
    }
}
