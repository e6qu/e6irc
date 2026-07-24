//! The `irc` network driver: a persistent outbound IRCv3 client
//! connection to an external network, reusing `e6irc-client`. Runs on
//! its own task with auto-reconnect (exponential backoff + jitter);
//! emits [`DriverEvent`]s and accepts raw command lines.

use std::time::Duration;

use e6irc_client::Connection;

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
        Ok(Err(_)) | Err(_) => return super::SessionOutcome::Dropped,
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
        Ok(Err(_)) | Err(_) => return super::SessionOutcome::Dropped,
    }
    ends.emit(ConnectionEvent::Connected);
    for chan in &config.autojoin {
        if conn.send_line(&format!("JOIN {chan}")).await.is_err() {
            return super::SessionOutcome::Dropped;
        }
    }

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
            msg = tokio::time::timeout(KEEPALIVE_IDLE, conn.next_message_with_line()) => match msg {
                Ok(Ok(Some((m, raw)))) => {
                    awaiting_keepalive = false;
                    // Answer PINGs transparently (keepalive is the
                    // driver's job, not the attached client's).
                    if m.command == "PING" {
                        let token = m.params.first().cloned().unwrap_or_default();
                        let _ = conn.send_line(&format!("PONG :{token}")).await;
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
                    // The upstream's own bytes, not a re-serialization of the
                    // parse: attached clients and the detached buffer get what
                    // the network actually sent, tags and all. `attach` strips
                    // the tags a client did not negotiate.
                    //
                    // A send with zero subscribers is fine — the driver
                    // is always-on regardless of attach.
                    ends.emit_line(raw);
                }
                Ok(_) => return super::SessionOutcome::Dropped, // clean EOF or read error
                Err(_) => {
                    // Idle past the keepalive window.
                    if awaiting_keepalive {
                        return super::SessionOutcome::Dropped; // our PING went unanswered → dead
                    }
                    awaiting_keepalive = true;
                    if conn.send_line("PING :e6bnc-keepalive").await.is_err() {
                        return super::SessionOutcome::Dropped;
                    }
                }
            },
            // Downstream command -> upstream.
            cmd = ends.next_command() => match cmd {
                Some(line) => {
                    if conn.send_line(&line).await.is_err() {
                        return super::SessionOutcome::Dropped;
                    }
                }
                None => return super::SessionOutcome::Stopped, // handle dropped
            },
        }
    }
}

/// Idle gap before the driver sends a keepalive PING (and again before it
/// declares a silent upstream dead). A live server PINGs well within this, so a
/// quiet-but-alive connection never trips it; a half-open one is caught within
/// `2 × KEEPALIVE_IDLE`.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(120);

async fn connect(config: &NetworkConfig) -> std::io::Result<Connection> {
    if config.tls {
        let name = config
            .addr
            .rsplit_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| config.addr.clone());
        Connection::connect_tls(&config.addr, &name, e6irc_client::webpki_root_store()).await
    } else {
        Connection::connect(&config.addr).await
    }
}
