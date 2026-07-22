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

    loop {
        tokio::select! {
            // Upstream -> buffer + event.
            msg = conn.next_message() => match msg {
                Ok(Some(m)) => {
                    // Answer PINGs transparently (keepalive is the
                    // driver's job, not the attached client's).
                    if m.command == "PING" {
                        let token = m.params.first().cloned().unwrap_or_default();
                        let _ = conn.send_line(&format!("PONG :{token}")).await;
                        continue;
                    }
                    // A send with zero subscribers is fine — the driver
                    // is always-on regardless of attach.
                    ends.emit_line(render(&m));
                }
                _ => return super::SessionOutcome::Dropped,
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

/// Reconstruct a wire line from an owned message for the buffer/attach.
fn render(m: &e6irc_client::OwnedMessage) -> String {
    let mut out = String::new();
    // Carry the IRCv3 message tags (server-time/msgid/account) so bouncer
    // backlog keeps timestamps. `attach` strips tags an attaching client did
    // not negotiate, so it is safe to store the fully-tagged line here.
    if !m.tags.is_empty() {
        out.push('@');
        for (i, (k, v)) in m.tags.iter().enumerate() {
            if i > 0 {
                out.push(';');
            }
            out.push_str(k);
            if let Some(v) = v {
                out.push('=');
                out.push_str(&e6irc_proto::message::escape_tag_value(v));
            }
        }
        out.push(' ');
    }
    if let Some(src) = &m.source {
        out.push(':');
        out.push_str(src);
        out.push(' ');
    }
    out.push_str(&m.command);
    for (i, p) in m.params.iter().enumerate() {
        out.push(' ');
        let last = i == m.params.len() - 1;
        if last && (p.is_empty() || p.contains(' ') || p.starts_with(':')) {
            out.push(':');
        }
        out.push_str(p);
    }
    out
}
