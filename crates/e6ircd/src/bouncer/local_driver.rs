//! The `local` network driver: an in-process client of this e6ircd's own
//! core. It gives a BNC user an always-on presence on the local network
//! (with backlog), exactly like the `irc` driver gives them presence on
//! an external one — but over the core queue instead of a socket.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use e6irc_queue::{Config as QueueConfig, Policy, Sender, queue};

use super::{ConnectionEvent, DriverEnds, NetworkConfig, NetworkDriver, NetworkHandle};
use crate::core::{ConnId, Input, Output};

/// Handles into the core, so the driver can open an in-process session.
#[derive(Clone)]
pub struct CoreHandles {
    pub core_tx: Sender<Input>,
    pub next_conn: Arc<AtomicU64>,
    pub sendq: usize,
}

pub struct LocalDriver {
    core: CoreHandles,
    nick: String,
    realname: String,
    autojoin: Vec<String>,
    buffer_cap: usize,
}

impl LocalDriver {
    /// Build a local driver from the same `NetworkConfig` the `irc`
    /// driver uses (addr/tls/sasl are ignored — there is no socket).
    pub fn new(core: CoreHandles, config: NetworkConfig) -> Self {
        Self {
            core,
            nick: config.nick,
            realname: config.realname,
            autojoin: config.autojoin,
            buffer_cap: config.buffer_cap,
        }
    }
}

impl NetworkDriver for LocalDriver {
    fn kind(&self) -> &'static str {
        "local"
    }

    fn start(self: Box<Self>) -> NetworkHandle {
        let (handle, ends) = NetworkHandle::channels(self.buffer_cap);
        let this = *self;
        let session = LocalSession {
            core: this.core,
            nick: this.nick,
            realname: this.realname,
            autojoin: this.autojoin,
        };
        tokio::spawn(run(session, ends));
        handle
    }
}

/// Per-session configuration for the local driver, reconnected on each drop.
struct LocalSession {
    core: CoreHandles,
    nick: String,
    realname: String,
    autojoin: Vec<String>,
}

async fn run(session: LocalSession, mut ends: DriverEnds) {
    // Like every other driver: a core-side close (the operator KILLs the BNC
    // user, or the core drops the in-process conn) must reconnect with a fresh
    // ConnId and emit `Disconnected` on the way — not exit the task silently and
    // leave `is_connected()` stuck true, as the previous one-shot loop did.
    super::run_with_backoff(session, &mut ends, |session, ends| {
        Box::pin(session_once(session, ends))
    })
    .await;
}

async fn session_once(session: &LocalSession, ends: &mut DriverEnds) -> super::SessionOutcome {
    use super::SessionOutcome::{Dropped, Stopped};
    let conn = ConnId(session.core.next_conn.fetch_add(1, Ordering::Relaxed));
    let (out_tx, mut out_rx) = queue::<Output>(QueueConfig {
        name: "local-sendq",
        capacity: session.core.sendq,
        policy: Policy::Fifo,
    });
    if session
        .core
        .core_tx
        .push(Input::Open {
            conn,
            tx: out_tx,
            host: "local".into(),
        })
        .await
        .is_err()
    {
        return Stopped; // core shutting down
    }
    // Register in-process, then auto-join.
    for line in [
        format!("NICK {}", session.nick),
        format!("USER {} 0 * :{}", session.nick, session.realname),
    ] {
        if session
            .core
            .core_tx
            .push(Input::Line {
                conn,
                line: line.into_bytes(),
            })
            .await
            .is_err()
        {
            return Stopped;
        }
    }
    for chan in &session.autojoin {
        let _ = session
            .core
            .core_tx
            .push(Input::Line {
                conn,
                line: format!("JOIN {chan}").into_bytes(),
            })
            .await;
    }
    ends.emit(ConnectionEvent::Connected);

    loop {
        tokio::select! {
            // Core output -> buffer + broadcast (attach playback/live).
            out = out_rx.pop() => match out {
                Some(env) => {
                    // Strip only the frame's CRLF, not all trailing whitespace —
                    // a trailing param may end in spaces.
                    let line = String::from_utf8_lossy(&env.payload.0)
                        .trim_end_matches(['\r', '\n'])
                        .to_string();
                    // The in-process session is a real registered session, so the
                    // liveness reaper PINGs it after ~2 min idle. There is no
                    // network peer to answer, so answer here — otherwise the
                    // reaper times out and drops the session every few minutes,
                    // churning this always-on network (spurious dis/reconnect
                    // notices, NICK/JOIN replay). The PING is internal keepalive,
                    // not conversation, so it is not shown in the buffer.
                    if let Some(token) = line.strip_prefix("PING ") {
                        let token = token.strip_prefix(':').unwrap_or(token);
                        let _ = session
                            .core
                            .core_tx
                            .push(Input::Line {
                                conn,
                                line: format!("PONG :{token}").into_bytes(),
                            })
                            .await;
                        continue;
                    }
                    ends.emit_line(line);
                }
                // Core closed our session: reconnect with a fresh ConnId (and
                // emit Disconnected via run_with_backoff) rather than die.
                None => return Dropped,
            },
            // Downstream command -> core.
            cmd = ends.next_command() => match cmd {
                Some(line) => {
                    if session
                        .core
                        .core_tx
                        .push(Input::Line { conn, line: line.into_bytes() })
                        .await
                        .is_err()
                    {
                        return Dropped;
                    }
                }
                None => {
                    // Every handle dropped: close our core session and stop for
                    // good (no reconnect — the network was removed).
                    let _ = session
                        .core
                        .core_tx
                        .push(Input::Closed {
                            conn,
                            reason: "local driver stopped".into(),
                        })
                        .await;
                    return Stopped;
                }
            },
        }
    }
}
