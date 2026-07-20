//! The `local` network driver: an in-process client of this e6ircd's own
//! core. It gives a BNC user an always-on presence on the local network
//! (with backlog), exactly like the `irc` driver gives them presence on
//! an external one — but over the core queue instead of a socket.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use e6irc_queue::{Config as QueueConfig, Policy, Sender, queue};

use super::{DriverEvent, NetworkConfig, NetworkDriver, NetworkHandle};
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
        let (handle, mut ends) = NetworkHandle::channels(self.buffer_cap);
        let this = *self;
        tokio::spawn(async move {
            let conn = ConnId(this.core.next_conn.fetch_add(1, Ordering::Relaxed));
            let (out_tx, mut out_rx) = queue::<Output>(QueueConfig {
                name: "local-sendq",
                capacity: this.core.sendq,
                policy: Policy::Fifo,
            });
            if this
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
                return; // core shutting down
            }
            // Register in-process, then auto-join.
            for line in [
                format!("NICK {}", this.nick),
                format!("USER {} 0 * :{}", this.nick, this.realname),
            ] {
                if this
                    .core
                    .core_tx
                    .push(Input::Line {
                        conn,
                        line: line.into_bytes(),
                    })
                    .await
                    .is_err()
                {
                    return;
                }
            }
            for chan in &this.autojoin {
                let _ = this
                    .core
                    .core_tx
                    .push(Input::Line {
                        conn,
                        line: format!("JOIN {chan}").into_bytes(),
                    })
                    .await;
            }
            ends.emit(DriverEvent::Connected);

            loop {
                tokio::select! {
                    // Core output -> buffer + broadcast (attach playback/live).
                    out = out_rx.pop() => match out {
                        Some(env) => {
                            // Strip only the frame's CRLF, not all trailing
                            // whitespace — a trailing param may end in spaces.
                            let line = String::from_utf8_lossy(&env.payload.0)
                                .trim_end_matches(['\r', '\n'])
                                .to_string();
                            ends.emit_line(line);
                        }
                        None => break, // core closed our session
                    },
                    // Downstream command -> core.
                    cmd = ends.next_command() => match cmd {
                        Some(line) => {
                            if this
                                .core
                                .core_tx
                                .push(Input::Line { conn, line: line.into_bytes() })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        None => {
                            // Every handle dropped: close our core session.
                            let _ = this
                                .core
                                .core_tx
                                .push(Input::Closed {
                                    conn,
                                    reason: "local driver stopped".into(),
                                })
                                .await;
                            break;
                        }
                    },
                }
            }
        });
        handle
    }
}
