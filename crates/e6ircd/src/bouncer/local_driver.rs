//! The `local` network driver: an in-process client of this e6ircd's own
//! core. It gives a BNC user an always-on presence on the local network
//! (with backlog), exactly like the `irc` driver gives them presence on
//! an external one — but over the core queue instead of a socket.

use std::sync::Arc;

use e6irc_queue::{Config as QueueConfig, Policy, queue};

use super::{ConnectionEvent, DriverEnds, NetworkConfig, NetworkDriver, NetworkHandle};
use crate::core::{ConnectionIdAllocator, CoreIngress, Input, Output};

/// The in-process network's name — the driver `kind`, the session host, and the
/// network a slash-less BNC attach defaults to (DESIGN §10.4: bare = `local`).
pub(crate) const LOCAL_NETWORK: &str = "local";

/// Handles into the core, so the driver can open an in-process session.
#[derive(Clone)]
pub struct CoreHandles {
    pub core_tx: CoreIngress,
    pub next_conn: Arc<ConnectionIdAllocator>,
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
        LOCAL_NETWORK
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
    use super::SessionOutcome::Stopped;
    let conn = match session.core.next_conn.allocate() {
        Ok(conn) => conn,
        Err(error) => {
            eprintln!("local bouncer connection stopped: {error}");
            return Stopped;
        }
    };
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
            transport: crate::core::ConnectionTransport::Local,
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
        if session
            .core
            .core_tx
            .push(Input::Line {
                conn,
                line: format!("JOIN {chan}").into_bytes(),
            })
            .await
            .is_err()
        {
            return Stopped;
        }
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
                        if session
                            .core
                            .core_tx
                            .push(Input::Line {
                                conn,
                                line: format!("PONG :{token}").into_bytes(),
                            })
                            .await
                            .is_err()
                        {
                            return Stopped;
                        }
                        continue;
                    }
                    ends.emit_line(line);
                }
                // Core closed our session: reconnect with a fresh ConnId (and
                // emit Disconnected via run_with_backoff) rather than die.
                None => {
                    return super::SessionOutcome::Dropped(super::NetworkFailure::ConnectionLost);
                }
            },
            // Downstream command -> core.
            cmd = ends.next_command() => match cmd {
                Some(cmd) => {
                    if session
                        .core
                        .core_tx
                        .push(Input::Line { conn, line: cmd.line.into_bytes() })
                        .await
                        .is_err()
                    {
                        return Stopped;
                    }
                }
                None => {
                    // Every handle dropped: close our core session and stop for
                    // good (no reconnect — the network was removed).
                    // Queue closure here already means the core is gone; either
                    // way the driver's requested terminal state is reached.
                    drop(
                        session
                            .core
                            .core_tx
                            .push(Input::Closed {
                                conn,
                                reason: "local driver stopped".into(),
                            })
                            .await,
                    );
                    return Stopped;
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use e6irc_queue::{Receiver, Sender};
    use tokio::sync::broadcast;

    fn core_queue(capacity: usize) -> (Sender<Input>, Receiver<Input>) {
        queue(QueueConfig {
            name: "local-driver-test-core",
            capacity,
            policy: Policy::Fifo,
        })
    }

    fn spawn_session(
        core_tx: Sender<Input>,
        autojoin: Vec<String>,
    ) -> (
        NetworkHandle,
        broadcast::Receiver<super::super::DriverEvent>,
        tokio::task::JoinHandle<super::super::SessionOutcome>,
    ) {
        let session = LocalSession {
            core: CoreHandles {
                core_tx: CoreIngress::single(core_tx),
                next_conn: Arc::new(ConnectionIdAllocator::new(std::num::NonZeroU64::MIN)),
                sendq: 8,
            },
            nick: "alice".into(),
            realname: "Alice".into(),
            autojoin,
        };
        let (handle, mut ends) = NetworkHandle::channels(8);
        let events = handle.subscribe();
        let task = tokio::spawn(async move { session_once(&session, &mut ends).await });
        (handle, events, task)
    }

    async fn finish_registration(core_rx: &mut Receiver<Input>) -> Sender<Output> {
        let open = core_rx.pop().await.expect("Open event").payload;
        let Input::Open { tx, .. } = open else {
            panic!("expected Open");
        };
        for expected in ["NICK alice", "USER alice 0 * :Alice"] {
            let input = core_rx.pop().await.expect("registration line").payload;
            let Input::Line { line, .. } = input else {
                panic!("expected registration line");
            };
            assert_eq!(String::from_utf8(line).unwrap(), expected);
        }
        tx
    }

    async fn stopped(
        task: tokio::task::JoinHandle<super::super::SessionOutcome>,
    ) -> super::super::SessionOutcome {
        tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .expect("local session must stop promptly")
            .expect("local session task")
    }

    /// Spawn a session and drive it through registration to the `Connected`
    /// event — the shared setup of the lifecycle tests. Returns everything;
    /// a test keeps only what it drives next.
    async fn connected_session() -> (
        Receiver<Input>,
        NetworkHandle,
        broadcast::Receiver<super::super::DriverEvent>,
        tokio::task::JoinHandle<super::super::SessionOutcome>,
        Sender<Output>,
    ) {
        let (core_tx, mut core_rx) = core_queue(8);
        let (handle, mut events, task) = spawn_session(core_tx, Vec::new());
        let out_tx = finish_registration(&mut core_rx).await;
        assert!(matches!(
            events.recv().await,
            Ok(super::super::DriverEvent::Status(
                super::super::DriverConnectionStatus::Connected
            ))
        ));
        (core_rx, handle, events, task, out_tx)
    }

    #[tokio::test]
    async fn autojoin_failure_stops_before_connected() {
        // Capacity one lets registration fill the queue with USER and park on
        // JOIN. Closing the receiver then deterministically fails auto-join.
        let (core_tx, mut core_rx) = core_queue(1);
        let (_handle, mut events, task) = spawn_session(core_tx.clone(), vec!["#room".into()]);

        assert!(matches!(
            core_rx.pop().await.expect("Open").payload,
            Input::Open { .. }
        ));
        assert!(matches!(
            core_rx.pop().await.expect("NICK").payload,
            Input::Line { .. }
        ));
        while core_tx.depth() == 0 {
            tokio::task::yield_now().await;
        }
        drop(core_rx);

        assert!(matches!(
            stopped(task).await,
            super::super::SessionOutcome::Stopped
        ));
        assert!(matches!(
            events.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn pong_failure_stops_when_the_core_is_gone() {
        let (core_rx, _handle, _events, task, out_tx) = connected_session().await;
        drop(core_rx);

        out_tx
            .push(Output(Bytes::from_static(b"PING :keepalive\r\n")))
            .await
            .expect("local output queue");
        assert!(matches!(
            stopped(task).await,
            super::super::SessionOutcome::Stopped
        ));
    }

    #[tokio::test]
    async fn downstream_failure_does_not_retry_a_closed_core() {
        let (core_rx, handle, _events, task, _out_tx) = connected_session().await;
        drop(core_rx);

        assert_eq!(
            handle.send("PRIVMSG #room :hello"),
            super::super::SendOutcome::Sent
        );
        assert!(matches!(
            stopped(task).await,
            super::super::SessionOutcome::Stopped
        ));
    }
}
