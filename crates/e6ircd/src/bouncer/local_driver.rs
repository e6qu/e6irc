//! The `local` network driver: an in-process client of this e6ircd's own
//! core. It gives a BNC user an always-on presence on the local network
//! (with backlog), exactly like the `irc` driver gives them presence on
//! an external one — but over the core queue instead of a socket.

use std::sync::Arc;

use e6irc_queue::{Config as QueueConfig, Policy, Receiver, queue};

use super::{ConnectionEvent, DriverEnds, NetworkConfig, NetworkDriver, NetworkHandle};
use crate::core::{ConnId, ConnectionIdAllocator, CoreIngress, Input, Output};

/// The in-process network's name — the driver `kind`, the session host, and the
/// network a slash-less BNC attach defaults to (DESIGN §10.4: bare = `local`).
pub(crate) const LOCAL_NETWORK: &str = "local";

/// The host the in-process session is opened with, and so the host the core
/// shows in its prefix.
const LOCAL_SESSION_HOST: &str = LOCAL_NETWORK;

/// The capabilities the in-process session negotiates with the core, in one
/// all-or-nothing `CAP REQ`, so the local network carries what any upstream
/// that offers them does:
///
/// - `message-tags`: an attached client's client-only tags (`+typing`,
///   `+draft/react`, `+draft/reply`) and its `TAGMSG` reach the core instead of
///   being stripped, and each message comes back with the `msgid` a reaction
///   or reply names.
/// - `server-time`: every line carries the core's own time, so the backlog
///   files and replays a message at the time the core gave it, the time the
///   core's CHATHISTORY and other clients see.
/// - `echo-message`: our own message comes back from the core with the `msgid`
///   and time the core gave it — without it the synthesized echo had neither,
///   so a reaction to one's own message named a message the backlog did not
///   hold — and only for a line the core accepted, so a refused one is
///   answered by its refusal alone, as on any upstream that echoes.
/// - `account-tag`: attached clients are offered it by the bouncer; the sender's
///   account rides each line, as the `irc` driver asks every upstream for.
///
/// Replies are told apart by order (`Correlation::Order`), which the core
/// answers in; `labeled-response` and `batch` would add nothing here.
const LOCAL_CAPABILITIES: &str = "account-tag echo-message message-tags server-time";

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
    username: String,
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
            // Already parsed: the same one-parameter guarantees hold for the
            // lines this driver injects into the in-process core.
            nick: config.nick.to_string(),
            username: config.username.to_string(),
            realname: config.realname.as_str().to_string(),
            autojoin: config.autojoin.iter().map(ToString::to_string).collect(),
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
            username: this.username,
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
    username: String,
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

/// How long the in-process core may take to welcome a registration. The core
/// is a queue away, so this only has to outlast a loaded core loop; it exists
/// so that a wedged core is a reported failure rather than a silent wait.
const WELCOME_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// The core's welcome: the nickname it granted, and the 001 line itself, which
/// is the first line of the session it begins.
struct Welcome {
    nick: String,
    line: String,
}

/// Queue one line for the core. `false` means the core is gone.
async fn say(core: &CoreIngress, conn: ConnId, line: String) -> bool {
    core.push(Input::Line {
        conn,
        line: line.into_bytes(),
    })
    .await
    .is_ok()
}

/// Read the core's replies until it welcomes the session under the configured
/// nickname, with [`LOCAL_CAPABILITIES`] acknowledged first. A refusal is read by the same table the IRC driver's registration
/// uses, so it takes the refusal schedule and parks like any other upstream's —
/// not the transient schedule of a connection that was made and lost. Lines
/// that are neither are the core talking to its new client, and are relayed.
async fn await_welcome(
    session: &LocalSession,
    conn: ConnId,
    out_rx: &mut Receiver<Output>,
    ends: &DriverEnds,
) -> Result<Welcome, super::SessionOutcome> {
    use super::SessionOutcome::{Dropped, RegistrationRejected, Stopped};
    let mut capabilities_acknowledged = false;
    loop {
        let Some(envelope) = out_rx.pop().await else {
            return Err(Dropped(super::NetworkFailure::ConnectionLost));
        };
        let line = String::from_utf8_lossy(&envelope.payload.0)
            .trim_end_matches(['\r', '\n'])
            .to_string();
        let Ok(parsed) = e6irc_proto::message::Message::parse(&line) else {
            ends.emit_line(line);
            continue;
        };
        let message = e6irc_client::OwnedMessage::from(&parsed);
        if let Some(rejection) = e6irc_client::RegistrationRejection::from_reply(
            &message,
            e6irc_client::ServerPasswordSent::No,
        ) {
            return Err(RegistrationRejected(rejection));
        }
        match message.command.as_str() {
            "CAP" => match message.params.get(1).map(String::as_str) {
                Some("ACK") => capabilities_acknowledged = true,
                // The core is this binary: refusing what the driver asks of it
                // is a defect in one or the other, said as such.
                _ => {
                    eprintln!(
                        "local bouncer session: the core refused {LOCAL_CAPABILITIES}: {line}"
                    );
                    return Err(super::SessionOutcome::Dropped(
                        super::NetworkFailure::UpstreamProtocolFailed,
                    ));
                }
            },
            "001" if !capabilities_acknowledged => {
                eprintln!(
                    "local bouncer session: the core welcomed the session without answering \
                     CAP REQ :{LOCAL_CAPABILITIES}"
                );
                return Err(super::SessionOutcome::Dropped(
                    super::NetworkFailure::UpstreamProtocolFailed,
                ));
            }
            "001" => {
                let welcomed = message.params.first().cloned().unwrap_or_default();
                // Before its 005, a network's names compare as RFC 1459 says.
                let nick = super::irc_driver::configured_nick_was_granted(
                    &e6irc_client::NetworkNames::default(),
                    &session.nick,
                    welcomed,
                )
                .map_err(RegistrationRejected)?;
                return Ok(Welcome { nick, line });
            }
            "PING" => {
                let token = message.params.first().cloned().unwrap_or_default();
                if !say(&session.core.core_tx, conn, format!("PONG :{token}")).await {
                    return Err(Stopped);
                }
            }
            _ => ends.emit_line(line),
        }
    }
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
            host: LOCAL_SESSION_HOST.into(),
            transport: crate::core::ConnectionTransport::Local,
        })
        .await
        .is_err()
    {
        return Stopped; // core shutting down
    }
    let outcome = drive_session(session, ends, conn, &mut out_rx).await;
    // The one way out of an opened core session, whatever ended it: close it
    // rather than leave it — holding the nickname — for the core's liveness
    // reaper. Queue closure here already means the core is gone.
    let reason = match outcome {
        Stopped => "local driver stopped",
        _ => "local driver session ended",
    };
    drop(
        session
            .core
            .core_tx
            .push(Input::Closed {
                conn,
                reason: reason.into(),
            })
            .await,
    );
    outcome
}

/// Register the opened core session `conn` and relay it until it ends.
async fn drive_session(
    session: &LocalSession,
    ends: &mut DriverEnds,
    conn: ConnId,
    out_rx: &mut Receiver<Output>,
) -> super::SessionOutcome {
    use super::SessionOutcome::Stopped;
    let core = &session.core.core_tx;
    // Register in-process. Queueing NICK and USER is only a request: the core
    // answers like any server, and it is the welcome that makes a session. The
    // capability request holds registration until `CAP END`, so the core has
    // answered it before it welcomes the session.
    for line in [
        format!("CAP REQ :{LOCAL_CAPABILITIES}"),
        format!("NICK {}", session.nick),
        format!("USER {} 0 * :{}", session.username, session.realname),
        "CAP END".to_string(),
    ] {
        if !say(core, conn, line).await {
            return Stopped;
        }
    }
    let welcomed = tokio::select! {
        _ = ends.stop_signal() => Err(Stopped),
        welcome = tokio::time::timeout(
            WELCOME_DEADLINE,
            await_welcome(session, conn, out_rx, ends),
        ) => welcome.unwrap_or(Err(super::SessionOutcome::Dropped(
            super::NetworkFailure::RegistrationTimedOut,
        ))),
    };
    let welcome = match welcomed {
        Ok(welcome) => welcome,
        Err(outcome) => return outcome,
    };
    // Comma-joined within the wire limit, as the IRC driver joins upstream:
    // the in-process session is a registered non-oper client of the core, so
    // one JOIN per channel would spend the command-flood burst on a long
    // autojoin list and be closed with Excess Flood before it finished.
    let autojoin: Vec<(String, Option<super::upstream_identity::ChannelKey>)> = session
        .autojoin
        .iter()
        .map(|channel| (channel.clone(), None))
        .collect();
    for line in super::irc_driver::join_lines(&autojoin) {
        if !say(core, conn, line).await {
            return Stopped;
        }
    }
    // `message-tags` is on: client-only tags are relayed, as to any upstream
    // that carries them.
    ends.set_client_tags(super::ClientTags::Relayed);
    ends.begin_irc_session(welcome.nick);
    ends.emit(ConnectionEvent::Connected);
    if ends.emit_session_line(welcome.line).is_err() {
        return super::SessionOutcome::Dropped(super::NetworkFailure::ChannelLimitExceeded);
    }
    // The core answers each attached client's commands on this one session,
    // in order, like any server; see `super::replies`.
    let mut router = super::replies::ReplyRouter::default();
    let mut echoes = super::irc_driver::UpstreamEchoes::default();

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
                    let message = e6irc_proto::message::Message::parse(&line)
                        .ok()
                        .map(|parsed| e6irc_client::OwnedMessage::from(&parsed));
                    match message.as_ref().map(|message| message.command.as_str()) {
                        // The in-process session is a real registered session,
                        // so the liveness reaper PINGs it after ~2 min idle.
                        // There is no network peer to answer, so answer here —
                        // otherwise the reaper times out and drops the session
                        // every few minutes, churning this always-on network
                        // (spurious dis/reconnect notices, NICK/JOIN replay).
                        // The PING is internal keepalive, not conversation, so
                        // it is not shown in the buffer.
                        Some("PING") => {
                            let token = message
                                .as_ref()
                                .and_then(|message| message.params.first().cloned())
                                .unwrap_or_default();
                            if !say(core, conn, format!("PONG :{token}")).await {
                                return Stopped;
                            }
                            continue;
                        }
                        // Capabilities are this session's negotiation with the
                        // core; an attached client negotiated its own with the
                        // bouncer and would act on these against the wrong hop.
                        Some("CAP") => continue,
                        _ => {}
                    }
                    let own_nick = ends
                        .irc_session_snapshot()
                        .map(|snapshot| snapshot.nick)
                        .unwrap_or_default();
                    let classified = match &message {
                        Some(message) => router.classify(
                            message,
                            line,
                            &ends.names(),
                            &own_nick,
                            std::time::Instant::now(),
                        ),
                        None => super::replies::Upstream::Session { line, origin: None },
                    };
                    match classified {
                        // A correlation PING's answer: the commands sent since
                        // want one of their own.
                        super::replies::Upstream::Consumed => {
                            if let Some(barrier) = router.barrier_due()
                                && !say(core, conn, barrier).await
                            {
                                return Stopped;
                            }
                        }
                        super::replies::Upstream::Reply { line, origin } => {
                            ends.emit_reply(origin, line);
                        }
                        super::replies::Upstream::Session { line, origin } => {
                            // Our own message, echoed by the core: the one echo
                            // of the line an attachment sent.
                            let emitted = match &message {
                                Some(message) => echoes.publish(
                                    ends,
                                    message,
                                    line,
                                    origin,
                                    &own_nick,
                                    &ends.names(),
                                ),
                                None => ends.emit_session_line(line),
                            };
                            if emitted.is_err() {
                                return super::SessionOutcome::Dropped(
                                    super::NetworkFailure::ChannelLimitExceeded,
                                );
                            }
                        }
                    }
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
                    let Some(line) = super::carriable(&cmd, super::ClientTags::Relayed, ends) else {
                        continue;
                    };
                    let written = router.forward(
                        cmd.origin,
                        &line,
                        super::replies::Correlation::Order,
                        &ends.names(),
                        std::time::Instant::now(),
                    );
                    for line in std::iter::once(written).chain(router.barrier_due()) {
                        if !say(core, conn, line).await {
                            return Stopped;
                        }
                    }
                    // The core echoes what it accepts (`echo-message`); the
                    // echo is routed back to the attachment that sent it.
                    echoes.sent(&line, cmd.origin, &ends.names());
                }
                // Every handle dropped: stop for good (no reconnect — the
                // network was removed).
                None => return Stopped,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use e6irc_queue::Sender;
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
            username: "ident".into(),
            realname: "Alice".into(),
            autojoin,
        };
        let (handle, mut ends) = NetworkHandle::channels(8);
        let events = handle.subscribe();
        let task = tokio::spawn(async move { session_once(&session, &mut ends).await });
        (handle, events, task)
    }

    /// Read the session's registration as the core would, up to answering
    /// its capability request, which the core does before anything else.
    async fn open_registration(core_rx: &mut Receiver<Input>) -> Sender<Output> {
        let open = core_rx.pop().await.expect("Open event").payload;
        let Input::Open { tx, .. } = open else {
            panic!("expected Open");
        };
        for expected in [
            "CAP REQ :account-tag echo-message message-tags server-time",
            "NICK alice",
            "USER ident 0 * :Alice",
            "CAP END",
        ] {
            let input = core_rx.pop().await.expect("registration line").payload;
            let Input::Line { line, .. } = input else {
                panic!("expected registration line");
            };
            assert_eq!(String::from_utf8(line).unwrap(), expected);
        }
        tx
    }

    async fn finish_registration(core_rx: &mut Receiver<Input>) -> Sender<Output> {
        let tx = open_registration(core_rx).await;
        core_says(
            &tx,
            ":e6.example CAP * ACK :account-tag echo-message message-tags server-time",
        )
        .await;
        tx
    }

    /// The capabilities are the core's to grant, and it is this binary: one it
    /// refuses, or a welcome that skipped the answer, is a protocol failure,
    /// never a session that silently lacks them.
    #[tokio::test]
    async fn a_refused_capability_request_is_a_protocol_failure() {
        for answer in [
            Some(":e6.example CAP * NAK :account-tag echo-message message-tags server-time"),
            None,
        ] {
            let (core_tx, mut core_rx) = core_queue(8);
            let (handle, _events, task) = spawn_session(core_tx, Vec::new());
            let out_tx = open_registration(&mut core_rx).await;
            if let Some(answer) = answer {
                core_says(&out_tx, answer).await;
            }
            core_says(&out_tx, ":e6.example 001 alice :Welcome").await;
            assert!(
                matches!(
                    stopped(task).await,
                    super::super::SessionOutcome::Dropped(
                        super::super::NetworkFailure::UpstreamProtocolFailed
                    )
                ),
                "{answer:?}"
            );
            assert!(handle.irc_session_snapshot().is_none());
        }
    }

    async fn core_says(out_tx: &Sender<Output>, line: &str) {
        out_tx
            .push(Output(Bytes::from(format!("{line}\r\n"))))
            .await
            .expect("local output queue");
    }

    /// A refused nickname used to look like a connection that was made and
    /// then lost: "connected" to every client, counters reset, and a re-dial
    /// every 200 ms forever. It is a registration refusal, on the refusal
    /// schedule, with the core's own reason.
    #[tokio::test]
    async fn a_refused_nickname_is_a_registration_refusal_not_a_lost_connection() {
        for (reply, refusal) in [
            (
                ":e6.example 433 * alice :Nickname is already in use",
                e6irc_client::RegistrationRefusal::NicknameInUse,
            ),
            (
                ":e6.example 432 * alice :Erroneous nickname",
                e6irc_client::RegistrationRefusal::InvalidNickname,
            ),
            (
                ":e6.example 001 Alicia :Welcome",
                e6irc_client::RegistrationRefusal::WelcomedAsAnotherNickname,
            ),
        ] {
            let (core_tx, mut core_rx) = core_queue(8);
            let (handle, _events, task) = spawn_session(core_tx, vec!["#room".into()]);
            let out_tx = finish_registration(&mut core_rx).await;
            core_says(&out_tx, reply).await;
            let super::super::SessionOutcome::RegistrationRejected(rejection) = stopped(task).await
            else {
                panic!("{reply} was not read as a registration refusal");
            };
            assert_eq!(rejection.refusal(), refusal, "{reply}");
            assert_ne!(
                handle.runtime_snapshot().lifecycle,
                super::super::NetworkLifecycle::Connected
            );
            assert!(handle.irc_session_snapshot().is_none());
            // The half-made core session is closed, never left to the reaper,
            // and nothing was joined under a nickname that was not granted.
            assert!(matches!(
                core_rx.pop().await.expect("close").payload,
                Input::Closed { .. }
            ));
        }
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
        // Queueing NICK and USER is a request, not a registration.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            matches!(
                events.try_recv(),
                Err(broadcast::error::TryRecvError::Empty)
            ),
            "the driver reported a session before the core welcomed it"
        );
        core_says(&out_tx, ":e6.example 001 alice :Welcome").await;
        assert!(matches!(
            events.recv().await,
            Ok(super::super::DriverEvent::Session(
                super::super::IrcSessionSnapshot { ref nick, ref channels }
            )) if nick == "alice" && channels.is_empty()
        ));
        assert!(matches!(
            events.recv().await,
            Ok(super::super::DriverEvent::Status {
                status: super::super::DriverConnectionStatus::Connected,
                ..
            })
        ));
        (core_rx, handle, events, task, out_tx)
    }

    /// The autojoin list reaches the core the way a real client sends it: one
    /// comma-joined JOIN per wire line, never one command per channel, which a
    /// long list would spend the core's command-flood burst on.
    #[tokio::test]
    async fn autojoin_is_sent_as_one_comma_joined_line() {
        let (core_tx, mut core_rx) = core_queue(8);
        let (_handle, _events, _task) = spawn_session(
            core_tx,
            vec!["#room".into(), "#other".into(), "#third".into()],
        );
        let out_tx = finish_registration(&mut core_rx).await;
        core_says(&out_tx, ":e6.example 001 alice :Welcome").await;
        let Input::Line { line, .. } = core_rx.pop().await.expect("join").payload else {
            panic!("expected the autojoin line");
        };
        assert_eq!(String::from_utf8(line).unwrap(), "JOIN #room,#other,#third");
    }

    #[tokio::test]
    async fn autojoin_failure_stops_before_connected() {
        // Two channel names too long to share one 510-byte JOIN line make two
        // lines; capacity one lets the first fill the queue and park the second.
        // Closing the receiver then deterministically fails auto-join.
        let (core_tx, mut core_rx) = core_queue(1);
        let (_handle, mut events, task) = spawn_session(
            core_tx.clone(),
            vec![
                format!("#{}", "r".repeat(300)),
                format!("#{}", "o".repeat(300)),
            ],
        );
        let out_tx = finish_registration(&mut core_rx).await;
        core_says(&out_tx, ":e6.example 001 alice :Welcome").await;
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

    /// A stop that arrives while the core has not yet welcomed the session
    /// closes the half-registered core session, as every other way out of
    /// registration does, instead of leaving it to the liveness reaper.
    #[tokio::test]
    async fn a_stop_during_registration_closes_the_core_session() {
        let (core_tx, mut core_rx) = core_queue(8);
        let (handle, _events, task) = spawn_session(core_tx, Vec::new());
        let _out_tx = finish_registration(&mut core_rx).await;
        handle.shutdown();
        assert!(matches!(
            stopped(task).await,
            super::super::SessionOutcome::Stopped
        ));
        assert!(matches!(
            core_rx.pop().await.expect("close").payload,
            Input::Closed { .. }
        ));
    }

    /// A session that ends because the core put it in more channels than
    /// the bouncer tracks is closed in the core like every other ending. It
    /// used to be left open, holding the nickname, until the liveness reaper
    /// found it, so the reconnect met its own ghost.
    #[tokio::test]
    async fn a_session_past_the_channel_limit_closes_its_core_session() {
        let (mut core_rx, _handle, _events, task, out_tx) = connected_session().await;
        for n in 0..=super::super::MAX_TRACKED_CHANNELS {
            core_says(&out_tx, &format!(":alice!ident@local JOIN #c{n}")).await;
        }
        assert!(matches!(
            stopped(task).await,
            super::super::SessionOutcome::Dropped(
                super::super::NetworkFailure::ChannelLimitExceeded
            )
        ));
        assert!(matches!(
            core_rx.pop().await.expect("close").payload,
            Input::Closed { .. }
        ));
    }

    /// The next line the session wrote to the core, and the ordering barrier
    /// its reply router sent after it (`super::super::replies`), which the
    /// core answers once it has answered the line.
    async fn core_heard(core_rx: &mut Receiver<Input>) -> (String, String) {
        let mut heard = Vec::new();
        while heard.len() < 2 {
            let Input::Line { line, .. } = core_rx.pop().await.expect("a line").payload else {
                panic!("expected a line");
            };
            heard.push(String::from_utf8(line).expect("UTF-8"));
        }
        let barrier = heard.pop().expect("two lines");
        let token = barrier
            .strip_prefix("PING :")
            .unwrap_or_else(|| panic!("expected a barrier, got {barrier}"));
        let answer = format!(":e6.example PONG e6.example :{token}");
        (heard.pop().expect("the line"), answer)
    }

    /// The next echo the session published, with the attachment it is for.
    async fn next_echo(
        events: &mut broadcast::Receiver<super::super::DriverEvent>,
    ) -> (String, u64) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Ok(super::super::DriverEvent::Echo { line, origin }) = events.recv().await {
                    return (line.line, origin);
                }
            }
        })
        .await
        .expect("the echo")
    }

    /// The local network carries what makes typing and reactions work: a
    /// client's tags and its `TAGMSG` reach the core as sent, and the one echo
    /// of a message is the core's, with the `msgid` and time the core gave it —
    /// the message a reaction to it names — routed to the attachment that sent
    /// it. Nothing is synthesized in its place.
    #[tokio::test]
    async fn client_tags_reach_the_core_and_the_core_echoes_the_message() {
        let (mut core_rx, handle, mut events, _task, out_tx) = connected_session().await;
        for (line, echoed) in [
            (
                "@+draft/reply=m0;+draft/react=:+1: TAGMSG #room",
                "@time=2026-01-01T00:00:01.000Z;msgid=m1;+draft/reply=m0;+draft/react=:+1: \
                 :alice!ident@local TAGMSG #room",
            ),
            (
                "PRIVMSG #room :hello",
                "@time=2026-01-01T00:00:02.000Z;msgid=m2 :alice!ident@local PRIVMSG #room :hello",
            ),
        ] {
            assert_eq!(handle.send_from(3, line), super::super::SendOutcome::Sent);
            let (heard, barrier) = core_heard(&mut core_rx).await;
            assert_eq!(heard, line);
            core_says(&out_tx, echoed).await;
            core_says(&out_tx, &barrier).await;
            assert_eq!(next_echo(&mut events).await, (echoed.to_string(), 3));
        }
        let (_, welcome) =
            super::super::serve::welcome("bnc.test", LOCAL_NETWORK, &handle, "alice".into());
        let welcome = welcome.join("\n");
        assert!(!welcome.contains("CLIENTTAGDENY=*"), "{welcome}");
    }

    /// A line the core refuses has no echo: its refusal is the whole answer,
    /// and no echo is made up for a message nobody received.
    #[tokio::test]
    async fn a_refused_message_is_not_echoed() {
        let (mut core_rx, handle, mut events, _task, out_tx) = connected_session().await;
        assert_eq!(
            handle.send_from(3, "PRIVMSG #nowhere :hello"),
            super::super::SendOutcome::Sent
        );
        let (heard, barrier) = core_heard(&mut core_rx).await;
        assert_eq!(heard, "PRIVMSG #nowhere :hello");
        core_says(&out_tx, ":e6.example 403 alice #nowhere :No such channel").await;
        core_says(&out_tx, &barrier).await;
        // The next message's echo is the next one published.
        assert_eq!(
            handle.send_from(4, "PRIVMSG #room :again"),
            super::super::SendOutcome::Sent
        );
        let echo =
            "@time=2026-01-01T00:00:03.000Z;msgid=m3 :alice!ident@local PRIVMSG #room :again";
        core_says(&out_tx, echo).await;
        assert_eq!(next_echo(&mut events).await, (echo.to_string(), 4));
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
