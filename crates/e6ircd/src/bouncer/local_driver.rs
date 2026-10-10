//! The `local` network driver: an in-process client of this e6ircd's own
//! core. It gives a BNC user an always-on presence on the local network
//! (with backlog), exactly like the `irc` driver gives them presence on
//! an external one — but over the core queue instead of a socket.
//!
//! In edge mode its session survives a graceful restart (decision D13): its
//! link is a holding one, whose records the driver hands the core's
//! [`LocalHomes`] for a cut to home on an edge, and the next core rebuilds the
//! session and hands it back. The driver then takes it up where it was — asks
//! the core what a welcome would have told and what its channels hold, and
//! tells nobody — instead of registering again: its channels see no QUIT and
//! no JOIN.

use std::sync::Arc;

use e6irc_edge::connection::CorePort;

use super::irc_driver::{JoinedChannels, UpstreamControl};
use super::upstream_identity::AutojoinChannel;
use super::{ConnectionEvent, DriverEnds, NetworkConfig, NetworkDriver, NetworkHandle};
use crate::core::local_home::{LocalHomeKey, LocalHomes, ResumedLocal};
use crate::core::{ConnId, ConnectionIdAllocator, CoreIngress, EdgeSession};

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

/// The token of the `PING` that ends a resumed session's questions: its
/// `PONG` follows every answer before it.
const RESUMED_TOKEN: &str = "e6irc-resumed";

/// Handles into the core, so the driver can open an in-process session.
#[derive(Clone)]
pub struct CoreHandles {
    pub core_tx: CoreIngress,
    pub next_conn: Arc<ConnectionIdAllocator>,
    /// Each session's SendQ capacity, in bytes.
    pub sendq_bytes: usize,
}

pub struct LocalDriver {
    core: CoreHandles,
    home: LocalHomeKey,
    nick: String,
    username: String,
    realname: String,
    autojoin: Vec<AutojoinChannel>,
    buffer_cap: usize,
}

impl LocalDriver {
    /// Build a local driver from the same `NetworkConfig` the `irc`
    /// driver uses (addr/tls/sasl are ignored — there is no socket), for the
    /// network `home` names.
    pub(crate) fn new(core: CoreHandles, config: NetworkConfig, home: LocalHomeKey) -> Self {
        Self {
            core,
            home,
            // Already parsed: the same one-parameter guarantees hold for the
            // lines this driver injects into the in-process core.
            nick: config.nick.to_string(),
            username: config.username.to_string(),
            realname: config.realname.as_str().to_string(),
            autojoin: config.autojoin,
            buffer_cap: config.buffer_cap,
        }
    }
}

impl NetworkDriver for LocalDriver {
    fn kind(&self) -> &'static str {
        LOCAL_NETWORK
    }

    fn prepare(self: Box<Self>) -> super::PreparedDriver {
        let (handle, ends) = NetworkHandle::channels(self.buffer_cap);
        let this = *self;
        let session = LocalSession {
            core: this.core,
            home: this.home,
            nick: this.nick,
            username: this.username,
            realname: this.realname,
            autojoin: this.autojoin,
            joined: JoinedChannels::default(),
        };
        super::PreparedDriver::new(handle, run(session, ends))
    }
}

/// Per-session configuration for the local driver, reconnected on each drop.
struct LocalSession {
    core: CoreHandles,
    /// Which network this is, as a restart homes its session.
    home: LocalHomeKey,
    nick: String,
    username: String,
    realname: String,
    /// The configured channels to join, keyed ones with their keys.
    autojoin: Vec<AutojoinChannel>,
    /// The channels the core confirmed this driver in, kept across sessions:
    /// after a KILL or a GHOST ends one, the next rejoins them as well as the
    /// configured ones, as the `irc` driver rejoins an upstream's (§10.2).
    joined: JoinedChannels,
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

/// The in-process session's lines to the core, metered like any client's
/// (`e6irc_edge::meter`): an owner's paste is paced, not refused.
struct CoreLines<'a> {
    core: &'a CoreIngress,
    conn: ConnId,
    meter: e6irc_edge::meter::LineMeter,
}

impl<'a> CoreLines<'a> {
    fn new(core: &'a CoreIngress, conn: ConnId, edge: &EdgeSession) -> Self {
        Self {
            core,
            conn,
            meter: edge.line_meter(core.command_flood()),
        }
    }

    /// Queue one line for the core. `false` means the core is gone.
    async fn say(&mut self, line: String) -> bool {
        let mut events = vec![e6irc_proto::framing::LineEvent::Line(line.into_bytes())];
        e6irc_edge::connection::hand_over(self.core, &mut self.meter, self.conn, &mut events).await
    }
}

/// The session's link as the driver reads it: the edge's end, and the homes
/// it hands what the core publishes for the session to be held.
struct SessionEnd<'a> {
    conn: ConnId,
    edge: &'a mut EdgeSession,
    homes: &'a LocalHomes,
}

impl SessionEnd<'_> {
    /// The core's next line to the in-process session, its CRLF stripped —
    /// only the frame's, not all trailing whitespace, since a trailing
    /// parameter may end in spaces. The session is its own writer, so taking a
    /// line is writing it ([`EdgeSession::pop`]), and what the core published
    /// after the lines taken is taken with it. `None` once the core has ended
    /// the session.
    async fn next_output(&mut self) -> Option<String> {
        let line = self.edge.pop().await?.payload.0;
        self.homes.hold(self.conn, self.edge);
        Some(
            String::from_utf8_lossy(&line)
                .trim_end_matches(['\r', '\n'])
                .to_string(),
        )
    }

    /// Take what the core published for the session to be held.
    fn take_held(&mut self) {
        self.homes.hold(self.conn, self.edge);
    }
}

/// Read the core's replies until it welcomes the session under the configured
/// nickname, with [`LOCAL_CAPABILITIES`] acknowledged first. A refusal is read by the same table the IRC driver's registration
/// uses, so it takes the refusal schedule and parks like any other upstream's —
/// not the transient schedule of a connection that was made and lost. Lines
/// that are neither are the core talking to its new client, and are relayed.
async fn await_welcome(
    session: &LocalSession,
    lines: &mut CoreLines<'_>,
    end: &mut SessionEnd<'_>,
    ends: &DriverEnds,
) -> Result<Welcome, super::SessionOutcome> {
    use super::SessionOutcome::{Dropped, RegistrationRejected, Stopped};
    let mut capabilities_acknowledged = false;
    loop {
        let Some(line) = end.next_output().await else {
            return Err(Dropped(super::NetworkFailure::ConnectionLost));
        };
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
                let nick = super::irc_driver::requested_nick_was_granted(
                    &e6irc_client::NetworkNames::default(),
                    &session.nick,
                    welcomed,
                )
                .map_err(RegistrationRejected)?;
                return Ok(Welcome { nick, line });
            }
            _ => match super::irc_driver::upstream_control(&message, ends) {
                Some(UpstreamControl::Answer(answer)) => {
                    if !lines.say(answer).await {
                        return Err(Stopped);
                    }
                }
                Some(UpstreamControl::Capabilities | UpstreamControl::Consumed) => {}
                Some(UpstreamControl::Closed(closed)) => {
                    return Err(super::SessionOutcome::ClosedByUpstream(closed));
                }
                None => ends.emit_line(line),
            },
        }
    }
}

/// The session one attempt drives: one a rebuild resumed for this network,
/// or a new one, registered here.
enum Taken {
    Resumed {
        nick: String,
        user: String,
        channels: Vec<String>,
    },
    Opened,
}

async fn session_once(session: &LocalSession, ends: &mut DriverEnds) -> super::SessionOutcome {
    use super::SessionOutcome::Stopped;
    // A core rebuilding what its edges held opens no session of its own until
    // it has: this one's channels are among those it restores, and the
    // session itself may be.
    let held = session.core.core_tx.directories().held;
    held.rebuilt.wait().await;
    let homes = held.homes;
    let (conn, mut edge, taken) = match homes.take_resumed(&session.home) {
        Some(ResumedLocal {
            conn,
            edge,
            nick,
            user,
            channels,
        }) => (
            conn,
            edge,
            Taken::Resumed {
                nick,
                user,
                channels,
            },
        ),
        None => {
            let conn = match session.core.next_conn.allocate() {
                Ok(conn) => conn,
                Err(error) => {
                    eprintln!("local bouncer connection stopped: {error}");
                    return Stopped;
                }
            };
            let Some(edge) = open(session, conn, &homes).await else {
                return Stopped; // core shutting down
            };
            (conn, edge, Taken::Opened)
        }
    };
    let outcome = {
        // Followed while it lasts, so a cut finds its record.
        let _followed = homes
            .homing()
            .then(|| homes.follow(conn, session.home.clone(), &edge));
        let mut end = SessionEnd {
            conn,
            edge: &mut edge,
            homes: &homes,
        };
        match taken {
            Taken::Resumed {
                nick,
                user,
                channels,
            } => resume_session(session, ends, &mut end, nick, user, channels).await,
            Taken::Opened => drive_session(session, ends, &mut end).await,
        }
    };
    // The one way out of an opened core session, whatever ended it: close it
    // rather than leave it — holding the nickname — for the core's liveness
    // reaper. Queue closure here already means the core is gone.
    let reason = match outcome {
        Stopped => "local driver stopped",
        _ => "local driver session ended",
    };
    session
        .core
        .core_tx
        .closed(
            conn,
            e6irc_edge::connection::SessionClosed::Stopped(reason.into()),
        )
        .await;
    outcome
}

/// Open `conn`'s session in the core: on a link whose records are held in
/// edge mode, so a cut can home it. `None` when the core is shutting down.
async fn open(session: &LocalSession, conn: ConnId, homes: &LocalHomes) -> Option<EdgeSession> {
    let core = &session.core.core_tx;
    let (open, edge) = core.open_input(
        conn,
        LOCAL_SESSION_HOST.into(),
        crate::core::ConnectionTransport::Local,
        None,
        session.core.sendq_bytes,
        homes.homing(),
    );
    core.push(open).await.ok().map(|_sequence| edge)
}

/// Register the opened core session and relay it until it ends.
async fn drive_session(
    session: &LocalSession,
    ends: &mut DriverEnds,
    end: &mut SessionEnd<'_>,
) -> super::SessionOutcome {
    use super::SessionOutcome::Stopped;
    let mut lines = CoreLines::new(&session.core.core_tx, end.conn, end.edge);
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
        if !lines.say(line).await {
            return Stopped;
        }
    }
    let welcomed = tokio::select! {
        _ = ends.stop_signal() => Err(Stopped),
        welcome = tokio::time::timeout(
            WELCOME_DEADLINE,
            await_welcome(session, &mut lines, end, ends),
        ) => welcome.unwrap_or(Err(super::SessionOutcome::Dropped(
            super::NetworkFailure::RegistrationTimedOut,
        ))),
    };
    let welcome = match welcomed {
        Ok(welcome) => welcome,
        Err(outcome) => return outcome,
    };
    // The configured channels and every one the core confirmed before the
    // session ended, comma-joined within the wire limit, as the IRC driver
    // rejoins upstream: the in-process session is metered like any client of
    // the core, so one JOIN per channel would spend the command-flood burst on
    // a long list and wait out its refill before it finished.
    for line in super::irc_driver::join_lines(&session.joined.rejoin(&session.autojoin)) {
        if !lines.say(line).await {
            return Stopped;
        }
    }
    // `message-tags` is on: client-only tags are relayed, as to any upstream
    // that carries them.
    ends.set_client_tags(super::ClientTags::Relayed);
    ends.begin_irc_session(welcome.nick.clone());
    ends.emit(ConnectionEvent::Connected);
    if ends.emit_session_line(welcome.line).is_err() {
        return super::SessionOutcome::Dropped(super::NetworkFailure::ChannelLimitExceeded);
    }
    let relay = Relay::new(
        session,
        lines,
        super::irc_driver::SelfIdentity {
            nick: welcome.nick,
            user: session.username.clone(),
            host: LOCAL_SESSION_HOST.to_string(),
        },
    );
    relay.run(ends, end, Vec::new()).await
}

/// Take up the session a rebuild resumed (D13), registered as `nick` (user
/// `user`) and in `channels`: ask the core what a welcome would have said of
/// the network (`VERSION`'s ISUPPORT) and what each channel holds (`TOPIC`,
/// `NAMES`), take the answers into the session's state without anyone seeing
/// them, and relay on. What the core says meanwhile that is not an answer is
/// relayed once the state is taken up.
async fn resume_session(
    session: &LocalSession,
    ends: &mut DriverEnds,
    end: &mut SessionEnd<'_>,
    nick: String,
    user: String,
    channels: Vec<String>,
) -> super::SessionOutcome {
    use super::SessionOutcome::Stopped;
    let mut lines = CoreLines::new(&session.core.core_tx, end.conn, end.edge);
    let questions = std::iter::once("VERSION".to_owned())
        .chain(
            channels
                .iter()
                .flat_map(|channel| [format!("TOPIC {channel}"), format!("NAMES {channel}")]),
        )
        .chain(std::iter::once(format!("PING :{RESUMED_TOKEN}")));
    for line in questions {
        if !lines.say(line).await {
            return Stopped;
        }
    }
    let answered = tokio::select! {
        _ = ends.stop_signal() => Err(Stopped),
        answers = tokio::time::timeout(WELCOME_DEADLINE, resumed_answers(&mut lines, end, ends))
            => answers.unwrap_or(Err(super::SessionOutcome::Dropped(
                super::NetworkFailure::RegistrationTimedOut,
            ))),
    };
    let (answers, deferred) = match answered {
        Ok(answered) => answered,
        Err(outcome) => return outcome,
    };
    let names = e6irc_client::NetworkNames::default();
    // The ISUPPORT first, then each channel as joining it would have told it:
    // our JOIN, then its topic and members.
    let isupport = answers
        .iter()
        .filter(|(_, message)| message.command == "005")
        .map(|(line, _)| line.clone());
    let joined = channels.iter().flat_map(|channel| {
        let own_join = format!(":{nick}!{user}@{LOCAL_SESSION_HOST} JOIN {channel}");
        let answers = answers
            .iter()
            .filter(|(_, message)| {
                answered_channel(message).is_some_and(|named| names.eq(named, channel))
            })
            .map(|(line, _)| line.clone());
        std::iter::once(own_join).chain(answers).collect::<Vec<_>>()
    });
    let burst: Vec<String> = isupport.chain(joined).collect();
    ends.set_client_tags(super::ClientTags::Relayed);
    let changes = match ends.resume_irc_session(nick.clone(), burst) {
        Ok(changes) => changes,
        Err(super::ChannelLimitExceeded) => {
            return super::SessionOutcome::Dropped(super::NetworkFailure::ChannelLimitExceeded);
        }
    };
    let mut relay = Relay::new(
        session,
        lines,
        super::irc_driver::SelfIdentity {
            nick,
            user,
            host: LOCAL_SESSION_HOST.to_string(),
        },
    );
    for change in changes {
        if super::irc_driver::track(
            ends,
            &session.joined,
            &mut relay.identity,
            &mut relay.requested_nicks,
            Ok(change),
        )
        .is_err()
        {
            return super::SessionOutcome::Dropped(super::NetworkFailure::ChannelLimitExceeded);
        }
    }
    ends.connected_across_restart();
    relay.run(ends, end, deferred).await
}

/// The channel a reply about one names: a topic's (`331`, `332`, `333`) or a
/// member list's (`353`, `366`).
fn answered_channel(message: &e6irc_client::OwnedMessage) -> Option<&str> {
    let index = match message.command.as_str() {
        "331" | "332" | "333" | "366" => 1,
        "353" => 2,
        _ => return None,
    };
    message.params.get(index).map(String::as_str)
}

/// A line the core sent while a resumed session's questions were answered,
/// parsed.
type Answer = (String, e6irc_client::OwnedMessage);

/// Read the core's answers to a resumed session's questions, up to the
/// `PONG` of [`RESUMED_TOKEN`]: the numerics addressed to the session, and
/// apart from them every other line, in order, for the relay to take once the
/// session's state is taken up. The core's own `PING` is answered here.
async fn resumed_answers(
    lines: &mut CoreLines<'_>,
    end: &mut SessionEnd<'_>,
    ends: &DriverEnds,
) -> Result<(Vec<Answer>, Vec<String>), super::SessionOutcome> {
    let mut answers = Vec::new();
    let mut deferred = Vec::new();
    loop {
        let Some(line) = end.next_output().await else {
            return Err(super::SessionOutcome::Dropped(
                super::NetworkFailure::ConnectionLost,
            ));
        };
        let Ok(parsed) = e6irc_proto::message::Message::parse(&line) else {
            deferred.push(line);
            continue;
        };
        let message = e6irc_client::OwnedMessage::from(&parsed);
        if message.command == "PONG"
            && message.params.last().map(String::as_str) == Some(RESUMED_TOKEN)
        {
            return Ok((answers, deferred));
        }
        if message.command == "PING" {
            match super::irc_driver::upstream_control(&message, ends) {
                Some(UpstreamControl::Answer(answer)) => {
                    if !lines.say(answer).await {
                        return Err(super::SessionOutcome::Stopped);
                    }
                }
                _ => deferred.push(line),
            }
            continue;
        }
        let numeric =
            message.command.len() == 3 && message.command.bytes().all(|byte| byte.is_ascii_digit());
        if numeric {
            answers.push((line, message));
        } else {
            deferred.push(line);
        }
    }
}

/// A registered session's relay between the core and the network's
/// attachments.
struct Relay<'a> {
    session: &'a LocalSession,
    lines: CoreLines<'a>,
    /// The core answers each attached client's commands on this one
    /// session, in order, like any server; see `super::replies`.
    router: super::replies::ReplyRouter,
    echoes: super::irc_driver::UpstreamEchoes,
    requested_nicks: super::irc_driver::RequestedNicks,
    identity: super::irc_driver::SelfIdentity,
}

impl<'a> Relay<'a> {
    fn new(
        session: &'a LocalSession,
        lines: CoreLines<'a>,
        identity: super::irc_driver::SelfIdentity,
    ) -> Self {
        Self {
            session,
            lines,
            router: super::replies::ReplyRouter::default(),
            echoes: super::irc_driver::UpstreamEchoes::default(),
            requested_nicks: super::irc_driver::RequestedNicks::default(),
            identity,
        }
    }

    /// Relay `first`, then everything else, until the session ends.
    async fn run(
        mut self,
        ends: &mut DriverEnds,
        end: &mut SessionEnd<'_>,
        first: Vec<String>,
    ) -> super::SessionOutcome {
        use super::SessionOutcome::Stopped;
        for line in first {
            if let Some(outcome) = self.output(ends, line).await {
                return outcome;
            }
        }
        let published = end.edge.held_signal();
        loop {
            // Past the session's command allowance, the attachments' commands
            // wait until a token is back; the core's output keeps flowing.
            let blocked = self.lines.meter.blocked_until(tokio::time::Instant::now());
            tokio::select! {
                () = tokio::time::sleep_until(blocked.unwrap_or_else(tokio::time::Instant::now)), if blocked.is_some() => {}
                // What the core publishes for the session to be held.
                () = published.published() => end.take_held(),
                // Core output -> buffer + broadcast (attach playback/live).
                out = end.next_output() => match out {
                    Some(line) => {
                        if let Some(outcome) = self.output(ends, line).await {
                            return outcome;
                        }
                    }
                    // Core closed our session: reconnect with a fresh ConnId
                    // (and emit Disconnected via run_with_backoff) rather than
                    // die.
                    None => {
                        return super::SessionOutcome::Dropped(
                            super::NetworkFailure::ConnectionLost,
                        );
                    }
                },
                // Downstream command -> core.
                cmd = ends.next_command(), if blocked.is_none() => match cmd {
                    Some(cmd) => {
                        if let Some(outcome) = self.command(ends, cmd).await {
                            return outcome;
                        }
                    }
                    // Every handle dropped: stop for good (no reconnect — the
                    // network was removed).
                    None => return Stopped,
                },
            }
        }
    }

    /// Relay one line of the core's; the session's end, when it ends it.
    async fn output(
        &mut self,
        ends: &mut DriverEnds,
        line: String,
    ) -> Option<super::SessionOutcome> {
        use super::SessionOutcome::Stopped;
        let message = e6irc_proto::message::Message::parse(&line)
            .ok()
            .map(|parsed| e6irc_client::OwnedMessage::from(&parsed));
        // The in-process session is a real registered session, so the
        // liveness reaper PINGs it after ~2 min idle, and the core ends it
        // with `ERROR` on a KILL, a GHOST or a ban: the session's own
        // business, read as the `irc` driver reads an upstream's, never an
        // attached client's line.
        match message
            .as_ref()
            .and_then(|message| super::irc_driver::upstream_control(message, ends))
        {
            Some(UpstreamControl::Answer(answer)) => {
                return (!self.lines.say(answer).await).then_some(Stopped);
            }
            Some(UpstreamControl::Capabilities | UpstreamControl::Consumed) => return None,
            Some(UpstreamControl::Closed(closed)) => {
                return Some(super::SessionOutcome::ClosedByUpstream(closed));
            }
            None => {}
        }
        if let Some(message) = &message {
            super::irc_driver::follow_membership(
                ends,
                &self.session.joined,
                message,
                &ends.names(),
            );
        }
        let own_nick = self.identity.nick.clone();
        let classified = match &message {
            Some(message) => self.router.classify(
                message,
                line,
                &ends.names(),
                &own_nick,
                std::time::Instant::now(),
            ),
            None => super::replies::Upstream::Session { line, origin: None },
        };
        match classified {
            // A correlation PING's answer: the commands sent since want one
            // of their own.
            super::replies::Upstream::Consumed => {
                if let Some(barrier) = self.router.barrier_due()
                    && !self.lines.say(barrier).await
                {
                    return Some(Stopped);
                }
            }
            super::replies::Upstream::Reply { line, origin } => {
                ends.emit_reply(origin, line);
            }
            super::replies::Upstream::Session { line, origin } => {
                // Our own message, echoed by the core: the one echo of the
                // line an attachment sent.
                let emitted = match &message {
                    Some(message) => {
                        self.echoes
                            .publish(ends, message, line, origin, &own_nick, &ends.names())
                    }
                    None => ends.emit_session_line(line),
                };
                if super::irc_driver::track(
                    ends,
                    &self.session.joined,
                    &mut self.identity,
                    &mut self.requested_nicks,
                    emitted,
                )
                .is_err()
                {
                    return Some(super::SessionOutcome::Dropped(
                        super::NetworkFailure::ChannelLimitExceeded,
                    ));
                }
            }
        }
        None
    }

    /// Send one attachment's command to the core; the session's end, when the
    /// core is gone.
    async fn command(
        &mut self,
        ends: &mut DriverEnds,
        cmd: super::ClientCommand,
    ) -> Option<super::SessionOutcome> {
        let line = super::irc_driver::outgoing(
            &cmd,
            super::ClientTags::Relayed,
            ends,
            &self.session.joined,
        )?;
        self.requested_nicks.observe(&line);
        let written = self.router.forward(
            cmd.origin,
            &line,
            super::replies::Correlation::Order,
            &ends.names(),
            std::time::Instant::now(),
        );
        for line in std::iter::once(written).chain(self.router.barrier_due()) {
            if !self.lines.say(line).await {
                return Some(super::SessionOutcome::Stopped);
            }
        }
        // The core echoes what it accepts (`echo-message`); the echo is routed
        // back to the attachment that sent it.
        self.echoes.sent(&line, cmd.origin, &ends.names());
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{Input, Output, SendQueue};
    use bytes::Bytes;
    use e6irc_queue::{Config as QueueConfig, Policy, Receiver, Sender, queue};
    use tokio::sync::broadcast;

    fn core_queue(capacity: usize) -> (Sender<Input>, Receiver<Input>) {
        queue(QueueConfig {
            name: "local-driver-test-core",
            capacity,
            policy: Policy::Fifo,
        })
    }

    fn core_handles(core_tx: Sender<Input>) -> CoreHandles {
        CoreHandles {
            core_tx: CoreIngress::single(core_tx),
            next_conn: Arc::new(ConnectionIdAllocator::new(std::num::NonZeroU64::MIN)),
            sendq_bytes: 8 * 512,
        }
    }

    fn local_session(core_tx: Sender<Input>, autojoin: Vec<String>) -> LocalSession {
        LocalSession {
            core: core_handles(core_tx),
            home: LocalHomeKey::new(None, LOCAL_NETWORK),
            nick: "alice".into(),
            username: "ident".into(),
            realname: "Alice".into(),
            autojoin: autojoin
                .into_iter()
                .map(|channel| {
                    AutojoinChannel::from_entry(&super::super::AutojoinEntry { channel, key: None })
                        .expect("a valid autojoin channel")
                })
                .collect(),
            joined: JoinedChannels::default(),
        }
    }

    fn spawn_session(
        core_tx: Sender<Input>,
        autojoin: Vec<String>,
    ) -> (
        NetworkHandle,
        broadcast::Receiver<super::super::DriverEvent>,
        tokio::task::JoinHandle<super::super::SessionOutcome>,
    ) {
        let session = local_session(core_tx, autojoin);
        let (handle, mut ends) = NetworkHandle::channels(8);
        let events = handle.subscribe();
        let task = tokio::spawn(async move { session_once(&session, &mut ends).await });
        (handle, events, task)
    }

    /// Read the session's registration as the core would, up to answering
    /// its capability request, which the core does before anything else.
    async fn open_registration(core_rx: &mut Receiver<Input>) -> SendQueue {
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

    async fn finish_registration(core_rx: &mut Receiver<Input>) -> SendQueue {
        let mut tx = open_registration(core_rx).await;
        core_says(
            &mut tx,
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
            let mut out_tx = open_registration(&mut core_rx).await;
            if let Some(answer) = answer {
                core_says(&mut out_tx, answer).await;
            }
            core_says(&mut out_tx, ":e6.example 001 alice :Welcome").await;
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

    /// Send `line` to the session over its link, waiting for the session to
    /// read enough of what came before for it to fit: the session reports
    /// each line written as it reads it.
    async fn core_says(out_tx: &mut SendQueue, line: &str) {
        let line = Output(Bytes::from(format!("{line}\r\n")));
        loop {
            match out_tx.0.output(line.clone()) {
                Ok(sent) => {
                    assert_eq!(sent, e6irc_edge::link::Sent::Buffered);
                    return;
                }
                Err(e6irc_edge::link::OutputRefused::OverBound) => tokio::task::yield_now().await,
                Err(refused) => panic!("{refused:?}"),
            }
        }
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
            let mut out_tx = finish_registration(&mut core_rx).await;
            core_says(&mut out_tx, reply).await;
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
        SendQueue,
    ) {
        let (core_tx, mut core_rx) = core_queue(8);
        let (handle, mut events, task) = spawn_session(core_tx, Vec::new());
        let mut out_tx = finish_registration(&mut core_rx).await;
        // Queueing NICK and USER is a request, not a registration.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            matches!(
                events.try_recv(),
                Err(broadcast::error::TryRecvError::Empty)
            ),
            "the driver reported a session before the core welcomed it"
        );
        core_says(&mut out_tx, ":e6.example 001 alice :Welcome").await;
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
        let mut out_tx = finish_registration(&mut core_rx).await;
        core_says(&mut out_tx, ":e6.example 001 alice :Welcome").await;
        let Input::Line { line, .. } = core_rx.pop().await.expect("join").payload else {
            panic!("expected the autojoin line");
        };
        assert_eq!(String::from_utf8(line).unwrap(), "JOIN #room,#other,#third");
    }

    #[tokio::test]
    async fn autojoin_failure_stops_before_connected() {
        // Nine 60-byte channel names cannot share one 510-byte JOIN line, so
        // they make two; capacity one lets the first fill the queue and park
        // the second. Closing the receiver then deterministically fails
        // auto-join.
        let (core_tx, mut core_rx) = core_queue(1);
        let (_handle, mut events, task) = spawn_session(
            core_tx.clone(),
            (0..9).map(|n| format!("#{n}{}", "r".repeat(58))).collect(),
        );
        let mut out_tx = finish_registration(&mut core_rx).await;
        core_says(&mut out_tx, ":e6.example 001 alice :Welcome").await;
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
        let (core_rx, _handle, _events, task, mut out_tx) = connected_session().await;
        drop(core_rx);

        core_says(&mut out_tx, "PING :keepalive").await;
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
        let (mut core_rx, _handle, _events, task, mut out_tx) = connected_session().await;
        for n in 0..=super::super::MAX_TRACKED_CHANNELS {
            core_says(&mut out_tx, &format!(":alice!ident@local JOIN #c{n}")).await;
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
        let (mut core_rx, handle, mut events, _task, mut out_tx) = connected_session().await;
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
            core_says(&mut out_tx, echoed).await;
            core_says(&mut out_tx, &barrier).await;
            assert_eq!(next_echo(&mut events).await, (echoed.to_string(), 3));
        }
        let welcome = super::super::serve::welcome_to("bnc.test", LOCAL_NETWORK, &handle, "alice")
            .lines
            .join("\n");
        assert!(!welcome.contains("CLIENTTAGDENY=*"), "{welcome}");
    }

    /// A line the core refuses has no echo: its refusal is the whole answer,
    /// and no echo is made up for a message nobody received.
    #[tokio::test]
    async fn a_refused_message_is_not_echoed() {
        let (mut core_rx, handle, mut events, _task, mut out_tx) = connected_session().await;
        assert_eq!(
            handle.send_from(3, "PRIVMSG #nowhere :hello"),
            super::super::SendOutcome::Sent
        );
        let (heard, barrier) = core_heard(&mut core_rx).await;
        assert_eq!(heard, "PRIVMSG #nowhere :hello");
        core_says(
            &mut out_tx,
            ":e6.example 403 alice #nowhere :No such channel",
        )
        .await;
        core_says(&mut out_tx, &barrier).await;
        // The next message's echo is the next one published.
        assert_eq!(
            handle.send_from(4, "PRIVMSG #room :again"),
            super::super::SendOutcome::Sent
        );
        // The core answers a line only after hearing it: an echo written
        // before the session has sent the message is an echo of nothing.
        let (heard, barrier) = core_heard(&mut core_rx).await;
        assert_eq!(heard, "PRIVMSG #room :again");
        let echo =
            "@time=2026-01-01T00:00:03.000Z;msgid=m3 :alice!ident@local PRIVMSG #room :again";
        core_says(&mut out_tx, echo).await;
        core_says(&mut out_tx, &barrier).await;
        assert_eq!(next_echo(&mut events).await, (echo.to_string(), 4));
    }

    /// The core ends the in-process session with `ERROR` on a KILL, a
    /// NickServ GHOST or REGAIN, a K- or D-line. The line used to be relayed
    /// like conversation: every attached client read an `ERROR` as the end of
    /// its own connection (several reconnect on it), and the backlog replayed
    /// it on every attach after. It is the session's end, said as a notice.
    #[tokio::test]
    async fn the_cores_error_ends_the_session_and_reaches_no_client() {
        let (_core_rx, handle, mut events, task, mut out_tx) = connected_session().await;
        core_says(
            &mut out_tx,
            "ERROR :Closing Link: local (Killed (oper (bye)))",
        )
        .await;
        let super::super::SessionOutcome::ClosedByUpstream(closed) = stopped(task).await else {
            panic!("the core's ERROR is the session's end");
        };
        assert_eq!(
            closed.diagnostic(),
            "Closing Link: local (Killed (oper (bye)))"
        );
        let mut published = Vec::new();
        while let Ok(event) = events.try_recv() {
            if let Some(line) = event.display_line() {
                published.push(line.to_string());
            }
        }
        let backlog = handle.buffer_snapshot();
        for line in published.iter().chain(&backlog) {
            assert!(!line.contains("ERROR"), "{line}");
        }
        assert!(
            backlog.iter().any(|line| line.ends_with(
                ":*bnc* NOTICE * :upstream closed the link: Closing Link: local (Killed (oper (bye)))"
            )),
            "{backlog:?}"
        );
    }

    /// A session the core ended (a KILL, a GHOST) is followed by one that
    /// rejoins every channel the core had confirmed, not only the configured
    /// ones: a channel joined at runtime used to be lost to the first KILL,
    /// where the `irc` driver rejoins an upstream's.
    #[tokio::test]
    async fn a_session_after_a_kill_rejoins_the_channels_joined_at_runtime() {
        let (core_tx, mut core_rx) = core_queue(16);
        let session = local_session(core_tx, vec!["#configured".into()]);
        let (_handle, mut ends) = NetworkHandle::channels(64);
        let task = tokio::spawn(async move {
            let first = session_once(&session, &mut ends).await;
            let second = session_once(&session, &mut ends).await;
            (first, second)
        });
        let mut out_tx = finish_registration(&mut core_rx).await;
        core_says(&mut out_tx, ":e6.example 001 alice :Welcome").await;
        let Input::Line { line, .. } = core_rx.pop().await.expect("join").payload else {
            panic!("expected the autojoin line");
        };
        assert_eq!(String::from_utf8(line).unwrap(), "JOIN #configured");
        core_says(&mut out_tx, ":alice!ident@local JOIN #configured").await;
        core_says(&mut out_tx, ":alice!ident@local JOIN #Runtime").await;
        core_says(
            &mut out_tx,
            "ERROR :Closing Link: local (Killed (oper (bye)))",
        )
        .await;
        assert!(matches!(
            core_rx.pop().await.expect("close").payload,
            Input::Closed { .. }
        ));
        let mut out_tx = finish_registration(&mut core_rx).await;
        core_says(&mut out_tx, ":e6.example 001 alice :Welcome").await;
        let Input::Line { line, .. } = core_rx.pop().await.expect("rejoin").payload else {
            panic!("expected the rejoin line");
        };
        assert_eq!(
            String::from_utf8(line).unwrap(),
            "JOIN #configured,#Runtime"
        );
        task.abort();
    }

    /// A prepared driver has done nothing: whoever starts it subscribes first
    /// and receives everything it says. The core session is opened only once
    /// the task runs.
    #[tokio::test]
    async fn a_prepared_driver_says_nothing_until_it_is_launched() {
        let (core_tx, mut core_rx) = core_queue(16);
        let driver = Box::new(LocalDriver::new(
            core_handles(core_tx),
            NetworkConfig::default(),
            LocalHomeKey::new(None, LOCAL_NETWORK),
        ));
        let (handle, run) = driver.prepare().split();
        let mut events = handle.subscribe();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(core_rx.depth(), 0, "no core session before the task runs");
        run.spawn();
        assert!(matches!(
            core_rx.pop().await.expect("open").payload,
            Input::Open { .. }
        ));
        drop(events.try_recv());
        handle.shutdown();
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

    /// A session a rebuild resumed is taken up, never registered again (D13):
    /// the driver asks the core what a welcome and each channel would have
    /// told, takes the answers in with no line reaching the backlog or an
    /// attachment, publishes the session once, and relays what the core said
    /// meanwhile after it.
    #[tokio::test]
    async fn a_resumed_session_is_taken_up_without_registering_or_a_line_buffered() {
        let (core_tx, mut core_rx) = core_queue(16);
        let session = local_session(core_tx, Vec::new());
        let (mut out_tx, edge) = crate::core::holding_send_queue("sendq", 8 * 512, 0);
        session.core.core_tx.directories().held.homes.resume(
            session.home.clone(),
            ResumedLocal {
                conn: ConnId(7),
                edge,
                nick: "alice".into(),
                user: "ident".into(),
                channels: vec!["#room".into()],
            },
        );
        let (handle, mut ends) = NetworkHandle::channels(8);
        let mut events = handle.subscribe();
        let task = tokio::spawn(async move { session_once(&session, &mut ends).await });
        for expected in [
            "VERSION",
            "TOPIC #room",
            "NAMES #room",
            "PING :e6irc-resumed",
        ] {
            let Input::Line { conn, line } = core_rx.pop().await.expect("a question").payload
            else {
                panic!("expected {expected:?}");
            };
            assert_eq!(conn, ConnId(7));
            assert_eq!(String::from_utf8(line).unwrap(), expected);
        }
        for line in [
            ":e6.example 351 alice e6ircd e6.example :a server",
            ":e6.example 005 alice CASEMAPPING=rfc1459 CHANTYPES=# :are supported",
            ":e6.example 332 alice #room :the topic",
            ":bob!bob@host PRIVMSG #room :meanwhile",
            ":e6.example 353 alice = #room :@alice bob",
            ":e6.example 366 alice #room :End of /NAMES list",
            ":e6.example PONG e6.example :e6irc-resumed",
        ] {
            core_says(&mut out_tx, line).await;
        }
        let mut seen = Vec::new();
        let relayed = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                match events.recv().await.expect("an event") {
                    super::super::DriverEvent::Line(buffered) => return buffered.line,
                    other => seen.push(other),
                }
            }
        })
        .await
        .expect("the line said meanwhile is relayed");
        assert!(relayed.ends_with("PRIVMSG #room :meanwhile"), "{relayed}");
        assert!(
            seen.iter().any(|event| matches!(
                event,
                super::super::DriverEvent::Session(super::super::IrcSessionSnapshot {
                    nick,
                    channels,
                }) if nick == "alice" && channels == &["#room".to_owned()]
            )),
            "{seen:?}"
        );
        assert_eq!(
            handle.runtime_snapshot().lifecycle,
            super::super::NetworkLifecycle::Connected
        );
        task.abort();
    }
}
