//! Discord gateway and REST bridge.
//!
//! CI drives its HTTP and WebSocket contract through a local protocol oracle.

use super::BoundedJson;
#[cfg(test)]
use std::collections::HashMap;
use std::time::Duration;

use futures_util::StreamExt;
use tokio_tungstenite::tungstenite::Message as Ws;

use super::{DriverEnds, NetworkDriver, NetworkHandle};

const DEFAULT_API: &str = "https://discord.com/api/v10";
const INTENTS: u64 = e6irc_proto::provider::DISCORD_GATEWAY_INTENTS;

#[derive(Debug, Clone)]
pub struct DiscordConfig {
    pub token: String,
    pub api_base: String,
    pub channels: Vec<String>,
    pub buffer_cap: usize,
    /// The server's policy on an API base inside its own network.
    pub internal_upstreams: crate::egress::InternalUpstreams,
}

pub struct DiscordDriver {
    config: DiscordConfig,
}

impl DiscordDriver {
    pub fn new(config: DiscordConfig) -> Self {
        Self { config }
    }
}

type GatewaySink = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    Ws,
>;

async fn send_gateway<T: serde::Serialize>(
    write: &mut GatewaySink,
    frame: &T,
    what: &str,
) -> Result<(), super::SessionOutcome> {
    use super::{NetworkFailure, SessionOutcome::Dropped};
    let frame = encode_gateway(frame).map_err(|error| {
        eprintln!("discord: could not encode {what}: {error}");
        Dropped(NetworkFailure::UpstreamProtocolFailed)
    })?;
    super::bridge_ws_send(write, frame)
        .await
        .map_err(|_| Dropped(NetworkFailure::UpstreamWriteFailed))
}

impl NetworkDriver for DiscordDriver {
    fn kind(&self) -> &'static str {
        "discord"
    }

    super::bridge_start!();
}

/// The gateway session a dropped connection resumes: Discord keeps it alive
/// for a while after the socket goes, and a RESUME on its
/// `resume_gateway_url` replays every event since `seq` — what the outage
/// would otherwise have lost — without spending one of the bot's daily
/// IDENTIFYs (1000 a day; past them Discord resets the token).
#[derive(Clone)]
struct ResumeState {
    session_id: String,
    resume_url: String,
    seq: Option<u64>,
}

/// What one Discord driver keeps across its sessions: the gateway session to
/// resume — replaced by each READY, advanced by every sequenced dispatch, and
/// forgotten when the gateway says it cannot be resumed (op 9 with `d:false`,
/// or a close code that ends it) — and the outbound deliveries, which are REST
/// posts that need no gateway and so outlive the socket that queued them.
struct Shared {
    config: DiscordConfig,
    resume: std::sync::Mutex<Option<ResumeState>>,
    deliveries: super::CarriedDeliveries,
}

impl Shared {
    fn new(config: DiscordConfig) -> Self {
        Self {
            config,
            resume: std::sync::Mutex::new(None),
            deliveries: super::CarriedDeliveries::new("Discord"),
        }
    }

    fn resume_state(&self) -> Option<ResumeState> {
        self.resume.lock().expect("discord resume state").clone()
    }

    fn remember(&self, state: ResumeState) {
        *self.resume.lock().expect("discord resume state") = Some(state);
    }

    fn advance(&self, seq: u64) {
        if let Some(state) = self.resume.lock().expect("discord resume state").as_mut() {
            state.seq = Some(seq);
        }
    }

    fn forget(&self, why: &str) {
        if self
            .resume
            .lock()
            .expect("discord resume state")
            .take()
            .is_some()
        {
            eprintln!(
                "discord: gateway session cannot be resumed ({why}); the next one identifies"
            );
        }
    }
}

async fn run(config: DiscordConfig, mut ends: DriverEnds) {
    let shared = std::sync::Arc::new(Shared::new(config));
    super::run_with_backoff_carrying(
        shared,
        &mut ends,
        |shared, ends| Box::pin(session_once(shared, ends)),
        Some(|shared| Box::pin(shared.deliveries.next_report())),
    )
    .await;
}

/// How long to wait after an op 9 before the next connection identifies:
/// Discord asks for a random one to five seconds, so the bots it invalidated
/// together do not all identify again at once.
fn invalid_session_wait() -> Duration {
    use aws_lc_rs::rand::SecureRandom;
    let mut bytes = [0u8; 2];
    match aws_lc_rs::rand::SystemRandom::new().fill(&mut bytes) {
        Ok(()) => Duration::from_millis(1_000 + u64::from(u16::from_le_bytes(bytes)) % 4_001),
        Err(_) => {
            eprintln!("discord: the system RNG failed; waiting the longest op 9 wait, 5 s");
            Duration::from_secs(5)
        }
    }
}

/// What a gateway close code means for this driver. Codes 4004 and
/// 4010–4014 are answers about the bot itself — its token, its shard, its API
/// version, its intents — that no retry changes; 4007 and 4009 end the
/// gateway session but not the bot's welcome; anything else is a lost
/// connection that resumes.
fn close_outcome(shared: &Shared, code: Option<u16>) -> super::SessionOutcome {
    use super::{ConfigurationRefusal, NetworkFailure, SessionOutcome};
    let refused = |diagnostic: &str| {
        shared.forget("the gateway refused the bot's configuration");
        eprintln!("discord: {diagnostic}; not retrying until the network is reconfigured");
        SessionOutcome::ConfigurationRejected(ConfigurationRefusal::new(
            NetworkFailure::GatewayConfigurationRefused,
            diagnostic,
        ))
    };
    match code {
        Some(4004) => {
            shared.forget("the token was refused");
            eprintln!("discord: gateway refused the bot token (close 4004); will stop retrying");
            SessionOutcome::AuthRejected(None)
        }
        Some(4010) => refused("the gateway refused the shard e6irc sent (close 4010)"),
        Some(4011) => refused(
            "the bot is in too many servers for one gateway connection; Discord requires \
             sharding, which e6irc does not do (close 4011)",
        ),
        Some(4012) => refused("the gateway refused e6irc's API version, v10 (close 4012)"),
        Some(4013) => refused("the gateway refused e6irc's intents as invalid (close 4013)"),
        Some(4014) => refused(
            "the gateway refused a privileged intent: switch on the Message Content intent \
             for this bot in the Discord developer portal (close 4014)",
        ),
        Some(code @ (4007 | 4009)) => {
            shared.forget(&format!("close {code}"));
            SessionOutcome::Dropped(NetworkFailure::ConnectionLost)
        }
        _ => SessionOutcome::Dropped(NetworkFailure::ConnectionLost),
    }
}

/// A gateway connection that said HELLO and was sent its IDENTIFY or RESUME,
/// with everything the session learned on the way.
struct OpenedGateway {
    http: super::BridgeHttp,
    base: String,
    id_to_channel: std::collections::HashMap<String, String>,
    channel_to_id: std::collections::HashMap<String, String>,
    me: Me,
    senders: super::BridgedSenders,
    write: GatewaySink,
    read: futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    hb_interval: u64,
    last_seq: Option<u64>,
}

async fn session_once(shared: &Shared, ends: &mut DriverEnds) -> super::SessionOutcome {
    use super::NetworkFailure;
    use super::SessionOutcome::Dropped;
    // Connecting needs nothing of `ends`, and can take a request timeout or
    // three: the deliveries the driver carries keep finishing meanwhile.
    let opened = super::while_carrying(
        ends,
        || shared.deliveries.next_report(),
        open_gateway(shared),
    )
    .await;
    let OpenedGateway {
        http,
        base,
        id_to_channel,
        channel_to_id,
        me,
        mut senders,
        mut write,
        mut read,
        hb_interval,
        mut last_seq,
    } = match opened {
        Ok(opened) => opened,
        Err(outcome) => return outcome,
    };
    let config = &shared.config;
    let identity = senders.own().clone();
    if let Err(outcome) = ends.begin_bridge_session(&identity, id_to_channel.values()) {
        return outcome;
    }

    let mut heartbeat = tokio::time::interval(Duration::from_millis(hb_interval));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Whether the last heartbeat is still waiting for its ACK. The gateway
    // ACKs each one; a heartbeat that finds the previous one unanswered is a
    // zombie connection — open, silent, and receiving nothing — so it is
    // dropped and resumed rather than trusted.
    let mut awaiting_ack = false;
    // Two missed heartbeat intervals of gateway silence. The heartbeat tick
    // below ends a turn of this loop well inside that window, so the window has
    // to outlive the turn (see `SilenceDeadline`) to ever be reached.
    let mut silence = super::SilenceDeadline::new(Duration::from_millis(
        hb_interval.saturating_mul(2).max(60_000),
    ));

    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                if awaiting_ack {
                    eprintln!("discord: the last heartbeat was never acknowledged; resuming");
                    return Dropped(NetworkFailure::KeepaliveTimedOut);
                }
                if let Err(outcome) = send_gateway(&mut write, &HeartbeatFrame::new(last_seq), "heartbeat").await {
                    return outcome;
                }
                awaiting_ack = true;
            }
            text = super::next_bridge_text(&mut read, &mut write, &mut silence, "discord", "gateway", |code| {
                close_outcome(shared, code)
            }) => {
                let text = match text {
                    Ok(Some(t)) => t,
                    Ok(None) => continue,
                    Err(outcome) => return outcome,
                };
                let frame = match parse_frame(&text) {
                    Ok(frame) => frame,
                    Err(e) => {
                        eprintln!("discord: malformed gateway frame: {e}");
                        return Dropped(NetworkFailure::UpstreamProtocolFailed);
                    }
                };
                if let Some(s) = frame.seq {
                    last_seq = Some(s);
                    shared.advance(s);
                }
                match frame.event {
                    Event::Ready { session_id, resume_url } => {
                        shared.remember(ResumeState { session_id, resume_url, seq: last_seq });
                    }
                    Event::Resumed => eprintln!("discord: gateway session resumed"),
                    Event::HeartbeatRequest => {
                        if let Err(outcome) = send_gateway(&mut write, &HeartbeatFrame::new(last_seq), "heartbeat").await {
                            return outcome;
                        }
                        awaiting_ack = true;
                    }
                    Event::Ack => awaiting_ack = false,
                    Event::Reconnect => {
                        eprintln!("discord: gateway asked for a new connection (op 7)");
                        return super::SessionOutcome::ReconnectRequested;
                    }
                    Event::InvalidSession { resumable } => {
                        eprintln!("discord: gateway invalidated the session (op 9, resumable: {resumable})");
                        if !resumable {
                            shared.forget("op 9");
                        }
                        return super::SessionOutcome::DroppedFor {
                            failure: NetworkFailure::ConnectionLost,
                            at_least: invalid_session_wait(),
                        };
                    }
                    Event::Message(message) => {
                        if message.author_id == me.id {
                            continue;
                        }
                        if let Some(channel) = id_to_channel.get(&message.channel_id) {
                            for line in message.lines(channel, &id_to_channel, &mut senders) {
                                ends.emit_line(line);
                            }
                        }
                    }
                    Event::Hello(_) | Event::Ignore => {}
                }
            }
            report = shared.deliveries.next_report() => report(ends),
            cmd = ends.next_command() => {
                let deliver = {
                    let (http, base, token) = (http.clone(), base.clone(), config.token.clone());
                    move |id: String, text: super::BridgeText| {
                        let (http, base, token) = (http.clone(), base.clone(), token.clone());
                        async move { send_message(&http, &base, &token, &id, &text).await }
                    }
                };
                if shared
                    .deliveries
                    .queue_command(ends, cmd, &channel_to_id, &identity, deliver)
                    .await
                    .is_none()
                {
                    return super::SessionOutcome::Stopped;
                }
            }
        }
    }
}

/// Everything before the gateway session begins: the channel lookups, the
/// bot's own account, the gateway's address, the socket, its HELLO, and the
/// IDENTIFY (or the RESUME of a session the driver kept).
async fn open_gateway(shared: &Shared) -> Result<OpenedGateway, super::SessionOutcome> {
    use super::NetworkFailure;
    use super::SessionOutcome::Dropped;
    let config = &shared.config;
    let http = super::bridge_http_or_outcome(
        "discord",
        Duration::from_secs(30),
        config.internal_upstreams,
    )?;
    let base = super::bridge_api_base(&config.api_base, DEFAULT_API);

    let (id_to_channel, channel_to_id) = super::resolve_bridge_channels(
        "discord",
        &config.channels,
        |id| {
            let http = &http;
            let base = &base;
            let token = &config.token;
            async move { fetch_channel_name(http, base, token, &id).await }
        },
        |id, error: super::ConnectFail| error.into_outcome(&format!("discord channel {id}")),
    )
    .await?;

    // Who the bot is, before anything is sent as it: its own posts come back
    // on the gateway and are dropped there, and each delivered message is
    // echoed under its name instead.
    let me = fetch_self(&http, &base, &config.token)
        .await
        .map_err(|error| error.into_outcome("discord bot user"))?;
    // Every sender is keyed by its user id: a username is not the account (a
    // webhook posts under any name it likes, the bot's own included).
    let senders = super::BridgedSenders::new(super::ProviderAccount {
        id: &me.id,
        name: &me.username,
        user: &me.id,
        host: "discord",
    });

    let resume = shared.resume_state();
    let gateway = match &resume {
        Some(resume) => resume.resume_url.clone(),
        None => match gateway_url(&http, &base).await {
            Ok(u) => u,
            Err(e) => {
                eprintln!("discord: gateway discovery failed: {e}");
                return Err(Dropped(NetworkFailure::UpstreamRequestFailed));
            }
        },
    };
    let url = match gateway_connection_url(&gateway) {
        Ok(url) => url,
        Err(error) => {
            eprintln!("discord: invalid gateway URL: {error}");
            shared.forget("its resume URL is invalid");
            return Err(Dropped(NetworkFailure::UpstreamProtocolFailed));
        }
    };
    let ws =
        super::bridge_ws_open(&url, "discord", "gateway", &base, config.internal_upstreams).await?;
    let (mut write, mut read) = ws.split();

    let hb_interval = match tokio::time::timeout(Duration::from_secs(30), read.next()).await {
        Ok(Some(Ok(Ws::Text(t)))) => match parse_frame(t.as_str()) {
            Ok(Frame {
                event: Event::Hello(ms),
                ..
            }) => ms,
            Ok(_) => {
                eprintln!("discord: first gateway frame was not HELLO");
                return Err(Dropped(NetworkFailure::UpstreamProtocolFailed));
            }
            Err(e) => {
                eprintln!("discord: malformed HELLO frame: {e}");
                return Err(Dropped(NetworkFailure::UpstreamProtocolFailed));
            }
        },
        Err(_) => {
            eprintln!("discord: HELLO timed out");
            return Err(Dropped(NetworkFailure::ConnectionTimedOut));
        }
        Ok(Some(Err(e))) => {
            eprintln!("discord: gateway read error before HELLO: {e}");
            return Err(Dropped(NetworkFailure::ConnectionLost));
        }
        Ok(Some(Ok(Ws::Close(frame)))) => {
            return Err(close_outcome(
                shared,
                frame.as_ref().map(|f| u16::from(f.code)),
            ));
        }
        Ok(None) => {
            eprintln!("discord: gateway closed before HELLO");
            return Err(Dropped(NetworkFailure::ConnectionLost));
        }
        Ok(Some(Ok(_))) => {
            eprintln!("discord: no HELLO from gateway");
            return Err(Dropped(NetworkFailure::UpstreamProtocolFailed));
        }
    };

    let last_seq = match &resume {
        Some(resume) => {
            send_gateway(
                &mut write,
                &ResumeFrame::new(&config.token, &resume.session_id, resume.seq),
                "RESUME",
            )
            .await?;
            resume.seq
        }
        None => {
            send_gateway(&mut write, &IdentifyFrame::new(&config.token), "IDENTIFY").await?;
            None
        }
    };
    Ok(OpenedGateway {
        http,
        base,
        id_to_channel,
        channel_to_id,
        me,
        senders,
        write,
        read,
        hb_interval,
        last_seq,
    })
}

struct Frame {
    seq: Option<u64>,
    event: Event,
}

enum Event {
    Hello(u64),
    Ready {
        session_id: String,
        resume_url: String,
    },
    Resumed,
    Message(DiscordMessage),
    HeartbeatRequest,
    Ack,
    /// Op 7: the gateway wants this connection replaced (and resumed).
    Reconnect,
    /// Op 9: the session is gone; `resumable` is its `d`.
    InvalidSession {
        resumable: bool,
    },
    Ignore,
}

/// One `MESSAGE_CREATE`, as the bridge relays it.
#[derive(Debug)]
struct DiscordMessage {
    channel_id: String,
    author_id: String,
    author: String,
    content: String,
    /// Each attachment's URL, in order.
    attachments: Vec<String>,
    /// The users the content mentions, by id: Discord sends the names beside
    /// the `<@id>` markup that names them.
    mentions: std::collections::HashMap<String, String>,
    /// What the message is called when it carries nothing the bridge can
    /// show (a sticker, an embed, a system message).
    unrelayable: String,
}

impl DiscordMessage {
    /// What the message says on IRC: its content, markup decoded, then each
    /// attachment's URL on a line of its own (like a Slack file share);
    /// `None` when there is neither.
    fn body(&self, channels: &std::collections::HashMap<String, String>) -> Option<String> {
        let mut body = decode_markup(&self.content, &self.mentions, channels);
        for url in &self.attachments {
            if !body.is_empty() {
                body.push('\n');
            }
            body.push_str(url);
        }
        (!body.is_empty()).then_some(body)
    }

    /// The IRC lines for this message in `channel`: what it says, or — when
    /// it carries nothing the bridge can show — one notice naming what it
    /// was, never nothing at all.
    fn lines(
        &self,
        channel: &str,
        channels: &std::collections::HashMap<String, String>,
        senders: &mut super::BridgedSenders,
    ) -> Vec<String> {
        let who = senders.identity(super::ProviderAccount {
            id: &self.author_id,
            name: &self.author,
            user: &self.author_id,
            host: "discord",
        });
        match self.body(channels) {
            Some(body) => super::render_bridged(&who, channel, &super::Inbound::message(&body)),
            None => vec![super::unrelayed_notice(
                "discord",
                channel,
                &self.unrelayable,
                Some(&who.nick),
            )],
        }
    }
}

/// Discord's message markup as IRC reads it: a user mention `<@id>` or
/// `<@!id>` is `@name` (named by the message's own `mentions`, else by the
/// id), a channel `<#id>` is its bridged channel's name (else `#id`), and a
/// custom emoji `<:name:id>` or `<a:name:id>` is `:name:`. Any other `<…>` —
/// a role mention, a timestamp, a link that suppresses its embed — stays as
/// written.
fn decode_markup(
    text: &str,
    mentions: &std::collections::HashMap<String, String>,
    channels: &std::collections::HashMap<String, String>,
) -> String {
    fn snowflake(id: &str) -> Option<&str> {
        (!id.is_empty() && id.bytes().all(|b| b.is_ascii_digit())).then_some(id)
    }
    let token = |inner: &str| -> Option<String> {
        if let Some(id) = inner
            .strip_prefix("@!")
            .or_else(|| inner.strip_prefix('@'))
            .and_then(snowflake)
        {
            return Some(format!("@{}", mentions.get(id).map_or(id, String::as_str)));
        }
        if let Some(id) = inner.strip_prefix('#').and_then(snowflake) {
            return Some(
                channels
                    .get(id)
                    .cloned()
                    .unwrap_or_else(|| format!("#{id}")),
            );
        }
        let (name, id) = inner
            .strip_prefix("a:")
            .or_else(|| inner.strip_prefix(':'))?
            .rsplit_once(':')?;
        let named = !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        (named && snowflake(id).is_some()).then(|| format!(":{name}:"))
    };
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find('<') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        match after
            .find('>')
            .and_then(|close| Some((token(&after[..close])?, close)))
        {
            Some((decoded, close)) => {
                out.push_str(&decoded);
                rest = &after[close + 1..];
            }
            None => {
                out.push('<');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

#[derive(serde::Serialize)]
struct ResumeFrame<'a> {
    op: u8,
    d: ResumeData<'a>,
}

#[derive(serde::Serialize)]
struct ResumeData<'a> {
    token: &'a str,
    session_id: &'a str,
    seq: Option<u64>,
}

impl<'a> ResumeFrame<'a> {
    fn new(token: &'a str, session_id: &'a str, seq: Option<u64>) -> Self {
        Self {
            op: 6,
            d: ResumeData {
                token,
                session_id,
                seq,
            },
        }
    }
}

#[derive(serde::Serialize)]
struct IdentifyFrame<'a> {
    op: u8,
    d: IdentifyData<'a>,
}

impl<'a> IdentifyFrame<'a> {
    fn new(token: &'a str) -> Self {
        Self {
            op: 2,
            d: IdentifyData {
                token,
                intents: INTENTS,
                properties: IdentifyProperties {
                    os: "linux",
                    browser: "e6irc",
                    device: "e6irc",
                },
            },
        }
    }
}

#[derive(serde::Serialize)]
struct IdentifyData<'a> {
    token: &'a str,
    intents: u64,
    properties: IdentifyProperties,
}

#[derive(serde::Serialize)]
struct IdentifyProperties {
    os: &'static str,
    browser: &'static str,
    device: &'static str,
}

#[derive(serde::Serialize)]
struct HeartbeatFrame {
    op: u8,
    d: Option<u64>,
}

impl HeartbeatFrame {
    fn new(sequence: Option<u64>) -> Self {
        Self { op: 1, d: sequence }
    }
}

fn encode_gateway<T: serde::Serialize>(value: &T) -> Result<Ws, String> {
    serde_json::to_string(value)
        .map(Ws::text)
        .map_err(|error| format!("gateway JSON: {error}"))
}

#[derive(serde::Deserialize)]
struct GatewayFrame {
    op: u64,
    #[serde(default)]
    s: Option<u64>,
    #[serde(default)]
    t: Option<String>,
}

#[derive(serde::Deserialize)]
struct GatewayPayload<T> {
    d: T,
}

#[derive(serde::Deserialize)]
struct HelloData {
    heartbeat_interval: u64,
}

#[derive(serde::Deserialize)]
struct ReadyData {
    session_id: String,
    resume_gateway_url: String,
}

#[derive(serde::Deserialize)]
struct MessageData {
    channel_id: String,
    author: DiscordUser,
    content: String,
    #[serde(default)]
    attachments: Vec<MessageAttachment>,
    #[serde(default)]
    mentions: Vec<DiscordUser>,
    #[serde(default)]
    sticker_items: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    embeds: Vec<serde::de::IgnoredAny>,
    /// The message type: 0 a message, 19 a reply, others system messages.
    #[serde(default, rename = "type")]
    kind: u64,
}

impl MessageData {
    /// What this message is called when nothing in it can be shown.
    fn unrelayable(&self) -> String {
        if !self.sticker_items.is_empty() {
            "sticker".into()
        } else if !self.embeds.is_empty() {
            "embed".into()
        } else if matches!(self.kind, 0 | 19) {
            "empty".into()
        } else {
            format!("type-{}", self.kind)
        }
    }
}

#[derive(serde::Deserialize)]
struct DiscordUser {
    id: String,
    username: String,
}

#[derive(serde::Deserialize)]
struct MessageAttachment {
    url: String,
}

fn decode_data<T: serde::de::DeserializeOwned>(text: &str, event: &str) -> Result<T, String> {
    serde_json::from_str::<GatewayPayload<T>>(text)
        .map(|payload| payload.d)
        .map_err(|e| format!("{event} data: {e}"))
}

fn parse_frame(text: &str) -> Result<Frame, String> {
    let frame: GatewayFrame =
        serde_json::from_str(text).map_err(|e| format!("gateway JSON: {e}"))?;
    let event = match frame.op {
        10 => {
            let hello: HelloData = decode_data(text, "HELLO")?;
            if hello.heartbeat_interval == 0 {
                return Err("HELLO heartbeat_interval was zero".to_string());
            }
            Event::Hello(hello.heartbeat_interval)
        }
        1 => Event::HeartbeatRequest,
        7 => Event::Reconnect,
        9 => {
            let resumable: bool = decode_data(text, "INVALID_SESSION")?;
            Event::InvalidSession { resumable }
        }
        11 => Event::Ack,
        0 => {
            let name = frame
                .t
                .as_deref()
                .ok_or("dispatch frame had no event name")?;
            if frame.s.is_none() {
                return Err(format!("{name} dispatch had no sequence number"));
            }
            match name {
                "READY" => {
                    let ready: ReadyData = decode_data(text, "READY")?;
                    if ready.session_id.is_empty() {
                        return Err("READY without a session id".to_string());
                    }
                    Event::Ready {
                        session_id: ready.session_id,
                        resume_url: ready.resume_gateway_url,
                    }
                }
                "RESUMED" => Event::Resumed,
                "MESSAGE_CREATE" => {
                    let message: MessageData = decode_data(text, "MESSAGE_CREATE")?;
                    let unrelayable = message.unrelayable();
                    Event::Message(DiscordMessage {
                        channel_id: message.channel_id,
                        author_id: message.author.id,
                        author: message.author.username,
                        content: message.content,
                        attachments: message
                            .attachments
                            .into_iter()
                            .map(|attachment| attachment.url)
                            .collect(),
                        mentions: message
                            .mentions
                            .into_iter()
                            .map(|user| (user.id, user.username))
                            .collect(),
                        unrelayable,
                    })
                }
                _ => Event::Ignore,
            }
        }
        _ => Event::Ignore,
    };
    Ok(Frame {
        seq: frame.s,
        event,
    })
}

async fn gateway_url(http: &super::BridgeHttp, base: &str) -> Result<String, String> {
    #[derive(serde::Deserialize)]
    struct GatewayResponse {
        url: String,
    }

    let response: GatewayResponse = super::bridge_send(http.get(&format!("{base}/gateway"))?)
        .await?
        .bounded_json()
        .await?;
    if response.url.is_empty() {
        Err("gateway response had an empty url".into())
    } else {
        Ok(response.url)
    }
}

fn gateway_connection_url(gateway: &str) -> Result<String, String> {
    let mut url =
        url::Url::parse(gateway).map_err(|_| "must be an absolute ws(s) URL".to_string())?;
    if !matches!(url.scheme(), "ws" | "wss")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("must be absolute ws(s), without credentials or fragment".into());
    }
    let preserved: Vec<_> = url
        .query_pairs()
        .filter(|(key, _)| key != "v" && key != "encoding")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    url.set_query(None);
    url.query_pairs_mut()
        .extend_pairs(preserved)
        .append_pair("v", "10")
        .append_pair("encoding", "json");
    Ok(url.to_string())
}

/// The bot's own account, from `GET /users/@me`.
#[derive(serde::Deserialize)]
struct Me {
    id: String,
    username: String,
}

async fn fetch_self(
    http: &super::BridgeHttp,
    base: &str,
    token: &str,
) -> Result<Me, super::ConnectFail> {
    let me: Me = super::bridge_send_credentials(
        http.get(&format!("{base}/users/@me"))?
            .header("Authorization", format!("Bot {token}")),
        super::CredentialRequest::Identity("bot user lookup"),
    )
    .await?
    .bounded_json()
    .await?;
    if me.id.is_empty() || me.username.is_empty() {
        Err("the bot user lookup returned no id or name"
            .to_string()
            .into())
    } else {
        Ok(me)
    }
}

async fn fetch_channel_name(
    http: &super::BridgeHttp,
    base: &str,
    token: &str,
    id: &str,
) -> Result<String, super::ConnectFail> {
    #[derive(serde::Deserialize)]
    struct ChannelResponse {
        name: String,
    }

    let response: ChannelResponse = super::bridge_send_credentials(
        http.get(&format!("{base}/channels/{id}"))?
            .header("Authorization", format!("Bot {token}")),
        super::CredentialRequest::DiscordChannel(id),
    )
    .await?
    .bounded_json()
    .await?;
    if response.name.is_empty() {
        Err(format!("channel {id} response had an empty name").into())
    } else {
        Ok(response.name)
    }
}

async fn send_message(
    http: &super::BridgeHttp,
    base: &str,
    token: &str,
    channel_id: &str,
    text: &super::BridgeText,
) -> Result<(), super::BridgeFailure> {
    #[derive(serde::Serialize)]
    struct MessageRequest {
        content: String,
        /// `parse: []`: nothing in the text pings anyone. Discord's default
        /// parses `@everyone`, `@here` and role mentions, so any IRC user
        /// in a bridged channel could page a whole guild.
        allowed_mentions: AllowedMentions,
    }
    #[derive(serde::Serialize)]
    struct AllowedMentions {
        parse: [&'static str; 0],
    }

    let req = http
        .post(&format!("{base}/channels/{channel_id}/messages"))?
        .header("Authorization", format!("Bot {token}"))
        .json(&MessageRequest {
            content: text.italic_markdown(str::to_string),
            allowed_mentions: AllowedMentions { parse: [] },
        });
    super::bridge_send(req).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hello_and_tracks_seq() {
        let f = parse_frame(r#"{"op":10,"d":{"heartbeat_interval":41250}}"#).expect("HELLO");
        assert!(matches!(f.event, Event::Hello(41250)));
        assert_eq!(f.seq, None);

        let f = parse_frame(
            r#"{"op":0,"s":7,"t":"READY","d":{"user":{"id":"999"},"session_id":"abc",
               "resume_gateway_url":"wss://resume.example"}}"#,
        )
        .expect("READY");
        assert_eq!(f.seq, Some(7));
        assert!(matches!(
            f.event,
            Event::Ready { session_id, resume_url }
                if session_id == "abc" && resume_url == "wss://resume.example"
        ));
    }

    #[test]
    fn parses_message_create() {
        let f = parse_frame(
            r#"{"op":0,"s":8,"t":"MESSAGE_CREATE","d":{"channel_id":"42","content":"hi",
               "author":{"id":"7","username":"alice"}}}"#,
        )
        .expect("MESSAGE_CREATE");
        assert_eq!(f.seq, Some(8));
        match f.event {
            Event::Message(message) => {
                assert_eq!(message.channel_id, "42");
                assert_eq!(message.author_id, "7");
                assert_eq!(message.author, "alice");
                assert_eq!(message.content, "hi");
            }
            _ => panic!("expected Message"),
        }
    }

    /// Discord's markup read the way an IRC user reads text.
    #[test]
    fn inbound_markup_decodes_mentions_channels_and_custom_emoji() {
        let mentions = HashMap::from([("7".to_string(), "bob".to_string())]);
        let channels = HashMap::from([("42".to_string(), "#general".to_string())]);
        for (markup, plain) in [
            ("<@7> hi", "@bob hi"),
            ("<@!7> hi", "@bob hi"),
            ("<@9> hi", "@9 hi"),
            ("in <#42> and <#99>", "in #general and #99"),
            ("<:blob:123> <a:party_parrot:456>", ":blob: :party_parrot:"),
            // A role, a timestamp, an embed-suppressed link: as written.
            (
                "<@&5> <t:1700000000:R> <https://x.example>",
                "<@&5> <t:1700000000:R> <https://x.example>",
            ),
            ("a < b <@7>", "a < b @bob"),
            ("unclosed <@7", "unclosed <@7"),
            ("<@7x> <:bad name:1>", "<@7x> <:bad name:1>"),
        ] {
            assert_eq!(
                decode_markup(markup, &mentions, &channels),
                plain,
                "{markup}"
            );
        }
    }

    /// A message with text and files is both, one link a line; one with
    /// neither is named by what it carried.
    #[test]
    fn a_message_body_is_its_text_then_its_attachments() {
        let message = |content: &str, attachments: &[&str], data: &str| {
            let frame = format!(
                r#"{{"op":0,"s":8,"t":"MESSAGE_CREATE","d":{{"channel_id":"42","content":{},
                   "author":{{"id":"7","username":"alice"}},"attachments":[{}]{data}}}}}"#,
                serde_json::json!(content),
                attachments
                    .iter()
                    .map(|url| format!(r#"{{"url":"{url}"}}"#))
                    .collect::<Vec<_>>()
                    .join(","),
            );
            match parse_frame(&frame).expect("MESSAGE_CREATE").event {
                Event::Message(message) => message,
                _ => panic!("expected Message"),
            }
        };
        let channels = HashMap::new();
        assert_eq!(
            message("look", &["https://a", "https://b"], "").body(&channels),
            Some("look\nhttps://a\nhttps://b".into())
        );
        assert_eq!(
            message("", &["https://a"], "").body(&channels),
            Some("https://a".into())
        );
        for (data, what) in [
            (r#","sticker_items":[{"id":"1","name":"wave"}]"#, "sticker"),
            (r#","embeds":[{"title":"x"}]"#, "embed"),
            (r#","type":7"#, "type-7"),
            ("", "empty"),
        ] {
            let message = message("", &[], data);
            assert_eq!(message.body(&channels), None);
            assert_eq!(message.unrelayable, what);
        }
    }

    #[test]
    fn the_op_9_wait_is_one_to_five_seconds() {
        for _ in 0..200 {
            let wait = invalid_session_wait();
            assert!(
                (Duration::from_secs(1)..=Duration::from_secs(5)).contains(&wait),
                "{wait:?}"
            );
        }
    }

    #[test]
    fn opcodes_and_garbage() {
        assert!(matches!(
            parse_frame(r#"{"op":1}"#).expect("heartbeat request").event,
            Event::HeartbeatRequest
        ));
        assert!(matches!(
            parse_frame(r#"{"op":11}"#).expect("heartbeat ack").event,
            Event::Ack
        ));
        assert!(matches!(
            parse_frame(r#"{"op":0,"s":9,"t":"TYPING_START"}"#)
                .expect("unknown dispatch")
                .event,
            Event::Ignore
        ));
        assert!(matches!(
            parse_frame(r#"{"op":7,"d":null}"#)
                .expect("reconnect")
                .event,
            Event::Reconnect
        ));
        for (frame, expected) in [
            (r#"{"op":9,"d":false}"#, false),
            (r#"{"op":9,"d":true}"#, true),
        ] {
            assert!(matches!(
                parse_frame(frame).expect("invalid session").event,
                Event::InvalidSession { resumable } if resumable == expected
            ));
        }
        assert!(parse_frame(r#"{"op":9}"#).is_err());
        assert!(matches!(
            parse_frame(r#"{"op":0,"s":4,"t":"RESUMED","d":{}}"#)
                .expect("resumed")
                .event,
            Event::Resumed
        ));
        assert!(parse_frame("not json").is_err());
    }

    #[test]
    fn rejects_malformed_known_frames_instead_of_defaulting_fields() {
        assert!(parse_frame(r#"{"op":10,"d":{}}"#).is_err());
        assert!(parse_frame(r#"{"op":10,"d":{"heartbeat_interval":0}}"#).is_err());
        assert!(parse_frame(r#"{"op":0,"t":"READY","d":{"user":{"id":"999"}}}"#).is_err());
        // A READY without the session it opened cannot be resumed later.
        assert!(parse_frame(r#"{"op":0,"s":1,"t":"READY","d":{"user":{"id":"999"}}}"#).is_err());
        assert!(
            parse_frame(
                r#"{"op":0,"s":8,"t":"MESSAGE_CREATE","d":{"channel_id":"42","content":"hi",
               "author":{"id":"7"}}}"#
            )
            .is_err()
        );
    }

    #[test]
    fn renders_and_routes() {
        assert_eq!(
            crate::bouncer::render_bridged(
                &crate::bouncer::BridgedSenders::new(crate::bouncer::ProviderAccount {
                    id: "1",
                    name: "bot",
                    user: "1",
                    host: "discord",
                })
                .identity(crate::bouncer::ProviderAccount {
                    id: "7",
                    name: "alice",
                    user: "7",
                    host: "discord",
                }),
                "#general",
                &crate::bouncer::Inbound::message("hi there")
            ),
            vec![":alice!7@discord PRIVMSG #general :hi there"]
        );
        // The map is keyed by the *folded* channel name (as the driver inserts).
        let mut map = HashMap::new();
        map.insert("#general".to_string(), "42".to_string());
        use crate::bouncer::{BridgeText, RouteResult, route_privmsg};
        let deliver = |target: &str, text: &str| RouteResult::Deliver {
            id: "42".to_string(),
            target: target.to_string(),
            text: BridgeText::Text(text.to_string()),
        };
        assert_eq!(
            route_privmsg("PRIVMSG #general :hello", &map),
            vec![deliver("#general", "hello")]
        );
        // Case-insensitive: a differently-cased target still routes, and is
        // named as the client spelled it.
        assert_eq!(
            route_privmsg("PRIVMSG #General :hi", &map),
            vec![deliver("#General", "hi")]
        );
        // A STATUSMSG prefix is stripped before the lookup.
        assert_eq!(
            route_privmsg("PRIVMSG @#general :ops", &map),
            vec![deliver("#general", "ops")]
        );
        // A comma target list routes each independently.
        assert_eq!(
            route_privmsg("PRIVMSG #general,#other :x", &map),
            vec![
                deliver("#general", "x"),
                RouteResult::Unmapped("#other".to_string()),
            ]
        );
        // A PRIVMSG to a non-bridged channel is surfaced, not silently dropped.
        assert_eq!(
            route_privmsg("PRIVMSG #other :x", &map),
            vec![RouteResult::Unmapped("#other".to_string())]
        );
        // A non-message command is refused explicitly.
        assert_eq!(
            route_privmsg("JOIN #general", &map),
            vec![RouteResult::Rejected(
                crate::bouncer::BridgeCommandRejection::UnsupportedCommand
            )]
        );
    }

    #[test]
    fn gateway_connection_url_preserves_existing_queries() {
        let url =
            gateway_connection_url("wss://gateway.example/socket?compress=zlib&v=1&encoding=etf")
                .expect("valid gateway URL");
        let parsed = url::Url::parse(&url).expect("output URL");
        let query: std::collections::HashMap<_, _> = parsed.query_pairs().collect();
        assert_eq!(query.get("compress"), Some(&"zlib".into()));
        assert_eq!(query.get("v"), Some(&"10".into()));
        assert_eq!(query.get("encoding"), Some(&"json".into()));
        for url in [
            "https://gateway.example/socket",
            "wss://user:secret@gateway.example/socket",
            "wss://gateway.example/socket#fragment",
            "/socket",
        ] {
            assert!(gateway_connection_url(url).is_err(), "accepted {url}");
        }
    }

    #[test]
    fn api_base_default_and_override() {
        let mut c = DiscordConfig {
            token: "t".into(),
            api_base: String::new(),
            channels: vec![],
            internal_upstreams: crate::egress::InternalUpstreams::Allow,
            buffer_cap: 10,
        };
        crate::bouncer::assert_bridge_api_base(
            &mut c.api_base,
            DEFAULT_API,
            "http://127.0.0.1:8080/",
        );
    }

    /// The channel lookup is the first request that carries the token, so it
    /// is where a revoked token is first refused. Reading that 401 as a
    /// transient request failure re-sent the dead token forever, although the
    /// gateway's own refusal of the same token (4004) already parks the network.
    #[tokio::test]
    #[cfg(feature = "slack")]
    async fn a_token_refused_at_the_channel_lookup_is_rejected_credentials() {
        use crate::bouncer::NetworkHandle;
        use crate::bouncer::bridge_oracle::Provider;

        let oracle = crate::bouncer::bridge_oracle::start(Provider::Discord).await;
        let config = DiscordConfig {
            token: "revoked-token".into(),
            api_base: oracle.api_base.clone(),
            channels: vec!["42".into()],
            internal_upstreams: crate::egress::InternalUpstreams::Allow,
            buffer_cap: 10,
        };
        let (_handle, mut ends) = NetworkHandle::channels(10);
        assert!(matches!(
            session_once(&Shared::new(config), &mut ends).await,
            crate::bouncer::SessionOutcome::AuthRejected(None)
        ));
    }

    #[cfg(feature = "slack")]
    mod gateway {
        use super::*;
        use crate::bouncer::bridge_oracle::{
            self, Options, Oracle, OracleEvent, Provider, discord_hello_frame,
            discord_message_frame, discord_ready_frame,
        };
        use crate::bouncer::{DriverEvent, NetworkHandle, SessionOutcome};
        use serde_json::json;

        fn config(oracle: &Oracle) -> DiscordConfig {
            DiscordConfig {
                token: "discord-token".into(),
                api_base: oracle.api_base.clone(),
                channels: vec!["42".into()],
                internal_upstreams: crate::egress::InternalUpstreams::Allow,
                buffer_cap: 10,
            }
        }

        async fn manual(options: Options) -> Oracle {
            bridge_oracle::start_with(
                Provider::Discord,
                Options {
                    manual: true,
                    ..options
                },
            )
            .await
        }

        /// One session of a driver that remembers nothing yet.
        fn spawn_session(
            oracle: &Oracle,
        ) -> (NetworkHandle, tokio::task::JoinHandle<SessionOutcome>) {
            let shared = std::sync::Arc::new(Shared::new(config(oracle)));
            let (handle, mut ends) = NetworkHandle::channels(10);
            let session = tokio::spawn(async move { session_once(&shared, &mut ends).await });
            (handle, session)
        }

        /// Connection `connection` says HELLO, the driver identifies, READY.
        async fn identify(oracle: &mut Oracle, connection: usize, interval_ms: u64) {
            assert!(matches!(
                oracle.next("connection").await,
                OracleEvent::Connected(n) if n == connection
            ));
            oracle.send(connection, discord_hello_frame(interval_ms));
            let (from, frame) = oracle.next_frame("IDENTIFY").await;
            assert_eq!(
                (from, frame["op"].as_u64()),
                (connection, Some(2)),
                "{frame}"
            );
            oracle.send(connection, discord_ready_frame(oracle));
        }

        async fn outcome_within(
            session: tokio::task::JoinHandle<SessionOutcome>,
            within: std::time::Duration,
        ) -> SessionOutcome {
            tokio::time::timeout(within, session)
                .await
                .expect("the session did not end")
                .expect("session task")
        }

        async fn line_containing(
            events: &mut tokio::sync::broadcast::Receiver<DriverEvent>,
            needle: &str,
        ) -> String {
            tokio::time::timeout(std::time::Duration::from_secs(3), async {
                loop {
                    if let Ok(DriverEvent::Line(line)) = events.recv().await
                        && line.line.contains(needle)
                    {
                        return line.line;
                    }
                }
            })
            .await
            .unwrap_or_else(|_| panic!("no line containing {needle:?}"))
        }

        /// After op 9 the gateway keeps acknowledging heartbeats, so a driver
        /// that ignored it stayed Connected and received nothing, forever.
        /// Discord asks for a random one to five seconds before the next
        /// IDENTIFY; the transient schedule alone re-dialled in 200 ms.
        #[tokio::test]
        async fn an_invalid_session_ends_the_session_and_waits_before_identifying() {
            let mut oracle = manual(Options::default()).await;
            let (_handle, session) = spawn_session(&oracle);
            identify(&mut oracle, 0, 60_000).await;
            oracle.send(0, json!({ "op": 9, "d": false }));
            match outcome_within(session, std::time::Duration::from_secs(2)).await {
                SessionOutcome::DroppedFor { failure, at_least } => {
                    assert_eq!(failure, crate::bouncer::NetworkFailure::ConnectionLost);
                    assert!(
                        (std::time::Duration::from_secs(1)..=std::time::Duration::from_secs(5))
                            .contains(&at_least),
                        "{at_least:?}"
                    );
                }
                _ => panic!("op 9 did not end the session with its wait"),
            }
        }

        /// The runner honours the wait: the next connection comes no sooner
        /// than a second after the op 9, even though the session held.
        #[tokio::test(flavor = "multi_thread")]
        async fn the_driver_redials_no_sooner_than_the_op_9_wait() {
            let mut oracle = manual(Options::default()).await;
            let handle = Box::new(DiscordDriver::new(config(&oracle))).start();
            identify(&mut oracle, 0, 60_000).await;
            let invalidated = tokio::time::Instant::now();
            oracle.send(0, json!({ "op": 9, "d": false }));
            tokio::time::timeout(std::time::Duration::from_secs(8), async {
                loop {
                    if let Some(OracleEvent::Connected(1)) = oracle.events.recv().await {
                        return;
                    }
                }
            })
            .await
            .expect("the driver never reconnected");
            assert!(
                invalidated.elapsed() >= std::time::Duration::from_secs(1),
                "re-dialled {:?} after op 9",
                invalidated.elapsed()
            );
            handle.shutdown_and_wait().await;
        }

        /// Op 7 asks for a new connection; it is not a failure.
        #[tokio::test]
        async fn a_reconnect_request_ends_the_session_without_a_failure() {
            let mut oracle = manual(Options::default()).await;
            let (_handle, session) = spawn_session(&oracle);
            identify(&mut oracle, 0, 60_000).await;
            oracle.send(0, json!({ "op": 7, "d": null }));
            assert!(matches!(
                outcome_within(session, std::time::Duration::from_secs(2)).await,
                SessionOutcome::ReconnectRequested
            ));
        }

        /// A dropped connection with a live session resumes it on the
        /// `resume_gateway_url`: the gateway replays what was missed, and no
        /// second IDENTIFY spends the bot's daily identify budget.
        #[tokio::test(flavor = "multi_thread")]
        async fn a_dropped_connection_resumes_and_is_replayed_what_it_missed() {
            let mut oracle = manual(Options::default()).await;
            let handle = Box::new(DiscordDriver::new(config(&oracle))).start();
            let mut events = handle.subscribe();
            identify(&mut oracle, 0, 60_000).await;
            oracle.send(0, discord_message_frame(2, "before the drop"));
            line_containing(&mut events, "before the drop").await;
            oracle.close(0, 4000);

            assert!(matches!(
                tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    loop {
                        if let OracleEvent::Connected(n) = oracle.events.recv().await.unwrap() {
                            return n;
                        }
                    }
                })
                .await
                .expect("the driver never reconnected"),
                1
            ));
            oracle.send(1, discord_hello_frame(60_000));
            let (from, frame) = oracle.next_frame("RESUME").await;
            assert_eq!(from, 1);
            assert_eq!(
                frame["op"], 6,
                "a second IDENTIFY instead of RESUME: {frame}"
            );
            assert_eq!(frame["d"]["token"], "discord-token");
            assert_eq!(frame["d"]["session_id"], "session-1");
            assert_eq!(frame["d"]["seq"], 2);
            oracle.send(1, json!({ "op": 0, "s": 3, "t": "RESUMED", "d": {} }));
            oracle.send(1, discord_message_frame(4, "replayed after resume"));
            line_containing(&mut events, "replayed after resume").await;
            handle.shutdown_and_wait().await;
        }

        /// A heartbeat that is never acknowledged is a zombie connection:
        /// the next heartbeat finds the last one unanswered and drops it.
        #[tokio::test]
        async fn an_unacknowledged_heartbeat_drops_the_zombie_connection() {
            let mut oracle = manual(Options::default()).await;
            let (_handle, session) = spawn_session(&oracle);
            identify(&mut oracle, 0, 100).await;
            assert!(matches!(
                outcome_within(session, std::time::Duration::from_secs(2)).await,
                SessionOutcome::Dropped(crate::bouncer::NetworkFailure::KeepaliveTimedOut)
            ));
        }

        /// No retry fixes a close about the bot's own configuration.
        #[tokio::test]
        async fn configuration_close_codes_park_instead_of_retrying() {
            for code in [4010, 4011, 4012, 4013, 4014] {
                let mut oracle = manual(Options::default()).await;
                let (_handle, session) = spawn_session(&oracle);
                identify(&mut oracle, 0, 60_000).await;
                oracle.close(0, code);
                match outcome_within(session, std::time::Duration::from_secs(2)).await {
                    SessionOutcome::ConfigurationRejected(refusal) => {
                        assert_eq!(
                            refusal.failure(),
                            crate::bouncer::NetworkFailure::GatewayConfigurationRefused
                        );
                        assert!(
                            refusal.diagnostic().contains(&code.to_string()),
                            "{refusal:?}"
                        );
                    }
                    SessionOutcome::Dropped(failure) => {
                        panic!("close {code} was not a configuration refusal: Dropped({failure:?})")
                    }
                    _ => panic!("close {code} was not a configuration refusal"),
                }
            }
            let mut oracle = manual(Options::default()).await;
            let (_handle, session) = spawn_session(&oracle);
            identify(&mut oracle, 0, 60_000).await;
            oracle.close(0, 4004);
            assert!(matches!(
                outcome_within(session, std::time::Duration::from_secs(2)).await,
                SessionOutcome::AuthRejected(None)
            ));
        }

        /// A configuration close parks the driver after one attempt: walking
        /// the refusal schedule would only repeat the same close.
        #[tokio::test(flavor = "multi_thread")]
        async fn a_configuration_close_parks_after_exactly_one_attempt() {
            use crate::bouncer::{DriverConnectionStatus, NetworkFailure};
            let mut oracle = manual(Options::default()).await;
            let handle = Box::new(DiscordDriver::new(config(&oracle))).start();
            let mut events = handle.subscribe();
            identify(&mut oracle, 0, 60_000).await;
            oracle.close(0, 4012);
            tokio::time::timeout(std::time::Duration::from_secs(3), async {
                loop {
                    match events.recv().await.expect("driver events") {
                        DriverEvent::Status {
                            status: DriverConnectionStatus::RegistrationFailed(failure),
                            ..
                        } => {
                            assert_eq!(failure, NetworkFailure::GatewayConfigurationRefused);
                            return;
                        }
                        DriverEvent::Status {
                            status: DriverConnectionStatus::Reconnecting(failure),
                            ..
                        } => panic!("close 4012 took the retry schedule ({failure:?})"),
                        _ => {}
                    }
                }
            })
            .await
            .expect("the driver never parked");
            assert_eq!(
                handle.runtime_snapshot().lifecycle,
                crate::bouncer::NetworkLifecycle::RegistrationFailed
            );
            assert_eq!(handle.runtime_snapshot().connection_attempts, 1);
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            while let Ok(event) = oracle.events.try_recv() {
                assert!(
                    !matches!(event, OracleEvent::Connected(_)),
                    "the parked driver dialed again"
                );
            }
            handle.shutdown_and_wait().await;
        }

        /// A slow REST post does not hold the gateway: a heartbeat request
        /// is answered while the post is still in flight.
        #[tokio::test]
        async fn a_slow_post_does_not_stall_the_heartbeat() {
            let mut oracle = manual(Options {
                post_delay: std::time::Duration::from_secs(5),
                ..Options::default()
            })
            .await;
            let (handle, _session) = spawn_session(&oracle);
            identify(&mut oracle, 0, 60_000).await;
            assert_eq!(
                handle.send("PRIVMSG #general :slow"),
                crate::bouncer::SendOutcome::Sent
            );
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            oracle.send(0, json!({ "op": 1, "d": null }));
            let started = tokio::time::Instant::now();
            loop {
                match oracle.next("heartbeat answer").await {
                    OracleEvent::ClientFrame(0, text) if text.contains("\"op\":1") => break,
                    _ => {}
                }
            }
            assert!(
                started.elapsed() < std::time::Duration::from_secs(1),
                "the heartbeat waited {:?} behind the post",
                started.elapsed()
            );
        }

        /// An IRC `/me` is Discord's italics, IRC formatting is stripped, and
        /// no post can page a whole guild.
        #[tokio::test]
        async fn posts_carry_actions_as_italics_strip_formatting_and_parse_no_mentions() {
            let mut oracle = manual(Options::default()).await;
            let (handle, _session) = spawn_session(&oracle);
            identify(&mut oracle, 0, 60_000).await;
            for (line, posted) in [
                ("PRIVMSG #general :\u{1}ACTION waves\u{1}", "_waves_"),
                (
                    "PRIVMSG #general :\u{2}bold\u{2} \u{3}4,2red\u{3} @everyone",
                    "bold red @everyone",
                ),
            ] {
                assert_eq!(handle.send(line), crate::bouncer::SendOutcome::Sent);
                loop {
                    if let OracleEvent::DiscordPost { body, .. } = oracle.next("post").await {
                        assert_eq!(body["content"], posted);
                        assert_eq!(body["allowed_mentions"], json!({ "parse": [] }));
                        break;
                    }
                }
            }
        }

        /// A 429 is waited out and the post retried, not reported lost.
        #[tokio::test]
        async fn a_rate_limited_post_is_retried_after_the_wait() {
            let mut oracle = manual(Options {
                rate_limit_first_post: true,
                ..Options::default()
            })
            .await;
            let (handle, _session) = spawn_session(&oracle);
            let mut events = handle.subscribe();
            identify(&mut oracle, 0, 60_000).await;
            assert_eq!(
                handle.send("PRIVMSG #general :limited"),
                crate::bouncer::SendOutcome::Sent
            );
            let mut limited = false;
            loop {
                match tokio::time::timeout(std::time::Duration::from_secs(4), oracle.events.recv())
                    .await
                    .expect("the post was never retried")
                    .expect("oracle events")
                {
                    OracleEvent::RateLimited => limited = true,
                    OracleEvent::DiscordPost { body, .. } => {
                        assert_eq!(body["content"], "limited");
                        break;
                    }
                    _ => {}
                }
            }
            assert!(limited);
            while let Ok(event) = events.try_recv() {
                if let DriverEvent::Line(line) = event {
                    assert!(!line.line.contains("not delivered"), "{}", line.line);
                }
            }
        }

        /// The echo of `text`, sent through the handle, once the provider
        /// accepted it; panics after `within`.
        async fn echo_of(
            events: &mut tokio::sync::broadcast::Receiver<DriverEvent>,
            text: &str,
            within: std::time::Duration,
        ) {
            tokio::time::timeout(within, async {
                loop {
                    match events.recv().await {
                        Ok(DriverEvent::Echo { line, .. }) if line.line.ends_with(text) => return,
                        Ok(DriverEvent::Line(line)) => {
                            assert!(!line.line.contains("not delivered"), "{}", line.line);
                        }
                        _ => {}
                    }
                }
            })
            .await
            .unwrap_or_else(|_| panic!("{text:?} was never delivered"));
        }

        /// A post is REST and needs no gateway: a client's message accepted
        /// before the connection dropped is still delivered — and echoed —
        /// after it. The queue was the session's, and a drop took every
        /// accepted message with it, unsaid.
        #[tokio::test(flavor = "multi_thread")]
        async fn a_message_queued_before_a_drop_is_delivered_after_it() {
            let mut oracle = manual(Options {
                post_delay: std::time::Duration::from_millis(600),
                ..Options::default()
            })
            .await;
            let handle = Box::new(DiscordDriver::new(config(&oracle))).start();
            let mut events = handle.subscribe();
            identify(&mut oracle, 0, 60_000).await;
            line_containing(&mut events, "component connected").await;
            assert_eq!(
                handle.send("PRIVMSG #general :sent before the drop"),
                crate::bouncer::SendOutcome::Sent
            );
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            oracle.close(0, 4000);
            echo_of(
                &mut events,
                ":sent before the drop",
                std::time::Duration::from_secs(5),
            )
            .await;
            handle.shutdown_and_wait().await;
        }

        /// A parked driver still finishes what it accepted: the delivery is
        /// made (or said to have failed), not held for as long as the park.
        #[tokio::test(flavor = "multi_thread")]
        async fn a_parked_driver_still_finishes_its_queued_deliveries() {
            let mut oracle = manual(Options {
                post_delay: std::time::Duration::from_millis(600),
                ..Options::default()
            })
            .await;
            let handle = Box::new(DiscordDriver::new(config(&oracle))).start();
            let mut events = handle.subscribe();
            identify(&mut oracle, 0, 60_000).await;
            line_containing(&mut events, "component connected").await;
            assert_eq!(
                handle.send("PRIVMSG #general :sent before the park"),
                crate::bouncer::SendOutcome::Sent
            );
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            oracle.close(0, 4012);
            echo_of(
                &mut events,
                ":sent before the park",
                std::time::Duration::from_secs(5),
            )
            .await;
            assert_eq!(
                handle.runtime_snapshot().lifecycle,
                crate::bouncer::NetworkLifecycle::RegistrationFailed
            );
            handle.shutdown_and_wait().await;
        }

        /// A 403 on the channel lookup is a channel the bot cannot see, and a
        /// 404 one that does not exist: both are about the configuration and
        /// name the channel. The 403 used to park the network as a refused
        /// token; the 404 was retried forever.
        #[tokio::test]
        async fn a_channel_the_bot_cannot_see_or_that_does_not_exist_is_a_mapping_refusal() {
            for (channel, says) in [
                (bridge_oracle::DISCORD_HIDDEN_CHANNEL, "cannot see"),
                ("44", "has no channel"),
            ] {
                let oracle = manual(Options::default()).await;
                let config = DiscordConfig {
                    channels: vec![channel.into()],
                    ..config(&oracle)
                };
                let (_handle, mut ends) = NetworkHandle::channels(10);
                match session_once(&Shared::new(config), &mut ends).await {
                    SessionOutcome::ConfigurationRejected(refusal) => {
                        assert_eq!(
                            refusal.failure(),
                            crate::bouncer::NetworkFailure::ChannelMappingFailed
                        );
                        assert!(
                            refusal.diagnostic().contains(says)
                                && refusal.diagnostic().contains(channel),
                            "{refusal:?}"
                        );
                    }
                    _ => panic!("channel {channel} was not a mapping refusal"),
                }
            }
        }

        /// Attachments ride with the text, one link a line; a mention, a
        /// channel and a custom emoji read as IRC reads them; a message with
        /// nothing to show is said, not skipped.
        #[tokio::test]
        async fn inbound_attachments_markup_and_unshowable_messages() {
            let mut oracle = manual(Options::default()).await;
            let (handle, _session) = spawn_session(&oracle);
            let mut events = handle.subscribe();
            identify(&mut oracle, 0, 60_000).await;
            let message = |sequence: u64, data: serde_json::Value| {
                let mut frame = discord_message_frame(sequence, "");
                for (key, value) in data.as_object().expect("message fields") {
                    frame["d"][key] = value.clone();
                }
                frame
            };
            oracle.send(
                0,
                message(
                    2,
                    json!({
                        "content": "look <@7> in <#42> <:blob:123>",
                        "mentions": [{ "id": "7", "username": "bob" }],
                        "attachments": [{ "url": "https://cdn.example/a.png" },
                                        { "url": "https://cdn.example/b.png" }],
                    }),
                ),
            );
            assert_eq!(
                line_containing(&mut events, "look").await,
                ":alice!user@discord PRIVMSG #general :look @bob in #general :blob:"
            );
            assert_eq!(
                line_containing(&mut events, "a.png").await,
                ":alice!user@discord PRIVMSG #general :https://cdn.example/a.png"
            );
            assert_eq!(
                line_containing(&mut events, "b.png").await,
                ":alice!user@discord PRIVMSG #general :https://cdn.example/b.png"
            );
            oracle.send(
                0,
                message(
                    3,
                    json!({ "sticker_items": [{ "id": "1", "name": "wave" }] }),
                ),
            );
            assert_eq!(
                line_containing(&mut events, "sticker").await,
                ":*bnc* NOTICE #general :discord: a sticker message from alice was not relayed"
            );
        }

        /// Remote text never reaches an IRC client as a CTCP request.
        #[tokio::test]
        async fn inbound_control_bytes_are_dropped() {
            let mut oracle = manual(Options::default()).await;
            let (handle, _session) = spawn_session(&oracle);
            let mut events = handle.subscribe();
            identify(&mut oracle, 0, 60_000).await;
            oracle.send(0, discord_message_frame(2, "\u{1}VERSION\u{1} \u{2}hi"));
            let line = line_containing(&mut events, "VERSION").await;
            assert_eq!(line, ":alice!user@discord PRIVMSG #general :VERSION hi");
        }
    }

    /// The scripted oracle, and a bridge network's session connecting to it,
    /// with a subscription taken before the session starts.
    #[cfg(feature = "slack")]
    async fn scripted_session() -> (
        crate::bouncer::bridge_oracle::Oracle,
        crate::bouncer::NetworkHandle,
        tokio::sync::broadcast::Receiver<crate::bouncer::DriverEvent>,
        tokio::task::JoinHandle<crate::bouncer::SessionOutcome>,
    ) {
        let oracle =
            crate::bouncer::bridge_oracle::start(crate::bouncer::bridge_oracle::Provider::Discord)
                .await;
        let config = Shared::new(DiscordConfig {
            token: "discord-token".into(),
            api_base: oracle.api_base.clone(),
            channels: vec!["42".into()],
            internal_upstreams: crate::egress::InternalUpstreams::Allow,
            buffer_cap: 10,
        });
        let (handle, mut ends) = crate::bouncer::NetworkHandle::bridge_channels(10);
        let driver_events = handle.subscribe();
        let session = tokio::spawn(async move { session_once(&config, &mut ends).await });
        (oracle, handle, driver_events, session)
    }

    #[tokio::test]
    #[cfg(feature = "slack")]
    async fn real_http_and_websocket_transport_bridge_both_directions() {
        let (mut oracle, handle, driver_events, session) = scripted_session().await;
        crate::bouncer::bridge_oracle::verify_round_trip(
            crate::bouncer::bridge_oracle::Provider::Discord,
            handle,
            driver_events,
            session,
            &mut oracle,
        )
        .await;
    }

    /// An attached echo-message client is the bot: welcomed under its name,
    /// and handed an echo under that same name.
    #[tokio::test]
    #[cfg(feature = "slack")]
    async fn an_attached_client_is_welcomed_as_the_bot_and_knows_its_echo() {
        let (_oracle, handle, _, session) = scripted_session().await;
        crate::bouncer::bridge_oracle::verify_attached_client(handle, session).await;
    }
}
