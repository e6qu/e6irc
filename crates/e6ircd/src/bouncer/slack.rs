//! Slack Socket Mode bridge.
//!
//! CI drives its HTTP and WebSocket contract through a local protocol oracle.

use super::BoundedJson;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio_tungstenite::tungstenite::Message as Ws;

use super::{DriverEnds, NetworkDriver, NetworkHandle};

/// Default Slack Web API base; overridable via config `addr`.
const DEFAULT_API: &str = "https://slack.com/api";

#[derive(Debug, Clone)]
pub struct SlackConfig {
    /// Bot token (`xoxb-…`), for Web API calls.
    pub bot_token: String,
    /// App-level token (`xapp-…`), for opening the Socket Mode connection.
    pub app_token: String,
    /// Web API base; empty means [`DEFAULT_API`].
    pub api_base: String,
    /// Slack channel ids to bridge.
    pub channels: Vec<String>,
    pub buffer_cap: usize,
    /// The server's policy on an API base inside its own network.
    pub internal_upstreams: crate::egress::InternalUpstreams,
}

pub struct SlackDriver {
    config: SlackConfig,
}

impl SlackDriver {
    pub fn new(config: SlackConfig) -> Self {
        Self { config }
    }
}

impl NetworkDriver for SlackDriver {
    fn kind(&self) -> &'static str {
        "slack"
    }

    super::bridge_start!();
}

async fn run(config: SlackConfig, mut ends: DriverEnds) {
    super::run_with_backoff(config, &mut ends, |config, ends| {
        Box::pin(session_once(config, ends))
    })
    .await;
}

/// How often the bridge pings each socket. Slack may say nothing for longer
/// than the silence window in a quiet workspace; a ping gets a pong back, so
/// the bridge proves its own connection alive instead of waiting to hear.
const PING_INTERVAL: Duration = Duration::from_secs(30);

/// Silence after which a socket is taken for dead: three missed pings.
const SILENCE_WINDOW: Duration = Duration::from_secs(90);

/// How long a socket Slack said it will retire is still read. Slack closes
/// it about ten seconds after the warning; one that lingers is let go.
const RETIRING_GRACE: Duration = Duration::from_secs(30);

/// Inbound messages waiting on a name lookup, in order. Past this Slack is
/// delivering faster than `users.info` answers, and a message is reported
/// unrelayed rather than queued without bound.
const INBOUND_QUEUE_CAPACITY: usize = 256;

/// Distinct user ids one message's mentions may look up. The ids are the
/// upstream's to choose; a message naming more shows the rest by id.
const MAX_MENTION_LOOKUPS: usize = 8;

/// Envelope ids remembered to recognise Slack's re-deliveries.
const RECENT_ENVELOPES: usize = 1024;

/// One Socket Mode connection.
struct Socket {
    write: futures_util::stream::SplitSink<super::BridgeWs, Ws>,
    read: futures_util::stream::SplitStream<super::BridgeWs>,
    silence: super::SilenceDeadline,
    /// When Slack said it will retire this socket, the moment the bridge
    /// stops reading it; `None` while it is the live one.
    retiring: Option<tokio::time::Instant>,
}

impl Socket {
    fn new(ws: super::BridgeWs) -> Self {
        let (write, read) = ws.split();
        Self {
            write,
            read,
            silence: super::SilenceDeadline::new(SILENCE_WINDOW),
            retiring: None,
        }
    }
}

/// The next frame from any live socket, with its index; pending forever when
/// there is none. Each socket's read is cancel-safe, so abandoning this in a
/// `select!` loses no frame.
async fn next_frame(sockets: &mut [Socket]) -> (usize, super::BridgeRead) {
    if sockets.is_empty() {
        return std::future::pending().await;
    }
    let reads = sockets.iter_mut().enumerate().map(|(index, socket)| {
        Box::pin(async move {
            let read = super::next_bridge_frame(
                &mut socket.read,
                &mut socket.write,
                &mut socket.silence,
                "slack",
                "socket",
            )
            .await;
            (index, read)
        })
    });
    futures_util::future::select_all(reads).await.0
}

type Opening = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<super::BridgeWs, super::SessionOutcome>> + Send>,
>;

/// Open the next Socket Mode connection: `apps.connections.open`, then the
/// WebSocket. Owns its inputs, so it runs beside the sockets being retired.
fn open_next(config: &SlackConfig, http: &super::BridgeHttp, base: &str) -> Opening {
    let (http, base) = (http.clone(), base.to_string());
    let (app_token, policy) = (config.app_token.clone(), config.internal_upstreams);
    Box::pin(async move {
        let url = open_socket(&http, &base, &app_token)
            .await
            .map_err(|error| slack_failure("apps.connections.open failed", &error))?;
        super::bridge_ws_open(&url, "slack", "socket", &base, policy).await
    })
}

/// Who this bot is, from `auth.test`: its own posts come back as events and
/// are its echo, while every other bot's are relayed.
#[derive(serde::Deserialize)]
struct Identity {
    /// The bot user's name: each delivered message is echoed under it.
    user: String,
    user_id: String,
    #[serde(default)]
    bot_id: Option<String>,
}

impl Identity {
    fn is_self(&self, message: &SlackMessage) -> bool {
        let ours = |bot: &Option<String>| bot.is_some() && *bot == self.bot_id;
        ours(&message.bot_id)
            || match &message.sender {
                Sender::User(user) => *user == self.user_id,
                Sender::Bot { bot_id, .. } => ours(&Some(bot_id.clone())),
            }
    }
}

async fn session_once(config: &SlackConfig, ends: &mut DriverEnds) -> super::SessionOutcome {
    use super::NetworkFailure;
    use super::SessionOutcome::Dropped;
    let http = match super::bridge_http_or_outcome(
        "slack",
        Duration::from_secs(30),
        config.internal_upstreams,
    ) {
        Ok(c) => c,
        Err(outcome) => return outcome,
    };
    let base = super::bridge_api_base(&config.api_base, DEFAULT_API);

    let identity: Identity = match slack_call(&http, &base, &config.bot_token, "auth.test").await {
        Ok(identity) => identity,
        Err(error) => return slack_failure("auth.test failed", &error),
    };
    let echo_identity = super::bridged_identity("slack", &identity.user);

    let (id_to_channel, channel_to_id) = match super::resolve_bridge_channels(
        "slack",
        &config.channels,
        |id| {
            let http = &http;
            let base = &base;
            let token = &config.bot_token;
            async move { fetch_channel_name(http, base, token, &id).await }
        },
        |id, error: String| slack_failure(&format!("channel {id} lookup failed"), &error),
    )
    .await
    {
        Ok(maps) => maps,
        Err(outcome) => return outcome,
    };

    let first = match open_next(config, &http, &base).await {
        Ok(ws) => ws,
        Err(outcome) => return outcome,
    };
    let mut sockets = vec![Socket::new(first)];
    if let Err(outcome) = ends.begin_bridge_session(&echo_identity, id_to_channel.values()) {
        return outcome;
    }

    let names = Arc::new(Mutex::new(UserNames::default()));
    let mut recent = RecentEnvelopes::default();
    let mut opening: Option<Opening> = None;
    let mut ping =
        tokio::time::interval_at(tokio::time::Instant::now() + PING_INTERVAL, PING_INTERVAL);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut deliveries = super::DeliveryQueue::new(super::DELIVERY_QUEUE_CAPACITY);
    let mut inbound: super::SerialQueue<Resolved> = super::SerialQueue::new(INBOUND_QUEUE_CAPACITY);

    loop {
        // The soonest moment a retiring socket is let go.
        let retire_at = sockets.iter().filter_map(|socket| socket.retiring).min();
        tokio::select! {
            (index, read) = next_frame(&mut sockets) => {
                let retiring = sockets[index].retiring.is_some();
                let text = match read {
                    super::BridgeRead::Text(text) => text,
                    super::BridgeRead::Skip => continue,
                    super::BridgeRead::Closed(_) | super::BridgeRead::ReadFailed
                    | super::BridgeRead::Idle | super::BridgeRead::WriteFailed if retiring => {
                        sockets.remove(index);
                        continue;
                    }
                    super::BridgeRead::Idle => return Dropped(NetworkFailure::KeepaliveTimedOut),
                    super::BridgeRead::WriteFailed => return Dropped(NetworkFailure::UpstreamWriteFailed),
                    super::BridgeRead::Closed(code) => {
                        eprintln!("slack: socket closed (close code {code:?})");
                        return Dropped(NetworkFailure::ConnectionLost);
                    }
                    super::BridgeRead::ReadFailed => return Dropped(NetworkFailure::ConnectionLost),
                };
                let envelope = match parse_envelope(&text) {
                    Ok(envelope) => envelope,
                    Err(e) => {
                        eprintln!("slack: malformed Socket Mode frame: {e}");
                        return Dropped(NetworkFailure::UpstreamProtocolFailed);
                    }
                };
                // Ack first, on the socket it came in on, before anything
                // that can wait: Slack re-sends what it has not seen acked
                // within three seconds.
                if let Some(ack_id) = &envelope.ack {
                    let ack = match socket_ack(ack_id) {
                        Ok(ack) => ack,
                        Err(error) => {
                            eprintln!("slack: could not encode Socket Mode ACK: {error}");
                            return Dropped(NetworkFailure::UpstreamProtocolFailed);
                        }
                    };
                    if sockets[index].write.send(ack).await.is_err() {
                        if retiring {
                            sockets.remove(index);
                            continue;
                        }
                        return Dropped(NetworkFailure::UpstreamWriteFailed);
                    }
                    if !recent.first_time(ack_id) {
                        eprintln!(
                            "slack: envelope {ack_id} delivered again (retry attempt {}); \
                             already relayed",
                            envelope.retry_attempt.unwrap_or(0)
                        );
                        continue;
                    }
                }
                match envelope.kind {
                    EnvelopeKind::Nothing => {}
                    EnvelopeKind::Disconnect(reason) => match reason {
                        DisconnectReason::Warning | DisconnectReason::RefreshRequested => {
                            if !retiring {
                                eprintln!("slack: socket retiring ({reason:?}); opening the next one");
                                sockets[index].retiring = Some(tokio::time::Instant::now() + RETIRING_GRACE);
                            }
                            if opening.is_none() && sockets.iter().all(|socket| socket.retiring.is_some()) {
                                opening = Some(open_next(config, &http, &base));
                            }
                        }
                        DisconnectReason::LinkDisabled => {
                            let diagnostic = "Socket Mode is switched off for this Slack app \
                                              (disconnect: link_disabled)";
                            eprintln!("slack: {diagnostic}");
                            return super::SessionOutcome::ConfigurationRejected(
                                super::ConfigurationRefusal::new(
                                    NetworkFailure::GatewayConfigurationRefused,
                                    diagnostic,
                                ),
                            );
                        }
                        DisconnectReason::Other(reason) => {
                            eprintln!("slack: socket disconnected ({reason})");
                            if retiring {
                                sockets.remove(index);
                                continue;
                            }
                            return Dropped(NetworkFailure::ConnectionLost);
                        }
                    },
                    EnvelopeKind::Message(message) => {
                        if identity.is_self(&message) || !id_to_channel.contains_key(&message.channel) {
                            continue;
                        }
                        let channel = message.channel.clone();
                        let work = resolve_names(http.clone(), base.clone(), config.bot_token.clone(), names.clone(), message);
                        if inbound.push(work).is_err() {
                            eprintln!("slack: {INBOUND_QUEUE_CAPACITY} messages wait on name lookups; one was not relayed");
                            ends.record_error(NetworkFailure::UpstreamRequestFailed);
                            if let Some(channel) = id_to_channel.get(&channel) {
                                ends.emit_line(format!(
                                    ":*bnc* NOTICE {channel} :slack: a message was not relayed; \
                                     name lookups are backlogged"
                                ));
                            }
                        }
                    }
                }
                if sockets.is_empty() && opening.is_none() {
                    return Dropped(NetworkFailure::ConnectionLost);
                }
            }
            opened = async { opening.as_mut().expect("guarded by the precondition").await }, if opening.is_some() => {
                opening = None;
                match opened {
                    Ok(ws) => sockets.push(Socket::new(ws)),
                    Err(outcome) => return outcome,
                }
            }
            _ = tokio::time::sleep_until(retire_at.unwrap_or_else(tokio::time::Instant::now)), if retire_at.is_some() => {
                let now = tokio::time::Instant::now();
                sockets.retain(|socket| {
                    let expired = socket.retiring.is_some_and(|at| at <= now);
                    if expired {
                        eprintln!("slack: a retired socket outlived its grace period; letting it go");
                    }
                    !expired
                });
                if sockets.is_empty() && opening.is_none() {
                    return Dropped(NetworkFailure::ConnectionLost);
                }
            }
            _ = ping.tick() => {
                for socket in &mut sockets {
                    if socket.write.send(Ws::Ping(Vec::new().into())).await.is_err() && socket.retiring.is_none() {
                        return Dropped(NetworkFailure::UpstreamWriteFailed);
                    }
                }
            }
            resolved = inbound.next() => {
                for (user, error) in &resolved.failures {
                    eprintln!("slack: users.info for {user} failed: {error}");
                    ends.record_error(NetworkFailure::UpstreamRequestFailed);
                }
                if let Some(channel) = id_to_channel.get(&resolved.message.channel) {
                    let names = names.lock().expect("slack name cache");
                    for line in render_message(&resolved.message, channel, &names, &id_to_channel) {
                        ends.emit_line(line);
                    }
                }
            }
            outcome = deliveries.next() => super::report_delivery(ends, "Slack", "channel", outcome),
            cmd = ends.next_command() => {
                let deliver = {
                    let (http, base, token) = (http.clone(), base.clone(), config.bot_token.clone());
                    move |id: String, text: super::BridgeText| {
                        let (http, base, token) = (http.clone(), base.clone(), token.clone());
                        async move { post_message(&http, &base, &token, &id, &text).await }
                    }
                };
                if super::queue_channel_command(ends, cmd, &channel_to_id, &echo_identity, "Slack", &mut deliveries, deliver)
                    .is_none()
                {
                    return super::SessionOutcome::Stopped;
                }
            }
        }
    }
}

/// A message once the names it needs are looked up, and the lookups that
/// failed (reported by the loop; never remembered as names).
struct Resolved {
    message: SlackMessage,
    failures: Vec<(String, String)>,
}

/// Look up the display names `message` needs that the cache lacks: its
/// sender's, and those of up to [`MAX_MENTION_LOOKUPS`] mentioned users. A
/// name is remembered only when the lookup succeeds; a failure leaves the id
/// to be shown as itself this once and looked up again next time — caching
/// the id as the name hid the sender for the rest of the session.
async fn resolve_names(
    http: super::BridgeHttp,
    base: String,
    bot_token: String,
    names: Arc<Mutex<UserNames>>,
    message: SlackMessage,
) -> Resolved {
    let mut wanted: Vec<String> = Vec::new();
    if let Sender::User(user) = &message.sender {
        wanted.push(user.clone());
    }
    for user in mentioned_users(message.content.text()) {
        if !wanted.contains(&user) && wanted.len() <= MAX_MENTION_LOOKUPS {
            wanted.push(user);
        }
    }
    let mut failures = Vec::new();
    for user in wanted {
        if names.lock().expect("slack name cache").get(&user).is_some() {
            continue;
        }
        match fetch_user_name(&http, &base, &bot_token, &user).await {
            Ok(name) => names.lock().expect("slack name cache").remember(user, name),
            Err(error) => failures.push((user, error)),
        }
    }
    Resolved { message, failures }
}

/// The IRC lines for one resolved message.
fn render_message(
    message: &SlackMessage,
    channel: &str,
    names: &UserNames,
    channels: &HashMap<String, String>,
) -> Vec<String> {
    let sender = match &message.sender {
        Sender::User(user) => names.get(user).cloned().unwrap_or_else(|| user.clone()),
        Sender::Bot { name, .. } => name.clone(),
    };
    let decode = |text: &str| decode_markup(text, names, channels);
    let inbound = match &message.content {
        Content::Message(text) => super::Inbound::message(&decode(text)),
        Content::Action(text) => super::Inbound::new(super::InboundKind::Action, &decode(text)),
        Content::Edited(text) => super::Inbound::message(&format!("* {}", decode(text))),
        Content::Unrelayed(subtype) => {
            return vec![super::unrelayed_notice(
                "slack",
                channel,
                subtype,
                Some(&sender),
            )];
        }
    };
    super::render_bridged("slack", &sender, channel, &inbound)
}

/// The user ids of the `<@U…>` mentions in `text` that carry no label.
fn mentioned_users(text: &str) -> Vec<String> {
    markup_spans(text)
        .into_iter()
        .filter_map(|span| match span {
            Span::Markup(inner) if !inner.contains('|') => {
                inner.strip_prefix('@').map(str::to_string)
            }
            _ => None,
        })
        .collect()
}

enum Span<'a> {
    Literal(&'a str),
    /// The inside of one `<…>`.
    Markup(&'a str),
}

/// `text` cut into literal runs and `<…>` markup. Slack escapes a literal `<`
/// or `>` as an entity, so a raw one is always markup; an unclosed `<` is
/// kept as text.
fn markup_spans(text: &str) -> Vec<Span<'_>> {
    let mut spans = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('<') {
        let Some(close) = rest[open..].find('>') else {
            break;
        };
        if open > 0 {
            spans.push(Span::Literal(&rest[..open]));
        }
        spans.push(Span::Markup(&rest[open + 1..open + close]));
        rest = &rest[open + close + 1..];
    }
    if !rest.is_empty() {
        spans.push(Span::Literal(rest));
    }
    spans
}

/// Slack's three entities, decoded. `&amp;` last, so `&amp;lt;` stays `&lt;`.
fn decode_entities(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Slack's escaping of outbound text: exactly the three characters its markup
/// reads. `<!channel>` typed on IRC arrives as text, not as a page.
fn escape_markup(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Slack message markup as IRC reads it: `<@U…>` is `@name` (from the name
/// cache, else the label, else the id), `<#C…|name>` is `#name`, `<!here>`
/// and friends are `@here`, `<url|label>` is `label (url)`, a bare `<url>`
/// the URL, and the entities are decoded.
fn decode_markup(text: &str, names: &UserNames, channels: &HashMap<String, String>) -> String {
    let mut out = String::with_capacity(text.len());
    for span in markup_spans(text) {
        let inner = match span {
            Span::Literal(literal) => {
                out.push_str(&decode_entities(literal));
                continue;
            }
            Span::Markup(inner) => inner,
        };
        let (target, label) = match inner.split_once('|') {
            Some((target, label)) => (target, Some(decode_entities(label))),
            None => (inner, None),
        };
        if let Some(user) = target.strip_prefix('@') {
            let name = names
                .get(user)
                .cloned()
                .or(label)
                .unwrap_or_else(|| user.to_string());
            out.push('@');
            out.push_str(&name);
        } else if let Some(channel) = target.strip_prefix('#') {
            match label.or_else(|| {
                channels
                    .get(channel)
                    .map(|name| name.trim_start_matches('#').to_string())
            }) {
                Some(name) => {
                    out.push('#');
                    out.push_str(&name);
                }
                None => {
                    out.push('#');
                    out.push_str(channel);
                }
            }
        } else if let Some(special) = target.strip_prefix('!') {
            let keyword = special.split('^').next().unwrap_or(special);
            match (keyword, label) {
                ("here" | "channel" | "everyone", _) => {
                    out.push('@');
                    out.push_str(keyword);
                }
                (_, Some(label)) => out.push_str(&label),
                (_, None) => {
                    out.push('@');
                    out.push_str(keyword);
                }
            }
        } else {
            let url = decode_entities(target);
            match label {
                Some(label) if label != url => {
                    out.push_str(&label);
                    out.push_str(" (");
                    out.push_str(&url);
                    out.push(')');
                }
                _ => out.push_str(&url),
            }
        }
    }
    out
}

/// Envelope ids recently seen, to recognise Slack's re-deliveries (an
/// envelope whose ack Slack did not see in time comes again, with
/// `retry_attempt` counting up). Bounded: the oldest id is forgotten first.
#[derive(Default)]
struct RecentEnvelopes {
    order: VecDeque<String>,
    seen: HashSet<String>,
}

impl RecentEnvelopes {
    /// Whether `id` is new; remembers it either way.
    fn first_time(&mut self, id: &str) -> bool {
        if self.seen.contains(id) {
            return false;
        }
        if self.order.len() >= RECENT_ENVELOPES
            && let Some(oldest) = self.order.pop_front()
        {
            self.seen.remove(&oldest);
        }
        self.order.push_back(id.to_string());
        self.seen.insert(id.to_string());
        true
    }
}

/// Who sent a relayed message.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Sender {
    User(String),
    /// A bot's post (`bot_message`): its `bot_id` and the name it posts as.
    Bot {
        bot_id: String,
        name: String,
    },
}

/// What a relayed message says.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Content {
    Message(String),
    /// `me_message`: an IRC ACTION.
    Action(String),
    /// `message_changed`: the new text, shown as `* new text` like an edit
    /// from Matrix.
    Edited(String),
    /// A subtype the bridge has no rendering for: said, not dropped.
    Unrelayed(String),
}

impl Content {
    fn text(&self) -> &str {
        match self {
            Self::Message(text) | Self::Action(text) | Self::Edited(text) => text,
            Self::Unrelayed(_) => "",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SlackMessage {
    channel: String,
    sender: Sender,
    /// The event's `bot_id`, which a bot's posts carry even without the
    /// `bot_message` subtype; how this bot recognises its own echo.
    bot_id: Option<String>,
    content: Content,
}

/// Distinct upstream user ids whose display names one session remembers. The
/// ids are the upstream's to mint, so the cache is bounded like every other
/// upstream-driven table; a workspace with more speakers than this only pays
/// a `users.info` lookup again after the cache is cleared.
const MAX_USER_NAMES: usize = 4096;

/// Display names by Slack user id, bounded by [`MAX_USER_NAMES`].
#[derive(Default)]
struct UserNames {
    names: HashMap<String, String>,
    /// How many times the full cache was cleared, for the log line.
    clears: u64,
}

impl UserNames {
    fn get(&self, user: &str) -> Option<&String> {
        self.names.get(user)
    }

    fn remember(&mut self, user: String, name: String) {
        if !self.names.contains_key(&user) && self.names.len() >= MAX_USER_NAMES {
            self.clears += 1;
            eprintln!(
                "slack: {MAX_USER_NAMES} distinct user ids seen; the display-name cache was \
                 cleared (clear #{})",
                self.clears
            );
            self.names.clear();
        }
        self.names.insert(user, name);
    }
}

/// Why Slack is closing a socket (`disconnect.reason`).
#[derive(Debug, Clone, PartialEq, Eq)]
enum DisconnectReason {
    /// The socket retires in about ten seconds; the next one should be open
    /// before then.
    Warning,
    /// Slack rotates the socket; reconnect now. Nothing failed.
    RefreshRequested,
    /// The app's Socket Mode was switched off: a configuration answer.
    LinkDisabled,
    Other(String),
}

#[derive(Debug)]
struct Envelope {
    ack: Option<String>,
    retry_attempt: Option<u32>,
    kind: EnvelopeKind,
}

#[derive(Debug)]
enum EnvelopeKind {
    Disconnect(DisconnectReason),
    Message(SlackMessage),
    /// Nothing to relay: `hello`, an envelope type or event the bridge does
    /// not subscribe to, a housekeeping subtype.
    Nothing,
}

#[derive(Serialize)]
struct SocketAck<'a> {
    envelope_id: &'a str,
}

fn socket_ack(envelope_id: &str) -> Result<Ws, String> {
    serde_json::to_string(&SocketAck { envelope_id })
        .map(Ws::text)
        .map_err(|error| format!("Socket Mode ACK: {error}"))
}

#[derive(serde::Deserialize)]
struct SocketFrame {
    #[serde(rename = "type")]
    kind: SocketFrameKind,
    #[serde(default)]
    envelope_id: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum SocketFrameKind {
    Disconnect,
    EventsApi,
    #[serde(other)]
    Other,
}

#[derive(serde::Deserialize)]
struct EventsApiFrame {
    envelope_id: String,
    #[serde(default)]
    retry_attempt: Option<u32>,
    payload: SocketPayload,
}

#[derive(serde::Deserialize)]
struct SocketPayload {
    event: SlackEvent,
}

#[derive(serde::Deserialize)]
struct SlackEvent {
    #[serde(rename = "type")]
    kind: SlackEventKind,
    #[serde(default)]
    bot_id: Option<String>,
    #[serde(default)]
    subtype: Option<String>,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    text: Option<String>,
    /// `bot_message`: the name the bot posts as.
    #[serde(default)]
    username: Option<String>,
    /// `file_share`: the shared files.
    #[serde(default)]
    files: Vec<SlackFile>,
    /// `message_changed`: the message as it now reads, and as it read.
    #[serde(default)]
    message: Option<ChangedMessage>,
    #[serde(default)]
    previous_message: Option<ChangedMessage>,
}

#[derive(serde::Deserialize)]
struct SlackFile {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    permalink: Option<String>,
}

#[derive(serde::Deserialize)]
struct ChangedMessage {
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    bot_id: Option<String>,
    #[serde(default)]
    text: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum SlackEventKind {
    Message,
    #[serde(other)]
    Other,
}

/// Message subtypes that are channel housekeeping, not something anyone
/// said: dropped by name. Any subtype not named here or handled below is
/// reported as unrelayed.
const HOUSEKEEPING_SUBTYPES: &[&str] = &[
    "channel_join",
    "channel_leave",
    "channel_topic",
    "channel_purpose",
    "channel_name",
    "channel_archive",
    "channel_unarchive",
    "channel_convert_to_private",
    "channel_convert_to_public",
    "channel_posting_permissions",
    "message_deleted",
];

fn parse_envelope(text: &str) -> Result<Envelope, String> {
    let frame: SocketFrame =
        serde_json::from_str(text).map_err(|e| format!("Socket Mode JSON: {e}"))?;
    match frame.kind {
        SocketFrameKind::Disconnect => {
            let reason = match frame.reason.as_deref() {
                Some("warning") => DisconnectReason::Warning,
                Some("refresh_requested") => DisconnectReason::RefreshRequested,
                Some("link_disabled") => DisconnectReason::LinkDisabled,
                Some(other) => DisconnectReason::Other(e6irc_client::bounded_diagnostic(other)),
                None => DisconnectReason::Other("no reason given".into()),
            };
            return Ok(Envelope {
                ack: frame.envelope_id,
                retry_attempt: None,
                kind: EnvelopeKind::Disconnect(reason),
            });
        }
        SocketFrameKind::Other => {
            return Ok(Envelope {
                ack: frame.envelope_id,
                retry_attempt: None,
                kind: EnvelopeKind::Nothing,
            });
        }
        SocketFrameKind::EventsApi => {}
    }

    let events: EventsApiFrame =
        serde_json::from_str(text).map_err(|e| format!("events_api frame: {e}"))?;
    let kind = match parse_message_event(events.payload.event)? {
        Some(message) => EnvelopeKind::Message(message),
        None => EnvelopeKind::Nothing,
    };
    Ok(Envelope {
        ack: Some(events.envelope_id),
        retry_attempt: events.retry_attempt,
        kind,
    })
}

/// The relayable message in one event, `None` for an event with nothing to
/// relay. The subtypes are a whitelist: each one the bridge renders is named
/// here, housekeeping is dropped by name, and anything else becomes an
/// [`Content::Unrelayed`] notice rather than vanishing.
fn parse_message_event(event: SlackEvent) -> Result<Option<SlackMessage>, String> {
    if !matches!(event.kind, SlackEventKind::Message) {
        return Ok(None);
    }
    let subtype = event.subtype.as_deref();
    if subtype.is_some_and(|subtype| HOUSEKEEPING_SUBTYPES.contains(&subtype)) {
        return Ok(None);
    }
    let channel = event.channel.ok_or("message event had no channel")?;
    let user = |user: Option<String>| {
        user.ok_or_else(|| format!("{} event had no user", subtype.unwrap_or("message")))
    };
    let text = |text: Option<String>| {
        text.ok_or_else(|| format!("{} event had no text", subtype.unwrap_or("message")))
    };
    let (sender, content, bot_id) = match subtype {
        None | Some("thread_broadcast") => (
            Sender::User(user(event.user)?),
            Content::Message(text(event.text)?),
            event.bot_id,
        ),
        Some("file_share") => {
            let mut body = event.text.unwrap_or_default();
            for file in event.files {
                let line = match (file.name, file.permalink) {
                    (Some(name), Some(link)) => format!("{name} <{link}>"),
                    (Some(name), None) => name,
                    (None, Some(link)) => link,
                    (None, None) => continue,
                };
                if !body.is_empty() {
                    body.push('\n');
                }
                body.push_str(&line);
            }
            (
                Sender::User(user(event.user)?),
                Content::Message(body),
                event.bot_id,
            )
        }
        Some("me_message") => (
            Sender::User(user(event.user)?),
            Content::Action(text(event.text)?),
            event.bot_id,
        ),
        Some("message_changed") => {
            let changed = event
                .message
                .ok_or("message_changed event had no message")?;
            let now = changed
                .text
                .ok_or("message_changed event had no new text")?;
            // An unfurled link or a reaction count also "changes" a message;
            // only a new text is an edit anyone made.
            if event
                .previous_message
                .and_then(|previous| previous.text)
                .as_deref()
                == Some(now.as_str())
            {
                return Ok(None);
            }
            let sender = match (changed.user, &changed.bot_id) {
                (Some(user), _) => Sender::User(user),
                (None, Some(bot_id)) => Sender::Bot {
                    bot_id: bot_id.clone(),
                    name: bot_id.clone(),
                },
                (None, None) => return Err("message_changed event had no author".into()),
            };
            (sender, Content::Edited(now), changed.bot_id)
        }
        Some("bot_message") => {
            let bot_id = event.bot_id.ok_or("bot_message event had no bot_id")?;
            let name = event
                .username
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| bot_id.clone());
            (
                Sender::Bot {
                    bot_id: bot_id.clone(),
                    name,
                },
                Content::Message(text(event.text)?),
                Some(bot_id),
            )
        }
        Some(other) => {
            let sender = match (event.user, &event.bot_id) {
                (Some(user), _) => Sender::User(user),
                (None, Some(bot_id)) => Sender::Bot {
                    bot_id: bot_id.clone(),
                    name: bot_id.clone(),
                },
                (None, None) => Sender::Bot {
                    bot_id: String::new(),
                    name: "slack".into(),
                },
            };
            (sender, Content::Unrelayed(other.to_string()), event.bot_id)
        }
    };
    Ok(Some(SlackMessage {
        channel,
        sender,
        bot_id,
        content,
    }))
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum SlackResponse<T> {
    Success(SlackSuccess<T>),
    Failure(SlackFailure),
}

#[derive(serde::Deserialize)]
struct SlackSuccess<T> {
    #[serde(rename = "ok", deserialize_with = "true_only")]
    _ok: (),
    #[serde(flatten)]
    value: T,
}

#[derive(serde::Deserialize)]
struct SlackFailure {
    #[serde(rename = "ok", deserialize_with = "false_only")]
    _ok: (),
    #[serde(default)]
    error: Option<String>,
}

fn true_only<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<(), D::Error> {
    if bool::deserialize(deserializer)? {
        Ok(())
    } else {
        Err(serde::de::Error::custom("expected ok=true"))
    }
}

fn false_only<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<(), D::Error> {
    if bool::deserialize(deserializer)? {
        Err(serde::de::Error::custom("expected ok=false"))
    } else {
        Ok(())
    }
}

impl<T> SlackResponse<T> {
    fn into_result(self) -> Result<T, String> {
        match self {
            Self::Success(response) => Ok(response.value),
            Self::Failure(response) => {
                Err(response.error.unwrap_or_else(|| "slack api error".into()))
            }
        }
    }
}

async fn decode_slack_response<T: DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, String> {
    response
        .bounded_json::<SlackResponse<T>>()
        .await?
        .into_result()
}

fn slack_failure(context: &str, err: &str) -> super::SessionOutcome {
    const AUTH_ERRORS: &[&str] = &[
        "invalid_auth",
        "not_authed",
        "account_inactive",
        "token_revoked",
        "token_expired",
        "invalid_token",
        "no_permission",
    ];
    if AUTH_ERRORS.contains(&err) {
        eprintln!("slack: {context}: {err} (auth rejected; will stop retrying)");
        super::SessionOutcome::AuthRejected(None)
    } else {
        eprintln!("slack: {context}: {err}");
        super::SessionOutcome::Dropped(super::NetworkFailure::UpstreamRequestFailed)
    }
}

/// A Web API method called with `POST` and the bot token, decoded.
async fn slack_call<T: DeserializeOwned>(
    http: &super::BridgeHttp,
    base: &str,
    token: &str,
    method: &str,
) -> Result<T, String> {
    decode_slack_response(
        super::bridge_send(
            http.post(&format!("{base}/{method}"))?
                .header("Authorization", format!("Bearer {token}")),
        )
        .await?,
    )
    .await
}

async fn open_socket(
    http: &super::BridgeHttp,
    base: &str,
    app_token: &str,
) -> Result<String, String> {
    #[derive(serde::Deserialize)]
    struct SocketOpen {
        url: String,
    }

    decode_slack_response::<SocketOpen>(
        http.post(&format!("{base}/apps.connections.open"))?
            .header("Authorization", format!("Bearer {app_token}"))
            .send()
            .await
            .map_err(|e| e.to_string())?,
    )
    .await
    .map(|response| response.url)
}

async fn fetch_channel_name(
    http: &super::BridgeHttp,
    base: &str,
    bot_token: &str,
    id: &str,
) -> Result<String, String> {
    #[derive(serde::Deserialize)]
    struct ChannelInfo {
        channel: SlackChannel,
    }
    #[derive(serde::Deserialize)]
    struct SlackChannel {
        name: String,
    }

    let response: ChannelInfo = slack_get_json(
        http,
        base,
        bot_token,
        "conversations.info",
        &[("channel", id)],
    )
    .await?;
    if response.channel.name.is_empty() {
        Err(format!("conversations.info for {id} had an empty name"))
    } else {
        Ok(response.channel.name)
    }
}

async fn slack_get_json<T: DeserializeOwned>(
    http: &super::BridgeHttp,
    base: &str,
    token: &str,
    method: &str,
    query: &[(&str, &str)],
) -> Result<T, String> {
    decode_slack_response(
        http.get(&format!("{base}/{method}"))?
            .header("Authorization", format!("Bearer {token}"))
            .query(query)
            .send()
            .await
            .map_err(|e| e.to_string())?,
    )
    .await
}

async fn fetch_user_name(
    http: &super::BridgeHttp,
    base: &str,
    bot_token: &str,
    id: &str,
) -> Result<String, String> {
    #[derive(serde::Deserialize)]
    struct UserInfo {
        user: SlackUser,
    }
    #[derive(serde::Deserialize)]
    struct SlackUser {
        #[serde(default)]
        profile: SlackProfile,
        #[serde(default)]
        name: Option<String>,
    }
    #[derive(Default, serde::Deserialize)]
    struct SlackProfile {
        #[serde(default)]
        display_name: Option<String>,
        #[serde(default)]
        real_name: Option<String>,
    }

    let response: UserInfo =
        slack_get_json(http, base, bot_token, "users.info", &[("user", id)]).await?;
    [
        response.user.profile.display_name,
        response.user.profile.real_name,
        response.user.name,
    ]
    .into_iter()
    .flatten()
    .find(|name| !name.is_empty())
    .ok_or_else(|| format!("users.info for {id} had no name"))
}

async fn post_message(
    http: &super::BridgeHttp,
    base: &str,
    bot_token: &str,
    channel_id: &str,
    text: &super::BridgeText,
) -> Result<(), super::BridgeFailure> {
    #[derive(Serialize)]
    struct PostMessage<'a> {
        channel: &'a str,
        text: String,
    }

    let req = http
        .post(&format!("{base}/chat.postMessage"))?
        .header("Authorization", format!("Bearer {bot_token}"))
        .json(&PostMessage {
            channel: channel_id,
            text: text.italic_markdown(escape_markup),
        });
    #[derive(serde::Deserialize)]
    struct Accepted {}

    decode_slack_response::<Accepted>(super::bridge_send(req).await?).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message_of(envelope: Envelope) -> SlackMessage {
        match envelope.kind {
            EnvelopeKind::Message(message) => message,
            other => panic!("not a message: {other:?}"),
        }
    }

    fn event(event: serde_json::Value) -> Envelope {
        parse_envelope(
            &serde_json::json!({ "envelope_id": "e", "type": "events_api",
                                 "payload": { "event": event } })
            .to_string(),
        )
        .expect("event envelope")
    }

    #[test]
    fn parses_message_envelope() {
        let e = parse_envelope(
            r#"{"envelope_id":"abc","type":"events_api","retry_attempt":2,"payload":{"event":
               {"type":"message","channel":"C1","user":"U1","text":"hi"}}}"#,
        )
        .expect("message envelope");
        assert_eq!(e.ack.as_deref(), Some("abc"));
        assert_eq!(e.retry_attempt, Some(2));
        let m = message_of(e);
        assert_eq!(m.channel, "C1");
        assert_eq!(m.sender, Sender::User("U1".into()));
        assert_eq!(m.content, Content::Message("hi".into()));
    }

    /// Each subtype the bridge renders is named; housekeeping is dropped by
    /// name; anything else is said as unrelayed, never silently lost.
    #[test]
    fn message_subtypes_are_a_whitelist() {
        let m = message_of(event(serde_json::json!({
            "type": "message", "subtype": "file_share", "channel": "C1", "user": "U1",
            "text": "look", "files": [{ "name": "a.png", "permalink": "https://files.example/a" }],
        })));
        assert_eq!(
            m.content,
            Content::Message("look\na.png <https://files.example/a>".into())
        );
        let m = message_of(event(serde_json::json!({
            "type": "message", "subtype": "thread_broadcast", "channel": "C1", "user": "U1",
            "text": "also to the channel",
        })));
        assert_eq!(m.content, Content::Message("also to the channel".into()));
        let m = message_of(event(serde_json::json!({
            "type": "message", "subtype": "me_message", "channel": "C1", "user": "U1", "text": "waves",
        })));
        assert_eq!(m.content, Content::Action("waves".into()));
        let m = message_of(event(serde_json::json!({
            "type": "message", "subtype": "message_changed", "channel": "C1",
            "message": { "user": "U1", "text": "fixed" }, "previous_message": { "user": "U1", "text": "fxied" },
        })));
        assert_eq!(
            (m.sender, m.content),
            (Sender::User("U1".into()), Content::Edited("fixed".into()))
        );
        // An unfurl "changes" the message without changing its text.
        assert!(matches!(
            event(serde_json::json!({
                "type": "message", "subtype": "message_changed", "channel": "C1",
                "message": { "user": "U1", "text": "same" }, "previous_message": { "text": "same" },
            }))
            .kind,
            EnvelopeKind::Nothing
        ));
        let m = message_of(event(serde_json::json!({
            "type": "message", "subtype": "bot_message", "channel": "C1", "bot_id": "B9",
            "username": "deploybot", "text": "deployed",
        })));
        assert_eq!(
            m.sender,
            Sender::Bot {
                bot_id: "B9".into(),
                name: "deploybot".into()
            }
        );
        assert_eq!(m.bot_id.as_deref(), Some("B9"));
        for housekeeping in [
            "channel_join",
            "channel_topic",
            "channel_purpose",
            "message_deleted",
        ] {
            assert!(
                matches!(
                    event(
                        serde_json::json!({ "type": "message", "subtype": housekeeping,
                                              "channel": "C1", "user": "U1" })
                    )
                    .kind,
                    EnvelopeKind::Nothing
                ),
                "{housekeeping}"
            );
        }
        let m = message_of(event(serde_json::json!({
            "type": "message", "subtype": "huddle_thread", "channel": "C1", "user": "U1",
        })));
        assert_eq!(m.content, Content::Unrelayed("huddle_thread".into()));
        // Our own posts are recognised whichever way Slack marks them.
        let identity = Identity {
            user: "e6ircbot".into(),
            user_id: "UBOT".into(),
            bot_id: Some("BBOT".into()),
        };
        for own in [
            serde_json::json!({ "type": "message", "channel": "C1", "user": "UBOT", "text": "echo" }),
            serde_json::json!({ "type": "message", "channel": "C1", "user": "U7", "bot_id": "BBOT", "text": "echo" }),
            serde_json::json!({ "type": "message", "subtype": "bot_message", "channel": "C1", "bot_id": "BBOT", "text": "echo" }),
        ] {
            assert!(identity.is_self(&message_of(event(own.clone()))), "{own}");
        }
        assert!(!identity.is_self(&m));
    }

    /// Slack's markup, read the way an IRC user reads text.
    #[test]
    fn inbound_markup_decodes_mentions_channels_links_and_entities() {
        let mut names = UserNames::default();
        names.remember("U2".into(), "Bob".into());
        let channels = HashMap::from([("C1".to_string(), "#general".to_string())]);
        for (markup, plain) in [
            ("<@U2> hi", "@Bob hi"),
            ("<@U9|carol> hi", "@carol hi"),
            ("<@U9> hi", "@U9 hi"),
            (
                "in <#C1|general> and <#C1> and <#C7>",
                "in #general and #general and #C7",
            ),
            ("<!here> <!channel> <!everyone>", "@here @channel @everyone"),
            (
                "<!subteam^S1|@oncall> <!date^1392734382^{date}|Feb 18>",
                "@oncall Feb 18",
            ),
            (
                "<https://x.example|site> <https://y.example>",
                "site (https://x.example) https://y.example",
            ),
            (
                "<mailto:a@b.example|a@b.example>",
                "a@b.example (mailto:a@b.example)",
            ),
            ("a &amp; b &lt;3 &gt; &amp;lt;", "a & b <3 > &lt;"),
            ("unclosed < bracket", "unclosed < bracket"),
        ] {
            assert_eq!(decode_markup(markup, &names, &channels), plain, "{markup}");
        }
        assert_eq!(mentioned_users("<@U2> <@U3|x> <#C1> <@U4>"), ["U2", "U4"]);
        assert_eq!(
            escape_markup("<!channel> & <@U1>"),
            "&lt;!channel&gt; &amp; &lt;@U1&gt;"
        );
    }

    #[test]
    fn a_re_delivered_envelope_is_recognised_and_the_memory_is_bounded() {
        let mut recent = RecentEnvelopes::default();
        assert!(recent.first_time("a"));
        assert!(!recent.first_time("a"));
        for index in 0..RECENT_ENVELOPES {
            assert!(recent.first_time(&format!("e{index}")));
        }
        assert_eq!(recent.seen.len(), RECENT_ENVELOPES);
        assert!(recent.first_time("a"), "the oldest id is forgotten first");
    }

    #[test]
    fn handles_disconnect_and_garbage() {
        for (reason, expected) in [
            ("warning", DisconnectReason::Warning),
            ("refresh_requested", DisconnectReason::RefreshRequested),
            ("link_disabled", DisconnectReason::LinkDisabled),
            (
                "too_many_websockets",
                DisconnectReason::Other("too_many_websockets".into()),
            ),
        ] {
            let e = parse_envelope(
                &serde_json::json!({ "type": "disconnect", "reason": reason }).to_string(),
            )
            .expect("disconnect");
            assert!(
                matches!(e.kind, EnvelopeKind::Disconnect(ref got) if *got == expected),
                "{e:?}"
            );
        }
        let e = parse_envelope(r#"{"type":"hello","num_connections":1}"#).expect("hello");
        assert!(e.ack.is_none() && matches!(e.kind, EnvelopeKind::Nothing));
        let e = parse_envelope(
            r#"{"envelope_id":"cmd","type":"slash_commands",
               "payload":{"command":"/ignored"}}"#,
        )
        .expect("unknown envelope");
        assert_eq!(e.ack.as_deref(), Some("cmd"));
        assert!(matches!(e.kind, EnvelopeKind::Nothing));
        assert!(parse_envelope("not json").is_err());
    }

    #[test]
    fn rejects_malformed_user_messages_instead_of_defaulting_fields() {
        assert!(
            parse_envelope(
                r#"{"type":"events_api","payload":{"event":
               {"type":"message","channel":"C1","user":"U1","text":"hi"}}}"#
            )
            .is_err()
        );
        assert!(
            parse_envelope(
                r#"{"envelope_id":"x","type":"events_api","payload":{"event":
               {"type":"message","channel":"C1","text":"hi"}}}"#
            )
            .is_err()
        );
        assert!(
            parse_envelope(
                r#"{"envelope_id":"x","type":"events_api","payload":{"event":
               {"type":"message","subtype":"bot_message","channel":"C1","text":"hi"}}}"#
            )
            .is_err()
        );
    }

    #[test]
    fn response_contract() {
        #[derive(serde::Deserialize, PartialEq, Debug)]
        struct Payload {
            value: String,
        }
        let parsed: SlackResponse<Payload> = serde_json::from_value(serde_json::json!({
            "ok": true,
            "value": "present"
        }))
        .expect("success response");
        assert_eq!(
            parsed.into_result(),
            Ok(Payload {
                value: "present".into()
            })
        );
        let parsed: SlackResponse<Payload> = serde_json::from_value(serde_json::json!({
            "ok": false,
            "error": "not_authed"
        }))
        .expect("failure response");
        assert_eq!(parsed.into_result(), Err("not_authed".to_string()));
    }

    #[test]
    fn renders_and_routes() {
        assert_eq!(
            crate::bouncer::render_bridged(
                "slack",
                "U1",
                "#general",
                &crate::bouncer::Inbound::message("hi")
            ),
            vec![":U1!U1@slack PRIVMSG #general :hi"]
        );
        let mut map = HashMap::new();
        map.insert("#general".to_string(), "C1".to_string());
        use crate::bouncer::{BridgeText, RouteResult, route_privmsg};
        assert_eq!(
            route_privmsg("PRIVMSG #general :hello", &map),
            vec![RouteResult::Deliver {
                id: "C1".to_string(),
                target: "#general".to_string(),
                text: BridgeText::Text("hello".to_string())
            }]
        );
        // Case-insensitive routing.
        assert_eq!(
            route_privmsg("PRIVMSG #GENERAL :hi", &map),
            vec![RouteResult::Deliver {
                id: "C1".to_string(),
                target: "#GENERAL".to_string(),
                text: BridgeText::Text("hi".to_string())
            }]
        );
        // A PRIVMSG to a non-bridged channel is surfaced, not silently dropped.
        assert_eq!(
            route_privmsg("PRIVMSG #nope :x", &map),
            vec![RouteResult::Unmapped("#nope".to_string())]
        );
    }

    /// The upstream mints the user ids, so it decides how many distinct ones a
    /// session sees; the cache cannot grow with them.
    #[test]
    fn the_user_name_cache_is_bounded_and_says_when_it_clears() {
        let mut names = UserNames::default();
        for index in 0..MAX_USER_NAMES {
            names.remember(format!("U{index}"), format!("user {index}"));
        }
        assert_eq!(names.names.len(), MAX_USER_NAMES);
        assert_eq!(names.clears, 0);
        // A known id is refreshed in place, never counted as growth.
        names.remember("U0".into(), "renamed".into());
        assert_eq!(names.get("U0").map(String::as_str), Some("renamed"));
        assert_eq!(names.names.len(), MAX_USER_NAMES);
        // One more distinct id clears the cache and counts the clear.
        names.remember("Unew".into(), "new".into());
        assert_eq!(names.names.len(), 1);
        assert_eq!(names.get("Unew").map(String::as_str), Some("new"));
        assert_eq!(names.clears, 1);
    }

    #[test]
    fn api_base_default_and_override() {
        let mut c = SlackConfig {
            bot_token: "b".into(),
            app_token: "a".into(),
            api_base: String::new(),
            internal_upstreams: crate::egress::InternalUpstreams::Allow,
            channels: vec![],
            buffer_cap: 10,
        };
        crate::bouncer::assert_bridge_api_base(&mut c.api_base, DEFAULT_API, "http://127.0.0.1:9/");
    }

    #[cfg(feature = "discord")]
    mod socket {
        use super::*;
        use crate::bouncer::bridge_oracle::{
            self, Options, Oracle, OracleEvent, Provider, slack_envelope, slack_message,
        };
        use crate::bouncer::{
            DriverConnectionStatus, DriverEvent, NetworkFailure, NetworkHandle, SendOutcome,
            SessionOutcome,
        };
        use serde_json::json;

        struct Bridge {
            oracle: Oracle,
            handle: NetworkHandle,
            events: tokio::sync::broadcast::Receiver<DriverEvent>,
            session: tokio::task::JoinHandle<SessionOutcome>,
        }

        async fn bridge(options: Options) -> Bridge {
            let oracle = bridge_oracle::start_with(
                Provider::Slack,
                Options {
                    manual: true,
                    ..options
                },
            )
            .await;
            let config = SlackConfig {
                bot_token: "xoxb-token".into(),
                app_token: "xapp-token".into(),
                api_base: oracle.api_base.clone(),
                internal_upstreams: crate::egress::InternalUpstreams::Allow,
                channels: vec!["C1".into()],
                buffer_cap: 64,
            };
            let (handle, mut ends) = NetworkHandle::channels(64);
            let events = handle.subscribe();
            let session = tokio::spawn(async move { session_once(&config, &mut ends).await });
            oracle.wait_connected(0).await;
            Bridge {
                oracle,
                handle,
                events,
                session,
            }
        }

        async fn acked(oracle: &mut Oracle, connection: usize, envelope: &str) {
            loop {
                let (from, frame) = oracle.next_frame("ACK").await;
                if frame["envelope_id"] == envelope {
                    assert_eq!(from, connection, "{envelope} acked on the wrong socket");
                    return;
                }
            }
        }

        async fn line(events: &mut tokio::sync::broadcast::Receiver<DriverEvent>) -> String {
            tokio::time::timeout(std::time::Duration::from_secs(3), async {
                loop {
                    match events.recv().await.expect("driver events") {
                        DriverEvent::Line(line) if !line.line.contains("component") => {
                            return line.line;
                        }
                        _ => {}
                    }
                }
            })
            .await
            .expect("no relayed line")
        }

        fn assert_no_reconnect(events: &mut tokio::sync::broadcast::Receiver<DriverEvent>) {
            while let Ok(event) = events.try_recv() {
                match event {
                    DriverEvent::Status {
                        status: DriverConnectionStatus::Reconnecting(failure),
                        ..
                    } => panic!("a handover published Reconnecting({failure:?})"),
                    DriverEvent::Line(line) => {
                        assert!(!line.line.contains("component error"), "{}", line.line);
                    }
                    _ => {}
                }
            }
        }

        async fn post(oracle: &mut Oracle) -> serde_json::Value {
            loop {
                if let OracleEvent::SlackPost { body, .. } = oracle.next("post").await {
                    return body;
                }
            }
        }

        /// Slack warns about ten seconds before it retires a socket. The old
        /// socket keeps delivering until then; its envelopes are still acked
        /// and relayed while the next socket takes over, and nothing is
        /// recorded as a failure.
        #[tokio::test]
        async fn a_disconnect_warning_hands_over_to_a_new_socket_without_losing_envelopes() {
            let mut b = bridge(Options::default()).await;
            b.oracle
                .send(0, slack_envelope("env-1", slack_message("one")));
            acked(&mut b.oracle, 0, "env-1").await;
            assert_eq!(
                line(&mut b.events).await,
                ":Alice!Alice@slack PRIVMSG #general :one"
            );
            b.oracle
                .send(0, json!({ "type": "disconnect", "reason": "warning" }));
            b.oracle.send(
                0,
                slack_envelope("env-2", slack_message("two on the old socket")),
            );
            acked(&mut b.oracle, 0, "env-2").await;
            assert!(
                line(&mut b.events)
                    .await
                    .ends_with(":two on the old socket")
            );
            b.oracle.wait_connected(1).await;
            b.oracle.send(
                1,
                slack_envelope("env-3", slack_message("three on the new socket")),
            );
            acked(&mut b.oracle, 1, "env-3").await;
            assert!(
                line(&mut b.events)
                    .await
                    .ends_with(":three on the new socket")
            );
            b.oracle.send(
                0,
                json!({ "type": "disconnect", "reason": "refresh_requested" }),
            );
            b.oracle.close(0, 1000);
            b.oracle
                .send(1, slack_envelope("env-4", slack_message("still here")));
            acked(&mut b.oracle, 1, "env-4").await;
            assert!(line(&mut b.events).await.ends_with(":still here"));
            assert!(!b.session.is_finished());
            assert_no_reconnect(&mut b.events);
        }

        /// A refresh is Slack rotating the socket, not a lost connection.
        #[tokio::test]
        async fn a_refresh_request_opens_the_next_socket_without_a_failure_record() {
            let mut b = bridge(Options::default()).await;
            b.oracle.send(
                0,
                json!({ "type": "disconnect", "reason": "refresh_requested" }),
            );
            b.oracle.wait_connected(1).await;
            b.oracle.close(0, 1000);
            b.oracle.send(
                1,
                slack_envelope("env-1", slack_message("after the refresh")),
            );
            acked(&mut b.oracle, 1, "env-1").await;
            assert!(line(&mut b.events).await.ends_with(":after the refresh"));
            assert!(!b.session.is_finished());
            assert_no_reconnect(&mut b.events);
        }

        /// `link_disabled` means the app's Socket Mode was switched off.
        #[tokio::test]
        async fn a_disabled_link_is_a_configuration_refusal() {
            let b = bridge(Options::default()).await;
            b.oracle.send(
                0,
                json!({ "type": "disconnect", "reason": "link_disabled" }),
            );
            match tokio::time::timeout(std::time::Duration::from_secs(2), b.session)
                .await
                .expect("the session did not end")
                .expect("session task")
            {
                SessionOutcome::ConfigurationRejected(refusal) => {
                    assert_eq!(
                        refusal.failure(),
                        NetworkFailure::GatewayConfigurationRefused
                    );
                    assert!(refusal.diagnostic().contains("Socket Mode"), "{refusal:?}");
                }
                _ => panic!("link_disabled was not a configuration refusal"),
            }
        }

        /// A slow `chat.postMessage` must not hold the socket: Slack re-sends
        /// an envelope not acked within three seconds, and a re-sent envelope
        /// is acked again but relayed once.
        #[tokio::test]
        async fn a_slow_post_does_not_delay_acks_and_a_redelivery_is_relayed_once() {
            let mut b = bridge(Options {
                post_delay: std::time::Duration::from_secs(5),
                ..Options::default()
            })
            .await;
            b.oracle
                .send(0, slack_envelope("env-1", slack_message("one")));
            acked(&mut b.oracle, 0, "env-1").await;
            assert!(line(&mut b.events).await.ends_with(":one"));
            assert_eq!(b.handle.send("PRIVMSG #general :slow"), SendOutcome::Sent);
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let started = tokio::time::Instant::now();
            b.oracle
                .send(0, slack_envelope("env-2", slack_message("two")));
            acked(&mut b.oracle, 0, "env-2").await;
            assert!(
                started.elapsed() < std::time::Duration::from_secs(3),
                "the ack waited {:?} behind the post",
                started.elapsed()
            );
            assert!(line(&mut b.events).await.ends_with(":two"));
            let mut again = slack_envelope("env-1", slack_message("one"));
            again["retry_attempt"] = json!(1);
            again["retry_reason"] = json!("timeout");
            b.oracle.send(0, again);
            acked(&mut b.oracle, 0, "env-1").await;
            b.oracle
                .send(0, slack_envelope("env-3", slack_message("three")));
            acked(&mut b.oracle, 0, "env-3").await;
            assert!(
                line(&mut b.events).await.ends_with(":three"),
                "the re-sent envelope was relayed a second time"
            );
        }

        /// A failed name lookup is not remembered as the name.
        #[tokio::test]
        async fn a_failed_name_lookup_is_retried_on_the_next_message() {
            let mut b = bridge(Options {
                fail_first_user_lookup: true,
                ..Options::default()
            })
            .await;
            b.oracle
                .send(0, slack_envelope("env-1", slack_message("one")));
            assert!(
                line(&mut b.events)
                    .await
                    .starts_with(":U1!U1@slack PRIVMSG #general :")
            );
            b.oracle
                .send(0, slack_envelope("env-2", slack_message("two")));
            let relayed = loop {
                let relayed = line(&mut b.events).await;
                if relayed.ends_with(":two") {
                    break relayed;
                }
            };
            assert_eq!(relayed, ":Alice!Alice@slack PRIVMSG #general :two");
            let mut lookups = 0;
            while let Ok(event) = b.oracle.events.try_recv() {
                if matches!(event, OracleEvent::UserLookup(ref user) if user == "U1") {
                    lookups += 1;
                }
            }
            assert_eq!(
                lookups, 2,
                "the failed lookup was cached instead of retried"
            );
        }

        /// Slack's markup is escaped on the way out, so an IRC line cannot
        /// page a channel with `<!channel>`, and `/me` is Slack italics.
        #[tokio::test]
        async fn posts_escape_markup_and_carry_actions_as_italics() {
            let mut b = bridge(Options::default()).await;
            for (sent, posted) in [
                (
                    "PRIVMSG #general :<!channel> a & b",
                    "&lt;!channel&gt; a &amp; b",
                ),
                ("PRIVMSG #general :\u{1}ACTION waves\u{1}", "_waves_"),
                (
                    "PRIVMSG #general :\u{1f}under\u{1f} \u{3}12blue",
                    "under blue",
                ),
            ] {
                assert_eq!(b.handle.send(sent), SendOutcome::Sent);
                let body = post(&mut b.oracle).await;
                assert_eq!(body["text"], posted, "{sent:?}");
            }
        }

        /// Slack's markup is decoded on the way in: mentions by name,
        /// channels by name, links with their label, entities unescaped.
        #[tokio::test]
        async fn inbound_markup_is_decoded() {
            let mut b = bridge(Options::default()).await;
            b.oracle.send(
                0,
                slack_envelope(
                    "env-1",
                    slack_message(
                        "<@U2> see <#C1|general> &amp; <https://x.example|site> &lt;3 <!here>",
                    ),
                ),
            );
            assert_eq!(
                line(&mut b.events).await,
                ":Alice!Alice@slack PRIVMSG #general :@Bob see #general & site \
                 (https://x.example) <3 @here"
            );
        }

        /// Other bots speak; this bot's own posts are its echo.
        #[tokio::test]
        async fn other_bots_are_relayed_and_our_own_posts_are_not() {
            let mut b = bridge(Options::default()).await;
            b.oracle.send(
                0,
                slack_envelope(
                    "env-1",
                    json!({ "type": "message", "subtype": "bot_message", "channel": "C1",
                            "bot_id": "BBOT", "username": "e6irc", "text": "our echo" }),
                ),
            );
            b.oracle.send(
                0,
                slack_envelope(
                    "env-2",
                    json!({ "type": "message", "subtype": "bot_message", "channel": "C1",
                            "bot_id": "BOTHER", "username": "deploybot", "text": "deployed" }),
                ),
            );
            assert_eq!(
                line(&mut b.events).await,
                ":deploybot!deploybot@slack PRIVMSG #general :deployed"
            );
        }

        /// `/me` in Slack is a `me_message`: an IRC ACTION.
        #[tokio::test]
        async fn a_me_message_is_an_action() {
            let mut b = bridge(Options::default()).await;
            b.oracle.send(
                0,
                slack_envelope(
                    "env-1",
                    json!({ "type": "message", "subtype": "me_message", "channel": "C1",
                            "user": "U1", "text": "waves" }),
                ),
            );
            assert_eq!(
                line(&mut b.events).await,
                ":Alice!Alice@slack PRIVMSG #general :\u{1}ACTION waves\u{1}"
            );
        }

        /// A quiet workspace sends nothing for longer than the silence
        /// window; the bridge pings so its own liveness is proven.
        #[tokio::test]
        async fn the_socket_is_pinged_while_the_workspace_is_quiet() {
            let mut b = bridge(Options::default()).await;
            // The driver arms its ping interval in the same poll that announces
            // it connected. Pausing before that let the clock jump straight to
            // this test's own 40 s bound while the socket's first frames were
            // still in flight on the real network (seen under load in CI's
            // coverage job).
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    if let Ok(DriverEvent::Status {
                        status: DriverConnectionStatus::Connected,
                        ..
                    }) = b.events.recv().await
                    {
                        return;
                    }
                }
            })
            .await
            .expect("the bridge announces it connected");
            // Real sockets, virtual time: the clock jumps to the next timer
            // whenever every task is waiting.
            tokio::time::pause();
            tokio::time::timeout(std::time::Duration::from_secs(40), async {
                loop {
                    if let Some(OracleEvent::Ping(0)) = b.oracle.events.recv().await {
                        return;
                    }
                }
            })
            .await
            .expect("no ping within 40 seconds of quiet");
        }
    }

    /// The scripted oracle, and a bridge network's session connecting to it,
    /// with a subscription taken before the session starts.
    #[cfg(feature = "discord")]
    async fn scripted_session() -> (
        crate::bouncer::bridge_oracle::Oracle,
        crate::bouncer::NetworkHandle,
        tokio::sync::broadcast::Receiver<crate::bouncer::DriverEvent>,
        tokio::task::JoinHandle<crate::bouncer::SessionOutcome>,
    ) {
        let oracle =
            crate::bouncer::bridge_oracle::start(crate::bouncer::bridge_oracle::Provider::Slack)
                .await;
        let config = SlackConfig {
            bot_token: "xoxb-token".into(),
            app_token: "xapp-token".into(),
            api_base: oracle.api_base.clone(),
            internal_upstreams: crate::egress::InternalUpstreams::Allow,
            channels: vec!["C1".into()],
            buffer_cap: 10,
        };
        let (handle, mut ends) = crate::bouncer::NetworkHandle::bridge_channels(10);
        let driver_events = handle.subscribe();
        let session = tokio::spawn(async move { session_once(&config, &mut ends).await });
        (oracle, handle, driver_events, session)
    }

    #[tokio::test]
    #[cfg(feature = "discord")]
    async fn real_http_and_websocket_transport_bridge_both_directions() {
        let (mut oracle, handle, driver_events, session) = scripted_session().await;
        crate::bouncer::bridge_oracle::verify_round_trip(
            crate::bouncer::bridge_oracle::Provider::Slack,
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
    #[cfg(feature = "discord")]
    async fn an_attached_client_is_welcomed_as_the_bot_and_knows_its_echo() {
        let (_oracle, handle, _, session) = scripted_session().await;
        crate::bouncer::bridge_oracle::verify_attached_client(handle, session).await;
    }
}
