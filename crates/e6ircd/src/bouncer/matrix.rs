//! Matrix client-server bridge.

use super::BoundedJson;
use std::collections::HashMap;

use serde::Serialize;

use super::{ConnectionEvent, DriverEnds, NetworkDriver, NetworkHandle};

/// The Matrix device one bouncer network is. See [`MatrixConfig::device`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixDevice {
    id: String,
    display_name: String,
}

impl MatrixDevice {
    /// The device of `owner`'s network `network`; `None` is a server-level
    /// network that no account owns. `*` cannot be an account name, so a shared
    /// network's device is never mistaken for an account's.
    pub fn for_network(owner: Option<&str>, network: &str) -> Self {
        Self {
            id: format!("e6irc/{}/{network}", owner.unwrap_or("*")),
            display_name: format!("e6irc bouncer ({network})"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MatrixConfig {
    /// Every password login names this device. A homeserver makes a new device
    /// for a login that names none and only `/logout` removes it — which a
    /// crashed or killed process never sends. Naming the same one each time
    /// leaves nothing to leak: the homeserver re-uses it.
    pub device: MatrixDevice,
    /// Homeserver base URL, e.g. `https://matrix.example.org` (`http://` only
    /// for a loopback test homeserver; see `validate_bridge_base`).
    pub homeserver: String,
    /// Login username (localpart).
    pub user: String,
    pub password: String,
    /// Room aliases to join and bridge (e.g. `#room:server`).
    pub rooms: Vec<String>,
    pub buffer_cap: usize,
    /// The server's policy on a homeserver inside its own network.
    pub internal_upstreams: crate::egress::InternalUpstreams,
}

pub struct MatrixDriver {
    config: MatrixConfig,
}

impl MatrixDriver {
    pub fn new(config: MatrixConfig) -> Self {
        Self { config }
    }
}

impl NetworkDriver for MatrixDriver {
    fn kind(&self) -> &'static str {
        "matrix"
    }

    super::bridge_start!();
}

struct Session {
    http: super::BridgeHttp,
    base: String,
    token: String,
    user_id: String,
    rooms: Rooms,
}

/// The joined rooms, by the three names a session needs: the folded IRC
/// channel a client addresses, the room id the homeserver speaks, and the
/// alias the owner configured (which a refusal names).
#[derive(Clone, Default)]
struct Rooms {
    channel_to_room: HashMap<String, String>,
    room_to_channel: HashMap<String, String>,
    room_to_alias: HashMap<String, String>,
}

/// Where the last session stopped reading, and the rooms it had joined: the
/// next session continues from here instead of joining again and starting
/// over. Starting over meant a fresh initial sync, which only establishes a
/// position — so everything said while the bridge was reconnecting was
/// skipped without a word.
#[derive(Clone)]
struct SyncPosition {
    since: String,
    rooms: Rooms,
}

/// One password login: the access token and who it belongs to.
#[derive(Clone)]
struct Login {
    http: super::BridgeHttp,
    access_token: String,
    user_id: String,
}

/// What one Matrix driver keeps for its whole lifetime, across reconnects.
///
/// Every password `/login` creates a new device on the homeserver, and nothing
/// removes it but `/logout`. A driver that logged in afresh on each reconnect
/// left one behind every few seconds for as long as its upstream was unhappy.
/// The login therefore belongs to the driver, not to the session: it is made
/// once, reused by every reconnect, replaced only when the homeserver says the
/// token is dead, and logged out when the driver stops.
struct Shared {
    config: MatrixConfig,
    login: tokio::sync::Mutex<Option<Login>>,
    /// Belongs to the login it was read with: forgotten with it.
    position: std::sync::Mutex<Option<SyncPosition>>,
    transactions: TransactionIds,
}

/// The transaction ids this driver puts on the messages it sends.
///
/// A transaction id tells the homeserver "the same message again": it answers
/// a repeat with the first event's id and stores nothing. The ids are scoped
/// to the device, and the device outlives both the session and the process (it
/// is named on every login, see [`MatrixConfig::device`]). So the counter
/// lives with the driver, not the session — a session that started again at
/// one made its first messages repeats of the previous session's, accepted
/// and never posted — and every id carries the moment this driver started, so
/// a restarted process does not replay the last one's ids either.
struct TransactionIds {
    started_at_millis: u64,
    next: std::sync::atomic::AtomicU64,
}

impl TransactionIds {
    fn new() -> Self {
        let started_at_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before 1970")
            .as_millis() as u64;
        Self {
            started_at_millis,
            next: std::sync::atomic::AtomicU64::new(1),
        }
    }

    fn next(&self) -> String {
        let sequence = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("e6{}x{sequence}", self.started_at_millis)
    }
}

impl Shared {
    fn new(config: MatrixConfig) -> Self {
        Self {
            config,
            login: tokio::sync::Mutex::new(None),
            position: std::sync::Mutex::new(None),
            transactions: TransactionIds::new(),
        }
    }

    async fn login(&self) -> Result<Login, super::ConnectFail> {
        let mut cached = self.login.lock().await;
        if let Some(login) = cached.as_ref() {
            return Ok(login.clone());
        }
        let http = super::BridgeHttp::new(
            std::time::Duration::from_secs(60),
            self.config.internal_upstreams,
        )
        .map_err(|e| e.to_string())?;
        let response: LoginResponse = super::bridge_send_credentials(
            http.post(&format!("{}/_matrix/client/v3/login", self.base()))?
                .json(&LoginRequest::password(&self.config)),
            "login",
        )
        .await?
        .bounded_json()
        .await?;
        if response.access_token.is_empty() || response.user_id.is_empty() {
            return Err(super::ConnectFail::Transient(
                "login response had an empty access token or user id".into(),
            ));
        }
        let login = Login {
            http,
            access_token: response.access_token,
            user_id: response.user_id,
        };
        *cached = Some(login.clone());
        Ok(login)
    }

    /// The homeserver answered 401 to this token: it is dead (expired, or the
    /// device was removed), so the next session logs in again. There is nothing
    /// to log out of.
    async fn forget_login(&self) {
        *self.login.lock().await = None;
        self.forget_position();
    }

    fn position(&self) -> Option<SyncPosition> {
        self.position.lock().expect("matrix sync position").clone()
    }

    fn store_position(&self, since: &str, rooms: &Rooms) {
        *self.position.lock().expect("matrix sync position") = Some(SyncPosition {
            since: since.to_string(),
            rooms: rooms.clone(),
        });
    }

    /// The next session joins every room again and starts from a fresh
    /// position: after a new login, a refused room, or a position the
    /// homeserver no longer accepts.
    fn forget_position(&self) {
        *self.position.lock().expect("matrix sync position") = None;
    }

    /// Remove this driver's device. Bounded, and a failure is only logged (the
    /// driver is stopping either way); the token itself is never printed.
    async fn logout(&self) {
        let Some(login) = self.login.lock().await.take() else {
            return;
        };
        let request = match login
            .http
            .post(&format!("{}/_matrix/client/v3/logout", self.base()))
        {
            Ok(request) => request
                .bearer_auth(&login.access_token)
                .json(&EmptyObject {}),
            Err(error) => {
                eprintln!("matrix: logout refused: {error}");
                return;
            }
        };
        match tokio::time::timeout(LOGOUT_DEADLINE, super::bridge_send(request)).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => eprintln!("matrix: logout failed: {error}"),
            Err(_) => eprintln!("matrix: logout timed out"),
        }
    }

    fn base(&self) -> &str {
        self.config.homeserver.trim_end_matches('/')
    }
}

const LOGOUT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

async fn run(config: MatrixConfig, mut ends: DriverEnds) {
    let shared = std::sync::Arc::new(Shared::new(config));
    super::run_with_backoff(shared.clone(), &mut ends, |shared, ends| {
        Box::pin(session_once(shared, ends))
    })
    .await;
    // Stopped for good — removed, replaced, or parked until it was.
    shared.logout().await;
}

/// The longest a `/sync` rate limit pauses the loop. Past it the wait is cut
/// short and the homeserver asked again; a `429` answers that too if it must.
const SYNC_RATE_LIMIT_CEILING: std::time::Duration = std::time::Duration::from_secs(300);

async fn session_once(shared: &Shared, ends: &mut DriverEnds) -> super::SessionOutcome {
    use super::SessionOutcome::Dropped;
    let stored = shared.position();
    let mut session = match &stored {
        Some(position) => match shared.login().await {
            Ok(login) => Session {
                http: login.http,
                base: shared.base().to_string(),
                token: login.access_token,
                user_id: login.user_id,
                rooms: position.rooms.clone(),
            },
            Err(e) => return e.into_outcome("matrix"),
        },
        None => match connect(shared).await {
            Ok(s) => s,
            Err(e) => {
                if matches!(e, super::ConnectFail::Configuration(_)) {
                    shared.forget_position();
                }
                return e.into_outcome("matrix");
            }
        },
    };
    ends.emit(ConnectionEvent::Connected);

    // `None` until the first sync of a fresh start, which only establishes a
    // position: its timeline is discarded. A resumed session has one already.
    let mut since = stored.map(|position| position.since);
    let resumed = since.is_some();
    // When the next sync may be sent: now, or after a rate limit's wait.
    let mut sync_at = tokio::time::Instant::now();

    loop {
        tokio::select! {
            result = async {
                tokio::time::sleep_until(sync_at).await;
                sync(&session, since.as_deref()).await
            } => match result {
                Ok(batch) => {
                    let initial = since.is_none();
                    since = Some(batch.next.clone());
                    if !initial
                        && let Some(outcome) = relay_batch(shared, &session, ends, batch)
                    {
                        return outcome;
                    }
                    shared.store_position(since.as_deref().expect("just set"), &session.rooms);
                }
                Err(RequestError::RateLimited(wait)) => {
                    let wait = wait.min(SYNC_RATE_LIMIT_CEILING);
                    eprintln!("matrix: sync rate-limited; asking again in {wait:?} from the same position");
                    sync_at = tokio::time::Instant::now() + wait;
                }
                Err(error) => return sync_failed(shared, resumed, error).await,
            },
            cmd = ends.next_command() => match cmd {
                Some(cmd) => handle_command(&mut session, shared, ends, &cmd.line).await,
                None => return super::SessionOutcome::Stopped, // every handle dropped
            },
        }
    }

    async fn sync_failed(
        shared: &Shared,
        resumed: bool,
        error: RequestError,
    ) -> super::SessionOutcome {
        match &error {
            RequestError::TokenRejected => shared.forget_login().await,
            // The homeserver refused the request itself — for a resumed
            // session, most likely a position it no longer knows. Keeping it
            // would refuse every session after this one the same way.
            RequestError::Refused(_) if resumed => shared.forget_position(),
            _ => {}
        }
        eprintln!("matrix: sync failed: {error}");
        Dropped(super::NetworkFailure::UpstreamRequestFailed)
    }
}

/// Relay one incremental sync. `Some` ends the session: a bridged room turned
/// out to be end-to-end encrypted, which is said in its channel once and
/// refused like the configuration it now is.
fn relay_batch(
    shared: &Shared,
    session: &Session,
    ends: &DriverEnds,
    batch: SyncBatch,
) -> Option<super::SessionOutcome> {
    for room_id in batch.truncated {
        // The homeserver had more than one sync carries and sent only the
        // newest. The gap is said, not hidden.
        if let Some(channel) = session.rooms.room_to_channel.get(&room_id) {
            ends.emit_line(format!(
                ":*bnc* NOTICE {channel} :matrix: more messages arrived than one \
                 sync carries; the oldest were not relayed"
            ));
        }
    }
    for m in batch.messages {
        if m.sender == session.user_id {
            continue;
        }
        let Some(channel) = session.rooms.room_to_channel.get(&m.room_id) else {
            continue;
        };
        let sender = matrix_localpart(&m.sender);
        match m.content {
            IncomingContent::Relay(message) => {
                for line in super::render_bridged("matrix", sender, channel, &message) {
                    ends.emit_line(line);
                }
            }
            IncomingContent::Unrelayed(msgtype) => {
                ends.emit_line(super::unrelayed_notice("matrix", channel, &msgtype, sender));
            }
        }
    }
    let room_id = batch
        .encrypted
        .into_iter()
        .find(|room| session.rooms.room_to_channel.contains_key(room))?;
    let channel = &session.rooms.room_to_channel[&room_id];
    let alias = session
        .rooms
        .room_to_alias
        .get(&room_id)
        .map_or(room_id.as_str(), String::as_str);
    ends.emit_line(format!(
        ":*bnc* NOTICE {channel} :matrix: this room is now end-to-end encrypted; the bridge \
         cannot read it and stops relaying until the network is reconfigured"
    ));
    shared.forget_position();
    Some(encrypted_room_refusal(alias).into_outcome("matrix"))
}

fn encrypted_room_refusal(alias: &str) -> super::ConnectFail {
    super::ConnectFail::Configuration(super::ConfigurationRefusal::new(
        super::NetworkFailure::RoomEncrypted,
        &format!("room {alias} is end-to-end encrypted; the bridge cannot read it"),
    ))
}

/// How a request made with the driver's access token failed. The status is the
/// only thing read from the response: 401 is about the token, 403 is about what
/// the account may do, and neither is a reason to log in again and again.
#[derive(Debug)]
enum RequestError {
    /// 401: the token is dead.
    TokenRejected,
    /// 403: the account is not allowed to do this.
    Forbidden,
    /// 404: there is no such thing (a room without encryption state).
    NotFound,
    /// 429: wait this long, then ask again.
    RateLimited(std::time::Duration),
    /// Another 4xx: the homeserver refused the request as asked.
    Refused(reqwest::StatusCode),
    Other(String),
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TokenRejected => f.write_str("the homeserver rejected the access token"),
            Self::Forbidden => f.write_str("the homeserver forbade the request"),
            Self::NotFound => f.write_str("the homeserver has no such resource"),
            Self::RateLimited(wait) => {
                write!(f, "the homeserver rate-limited the request ({wait:?})")
            }
            Self::Refused(status) => {
                write!(f, "the homeserver refused the request (HTTP {status})")
            }
            Self::Other(detail) => f.write_str(detail),
        }
    }
}

impl From<String> for RequestError {
    fn from(detail: String) -> Self {
        Self::Other(detail)
    }
}

async fn send_authorized(
    request: reqwest::RequestBuilder,
) -> Result<reqwest::Response, RequestError> {
    let response = request.send().await.map_err(|e| e.to_string())?;
    let status = response.status();
    match status {
        reqwest::StatusCode::UNAUTHORIZED => Err(RequestError::TokenRejected),
        reqwest::StatusCode::FORBIDDEN => Err(RequestError::Forbidden),
        reqwest::StatusCode::NOT_FOUND => Err(RequestError::NotFound),
        _ => super::bridge_response_status(response)
            .await
            .map_err(|failure| match failure {
                super::BridgeFailure::RateLimited(wait) => RequestError::RateLimited(wait),
                super::BridgeFailure::Failed(_) if status.is_client_error() => {
                    RequestError::Refused(status)
                }
                super::BridgeFailure::Failed(detail) => RequestError::Other(detail),
            }),
    }
}

async fn connect(shared: &Shared) -> Result<Session, super::ConnectFail> {
    use super::{ConfigurationRefusal, ConnectFail, NetworkFailure};
    let config = &shared.config;
    let login = shared.login().await?;
    let mut session = Session {
        http: login.http,
        base: shared.base().to_string(),
        token: login.access_token,
        user_id: login.user_id,
        rooms: Rooms::default(),
    };
    let unmappable = |detail: String| {
        ConnectFail::Configuration(ConfigurationRefusal::new(
            NetworkFailure::ChannelMappingFailed,
            &detail,
        ))
    };
    let transient = async |what: String, error: RequestError| {
        if matches!(error, RequestError::TokenRejected) {
            shared.forget_login().await;
        }
        ConnectFail::Transient(format!("{what}: {error}"))
    };
    for alias in &config.rooms {
        let channel = alias_to_channel(alias);
        if !crate::sanitize::valid_channel_name(&channel) {
            return Err(unmappable(format!(
                "room alias {alias} maps to an unsafe IRC channel name"
            )));
        }
        let folded = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(&channel);
        if session.rooms.channel_to_room.contains_key(&folded) {
            return Err(unmappable(format!(
                "two room aliases map to the IRC channel {folded}; rename one"
            )));
        }
        let room_id = match join_room(&session, alias).await {
            Ok(room_id) => room_id,
            Err(RequestError::Forbidden) => {
                return Err(ConnectFail::Configuration(ConfigurationRefusal::new(
                    NetworkFailure::ChannelJoinRefused,
                    &format!("the homeserver forbade joining {alias} (not invited, or banned)"),
                )));
            }
            Err(error) => return Err(transient(format!("join {alias}"), error).await),
        };
        // The bridge holds no device keys: an encrypted room would join,
        // sync, and relay nothing, forever, with nothing said.
        match room_encryption(&session, &room_id).await {
            Ok(()) => return Err(encrypted_room_refusal(alias)),
            Err(RequestError::NotFound) => {}
            Err(error) => {
                return Err(transient(format!("encryption state of {alias}"), error).await);
            }
        }
        session
            .rooms
            .channel_to_room
            .insert(folded, room_id.clone());
        session
            .rooms
            .room_to_channel
            .insert(room_id.clone(), channel);
        session.rooms.room_to_alias.insert(room_id, alias.clone());
    }
    Ok(session)
}

/// `Ok` when the room has an `m.room.encryption` state event — it is
/// end-to-end encrypted; [`RequestError::NotFound`] when it has none.
async fn room_encryption(s: &Session, room_id: &str) -> Result<(), RequestError> {
    send_authorized(
        s.http
            .get(&format!(
                "{}/_matrix/client/v3/rooms/{}/state/m.room.encryption",
                s.base,
                urlencode(room_id)
            ))?
            .bearer_auth(&s.token),
    )
    .await
    .map(|_| ())
}

async fn join_room(s: &Session, alias: &str) -> Result<String, RequestError> {
    let encoded = urlencode(alias);
    let response: JoinResponse = send_authorized(
        s.http
            .post(&format!("{}/_matrix/client/v3/join/{encoded}", s.base))?
            .bearer_auth(&s.token)
            .json(&EmptyObject {}),
    )
    .await?
    .bounded_json()
    .await?;
    if response.room_id.is_empty() {
        Err(format!("join {alias} returned an empty room id").into())
    } else {
        Ok(response.room_id)
    }
}

#[derive(Serialize)]
struct LoginRequest<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    identifier: LoginIdentifier<'a>,
    password: &'a str,
    /// See [`MatrixConfig::device`]: the same device on every login.
    device_id: &'a str,
    initial_device_display_name: &'a str,
}

impl<'a> LoginRequest<'a> {
    fn password(config: &'a MatrixConfig) -> Self {
        Self {
            kind: "m.login.password",
            identifier: LoginIdentifier {
                kind: "m.id.user",
                user: &config.user,
            },
            password: &config.password,
            device_id: &config.device.id,
            initial_device_display_name: &config.device.display_name,
        }
    }
}

#[derive(Serialize)]
struct LoginIdentifier<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    user: &'a str,
}

#[derive(serde::Deserialize)]
struct LoginResponse {
    access_token: String,
    user_id: String,
}

#[derive(serde::Deserialize)]
struct JoinResponse {
    room_id: String,
}

#[derive(Serialize)]
struct EmptyObject {}

#[derive(Serialize)]
struct MatrixMessageRequest<'a> {
    msgtype: &'static str,
    body: &'a str,
}

impl<'a> MatrixMessageRequest<'a> {
    /// An IRC `/me` is an `m.emote`; anything else an `m.text`.
    fn new(text: &'a super::BridgeText) -> Self {
        match text {
            super::BridgeText::Text(body) => Self {
                msgtype: "m.text",
                body,
            },
            super::BridgeText::Action(body) => Self {
                msgtype: "m.emote",
                body,
            },
        }
    }
}

struct Incoming {
    room_id: String,
    sender: String,
    content: IncomingContent,
}

enum IncomingContent {
    Relay(super::Inbound),
    /// A message type the bridge cannot show, by its name: said, not dropped.
    Unrelayed(String),
}

#[derive(serde::Deserialize)]
struct SyncResponse {
    next_batch: String,
    #[serde(default)]
    rooms: SyncRooms,
}

#[derive(Default, serde::Deserialize)]
struct SyncRooms {
    #[serde(default)]
    join: HashMap<String, JoinedRoom>,
}

#[derive(serde::Deserialize)]
struct JoinedRoom {
    /// Absent when a filtered sync has nothing new for the room.
    #[serde(default)]
    timeline: Timeline,
}

#[derive(Default, serde::Deserialize)]
struct Timeline {
    #[serde(default)]
    events: Vec<TimelineEvent>,
    /// The homeserver had more events than the filter's limit and sent only
    /// the newest.
    #[serde(default)]
    limited: bool,
}

#[derive(serde::Deserialize)]
#[serde(tag = "type")]
enum TimelineEvent {
    #[serde(rename = "m.room.message")]
    Message {
        #[serde(default)]
        sender: Option<String>,
        content: MessageContent,
    },
    /// A message the bridge cannot decrypt.
    #[serde(rename = "m.room.encrypted")]
    Encrypted,
    /// The state event that switches encryption on.
    #[serde(rename = "m.room.encryption")]
    EncryptionEnabled,
    #[serde(other)]
    Other,
}

#[derive(serde::Deserialize)]
struct MessageContent {
    msgtype: String,
    #[serde(default)]
    body: Option<String>,
    /// Media (`m.image`, `m.file`, `m.audio`, `m.video`): the `mxc://` URI.
    #[serde(default)]
    url: Option<String>,
    /// `m.location`: the `geo:` URI.
    #[serde(default)]
    geo_uri: Option<String>,
}

/// One sync's worth: where to continue from, the messages, the rooms whose
/// timeline the homeserver cut short, and the rooms that showed encryption.
struct SyncBatch {
    next: String,
    messages: Vec<Incoming>,
    truncated: Vec<String>,
    encrypted: Vec<String>,
}

/// The HTTP address of `mxc://server/media-id` on `homeserver`, or `None`
/// when the URI is not one. Both parts are checked against the spec's
/// grammar, since they are upstream text placed into a URL path.
fn media_download_url(homeserver: &str, mxc: &str) -> Option<String> {
    let (server, media) = mxc.strip_prefix("mxc://")?.split_once('/')?;
    let server_ok = !server.is_empty()
        && server
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'));
    let media_ok = !media.is_empty()
        && media
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'));
    (server_ok && media_ok)
        .then(|| format!("{homeserver}/_matrix/media/v3/download/{server}/{media}"))
}

/// What one `m.room.message` shows on IRC, by `msgtype`: text as a message,
/// `m.emote` as an ACTION, `m.notice` as a NOTICE, media as its body and a
/// download link, `m.location` as its body and `geo:` URI. Any other type —
/// or media without a usable link — is named as unrelayed.
fn message_content(
    homeserver: &str,
    room_id: &str,
    content: MessageContent,
) -> Result<IncomingContent, String> {
    use super::{Inbound, InboundKind};
    let body = |content: &MessageContent| {
        content
            .body
            .clone()
            .ok_or_else(|| format!("{} event in {room_id} had no body", content.msgtype))
    };
    let relay = |kind: InboundKind, text: String| IncomingContent::Relay(Inbound::new(kind, &text));
    Ok(match content.msgtype.as_str() {
        "m.text" => relay(InboundKind::Message, body(&content)?),
        "m.emote" => relay(InboundKind::Action, body(&content)?),
        "m.notice" => relay(InboundKind::Notice, body(&content)?),
        "m.image" | "m.file" | "m.audio" | "m.video" => {
            let text = body(&content)?;
            match content
                .url
                .as_deref()
                .and_then(|mxc| media_download_url(homeserver, mxc))
            {
                Some(link) => relay(InboundKind::Message, format!("{text} <{link}>")),
                None => IncomingContent::Unrelayed(content.msgtype),
            }
        }
        "m.location" => {
            let text = body(&content)?;
            match content
                .geo_uri
                .as_deref()
                .filter(|geo| geo.starts_with("geo:"))
            {
                Some(geo) => relay(InboundKind::Message, format!("{text} <{geo}>")),
                None => IncomingContent::Unrelayed(content.msgtype),
            }
        }
        _ => IncomingContent::Unrelayed(content.msgtype),
    })
}

fn collect_sync_messages(homeserver: &str, body: SyncResponse) -> Result<SyncBatch, String> {
    if body.next_batch.is_empty() {
        return Err("sync returned an empty next_batch".to_string());
    }
    let mut messages = Vec::new();
    let mut truncated = Vec::new();
    let mut encrypted = Vec::new();
    for (room_id, room) in body.rooms.join {
        if room.timeline.limited {
            truncated.push(room_id.clone());
        }
        for event in room.timeline.events {
            let (sender, content) = match event {
                TimelineEvent::Message { sender, content } => (sender, content),
                TimelineEvent::Encrypted | TimelineEvent::EncryptionEnabled => {
                    if !encrypted.contains(&room_id) {
                        encrypted.push(room_id.clone());
                    }
                    continue;
                }
                TimelineEvent::Other => continue,
            };
            let sender = sender
                .ok_or_else(|| format!("{} event in {room_id} had no sender", content.msgtype))?;
            messages.push(Incoming {
                room_id: room_id.clone(),
                sender,
                content: message_content(homeserver, &room_id, content)?,
            });
        }
    }
    Ok(SyncBatch {
        next: body.next_batch,
        messages,
        truncated,
        encrypted,
    })
}

/// Events per room in one incremental sync. A long poll is twenty seconds, so
/// this is a burst no conversation reaches; past it the gap is announced.
const SYNC_TIMELINE_LIMIT: u32 = 250;

/// The sync filter: only the bridged rooms, no presence, account data or
/// ephemeral events, members loaded lazily. Unfiltered, the first sync is the
/// whole account — every room with all its state — which on a populated account
/// is past [`super::MAX_BRIDGE_RESPONSE_BYTES`]: the bridge could never come
/// up, and downloaded it all again on every retry.
fn sync_filter(s: &Session, timeline_limit: u32) -> String {
    let mut rooms: Vec<&str> = s.rooms.room_to_channel.keys().map(String::as_str).collect();
    rooms.sort_unstable();
    let nothing = serde_json::json!({ "not_types": ["*"] });
    serde_json::json!({
        "presence": nothing,
        "account_data": nothing,
        "room": {
            "rooms": rooms,
            "account_data": nothing,
            "ephemeral": nothing,
            "state": { "lazy_load_members": true },
            "timeline": { "limit": timeline_limit, "lazy_load_members": true },
        },
    })
    .to_string()
}

async fn sync(s: &Session, since: Option<&str>) -> Result<SyncBatch, RequestError> {
    let (timeout, timeline_limit) = match since {
        Some(_) => (20000, SYNC_TIMELINE_LIMIT),
        None => (0, 1),
    };
    let mut req = s
        .http
        .get(&format!("{}/_matrix/client/v3/sync", s.base))?
        .bearer_auth(&s.token)
        .query(&[
            ("timeout", timeout.to_string()),
            ("filter", sync_filter(s, timeline_limit)),
        ]);
    if let Some(since) = since {
        req = req.query(&[("since", since)]);
    }
    let body: SyncResponse = send_authorized(req).await?.bounded_json().await?;
    Ok(collect_sync_messages(&s.base, body)?)
}

async fn handle_command(s: &mut Session, shared: &Shared, ends: &super::DriverEnds, line: &str) {
    let routed = super::route_privmsg(line, &s.rooms.channel_to_room);
    super::relay_routed(ends, routed, "Matrix", "room", |room_id, text| {
        // A retry after a rate limit takes a new transaction id: the
        // homeserver refused the first, so it stored nothing under it.
        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/send/m.room.message/{}",
            s.base,
            urlencode(&room_id),
            shared.transactions.next(),
        );
        let req = s.http.put(&url).map(|req| {
            req.bearer_auth(&s.token)
                .json(&MatrixMessageRequest::new(&text))
        });
        async move { super::bridge_send(req?).await.map(|_| ()) }
    })
    .await;
}

fn alias_to_channel(alias: &str) -> String {
    match alias.split_once(':') {
        Some((local, _)) => local.to_string(),
        None => alias.to_string(),
    }
}

fn matrix_localpart(sender: &str) -> &str {
    sender
        .strip_prefix('@')
        .and_then(|s| s.split_once(':').map(|(l, _)| l))
        .unwrap_or(sender)
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A homeserver small enough to read: it counts what a leaking driver
    /// multiplies (logins, joins), remembers what a careless one forgets
    /// (logouts), and records the sync it is asked for. Incremental syncs are
    /// answered from `sync_script` in order, and with a 502 once it is empty
    /// — which is what ends each session and forces the reconnects.
    #[derive(Clone, Default)]
    struct Homeserver(std::sync::Arc<std::sync::Mutex<HomeserverState>>);

    #[derive(Default)]
    struct HomeserverState {
        logins: usize,
        joins: usize,
        login_requests: Vec<serde_json::Value>,
        logged_out: Vec<String>,
        sync_queries: Vec<HashMap<String, String>>,
        sync_script: std::collections::VecDeque<(u16, serde_json::Value)>,
        /// The transaction id of every message sent, in order.
        sent_transactions: Vec<String>,
        /// The body of every message sent, in order.
        sent_messages: Vec<serde_json::Value>,
    }

    impl Homeserver {
        async fn start() -> (Self, String) {
            use axum::extract::{Path, Query, State};
            use axum::http::{HeaderMap, StatusCode};
            use axum::routing::{get, post, put};

            fn token(headers: &HeaderMap) -> String {
                headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.strip_prefix("Bearer "))
                    .unwrap_or_default()
                    .to_string()
            }
            let router = axum::Router::new()
                .route(
                    "/_matrix/client/v3/login",
                    post(|State(server): State<Homeserver>,
                          axum::Json(request): axum::Json<serde_json::Value>| async move {
                        let mut state = server.0.lock().unwrap();
                        state.logins += 1;
                        state.login_requests.push(request);
                        axum::Json(serde_json::json!({
                            "access_token": format!("token-{}", state.logins),
                            "user_id": "@bot:hs.example",
                        }))
                    }),
                )
                .route(
                    "/_matrix/client/v3/join/{alias}",
                    post(|State(server): State<Homeserver>, Path(alias): Path<String>| async move {
                        server.0.lock().unwrap().joins += 1;
                        if alias.starts_with("#forbidden") {
                            return (
                                StatusCode::FORBIDDEN,
                                axum::Json(serde_json::json!({ "errcode": "M_FORBIDDEN" })),
                            );
                        }
                        // `#name:server` is the room `!name:server`.
                        let room = format!("!{}", alias.trim_start_matches('#'));
                        (
                            StatusCode::OK,
                            axum::Json(serde_json::json!({ "room_id": room })),
                        )
                    }),
                )
                .route(
                    "/_matrix/client/v3/rooms/{room}/state/m.room.encryption",
                    get(|Path(room): Path<String>| async move {
                        if room.starts_with("!secret") {
                            return (
                                StatusCode::OK,
                                axum::Json(serde_json::json!({ "algorithm": "m.megolm.v1.aes-sha2" })),
                            );
                        }
                        (
                            StatusCode::NOT_FOUND,
                            axum::Json(serde_json::json!({ "errcode": "M_NOT_FOUND" })),
                        )
                    }),
                )
                .route(
                    "/_matrix/client/v3/sync",
                    get(
                        |State(server): State<Homeserver>,
                         Query(query): Query<HashMap<String, String>>| async move {
                            let incremental = query.contains_key("since");
                            let mut state = server.0.lock().unwrap();
                            state.sync_queries.push(query);
                            if !incremental {
                                return (
                                    StatusCode::OK,
                                    axum::Json(serde_json::json!({ "next_batch": "s1" })),
                                );
                            }
                            let (status, body) = state
                                .sync_script
                                .pop_front()
                                .unwrap_or((502, serde_json::json!({})));
                            (StatusCode::from_u16(status).unwrap(), axum::Json(body))
                        },
                    ),
                )
                .route(
                    "/_matrix/client/v3/logout",
                    post(
                        |State(server): State<Homeserver>, headers: HeaderMap| async move {
                            server.0.lock().unwrap().logged_out.push(token(&headers));
                            axum::Json(serde_json::json!({}))
                        },
                    ),
                )
                .route(
                    "/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}",
                    put(
                        |State(server): State<Homeserver>,
                         Path((_room, txn)): Path<(String, String)>,
                         axum::Json(body): axum::Json<serde_json::Value>| async move {
                            let mut state = server.0.lock().unwrap();
                            state.sent_transactions.push(txn);
                            state.sent_messages.push(body);
                            axum::Json(serde_json::json!({ "event_id": "$event:hs.example" }))
                        },
                    ),
                );
            let server = Self::default();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let app = router.with_state(server.clone());
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            (server, base)
        }

        fn script(&self, answers: impl IntoIterator<Item = (u16, serde_json::Value)>) {
            self.0.lock().unwrap().sync_script.extend(answers);
        }

        fn since_values(&self) -> Vec<Option<String>> {
            self.0
                .lock()
                .unwrap()
                .sync_queries
                .iter()
                .map(|query| query.get("since").cloned())
                .collect()
        }
    }

    /// A sync answer with `events` in the timeline of `!room:hs.example`.
    fn timeline(next_batch: &str, events: serde_json::Value) -> (u16, serde_json::Value) {
        (
            200,
            serde_json::json!({
                "next_batch": next_batch,
                "rooms": { "join": { "!room:hs.example": { "timeline": { "events": events } } } },
            }),
        )
    }

    fn lines(
        events: &mut tokio::sync::broadcast::Receiver<crate::bouncer::DriverEvent>,
    ) -> Vec<String> {
        let mut lines = Vec::new();
        while let Ok(event) = events.try_recv() {
            if let crate::bouncer::DriverEvent::Line(line) = event {
                lines.push(line.line);
            }
        }
        lines
    }

    /// The sync position belongs to the driver like its login: a session
    /// that started over from a fresh initial sync — which only establishes
    /// a position — silently skipped everything said during the outage.
    #[tokio::test]
    async fn the_next_session_resumes_the_sync_position_instead_of_starting_over() {
        let (server, base) = Homeserver::start().await;
        let shared = Shared::new(config(&base, &["#room:hs.example"]));
        let (_handle, mut ends) = NetworkHandle::channels(8);
        session_once(&shared, &mut ends).await;
        server.script([timeline(
            "s2",
            serde_json::json!([{ "type": "m.room.message", "sender": "@alice:hs.example",
                                 "content": { "msgtype": "m.text", "body": "said during the outage" } }]),
        )]);
        let (handle, mut ends) = NetworkHandle::channels(8);
        let mut events = handle.subscribe();
        session_once(&shared, &mut ends).await;
        assert_eq!(
            server.since_values(),
            [
                None,
                Some("s1".into()),
                Some("s1".into()),
                Some("s2".into())
            ],
            "the second session did not continue from the first one's position"
        );
        assert_eq!(
            server.0.lock().unwrap().joins,
            1,
            "the second session joined again"
        );
        assert!(
            lines(&mut events)
                .iter()
                .any(|line| line == ":alice!alice@matrix PRIVMSG #room :said during the outage"),
        );
    }

    /// A 429 on `/sync` is a pause, not a lost session: the driver waits what
    /// the homeserver asks and asks again from the same position. Ending the
    /// session re-did every join a moment later — the writes being limited.
    #[tokio::test]
    async fn a_rate_limited_sync_waits_and_asks_again_from_the_same_position() {
        let (server, base) = Homeserver::start().await;
        server.script([
            (429, serde_json::json!({ "errcode": "M_LIMIT_EXCEEDED", "retry_after_ms": 100 })),
            timeline(
                "s2",
                serde_json::json!([{ "type": "m.room.message", "sender": "@alice:hs.example",
                                     "content": { "msgtype": "m.text", "body": "after the limit" } }]),
            ),
        ]);
        let shared = Shared::new(config(&base, &["#room:hs.example"]));
        let (handle, mut ends) = NetworkHandle::channels(8);
        let mut events = handle.subscribe();
        session_once(&shared, &mut ends).await;
        assert_eq!(
            server.since_values(),
            [
                None,
                Some("s1".into()),
                Some("s1".into()),
                Some("s2".into())
            ]
        );
        assert_eq!(server.0.lock().unwrap().joins, 1);
        assert!(
            lines(&mut events)
                .iter()
                .any(|line| line.ends_with(":after the limit"))
        );
    }

    /// The bridge holds no device keys, so an encrypted room is unreadable:
    /// said as a refusal naming the room, not a bridge that relays nothing.
    #[tokio::test]
    async fn an_encrypted_room_is_a_configuration_refusal() {
        use crate::bouncer::{NetworkFailure, SessionOutcome};
        let (_server, base) = Homeserver::start().await;
        let shared = Shared::new(config(&base, &["#secret:hs.example"]));
        let (_handle, mut ends) = NetworkHandle::channels(8);
        let SessionOutcome::ConfigurationRejected(refusal) = session_once(&shared, &mut ends).await
        else {
            panic!("an encrypted room was not refused");
        };
        assert_eq!(refusal.failure(), NetworkFailure::RoomEncrypted);
        assert!(
            refusal.diagnostic().contains("#secret:hs.example")
                && refusal.diagnostic().contains("end-to-end encrypted"),
            "{refusal:?}"
        );
    }

    /// A room that turns encryption on mid-session is said in the channel and
    /// refused the same way.
    #[tokio::test]
    async fn encryption_switched_on_mid_session_is_said_and_refused() {
        use crate::bouncer::{NetworkFailure, SessionOutcome};
        let (server, base) = Homeserver::start().await;
        server.script([timeline(
            "s2",
            serde_json::json!([{ "type": "m.room.encrypted", "sender": "@alice:hs.example",
                                 "content": { "algorithm": "m.megolm.v1.aes-sha2", "ciphertext": "x" } }]),
        )]);
        let shared = Shared::new(config(&base, &["#room:hs.example"]));
        let (handle, mut ends) = NetworkHandle::channels(8);
        let mut events = handle.subscribe();
        let SessionOutcome::ConfigurationRejected(refusal) = session_once(&shared, &mut ends).await
        else {
            panic!("an encrypted event did not refuse the room");
        };
        assert_eq!(refusal.failure(), NetworkFailure::RoomEncrypted);
        let notices: Vec<_> = lines(&mut events)
            .into_iter()
            .filter(|line| line.starts_with(":*bnc* NOTICE #room :") && line.contains("encrypted"))
            .collect();
        assert_eq!(notices.len(), 1, "{notices:?}");
    }

    /// An IRC `/me` is an `m.emote`, and IRC formatting stays behind.
    #[tokio::test]
    async fn an_action_is_sent_as_an_emote_without_irc_formatting() {
        let (server, base) = Homeserver::start().await;
        let shared = Shared::new(config(&base, &["#room:hs.example"]));
        let (_handle, ends) = NetworkHandle::channels(8);
        let mut session = connect(&shared).await.unwrap_or_else(|_| panic!("connect"));
        for line in [
            "PRIVMSG #room :\u{1}ACTION waves\u{1}",
            "PRIVMSG #room :\u{2}bold\u{2}",
        ] {
            handle_command(&mut session, &shared, &ends, line).await;
        }
        assert_eq!(
            server.0.lock().unwrap().sent_messages,
            [
                serde_json::json!({ "msgtype": "m.emote", "body": "waves" }),
                serde_json::json!({ "msgtype": "m.text", "body": "bold" }),
            ]
        );
    }

    fn config(homeserver: &str, rooms: &[&str]) -> MatrixConfig {
        MatrixConfig {
            device: MatrixDevice::for_network(Some("alice"), "work-chat"),
            homeserver: homeserver.into(),
            user: "bot".into(),
            password: "secret".into(),
            rooms: rooms.iter().map(ToString::to_string).collect(),
            internal_upstreams: crate::egress::InternalUpstreams::Allow,
            buffer_cap: 8,
        }
    }

    /// Not invited, an alias that is not a safe channel name, two aliases that
    /// fold to one channel: none of these is fixed by trying again.
    #[tokio::test]
    async fn what_the_configuration_asks_for_and_cannot_have_is_a_refusal_not_a_retry() {
        use crate::bouncer::{NetworkFailure, SessionOutcome};

        let (_server, base) = Homeserver::start().await;
        for (rooms, failure, named) in [
            (
                &["#forbidden:hs.example"][..],
                NetworkFailure::ChannelJoinRefused,
                "#forbidden:hs.example",
            ),
            (
                &["#bad name:hs.example"][..],
                NetworkFailure::ChannelMappingFailed,
                "#bad name:hs.example",
            ),
            (
                &["#Room:hs.example", "#room:other.example"][..],
                NetworkFailure::ChannelMappingFailed,
                "#room",
            ),
        ] {
            let shared = Shared::new(config(&base, rooms));
            let (_handle, mut ends) = NetworkHandle::channels(8);
            let SessionOutcome::ConfigurationRejected(refusal) =
                session_once(&shared, &mut ends).await
            else {
                panic!("{rooms:?} was not read as a configuration refusal");
            };
            assert_eq!(refusal.failure(), failure, "{rooms:?}");
            assert!(refusal.diagnostic().contains(named), "{refusal:?}");
        }
    }

    /// Every password login is a new device on the homeserver. A driver that
    /// logged in again on each reconnect, and never logged out, left one behind
    /// every few seconds for as long as its upstream was unhappy.
    #[tokio::test(flavor = "multi_thread")]
    async fn reconnects_reuse_one_login_and_stopping_logs_it_out() {
        let (server, base) = Homeserver::start().await;
        let handle = Box::new(MatrixDriver::new(config(&base, &["#room:hs.example"]))).start();
        let sessions = |server: &Homeserver| {
            let state = server.0.lock().unwrap();
            // Each session's one incremental sync is refused, which ends it.
            state
                .sync_queries
                .iter()
                .filter(|query| query.contains_key("since"))
                .count()
        };
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            while sessions(&server) < 3 {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the driver never reconnected");
        assert_eq!(
            server.0.lock().unwrap().logins,
            1,
            "each reconnect logged in again, leaving a device behind"
        );

        handle.shutdown();
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while server.0.lock().unwrap().logged_out.is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the stopped driver never logged its device out");
        assert_eq!(server.0.lock().unwrap().logged_out, ["token-1"]);
    }

    /// Logging out needs the process to be alive to do it. One that crashed, or
    /// was killed, left its device behind and made another on the next start.
    /// A login that names the same device every time has nothing to leak: the
    /// homeserver re-uses it.
    #[tokio::test(flavor = "multi_thread")]
    async fn every_lifetime_of_one_network_presents_the_same_device() {
        let (server, base) = Homeserver::start().await;
        for lifetime in 1..=2 {
            let handle = Box::new(MatrixDriver::new(config(&base, &["#room:hs.example"]))).start();
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                while server.0.lock().unwrap().logins < lifetime {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("the driver never logged in");
            handle.shutdown_and_wait().await;
        }
        let requests = server.0.lock().unwrap().login_requests.clone();
        assert_eq!(requests.len(), 2);
        for request in &requests {
            assert_eq!(request["device_id"], "e6irc/alice/work-chat", "{request}");
            assert_eq!(
                request["initial_device_display_name"],
                "e6irc bouncer (work-chat)"
            );
        }
        // A network nobody owns is still one device, and not any account's.
        assert_eq!(MatrixDevice::for_network(None, "lobby").id, "e6irc/*/lobby");
    }

    /// A transaction id tells the homeserver "the same message again" — it
    /// answers a repeat with the first event's id and stores nothing. The login
    /// (and its token, which scopes the ids) outlives sessions, so a counter
    /// that restarted with each session made a reconnected driver's first
    /// messages repeats of the previous session's: accepted, and never posted.
    #[tokio::test]
    async fn no_two_sessions_of_one_driver_reuse_a_transaction_id() {
        let (server, base) = Homeserver::start().await;
        let shared = Shared::new(config(&base, &["#room:hs.example"]));
        let (_handle, ends) = NetworkHandle::channels(8);
        for text in ["one", "two"] {
            let mut session = connect(&shared).await.unwrap_or_else(|_| panic!("connect"));
            handle_command(
                &mut session,
                &shared,
                &ends,
                &format!("PRIVMSG #room :{text}"),
            )
            .await;
        }
        let sent = server.0.lock().unwrap().sent_transactions.clone();
        assert_eq!(sent.len(), 2, "{sent:?}");
        assert_ne!(
            sent[0], sent[1],
            "the second session repeated the first's id"
        );
    }

    /// `2130706433` is 127.0.0.1 to the URL parser and to the kernel, but not to
    /// `IpAddr::from_str`, and an IP-literal host never reaches the vetting
    /// resolver. The request itself has to be judged: under the default policy
    /// no socket is opened; under the operator's allowance the login proceeds.
    #[tokio::test]
    async fn a_homeserver_named_by_a_disguised_loopback_literal_is_refused_before_any_socket_opens()
    {
        use crate::egress::InternalUpstreams;
        let (server, base) = Homeserver::start().await;
        let port = url::Url::parse(&base).unwrap().port().unwrap();
        let disguised = format!("http://2130706433:{port}");
        for (policy, logins) in [
            (InternalUpstreams::Refuse, 0),
            (InternalUpstreams::Allow, 1),
        ] {
            let mut config = config(&disguised, &["#room:hs.example"]);
            config.internal_upstreams = policy;
            let shared = Shared::new(config);
            let (_handle, mut ends) = NetworkHandle::channels(8);
            session_once(&shared, &mut ends).await;
            assert_eq!(server.0.lock().unwrap().logins, logins, "under {policy:?}");
        }
    }

    /// An unfiltered initial sync is the whole account: every room, all state,
    /// presence, account data. On a populated account that is past the response
    /// cap, so the bridge could never come up — and downloaded it again on
    /// every retry.
    #[tokio::test]
    async fn the_sync_asks_only_for_the_bridged_rooms() {
        let (server, base) = Homeserver::start().await;
        let shared = Shared::new(config(&base, &["#room:hs.example"]));
        let (_handle, mut ends) = NetworkHandle::channels(8);
        // The fake fails the first incremental sync, which ends the session.
        session_once(&shared, &mut ends).await;
        let queries = server.0.lock().unwrap().sync_queries.clone();
        assert_eq!(queries.len(), 2, "{queries:?}");
        for query in &queries {
            let filter: serde_json::Value =
                serde_json::from_str(query.get("filter").expect("every sync carries the filter"))
                    .expect("the filter is JSON");
            assert_eq!(
                filter["room"]["rooms"],
                serde_json::json!(["!room:hs.example"])
            );
            assert_eq!(filter["room"]["state"]["lazy_load_members"], true);
            for excluded in [
                &filter["presence"],
                &filter["account_data"],
                &filter["room"]["account_data"],
                &filter["room"]["ephemeral"],
            ] {
                assert_eq!(excluded["not_types"], serde_json::json!(["*"]), "{filter}");
            }
            assert!(filter["room"]["timeline"]["limit"].as_u64().is_some());
        }
        // The first sync only establishes a position; its timeline is discarded.
        let initial: serde_json::Value = serde_json::from_str(&queries[0]["filter"]).unwrap();
        assert_eq!(initial["room"]["timeline"]["limit"], 1);
    }

    #[test]
    fn maps_alias_and_sender() {
        assert_eq!(alias_to_channel("#room:localhost"), "#room");
        assert_eq!(alias_to_channel("#plain"), "#plain");
        assert_eq!(matrix_localpart("@alice:localhost"), "alice");
        assert_eq!(matrix_localpart("plain"), "plain");
        assert_eq!(
            super::super::render_bridged(
                "matrix",
                matrix_localpart("@alice:localhost"),
                "#room",
                &super::super::Inbound::new(super::super::InboundKind::Message, "hi there")
            ),
            vec![":alice!alice@matrix PRIVMSG #room :hi there"]
        );
    }

    #[test]
    fn urlencodes_room_ids() {
        assert_eq!(urlencode("!abc:localhost"), "%21abc%3Alocalhost");
        assert_eq!(urlencode("#room:localhost"), "%23room%3Alocalhost");
    }

    #[test]
    fn hostile_sender_cannot_forge_a_prefix() {
        // A malicious homeserver sets the sender to smuggle a space and IRC
        // metacharacters into the source-prefix position; the nick token must
        // neutralize them so no second source/command is forged.
        let lines = super::super::render_bridged(
            "matrix",
            matrix_localpart("@evil x!y@z NOTICE victim :hi:localhost"),
            "#room",
            &super::super::Inbound::new(super::super::InboundKind::Message, "body"),
        );
        assert_eq!(lines.len(), 1);
        let line = &lines[0];
        let prefix = line
            .strip_prefix(':')
            .and_then(|l| l.split(' ').next())
            .expect("prefix");
        assert!(
            !prefix.contains(' '),
            "prefix must be a single token: {line}"
        );
        assert!(
            !prefix.contains('!') || prefix.matches('!').count() == 1,
            "only the driver's own !user@host separator: {line}"
        );
        // The command/target the driver intends is preserved.
        assert!(line.contains("PRIVMSG #room :body"), "{line}");
    }

    fn relayed_lines(batch: SyncBatch) -> Vec<String> {
        batch
            .messages
            .into_iter()
            .flat_map(|m| match m.content {
                IncomingContent::Relay(message) => super::super::render_bridged(
                    "matrix",
                    matrix_localpart(&m.sender),
                    "#room",
                    &message,
                ),
                IncomingContent::Unrelayed(msgtype) => vec![super::super::unrelayed_notice(
                    "matrix",
                    "#room",
                    &msgtype,
                    matrix_localpart(&m.sender),
                )],
            })
            .collect()
    }

    #[test]
    fn sync_parser_renders_every_msgtype_and_rejects_malformed_messages() {
        let response: SyncResponse = serde_json::from_str(
            r#"{"next_batch":"s1","rooms":{"join":{"!room:example":{"timeline":{"events":[
                {"type":"m.reaction","sender":"@bob:example","content":{}},
                {"type":"m.room.message","sender":"@alice:example",
                 "content":{"msgtype":"m.text","body":"hello"}},
                {"type":"m.room.message","sender":"@alice:example",
                 "content":{"msgtype":"m.emote","body":"waves"}},
                {"type":"m.room.message","sender":"@bot:example",
                 "content":{"msgtype":"m.notice","body":"build passed"}},
                {"type":"m.room.message","sender":"@alice:example",
                 "content":{"msgtype":"m.image","body":"cat.png","url":"mxc://example.org/AbC_12-x"}},
                {"type":"m.room.message","sender":"@alice:example",
                 "content":{"msgtype":"m.file","body":"notes.txt","url":"mxc://example.org/f1"}},
                {"type":"m.room.message","sender":"@alice:example",
                 "content":{"msgtype":"m.audio","body":"song.ogg","url":"mxc://example.org/a1"}},
                {"type":"m.room.message","sender":"@alice:example",
                 "content":{"msgtype":"m.video","body":"clip.mp4","url":"mxc://example.org/v1"}},
                {"type":"m.room.message","sender":"@alice:example",
                 "content":{"msgtype":"m.location","body":"the pub","geo_uri":"geo:51.5,-0.1"}},
                {"type":"m.room.message","sender":"@alice:example",
                 "content":{"msgtype":"m.image","body":"evil","url":"mxc://example.org/../../x"}},
                {"type":"m.room.message","sender":"@alice:example",
                 "content":{"msgtype":"m.key.verification.request","body":"verify?"}},
                {"type":"m.room.message","sender":"@alice:example",
                 "content":{"msgtype":"m.text","body":"\u0001VERSION\u0001"}}
            ]}}}}}"#,
        )
        .expect("sync response");
        let batch = collect_sync_messages("https://hs.example", response).expect("valid sync");
        assert_eq!(batch.next, "s1");
        assert!(batch.truncated.is_empty() && batch.encrypted.is_empty());
        assert_eq!(
            relayed_lines(batch),
            [
                ":alice!alice@matrix PRIVMSG #room :hello",
                ":alice!alice@matrix PRIVMSG #room :\u{1}ACTION waves\u{1}",
                ":bot!bot@matrix NOTICE #room :build passed",
                ":alice!alice@matrix PRIVMSG #room :cat.png \
                 <https://hs.example/_matrix/media/v3/download/example.org/AbC_12-x>",
                ":alice!alice@matrix PRIVMSG #room :notes.txt \
                 <https://hs.example/_matrix/media/v3/download/example.org/f1>",
                ":alice!alice@matrix PRIVMSG #room :song.ogg \
                 <https://hs.example/_matrix/media/v3/download/example.org/a1>",
                ":alice!alice@matrix PRIVMSG #room :clip.mp4 \
                 <https://hs.example/_matrix/media/v3/download/example.org/v1>",
                ":alice!alice@matrix PRIVMSG #room :the pub <geo:51.5,-0.1>",
                ":*bnc* NOTICE #room :matrix: a m.image message from alice was not relayed",
                ":*bnc* NOTICE #room :matrix: a m.key.verification.request message from alice \
                 was not relayed",
                ":alice!alice@matrix PRIVMSG #room :VERSION",
            ]
        );

        // A room with nothing new has no timeline under a filter, and a
        // timeline the homeserver cut short says so.
        let quiet: SyncResponse = serde_json::from_str(
            r#"{"next_batch":"s3","rooms":{"join":{
                "!quiet:example":{},
                "!busy:example":{"timeline":{"limited":true,"events":[]}},
                "!secret:example":{"timeline":{"events":[
                    {"type":"m.room.encrypted","sender":"@a:example","content":{}}]}}}}}"#,
        )
        .expect("filtered sync response");
        let batch = collect_sync_messages("https://hs.example", quiet).expect("valid sync");
        assert_eq!(batch.truncated, ["!busy:example"]);
        assert_eq!(batch.encrypted, ["!secret:example"]);

        for malformed in [
            r#"{"next_batch":"s2","rooms":{"join":{"!room:example":{"timeline":{"events":[
                {"type":"m.room.message","content":{"msgtype":"m.text","body":"hello"}}
            ]}}}}}"#,
            r#"{"next_batch":"s2","rooms":{"join":{"!room:example":{"timeline":{"events":[
                {"type":"m.room.message","sender":"@alice:example",
                 "content":{"msgtype":"m.text"}}
            ]}}}}}"#,
            r#"{"next_batch":"s2","rooms":{"join":{"!room:example":{"timeline":{"events":[
                {"type":"m.room.message","sender":"@alice:example",
                 "content":{"msgtype":"m.emote"}}
            ]}}}}}"#,
        ] {
            let response: SyncResponse =
                serde_json::from_str(malformed).expect("outer sync response");
            assert!(collect_sync_messages("https://hs.example", response).is_err());
        }
    }
}
