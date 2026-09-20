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
    /// Homeserver base URL, e.g. `http://127.0.0.1:16167`.
    pub homeserver: String,
    /// Login username (localpart).
    pub user: String,
    pub password: String,
    /// Room aliases to join and bridge (e.g. `#room:server`).
    pub rooms: Vec<String>,
    pub buffer_cap: usize,
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
    http: reqwest::Client,
    base: String,
    token: String,
    user_id: String,
    channel_to_room: HashMap<String, String>,
    room_to_channel: HashMap<String, String>,
    txn: u64,
}

/// One password login: the access token and who it belongs to.
#[derive(Clone)]
struct Login {
    http: reqwest::Client,
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
}

impl Shared {
    fn new(config: MatrixConfig) -> Self {
        Self {
            config,
            login: tokio::sync::Mutex::new(None),
        }
    }

    async fn login(&self) -> Result<Login, super::ConnectFail> {
        let mut cached = self.login.lock().await;
        if let Some(login) = cached.as_ref() {
            return Ok(login.clone());
        }
        let http = super::bridge_http_client(std::time::Duration::from_secs(60))
            .map_err(|e| e.to_string())?;
        let response: LoginResponse = super::bridge_send_credentials(
            http.post(format!("{}/_matrix/client/v3/login", self.base()))
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
    }

    /// Remove this driver's device. Bounded, and a failure is only logged (the
    /// driver is stopping either way); the token itself is never printed.
    async fn logout(&self) {
        let Some(login) = self.login.lock().await.take() else {
            return;
        };
        let request = login
            .http
            .post(format!("{}/_matrix/client/v3/logout", self.base()))
            .bearer_auth(&login.access_token)
            .json(&EmptyObject {});
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

async fn session_once(shared: &Shared, ends: &mut DriverEnds) -> super::SessionOutcome {
    use super::SessionOutcome::Dropped;
    let mut session = match connect(shared).await {
        Ok(s) => s,
        Err(e) => return e.into_outcome("matrix"),
    };
    ends.emit(ConnectionEvent::Connected);

    // The first sync only establishes a position: its timeline is discarded.
    let mut since = match sync(&session, None).await {
        Ok(batch) => batch.next,
        Err(error) => return sync_failed(shared, "initial sync", error).await,
    };

    loop {
        tokio::select! {
            result = sync(&session, Some(&since)) => match result {
                Ok(batch) => {
                    since = batch.next;
                    for room_id in batch.truncated {
                        // The homeserver had more than one sync carries and
                        // sent only the newest. The gap is said, not hidden.
                        if let Some(channel) = session.room_to_channel.get(&room_id) {
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
                        if let Some(channel) = session.room_to_channel.get(&m.room_id) {
                            for line in super::render_bridged_privmsg(
                                "matrix",
                                matrix_localpart(&m.sender),
                                channel,
                                &m.body,
                            ) {
                                ends.emit_line(line);
                            }
                        }
                    }
                }
                Err(error) => return sync_failed(shared, "sync", error).await,
            },
            cmd = ends.next_command() => match cmd {
                Some(cmd) => handle_command(&mut session, ends, &cmd.line).await,
                None => return super::SessionOutcome::Stopped, // every handle dropped
            },
        }
    }

    async fn sync_failed(
        shared: &Shared,
        what: &str,
        error: RequestError,
    ) -> super::SessionOutcome {
        if matches!(error, RequestError::TokenRejected) {
            shared.forget_login().await;
        }
        eprintln!("matrix: {what} failed: {error}");
        Dropped(super::NetworkFailure::UpstreamRequestFailed)
    }
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
    Other(String),
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TokenRejected => f.write_str("the homeserver rejected the access token"),
            Self::Forbidden => f.write_str("the homeserver forbade the request"),
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
    match response.status() {
        reqwest::StatusCode::UNAUTHORIZED => Err(RequestError::TokenRejected),
        reqwest::StatusCode::FORBIDDEN => Err(RequestError::Forbidden),
        _ => Ok(response.error_for_status().map_err(|e| e.to_string())?),
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
        channel_to_room: HashMap::new(),
        room_to_channel: HashMap::new(),
        txn: 0,
    };
    let unmappable = |detail: String| {
        ConnectFail::Configuration(ConfigurationRefusal::new(
            NetworkFailure::ChannelMappingFailed,
            &detail,
        ))
    };
    for alias in &config.rooms {
        let channel = alias_to_channel(alias);
        if !crate::sanitize::valid_channel_name(&channel) {
            return Err(unmappable(format!(
                "room alias {alias} maps to an unsafe IRC channel name"
            )));
        }
        let folded = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(&channel);
        if session.channel_to_room.contains_key(&folded) {
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
            Err(RequestError::TokenRejected) => {
                shared.forget_login().await;
                return Err(ConnectFail::Transient(format!(
                    "join {alias}: {}",
                    RequestError::TokenRejected
                )));
            }
            Err(RequestError::Other(detail)) => return Err(ConnectFail::Transient(detail)),
        };
        session.channel_to_room.insert(folded, room_id.clone());
        session.room_to_channel.insert(room_id, channel);
    }
    Ok(session)
}

async fn join_room(s: &Session, alias: &str) -> Result<String, RequestError> {
    let encoded = urlencode(alias);
    let response: JoinResponse = send_authorized(
        s.http
            .post(format!("{}/_matrix/client/v3/join/{encoded}", s.base))
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
    fn text(body: &'a str) -> Self {
        Self {
            msgtype: "m.text",
            body,
        }
    }
}

struct Incoming {
    room_id: String,
    sender: String,
    body: String,
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
    #[serde(other)]
    Other,
}

#[derive(serde::Deserialize)]
struct MessageContent {
    msgtype: MatrixMessageType,
    #[serde(default)]
    body: Option<String>,
}

#[derive(serde::Deserialize)]
enum MatrixMessageType {
    #[serde(rename = "m.text")]
    Text,
    #[serde(other)]
    Other,
}

/// One sync's worth: where to continue from, the text messages, and the rooms
/// whose timeline the homeserver cut short.
struct SyncBatch {
    next: String,
    messages: Vec<Incoming>,
    truncated: Vec<String>,
}

fn collect_sync_messages(body: SyncResponse) -> Result<SyncBatch, String> {
    if body.next_batch.is_empty() {
        return Err("sync returned an empty next_batch".to_string());
    }
    let mut messages = Vec::new();
    let mut truncated = Vec::new();
    for (room_id, room) in body.rooms.join {
        if room.timeline.limited {
            truncated.push(room_id.clone());
        }
        for event in room.timeline.events {
            let TimelineEvent::Message { sender, content } = event else {
                continue;
            };
            if !matches!(content.msgtype, MatrixMessageType::Text) {
                continue;
            }
            messages.push(Incoming {
                room_id: room_id.clone(),
                sender: sender.ok_or_else(|| format!("m.text event in {room_id} had no sender"))?,
                body: content
                    .body
                    .ok_or_else(|| format!("m.text event in {room_id} had no body"))?,
            });
        }
    }
    Ok(SyncBatch {
        next: body.next_batch,
        messages,
        truncated,
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
    let mut rooms: Vec<&str> = s.room_to_channel.keys().map(String::as_str).collect();
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
        .get(format!("{}/_matrix/client/v3/sync", s.base))
        .bearer_auth(&s.token)
        .query(&[
            ("timeout", timeout.to_string()),
            ("filter", sync_filter(s, timeline_limit)),
        ]);
    if let Some(since) = since {
        req = req.query(&[("since", since)]);
    }
    let body: SyncResponse = send_authorized(req).await?.bounded_json().await?;
    Ok(collect_sync_messages(body)?)
}

async fn handle_command(s: &mut Session, ends: &super::DriverEnds, line: &str) {
    let routed = super::route_privmsg(line, &s.channel_to_room);
    super::relay_routed(ends, routed, "Matrix", "room", |room_id, text| {
        s.txn += 1;
        let txn = s.txn;
        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/send/m.room.message/e6{txn}",
            s.base,
            urlencode(&room_id),
        );
        let req = s
            .http
            .put(url)
            .bearer_auth(&s.token)
            .json(&MatrixMessageRequest::text(&text));
        async move { super::bridge_send(req).await.map(|_| ()) }
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
    /// multiplies (logins), remembers what a careless one forgets (logouts), and
    /// records the sync it is asked for.
    #[derive(Clone, Default)]
    struct Homeserver(std::sync::Arc<std::sync::Mutex<HomeserverState>>);

    #[derive(Default)]
    struct HomeserverState {
        logins: usize,
        login_requests: Vec<serde_json::Value>,
        logged_out: Vec<String>,
        sync_queries: Vec<HashMap<String, String>>,
    }

    impl Homeserver {
        async fn start() -> (Self, String) {
            use axum::extract::{Path, Query, State};
            use axum::http::{HeaderMap, StatusCode};
            use axum::routing::{get, post};

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
                    post(|Path(alias): Path<String>| async move {
                        if alias.starts_with("#forbidden") {
                            return (
                                StatusCode::FORBIDDEN,
                                axum::Json(serde_json::json!({ "errcode": "M_FORBIDDEN" })),
                            );
                        }
                        (
                            StatusCode::OK,
                            axum::Json(serde_json::json!({ "room_id": "!room:hs.example" })),
                        )
                    }),
                )
                .route(
                    "/_matrix/client/v3/sync",
                    get(
                        |State(server): State<Homeserver>,
                         Query(query): Query<HashMap<String, String>>| async move {
                            let incremental = query.contains_key("since");
                            server.0.lock().unwrap().sync_queries.push(query);
                            if incremental {
                                // Every session is cut short after its first
                                // sync, which is what forces the reconnects.
                                return (
                                    StatusCode::BAD_GATEWAY,
                                    axum::Json(serde_json::json!({})),
                                );
                            }
                            (
                                StatusCode::OK,
                                axum::Json(serde_json::json!({ "next_batch": "s1" })),
                            )
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
                );
            let server = Self::default();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let app = router.with_state(server.clone());
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            (server, base)
        }
    }

    fn config(homeserver: &str, rooms: &[&str]) -> MatrixConfig {
        MatrixConfig {
            device: MatrixDevice::for_network(Some("alice"), "work-chat"),
            homeserver: homeserver.into(),
            user: "bot".into(),
            password: "secret".into(),
            rooms: rooms.iter().map(ToString::to_string).collect(),
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
            state
                .sync_queries
                .iter()
                .filter(|query| !query.contains_key("since"))
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
            super::super::render_bridged_privmsg(
                "matrix",
                matrix_localpart("@alice:localhost"),
                "#room",
                "hi there"
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
        let lines = super::super::render_bridged_privmsg(
            "matrix",
            matrix_localpart("@evil x!y@z NOTICE victim :hi:localhost"),
            "#room",
            "body",
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

    #[test]
    fn sync_parser_keeps_unknown_events_but_rejects_malformed_text_messages() {
        let response: SyncResponse = serde_json::from_str(
            r#"{"next_batch":"s1","rooms":{"join":{"!room:example":{"timeline":{"events":[
                {"type":"m.reaction","sender":"@bob:example","content":{}},
                {"type":"m.room.message","sender":"@alice:example",
                 "content":{"msgtype":"m.text","body":"hello"}}
            ]}}}}}"#,
        )
        .expect("sync response");
        let SyncBatch {
            next,
            messages,
            truncated,
        } = collect_sync_messages(response).expect("valid sync");
        assert_eq!(next, "s1");
        assert!(truncated.is_empty());
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].sender, "@alice:example");
        assert_eq!(messages[0].body, "hello");

        // A room with nothing new has no timeline under a filter, and a
        // timeline the homeserver cut short says so.
        let quiet: SyncResponse = serde_json::from_str(
            r#"{"next_batch":"s3","rooms":{"join":{
                "!quiet:example":{},
                "!busy:example":{"timeline":{"limited":true,"events":[]}}}}}"#,
        )
        .expect("filtered sync response");
        let batch = collect_sync_messages(quiet).expect("valid sync");
        assert_eq!(batch.truncated, ["!busy:example"]);

        for malformed in [
            r#"{"next_batch":"s2","rooms":{"join":{"!room:example":{"timeline":{"events":[
                {"type":"m.room.message","content":{"msgtype":"m.text","body":"hello"}}
            ]}}}}}"#,
            r#"{"next_batch":"s2","rooms":{"join":{"!room:example":{"timeline":{"events":[
                {"type":"m.room.message","sender":"@alice:example",
                 "content":{"msgtype":"m.text"}}
            ]}}}}}"#,
        ] {
            let response: SyncResponse =
                serde_json::from_str(malformed).expect("outer sync response");
            assert!(collect_sync_messages(response).is_err());
        }
    }
}
