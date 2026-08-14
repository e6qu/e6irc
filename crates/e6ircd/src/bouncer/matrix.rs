//! Matrix client-server bridge.

use super::BoundedJson;
use std::collections::HashMap;

use serde::Serialize;

use super::{ConnectionEvent, DriverEnds, NetworkDriver, NetworkHandle};

#[derive(Debug, Clone)]
pub struct MatrixConfig {
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

super::bridge_run!(MatrixConfig);

async fn session_once(config: &MatrixConfig, ends: &mut DriverEnds) -> super::SessionOutcome {
    let mut session = match connect(config).await {
        Ok(s) => s,
        Err(e) => return e.into_outcome("matrix"),
    };
    ends.emit(ConnectionEvent::Connected);

    let mut since = match sync(&session, None).await {
        Ok((next, _)) => next,
        Err(e) => {
            eprintln!("matrix: initial sync failed: {e}");
            return super::SessionOutcome::Dropped(super::NetworkFailure::UpstreamRequestFailed);
        }
    };

    loop {
        tokio::select! {
            result = sync(&session, Some(&since)) => match result {
                Ok((next, messages)) => {
                    since = next;
                    for m in messages {
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
                Err(e) => {
                    eprintln!("matrix: sync error: {e}");
                    return super::SessionOutcome::Dropped(
                        super::NetworkFailure::UpstreamRequestFailed,
                    );
                }
            },
            cmd = ends.next_command() => match cmd {
                Some(cmd) => handle_command(&mut session, ends, &cmd.line).await,
                None => return super::SessionOutcome::Stopped, // every handle dropped
            },
        }
    }
}

async fn connect(config: &MatrixConfig) -> Result<Session, super::ConnectFail> {
    let http =
        super::bridge_http_client(std::time::Duration::from_secs(60)).map_err(|e| e.to_string())?;
    let base = config.homeserver.trim_end_matches('/').to_string();

    let resp = http
        .post(format!("{base}/_matrix/client/v3/login"))
        .json(&LoginRequest::password(&config.user, &config.password))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status();
    let login: LoginResponse = match resp.error_for_status() {
        Ok(r) => r.bounded_json().await?,
        Err(e) => {
            let msg = format!("login rejected: {e}");
            return Err(if super::is_http_auth_rejection(Some(status)) {
                super::ConnectFail::Auth(msg)
            } else {
                super::ConnectFail::Transient(msg)
            });
        }
    };
    if login.access_token.is_empty() || login.user_id.is_empty() {
        return Err(super::ConnectFail::Transient(
            "login response had an empty access token or user id".into(),
        ));
    }

    let mut session = Session {
        http,
        base,
        token: login.access_token,
        user_id: login.user_id,
        channel_to_room: HashMap::new(),
        room_to_channel: HashMap::new(),
        txn: 0,
    };
    for alias in &config.rooms {
        let channel = alias_to_channel(alias);
        if !crate::sanitize::valid_channel_name(&channel) {
            return Err(super::ConnectFail::Transient(format!(
                "matrix: room alias {alias:?} maps to an unsafe IRC channel {channel:?}"
            )));
        }
        let folded = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(&channel);
        if session.channel_to_room.contains_key(&folded) {
            return Err(super::ConnectFail::Transient(format!(
                "matrix: two rooms map to the same IRC channel {channel:?}; rename one alias"
            )));
        }
        let room_id = join_room(&session, alias).await?;
        session.channel_to_room.insert(folded, room_id.clone());
        session.room_to_channel.insert(room_id, channel);
    }
    Ok(session)
}

async fn join_room(s: &Session, alias: &str) -> Result<String, String> {
    let encoded = urlencode(alias);
    let response: JoinResponse = s
        .http
        .post(format!("{}/_matrix/client/v3/join/{encoded}", s.base))
        .bearer_auth(&s.token)
        .json(&EmptyObject {})
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| format!("join {alias} rejected: {e}"))?
        .bounded_json()
        .await?;
    if response.room_id.is_empty() {
        Err(format!("join {alias} returned an empty room id"))
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
}

impl<'a> LoginRequest<'a> {
    fn password(user: &'a str, password: &'a str) -> Self {
        Self {
            kind: "m.login.password",
            identifier: LoginIdentifier {
                kind: "m.id.user",
                user,
            },
            password,
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
    timeline: Timeline,
}

#[derive(serde::Deserialize)]
struct Timeline {
    events: Vec<TimelineEvent>,
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

fn collect_sync_messages(body: SyncResponse) -> Result<(String, Vec<Incoming>), String> {
    if body.next_batch.is_empty() {
        return Err("sync returned an empty next_batch".to_string());
    }
    let mut messages = Vec::new();
    for (room_id, room) in body.rooms.join {
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
    Ok((body.next_batch, messages))
}

async fn sync(s: &Session, since: Option<&str>) -> Result<(String, Vec<Incoming>), String> {
    let timeout = if since.is_some() { 20000 } else { 0 };
    let mut req = s
        .http
        .get(format!("{}/_matrix/client/v3/sync", s.base))
        .bearer_auth(&s.token)
        .query(&[("timeout", timeout.to_string())]);
    if let Some(since) = since {
        req = req.query(&[("since", since)]);
    }
    let body: SyncResponse = super::bridge_send(req).await?.bounded_json().await?;
    collect_sync_messages(body)
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
        let (next, messages) = collect_sync_messages(response).expect("valid sync");
        assert_eq!(next, "s1");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].sender, "@alice:example");
        assert_eq!(messages[0].body, "hello");

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
