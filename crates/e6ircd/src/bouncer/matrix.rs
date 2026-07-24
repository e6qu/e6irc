//! The `matrix` bridge driver (DESIGN §10.5): a [`NetworkDriver`] that
//! presents a Matrix homeserver as a BNC network. It logs in over the
//! Matrix client-server API, joins the configured rooms, and bridges
//! `m.room.message` events to IRC PRIVMSG lines and back. All of its HTTP
//! (reqwest) lives behind the `matrix` feature.
//!
//! Mapping: a room alias `#name:server` ⇄ IRC channel `#name`; a Matrix
//! sender `@user:server` ⇄ nick `user`; `m.text` message body ⇄ PRIVMSG
//! text. Non-text events and the bridge user's own echoes are dropped.

use super::BoundedJson;
use std::collections::HashMap;

use super::{ConnectionEvent, DriverEnds, NetworkDriver, NetworkHandle};

/// Static configuration for one bridged Matrix homeserver.
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

    fn start(self: Box<Self>) -> NetworkHandle {
        let (handle, ends) = NetworkHandle::channels(self.config.buffer_cap);
        tokio::spawn(run(self.config, ends));
        handle
    }
}

/// Session state after login.
struct Session {
    http: reqwest::Client,
    base: String,
    token: String,
    user_id: String,
    /// Bridged channel name (`#name`) → Matrix room id.
    channel_to_room: HashMap<String, String>,
    /// Matrix room id → channel name.
    room_to_channel: HashMap<String, String>,
    txn: u64,
}

async fn run(config: MatrixConfig, mut ends: DriverEnds) {
    // Always-on: a transient failure reconnects with backoff rather than
    // permanently killing the network (which would silently drop every later
    // upstream message). Only a dropped handle stops the driver.
    super::run_with_backoff(config, &mut ends, |config, ends| {
        Box::pin(session_once(config, ends))
    })
    .await;
}

async fn session_once(config: &MatrixConfig, ends: &mut DriverEnds) -> super::SessionOutcome {
    let mut session = match connect(config).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("matrix: connect failed: {e}");
            return super::SessionOutcome::Dropped;
        }
    };
    ends.emit(ConnectionEvent::Connected);

    // Initial sync to get a stream position without replaying all history.
    let mut since = match sync(&session, None).await {
        Ok((next, _)) => next,
        Err(e) => {
            eprintln!("matrix: initial sync failed: {e}");
            return super::SessionOutcome::Dropped;
        }
    };

    loop {
        tokio::select! {
                   result = sync(&session, Some(&since)) => match result {
                       Ok((next, messages)) => {
                           since = next;
                           for m in messages {
                               // Skip our own echoes (the attached client already
                               // saw what it sent).
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
                           return super::SessionOutcome::Dropped;
                       }
                   },
                   cmd = ends.next_command() => match cmd {
                       Some(line) => match handle_command(&mut session, &line).await {
                           Relayed::Ok => {}
                           Relayed::Unmapped(target) => ends.emit_line(super::unmapped_target_notice(
            "Matrix", "room", &target,
        )),
                           Relayed::Failed(room) => {
                               // `room` is a homeserver-supplied id, unbounded
                               // here; truncate so this failure notice can't
                               // itself be discarded for length — which would
                               // resurrect the silent-drop it exists to prevent.
                               ends.emit_line(super::undelivered_notice("Matrix", "room", &room))
                           }
                       },
                       None => return super::SessionOutcome::Stopped, // every handle dropped
                   },
               }
    }
}

/// Log in and join the configured rooms.
async fn connect(config: &MatrixConfig) -> Result<Session, String> {
    // A timeout longer than the /sync long-poll (20s) so a black-holed
    // connection fails the request — otherwise the future never resolves,
    // `session_once` never returns, and the reconnect loop never runs.
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| e.to_string())?;
    let base = config.homeserver.trim_end_matches('/').to_string();

    let login: serde_json::Value = http
        .post(format!("{base}/_matrix/client/v3/login"))
        .json(&serde_json::json!({
            "type": "m.login.password",
            "identifier": { "type": "m.id.user", "user": config.user },
            "password": config.password,
        }))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| format!("login rejected: {e}"))?
        .bounded_json()
        .await?;
    let token = login["access_token"]
        .as_str()
        .ok_or("no access_token in login response")?
        .to_string();
    // Own-echo suppression keys on this id (`m.sender == user_id`); an empty
    // fallback would silently defeat it and loop our own messages back, so a
    // login response without a user_id is a hard failure.
    let user_id = login["user_id"]
        .as_str()
        .ok_or("no user_id in login response")?
        .to_string();

    let mut session = Session {
        http,
        base,
        token,
        user_id,
        channel_to_room: HashMap::new(),
        room_to_channel: HashMap::new(),
        txn: 0,
    };
    for alias in &config.rooms {
        let channel = alias_to_channel(alias);
        // The alias comes from config (trusted), but it lands in a PRIVMSG
        // middle parameter, so refuse one that isn't a legal channel — a space
        // or `:` in it would forge extra params. Fail loudly, as the Slack and
        // Discord bridges already do for their fetched names.
        if !crate::sanitize::valid_channel_name(&channel) {
            return Err(format!(
                "matrix: room alias {alias:?} maps to an unsafe IRC channel {channel:?}"
            ));
        }
        // Two rooms that derive the same IRC channel name would silently
        // overwrite each other in the map — outbound reaching only one room,
        // inbound from both collapsing under one channel. Refuse loudly, like an
        // unsafe name, rather than lose the mapping.
        if session.channel_to_room.contains_key(&channel) {
            return Err(format!(
                "matrix: two rooms map to the same IRC channel {channel:?}; rename one alias"
            ));
        }
        let room_id = join_room(&session, alias).await?;
        session
            .channel_to_room
            .insert(channel.clone(), room_id.clone());
        session.room_to_channel.insert(room_id, channel);
    }
    Ok(session)
}

async fn join_room(s: &Session, alias: &str) -> Result<String, String> {
    let encoded = urlencode(alias);
    let resp: serde_json::Value = s
        .http
        .post(format!("{}/_matrix/client/v3/join/{encoded}", s.base))
        .bearer_auth(&s.token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| format!("join {alias} rejected: {e}"))?
        .bounded_json()
        .await?;
    resp["room_id"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("no room_id joining {alias}"))
}

/// One incoming Matrix text message, mapped to bridge terms.
struct Incoming {
    room_id: String,
    sender: String,
    body: String,
}

/// Long-poll `/sync`; returns the next batch token and any text messages.
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
    let body: serde_json::Value = req
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .bounded_json()
        .await?;

    let next = body["next_batch"]
        .as_str()
        .ok_or("sync had no next_batch")?
        .to_string();
    let mut messages = Vec::new();
    if let Some(join) = body["rooms"]["join"].as_object() {
        for (room_id, room) in join {
            let Some(events) = room["timeline"]["events"].as_array() else {
                continue;
            };
            for ev in events {
                if ev["type"] == "m.room.message"
                    && ev["content"]["msgtype"] == "m.text"
                    && let Some(text) = ev["content"]["body"].as_str()
                {
                    messages.push(Incoming {
                        room_id: room_id.clone(),
                        sender: ev["sender"].as_str().unwrap_or("?").to_string(),
                        body: text.to_string(),
                    });
                }
            }
        }
    }
    Ok((next, messages))
}

/// Deliver a downstream PRIVMSG to Matrix. Returns `Some(target)` when a
/// PRIVMSG could not be delivered because no bridged room maps to it, so the
/// caller can surface the loss rather than dropping it silently.
/// Outcome of relaying a downstream command to Matrix, so the caller can
/// surface a loss (unmapped target or a failed upstream send) instead of
/// dropping it silently.
enum Relayed {
    Ok,
    Unmapped(String),
    Failed(String),
}

async fn handle_command(s: &mut Session, line: &str) -> Relayed {
    let (room_id, text) = match super::route_privmsg(line, &s.channel_to_room) {
        super::RouteResult::Deliver(room_id, text) => (room_id, text),
        super::RouteResult::Unmapped(target) => return Relayed::Unmapped(target),
        super::RouteResult::Ignore => return Relayed::Ok,
    };
    s.txn += 1;
    let txn = s.txn;
    let url = format!(
        "{}/_matrix/client/v3/rooms/{}/send/m.room.message/e6{txn}",
        s.base,
        urlencode(&room_id),
    );
    let send = s
        .http
        .put(url)
        .bearer_auth(&s.token)
        .json(&serde_json::json!({ "msgtype": "m.text", "body": text }))
        .send()
        .await;
    if let Err(e) = send {
        eprintln!("matrix: send to room {room_id} failed: {e}");
        return Relayed::Failed(room_id);
    }
    Relayed::Ok
}

/// `#name:server` → IRC channel `#name`.
fn alias_to_channel(alias: &str) -> String {
    match alias.split_once(':') {
        Some((local, _)) => local.to_string(),
        None => alias.to_string(),
    }
}

/// `@user:server` → `user`. The shared renderer reduces whatever this returns
/// to a safe nick token; without the localpart the `@` and `:` of a full Matrix
/// ID would survive as underscores and every bridged nick would change.
fn matrix_localpart(sender: &str) -> &str {
    sender
        .strip_prefix('@')
        .and_then(|s| s.split_once(':').map(|(l, _)| l))
        .unwrap_or(sender)
}

/// Percent-encode a path segment (room ids/aliases contain `!`, `#`, `:`).
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
}
