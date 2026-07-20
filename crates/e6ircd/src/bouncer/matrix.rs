//! The `matrix` bridge driver (DESIGN §10.5): a [`NetworkDriver`] that
//! presents a Matrix homeserver as a BNC network. It logs in over the
//! Matrix client-server API, joins the configured rooms, and bridges
//! `m.room.message` events to IRC PRIVMSG lines and back. All of its HTTP
//! (reqwest) lives behind the `matrix` feature.
//!
//! Mapping: a room alias `#name:server` ⇄ IRC channel `#name`; a Matrix
//! sender `@user:server` ⇄ nick `user`; `m.text` message body ⇄ PRIVMSG
//! text. Non-text events and the bridge user's own echoes are dropped.

use std::collections::HashMap;

use super::{DriverEnds, DriverEvent, NetworkDriver, NetworkHandle};

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
    let mut backoff = std::time::Duration::from_millis(200);
    loop {
        let started = tokio::time::Instant::now();
        match session_once(&config, &mut ends).await {
            super::SessionOutcome::Stopped => return,
            super::SessionOutcome::Dropped => {
                ends.emit(DriverEvent::Disconnected);
                // A session that lasted a while clearly connected; reset the
                // backoff so a flapping-but-reachable upstream reconnects
                // promptly instead of escalating toward the 30s cap forever.
                if started.elapsed() >= std::time::Duration::from_secs(10) {
                    backoff = std::time::Duration::from_millis(200);
                }
                let jitter = std::time::Duration::from_millis((backoff.as_millis() as u64) % 97);
                tokio::time::sleep(backoff + jitter).await;
                backoff = (backoff * 2).min(std::time::Duration::from_secs(30));
            }
        }
    }
}

async fn session_once(config: &MatrixConfig, ends: &mut DriverEnds) -> super::SessionOutcome {
    let mut session = match connect(config).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("matrix: connect failed: {e}");
            return super::SessionOutcome::Dropped;
        }
    };
    ends.emit(DriverEvent::Connected);

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
                            ends.emit_line(render_privmsg(&m.sender, channel, &m.body));
                        }
                    }
                }
                Err(e) => {
                    eprintln!("matrix: sync error: {e}");
                    return super::SessionOutcome::Dropped;
                }
            },
            cmd = ends.next_command() => match cmd {
                Some(line) => {
                    if let Some(target) = handle_command(&mut session, &line).await {
                        ends.emit_line(format!(
                            ":*bnc* NOTICE {target} :not delivered: no bridged Matrix room for {target}"
                        ));
                    }
                }
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
        .json()
        .await
        .map_err(|e| e.to_string())?;
    let token = login["access_token"]
        .as_str()
        .ok_or("no access_token in login response")?
        .to_string();
    let user_id = login["user_id"].as_str().unwrap_or("").to_string();

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
        let room_id = join_room(&session, alias).await?;
        let channel = alias_to_channel(alias);
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
        .json()
        .await
        .map_err(|e| e.to_string())?;
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
        .json()
        .await
        .map_err(|e| e.to_string())?;

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

/// Relay a downstream IRC command upstream. Only channel PRIVMSGs to a
/// bridged room are meaningful; others are dropped.
/// Deliver a downstream PRIVMSG to Matrix. Returns `Some(target)` when a
/// PRIVMSG could not be delivered because no bridged room maps to it, so the
/// caller can surface the loss rather than dropping it silently.
async fn handle_command(s: &mut Session, line: &str) -> Option<String> {
    let msg = e6irc_proto::message::Message::parse(line).ok()?;
    if !msg.command.eq_ignore_ascii_case("PRIVMSG") {
        return None;
    }
    let (Some(target), Some(text)) = (msg.params.first(), msg.params.get(1)) else {
        return None;
    };
    let Some(room_id) = s.channel_to_room.get(*target).cloned() else {
        return Some(target.to_string()); // PRIVMSG to a non-bridged channel: lost
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
        eprintln!("matrix: send to {target} failed: {e}");
    }
    None
}

/// `#name:server` → IRC channel `#name`.
fn alias_to_channel(alias: &str) -> String {
    match alias.split_once(':') {
        Some((local, _)) => local.to_string(),
        None => alias.to_string(),
    }
}

/// `@user:server` → nick `user`; render as an IRC PRIVMSG line.
fn render_privmsg(sender: &str, channel: &str, body: &str) -> String {
    let nick = sender
        .strip_prefix('@')
        .and_then(|s| s.split_once(':').map(|(l, _)| l))
        .unwrap_or(sender);
    format!(":{nick}!{nick}@matrix PRIVMSG {channel} :{body}")
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
        assert_eq!(
            render_privmsg("@alice:localhost", "#room", "hi there"),
            ":alice!alice@matrix PRIVMSG #room :hi there"
        );
    }

    #[test]
    fn urlencodes_room_ids() {
        assert_eq!(urlencode("!abc:localhost"), "%21abc%3Alocalhost");
        assert_eq!(urlencode("#room:localhost"), "%23room%3Alocalhost");
    }
}
