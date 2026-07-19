//! The `discord` bridge driver (DESIGN §10.5): a [`NetworkDriver`] that
//! presents a Discord bot session as a BNC network. It connects to the
//! Discord gateway (a WebSocket), IDENTIFYs with a bot token, keeps the
//! heartbeat, and bridges `MESSAGE_CREATE` events to IRC PRIVMSG lines and
//! back (the reverse direction sends via the REST API). All of its HTTP
//! and WebSocket code lives behind the `discord` feature.
//!
//! Mapping: each configured Discord channel id is looked up once for its
//! name and bridged as IRC channel `#name`; a message author's username ⇄
//! nick; message `content` ⇄ PRIVMSG text. The bot's own messages and
//! non-message events are dropped.
//!
//! There is no self-hostable Discord server to test against (Spacebar, the
//! only reimplementation, does not run — SIGSEGV on its current image), so
//! the pure mapping/parse/route logic below is unit-tested offline and the
//! end-to-end path is covered by a live-gated integration test that needs a
//! real bot token. This module is NOT verified against live Discord in CI.

use std::collections::HashMap;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as Ws;

use super::{DriverEnds, DriverEvent, NetworkDriver, NetworkHandle};

/// Default Discord REST base; overridable via config `addr` for a custom
/// or self-hosted API-compatible endpoint.
const DEFAULT_API: &str = "https://discord.com/api/v10";
/// Gateway intents: GUILDS (1<<0) | GUILD_MESSAGES (1<<9) |
/// MESSAGE_CONTENT (1<<15) — the minimum to receive channel message text.
const INTENTS: u64 = (1 << 0) | (1 << 9) | (1 << 15);

#[derive(Debug, Clone)]
pub struct DiscordConfig {
    /// Bot token (used raw in the gateway IDENTIFY and as `Bot <token>`
    /// on REST calls).
    pub token: String,
    /// REST API base; empty means [`DEFAULT_API`].
    pub api_base: String,
    /// Discord channel ids to bridge.
    pub channels: Vec<String>,
    pub buffer_cap: usize,
}

pub struct DiscordDriver {
    config: DiscordConfig,
}

impl DiscordDriver {
    pub fn new(config: DiscordConfig) -> Self {
        Self { config }
    }
}

impl NetworkDriver for DiscordDriver {
    fn kind(&self) -> &'static str {
        "discord"
    }

    fn start(self: Box<Self>) -> NetworkHandle {
        let (handle, ends) = NetworkHandle::channels(self.config.buffer_cap);
        tokio::spawn(run(self.config, ends));
        handle
    }
}

fn api_base(config: &DiscordConfig) -> String {
    if config.api_base.is_empty() {
        DEFAULT_API.to_string()
    } else {
        config.api_base.trim_end_matches('/').to_string()
    }
}

async fn run(config: DiscordConfig, mut ends: DriverEnds) {
    let http = reqwest::Client::new();
    let base = api_base(&config);

    // Resolve each configured channel id to its #name once.
    let mut id_to_channel: HashMap<String, String> = HashMap::new();
    let mut channel_to_id: HashMap<String, String> = HashMap::new();
    for id in &config.channels {
        match fetch_channel_name(&http, &base, &config.token, id).await {
            Ok(name) => {
                let channel = format!("#{name}");
                id_to_channel.insert(id.clone(), channel.clone());
                channel_to_id.insert(channel, id.clone());
            }
            Err(e) => {
                eprintln!("discord: channel {id} lookup failed: {e}");
                ends.emit(DriverEvent::Disconnected);
                return;
            }
        }
    }

    let gateway = match gateway_url(&http, &base).await {
        Ok(u) => u,
        Err(e) => {
            eprintln!("discord: gateway discovery failed: {e}");
            ends.emit(DriverEvent::Disconnected);
            return;
        }
    };
    let url = format!("{}/?v=10&encoding=json", gateway.trim_end_matches('/'));
    let (ws, _) = match tokio_tungstenite::connect_async(&url).await {
        Ok(x) => x,
        Err(e) => {
            eprintln!("discord: gateway connect failed: {e}");
            ends.emit(DriverEvent::Disconnected);
            return;
        }
    };
    let (mut write, mut read) = ws.split();

    // First frame must be HELLO, carrying the heartbeat interval.
    let hb_interval = match read.next().await {
        Some(Ok(Ws::Text(t))) => match parse_frame(t.as_str()).event {
            Event::Hello(ms) => ms,
            _ => {
                eprintln!("discord: first gateway frame was not HELLO");
                ends.emit(DriverEvent::Disconnected);
                return;
            }
        },
        _ => {
            eprintln!("discord: no HELLO from gateway");
            ends.emit(DriverEvent::Disconnected);
            return;
        }
    };

    let identify = serde_json::json!({
        "op": 2,
        "d": {
            "token": config.token,
            "intents": INTENTS,
            "properties": { "os": "linux", "browser": "e6irc", "device": "e6irc" },
        }
    });
    if write.send(Ws::text(identify.to_string())).await.is_err() {
        ends.emit(DriverEvent::Disconnected);
        return;
    }
    ends.emit(DriverEvent::Connected);

    let mut heartbeat = tokio::time::interval(Duration::from_millis(hb_interval.max(1000)));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_seq: Option<u64> = None;
    let mut our_id = String::new();

    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                let hb = serde_json::json!({ "op": 1, "d": last_seq });
                if write.send(Ws::text(hb.to_string())).await.is_err() {
                    break;
                }
            }
            frame = read.next() => {
                let text = match frame {
                    Some(Ok(Ws::Text(t))) => t.as_str().to_string(),
                    Some(Ok(Ws::Ping(p))) => {
                        let _ = write.send(Ws::Pong(p)).await;
                        continue;
                    }
                    Some(Ok(Ws::Close(_))) | None => break,
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => {
                        eprintln!("discord: gateway read error: {e}");
                        break;
                    }
                };
                let frame = parse_frame(&text);
                if let Some(s) = frame.seq {
                    last_seq = Some(s);
                }
                match frame.event {
                    Event::Ready(id) => our_id = id,
                    Event::HeartbeatRequest => {
                        let hb = serde_json::json!({ "op": 1, "d": last_seq });
                        if write.send(Ws::text(hb.to_string())).await.is_err() {
                            break;
                        }
                    }
                    Event::Message { channel_id, author_id, author, content } => {
                        // Skip our own messages (the attached client already
                        // saw what it sent) and empty/non-bridged channels.
                        if author_id == our_id || content.is_empty() {
                            continue;
                        }
                        if let Some(channel) = id_to_channel.get(&channel_id) {
                            ends.emit_line(render_privmsg(&author, channel, &content));
                        }
                    }
                    Event::Hello(_) | Event::Ack | Event::Ignore => {}
                }
            }
            cmd = ends.next_command() => match cmd {
                Some(line) => {
                    if let Some((id, text)) = route_command(&line, &channel_to_id)
                        && let Err(e) = send_message(&http, &base, &config.token, &id, &text).await
                    {
                        eprintln!("discord: send to {id} failed: {e}");
                    }
                }
                None => break, // every handle dropped
            },
        }
    }
    ends.emit(DriverEvent::Disconnected);
}

/// A parsed gateway frame: its sequence number (if any) and classified
/// event. Kept pure so it can be unit-tested with synthetic frames.
struct Frame {
    seq: Option<u64>,
    event: Event,
}

enum Event {
    Hello(u64),
    Ready(String),
    Message {
        channel_id: String,
        author_id: String,
        author: String,
        content: String,
    },
    HeartbeatRequest,
    Ack,
    Ignore,
}

fn parse_frame(text: &str) -> Frame {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return Frame {
            seq: None,
            event: Event::Ignore,
        };
    };
    let seq = v["s"].as_u64();
    let event = match v["op"].as_u64() {
        Some(10) => Event::Hello(v["d"]["heartbeat_interval"].as_u64().unwrap_or(45000)),
        Some(1) => Event::HeartbeatRequest,
        Some(11) => Event::Ack,
        Some(0) => match v["t"].as_str().unwrap_or("") {
            "READY" => Event::Ready(v["d"]["user"]["id"].as_str().unwrap_or("").to_string()),
            "MESSAGE_CREATE" => {
                let d = &v["d"];
                Event::Message {
                    channel_id: d["channel_id"].as_str().unwrap_or("").to_string(),
                    author_id: d["author"]["id"].as_str().unwrap_or("").to_string(),
                    author: d["author"]["username"].as_str().unwrap_or("?").to_string(),
                    content: d["content"].as_str().unwrap_or("").to_string(),
                }
            }
            _ => Event::Ignore,
        },
        _ => Event::Ignore,
    };
    Frame { seq, event }
}

/// A Discord message author + channel + text, rendered as an IRC line.
fn render_privmsg(author: &str, channel: &str, content: &str) -> String {
    format!(":{author}!{author}@discord PRIVMSG {channel} :{content}")
}

/// A downstream IRC line → (channel id, text) if it is a PRIVMSG to a
/// bridged channel; else `None`.
fn route_command(line: &str, channel_to_id: &HashMap<String, String>) -> Option<(String, String)> {
    let msg = e6irc_proto::message::Message::parse(line).ok()?;
    if !msg.command.eq_ignore_ascii_case("PRIVMSG") {
        return None;
    }
    let target = msg.params.first()?;
    let text = msg.params.get(1)?;
    let id = channel_to_id.get(*target)?;
    Some((id.clone(), text.to_string()))
}

async fn gateway_url(http: &reqwest::Client, base: &str) -> Result<String, String> {
    let v: serde_json::Value = http
        .get(format!("{base}/gateway"))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    v["url"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "gateway response had no url".to_string())
}

async fn fetch_channel_name(
    http: &reqwest::Client,
    base: &str,
    token: &str,
    id: &str,
) -> Result<String, String> {
    let v: serde_json::Value = http
        .get(format!("{base}/channels/{id}"))
        .header("Authorization", format!("Bot {token}"))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    v["name"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("channel {id} response had no name"))
}

async fn send_message(
    http: &reqwest::Client,
    base: &str,
    token: &str,
    channel_id: &str,
    text: &str,
) -> Result<(), String> {
    http.post(format!("{base}/channels/{channel_id}/messages"))
        .header("Authorization", format!("Bot {token}"))
        .json(&serde_json::json!({ "content": text }))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hello_and_tracks_seq() {
        let f = parse_frame(r#"{"op":10,"d":{"heartbeat_interval":41250}}"#);
        assert!(matches!(f.event, Event::Hello(41250)));
        assert_eq!(f.seq, None);

        let f = parse_frame(r#"{"op":0,"s":7,"t":"READY","d":{"user":{"id":"999"}}}"#);
        assert_eq!(f.seq, Some(7));
        assert!(matches!(f.event, Event::Ready(id) if id == "999"));
    }

    #[test]
    fn parses_message_create() {
        let f = parse_frame(
            r#"{"op":0,"s":8,"t":"MESSAGE_CREATE","d":{"channel_id":"42","content":"hi",
               "author":{"id":"7","username":"alice"}}}"#,
        );
        assert_eq!(f.seq, Some(8));
        match f.event {
            Event::Message {
                channel_id,
                author_id,
                author,
                content,
            } => {
                assert_eq!(channel_id, "42");
                assert_eq!(author_id, "7");
                assert_eq!(author, "alice");
                assert_eq!(content, "hi");
            }
            _ => panic!("expected Message"),
        }
    }

    #[test]
    fn opcodes_and_garbage() {
        assert!(matches!(
            parse_frame(r#"{"op":1}"#).event,
            Event::HeartbeatRequest
        ));
        assert!(matches!(parse_frame(r#"{"op":11}"#).event, Event::Ack));
        assert!(matches!(
            parse_frame(r#"{"op":0,"t":"TYPING_START"}"#).event,
            Event::Ignore
        ));
        assert!(matches!(parse_frame("not json").event, Event::Ignore));
    }

    #[test]
    fn renders_and_routes() {
        assert_eq!(
            render_privmsg("alice", "#general", "hi there"),
            ":alice!alice@discord PRIVMSG #general :hi there"
        );
        let mut map = HashMap::new();
        map.insert("#general".to_string(), "42".to_string());
        assert_eq!(
            route_command("PRIVMSG #general :hello", &map),
            Some(("42".to_string(), "hello".to_string()))
        );
        assert_eq!(route_command("PRIVMSG #other :x", &map), None);
        assert_eq!(route_command("JOIN #general", &map), None);
    }

    #[test]
    fn api_base_default_and_override() {
        let mut c = DiscordConfig {
            token: "t".into(),
            api_base: String::new(),
            channels: vec![],
            buffer_cap: 10,
        };
        assert_eq!(api_base(&c), DEFAULT_API);
        c.api_base = "http://localhost:8080/".into();
        assert_eq!(api_base(&c), "http://localhost:8080");
    }
}
