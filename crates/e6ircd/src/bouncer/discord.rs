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

use super::{ConnectionEvent, DriverEnds, NetworkDriver, NetworkHandle};

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
    // Always-on: reconnect (from scratch) with backoff on any gateway drop,
    // rather than dying on the first disconnect and silently dropping all
    // later messages. Only a dropped handle stops the driver.
    super::run_with_backoff(config, &mut ends, |config, ends| {
        Box::pin(session_once(config, ends))
    })
    .await;
}

async fn session_once(config: &DiscordConfig, ends: &mut DriverEnds) -> super::SessionOutcome {
    use super::SessionOutcome::Dropped;
    // Bound REST calls so a hung request can't stall the gateway loop.
    let http = match reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("discord: http client build failed: {e}");
            return Dropped;
        }
    };
    let base = api_base(config);

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
                return Dropped;
            }
        }
    }

    let gateway = match gateway_url(&http, &base).await {
        Ok(u) => u,
        Err(e) => {
            eprintln!("discord: gateway discovery failed: {e}");
            return Dropped;
        }
    };
    let url = format!("{}/?v=10&encoding=json", gateway.trim_end_matches('/'));
    // Bound the WS handshake so a black-holed gateway (accepts the connection
    // then goes silent) can't wedge the driver — the same guard irc_driver and
    // matrix already have.
    let (ws, _) = match tokio::time::timeout(
        Duration::from_secs(30),
        tokio_tungstenite::connect_async(&url),
    )
    .await
    {
        Ok(Ok(x)) => x,
        Ok(Err(e)) => {
            eprintln!("discord: gateway connect failed: {e}");
            return Dropped;
        }
        Err(_) => {
            eprintln!("discord: gateway connect timed out");
            return Dropped;
        }
    };
    let (mut write, mut read) = ws.split();

    // First frame must be HELLO, carrying the heartbeat interval.
    let hb_interval = match tokio::time::timeout(Duration::from_secs(30), read.next()).await {
        Ok(Some(Ok(Ws::Text(t)))) => match parse_frame(t.as_str()).event {
            Event::Hello(ms) => ms,
            _ => {
                eprintln!("discord: first gateway frame was not HELLO");
                return Dropped;
            }
        },
        _ => {
            eprintln!("discord: no HELLO from gateway");
            return Dropped;
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
        return Dropped;
    }
    ends.emit(ConnectionEvent::Connected);

    let mut heartbeat = tokio::time::interval(Duration::from_millis(hb_interval.max(1000)));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_seq: Option<u64> = None;
    let mut our_id = String::new();
    // A healthy gateway sends heartbeat ACKs each interval, so no data for well
    // past two intervals means it's black-holed — reconnect instead of hanging.
    let read_timeout = Duration::from_millis(hb_interval.saturating_mul(2).max(60_000));

    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                let hb = serde_json::json!({ "op": 1, "d": last_seq });
                if write.send(Ws::text(hb.to_string())).await.is_err() {
                    return Dropped;
                }
            }
            frame = tokio::time::timeout(read_timeout, read.next()) => {
                let Ok(frame) = frame else {
                    eprintln!("discord: gateway idle past timeout; reconnecting");
                    return Dropped;
                };
                let text = match frame {
                    Some(Ok(Ws::Text(t))) => t.as_str().to_string(),
                    Some(Ok(Ws::Ping(p))) => {
                        let _ = write.send(Ws::Pong(p)).await;
                        continue;
                    }
                    Some(Ok(Ws::Close(_))) | None => return Dropped,
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => {
                        eprintln!("discord: gateway read error: {e}");
                        return Dropped;
                    }
                };
                let frame = parse_frame(&text);
                if let Some(s) = frame.seq {
                    last_seq = Some(s);
                }
                match frame.event {
                    Event::Ready(id) => {
                        // Own-echo suppression keys on this id; an empty one
                        // would loop our own posts back. A READY without a user
                        // id is a broken session — drop it and reconnect rather
                        // than run with echo suppression silently disabled.
                        if id.is_empty() {
                            eprintln!("discord: READY without user id");
                            return Dropped;
                        }
                        our_id = id;
                    }
                    Event::HeartbeatRequest => {
                        let hb = serde_json::json!({ "op": 1, "d": last_seq });
                        if write.send(Ws::text(hb.to_string())).await.is_err() {
                            return Dropped;
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
                Some(line) => match super::route_privmsg(&line, &channel_to_id) {
                    super::RouteResult::Deliver(id, text) => {
                        if let Err(e) = send_message(&http, &base, &config.token, &id, &text).await {
                            eprintln!("discord: send to {id} failed: {e}");
                            // Surface the loss to the client, like the unmapped
                            // path — a delivery failure isn't a silent drop.
                            ends.emit_line(format!(
                                ":*bnc* NOTICE * :message not delivered to Discord channel {id}"
                            ));
                        }
                    }
                    super::RouteResult::Unmapped(target) => {
                        ends.emit_line(format!(
                            ":*bnc* NOTICE {target} :not delivered: no bridged Discord channel for {target}"
                        ));
                    }
                    super::RouteResult::Ignore => {}
                },
                None => return super::SessionOutcome::Stopped, // every handle dropped
            },
        }
    }
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
    // The author name is hostile-upstream input; reduce it to a safe nick token
    // so it can't forge a source/command in the prefix position.
    let nick = super::nick_token(author);
    format!(":{nick}!{nick}@discord PRIVMSG {channel} :{content}")
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
        use crate::bouncer::{RouteResult, route_privmsg};
        assert_eq!(
            route_privmsg("PRIVMSG #general :hello", &map),
            RouteResult::Deliver("42".to_string(), "hello".to_string())
        );
        // A PRIVMSG to a non-bridged channel is surfaced, not silently dropped.
        assert_eq!(
            route_privmsg("PRIVMSG #other :x", &map),
            RouteResult::Unmapped("#other".to_string())
        );
        // A non-message command is ignored quietly.
        assert_eq!(route_privmsg("JOIN #general", &map), RouteResult::Ignore);
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
