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

use super::BoundedJson;
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
    // Bound REST calls so a hung request can't stall the gateway loop; vet every
    // resolved IP and refuse redirects (SSRF control; see `bridge_http_client`).
    let http = match super::bridge_http_client(Duration::from_secs(30)) {
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
                // The gateway (or a self-hosted API-compatible endpoint) supplies
                // this name; it lands in a PRIVMSG middle parameter, so a space or
                // `:` in it would forge extra params. Refuse it loudly rather than
                // ever putting an unsafe target on the wire.
                if !crate::sanitize::valid_channel_name(&channel) {
                    eprintln!(
                        "discord: channel {id} has an unsafe name {name:?}; refusing to bridge it"
                    );
                    return Dropped;
                }
                // Two Discord channels whose IRC names collide *under the
                // casemapping* derive one IRC channel and would silently
                // overwrite the mapping; the forward map is folded-keyed so a
                // case variant is caught here and routed correctly.
                let folded = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(&channel);
                if channel_to_id.contains_key(&folded) {
                    eprintln!(
                        "discord: channel {id} name {name:?} collides with an already-bridged \
                         channel {channel:?}; refusing to bridge it"
                    );
                    return Dropped;
                }
                id_to_channel.insert(id.clone(), channel.clone());
                channel_to_id.insert(folded, id.clone());
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
    let ws = match tokio::time::timeout(
        Duration::from_secs(30),
        super::bridge_ws_connect(&url, super::bridge_ws_config()),
    )
    .await
    {
        Ok(Ok(ws)) => ws,
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
                    Some(Ok(Ws::Close(frame))) => {
                        // Discord close code 4004 = authentication failed (bad
                        // token); 4013/4014 = invalid/disallowed gateway intents.
                        // These are permanent config errors — stop re-dialing (like
                        // the IRC driver on a rejected password) rather than
                        // reconnecting forever with the same bad token.
                        let code = frame.as_ref().map(|f| u16::from(f.code));
                        if matches!(code, Some(4004 | 4013 | 4014)) {
                            eprintln!(
                                "discord: gateway closed with fatal auth/intents code {code:?}; \
                                 will stop retrying"
                            );
                            return super::SessionOutcome::AuthRejected;
                        }
                        return Dropped;
                    }
                    None => return Dropped,
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
                    Event::Message { channel_id, author_id, author, content, attachments } => {
                        // Skip our own messages (the attached client already saw
                        // what it sent).
                        if author_id == our_id {
                            continue;
                        }
                        // Render the text, or the attachment URLs when there is no
                        // text body — an image/file-only message must not silently
                        // vanish on the IRC side. A message with neither (e.g. a
                        // bare embed we don't render) is skipped.
                        let body = if !content.is_empty() {
                            content
                        } else if !attachments.is_empty() {
                            attachments.join(" ")
                        } else {
                            continue;
                        };
                        if let Some(channel) = id_to_channel.get(&channel_id) {
                            for line in super::render_bridged_privmsg(
                                "discord", &author, channel, &body,
                            ) {
                                ends.emit_line(line);
                            }
                        }
                    }
                    Event::Hello(_) | Event::Ack | Event::Ignore => {}
                }
            }
            cmd = ends.next_command() => match cmd {
                // One line may resolve to several targets (a comma list); each
                // target's outcome is surfaced independently by `relay_routed`.
                Some(line) => {
                    let routed = super::route_privmsg(&line, &channel_to_id);
                    super::relay_routed(ends, routed, "Discord", "channel", |id, text| {
                        let http = http.clone();
                        let base = base.clone();
                        let token = config.token.clone();
                        async move { send_message(&http, &base, &token, &id, &text).await }
                    })
                    .await;
                }
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
        /// Attachment URLs — rendered when there is no text `content`, so an
        /// image/file-only message doesn't vanish on the IRC side.
        attachments: Vec<String>,
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
                    attachments: d["attachments"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x["url"].as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default(),
                }
            }
            _ => Event::Ignore,
        },
        _ => Event::Ignore,
    };
    Frame { seq, event }
}

async fn gateway_url(http: &reqwest::Client, base: &str) -> Result<String, String> {
    let v: serde_json::Value = http
        .get(format!("{base}/gateway"))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .bounded_json()
        .await?;
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
        .bounded_json()
        .await?;
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
    let req = http
        .post(format!("{base}/channels/{channel_id}/messages"))
        .header("Authorization", format!("Bot {token}"))
        .json(&serde_json::json!({ "content": text }));
    super::bridge_send(req).await?;
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
                attachments: _,
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
            crate::bouncer::render_bridged_privmsg("discord", "alice", "#general", "hi there"),
            vec![":alice!alice@discord PRIVMSG #general :hi there"]
        );
        // The map is keyed by the *folded* channel name (as the driver inserts).
        let mut map = HashMap::new();
        map.insert("#general".to_string(), "42".to_string());
        use crate::bouncer::{RouteResult, route_privmsg};
        assert_eq!(
            route_privmsg("PRIVMSG #general :hello", &map),
            vec![RouteResult::Deliver("42".to_string(), "hello".to_string())]
        );
        // Case-insensitive: a differently-cased target still routes.
        assert_eq!(
            route_privmsg("PRIVMSG #General :hi", &map),
            vec![RouteResult::Deliver("42".to_string(), "hi".to_string())]
        );
        // A STATUSMSG prefix is stripped before the lookup.
        assert_eq!(
            route_privmsg("PRIVMSG @#general :ops", &map),
            vec![RouteResult::Deliver("42".to_string(), "ops".to_string())]
        );
        // A comma target list routes each independently.
        assert_eq!(
            route_privmsg("PRIVMSG #general,#other :x", &map),
            vec![
                RouteResult::Deliver("42".to_string(), "x".to_string()),
                RouteResult::Unmapped("#other".to_string()),
            ]
        );
        // A PRIVMSG to a non-bridged channel is surfaced, not silently dropped.
        assert_eq!(
            route_privmsg("PRIVMSG #other :x", &map),
            vec![RouteResult::Unmapped("#other".to_string())]
        );
        // A non-message command is ignored quietly.
        assert_eq!(
            route_privmsg("JOIN #general", &map),
            vec![RouteResult::Ignore]
        );
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
