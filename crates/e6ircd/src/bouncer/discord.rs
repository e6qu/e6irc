//! Discord gateway and REST bridge.
//!
//! CI drives its HTTP and WebSocket contract through a local protocol oracle.

use super::BoundedJson;
#[cfg(test)]
use std::collections::HashMap;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as Ws;

use super::{ConnectionEvent, DriverEnds, NetworkDriver, NetworkHandle};

const DEFAULT_API: &str = "https://discord.com/api/v10";
const INTENTS: u64 = (1 << 0) | (1 << 9) | (1 << 15);

#[derive(Debug, Clone)]
pub struct DiscordConfig {
    pub token: String,
    pub api_base: String,
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

    super::bridge_start!();
}

super::bridge_run!(DiscordConfig);

async fn session_once(config: &DiscordConfig, ends: &mut DriverEnds) -> super::SessionOutcome {
    use super::NetworkFailure;
    use super::SessionOutcome::Dropped;
    let http = match super::bridge_http_or_outcome("discord", Duration::from_secs(30)) {
        Ok(c) => c,
        Err(outcome) => return outcome,
    };
    let base = super::bridge_api_base(&config.api_base, DEFAULT_API);

    let (id_to_channel, channel_to_id) = match super::resolve_bridge_channels(
        "discord",
        &config.channels,
        |id| {
            let http = &http;
            let base = &base;
            let token = &config.token;
            async move { fetch_channel_name(http, base, token, &id).await }
        },
        |id, error| {
            eprintln!("discord: channel {id} lookup failed: {error}");
            Dropped(NetworkFailure::UpstreamRequestFailed)
        },
    )
    .await
    {
        Ok(maps) => maps,
        Err(outcome) => return outcome,
    };

    let gateway = match gateway_url(&http, &base).await {
        Ok(u) => u,
        Err(e) => {
            eprintln!("discord: gateway discovery failed: {e}");
            return Dropped(NetworkFailure::UpstreamRequestFailed);
        }
    };
    let url = match gateway_connection_url(&gateway) {
        Ok(url) => url,
        Err(error) => {
            eprintln!("discord: invalid gateway URL: {error}");
            return Dropped(NetworkFailure::UpstreamProtocolFailed);
        }
    };
    let ws = match super::bridge_ws_open(&url, "discord", "gateway").await {
        Ok(ws) => ws,
        Err(outcome) => return outcome,
    };
    let (mut write, mut read) = ws.split();

    let hb_interval = match tokio::time::timeout(Duration::from_secs(30), read.next()).await {
        Ok(Some(Ok(Ws::Text(t)))) => match parse_frame(t.as_str()) {
            Ok(Frame {
                event: Event::Hello(ms),
                ..
            }) => ms,
            Ok(_) => {
                eprintln!("discord: first gateway frame was not HELLO");
                return Dropped(NetworkFailure::UpstreamProtocolFailed);
            }
            Err(e) => {
                eprintln!("discord: malformed HELLO frame: {e}");
                return Dropped(NetworkFailure::UpstreamProtocolFailed);
            }
        },
        Err(_) => {
            eprintln!("discord: HELLO timed out");
            return Dropped(NetworkFailure::ConnectionTimedOut);
        }
        Ok(Some(Err(e))) => {
            eprintln!("discord: gateway read error before HELLO: {e}");
            return Dropped(NetworkFailure::ConnectionLost);
        }
        Ok(None) => {
            eprintln!("discord: gateway closed before HELLO");
            return Dropped(NetworkFailure::ConnectionLost);
        }
        Ok(Some(Ok(_))) => {
            eprintln!("discord: no HELLO from gateway");
            return Dropped(NetworkFailure::UpstreamProtocolFailed);
        }
    };

    let identify = match encode_gateway(&IdentifyFrame::new(&config.token)) {
        Ok(identify) => identify,
        Err(error) => {
            eprintln!("discord: could not encode IDENTIFY: {error}");
            return Dropped(NetworkFailure::UpstreamProtocolFailed);
        }
    };
    if write.send(identify).await.is_err() {
        return Dropped(NetworkFailure::UpstreamWriteFailed);
    }
    ends.emit(ConnectionEvent::Connected);

    let mut heartbeat = tokio::time::interval(Duration::from_millis(hb_interval));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_seq: Option<u64> = None;
    let mut our_id = String::new();
    let read_timeout = Duration::from_millis(hb_interval.saturating_mul(2).max(60_000));

    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                let heartbeat = match encode_gateway(&HeartbeatFrame::new(last_seq)) {
                    Ok(heartbeat) => heartbeat,
                    Err(error) => {
                        eprintln!("discord: could not encode heartbeat: {error}");
                        return Dropped(NetworkFailure::UpstreamProtocolFailed);
                    }
                };
                if write.send(heartbeat).await.is_err() {
                    return Dropped(NetworkFailure::UpstreamWriteFailed);
                }
            }
            text = super::next_bridge_text(&mut read, &mut write, read_timeout, "discord", "gateway", |code| {
                if matches!(code, Some(4004 | 4013 | 4014)) {
                    eprintln!(
                        "discord: gateway closed with fatal auth/intents code {code:?}; \
                         will stop retrying"
                    );
                    super::SessionOutcome::AuthRejected
                } else {
                    Dropped(NetworkFailure::ConnectionLost)
                }
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
                }
                match frame.event {
                    Event::Ready(id) => {
                        if id.is_empty() {
                            eprintln!("discord: READY without user id");
                            return Dropped(NetworkFailure::UpstreamProtocolFailed);
                        }
                        our_id = id;
                    }
                    Event::HeartbeatRequest => {
                        let heartbeat = match encode_gateway(&HeartbeatFrame::new(last_seq)) {
                            Ok(heartbeat) => heartbeat,
                            Err(error) => {
                                eprintln!("discord: could not encode heartbeat: {error}");
                                return Dropped(NetworkFailure::UpstreamProtocolFailed);
                            }
                        };
                        if write.send(heartbeat).await.is_err() {
                            return Dropped(NetworkFailure::UpstreamWriteFailed);
                        }
                    }
                    Event::Message { channel_id, author_id, author, content, attachments } => {
                        if author_id == our_id {
                            continue;
                        }
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
                Some(cmd) => {
                    let routed = super::route_privmsg(&cmd.line, &channel_to_id);
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
        attachments: Vec<String>,
    },
    HeartbeatRequest,
    Ack,
    Ignore,
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
    user: ReadyUser,
}

#[derive(serde::Deserialize)]
struct ReadyUser {
    id: String,
}

#[derive(serde::Deserialize)]
struct MessageData {
    channel_id: String,
    author: MessageAuthor,
    content: String,
    #[serde(default)]
    attachments: Vec<MessageAttachment>,
}

#[derive(serde::Deserialize)]
struct MessageAuthor {
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
                    Event::Ready(ready.user.id)
                }
                "MESSAGE_CREATE" => {
                    let message: MessageData = decode_data(text, "MESSAGE_CREATE")?;
                    Event::Message {
                        channel_id: message.channel_id,
                        author_id: message.author.id,
                        author: message.author.username,
                        content: message.content,
                        attachments: message
                            .attachments
                            .into_iter()
                            .map(|attachment| attachment.url)
                            .collect(),
                    }
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

async fn gateway_url(http: &reqwest::Client, base: &str) -> Result<String, String> {
    #[derive(serde::Deserialize)]
    struct GatewayResponse {
        url: String,
    }

    let response: GatewayResponse = super::bridge_send(http.get(format!("{base}/gateway")))
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
    let mut url = openidconnect::url::Url::parse(gateway)
        .map_err(|_| "must be an absolute ws(s) URL".to_string())?;
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

async fn fetch_channel_name(
    http: &reqwest::Client,
    base: &str,
    token: &str,
    id: &str,
) -> Result<String, String> {
    #[derive(serde::Deserialize)]
    struct ChannelResponse {
        name: String,
    }

    let response: ChannelResponse = super::bridge_send(
        http.get(format!("{base}/channels/{id}"))
            .header("Authorization", format!("Bot {token}")),
    )
    .await?
    .bounded_json()
    .await?;
    if response.name.is_empty() {
        Err(format!("channel {id} response had an empty name"))
    } else {
        Ok(response.name)
    }
}

async fn send_message(
    http: &reqwest::Client,
    base: &str,
    token: &str,
    channel_id: &str,
    text: &str,
) -> Result<(), String> {
    #[derive(serde::Serialize)]
    struct MessageRequest<'a> {
        content: &'a str,
    }

    let req = http
        .post(format!("{base}/channels/{channel_id}/messages"))
        .header("Authorization", format!("Bot {token}"))
        .json(&MessageRequest { content: text });
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

        let f =
            parse_frame(r#"{"op":0,"s":7,"t":"READY","d":{"user":{"id":"999"}}}"#).expect("READY");
        assert_eq!(f.seq, Some(7));
        assert!(matches!(f.event, Event::Ready(id) if id == "999"));
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
        assert!(parse_frame("not json").is_err());
    }

    #[test]
    fn rejects_malformed_known_frames_instead_of_defaulting_fields() {
        assert!(parse_frame(r#"{"op":10,"d":{}}"#).is_err());
        assert!(parse_frame(r#"{"op":10,"d":{"heartbeat_interval":0}}"#).is_err());
        assert!(parse_frame(r#"{"op":0,"t":"READY","d":{"user":{"id":"999"}}}"#).is_err());
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
    fn gateway_connection_url_preserves_existing_queries() {
        let url =
            gateway_connection_url("wss://gateway.example/socket?compress=zlib&v=1&encoding=etf")
                .expect("valid gateway URL");
        let parsed = openidconnect::url::Url::parse(&url).expect("output URL");
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
            buffer_cap: 10,
        };
        assert_eq!(
            crate::bouncer::bridge_api_base(&c.api_base, DEFAULT_API),
            DEFAULT_API
        );
        c.api_base = "http://localhost:8080/".into();
        assert_eq!(
            crate::bouncer::bridge_api_base(&c.api_base, DEFAULT_API),
            "http://localhost:8080"
        );
    }

    #[tokio::test]
    #[cfg(feature = "slack")]
    async fn real_http_and_websocket_transport_bridge_both_directions() {
        use crate::bouncer::NetworkHandle;
        use crate::bouncer::bridge_oracle::Provider;

        let mut oracle = crate::bouncer::bridge_oracle::start(Provider::Discord).await;
        let config = DiscordConfig {
            token: "discord-token".into(),
            api_base: oracle.api_base.clone(),
            channels: vec!["42".into()],
            buffer_cap: 10,
        };
        let (handle, mut ends) = NetworkHandle::channels(10);
        let driver_events = handle.subscribe();
        let session = tokio::spawn(async move { session_once(&config, &mut ends).await });

        crate::bouncer::bridge_oracle::verify_round_trip(
            Provider::Discord,
            handle,
            driver_events,
            session,
            &mut oracle,
        )
        .await;
    }
}
