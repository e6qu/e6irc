//! e2e for the ws-irc endpoint: a real WebSocket client registers and
//! exchanges messages with a TCP client through the same core.

use e6ircd::config::{Config, HttpConfig, ListenerConfig};
use e6ircd::net;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as Tung;

fn config() -> Config {
    Config {
        server_name: "irc.ws.example".into(),
        network_name: "WsNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![],
        }),
        ..Config::default()
    }
}

#[tokio::test]
async fn ws_client_registers_and_messages_a_tcp_client() {
    let running = net::start(config()).await.expect("start");
    let http = running.http_addr.expect("http");

    let (mut ws, _resp) = tokio_tungstenite::connect_async(format!("ws://{http}/ws/irc"))
        .await
        .expect("ws connect");

    // register over WS, one line per frame
    ws.send(Tung::text("NICK wsclient")).await.unwrap();
    ws.send(Tung::text("USER w 0 * :WS")).await.unwrap();
    // read frames until welcome
    let welcome = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(Ok(Tung::Text(t))) = ws.next().await {
                if t.contains(" 001 ") {
                    return t.to_string();
                }
            } else {
                panic!("ws closed before welcome");
            }
        }
    })
    .await
    .expect("timeout");
    assert!(welcome.contains("wsclient"), "{welcome}");

    ws.send(Tung::text("JOIN #ws")).await.unwrap();
    // wait for end-of-names
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(Ok(Tung::Text(t))) = ws.next().await {
                if t.contains(" 366 ") {
                    return;
                }
            } else {
                panic!("closed");
            }
        }
    })
    .await
    .expect("timeout");

    // a TCP client joins and sends; the WS client receives it
    let tcp = e6irc_client::Connection::connect(&running.addrs[0].to_string())
        .await
        .expect("tcp");
    let mut tcp = tcp;
    tcp.register("tcpclient", "tcp").await.expect("register");
    tcp.send_line("JOIN #ws").await.unwrap();
    loop {
        let m = tcp.next_message().await.unwrap().unwrap();
        if m.command == "366" {
            break;
        }
    }
    tcp.send_line("PRIVMSG #ws :hello over websocket")
        .await
        .unwrap();

    let got = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(Ok(Tung::Text(t))) = ws.next().await {
                if t.contains("PRIVMSG #ws") {
                    return t.to_string();
                }
            } else {
                panic!("closed");
            }
        }
    })
    .await
    .expect("timeout");
    assert!(got.contains("hello over websocket"), "{got}");
    assert!(got.starts_with(":tcpclient!"), "{got}");
}

/// Read text frames until one contains `needle`; panics on close/timeout.
async fn read_until(
    ws: &mut (impl StreamExt<Item = Result<Tung, tokio_tungstenite::tungstenite::Error>> + Unpin),
    needle: &str,
) -> String {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match ws.next().await {
                Some(Ok(Tung::Text(t))) if t.contains(needle) => return t.to_string(),
                Some(Ok(_)) => continue,
                _ => panic!("ws closed before {needle:?}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {needle:?}"))
}

/// A dedicated `websocket = true` listener (no [http] section) serves IRC over
/// WebSocket at the root path, so `ws://addr/` reaches the same core as a raw
/// TCP listener would. This is the surface upstream irctest's websocket suite
/// drives (it connects to `ws://host:port` with no path).
#[tokio::test]
async fn dedicated_ws_listener_serves_irc_at_root() {
    let config = Config {
        server_name: "irc.wsl.example".into(),
        network_name: "WsLNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: true,
        }],
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let addr = running.addrs[0];
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/"))
        .await
        .expect("ws connect at root");
    ws.send(Tung::text("NICK wsroot")).await.unwrap();
    ws.send(Tung::text("USER w 0 * :W")).await.unwrap();
    let welcome = read_until(&mut ws, " 001 ").await;
    assert!(welcome.contains("wsroot"), "{welcome}");
}

/// IRCv3 WebSocket requires exactly one unterminated IRC line per message. An
/// embedded CRLF must reject the whole frame, never execute its second command.
#[tokio::test]
async fn ws_embedded_line_delimiter_cannot_forge_a_second_command() {
    let running = net::start(config()).await.expect("start");
    let http = running.http_addr.expect("http");
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{http}/ws/irc"))
        .await
        .expect("ws connect");
    ws.send(Tung::text("NICK multi\r\nUSER m 0 * :M"))
        .await
        .unwrap();
    let failure = read_until(&mut ws, "INVALID_MESSAGE").await;
    assert!(failure.contains("Malformed line"), "{failure}");
    ws.send(Tung::text("NICK multi")).await.unwrap();
    ws.send(Tung::text("USER m 0 * :M")).await.unwrap();
    let welcome = read_until(&mut ws, " 001 ").await;
    assert!(welcome.contains("multi"), "{welcome}");
}

/// A binary frame is a valid carrier for an IRC line under the ircv3 WS
/// subprotocol; the server must accept it exactly like a text frame.
#[tokio::test]
async fn ws_binary_frame_is_accepted() {
    let running = net::start(config()).await.expect("start");
    let http = running.http_addr.expect("http");
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{http}/ws/irc"))
        .await
        .expect("ws connect");
    ws.send(Tung::binary(b"NICK binclient".to_vec()))
        .await
        .unwrap();
    ws.send(Tung::binary(b"USER b 0 * :B".to_vec()))
        .await
        .unwrap();
    let welcome = read_until(&mut ws, " 001 ").await;
    assert!(welcome.contains("binclient"), "{welcome}");
}

/// An overlong line over WS draws ERR_INPUTTOOLONG (417), the same as the raw
/// TCP path — the frame is bounded and the overlong event is surfaced, never
/// silently truncated.
#[tokio::test]
async fn ws_overlong_line_is_refused() {
    let running = net::start(config()).await.expect("start");
    let http = running.http_addr.expect("http");
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{http}/ws/irc"))
        .await
        .expect("ws connect");
    ws.send(Tung::text("NICK longc")).await.unwrap();
    ws.send(Tung::text("USER l 0 * :L")).await.unwrap();
    let _ = read_until(&mut ws, " 001 ").await;
    // Well over the 512-byte line limit.
    let overlong = format!("PRIVMSG #x :{}", "A".repeat(1024));
    ws.send(Tung::text(overlong)).await.unwrap();
    let reply = read_until(&mut ws, " 417 ").await;
    assert!(reply.contains("417"), "{reply}");
}
