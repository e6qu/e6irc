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
