//! e2e for the live web-UI socket (`/ws/ui`): a cookie/bearer-auth'd
//! WebSocket attaches to one of the caller's BNC networks, receives
//! upstream traffic as JSON line events, and relays composer input back to
//! the upstream. PG-gated (auth needs the account store).

use e6ircd::config::{BncConfig, Config, DatabaseConfig, HttpConfig, ListenerConfig, NetworkEntry};
use e6ircd::net;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as Tung;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

mod support;

async fn upstream() -> std::net::SocketAddr {
    let cfg = Config {
        server_name: "irc.up.example".into(),
        network_name: "Up".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        ..Config::default()
    };
    net::start(cfg).await.expect("upstream start").addrs[0]
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn ws_ui_streams_json_events_and_relays_composer() {
    let url = support::test_db("ws_ui_streams_json_events_and_relays_composer").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account(&pool, "alice", "s3cr3t")
        .await
        .expect("acct");
    let token = e6ircd::db::issue_api_token(&pool, "alice", "web")
        .await
        .expect("token");
    drop(pool);

    let up = upstream().await;

    let config = Config {
        server_name: "irc.web.example".into(),
        network_name: "Web".into(),
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
        database: Some(DatabaseConfig { url }),
        networks: vec![NetworkEntry {
            kind: Default::default(),
            name: "up".into(),
            owner: Some("alice".into()),
            addr: up.to_string(),
            tls: false,
            nick: "alicebnc".into(),
            realname: None,
            autojoin: vec!["#lobby".into()],
            buffer_cap: 1000,
            sasl_account: None,
            sasl_password: None,
        }],
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
        }),
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let http = running.http_addr.expect("http bound");

    // let the driver connect + join upstream
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    // a peer on the upstream
    let mut peer = e6irc_client::Connection::connect(&up.to_string())
        .await
        .unwrap();
    peer.register("peer", "peer").await.unwrap();
    peer.send_line("JOIN #lobby").await.unwrap();
    loop {
        if peer.next_message().await.unwrap().unwrap().command == "366" {
            break;
        }
    }

    // open the UI socket with bearer auth
    let mut req = format!("ws://{http}/ws/ui?network=up")
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    let (mut ws, _resp) = tokio_tungstenite::connect_async(req)
        .await
        .expect("ws/ui connect");

    // upstream -> UI: the peer posts, the UI receives a JSON line event
    // carrying the raw IRC line (the browser client parses it into a buffer).
    peer.send_line("PRIVMSG #lobby :hello web").await.unwrap();
    let event = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match ws.next().await {
                Some(Ok(Tung::Text(t))) if t.contains("hello web") => return t.to_string(),
                Some(Ok(_)) => {}
                _ => panic!("ws/ui closed before the message"),
            }
        }
    })
    .await
    .expect("timeout waiting for line event");
    let v: serde_json::Value = serde_json::from_str(&event).expect("json event");
    assert_eq!(v["t"], "line", "not a line event: {event}");
    assert!(
        v["v"]
            .as_str()
            .unwrap_or("")
            .contains("PRIVMSG #lobby :hello web"),
        "line event missing the raw line: {event}"
    );

    // UI composer -> upstream: text up the socket reaches the peer
    ws.send(Tung::text("PRIVMSG #lobby :from web composer"))
        .await
        .unwrap();
    let got = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let m = peer.next_message().await.unwrap().unwrap();
            if m.command == "PRIVMSG"
                && m.params.get(1).map(String::as_str) == Some("from web composer")
            {
                return m;
            }
        }
    })
    .await
    .expect("peer never got the composer message");
    assert!(
        got.source.as_deref().unwrap_or("").starts_with("alicebnc!"),
        "{got:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn ws_ui_requires_authentication() {
    let url = support::test_db("ws_ui_requires_authentication").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    drop(pool);

    let config = Config {
        server_name: "irc.web.example".into(),
        network_name: "Web".into(),
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
        database: Some(DatabaseConfig { url }),
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
        }),
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let http = running.http_addr.expect("http bound");

    // No Authorization header: the upgrade must be refused.
    let result = tokio_tungstenite::connect_async(format!("ws://{http}/ws/ui?network=up")).await;
    assert!(result.is_err(), "unauthenticated ws/ui must be refused");
}

/// One raw HTTP/1.1 request/response over a fresh socket; returns (status, body).
async fn http_req(addr: std::net::SocketAddr, req: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect");
    s.write_all(req.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.expect("read");
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = text.split_once("\r\n\r\n").expect("split");
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|c| c.parse().ok())
        .expect("status");
    (status, body.to_string())
}

/// When a network the web UI is attached to is removed, the socket must be told
/// and detach — not dangle forever on a dead network (the handle keeps the
/// event broadcast open, so `Closed` alone never fires). Regression: `ws_ui_conn`
/// now watches the stop signal, mirroring the raw-IRC `attach` path.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn ws_ui_detaches_when_its_network_is_removed() {
    let url = support::test_db("ws_ui_detaches_when_its_network_is_removed").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account(&pool, "alice", "s3cr3t")
        .await
        .expect("acct");
    let token = e6ircd::db::issue_api_token(&pool, "alice", "web")
        .await
        .expect("token");
    drop(pool);

    let up = upstream().await;
    let config = Config {
        server_name: "irc.web.example".into(),
        network_name: "Web".into(),
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
        database: Some(DatabaseConfig { url }),
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
        }),
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");

    // Create the network via REST (a config network has no DB row and can't be
    // deleted; a REST-created one can).
    let body = format!(r#"{{"name":"up","addr":"{up}","nick":"alicebnc"}}"#);
    let (status, _) = http_req(
        http,
        &format!(
            "POST /api/v1/me/networks HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
    .await;
    assert_eq!(status, 201, "network create");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Attach the web UI to it.
    let mut req = format!("ws://{http}/ws/ui?network=up")
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    let (mut ws, _) = tokio_tungstenite::connect_async(req)
        .await
        .expect("ws/ui connect");
    // Drain the initial status/backlog event.
    let _ = tokio::time::timeout(std::time::Duration::from_millis(300), ws.next()).await;

    // Remove the network.
    let (status, _) = http_req(
        http,
        &format!(
            "DELETE /api/v1/me/networks/up HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_eq!(status, 204, "network delete");

    // The socket must detach promptly — either a "network removed" event or a
    // clean close — not hang open forever.
    let detached = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match ws.next().await {
                Some(Ok(Tung::Text(t))) if t.contains("network removed") => return true,
                Some(Ok(_)) => {}
                None | Some(Err(_)) => return true, // socket closed
            }
        }
    })
    .await
    .expect("ws/ui must detach, not dangle on the removed network");
    assert!(detached);
}
