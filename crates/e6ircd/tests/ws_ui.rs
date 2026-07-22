//! e2e for the live web-UI socket (`/ws/ui`): a cookie/bearer-auth'd
//! WebSocket attaches to one of the caller's BNC networks, receives
//! upstream traffic as HTML fragments, and relays composer input back to
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
        }],
        ..Config::default()
    };
    net::start(cfg).await.expect("upstream start").addrs[0]
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn ws_ui_streams_fragments_and_relays_composer() {
    let url = support::test_db("ws_ui_streams_fragments_and_relays_composer").await;
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

    // upstream -> UI: the peer posts, the UI receives an HTML fragment
    peer.send_line("PRIVMSG #lobby :hello web").await.unwrap();
    let fragment = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match ws.next().await {
                Some(Ok(Tung::Text(t))) if t.contains("hello web") => return t.to_string(),
                Some(Ok(_)) => {}
                _ => panic!("ws/ui closed before the message"),
            }
        }
    })
    .await
    .expect("timeout waiting for fragment");
    assert!(
        fragment.contains("hx-swap-oob=\"beforeend:#buffer\""),
        "not an OOB fragment: {fragment}"
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
