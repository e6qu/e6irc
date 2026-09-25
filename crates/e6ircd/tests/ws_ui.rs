//! e2e for the live web-UI socket (`/ws/ui`): a cookie/bearer-auth'd
//! WebSocket attaches to one of the caller's BNC networks, receives
//! upstream traffic as JSON line events, receives a typed replay-complete
//! boundary, and relays composer input back to the upstream. PG-gated (auth
//! needs the account store).

use e6ircd::config::{BncConfig, Config, DatabaseConfig, HttpConfig, ListenerConfig, NetworkEntry};
use e6ircd::net;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as Tung;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

mod support;

#[path = "support/deadline.rs"]
mod deadline;
#[path = "support/membership.rs"]
mod membership;

/// A full-access personal access token with the default lifetime, minted the
/// way the REST endpoint mints one.
async fn issue_api_token(
    pool: &sqlx::PgPool,
    account: &str,
    label: &str,
) -> Result<String, e6ircd::db::DbError> {
    e6ircd::db::issue_scoped_api_token(
        pool,
        account,
        label,
        e6ircd::identity::ApiTokenScopes::new(e6ircd::identity::ApiTokenScope::ALL)
            .expect("every scope is a non-empty set"),
        e6ircd::identity::ApiTokenLifetimeDays::DEFAULT,
    )
    .await
}

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
    e6ircd::db::create_account_with_contact(&pool, "alice", "s3cr3t", None)
        .await
        .expect("acct");
    let token = issue_api_token(&pool, "alice", "web").await.expect("token");
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
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        networks: vec![NetworkEntry {
            kind: e6ircd::config::NetworkKind::Irc,
            name: "up".into(),
            owner: Some("alice".into()),
            addr: up.to_string(),
            tls: false,
            nick: "alicebnc".into(),
            username: Some("tester".into()),
            realname: Some("alicebnc".into()),
            autojoin: vec!["#lobby".into()],
            buffer_cap: 1000,
            sasl_account: None,
            sasl_password: None,
            server_password: None,
        }],
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }),
        internal_upstreams: e6ircd::egress::InternalUpstreams::Allow,
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let http = running.http_addr.expect("http bound");

    membership::wait_joined(up, "alicebnc", "#lobby").await;

    // a peer on the upstream
    let mut peer = e6irc_client::Connection::connect(&up.to_string())
        .await
        .unwrap();
    peer.register(&e6irc_client::Identity {
        nick: "peer",
        username: "peer",
        realname: "peer",
        server_password: None,
    })
    .await
    .unwrap();
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

    // Initial status and detached-buffer playback end at an explicit typed
    // boundary. The browser waits for this before asking for current NAMES, so
    // a replayed stale NAMES reply can never win an ordering race.
    let (boundary, session) = tokio::time::timeout(deadline::HANG, async {
        let mut session = None;
        loop {
            match ws.next().await {
                Some(Ok(Tung::Text(t))) => {
                    let event: serde_json::Value =
                        serde_json::from_str(&t).expect("initial ws/ui event");
                    if event["t"] == "session" {
                        session = Some(event.clone());
                    }
                    // The replay is read as the session's current nick, so
                    // the session comes before the first replayed line.
                    if event["t"] == "line" {
                        assert!(
                            session.is_some(),
                            "a replayed line preceded the session event: {event}"
                        );
                    }
                    if event["t"] == "snapshot" {
                        return (event, session);
                    }
                }
                Some(Ok(_)) => {}
                _ => panic!("ws/ui closed before the replay boundary"),
            }
        }
    })
    .await
    .expect("timeout waiting for replay boundary");
    assert_eq!(boundary["v"], "complete");
    assert!(
        boundary["cursor"]
            .as_str()
            .is_some_and(|cursor| !cursor.is_empty()),
        "the boundary names the ring position to resume from: {boundary}"
    );
    let session =
        session.expect("the replay boundary must be preceded by authoritative IRC session state");
    assert_eq!(session["nick"], "alicebnc", "{session}");
    assert_eq!(
        session["channels"],
        serde_json::json!(["#lobby"]),
        "{session}"
    );
    // The upstream's own ISUPPORT rides with it, so channel modes are read the
    // network's way even after the ring evicts the 005 lines.
    let isupport = session["isupport"].as_array().expect("isupport tokens");
    assert!(
        isupport.iter().any(|token| token
            .as_str()
            .is_some_and(|token| token.starts_with("PREFIX="))),
        "{session}"
    );

    // upstream -> UI: the peer posts, the UI receives a JSON line event
    // carrying the raw IRC line (the browser client parses it into a buffer).
    peer.send_line("PRIVMSG #lobby :hello web").await.unwrap();
    let event = tokio::time::timeout(deadline::HANG, async {
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
    let raw = v["v"].as_str().expect("line value");
    assert!(
        raw.starts_with("@") && raw.contains("time=") && raw.contains("msgid="),
        "live UI event lost the tags needed to reconcile history: {event}"
    );

    // UI composer -> upstream: text up the socket reaches the peer
    ws.send(Tung::text(
        serde_json::json!({
            "id": "integration-1",
            "target": "#lobby",
            "message": "from web composer",
        })
        .to_string(),
    ))
    .await
    .unwrap();
    let got = tokio::time::timeout(deadline::HANG, async {
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
    let accepted = tokio::time::timeout(deadline::HANG, async {
        loop {
            match ws.next().await {
                Some(Ok(Tung::Text(text))) => {
                    let event: serde_json::Value =
                        serde_json::from_str(&text).expect("composer result event");
                    if event["t"] == "sent" {
                        return event;
                    }
                }
                Some(Ok(_)) => {}
                _ => panic!("ws/ui closed before the composer acknowledgement"),
            }
        }
    })
    .await
    .expect("composer acknowledgement timed out");
    assert_eq!(accepted["v"], "integration-1");

    // Unsupported input is rejected locally without closing a healthy socket.
    ws.send(Tung::binary(b"not a composer frame".to_vec()))
        .await
        .unwrap();
    let binary_rejected = tokio::time::timeout(deadline::HANG, async {
        loop {
            match ws.next().await {
                Some(Ok(Tung::Text(text))) if text.contains("must be text JSON") => return text,
                Some(Ok(_)) => {}
                _ => panic!("ws/ui closed after a binary composer request"),
            }
        }
    })
    .await
    .expect("binary composer rejection was not reported");
    assert!(binary_rejected.contains("must be text JSON"));

    ws.send(Tung::text(
        serde_json::json!({
            "target": "#lobby",
            "message": "must not be sent",
            "extra": true,
        })
        .to_string(),
    ))
    .await
    .unwrap();
    let rejected = tokio::time::timeout(deadline::HANG, async {
        loop {
            match ws.next().await {
                Some(Ok(Tung::Text(text))) if text.contains("invalid composer request") => {
                    return text;
                }
                Some(Ok(_)) => {}
                _ => panic!("ws/ui closed after an invalid composer request"),
            }
        }
    })
    .await
    .expect("composer rejection was not reported");
    assert!(rejected.contains("invalid composer request"));

    ws.send(Tung::text(
        serde_json::json!({
            "id": "integration-2",
            "target": "#lobby",
            "message": "still connected",
        })
        .to_string(),
    ))
    .await
    .unwrap();
    let got = tokio::time::timeout(deadline::HANG, async {
        loop {
            let message = peer.next_message().await.unwrap().unwrap();
            if message.command == "PRIVMSG"
                && message.params.get(1).map(String::as_str) == Some("still connected")
            {
                return message;
            }
        }
    })
    .await
    .expect("valid composer frame after rejection never reached the peer");
    assert!(
        got.source.as_deref().unwrap_or("").starts_with("alicebnc!"),
        "{got:?}"
    );
}

/// Read `/ws/ui` events up to and including the replay boundary.
async fn events_until_snapshot(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Vec<serde_json::Value> {
    tokio::time::timeout(deadline::HANG, async {
        let mut events = Vec::new();
        loop {
            match ws.next().await {
                Some(Ok(Tung::Text(text))) => {
                    let event: serde_json::Value =
                        serde_json::from_str(&text).expect("ws/ui event JSON");
                    let boundary = event["t"] == "snapshot";
                    events.push(event);
                    if boundary {
                        return events;
                    }
                }
                Some(Ok(_)) => {}
                _ => panic!("ws/ui closed before the replay boundary"),
            }
        }
    })
    .await
    .expect("timeout waiting for replay boundary")
}

fn line_values(events: &[serde_json::Value]) -> Vec<&str> {
    events
        .iter()
        .filter(|event| event["t"] == "line")
        .map(|event| event["v"].as_str().expect("line value"))
        .collect()
}

/// A returning socket hands back the cursor of the last line it handled and is
/// replayed exactly the lines after it — never the ones it already showed. A
/// cursor the ring cannot honour is answered with a typed `replay full` and the
/// whole ring, so the client knows to start over instead of guessing.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn ws_ui_resumes_after_a_cursor_and_says_when_it_cannot() {
    let url = support::test_db("ws_ui_resumes_after_a_cursor_and_says_when_it_cannot").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "s3cr3t", None)
        .await
        .expect("acct");
    let token = issue_api_token(&pool, "alice", "web").await.expect("token");
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
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        networks: vec![NetworkEntry {
            kind: e6ircd::config::NetworkKind::Irc,
            name: "up".into(),
            owner: Some("alice".into()),
            addr: up.to_string(),
            tls: false,
            nick: "alicebnc".into(),
            username: Some("tester".into()),
            realname: Some("alicebnc".into()),
            autojoin: vec!["#lobby".into()],
            buffer_cap: 1000,
            sasl_account: None,
            sasl_password: None,
            server_password: None,
        }],
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }),
        internal_upstreams: e6ircd::egress::InternalUpstreams::Allow,
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let http = running.http_addr.expect("http bound");
    membership::wait_joined(up, "alicebnc", "#lobby").await;

    let mut peer = e6irc_client::Connection::connect(&up.to_string())
        .await
        .unwrap();
    peer.register(&e6irc_client::Identity {
        nick: "peer",
        username: "peer",
        realname: "peer",
        server_password: None,
    })
    .await
    .unwrap();
    peer.send_line("JOIN #lobby").await.unwrap();
    loop {
        if peer.next_message().await.unwrap().unwrap().command == "366" {
            break;
        }
    }

    let attach = |query: String| {
        let token = token.clone();
        async move {
            let mut req = format!("ws://{http}/ws/ui?network=up{query}")
                .into_client_request()
                .unwrap();
            req.headers_mut()
                .insert("authorization", format!("Bearer {token}").parse().unwrap());
            tokio_tungstenite::connect_async(req)
                .await
                .expect("ws/ui connect")
                .0
        }
    };

    // First attach: the whole ring, no reset (nothing was presented).
    let mut first = attach(String::new()).await;
    let initial = events_until_snapshot(&mut first).await;
    assert!(
        !initial.iter().any(|event| event["t"] == "replay"),
        "a first attach presented no cursor and is told of no reset: {initial:?}"
    );
    peer.send_line("PRIVMSG #lobby :one").await.unwrap();
    let one = tokio::time::timeout(deadline::HANG, async {
        loop {
            match first.next().await {
                Some(Ok(Tung::Text(text))) if text.contains(":one") => {
                    return serde_json::from_str::<serde_json::Value>(&text).expect("json");
                }
                Some(Ok(_)) => {}
                _ => panic!("ws/ui closed before the line"),
            }
        }
    })
    .await
    .expect("timeout waiting for the first line");
    let cursor = one["cursor"].as_str().expect("every line carries a cursor");
    drop(first);
    peer.send_line("PRIVMSG #lobby :two").await.unwrap();

    // Resume: only what came after the cursor, and no reset. Nothing is
    // attached while `two` travels to the driver, so resume until the replay
    // includes it (an earlier resume, before it arrived, replays nothing new).
    let (resumed, events) = tokio::time::timeout(deadline::HANG, async {
        loop {
            let mut resumed = attach(format!("&after={cursor}")).await;
            let events = events_until_snapshot(&mut resumed).await;
            if line_values(&events)
                .iter()
                .any(|line| line.contains("PRIVMSG #lobby :two"))
            {
                return (resumed, events);
            }
            drop(resumed);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the line after the cursor is never replayed");
    let lines = line_values(&events);
    assert!(
        !lines
            .iter()
            .any(|line| line.contains("PRIVMSG #lobby :one")),
        "the line the cursor names is not shown again: {lines:?}"
    );
    assert!(
        !events.iter().any(|event| event["t"] == "replay"),
        "an honoured cursor is not a reset: {events:?}"
    );
    let boundary_cursor = events
        .last()
        .and_then(|event| event["cursor"].as_str())
        .expect("boundary cursor");
    assert_ne!(
        boundary_cursor, cursor,
        "the boundary names the newest position"
    );
    drop(resumed);

    // A stale cursor (another ring's epoch) and a malformed one: the client is
    // told to start over, then gets everything.
    for stale in ["1:1", "not-a-cursor"] {
        let mut socket = attach(format!("&after={stale}")).await;
        let events = events_until_snapshot(&mut socket).await;
        let first_after_status = events
            .iter()
            .find(|event| event["t"] != "status")
            .expect("events after the status");
        assert_eq!(
            first_after_status,
            &serde_json::json!({ "t": "replay", "v": "full" }),
            "{stale}: {events:?}"
        );
        let lines = line_values(&events);
        assert!(
            lines
                .iter()
                .any(|line| line.contains("PRIVMSG #lobby :one"))
                && lines
                    .iter()
                    .any(|line| line.contains("PRIVMSG #lobby :two")),
            "{stale}: the whole ring follows the reset: {lines:?}"
        );
    }
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
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }),
        internal_upstreams: e6ircd::egress::InternalUpstreams::Allow,
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
    e6ircd::db::create_account_with_contact(&pool, "alice", "s3cr3t", None)
        .await
        .expect("acct");
    let token = issue_api_token(&pool, "alice", "web").await.expect("token");
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
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }),
        internal_upstreams: e6ircd::egress::InternalUpstreams::Allow,
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");

    // Create the network via REST (a config network has no DB row and can't be
    // deleted; a REST-created one can).
    let body = format!(
        r#"{{"kind":"irc","name":"up","addr":"{up}","tls":false,"nick":"alicebnc","username":"alicebnc","realname":"Alice BNC","autojoin":[]}}"#
    );
    let (status, _) = http_req(
        http,
        &format!(
            "POST /api/v1/me/networks HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
    .await;
    assert_eq!(status, 201, "network create");

    // Attach the web UI to it.
    let mut req = format!("ws://{http}/ws/ui?network=up")
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    let (mut ws, _) = tokio_tungstenite::connect_async(req)
        .await
        .expect("ws/ui connect");
    // Read through the attach's replay boundary, so every event after it is
    // caused by the removal below.
    events_until_snapshot(&mut ws).await;

    // Remove the network.
    let (status, _) = http_req(
        http,
        &format!(
            "DELETE /api/v1/me/networks/up HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_eq!(status, 204, "network delete");

    // The socket must send a typed terminal status and detach promptly. The
    // browser uses this event to stop reconnecting a removed/disabled network.
    let detached = tokio::time::timeout(deadline::HANG, async {
        loop {
            match ws.next().await {
                Some(Ok(Tung::Text(t))) => {
                    let event: serde_json::Value = serde_json::from_str(&t).expect("JSON event");
                    if event["t"] == "status" && event["v"] == "unavailable" {
                        return true;
                    }
                }
                Some(Ok(_)) => {}
                None | Some(Err(_)) => panic!("socket closed without terminal status"),
            }
        }
    })
    .await
    .expect("ws/ui must detach, not dangle on the removed network");
    assert!(detached);
}
