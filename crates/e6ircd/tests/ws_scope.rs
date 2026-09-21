//! e2e for who may open and who may send on the live web-UI socket
//! (`/ws/ui`): the upgrade is a `GET`, so neither the method-to-scope mapping
//! nor the browser's same-origin policy guards it — the route has to. PG-gated
//! (auth needs the account store).

use e6ircd::config::{BncConfig, Config, DatabaseConfig, HttpConfig, ListenerConfig, NetworkEntry};
use e6ircd::identity::{ApiTokenLifetimeDays, ApiTokenScope, ApiTokenScopes};
use e6ircd::net;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as Tung;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

mod support;

type UiSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

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

/// A bouncer whose account `alice` owns one network, `up`, on `upstream`.
async fn bouncer(
    url: String,
    upstream: std::net::SocketAddr,
    public_url: Option<&str>,
) -> std::net::SocketAddr {
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
            public_url: public_url.map(Into::into),
            secure_cookies: false,
            admin_accounts: vec![],
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
        }),
        networks: vec![NetworkEntry {
            kind: e6ircd::config::NetworkKind::Irc,
            name: "up".into(),
            owner: Some("alice".into()),
            addr: upstream.to_string(),
            tls: false,
            nick: "alicebnc".into(),
            username: Some("tester".into()),
            realname: Some("alicebnc".into()),
            autojoin: vec!["#lobby".into()],
            buffer_cap: 1000,
            sasl_account: None,
            sasl_password: None,
        }],
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
        }),
        internal_upstreams: e6ircd::egress::InternalUpstreams::Allow,
        ..Config::default()
    };
    net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http bound")
}

/// Open `/ws/ui` with the given request headers and read up to the replay
/// boundary, so the socket is attached and the driver has joined upstream.
async fn attach(http: std::net::SocketAddr, headers: &[(&'static str, String)]) -> UiSocket {
    let mut request = format!("ws://{http}/ws/ui?network=up")
        .into_client_request()
        .unwrap();
    for (name, value) in headers {
        request.headers_mut().insert(*name, value.parse().unwrap());
    }
    let (mut socket, _) = tokio_tungstenite::connect_async(request)
        .await
        .expect("ws/ui connect");
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match socket.next().await {
                Some(Ok(Tung::Text(text))) if text.contains("\"snapshot\"") => return,
                Some(Ok(_)) => {}
                _ => panic!("ws/ui closed before the replay boundary"),
            }
        }
    })
    .await
    .expect("replay boundary");
    socket
}

/// Send one composer frame and return the typed result event that answers it.
async fn compose(socket: &mut UiSocket, id: &str, message: &str) -> serde_json::Value {
    socket
        .send(Tung::text(
            serde_json::json!({ "id": id, "target": "#lobby", "message": message }).to_string(),
        ))
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match socket.next().await {
                Some(Ok(Tung::Text(text))) => {
                    let event: serde_json::Value = serde_json::from_str(&text).expect("UI event");
                    if event["v"] == id && (event["t"] == "sent" || event["t"] == "send-error") {
                        return event;
                    }
                }
                Some(Ok(_)) => {}
                _ => panic!("ws/ui closed before the composer result"),
            }
        }
    })
    .await
    .expect("composer result")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn ui_socket_sending_requires_write_authority() {
    let url = support::test_db("ui_socket_sending_requires_write_authority").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "s3cr3t", None)
        .await
        .expect("account");
    let lifetime = ApiTokenLifetimeDays::new(7).expect("lifetime");
    let reader = e6ircd::db::issue_scoped_api_token(
        &pool,
        "alice",
        "dashboard",
        ApiTokenScopes::new([ApiTokenScope::Read]).expect("scope"),
        lifetime,
    )
    .await
    .expect("read token");
    let writer = e6ircd::db::issue_scoped_api_token(
        &pool,
        "alice",
        "client",
        ApiTokenScopes::new([ApiTokenScope::Read, ApiTokenScope::Write]).expect("scopes"),
        lifetime,
    )
    .await
    .expect("read/write token");
    let session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("session");
    drop(pool);

    let up = upstream().await;
    let http = bouncer(url, up, None).await;
    let mut peer = e6irc_client::Connection::connect(&up.to_string())
        .await
        .unwrap();
    peer.register(&e6irc_client::Identity {
        nick: "peer",
        username: "peer",
        realname: "peer",
    })
    .await
    .unwrap();
    peer.send_line("JOIN #lobby").await.unwrap();

    let mut read_only = attach(http, &[("authorization", format!("Bearer {reader}"))]).await;
    for (id, message) in [
        ("read-1", "plain text from a reader"),
        ("read-2", "/raw PRIVMSG #lobby :raw text from a reader"),
        ("read-3", "/quote PRIVMSG #lobby :quoted text from a reader"),
    ] {
        let refused = compose(&mut read_only, id, message).await;
        assert_eq!(refused["t"], "send-error", "{refused}");
        assert!(
            refused["message"]
                .as_str()
                .is_some_and(|message| message.contains("write")),
            "{refused}"
        );
    }

    let mut read_write = attach(http, &[("authorization", format!("Bearer {writer}"))]).await;
    let sent = compose(&mut read_write, "write-1", "from a writer").await;
    assert_eq!(sent["t"], "sent", "{sent}");
    let mut browser = attach(http, &[("cookie", format!("e6irc_session={session}"))]).await;
    let sent = compose(&mut browser, "session-1", "from a browser").await;
    assert_eq!(sent["t"], "sent", "{sent}");

    // The upstream delivers in order, so everything the peer hears from the
    // bouncer up to the browser's line is everything the bouncer ever sent.
    let heard = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut heard = Vec::new();
        loop {
            let message = peer.next_message().await.unwrap().unwrap();
            if message.command == "PRIVMSG" {
                let text = message.params.get(1).cloned().unwrap_or_default();
                let last = text == "from a browser";
                heard.push(text);
                if last {
                    return heard;
                }
            }
        }
    })
    .await
    .expect("the peer never heard the browser");
    assert_eq!(heard, ["from a writer", "from a browser"]);
}

/// The always-on upstream session is the bouncer's to keep, and the attach
/// layer's own commands are answered by the attach layer. None of them is the
/// composer's to send upstream, however it is spelled.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn the_composer_cannot_end_or_renegotiate_the_upstream_session() {
    let up = upstream().await;
    let (url, cookie) =
        database_with_session("the_composer_cannot_end_or_renegotiate_the_upstream_session").await;
    let http = bouncer(url, up, None).await;
    let mut peer = e6irc_client::Connection::connect(&up.to_string())
        .await
        .unwrap();
    peer.register(&e6irc_client::Identity {
        nick: "peer",
        username: "peer",
        realname: "peer",
    })
    .await
    .unwrap();
    peer.send_line("JOIN #lobby").await.unwrap();

    let mut browser = attach(http, &[cookie]).await;
    for (index, message) in [
        "/quit",
        "/quit gone for good",
        "/raw QUIT :gone for good",
        "/quote quit",
        "/raw @label=x :alicebnc QUIT",
        "/ping upstream",
        "/raw PONG :token",
        "/raw CAP LS 302",
        "/cap req :sasl",
        "/raw AUTHENTICATE PLAIN",
        "/raw CHATHISTORY LATEST #lobby * 10",
        "/markread #lobby",
    ]
    .into_iter()
    .enumerate()
    {
        let refused = compose(&mut browser, &format!("refused-{index}"), message).await;
        assert_eq!(refused["t"], "send-error", "{message}: {refused}");
        assert!(
            refused["message"]
                .as_str()
                .is_some_and(|text| text.contains("othing was sent")),
            "{message}: {refused}"
        );
    }
    let sent = compose(&mut browser, "still-here", "still here").await;
    assert_eq!(sent["t"], "sent", "{sent}");

    // The upstream delivers in order: had any refused line reached it, the
    // session would have quit before this text, and the peer would never hear it.
    let heard = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut heard = Vec::new();
        loop {
            let message = peer.next_message().await.unwrap().unwrap();
            let from_bouncer = message
                .source
                .as_deref()
                .is_some_and(|prefix| prefix.starts_with("alicebnc!"));
            if from_bouncer && message.command != "JOIN" {
                let last = message.command == "PRIVMSG";
                heard.push(message.command.clone());
                if last {
                    return heard;
                }
            }
        }
    })
    .await
    .expect("the peer never heard the browser");
    assert_eq!(heard, ["PRIVMSG"]);
}

/// The HTTP status an upgrade attempt with these headers is refused with, or
/// `101` when it is accepted.
async fn upgrade_status(http: std::net::SocketAddr, headers: &[(&'static str, String)]) -> u16 {
    let mut request = format!("ws://{http}/ws/ui?network=up")
        .into_client_request()
        .unwrap();
    for (name, value) in headers {
        request.headers_mut().insert(*name, value.parse().unwrap());
    }
    match tokio_tungstenite::connect_async(request).await {
        Ok(_) => 101,
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => response.status().as_u16(),
        Err(error) => panic!("upgrade failed without an HTTP answer: {error}"),
    }
}

/// A fresh database holding `alice` and one browser session, as the database
/// URL and the session's `Cookie` header.
async fn database_with_session(database: &str) -> (String, (&'static str, String)) {
    let url = support::test_db(database).await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "s3cr3t", None)
        .await
        .expect("account");
    let session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("session");
    (url, ("cookie", format!("e6irc_session={session}")))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn ui_socket_refuses_a_browser_origin_it_cannot_verify() {
    let up = upstream().await;
    let (url, cookie) =
        database_with_session("ui_socket_refuses_a_browser_origin_it_cannot_verify").await;

    // No public URL: the only origin the server can vouch for is the one the
    // browser addressed, which is the `Host` it sent.
    let http = bouncer(url, up, None).await;
    for foreign in ["http://evil.example", "http://sibling.127.0.0.1", "null"] {
        assert_eq!(
            upgrade_status(http, &[cookie.clone(), ("origin", foreign.into())]).await,
            403,
            "{foreign}"
        );
    }
    assert_eq!(
        upgrade_status(
            http,
            &[cookie.clone(), ("origin", format!("http://{http}"))]
        )
        .await,
        101
    );
    assert_eq!(
        upgrade_status(http, std::slice::from_ref(&cookie)).await,
        101,
        "a client that sends no Origin is not a browser and carries no ambient cookie"
    );

    // A configured public URL is the origin, whatever `Host` a proxy forwards.
    // The public URL is a stored setting, so this server gets its own database.
    let (url, cookie) = database_with_session("ui_socket_origin_is_the_public_url").await;
    let http = bouncer(url, up, Some("http://chat.example")).await;
    assert_eq!(
        upgrade_status(
            http,
            &[cookie.clone(), ("origin", format!("http://{http}"))]
        )
        .await,
        403
    );
    assert_eq!(
        upgrade_status(
            http,
            &[cookie.clone(), ("origin", "http://chat.example".into())]
        )
        .await,
        101
    );
}
