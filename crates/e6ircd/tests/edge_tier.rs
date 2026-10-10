//! The core link between processes (DESIGN §19.2), driven through the
//! library: a core in edge mode (`[edge_link]`) and an edge
//! (`e6irc_edge::process`) in this test process, linked over real TCP with
//! mutual TLS. What the core refuses at `Hello` and says in `Welcome`; and,
//! with PostgreSQL, the session kinds that reach the bouncer — a live chat
//! socket and an attach — through an edge, the roster that keeps an edge's
//! slot across cores, and the console showing the edges' listeners
//! read-only.

mod support;

#[path = "support/deadline.rs"]
mod deadline;
#[path = "support/membership.rs"]
mod membership;

use std::net::SocketAddr;
use std::path::PathBuf;

use e6irc_edge::core_link::tls::{LinkCredentialFiles, LinkCredentials};
use e6irc_link::{EdgeName, Hello, Role, Slot, Stream, VersionRange};
use e6ircd::config::{Config, DatabaseConfig, HttpConfig, NetworkEntry};
use e6ircd::edge_link::EdgeLinkConfig;
use e6ircd::net;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as Frame;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

/// A scratch directory with a deployment's link credentials.
struct Credentials {
    dir: PathBuf,
}

impl Credentials {
    fn new(test: &str, edges: &[&str]) -> Self {
        let dir =
            std::env::temp_dir().join(format!("e6irc-edge-tier-{test}-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&dir));
        e6ircd::edge_credentials::init(&dir).expect("init");
        for edge in edges {
            e6ircd::edge_credentials::issue(&dir, &EdgeName::new(edge).expect("name"))
                .expect("issue");
        }
        Self { dir }
    }

    fn core(&self) -> LinkCredentialFiles {
        LinkCredentialFiles {
            ca: self
                .dir
                .join(e6ircd::edge_credentials::AUTHORITY_CERTIFICATE),
            cert: self.dir.join(e6ircd::edge_credentials::CORE_CERTIFICATE),
            key: self.dir.join(e6ircd::edge_credentials::CORE_KEY),
        }
    }

    fn edge(&self, name: &str) -> LinkCredentialFiles {
        let (cert, key) = e6ircd::edge_credentials::edge_files(&EdgeName::new(name).expect("name"));
        LinkCredentialFiles {
            ca: self
                .dir
                .join(e6ircd::edge_credentials::AUTHORITY_CERTIFICATE),
            cert: self.dir.join(cert),
            key: self.dir.join(key),
        }
    }
}

impl Drop for Credentials {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.dir));
    }
}

/// A core in edge mode, its link on `link`, with no database.
fn core_config(credentials: &Credentials, link: &str) -> Config {
    Config {
        server_name: "irc.tier.test".into(),
        network_name: "TierNet".into(),
        edge_link: Some(EdgeLinkConfig {
            addr: link.parse().expect("address"),
            credentials: credentials.core(),
        }),
        ..Config::default()
    }
}

/// Present `hello` on a new link connection to `core` as `edge`: the core's
/// answer, `Welcome` or its refusal's text.
async fn say_hello(
    core: SocketAddr,
    credentials: &LinkCredentialFiles,
    hello: Hello,
) -> Result<e6irc_link::Welcome, String> {
    e6irc_edge::certificate::install_crypto_provider();
    let connector = LinkCredentials::load(credentials)
        .expect("credentials")
        .edge_connector()
        .expect("connector");
    let tcp = tokio::net::TcpStream::connect(core).await.expect("connect");
    let mut tls = connector
        .connect(e6irc_edge::core_link::tls::core_server_name(), tcp)
        .await
        .map_err(|error| format!("TLS: {error}"))?;
    e6irc_edge::core_link::remote::handshake(&mut tls, hello).await
}

fn hello(edge: &str) -> Hello {
    Hello {
        versions: VersionRange::spoken(),
        role: Role::Serving,
        edge: EdgeName::new(edge).expect("name"),
        stream: Stream::Sessions { index: 0 },
        slot: None,
        highest_epoch: 0,
        listeners: Vec::new(),
        cut: None,
    }
}

/// `Welcome` gives the edge the terms it follows, and `Hello` is refused by
/// name for each thing a core cannot link with: versions it does not speak
/// (naming both sides' and which to upgrade), the observer role (the warm
/// standby is not in this release), an edge whose certificate names another
/// edge, an edge that already accepted a newer epoch than this core's (this
/// core lost the lease), and a stream of a link that does not exist.
#[tokio::test(flavor = "multi_thread")]
async fn the_core_welcomes_with_its_terms_and_refuses_each_hello_it_cannot_link_by_name() {
    let credentials = Credentials::new("hello", &["edge-a", "edge-b"]);
    let mut config = core_config(&credentials, "127.0.0.1:0");
    config.core_queue = 64;
    config.sendq_bytes = 100_000;
    config.limits.max_connections_per_ip = Some(3);
    config.limits.trusted_proxies = vec!["10.0.0.0/8".parse().expect("network")];
    let running = net::start(config).await.expect("start");
    let link = running.edge_link_addr.expect("edge mode binds the link");

    let welcome = say_hello(link, &credentials.edge("edge-a"), hello("edge-a"))
        .await
        .expect("welcomed");
    assert_eq!(welcome.version, e6irc_link::LINK_VERSION);
    assert_eq!(welcome.epoch, 0, "no database: no lease epoch");
    assert_eq!(welcome.slot, Slot::new(1).expect("slot"));
    assert_eq!(welcome.streams, 1);
    assert_eq!(welcome.terms.sendq_bytes, 100_000);
    assert_eq!(welcome.terms.max_connections_per_ip, Some(3));
    assert_eq!(welcome.terms.line_credit, 64);
    assert_eq!(
        welcome.terms.trusted_proxies,
        vec![("10.0.0.0".parse().expect("address"), 8)]
    );
    assert!(welcome.terms.command_flood.is_some());
    // A second edge gets a slot of its own.
    let second = say_hello(link, &credentials.edge("edge-b"), hello("edge-b"))
        .await
        .expect("welcomed");
    assert_eq!(second.slot, Slot::new(2).expect("slot"));
    // An edge of the release before speaks version 1 only: the core speaks it
    // too, and admits it to serve at once, as that version knows no other way.
    let older = say_hello(
        link,
        &credentials.edge("edge-b"),
        Hello {
            versions: VersionRange::new(1, 1).expect("range"),
            ..hello("edge-b")
        },
    )
    .await
    .expect("welcomed");
    assert_eq!(older.version, 1);
    assert_eq!(older.admission, e6irc_link::Admission::Serve);
    assert_eq!(e6irc_link::OLDEST_SPOKEN, e6irc_link::LINK_VERSION - 1);

    let refused = |result: Result<e6irc_link::Welcome, String>| result.expect_err("refused");
    let too_new = VersionRange::new(e6irc_link::LINK_VERSION + 1, e6irc_link::LINK_VERSION + 2)
        .expect("range");
    let text = refused(
        say_hello(
            link,
            &credentials.edge("edge-a"),
            Hello {
                versions: too_new,
                ..hello("edge-a")
            },
        )
        .await,
    );
    assert!(text.contains("version mismatch"), "{text}");
    assert!(text.contains("upgrade the core"), "{text}");

    let text = refused(
        say_hello(
            link,
            &credentials.edge("edge-a"),
            Hello {
                role: Role::Observer,
                ..hello("edge-a")
            },
        )
        .await,
    );
    assert!(text.contains("observer"), "{text}");

    let text = refused(say_hello(link, &credentials.edge("edge-b"), hello("edge-a")).await);
    assert!(text.contains("not issued for edge edge-a"), "{text}");

    let text = refused(
        say_hello(
            link,
            &credentials.edge("edge-a"),
            Hello {
                highest_epoch: 4,
                ..hello("edge-a")
            },
        )
        .await,
    );
    assert!(text.contains("no longer holds the lease"), "{text}");

    let text = refused(
        say_hello(
            link,
            &credentials.edge("edge-a"),
            Hello {
                stream: Stream::Sessions { index: 1 },
                slot: Slot::new(1),
                ..hello("edge-a")
            },
        )
        .await,
    );
    assert!(text.contains("no stream 1"), "{text}");
    let text = refused(
        say_hello(
            link,
            &credentials.edge("edge-a"),
            Hello {
                stream: Stream::Http,
                slot: Slot::new(9),
                ..hello("edge-a")
            },
        )
        .await,
    );
    assert!(text.contains("no link to this core"), "{text}");
    drop(running);
}

/// A port that was free a moment ago.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("address")
        .port()
}

/// An edge running in this process, with an IRC listener: its web and attach
/// listeners' addresses, and its stop.
struct Edge {
    web: SocketAddr,
    attach: SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Edge {
    async fn start(credentials: &Credentials, name: &str, core: SocketAddr) -> Self {
        let address =
            |port: u16| -> SocketAddr { format!("127.0.0.1:{port}").parse().expect("address") };
        let (irc, web, attach) = (
            address(free_port()),
            address(free_port()),
            address(free_port()),
        );
        let config: e6irc_edge::process::EdgeConfig = toml::from_str(&format!(
            "[edge]\n\
             name = \"{name}\"\n\
             core = [\"{core}\"]\n\
             ca = '{}'\n\
             cert = '{}'\n\
             key = '{}'\n\
             [[listeners]]\n\
             addr = \"{irc}\"\n\
             [http]\n\
             addr = \"{web}\"\n\
             [attach]\n\
             addr = \"{attach}\"\n",
            credentials.edge(name).ca.display(),
            credentials.edge(name).cert.display(),
            credentials.edge(name).key.display(),
        ))
        .expect("an edge configuration");
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(e6irc_edge::process::run(
            config,
            async move {
                drop(stopped.await);
            },
            None,
        ));
        let edge = Self {
            web,
            attach,
            stop: Some(stop),
            task,
        };
        edge.until_accepting().await;
        edge
    }

    /// Wait until the edge accepts: it binds at once, and answers its own
    /// `/healthz` only once it has linked and serves.
    async fn until_accepting(&self) {
        tokio::time::timeout(deadline::HANG, async {
            loop {
                if let Ok((200, _)) = get(self.web, "/healthz", None).await {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the edge links and accepts");
    }
}

impl Drop for Edge {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            // An edge that already stopped needs no telling.
            stop.send(()).unwrap_or(());
        }
        self.task.abort();
    }
}

/// One HTTP/1.1 request, bearer-authenticated when `token` is given.
async fn request(
    address: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &str,
) -> std::io::Result<(u16, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    let authorization = token
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    stream
        .write_all(
            format!(
                "{method} {path} HTTP/1.1\r\nHost: t\r\n{authorization}Content-Type: \
                 application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await?;
    let mut response = Vec::new();
    tokio::time::timeout(deadline::HANG, stream.read_to_end(&mut response))
        .await
        .map_err(|_| std::io::Error::other("no answer"))??;
    let text = String::from_utf8_lossy(&response).into_owned();
    let status = text
        .get(9..12)
        .and_then(|status| status.parse().ok())
        .ok_or_else(|| std::io::Error::other(format!("not HTTP: {text:?}")))?;
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    Ok((status, body))
}

async fn get(
    address: SocketAddr,
    path: &str,
    token: Option<&str>,
) -> std::io::Result<(u16, String)> {
    request(address, "GET", path, token, "").await
}

/// A full-access personal access token, minted as the REST endpoint does.
async fn token(pool: &sqlx::PgPool, account: &str) -> String {
    e6ircd::db::issue_scoped_api_token(
        pool,
        account,
        "edge-tier",
        e6ircd::identity::ApiTokenScopes::new(e6ircd::identity::ApiTokenScope::ALL)
            .expect("every scope"),
        e6ircd::identity::ApiTokenLifetimeDays::DEFAULT,
    )
    .await
    .expect("a token")
}

/// A single-process server for the bouncer's upstream.
async fn upstream() -> SocketAddr {
    let config = Config {
        server_name: "irc.up.example".into(),
        network_name: "Up".into(),
        listeners: vec![e6ircd::config::ListenerConfig {
            addr: "127.0.0.1:0".parse().expect("address"),
            tls: None,
            websocket: false,
        }],
        ..Config::default()
    };
    net::start(config).await.expect("upstream").addrs[0]
}

/// A database-backed core in edge mode, with alice's network on `up` and
/// `root` a configured administrator.
async fn database_core(
    credentials: &Credentials,
    url: e6ircd::db::DatabaseUrl,
    link: &str,
    up: SocketAddr,
) -> net::Running {
    let mut config = core_config(credentials, link);
    config.database = Some(DatabaseConfig {
        url,
        startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
        max_connections: None,
    });
    config.http = Some(HttpConfig {
        addr: "127.0.0.1:0".parse().expect("address"),
        public_url: None,
        secure_cookies: false,
        admin_accounts: vec!["root".into()],
        hsts_include_subdomains: false,
    });
    config.networks = vec![NetworkEntry {
        kind: e6ircd::config::NetworkKind::Irc,
        name: "up".into(),
        owner: Some("alice".into()),
        addr: up.to_string(),
        tls: false,
        nick: "alicebnc".into(),
        username: Some("alice".into()),
        realname: Some("alicebnc".into()),
        autojoin: vec!["#lobby".into()],
        buffer_cap: 1000,
        sasl_account: None,
        sasl_password: None,
        server_password: None,
    }];
    config.internal_upstreams = e6ircd::egress::InternalUpstreams::Allow;
    net::start(config).await.expect("start the core")
}

async fn peer_on(up: SocketAddr) -> e6irc_client::Connection {
    let mut peer = e6irc_client::Connection::connect(&up.to_string())
        .await
        .expect("connect");
    peer.register(&e6irc_client::Identity {
        nick: "peer",
        username: "peer",
        realname: "peer",
        server_password: None,
    })
    .await
    .expect("register");
    peer.send_line("JOIN #lobby").await.expect("join");
    loop {
        if peer
            .next_message()
            .await
            .expect("read")
            .expect("a line")
            .command
            == "366"
        {
            return peer;
        }
    }
}

/// The session kinds that reach the bouncer, through an edge: a live chat
/// socket — upgraded by the edge once the core authorized it, its messages
/// and output carried by the link — and a bouncer attach on the edge's attach
/// listener. Both reach the upstream and hear from it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn a_live_chat_socket_and_an_attach_reach_the_bouncer_through_an_edge() {
    let url =
        support::test_db("a_live_chat_socket_and_an_attach_reach_the_bouncer_through_an_edge")
            .await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "s3cr3t", None)
        .await
        .expect("account");
    let alice = token(&pool, "alice").await;
    let up = upstream().await;
    let credentials = Credentials::new("bouncer", &["edge-a"]);
    let core = database_core(&credentials, url, "127.0.0.1:0", up).await;
    let edge = Edge::start(&credentials, "edge-a", core.edge_link_addr.expect("link")).await;
    membership::wait_joined(up, "alicebnc", "#lobby").await;
    let mut peer = peer_on(up).await;

    let mut request = format!("ws://{}/ws/ui?network=up", edge.web)
        .into_client_request()
        .expect("request");
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {alice}").parse().expect("header"),
    );
    let (mut ui, _) = tokio_tungstenite::connect_async(request)
        .await
        .expect("a live chat socket through the edge");
    tokio::time::timeout(deadline::HANG, async {
        loop {
            match ui.next().await {
                Some(Ok(Frame::Text(text))) if text.contains("\"t\":\"snapshot\"") => return,
                Some(Ok(_)) => {}
                other => panic!("the socket ended before its replay boundary: {other:?}"),
            }
        }
    })
    .await
    .expect("the replay boundary");
    peer.send_line("PRIVMSG #lobby :hello through the edge")
        .await
        .expect("send");
    tokio::time::timeout(deadline::HANG, async {
        loop {
            match ui.next().await {
                Some(Ok(Frame::Text(text))) if text.contains("hello through the edge") => return,
                Some(Ok(_)) => {}
                other => panic!("the socket ended before the line: {other:?}"),
            }
        }
    })
    .await
    .expect("the upstream's line");
    ui.send(Frame::text(
        serde_json::json!({ "id": "edge-1", "target": "#lobby", "message": "from the web" })
            .to_string(),
    ))
    .await
    .expect("compose");
    tokio::time::timeout(deadline::HANG, async {
        loop {
            let message = peer.next_message().await.expect("read").expect("a line");
            if message.params.iter().any(|param| param == "from the web") {
                return;
            }
        }
    })
    .await
    .expect("the composer's line upstream");

    let mut attached = e6irc_client::Connection::connect(&edge.attach.to_string())
        .await
        .expect("connect to the attach listener");
    attached
        .register_sasl(
            &e6irc_client::Identity {
                nick: "alice/up",
                username: "alice",
                realname: "Alice",
                server_password: None,
            },
            "alice",
            "s3cr3t",
        )
        .await
        .expect("attach through the edge");
    peer.send_line("PRIVMSG #lobby :hello attach")
        .await
        .expect("send");
    tokio::time::timeout(deadline::HANG, async {
        loop {
            let message = attached
                .next_message()
                .await
                .expect("read")
                .expect("a line");
            if message.params.iter().any(|param| param == "hello attach") {
                return;
            }
        }
    })
    .await
    .expect("the upstream's line through the attach");
}

/// Read `socket` until a text message contains `needle`; the socket must not
/// end first.
async fn ui_until(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    needle: &str,
) -> String {
    tokio::time::timeout(deadline::HANG, async {
        loop {
            match socket.next().await {
                Some(Ok(Frame::Text(text))) if text.contains(needle) => return text.to_string(),
                Some(Ok(_)) => {}
                other => panic!("the socket ended before {needle:?}: {other:?}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no message with {needle:?}"))
}

/// A graceful restart keeps a live chat socket (DESIGN §19.3): the edge holds
/// it, and the next core resumes it from its record — its account's network,
/// its credential read again, its replay after the cursor its client read
/// through — so the socket stays open and its client sees the network's
/// lines and sends as before.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn a_live_chat_socket_survives_a_graceful_restart() {
    let url = support::test_db("a_live_chat_socket_survives_a_graceful_restart").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "s3cr3t", None)
        .await
        .expect("account");
    let alice = token(&pool, "alice").await;
    let up = upstream().await;
    let credentials = Credentials::new("restart-ui", &["edge-a"]);
    let core = database_core(&credentials, url.clone(), "127.0.0.1:0", up).await;
    let link = core.edge_link_addr.expect("link");
    let edge = Edge::start(&credentials, "edge-a", link).await;
    membership::wait_joined(up, "alicebnc", "#lobby").await;
    let mut peer = peer_on(up).await;

    let mut request = format!("ws://{}/ws/ui?network=up", edge.web)
        .into_client_request()
        .expect("request");
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {alice}").parse().expect("header"),
    );
    let (mut ui, _) = tokio_tungstenite::connect_async(request)
        .await
        .expect("a live chat socket through the edge");
    ui_until(&mut ui, "\"t\":\"snapshot\"").await;
    peer.send_line("PRIVMSG #lobby :before the restart")
        .await
        .expect("send");
    ui_until(&mut ui, "before the restart").await;

    core.shutdown.run(net::StopMode::Handover).await;
    let _next = database_core(&credentials, url, &link.to_string(), up).await;
    // Resumed: the replay boundary again, after only what the socket had not
    // been sent.
    let boundary = ui_until(&mut ui, "\"t\":\"snapshot\"").await;
    assert!(!boundary.contains("before the restart"), "{boundary}");
    membership::wait_joined(up, "alicebnc", "#lobby").await;
    peer.send_line("PRIVMSG #lobby :after the restart")
        .await
        .expect("send");
    ui_until(&mut ui, "after the restart").await;
    ui.send(Frame::text(
        serde_json::json!({ "id": "after-1", "target": "#lobby", "message": "still composing" })
            .to_string(),
    ))
    .await
    .expect("compose");
    tokio::time::timeout(deadline::HANG, async {
        loop {
            let message = peer.next_message().await.expect("read").expect("a line");
            if message
                .params
                .iter()
                .any(|param| param == "still composing")
            {
                return;
            }
        }
    })
    .await
    .expect("the composer's line upstream after the restart");
}

/// The roster keeps an edge's slot: a core that follows another on the same
/// database gives a linking edge the slot the roster holds for it, and the
/// row says when it linked and under which epoch. The console shows the
/// edges' listeners and refuses to change listeners in edge mode.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn the_roster_keeps_an_edge_s_slot_and_the_console_shows_its_listeners() {
    let url =
        support::test_db("the_roster_keeps_an_edge_s_slot_and_the_console_shows_its_listeners")
            .await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "root", "s3cr3t", None)
        .await
        .expect("account");
    let root = token(&pool, "root").await;
    let up = upstream().await;
    let credentials = Credentials::new("roster", &["edge-a", "edge-b"]);
    let first = database_core(&credentials, url.clone(), "127.0.0.1:0", up).await;
    let link = first.edge_link_addr.expect("link");
    // edge-b links first, so edge-a's slot is not the first one.
    let _b = Edge::start(&credentials, "edge-b", link).await;
    let a = Edge::start(&credentials, "edge-a", link).await;
    let slots: Vec<(String, i32, i64)> =
        sqlx::query_as("SELECT edge, slot, last_epoch FROM core_edges ORDER BY edge")
            .fetch_all(&pool)
            .await
            .expect("the roster");
    assert_eq!(slots.len(), 2, "{slots:?}");
    assert_eq!(slots[0].0, "edge-a");
    assert_eq!(slots[1].0, "edge-b");
    let (slot_a, slot_b) = (slots[0].1, slots[1].1);
    assert_ne!(slot_a, slot_b);

    // The console, reached through the edge, shows edge mode and each edge's
    // listeners, and does not change listeners here.
    let (status, body) = get(a.web, "/api/v1/admin/configuration", Some(&root))
        .await
        .expect("configuration");
    assert_eq!(status, 200, "{body}");
    let configuration: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(configuration["runtime"]["edge_mode"], true, "{body}");
    let edges = configuration["runtime"]["edges"].as_array().expect("edges");
    let reported = edges
        .iter()
        .find(|edge| edge["name"] == "edge-a")
        .expect("edge-a is listed");
    assert_eq!(reported["slot"], slot_a, "{body}");
    let kinds: Vec<&str> = reported["listeners"]
        .as_array()
        .expect("listeners")
        .iter()
        .map(|listener| listener["kind"].as_str().expect("kind"))
        .collect();
    assert_eq!(kinds, ["irc", "http", "attach"], "{body}");
    // Plaintext listeners, as edge-a's configuration names them: no
    // certificate (a TLS listener reports its certificate's path).
    for listener in reported["listeners"].as_array().expect("listeners") {
        assert_eq!(listener["certificate"], serde_json::Value::Null, "{body}");
    }
    let mut settings = configuration["settings"].clone();
    settings["listeners"] =
        serde_json::json!([{ "addr": "127.0.0.1:6667", "tls": null, "websocket": false }]);
    let patch = serde_json::json!({ "revision": configuration["revision"], "settings": settings });
    let (status, body) = request(
        a.web,
        "PATCH",
        "/api/v1/admin/configuration",
        Some(&root),
        &patch.to_string(),
    )
    .await
    .expect("patch");
    assert_eq!(status, 409, "{body}");
    assert!(body.contains("edge mode"), "{body}");

    // The next core, on the same database, gives edge-a its slot again.
    let first_shutdown = first.shutdown;
    assert_eq!(
        first_shutdown.run(net::StopMode::Final).await,
        net::ShutdownOutcome::Flushed
    );
    let _second = database_core(&credentials, url, &link.to_string(), up).await;
    a.until_accepting().await;
    let again: (i32, i64) =
        sqlx::query_as("SELECT slot, last_epoch FROM core_edges WHERE edge = 'edge-a'")
            .fetch_one(&pool)
            .await
            .expect("the roster row");
    assert_eq!(again.0, slot_a);
    tokio::time::timeout(deadline::HANG, async {
        loop {
            let (_, epoch): (i32, i64) =
                sqlx::query_as("SELECT slot, last_epoch FROM core_edges WHERE edge = 'edge-a'")
                    .fetch_one(&pool)
                    .await
                    .expect("the roster row");
            if epoch > slots[0].2 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("edge-a linked again under the next core's epoch");
}
