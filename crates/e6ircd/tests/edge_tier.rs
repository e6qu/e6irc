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
            record_format: None,
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
    irc: SocketAddr,
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
            irc,
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
        client_certificate: None,
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

/// The next line of `attached` that has `text` as a parameter; the
/// connection must not end first.
async fn attached_until(attached: &mut e6irc_client::Connection, text: &str) {
    tokio::time::timeout(deadline::HANG, async {
        loop {
            let message = attached
                .next_message()
                .await
                .expect("read")
                .unwrap_or_else(|| panic!("the attachment ended before {text:?}"));
            assert_ne!(message.command, "ERROR", "{message:?}");
            if message.params.iter().any(|param| param == text) {
                return;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no line with {text:?}"));
}

/// A graceful restart keeps a bouncer attachment (DESIGN §19.3): the edge
/// holds it, and the next core resumes it from its record — its login checked
/// again, its network, what it was shown — without welcoming it again: the
/// client sees no `ERROR`, no second `001`, and the network's lines and its
/// own sends carry on.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn a_bouncer_attachment_survives_a_graceful_restart() {
    let url = support::test_db("a_bouncer_attachment_survives_a_graceful_restart").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "s3cr3t", None)
        .await
        .expect("account");
    let up = upstream().await;
    let credentials = Credentials::new("restart-attach", &["edge-a"]);
    let core = database_core(&credentials, url.clone(), "127.0.0.1:0", up).await;
    let link = core.edge_link_addr.expect("link");
    let edge = Edge::start(&credentials, "edge-a", link).await;
    membership::wait_joined(up, "alicebnc", "#lobby").await;
    let mut peer = peer_on(up).await;
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
    peer.send_line("PRIVMSG #lobby :before the restart")
        .await
        .expect("send");
    attached_until(&mut attached, "before the restart").await;

    core.shutdown.run(net::StopMode::Handover).await;
    let _next = database_core(&credentials, url, &link.to_string(), up).await;
    membership::wait_joined(up, "alicebnc", "#lobby").await;
    peer.send_line("PRIVMSG #lobby :after the restart")
        .await
        .expect("send");
    let welcomed_again = tokio::time::timeout(deadline::HANG, async {
        loop {
            let message = attached
                .next_message()
                .await
                .expect("read")
                .expect("the attachment stays open");
            assert_ne!(message.command, "ERROR", "{message:?}");
            if message.command == "001" {
                return true;
            }
            if message
                .params
                .iter()
                .any(|param| param == "after the restart")
            {
                return false;
            }
        }
    })
    .await
    .expect("the line after the restart");
    assert!(!welcomed_again, "the attachment was welcomed a second time");
    attached
        .send_line("PRIVMSG #lobby :from the attachment")
        .await
        .expect("send");
    tokio::time::timeout(deadline::HANG, async {
        loop {
            let message = peer.next_message().await.expect("read").expect("a line");
            if message
                .params
                .iter()
                .any(|param| param == "from the attachment")
            {
                return;
            }
        }
    })
    .await
    .expect("the attachment's line upstream after the restart");
}

/// One scripted client's step: who sends which line.
const SCRIPT: &[(usize, &str)] = &[
    (0, "NICK alice"),
    (0, "USER alice 0 * :Alice"),
    (1, "NICK bob"),
    (1, "USER bob 0 * :Bob"),
    (0, "JOIN #steps"),
    (1, "JOIN #steps"),
    (0, "TOPIC #steps :before or after"),
    (0, "MODE #steps +v bob"),
    (1, "PRIVMSG #steps :hello"),
    (0, "NICK alice2"),
    (1, "AWAY :gone"),
    (0, "PRIVMSG bob :are you there"),
    (1, "MONITOR + alice2"),
    (0, "NAMES #steps"),
    (1, "PART #steps :bye"),
    (0, "WHOIS bob"),
];

/// A transcript line as two runs of one script compare it: without its tags,
/// and without what differs between cores by design — the welcome's server
/// facts and LUSERS counts, the MOTD, idle times.
fn comparable(line: &str) -> Option<String> {
    let line = match line.strip_prefix('@') {
        Some(tagged) => tagged.split_once(' ').map_or("", |(_, rest)| rest),
        None => line,
    };
    let numeric = line.split(' ').nth(1).unwrap_or("");
    let varies = [
        "002", "003", "004", "005", "251", "252", "253", "254", "255", "265", "266", "317", "372",
        "375", "376", "422",
    ];
    (!varies.contains(&numeric)).then(|| line.to_owned())
}

/// Run [`SCRIPT`] through an edge, gracefully restarting the core twice in a
/// row after step `restart_after` (none, when `None`) — onto a core with
/// another shard count, then onto a third: each client's transcript.
async fn scripted_run(restart_after: Option<usize>) -> [Vec<String>; 2] {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let credentials = Credentials::new(&format!("steps-{restart_after:?}"), &["edge-a"]);
    let mut config = core_config(&credentials, "127.0.0.1:0");
    config.core_workers = 1;
    let mut core = Some(net::start(config).await.expect("core"));
    let link = core
        .as_ref()
        .and_then(|core| core.edge_link_addr)
        .expect("link");
    let edge = Edge::start(&credentials, "edge-a", link).await;
    let mut clients = Vec::new();
    for _ in 0..2 {
        let stream = tokio::net::TcpStream::connect(edge.irc)
            .await
            .expect("connect");
        let (read, write) = stream.into_split();
        clients.push((tokio::io::BufReader::new(read), write));
    }
    let mut transcripts = [Vec::new(), Vec::new()];
    for (step, (who, line)) in SCRIPT.iter().enumerate() {
        clients[*who]
            .1
            .write_all(
                format!(
                    "{line}
"
                )
                .as_bytes(),
            )
            .await
            .expect("send");
        // Every client has everything this step caused once it has the answer
        // to its own PING.
        for (index, (read, write)) in clients.iter_mut().enumerate() {
            write
                .write_all(
                    format!(
                        "PING :step{step}
"
                    )
                    .as_bytes(),
                )
                .await
                .expect("ping");
            loop {
                let mut received = String::new();
                tokio::time::timeout(deadline::HANG, read.read_line(&mut received))
                    .await
                    .unwrap_or_else(|_| panic!("client {index} waited in vain at step {step}"))
                    .expect("read");
                assert!(
                    !received.is_empty(),
                    "client {index} was closed at step {step}"
                );
                let received = received.trim_end().to_owned();
                if received.contains(" PONG ") && received.ends_with(&format!(":step{step}")) {
                    break;
                }
                // A registering client is asked to answer a PING of the
                // server's own.
                if let Some(token) = received.strip_prefix("PING ") {
                    write
                        .write_all(
                            format!(
                                "PONG {token}
"
                            )
                            .as_bytes(),
                        )
                        .await
                        .expect("pong");
                    continue;
                }
                transcripts[index].extend(comparable(&received));
            }
        }
        if restart_after == Some(step) {
            // Twice in a row, nothing said between: what the first next core
            // rebuilt, it hands on whole.
            for core_workers in [2, 3] {
                let stopping = core.take().expect("the core before");
                stopping.shutdown.run(net::StopMode::Handover).await;
                let mut next = core_config(&credentials, &link.to_string());
                next.core_workers = core_workers;
                core = Some(net::start(next).await.expect("the next core"));
            }
        }
    }
    drop(edge);
    if let Some(core) = core {
        core.shutdown.run(net::StopMode::Final).await;
    }
    transcripts
}

/// Restart at every step (DESIGN §19.11): a scripted two-client conversation
/// gives the same transcripts, line for line, whether the core runs it alone
/// or is gracefully restarted twice in a row after any one of its steps —
/// onto a core with another shard count, then a third — registration, channel
/// state, ranks, nick changes, away, private messages, the monitor list and
/// replies alike.
#[tokio::test(flavor = "multi_thread")]
async fn a_graceful_restart_after_any_step_changes_no_transcript() {
    let baseline = scripted_run(None).await;
    assert!(
        baseline[1]
            .iter()
            .any(|line| line.ends_with(":are you there")),
        "{baseline:#?}"
    );
    for (step, said) in SCRIPT.iter().enumerate() {
        let restarted = scripted_run(Some(step)).await;
        for (client, (restarted, baseline)) in restarted.iter().zip(&baseline).enumerate() {
            assert_eq!(
                restarted, baseline,
                "client {client}'s transcript changed by a restart after step {step} ({said:?})"
            );
        }
    }
}

/// The `local` driver's session lives in the core itself, so a graceful
/// restart homes it on an edge (D13): the next core rebuilds it and its driver
/// takes it up instead of registering again. Its channel sees no QUIT and no
/// JOIN, the attachment on its network is not welcomed again, and lines carry
/// on both ways through the resumed session.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn a_local_driver_session_survives_a_graceful_restart_unseen() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let url = support::test_db("a_local_driver_session_survives_a_restart").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "s3cr3t", None)
        .await
        .expect("account");
    let credentials = Credentials::new("restart-local", &["edge-a"]);
    let local_config = |link: &str| {
        let mut config = core_config(&credentials, link);
        config.database = Some(DatabaseConfig {
            url: url.clone(),
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        });
        config.networks = vec![NetworkEntry {
            kind: e6ircd::config::NetworkKind::Local,
            name: "home".into(),
            owner: Some("alice".into()),
            addr: String::new(),
            tls: false,
            nick: "alicelocal".into(),
            username: Some("alice".into()),
            realname: Some("Alice Local".into()),
            autojoin: vec!["#local".into()],
            buffer_cap: 1000,
            sasl_account: None,
            sasl_password: None,
            server_password: None,
            client_certificate: None,
        }];
        config
    };
    let core = net::start(local_config("127.0.0.1:0")).await.expect("core");
    let link = core.edge_link_addr.expect("link");
    let edge = Edge::start(&credentials, "edge-a", link).await;
    let stream = tokio::net::TcpStream::connect(edge.irc)
        .await
        .expect("connect");
    let (read, mut write) = stream.into_split();
    let mut read = tokio::io::BufReader::new(read);
    // Every line bob reads up to the one holding `needle`.
    let mut until = async |needle: &str| -> Vec<String> {
        tokio::time::timeout(deadline::HANG, async {
            let mut seen = Vec::new();
            loop {
                let mut line = String::new();
                read.read_line(&mut line).await.expect("read");
                assert!(!line.is_empty(), "closed before {needle:?}");
                let found = line.contains(needle);
                seen.push(line);
                if found {
                    return seen;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("no {needle:?}"))
    };
    write
        .write_all(b"NICK bob\r\nUSER bob 0 * :Bob\r\nJOIN #local\r\n")
        .await
        .expect("send");
    let names = until(" 353 ").await;
    if !names.concat().contains("alicelocal") {
        until(":alicelocal!").await;
    }
    let mut attached = e6irc_client::Connection::connect(&edge.attach.to_string())
        .await
        .expect("connect to the attach listener");
    attached
        .register_sasl(
            &e6irc_client::Identity {
                nick: "alice/home",
                username: "alice",
                realname: "Alice",
                server_password: None,
            },
            "alice",
            "s3cr3t",
        )
        .await
        .expect("attach through the edge");
    write
        .write_all(b"PRIVMSG #local :before the restart\r\n")
        .await
        .expect("send");
    attached_until(&mut attached, "before the restart").await;

    core.shutdown.run(net::StopMode::Handover).await;
    let _next = net::start(local_config(&link.to_string()))
        .await
        .expect("the next core");
    write
        .write_all(b"PRIVMSG #local :after the restart\r\n")
        .await
        .expect("send");
    let seen_by_attachment = tokio::time::timeout(deadline::HANG, async {
        let mut seen = Vec::new();
        loop {
            let message = attached
                .next_message()
                .await
                .expect("read")
                .expect("the attachment stays open");
            let done = message
                .params
                .iter()
                .any(|param| param == "after the restart");
            seen.push(message);
            if done {
                return seen;
            }
        }
    })
    .await
    .expect("the line after the restart reaches the attachment");
    for message in &seen_by_attachment {
        assert!(
            !["ERROR", "001", "JOIN", "PART", "QUIT"].contains(&message.command.as_str()),
            "the attachment saw the restart: {message:?}"
        );
    }
    attached
        .send_line("PRIVMSG #local :from the attachment")
        .await
        .expect("send");
    let seen_by_bob = until("from the attachment").await;
    let said = seen_by_bob.last().expect("the line");
    assert!(said.starts_with(":alicelocal!"), "{said}");
    for line in &seen_by_bob {
        assert!(
            !line.contains(" QUIT ") && !line.contains(" JOIN "),
            "the channel saw the restart: {line}"
        );
    }
    write.write_all(b"NAMES #local\r\n").await.expect("send");
    let names = until(" 366 ").await;
    assert!(names.concat().contains("alicelocal"), "{names:?}");

    // The resumed session is homed again at the next cut.
    _next.shutdown.run(net::StopMode::Handover).await;
    let _third = net::start(local_config(&link.to_string()))
        .await
        .expect("the third core");
    attached
        .send_line("PRIVMSG #local :after the second restart")
        .await
        .expect("send");
    let seen_by_bob = until("after the second restart").await;
    let said = seen_by_bob.last().expect("the line");
    assert!(said.starts_with(":alicelocal!"), "{said}");
    for line in &seen_by_bob {
        assert!(
            !line.contains(" QUIT ") && !line.contains(" JOIN "),
            "the channel saw the second restart: {line}"
        );
    }
}

/// A SASL exchange that spans a graceful restart completes (DESIGN §19.3):
/// the payload's first 400-byte chunk is retained for replay rather than
/// recorded, the edge replays it to the next core first, and the client's
/// last chunk completes the login there. Then the record format is advanced
/// (`e6ircd records advance`, D11) while the session is served, and the core
/// after reads the newest format it was written in.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn a_sasl_exchange_and_a_format_advance_span_graceful_restarts() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let url = support::test_db("a_sasl_exchange_and_a_format_advance_span_graceful_restarts").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    // Long enough that its PLAIN payload takes two chunks.
    let password = "correct horse battery staple ".repeat(12);
    e6ircd::db::create_account_with_contact(&pool, "alice", &password, None)
        .await
        .expect("account");
    let credentials = Credentials::new("restart-sasl", &["edge-a"]);
    let database_config = |link: &str| {
        let mut config = core_config(&credentials, link);
        config.database = Some(DatabaseConfig {
            url: url.clone(),
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        });
        config
    };
    let core = net::start(database_config("127.0.0.1:0"))
        .await
        .expect("core");
    let link = core.edge_link_addr.expect("link");
    let edge = Edge::start(&credentials, "edge-a", link).await;
    let stream = tokio::net::TcpStream::connect(edge.irc)
        .await
        .expect("connect");
    let (read, mut write) = stream.into_split();
    let mut read = tokio::io::BufReader::new(read);
    let mut until = async |needle: &str| -> String {
        tokio::time::timeout(deadline::HANG, async {
            loop {
                let mut line = String::new();
                read.read_line(&mut line).await.expect("read");
                assert!(!line.is_empty(), "closed before {needle:?}");
                assert!(!line.starts_with("ERROR"), "{line}");
                if line.contains(needle) {
                    return line;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("no {needle:?}"))
    };
    for line in [
        "CAP LS 302",
        "CAP REQ :sasl",
        "NICK alice",
        "USER alice 0 * :Alice",
    ] {
        write
            .write_all(format!("{line}\r\n").as_bytes())
            .await
            .expect("send");
    }
    until("ACK").await;
    write
        .write_all(b"AUTHENTICATE PLAIN\r\n")
        .await
        .expect("send");
    until("AUTHENTICATE +").await;
    let payload = e6irc_proto::base64::encode(format!("\0alice\0{password}").as_bytes());
    assert!(payload.len() > 400 && payload.len() < 800);
    write
        .write_all(format!("AUTHENTICATE {}\r\n", &payload[..400]).as_bytes())
        .await
        .expect("send");

    core.shutdown.run(net::StopMode::Handover).await;
    let next = net::start(database_config(&link.to_string()))
        .await
        .expect("the next core");
    write
        .write_all(format!("AUTHENTICATE {}\r\n", &payload[400..]).as_bytes())
        .await
        .expect("send");
    until(" 903 ").await;
    write.write_all(b"CAP END\r\n").await.expect("send");
    assert!(until(" 001 ").await.contains(" 001 alice "));

    // The rolling upgrade's window (D11): these cores wrote the previous
    // format; once advanced, the serving core writes the newest, and the
    // core after it reads that.
    assert_eq!(
        e6ircd::db::advance_record_format(&pool)
            .await
            .expect("advance"),
        (1, 2)
    );
    write
        .write_all(b"AWAY :after the advance\r\n")
        .await
        .expect("send");
    until(" 306 ").await;
    next.shutdown.run(net::StopMode::Handover).await;
    let _third = net::start(database_config(&link.to_string()))
        .await
        .expect("the third core");
    write.write_all(b"WHOIS alice\r\n").await.expect("send");
    assert!(until(" 301 ").await.ends_with(":after the advance\r\n"));
    let logged_in = until(" 330 ").await;
    assert!(logged_in.contains(" alice alice "), "{logged_in}");
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
