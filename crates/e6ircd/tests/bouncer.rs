//! BNC irc-driver e2e: point the driver at an e6ircd instance acting
//! as the "external network" and verify it registers, relays, and
//! buffers upstream traffic.

use e6ircd::bouncer::{
    DriverConnectionStatus, DriverEvent, IrcNetwork, NetworkConfig, NetworkHandle,
    NetworkLifecycle, SendOutcome, preflight_irc,
};
use e6ircd::config::{Config, ListenerConfig, NetworkKind};
use e6ircd::egress::InternalUpstreams;
use e6ircd::net;

mod support;

async fn upstream() -> std::net::SocketAddr {
    let config = Config {
        server_name: "irc.upstream.example".into(),
        network_name: "Upstream".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        // Tests pipeline hundreds of lines at this stand-in upstream in one
        // instant; its default command-flood bucket is not what they measure.
        limits: e6ircd::config::LimitsConfig {
            command_burst: 10_000,
            command_rate: 10_000,
            ..e6ircd::config::LimitsConfig::default()
        },
        ..Config::default()
    };
    net::start(config).await.expect("start").addrs[0]
}

/// Poll the sticky lifecycle until the driver reaches `expected`.
async fn wait_lifecycle(handle: &NetworkHandle, expected: NetworkLifecycle) {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        while handle.runtime_snapshot().lifecycle != expected {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "driver never reached {expected:?}: {:?}",
            handle.runtime_snapshot()
        )
    });
}

/// Subscribe first, then inspect the sticky state. The driver runs on another
/// executor thread, so "no await since start" does not prevent `Connected`
/// from being broadcast before this test subscribes.
async fn wait_connected(
    handle: &NetworkHandle,
    events: &mut tokio::sync::broadcast::Receiver<DriverEvent>,
) {
    if handle.runtime_snapshot().lifecycle == NetworkLifecycle::Connected {
        return;
    }
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match events.recv().await {
                Ok(DriverEvent::Status {
                    status: DriverConnectionStatus::Connected,
                    ..
                }) => return,
                Ok(DriverEvent::Status { status, .. })
                    if !matches!(status, DriverConnectionStatus::Reconnecting(_)) =>
                {
                    panic!("driver disconnected before connecting");
                }
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    if handle.runtime_snapshot().lifecycle == NetworkLifecycle::Connected {
                        return;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    panic!("driver event stream closed before connecting");
                }
            }
        }
    })
    .await
    .expect("driver did not connect");
}

#[tokio::test(flavor = "multi_thread")]
async fn preflight_uses_the_real_driver_registration_path_without_starting_a_network() {
    let addr = upstream().await;
    let result = preflight_irc(
        &NetworkConfig {
            addr: addr.to_string(),
            nick: "preflight".parse().expect("test nickname"),
            realname: "preflight qualification".parse().expect("test real name"),
            internal_upstreams: InternalUpstreams::Allow,
            ..NetworkConfig::default()
        },
        std::time::Duration::from_secs(25),
    )
    .await
    .expect("local upstream qualifies");

    assert_eq!(result.resolved_addresses, 1);
    assert_eq!(result.confirmed_nick, "preflight");
    // Timings are allowed to be zero on a fast local clock, but every stage is
    // represented independently rather than one opaque total.
    let _stage_timings = (result.dns_ms, result.connect_ms, result.registration_ms);
}

#[tokio::test(flavor = "multi_thread")]
async fn driver_registers_relays_and_buffers() {
    let addr = upstream().await;

    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".parse().expect("test nickname"),
        realname: "bnc".parse().expect("test real name"),
        autojoin: vec!["#bnc".parse().expect("test channel")],
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    });
    let mut events = handle.subscribe();
    wait_connected(&handle, &mut events).await;

    // a separate client joins #bnc and messages it
    let mut other = e6irc_client::Connection::connect(&addr.to_string())
        .await
        .expect("connect");
    other
        .register(&e6irc_client::Identity {
            nick: "speaker",
            username: "speaker",
            realname: "speaker",
            server_password: None,
        })
        .await
        .expect("register");
    other.send_line("JOIN #bnc").await.unwrap();
    loop {
        let m = other.next_message().await.unwrap().unwrap();
        if m.command == "366" {
            break;
        }
    }
    other
        .send_line("PRIVMSG #bnc :hello bouncer")
        .await
        .unwrap();

    // the driver relays it as an event
    let got = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match events.recv().await {
                Ok(DriverEvent::Line(e6ircd::bouncer::BufferedLine { line: l, .. }))
                    if l.contains("PRIVMSG #bnc :hello bouncer") =>
                {
                    return l;
                }
                Ok(_) => {}
                Err(_) => panic!("driver stopped"),
            }
        }
    })
    .await
    .expect("timeout waiting for relayed message");
    // The driver negotiated server-time upstream, so the relayed line now
    // carries IRCv3 tags; the source prefix follows the tag section, and the
    // backlog preserves the timestamp.
    assert!(got.starts_with('@') && got.contains(" :speaker!"), "{got}");
    assert!(
        got.contains("time="),
        "backlog must keep server-time: {got}"
    );

    // ...and it's in the detached buffer for later playback
    let buffer = handle.buffer_snapshot();
    assert!(
        buffer
            .iter()
            .any(|l| l.contains("PRIVMSG #bnc :hello bouncer")),
        "buffer missing the message: {buffer:?}"
    );

    // downstream command reaches upstream: the driver sends a message
    // that the other client receives
    assert_eq!(
        handle.send("PRIVMSG #bnc :from the bouncer"),
        SendOutcome::Sent
    );
    let echoed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let m = other.next_message().await.unwrap().unwrap();
            if m.command == "PRIVMSG"
                && m.params.get(1).map(String::as_str) == Some("from the bouncer")
            {
                return m;
            }
        }
    })
    .await
    .expect("timeout waiting for bouncer message");
    assert!(
        echoed
            .source
            .as_deref()
            .unwrap_or("")
            .starts_with("bncbot!"),
        "{echoed:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn driver_reconnects_after_upstream_drop() {
    // A driver pointed at a dead address emits Disconnected and keeps
    // retrying (doesn't stop) until the handle is dropped.
    let handle = IrcNetwork::start(NetworkConfig {
        addr: "127.0.0.1:1".into(), // nothing listening
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    });
    let mut events = handle.subscribe();
    let disconnected = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match events.recv().await {
                Ok(DriverEvent::Status {
                    status: DriverConnectionStatus::Reconnecting(_),
                    ..
                }) => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
    })
    .await
    .expect("timeout");
    assert!(disconnected, "expected a Disconnected event");
}

/// A single non-UTF-8 line from the upstream must be relayed lossily, while an
/// over-long line must produce a visible bounded rejection. Neither may be
/// treated as EOF and used to tear down the whole link. IRC message bodies are
/// arbitrary bytes (Latin-1 etc. are routine), so without this any channel
/// member could keep a victim's bouncer flapping by sending one high-byte
/// message.
#[tokio::test(flavor = "multi_thread")]
async fn upstream_non_utf8_line_is_relayed_not_fatal() {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (send_lines, lines_requested) = tokio::sync::oneshot::channel();
    let upstream = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let (read, mut write) = sock.into_split();
        let mut read = tokio::io::BufReader::new(read);
        let mut line = Vec::new();
        loop {
            line.clear();
            let bytes_read = read.read_until(b'\n', &mut line).await.unwrap();
            assert_ne!(bytes_read, 0, "driver closed during registration");
            if line == b"CAP LS 302\r\n" {
                write
                    .write_all(b":up CAP * LS :server-time message-tags account-tag\r\n")
                    .await
                    .unwrap();
            } else if let Some(capability) = line
                .strip_prefix(b"CAP REQ :")
                .and_then(|line| line.strip_suffix(b"\r\n"))
            {
                write.write_all(b":up CAP * ACK :").await.unwrap();
                write.write_all(capability).await.unwrap();
                write.write_all(b"\r\n").await.unwrap();
            }
            if line == b"CAP END\r\n" {
                break;
            }
        }
        // Behave like an IRC server: welcome only after the complete client
        // registration burst. The old test wrote every reply immediately after
        // accept, then relied on socket buffering to impose its phases; under a
        // loaded runner that made the integration assertion timing-dependent.
        write
            .write_all(b":up 001 bncbot :welcome\r\n")
            .await
            .unwrap();
        lines_requested
            .await
            .expect("test stopped before line phase");
        // A non-UTF-8 channel-message body (0xE9 = Latin-1 'e-acute').
        write
            .write_all(b":speaker!s@h PRIVMSG #bnc :caf\xe9\r\n")
            .await
            .unwrap();
        // This cannot be relayed inside the accepted server-frame bound, but
        // its loss must remain visible and must not consume the next event from
        // the same socket read.
        write
            .write_all(&vec![b'x'; e6irc_proto::message::MAX_SERVER_FRAME_LEN + 1])
            .await
            .unwrap();
        write.write_all(b"\r\n").await.unwrap();
        // A following, ordinary line — its arrival on the SAME connection proves
        // the bad line did not drop the session.
        write
            .write_all(b":speaker!s@h PRIVMSG #bnc :after the bad line\r\n")
            .await
            .unwrap();
        // Keep the connection open and drain anything the driver sends, so no
        // EOF is observed (which would legitimately reconnect).
        let mut buf = [0u8; 1024];
        while read.read(&mut buf).await.unwrap_or(0) != 0 {}
    });

    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".parse().expect("test nickname"),
        realname: "bnc".parse().expect("test real name"),
        autojoin: vec![],
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    });
    let mut events = handle.subscribe();

    // Establish a causal phase boundary instead of racing the test's line burst
    // against registration. Once Connected is observed, the same established
    // socket is instructed to send the malformed and ordinary lines.
    wait_connected(&handle, &mut events).await;
    send_lines.send(()).expect("mock upstream stopped");

    // Collect events until the post-bad-line message arrives; assert no
    // Disconnected (reconnect) happened in between.
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut saw_bad_line = false;
        let mut saw_rejection = false;
        let mut disconnected_before_after = false;
        loop {
            match events.recv().await {
                Ok(DriverEvent::Line(e6ircd::bouncer::BufferedLine { line: l, .. }))
                    if l.contains("PRIVMSG #bnc :caf") =>
                {
                    // The non-UTF-8 body was relayed, lossily decoded.
                    saw_bad_line = true;
                }
                Ok(DriverEvent::Line(e6ircd::bouncer::BufferedLine { line: l, .. }))
                    if l.contains("upstream input rejected") =>
                {
                    saw_rejection = true;
                }
                Ok(DriverEvent::Line(e6ircd::bouncer::BufferedLine { line: l, .. }))
                    if l.contains("after the bad line") =>
                {
                    return (saw_bad_line, saw_rejection, disconnected_before_after);
                }
                Ok(DriverEvent::Status {
                    status: DriverConnectionStatus::Reconnecting(_),
                    ..
                }) => disconnected_before_after = true,
                Ok(_) => {}
                Err(_) => panic!("driver stopped"),
            }
        }
    })
    .await
    .expect("the ordinary line after the bad one must still arrive");

    assert!(outcome.0, "the non-UTF-8 line must be relayed, not dropped");
    assert!(
        outcome.1,
        "the over-long line must produce a visible bounded rejection"
    );
    assert!(
        !outcome.2,
        "the bad line must not disconnect/reconnect the session"
    );
    drop(events);
    drop(handle);
    tokio::time::timeout(std::time::Duration::from_secs(5), upstream)
        .await
        .expect("mock upstream did not observe driver shutdown")
        .expect("mock upstream task failed");
}

/// Provision a fresh single-account database and return its URL. `test` is the
/// calling test's name — a shared helper must not name the database after
/// itself, or every test it serves would share one.
async fn bnc_account_db(test: &str, account: &str, password: &str) -> String {
    let url = support::test_db(test).await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, account, password, None)
        .await
        .expect("create");
    drop(pool);
    url
}

/// A pool for the test's own observation queries on an already-migrated
/// database. Not `db::connect_and_migrate`: that is the daemon's pool, whose
/// 2 s acquire timeout is a production bound, and on a loaded test host it
/// turned a slow poll into `count: PoolTimedOut`.
async fn observer_pool(url: &str) -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .connect(url)
        .await
        .expect("observer pool")
}

fn bnc_config(up: std::net::SocketAddr, url: String) -> Config {
    use e6ircd::config::{BncConfig, DatabaseConfig, NetworkEntry};
    Config {
        server_name: "irc.bnc.example".into(),
        network_name: "BncHost".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        networks: vec![
            NetworkEntry {
                kind: NetworkKind::Irc,
                name: "up".into(),
                owner: Some("alice".into()),
                addr: up.to_string(),
                tls: false,
                nick: "bncnick".into(),
                username: Some("tester".into()),
                realname: Some("bncnick".into()),
                autojoin: vec!["#lobby".into()],
                buffer_cap: 1000,
                sasl_account: None,
                sasl_password: None,
                server_password: None,
            },
            // A network owned by a different account: alice must not see it.
            NetworkEntry {
                kind: NetworkKind::Irc,
                name: "bobnet".into(),
                owner: Some("bob".into()),
                addr: up.to_string(),
                tls: false,
                nick: "bobnick".into(),
                username: Some("tester".into()),
                realname: Some("bobnick".into()),
                autojoin: vec![],
                buffer_cap: 1000,
                sasl_account: None,
                sasl_password: None,
                server_password: None,
            },
        ],
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }),
        internal_upstreams: e6ircd::egress::InternalUpstreams::Allow,
        ..Config::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn bnc_listener_authenticates_and_routes_client_to_network() {
    let url = bnc_account_db(
        "bnc_listener_authenticates_and_routes_client_to_network",
        "alice",
        "s3cr3t",
    )
    .await;
    let up = upstream().await;
    let running = net::start(bnc_config(up, url)).await.expect("start");
    let bnc = running.bnc_addr.expect("bnc bound");

    // give the driver a moment to connect + join upstream
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    // a peer on the upstream will exchange messages
    let mut peer = e6irc_client::Connection::connect(&up.to_string())
        .await
        .unwrap();
    peer.register(&e6irc_client::Identity {
        nick: "uppeer",
        username: "uppeer",
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

    // client authenticates to the BNC via SASL PLAIN, selecting the
    // network via the nick/network suffix.
    let mut client = e6irc_client::Connection::connect(&bnc.to_string())
        .await
        .unwrap();
    let confirmed = client
        .register_sasl(
            &e6irc_client::Identity {
                nick: "alice/up",
                username: "aliceup",
                realname: "Me",
                server_password: None,
            },
            "alice",
            "s3cr3t",
        )
        .await
        .expect("bnc SASL auth");
    assert_eq!(confirmed, "bncnick", "{confirmed}");

    // client -> upstream: peer receives it as coming from the driver nick
    client
        .send_line("PRIVMSG #lobby :hi from bnc client")
        .await
        .unwrap();
    let got = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let m = peer.next_message().await.unwrap().unwrap();
            if m.command == "PRIVMSG"
                && m.params.get(1).map(String::as_str) == Some("hi from bnc client")
            {
                return m;
            }
        }
    })
    .await
    .expect("upstream never got it");
    assert!(
        got.source.as_deref().unwrap_or("").starts_with("bncnick!"),
        "{got:?}"
    );

    // upstream -> client: peer posts, the bnc client receives it live
    peer.send_line("PRIVMSG #lobby :hi from upstream")
        .await
        .unwrap();
    let live = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let m = client.next_message().await.unwrap().unwrap();
            if m.command == "PRIVMSG"
                && m.params.get(1).map(String::as_str) == Some("hi from upstream")
            {
                return m;
            }
        }
    })
    .await
    .expect("client never got upstream msg");
    assert_eq!(live.params.first().map(String::as_str), Some("#lobby"));
}

/// Off loopback the attach listener must be TLS, because attaching clients
/// send their account password. A TLS listener serves its certificate, a
/// client that verifies it attaches with SASL PLAIN inside the tunnel, and a
/// plaintext client is never answered in cleartext.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn bnc_listener_attaches_over_tls() {
    let url = bnc_account_db("bnc_listener_attaches_over_tls", "alice", "s3cr3t").await;
    let up = upstream().await;
    let certificate =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("certificate");
    let dir = std::env::temp_dir().join(format!("e6irc-bnc-tls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("directory");
    let tls = e6ircd::config::TlsConfig {
        cert_path: dir.join("cert.pem"),
        key_path: dir.join("key.pem"),
    };
    std::fs::write(&tls.cert_path, certificate.cert.pem()).expect("write certificate");
    std::fs::write(&tls.key_path, certificate.signing_key.serialize_pem()).expect("write key");
    let mut config = bnc_config(up, url);
    config.bnc.as_mut().expect("bnc").tls = Some(tls);
    let running = net::start(config).await.expect("start");
    let bnc = running.bnc_addr.expect("bnc bound");
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(certificate.cert.der().clone())
        .expect("trust the test certificate");
    let mut client = e6irc_client::Connection::connect_tls(&bnc.to_string(), "localhost", roots)
        .await
        .expect("TLS handshake with the attach listener");
    let confirmed = client
        .register_sasl(
            &e6irc_client::Identity {
                nick: "alice/up",
                username: "aliceup",
                realname: "Me",
                server_password: None,
            },
            "alice",
            "s3cr3t",
        )
        .await
        .expect("SASL attach over TLS");
    assert_eq!(confirmed, "bncnick");

    // A plaintext client speaks to a TLS endpoint: it is never registered.
    let mut plain = e6irc_client::Connection::connect(&bnc.to_string())
        .await
        .expect("TCP connect");
    let refused = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        plain.register(&e6irc_client::Identity {
            nick: "alice/up",
            username: "aliceup",
            realname: "Me",
            server_password: None,
        }),
    )
    .await
    .expect("the listener closes a plaintext client");
    assert!(refused.is_err(), "{refused:?}");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn bnc_listener_rejects_unauthenticated_and_wrong_password() {
    let url = bnc_account_db(
        "bnc_listener_rejects_unauthenticated_and_wrong_password",
        "alice",
        "s3cr3t",
    )
    .await;
    let up = upstream().await;
    let running = net::start(bnc_config(up, url)).await.expect("start");
    let bnc = running.bnc_addr.expect("bnc bound");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // No SASL at all: plain registration is refused (connection closes
    // before 001).
    let mut anon = e6irc_client::Connection::connect(&bnc.to_string())
        .await
        .unwrap();
    assert!(
        anon.register(&e6irc_client::Identity {
            nick: "alice/up",
            username: "aliceup",
            realname: "Me",
            server_password: None,
        })
        .await
        .is_err(),
        "unauthenticated attach must be refused"
    );

    // Wrong password: SASL fails (904), register_sasl errors.
    let mut bad = e6irc_client::Connection::connect(&bnc.to_string())
        .await
        .unwrap();
    assert!(
        bad.register_sasl(
            &e6irc_client::Identity {
                nick: "alice/up",
                username: "aliceup",
                realname: "Me",
                server_password: None,
            },
            "alice",
            "wrong"
        )
        .await
        .is_err(),
        "wrong password must be refused"
    );

    // Cross-account: alice authenticates fine but selects bob's network.
    // It is not visible to her, so the bouncer sends an "Unknown network"
    // notice and closes before the welcome — no 001, no live traffic — so
    // register_sasl (which waits for 001) errors.
    let mut cross = e6irc_client::Connection::connect(&bnc.to_string())
        .await
        .unwrap();
    assert!(
        cross
            .register_sasl(
                &e6irc_client::Identity {
                    nick: "alice/bobnet",
                    username: "alicebobne",
                    realname: "Me",
                    server_password: None,
                },
                "alice",
                "s3cr3t"
            )
            .await
            .is_err(),
        "alice must not attach to bob's network"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn bnc_listener_accepts_chunked_sasl_plain() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // A password long enough that base64(authzid\0authcid\0passwd) exceeds the
    // 400-char AUTHENTICATE line limit, forcing the client to chunk it — the
    // continuation path the BNC handshake must accumulate (SASL spec).
    let long_pw = "p".repeat(320);
    let url = bnc_account_db("bnc_listener_accepts_chunked_sasl_plain", "alice", &long_pw).await;
    let up = upstream().await;
    let running = net::start(bnc_config(up, url)).await.expect("start");
    let bnc = running.bnc_addr.expect("bnc bound");
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let mut sock = tokio::net::TcpStream::connect(bnc).await.unwrap();
    sock.write_all(
        b"CAP LS 302\r\nCAP REQ :sasl\r\nNICK alice/up\r\nUSER x 0 * :x\r\nAUTHENTICATE PLAIN\r\n",
    )
    .await
    .unwrap();

    // Wait for the server's "AUTHENTICATE +" go-ahead.
    let mut b = [0u8; 2048];
    let mut acc = String::new();
    loop {
        let n = sock.read(&mut b).await.unwrap();
        assert!(n > 0, "closed before AUTHENTICATE +");
        acc.push_str(&String::from_utf8_lossy(&b[..n]));
        if acc.contains("AUTHENTICATE +") {
            break;
        }
    }

    // Chunk the base64 PLAIN payload at 400 chars: a full 400-char line means
    // "more follows"; the shorter final line completes it.
    let payload = e6irc_proto::base64::encode(format!("\0alice\0{long_pw}").as_bytes());
    assert!(
        payload.len() > 400,
        "payload should span >1 line: {}",
        payload.len()
    );
    let (first, rest) = payload.split_at(400);
    sock.write_all(format!("AUTHENTICATE {first}\r\n").as_bytes())
        .await
        .unwrap();
    sock.write_all(format!("AUTHENTICATE {rest}\r\n").as_bytes())
        .await
        .unwrap();

    // Only correct accumulation yields the valid credential -> RPL_SASLSUCCESS
    // (903); a broken chunker would verify the first chunk alone and fail (904).
    let mut acc = String::new();
    let ok = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let n = sock.read(&mut b).await.unwrap();
            if n == 0 {
                return false;
            }
            acc.push_str(&String::from_utf8_lossy(&b[..n]));
            if acc.contains(" 903 ") {
                return true;
            }
            if acc.contains(" 904 ") {
                return false;
            }
        }
    })
    .await
    .expect("timed out waiting for SASL verdict");
    assert!(ok, "chunked SASL PLAIN should succeed: {acc}");

    sock.write_all(b"AUTHENTICATE PLAIN\r\n").await.unwrap();
    let mut already = String::new();
    let refused = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let n = sock.read(&mut b).await.unwrap();
            if n == 0 {
                return false;
            }
            already.push_str(&String::from_utf8_lossy(&b[..n]));
            if already.contains(" 907 ") {
                return true;
            }
        }
    })
    .await
    .expect("timed out waiting for already-authenticated refusal");
    assert!(
        refused,
        "a second SASL exchange must receive 907: {already}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn driver_authenticates_to_sasl_upstream() {
    use e6ircd::config::DatabaseConfig;
    let url = support::test_db("driver_authenticates_to_sasl_upstream").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "bncacct", "bncpass", None)
        .await
        .expect("create");
    drop(pool);

    // upstream requires SASL (has a database)
    let up_config = Config {
        server_name: "irc.saslup.example".into(),
        network_name: "SaslUp".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let up = net::start(up_config).await.expect("start").addrs[0];

    // driver with SASL creds
    let handle = IrcNetwork::start(NetworkConfig {
        addr: up.to_string(),
        nick: "bncacct".parse().expect("test nickname"),
        realname: "bnc".parse().expect("test real name"),
        sasl: Some(("bncacct".into(), "bncpass".into())),
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    });
    let mut events = handle.subscribe();
    wait_connected(&handle, &mut events).await;

    // Connected implies SASL success (register_sasl errors on 904, so
    // 001 only follows successful AUTHENTICATE). Confirm the upstream
    // really set the account via an independent observer's WHOIS.
    let mut observer = e6irc_client::Connection::connect(&up.to_string())
        .await
        .unwrap();
    observer
        .register(&e6irc_client::Identity {
            nick: "obs",
            username: "obs",
            realname: "obs",
            server_password: None,
        })
        .await
        .unwrap();
    observer.send_line("WHOIS bncacct").await.unwrap();
    let logged_in = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let m = observer.next_message().await.unwrap().unwrap();
            // 330 RPL_WHOISACCOUNT: <me> <nick> <account> :is logged in as
            if m.command == "330" && m.params.get(2).map(String::as_str) == Some("bncacct") {
                return true;
            }
            if m.command == "318" {
                return false; // end of WHOIS, no 330 seen
            }
        }
    })
    .await
    .expect("timeout");
    assert!(logged_in, "upstream did not report the driver as logged in");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn bnc_buffer_persists_and_restores_across_restart() {
    let url = bnc_account_db(
        "bnc_buffer_persists_and_restores_across_restart",
        "alice",
        "s3cr3t",
    )
    .await;
    let up = upstream().await;

    // Server A: a network owned by alice, connected to the upstream.
    let running_a = net::start(bnc_config(up, url.clone()))
        .await
        .expect("start A");
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    // A peer posts a line the driver receives, buffers, and persists.
    let mut peer = e6irc_client::Connection::connect(&up.to_string())
        .await
        .unwrap();
    peer.register(&e6irc_client::Identity {
        nick: "uppeer",
        username: "uppeer",
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
    peer.send_line("PRIVMSG #lobby :persisted line")
        .await
        .unwrap();

    // Wait until the line is in the persisted buffer.
    let pool = observer_pool(&url).await;
    let persisted = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let lines = e6ircd::db::recent_bnc_lines(&pool, "alice", "up", 100)
                .await
                .unwrap();
            if lines.iter().any(|l| l.contains("persisted line")) {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("timeout");
    assert!(persisted, "line was not persisted to the BNC buffer");
    drop(running_a);
    drop(pool);

    // Server B: same DB, but the network points at a dead upstream so the
    // only content is the restored backlog. Attaching replays it.
    use e6ircd::config::{BncConfig, DatabaseConfig, NetworkEntry};
    let config_b = Config {
        server_name: "irc.bncB.example".into(),
        network_name: "BncHostB".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        database: Some(DatabaseConfig {
            url: url.clone(),
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        networks: vec![NetworkEntry {
            kind: NetworkKind::Irc,
            name: "up".into(),
            owner: Some("alice".into()),
            addr: "127.0.0.1:1".into(), // unreachable: no live traffic
            tls: false,
            nick: "bncnick".into(),
            username: Some("tester".into()),
            realname: Some("bncnick".into()),
            autojoin: vec![],
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
    let running_b = net::start(config_b).await.expect("start B");
    let bnc = running_b.bnc_addr.expect("bnc bound");
    // Let the persistence task restore the backlog into the buffer.
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let mut client = e6irc_client::Connection::connect(&bnc.to_string())
        .await
        .unwrap();
    client
        .register_sasl(
            &e6irc_client::Identity {
                nick: "alice/up",
                username: "aliceup",
                realname: "Me",
                server_password: None,
            },
            "alice",
            "s3cr3t",
        )
        .await
        .expect("attach");
    // Playback of the restored backlog contains the persisted line.
    let replayed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let m = client.next_message().await.unwrap();
            match m {
                Some(m)
                    if m.command == "PRIVMSG"
                        && m.params.get(1).map(String::as_str) == Some("persisted line") =>
                {
                    return true;
                }
                Some(_) => {}
                None => return false,
            }
        }
    })
    .await
    .expect("timeout");
    assert!(replayed, "restored backlog was not replayed on attach");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn local_driver_presents_the_in_process_network() {
    use e6ircd::config::{BncConfig, DatabaseConfig, NetworkEntry, NetworkKind};
    let url = bnc_account_db(
        "local_driver_presents_the_in_process_network",
        "alice",
        "s3cr3t",
    )
    .await;

    // A server whose BNC exposes a `local` network (this ircd itself).
    let config = Config {
        server_name: "irc.local.example".into(),
        network_name: "LocalNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        networks: vec![NetworkEntry {
            name: "home".into(),
            kind: NetworkKind::Local,
            owner: Some("alice".into()),
            addr: String::new(),
            tls: false,
            nick: "alicelocal".into(),
            username: Some("tester".into()),
            realname: Some("Alice Local".into()),
            autojoin: vec!["#local".into()],
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
    let irc = running.addrs[0];
    let bnc = running.bnc_addr.expect("bnc bound");

    // Let the local driver register in-process and join #local.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // A normal client on the main listener joins #local and speaks.
    let mut peer = e6irc_client::Connection::connect(&irc.to_string())
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
    peer.send_line("JOIN #local").await.unwrap();
    loop {
        if peer.next_message().await.unwrap().unwrap().command == "366" {
            break;
        }
    }

    // Attach to the local network via the BNC and confirm we relay the
    // in-process traffic (the driver is joined to #local as alicelocal).
    let mut client = e6irc_client::Connection::connect(&bnc.to_string())
        .await
        .unwrap();
    client
        .register_sasl(
            &e6irc_client::Identity {
                nick: "alice/home",
                username: "alicehome",
                realname: "Me",
                server_password: None,
            },
            "alice",
            "s3cr3t",
        )
        .await
        .expect("attach to local network");

    peer.send_line("PRIVMSG #local :hi from the main listener")
        .await
        .unwrap();
    let got = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let m = client.next_message().await.unwrap();
            match m {
                Some(m)
                    if m.command == "PRIVMSG"
                        && m.params.get(1).map(String::as_str)
                            == Some("hi from the main listener") =>
                {
                    return true;
                }
                Some(_) => {}
                None => return false,
            }
        }
    })
    .await
    .expect("timeout");
    assert!(
        got,
        "local network did not relay in-process channel traffic"
    );
}

/// The persistence task must actually reach the trim. Driven through the real
/// task rather than by calling the database functions directly, because that is
/// the part a regression would break: whether every network is *reached* is now
/// structural (each task counts its own appends, so there is no interleaving
/// left to get wrong), but whether the counter is consulted at all is not.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn persisted_bnc_buffer_is_trimmed_by_its_own_traffic() {
    let url = bnc_account_db(
        "persisted_bnc_buffer_is_trimmed_by_its_own_traffic",
        "alice",
        "s3cr3t",
    )
    .await;
    let up = upstream().await;
    let running = net::start(bnc_config(up, url.clone()))
        .await
        .expect("start");
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let mut peer = e6irc_client::Connection::connect(&up.to_string())
        .await
        .expect("peer connect");
    peer.register(&e6irc_client::Identity {
        nick: "uppeer",
        username: "uppeer",
        realname: "peer",
        server_password: None,
    })
    .await
    .expect("peer register");
    peer.send_line("JOIN #lobby").await.expect("join");
    loop {
        if peer.next_message().await.unwrap().unwrap().command == "366" {
            break;
        }
    }

    let pool = observer_pool(&url).await;
    let rows = || {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM bnc_buffer WHERE owner = 'alice' AND network = 'up'",
            )
            .fetch_one(&pool)
            .await
            .expect("count")
        }
    };

    // Enough traffic to cross the retention cap and reach a trim beyond it.
    // Sent in paced batches: the persistence task reads from a bounded
    // broadcast, so an unpaced flood makes it lag and drop lines (it says so on
    // stderr) and the test would measure the lag rather than the trim.
    let target = 5_000 + 2 * e6ircd::db::BNC_TRIM_INTERVAL as i64 + 100;
    let mut sent = 0i64;
    while sent < target {
        for i in 0..250 {
            peer.send_line(&format!("PRIVMSG #lobby :line {}", sent + i))
                .await
                .expect("send");
        }
        sent += 250;
        // Let persistence catch up before sending more.
        let want = sent.min(5_000);
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while rows().await < want {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("persistence fell behind at {sent} lines"));
    }

    // Everything is sent; wait for the count to stop moving before asserting.
    // Sampling while it is still climbing would pass on a buffer that is merely
    // *passing through* the bound on its way past it — which is exactly what an
    // earlier version of this test did, and it stayed green with the trim
    // disabled.
    let settled = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let mut last = -1i64;
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            let n = rows().await;
            if n == last {
                return n;
            }
            last = n;
        }
    })
    .await
    .expect("the persisted buffer never stopped growing");
    let bound = 5_000 + e6ircd::db::BNC_TRIM_INTERVAL as i64;
    assert!(
        settled > 5_000 - e6ircd::db::BNC_TRIM_INTERVAL as i64 && settled <= bound,
        "settled at {settled} rows, outside the retained window"
    );
    drop(running);
}

/// The detached buffer must hold what the upstream actually sent. The driver
/// used to re-serialize its own parse of each line, which is a second
/// implementation of the wire format: a single-word trailing parameter came
/// back without its `:`, because a re-serializer only adds one when it has to.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn buffered_upstream_lines_keep_their_wire_form() {
    let url = bnc_account_db(
        "buffered_upstream_lines_keep_their_wire_form",
        "alice",
        "s3cr3t",
    )
    .await;
    let up = upstream().await;
    let running = net::start(bnc_config(up, url.clone()))
        .await
        .expect("start");
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let mut peer = e6irc_client::Connection::connect(&up.to_string())
        .await
        .expect("peer connect");
    peer.register(&e6irc_client::Identity {
        nick: "uppeer",
        username: "uppeer",
        realname: "peer",
        server_password: None,
    })
    .await
    .expect("peer register");
    peer.send_line("JOIN #lobby").await.expect("join");
    loop {
        if peer.next_message().await.unwrap().unwrap().command == "366" {
            break;
        }
    }
    // A single word as the trailing parameter: legal either way on the wire,
    // and exactly where a re-serializer diverges from the sender.
    peer.send_line("PRIVMSG #lobby :hi").await.expect("send");

    let pool = observer_pool(&url).await;
    let line = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let lines = e6ircd::db::recent_bnc_lines(&pool, "alice", "up", 100)
                .await
                .expect("read");
            if let Some(l) = lines.iter().find(|l| l.contains("PRIVMSG #lobby")) {
                return l.clone();
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the line was never buffered");
    assert!(
        line.ends_with(" :hi"),
        "buffered {line:?}; the trailing colon the upstream sent was lost"
    );
    drop(running);
}

// ---- scripted raw upstream -------------------------------------------------
//
// Some driver behaviors need an upstream that a real e6ircd cannot play (a
// silent peer that never answers PING, a server that renames us mid-session,
// a connection that dies on cue). This helper speaks just enough IRC to
// complete the e6irc-client registration exchange and then hands the session
// to the test's script.

struct FakeSession {
    reader: tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
}

impl FakeSession {
    async fn read_line(&mut self) -> String {
        use tokio::io::AsyncBufReadExt;
        let mut line = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.reader.read_line(&mut line),
        )
        .await
        .expect("upstream read timed out")
        .expect("upstream read failed");
        line.trim_end().to_string()
    }

    async fn send(&mut self, line: &str) {
        use tokio::io::AsyncWriteExt;
        self.writer
            .write_all(format!("{line}\r\n").as_bytes())
            .await
            .expect("upstream write failed");
    }

    /// The driver asks once for the whole advertised metadata set.
    async fn acknowledge_metadata(&mut self) {
        let metadata = "server-time message-tags account-tag";
        assert_eq!(self.read_line().await, format!("CAP REQ :{metadata}"));
        self.send(&format!(":up CAP * ACK :{metadata}")).await;
    }

    async fn negotiate_capabilities(&mut self) {
        assert_eq!(self.read_line().await, "CAP LS 302");
        self.send(":up CAP * LS :server-time message-tags account-tag")
            .await;
        self.acknowledge_metadata().await;
    }

    async fn negotiate_sasl_capabilities(&mut self) {
        assert_eq!(self.read_line().await, "CAP LS 302");
        self.send(":up CAP * LS :sasl=PLAIN server-time message-tags account-tag")
            .await;
        assert_eq!(self.read_line().await, "CAP REQ :sasl");
        self.send(":up CAP * ACK :sasl").await;
        self.acknowledge_metadata().await;
    }

    /// Registration with an upstream that offers `echo-message`: the driver
    /// asks for it on its own, after the metadata set, and is acknowledged.
    async fn complete_registration_with_echo_message(&mut self, nick: &str) {
        assert_eq!(self.read_line().await, "CAP LS 302");
        self.send(":up CAP * LS :server-time message-tags account-tag echo-message")
            .await;
        self.acknowledge_metadata().await;
        assert_eq!(self.read_line().await, "CAP REQ :echo-message");
        self.send(":up CAP * ACK :echo-message").await;
        loop {
            let line = self.read_line().await;
            if line.starts_with("USER ") {
                self.send(&format!(":up 001 {nick} :welcome")).await;
                return;
            }
        }
    }

    /// Read until the registration burst (NICK/USER) completes, then welcome
    /// the client. Returns nothing; the driver treats 001 as registered.
    async fn complete_registration(&mut self, nick: &str) {
        self.negotiate_capabilities().await;
        loop {
            let line = self.read_line().await;
            if line.starts_with("USER ") {
                self.send(&format!(":up 001 {nick} :welcome")).await;
                return;
            }
        }
    }
}

async fn fake_accept(listener: &tokio::net::TcpListener) -> FakeSession {
    let (socket, _) = listener.accept().await.expect("accept");
    let (read, writer) = socket.into_split();
    FakeSession {
        reader: tokio::io::BufReader::new(read),
        writer,
    }
}

/// The connection test's budget belongs to the whole test: the stage that is
/// running when it ends reports its OWN timeout, and the upstream still hears a
/// goodbye rather than a dropped socket.
#[tokio::test(flavor = "multi_thread")]
async fn a_connection_test_out_of_budget_names_its_stage_and_still_quits() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (heard_tx, mut heard_rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        let mut session = fake_accept(&listener).await;
        session.negotiate_capabilities().await;
        // Registration is never answered; record whatever else arrives.
        loop {
            let line = session.read_line().await;
            if line.is_empty() {
                break;
            }
            if line.starts_with("QUIT") {
                heard_tx.send(line).await.unwrap();
            }
        }
    });
    let failure = preflight_irc(
        &NetworkConfig {
            addr: addr.to_string(),
            nick: "preflight".parse().expect("test nickname"),
            internal_upstreams: InternalUpstreams::Allow,
            ..NetworkConfig::default()
        },
        std::time::Duration::from_millis(400),
    )
    .await
    .expect_err("an upstream that never welcomes cannot qualify");
    assert_eq!(failure.code(), "registration_timed_out");
    let goodbye = tokio::time::timeout(std::time::Duration::from_secs(5), heard_rx.recv())
        .await
        .expect("the upstream never heard a goodbye")
        .expect("upstream script ended");
    assert_eq!(goodbye, "QUIT :connection test complete");
}

/// The driver and the connection test put exactly the configured user name on
/// the wire. It used to be the first ten bytes of the nickname, so a legal
/// nickname such as `_bot` sent `USER _bot`, which Solanum refuses.
#[tokio::test(flavor = "multi_thread")]
async fn the_configured_username_is_what_the_upstream_is_sent() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (user_tx, mut user_rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        loop {
            let mut session = fake_accept(&listener).await;
            session.negotiate_capabilities().await;
            loop {
                let line = session.read_line().await;
                if line.starts_with("USER ") {
                    user_tx.send(line).await.expect("test is still listening");
                    session.send(":up 001 _bot :welcome").await;
                    break;
                }
            }
            while !session.read_line().await.is_empty() {}
        }
    });
    let config = NetworkConfig {
        addr: addr.to_string(),
        nick: "_bot".parse().expect("a legal nickname"),
        username: "botident".parse().expect("test user name"),
        realname: "Real Name".parse().expect("test real name"),
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    };
    preflight_irc(&config, std::time::Duration::from_secs(10))
        .await
        .expect("the connection test registers");
    let handle = IrcNetwork::start(config);
    for registration in ["the connection test", "the driver"] {
        let user = tokio::time::timeout(std::time::Duration::from_secs(10), user_rx.recv())
            .await
            .unwrap_or_else(|_| panic!("{registration} never sent USER"))
            .expect("upstream script ended");
        assert_eq!(user, "USER botident 0 * :Real Name", "{registration}");
    }
    drop(handle);
}

/// A private upstream that wants `PASS :right` before anything else, and
/// answers `464` to a wrong password or to none. Every line each connection
/// opened with goes to `first_lines`.
fn private_upstream(
    listener: tokio::net::TcpListener,
    first_lines: tokio::sync::mpsc::Sender<String>,
) {
    tokio::spawn(async move {
        loop {
            let mut session = fake_accept(&listener).await;
            let first_lines = first_lines.clone();
            tokio::spawn(async move {
                let first = session.read_line().await;
                first_lines.send(first.clone()).await.ok();
                match first.as_str() {
                    "PASS :right" => {
                        session.complete_registration("private").await;
                    }
                    "CAP LS 302" => session.send(":up 464 * :Password required").await,
                    _ => session.send(":up 464 * :Password incorrect").await,
                }
                while !session.read_line().await.is_empty() {}
            });
        }
    });
}

/// A private server's password goes out as the first line, before `CAP LS`,
/// from the connection test and the driver alike. A missing one and a
/// rejected one are told apart; a rejected one waits on the refusal schedule
/// like any configuration the server will not take, and the right one
/// connects.
#[tokio::test(flavor = "multi_thread")]
async fn a_server_password_is_sent_first_and_its_refusals_are_told_apart() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (first_tx, mut first_rx) = tokio::sync::mpsc::channel(64);
    private_upstream(listener, first_tx);
    let config = |server_password: Option<&str>| NetworkConfig {
        addr: addr.to_string(),
        nick: "private".parse().expect("test nickname"),
        server_password: server_password
            .map(|value| e6irc_client::ServerPassword::parse(value.into()).expect("valid")),
        rejection_retry_floor: std::time::Duration::from_millis(200),
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    };
    let budget = std::time::Duration::from_secs(10);
    let mut first_line = async || {
        tokio::time::timeout(budget, first_rx.recv())
            .await
            .expect("the upstream heard nothing")
            .expect("upstream script ended")
    };

    let missing = preflight_irc(&config(None), budget)
        .await
        .expect_err("no password");
    assert_eq!(missing.code(), "server_password_required");
    assert!(
        missing.summary().contains("does not supply"),
        "{}",
        missing.summary()
    );
    assert_eq!(first_line().await, "CAP LS 302");

    let rejected = preflight_irc(&config(Some("wrong")), budget)
        .await
        .expect_err("a wrong password");
    assert_eq!(rejected.code(), "server_password_rejected");
    assert!(
        rejected
            .summary()
            .contains("rejected the configured server password"),
        "{}",
        rejected.summary()
    );
    assert!(!rejected.summary().contains("wrong"));
    assert_eq!(first_line().await, "PASS :wrong");

    preflight_irc(&config(Some("right")), budget)
        .await
        .expect("the right password qualifies");
    assert_eq!(first_line().await, "PASS :right");

    // The driver: a rejected password is reported and retried on the refusal
    // schedule, not hammered and not parked at once.
    let wrong = IrcNetwork::start(config(Some("wrong")));
    for attempt in ["first", "second"] {
        assert_eq!(first_line().await, "PASS :wrong", "{attempt} attempt");
    }
    let snapshot = wrong.runtime_snapshot();
    assert_eq!(
        snapshot.last_error,
        Some(e6ircd::bouncer::NetworkFailure::ServerPasswordRejected),
        "{snapshot:?}"
    );
    assert_ne!(
        snapshot.lifecycle,
        NetworkLifecycle::Connected,
        "{snapshot:?}"
    );
    assert_eq!(
        snapshot.last_error_diagnostic.as_deref(),
        Some("Password incorrect")
    );
    drop(wrong);

    let right = IrcNetwork::start(config(Some("right")));
    let mut events = right.subscribe();
    wait_connected(&right, &mut events).await;
    drop(right);
}

/// Registration is the qualification. The test joins none of the configured
/// channels -- their members would otherwise see a JOIN/QUIT pair from every
/// test -- and still leaves politely.
#[tokio::test(flavor = "multi_thread")]
async fn a_connection_test_joins_nothing_and_still_quits() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (heard_tx, mut heard_rx) = tokio::sync::mpsc::channel(64);
    tokio::spawn(async move {
        let mut session = fake_accept(&listener).await;
        session.complete_registration("preflight").await;
        loop {
            let line = session.read_line().await;
            if line.is_empty() {
                break;
            }
            let goodbye = line.starts_with("QUIT");
            heard_tx.send(line).await.unwrap();
            if goodbye {
                break;
            }
        }
    });
    let result = preflight_irc(
        &NetworkConfig {
            addr: addr.to_string(),
            nick: "preflight".parse().expect("test nickname"),
            autojoin: vec![
                "#lobby".parse().expect("test channel"),
                "#dev".parse().expect("test channel"),
            ],
            internal_upstreams: InternalUpstreams::Allow,
            ..NetworkConfig::default()
        },
        std::time::Duration::from_secs(10),
    )
    .await
    .expect("registration qualifies the upstream");
    assert_eq!(result.confirmed_nick, "preflight");
    let mut heard = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let line = heard_rx.recv().await.expect("upstream script ended");
            let goodbye = line.starts_with("QUIT");
            heard.push(line);
            if goodbye {
                break;
            }
        }
    })
    .await
    .expect("the upstream never heard a goodbye");
    assert!(
        heard.iter().all(|line| !line.starts_with("JOIN")),
        "the connection test joined a channel: {heard:?}"
    );
    assert_eq!(
        heard.last().map(String::as_str),
        Some("QUIT :connection test complete"),
        "{heard:?}"
    );
}

/// A taken nickname is reported, never worked around. The driver does not
/// invent `bncbot_` on the owner's behalf: it says what the upstream said, waits
/// on the refusal schedule, and -- when the holder was only a ghost of its own
/// previous session -- registers under the configured nickname once it is free.
#[tokio::test(flavor = "multi_thread")]
async fn a_taken_nickname_is_reported_and_never_replaced() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (nick_tx, mut nick_rx) = tokio::sync::mpsc::channel(8);
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        // First dial: the nickname is held. Record every NICK the driver
        // offers on this connection; it must offer exactly the configured one.
        let mut session = fake_accept(&listener).await;
        session.negotiate_capabilities().await;
        loop {
            let line = session.read_line().await;
            if let Some(nick) = line.strip_prefix("NICK ") {
                nick_tx.send(nick.to_string()).await.unwrap();
                session
                    .send(&format!(":up 433 * {nick} :Nickname is already in use"))
                    .await;
            }
            if line.is_empty() {
                break;
            }
        }
        // The ghost times out; the next dial is welcomed under the same nick.
        release_rx.await.expect("test released the nickname");
        let mut session = fake_accept(&listener).await;
        session.negotiate_capabilities().await;
        loop {
            let line = session.read_line().await;
            if let Some(nick) = line.strip_prefix("NICK ") {
                nick_tx.send(nick.to_string()).await.unwrap();
            }
            if line.starts_with("USER ") {
                session.send(":up 001 bncbot :welcome").await;
                break;
            }
        }
        while !session.read_line().await.is_empty() {}
    });

    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".parse().expect("test nickname"),
        rejection_retry_floor: std::time::Duration::from_millis(200),
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    });
    let mut events = handle.subscribe();

    let refused = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let snapshot = handle.runtime_snapshot();
            if snapshot.last_error.is_some() {
                return snapshot;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the refusal was never reported");
    assert_eq!(refused.lifecycle, NetworkLifecycle::Reconnecting);
    assert_eq!(
        refused.last_error,
        Some(e6ircd::bouncer::NetworkFailure::NicknameInUse),
        "{refused:?}"
    );
    assert_eq!(
        refused.last_error_diagnostic.as_deref(),
        Some("Nickname is already in use"),
        "{refused:?}"
    );

    release_tx.send(()).expect("upstream script is waiting");
    wait_connected(&handle, &mut events).await;
    let mut offered = Vec::new();
    while let Ok(nick) = nick_rx.try_recv() {
        offered.push(nick);
    }
    assert_eq!(
        offered,
        ["bncbot", "bncbot"],
        "only the configured nickname is ever offered"
    );
}

/// A forced upstream NICK changes the driver's identity; later self-echoes
/// use the new nick, and the owner is told -- in the runtime snapshot and as a
/// notice in the backlog -- that the session now runs under a name they did
/// not choose.
#[tokio::test(flavor = "multi_thread")]
async fn driver_tracks_forced_upstream_nick_change() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (nick_tx, mut nick_rx) = tokio::sync::mpsc::channel::<()>(1);
    let (go_tx, mut go_rx) = tokio::sync::mpsc::channel::<()>(1);
    tokio::spawn(async move {
        let mut session = fake_accept(&listener).await;
        session.complete_registration("bncbot").await;
        nick_rx.recv().await;
        session.send(":bncbot!~bncbot@up NICK :renamed").await;
        go_rx.recv().await;
        // Stay open: the test ends by dropping the handle.
        loop {
            let _ = session.read_line().await;
        }
    });

    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".parse().expect("test nickname"),
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    });
    let mut events = handle.subscribe();
    wait_connected(&handle, &mut events).await;
    nick_tx.send(()).await.unwrap();
    // Drain the NICK line itself, then send a message whose echo must use
    // the new nick.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Ok(DriverEvent::Line(e6ircd::bouncer::BufferedLine { line, .. })) =
                events.recv().await
                && line.contains("NICK :renamed")
            {
                break;
            }
        }
    })
    .await
    .expect("nick line never relayed");
    let renamed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let snapshot = handle.runtime_snapshot();
            if snapshot.last_error.is_some() {
                return snapshot;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the rename was never recorded");
    assert_eq!(
        renamed.lifecycle,
        NetworkLifecycle::Connected,
        "{renamed:?}"
    );
    assert_eq!(
        renamed.last_error,
        Some(e6ircd::bouncer::NetworkFailure::RenamedByUpstream),
        "{renamed:?}"
    );
    assert_eq!(
        renamed.last_error_diagnostic.as_deref(),
        Some("upstream renamed this session from bncbot to renamed"),
        "{renamed:?}"
    );
    let notices: Vec<String> = handle
        .buffer_snapshot()
        .into_iter()
        .filter(|line| line.contains("renamed this session"))
        .collect();
    assert_eq!(notices.len(), 1, "one notice per rename: {notices:?}");
    assert!(
        notices[0].starts_with(":*bnc* NOTICE * :")
            && notices[0].contains("(renamed_by_upstream); upstream: upstream renamed this session from bncbot to renamed"),
        "{notices:?}"
    );
    assert_eq!(
        handle.send("PRIVMSG #room :after rename"),
        SendOutcome::Sent
    );
    go_tx.send(()).await.unwrap();
    let echo = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Ok(DriverEvent::Echo {
                line: e6ircd::bouncer::BufferedLine { line, .. },
                ..
            }) = events.recv().await
            {
                return line;
            }
        }
    })
    .await
    .expect("no echo");
    // The NICK echo also revealed the user and host the upstream shows.
    assert!(echo.contains(":renamed!~bncbot@up PRIVMSG"), "{echo}");
}

/// Start a driver against a scripted upstream that offers `echo-message` and
/// answers the first `PRIVMSG` it reads with `answer` (its lines, `{line}`
/// replaced by what it read).
async fn echo_message_upstream(answer: &'static [&'static str]) -> NetworkHandle {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut session = fake_accept(&listener).await;
        session
            .complete_registration_with_echo_message("bncbot")
            .await;
        loop {
            let line = session.read_line().await;
            if line.starts_with("PRIVMSG ") {
                for reply in answer {
                    session.send(&reply.replace("{line}", &line)).await;
                }
            }
        }
    });
    IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".parse().expect("test nickname"),
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    })
}

/// Every event the driver emits within `window`.
async fn events_within(
    events: &mut tokio::sync::broadcast::Receiver<DriverEvent>,
    window: std::time::Duration,
) -> Vec<DriverEvent> {
    let mut seen = Vec::new();
    let _ = tokio::time::timeout(window, async {
        while let Ok(event) = events.recv().await {
            seen.push(event);
        }
    })
    .await;
    seen
}

/// An upstream that offers `echo-message` is asked for it, and its echo is
/// the one the originator sees: an upstream that refuses the message (404)
/// sends no echo, so the refusal — not a bouncer-made echo written before the
/// upstream answered — is the verdict an attached `e6irc send` reads.
#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_refusal_is_not_preceded_by_a_synthesized_echo() {
    let handle = echo_message_upstream(&[":up 404 bncbot #room :Cannot send to channel"]).await;
    let mut events = handle.subscribe();
    wait_connected(&handle, &mut events).await;
    assert_eq!(
        handle.send_from(7, "PRIVMSG #room :hello"),
        SendOutcome::Sent
    );
    let seen = events_within(&mut events, std::time::Duration::from_secs(2)).await;
    assert!(
        !seen
            .iter()
            .any(|event| matches!(event, DriverEvent::Echo { .. })),
        "a refused message was echoed: {seen:?}"
    );
    assert!(
        seen.iter().any(|event| matches!(
            event,
            DriverEvent::Line(e6ircd::bouncer::BufferedLine { line, .. }) if line.contains(" 404 ")
        )),
        "the refusal reaches the attached clients: {seen:?}"
    );
}

/// The upstream's own echo of an accepted message is relayed as the one echo
/// of that line, routed to its originator — never doubled by a synthesized one.
#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_echo_is_the_only_echo_and_keeps_its_originator() {
    let handle = echo_message_upstream(&[
        "@time=2026-09-21T10:00:00.000Z :bncbot!~bncbot@up.example PRIVMSG #room :hello",
    ])
    .await;
    let mut events = handle.subscribe();
    wait_connected(&handle, &mut events).await;
    assert_eq!(
        handle.send_from(7, "PRIVMSG #room :hello"),
        SendOutcome::Sent
    );
    let seen = events_within(&mut events, std::time::Duration::from_secs(2)).await;
    let echoes: Vec<(String, u64)> = seen
        .iter()
        .filter_map(|event| match event {
            DriverEvent::Echo {
                line: e6ircd::bouncer::BufferedLine { line, .. },
                origin,
            } => Some((line.clone(), *origin)),
            _ => None,
        })
        .collect();
    assert_eq!(echoes.len(), 1, "exactly one echo: {seen:?}");
    assert_eq!(echoes[0].1, 7, "routed to the attachment that sent it");
    assert!(
        echoes[0].0.contains("2026-09-21T10:00:00.000Z")
            && echoes[0]
                .0
                .contains(":bncbot!~bncbot@up.example PRIVMSG #room :hello"),
        "the upstream's own echo, with its provenance: {}",
        echoes[0].0
    );
    assert!(
        !seen.iter().any(|event| matches!(
            event,
            DriverEvent::Line(e6ircd::bouncer::BufferedLine { line, .. }) if line.contains("PRIVMSG #room")
        )),
        "the echo is not also relayed as an ordinary line: {seen:?}"
    );
    let buffered = handle
        .buffer_snapshot()
        .into_iter()
        .filter(|line| line.contains("PRIVMSG #room :hello"))
        .count();
    assert_eq!(buffered, 1, "the backlog holds the line once");
}

/// A NickServ password echoed by the upstream is redacted before it reaches
/// the backlog, as the bouncer's own echo always was.
#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_echo_of_a_nickserv_password_is_redacted() {
    let handle =
        echo_message_upstream(&[":bncbot!~bncbot@up PRIVMSG NickServ :IDENTIFY hunter2"]).await;
    let mut events = handle.subscribe();
    wait_connected(&handle, &mut events).await;
    assert_eq!(
        handle.send_from(7, "PRIVMSG NickServ :IDENTIFY hunter2"),
        SendOutcome::Sent
    );
    let seen = events_within(&mut events, std::time::Duration::from_secs(2)).await;
    let echo = seen
        .iter()
        .find_map(|event| match event {
            DriverEvent::Echo {
                line: e6ircd::bouncer::BufferedLine { line, .. },
                ..
            } => Some(line.clone()),
            _ => None,
        })
        .expect("the echo is relayed");
    assert!(!echo.contains("hunter2"), "{echo}");
    assert!(
        echo.contains("[sensitive NickServ command redacted]"),
        "{echo}"
    );
    assert!(
        handle
            .buffer_snapshot()
            .iter()
            .all(|line| !line.contains("hunter2")),
        "the backlog never holds the password"
    );
}

/// Channels joined at runtime (not in the configured autojoin) are rejoined
/// after a reconnect, alongside the configured ones.
#[tokio::test(flavor = "multi_thread")]
async fn runtime_joined_channels_are_rejoined_after_reconnect() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (join_tx, mut join_rx) = tokio::sync::mpsc::channel(8);
    let (drop_tx, mut drop_rx) = tokio::sync::mpsc::channel::<()>(1);
    tokio::spawn(async move {
        // First session: register, confirm the autojoin, confirm a runtime
        // JOIN, then die on cue.
        let mut first = fake_accept(&listener).await;
        first.complete_registration("bncbot").await;
        loop {
            let line = first.read_line().await;
            if line == "JOIN #static" {
                first.send(":bncbot!~bncbot@up JOIN #static").await;
            } else if line == "JOIN #dynamic" {
                first.send(":bncbot!~bncbot@up JOIN #dynamic").await;
                break;
            }
        }
        drop_rx.recv().await;
        drop(first);
        // Second session: report every channel the driver's JOIN lines name
        // (a rejoin comma-joins them).
        let mut second = fake_accept(&listener).await;
        second.complete_registration("bncbot").await;
        loop {
            let line = second.read_line().await;
            if let Some(chans) = line.strip_prefix("JOIN ") {
                for chan in chans.split(',') {
                    join_tx.send(chan.to_string()).await.unwrap();
                }
                if chans.contains("#dynamic") {
                    return;
                }
            }
        }
    });

    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".parse().expect("test nickname"),
        autojoin: vec!["#static".parse().expect("test channel")],
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    });
    let mut events = handle.subscribe();
    wait_connected(&handle, &mut events).await;
    // Join a channel at runtime, wait for the driver's membership tracking to
    // observe the upstream's confirmation (relayed as a normal line).
    assert_eq!(handle.send("JOIN #dynamic"), SendOutcome::Sent);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Ok(DriverEvent::Line(e6ircd::bouncer::BufferedLine { line, .. })) =
                events.recv().await
                && line.contains("JOIN #dynamic")
            {
                break;
            }
        }
    })
    .await
    .expect("join confirmation never relayed");
    drop_tx.send(()).await.unwrap();
    // The driver reconnects and rejoins both channels.
    let mut rejoined = std::collections::HashSet::new();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while rejoined.len() < 2 {
            rejoined.insert(join_rx.recv().await.expect("join channel closed"));
        }
    })
    .await
    .expect("channels not rejoined");
    assert_eq!(
        rejoined
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        ["#dynamic", "#static"]
            .into_iter()
            .map(String::from)
            .collect()
    );
}

/// A half-open upstream (accepts, registers, then goes silent and never
/// answers PING) is declared dead within two keepalive windows and the
/// driver reconnects.
#[tokio::test(flavor = "multi_thread")]
async fn silent_upstream_trips_keepalive_and_reconnects() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        // Session 1: register, then go silent (read and discard, never
        // answer the driver's keepalive PING).
        let mut first = fake_accept(&listener).await;
        first.complete_registration("bncbot").await;
        loop {
            let line = first.read_line().await;
            if line.is_empty() {
                break; // driver gave up and closed
            }
        }
        // Session 2: the reconnect; register again and hold.
        let mut second = fake_accept(&listener).await;
        second.complete_registration("bncbot").await;
        loop {
            let line = second.read_line().await;
            if line.is_empty() {
                break;
            }
        }
    });

    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".parse().expect("test nickname"),
        keepalive_idle: std::time::Duration::from_millis(150),
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    });
    let mut events = handle.subscribe();
    wait_connected(&handle, &mut events).await;
    // Disconnect (keepalive timeout) then reconnect.
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            match events.recv().await {
                Ok(DriverEvent::Status {
                    status: DriverConnectionStatus::Reconnecting(_),
                    ..
                }) => break,
                Ok(_) => {}
                Err(_) => panic!("event stream ended before the keepalive trip"),
            }
        }
    })
    .await
    .expect("silent upstream was never declared dead");
    wait_connected(&handle, &mut events).await;
    let snapshot = handle.runtime_snapshot();
    assert_eq!(
        snapshot.lifecycle,
        e6ircd::bouncer::NetworkLifecycle::Connected
    );
}

/// A server that truncates to its NICKLEN welcomes the connection under a
/// nickname the owner never chose. The driver does not run under it: the
/// identity on an upstream is the configured one or none.
///
/// The session was registered, so it leaves with `QUIT` rather than a dropped
/// socket; and since no retry can shorten the nickname, the driver parks on
/// the first such welcome instead of registering, and quitting, five times.
#[tokio::test(flavor = "multi_thread")]
async fn a_welcome_under_a_different_nickname_is_a_refusal_not_an_identity() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (heard_tx, mut heard_rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move {
        let mut session = fake_accept(&listener).await;
        session.complete_registration("averyveryverylon").await;
        loop {
            let line = session.read_line().await;
            if line.is_empty() || line.starts_with("QUIT") {
                heard_tx.send(line).await.unwrap();
                break;
            }
        }
        // Any later dial would be the driver retrying what cannot change.
        let _second = fake_accept(&listener).await;
        heard_tx.send("a second dial".to_string()).await.unwrap();
        std::future::pending::<()>().await;
    });
    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "averyveryverylongnick".parse().expect("test nickname"),
        rejection_retry_floor: std::time::Duration::from_millis(20),
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    });
    let snapshot = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let snapshot = handle.runtime_snapshot();
            assert_ne!(
                snapshot.lifecycle,
                NetworkLifecycle::Connected,
                "the driver ran under a nickname nobody configured"
            );
            if snapshot.lifecycle == NetworkLifecycle::RegistrationFailed {
                return snapshot;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the welcome was neither accepted nor refused");
    assert_eq!(
        snapshot.last_error,
        Some(e6ircd::bouncer::NetworkFailure::InvalidNickname),
        "{snapshot:?}"
    );
    assert_eq!(
        snapshot.last_error_diagnostic.as_deref(),
        Some("requested averyveryverylongnick, but the server welcomed averyveryverylon"),
        "{snapshot:?}"
    );
    assert_eq!(
        snapshot.connection_attempts, 1,
        "a welcome under another nickname parks on the first occurrence: {snapshot:?}"
    );
    assert!(handle.irc_session_snapshot().is_none());
    let goodbye = tokio::time::timeout(std::time::Duration::from_secs(5), heard_rx.recv())
        .await
        .expect("the upstream heard neither a goodbye nor a close")
        .expect("upstream script ended");
    assert!(
        goodbye.starts_with("QUIT :"),
        "a registered session leaves with QUIT, not a dropped socket: {goodbye:?}"
    );
    // Parked: the upstream sees no second dial within the refusal schedule.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(heard_rx.try_recv().is_err(), "the driver dialled again");
}

/// Capabilities are negotiated hop by hop. An attached client negotiated with
/// the bouncer; the upstream's `CAP NEW`/`CAP DEL` describe a negotiation the
/// client is not part of, and a client that acts on one (requesting `sasl` from
/// the bouncer because the upstream gained it) is answered about the wrong hop.
#[tokio::test(flavor = "multi_thread")]
async fn upstream_capability_changes_are_not_relayed_to_attached_clients() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut session = fake_accept(&listener).await;
        session.complete_registration("bncbot").await;
        session.send(":up CAP bncbot NEW :sasl=PLAIN").await;
        session.send(":up CAP bncbot DEL :account-tag").await;
        session
            .send(":friend!u@h PRIVMSG bncbot :after the capability change")
            .await;
        while !session.read_line().await.is_empty() {}
    });
    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".parse().expect("test nickname"),
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    });
    let lines = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let lines = handle.buffer_snapshot();
            if lines
                .iter()
                .any(|line| line.contains("after the capability change"))
            {
                return lines;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the marker after the CAP lines was never buffered");
    assert!(
        !lines.iter().any(|line| line.contains(" CAP ")),
        "an upstream CAP line reached the client-facing stream: {lines:?}"
    );
}

/// The idle window measures the *upstream's* silence. A client that keeps
/// typing into a half-open link must not keep it looking alive: each command
/// used to restart the window, so the dead upstream was never noticed for as
/// long as anyone was talking into it.
#[tokio::test(flavor = "multi_thread")]
async fn downstream_traffic_does_not_hide_a_silent_upstream() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut session = fake_accept(&listener).await;
        session.complete_registration("bncbot").await;
        // Read and discard everything, the keepalive PING included.
        while !session.read_line().await.is_empty() {}
        let _held = fake_accept(&listener).await;
        std::future::pending::<()>().await;
    });

    let handle = std::sync::Arc::new(IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".parse().expect("test nickname"),
        keepalive_idle: std::time::Duration::from_millis(150),
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    }));
    let mut events = handle.subscribe();
    wait_connected(&handle, &mut events).await;
    let typist = handle.clone();
    let typing = tokio::spawn(async move {
        loop {
            typist.send("PRIVMSG #room :still typing");
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        }
    });
    let tripped = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            match events.recv().await {
                Ok(DriverEvent::Status {
                    status: DriverConnectionStatus::Reconnecting(failure),
                    ..
                }) => return failure,
                Ok(_) => {}
                Err(_) => panic!("event stream ended before the keepalive trip"),
            }
        }
    })
    .await;
    typing.abort();
    assert_eq!(
        tripped.expect("a silent upstream stayed connected while a client typed"),
        e6ircd::bouncer::NetworkFailure::KeepaliveTimedOut
    );
}

/// An upstream that rejects registration on every attempt, for a reason only a
/// change of configuration can clear, is retried on the refusal schedule and
/// then parked loudly, not hammered forever.
#[tokio::test(flavor = "multi_thread")]
async fn repeated_registration_rejection_parks_the_driver() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let mut session = fake_accept(&listener).await;
            session.negotiate_capabilities().await;
            while !session.read_line().await.starts_with("USER ") {}
            session.send(":up 432 * bncbot :Erroneous nickname").await;
        }
    });
    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".parse().expect("test nickname"),
        rejection_retry_floor: std::time::Duration::from_millis(20),
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    });
    let mut events = handle.subscribe();
    let notice = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            match events.recv().await {
                Ok(DriverEvent::Line(e6ircd::bouncer::BufferedLine { line, .. }))
                    if line.contains("not reconnecting until this network is reconfigured") =>
                {
                    return line;
                }
                Ok(_) => {}
                Err(_) => panic!("event stream ended before the driver parked"),
            }
        }
    })
    .await
    .expect("driver never parked");
    assert!(notice.contains("*bnc* NOTICE"), "{notice}");
    let snapshot = handle.runtime_snapshot();
    assert_eq!(
        snapshot.lifecycle,
        e6ircd::bouncer::NetworkLifecycle::RegistrationFailed
    );
    assert_eq!(snapshot.connection_attempts, 5, "{snapshot:?}");
}

/// A driver that is stopped — removed, or replaced by its own reconfigured
/// successor — leaves as a client would. Dropping the socket instead left the
/// upstream a ghost session holding the nick, which the successor then met as
/// a 433 and took the whole refusal schedule for.
#[tokio::test(flavor = "multi_thread")]
async fn a_stopped_driver_says_quit_to_its_upstream() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let mut session = fake_accept(&listener).await;
        session.complete_registration("bncbot").await;
        // The goodbye, or the empty line an unannounced close reads as.
        loop {
            let line = session.read_line().await;
            if line.is_empty() || line.starts_with("QUIT") {
                return line;
            }
        }
    });
    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".parse().expect("test nickname"),
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    });
    wait_lifecycle(&handle, NetworkLifecycle::Connected).await;
    handle.shutdown_and_wait().await;
    assert_eq!(
        upstream.await.expect("scripted upstream"),
        "QUIT :e6irc bouncer stopping"
    );
}

/// Solanum withdraws the `sasl` capability while services are down. That
/// clears by itself, so it must never park: parked networks stay down until
/// their owner re-saves them, and a few minutes of services downtime would
/// take every SASL network with it. The reason stays readable for the whole
/// wait, and the driver connects by itself once services are back.
#[tokio::test(flavor = "multi_thread")]
async fn a_services_outage_is_outlasted_not_parked() {
    const OUTAGE_DIALS: u32 = 8;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (dial_tx, mut dial_rx) = tokio::sync::mpsc::channel(32);
    tokio::spawn(async move {
        for _ in 0..OUTAGE_DIALS {
            let mut session = fake_accept(&listener).await;
            assert_eq!(session.read_line().await, "CAP LS 302");
            session.send(":up CAP * LS :server-time").await;
            dial_tx.send(()).await.expect("test is still listening");
        }
        // Services are back.
        let mut session = fake_accept(&listener).await;
        session.negotiate_sasl_capabilities().await;
        assert_eq!(session.read_line().await, "AUTHENTICATE PLAIN");
        session.send("AUTHENTICATE +").await;
        while !session.read_line().await.starts_with("AUTHENTICATE ") {}
        session
            .send(":up 903 bncbot :SASL authentication successful")
            .await;
        assert_eq!(session.read_line().await, "CAP END");
        session.send(":up 001 bncbot :welcome").await;
        while !session.read_line().await.is_empty() {}
    });
    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".parse().expect("test nickname"),
        sasl: Some(("account".into(), "secret".into())),
        rejection_retry_floor: std::time::Duration::from_millis(5),
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    });
    for dial in 1..=OUTAGE_DIALS {
        tokio::time::timeout(std::time::Duration::from_secs(10), dial_rx.recv())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "the driver stopped dialing after {} attempts: {:?}",
                    dial - 1,
                    handle.runtime_snapshot()
                )
            });
        if dial > 1 {
            // The previous refusal has been recorded by the time of this dial.
            let waiting = handle.runtime_snapshot();
            assert_ne!(waiting.lifecycle, NetworkLifecycle::RegistrationFailed);
            assert_eq!(
                waiting.last_error,
                Some(e6ircd::bouncer::NetworkFailure::SaslUnavailable),
                "the reason stays visible for the whole outage: {waiting:?}"
            );
        }
    }
    let mut events = handle.subscribe();
    wait_connected(&handle, &mut events).await;
    assert!(handle.runtime_snapshot().connection_attempts > u64::from(OUTAGE_DIALS));
}

/// Rejected credentials are never re-sent: a retry can only fail the same way,
/// and every failure counts against the account on the upstream. The driver
/// parks on the first rejection and dials exactly once.
#[tokio::test(flavor = "multi_thread")]
async fn rejected_credentials_park_without_a_second_dial() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (dial_tx, mut dial_rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        loop {
            let mut session = fake_accept(&listener).await;
            dial_tx.send(()).await.expect("test is still listening");
            session.negotiate_sasl_capabilities().await;
            assert_eq!(session.read_line().await, "AUTHENTICATE PLAIN");
            session.send("AUTHENTICATE +").await;
            loop {
                if session.read_line().await.starts_with("AUTHENTICATE ") {
                    break;
                }
            }
            session.send(":up 904 * :SASL authentication failed").await;
        }
    });
    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".parse().expect("test nickname"),
        sasl: Some(("account".into(), "wrong".into())),
        rejection_retry_floor: std::time::Duration::from_millis(20),
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    });
    wait_lifecycle(&handle, NetworkLifecycle::AuthenticationFailed).await;
    dial_rx.recv().await.expect("the first dial");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(500), dial_rx.recv())
            .await
            .is_err(),
        "a parked driver must not dial the upstream again"
    );
    let snapshot = handle.runtime_snapshot();
    assert_eq!(snapshot.connection_attempts, 1);
    assert_eq!(
        snapshot.last_error_diagnostic.as_deref(),
        Some("SASL authentication failed"),
        "the owner reads the upstream's own words: {snapshot:?}"
    );
}

/// An upstream that offers SASL but not PLAIN says nothing about the password.
/// Parking it as rejected credentials sent the owner to retype a correct
/// password forever; it is a worded registration refusal, and no credential is
/// ever put on the wire.
#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_without_the_sasl_mechanism_is_not_a_credential_rejection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let mut session = fake_accept(&listener).await;
            assert_eq!(session.read_line().await, "CAP LS 302");
            session
                .send(":up CAP * LS :sasl=EXTERNAL,SCRAM-SHA-256 server-time")
                .await;
            assert_eq!(
                session.read_line().await,
                "",
                "the driver must hang up without starting a credential exchange"
            );
        }
    });
    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".parse().expect("test nickname"),
        sasl: Some(("account".into(), "correct".into())),
        rejection_retry_floor: std::time::Duration::from_millis(20),
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    });
    // Wait on exactly what is asserted: the recorded refusal. (It is retried,
    // never parked — see `a_services_outage_is_outlasted_not_parked`.)
    let snapshot = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            let snapshot = handle.runtime_snapshot();
            if snapshot.last_error.is_some() {
                return snapshot;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the refusal was never recorded");
    assert_ne!(
        snapshot.lifecycle,
        NetworkLifecycle::AuthenticationFailed,
        "a missing mechanism says nothing about the password: {snapshot:?}"
    );
    assert_eq!(
        snapshot.last_error,
        Some(e6ircd::bouncer::NetworkFailure::SaslUnavailable),
        "{snapshot:?}"
    );
    assert_eq!(
        snapshot.last_error_diagnostic.as_deref(),
        Some("requested PLAIN; the server offers EXTERNAL,SCRAM-SHA-256"),
        "{snapshot:?}"
    );
}

/// A refusing upstream's own connection throttle shows up as dials that die
/// before registration. Such a drop must not forgive the refusals already
/// counted, or the driver would never park and would re-dial forever. A taken
/// nickname is the refusal that parks after its schedule: the holder is
/// usually a ghost of the driver's own last session, and one that outlasts
/// four minutes of retries is not.
#[tokio::test(flavor = "multi_thread")]
async fn a_dropped_dial_between_refusals_does_not_reset_the_park_count() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        // Five refusals and the one dropped dial between them; the driver parks
        // after the sixth and never dials again.
        for dial in 1..=6 {
            let mut session = fake_accept(&listener).await;
            if dial == 3 {
                // Closed before a single line: a transient drop, not a refusal.
                continue;
            }
            session.negotiate_capabilities().await;
            loop {
                if session.read_line().await.starts_with("USER ") {
                    break;
                }
            }
            session
                .send(":up 433 * bncbot :Nickname is already in use")
                .await;
        }
    });
    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".parse().expect("test nickname"),
        rejection_retry_floor: std::time::Duration::from_millis(20),
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    });
    wait_lifecycle(&handle, NetworkLifecycle::RegistrationFailed).await;
    let snapshot = handle.runtime_snapshot();
    // Five refusals plus the one dropped dial between them.
    assert_eq!(snapshot.connection_attempts, 6, "{snapshot:?}");
    assert_eq!(
        snapshot.last_error,
        Some(e6ircd::bouncer::NetworkFailure::NicknameInUse),
        "{snapshot:?}"
    );
    assert_eq!(
        snapshot.last_error_diagnostic.as_deref(),
        Some("Nickname is already in use"),
        "{snapshot:?}"
    );
}

/// While a refused registration waits for its slower retry, the upstream's
/// own reason stays readable instead of appearing only once the driver parks.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_registration_keeps_its_reason_while_retrying() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut session = fake_accept(&listener).await;
        session
            .send("ERROR :Closing Link: client (Trying to reconnect too fast.)")
            .await;
        // Hold later dials open so the driver stays in its retry wait.
        let _held = fake_accept(&listener).await;
        std::future::pending::<()>().await;
    });
    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".parse().expect("test nickname"),
        rejection_retry_floor: std::time::Duration::from_secs(30),
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    });
    let snapshot = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let snapshot = handle.runtime_snapshot();
            if snapshot.last_error.is_some() {
                return snapshot;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the refusal was never recorded");
    assert_eq!(snapshot.lifecycle, NetworkLifecycle::Reconnecting);
    assert_eq!(
        snapshot.last_error_diagnostic.as_deref(),
        Some("Closing Link: client (Trying to reconnect too fast.)"),
        "{snapshot:?}"
    );
    assert!(snapshot.next_retry_at.is_some(), "{snapshot:?}");
}

/// A full buffer evicts the oldest line, keeping the newest `cap`.
#[tokio::test(flavor = "multi_thread")]
async fn full_buffer_evicts_oldest() {
    let addr = upstream().await;
    let mut peer = e6irc_client::Connection::connect(&addr.to_string())
        .await
        .unwrap();
    peer.register(&e6irc_client::Identity {
        nick: "speaker",
        username: "speaker",
        realname: "speaker",
        server_password: None,
    })
    .await
    .unwrap();
    peer.send_line("JOIN #ring").await.unwrap();
    loop {
        if peer.next_message().await.unwrap().unwrap().command == "366" {
            break;
        }
    }
    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".parse().expect("test nickname"),
        autojoin: vec!["#ring".parse().expect("test channel")],
        buffer_cap: 3,
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    });
    let mut events = handle.subscribe();
    wait_connected(&handle, &mut events).await;
    loop {
        let message = peer.next_message().await.unwrap().unwrap();
        if message.command == "JOIN"
            && message
                .params
                .first()
                .is_some_and(|channel| channel == "#ring")
            && message
                .source
                .as_deref()
                .is_some_and(|source| source.starts_with("bncbot!"))
        {
            break;
        }
    }
    for i in 1..=5 {
        peer.send_line(&format!("PRIVMSG #ring :message {i}"))
            .await
            .unwrap();
    }
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let snapshot = handle.buffer_snapshot();
            let messages: Vec<&String> = snapshot
                .iter()
                .filter(|l| l.contains("PRIVMSG #ring :message"))
                .collect();
            // Wait for message 5 to land — the buffer passes through an
            // intermediate 3-message state (1, 2, 3) before 4 and 5 arrive
            // and evict the oldest. Checking for the newest three
            // specifically avoids that false positive on slower runners.
            if messages.iter().any(|m| m.contains("message 5")) {
                assert_eq!(messages.len(), 3, "{messages:?}");
                assert!(messages[0].contains("message 3"), "{messages:?}");
                assert!(messages[1].contains("message 4"), "{messages:?}");
                assert!(messages[2].contains("message 5"), "{messages:?}");
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("buffer did not settle at its cap");
}

/// A message sent over the BNC listener is persisted to PostgreSQL as a
/// synthesized echo, so a client that attaches after a restart still sees
/// both sides of the conversation.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn self_echo_is_persisted_to_the_backlog() {
    let url = bnc_account_db("self_echo_is_persisted_to_the_backlog", "alice", "s3cr3t").await;
    let up = upstream().await;
    let running = net::start(bnc_config(up, url.clone()))
        .await
        .expect("start");
    let bnc = running.bnc_addr.expect("bnc bound");
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let mut client = e6irc_client::Connection::connect(&bnc.to_string())
        .await
        .unwrap();
    client
        .register_sasl(
            &e6irc_client::Identity {
                nick: "alice/up",
                username: "aliceup",
                realname: "Me",
                server_password: None,
            },
            "alice",
            "s3cr3t",
        )
        .await
        .expect("bnc SASL auth");
    client
        .send_line("PRIVMSG #lobby :my side of the talk")
        .await
        .unwrap();

    let pool = observer_pool(&url).await;
    let line = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let lines = e6ircd::db::recent_bnc_lines(&pool, "alice", "up", 100)
                .await
                .expect("read");
            if let Some(l) = lines.iter().find(|l| l.contains("my side of the talk")) {
                return l.clone();
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the echo was never persisted");
    assert!(
        line.contains(":bncnick!tester@127.0.0.1 PRIVMSG"),
        "persisted echo carries the identity the upstream shows for the session: {line}"
    );
    drop(running);
}

/// Attach to the BNC listener negotiating the backlog-paging caps the default
/// `register_sasl` helper does not: `batch`, `draft/chathistory`, and
/// `draft/read-marker` (plus `server-time`/`message-tags` so stored lines keep
/// their tags). Drives the handshake manually, one message at a time.
async fn bnc_attach_with_history(
    bnc: std::net::SocketAddr,
    nick: &str,
    account: &str,
    password: &str,
) -> e6irc_client::Connection {
    let mut client = e6irc_client::Connection::connect(&bnc.to_string())
        .await
        .expect("bnc connect");
    client.send_line("CAP LS 302").await.expect("CAP LS");
    let ls = client.next_message().await.unwrap().expect("CAP LS reply");
    assert_eq!(ls.command, "CAP", "{ls:?}");
    client
        .send_line(
            "CAP REQ :sasl server-time message-tags batch draft/chathistory draft/read-marker",
        )
        .await
        .expect("CAP REQ");
    let ack = client.next_message().await.unwrap().expect("CAP ACK");
    assert_eq!(ack.command, "CAP", "{ack:?}");
    client
        .send_line("AUTHENTICATE PLAIN")
        .await
        .expect("AUTHENTICATE");
    let challenge = client
        .next_message()
        .await
        .unwrap()
        .expect("SASL challenge");
    assert_eq!(challenge.command, "AUTHENTICATE", "{challenge:?}");
    client
        .send_line(&format!("NICK {nick}"))
        .await
        .expect("NICK");
    client
        .send_line(&format!("USER {nick} 0 * :Me"))
        .await
        .expect("USER");
    let payload = e6irc_proto::base64::encode(format!("\0{account}\0{password}").as_bytes());
    client
        .send_line(&format!("AUTHENTICATE {payload}"))
        .await
        .expect("SASL payload");
    // 900 (logged in as) then 903 (success).
    let _logged_in = client.next_message().await.unwrap().expect("900");
    let success = client.next_message().await.unwrap().expect("903");
    assert_eq!(success.command, "903", "{success:?}");
    client.send_line("CAP END").await.expect("CAP END");
    let welcome = client.next_message().await.unwrap().expect("001");
    assert_eq!(welcome.command, "001", "{welcome:?}");
    let isupport = client.next_message().await.unwrap().expect("005");
    assert_eq!(isupport.command, "005", "{isupport:?}");
    assert!(
        isupport
            .params
            .iter()
            .any(|param| param == "CASEMAPPING=rfc1459"),
        "{isupport:?}"
    );
    assert!(
        isupport
            .params
            .iter()
            .any(|param| param == "CHATHISTORY=500"),
        "{isupport:?}"
    );
    // End-of-MOTD numeric closes the registration burst.
    let motd = client.next_message().await.unwrap().expect("422");
    assert_eq!(motd.command, "422", "{motd:?}");
    client
}

/// CHATHISTORY pages the PG backlog on the attach listener, MARKREAD keeps and
/// returns a per-target position, and the two compose (a client can resume a
/// target from its marker with `CHATHISTORY AFTER ... timestamp=`).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn bnc_listener_serves_chathistory_and_markread() {
    let url = bnc_account_db(
        "bnc_listener_serves_chathistory_and_markread",
        "alice",
        "s3cr3t",
    )
    .await;
    let up = upstream().await;
    let running = net::start(bnc_config(up, url)).await.expect("start");
    let bnc = running.bnc_addr.expect("bnc bound");
    // give the driver a moment to connect + join upstream
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let mut peer = e6irc_client::Connection::connect(&up.to_string())
        .await
        .unwrap();
    peer.register(&e6irc_client::Identity {
        nick: "uppeer",
        username: "uppeer",
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
    // A handful of messages to page over.
    for i in 0..5 {
        peer.send_line(&format!("PRIVMSG #lobby :buffered msg {i}"))
            .await
            .unwrap();
    }
    // Let the persistence task drain the backlog before paging.
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;

    let mut client = bnc_attach_with_history(bnc, "alice/up", "alice", "s3cr3t").await;

    // The driver's upstream registration burst (003/004/005/... numerics) and
    // connection-state NOTICEs relay through attach; drain everything until the
    // stream is quiet so none of it interleaves with the batched paging below.
    loop {
        let quiet =
            tokio::time::timeout(std::time::Duration::from_millis(300), client.next_message())
                .await;
        match quiet {
            Ok(Ok(Some(_))) => continue,
            _ => break,
        }
    }

    // CHATHISTORY LATEST, batched and ordered oldest-to-newest on the wire.
    client
        .send_line("CHATHISTORY LATEST #lobby * 10")
        .await
        .unwrap();
    let open = client.next_message().await.unwrap().expect("batch open");
    assert_eq!(open.command, "BATCH", "{open:?}");
    assert!(
        open.params
            .first()
            .map(String::as_str)
            .unwrap_or("")
            .starts_with('+'),
        "{open:?}"
    );
    let mut msgs = Vec::new();
    loop {
        let m = client.next_message().await.unwrap().expect("batch body");
        if m.command == "BATCH" {
            assert!(
                m.params
                    .first()
                    .map(String::as_str)
                    .unwrap_or("")
                    .starts_with('-'),
                "{m:?}"
            );
            break;
        }
        msgs.push(m);
    }
    assert_eq!(msgs.len(), 5, "expected the five buffered messages");
    assert_eq!(msgs[0].command, "PRIVMSG", "{:?}", msgs[0]);
    assert_eq!(
        msgs[0].params.first().map(String::as_str),
        Some("#lobby"),
        "{:?}",
        msgs[0]
    );

    // MARKREAD set then query: the position round-trips.
    client
        .send_line("MARKREAD #lobby timestamp=2024-01-01T00:00:00.000Z")
        .await
        .unwrap();
    let ack = client.next_message().await.unwrap().expect("MARKREAD ack");
    assert_eq!(ack.command, "MARKREAD", "{ack:?}");
    assert_eq!(
        ack.params.get(1).map(String::as_str),
        Some("timestamp=2024-01-01T00:00:00.000Z"),
        "{ack:?}"
    );
    client
        .send_line("MARKREAD #lobby timestamp=2020-01-01T00:00:00.000Z")
        .await
        .unwrap();
    let older = client
        .next_message()
        .await
        .unwrap()
        .expect("older MARKREAD ack");
    assert_eq!(
        older.params.get(1).map(String::as_str),
        Some("timestamp=2024-01-01T00:00:00.000Z"),
        "a read marker must never move backwards: {older:?}"
    );
    client.send_line("MARKREAD #lobby").await.unwrap();
    let query = client
        .next_message()
        .await
        .unwrap()
        .expect("MARKREAD query");
    assert_eq!(query.command, "MARKREAD", "{query:?}");
    assert_eq!(
        query.params.get(1).map(String::as_str),
        Some("timestamp=2024-01-01T00:00:00.000Z"),
        "{query:?}"
    );

    // The marker composes with paging: AFTER that instant returns only the
    // messages newer than it. Every stored message is newer than 2024, so all
    // five come back (id > 0 = from the very start of the target's history).
    client
        .send_line("CHATHISTORY AFTER #lobby timestamp=2024-01-01T00:00:00.000Z 100")
        .await
        .unwrap();
    let open = client.next_message().await.unwrap().expect("batch open");
    assert_eq!(open.command, "BATCH", "{open:?}");
    let mut after = Vec::new();
    loop {
        let m = client.next_message().await.unwrap().expect("batch body");
        if m.command == "BATCH" {
            break;
        }
        after.push(m);
    }
    assert_eq!(after.len(), 5, "AFTER the 2024 marker returns everything");

    // An unknown msgid names no position. An empty page would tell a resuming
    // client "nothing new"; it is said to be an error, in the line the core
    // also sends.
    client
        .send_line("CHATHISTORY BEFORE #lobby msgid=doesnotexist 10")
        .await
        .unwrap();
    let refused = client.next_message().await.unwrap().expect("FAIL reply");
    assert_eq!(refused.command, "FAIL", "{refused:?}");
    assert_eq!(
        refused.params,
        [
            "CHATHISTORY",
            "MESSAGE_ERROR",
            "BEFORE",
            "#lobby",
            "unknown msgid"
        ],
    );
    // A timestamp always names a position: past the newest message is a
    // genuinely empty page.
    client
        .send_line("CHATHISTORY AFTER #lobby timestamp=2099-01-01T00:00:00.000Z 10")
        .await
        .unwrap();
    let open = client.next_message().await.unwrap().expect("batch open");
    assert_eq!(open.command, "BATCH", "{open:?}");
    let empty = client
        .next_message()
        .await
        .unwrap()
        .expect("empty batch body");
    assert_eq!(empty.command, "BATCH", "{empty:?}");

    // TARGETS lists #lobby with a timestamp inside the requested open window.
    client
        .send_line(
            "CHATHISTORY TARGETS timestamp=2020-01-01T00:00:00.000Z \
             timestamp=2030-01-01T00:00:00.000Z 50",
        )
        .await
        .unwrap();
    let open = client
        .next_message()
        .await
        .unwrap()
        .expect("targets batch open");
    assert_eq!(open.command, "BATCH", "{open:?}");
    assert_eq!(
        open.params.get(1).map(String::as_str),
        Some("draft/chathistory-targets"),
        "{open:?}"
    );
    let target_line = client.next_message().await.unwrap().expect("targets body");
    assert_eq!(target_line.command, "CHATHISTORY", "{target_line:?}");
    assert_eq!(
        target_line.params.first().map(String::as_str),
        Some("TARGETS"),
        "{target_line:?}"
    );
    assert_eq!(
        target_line.params.get(1).map(String::as_str),
        Some("#lobby"),
        "{target_line:?}"
    );
    assert!(
        target_line.params.get(2).is_some(),
        "targets carry a resume timestamp: {target_line:?}"
    );
    drop(running);
}

/// The network's capacity and policy answers, given before the welcome. They
/// end by themselves, so the driver never parks on them however many arrive in
/// a row: it retries on the slow schedule, keeping the reason visible, and
/// connects once the network lets it.
enum PreWelcomeAnswer {
    /// A pre-welcome `ERROR`: Solanum's "Reconnecting too fast, throttled",
    /// "Too many host connections", a K-line.
    ThrottleError,
    /// A 465.
    Banned,
}

/// Six refusals of one kind -- more than the schedule-then-park policy
/// tolerates -- then a welcome. The driver reaches `Connected`, never
/// `RegistrationFailed`, and the reason was visible while it waited.
async fn outlasted_never_parked(answer: PreWelcomeAnswer) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (expected_failure, expected_text) = match answer {
        PreWelcomeAnswer::ThrottleError => (
            e6ircd::bouncer::NetworkFailure::RegistrationRejected,
            "Closing Link: 127.0.0.1 (Reconnecting too fast, throttled)",
        ),
        PreWelcomeAnswer::Banned => (
            e6ircd::bouncer::NetworkFailure::NetworkBanned,
            "You are banned from this server",
        ),
    };
    tokio::spawn(async move {
        for _ in 1..=6 {
            let mut session = fake_accept(&listener).await;
            match answer {
                PreWelcomeAnswer::ThrottleError => {
                    session
                        .send("ERROR :Closing Link: 127.0.0.1 (Reconnecting too fast, throttled)")
                        .await;
                }
                PreWelcomeAnswer::Banned => {
                    session.negotiate_capabilities().await;
                    loop {
                        if session.read_line().await.starts_with("USER ") {
                            break;
                        }
                    }
                    session
                        .send(":up 465 bncbot :You are banned from this server")
                        .await;
                }
            }
            drop(session);
        }
        let mut session = fake_accept(&listener).await;
        session.complete_registration("bncbot").await;
        while !session.read_line().await.is_empty() {}
    });
    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".parse().expect("test nickname"),
        rejection_retry_floor: std::time::Duration::from_millis(20),
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    });
    let mut reason_seen = false;
    let connected = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            let snapshot = handle.runtime_snapshot();
            assert_ne!(
                snapshot.lifecycle,
                NetworkLifecycle::RegistrationFailed,
                "a capacity or policy answer parked the driver: {snapshot:?}"
            );
            if snapshot.lifecycle == NetworkLifecycle::Reconnecting
                && snapshot.last_error == Some(expected_failure)
            {
                assert_eq!(
                    snapshot.last_error_diagnostic.as_deref(),
                    Some(expected_text),
                    "{snapshot:?}"
                );
                reason_seen = true;
            }
            if snapshot.lifecycle == NetworkLifecycle::Connected {
                return snapshot;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("the driver never connected");
    assert_eq!(connected.connection_attempts, 7, "{connected:?}");
    assert!(reason_seen, "the upstream's reason was never visible");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_connection_throttle_is_outlasted_never_parked() {
    outlasted_never_parked(PreWelcomeAnswer::ThrottleError).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_ban_is_outlasted_never_parked() {
    outlasted_never_parked(PreWelcomeAnswer::Banned).await;
}

/// A registered session the upstream closes with `ERROR` is reported as the
/// reason it was lost. The `ERROR` line itself never reaches an attached
/// client -- to a client it means *its* connection is over, and replayed from
/// the backlog it would mean it again -- and never enters the backlog.
#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_error_after_registration_is_a_notice_not_an_error() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (drop_tx, mut drop_rx) = tokio::sync::mpsc::channel::<()>(1);
    tokio::spawn(async move {
        let mut session = fake_accept(&listener).await;
        session.complete_registration("bncbot").await;
        drop_rx.recv().await;
        session
            .send("ERROR :Closing Link: 127.0.0.1 (Excess Flood)")
            .await;
        drop(session);
        // Hold later dials open so the driver stays in its reconnect wait.
        let _held = fake_accept(&listener).await;
        std::future::pending::<()>().await;
    });
    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".parse().expect("test nickname"),
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    });
    let mut events = handle.subscribe();
    wait_connected(&handle, &mut events).await;
    drop_tx.send(()).await.unwrap();
    // What an attached client reads, up to and including the notice.
    let mut read = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match events.recv().await {
                Ok(DriverEvent::Line(e6ircd::bouncer::BufferedLine { line, .. }))
                | Ok(DriverEvent::Notice(e6ircd::bouncer::BufferedLine { line, .. })) => {
                    let notice = line.contains("upstream closed the link");
                    read.push(line);
                    if notice {
                        return;
                    }
                }
                Ok(_) => {}
                Err(error) => panic!("event stream ended: {error}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no notice about the closed link: {read:?}"));
    assert_eq!(
        read.last().map(String::as_str),
        Some(":*bnc* NOTICE * :upstream closed the link: Closing Link: 127.0.0.1 (Excess Flood)"),
        "{read:?}"
    );
    let is_error_command = |line: &str| {
        line.strip_prefix(':')
            .and_then(|rest| rest.split_once(' '))
            .map_or(line.starts_with("ERROR"), |(_, rest)| {
                rest.starts_with("ERROR")
            })
    };
    assert!(
        !read.iter().any(|line| is_error_command(line)),
        "an ERROR command reached the attached client: {read:?}"
    );
    let snapshot = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let snapshot = handle.runtime_snapshot();
            if snapshot.lifecycle == NetworkLifecycle::Reconnecting {
                return snapshot;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the drop was never reported");
    assert_eq!(
        snapshot.last_error,
        Some(e6ircd::bouncer::NetworkFailure::ConnectionLost),
        "{snapshot:?}"
    );
    assert_eq!(
        snapshot.last_error_diagnostic.as_deref(),
        Some("Closing Link: 127.0.0.1 (Excess Flood)"),
        "{snapshot:?}"
    );
    let backlog = handle.buffer_snapshot();
    assert!(
        !backlog.iter().any(|line| is_error_command(line)),
        "an ERROR command entered the backlog: {backlog:?}"
    );
    assert!(
        backlog
            .iter()
            .any(|line| line.contains("upstream closed the link: Closing Link")),
        "{backlog:?}"
    );
}

/// 437 (the nick delay after a recent holder) is a refusal like 433: it is
/// reported with the upstream's text at once, not after the 30 s registration
/// timeout as an anonymous `registration_timed_out`.
#[tokio::test(flavor = "multi_thread")]
async fn a_nick_delay_is_a_typed_refusal_within_milliseconds() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut session = fake_accept(&listener).await;
        session.negotiate_capabilities().await;
        loop {
            if session.read_line().await.starts_with("USER ") {
                break;
            }
        }
        session
            .send(":up 437 * bncbot :Nick/channel is temporarily unavailable")
            .await;
        // Hold later dials open so the driver stays in its retry wait.
        let _held = fake_accept(&listener).await;
        std::future::pending::<()>().await;
    });
    let started = std::time::Instant::now();
    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".parse().expect("test nickname"),
        rejection_retry_floor: std::time::Duration::from_secs(30),
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    });
    let snapshot = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let snapshot = handle.runtime_snapshot();
            if snapshot.last_error.is_some() {
                return snapshot;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the 437 was not read as a refusal before the registration timeout");
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(
        snapshot.lifecycle,
        NetworkLifecycle::Reconnecting,
        "{snapshot:?}"
    );
    assert_eq!(
        snapshot.last_error,
        Some(e6ircd::bouncer::NetworkFailure::NicknameInUse),
        "{snapshot:?}"
    );
    assert_eq!(
        snapshot.last_error_diagnostic.as_deref(),
        Some("Nick/channel is temporarily unavailable"),
        "{snapshot:?}"
    );
}

/// A rejoin names its channels in as few `JOIN` lines as the wire allows. One
/// line per channel was a burst Solanum's flood allowance answers by closing
/// the link ("Excess Flood") on any network with more than a few dozen.
#[tokio::test(flavor = "multi_thread")]
async fn a_rejoin_of_many_channels_takes_few_join_lines() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let channels: Vec<String> = (0..100).map(|index| format!("#room{index:02}")).collect();
    let expected = channels.clone();
    let (lines_tx, mut lines_rx) = tokio::sync::mpsc::channel(16);
    tokio::spawn(async move {
        let mut session = fake_accept(&listener).await;
        session.complete_registration("bncbot").await;
        let mut named = std::collections::HashSet::new();
        while named.len() < expected.len() {
            let line = session.read_line().await;
            if let Some(chans) = line.strip_prefix("JOIN ") {
                for chan in chans.split(',') {
                    named.insert(chan.to_string());
                }
                lines_tx.send(line.clone()).await.unwrap();
            }
        }
        while !session.read_line().await.is_empty() {}
    });
    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".parse().expect("test nickname"),
        autojoin: channels
            .iter()
            .map(|channel| channel.parse().expect("test channel"))
            .collect(),
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    });
    let mut events = handle.subscribe();
    wait_connected(&handle, &mut events).await;
    let mut lines = Vec::new();
    let mut named: Vec<String> = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while named.len() < channels.len() {
            let line = lines_rx.recv().await.expect("upstream script ended");
            named.extend(line["JOIN ".len()..].split(',').map(str::to_string));
            lines.push(line);
        }
    })
    .await
    .expect("not every channel was joined");
    assert!(lines.len() <= 5, "{} JOIN lines: {lines:?}", lines.len());
    assert!(
        lines.iter().all(|line| line.len() <= 510),
        "a JOIN line exceeds the wire budget: {lines:?}"
    );
    let mut sorted = named.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        named.len(),
        channels.len(),
        "a channel was named twice: {lines:?}"
    );
    assert_eq!(sorted, channels, "{lines:?}");
}

/// The synthesized echo of an own message carries the identity the upstream
/// shows: the configured user name behind a `~` and the server's name until
/// one of our own echoes reveals the real user and host, and those afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn self_echoes_carry_the_identity_the_upstream_shows() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (confirm_tx, mut confirm_rx) = tokio::sync::mpsc::channel::<()>(1);
    tokio::spawn(async move {
        let mut session = fake_accept(&listener).await;
        session.complete_registration("bncbot").await;
        loop {
            if session.read_line().await.starts_with("JOIN ") {
                break;
            }
        }
        confirm_rx.recv().await;
        session.send(":bncbot!~e6e2e@82.77.225.81 JOIN #room").await;
        loop {
            let _ = session.read_line().await;
        }
    });
    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".parse().expect("test nickname"),
        username: "e6e2e".parse().expect("test user name"),
        autojoin: vec!["#room".parse().expect("test channel")],
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    });
    let mut events = handle.subscribe();
    wait_connected(&handle, &mut events).await;
    async fn next_echo(events: &mut tokio::sync::broadcast::Receiver<DriverEvent>) -> String {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Ok(DriverEvent::Echo {
                    line: e6ircd::bouncer::BufferedLine { line, .. },
                    ..
                }) = events.recv().await
                {
                    return line;
                }
            }
        })
        .await
        .expect("no echo")
    }
    assert_eq!(handle.send("PRIVMSG #room :before"), SendOutcome::Sent);
    let before = next_echo(&mut events).await;
    assert!(
        before.contains(":bncbot!~e6e2e@127.0.0.1 PRIVMSG #room :before"),
        "the configured user name and the server name, until better is known: {before}"
    );
    confirm_tx.send(()).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Ok(DriverEvent::Line(e6ircd::bouncer::BufferedLine { line, .. })) =
                events.recv().await
                && line.contains("JOIN #room")
            {
                break;
            }
        }
    })
    .await
    .expect("join confirmation never relayed");
    assert_eq!(handle.send("PRIVMSG #room :after"), SendOutcome::Sent);
    let after = next_echo(&mut events).await;
    assert!(
        after.contains(":bncbot!~e6e2e@82.77.225.81 PRIVMSG #room :after"),
        "the host the upstream showed in our own JOIN: {after}"
    );
}

/// A server without capability negotiation may answer `CAP LS` with 451
/// ("you have not registered"). That is not a refusal to register: the driver
/// registers plainly and connects on the first attempt.
#[tokio::test(flavor = "multi_thread")]
async fn a_server_answering_451_to_capability_discovery_connects_at_once() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut session = fake_accept(&listener).await;
        assert_eq!(session.read_line().await, "CAP LS 302");
        session.send(":up 451 * :You have not registered").await;
        loop {
            let line = session.read_line().await;
            assert!(!line.starts_with("CAP"), "{line}");
            if line.starts_with("USER ") {
                session.send(":up 001 bncbot :welcome").await;
                break;
            }
        }
        while !session.read_line().await.is_empty() {}
    });
    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".parse().expect("test nickname"),
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    });
    let mut events = handle.subscribe();
    wait_connected(&handle, &mut events).await;
    let snapshot = handle.runtime_snapshot();
    assert_eq!(snapshot.connection_attempts, 1, "{snapshot:?}");
    assert_eq!(snapshot.last_error, None, "{snapshot:?}");
}

/// The per-network backlog cap holds across restarts. The amortized trim used
/// to count only the lines one persistence task wrote since it started, so a
/// network restarted before every thousandth line was never trimmed at all.
/// Each start now trims once, after the preload.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn the_backlog_cap_holds_across_restarts() {
    const CAP: i64 = 5_000;
    let url = bnc_account_db("the_backlog_cap_holds_across_restarts", "alice", "s3cr3t").await;
    let pool = observer_pool(&url).await;
    // A buffer already at the cap, as a long-running network leaves it.
    sqlx::query(
        "INSERT INTO bnc_buffer (owner, network, line, sent_at)
         SELECT 'alice', 'up', ':s NOTICE * :seed ' || n, '2026-01-01T00:00:00.000Z'
         FROM generate_series(1, $1) n",
    )
    .bind(CAP as i32)
    .execute(&pool)
    .await
    .expect("seed backlog");
    // Rows that existed before a start: the start's trim must bring them
    // within the cap (lines the new driver writes afterwards are not its
    // business — the amortized trim bounds those).
    let newest_id = || {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Option<i64>>("SELECT max(id) FROM bnc_buffer")
                .fetch_one(&pool)
                .await
                .expect("max id")
                .unwrap_or(0)
        }
    };
    let rows_through = |through: i64| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM bnc_buffer
                 WHERE owner = 'alice' AND network = 'up' AND id <= $1",
            )
            .bind(through)
            .fetch_one(&pool)
            .await
            .expect("count")
        }
    };
    let batch_rows = |batch: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM bnc_buffer
                 WHERE owner = 'alice' AND network = 'up' AND line LIKE $1",
            )
            .bind(format!("%:{batch} %"))
            .fetch_one(&pool)
            .await
            .expect("count batch")
        }
    };
    let up = upstream().await;
    let mut peer = e6irc_client::Connection::connect(&up.to_string())
        .await
        .expect("peer connect");
    peer.register(&e6irc_client::Identity {
        nick: "uppeer",
        username: "uppeer",
        realname: "peer",
        server_password: None,
    })
    .await
    .expect("peer register");
    peer.send_line("JOIN #lobby").await.expect("join");
    loop {
        if peer.next_message().await.unwrap().unwrap().command == "366" {
            break;
        }
    }
    for batch in ["first", "second"] {
        let before = newest_id().await;
        let running = net::start(bnc_config(up, url.clone()))
            .await
            .expect("start");
        // The start trims the buffer back to the cap.
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            while rows_through(before).await > CAP {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("the {batch} start left the backlog over the cap"));
        // Wait until the driver has joined and persists the peer's lines.
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        for n in 0..600 {
            peer.send_line(&format!("PRIVMSG #lobby :{batch} {n}"))
                .await
                .expect("send");
            if n % 100 == 99 {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while batch_rows(batch).await < 600 {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("the {batch} batch was never fully persisted"));
        running.shutdown.run().await;
    }
    // A third start trims again.
    let before = newest_id().await;
    let running = net::start(bnc_config(up, url.clone()))
        .await
        .expect("start");
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        while rows_through(before).await > CAP {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the final start left the backlog over the cap");
    assert_eq!(batch_rows("second").await, 600, "the newest lines are kept");
    running.shutdown.run().await;
}
