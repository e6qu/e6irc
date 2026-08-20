//! BNC irc-driver e2e: point the driver at an e6ircd instance acting
//! as the "external network" and verify it registers, relays, and
//! buffers upstream traffic.

use e6ircd::bouncer::{
    DriverConnectionStatus, DriverEvent, IrcNetwork, NetworkConfig, NetworkHandle,
    NetworkLifecycle, SendOutcome, preflight_irc,
};
use e6ircd::config::{Config, ListenerConfig, NetworkKind};
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
        ..Config::default()
    };
    net::start(config).await.expect("start").addrs[0]
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
    let result = preflight_irc(&NetworkConfig {
        addr: addr.to_string(),
        nick: "preflight".into(),
        realname: "preflight qualification".into(),
        ..NetworkConfig::default()
    })
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
        nick: "bncbot".into(),
        realname: "bnc".into(),
        autojoin: vec!["#bnc".into()],
        ..NetworkConfig::default()
    });
    let mut events = handle.subscribe();
    wait_connected(&handle, &mut events).await;

    // a separate client joins #bnc and messages it
    let mut other = e6irc_client::Connection::connect(&addr.to_string())
        .await
        .expect("connect");
    other
        .register("speaker", "speaker")
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
                Ok(DriverEvent::Line(l)) if l.contains("PRIVMSG #bnc :hello bouncer") => {
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
        nick: "bncbot".into(),
        realname: "bnc".into(),
        autojoin: vec![],
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
                Ok(DriverEvent::Line(l)) if l.contains("PRIVMSG #bnc :caf") => {
                    // The non-UTF-8 body was relayed, lossily decoded.
                    saw_bad_line = true;
                }
                Ok(DriverEvent::Line(l)) if l.contains("upstream input rejected") => {
                    saw_rejection = true;
                }
                Ok(DriverEvent::Line(l)) if l.contains("after the bad line") => {
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
    e6ircd::db::create_account(&pool, account, password)
        .await
        .expect("create");
    drop(pool);
    url
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
        database: Some(DatabaseConfig { url }),
        networks: vec![
            NetworkEntry {
                kind: NetworkKind::Irc,
                name: "up".into(),
                owner: Some("alice".into()),
                addr: up.to_string(),
                tls: false,
                nick: "bncnick".into(),
                realname: Some("bncnick".into()),
                autojoin: vec!["#lobby".into()],
                buffer_cap: 1000,
                sasl_account: None,
                sasl_password: None,
            },
            // A network owned by a different account: alice must not see it.
            NetworkEntry {
                kind: NetworkKind::Irc,
                name: "bobnet".into(),
                owner: Some("bob".into()),
                addr: up.to_string(),
                tls: false,
                nick: "bobnick".into(),
                realname: Some("bobnick".into()),
                autojoin: vec![],
                buffer_cap: 1000,
                sasl_account: None,
                sasl_password: None,
            },
        ],
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
        }),
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
    peer.register("uppeer", "peer").await.unwrap();
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
        .register_sasl("alice/up", "Me", "alice", "s3cr3t")
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
        anon.register("alice/up", "Me").await.is_err(),
        "unauthenticated attach must be refused"
    );

    // Wrong password: SASL fails (904), register_sasl errors.
    let mut bad = e6irc_client::Connection::connect(&bnc.to_string())
        .await
        .unwrap();
    assert!(
        bad.register_sasl("alice/up", "Me", "alice", "wrong")
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
            .register_sasl("alice/bobnet", "Me", "alice", "s3cr3t")
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
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn driver_authenticates_to_sasl_upstream() {
    use e6ircd::config::DatabaseConfig;
    let url = support::test_db("driver_authenticates_to_sasl_upstream").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account(&pool, "bncacct", "bncpass")
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
        database: Some(DatabaseConfig { url }),
        ..Config::default()
    };
    let up = net::start(up_config).await.expect("start").addrs[0];

    // driver with SASL creds
    let handle = IrcNetwork::start(NetworkConfig {
        addr: up.to_string(),
        nick: "bncacct".into(),
        realname: "bnc".into(),
        sasl: Some(("bncacct".into(), "bncpass".into())),
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
    observer.register("obs", "obs").await.unwrap();
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
    peer.register("uppeer", "peer").await.unwrap();
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
    let pool = e6ircd::db::connect_and_migrate(&url).await.expect("pool");
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
        database: Some(DatabaseConfig { url: url.clone() }),
        networks: vec![NetworkEntry {
            kind: NetworkKind::Irc,
            name: "up".into(),
            owner: Some("alice".into()),
            addr: "127.0.0.1:1".into(), // unreachable: no live traffic
            tls: false,
            nick: "bncnick".into(),
            realname: Some("bncnick".into()),
            autojoin: vec![],
            buffer_cap: 1000,
            sasl_account: None,
            sasl_password: None,
        }],
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
        }),
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
        .register_sasl("alice/up", "Me", "alice", "s3cr3t")
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
        database: Some(DatabaseConfig { url }),
        networks: vec![NetworkEntry {
            name: "home".into(),
            kind: NetworkKind::Local,
            owner: Some("alice".into()),
            addr: String::new(),
            tls: false,
            nick: "alicelocal".into(),
            realname: Some("Alice Local".into()),
            autojoin: vec!["#local".into()],
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
    let irc = running.addrs[0];
    let bnc = running.bnc_addr.expect("bnc bound");

    // Let the local driver register in-process and join #local.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // A normal client on the main listener joins #local and speaks.
    let mut peer = e6irc_client::Connection::connect(&irc.to_string())
        .await
        .unwrap();
    peer.register("peer", "peer").await.unwrap();
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
        .register_sasl("alice/home", "Me", "alice", "s3cr3t")
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
    peer.register("uppeer", "peer")
        .await
        .expect("peer register");
    peer.send_line("JOIN #lobby").await.expect("join");
    loop {
        if peer.next_message().await.unwrap().unwrap().command == "366" {
            break;
        }
    }

    let pool = e6ircd::db::connect_and_migrate(&url).await.expect("pool");
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
    peer.register("uppeer", "peer")
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

    let pool = e6ircd::db::connect_and_migrate(&url).await.expect("pool");
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

    async fn negotiate_capabilities(&mut self) {
        assert_eq!(self.read_line().await, "CAP LS 302");
        self.send(":up CAP * LS :server-time message-tags account-tag")
            .await;
        for capability in ["server-time", "message-tags", "account-tag"] {
            assert_eq!(self.read_line().await, format!("CAP REQ :{capability}"));
            self.send(&format!(":up CAP * ACK :{capability}")).await;
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

/// A ghost holding our configured nick draws a 433; the driver must offer
/// one replacement nick on the same connection instead of giving up.
#[tokio::test(flavor = "multi_thread")]
async fn nick_conflict_retries_with_alt_nick() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (nick_tx, mut nick_rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        let mut session = fake_accept(&listener).await;
        session.negotiate_capabilities().await;
        let mut refused = false;
        // The registration burst is pipelined (NICK, USER, CAP END arrive
        // together), so the 433 meets the client in await_welcome; the retry
        // is a second NICK, which is what gets welcomed.
        loop {
            let line = session.read_line().await;
            if line == "NICK bncbot" && !refused {
                refused = true;
                session
                    .send(":up 433 * bncbot :Nickname is already in use")
                    .await;
            } else if let Some(nick) = line.strip_prefix("NICK ") {
                nick_tx.send(nick.to_string()).await.unwrap();
                session.send(&format!(":up 001 {nick} :welcome")).await;
                break;
            }
        }
        // Hold the session open so the driver stays connected.
        loop {
            let line = session.read_line().await;
            if line.is_empty() {
                break;
            }
        }
    });

    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".into(),
        ..NetworkConfig::default()
    });
    let mut events = handle.subscribe();
    wait_connected(&handle, &mut events).await;
    let offered = tokio::time::timeout(std::time::Duration::from_secs(5), nick_rx.recv())
        .await
        .expect("no replacement nick")
        .expect("channel closed");
    assert_eq!(offered, "bncbot_");

    // The synthesized self-echo uses the confirmed nick, while the ident
    // stays the originally configured one.
    assert_eq!(handle.send("PRIVMSG #room :who am i"), SendOutcome::Sent);
    let echo = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Ok(DriverEvent::Echo { line, .. }) = events.recv().await {
                return line;
            }
        }
    })
    .await
    .expect("no echo");
    assert!(echo.contains(":bncbot_!~bncbot@"), "{echo}");
}

/// A forced upstream NICK changes the driver's identity; later self-echoes
/// use the new nick.
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
        nick: "bncbot".into(),
        ..NetworkConfig::default()
    });
    let mut events = handle.subscribe();
    wait_connected(&handle, &mut events).await;
    nick_tx.send(()).await.unwrap();
    // Drain the NICK line itself, then send a message whose echo must use
    // the new nick.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Ok(DriverEvent::Line(line)) = events.recv().await
                && line.contains("NICK :renamed")
            {
                break;
            }
        }
    })
    .await
    .expect("nick line never relayed");
    assert_eq!(
        handle.send("PRIVMSG #room :after rename"),
        SendOutcome::Sent
    );
    go_tx.send(()).await.unwrap();
    let echo = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Ok(DriverEvent::Echo { line, .. }) = events.recv().await {
                return line;
            }
        }
    })
    .await
    .expect("no echo");
    assert!(echo.contains(":renamed!~bncbot@"), "{echo}");
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
        // Second session: report every JOIN the driver sends.
        let mut second = fake_accept(&listener).await;
        second.complete_registration("bncbot").await;
        loop {
            let line = second.read_line().await;
            if let Some(chan) = line.strip_prefix("JOIN ") {
                join_tx.send(chan.to_string()).await.unwrap();
                if chan == "#dynamic" {
                    return;
                }
            }
        }
    });

    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".into(),
        autojoin: vec!["#static".into()],
        ..NetworkConfig::default()
    });
    let mut events = handle.subscribe();
    wait_connected(&handle, &mut events).await;
    // Join a channel at runtime, wait for the driver's membership tracking to
    // observe the upstream's confirmation (relayed as a normal line).
    assert_eq!(handle.send("JOIN #dynamic"), SendOutcome::Sent);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Ok(DriverEvent::Line(line)) = events.recv().await
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
        nick: "bncbot".into(),
        keepalive_idle: std::time::Duration::from_millis(150),
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

/// An upstream that rejects registration on every attempt is retried with
/// backoff and then parked loudly, not hammered forever.
#[tokio::test(flavor = "multi_thread")]
async fn repeated_registration_rejection_parks_the_driver() {
    let addr = upstream().await;
    // A DB-less upstream does not advertise SASL, so requiring it makes every
    // registration attempt fail with a terminal (non-transient) rejection.
    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".into(),
        sasl: Some(("account".into(), "secret".into())),
        ..NetworkConfig::default()
    });
    let mut events = handle.subscribe();
    let notice = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            match events.recv().await {
                Ok(DriverEvent::Line(line))
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
    assert!(snapshot.connection_attempts >= 5, "{snapshot:?}");
}

/// A full buffer evicts the oldest line, keeping the newest `cap`.
#[tokio::test(flavor = "multi_thread")]
async fn full_buffer_evicts_oldest() {
    let addr = upstream().await;
    let mut peer = e6irc_client::Connection::connect(&addr.to_string())
        .await
        .unwrap();
    peer.register("speaker", "speaker").await.unwrap();
    peer.send_line("JOIN #ring").await.unwrap();
    loop {
        if peer.next_message().await.unwrap().unwrap().command == "366" {
            break;
        }
    }
    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bncbot".into(),
        autojoin: vec!["#ring".into()],
        buffer_cap: 3,
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
        .register_sasl("alice/up", "Me", "alice", "s3cr3t")
        .await
        .expect("bnc SASL auth");
    client
        .send_line("PRIVMSG #lobby :my side of the talk")
        .await
        .unwrap();

    let pool = e6ircd::db::connect_and_migrate(&url).await.expect("pool");
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
        line.contains(":bncnick!~bncnick@"),
        "persisted echo carries the upstream identity: {line}"
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
    peer.register("uppeer", "peer").await.unwrap();
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
        Some("2024-01-01T00:00:00.000Z"),
        "{ack:?}"
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
        Some("2024-01-01T00:00:00.000Z"),
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

    // An unknown msgid selector is an empty page, not an error.
    client
        .send_line("CHATHISTORY BEFORE #lobby msgid=doesnotexist 10")
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
