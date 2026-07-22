//! BNC irc-driver e2e: point the driver at an e6ircd instance acting
//! as the "external network" and verify it registers, relays, and
//! buffers upstream traffic.

use e6ircd::bouncer::{DriverEvent, IrcNetwork, NetworkConfig};
use e6ircd::config::{Config, ListenerConfig};
use e6ircd::net;

mod support;

async fn upstream() -> std::net::SocketAddr {
    let config = Config {
        server_name: "irc.upstream.example".into(),
        network_name: "Upstream".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }],
        ..Config::default()
    };
    net::start(config).await.expect("start").addrs[0]
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
    // subscribe before the driver task runs (no await yet) so no events race us
    let mut events = handle.subscribe();

    // wait for Connected
    let connected = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match events.recv().await {
                Ok(DriverEvent::Connected) => return,
                Ok(_) => {}
                Err(_) => panic!("driver stopped"),
            }
        }
    })
    .await;
    assert!(connected.is_ok(), "driver never connected");

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
    handle.send("PRIVMSG #bnc :from the bouncer");
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
                Ok(DriverEvent::Disconnected) => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
    })
    .await
    .expect("timeout");
    assert!(disconnected, "expected a Disconnected event");
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
        }],
        database: Some(DatabaseConfig { url }),
        networks: vec![
            NetworkEntry {
                kind: Default::default(),
                name: "up".into(),
                owner: Some("alice".into()),
                addr: up.to_string(),
                tls: false,
                nick: "bncnick".into(),
                realname: None,
                autojoin: vec!["#lobby".into()],
                buffer_cap: 1000,
                sasl_account: None,
                sasl_password: None,
            },
            // A network owned by a different account: alice must not see it.
            NetworkEntry {
                kind: Default::default(),
                name: "bobnet".into(),
                owner: Some("bob".into()),
                addr: up.to_string(),
                tls: false,
                nick: "bobnick".into(),
                realname: None,
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
    assert!(confirmed.starts_with("alice/up"), "{confirmed}");

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
    let connected = tokio::time::timeout(std::time::Duration::from_secs(6), async {
        loop {
            match events.recv().await {
                Ok(DriverEvent::Connected) => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
    })
    .await
    .expect("timeout");
    assert!(
        connected,
        "driver failed to SASL-authenticate to the upstream"
    );

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
        }],
        database: Some(DatabaseConfig { url: url.clone() }),
        networks: vec![NetworkEntry {
            kind: Default::default(),
            name: "up".into(),
            owner: Some("alice".into()),
            addr: "127.0.0.1:1".into(), // unreachable: no live traffic
            tls: false,
            nick: "bncnick".into(),
            realname: None,
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
        }],
        database: Some(DatabaseConfig { url }),
        networks: vec![NetworkEntry {
            name: "home".into(),
            kind: NetworkKind::Local,
            owner: Some("alice".into()),
            addr: String::new(),
            tls: false,
            nick: "alicelocal".into(),
            realname: None,
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
