//! End-to-end tests over real sockets: a full `e6ircd` network stack
//! (listeners → conn tasks → core worker) exercised the way a real IRC
//! client would.

use std::time::Duration;

use e6ircd::config::{Config, ListenerConfig, TlsConfig};
use e6ircd::net;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

fn test_config() -> Config {
    Config {
        server_name: "irc.e2e.example".into(),
        network_name: "E2ENet".into(),
        motd: vec!["e2e".into()],
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        ..Config::default()
    }
}

struct Client {
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
}

impl Client {
    async fn connect(addr: std::net::SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).await.expect("connect");
        let (r, w) = stream.into_split();
        Self {
            reader: BufReader::new(r),
            writer: w,
        }
    }

    async fn send(&mut self, line: &str) {
        self.writer
            .write_all(format!("{line}\r\n").as_bytes())
            .await
            .expect("write");
    }

    /// Read lines until one contains `needle` (5s cap); returns it.
    async fn expect(&mut self, needle: &str) -> String {
        timeout(Duration::from_secs(5), async {
            loop {
                let mut line = String::new();
                let n = self.reader.read_line(&mut line).await.expect("read");
                assert!(n > 0, "EOF while waiting for {needle:?}");
                if line.contains(needle) {
                    return line.trim_end().to_string();
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timeout waiting for {needle:?}"))
    }

    async fn register(&mut self, nick: &str) {
        self.send(&format!("NICK {nick}")).await;
        self.send(&format!("USER {nick} 0 * :{nick}")).await;
        self.expect(" 376 ").await; // end of MOTD = burst complete
    }
}

#[tokio::test]
async fn two_clients_join_and_message() {
    let running = net::start(test_config()).await.expect("start");
    let addr = running.addrs[0];

    let mut alice = Client::connect(addr).await;
    alice.register("alice").await;
    let mut bob = Client::connect(addr).await;
    bob.register("bob").await;

    alice.send("JOIN #e2e").await;
    alice.expect(" 366 ").await;
    bob.send("JOIN #e2e").await;
    bob.expect(" 366 ").await;
    alice.expect("bob").await; // bob's JOIN seen by alice

    alice.send("PRIVMSG #e2e :hello over tcp").await;
    let got = bob.expect("PRIVMSG").await;
    assert!(got.starts_with(":alice!alice@"), "{got}");
    assert!(got.ends_with("PRIVMSG #e2e :hello over tcp"), "{got}");
}

#[tokio::test]
async fn runtime_shards_deliver_and_stop_together() {
    for core_workers in [2, 3] {
        let mut config = test_config();
        config.core_workers = core_workers;
        let running = net::start(config).await.expect("start sharded server");
        let addr = running.addrs[0];
        let mut clients = Vec::new();
        for index in 0..12 {
            let mut client = Client::connect(addr).await;
            client
                .register(&format!("shard{core_workers}_{index}"))
                .await;
            client.send("JOIN #runtime").await;
            client.expect(" 366 ").await;
            clients.push(client);
        }

        clients[0]
            .send("PRIVMSG #runtime :cross-shard runtime delivery")
            .await;
        for client in clients.iter_mut().skip(1) {
            let line = client
                .expect("PRIVMSG #runtime :cross-shard runtime delivery")
                .await;
            assert!(line.contains("shard"), "unexpected delivery: {line}");
        }

        // Connection identifiers are handed out in order and a session lives
        // on shard `id % workers`, so neighbours in this list are on different
        // shards: everything below crosses from one worker to another.
        let (asker, rest) = clients.split_first_mut().expect("clients");
        let peer = &mut rest[0];
        let peer_nick = format!("shard{core_workers}_1");
        asker
            .send(&format!("PRIVMSG {peer_nick} :across the shards"))
            .await;
        let line = peer.expect("across the shards").await;
        assert!(line.contains(&format!("PRIVMSG {peer_nick} :")), "{line}");

        asker.send(&format!("WHOIS {peer_nick}")).await;
        let user = asker.expect(" 311 ").await;
        assert!(user.contains(&peer_nick), "{user}");
        let channels = asker.expect(" 319 ").await;
        assert!(channels.contains("#runtime"), "{channels}");
        asker.expect(" 318 ").await;

        let watched = format!("late{core_workers}");
        asker.send(&format!("MONITOR + {watched}")).await;
        asker.expect(" 731 ").await;
        let mut late = Client::connect(addr).await;
        late.register(&watched).await;
        let online = asker.expect(" 730 ").await;
        assert!(online.contains(&format!("{watched}!")), "{online}");
        late.send("QUIT :done").await;
        let offline = asker.expect(" 731 ").await;
        assert!(offline.contains(&watched), "{offline}");

        assert_eq!(
            running.shutdown.run().await,
            net::ShutdownOutcome::Flushed,
            "all {core_workers} shards must stop cleanly"
        );
    }
}

#[tokio::test]
async fn whois_reports_idle_and_signon() {
    let running = net::start(test_config()).await.expect("start");
    let addr = running.addrs[0];

    let mut alice = Client::connect(addr).await;
    alice.register("alice").await;
    let mut bob = Client::connect(addr).await;
    bob.register("bob").await;

    // WHOIS bob must include RPL_WHOISIDLE (317) with an idle count and a
    // signon timestamp, terminated by RPL_ENDOFWHOIS (318).
    alice.send("WHOIS bob").await;
    let idle = alice.expect(" 317 ").await;
    assert!(idle.contains(" 317 alice bob "), "{idle}");
    // Params after the nick are: <idle> <signon> :seconds idle, signon time
    let tail = idle.split(" 317 alice bob ").nth(1).expect("317 params");
    let mut fields = tail.split_whitespace();
    let idle_secs: u64 = fields.next().unwrap().parse().expect("idle is an integer");
    let signon: u64 = fields
        .next()
        .unwrap()
        .parse()
        .expect("signon is an integer");
    assert!(idle_secs < 5, "idle should be near-zero, got {idle_secs}");
    assert!(signon > 0, "signon must be a real timestamp, got {signon}");
    alice.expect(" 318 ").await;
}

#[tokio::test]
async fn quit_closes_the_socket() {
    let running = net::start(test_config()).await.expect("start");
    let mut c = Client::connect(running.addrs[0]).await;
    c.register("quitter").await;
    c.send("QUIT :done").await;
    c.expect("ERROR :Closing Link").await;
    // server closes: read must hit EOF
    let eof = timeout(Duration::from_secs(5), async {
        loop {
            let mut line = String::new();
            if c.reader.read_line(&mut line).await.expect("read") == 0 {
                return;
            }
        }
    })
    .await;
    assert!(eof.is_ok(), "socket not closed after QUIT");
}

/// A client that sends its whole session and then closes its sending side
/// (`nc -N`, a scripted client) still reads every reply: the welcome and the
/// closing `ERROR`. The connection used to be torn down the moment the read
/// side saw EOF, discarding whatever the core had not yet written.
#[tokio::test]
async fn a_half_closing_client_reads_every_reply_to_what_it_sent() {
    use tokio::io::AsyncReadExt;
    let running = net::start(test_config()).await.expect("start");
    let mut stream = TcpStream::connect(running.addrs[0]).await.expect("connect");
    stream
        .write_all(b"NICK halfclose\r\nUSER halfclose 0 * :half\r\nQUIT :bye\r\n")
        .await
        .expect("write");
    stream.shutdown().await.expect("half-close");
    let mut received = Vec::new();
    timeout(Duration::from_secs(10), stream.read_to_end(&mut received))
        .await
        .expect("the server closes once it has answered")
        .expect("read");
    let received = String::from_utf8_lossy(&received);
    assert!(received.contains(" 001 halfclose "), "{received}");
    assert!(received.contains(" 376 halfclose "), "{received}");
    assert!(received.contains("ERROR :Closing Link"), "{received}");
}

#[tokio::test]
async fn overlong_line_gets_417_and_connection_survives() {
    let running = net::start(test_config()).await.expect("start");
    let mut c = Client::connect(running.addrs[0]).await;
    c.register("longy").await;
    let long = format!("PRIVMSG #x :{}", "A".repeat(600));
    c.send(&long).await;
    c.expect(" 417 ").await;
    c.send("PING still-alive").await;
    c.expect("PONG").await;
}

#[tokio::test]
async fn tls_client_full_flow() {
    use rustls_pki_types::pem::PemObject;

    // self-signed cert for the test only
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("gen cert");
    let dir = std::env::temp_dir().join(format!("e6irc-tls-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).expect("write key");

    let mut config = test_config();
    config.listeners = vec![ListenerConfig {
        addr: "127.0.0.1:0".parse().unwrap(),
        tls: Some(TlsConfig {
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
        }),
        websocket: false,
    }];
    let running = net::start(config).await.expect("start tls");
    let addr = running.addrs[0];

    // client trusts exactly the test cert
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from_pem_file(&cert_path).expect("read cert"))
        .expect("add root");
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));
    let tcp = TcpStream::connect(addr).await.expect("tcp");
    let mut tls = connector
        .connect("localhost".try_into().unwrap(), tcp)
        .await
        .expect("tls handshake");

    tls.write_all(b"NICK secure\r\nUSER s 0 * :S\r\n")
        .await
        .expect("write");
    let mut reader = BufReader::new(tls);
    let got = timeout(Duration::from_secs(5), async {
        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line).await.expect("read");
            assert!(n > 0, "EOF before welcome");
            if line.contains(" 001 ") {
                return line;
            }
        }
    })
    .await
    .expect("timeout waiting for 001 over TLS");
    assert!(got.contains("secure"), "{got}");

    std::fs::remove_dir_all(&dir).ok();
}

/// e6ircd has no connection password of its own, so a `PASS` before
/// registration is accepted and ignored, as RFC 2812 servers without one do —
/// a 451 in answer to it would be read by a client as the answer to the
/// `CAP LS` it sends next. After registration it is 462, like `USER`.
#[tokio::test]
async fn a_server_password_is_accepted_before_registration_and_refused_after() {
    let config = Config {
        server_name: "irc.pass.example".into(),
        network_name: "PassNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        ..Config::default()
    };
    let addr = net::start(config).await.expect("start").addrs[0];
    let password = e6irc_client::ServerPassword::parse("unused".into()).expect("valid");
    let mut c = e6irc_client::Connection::connect(&addr.to_string())
        .await
        .unwrap();
    let nick = timeout(
        Duration::from_secs(5),
        c.register(&e6irc_client::Identity {
            nick: "passer",
            username: "passer",
            realname: "p",
            server_password: Some(&password),
        }),
    )
    .await
    .expect("registration after PASS neither finished nor failed")
    .expect("register after PASS");
    assert_eq!(nick, "passer");
    c.send_line("PASS :again").await.unwrap();
    let reply = timeout(Duration::from_secs(5), async {
        loop {
            let message = c.next_message().await.unwrap().expect("open");
            // The welcome burst (a 422 for the absent MOTD among it) comes
            // first; the answer to PASS is one of these.
            if matches!(message.command.as_str(), "421" | "451" | "461" | "462") {
                return message;
            }
        }
    })
    .await
    .expect("PASS after registration is answered");
    assert_eq!(reply.command, "462", "{reply:?}");
}

#[tokio::test]
async fn per_ip_connection_limit_refuses_excess() {
    use e6ircd::config::LimitsConfig;
    let config = Config {
        server_name: "irc.limit.example".into(),
        network_name: "LimitNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        limits: LimitsConfig {
            max_connections_per_ip: Some(2),
            registration_burst: None,
            ..LimitsConfig::default()
        },
        ..Config::default()
    };
    let addr = net::start(config).await.expect("start").addrs[0];

    // Two connections from this IP register fine and stay open.
    let mut held = Vec::new();
    for i in 0..2 {
        let mut c = e6irc_client::Connection::connect(&addr.to_string())
            .await
            .unwrap();
        c.register(&e6irc_client::Identity {
            nick: &format!("keep{i}"),
            username: "tester",
            realname: "k",
            server_password: None,
        })
        .await
        .expect("register");
        held.push(c);
    }

    // The third is refused at accept: the socket closes before welcome.
    let mut third = e6irc_client::Connection::connect(&addr.to_string())
        .await
        .unwrap();
    assert!(
        third
            .register(&e6irc_client::Identity {
                nick: "third",
                username: "third",
                realname: "t",
                server_password: None,
            })
            .await
            .is_err(),
        "third connection from the same IP must be refused"
    );

    // Freeing a slot lets a new connection in again.
    held.pop();
    // Give the dropped connection's task a moment to release its slot.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut again = e6irc_client::Connection::connect(&addr.to_string())
        .await
        .unwrap();
    again
        .register(&e6irc_client::Identity {
            nick: "again",
            username: "again",
            realname: "a",
            server_password: None,
        })
        .await
        .expect("a freed slot should admit a new connection");
}

#[tokio::test]
async fn command_flood_throttle_closes_excess() {
    use e6ircd::config::LimitsConfig;
    let config = Config {
        server_name: "irc.flood.example".into(),
        network_name: "FloodNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        limits: LimitsConfig {
            max_connections_per_ip: None,
            command_burst: 5,
            command_rate: 1,
            registration_burst: None,
            ..LimitsConfig::default()
        },
        ..Config::default()
    };
    let addr = net::start(config).await.expect("start").addrs[0];

    let mut c = e6irc_client::Connection::connect(&addr.to_string())
        .await
        .unwrap();
    c.register(&e6irc_client::Identity {
        nick: "flooder",
        username: "flooder",
        realname: "f",
        server_password: None,
    })
    .await
    .expect("register");

    // Burst well past the bucket within the same second; the socket may
    // close mid-burst, so send errors are expected and ignored.
    for _ in 0..12 {
        let _ = c.send_line("PRIVMSG nobody :flood").await;
    }

    // The link is closed loudly (ERROR) then EOF.
    let killed = timeout(Duration::from_secs(5), async {
        loop {
            match c.next_message().await {
                Ok(Some(m)) if m.command == "ERROR" => return true,
                Ok(Some(_)) => {}
                _ => return true, // EOF / error = closed
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(killed, "excess commands must close the link (Excess Flood)");
}
