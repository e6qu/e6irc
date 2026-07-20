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

#[tokio::test]
async fn per_ip_connection_limit_refuses_excess() {
    use e6ircd::config::LimitsConfig;
    let config = Config {
        server_name: "irc.limit.example".into(),
        network_name: "LimitNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }],
        limits: LimitsConfig {
            max_connections_per_ip: Some(2),
            command_burst: None,
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
        c.register(&format!("keep{i}"), "k")
            .await
            .expect("register");
        held.push(c);
    }

    // The third is refused at accept: the socket closes before welcome.
    let mut third = e6irc_client::Connection::connect(&addr.to_string())
        .await
        .unwrap();
    assert!(
        third.register("third", "t").await.is_err(),
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
        .register("again", "a")
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
        }],
        limits: LimitsConfig {
            max_connections_per_ip: None,
            command_burst: Some(5),
            ..LimitsConfig::default()
        },
        ..Config::default()
    };
    let addr = net::start(config).await.expect("start").addrs[0];

    let mut c = e6irc_client::Connection::connect(&addr.to_string())
        .await
        .unwrap();
    c.register("flooder", "f").await.expect("register");

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
