//! End-to-end: drive the built `e6irc` CLI binary against a real
//! e6ircd, using the client library for the observing side.

use std::process::Command;

use e6irc_client::Connection;

/// Start an e6ircd in-process on an ephemeral port and return its addr.
async fn start_server() -> std::net::SocketAddr {
    let config = e6ircd::config::Config {
        server_name: "irc.cli.example".into(),
        network_name: "CliNet".into(),
        listeners: vec![e6ircd::config::ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }],
        ..e6ircd::config::Config::default()
    };
    let running = e6ircd::net::start(config).await.expect("start");
    running.addrs[0]
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_send_reaches_a_tailing_client() {
    let addr = start_server().await;

    // an observer joins #cli via the client library and waits
    let mut observer = Connection::connect(&addr.to_string())
        .await
        .expect("connect");
    observer
        .register("watcher", "watcher")
        .await
        .expect("register");
    observer.send_line("JOIN #cli").await.expect("join");
    // drain the join burst
    loop {
        let m = observer.next_message().await.expect("read").expect("msg");
        if m.command == "366" {
            break;
        }
    }

    // the CLI binary sends a message to #cli
    let bin = env!("CARGO_BIN_EXE_e6irc");
    let status = tokio::task::spawn_blocking({
        let addr = addr.to_string();
        move || {
            Command::new(bin)
                .args([
                    "--server",
                    &addr,
                    "--nick",
                    "sender",
                    "send",
                    "#cli",
                    "hello from the cli",
                ])
                .status()
                .expect("run cli")
        }
    })
    .await
    .expect("join");
    assert!(status.success(), "cli exited non-zero");

    // the observer receives it
    let got = loop {
        let m = observer.next_message().await.expect("read").expect("msg");
        if m.command == "PRIVMSG" && m.params.first().map(String::as_str) == Some("#cli") {
            break m;
        }
    };
    assert_eq!(
        got.params.get(1).map(String::as_str),
        Some("hello from the cli")
    );
    assert!(
        got.source.as_deref().unwrap_or("").starts_with("sender!"),
        "{got:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn cli_sasl_login() {
    let url = std::env::var("E6IRC_TEST_DATABASE_URL").expect("E6IRC_TEST_DATABASE_URL");
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    sqlx::query("TRUNCATE accounts CASCADE")
        .execute(&pool)
        .await
        .expect("clean");
    e6ircd::db::create_account(&pool, "cliuser", "clipass")
        .await
        .expect("create");
    drop(pool);

    let config = e6ircd::config::Config {
        server_name: "irc.clisasl.example".into(),
        network_name: "CliSaslNet".into(),
        listeners: vec![e6ircd::config::ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }],
        database: Some(e6ircd::config::DatabaseConfig { url }),
        ..e6ircd::config::Config::default()
    };
    let running = e6ircd::net::start(config).await.expect("start");
    let addr = running.addrs[0];

    // observer joins to receive the CLI's authenticated message
    let mut observer = Connection::connect(&addr.to_string())
        .await
        .expect("connect");
    observer
        .register("watch2", "watch2")
        .await
        .expect("register");
    observer.send_line("JOIN #s").await.expect("join");
    loop {
        let m = observer.next_message().await.expect("read").expect("msg");
        if m.command == "366" {
            break;
        }
    }

    let bin = env!("CARGO_BIN_EXE_e6irc");
    let status = tokio::task::spawn_blocking({
        let addr = addr.to_string();
        move || {
            std::process::Command::new(bin)
                .args([
                    "--server",
                    &addr,
                    "--nick",
                    "cliuser",
                    "--account",
                    "cliuser",
                    "--password",
                    "clipass",
                    "send",
                    "#s",
                    "authed hello",
                ])
                .status()
                .expect("run cli")
        }
    })
    .await
    .expect("join");
    assert!(status.success(), "cli SASL send failed");

    let got = loop {
        let m = observer.next_message().await.expect("read").expect("msg");
        if m.command == "PRIVMSG" && m.params.first().map(String::as_str) == Some("#s") {
            break m;
        }
    };
    assert_eq!(got.params.get(1).map(String::as_str), Some("authed hello"));
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_history_reads_recent_messages() {
    let addr = start_server().await;

    // seed: a client joins #hist and posts two messages
    let mut seeder = Connection::connect(&addr.to_string())
        .await
        .expect("connect");
    seeder.register("seeder", "seeder").await.expect("register");
    seeder.send_line("JOIN #hist").await.expect("join");
    loop {
        let m = seeder.next_message().await.expect("read").expect("msg");
        if m.command == "366" {
            break;
        }
    }
    seeder
        .send_line("PRIVMSG #hist :first line")
        .await
        .expect("send");
    seeder
        .send_line("PRIVMSG #hist :second line")
        .await
        .expect("send");
    // sync: ping and wait for pong so the server has processed them
    seeder.send_line("PING :sync").await.expect("ping");
    loop {
        let m = seeder.next_message().await.expect("read").expect("msg");
        if m.command == "PONG" {
            break;
        }
    }

    // the CLI history subcommand reads them back
    let bin = env!("CARGO_BIN_EXE_e6irc");
    let output = tokio::task::spawn_blocking({
        let addr = addr.to_string();
        move || {
            std::process::Command::new(bin)
                .args([
                    "--server", &addr, "--nick", "reader", "history", "#hist", "--count", "10",
                ])
                .output()
                .expect("run cli")
        }
    })
    .await
    .expect("join");
    assert!(
        output.status.success(),
        "history failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("first line"), "missing first: {stdout}");
    assert!(stdout.contains("second line"), "missing second: {stdout}");
    // oldest-first order
    let first = stdout.find("first line").unwrap();
    let second = stdout.find("second line").unwrap();
    assert!(first < second, "wrong order: {stdout}");
}

#[tokio::test(flavor = "multi_thread")]
async fn client_tls_connect() {
    use rustls_pki_types::pem::PemObject;

    // self-signed cert for the test
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("cert");
    let dir = std::env::temp_dir().join(format!("e6irc-clitls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();

    let config = e6ircd::config::Config {
        server_name: "irc.clitls.example".into(),
        network_name: "CliTlsNet".into(),
        listeners: vec![e6ircd::config::ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: Some(e6ircd::config::TlsConfig {
                cert_path: cert_path.clone(),
                key_path,
            }),
        }],
        ..e6ircd::config::Config::default()
    };
    let running = e6ircd::net::start(config).await.expect("start");
    let addr = running.addrs[0];

    // trust only the test cert
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from_pem_file(&cert_path).unwrap())
        .unwrap();
    let mut conn = e6irc_client::Connection::connect_tls(&addr.to_string(), "localhost", roots)
        .await
        .expect("tls connect");
    let nick = conn.register("tlsclient", "tls").await.expect("register");
    assert_eq!(nick, "tlsclient");

    std::fs::remove_dir_all(&dir).ok();
}

/// Start an e6ircd with an HTTP listener; return (irc_addr, http_addr).
async fn start_server_with_http() -> (std::net::SocketAddr, std::net::SocketAddr) {
    let config = e6ircd::config::Config {
        server_name: "irc.cliapi.example".into(),
        network_name: "CliApi".into(),
        listeners: vec![e6ircd::config::ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }],
        http: Some(e6ircd::config::HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![],
        }),
        ..e6ircd::config::Config::default()
    };
    let running = e6ircd::net::start(config).await.expect("start");
    (running.addrs[0], running.http_addr.expect("http bound"))
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_api_hits_rest_endpoints() {
    let (_irc, http) = start_server_with_http().await;
    let base = format!("http://{http}");
    let bin = env!("CARGO_BIN_EXE_e6irc");

    // /healthz -> "ok", exit 0
    let out = tokio::task::spawn_blocking({
        let base = base.clone();
        move || {
            Command::new(bin)
                .args(["api", "GET", "/healthz", "--base", &base])
                .output()
                .expect("run")
        }
    })
    .await
    .unwrap();
    assert!(out.status.success(), "healthz should exit 0");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("ok"),
        "{:?}",
        String::from_utf8_lossy(&out.stdout)
    );

    // /api/v1/server -> JSON with server_name
    let out = tokio::task::spawn_blocking({
        let base = base.clone();
        move || {
            Command::new(bin)
                .args(["api", "GET", "/api/v1/server", "--base", &base])
                .output()
                .expect("run")
        }
    })
    .await
    .unwrap();
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("irc.cliapi.example"),
        "{:?}",
        String::from_utf8_lossy(&out.stdout)
    );

    // A non-2xx path (unknown route -> 404) makes the CLI exit nonzero.
    let out = tokio::task::spawn_blocking({
        let base = base.clone();
        move || {
            Command::new(bin)
                .args(["api", "GET", "/api/v1/nope", "--base", &base])
                .output()
                .expect("run")
        }
    })
    .await
    .unwrap();
    assert!(!out.status.success(), "404 must be a nonzero exit");
}
