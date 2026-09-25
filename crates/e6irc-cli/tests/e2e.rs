//! End-to-end: drive the built `e6irc` CLI binary against a real
//! e6ircd, using the client library for the observing side.

use std::process::Command;

use e6irc_client::Connection;

fn cli_sasl_database_name() -> String {
    format!("e6irc_cli_sasl_login_{}", std::process::id())
}

/// Give the CLI's database journey an empty database of its own. The URL from
/// the environment is an administrative connection, not shared test storage:
/// other integration binaries deliberately leave real managed configuration
/// in it while proving restart and secret-sealing behavior.
async fn prepare_cli_sasl_database(admin_url: &str, database_name: &str) -> String {
    let pool = sqlx::PgPool::connect(admin_url)
        .await
        .expect("connect to the administrative database");
    let drop_database = format!(r#"DROP DATABASE IF EXISTS "{database_name}" WITH (FORCE)"#);
    let create_database = format!(r#"CREATE DATABASE "{database_name}""#);
    sqlx::raw_sql(sqlx::AssertSqlSafe(drop_database))
        .execute(&pool)
        .await
        .expect("drop the previous CLI test database");
    sqlx::raw_sql(sqlx::AssertSqlSafe(create_database))
        .execute(&pool)
        .await
        .expect("create the CLI test database");
    pool.close().await;

    let mut url = reqwest::Url::parse(admin_url).expect("database URL");
    url.set_path(database_name);
    url.to_string()
}

async fn drop_cli_sasl_database(admin_url: &str, database_name: &str) {
    let pool = sqlx::PgPool::connect(admin_url)
        .await
        .expect("reconnect to the administrative database");
    let drop_database = format!(r#"DROP DATABASE "{database_name}" WITH (FORCE)"#);
    sqlx::raw_sql(sqlx::AssertSqlSafe(drop_database))
        .execute(&pool)
        .await
        .expect("drop the CLI test database");
    pool.close().await;
}

/// Start an e6ircd in-process on an ephemeral port and return its addr.
async fn start_server() -> std::net::SocketAddr {
    let config = e6ircd::config::Config {
        server_name: "irc.cli.example".into(),
        network_name: "CliNet".into(),
        listeners: vec![e6ircd::config::ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
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
        .register(&e6irc_client::Identity {
            nick: "watcher",
            username: "watcher",
            realname: "watcher",
            server_password: None,
        })
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
                    "--username",
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
async fn cli_json_tail_is_machine_safe_against_a_real_server() {
    let addr = start_server().await;
    let mut sender = Connection::connect(&addr.to_string())
        .await
        .expect("connect");
    sender
        .register(&e6irc_client::Identity {
            nick: "sender",
            username: "sender",
            realname: "sender",
            server_password: None,
        })
        .await
        .expect("register");
    sender.send_line("JOIN #json").await.expect("join");
    loop {
        let message = sender.next_message().await.unwrap().unwrap();
        if message.command == "366" {
            break;
        }
    }

    let bin = env!("CARGO_BIN_EXE_e6irc");
    let tail = tokio::task::spawn_blocking({
        let addr = addr.to_string();
        move || {
            Command::new(bin)
                .args([
                    "--server",
                    &addr,
                    "--nick",
                    "jsonreader",
                    "--username",
                    "jsonreader",
                    "tail",
                    "#json",
                    "--count",
                    "1",
                    "--json",
                ])
                .output()
                .expect("run JSON tail")
        }
    });
    loop {
        let message = sender.next_message().await.unwrap().unwrap();
        if message.command == "JOIN"
            && message
                .source
                .as_deref()
                .is_some_and(|source| source.starts_with("jsonreader!"))
        {
            break;
        }
    }
    sender
        .send_line("PRIVMSG #json :machine-safe")
        .await
        .unwrap();
    let output = tail.await.unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        value["source"]
            .as_str()
            .is_some_and(|source| source.starts_with("sender!")),
        "{value}"
    );
    assert_eq!(value["target"], "#json");
    assert_eq!(value["text"], "machine-safe");
    assert!(value["tags"].is_array());
}

/// `send` to a nick nobody holds draws a 401 after the PRIVMSG; the exit code
/// is this tool's product, so that delivery failure must be a non-zero exit —
/// it used to be silently drained on the way out, reporting success for a
/// message that reached no one.
#[tokio::test(flavor = "multi_thread")]
async fn cli_send_to_missing_nick_exits_nonzero() {
    let addr = start_server().await;
    let bin = env!("CARGO_BIN_EXE_e6irc");
    let output = tokio::task::spawn_blocking({
        let addr = addr.to_string();
        move || {
            Command::new(bin)
                .args([
                    "--server",
                    &addr,
                    "--nick",
                    "sender2",
                    "--username",
                    "sender2",
                    "send",
                    "nobody",
                    "hi",
                ])
                .output()
                .expect("run cli")
        }
    })
    .await
    .expect("join");
    assert!(
        !output.status.success(),
        "send to a nonexistent nick must exit non-zero; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("cannot send"),
        "stderr must say why: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn cli_sasl_login() {
    let admin_url = std::env::var("E6IRC_TEST_DATABASE_URL").expect("E6IRC_TEST_DATABASE_URL");
    let database_name = cli_sasl_database_name();
    let url = prepare_cli_sasl_database(&admin_url, &database_name).await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "cliuser", "clipass", None)
        .await
        .expect("create");
    let oauth_token = e6ircd::db::issue_scoped_api_token(
        &pool,
        "cliuser",
        "cli-e2e",
        e6ircd::identity::ApiTokenScopes::new(e6ircd::identity::ApiTokenScope::ALL)
            .expect("every scope is a non-empty set"),
        e6ircd::identity::ApiTokenLifetimeDays::DEFAULT,
    )
    .await
    .expect("issue OAuth token");

    let config = e6ircd::config::Config {
        server_name: "irc.clisasl.example".into(),
        network_name: "CliSaslNet".into(),
        listeners: vec![e6ircd::config::ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(e6ircd::config::HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            // An http:// origin: the daemon refuses an https public URL with insecure
            // cookies, and this harness runs without TLS.
            public_url: Some("http://cli.e2e.example".into()),
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        }),
        database: Some(e6ircd::config::DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..e6ircd::config::Config::default()
    };
    let running = e6ircd::net::start(config).await.expect("start");
    let addr = running.addrs[0];
    let http = running.http_addr.expect("HTTP listener");

    // observer joins to receive the CLI's authenticated message
    let mut observer = Connection::connect(&addr.to_string())
        .await
        .expect("connect");
    observer
        .register(&e6irc_client::Identity {
            nick: "watch2",
            username: "watch2",
            realname: "watch2",
            server_password: None,
        })
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
                    "--username",
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

    let token_directory =
        std::env::temp_dir().join(format!("e6irc-cli-oauth-{}", std::process::id()));
    let token_path = token_directory.join("token.json");
    let cached =
        e6irc_client::token_cache::CachedToken::new("http://127.0.0.1:1".into(), oauth_token)
            .unwrap();
    e6irc_client::token_cache::store_token(&token_path, &cached).unwrap();
    let status = tokio::task::spawn_blocking({
        let addr = addr.to_string();
        let token_path = token_path.clone();
        move || {
            Command::new(bin)
                .args([
                    "--server",
                    &addr,
                    "--nick",
                    "oauthcli",
                    "--username",
                    "oauthcli",
                ])
                .arg("--oauth-from-cache")
                .arg("--token-file")
                .arg(token_path)
                .args(["send", "#s", "oauth hello"])
                .status()
                .expect("run OAuth CLI")
        }
    })
    .await
    .expect("join");
    assert!(status.success(), "CLI OAuth send failed");
    let got = loop {
        let message = observer.next_message().await.expect("read").expect("msg");
        if message.command == "PRIVMSG"
            && message.params.get(1).map(String::as_str) == Some("oauth hello")
        {
            break message;
        }
    };
    assert!(
        got.source.as_deref().unwrap_or("").starts_with("oauthcli!"),
        "{got:?}"
    );

    // Drive the shipped device-login command against the real HTTP and
    // PostgreSQL implementation. Approval is the one user action; the test
    // performs it through the same database primitive used by the approval
    // page, then proves the resulting cache authenticates an API request.
    // The cache is named by a bare file name, relative to the working
    // directory: its parent is empty, which must mean `.`.
    let device_path = token_directory.join("device-token.json");
    let login_directory = token_directory.clone();
    let base = format!("http://{http}");
    let base_for_child = base.clone();
    let (code_sender, code_receiver) = std::sync::mpsc::sync_channel(1);
    let login = tokio::task::spawn_blocking(move || {
        use std::io::{BufRead as _, BufReader};
        use std::process::Stdio;

        let mut child = Command::new(bin)
            .current_dir(login_directory)
            .args(["--token-file", "device-token.json"])
            .args(["login", "--base", &base_for_child])
            .stderr(Stdio::piped())
            .spawn()
            .expect("start device login");
        let stderr = child.stderr.take().expect("piped stderr");
        let mut transcript = Vec::new();
        for line in BufReader::new(stderr).lines() {
            let line = line.expect("read device-login stderr");
            if let Some((_, code)) = line.rsplit_once(" and enter ") {
                code_sender.send(code.to_owned()).expect("send user code");
            }
            transcript.push(line);
        }
        let status = child.wait().expect("wait for device login");
        (status, transcript.join("\n"))
    });
    let user_code = tokio::task::spawn_blocking(move || {
        code_receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("CLI did not print a device user code")
    })
    .await
    .expect("receive task");
    assert_eq!(
        e6ircd::db::approve_device_grant(&pool, &user_code, "cliuser")
            .await
            .expect("approve grant"),
        e6ircd::db::DeviceApproval::Approved,
        "device grant was not pending"
    );
    let (status, transcript) = login.await.expect("device login task");
    assert!(status.success(), "device login failed: {transcript}");
    assert!(
        transcript.contains("Open http://cli.e2e.example/device and enter "),
        "device verification URI must be absolute: {transcript}"
    );
    let cached = e6irc_client::token_cache::load_token(&device_path)
        .unwrap()
        .expect("device token cache");
    assert_eq!(cached.base_url(), base);

    let output = tokio::task::spawn_blocking({
        let device_path = device_path.clone();
        move || {
            Command::new(bin)
                .arg("--token-file")
                .arg(device_path)
                .args(["api", "GET", "/api/v1/me"])
                .output()
                .expect("use device token")
        }
    })
    .await
    .expect("API task");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("cliuser"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    std::fs::remove_dir_all(token_directory).unwrap();
    drop(observer);
    assert_eq!(
        running.shutdown.run().await,
        e6ircd::net::ShutdownOutcome::Flushed
    );
    pool.close().await;
    drop_cli_sasl_database(&admin_url, &database_name).await;
}

/// A token cache that cannot be written is refused before the device flow
/// starts: nothing is asked of the server, so the user is never asked to
/// approve a login whose token would be thrown away.
#[tokio::test]
async fn cli_login_refuses_an_unwritable_token_cache_before_the_device_flow() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("address"));
    let directory = std::env::temp_dir().join(format!("e6irc-cli-login-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("directory");
    let not_a_directory = directory.join("file");
    std::fs::write(&not_a_directory, b"x").expect("file");
    let output = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_e6irc"))
            .arg("--token-file")
            .arg(not_a_directory.join("token.json"))
            .args(["login", "--base", &base])
            .output()
            .expect("run login")
    })
    .await
    .expect("join");
    listener.set_nonblocking(true).expect("nonblocking");
    assert!(
        listener.accept().is_err(),
        "the device flow must not have started"
    );
    std::fs::remove_dir_all(&directory).expect("cleanup");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot store a token at"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_rejects_one_credential_flag_without_the_other() {
    // Giving only --account (or only --password) must fail loudly, not silently
    // register unauthenticated and send as the wrong identity.
    let addr = start_server().await;
    let bin = env!("CARGO_BIN_EXE_e6irc");
    let status = tokio::task::spawn_blocking({
        let addr = addr.to_string();
        move || {
            std::process::Command::new(bin)
                .args([
                    "--server",
                    &addr,
                    "--nick",
                    "half",
                    "--username",
                    "half",
                    "--account",
                    "alice",
                    "send",
                    "#x",
                    "hi",
                ])
                .status()
                .expect("run cli")
        }
    })
    .await
    .expect("join");
    assert!(
        !status.success(),
        "CLI must fail when --account is given without --password"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_history_reads_recent_messages() {
    let addr = start_server().await;

    // seed: a client joins #hist and posts two messages
    let mut seeder = Connection::connect(&addr.to_string())
        .await
        .expect("connect");
    seeder
        .register(&e6irc_client::Identity {
            nick: "seeder",
            username: "seeder",
            realname: "seeder",
            server_password: None,
        })
        .await
        .expect("register");
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
                    "--server",
                    &addr,
                    "--nick",
                    "reader",
                    "--username",
                    "reader",
                    "history",
                    "#hist",
                    "--count",
                    "10",
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
            websocket: false,
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
    let nick = conn
        .register(&e6irc_client::Identity {
            nick: "tlsclient",
            username: "tlsclient",
            realname: "tls",
            server_password: None,
        })
        .await
        .expect("register");
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
            websocket: false,
        }],
        http: Some(e6ircd::config::HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
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

    // An explicitly supplied token must make the cache irrelevant. This is
    // important in minimal service/container environments with no home
    // directory from which a default cache path could be derived.
    #[cfg(unix)]
    let out = tokio::task::spawn_blocking({
        let base = base.clone();
        move || {
            Command::new(bin)
                .env_remove("HOME")
                .env_remove("XDG_CONFIG_HOME")
                .args([
                    "api", "GET", "/healthz", "--base", &base, "--token", "explicit",
                ])
                .output()
                .expect("run API with explicit token")
        }
    })
    .await
    .unwrap();
    #[cfg(unix)]
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
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

/// A server that welcomes the CLI, confirms whatever it joins, and then drops
/// the connection. Yields every line the CLI sent.
async fn server_that_drops_after_the_join() -> (String, tokio::task::JoinHandle<Vec<String>>) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let served = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (reader, mut writer) = socket.into_split();
        let mut lines = tokio::io::BufReader::new(reader).lines();
        let mut seen = Vec::new();
        // A CLI that never joins must not hold the test open.
        let join_window = std::time::Duration::from_secs(2);
        while let Ok(Ok(Some(line))) = tokio::time::timeout(join_window, lines.next_line()).await {
            let reply = match line.split_once(' ') {
                Some(("CAP", "LS 302")) => ":srv CAP * LS :\r\n".to_string(),
                Some(("CAP", "END")) => ":srv 001 tailer :Welcome\r\n".to_string(),
                Some(("PING", token)) => format!(":srv PONG srv {token}\r\n"),
                Some(("JOIN", channel)) => format!(":srv 366 tailer {channel} :End of NAMES\r\n"),
                _ => String::new(),
            };
            writer.write_all(reply.as_bytes()).await.unwrap();
            let joined = line.starts_with("JOIN ");
            seen.push(line);
            if joined {
                break;
            }
        }
        seen
    });
    (address, served)
}

async fn tail_forever(address: String, target: &'static str) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_e6irc");
    tokio::task::spawn_blocking(move || {
        Command::new(bin)
            .args([
                "--server",
                &address,
                "--nick",
                "tailer",
                "--username",
                "tailer",
                "tail",
                target,
            ])
            .output()
            .expect("run tail")
    })
    .await
    .expect("join")
}

/// An unbounded tail has no successful end: the only way it stops by itself is
/// the server going away, and a supervisor must be able to see that.
#[tokio::test(flavor = "multi_thread")]
async fn cli_tail_forever_fails_when_the_server_drops_the_connection() {
    let (address, served) = server_that_drops_after_the_join().await;
    let output = tail_forever(address, "#room").await;
    served.await.unwrap();
    assert!(
        !output.status.success(),
        "a dropped connection ended an unbounded tail with success"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("closed"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `&` channels are channels: tailing one must join it, not wait in silence
/// for messages the server will never relay to a non-member.
#[tokio::test(flavor = "multi_thread")]
async fn cli_tail_joins_a_local_channel() {
    let (address, served) = server_that_drops_after_the_join().await;
    tail_forever(address, "&local").await;
    let seen = served.await.unwrap();
    assert!(seen.contains(&"JOIN &local".to_string()), "{seen:?}");
}

/// Run `e6irc` with SASL PLAIN for `alice` against TEST-NET-1, which is never
/// dialed when the command is refused first. Yields (succeeded, stderr).
async fn send_as_alice(
    arguments: Vec<String>,
    environment: &'static [(&'static str, &'static str)],
) -> (bool, String) {
    let bin = env!("CARGO_BIN_EXE_e6irc");
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        tokio::task::spawn_blocking(move || {
            Command::new(bin)
                .args([
                    "--server",
                    "192.0.2.1:6667",
                    "--nick",
                    "alice",
                    "--username",
                    "alice",
                ])
                .args(["--account", "alice", "--response-timeout", "2"])
                .args(arguments)
                .args(["send", "bob", "hello"])
                .env_remove("E6IRC_PASSWORD")
                .env_remove("E6IRC_OAUTH_TOKEN")
                .envs(environment.iter().copied())
                .output()
                .expect("run cli")
        }),
    )
    .await
    .expect("the command neither finished nor failed")
    .expect("join");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(ToString::to_string).collect()
}

/// SASL PLAIN is the password in base64. Without --tls it crosses the network
/// readable by anyone on the path, so it is refused unless asked for.
#[tokio::test(flavor = "multi_thread")]
async fn cli_refuses_to_send_a_password_in_cleartext_to_another_machine() {
    let (succeeded, stderr) = send_as_alice(arguments(&["--password", "secret"]), &[]).await;
    assert!(!succeeded);
    assert!(stderr.contains("cleartext"), "{stderr}");
    assert!(stderr.contains("--allow-cleartext-credentials"), "{stderr}");

    // Asked for, it is attempted: the failure is then the unreachable server's.
    let (succeeded, stderr) = send_as_alice(
        arguments(&["--password", "secret", "--allow-cleartext-credentials"]),
        &[],
    )
    .await;
    assert!(!succeeded);
    assert!(!stderr.contains("cleartext"), "{stderr}");
}

/// A password never has to appear in the process list: the environment and a
/// private file are both read, and a file others can read is refused.
#[tokio::test(flavor = "multi_thread")]
#[cfg(unix)]
async fn cli_takes_the_password_from_the_environment_or_a_private_file() {
    use std::os::unix::fs::PermissionsExt;

    // Reaching the cleartext refusal proves a password was found.
    let (_, stderr) = send_as_alice(Vec::new(), &[("E6IRC_PASSWORD", "from-env")]).await;
    assert!(stderr.contains("cleartext"), "{stderr}");
    let (_, stderr) = send_as_alice(Vec::new(), &[]).await;
    assert!(stderr.contains("--account needs a password"), "{stderr}");

    let directory = std::env::temp_dir().join(format!("e6irc-cli-secret-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("password");
    let from_file = || arguments(&["--password-file", path.to_str().expect("UTF-8 path")]);
    std::fs::write(&path, "from-file\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (_, stderr) = send_as_alice(from_file(), &[]).await;
    assert!(stderr.contains("cleartext"), "{stderr}");

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (succeeded, stderr) = send_as_alice(from_file(), &[]).await;
    assert!(!succeeded);
    assert!(stderr.contains("chmod 600"), "{stderr}");
    std::fs::remove_dir_all(&directory).unwrap();
}

/// The CLI takes a server password from the environment (or a file, or the
/// command line, under the resolver's shared rules), sends it as the very
/// first line, and reports a rejection without echoing it; one bound for a
/// server that is not this machine over plaintext is refused before dialing.
#[tokio::test(flavor = "multi_thread")]
async fn cli_sends_a_server_password_first_and_reports_its_rejection() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let first_line = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (reader, mut writer) = socket.into_split();
        let mut lines = tokio::io::BufReader::new(reader).lines();
        let first = lines.next_line().await.unwrap().expect("a first line");
        writer
            .write_all(b":up 464 * :Password incorrect\r\n")
            .await
            .unwrap();
        // Read on until the client leaves. Dropping the socket here, while
        // the client still writes NICK/USER, answers those writes with a
        // reset, and Windows discards the unread 464 along with it: the client
        // then sees "connection aborted", not the refusal under test.
        while let Ok(Some(_)) = lines.next_line().await {}
        first
    });
    let bin = env!("CARGO_BIN_EXE_e6irc");
    let output = tokio::task::spawn_blocking(move || {
        Command::new(bin)
            .env("E6IRC_SERVER_PASSWORD", "from-the-environment")
            .args(["--server", &addr, "--nick", "sender", "send", "#cli", "hi"])
            .output()
            .expect("run cli")
    })
    .await
    .expect("join");
    assert_eq!(first_line.await.unwrap(), "PASS :from-the-environment");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ServerPasswordRejected"), "{stderr}");
    assert!(!stderr.contains("from-the-environment"), "{stderr}");

    let output = tokio::task::spawn_blocking(move || {
        Command::new(bin)
            .env_remove("E6IRC_SERVER_PASSWORD")
            .args([
                "--server",
                "192.0.2.1:6667",
                "--nick",
                "sender",
                "--server-password",
                "typed",
                "send",
                "#cli",
                "hi",
            ])
            .output()
            .expect("run cli")
    })
    .await
    .expect("join");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("server password") && stderr.contains("cleartext"),
        "{stderr}"
    );
}

/// Run the CLI with `arguments` (after `--server <address>`), optionally
/// feeding `stdin`, and bound the run so a hang fails the test instead of
/// stalling it.
async fn run_cli(
    address: String,
    arguments: &'static [&'static str],
    stdin: &'static str,
) -> std::process::Output {
    use std::io::Write as _;
    use std::process::Stdio;

    let bin = env!("CARGO_BIN_EXE_e6irc");
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::task::spawn_blocking(move || {
            let mut child = Command::new(bin)
                .args(["--server", &address, "--response-timeout", "5"])
                .args(arguments)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("run cli");
            child
                .stdin
                .take()
                .expect("piped stdin")
                .write_all(stdin.as_bytes())
                .expect("write stdin");
            child.wait_with_output().expect("wait for cli")
        }),
    )
    .await
    .expect("the command neither finished nor failed")
    .expect("join")
}

/// A scripted IRC server: each line the CLI sends that starts with a key is
/// answered with the value (`{nick}` is the CLI's nick, "sender"). `QUIT`
/// closes the connection at once, as a bouncer attach does. A refusal named
/// in `late` is sent that long after the line it answers. Yields every line
/// the CLI sent.
async fn scripted_server(
    advertised: &'static str,
    replies: &'static [(&'static str, &'static str)],
    late: Option<(&'static str, &'static str, std::time::Duration)>,
) -> (String, tokio::task::JoinHandle<Vec<String>>) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let served = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (reader, writer) = socket.into_split();
        let writer = std::sync::Arc::new(tokio::sync::Mutex::new(writer));
        let mut lines = tokio::io::BufReader::new(reader).lines();
        let mut seen = Vec::new();
        while let Ok(Ok(Some(line))) =
            tokio::time::timeout(std::time::Duration::from_secs(10), lines.next_line()).await
        {
            seen.push(line.clone());
            if line.starts_with("QUIT") {
                break;
            }
            let mut reply = match line.as_str() {
                "CAP LS 302" => format!(":srv CAP * LS :{advertised}"),
                "CAP END" => ":srv 001 sender :Welcome".to_owned(),
                _ => String::new(),
            };
            if let Some(token) = line.strip_prefix("PING ") {
                reply = format!(":srv PONG srv {token}");
            }
            if let Some(capabilities) = line.strip_prefix("CAP REQ :") {
                reply = format!(":srv CAP sender ACK :{capabilities}");
            }
            if let Some((_, answer)) = replies.iter().find(|(prefix, _)| line.starts_with(prefix)) {
                reply = (*answer).to_owned();
            }
            if let Some((prefix, answer, delay)) = late
                && line.starts_with(prefix)
            {
                let writer = writer.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let mut writer = writer.lock().await;
                    drop(writer.write_all(format!("{answer}\r\n").as_bytes()).await);
                });
            }
            if !reply.is_empty() {
                let mut writer = writer.lock().await;
                writer
                    .write_all(format!("{reply}\r\n").as_bytes())
                    .await
                    .unwrap();
            }
        }
        seen
    });
    (address, served)
}

/// Through a bouncer attach the upstream's refusal arrives after the
/// bouncer has already closed on `QUIT`. `send` must wait for the server's
/// verdict — the echo of its own message, or a refusal — before quitting.
#[tokio::test(flavor = "multi_thread")]
async fn cli_send_waits_for_a_late_refusal_before_quitting() {
    let (address, served) = scripted_server(
        "echo-message",
        &[],
        Some((
            "PRIVMSG bob ",
            ":srv 486 sender bob :You must log in to message this user",
            std::time::Duration::from_millis(300),
        )),
    )
    .await;
    let output = run_cli(address, &["--nick", "sender", "send", "bob", "hi"], "").await;
    let seen = served.await.unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a refused message exited 0; sent {seen:?}; stderr {stderr}"
    );
    assert!(stderr.contains("You must log in"), "{stderr}");
}

/// Without echo-message nothing tells delivery from silent loss, so `send`
/// refuses to claim it — before the message is sent.
#[tokio::test(flavor = "multi_thread")]
async fn cli_send_without_echo_message_says_delivery_cannot_be_confirmed() {
    let (address, served) = scripted_server("", &[], None).await;
    let output = run_cli(address, &["--nick", "sender", "send", "bob", "hi"], "").await;
    let seen = served.await.unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "sent {seen:?}; stderr {stderr}");
    assert!(stderr.contains("delivery cannot be confirmed"), "{stderr}");
    assert!(
        !seen.iter().any(|line| line.starts_with("PRIVMSG")),
        "an unconfirmable message was sent anyway: {seen:?}"
    );
}

/// Through a bridge attach the client is the provider account: e6irc
/// welcomes it under the account's nick, not the one it asked for, re-states
/// its membership of a bridged channel when it joins, and echoes its message
/// under that nick. `send` takes its own nick from the welcome, so it knows
/// the echo as its own — the lines here are the bouncer's, byte for byte.
#[tokio::test(flavor = "multi_thread")]
async fn cli_send_over_a_bridge_confirms_the_echo_under_the_account_nick() {
    let (address, served) = scripted_server(
        "echo-message",
        &[
            (
                "CAP END",
                ":srv 001 e6ircbot :Welcome to e6irc BNC, attached to 'team'",
            ),
            (
                "JOIN #general",
                ":e6ircbot!~bnc@e6irc JOIN #general\r\n\
                 :*bnc* 353 e6ircbot = #general :e6ircbot\r\n\
                 :*bnc* 366 e6ircbot #general :End of /NAMES list",
            ),
            (
                "PRIVMSG #general ",
                ":e6ircbot!e6ircbot@discord PRIVMSG #general :hi",
            ),
        ],
        None,
    )
    .await;
    let output = run_cli(address, &["--nick", "alice", "send", "#general", "hi"], "").await;
    let seen = served.await.unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the echo under the account's nick was not taken as ours; sent {seen:?}; stderr {stderr}"
    );
}

/// The network's 005 decides what `send` compares and joins. On an `ascii`
/// network an echo to `#a{` is not the message sent to `#a[` (under the
/// rfc1459 default it would be, and the refusal after it would go unread);
/// with `CHANTYPES=#!` a `!` target is a channel, joined before speaking.
#[tokio::test(flavor = "multi_thread")]
async fn cli_send_follows_the_networks_casemapping_and_chantypes() {
    let (address, served) = scripted_server(
        "echo-message",
        &[
            (
                "CAP END",
                ":srv 001 sender :Welcome\r\n\
                 :srv 005 sender CASEMAPPING=ascii CHANTYPES=#! :are supported by this server",
            ),
            (
                "JOIN !a[",
                ":sender!u@h JOIN !a[\r\n:srv 366 sender !a[ :End of NAMES",
            ),
            (
                "PRIVMSG !a[ ",
                ":sender!u@h PRIVMSG !a{ :hi\r\n:srv 404 sender !a[ :Cannot send to channel",
            ),
        ],
        None,
    )
    .await;
    let output = run_cli(address, &["--nick", "sender", "send", "!a[", "hi"], "").await;
    let seen = served.await.unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        seen.iter().any(|line| line == "JOIN !a["),
        "a CHANTYPES channel is joined first: {seen:?}"
    );
    assert!(
        !output.status.success(),
        "the echo to another channel was taken as ours; sent {seen:?}; stderr {stderr}"
    );
    assert!(stderr.contains("Cannot send to channel"), "{stderr}");
}

/// Register an observer on `address` as `nick`, and join `channel` (so it
/// holds channel operator status there).
async fn observer_in(address: &str, nick: &'static str, channel: &str) -> Connection {
    let mut observer = Connection::connect(address).await.expect("connect");
    observer
        .register(&e6irc_client::Identity {
            nick,
            username: nick,
            realname: nick,
            server_password: None,
        })
        .await
        .expect("register");
    observer
        .send_line(&format!("JOIN {channel}"))
        .await
        .expect("join");
    loop {
        let message = observer.next_message().await.expect("read").expect("msg");
        if message.command == "366" {
            break;
        }
    }
    observer
}

/// Set `mode` on `channel` and wait until the server has applied it.
async fn set_mode(observer: &mut Connection, channel: &str, mode: &str) {
    observer
        .send_line(&format!("MODE {channel} {mode}"))
        .await
        .expect("mode");
    loop {
        let message = observer.next_message().await.expect("read").expect("msg");
        if message.command == "MODE" {
            break;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_send_to_a_moderated_channel_exits_nonzero() {
    let addr = start_server().await.to_string();
    let mut observer = observer_in(&addr, "moderator", "#moderated").await;
    set_mode(&mut observer, "#moderated", "+m").await;
    let output = run_cli(
        addr,
        &["--nick", "voiceless", "send", "#moderated", "unheard"],
        "",
    )
    .await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("cannot send to #moderated"), "{stderr}");
    assert!(stderr.contains("404"), "{stderr}");
}

/// `raw` is a conversation with the server: its replies are printed, and a
/// refusal is an error exit rather than a line nobody reads.
#[tokio::test(flavor = "multi_thread")]
async fn cli_raw_prints_replies_and_fails_on_a_refusal() {
    let addr = start_server().await.to_string();
    let mut observer = observer_in(&addr, "gatekeeper", "#invite").await;
    set_mode(&mut observer, "#invite", "+i").await;
    let output = run_cli(
        addr,
        &["--nick", "rawclient", "raw"],
        "WHOIS gatekeeper\nJOIN #invite\n",
    )
    .await;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stdout {stdout}; stderr {stderr}");
    assert!(stderr.contains(" 473 "), "{stderr}");
    assert!(stdout.contains(" 311 rawclient gatekeeper "), "{stdout}");
    assert!(
        !stdout.contains(" 473 "),
        "a refusal belongs on stderr: {stdout}"
    );
}

/// A reader that goes away (`e6irc tail … | head -1`) is the end of the
/// output, not a crash.
#[tokio::test(flavor = "multi_thread")]
async fn cli_tail_ends_cleanly_when_its_reader_goes_away() {
    use std::io::BufRead as _;
    use std::process::Stdio;

    let addr = start_server().await.to_string();
    let mut sender = observer_in(&addr, "speaker", "#pipe").await;
    let bin = env!("CARGO_BIN_EXE_e6irc");
    let mut child = Command::new(bin)
        .args(["--server", &addr, "--nick", "piped", "tail", "#pipe"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run tail");
    loop {
        let message = sender.next_message().await.unwrap().unwrap();
        if message.command == "JOIN"
            && message
                .source
                .as_deref()
                .is_some_and(|source| source.starts_with("piped!"))
        {
            break;
        }
    }
    sender.send_line("PRIVMSG #pipe :first").await.unwrap();
    let stdout = child.stdout.take().expect("piped stdout");
    let first = tokio::task::spawn_blocking(move || {
        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read the first line");
        // Dropping the reader closes the pipe.
        line
    })
    .await
    .unwrap();
    assert!(first.contains("first"), "{first}");
    for text in ["second", "third", "fourth"] {
        sender
            .send_line(&format!("PRIVMSG #pipe :{text}"))
            .await
            .unwrap();
    }
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        tokio::task::spawn_blocking(move || child.wait_with_output().expect("wait")),
    )
    .await
    .expect("tail kept running with nobody reading")
    .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert!(output.status.success(), "{stderr}");
}

/// The API client talks to the origin it was given. A proxy named in the
/// environment would otherwise see every request, bearer token included.
#[tokio::test(flavor = "multi_thread")]
async fn cli_api_never_goes_through_a_proxy_from_the_environment() {
    let (_irc, http) = start_server_with_http().await;
    let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    proxy.set_nonblocking(true).unwrap();
    let proxy_url = format!("http://{}", proxy.local_addr().unwrap());
    let base = format!("http://{http}");
    let bin = env!("CARGO_BIN_EXE_e6irc");
    let output = tokio::task::spawn_blocking(move || {
        Command::new(bin)
            .env("HTTP_PROXY", &proxy_url)
            .env("http_proxy", &proxy_url)
            .env("HTTPS_PROXY", &proxy_url)
            .env("ALL_PROXY", &proxy_url)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .args(["api", "GET", "/healthz", "--base", &base, "--token", "t"])
            .output()
            .expect("run api")
    })
    .await
    .unwrap();
    let reached_proxy = proxy.accept().is_ok();
    assert!(!reached_proxy, "the request went to the proxy");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
