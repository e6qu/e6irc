//! e2e tests for the HTTP layer, over real sockets with a raw
//! HTTP/1.1 client (no client library needed for these shapes).

use e6ircd::config::{
    BootstrapConfig, Config, DatabaseConfig, HttpConfig, ListenerConfig, SecretsConfig,
};
use e6ircd::net;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

mod support;

#[path = "support/deadline.rs"]
mod deadline;

/// A full-access personal access token with the default lifetime, minted the
/// way the REST endpoint mints one.
async fn issue_api_token(
    pool: &sqlx::PgPool,
    account: &str,
    label: &str,
) -> Result<String, e6ircd::db::DbError> {
    e6ircd::db::issue_scoped_api_token(
        pool,
        account,
        label,
        e6ircd::identity::ApiTokenScopes::new(e6ircd::identity::ApiTokenScope::ALL)
            .expect("every scope is a non-empty set"),
        e6ircd::identity::ApiTokenLifetimeDays::DEFAULT,
    )
    .await
}

/// Persist a server ban the way the server does: the audited mutation, so the
/// ban and its audit record commit together.
async fn add_server_ban(
    pool: &sqlx::PgPool,
    mask: &str,
    mask_display: &str,
    reason: &str,
    set_by: &str,
    kind: &str,
) -> Result<(), e6ircd::db::DbError> {
    e6ircd::db::mutate_server_ban_audited(
        pool,
        &e6ircd::core::ServerBanMutation::Add {
            mask: mask.into(),
            mask_display: mask_display.into(),
            reason: reason.into(),
            set_by: set_by.into(),
            kind: kind.into(),
        },
    )
    .await
    .map(|_| ())
}

fn test_config() -> Config {
    Config {
        server_name: "irc.http.example".into(),
        network_name: "HttpNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        }),
        ..Config::default()
    }
}

async fn request(addr: std::net::SocketAddr, req: &str) -> (u16, String, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read");
    let split = buf
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("http response split");
    let head = String::from_utf8_lossy(&buf[..split]).to_string();
    let raw_body = &buf[split + 4..];
    // A streamed response (the account export) arrives chunked.
    let body = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        dechunk(raw_body)
    } else {
        raw_body.to_vec()
    };
    let body = String::from_utf8_lossy(&body).to_string();
    let status: u16 = head
        .lines()
        .next()
        .expect("status line")
        .split(' ')
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status");
    (status, head, body)
}

/// The payload of an HTTP/1.1 chunked body: each chunk is its hexadecimal
/// size, CRLF, that many bytes, CRLF; a zero-size chunk ends it.
fn dechunk(mut raw: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    loop {
        let line_end = raw
            .windows(2)
            .position(|window| window == b"\r\n")
            .expect("chunk size line");
        let size_text = std::str::from_utf8(&raw[..line_end]).expect("ASCII chunk size");
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .expect("hexadecimal chunk size");
        raw = &raw[line_end + 2..];
        if size == 0 {
            return body;
        }
        body.extend_from_slice(&raw[..size]);
        raw = &raw[size + 2..];
    }
}

fn get(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
}

async fn wait_http_ready(addr: std::net::SocketAddr) {
    for _ in 0..200 {
        let (status, _, _) = request(addr, &get("/readyz")).await;
        if status == 200 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("HTTP server did not become ready");
}

async fn wait_irc_ready(addr: std::net::SocketAddr) {
    static NEXT_NICK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    for _ in 0..20 {
        let nick = format!(
            "ready{}",
            NEXT_NICK.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let result = tokio::time::timeout(deadline::HANG, async {
            let mut client = e6irc_client::Connection::connect(&addr.to_string()).await?;
            client
                .register(&e6irc_client::Identity {
                    nick: &nick,
                    username: "tester",
                    realname: "readiness",
                    server_password: None,
                })
                .await
        })
        .await;
        if matches!(result, Ok(Ok(_))) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("IRC server did not become ready");
}

fn response_header<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().find_map(|line| {
        let (header, value) = line.split_once(':')?;
        header.eq_ignore_ascii_case(name).then_some(value.trim())
    })
}

fn csrf_from_html(html: &str) -> &str {
    html.split("name=\"csrf\" value=\"")
        .nth(1)
        .and_then(|tail| tail.split('"').next())
        .expect("csrf token in page")
}

fn login_state_from_html(html: &str) -> &str {
    html.split("name=\"login_state\" value=\"")
        .nth(1)
        .and_then(|tail| tail.split('"').next())
        .expect("login state in page")
}

fn bootstrap_state_from_html(html: &str) -> &str {
    html.split("name=\"bootstrap_state\" value=\"")
        .nth(1)
        .and_then(|tail| tail.split('"').next())
        .expect("bootstrap state in page")
}

fn invitation_state_from_html(html: &str) -> &str {
    html.split("name=\"invitation_state\" value=\"")
        .nth(1)
        .and_then(|tail| tail.split('"').next())
        .expect("invitation state in page")
}

fn assert_visible_e6irc_brand(html: &str) {
    assert!(
        html.contains("<span class=\"brand\">e6irc</span>"),
        "{html}"
    );
}

fn form_value(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(byte).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

struct TemporaryFile(std::path::PathBuf);

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).ok();
    }
}

fn temporary_path(label: &str) -> std::path::PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "e6irc-http-{label}-{}-{sequence}",
        std::process::id()
    ))
}

#[tokio::test]
async fn healthz_is_public_and_ok() {
    // Liveness is the process plus every core shard's heartbeat, so it turns
    // 200 once each shard has finished its first event (its first tick).
    let running = net::start(test_config()).await.expect("start");
    let http = running.http_addr.expect("http bound");
    let mut last = (0, String::new());
    for _ in 0..200 {
        let (status, _, body) = request(http, &get("/healthz")).await;
        last = (status, body);
        if last.0 == 200 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert_eq!(last.0, 200, "{}", last.1);
    assert_eq!(last.1, "ok");
}

#[tokio::test]
async fn device_authorization_requires_an_absolute_public_url() {
    let running = net::start(test_config()).await.expect("start");
    let http = running.http_addr.expect("http bound");
    let start_request = "POST /api/v1/auth/device/start HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

    let (status, headers, body) = request(http, start_request).await;
    assert_eq!(status, 503);
    assert!(headers.contains("application/problem+json"), "{headers}");
    assert!(body.contains("Device authorization unavailable"), "{body}");
}

#[tokio::test]
async fn bootstrap_routes_are_closed_when_not_configured() {
    let running = net::start(test_config()).await.expect("start");
    let http = running.http_addr.expect("HTTP bound");

    let (status, headers, _) = request(http, &get("/bootstrap")).await;
    assert_eq!(status, 303);
    assert_eq!(response_header(&headers, "location"), Some("/login"));

    let body = "token=unused";
    let post = format!(
        "POST /bootstrap HTTP/1.1\r\nHost: t\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    let (status, headers, body) = request(http, &post).await;
    assert_eq!(status, 404);
    assert!(headers.contains("application/problem+json"), "{headers}");
    assert!(body.contains("Bootstrap unavailable"), "{body}");
}

/// A client that stops halfway through its request headers, or keeps a
/// connection open and idle after a response, holds a socket, a task and a
/// per-address connection slot. Both are closed once the header deadline
/// passes; before, the server's builder had no timer, so hyper's header
/// timeout was silently dropped and both were held forever.
#[tokio::test]
async fn half_sent_headers_and_idle_keep_alive_are_closed_at_the_header_deadline() {
    let running = net::start(test_config()).await.expect("start");
    let http = running.http_addr.expect("http bound");
    wait_http_ready(http).await;

    let mut half_sent = TcpStream::connect(http).await.expect("connect");
    half_sent
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: t\r\n")
        .await
        .expect("write part of the header block");
    let mut idle = TcpStream::connect(http).await.expect("connect");
    idle.write_all(b"GET /healthz HTTP/1.1\r\nHost: t\r\n\r\n")
        .await
        .expect("write a keep-alive request");
    let mut response = [0u8; 1024];
    let read = idle.read(&mut response).await.expect("response");
    assert!(
        String::from_utf8_lossy(&response[..read]).starts_with("HTTP/1.1 200"),
        "the kept-alive connection is answered first"
    );

    let started = std::time::Instant::now();
    for (name, stream) in [
        ("half-sent headers", &mut half_sent),
        ("idle keep-alive", &mut idle),
    ] {
        let mut rest = Vec::new();
        let closed = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            stream.read_to_end(&mut rest),
        )
        .await;
        assert!(
            closed.is_ok(),
            "{name}: the server still held the connection after 20 s"
        );
    }
    assert!(
        started.elapsed() >= std::time::Duration::from_secs(5),
        "the connections were closed before any reasonable header deadline: {:?}",
        started.elapsed()
    );
}

/// Only the half-sent request is a refusal. hyper reports the same timeout for
/// a kept-alive connection that sat idle after its response, and a reverse
/// proxy holding idle upstream connections made the deployed daemon log
/// "refused … headers not received in time" every ten seconds.
#[tokio::test]
async fn an_idle_kept_alive_connection_is_not_logged_as_a_refusal() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("a free port")
        .port();
    let directory = std::env::temp_dir().join(format!("e6irc-idle-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("config directory");
    let config_path = directory.join("e6irc.toml");
    std::fs::write(
        &config_path,
        format!(
            "server_name = \"irc.idle.example\"\nnetwork_name = \"IdleNet\"\n\
             [[listeners]]\naddr = \"127.0.0.1:0\"\n\
             [http]\naddr = \"127.0.0.1:{port}\"\nsecure_cookies = false\n"
        ),
    )
    .expect("write config");
    let mut daemon = std::process::Command::new(env!("CARGO_BIN_EXE_e6ircd"))
        .arg("--config")
        .arg(&config_path)
        // Not `env_clear`: Windows sockets need `SystemRoot`. Only this
        // daemon's own variables are kept out.
        .env_clear()
        .envs(std::env::vars().filter(|(name, _)| !name.starts_with("E6IRC_")))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("start e6ircd");
    // Read stderr as it is written: the refusal is logged just after the
    // socket closes, so reading only after a kill would race it.
    let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let reader = {
        use std::io::BufRead as _;
        let stderr = daemon.stderr.take().expect("piped stderr");
        let lines = lines.clone();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stderr)
                .lines()
                .map_while(Result::ok)
            {
                lines.lock().expect("stderr lines").push(line);
            }
        })
    };
    let refusals = || {
        lines
            .lock()
            .expect("stderr lines")
            .iter()
            .filter(|line| line.contains("headers not received in time"))
            .count()
    };
    let http: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let started = std::time::Instant::now();
    while TcpStream::connect(http).await.is_err() {
        if let Some(status) = daemon.try_wait().expect("poll e6ircd") {
            reader.join().expect("stderr reader");
            panic!(
                "e6ircd exited before listening: {status}\n{}",
                lines.lock().expect("stderr lines").join("\n")
            );
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "e6ircd never listened on {http}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    // Accepting is not ready: an instrumented build answers before its health
    // check passes.
    while request(http, &get("/healthz")).await.0 != 200 {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "e6ircd never became healthy"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let mut idle = TcpStream::connect(http).await.expect("connect");
    idle.write_all(b"GET /healthz HTTP/1.1\r\nHost: t\r\n\r\n")
        .await
        .expect("a keep-alive request");
    let mut response = [0u8; 1024];
    let read = idle.read(&mut response).await.expect("response");
    let answer = String::from_utf8_lossy(&response[..read]);
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    let mut rest = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        idle.read_to_end(&mut rest),
    )
    .await
    .expect("the idle connection is closed at the deadline")
    .expect("read");

    // Give a mistaken refusal line the time it would take to appear.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(
        refusals(),
        0,
        "the idle kept-alive close was logged as a refusal"
    );

    let mut half_sent = TcpStream::connect(http).await.expect("connect");
    half_sent
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: t\r\n")
        .await
        .expect("part of a header block");
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        half_sent.read_to_end(&mut rest),
    )
    .await
    .expect("the half-sent request is closed at the deadline")
    .expect("read");

    let logged = tokio::time::timeout(deadline::HANG, async {
        while refusals() == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await;
    daemon.kill().expect("stop e6ircd");
    daemon.wait().expect("reap e6ircd");
    reader.join().expect("stderr reader");
    assert!(
        logged.is_ok(),
        "the half-sent request was not logged as a refusal"
    );
    assert_eq!(refusals(), 1, "exactly the half-sent request is a refusal");
    std::fs::remove_dir_all(&directory).expect("remove config directory");
}

/// One address holding every request slot it may have — each one a request
/// whose body never finishes — is refused further work, while the probes an
/// orchestrator restarts the process on keep answering: they are not queued
/// behind the service's work bounds.
#[tokio::test]
async fn one_address_saturating_its_requests_leaves_the_probes_answering() {
    let running = net::start(test_config()).await.expect("start");
    let http = running.http_addr.expect("http bound");
    wait_http_ready(http).await;

    let mut stalled = Vec::new();
    for _ in 0..net::MAX_HTTP_REQUESTS_IN_FLIGHT_PER_IP {
        let mut stream = TcpStream::connect(http).await.expect("connect");
        stream
            .write_all(
                b"POST /login HTTP/1.1\r\nHost: t\r\n\
                  Content-Type: application/x-www-form-urlencoded\r\n\
                  Content-Length: 4096\r\n\r\naccount=",
            )
            .await
            .expect("write a request whose body never finishes");
        stalled.push(stream);
    }
    // Every stalled request has reached the service and holds its slot.
    let mut refused = None;
    for _ in 0..200 {
        let (status, _, _) = request(http, &get("/api/v1/server")).await;
        if status == 429 {
            refused = Some(status);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert_eq!(
        refused,
        Some(429),
        "a request past the address's in-flight bound is refused"
    );
    let (status, _, body) = request(http, &get("/healthz")).await;
    assert_eq!(status, 200, "liveness answers under saturation: {body}");
    let (status, _, body) = request(http, &get("/readyz")).await;
    assert_eq!(status, 200, "readiness answers under saturation: {body}");
    drop(stalled);
}

/// Every route class carries the same header baseline, whatever its handler
/// set: no powerful browser feature, no cross-origin embedding of a resource,
/// no cross-window reference into a page, no caching of anything personal, and
/// a JSON body that can never be rendered as a document. A handler's own value
/// wins — a hashed asset keeps its long cache lifetime, a page its CSP — and no
/// page needs inline style.
#[cfg(feature = "embed-web")]
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn every_route_class_carries_the_header_baseline() {
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum Class {
        Page,
        Json,
        Asset,
    }
    let url = support::test_db("every_route_class_carries_the_header_baseline").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("account");
    let session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("session");
    drop(pool);
    let mut config = test_config();
    config.database = Some(DatabaseConfig {
        url,
        startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
        max_connections: None,
    });
    // The console overview is an administrator's page.
    config.http.as_mut().expect("http").admin_accounts = vec!["alice".into()];
    let running = net::start(config).await.expect("start");
    let http = running.http_addr.expect("http bound");
    let asset = std::fs::read_dir(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../web/dist/assets"
    ))
    .expect("the embedded web client is built")
    .filter_map(Result::ok)
    .map(|entry| entry.file_name().to_string_lossy().into_owned())
    .find(|name| name.ends_with(".js"))
    .expect("the build has a script");
    let asset = format!("/assets/{asset}");
    // The web shell is the same document for everyone and revalidates on
    // every load (`no-cache`); everything personal is `no-store`.
    let rows: [(&str, bool, u16, Class, &str); 7] = [
        ("/", true, 200, Class::Page, "no-cache"),
        ("/console", true, 200, Class::Page, "no-store"),
        ("/login", false, 200, Class::Page, "no-store"),
        ("/api/v1/me", true, 200, Class::Json, "no-store"),
        ("/api/v1/openapi.json", false, 200, Class::Json, "no-store"),
        ("/no-such-route", false, 404, Class::Json, "no-store"),
        (
            &asset,
            false,
            200,
            Class::Asset,
            "public, max-age=31536000, immutable",
        ),
    ];
    for (path, authenticated, expected_status, class, cache) in rows {
        let cookie = if authenticated {
            format!("Cookie: e6irc_session={session}\r\n")
        } else {
            String::new()
        };
        let (status, headers, _) = request(
            http,
            &format!("GET {path} HTTP/1.1\r\nHost: t\r\n{cookie}Connection: close\r\n\r\n"),
        )
        .await;
        assert_eq!(status, expected_status, "{path}: {headers}");
        let header = |name: &str| response_header(&headers, name).unwrap_or_default();
        assert!(
            header("permissions-policy").contains("camera=()")
                && header("permissions-policy").contains("microphone=()")
                && header("permissions-policy").contains("geolocation=()"),
            "{path}: {headers}"
        );
        assert_eq!(
            header("cross-origin-resource-policy"),
            "same-origin",
            "{path}"
        );
        assert_eq!(header("x-content-type-options"), "nosniff", "{path}");
        assert_eq!(header("cache-control"), cache, "{path}");
        match class {
            Class::Page => {
                assert_eq!(
                    header("cross-origin-opener-policy"),
                    "same-origin",
                    "{path}"
                );
                let policy = header("content-security-policy");
                assert!(
                    policy.contains("frame-ancestors 'none'"),
                    "{path}: {policy}"
                );
                assert!(!policy.contains("unsafe-inline"), "{path}: {policy}");
            }
            Class::Json => {
                assert_eq!(
                    header("content-security-policy"),
                    "default-src 'none'; frame-ancestors 'none'",
                    "{path}"
                );
            }
            Class::Asset => {}
        }
    }
}

#[tokio::test]
async fn every_response_has_a_fresh_server_correlation_id_and_https_hsts() {
    let mut config = test_config();
    let http_config = config.http.as_mut().expect("HTTP config");
    http_config.public_url = Some("https://irc.http.example".into());
    http_config.secure_cookies = true;
    let running = net::start(config).await.expect("start");
    let http = running.http_addr.expect("http bound");

    let (_, first_headers, _) = request(http, &get("/healthz")).await;
    let (_, second_headers, _) = request(http, &get("/api/v1/nope")).await;
    let first_id = response_header(&first_headers, "x-request-id").expect("request ID");
    let second_id = response_header(&second_headers, "x-request-id").expect("request ID");
    assert_eq!(first_id.len(), 32);
    assert!(first_id.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_ne!(first_id, second_id);
    // HSTS covers this origin only unless the operator states that every
    // subdomain is HTTPS too; it never asks for preloading, which no
    // configuration change can take back.
    assert_eq!(
        response_header(&first_headers, "strict-transport-security"),
        Some("max-age=31536000")
    );

    let mut config = test_config();
    let http_config = config.http.as_mut().expect("HTTP config");
    http_config.public_url = Some("https://irc.http.example".into());
    http_config.secure_cookies = true;
    http_config.hsts_include_subdomains = true;
    let running = net::start(config).await.expect("start");
    let http = running.http_addr.expect("http bound");
    let (_, headers, _) = request(http, &get("/healthz")).await;
    assert_eq!(
        response_header(&headers, "strict-transport-security"),
        Some("max-age=31536000; includeSubDomains")
    );

    let running = net::start(test_config()).await.expect("plain HTTP start");
    let http = running.http_addr.expect("HTTP bound");
    let (_, headers, _) = request(http, &get("/healthz")).await;
    assert!(
        response_header(&headers, "strict-transport-security").is_none(),
        "HSTS over an explicitly plain public origin would make development hosts unreachable"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn browser_bootstrap_creates_the_only_first_admin_and_closes_itself() {
    let database_url =
        support::test_db("browser_bootstrap_creates_the_only_first_admin_and_closes_itself").await;
    let mut config = test_config();
    config.database = Some(DatabaseConfig {
        url: database_url,
        startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
        max_connections: None,
    });
    config.bootstrap = Some(BootstrapConfig {
        token: "0123456789abcdef0123456789abcdef".into(),
    });
    let running = net::start(config).await.expect("start");
    let http = running.http_addr.expect("HTTP bound");

    let (status, _, login) = request(http, &get("/login")).await;
    assert_eq!(status, 200);
    assert!(login.contains("href=\"/bootstrap\""), "{login}");

    let (status, bootstrap_headers, bootstrap_page) = request(http, &get("/bootstrap")).await;
    assert_eq!(status, 200);
    assert!(bootstrap_page.contains("Create the administrator"));
    let bootstrap_state = bootstrap_state_from_html(&bootstrap_page);
    let state_cookie = response_header(&bootstrap_headers, "set-cookie")
        .expect("bootstrap state cookie")
        .split(';')
        .next()
        .expect("cookie pair");

    let bad_body = format!(
        "bootstrap_state={}&token={}&account=Alice&password={}&password_confirmation={}",
        form_value(bootstrap_state),
        form_value("incorrect-token-incorrect-token"),
        form_value("correct horse battery staple"),
        form_value("correct horse battery staple"),
    );
    let bad_request = format!(
        "POST /bootstrap HTTP/1.1\r\nHost: t\r\nCookie: {state_cookie}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{bad_body}",
        bad_body.len()
    );
    let (status, _, body) = request(http, &bad_request).await;
    assert_eq!(status, 401);
    assert!(body.contains("Invalid bootstrap token."));

    let (_, bootstrap_headers, bootstrap_page) = request(http, &get("/bootstrap")).await;
    let bootstrap_state = bootstrap_state_from_html(&bootstrap_page);
    let state_cookie = response_header(&bootstrap_headers, "set-cookie")
        .expect("replacement bootstrap state cookie")
        .split(';')
        .next()
        .expect("cookie pair");
    let good_body = format!(
        "bootstrap_state={}&token={}&account=Alice&password={}&password_confirmation={}",
        form_value(bootstrap_state),
        form_value("0123456789abcdef0123456789abcdef"),
        form_value("correct horse battery staple"),
        form_value("correct horse battery staple"),
    );
    let good_request = format!(
        "POST /bootstrap HTTP/1.1\r\nHost: t\r\nCookie: {state_cookie}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{good_body}",
        good_body.len()
    );
    let (status, headers, _) = request(http, &good_request).await;
    assert_eq!(status, 303, "{headers}");
    assert_eq!(response_header(&headers, "location"), Some("/console"));
    let session = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find_map(|(name, value)| {
            (name.eq_ignore_ascii_case("set-cookie") && value.trim().starts_with("e6irc_session="))
                .then(|| {
                    value
                        .trim()
                        .split(';')
                        .next()
                        .expect("session cookie pair")
                        .to_string()
                })
        })
        .expect("administrator session cookie");

    let console_request = format!(
        "GET /console HTTP/1.1\r\nHost: t\r\nCookie: {session}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, console) = request(http, &console_request).await;
    assert_eq!(status, 200);
    assert!(console.contains("Alice"), "{console}");

    let (status, headers, _) = request(http, &get("/bootstrap")).await;
    assert_eq!(status, 303);
    assert_eq!(response_header(&headers, "location"), Some("/login"));
    let (_, _, login) = request(http, &get("/login")).await;
    assert!(!login.contains("href=\"/bootstrap\""), "{login}");
}

#[tokio::test]
async fn readyz_reports_core_and_optional_database_state() {
    let running = net::start(test_config()).await.expect("start");
    let http = running.http_addr.expect("http bound");
    let mut response = request(http, &get("/readyz")).await;
    for _ in 0..20 {
        if response.0 == 200 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        response = request(http, &get("/readyz")).await;
    }
    assert_eq!(response.0, 200, "{}", response.2);
    let body: serde_json::Value = serde_json::from_str(&response.2).expect("readiness JSON");
    assert_eq!(body["ready"], true);
    assert_eq!(body["core"], "ready");
    assert_eq!(body["database"], "not_configured");
}

#[tokio::test]
async fn signed_out_page_is_public_reload_safe_and_accessible() {
    let running = net::start(test_config()).await.expect("start");
    let http = running.http_addr.expect("http bound");

    for attempt in 1..=2 {
        let (status, headers, body) = request(http, &get("/auth/signed-out")).await;
        assert_eq!(status, 200, "attempt {attempt}: {headers}");
        let headers = headers.to_ascii_lowercase();
        assert!(
            headers.contains("content-type: text/html; charset=utf-8"),
            "attempt {attempt}: {headers}"
        );
        assert!(
            headers.contains("cache-control: no-store"),
            "attempt {attempt}: {headers}"
        );
        assert!(
            headers.contains("content-security-policy: default-src 'none'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
            "attempt {attempt}: {headers}"
        );
        assert_visible_e6irc_brand(&body);
        assert!(
            body.contains("<h1 id=\"signed-out-title\">You are signed out</h1>"),
            "{body}"
        );
        assert!(
            body.contains("href=\"/login\">Choose a sign-in provider</a>"),
            "{body}"
        );
    }

    let (status, headers, styles) = request(http, &get("/auth.css")).await;
    assert_eq!(status, 200, "{headers}");
    assert!(styles.contains("prefers-color-scheme: dark"), "{styles}");
    assert!(styles.contains(".primary-action:focus-visible"), "{styles}");
    assert!(
        styles.contains("prefers-reduced-motion: no-preference"),
        "{styles}"
    );
}

#[tokio::test]
async fn network_presets_endpoint_serves_the_curated_catalog() {
    let running = net::start(test_config()).await.expect("start");
    let http = running.http_addr.expect("http bound");
    let (status, _, body) = request(http, &get("/api/v1/network-presets")).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let presets = v["presets"].as_array().expect("presets array");
    assert_eq!(
        presets[0],
        serde_json::json!({
            "id": "libera",
            "label": "Libera Chat",
            "name": "libera",
            "addr": "irc.libera.chat:6697",
            "tls": true,
        }),
        "{body}"
    );
    assert!(
        presets.iter().all(|preset| preset["tls"] == true),
        "every curated public network is TLS-only: {body}"
    );
}

#[tokio::test]
async fn server_info_endpoint() {
    let running = net::start(test_config()).await.expect("start");
    let http = running.http_addr.expect("http bound");
    let (status, head, body) = request(http, &get("/api/v1/server")).await;
    assert_eq!(status, 200);
    assert!(
        head.to_lowercase()
            .contains("content-type: application/json"),
        "{head}"
    );
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["server_name"], "irc.http.example");
    assert_eq!(v["network_name"], "HttpNet");
    assert!(v["version"].as_str().is_some());
}

#[tokio::test]
async fn unknown_route_is_problem_json_404() {
    let running = net::start(test_config()).await.expect("start");
    let http = running.http_addr.expect("http bound");
    let (status, head, body) = request(http, &get("/api/v1/nope")).await;
    assert_eq!(status, 404);
    assert!(
        head.to_lowercase().contains("application/problem+json"),
        "{head}"
    );
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["status"], 404);
    assert!(v["title"].as_str().is_some());
}

/// The problem document every refusal shares: its content type, and a body
/// whose `status` member repeats the status line.
fn assert_problem(status: u16, head: &str, body: &str, expected: u16) -> serde_json::Value {
    assert_eq!(status, expected, "{head}\n{body}");
    assert!(
        head.to_lowercase()
            .contains("content-type: application/problem+json"),
        "{head}"
    );
    let v: serde_json::Value = serde_json::from_str(body).expect("problem json");
    assert_eq!(v["status"], expected, "{body}");
    v
}

/// The seconds a `429` asks the client to wait, required to be present.
fn retry_after(head: &str) -> u64 {
    response_header(head, "retry-after")
        .unwrap_or_else(|| panic!("a 429 without Retry-After: {head}"))
        .parse()
        .expect("numeric Retry-After")
}

#[tokio::test]
async fn an_unserved_method_is_a_problem_json_405_that_keeps_allow() {
    let running = net::start(test_config()).await.expect("start");
    let http = running.http_addr.expect("http bound");
    for (req, allow) in [
        // A documented API route, a console page, and a probe — the probes
        // are routed apart from the rest and must not escape the contract.
        (
            "DELETE /api/v1/server HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
            "GET,HEAD",
        ),
        (
            "PUT /console HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "GET,HEAD",
        ),
        (
            "POST /healthz HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "GET,HEAD",
        ),
    ] {
        let (status, head, body) = request(http, req).await;
        assert_problem(status, &head, &body, 405);
        assert_eq!(
            response_header(&head, "allow").map(|value| value.replace(' ', "")),
            Some(allow.to_string()),
            "{head}"
        );
    }
}

#[tokio::test]
async fn a_malformed_path_parameter_is_a_problem_json_400() {
    let running = net::start(test_config()).await.expect("start");
    let http = running.http_addr.expect("http bound");
    // `%FF` is not UTF-8, so no `String` path parameter can hold it.
    let (status, head, body) = request(http, &get("/api/v1/auth/oidc/%FF/start")).await;
    let v = assert_problem(status, &head, &body, 400);
    assert_eq!(v["title"], "Invalid path parameter", "{body}");
}

#[tokio::test]
async fn a_plain_get_of_the_websocket_endpoint_is_a_problem_document() {
    let running = net::start(test_config()).await.expect("start");
    let http = running.http_addr.expect("http bound");
    let (status, head, body) = request(http, &get("/ws/irc")).await;
    assert!((400..500).contains(&status), "{head}");
    let v = assert_problem(status, &head, &body, status);
    assert_eq!(v["title"], "Invalid WebSocket upgrade", "{body}");
}

#[tokio::test]
async fn the_per_address_authentication_budget_says_when_to_retry() {
    let mut config = test_config();
    config.limits.auth_rate_burst = Some(1);
    let running = net::start(config).await.expect("start");
    let http = running.http_addr.expect("http bound");
    let body = r#"{"account":"a","password":"p","label":"test"}"#;
    let req = format!(
        "POST /api/v1/auth/app-passwords HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    // The one token is spent on a refusal for want of a database.
    let (status, _, _) = request(http, &req).await;
    assert_eq!(status, 503);
    let (status, head, body) = request(http, &req).await;
    assert_problem(status, &head, &body, 429);
    // One token refills over a sixty-second window at a burst of one.
    let wait = retry_after(&head);
    assert!((1..=60).contains(&wait), "{head}");
}

/// Send a WebSocket upgrade for `/ws/irc` and read only the response head, so
/// an accepted connection stays open and keeps its per-address slot.
async fn open_irc_websocket(addr: std::net::SocketAddr) -> (TcpStream, u16, String, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(
            b"GET /ws/irc HTTP/1.1\r\nHost: t\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
              Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        )
        .await
        .expect("write");
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.expect("response head");
        buf.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&buf).to_string();
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("status code");
    let length = response_header(&head, "content-length").map_or(0, |value| {
        value.parse::<usize>().expect("numeric Content-Length")
    });
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await.expect("response body");
    (
        stream,
        status,
        head,
        String::from_utf8_lossy(&body).to_string(),
    )
}

#[tokio::test]
async fn the_websocket_connection_cap_says_when_to_retry() {
    let mut config = test_config();
    config.limits.max_connections_per_ip = Some(1);
    let running = net::start(config).await.expect("start");
    let http = running.http_addr.expect("http bound");
    let (_held, status, head, _) = open_irc_websocket(http).await;
    assert_eq!(status, 101, "{head}");
    let (_, status, head, body) = open_irc_websocket(http).await;
    assert_problem(status, &head, &body, 429);
    // The soonest a slot is certain to free: the registration timeout.
    assert_eq!(retry_after(&head), 30, "{head}");
}

#[tokio::test]
async fn app_password_requires_database() {
    // Without a configured database the endpoint must fail loudly, not
    // pretend to issue credentials.
    let running = net::start(test_config()).await.expect("start");
    let http = running.http_addr.expect("http bound");
    let body = r#"{"account":"a","password":"p","label":"test"}"#;
    let req = format!(
        "POST /api/v1/auth/app-passwords HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let (status, head, _) = request(http, &req).await;
    assert_eq!(status, 503);
    assert!(
        head.to_lowercase().contains("application/problem+json"),
        "{head}"
    );
}

// ---- per-account BNC network management (PG-gated) ----------------------

use e6ircd::config::BncConfig;

/// Start a throwaway plain e6ircd to act as an upstream network.
async fn upstream_server() -> net::Running {
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
    net::start(cfg).await.expect("upstream start")
}

async fn post_json(
    addr: std::net::SocketAddr,
    path: &str,
    token: &str,
    body: &str,
) -> (u16, String) {
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let (status, _head, body) = request(addr, &req).await;
    (status, body)
}

async fn patch_json(
    addr: std::net::SocketAddr,
    path: &str,
    token: &str,
    body: &str,
) -> (u16, String) {
    let req = format!(
        "PATCH {path} HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let (status, _head, body) = request(addr, &req).await;
    (status, body)
}

/// `runtime.connection_attempts` of the first listed network.
fn first_network_attempts(body: &str) -> u64 {
    let v: serde_json::Value = serde_json::from_str(body).expect("json");
    v["networks"][0]["runtime"]["connection_attempts"]
        .as_u64()
        .unwrap_or_else(|| panic!("no connection_attempts in {body}"))
}

/// By default the server connects to no upstream inside its own network: an
/// account holder could otherwise make it probe internal infrastructure. The
/// refusal is the same at every ingress -- creating a network, the connection
/// test -- and a hostname that only resolves internally is refused at dial time.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn internal_upstreams_are_refused_unless_the_operator_allows_them() {
    let url =
        support::test_db("internal_upstreams_are_refused_unless_the_operator_allows_them").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "s3cr3t", None)
        .await
        .expect("acct");
    let token = issue_api_token(&pool, "alice", "test")
        .await
        .expect("token");
    drop(pool);
    let upstream = upstream_server().await;
    let up = upstream.addrs[0];

    // The default configuration: `internal_upstreams` is not set.
    let config = Config {
        server_name: "irc.internal.example".into(),
        network_name: "Internal".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }),
        ..Config::default()
    };
    assert_eq!(
        config.internal_upstreams,
        e6ircd::egress::InternalUpstreams::Refuse
    );
    let running = net::start(config).await.expect("start");
    let http = running.http_addr.expect("http bound");
    wait_http_ready(http).await;

    for (path, body) in [
        (
            "/api/v1/me/networks",
            format!(r#"{{"kind":"irc","name":"lan","addr":"{up}","tls":false,"nick":"probe","username":"probe","realname":"Probe","autojoin":[]}}"#),
        ),
        (
            "/api/v1/me/network-preflight",
            format!(r#"{{"addr":"{up}","tls":false,"nick":"probe","username":"probe","realname":"Probe","autojoin":[]}}"#),
        ),
        (
            "/api/v1/me/networks",
            r#"{"kind":"irc","name":"lan","addr":"10.0.0.5:6667","tls":true,"nick":"probe","username":"probe","realname":"Probe","autojoin":[]}"#.to_string(),
        ),
    ] {
        let (status, answer) = post_json(http, path, &token, &body).await;
        assert_eq!(status, 400, "{path}: {answer}");
        let problem: serde_json::Value = serde_json::from_str(&answer).expect("problem json");
        assert_eq!(problem["title"], "Disallowed upstream address", "{answer}");
        assert_eq!(problem["field"], "addr", "{answer}");
        assert!(
            !answer.contains("127.0.0.1") && !answer.contains("10.0.0.5"),
            "the refusal must not echo the address: {answer}"
        );
    }

    // A hostname passes the literal check and is judged where it resolves.
    let (status, answer) = post_json(
        http,
        "/api/v1/me/network-preflight",
        &token,
        &format!(
            r#"{{"addr":"localhost:{}","tls":false,"nick":"probe","username":"probe","realname":"Probe","autojoin":[]}}"#,
            up.port()
        ),
    )
    .await;
    assert_eq!(status, 502, "{answer}");
    let problem: serde_json::Value = serde_json::from_str(&answer).expect("problem json");
    assert_eq!(problem["title"], "IRC network preflight failed", "{answer}");
    assert!(
        problem["detail"]
            .as_str()
            .is_some_and(|detail| detail.ends_with("(address_blocked)")),
        "the dial-time refusal is the typed address_blocked failure: {answer}"
    );
    let (status, _, listed) = request(
        http,
        &format!(
            "GET /api/v1/me/networks HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_eq!(status, 200, "{listed}");
    let networks: serde_json::Value = serde_json::from_str(&listed).expect("networks");
    assert_eq!(
        networks["networks"],
        serde_json::json!([]),
        "nothing was created"
    );
    assert_eq!(
        running.shutdown.run().await,
        e6ircd::net::ShutdownOutcome::Flushed
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn bnc_network_management_lifecycle() {
    let url = support::test_db("bnc_network_management_lifecycle").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "s3cr3t", None)
        .await
        .expect("acct");
    let token = issue_api_token(&pool, "alice", "test")
        .await
        .expect("token");
    drop(pool);

    let upstream = upstream_server().await;
    let up = upstream.addrs[0];

    let config = Config {
        server_name: "irc.mgmt.example".into(),
        network_name: "Mgmt".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url: url.clone(),
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }),
        internal_upstreams: e6ircd::egress::InternalUpstreams::Allow,
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let http = running.http_addr.expect("http bound");
    let bnc = running.bnc_addr.expect("bnc bound");
    wait_http_ready(http).await;

    // Missing or wrong-kind fields fail at the HTTP boundary.
    let (status, _) = post_json(
        http,
        "/api/v1/me/network-preflight",
        &token,
        &format!(r#"{{"addr":"{up}","nick":"probe","username":"probe","realname":"Preflight"}}"#),
    )
    .await;
    assert_eq!(status, 400, "preflight must require tls");
    let (status, _) = post_json(
        http,
        "/api/v1/me/networks",
        &token,
        &format!(r#"{{"name":"implicit","addr":"{up}","tls":false,"nick":"probe","username":"probe","realname":"Probe","autojoin":[]}}"#),
    )
    .await;
    assert_eq!(status, 400, "network creation must require kind");
    let (status, _) = post_json(
        http,
        "/api/v1/me/networks",
        &token,
        r#"{"kind":"discord","name":"wrong-fields","addr":"","tls":true,"nick":"x","autojoin":[],"sasl_password":"token"}"#,
    )
    .await;
    assert_eq!(status, 400, "discord creation must reject IRC fields");

    // Qualification uses the production resolver, transport, and registration
    // path without persisting or starting a driver, and joins nothing.
    let (status, body) = post_json(
        http,
        "/api/v1/me/network-preflight",
        &token,
        &format!(r##"{{"addr":"{up}","tls":false,"nick":"probe","username":"probe","realname":"Preflight","autojoin":["#preflight"]}}"##),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let qualified: serde_json::Value = serde_json::from_str(&body).expect("preflight json");
    assert_eq!(qualified["ok"], true, "{body}");
    assert_eq!(qualified["confirmed_nick"], "probe", "{body}");
    assert!(
        qualified.get("joined_channels").is_none(),
        "the connection test joins nothing and says nothing about channels: {body}"
    );
    assert_eq!(qualified["resolved_addresses"], 1, "{body}");
    for stage in ["dns_ms", "connect_ms", "registration_ms"] {
        assert!(qualified[stage].is_u64(), "missing {stage}: {body}");
    }

    let (status, body) = post_json(
        http,
        "/api/v1/me/network-preflight",
        &token,
        &format!(r#"{{"addr":"{up}","tls":false,"nick":"probe","username":"probe","realname":"Preflight","sasl_account":"alice"}}"#),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    let problem: serde_json::Value = serde_json::from_str(&body).expect("problem json");
    assert_eq!(problem["status"], 400, "{body}");
    assert_eq!(problem["title"], "Incomplete upstream SASL", "{body}");
    assert_eq!(
        problem["detail"], "provide both sasl_account and sasl_password, or neither",
        "{body}"
    );

    let list_req = format!(
        "GET /api/v1/me/networks HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, body) = request(http, &list_req).await;
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert!(
        v["networks"].as_array().is_some_and(Vec::is_empty),
        "{body}"
    );

    // create a network pointing at the upstream
    let (status, _) = post_json(
        http,
        "/api/v1/me/networks",
        &token,
        &format!(r##"{{"kind":"irc","name":"work","addr":"{up}","tls":false,"nick":"alice_","username":"alice_","realname":"Alice","autojoin":["#lobby"]}}"##),
    )
    .await;
    assert_eq!(status, 201, "create should succeed");

    // The IRC user name is stated, never derived: absent, or outside the one
    // grammar every server accepts, is refused at its field — and it is not a
    // field a bridge has.
    for (request, detail) in [
        (
            r#"{"kind":"irc","name":"nouser","addr":"up.example:1","tls":false,"nick":"_bot","realname":"B","autojoin":[]}"#,
            "username",
        ),
        (
            r#"{"kind":"irc","name":"derived","addr":"up.example:1","tls":false,"nick":"_bot","username":"_bot","realname":"B","autojoin":[]}"#,
            "must begin with an ASCII letter or digit",
        ),
        (
            r#"{"kind":"irc","name":"dotted","addr":"up.example:1","tls":false,"nick":"bot","username":"first.last","realname":"B","autojoin":[]}"#,
            "may contain only ASCII letters, digits",
        ),
        (
            r#"{"kind":"discord","name":"bridge","addr":"","tls":true,"autojoin":[],"sasl_password":"t","username":"bot"}"#,
            "username",
        ),
    ] {
        let (status, body) = post_json(http, "/api/v1/me/networks", &token, request).await;
        assert!(status == 400 || status == 422, "{request}: {status} {body}");
        assert!(body.contains(detail), "{request}: {body}");
    }
    let (status, body) = post_json(
        http,
        "/api/v1/me/network-preflight",
        &token,
        r#"{"addr":"up.example:1","tls":false,"nick":"probe","username":"_probe","realname":"P"}"#,
    )
    .await;
    assert_eq!(status, 400, "{body}");
    let problem: serde_json::Value = serde_json::from_str(&body).expect("problem JSON");
    assert_eq!(problem["field"], "username", "{body}");

    // The SASL pair is bounded and control-checked like every other field:
    // an oversized password (dead sealed weight per row) and a NUL — PLAIN's
    // own field separator, an injection primitive on the upstream — are
    // refused before anything is sealed or stored.
    let big = "p".repeat(513);
    let (status, _) = post_json(
        http,
        "/api/v1/me/networks",
        &token,
        &format!(
            r#"{{"kind":"irc","name":"big","addr":"up.example:1","tls":false,"nick":"n","username":"n","realname":"N","autojoin":[],"sasl_account":"a","sasl_password":"{big}"}}"#
        ),
    )
    .await;
    assert_eq!(status, 400, "oversized sasl_password must be refused");
    let (status, _) = post_json(
        http,
        "/api/v1/me/networks",
        &token,
        r#"{"kind":"irc","name":"nul","addr":"up.example:1","tls":false,"nick":"n","username":"n","realname":"N","autojoin":[],"sasl_account":"a\u0000b","sasl_password":"p"}"#,
    )
    .await;
    assert_eq!(status, 400, "NUL in sasl_account must be refused");

    // it appears in the list
    let (status, _, body) = request(http, &list_req).await;
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["networks"][0]["name"], "work");
    assert_eq!(v["networks"][0]["has_sasl_password"], false);

    // the driver started: once the listing reports it connected, alice can
    // attach to it via the BNC port
    tokio::time::timeout(deadline::HANG, async {
        loop {
            let (_, _, body) = request(http, &list_req).await;
            let v: serde_json::Value = serde_json::from_str(&body).expect("json");
            if v["networks"][0]["runtime"]["state"] == "connected" {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the created network's driver never connected");
    let mut client = e6irc_client::Connection::connect(&bnc.to_string())
        .await
        .unwrap();
    let confirmed = client
        .register_sasl(
            &e6irc_client::Identity {
                nick: "alice/work",
                username: "alicework",
                realname: "Me",
                server_password: None,
            },
            "alice",
            "s3cr3t",
        )
        .await
        .expect("attach to the just-created network");
    // The slash-bearing registration nick is only a BNC routing selector.
    // Once attached, RPL_WELCOME must name the authoritative upstream nick.
    assert_eq!(confirmed, "alice_");
    drop(client);

    // the live driver reached the upstream, so the listing reports it up
    let (_, _, body) = request(http, &list_req).await;
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["networks"][0]["connected"], true, "{body}");
    assert_eq!(v["networks"][0]["enabled"], true, "{body}");
    assert_eq!(v["networks"][0]["runtime"]["state"], "connected", "{body}");
    assert!(
        v["networks"][0]["runtime"]["connection_attempts"]
            .as_u64()
            .is_some_and(|attempts| attempts >= 1),
        "{body}"
    );
    assert!(
        v["networks"][0]["runtime"]["connect_latency_ms"].is_u64(),
        "{body}"
    );
    assert!(
        v["networks"][0]["runtime"]["traffic"]["lines_in"].is_u64(),
        "{body}"
    );

    let detail_req = format!(
        "GET /api/v1/me/networks/work HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, detail) = request(http, &detail_req).await;
    assert_eq!(status, 200, "{detail}");
    let detail: serde_json::Value = serde_json::from_str(&detail).expect("network detail json");
    assert_eq!(detail["name"], "work");
    assert_eq!(detail["runtime"]["state"], "connected");
    assert_eq!(detail["has_sasl_password"], false);

    // Full configuration replacement is available through REST as well. The
    // credential action is mandatory even when there is no secret to change.
    let update = format!(
        r##"{{"addr":"{up}","tls":false,"nick":"alice_updated","username":"alice_upda","realname":"Alice","autojoin":["#other"],"credentials":{{"action":"keep"}},"server_password":{{"action":"keep"}}}}"##
    );
    let update_req = format!(
        "PUT /api/v1/me/networks/work HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{update}",
        update.len()
    );
    let (status, _, body) = request(http, &update_req).await;
    assert_eq!(status, 204, "update: {body}");
    // The audit row names the fields the edit changed (by name only) and the
    // kind; `addr` and `tls` were resubmitted unchanged and are not listed.
    let audit_pool = sqlx::PgPool::connect(&url).await.expect("audit pool");
    let (target, detail): (String, String) = sqlx::query_as(
        "SELECT target, detail FROM audit_log WHERE action = 'NETWORK_UPDATE' ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&audit_pool)
    .await
    .expect("NETWORK_UPDATE audit row");
    assert_eq!(target, "alice/work");
    assert_eq!(detail, "irc; changed: nick, username, autojoin");
    let (_, create_detail): (String, String) = sqlx::query_as(
        "SELECT target, detail FROM audit_log WHERE action = 'NETWORK_CREATE' ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&audit_pool)
    .await
    .expect("NETWORK_CREATE audit row");
    assert!(
        create_detail.starts_with("irc; fields: addr, tls, nick"),
        "{create_detail}"
    );
    assert!(!create_detail.contains(&up.to_string()), "{create_detail}");
    audit_pool.close().await;
    let (status, _, detail) = request(http, &detail_req).await;
    assert_eq!(status, 200, "{detail}");
    let detail: serde_json::Value = serde_json::from_str(&detail).expect("updated detail json");
    assert_eq!(detail["nick"], "alice_updated");
    assert_eq!(detail["username"], "alice_upda");
    assert_eq!(detail["realname"], "Alice");
    assert_eq!(detail["autojoin"], serde_json::json!(["#other"]));

    let ambiguous = format!(r#"{{"addr":"{up}","tls":false,"nick":"ignored"}}"#);
    let ambiguous_req = format!(
        "PUT /api/v1/me/networks/work HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{ambiguous}",
        ambiguous.len()
    );
    let (status, _, _) = request(http, &ambiguous_req).await;
    assert_eq!(
        status, 400,
        "an omitted credential action must not silently preserve or clear"
    );

    // PUT replaces the whole configuration, so an omitted autojoin list is
    // refused rather than read as "none" -- which silently cleared it.
    let no_autojoin = format!(
        r#"{{"addr":"{up}","tls":false,"nick":"alice_updated","username":"alice_upda","realname":"Alice","credentials":{{"action":"keep"}},"server_password":{{"action":"keep"}}}}"#
    );
    let no_autojoin_req = format!(
        "PUT /api/v1/me/networks/work HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{no_autojoin}",
        no_autojoin.len()
    );
    let (status, head, body) = request(http, &no_autojoin_req).await;
    assert_eq!(status, 400, "{body}");
    assert!(
        head.to_lowercase().contains("application/problem+json"),
        "{head}"
    );
    assert!(body.contains("autojoin"), "{body}");
    let (status, _, detail) = request(http, &detail_req).await;
    assert_eq!(status, 200, "{detail}");
    let detail: serde_json::Value = serde_json::from_str(&detail).expect("detail json");
    assert_eq!(detail["autojoin"], serde_json::json!(["#other"]));

    // An integer ID that is not one is the same problem document as every
    // other refusal, not axum's plain-text rejection.
    let bad_id = format!(
        "DELETE /api/v1/me/tokens/not-a-number HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
    let (status, head, body) = request(http, &bad_id).await;
    let v = assert_problem(status, &head, &body, 400);
    assert_eq!(v["title"], "Invalid path parameter", "{body}");

    // disable it: the flag flips and the driver stops (no live handle, so
    // `connected` is null), while the config row survives.
    let patch = |enabled: bool| {
        let body = format!(r#"{{"enabled":{enabled}}}"#);
        format!(
            "PATCH /api/v1/me/networks/work HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    };
    let (status, _, body) = request(http, &patch(false)).await;
    assert_eq!(status, 200, "disable: {body}");
    let (_, _, body) = request(http, &list_req).await;
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["networks"][0]["enabled"], false, "{body}");
    assert!(v["networks"][0]["connected"].is_null(), "{body}");

    // re-enable it: the driver restarts and reconnects to the still-live
    // upstream, so `connected` returns to true.
    let (status, _, body) = request(http, &patch(true)).await;
    assert_eq!(status, 200, "enable: {body}");
    let mut reconnected = false;
    let mut latest_status = String::new();
    for _ in 0..30 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let (_, _, body) = request(http, &list_req).await;
        latest_status = body.clone();
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["networks"][0]["enabled"], true, "{body}");
        if v["networks"][0]["connected"] == true {
            reconnected = true;
            break;
        }
    }
    assert!(
        reconnected,
        "re-enabled driver never reconnected: {latest_status}"
    );

    // Enabling an already-enabled network is idempotent: it answers normally
    // (it used to panic the handler on a registry assertion) and leaves the
    // healthy upstream session alone instead of restarting it.
    let attempts_before = first_network_attempts(&request(http, &list_req).await.2);
    let (status, _, body) = request(http, &patch(true)).await;
    assert_eq!(status, 200, "repeated enable: {body}");
    let (_, _, body) = request(http, &list_req).await;
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["networks"][0]["connected"], true, "{body}");
    assert_eq!(first_network_attempts(&body), attempts_before, "{body}");

    // delete it
    let del_req = format!(
        "DELETE /api/v1/me/networks/work HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, _) = request(http, &del_req).await;
    assert_eq!(status, 204, "delete should succeed");

    let (status, _, body) = request(http, &list_req).await;
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert!(v["networks"].as_array().unwrap().is_empty(), "{body}");
}

/// A SASL password or server password is refused, by field, for an upstream
/// reached without TLS — at create and at the connection test alike — before
/// anything is stored or dialled. The one exception is the test harness's
/// in-process upstream: a loopback address, under `internal_upstreams = "allow"`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn cleartext_upstream_credentials_are_refused_by_field() {
    let url = support::test_db("cleartext_upstream_credentials_are_refused_by_field").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "s3cr3t", None)
        .await
        .expect("account");
    let token = issue_api_token(&pool, "alice", "test")
        .await
        .expect("token");
    drop(pool);
    let mut config = test_config();
    config.database = Some(DatabaseConfig {
        url,
        startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
        max_connections: None,
    });
    config.internal_upstreams = e6ircd::egress::InternalUpstreams::Allow;
    let running = net::start(config).await.expect("start");
    let http = running.http_addr.expect("http bound");
    let field = |body: &str| {
        serde_json::from_str::<serde_json::Value>(body).expect("problem JSON")["field"].clone()
    };
    let identity = r#""nick":"alice_","username":"alice_","realname":"Alice","autojoin":[]"#;
    for (path, credential, expected) in [
        (
            "/api/v1/me/networks",
            r#""kind":"irc","name":"plain","sasl_account":"alice","sasl_password":"upstreampass""#,
            "sasl_password",
        ),
        (
            "/api/v1/me/networks",
            r#""kind":"irc","name":"plain","server_password":"open sesame""#,
            "server_password",
        ),
        (
            "/api/v1/me/network-preflight",
            r#""sasl_account":"alice","sasl_password":"upstreampass""#,
            "sasl_password",
        ),
    ] {
        let body = format!(r#"{{{identity},"addr":"irc.example:6667","tls":false,{credential}}}"#);
        let (status, answer) = post_json(http, path, &token, &body).await;
        assert_eq!(status, 400, "{path} {credential}: {answer}");
        assert_eq!(field(&answer), expected, "{answer}");
        assert!(answer.contains("TLS"), "{answer}");
    }
    // The in-process loopback upstream of a test harness may be sent them.
    let (status, answer) = post_json(
        http,
        "/api/v1/me/networks",
        &token,
        &format!(
            r#"{{{identity},"kind":"irc","name":"harness","addr":"127.0.0.1:6667","tls":false,"sasl_account":"alice","sasl_password":"upstreampass"}}"#
        ),
    )
    .await;
    assert_ne!(field(&answer), "sasl_password", "{status}: {answer}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn bnc_network_upstream_secret_requires_master_key() {
    let url = support::test_db("bnc_network_upstream_secret_requires_master_key").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "s3cr3t", None)
        .await
        .expect("acct");
    let token = issue_api_token(&pool, "alice", "test")
        .await
        .expect("token");
    e6ircd::db::create_bnc_network(
        &pool,
        "alice",
        &e6ircd::db::BncNetworkRow {
            kind: e6ircd::config::NetworkKind::Irc,
            name: "stored-secret".into(),
            addr: "up.example:6697".into(),
            tls: true,
            nick: "alice_".into(),
            username: Some("tester".into()),
            realname: Some("Alice".into()),
            autojoin: vec![],
            sasl_account: Some("alice".into()),
            // Simulates a deployment whose key was removed after credentials
            // had already been stored. Boot cannot open it, but explicit
            // credential removal must still recover the network.
            sasl_password_sealed: Some("enc:v2:unavailable-without-key".into()),
            enabled: true,
            server_password_sealed: None,
        },
        e6ircd::db::NetworkAudit {
            actor: "alice",
            detail: "",
        },
    )
    .await
    .expect("stored credential row");
    drop(pool);

    // server with NO [secrets] key configured
    let config = Config {
        server_name: "irc.nokey.example".into(),
        network_name: "NoKey".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }),
        internal_upstreams: e6ircd::egress::InternalUpstreams::Allow,
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let http = running.http_addr.expect("http bound");

    // creating a network WITH an upstream password fails loudly (409):
    // the server has no key to seal it, and must not store it in clear.
    let (status, _) = post_json(
        http,
        "/api/v1/me/networks",
        &token,
        r#"{"kind":"irc","name":"work","addr":"irc.example:6697","tls":true,"nick":"alice_","username":"alice_","realname":"Alice","autojoin":[],"sasl_account":"alice","sasl_password":"upstreampass"}"#,
    )
    .await;
    assert_eq!(
        status, 409,
        "must refuse to store an upstream secret unsealed"
    );
    // A server password alone is a secret too.
    let (status, _) = post_json(
        http,
        "/api/v1/me/networks",
        &token,
        r#"{"kind":"irc","name":"private","addr":"irc.example:6697","tls":true,"nick":"alice_","username":"alice_","realname":"Alice","autojoin":[],"server_password":"open sesame"}"#,
    )
    .await;
    assert_eq!(
        status, 409,
        "must refuse to store a server password unsealed"
    );

    let remove = r#"{"addr":"up.example:6697","tls":true,"nick":"alice_","username":"alice_","realname":"Alice","autojoin":[],"credentials":{"action":"remove"},"server_password":{"action":"keep"}}"#;
    let remove_req = format!(
        "PUT /api/v1/me/networks/stored-secret HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{remove}",
        remove.len()
    );
    let (status, _, body) = request(http, &remove_req).await;
    assert_eq!(
        status, 204,
        "removing an unreadable stored credential must recover the network: {body}"
    );
    let detail_req = format!(
        "GET /api/v1/me/networks/stored-secret HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, body) = request(http, &detail_req).await;
    assert_eq!(status, 200, "{body}");
    let detail: serde_json::Value = serde_json::from_str(&body).expect("network detail");
    assert_eq!(detail["has_sasl_account"], false, "{body}");
    assert_eq!(detail["has_sasl_password"], false, "{body}");
}

/// A private upstream that registers only a connection whose first line is
/// `PASS :<one of accepted>`, answering 464 otherwise.
async fn private_upstream(accepted: &'static [&'static str]) -> std::net::SocketAddr {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.expect("accept");
            tokio::spawn(async move {
                let (reader, mut writer) = socket.into_split();
                let mut lines = tokio::io::BufReader::new(reader).lines();
                let Ok(Some(first)) = lines.next_line().await else {
                    return;
                };
                let admitted = first
                    .strip_prefix("PASS :")
                    .is_some_and(|password| accepted.contains(&password));
                if !admitted {
                    writer
                        .write_all(b":up 464 * :Password incorrect\r\n")
                        .await
                        .ok();
                    while let Ok(Some(_)) = lines.next_line().await {}
                    return;
                }
                while let Ok(Some(line)) = lines.next_line().await {
                    let reply = if line == "CAP LS 302" {
                        ":up CAP * LS :".to_owned()
                    } else if let Some(nick) = line.strip_prefix("NICK ") {
                        format!(":up 001 {nick} :welcome")
                    } else if let Some(token) = line.strip_prefix("PING ") {
                        format!(":up PONG up {token}")
                    } else {
                        continue;
                    };
                    if writer
                        .write_all(format!("{reply}\r\n").as_bytes())
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// The server password over the API: accepted on create and the connection
/// test, refused at its field when it cannot travel in one `PASS` line, stored
/// sealed under the owner's context, reported only as a flag, and changed on
/// replace only by an explicit action.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn a_server_password_is_sealed_write_only_and_replaced_only_by_an_action() {
    let url = support::test_db("server_password_is_sealed_write_only").await;
    let secret_key = e6ircd::secret::SecretKey::generate();
    let key_path = temporary_path("server-password-key");
    std::fs::write(&key_path, secret_key.to_base64()).expect("write test key");
    let _key_file = TemporaryFile(key_path.clone());
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "s3cr3t", None)
        .await
        .expect("acct");
    let token = issue_api_token(&pool, "alice", "test")
        .await
        .expect("token");
    let up = private_upstream(&["letmein-7f3a", "rotated-9c1e"]).await;
    let running = net::start(Config {
        server_name: "irc.pass.example".into(),
        network_name: "PassNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url: url.clone(),
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }),
        secrets: Some(SecretsConfig {
            key_file: key_path,
            previous_key_files: Vec::new(),
        }),
        internal_upstreams: e6ircd::egress::InternalUpstreams::Allow,
        ..Config::default()
    })
    .await
    .expect("start");
    let http = running.http_addr.expect("http bound");
    wait_http_ready(http).await;
    let identity = format!(
        r#""addr":"{up}","tls":false,"nick":"alice_","username":"alice_","realname":"Alice""#
    );
    let problem_field = |body: &str| -> serde_json::Value {
        serde_json::from_str::<serde_json::Value>(body).expect("problem JSON")["field"].clone()
    };

    // The connection test: refused at its field before dialing, rejected by
    // the upstream with its own code, and qualified by the right one.
    let over_long = format!(r#""{}""#, "x".repeat(505));
    for (password, status, expected) in [
        (r#""a\r\nQUIT""#, 400, "server_password"),
        (over_long.as_str(), 400, "server_password"),
        (r#""wrong""#, 502, "server_password_rejected"),
        (r#""letmein-7f3a""#, 200, "confirmed_nick"),
    ] {
        let (got, body) = post_json(
            http,
            "/api/v1/me/network-preflight",
            &token,
            &format!(r#"{{{identity},"server_password":{password}}}"#),
        )
        .await;
        assert_eq!(got, status, "{password}: {body}");
        if status == 400 {
            assert_eq!(problem_field(&body), expected, "{body}");
        } else {
            assert!(body.contains(expected), "{password}: {body}");
        }
    }
    let (status, body) = post_json(
        http,
        "/api/v1/me/network-preflight",
        &token,
        &format!("{{{identity}}}"),
    )
    .await;
    assert_eq!(status, 502, "{body}");
    assert!(body.contains("server_password_required"), "{body}");

    // Create: refused at its field, then stored sealed and shown as a flag.
    let create = |name: &str, password: &str| {
        format!(
            r#"{{"kind":"irc","name":"{name}",{identity},"autojoin":[],"server_password":{password}}}"#
        )
    };
    let (status, body) = post_json(
        http,
        "/api/v1/me/networks",
        &token,
        &create("bad", r#""a\u0000b""#),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(problem_field(&body), "server_password", "{body}");
    let (status, body) = post_json(
        http,
        "/api/v1/me/networks",
        &token,
        &create("private", r#""letmein-7f3a""#),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let context = e6ircd::bouncer::bnc_secret_context("alice");
    let stored = async || {
        e6ircd::db::get_bnc_network(&pool, "alice", "private")
            .await
            .expect("get")
            .expect("network")
            .server_password_sealed
    };
    let sealed = stored().await.expect("stored");
    assert!(e6ircd::secret::is_sealed(&sealed), "stored in the clear");
    assert_eq!(secret_key.open(&sealed, &context).unwrap(), "letmein-7f3a");
    let detail_req = format!(
        "GET /api/v1/me/networks/private HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, body) = request(http, &detail_req).await;
    assert_eq!(status, 200, "{body}");
    let detail: serde_json::Value = serde_json::from_str(&body).expect("detail");
    assert_eq!(detail["has_server_password"], true, "{body}");
    assert!(
        !body.contains("letmein-7f3a") && !body.contains(&sealed),
        "{body}"
    );
    // The driver sent it: the network connects.
    let connected = tokio::time::timeout(deadline::HANG, async {
        loop {
            let (_, _, body) = request(http, &detail_req).await;
            if body.contains(r#""connected":true"#) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(connected.is_ok(), "the driver never registered with PASS");

    // Replace: the action is required; keep keeps the ciphertext byte for
    // byte, set reseals, remove clears.
    let put = |server_password: &str| {
        let body = format!(
            r#"{{{identity},"autojoin":[],"credentials":{{"action":"keep"}}{server_password}}}"#
        );
        format!(
            "PUT /api/v1/me/networks/private HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    };
    let (status, _, body) = request(http, &put("")).await;
    assert_eq!(status, 400, "an omitted action is ambiguous: {body}");
    let (status, _, body) = request(http, &put(r#","server_password":{"action":"keep"}"#)).await;
    assert_eq!(status, 204, "{body}");
    assert_eq!(stored().await.as_deref(), Some(sealed.as_str()));
    let (status, _, body) = request(
        http,
        &put(r#","server_password":{"action":"set","password":"a\r\nb"}"#),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(problem_field(&body), "server_password", "{body}");
    let (status, _, body) = request(
        http,
        &put(r#","server_password":{"action":"set","password":"rotated-9c1e"}"#),
    )
    .await;
    assert_eq!(status, 204, "{body}");
    let resealed = stored().await.expect("stored");
    assert_ne!(resealed, sealed);
    assert_eq!(
        secret_key.open(&resealed, &context).unwrap(),
        "rotated-9c1e"
    );
    let (status, _, body) = request(http, &put(r#","server_password":{"action":"remove"}"#)).await;
    assert_eq!(status, 204, "{body}");
    assert_eq!(stored().await, None);
    let (_, _, body) = request(http, &detail_req).await;
    let detail: serde_json::Value = serde_json::from_str(&body).expect("detail");
    assert_eq!(detail["has_server_password"], false, "{body}");

    // The audit trail names the field, never the value.
    let details: Vec<String> = sqlx::query_scalar(
        "SELECT detail FROM audit_log WHERE action IN ('NETWORK_CREATE', 'NETWORK_UPDATE') ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("audit");
    assert!(details[0].contains("server_password"), "{details:?}");
    assert!(
        details
            .iter()
            .filter(|detail| detail.contains("changed: server_password"))
            .count()
            >= 2,
        "{details:?}"
    );
    assert!(
        details
            .iter()
            .all(|detail| !detail.contains("letmein") && !detail.contains("rotated")),
        "{details:?}"
    );
}

// ---- embedded web client (DESIGN §13.3) ---------------------------------

#[cfg(feature = "embed-web")]
#[tokio::test]
async fn web_shell_is_served_at_root_when_embedded() {
    let running = net::start(test_config()).await.expect("start");
    let http = running.http_addr.expect("http bound");
    let (status, head, body) = request(http, &get("/")).await;
    assert_eq!(status, 503);
    assert!(head.to_lowercase().contains("problem+json"), "{head}");
    assert!(body.contains("No database configured"), "{body}");
}

#[cfg(not(feature = "embed-web"))]
#[tokio::test]
async fn root_is_not_served_without_embed_web() {
    // Assets live on S3/CDN in this build; the binary serves only the API.
    let running = net::start(test_config()).await.expect("start");
    let http = running.http_addr.expect("http bound");
    let (status, _, _) = request(http, &get("/")).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn console_runtime_is_served_in_every_build() {
    let running = net::start(test_config()).await.expect("start");
    let http = running.http_addr.expect("http bound");
    let (status, headers, body) = request(http, &get("/console.js")).await;
    assert_eq!(status, 200, "{headers}");
    let headers = headers.to_ascii_lowercase();
    assert!(
        headers.contains("content-type: text/javascript; charset=utf-8"),
        "{headers}"
    );
    assert!(
        headers.contains("x-content-type-options: nosniff"),
        "{headers}"
    );
    assert!(body.contains("dataset.confirm"), "{body}");
    assert!(body.contains("data-console-confirm"), "{body}");
    assert!(body.contains("showModal"), "{body}");
    assert!(body.contains("data-api-network-operations"), "{body}");
    assert!(body.contains("data-api-network-create"), "{body}");
    assert!(body.contains("data-api-oper-create"), "{body}");
    assert!(body.contains("data-api-oidc-create"), "{body}");
    assert!(body.contains("data-api-configuration-patch"), "{body}");
    assert!(body.contains("data-api-ban-create"), "{body}");
    assert!(body.contains("data-api-session-page"), "{body}");
    assert!(body.contains("data-api-account-app-password"), "{body}");
    assert!(body.contains("data-api-channel-register"), "{body}");
    assert!(body.contains("/console-settings.js"), "{body}");
    assert!(body.contains("data-api-admin-account-create"), "{body}");
    // The console hands its session token to the shared contract module, which
    // is the only place the header is built.
    assert!(body.contains("csrf: form.querySelector"), "{body}");
    assert!(
        body.contains("/api/v1/admin/configuration/networks"),
        "{body}"
    );
    assert!(body.contains("/console-contract.js"), "{body}");

    let (status, headers, body) = request(http, &get("/console-contract.js")).await;
    assert_eq!(status, 200, "{headers}");
    assert!(body.contains("readApiJson"), "{body}");
    assert!(body.contains("X-E6IRC-CSRF"), "{body}");

    let (status, headers, body) = request(http, &get("/console-settings.js")).await;
    assert_eq!(status, 200, "{headers}");
    assert!(body.contains("loadSettings"), "{body}");
}

#[tokio::test]
async fn openapi_spec_is_served() {
    let running = net::start(test_config()).await.expect("start");
    let http = running.http_addr.expect("http bound");
    let (status, head, body) = request(http, &get("/api/v1/openapi.json")).await;
    assert_eq!(status, 200);
    assert!(head.to_lowercase().contains("application/json"), "{head}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON spec");
    assert_eq!(v["openapi"], "3.1.0");
    assert_eq!(
        v["paths"]["/api/v1/me/tokens/{id}"]["delete"]["parameters"],
        serde_json::json!([{
            "name": "id", "in": "path", "required": true,
            "schema": { "type": "integer", "minimum": 1 }
        }])
    );
    let identity_schema = &v["paths"]["/api/v1/me"]["get"]["responses"]["200"]["content"]["application/json"]
        ["schema"];
    assert_eq!(identity_schema["additionalProperties"], false);
    assert!(
        identity_schema["required"]
            .as_array()
            .is_some_and(|fields| fields.iter().any(|field| field == "account"))
    );
    assert_eq!(
        identity_schema["properties"]["logout_url"]["pattern"],
        "^/[^/]"
    );
    assert_eq!(
        identity_schema["properties"]
            .as_object()
            .map(|properties| properties.keys().cloned().collect::<Vec<_>>()),
        Some(vec![
            "account".into(),
            "csrf_token".into(),
            "email".into(),
            "logout_url".into(),
            "provider".into(),
            "release_revision".into(),
            "role".into(),
        ])
    );
    assert_eq!(
        identity_schema["properties"]["csrf_token"]["type"],
        "string"
    );
    let network_list_schema = &v["paths"]["/api/v1/me/networks"]["get"]["responses"]["200"]["content"]
        ["application/json"]["schema"];
    assert_eq!(network_list_schema["additionalProperties"], false);
    assert_eq!(
        network_list_schema["properties"]["networks"]["items"]["required"],
        serde_json::json!([
            "name",
            "kind",
            "addr",
            "tls",
            "nick",
            "username",
            "realname",
            "autojoin",
            "sasl_account",
            "has_sasl_account",
            "has_sasl_password",
            "has_server_password",
            "enabled",
            "connected",
            "runtime",
        ])
    );
    assert_eq!(
        network_list_schema["properties"]["networks"]["items"]["additionalProperties"],
        false
    );
    assert_eq!(
        network_list_schema["properties"]["networks"]["items"]["properties"]["runtime"]["oneOf"][1]
            ["properties"]["state"]["enum"],
        serde_json::json!([
            "connecting",
            "connected",
            "reconnecting",
            "authentication_failed",
            "registration_failed",
        ])
    );
    let create_network_schema = &v["paths"]["/api/v1/me/networks"]["post"]["requestBody"]["content"]
        ["application/json"]["schema"];
    let create_variants = create_network_schema["oneOf"]
        .as_array()
        .expect("network creation variants");
    assert_eq!(create_variants.len(), 4);
    for variant in create_variants {
        assert_eq!(variant["additionalProperties"], false);
    }
    assert_eq!(
        create_variants[0]["required"],
        serde_json::json!([
            "kind", "name", "addr", "tls", "nick", "username", "realname", "autojoin"
        ])
    );
    assert_eq!(create_variants[0]["properties"]["kind"]["const"], "irc");
    assert_eq!(create_variants[1]["properties"]["kind"]["const"], "matrix");
    assert_eq!(create_variants[2]["properties"]["kind"]["const"], "discord");
    assert_eq!(create_variants[3]["properties"]["kind"]["const"], "slack");
    let preflight_schema = &v["paths"]["/api/v1/me/network-preflight"]["post"]["requestBody"]["content"]
        ["application/json"]["schema"];
    assert_eq!(
        preflight_schema["required"],
        serde_json::json!(["addr", "tls", "nick", "username", "realname"])
    );
    assert_eq!(preflight_schema["properties"]["autojoin"]["type"], "array");
    let app_password_schema = &v["paths"]["/api/v1/auth/app-passwords"]["post"]["requestBody"]["content"]
        ["application/json"]["schema"];
    assert_eq!(app_password_schema["additionalProperties"], false);
    for (path, method) in [
        ("/api/v1/me/profile", "patch"),
        ("/api/v1/me/password", "put"),
        ("/api/v1/me/tokens", "post"),
        ("/api/v1/auth/device/token", "post"),
        ("/api/v1/auth/device/approve", "post"),
        ("/api/v1/admin/bans", "post"),
        ("/api/v1/admin/configuration", "patch"),
        ("/api/v1/admin/configuration/opers", "post"),
        ("/api/v1/admin/configuration/opers/{name}", "delete"),
        ("/api/v1/admin/configuration/oidc-providers", "post"),
        (
            "/api/v1/admin/configuration/oidc-providers/{name}",
            "delete",
        ),
        ("/api/v1/admin/configuration/networks", "post"),
        ("/api/v1/admin/configuration/networks/{name}", "delete"),
        ("/api/v1/admin/networks/{owner}/{name}", "patch"),
    ] {
        let schema =
            &v["paths"][path][method]["requestBody"]["content"]["application/json"]["schema"];
        let closed = schema["additionalProperties"] == false
            || schema["oneOf"].as_array().is_some_and(|variants| {
                !variants.is_empty()
                    && variants
                        .iter()
                        .all(|variant| variant["additionalProperties"] == false)
            });
        assert!(closed, "{method} {path}");
    }
    let patch_network_schema = &v["paths"]["/api/v1/me/networks/{name}"]["patch"]["requestBody"]["content"]
        ["application/json"]["schema"];
    assert_eq!(patch_network_schema["additionalProperties"], false);
    let managed_network_delete_schema = &v["paths"]["/api/v1/admin/configuration/networks/{name}"]
        ["delete"]["requestBody"]["content"]["application/json"]["schema"];
    assert_eq!(managed_network_delete_schema["additionalProperties"], false);
    assert_eq!(
        managed_network_delete_schema["required"],
        serde_json::json!(["revision", "owner"])
    );
    let scalar_settings_schema = &v["paths"]["/api/v1/admin/configuration"]["patch"]["requestBody"]
        ["content"]["application/json"]["schema"]["properties"]["settings"];
    assert_eq!(scalar_settings_schema["additionalProperties"], false);
    assert_eq!(
        scalar_settings_schema["required"],
        serde_json::json!([
            "server_name",
            "network_name",
            "description",
            "motd",
            "nicklen",
            "sendq",
            "core_queue",
            "core_workers",
            "max_hot_channels",
            "listeners",
            "registration",
            "limits",
            "observability",
            "storage",
            "bnc_addr",
            "bnc_tls",
            "public_url",
            "secure_cookies",
            "admin_accounts",
        ])
    );
    for field in ["registration", "limits", "observability", "storage"] {
        assert_eq!(
            scalar_settings_schema["properties"][field]["additionalProperties"], false,
            "{field}"
        );
    }
    let listener_schema = &scalar_settings_schema["properties"]["listeners"]["items"];
    assert_eq!(listener_schema["additionalProperties"], false);
    assert_eq!(listener_schema["required"], serde_json::json!(["addr"]));
    assert_eq!(
        listener_schema["properties"]["tls"]["oneOf"][0]["additionalProperties"],
        false
    );
    assert_eq!(
        scalar_settings_schema["properties"]["nicklen"]["maximum"],
        64
    );
    let limits_schema = &scalar_settings_schema["properties"]["limits"]["properties"];
    for field in [
        "max_connections_per_ip",
        "command_burst",
        "command_rate",
        "auth_rate_burst",
        "api_rate_burst",
        "administrator_api_rate_burst",
        "registration_burst",
    ] {
        assert_eq!(limits_schema[field]["minimum"], 1, "{field}");
    }
    let observability_schema = &scalar_settings_schema["properties"]["observability"]["properties"];
    assert_eq!(
        observability_schema["sample_interval_seconds"],
        serde_json::json!({ "type": "integer", "minimum": 5, "maximum": 300 })
    );
    assert_eq!(
        observability_schema["retention_hours"],
        serde_json::json!({ "type": "integer", "minimum": 1, "maximum": 2160 })
    );
    let storage_schema = &scalar_settings_schema["properties"]["storage"]["properties"];
    for field in ["history_retention_days", "audit_retention_days"] {
        assert_eq!(storage_schema[field]["minimum"], 1, "{field}");
        assert_eq!(storage_schema[field]["maximum"], 3650, "{field}");
    }
    let buffer_schema = &v["paths"]["/api/v1/me/networks/{name}/buffer"]["get"]["responses"]["200"]
        ["content"]["application/json"]["schema"];
    assert_eq!(buffer_schema["additionalProperties"], false);
    assert_eq!(buffer_schema["required"], serde_json::json!(["lines"]));
    assert_eq!(
        buffer_schema["properties"]["lines"]["items"]["type"],
        "string"
    );
    // Method/path completeness is enforced mechanically by the route catalog's
    // unit test. These assertions protect the richer request-schema contract
    // that cannot be inferred from an axum handler.
    assert!(
        v["paths"]["/api/v1/me/networks"]["post"].is_object(),
        "{body}"
    );
    assert!(
        v["paths"]["/api/v1/me/networks/{name}"]["get"].is_object(),
        "{body}"
    );
    assert!(
        v["paths"]["/api/v1/me/networks/{name}"]["put"].is_object(),
        "{body}"
    );
    assert!(v["paths"]["/api/v1/me/channels"]["get"].is_object());
    assert!(v["paths"]["/api/v1/me/channels/{name}"]["patch"].is_object());
    assert!(v["paths"]["/api/v1/me/channels/{name}/access/{account}"]["put"].is_object());
    assert_eq!(
        v["paths"]["/api/v1/me/channels/{name}"]["patch"]["requestBody"]["content"]
            ["application/json"]["schema"]["oneOf"]
            .as_array()
            .map(Vec::len),
        Some(4)
    );
    assert_eq!(
        v["paths"]["/api/v1/me/channels/{name}/access/{account}"]["put"]["requestBody"]["content"]
            ["application/json"]["schema"]["additionalProperties"],
        false
    );
    assert!(v["paths"]["/healthz"]["get"].is_object());
    assert!(v["paths"]["/readyz"]["get"].is_object());
    let observability_schema = &v["paths"]["/api/v1/admin/observability"]["get"]["responses"]["200"]
        ["content"]["application/json"]["schema"];
    assert_eq!(observability_schema["type"], "object");
    assert_eq!(observability_schema["additionalProperties"], false);
    assert_eq!(
        observability_schema["required"],
        serde_json::json!(["current", "history"])
    );
    let snapshot_schema = &observability_schema["properties"]["current"];
    assert_eq!(snapshot_schema["additionalProperties"], false);
    assert_eq!(snapshot_schema["properties"]["schema_version"]["const"], 4);
    assert_eq!(
        snapshot_schema["properties"]["database_pool"]["required"],
        serde_json::json!(["size", "idle", "max", "acquire_timeouts_total"])
    );
    assert_eq!(
        snapshot_schema["properties"]["queues"]["additionalProperties"]["properties"]["mode"]["enum"],
        serde_json::json!(["fifo", "lifo"])
    );
    assert_eq!(
        snapshot_schema["properties"]["queues"]["additionalProperties"]["properties"]["capacity"]["minimum"],
        1
    );
    let buffer = &v["paths"]["/api/v1/me/networks/{name}/buffer"]["get"]["responses"]["200"]["content"]
        ["application/json"]["schema"]["properties"]["lines"];
    assert_eq!(buffer["maxItems"], 1_000);
    assert_eq!(
        buffer["items"]["maxLength"],
        e6irc_proto::message::MAX_SERVER_FRAME_LEN
    );
    let runtime_failures = &v["paths"]["/api/v1/me/networks/{name}"]["get"]["responses"]["200"]["content"]
        ["application/json"]["schema"]["properties"]["runtime"]["oneOf"][1]["properties"]["recent_failures"];
    assert_eq!(
        runtime_failures["maxItems"],
        e6ircd::bouncer::NETWORK_FAILURE_HISTORY_LIMIT
    );
    let operation_runtime = &v["paths"]["/api/v1/me/networks/{name}/operations"]["get"]["responses"]
        ["200"]["content"]["application/json"]["schema"]["properties"]["runtime"];
    assert_eq!(
        operation_runtime,
        &v["paths"]["/api/v1/me/networks/{name}"]["get"]["responses"]["200"]["content"]["application/json"]
            ["schema"]["properties"]["runtime"]
    );
    assert!(v["paths"]["/api/v1/admin/monitoring"].is_null());
    assert!(v["paths"]["/api/v1/admin/metrics"]["get"].is_object());
    assert_eq!(
        v["paths"]["/api/v1/monitoring/observation"]["get"]["responses"]["200"]["content"]["application/json"]
            ["schema"]["properties"]["schema_version"]["const"],
        "e6qu.monitoring/v2"
    );
    assert!(
        v["paths"]["/api/v1/monitoring/observation"]["get"]["responses"]["200"]
            ["content"]["application/json"]["schema"]["properties"]
            .get("cost_estimate")
            .is_none()
    );
    let account_parameters = v["paths"]["/api/v1/admin/accounts"]["get"]["parameters"]
        .as_array()
        .expect("account-directory query parameters");
    for name in ["limit", "before_id", "name"] {
        assert!(
            account_parameters
                .iter()
                .any(|parameter| parameter["name"] == name),
            "OpenAPI account-directory query is missing {name}"
        );
    }
    let channel_parameters = v["paths"]["/api/v1/admin/channels"]["get"]["parameters"]
        .as_array()
        .expect("registered-channel query parameters");
    for name in ["limit", "before_id", "name", "founder"] {
        assert!(
            channel_parameters
                .iter()
                .any(|parameter| parameter["name"] == name),
            "OpenAPI registered-channel query is missing {name}"
        );
    }
    let ban_parameters = v["paths"]["/api/v1/admin/bans"]["get"]["parameters"]
        .as_array()
        .expect("server-ban query parameters");
    for name in ["limit", "before_id", "kind", "mask"] {
        assert!(
            ban_parameters
                .iter()
                .any(|parameter| parameter["name"] == name),
            "OpenAPI server-ban query is missing {name}"
        );
    }
    let audit_parameters = v["paths"]["/api/v1/admin/audit"]["get"]["parameters"]
        .as_array()
        .expect("audit query parameters");
    for name in ["limit", "before_id", "actor", "action", "target"] {
        assert!(
            audit_parameters
                .iter()
                .any(|parameter| parameter["name"] == name),
            "OpenAPI audit query is missing {name}"
        );
    }
    let admin_connection_parameters = v["paths"]["/api/v1/admin/connections"]["get"]["parameters"]
        .as_array()
        .expect("admin live-connection query parameters");
    for name in ["limit", "before_id", "nick", "account", "transport", "oper"] {
        assert!(
            admin_connection_parameters
                .iter()
                .any(|parameter| parameter["name"] == name),
            "OpenAPI admin live-connection query is missing {name}"
        );
    }
    let own_connection_parameters = v["paths"]["/api/v1/me/connections"]["get"]["parameters"]
        .as_array()
        .expect("owner live-connection query parameters");
    for name in ["limit", "before_id", "nick", "transport", "oper"] {
        assert!(
            own_connection_parameters
                .iter()
                .any(|parameter| parameter["name"] == name),
            "OpenAPI owner live-connection query is missing {name}"
        );
    }
    assert!(
        !own_connection_parameters
            .iter()
            .any(|parameter| parameter["name"] == "account"),
        "owner query must not advertise a cross-account filter"
    );
    for path in [
        "/api/v1/admin/connections/{id}",
        "/api/v1/me/connections/{id}",
    ] {
        let parameters = v["paths"][path]["delete"]["parameters"]
            .as_array()
            .expect("connection mutation parameters");
        for name in ["id", "reason"] {
            assert!(
                parameters.iter().any(|parameter| parameter["name"] == name),
                "OpenAPI {path} mutation is missing {name}"
            );
        }
    }
    assert!(v["paths"]["/api/v1/me/identities/{id}"]["delete"].is_object());
    assert!(v["paths"]["/api/v1/me/password"]["put"].is_object());
    assert!(v["paths"]["/api/v1/auth/oidc/backchannel-logout"]["post"].is_object());
    assert!(v["paths"]["/api/v1/auth/oidc/frontchannel-logout"]["get"].is_object());
    assert!(v["components"]["securitySchemes"]["bearer"].is_object());
    // Operations a bearer is refused from advertise only the browser session.
    let browser_only = serde_json::json!([
        { "browserSession": [] },
        { "secureBrowserSession": [] }
    ]);
    for (path, method) in [
        ("/api/v1/me/sessions", "delete"),
        ("/api/v1/me/profile", "patch"),
        ("/api/v1/me/account", "delete"),
        ("/api/v1/me/password", "put"),
        ("/api/v1/me/credentials", "post"),
        ("/api/v1/me/identities/{id}", "delete"),
        ("/api/v1/auth/oidc/{provider}/link", "get"),
        ("/api/v1/me/tokens", "post"),
        ("/api/v1/auth/device/approve", "post"),
    ] {
        assert_eq!(
            v["paths"][path][method]["security"], browser_only,
            "{method} {path}"
        );
    }
    // Every account-authenticated operation documents what admission answers.
    for status in ["401", "403", "429", "503"] {
        assert!(
            v["paths"]["/api/v1/me"]["get"]["responses"][status].is_object(),
            "GET /api/v1/me lacks {status}"
        );
        assert!(
            v["paths"]["/api/v1/admin/stats"]["get"]["responses"][status].is_object(),
            "GET /api/v1/admin/stats lacks {status}"
        );
    }
    assert_eq!(
        v["paths"]["/api/v1/me/password"]["put"]["responses"]["200"]["content"]["application/json"]
            ["schema"]["properties"]["detail"]["const"],
        "Other browser sessions were signed out; app passwords and access tokens are unchanged — revoke them below if you suspect them."
    );
    assert!(v["paths"]["/api/v1/me/password"]["put"]["responses"]["204"].is_null());
    let callback_parameters =
        v["paths"]["/api/v1/auth/oidc/{provider}/callback"]["get"]["parameters"]
            .as_array()
            .expect("callback parameters");
    for name in ["code", "state", "error", "iss"] {
        assert!(
            callback_parameters
                .iter()
                .any(|parameter| parameter["name"] == name),
            "OpenAPI OIDC callback query is missing {name}"
        );
    }
    for status in ["307", "400", "401", "403", "409", "502", "503"] {
        assert!(
            v["paths"]["/api/v1/auth/oidc/{provider}/callback"]["get"]["responses"][status]
                .is_object(),
            "OIDC callback lacks {status}"
        );
    }
    for path in [
        "/api/v1/auth/oidc/{provider}/start",
        "/api/v1/auth/oidc/{provider}/sso",
        "/api/v1/auth/oidc/{provider}/link",
    ] {
        let responses = &v["paths"][path]["get"]["responses"];
        assert!(responses["502"].is_object(), "{path} lacks 502");
        assert!(responses["429"].is_object(), "{path} lacks 429");
    }
    for path in [
        "/api/v1/auth/oidc/{provider}/start",
        "/api/v1/auth/oidc/{provider}/sso",
    ] {
        assert!(
            v["paths"][path]["get"]["responses"]["503"].is_null(),
            "{path}: no server-held login capacity exists to run out of"
        );
    }
    assert!(
        v["paths"]["/api/v1/auth/oidc/{provider}/link"]["get"]["parameters"]
            .as_array()
            .expect("link parameters")
            .iter()
            .any(|parameter| parameter["name"] == "csrf" && parameter["required"] == true),
        "linking documents its required CSRF query value"
    );
    assert_eq!(
        v["paths"]["/api/v1/me/networks/{name}/buffer"]["get"]["parameters"][1]["schema"]["default"],
        200
    );
    assert_eq!(
        v["paths"]["/api/v1/admin/channels"]["get"]["responses"]["200"]["content"]["application/json"]
            ["schema"]["properties"]["channels"]["items"]["properties"]["policy"]["properties"]["topic_retained"]
            ["type"],
        "boolean"
    );
    assert_eq!(
        v["paths"]["/api/v1/admin/configuration/networks"]["post"]["requestBody"]["content"]["application/json"]
            ["schema"]["oneOf"][0]["required"],
        serde_json::json!([
            "kind",
            "revision",
            "name",
            "addr",
            "tls",
            "nick",
            "username",
            "realname",
            "autojoin",
            "buffer_cap"
        ])
    );
    assert_eq!(
        v["paths"]["/api/v1/admin/configuration/oidc-providers"]["post"]["requestBody"]["content"]
            ["application/json"]["schema"]["properties"]["end_session_endpoint"]["type"],
        serde_json::json!(["string", "null"])
    );
    assert_eq!(
        v["paths"]["/api/v1/auth/app-passwords"]["post"]["requestBody"]["content"]["application/json"]
            ["schema"]["properties"]["label"]["minLength"],
        1
    );
}

// ---- server-rendered pages (askama) -------------------------------------

#[tokio::test]
async fn login_page_renders() {
    let running = net::start(test_config()).await.expect("start");
    let http = running.http_addr.expect("http bound");
    let (status, head, body) = request(http, &get("/login")).await;
    assert_eq!(status, 200);
    assert!(head.to_lowercase().contains("text/html"), "{head}");
    assert!(body.contains("<title>e6irc — sign in</title>"), "{body}");
    // Neither PostgreSQL nor an OIDC provider is configured in the bare test
    // config, so the page says explicitly that authentication is unavailable.
    assert!(body.contains("No login methods"), "{body}");
    assert!(!body.contains("name=\"password\""), "{body}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn local_login_is_browser_bound_and_accepts_only_the_primary_password() {
    let url =
        support::test_db("local_login_is_browser_bound_and_accepts_only_the_primary_password")
            .await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "Alice", "primary", None)
        .await
        .expect("account");
    let app_password = e6ircd::db::issue_app_password(&pool, "Alice", "primary", "client")
        .await
        .expect("app password");

    let config = Config {
        server_name: "irc.login.example".into(),
        network_name: "LoginNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");

    let (status, headers, body) = request(http, &get("/login")).await;
    assert_eq!(status, 200, "{headers}");
    assert!(body.contains("action=\"/login\""), "{body}");
    assert!(headers.contains("e6irc_login_state="), "{headers}");
    assert!(headers.contains("SameSite=Strict"), "{headers}");
    let state = login_state_from_html(&body).to_string();

    let unbound = format!("login_state={state}&account=Alice&password=primary");
    let req = format!(
        "POST /login HTTP/1.1\r\nHost: t\r\nContent-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{unbound}",
        unbound.len()
    );
    let (status, _, body) = request(http, &req).await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("form expired"), "{body}");

    let (_, _, body) = request(http, &get("/login")).await;
    let state = login_state_from_html(&body);
    let app_attempt = format!(
        "login_state={state}&account=Alice&password={}",
        form_value(&app_password)
    );
    let req = format!(
        "POST /login HTTP/1.1\r\nHost: t\r\nCookie: e6irc_login_state={state}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{app_attempt}",
        app_attempt.len()
    );
    let (status, _, body) = request(http, &req).await;
    assert_eq!(status, 401, "{body}");
    assert!(body.contains("Invalid account or password"), "{body}");

    let (_, _, body) = request(http, &get("/login")).await;
    let state = login_state_from_html(&body);
    let valid = format!("login_state={state}&account=aLiCe&password=primary");
    let req = format!(
        "POST /login HTTP/1.1\r\nHost: t\r\nCookie: e6irc_login_state={state}\r\n\
         User-Agent: e6irc test browser\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{valid}",
        valid.len()
    );
    let (status, headers, _) = request(http, &req).await;
    assert_eq!(status, 303, "{headers}");
    assert!(headers.contains("location: /"), "{headers}");
    assert!(headers.contains("e6irc_session="), "{headers}");
    assert!(headers.contains("e6irc_login_state=;"), "{headers}");
    let session_token = headers
        .lines()
        .find_map(|line| line.strip_prefix("set-cookie: e6irc_session="))
        .and_then(|value| value.split(';').next())
        .expect("session cookie");
    let sessions = e6ircd::db::list_web_sessions(&pool, "Alice", Some(session_token))
        .await
        .expect("browser session inventory");
    assert_eq!(sessions.len(), 1);
    assert!(sessions[0].current);
    assert_eq!(
        sessions[0].user_agent.as_deref(),
        Some("e6irc test browser")
    );
}

/// Without a database no browser can be signed in, and `/login` could not sign
/// one in either: the page says so instead of bouncing the visitor into a form
/// that cannot work. (The redirect for a visitor with no session, on a server
/// that has a database, is covered by
/// `console_pages_are_cookie_only_and_report_their_refusals`.)
#[tokio::test]
async fn account_page_reports_a_missing_database_instead_of_redirecting() {
    let running = net::start(test_config()).await.expect("start");
    let http = running.http_addr.expect("http bound");
    let (status, head, body) = request(http, &get("/account")).await;
    assert_eq!(status, 503, "{body}");
    assert!(
        head.to_lowercase().contains("application/problem+json"),
        "{head}"
    );
    assert!(body.contains("No database configured"), "{body}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn account_url_redirects_to_the_complete_account_console() {
    let url = support::test_db("account_url_redirects_to_the_complete_account_console").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("acct");
    let session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("session");
    drop(pool);

    let config = Config {
        server_name: "irc.acct.example".into(),
        network_name: "AcctNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let http = running.http_addr.expect("http bound");

    let old_url = format!(
        "GET /account HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, head, _) = request(http, &old_url).await;
    assert_eq!(status, 303, "{head}");
    assert!(
        head.to_ascii_lowercase()
            .contains("location: /console/account"),
        "{head}"
    );

    let console = format!(
        "GET /console/account HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, head, body) = request(http, &console).await;
    assert_eq!(status, 200, "{head}");
    assert!(body.contains("Account &amp; access"), "{body}");
    assert!(body.contains("<strong>alice</strong>"), "{body}");
    assert!(body.contains("IRC credentials"), "{body}");
    assert!(body.contains("Personal access tokens"), "{body}");
    assert!(body.contains("Login identities"), "{body}");
    assert!(body.contains("Read state"), "{body}");
    assert!(body.contains("src=\"/console.js\""), "{body}");
    assert!(body.contains("data-console-theme"), "{body}");
    assert!(
        body.contains("href=\"#console-main\">Skip to main content"),
        "{body}"
    );
    assert!(
        body.contains("<main id=\"console-main\" tabindex=\"-1\">"),
        "{body}"
    );
    assert!(
        body.contains("href=\"/console/account\" class=\"active\" aria-current=\"page\""),
        "{body}"
    );
    assert!(
        !body.contains("data-console-theme-result role="),
        "the theme announcement must not create a second status landmark: {body}"
    );
    assert!(body.contains("data-console-confirm"), "{body}");
    // The console's styles live in its one stylesheet: the page carries
    // `style-src 'self'`, which admits no inline style.
    assert!(body.contains("href=\"/console.css\""), "{body}");
    assert!(!body.contains("<style"), "{body}");
    assert!(
        head.to_ascii_lowercase().contains(
            "content-security-policy: default-src 'none'; script-src 'self'; style-src 'self';"
        ),
        "{head}"
    );
    let (status, css_head, css) = request(http, &get("/console.css")).await;
    assert_eq!(status, 200, "{css_head}");
    assert!(
        css_head
            .to_ascii_lowercase()
            .contains("content-type: text/css; charset=utf-8"),
        "{css_head}"
    );
    assert!(
        css.contains("prefers-reduced-motion: no-preference"),
        "{css}"
    );
    assert!(css.contains("forced-colors: active"), "{css}");
    assert!(css.contains("danger-panel, .confirm-dialog"), "{css}");
}

/// The console BNC networks page lists the caller's own networks (with a live
/// status column) for any authenticated user, and redirects an anonymous
/// visitor to `/login`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn console_networks_page_lists_the_callers_networks() {
    let url = support::test_db("console_networks_page_lists_the_callers_networks").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("acct");
    e6ircd::db::create_bnc_network(
        &pool,
        "alice",
        &e6ircd::db::BncNetworkRow {
            kind: e6ircd::config::NetworkKind::Irc,
            name: "libera".into(),
            addr: "irc.libera.chat:6697".into(),
            tls: true,
            nick: "alice_".into(),
            username: Some("tester".into()),
            realname: Some("Alice".into()),
            autojoin: vec!["#e6irc".into()],
            sasl_account: None,
            sasl_password_sealed: None,
            enabled: true,
            server_password_sealed: None,
        },
        e6ircd::db::NetworkAudit {
            actor: "alice",
            detail: "",
        },
    )
    .await
    .expect("network");
    e6ircd::db::persist_bnc_line(
        &pool,
        &e6ircd::db::open_bnc_buffer(
            &pool,
            Some("alice"),
            "libera",
            e6ircd::db::BncNetworkDefinition::Configured,
        )
        .await
        .expect("open buffer"),
        Some("alice"),
        ":mallory PRIVMSG #e6irc :<script>alert('escaped')</script>",
    )
    .await
    .expect("seed hostile backlog line");
    let session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("session");
    drop(pool);

    let config = Config {
        server_name: "irc.console.example".into(),
        network_name: "ConsoleNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http bound");

    // Anonymous -> redirect to /login.
    let (status, head, _) = request(http, &get("/console/networks")).await;
    assert_eq!(status, 303, "{head}");
    assert!(head.to_lowercase().contains("location: /login"), "{head}");

    // Authenticated -> an API-backed console shell. The durable and live
    // network projection is owned by GET /api/v1/me/networks, never a parallel
    // rendered console fragment.
    let req = format!(
        "GET /console/networks HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, head, body) = request(http, &req).await;
    assert_eq!(status, 200, "{head}");
    for needle in [
        "e6irc console",
        "Your networks",
        "data-api-owner-network-list",
        "Loading configured networks…",
    ] {
        assert!(
            body.contains(needle),
            "console networks missing {needle:?}: {body}"
        );
    }
    assert!(
        !body.contains("/console/networks/rows"),
        "console networks retained a rendered-list read path: {body}"
    );
    let list_req = format!(
        "GET /api/v1/me/networks HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, list) = request(http, &list_req).await;
    assert_eq!(status, 200, "{list}");
    let list: serde_json::Value = serde_json::from_str(&list).expect("network API JSON");
    assert_eq!(list["networks"][0]["name"], "libera", "{list}");
    assert_eq!(
        list["networks"][0]["addr"], "irc.libera.chat:6697",
        "{list}"
    );
    let detail_req = format!(
        "GET /console/networks/libera HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, detail) = request(http, &detail_req).await;
    assert_eq!(status, 200, "{detail}");
    for needle in [
        "data-api-owner-network-detail",
        "Loading network…",
        "Live connection diagnostics",
        "data-api-network-operations",
        "data-network-name=\"libera\"",
        "Loading network operations…",
    ] {
        assert!(
            detail.contains(needle),
            "network detail missing {needle:?}: {detail}"
        );
    }
    assert!(
        !detail.contains("/console/networks/libera/operations"),
        "{detail}"
    );
    for stored_value in ["irc.libera.chat:6697", "#e6irc", "Not set"] {
        assert!(
            !detail.contains(stored_value),
            "network detail retained the stored database projection {stored_value:?}: {detail}"
        );
    }
    // The network's settings have one editor — the chat client's dialog — and
    // the stored log is read on this page, so neither has a console page of
    // its own any more.
    for gone in [
        "/console/networks/libera/edit",
        "/console/networks/libera/logs",
    ] {
        let request_line = format!(
            "GET {gone} HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
        );
        let (status, _, body) = request(http, &request_line).await;
        assert_eq!(status, 404, "{gone} is still served: {body}");
    }
    let operations_req = format!(
        "GET /api/v1/me/networks/libera/operations HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, headers, operations) = request(http, &operations_req).await;
    assert_eq!(status, 200, "{operations}");
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("cache-control: no-store"),
        "{headers}"
    );
    let operations: serde_json::Value =
        serde_json::from_str(&operations).expect("network operations JSON");
    assert_eq!(operations["enabled"], true, "{operations}");
    assert!(operations["runtime"]["state"].is_string(), "{operations}");
    assert_eq!(operations["storage"]["lines"], 1, "{operations}");
    assert!(operations.get("errors").is_none(), "{operations}");
    assert_eq!(
        operations["recent_lines"][0],
        ":mallory PRIVMSG #e6irc :<script>alert('escaped')</script>"
    );
}

/// The console networks page can add and remove a network with standard forms even before
/// the raw attach listener is enabled. Network management depends on the
/// database-backed registry, not on an unrelated startup listener flag.

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn console_configuration_enables_and_persists_bnc_listener() {
    let url = support::test_db("console_configuration_enables_and_persists_bnc_listener").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("account");
    let session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("session");
    drop(pool);

    let config = Config {
        server_name: "irc.control.example".into(),
        network_name: "ControlNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec!["alice".into()],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url: url.clone(),
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    assert!(running.bnc_addr.is_none(), "bootstrap listener is off");
    let http = running.http_addr.expect("http");
    let get_page = format!(
        "GET /console/configuration HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, page) = request(http, &get_page).await;
    assert_eq!(status, 200, "{page}");
    assert!(page.contains("Configuration"), "{page}");
    assert!(page.contains("data-api-configuration-read"), "{page}");
    assert!(page.contains("Loading…"), "{page}");
    assert!(
        !page.contains("value=\"irc.control.example\""),
        "configuration state must come from the API, not the console document: {page}"
    );
    assert!(page.contains("Monitoring history"), "{page}");
    let csrf = page
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("CSRF token");

    let monitoring = format!(
        "GET /console/monitoring HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, monitoring_page) = request(http, &monitoring).await;
    assert_eq!(status, 200, "{monitoring_page}");
    for needle in [
        "data-api-admin-monitoring",
        "data-minutes=\"60\"",
        "data-refresh-seconds=\"10\"",
        "Loading monitoring data…",
    ] {
        assert!(
            monitoring_page.contains(needle),
            "monitoring console missing {needle:?}: {monitoring_page}"
        );
    }

    let six_hour_monitoring = format!(
        "GET /console/monitoring?minutes=360 HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, six_hour_page) = request(http, &six_hour_monitoring).await;
    assert_eq!(status, 200, "{six_hour_page}");
    assert!(
        six_hour_page.contains("data-minutes=\"360\""),
        "{six_hour_page}"
    );
    assert!(six_hour_page.contains("6 hours"), "{six_hour_page}");
    assert!(
        !monitoring_page.contains("/console/monitoring/panel"),
        "{monitoring_page}"
    );

    let logs = format!(
        "GET /console/logs HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, logs_page) = request(http, &logs).await;
    assert_eq!(status, 200, "{logs_page}");
    for needle in [
        "data-api-server-log",
        "data-refresh-seconds=\"5\"",
        "Loading live logs…",
        "Live logs",
    ] {
        assert!(
            logs_page.contains(needle),
            "live logs console missing {needle:?}: {logs_page}"
        );
    }

    let logs_api = format!(
        "GET /api/v1/admin/logs HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, logs_headers, body) = request(http, &logs_api).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        logs_headers
            .to_ascii_lowercase()
            .contains("cache-control: no-store")
    );
    let logs: serde_json::Value = serde_json::from_str(&body).expect("logs JSON");
    assert!(logs["entries"].is_array(), "{logs}");

    let invalid_monitoring = format!(
        "GET /console/monitoring?minutes=17 HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, body) = request(http, &invalid_monitoring).await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("Invalid monitoring window"), "{body}");

    let observability = format!(
        "GET /api/v1/admin/observability?minutes=60 HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, observability_headers, body) = request(http, &observability).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        observability_headers
            .to_ascii_lowercase()
            .contains("cache-control: no-store"),
        "{observability_headers}"
    );
    let body: serde_json::Value = serde_json::from_str(&body).expect("observability JSON");
    assert!(body["current"]["active_connections"].is_u64());
    assert!(body["current"]["core_latency"]["p95_us"].is_u64());
    assert!(body["current"]["queues"]["core-0"]["depth"].is_u64());
    assert_eq!(body["current"]["queues"]["core-0"]["capacity"], 65_536);
    assert_eq!(body["current"]["queues"]["db"]["capacity"], 1_024);
    assert_eq!(body["current"]["queues"]["core-0"]["mode"], "fifo");
    assert!(body["history"].is_array());
    let removed_monitoring_api = format!(
        "GET /api/v1/admin/monitoring?minutes=60 HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, removed_monitoring_body) = request(http, &removed_monitoring_api).await;
    assert_eq!(status, 404, "{removed_monitoring_body}");

    let invalid_observability = format!(
        "GET /api/v1/admin/observability?minutes=10081 HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, invalid_body) = request(http, &invalid_observability).await;
    assert_eq!(status, 400, "{invalid_body}");
    assert!(
        invalid_body.contains("Invalid monitoring range"),
        "{invalid_body}"
    );
    let mut old_snapshot = body["current"].clone();
    let old_sampled_at = old_snapshot["sampled_at_ms"]
        .as_u64()
        .expect("sample timestamp")
        .saturating_sub(2 * 60 * 60 * 1_000);
    old_snapshot["sampled_at_ms"] = old_sampled_at.into();
    let verification_pool = sqlx::PgPool::connect(&url)
        .await
        .expect("verification pool");
    sqlx::query("INSERT INTO observability_samples (sampled_at_ms, snapshot) VALUES ($1, $2)")
        .bind(i64::try_from(old_sampled_at).unwrap())
        .bind(old_snapshot)
        .execute(&verification_pool)
        .await
        .expect("seed expired monitoring sample");

    let metrics = format!(
        "GET /api/v1/admin/metrics HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, headers, body) = request(http, &metrics).await;
    assert_eq!(status, 200, "{body}");
    assert!(headers.contains("text/plain; version=0.0.4"), "{headers}");
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("cache-control: no-store"),
        "{headers}"
    );
    assert!(body.contains("e6irc_connections{state=\"registered\"}"));
    assert!(body.contains("e6irc_core_latency_seconds_bucket"));
    assert!(body.contains("e6irc_queue_depth{queue=\"core-0\"}"));
    assert!(body.contains("e6irc_queue_capacity{queue=\"db\"} 1024"));
    assert!(body.contains("e6irc_queue_mode{queue=\"core-0\",mode=\"fifo\"} 1"));

    let configuration = format!(
        "GET /api/v1/admin/configuration HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, body) = request(http, &configuration).await;
    assert_eq!(status, 200, "{body}");
    let current: serde_json::Value = serde_json::from_str(&body).expect("configuration JSON");
    assert_eq!(
        current["runtime"]["http_bind"].as_str(),
        Some("127.0.0.1:0")
    );
    assert!(current["runtime"]["network_drivers"].is_array());
    assert!(
        current["runtime"]["network_drivers"]
            .as_array()
            .is_some_and(|drivers| drivers.contains(&serde_json::json!("irc")))
    );
    // The obvious way to change one setting, and the only way a script can:
    // read the resource, change a field, send it back. The credential
    // collections it carries are managed elsewhere, but echoing them exactly
    // as read must not be refused -- it was, so a read-modify-write could not
    // work at all.
    let mut round_trip = current["settings"].clone();
    round_trip["description"] = serde_json::Value::String("round trip".into());
    let round_trip_body =
        serde_json::json!({ "revision": current["revision"], "settings": round_trip }).to_string();
    let round_trip_request = format!(
        "PATCH /api/v1/admin/configuration HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-E6IRC-CSRF: {csrf}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{round_trip_body}",
        round_trip_body.len()
    );
    let (status, _, body) = request(http, &round_trip_request).await;
    assert_eq!(status, 200, "a faithful round-trip was refused: {body}");
    let revision_after_round_trip = serde_json::from_str::<serde_json::Value>(&body)
        .expect("patch JSON")["revision"]
        .as_i64()
        .expect("revision");

    // Changing one of those collections here is refused by name, with the
    // endpoint that does change it -- never silently dropped.
    let mut forged = current["settings"].clone();
    forged["opers"] = serde_json::json!([{ "name": "sneaky", "password": "x" }]);
    let forged_body =
        serde_json::json!({ "revision": revision_after_round_trip, "settings": forged })
            .to_string();
    let forged_request = format!(
        "PATCH /api/v1/admin/configuration HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-E6IRC-CSRF: {csrf}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{forged_body}",
        forged_body.len()
    );
    let (status, _, body) = request(http, &forged_request).await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body.contains("/api/v1/admin/configuration/opers"),
        "the refusal names the endpoint that changes it: {body}"
    );

    let mut settings = current["settings"].clone();
    settings["description"] = serde_json::Value::String("round trip".into());
    let settings_object = settings.as_object_mut().expect("settings object");
    settings_object.remove("oidc_providers");
    settings_object.remove("opers");
    settings_object.remove("networks");
    settings_object.remove("credentials_from_bootstrap");
    settings_object["bnc_addr"] = serde_json::Value::String("127.0.0.1:0".into());
    settings_object["observability"]["enabled"] = serde_json::Value::Bool(true);
    settings_object["observability"]["sample_interval_seconds"] = 5.into();
    settings_object["observability"]["retention_hours"] = 1.into();
    let patch_body =
        serde_json::json!({ "revision": revision_after_round_trip, "settings": settings })
            .to_string();
    let patch = format!(
        "PATCH /api/v1/admin/configuration HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-E6IRC-CSRF: {csrf}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{patch_body}",
        patch_body.len()
    );
    let (status, _, body) = request(http, &patch).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["revision"],
        revision_after_round_trip + 1
    );
    // An attach listener off loopback without a certificate would take account
    // passwords in cleartext: the save is refused, naming the setting.
    let mut cleartext = settings.clone();
    cleartext["bnc_addr"] = serde_json::Value::String("0.0.0.0:0".into());
    cleartext["bnc_tls"] = serde_json::Value::Null;
    let cleartext_body =
        serde_json::json!({ "revision": revision_after_round_trip + 1, "settings": cleartext })
            .to_string();
    let (status, _, body) = request(
        http,
        &format!(
            "PATCH /api/v1/admin/configuration HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
             X-E6IRC-CSRF: {csrf}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{cleartext_body}",
            cleartext_body.len()
        ),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("bnc_tls"), "{body}");
    let mut stored_history = false;
    for _ in 0..14 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let (status, _, body) = request(http, &observability).await;
        assert_eq!(status, 200, "{body}");
        let body: serde_json::Value =
            serde_json::from_str(&body).expect("observability history JSON");
        if body["history"]
            .as_array()
            .is_some_and(|history| !history.is_empty())
        {
            stored_history = true;
            break;
        }
    }
    assert!(
        stored_history,
        "live sampler did not persist an observability sample"
    );
    // Pruning belongs to storage maintenance, not the sampler, so it happens
    // whether or not sampling is on: the sampler left the expired row alone,
    // and one maintenance batch under the configured hour of retention drops it.
    let expired_sample_count = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM observability_samples WHERE sampled_at_ms = $1",
        )
        .bind(i64::try_from(old_sampled_at).unwrap())
        .fetch_one(&verification_pool)
        .await
        .expect("expired sample count")
    };
    assert_eq!(
        expired_sample_count().await,
        1,
        "the sampler is not the pruner"
    );
    let report = e6ircd::db::run_storage_maintenance(
        &verification_pool,
        e6ircd::db::StorageRetention {
            history_days: 30,
            audit_days: 365,
            observability_hours: 1,
        },
    )
    .await
    .expect("maintenance");
    assert!(report.observability_samples >= 1, "{report:?}");
    assert_eq!(
        expired_sample_count().await,
        0,
        "maintenance did not prune expired history"
    );

    let (status, _, body) = request(http, &observability).await;
    assert_eq!(status, 200, "{body}");
    let current: serde_json::Value = serde_json::from_str::<serde_json::Value>(&body)
        .expect("current monitoring JSON")["current"]
        .clone();
    let until = current["sampled_at_ms"]
        .as_i64()
        .expect("current timestamp");
    sqlx::query(
        "INSERT INTO observability_samples (sampled_at_ms, snapshot)
         SELECT point, jsonb_set($1::jsonb, '{sampled_at_ms}', to_jsonb(point))
           FROM generate_series($2::bigint, $3::bigint, 3000) AS point
         ON CONFLICT (sampled_at_ms) DO NOTHING",
    )
    .bind(current)
    .bind(until - 60 * 60 * 1_000)
    .bind(until - 1)
    .execute(&verification_pool)
    .await
    .expect("seed dense monitoring history");
    let (status, _, body) = request(http, &observability).await;
    assert_eq!(status, 200, "{body}");
    let body: serde_json::Value =
        serde_json::from_str(&body).expect("downsampled observability JSON");
    let history = body["history"].as_array().expect("history array");
    assert!(
        (900..=1000).contains(&history.len()),
        "dense history was not evenly bounded: {} samples",
        history.len()
    );
    verification_pool.close().await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("reconnect");
    let snapshot = e6ircd::db::load_managed_config(&pool)
        .await
        .expect("settings");
    assert_eq!(snapshot.revision, revision_after_round_trip + 1);
    assert_eq!(
        snapshot.settings.bnc_addr,
        Some("127.0.0.1:0".parse().unwrap())
    );
    drop(pool);
    assert_eq!(
        running.shutdown.run().await,
        e6ircd::net::ShutdownOutcome::Flushed
    );
}

/// Every credential-bearing collection on the Configuration page crosses the
/// same real form → validation/sealing → revision/audit → PostgreSQL path.
/// This protects the controls that a scalar-only configuration test cannot
/// cover and proves that rendered responses never disclose submitted secrets.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn console_configuration_manages_every_credential_collection() {
    let url = support::test_db("console_configuration_manages_every_credential_collection").await;
    let secret_key = e6ircd::secret::SecretKey::generate();
    let key_path = temporary_path("managed-configuration-key");
    std::fs::write(&key_path, secret_key.to_base64()).expect("write test key");
    let _key_file = TemporaryFile(key_path.clone());

    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("account");
    let session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("session");
    drop(pool);

    let config = Config {
        server_name: "irc.collections.example".into(),
        network_name: "CollectionsNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: Some("http://irc.collections.example".into()),
            secure_cookies: false,
            admin_accounts: vec!["alice".into()],
            hsts_include_subdomains: false,
        }),
        database: Some(e6ircd::config::DatabaseConfig {
            url: url.clone(),
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        secrets: Some(SecretsConfig {
            key_file: key_path,
            previous_key_files: Vec::new(),
        }),
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let http = running.http_addr.expect("http");
    wait_http_ready(http).await;
    let page_request = format!(
        "GET /console/configuration HTTP/1.1\r\nHost: t\r\n\
         Cookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, page) = request(http, &page_request).await;
    assert_eq!(status, 200, "{page}");
    let csrf = csrf_from_html(&page).to_string();
    assert!(
        page.contains("data-api-network-create"),
        "server-network creation must go through the JSON API: {page}"
    );
    assert!(
        page.contains("data-api-configuration-read"),
        "configuration state must load through the JSON API: {page}"
    );
    assert!(
        page.contains("data-api-oper-create"),
        "operator creation must go through the JSON API: {page}"
    );
    assert!(
        page.contains("action=\"/api/v1/admin/configuration/opers\""),
        "operator creation must not target a rendered mutation handler: {page}"
    );
    assert!(
        page.contains("data-api-oidc-create"),
        "provider creation must go through the JSON API: {page}"
    );
    assert!(
        page.contains("action=\"/api/v1/admin/configuration/oidc-providers\""),
        "provider creation must not target a rendered mutation handler: {page}"
    );

    let oper_secret = "operator-password-must-not-render";
    let oper_body = format!(r#"{{"revision":1,"name":"netop","password":"{oper_secret}"}}"#);
    let oper_request = format!(
        "POST /api/v1/admin/configuration/opers HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-E6IRC-CSRF: {csrf}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{oper_body}",
        oper_body.len()
    );
    let (status, _, body) = request(http, &oper_request).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["revision"],
        2
    );
    assert!(!body.contains(oper_secret), "{body}");

    let missing_claim_body = r#"{"revision":2,"name":"incomplete","issuer_url":"https://id.example","client_id":"e6irc","client_secret":"secret","token_endpoint_auth_method":"client_secret_post"}"#;
    let missing_claim_request = format!(
        "POST /api/v1/admin/configuration/oidc-providers HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-E6IRC-CSRF: {csrf}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{missing_claim_body}",
        missing_claim_body.len()
    );
    let (status, _, body) = request(http, &missing_claim_request).await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("account_claim"), "{body}");

    let oidc_secret = "provider-secret-must-not-render";
    let oidc_body = format!(
        r#"{{"revision":2,"name":"workforce","issuer_url":"https://id.example","client_id":"e6irc","client_secret":"{oidc_secret}","account_claim":"email","scopes":["openid","profile"],"allowed_email_domains":[],"end_session_endpoint":"https://id.example/logout","token_endpoint_auth_method":"client_secret_post"}}"#
    );
    let oidc_request = format!(
        "POST /api/v1/admin/configuration/oidc-providers HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-E6IRC-CSRF: {csrf}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{oidc_body}",
        oidc_body.len()
    );
    let (status, _, body) = request(http, &oidc_request).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["revision"],
        3
    );
    assert!(!body.contains(oidc_secret), "{body}");

    let upstream_secret = "upstream-password-must-not-render";
    let network_body = format!(
        r##"{{"revision":3,"name":"staffnet","owner":"alice","kind":"irc","addr":"irc.example:6697","tls":true,"nick":"alice","username":"alice","realname":"Alice","autojoin":["#staff"],"buffer_cap":321,"sasl_account":"alice-login","sasl_password":"{upstream_secret}"}}"##
    );
    let network_request = format!(
        "POST /api/v1/admin/configuration/networks HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-E6IRC-CSRF: {csrf}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{network_body}",
        network_body.len()
    );
    let (status, _, body) = request(http, &network_request).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["revision"],
        4
    );
    assert!(!body.contains(upstream_secret), "{body}");

    for (revision, network_body, secret) in [
        (
            4,
            r#"{"revision":4,"name":"local","kind":"local","addr":"","tls":false,"nick":"alice","username":"alice","realname":"Alice","autojoin":[],"buffer_cap":321}"#,
            None,
        ),
        (
            5,
            r#"{"revision":5,"name":"matrix","kind":"matrix","addr":"https://matrix.example.test","tls":true,"nick":"@alice:example.test","autojoin":[],"buffer_cap":321,"sasl_password":"matrix-secret"}"#,
            Some("matrix-secret"),
        ),
        (
            6,
            r#"{"revision":6,"name":"discord","kind":"discord","addr":"","tls":true,"autojoin":[],"buffer_cap":321,"sasl_password":"discord-secret"}"#,
            Some("discord-secret"),
        ),
        (
            7,
            r#"{"revision":7,"name":"slack","kind":"slack","addr":"","tls":true,"autojoin":[],"buffer_cap":321,"sasl_account":"slack-account","sasl_password":"slack-secret"}"#,
            Some("slack-secret"),
        ),
    ] {
        let network_request = format!(
            "POST /api/v1/admin/configuration/networks HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
             X-E6IRC-CSRF: {csrf}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{network_body}",
            network_body.len()
        );
        let (status, _, body) = request(http, &network_request).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).unwrap()["revision"],
            revision + 1
        );
        if let Some(secret) = secret {
            assert!(!body.contains(secret), "{body}");
        }
    }

    let configuration_api = format!(
        "GET /api/v1/admin/configuration HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         Connection: close\r\n\r\n"
    );
    let (status, _, body) = request(http, &configuration_api).await;
    assert_eq!(status, 200, "{body}");
    assert!(!body.contains(oper_secret), "{body}");
    assert!(!body.contains(oidc_secret), "{body}");
    assert!(!body.contains(upstream_secret), "{body}");
    let api: serde_json::Value = serde_json::from_str(&body).expect("configuration JSON");
    assert_eq!(api["revision"], 8);
    assert_eq!(api["runtime"]["has_master_key"], true);
    assert_eq!(api["runtime"]["master_key_count"], 1);
    assert_eq!(api["settings"]["opers"][0]["password"], "");
    assert_eq!(api["settings"]["oidc_providers"][0]["client_secret"], "");
    assert_eq!(
        api["settings"]["oidc_providers"][0]["account_claim"],
        "email"
    );
    assert_eq!(
        api["settings"]["networks"].as_array().map(Vec::len),
        Some(5)
    );
    for network in api["settings"]["networks"].as_array().unwrap() {
        assert!(network["sasl_password"].is_null(), "{network}");
    }
    assert!(api["settings"]["credentials_from_bootstrap"].is_boolean());
    let mut scalar_settings = api["settings"].clone();
    let scalar = scalar_settings.as_object_mut().expect("settings object");
    scalar.remove("oidc_providers");
    scalar.remove("opers");
    scalar.remove("networks");
    scalar.remove("credentials_from_bootstrap");
    scalar.insert(
        "description".into(),
        serde_json::Value::String("API-managed description".into()),
    );
    let patch_body = serde_json::json!({ "revision": 8, "settings": scalar_settings }).to_string();
    let patch_request = format!(
        "PATCH /api/v1/admin/configuration HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-E6IRC-CSRF: {csrf}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{patch_body}",
        patch_body.len()
    );
    let (status, _, body) = request(http, &patch_request).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["revision"],
        9
    );

    let verification_pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("verification pool");
    let snapshot = e6ircd::db::load_managed_config(&verification_pool)
        .await
        .expect("managed configuration");
    assert_eq!(snapshot.revision, 9);
    assert_eq!(snapshot.settings.description, "API-managed description");
    assert_eq!(snapshot.updated_by, "alice");
    assert_eq!(snapshot.settings.opers.len(), 1);
    assert_eq!(
        secret_key
            .open(
                &snapshot.settings.opers[0].password,
                e6ircd::secret::CONFIG_CONTEXT,
            )
            .expect("open operator password"),
        oper_secret
    );
    assert_eq!(snapshot.settings.oidc_providers.len(), 1);
    assert_eq!(
        secret_key
            .open(
                &snapshot.settings.oidc_providers[0].client_secret,
                e6ircd::secret::CONFIG_CONTEXT,
            )
            .expect("open provider secret"),
        oidc_secret
    );
    assert_eq!(
        snapshot
            .settings
            .networks
            .iter()
            .map(|network| (network.name.as_str(), network.kind.as_db_str()))
            .collect::<Vec<_>>(),
        [
            ("staffnet", "irc"),
            ("local", "local"),
            ("matrix", "matrix"),
            ("discord", "discord"),
            ("slack", "slack"),
        ]
    );
    let stored_network = &snapshot.settings.networks[0];
    assert_eq!(stored_network.owner.as_deref(), Some("alice"));
    assert_eq!(stored_network.autojoin, ["#staff"]);
    assert_eq!(stored_network.buffer_cap, 321);
    assert_eq!(
        secret_key
            .open(
                stored_network
                    .sasl_password
                    .as_deref()
                    .expect("stored upstream password"),
                e6ircd::secret::CONFIG_CONTEXT,
            )
            .expect("open upstream password"),
        upstream_secret
    );
    for (name, password) in [
        ("matrix", "matrix-secret"),
        ("discord", "discord-secret"),
        ("slack", "slack-secret"),
    ] {
        let network = snapshot
            .settings
            .networks
            .iter()
            .find(|network| network.name == name)
            .expect("stored network");
        assert_eq!(
            secret_key
                .open(
                    network.sasl_password.as_deref().expect("stored password"),
                    e6ircd::secret::CONFIG_CONTEXT,
                )
                .expect("open stored password"),
            password
        );
    }
    let slack = snapshot
        .settings
        .networks
        .iter()
        .find(|network| network.name == "slack")
        .expect("stored Slack network");
    assert_eq!(
        secret_key
            .open(
                slack
                    .sasl_account
                    .as_deref()
                    .expect("stored Slack bot token"),
                e6ircd::secret::CONFIG_CONTEXT,
            )
            .expect("open stored Slack bot token"),
        "slack-account"
    );

    let audit_details: Vec<String> =
        sqlx::query_scalar("SELECT detail FROM audit_log WHERE action = 'CONFIG' ORDER BY id")
            .fetch_all(&verification_pool)
            .await
            .expect("configuration audit");
    assert_eq!(audit_details.len(), 8);
    assert!(audit_details[0].contains("added IRC operator netop"));
    assert!(audit_details[1].contains("added OpenID Connect provider workforce"));
    assert!(audit_details[2].contains("added server network staffnet"));
    for name in ["local", "matrix", "discord", "slack"] {
        assert!(
            audit_details
                .iter()
                .any(|detail| detail.contains(&format!("added server network {name}"))),
            "missing audit entry for {name}"
        );
    }
    for detail in &audit_details {
        assert!(!detail.contains(oper_secret), "{detail}");
        assert!(!detail.contains(oidc_secret), "{detail}");
        assert!(!detail.contains(upstream_secret), "{detail}");
    }

    let delete_oper_body = r#"{"revision":9}"#;
    let delete_oper = format!(
        "DELETE /api/v1/admin/configuration/opers/netop HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-E6IRC-CSRF: {csrf}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{delete_oper_body}",
        delete_oper_body.len()
    );
    let (status, _, body) = request(http, &delete_oper).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["revision"],
        10
    );

    let delete_oidc_body = r#"{"revision":10}"#;
    let delete_oidc = format!(
        "DELETE /api/v1/admin/configuration/oidc-providers/workforce HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-E6IRC-CSRF: {csrf}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{delete_oidc_body}",
        delete_oidc_body.len()
    );
    let (status, _, body) = request(http, &delete_oidc).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["revision"],
        11
    );
    let mut revision = 11;
    for (name, owner) in [
        ("staffnet", Some("alice")),
        ("local", None),
        ("matrix", None),
        ("discord", None),
        ("slack", None),
    ] {
        let delete_network_body =
            serde_json::json!({ "revision": revision, "owner": owner }).to_string();
        let delete_network = format!(
            "DELETE /api/v1/admin/configuration/networks/{name} HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
             X-E6IRC-CSRF: {csrf}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{delete_network_body}",
            delete_network_body.len()
        );
        let (status, _, body) = request(http, &delete_network).await;
        assert_eq!(status, 200, "{body}");
        revision += 1;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).unwrap()["revision"],
            revision
        );
    }
    let snapshot = e6ircd::db::load_managed_config(&verification_pool)
        .await
        .expect("managed configuration after deletes");
    assert_eq!(snapshot.revision, 16);
    assert!(snapshot.settings.opers.is_empty());
    assert!(snapshot.settings.oidc_providers.is_empty());
    assert!(snapshot.settings.networks.is_empty());
    verification_pool.close().await;

    assert_eq!(
        running.shutdown.run().await,
        e6ircd::net::ShutdownOutcome::Flushed
    );
}

/// Editing a network from the console: the pre-filled form, a successful field
/// update (persisted + reflected in the list), and the SSRF guard on a changed
/// address re-rendering with an error banner.

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn owned_channel_api_covers_configuration_access_transfer_and_drop() {
    let url =
        support::test_db("owned_channel_api_covers_configuration_access_transfer_and_drop").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    for account in ["boss", "alice", "mallory"] {
        e6ircd::db::create_account_with_contact(&pool, account, "pw", None)
            .await
            .expect("account");
    }
    let boss_token = issue_api_token(&pool, "boss", "test")
        .await
        .expect("boss token");
    let alice_token = issue_api_token(&pool, "alice", "test")
        .await
        .expect("alice token");
    let mallory_token = issue_api_token(&pool, "mallory", "test")
        .await
        .expect("mallory token");
    sqlx::query(
        "INSERT INTO channels (name, name_folded, founder_account_id)
         SELECT '#Control', '#control', id FROM accounts WHERE name_folded = 'boss'",
    )
    .execute(&pool)
    .await
    .expect("channel");
    drop(pool);

    let config = Config {
        server_name: "irc.channels.example".into(),
        network_name: "ChannelNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let http = running.http_addr.expect("http");

    let api = |method: &str, path: &str, token: &str, body: Option<&str>| {
        let body = body.unwrap_or("");
        format!(
            "{method} {path} HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    };

    let (status, _, body) =
        request(http, &api("GET", "/api/v1/me/channels", &boss_token, None)).await;
    assert_eq!(status, 200, "{body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("inventory");
    assert_eq!(json["channels"][0]["name"], "#Control");
    assert_eq!(json["channels"][0]["access"], serde_json::json!([]));

    let (status, _, body) = request(
        http,
        &api(
            "PATCH",
            "/api/v1/me/channels/%23Control",
            &mallory_token,
            Some(r#"{"action":"set_mlock","mlock":"+nt"}"#),
        ),
    )
    .await;
    assert_eq!(status, 404, "non-founder mutation leaked scope: {body}");

    let mut live_owner = e6irc_client::Connection::connect(&running.addrs[0].to_string())
        .await
        .expect("owner client");
    live_owner
        .register_sasl(
            &e6irc_client::Identity {
                nick: "boss-live",
                username: "boss-live",
                realname: "Boss",
                server_password: None,
            },
            "boss",
            "pw",
        )
        .await
        .expect("owner SASL");
    live_owner.send_line("JOIN #Api").await.expect("join");
    loop {
        let message = live_owner
            .next_message()
            .await
            .expect("join reply")
            .expect("join EOF");
        if message.command == "366" {
            break;
        }
    }
    let (status, _, body) = request(
        http,
        &api(
            "POST",
            "/api/v1/me/channels",
            &boss_token,
            Some(r##"{"name":"#Api"}"##),
        ),
    )
    .await;
    assert_eq!(status, 201, "owner API registration failed: {body}");
    let (status, _, body) = request(
        http,
        &api("GET", "/api/v1/me/channels/%23Api", &boss_token, None),
    )
    .await;
    assert_eq!(
        status, 200,
        "registered channel was not immediately readable: {body}"
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).expect("registered channel")["founder"],
        "boss"
    );

    for body in [r#"{"flags":""}"#, r#"{"flags":"oo"}"#] {
        let (status, _, response) = request(
            http,
            &api(
                "PUT",
                "/api/v1/me/channels/%23Control/access/alice",
                &boss_token,
                Some(body),
            ),
        )
        .await;
        assert_eq!(
            status, 400,
            "invalid PUT {body} became an access mutation: {response}"
        );
    }

    for (method, path, body) in [
        (
            "PUT",
            "/api/v1/me/channels/%23Control/access/alice",
            r#"{"flags":"vo"}"#,
        ),
        (
            "PATCH",
            "/api/v1/me/channels/%23Control",
            r#"{"action":"set_topic","topic":"Welcome"}"#,
        ),
        (
            "PATCH",
            "/api/v1/me/channels/%23Control",
            r#"{"action":"set_mlock","mlock":"+tn-i"}"#,
        ),
    ] {
        let (status, _, response) =
            request(http, &api(method, path, &boss_token, Some(body))).await;
        assert_eq!(status, 200, "{method} {path}: {response}");
    }
    let (status, _, body) = request(
        http,
        &api(
            "PATCH",
            "/api/v1/me/channels/%23Control",
            &boss_token,
            Some(r#"{"action":"set_keeptopic","enabled":false}"#),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, headers, body) = request(
        http,
        &api(
            "PATCH",
            "/api/v1/me/channels/%23Control",
            &boss_token,
            Some(r#"{"action":"set_topic","topic":"must fail"}"#),
        ),
    )
    .await;
    assert_eq!(status, 409, "{body}");
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("content-type: application/problem+json"),
        "{headers}"
    );

    let (status, _, body) = request(
        http,
        &api("GET", "/api/v1/me/channels/%23CONTROL", &boss_token, None),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("channel");
    assert_eq!(json["keeptopic"], false);
    assert_eq!(json["topic"], serde_json::Value::Null);
    assert_eq!(json["mlock"], "+nt-i");
    assert_eq!(json["access"][0]["account"], "alice");
    assert_eq!(json["access"][0]["flags"], "ov");

    let (status, _, body) = request(
        http,
        &api(
            "PATCH",
            "/api/v1/me/channels/%23Control",
            &boss_token,
            Some(r#"{"action":"transfer_founder","account":"alice"}"#),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (_, _, body) = request(http, &api("GET", "/api/v1/me/channels", &boss_token, None)).await;
    let inventory = serde_json::from_str::<serde_json::Value>(&body).unwrap();
    assert_eq!(inventory["channels"].as_array().map(Vec::len), Some(1));
    assert_eq!(inventory["channels"][0]["name"], "#Api");
    let (_, _, body) = request(http, &api("GET", "/api/v1/me/channels", &alice_token, None)).await;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["channels"][0]["founder"],
        "alice"
    );
    let (status, _, body) = request(
        http,
        &api(
            "DELETE",
            "/api/v1/me/channels/%23Control",
            &alice_token,
            None,
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, _, body) = request(
        http,
        &api("DELETE", "/api/v1/me/channels/%23Api", &boss_token, None),
    )
    .await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn owned_channel_api_and_console_shell_are_scoped_and_csrf_protected() {
    let url =
        support::test_db("owned_channel_api_and_console_shell_are_scoped_and_csrf_protected").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    for account in ["boss", "alice", "mallory"] {
        e6ircd::db::create_account_with_contact(&pool, account, "pw", None)
            .await
            .expect("account");
    }
    let boss_session = e6ircd::db::create_web_session(&pool, "boss", None)
        .await
        .expect("boss session");
    let mallory_session = e6ircd::db::create_web_session(&pool, "mallory", None)
        .await
        .expect("mallory session");
    sqlx::query(
        "INSERT INTO channels (name, name_folded, founder_account_id)
         SELECT '#Control', '#control', id FROM accounts WHERE name_folded = 'boss'",
    )
    .execute(&pool)
    .await
    .expect("channel");
    drop(pool);

    let config = Config {
        server_name: "irc.channel-console.example".into(),
        network_name: "ChannelConsoleNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let http = running.http_addr.expect("http");
    wait_http_ready(http).await;
    wait_irc_ready(running.addrs[0]).await;
    let page_request = |session: &str| {
        format!(
            "GET /console/channels HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
        )
    };

    let (status, _, page) = request(http, &page_request(&boss_session)).await;
    assert_eq!(status, 200, "{page}");
    for needle in [
        "Your channels",
        "data-api-owned-channel-list",
        "Loading registered channels",
    ] {
        assert!(page.contains(needle), "page missing {needle:?}: {page}");
    }
    assert!(
        !page.contains("#Control"),
        "channel data leaked into shell: {page}"
    );
    let csrf = csrf_from_html(&page).to_string();
    let (_, _, mallory_page) = request(http, &page_request(&mallory_session)).await;
    assert!(
        mallory_page.contains("data-api-owned-channel-list"),
        "{mallory_page}"
    );
    assert!(
        !mallory_page.contains("#Control"),
        "another account's channel leaked: {mallory_page}"
    );

    let api_request = |method: &str, path: &str, body: &str, csrf: Option<&str>| {
        let csrf_header =
            csrf.map_or_else(String::new, |token| format!("X-E6IRC-CSRF: {token}\r\n"));
        format!(
            "{method} {path} HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={boss_session}\r\n{csrf_header}\
             Content-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        )
    };
    let mut live_owner = e6irc_client::Connection::connect(&running.addrs[0].to_string())
        .await
        .expect("owner client");
    live_owner
        .register_sasl(
            &e6irc_client::Identity {
                nick: "boss-console",
                username: "boss-conso",
                realname: "Boss",
                server_password: None,
            },
            "boss",
            "pw",
        )
        .await
        .expect("owner SASL");
    live_owner.send_line("JOIN #Web").await.expect("join");
    loop {
        let message = live_owner
            .next_message()
            .await
            .expect("join reply")
            .expect("join EOF");
        if message.command == "366" {
            break;
        }
    }
    let register = r##"{"name":"#Web"}"##;
    let (status, headers, body) = request(
        http,
        &api_request("POST", "/api/v1/me/channels", register, Some(&csrf)),
    )
    .await;
    assert_eq!(status, 201, "{headers}\n{body}");

    let empty_access = r#"{"flags":""}"#;
    let (status, _, body) = request(
        http,
        &api_request(
            "PUT",
            "/api/v1/me/channels/%23Control/access/alice",
            empty_access,
            Some(&csrf),
        ),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body.contains("access flags must be one of o, v, ov, or vo"),
        "empty access grant was not rejected: {body}"
    );

    for (path, body) in [
        (
            "/api/v1/me/channels/%23Control",
            r#"{"action":"set_topic","topic":"Welcome operators"}"#,
        ),
        (
            "/api/v1/me/channels/%23Control",
            r#"{"action":"set_mlock","mlock":"+nt-i"}"#,
        ),
        (
            "/api/v1/me/channels/%23Control/access/alice",
            r#"{"flags":"ov"}"#,
        ),
    ] {
        let method = if path.ends_with("/alice") {
            "PUT"
        } else {
            "PATCH"
        };
        let (status, headers, body) =
            request(http, &api_request(method, path, body, Some(&csrf))).await;
        assert_eq!(status, 200, "{path}: {headers}\n{body}");
    }
    let (status, _, updated) = request(
        http,
        &format!(
            "GET /api/v1/me/channels/%23Control HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={boss_session}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_eq!(status, 200, "{updated}");
    let updated: serde_json::Value = serde_json::from_str(&updated).expect("channel API response");
    assert_eq!(updated["topic"], "Welcome operators");
    assert_eq!(updated["mlock"], "+nt-i");
    assert_eq!(updated["access"][0]["account"], "alice");
    assert_eq!(updated["access"][0]["flags"], "ov");
    let (_, _, shell) = request(http, &page_request(&boss_session)).await;
    assert!(
        !shell.contains("Welcome operators"),
        "channel state leaked into shell: {shell}"
    );

    let invalid = r#"{"action":"set_mlock","mlock":"+k"}"#;
    let (status, _, body) = request(
        http,
        &api_request(
            "PATCH",
            "/api/v1/me/channels/%23Control",
            invalid,
            Some(&csrf),
        ),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body.contains("not a lockable mode"),
        "invalid MLOCK was not rejected: {body}"
    );

    let (status, _, _) = request(
        http,
        &api_request(
            "DELETE",
            "/api/v1/me/channels/%23Control",
            "",
            Some("wrong"),
        ),
    )
    .await;
    assert_eq!(status, 403);

    let (status, _, body) = request(
        http,
        &api_request("DELETE", "/api/v1/me/channels/%23Control", "", Some(&csrf)),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, _, remaining) = request(
        http,
        &format!(
            "GET /api/v1/me/channels HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={boss_session}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_eq!(status, 200, "{remaining}");
    let remaining: serde_json::Value = serde_json::from_str(&remaining).expect("channel list");
    assert_eq!(remaining["channels"].as_array().map(Vec::len), Some(1));
    assert_eq!(remaining["channels"][0]["name"], "#Web");
    let (status, _, body) = request(
        http,
        &api_request("DELETE", "/api/v1/me/channels/%23Web", "", Some(&csrf)),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, _, empty) = request(
        http,
        &format!(
            "GET /api/v1/me/channels HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={boss_session}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_eq!(status, 200, "{empty}");
    let empty: serde_json::Value = serde_json::from_str(&empty).expect("empty channel list");
    assert_eq!(empty["channels"].as_array().map(Vec::len), Some(0));
}

// ---- admin API (PG-gated) -----------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn admin_accounts_endpoint_is_gated() {
    let url = support::test_db("admin_accounts_endpoint_is_gated").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("alice");
    e6ircd::db::create_account_with_contact(&pool, "bob", "pw", None)
        .await
        .expect("bob");
    let alice_token = issue_api_token(&pool, "alice", "t").await.expect("tok");
    let bob_token = issue_api_token(&pool, "bob", "t").await.expect("tok");
    // Seed data for the other admin read endpoints.
    add_server_ban(&pool, "spammer@*", "spammer@*", "spam", "alice", "kline")
        .await
        .expect("kline");
    e6ircd::db::insert_audit_log(&pool, "alice", "KLINE", "spammer@*", "spam")
        .await
        .expect("audit");
    sqlx::query(
        "INSERT INTO channels (name, name_folded, founder_account_id)
         SELECT '#lounge', '#lounge', id FROM accounts WHERE name_folded = 'alice'",
    )
    .execute(&pool)
    .await
    .expect("channel");

    let config = Config {
        server_name: "irc.admin.example".into(),
        network_name: "AdminNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec!["alice".into()],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");

    let getauth = |token: &str| {
        format!(
            "GET /api/v1/admin/accounts HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        )
    };
    // no auth -> 401
    let (status, _, _) = request(http, &get("/api/v1/admin/accounts")).await;
    assert_eq!(status, 401);
    // non-admin -> 403
    let (status, _, _) = request(http, &getauth(&bob_token)).await;
    assert_eq!(status, 403);
    // Authority is read from the account row on every request: a grant
    // written to the database behind the running server's back — as
    // `e6ircd recover-administrator` or another replica writes it — is
    // honoured by the very next request, and its revocation likewise.
    let bob_id = e6ircd::db::account_id_by_name(&pool, "bob")
        .await
        .expect("bob id")
        .expect("bob exists");
    e6ircd::db::set_account_administrator(&pool, bob_id, true, "alice", &["alice".into()])
        .await
        .expect("grant bob");
    let (status, _, body) = request(http, &getauth(&bob_token)).await;
    assert_eq!(status, 200, "a durable grant needs no restart: {body}");
    e6ircd::db::set_account_administrator(&pool, bob_id, false, "alice", &["alice".into()])
        .await
        .expect("revoke bob");
    let (status, _, _) = request(http, &getauth(&bob_token)).await;
    assert_eq!(status, 403, "a durable revocation needs no restart");
    drop(pool);
    // admin -> 200 + both accounts
    let (status, headers, body) = request(http, &getauth(&alice_token)).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("cache-control: no-store"),
        "{headers}"
    );
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let names: Vec<&str> = v["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"alice") && names.contains(&"bob"),
        "{names:?}"
    );

    // The other admin read endpoints are gated the same way and return
    // their seeded data.
    for (path, key) in [
        ("/api/v1/admin/channels", "channels"),
        ("/api/v1/admin/bans", "bans"),
        ("/api/v1/admin/audit", "audit"),
        ("/api/v1/admin/stats", "accounts"),
    ] {
        let auth = |token: &str| {
            format!(
                "GET {path} HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
            )
        };
        let (status, _, _) = request(http, &get(path)).await;
        assert_eq!(status, 401, "{path} unauthenticated");
        let (status, _, _) = request(http, &auth(&bob_token)).await;
        assert_eq!(status, 403, "{path} non-admin");
        let (status, headers, body) = request(http, &auth(&alice_token)).await;
        assert_eq!(status, 200, "{path}: {body}");
        assert!(
            headers
                .to_ascii_lowercase()
                .contains("cache-control: no-store"),
            "admin response is cacheable: {headers}"
        );
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        // Every admin read endpoint returns its keyed payload: a non-empty
        // array for the list endpoints, a present value for stats' counts.
        assert!(
            v[key].as_array().is_some_and(|a| !a.is_empty()) || v[key].is_number(),
            "{path} empty: {body}"
        );
    }

    // Collection limits are contracts, not suggestions: out-of-range windows
    // fail rather than being silently clamped to a different query.
    for (path, title) in [
        ("/api/v1/admin/accounts", "Invalid account-directory limit"),
        ("/api/v1/admin/channels", "Invalid registered-channel limit"),
        ("/api/v1/admin/bans", "Invalid server-ban limit"),
        ("/api/v1/admin/audit", "Invalid audit limit"),
    ] {
        for limit in [0, 1001] {
            let req = format!(
                "GET {path}?limit={limit} HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {alice_token}\r\nConnection: close\r\n\r\n"
            );
            let (status, headers, body) = request(http, &req).await;
            assert_eq!(status, 400, "{body}");
            assert!(
                headers
                    .to_ascii_lowercase()
                    .contains("content-type: application/problem+json"),
                "{headers}"
            );
            assert!(body.contains(title), "{body}");
        }
    }

    // Stats reflects the seeded data (2 accounts, 1 channel, 1 server ban).
    let stats_auth = format!(
        "GET /api/v1/admin/stats HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {alice_token}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, _) = request(http, &get("/api/v1/admin/stats")).await;
    assert_eq!(status, 401, "stats unauthenticated");
    let (status, _, body) = request(http, &stats_auth).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["accounts"], 2, "{body}");
    assert_eq!(v["registered_channels"], 1, "{body}");
    assert_eq!(v["server_bans"], 1, "{body}");
}

/// The admin `/console` page is gated exactly like the admin JSON API — an
/// anonymous visitor is redirected to `/login`, a signed-in non-admin gets 403,
/// and an admin gets a static dashboard shell whose data comes from the admin APIs.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn admin_console_page_is_api_hydrated_and_admin_only() {
    let url = support::test_db("admin_console_page_renders_server_data_for_admins_only").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("alice");
    e6ircd::db::create_account_with_contact(&pool, "bob", "pw", None)
        .await
        .expect("bob");
    let alice_session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("alice session");
    let bob_session = e6ircd::db::create_web_session(&pool, "bob", None)
        .await
        .expect("bob session");
    add_server_ban(&pool, "spammer@*", "spammer@*", "spam", "alice", "kline")
        .await
        .expect("kline");
    e6ircd::db::insert_audit_log(&pool, "alice", "KLINE", "spammer@*", "spam")
        .await
        .expect("audit");
    sqlx::query(
        "INSERT INTO channels (name, name_folded, founder_account_id)
         SELECT '#lounge', '#lounge', id FROM accounts WHERE name_folded = 'alice'",
    )
    .execute(&pool)
    .await
    .expect("channel");
    drop(pool);

    let config = Config {
        server_name: "irc.console.example".into(),
        network_name: "ConsoleNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec!["alice".into()],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");

    let page = |session: &str| {
        format!(
            "GET /console HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
        )
    };
    // Anonymous -> redirect to /login (a page, not a 401 like the JSON API).
    let (status, head, _) = request(http, &get("/console")).await;
    assert_eq!(status, 303, "{head}");
    assert!(head.to_lowercase().contains("location: /login"), "{head}");
    // Signed-in non-admin -> 403.
    let (status, _, _) = request(http, &page(&bob_session)).await;
    assert_eq!(status, 403);
    // Admin -> API-hydrated 200 shell; the seeded data must not be embedded.
    let (status, _, body) = request(http, &page(&alice_session)).await;
    assert_eq!(status, 200, "{body}");
    for needle in [
        "e6irc console",
        "data-api-admin-overview",
        "Loading overview…",
    ] {
        assert!(body.contains(needle), "console missing {needle:?}: {body}");
    }
    for needle in ["#lounge", "spammer@*", "KLINE"] {
        assert!(
            !body.contains(needle),
            "overview data must come from administrator APIs, not the shell: {body}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn account_directory_filters_pages_counts_and_escapes_for_admins_only() {
    let url =
        support::test_db("account_directory_filters_pages_counts_and_escapes_for_admins_only")
            .await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    for name in ["Alice", "Bob", "Carol"] {
        e6ircd::db::create_account_with_contact(&pool, name, "pw", None)
            .await
            .unwrap_or_else(|error| panic!("create {name}: {error}"));
    }
    sqlx::query(
        "INSERT INTO accounts (name, name_folded)
         VALUES ('Eve<script>alert(1)</script>', 'eve<script>alert(1)</script>')",
    )
    .execute(&pool)
    .await
    .expect("hostile display account");
    let alice_session = e6ircd::db::create_web_session(&pool, "Alice", None)
        .await
        .expect("alice session");
    let bob_session = e6ircd::db::create_web_session(&pool, "Bob", None)
        .await
        .expect("bob session");
    e6ircd::db::issue_app_password_for_account(&pool, "Alice", "desktop")
        .await
        .expect("app password");
    let api_secret = issue_api_token(&pool, "Alice", "automation")
        .await
        .expect("API token");
    assert_eq!(
        e6ircd::db::link_oidc_identity(
            &pool,
            "Alice",
            "https://issuer.example",
            "sensitive-subject",
        )
        .await
        .expect("OIDC identity"),
        e6ircd::db::LinkOutcome::Linked
    );
    sqlx::query(
        "WITH account AS (
             SELECT id FROM accounts WHERE name_folded = 'alice'
         ), network AS (
             INSERT INTO bnc_networks (account_id, name, addr, nick, username, kind)
             SELECT id, 'local', '', 'Alice', 'alice', 'irc' FROM account
         )
         INSERT INTO channels (name, name_folded, founder_account_id)
         SELECT '#alice', '#alice', id FROM account",
    )
    .execute(&pool)
    .await
    .expect("resource posture");

    let config = Config {
        server_name: "irc.accounts.example".into(),
        network_name: "AccountsNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec!["alice".into()],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");
    let cookie_get = |path: &str, session: &str| {
        format!(
            "GET {path} HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
        )
    };

    let (status, headers, body) = request(
        http,
        &cookie_get("/api/v1/admin/accounts?limit=2", &alice_session),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("cache-control: no-store"),
        "{headers}"
    );
    let first: serde_json::Value = serde_json::from_str(&body).expect("first page JSON");
    assert_eq!(first["accounts"].as_array().expect("account rows").len(), 2);
    let cursor = first["next_before_id"].as_i64().expect("next page cursor");
    assert!(first["accounts"][0]["id"].as_i64().is_some(), "{body}");

    e6ircd::db::create_account_with_contact(&pool, "Dave", "pw", None)
        .await
        .expect("concurrent account");
    let older_path = format!("/api/v1/admin/accounts?limit=2&before_id={cursor}");
    let (status, _, older_body) = request(http, &cookie_get(&older_path, &alice_session)).await;
    assert_eq!(status, 200, "{older_body}");
    let older: serde_json::Value = serde_json::from_str(&older_body).expect("older page JSON");
    assert!(
        older["accounts"]
            .as_array()
            .expect("older rows")
            .iter()
            .all(|entry| entry["id"].as_i64().is_some_and(|id| id < cursor)),
        "cursor admitted a newer or duplicate account: {older_body}"
    );

    let (status, _, exact_body) = request(
        http,
        &cookie_get("/api/v1/admin/accounts?name=aLiCe", &alice_session),
    )
    .await;
    assert_eq!(status, 200, "{exact_body}");
    let exact: serde_json::Value = serde_json::from_str(&exact_body).expect("exact JSON");
    assert_eq!(
        exact["accounts"].as_array().expect("exact rows").len(),
        1,
        "{exact_body}"
    );
    let alice = &exact["accounts"][0];
    assert_eq!(alice["name"], "Alice");
    assert_eq!(
        alice["administrator"], true,
        "configuration-backed administrators are effective administrators too"
    );
    assert_eq!(alice["administrator_sources"]["durable"], false);
    assert_eq!(alice["administrator_sources"]["configuration"], true);
    assert_eq!(alice["current"], true);
    assert_eq!(alice["suspended"], false);
    assert_eq!(alice["authentication"]["local_password"], true);
    assert_eq!(alice["authentication"]["app_passwords"], 1);
    assert_eq!(alice["authentication"]["api_tokens"], 1);
    assert_eq!(alice["authentication"]["oidc_identities"], 1);
    assert_eq!(alice["authentication"]["browser_sessions"], 1);
    assert_eq!(alice["resources"]["networks"], 1);
    assert_eq!(alice["resources"]["founded_channels"], 1);
    assert!(
        !exact_body.contains(&api_secret),
        "API secret leaked: {exact_body}"
    );
    assert!(
        !exact_body.contains("sensitive-subject"),
        "OIDC subject leaked: {exact_body}"
    );

    let hostile_path = "/console/accounts?name=Eve%3Cscript%3Ealert%281%29%3C%2Fscript%3E";
    let (status, _, page) = request(http, &cookie_get(hostile_path, &alice_session)).await;
    assert_eq!(status, 200, "{page}");
    assert!(page.contains("<h1>Account directory</h1>"), "{page}");
    assert!(page.contains("data-api-admin-accounts-page"), "{page}");
    assert!(!page.contains("Eve"), "{page}");
    assert!(!page.contains("<script>alert(1)</script>"), "{page}");
    let (status, _, alice_page) = request(
        http,
        &cookie_get("/console/accounts?name=aLiCe", &alice_session),
    )
    .await;
    assert_eq!(status, 200, "{alice_page}");
    assert!(
        alice_page.contains("data-api-admin-accounts"),
        "{alice_page}"
    );
    assert!(!alice_page.contains("local password"), "{alice_page}");
    assert!(
        !alice_page.contains("/suspension") && !alice_page.contains("/administrator"),
        "case-only display differences must not expose self-targeting actions: {alice_page}"
    );

    let (status, _, short_page) = request(
        http,
        &cookie_get("/console/accounts?limit=2", &alice_session),
    )
    .await;
    assert_eq!(status, 200, "{short_page}");
    assert!(
        short_page.contains("data-api-admin-accounts-filter"),
        "{short_page}"
    );

    let (status, headers, _) = request(http, &get("/console/accounts")).await;
    assert_eq!(status, 303, "{headers}");
    assert!(
        headers.to_ascii_lowercase().contains("location: /login"),
        "{headers}"
    );
    let (status, _, _) = request(http, &cookie_get("/console/accounts", &bob_session)).await;
    assert_eq!(status, 403);
    let (status, _, invalid) = request(
        http,
        &cookie_get("/api/v1/admin/accounts?before_id=0", &alice_session),
    )
    .await;
    assert_eq!(status, 400, "{invalid}");
    assert!(
        invalid.contains("Invalid account-directory cursor"),
        "{invalid}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn durable_admin_can_suspend_and_reactivate_an_account_end_to_end() {
    let url =
        support::test_db("durable_admin_can_suspend_and_reactivate_an_account_end_to_end").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    let alice_id = e6ircd::db::bootstrap_first_admin(&pool, "Alice", "administrator password")
        .await
        .expect("durable administrator");
    let bob_id = e6ircd::db::create_account_with_contact(&pool, "Bob", "bob password", None)
        .await
        .expect("Bob");
    let alice_token = issue_api_token(&pool, "Alice", "administrator API")
        .await
        .expect("Alice token");
    let bob_token = issue_api_token(&pool, "Bob", "Bob API")
        .await
        .expect("Bob token");
    let bob_session = e6ircd::db::create_web_session(&pool, "Bob", None)
        .await
        .expect("Bob browser session");
    drop(pool);

    let config = Config {
        server_name: "irc.lifecycle.example".into(),
        network_name: "LifecycleNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url: url.clone(),
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("HTTP");

    let (status, body) = patch_json(
        http,
        &format!("/api/v1/admin/accounts/{bob_id}"),
        &alice_token,
        r#"{"suspended":true,"administrator":true}"#,
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("Invalid request body"), "{body}");

    let (status, body) = patch_json(
        http,
        &format!("/api/v1/admin/accounts/{bob_id}"),
        &alice_token,
        r#"{"suspended":true}"#,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let response: serde_json::Value = serde_json::from_str(&body).expect("state JSON");
    assert_eq!(response["account_id"], bob_id);
    assert_eq!(response["suspended"], true);

    let bob_api_request = format!(
        "GET /api/v1/me HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {bob_token}\r\n\
         Connection: close\r\n\r\n"
    );
    let (status, _, _) = request(http, &bob_api_request).await;
    assert_eq!(status, 401, "suspension revokes Bob's existing API token");
    let bob_console_request = format!(
        "GET /console HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={bob_session}\r\n\
         Connection: close\r\n\r\n"
    );
    let (status, headers, _) = request(http, &bob_console_request).await;
    assert_eq!(status, 303, "{headers}");
    assert_eq!(response_header(&headers, "location"), Some("/login"));

    let admin_directory_request = format!(
        "GET /api/v1/admin/accounts?name=Bob HTTP/1.1\r\nHost: t\r\n\
         Authorization: Bearer {alice_token}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, body) = request(http, &admin_directory_request).await;
    assert_eq!(status, 200, "{body}");
    let directory: serde_json::Value = serde_json::from_str(&body).expect("directory JSON");
    assert_eq!(directory["accounts"][0]["suspended"], true);

    let (status, body) = patch_json(
        http,
        &format!("/api/v1/admin/accounts/{alice_id}"),
        &alice_token,
        r#"{"suspended":true}"#,
    )
    .await;
    assert_eq!(status, 409, "{body}");
    assert!(body.contains("cannot suspend itself"), "{body}");

    let (status, body) = patch_json(
        http,
        &format!("/api/v1/admin/accounts/{bob_id}"),
        &alice_token,
        r#"{"suspended":false}"#,
    )
    .await;
    assert_eq!(status, 200, "{body}");

    let verification = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("reconnect");
    assert_eq!(
        e6ircd::db::verify_credentials(&verification, "Bob", "bob password")
            .await
            .expect("verify"),
        Some("Bob".into())
    );
    assert_eq!(
        e6ircd::db::api_token_account(&verification, &bob_token)
            .await
            .expect("old token lookup"),
        None,
        "reactivation never resurrects a revoked bearer"
    );
    let new_bob_token = issue_api_token(&verification, "Bob", "reactivated API")
        .await
        .expect("new Bob token");
    drop(verification);
    let (status, body) = patch_json(
        http,
        &format!("/api/v1/admin/accounts/{alice_id}"),
        &new_bob_token,
        r#"{"suspended":true}"#,
    )
    .await;
    assert_eq!(status, 403, "{body}");

    let (status, body) = patch_json(
        http,
        &format!("/api/v1/admin/accounts/{alice_id}"),
        &alice_token,
        r#"{"administrator":false}"#,
    )
    .await;
    assert_eq!(status, 409, "{body}");
    assert!(body.contains("cannot remove its own authority"), "{body}");

    let (status, body) = patch_json(
        http,
        &format!("/api/v1/admin/accounts/{bob_id}"),
        &alice_token,
        r#"{"administrator":true}"#,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let bob_admin_request = format!(
        "GET /api/v1/admin/accounts?name=Bob HTTP/1.1\r\nHost: t\r\n\
         Authorization: Bearer {new_bob_token}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, body) = request(http, &bob_admin_request).await;
    assert_eq!(status, 200, "{body}");
    let bob_directory: serde_json::Value = serde_json::from_str(&body).expect("Bob directory JSON");
    assert_eq!(bob_directory["accounts"][0]["administrator"], true);
    assert_eq!(
        bob_directory["accounts"][0]["administrator_sources"]["durable"],
        true
    );
    assert_eq!(
        bob_directory["accounts"][0]["administrator_sources"]["configuration"],
        false
    );

    let (status, body) = patch_json(
        http,
        &format!("/api/v1/admin/accounts/{alice_id}"),
        &new_bob_token,
        r#"{"administrator":false}"#,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, _, body) = request(http, &admin_directory_request).await;
    assert_eq!(
        status, 403,
        "durable revocation must update the live authorization registry: {body}"
    );
    let (status, body) = patch_json(
        http,
        &format!("/api/v1/admin/accounts/{alice_id}"),
        &new_bob_token,
        r#"{"administrator":true}"#,
    )
    .await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn invitation_creation_export_and_permanent_deletion_work_end_to_end() {
    let url =
        support::test_db("invitation_creation_export_and_permanent_deletion_work_end_to_end").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    let alice_id = e6ircd::db::bootstrap_first_admin(&pool, "Alice", "administrator password")
        .await
        .expect("Alice");
    let alice_token = issue_api_token(&pool, "Alice", "administrator API")
        .await
        .expect("Alice token");
    let alice_session = e6ircd::db::create_web_session(&pool, "Alice", None)
        .await
        .expect("Alice session");

    let config = Config {
        server_name: "irc.onboarding.example".into(),
        network_name: "OnboardingNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: Some("http://irc.onboarding.example".into()),
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url: url.clone(),
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }),
        internal_upstreams: e6ircd::egress::InternalUpstreams::Allow,
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("HTTP");

    let accounts_page = format!(
        "GET /console/accounts HTTP/1.1\r\nHost: t\r\n\
         Cookie: e6irc_session={alice_session}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, body) = request(http, &accounts_page).await;
    assert_eq!(status, 200, "{body}");
    for control in [
        "Invite an account",
        "Create an account",
        "data-api-admin-invitations",
    ] {
        assert!(body.contains(control), "missing {control:?}: {body}");
    }

    let invitation_body = serde_json::json!({
        "account": "Bob",
        "contact_email": "Bob@Example.COM",
        "expires_in_days": 7,
        "administrator": false,
    })
    .to_string();
    let (status, body) = post_json(
        http,
        "/api/v1/admin/invitations",
        &alice_token,
        &invitation_body,
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let invitation: serde_json::Value = serde_json::from_str(&body).expect("invitation response");
    let invitation_url = invitation["invitation_url"]
        .as_str()
        .expect("single-use URL");
    assert!(
        invitation_url.starts_with("http://irc.onboarding.example/invite/e6i_"),
        "{body}"
    );
    let invitation_path = invitation_url
        .strip_prefix("http://irc.onboarding.example")
        .expect("configured public origin");
    let invitation_directory = format!(
        "GET /api/v1/admin/invitations?limit=1 HTTP/1.1\r\nHost: t\r\n\
         Authorization: Bearer {alice_token}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, body) = request(http, &invitation_directory).await;
    assert_eq!(status, 200, "{body}");
    let directory: serde_json::Value = serde_json::from_str(&body).expect("invitation directory");
    assert_eq!(directory["invitations"][0]["account"], "Bob");
    assert_eq!(directory["next_before_id"], serde_json::Value::Null);
    assert!(
        !body.contains("e6i_"),
        "bearer leaked into directory: {body}"
    );
    let invalid_directory = format!(
        "GET /api/v1/admin/invitations?limit=0 HTTP/1.1\r\nHost: t\r\n\
         Authorization: Bearer {alice_token}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, body) = request(http, &invalid_directory).await;
    assert_eq!(status, 400, "{body}");

    let (status, invite_headers, invite_page) = request(http, &get(invitation_path)).await;
    assert_eq!(status, 200, "{invite_page}");
    assert!(
        invite_page.contains("Create <code>Bob</code>"),
        "{invite_page}"
    );
    assert!(!invitation_state_from_html(&invite_page).is_empty());
    let invitation_cookie = response_header(&invite_headers, "set-cookie")
        .expect("invitation cookie")
        .split(';')
        .next()
        .expect("cookie pair")
        .to_string();
    let bad_accept =
        "invitation_state=wrong&password=bob-password&password_confirmation=bob-password";
    let bad_request = format!(
        "POST {invitation_path} HTTP/1.1\r\nHost: t\r\nCookie: {invitation_cookie}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{bad_accept}",
        bad_accept.len()
    );
    let (status, _, body) = request(http, &bad_request).await;
    assert_eq!(status, 403, "{body}");

    let (status, invite_headers, invite_page) = request(http, &get(invitation_path)).await;
    assert_eq!(status, 200, "{invite_page}");
    let invitation_state = invitation_state_from_html(&invite_page).to_string();
    let invitation_cookie = response_header(&invite_headers, "set-cookie")
        .expect("invitation cookie")
        .split(';')
        .next()
        .expect("cookie pair");
    let accept_body = format!(
        "invitation_state={}&password=bob-password&password_confirmation=bob-password",
        form_value(&invitation_state)
    );
    let accept_request = format!(
        "POST {invitation_path} HTTP/1.1\r\nHost: t\r\nCookie: {invitation_cookie}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{accept_body}",
        accept_body.len()
    );
    let (status, accept_headers, body) = request(http, &accept_request).await;
    assert_eq!(status, 303, "{body}");
    // Bob was invited without administration, so his first page is his own
    // account page, not the administrators' overview.
    assert_eq!(
        response_header(&accept_headers, "location"),
        Some("/console/account")
    );
    let bob_session_cookie = accept_headers
        .lines()
        .find_map(|line| {
            line.strip_prefix("set-cookie: e6irc_session=")
                .or_else(|| line.strip_prefix("Set-Cookie: e6irc_session="))
        })
        .and_then(|value| value.split(';').next())
        .expect("Bob session cookie")
        .to_string();
    let first_page = format!(
        "GET /console/account HTTP/1.1\r\nHost: t\r\n\
         Cookie: e6irc_session={bob_session_cookie}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, body) = request(http, &first_page).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        e6ircd::db::verify_local_password(&pool, "Bob", "bob-password")
            .await
            .expect("Bob password"),
        Some("Bob".into())
    );
    let (status, _, body) = request(http, &get(invitation_path)).await;
    assert_eq!(status, 404, "{body}");

    let bob_export = format!(
        "GET /api/v1/me/export HTTP/1.1\r\nHost: t\r\n\
         Cookie: e6irc_session={bob_session_cookie}\r\nConnection: close\r\n\r\n"
    );
    let (status, headers, body) = request(http, &bob_export).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        headers.contains("attachment; filename=\"e6irc-account-export.json\""),
        "{headers}"
    );
    let export: serde_json::Value = serde_json::from_str(&body).expect("export JSON");
    assert_eq!(export["account"]["name"], "Bob");
    assert_eq!(export["account"]["contact_email"], "Bob@example.com");

    let create_carol = serde_json::json!({
        "account": "Carol",
        "password": "carol password",
        "contact_email": null,
        "administrator": false,
    })
    .to_string();
    let (status, body) =
        post_json(http, "/api/v1/admin/accounts", &alice_token, &create_carol).await;
    assert_eq!(status, 201, "{body}");
    let carol_id = serde_json::from_str::<serde_json::Value>(&body).expect("Carol response")["id"]
        .as_i64()
        .expect("Carol id");
    let delete_carol_body = r#"{"confirmation":"Carol"}"#;
    let delete_carol = format!(
        "DELETE /api/v1/admin/accounts/{carol_id} HTTP/1.1\r\nHost: t\r\n\
         Authorization: Bearer {alice_token}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{delete_carol_body}",
        delete_carol_body.len()
    );
    let (status, _, body) = request(http, &delete_carol).await;
    assert_eq!(status, 200, "{body}");
    assert!(matches!(
        e6ircd::db::create_account_with_contact(&pool, "carol", "replacement", None).await,
        Err(e6ircd::db::DbError::DuplicateAccount(_))
    ));

    let bob_id = e6ircd::db::account_id_by_name(&pool, "Bob")
        .await
        .expect("Bob lookup")
        .expect("Bob");
    sqlx::query(
        "INSERT INTO channels (name, name_folded, founder_account_id)
         VALUES ('#bob', '#bob', $1)",
    )
    .bind(bob_id)
    .execute(&pool)
    .await
    .expect("Bob channel");
    let bob_account_page = format!(
        "GET /console/account HTTP/1.1\r\nHost: t\r\n\
         Cookie: e6irc_session={bob_session_cookie}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, page) = request(http, &bob_account_page).await;
    assert_eq!(status, 200, "{page}");
    assert!(page.contains("Download my data"), "{page}");
    assert!(page.contains("Security activity"), "{page}");
    assert!(page.contains("Delete my account permanently"), "{page}");
    let bob_csrf = csrf_from_html(&page).to_string();
    let delete_bob_body = r#"{"confirmation":"Bob"}"#;
    let delete_bob = |csrf: &str| {
        format!(
            "DELETE /api/v1/me/account HTTP/1.1\r\nHost: t\r\n\
             Cookie: e6irc_session={bob_session_cookie}\r\nX-E6IRC-CSRF: {csrf}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{delete_bob_body}",
            delete_bob_body.len()
        )
    };
    let (status, _, body) = request(http, &delete_bob(&bob_csrf)).await;
    assert_eq!(status, 409, "{body}");
    assert!(body.contains("transfer or unregister"), "{body}");
    assert!(
        e6ircd::db::set_channel_founder(&pool, "#bob", "alice", "founder")
            .await
            .expect("transfer")
    );
    let (status, headers, body) = request(http, &delete_bob(&bob_csrf)).await;
    assert_eq!(status, 204, "{body}");
    assert!(headers.contains("Max-Age=0"), "{headers}");
    assert_eq!(
        e6ircd::db::account_id_by_name(&pool, "Bob")
            .await
            .expect("Bob lookup"),
        None
    );
    let (status, headers, _) = request(http, &bob_account_page).await;
    assert_eq!(status, 303, "{headers}");
    assert_eq!(response_header(&headers, "location"), Some("/login"));

    assert!(
        e6ircd::db::account_name_by_id(&pool, alice_id)
            .await
            .expect("Alice")
            .is_some()
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn policy_directories_filter_page_and_escape_for_admins_only() {
    let url = support::test_db("policy_directories_filter_page_and_escape_for_admins_only").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    for name in ["Alice", "Bob"] {
        e6ircd::db::create_account_with_contact(&pool, name, "pw", None)
            .await
            .unwrap_or_else(|error| panic!("create {name}: {error}"));
    }
    let alice_session = e6ircd::db::create_web_session(&pool, "Alice", None)
        .await
        .expect("alice session");
    let bob_session = e6ircd::db::create_web_session(&pool, "Bob", None)
        .await
        .expect("bob session");
    for (channel, founder) in [
        ("#Alpha", "alice"),
        ("#Bravo", "bob"),
        ("#Charlie", "alice"),
        ("#Eve<script>", "bob"),
    ] {
        sqlx::query(
            "INSERT INTO channels (name, name_folded, founder_account_id)
             SELECT $1, $2, id FROM accounts WHERE name_folded = $3",
        )
        .bind(channel)
        .bind(channel.to_ascii_lowercase())
        .bind(founder)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("insert {channel}: {error}"));
    }
    sqlx::query(
        "UPDATE channels
         SET keeptopic = FALSE, topic = 'retained', topic_setter = 'Alice',
             topic_set_at = now(), mlock = '+nt'
         WHERE name_folded = '#alpha'",
    )
    .execute(&pool)
    .await
    .expect("retained channel policy");
    sqlx::query(
        "INSERT INTO channel_access (channel_id, account_id, flags)
         SELECT c.id, a.id, 'ov'
         FROM channels c, accounts a
         WHERE c.name_folded = '#alpha' AND a.name_folded = 'bob'",
    )
    .execute(&pool)
    .await
    .expect("channel access");
    for (mask, display, reason, setter, kind) in [
        ("bad@host", "Bad@Host", "spam", "Alice", "kline"),
        ("192.0.2.*", "192.0.2.*", "proxy", "Bob", "dline"),
        ("*bot*", "*Bot*", "automation", "Alice", "xline"),
        (
            "evil@host",
            "Evil@Host",
            "<script>alert(1)</script>",
            "Bob",
            "kline",
        ),
    ] {
        add_server_ban(&pool, mask, display, reason, setter, kind)
            .await
            .unwrap_or_else(|error| panic!("add {kind} {display}: {error}"));
    }

    let config = Config {
        server_name: "irc.policy.example".into(),
        network_name: "PolicyNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec!["alice".into()],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");
    let cookie_get = |path: &str, session: &str| {
        format!(
            "GET {path} HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
        )
    };

    let (status, headers, body) = request(
        http,
        &cookie_get("/api/v1/admin/channels?limit=2", &alice_session),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("cache-control: no-store"),
        "{headers}"
    );
    let channels: serde_json::Value = serde_json::from_str(&body).expect("channel JSON");
    assert_eq!(
        channels["channels"].as_array().expect("channel rows").len(),
        2
    );
    let channel_cursor = channels["next_before_id"].as_i64().expect("channel cursor");
    sqlx::query(
        "INSERT INTO channels (name, name_folded, founder_account_id)
         SELECT '#Delta', '#delta', id FROM accounts WHERE name_folded = 'alice'",
    )
    .execute(&pool)
    .await
    .expect("concurrent channel");
    let channel_older_path = format!("/api/v1/admin/channels?limit=2&before_id={channel_cursor}");
    let (status, _, older_body) =
        request(http, &cookie_get(&channel_older_path, &alice_session)).await;
    assert_eq!(status, 200, "{older_body}");
    let older: serde_json::Value = serde_json::from_str(&older_body).expect("older channels");
    assert!(
        older["channels"]
            .as_array()
            .expect("older channel rows")
            .iter()
            .all(|entry| entry["id"].as_i64().is_some_and(|id| id < channel_cursor)),
        "channel cursor admitted a newer or duplicate row: {older_body}"
    );
    let exact_channel = "/api/v1/admin/channels?name=%23aLpHa&founder=aLiCe";
    let (status, _, exact_body) = request(http, &cookie_get(exact_channel, &alice_session)).await;
    assert_eq!(status, 200, "{exact_body}");
    let exact: serde_json::Value = serde_json::from_str(&exact_body).expect("exact channel");
    assert_eq!(exact["channels"].as_array().expect("exact rows").len(), 1);
    assert_eq!(exact["channels"][0]["name"], "#Alpha");
    assert_eq!(exact["channels"][0]["founder"], "Alice");
    assert_eq!(exact["channels"][0]["policy"]["keeptopic"], false);
    assert_eq!(exact["channels"][0]["policy"]["topic_retained"], true);
    assert_eq!(exact["channels"][0]["policy"]["mlock"], "+nt");
    assert_eq!(exact["channels"][0]["policy"]["access_entries"], 1);

    let (status, headers, body) = request(
        http,
        &cookie_get("/api/v1/admin/bans?limit=2", &alice_session),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("cache-control: no-store"),
        "{headers}"
    );
    let bans: serde_json::Value = serde_json::from_str(&body).expect("ban JSON");
    assert_eq!(bans["bans"].as_array().expect("ban rows").len(), 2);
    let ban_cursor = bans["next_before_id"].as_i64().expect("ban cursor");
    add_server_ban(
        &pool,
        "new@host",
        "New@Host",
        "concurrent",
        "Alice",
        "kline",
    )
    .await
    .expect("concurrent ban");
    let ban_older_path = format!("/api/v1/admin/bans?limit=2&before_id={ban_cursor}");
    let (status, _, older_body) = request(http, &cookie_get(&ban_older_path, &alice_session)).await;
    assert_eq!(status, 200, "{older_body}");
    let older: serde_json::Value = serde_json::from_str(&older_body).expect("older bans");
    assert!(
        older["bans"]
            .as_array()
            .expect("older ban rows")
            .iter()
            .all(|entry| entry["id"].as_i64().is_some_and(|id| id < ban_cursor)),
        "server-ban cursor admitted a newer or duplicate row: {older_body}"
    );
    let exact_ban = "/api/v1/admin/bans?kind=kline&mask=BAD%40HOST";
    let (status, _, exact_body) = request(http, &cookie_get(exact_ban, &alice_session)).await;
    assert_eq!(status, 200, "{exact_body}");
    let exact: serde_json::Value = serde_json::from_str(&exact_body).expect("exact ban");
    assert_eq!(exact["bans"].as_array().expect("exact rows").len(), 1);
    assert_eq!(exact["bans"][0]["mask"], "Bad@Host");
    assert_eq!(exact["bans"][0]["reason"], "spam");
    assert_eq!(exact["bans"][0]["set_by"], "Alice");

    let (status, _, channel_page) =
        request(http, &cookie_get("/console/admin/channels", &alice_session)).await;
    assert_eq!(status, 200, "{channel_page}");
    assert!(
        channel_page.contains("<h1>Registered-channel directory</h1>"),
        "{channel_page}"
    );
    assert!(
        channel_page.contains("data-api-admin-channel-list"),
        "{channel_page}"
    );
    assert!(!channel_page.contains("#Eve<script>"), "{channel_page}");
    let (status, _, channel_short_page) = request(
        http,
        &cookie_get("/console/admin/channels?limit=2", &alice_session),
    )
    .await;
    assert_eq!(status, 200, "{channel_short_page}");
    assert!(
        channel_short_page.contains("Loading registered channels"),
        "{channel_short_page}"
    );

    let (status, _, ban_page) = request(http, &cookie_get("/console/bans", &alice_session)).await;
    assert_eq!(status, 200, "{ban_page}");
    assert!(ban_page.contains("<h1>Server bans</h1>"), "{ban_page}");
    assert!(ban_page.contains("data-api-admin-ban-list"), "{ban_page}");
    assert!(
        !ban_page.contains("<script>alert(1)</script>"),
        "{ban_page}"
    );
    let (status, _, ban_short_page) =
        request(http, &cookie_get("/console/bans?limit=2", &alice_session)).await;
    assert_eq!(status, 200, "{ban_short_page}");
    assert!(
        ban_short_page.contains("Loading server bans"),
        "{ban_short_page}"
    );

    for path in ["/console/admin/channels", "/console/bans"] {
        let (status, headers, _) = request(http, &get(path)).await;
        assert_eq!(status, 303, "{path}: {headers}");
        assert!(
            headers.to_ascii_lowercase().contains("location: /login"),
            "{path}: {headers}"
        );
        let (status, _, _) = request(http, &cookie_get(path, &bob_session)).await;
        assert_eq!(status, 403, "{path}");
    }
    for (path, title) in [
        (
            "/api/v1/admin/channels?before_id=0",
            "Invalid registered-channel cursor",
        ),
        ("/api/v1/admin/bans?kind=gline", "Invalid server-ban filter"),
    ] {
        let (status, _, invalid) = request(http, &cookie_get(path, &alice_session)).await;
        assert_eq!(status, 400, "{invalid}");
        assert!(invalid.contains(title), "{invalid}");
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn audit_explorer_filters_pages_and_escapes_for_admins_only() {
    let url = support::test_db("audit_explorer_filters_pages_and_escapes_for_admins_only").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("alice");
    e6ircd::db::create_account_with_contact(&pool, "bob", "pw", None)
        .await
        .expect("bob");
    let alice_session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("alice session");
    let bob_session = e6ircd::db::create_web_session(&pool, "bob", None)
        .await
        .expect("bob session");
    for (actor, action, target, detail) in [
        ("alice", "OPER", "alice", ""),
        ("bob", "KLINE", "first@host", "<script>alert(1)</script>"),
        ("alice", "KLINE", "second@host", "abuse"),
        ("alice", "CONFIG", "server", "revision 2"),
        ("bob", "KLINE", "third@host", "spam"),
    ] {
        e6ircd::db::insert_audit_log(&pool, actor, action, target, detail)
            .await
            .expect("seed audit entry");
    }

    let config = Config {
        server_name: "irc.audit.example".into(),
        network_name: "AuditNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec!["alice".into()],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");
    let cookie_get = |path: &str, session: &str| {
        format!(
            "GET {path} HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
        )
    };

    let (status, headers, body) = request(
        http,
        &cookie_get("/api/v1/admin/audit?limit=2", &alice_session),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("cache-control: no-store"),
        "{headers}"
    );
    let first: serde_json::Value = serde_json::from_str(&body).expect("first page JSON");
    assert_eq!(first["audit"].as_array().expect("audit rows").len(), 2);
    assert!(first["audit"][0]["id"].as_i64().is_some(), "{body}");
    let cursor = first["next_before_id"].as_i64().expect("next page cursor");

    e6ircd::db::insert_audit_log(&pool, "alice", "OPER", "alice", "concurrent")
        .await
        .expect("concurrent audit append");
    let older_path = format!("/api/v1/admin/audit?limit=2&before_id={cursor}");
    let (status, _, older_body) = request(http, &cookie_get(&older_path, &alice_session)).await;
    assert_eq!(status, 200, "{older_body}");
    let older: serde_json::Value = serde_json::from_str(&older_body).expect("older page JSON");
    assert!(
        older["audit"]
            .as_array()
            .expect("older rows")
            .iter()
            .all(|entry| entry["id"].as_i64().is_some_and(|id| id < cursor)),
        "cursor admitted a newer or duplicate entry: {older_body}"
    );

    let filtered = "/api/v1/admin/audit?actor=alice&action=KLINE&target=second%40host";
    let (status, _, filtered_body) = request(http, &cookie_get(filtered, &alice_session)).await;
    assert_eq!(status, 200, "{filtered_body}");
    let filtered: serde_json::Value = serde_json::from_str(&filtered_body).expect("filtered JSON");
    assert_eq!(
        filtered["audit"].as_array().expect("filtered rows").len(),
        1,
        "{filtered_body}"
    );
    assert_eq!(filtered["audit"][0]["detail"], "abuse");

    let (status, _, page) = request(http, &cookie_get("/console/audit", &alice_session)).await;
    assert_eq!(status, 200, "{page}");
    assert!(page.contains("<h1>Audit log</h1>"), "{page}");
    assert!(page.contains("Find audit entries"), "{page}");
    assert!(page.contains("data-api-admin-audit-list"), "{page}");
    assert!(!page.contains("<script>alert(1)</script>"), "{page}");
    let (status, _, short_page) =
        request(http, &cookie_get("/console/audit?limit=2", &alice_session)).await;
    assert_eq!(status, 200, "{short_page}");
    assert!(
        short_page.contains("Loading audited actions"),
        "{short_page}"
    );

    let (status, _, filtered_page) = request(
        http,
        &cookie_get("/console/audit?action=CONFIG", &alice_session),
    )
    .await;
    assert_eq!(status, 200, "{filtered_page}");
    assert!(
        filtered_page.contains("data-api-admin-audit-list"),
        "{filtered_page}"
    );
    assert!(!filtered_page.contains("revision 2"), "{filtered_page}");
    assert!(!filtered_page.contains("third@host"), "{filtered_page}");

    let (status, headers, _) = request(http, &get("/console/audit")).await;
    assert_eq!(status, 303, "{headers}");
    assert!(
        headers.to_ascii_lowercase().contains("location: /login"),
        "{headers}"
    );
    let (status, _, _) = request(http, &cookie_get("/console/audit", &bob_session)).await;
    assert_eq!(status, 403);
    let (status, _, invalid) = request(
        http,
        &cookie_get("/api/v1/admin/audit?before_id=0", &alice_session),
    )
    .await;
    assert_eq!(status, 400, "{invalid}");
    assert!(invalid.contains("Invalid audit cursor"), "{invalid}");
}

/// Admin console server-management actions: add/remove a server ban and drop a
/// registered channel, all driven through the core (so they enforce like the
/// IRC oper/services commands) and admin-gated + CSRF-protected.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn admin_console_ban_and_channel_actions() {
    let url = support::test_db("admin_console_ban_and_channel_actions").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("alice");
    let session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("session");
    sqlx::query(
        "INSERT INTO channels (name, name_folded, founder_account_id)
         SELECT '#dropme', '#dropme', id FROM accounts WHERE name_folded = 'alice'",
    )
    .execute(&pool)
    .await
    .expect("channel");
    drop(pool);

    let config = Config {
        server_name: "irc.admin.example".into(),
        network_name: "AdminNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec!["alice".into()],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");

    // Load the server-ban page and extract the session-bound CSRF token.
    let ban_page_req = format!(
        "GET /console/bans HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, page) = request(http, &ban_page_req).await;
    assert_eq!(status, 200, "{page}");
    assert!(page.contains("data-api-ban-create"), "{page}");
    assert!(page.contains("action=\"/api/v1/admin/bans\""), "{page}");
    let csrf = page
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("csrf token in server-ban page")
        .to_string();
    assert!(!csrf.is_empty());

    // Fetch a policy page and test for a needle, retrying while the redirect's
    // committed core action becomes visible to the independent directory query.
    let policy_page_has = |path: &'static str, needle: &'static str, want: bool| {
        let session = session.clone();
        async move {
            for _ in 0..40 {
                let req = format!(
                    "GET {path} HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
                );
                let (_, _, body) = request(http, &req).await;
                if body.contains(needle) == want {
                    return true;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            false
        }
    };

    // Add a K-line through the API; the persisted policy appears in the
    // administrator directory after the core commits the transition.
    let body = r#"{"kind":"kline","mask":"*@bad.example","reason":"spam"}"#;
    let add = format!(
        "POST /api/v1/admin/bans HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-E6IRC-CSRF: {csrf}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    let (status, _, _) = request(http, &add).await;
    assert_eq!(status, 201);
    assert!(
        policy_page_has("/api/v1/admin/bans", "*@bad.example", true).await,
        "ban not listed after add"
    );

    let directory = format!(
        "GET /api/v1/admin/bans?kind=kline&mask=%2A%40bad.example HTTP/1.1\r\nHost: t\r\n\
         Cookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, body) = request(http, &directory).await;
    assert_eq!(status, 200, "{body}");
    let ban_id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["bans"][0]["id"]
        .as_i64()
        .expect("stable server-ban id");

    // Delete that exact immutable policy resource; a client never selects a
    // mutable visible mask for removal.
    let del_req = format!(
        "DELETE /api/v1/admin/bans/{ban_id} HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-E6IRC-CSRF: {csrf}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, _) = request(http, &del_req).await;
    assert_eq!(status, 204);
    assert!(
        policy_page_has("/api/v1/admin/bans", "*@bad.example", false).await,
        "ban still listed after remove"
    );
    assert!(
        policy_page_has(
            "/api/v1/admin/audit?action=UNKLINE&target=%2A%40bad.example",
            "UNKLINE",
            true,
        )
        .await,
        "server-ban removal was not recorded in the administrator audit API"
    );

    // Drop the registered channel through its administrator API resource; the
    // registry becomes empty after the core commits the ordered transition.
    assert!(
        policy_page_has("/api/v1/admin/channels", "#dropme", true).await,
        "channel not listed to begin with"
    );
    let drop_req = format!(
        "DELETE /api/v1/admin/channels/%23dropme HTTP/1.1\r\nHost: t\r\n\
         Cookie: e6irc_session={session}\r\nX-E6IRC-CSRF: {csrf}\r\n\
         Connection: close\r\n\r\n"
    );
    let (status, _, _) = request(http, &drop_req).await;
    assert_eq!(status, 204);
    assert!(
        policy_page_has("/api/v1/admin/channels", "#dropme", false).await,
        "channel still listed after drop"
    );

    // Gate: browser API mutations require their session CSRF token and an
    // authenticated administrator; the retired rendered route cannot bypass
    // those boundaries.
    let bad = r#"{"kind":"kline","mask":"*@x.example","reason":"x"}"#;
    let bad_req = format!(
        "POST /api/v1/admin/bans HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-E6IRC-CSRF: wrong\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{bad}",
        bad.len()
    );
    let (status, _, _) = request(http, &bad_req).await;
    assert_eq!(status, 403);
    let anon = format!(
        "POST /api/v1/admin/bans HTTP/1.1\r\nHost: t\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{bad}",
        bad.len()
    );
    let (status, head, _) = request(http, &anon).await;
    assert_eq!(status, 401, "{head}");
}

/// The administrator connection API and console expose immutable connection
/// ids and the console disconnects that exact resource.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn admin_connection_directory_and_disconnect_controls() {
    let url = support::test_db("admin_connection_directory_and_disconnect_controls").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("alice");
    e6ircd::db::create_account_with_contact(&pool, "bob", "pw", None)
        .await
        .expect("bob");
    let session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("session");
    let bob_session = e6ircd::db::create_web_session(&pool, "bob", None)
        .await
        .expect("bob session");
    drop(pool);

    let config = Config {
        server_name: "irc.sess.example".into(),
        network_name: "SessNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec!["alice".into()],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        core_workers: 3,
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let irc = running.addrs[0];
    let http = running.http_addr.expect("http");
    let authenticated_get = |path: &str, cookie: &str| {
        format!(
            "GET {path} HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={cookie}\r\n\
             Connection: close\r\n\r\n"
        )
    };

    let (status, _, _) = request(http, &get("/api/v1/admin/connections")).await;
    assert_eq!(status, 401);
    let (status, _, _) = request(
        http,
        &authenticated_get("/api/v1/admin/connections", &bob_session),
    )
    .await;
    assert_eq!(status, 403);

    // A client connects and registers, so it is a live session.
    let mut victim = e6irc_client::Connection::connect(&irc.to_string())
        .await
        .expect("tcp");
    victim
        .register(&e6irc_client::Identity {
            nick: "victim",
            username: "victim",
            realname: "v",
            server_password: None,
        })
        .await
        .expect("register");
    let mut peer = e6irc_client::Connection::connect(&irc.to_string())
        .await
        .expect("peer tcp");
    peer.register(&e6irc_client::Identity {
        nick: "peer",
        username: "peer",
        realname: "p",
        server_password: None,
    })
    .await
    .expect("register peer");

    let sessions_req = format!(
        "GET /console/sessions HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, page_body) = request(http, &sessions_req).await;
    assert_eq!(status, 200, "{page_body}");
    assert!(page_body.contains("data-api-session-page"), "{page_body}");
    assert!(!page_body.contains("victim"), "{page_body}");
    let csrf = csrf_from_html(&page_body).to_string();
    let api_req = format!(
        "GET /api/v1/admin/connections?limit=1&nick=VICTIM&transport=tcp HTTP/1.1\r\n\
         Host: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (api_head, api_body) = loop {
        let (status, head, body) = request(http, &api_req).await;
        assert_eq!(status, 200, "{body}");
        if body.contains("victim") {
            break (head, body);
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    assert!(
        api_head
            .to_ascii_lowercase()
            .contains("cache-control: no-store"),
        "{api_head}"
    );
    let api: serde_json::Value = serde_json::from_str(&api_body).expect("connection JSON");
    let connection_id = api["connections"][0]["id"]
        .as_str()
        .expect("exact decimal connection id")
        .parse::<u64>()
        .expect("connection id");
    assert_eq!(api["connections"][0]["nick"], "victim");
    assert_eq!(api["connections"][0]["transport"], "tcp");
    assert!(api["connections"][0]["connected_at"].is_string());
    assert!(api["connections"][0]["idle_seconds"].is_u64());

    let newest_page = authenticated_get("/api/v1/admin/connections?limit=1", &session);
    let (status, _, body) = request(http, &newest_page).await;
    assert_eq!(status, 200, "{body}");
    let newest: serde_json::Value = serde_json::from_str(&body).expect("newest page");
    assert_eq!(newest["connections"][0]["nick"], "peer");
    let cursor = newest["next_before_id"]
        .as_str()
        .expect("exact decimal next-page cursor");
    let older_page = authenticated_get(
        &format!("/api/v1/admin/connections?limit=1&before_id={cursor}"),
        &session,
    );
    let (status, _, body) = request(http, &older_page).await;
    assert_eq!(status, 200, "{body}");
    let older: serde_json::Value = serde_json::from_str(&body).expect("older page");
    assert_eq!(older["connections"][0]["nick"], "victim");

    for path in [
        "/api/v1/admin/connections?limit=0",
        "/api/v1/admin/connections?limit=1001",
        "/api/v1/admin/connections?before_id=0",
        "/api/v1/admin/connections?transport=udp",
        "/api/v1/admin/connections?oper=yes",
    ] {
        let (status, head, body) = request(http, &authenticated_get(path, &session)).await;
        assert_eq!(status, 400, "{path}: {body}");
        assert!(
            head.to_ascii_lowercase()
                .contains("content-type: application/problem+json"),
            "{head}"
        );
    }

    // Disconnect the exact immutable resource through the administrator API.
    let kill = format!(
        "DELETE /api/v1/admin/connections/{connection_id}?reason=cleanup HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-E6IRC-CSRF: {csrf}\r\nConnection: close\r\n\r\n"
    );
    let (status, head, _) = request(http, &kill).await;
    assert_eq!(status, 204, "{head}");

    // The victim's connection is closed by the server (an ERROR then EOF).
    let killed = tokio::time::timeout(deadline::HANG, async {
        loop {
            match victim.next_message().await {
                Ok(Some(m)) if m.command == "ERROR" => return true,
                Ok(Some(_)) => continue,
                _ => return true, // EOF / closed
            }
        }
    })
    .await
    .expect("victim was not disconnected");
    assert!(killed);

    // It no longer appears in the API inventory that hydrates the console.
    let mut gone = false;
    for _ in 0..40 {
        let (_, _, body) = request(http, &api_req).await;
        if !body.contains("victim") {
            gone = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(gone, "victim still listed after disconnect");

    // The JSON mutation targets the same immutable resource and a repeated
    // request reports the now-stale identifier instead of succeeding twice.
    let mut api_victim = e6irc_client::Connection::connect(&irc.to_string())
        .await
        .expect("second tcp client");
    api_victim
        .register(&e6irc_client::Identity {
            nick: "api-victim",
            username: "api-victim",
            realname: "v",
            server_password: None,
        })
        .await
        .expect("register second client");
    let api_lookup = format!(
        "GET /api/v1/admin/connections?nick=api-victim HTTP/1.1\r\n\
         Host: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let api_connection_id = loop {
        let (status, _, body) = request(http, &api_lookup).await;
        assert_eq!(status, 200, "{body}");
        let value: serde_json::Value = serde_json::from_str(&body).expect("connection page");
        if let Some(id) = value["connections"]
            .as_array()
            .and_then(|rows| rows.first())
            .and_then(|row| row["id"].as_str())
            .and_then(|id| id.parse::<u64>().ok())
        {
            break id;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    let delete = format!(
        "DELETE /api/v1/admin/connections/{api_connection_id}?reason=api-cleanup HTTP/1.1\r\n\
         Host: t\r\nCookie: e6irc_session={session}\r\nX-E6IRC-CSRF: {csrf}\r\n\
         Connection: close\r\n\r\n"
    );
    let (status, head, body) = request(http, &delete).await;
    assert_eq!(status, 204, "{body}");
    assert!(
        head.to_ascii_lowercase()
            .contains("cache-control: no-store"),
        "{head}"
    );
    let (status, _, body) = request(http, &delete).await;
    assert_eq!(status, 404, "{body}");
}

/// The per-user sessions view lists only the caller's own SASL-authenticated
/// clients and can disconnect them — but never another account's session, even
/// though it is not admin-gated.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn my_sessions_are_scoped_to_the_caller() {
    let url = support::test_db("my_sessions_are_scoped_to_the_caller").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "s3cr3t", None)
        .await
        .expect("alice");
    e6ircd::db::create_account_with_contact(&pool, "bob", "s3cr3t", None)
        .await
        .expect("bob");
    let session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("session");
    drop(pool);

    let config = Config {
        server_name: "irc.mysess.example".into(),
        network_name: "MySessNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![], // alice is NOT an admin: this is self-service,
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let irc = running.addrs[0];
    let http = running.http_addr.expect("http");

    // Two IRC clients, SASL-authenticated as alice and as bob.
    let mut alice_cli = e6irc_client::Connection::connect(&irc.to_string())
        .await
        .expect("tcp a");
    alice_cli
        .register_sasl(
            &e6irc_client::Identity {
                nick: "alicecli",
                username: "alicecli",
                realname: "A",
                server_password: None,
            },
            "alice",
            "s3cr3t",
        )
        .await
        .expect("alice sasl");
    let mut bob_cli = e6irc_client::Connection::connect(&irc.to_string())
        .await
        .expect("tcp b");
    bob_cli
        .register_sasl(
            &e6irc_client::Identity {
                nick: "bobcli",
                username: "bobcli",
                realname: "B",
                server_password: None,
            },
            "bob",
            "s3cr3t",
        )
        .await
        .expect("bob sasl");

    let page_req = format!(
        "GET /console/my-sessions HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, page_body) = request(http, &page_req).await;
    assert_eq!(status, 200, "{page_body}");
    assert!(page_body.contains("data-api-session-page"), "{page_body}");
    assert!(
        !page_body.contains("alicecli") && !page_body.contains("bobcli"),
        "{page_body}"
    );
    let csrf = csrf_from_html(&page_body).to_string();
    assert!(
        page_body.contains("data-api-live-connections"),
        "owner session page must reserve an API connection view"
    );
    let owner_api = format!(
        "GET /api/v1/me/connections?nick=ALICECLI&transport=tcp HTTP/1.1\r\n\
         Host: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (head, body) = loop {
        let (status, head, body) = request(http, &owner_api).await;
        assert_eq!(status, 200, "{body}");
        if body.contains("alicecli") {
            break (head, body);
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    assert!(
        head.to_ascii_lowercase()
            .contains("cache-control: no-store"),
        "{head}"
    );
    let owner_page: serde_json::Value = serde_json::from_str(&body).expect("owner connection page");
    assert_eq!(owner_page["connections"].as_array().map(Vec::len), Some(1));
    let alice_connection_id = owner_page["connections"][0]["id"]
        .as_str()
        .expect("exact decimal connection id")
        .parse::<u64>()
        .expect("connection id");
    // The next accepted IRC connection belongs to Bob. Guessing its immutable
    // id is still refused because owner authorization is re-checked in core.
    let bob_connection_id = alice_connection_id + 1;
    assert_eq!(owner_page["connections"][0]["nick"], "alicecli");
    let delete_bob_api = format!(
        "DELETE /api/v1/me/connections/{bob_connection_id}?reason=nope HTTP/1.1\r\n\
         Host: t\r\nCookie: e6irc_session={session}\r\nX-E6IRC-CSRF: {csrf}\r\n\
         Connection: close\r\n\r\n"
    );
    let (status, _, body) = request(http, &delete_bob_api).await;
    assert_eq!(status, 404, "{body}");

    // bob is still alive: a PING gets a PONG.
    bob_cli.send_line("PING :stillhere").await.unwrap();
    let bob_alive = tokio::time::timeout(deadline::HANG, async {
        loop {
            match bob_cli.next_message().await {
                Ok(Some(m)) if m.command == "PONG" => return true,
                Ok(Some(_)) => continue,
                _ => return false,
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(bob_alive, "bob was wrongly disconnected by alice");

    let mut alice_api_cli = e6irc_client::Connection::connect(&irc.to_string())
        .await
        .expect("alice API tcp");
    alice_api_cli
        .register_sasl(
            &e6irc_client::Identity {
                nick: "aliceapi",
                username: "aliceapi",
                realname: "A",
                server_password: None,
            },
            "alice",
            "s3cr3t",
        )
        .await
        .expect("alice API SASL");
    let alice_api_lookup = format!(
        "GET /api/v1/me/connections?nick=aliceapi HTTP/1.1\r\n\
         Host: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let alice_api_connection_id = loop {
        let (status, _, body) = request(http, &alice_api_lookup).await;
        assert_eq!(status, 200, "{body}");
        let page: serde_json::Value = serde_json::from_str(&body).expect("owner API page");
        if let Some(id) = page["connections"]
            .as_array()
            .and_then(|rows| rows.first())
            .and_then(|row| row["id"].as_str())
        {
            break id.to_owned();
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    let delete_alice_api = format!(
        "DELETE /api/v1/me/connections/{alice_api_connection_id}?reason=owner-api HTTP/1.1\r\n\
         Host: t\r\nCookie: e6irc_session={session}\r\nX-E6IRC-CSRF: {csrf}\r\n\
         Connection: close\r\n\r\n"
    );
    let (status, head, body) = request(http, &delete_alice_api).await;
    assert_eq!(status, 204, "{body}");
    assert!(
        head.to_ascii_lowercase()
            .contains("cache-control: no-store"),
        "{head}"
    );
    let (status, _, body) = request(http, &delete_alice_api).await;
    assert_eq!(status, 404, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn browser_sessions_are_visible_and_owner_scoped_across_api_and_console() {
    let url =
        support::test_db("browser_sessions_are_visible_and_owner_scoped_across_api_and_console")
            .await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("alice");
    e6ircd::db::create_account_with_contact(&pool, "bob", "pw", None)
        .await
        .expect("bob");
    let current_agent =
        e6ircd::db::SessionUserAgent::from_header("Current Browser").expect("agent");
    let other_agent = e6ircd::db::SessionUserAgent::from_header("Browser <other>").expect("agent");
    let current = e6ircd::db::create_web_session(&pool, "alice", Some(&current_agent))
        .await
        .expect("current session");
    let other = e6ircd::db::create_web_session(&pool, "alice", Some(&other_agent))
        .await
        .expect("other session");
    let bob = e6ircd::db::create_web_session(&pool, "bob", None)
        .await
        .expect("bob session");

    let config = Config {
        server_name: "irc.browser-sessions.example".into(),
        network_name: "BrowserSessionsNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");

    let api_list = format!(
        "GET /api/v1/me/sessions HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={current}\r\nConnection: close\r\n\r\n"
    );
    let (status, headers, body) = request(http, &api_list).await;
    assert_eq!(status, 200, "{body}");
    assert!(headers.contains("cache-control: no-store"), "{headers}");
    assert!(!body.contains("token_hash"), "{body}");
    let payload: serde_json::Value = serde_json::from_str(&body).expect("session JSON");
    let sessions = payload["sessions"].as_array().expect("sessions array");
    assert_eq!(sessions.len(), 2, "{payload}");
    assert_eq!(
        sessions.iter().filter(|row| row["current"] == true).count(),
        1
    );
    let current_id = sessions
        .iter()
        .find(|row| row["current"] == true)
        .and_then(|row| row["id"].as_i64())
        .expect("current id");
    let other_id = sessions
        .iter()
        .find(|row| row["current"] == false)
        .and_then(|row| row["id"].as_i64())
        .expect("other id");

    let page = format!(
        "GET /console/my-sessions HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={current}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, page_body) = request(http, &page).await;
    assert_eq!(status, 200, "{page_body}");
    assert!(
        page_body.contains("data-api-browser-sessions"),
        "{page_body}"
    );
    assert!(!page_body.contains("Current Browser"), "{page_body}");
    assert!(
        !page_body.contains("Browser &#60;other&#62;"),
        "{page_body}"
    );
    assert!(!page_body.contains("Browser <other>"), "{page_body}");
    let csrf = csrf_from_html(&page_body).to_string();

    let bob_id = e6ircd::db::list_web_sessions(&pool, "bob", Some(&bob))
        .await
        .expect("list bob")[0]
        .id;
    let cross_account = format!(
        "DELETE /api/v1/me/sessions/{bob_id} HTTP/1.1\r\nHost: t\r\n\
         Cookie: e6irc_session={current}\r\nX-E6IRC-CSRF: {csrf}\r\n\
         Connection: close\r\n\r\n"
    );
    let (status, _, _) = request(http, &cross_account).await;
    assert_eq!(status, 404);
    assert_eq!(
        e6ircd::db::session_account(&pool, &bob)
            .await
            .expect("bob session"),
        Some("bob".into())
    );

    let revoke_other = format!(
        "DELETE /api/v1/me/sessions/{other_id} HTTP/1.1\r\nHost: t\r\n\
         Cookie: e6irc_session={current}\r\nX-E6IRC-CSRF: {csrf}\r\n\
         Connection: close\r\n\r\n"
    );
    let (status, headers, _) = request(http, &revoke_other).await;
    assert_eq!(status, 204, "{headers}");
    assert!(!headers.contains("set-cookie:"), "{headers}");
    assert_eq!(
        e6ircd::db::session_account(&pool, &other)
            .await
            .expect("other session"),
        None
    );

    let third = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("third session");
    let revoke_others = format!(
        "DELETE /api/v1/me/sessions?except=current HTTP/1.1\r\nHost: t\r\n\
         Cookie: e6irc_session={current}\r\nX-E6IRC-CSRF: {csrf}\r\n\
         Connection: close\r\n\r\n"
    );
    let (status, headers, body) = request(http, &revoke_others).await;
    assert_eq!(status, 200, "{headers}: {body}");
    assert!(headers.contains("cache-control: no-store"), "{headers}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["revoked"],
        1
    );
    assert_eq!(
        e6ircd::db::session_account(&pool, &current)
            .await
            .expect("current session"),
        Some("alice".into())
    );
    assert_eq!(
        e6ircd::db::session_account(&pool, &third)
            .await
            .expect("third session"),
        None
    );

    let revoke_current = format!(
        "DELETE /api/v1/me/sessions/{current_id} HTTP/1.1\r\nHost: t\r\n\
         Cookie: e6irc_session={current}\r\nX-E6IRC-CSRF: {csrf}\r\n\
         Connection: close\r\n\r\n"
    );
    let (status, headers, _) = request(http, &revoke_current).await;
    assert_eq!(status, 204, "{headers}");
    assert!(headers.contains("e6irc_session=;"), "{headers}");
    assert!(headers.contains("Max-Age=0"), "{headers}");
    assert_eq!(
        e6ircd::db::session_account(&pool, &current)
            .await
            .expect("current revoked"),
        None
    );
}

/// The console Integrations page is admin-gated and lists every chat-platform
/// bridge with build availability matching the exact feature configuration.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn console_integrations_page_lists_platforms_for_admins_only() {
    let url = support::test_db("console_integrations_page_lists_platforms_for_admins_only").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("alice");
    e6ircd::db::create_account_with_contact(&pool, "bob", "pw", None)
        .await
        .expect("bob");
    let alice_token = issue_api_token(&pool, "alice", "t").await.expect("tok");
    let alice_session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("alice session");
    let bob_session = e6ircd::db::create_web_session(&pool, "bob", None)
        .await
        .expect("bob session");
    e6ircd::db::create_bnc_network(
        &pool,
        "alice",
        &e6ircd::db::BncNetworkRow {
            kind: e6ircd::config::NetworkKind::Matrix,
            name: "matrix-archive".into(),
            addr: "https://matrix.example".into(),
            tls: true,
            nick: "alice".into(),
            username: None,
            realname: None,
            autojoin: vec![],
            sasl_account: None,
            sasl_password_sealed: Some("enc:v1:test".into()),
            enabled: false,
            server_password_sealed: None,
        },
        e6ircd::db::NetworkAudit {
            actor: "alice",
            detail: "",
        },
    )
    .await
    .expect("disabled bridge");
    drop(pool);

    let config = Config {
        server_name: "irc.console.example".into(),
        network_name: "ConsoleNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec!["alice".into()],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");

    let page = |session: &str| {
        format!(
            "GET /console/integrations HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
        )
    };
    // Anonymous -> redirect to /login.
    let (status, head, _) = request(http, &get("/console/integrations")).await;
    assert_eq!(status, 303, "{head}");
    // Signed-in non-admin -> 403.
    let (status, _, _) = request(http, &page(&bob_session)).await;
    assert_eq!(status, 403);
    // Admin -> 200 with static bridge capabilities; the stored bridge inventory
    // is hydrated from the administrator API rather than rendered into HTML.
    let (status, _, body) = request(http, &page(&alice_session)).await;
    assert_eq!(status, 200, "{body}");
    for needle in [
        "Integrations",
        "Matrix",
        "Discord",
        "Slack",
        "data-api-integrations",
        "Loading Matrix bridges",
    ] {
        assert!(
            body.contains(needle),
            "integrations missing {needle:?}: {body}"
        );
    }
    assert!(
        !body.contains("/console/integrations/matrix-archive"),
        "{body}"
    );
    let inventory = format!(
        "GET /api/v1/admin/networks HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {alice_token}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, inventory) = request(http, &inventory).await;
    assert_eq!(status, 200, "{inventory}");
    assert!(inventory.contains("matrix-archive"), "{inventory}");
    let built = [
        cfg!(feature = "matrix"),
        cfg!(feature = "discord"),
        cfg!(feature = "slack"),
    ]
    .into_iter()
    .filter(|enabled| *enabled)
    .count();
    assert_eq!(body.matches(">built in<").count(), built, "{body}");
    assert_eq!(body.matches(">not built<").count(), 3 - built, "{body}");
}

/// Adding a bridge from the console is admin + CSRF gated and follows the
/// selected kind's compile-time availability. A build without Matrix refuses
/// it at the feature gate; a Matrix build reaches the shared create path and
/// fails loudly because this fixture deliberately has no token-sealing key.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn console_add_bridge_is_gated_and_feature_checked() {
    let url = support::test_db("console_add_bridge_is_gated_and_feature_checked").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("alice");
    let session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("session");
    e6ircd::db::create_bnc_network(
        &pool,
        "alice",
        &e6ircd::db::BncNetworkRow {
            kind: e6ircd::config::NetworkKind::Matrix,
            name: "paused".into(),
            addr: "https://matrix.example".into(),
            tls: true,
            nick: "alice".into(),
            username: None,
            realname: None,
            autojoin: vec![],
            sasl_account: None,
            sasl_password_sealed: Some("enc:v1:test".into()),
            enabled: false,
            server_password_sealed: None,
        },
        e6ircd::db::NetworkAudit {
            actor: "alice",
            detail: "",
        },
    )
    .await
    .expect("paused bridge");
    drop(pool);

    let config = Config {
        server_name: "irc.console.example".into(),
        network_name: "ConsoleNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec!["alice".into()],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url: url.clone(),
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }),
        internal_upstreams: e6ircd::egress::InternalUpstreams::Allow,
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");

    // The CSRF token is session-bound; read it from the account page.
    let page = format!(
        "GET /console/account HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (_, _, body) = request(http, &page).await;
    let csrf = csrf_from_html(&body).to_string();

    let toggle = format!("csrf={csrf}&name=paused&enabled=false");
    let toggle_post = format!(
        "POST /console/integrations/toggle HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{toggle}",
        toggle.len()
    );
    let (status, headers, _) = request(http, &toggle_post).await;
    assert_eq!(status, 404, "{headers}");

    // Enabling requires constructing the prospective driver before the durable
    // flag changes. This row cannot be built (missing feature or master key), so
    // the exact failure is rendered and storage remains disabled—no compensating
    // rollback window can leave it marked enabled without a driver.
    let enable = format!("csrf={csrf}&name=paused&enabled=true");
    let enable_post = format!(
        "POST /console/integrations/toggle HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{enable}",
        enable.len()
    );
    let (status, _, body) = request(http, &enable_post).await;
    assert_eq!(status, 404, "{body}");
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("reconnect");
    let paused = e6ircd::db::get_bnc_network(&pool, "alice", "paused")
        .await
        .expect("read paused bridge")
        .expect("paused bridge still exists");
    assert!(
        !paused.enabled,
        "failed enable must not change durable state"
    );
    drop(pool);

    let form = format!(
        "csrf={csrf}&kind=matrix&name=hq&addr=https://matrix.example&nick=e6bot&sasl_password=secret"
    );
    let post = format!(
        "POST /console/integrations HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{form}",
        form.len()
    );
    let (status, _, body) = request(http, &post).await;
    assert_eq!(status, 405, "{body}");

    // Removed form routes do not reach CSRF dispatch.
    let form_nocsrf = "csrf=wrong&kind=matrix&name=hq&sasl_password=x";
    let post_nocsrf = format!(
        "POST /console/integrations HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{form_nocsrf}",
        form_nocsrf.len()
    );
    let (status, _, _) = request(http, &post_nocsrf).await;
    assert_eq!(status, 405);
}

/// The all-feature database lane proves the complete bridge management
/// contract: the console never renders tokens, edits each platform with its
/// exact field shape, partial Slack replacement preserves the other ciphertext,
/// and the REST surface uses the same validation and storage transition.
#[cfg(all(
    feature = "matrix",
    feature = "discord",
    feature = "slack",
    feature = "embed-web"
))]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn bridge_edit_ui_and_api_manage_every_platform_without_exposing_secrets() {
    let url =
        support::test_db("bridge_edit_ui_and_api_manage_every_platform_without_exposing_secrets")
            .await;
    let secret_key = e6ircd::secret::SecretKey::generate();
    let key_path = temporary_path("bridge-edit-key");
    std::fs::write(&key_path, secret_key.to_base64()).expect("write test key");
    let _key_file = TemporaryFile(key_path.clone());
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("alice");
    let session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("session");
    let api_token = issue_api_token(&pool, "alice", "bridge-edit")
        .await
        .expect("API token");
    let context = e6ircd::bouncer::bnc_secret_context("alice");
    let matrix_password = secret_key.seal("matrix-old-password", &context);
    let discord_token = secret_key.seal("discord-old-token", &context);
    let slack_bot_token = secret_key.seal("slack-old-bot", &context);
    let slack_app_token = secret_key.seal("slack-old-app", &context);
    for row in [
        e6ircd::db::BncNetworkRow {
            kind: e6ircd::config::NetworkKind::Matrix,
            name: "matrix-main".into(),
            addr: "https://matrix.old.example".into(),
            tls: true,
            nick: "@alice:old.example".into(),
            username: None,
            realname: None,
            autojoin: vec!["!old:example".into()],
            sasl_account: None,
            sasl_password_sealed: Some(matrix_password),
            enabled: false,
            server_password_sealed: None,
        },
        e6ircd::db::BncNetworkRow {
            kind: e6ircd::config::NetworkKind::Discord,
            name: "discord-main".into(),
            addr: String::new(),
            tls: true,
            nick: String::new(),
            username: None,
            realname: None,
            autojoin: vec!["100".into()],
            sasl_account: None,
            sasl_password_sealed: Some(discord_token),
            enabled: false,
            server_password_sealed: None,
        },
        e6ircd::db::BncNetworkRow {
            kind: e6ircd::config::NetworkKind::Slack,
            name: "slack-main".into(),
            addr: String::new(),
            tls: true,
            nick: String::new(),
            username: None,
            realname: None,
            autojoin: vec!["C100".into()],
            sasl_account: Some(slack_bot_token.clone()),
            sasl_password_sealed: Some(slack_app_token),
            enabled: false,
            server_password_sealed: None,
        },
    ] {
        e6ircd::db::create_bnc_network(
            &pool,
            "alice",
            &row,
            e6ircd::db::NetworkAudit {
                actor: "alice",
                detail: "",
            },
        )
        .await
        .expect("create bridge fixture");
    }
    drop(pool);

    let running = net::start(Config {
        server_name: "irc.bridge-edit.example".into(),
        network_name: "BridgeEditNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec!["alice".into()],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url: url.clone(),
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }),
        secrets: Some(SecretsConfig {
            key_file: key_path,
            previous_key_files: Vec::new(),
        }),
        internal_upstreams: e6ircd::egress::InternalUpstreams::Allow,
        ..Config::default()
    })
    .await
    .expect("start");
    let http = running.http_addr.expect("http");
    let cookie = |path: &str| {
        format!(
            "GET {path} HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
        )
    };
    let (status, _, integrations) = request(http, &cookie("/console/integrations")).await;
    assert_eq!(status, 200, "{integrations}");
    assert!(
        integrations.contains("data-api-integrations"),
        "{integrations}"
    );
    for name in ["matrix-main", "discord-main", "slack-main"] {
        assert!(
            !integrations.contains(&format!("/console/integrations/{name}")),
            "{integrations}"
        );
    }
    let inventory = format!(
        "GET /api/v1/admin/networks HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {api_token}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, inventory) = request(http, &inventory).await;
    assert_eq!(status, 200, "{inventory}");
    for name in ["matrix-main", "discord-main", "slack-main"] {
        assert!(inventory.contains(name), "{inventory}");
    }

    let (status, _, matrix_form) =
        request(http, &cookie("/console/integrations/matrix-main/edit")).await;
    assert_eq!(status, 200, "{matrix_form}");
    assert!(matrix_form.contains("data-api-owner-bridge-editor"));
    assert!(matrix_form.contains("Loading integration…"));
    assert!(!matrix_form.contains("https://matrix.old.example"));
    assert!(!matrix_form.contains("@alice:old.example"));
    assert!(!matrix_form.contains("matrix-old-password"));

    let (_, _, account_page) = request(http, &cookie("/console/account")).await;
    let csrf = csrf_from_html(&account_page).to_string();
    let matrix_update = serde_json::json!({
        "addr": "https://matrix.new.example",
        "tls": true,
        "nick": "@alice:new.example",
        "autojoin": ["!one:new.example", "!two:new.example"],
        "credentials": { "action": "set", "password": "matrix-new-password" },
        "server_password": { "action": "keep" }
    })
    .to_string();
    let matrix_request = format!(
        "PUT /api/v1/me/networks/matrix-main HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {api_token}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{matrix_update}",
        matrix_update.len()
    );
    let (status, headers, body) = request(http, &matrix_request).await;
    assert_eq!(status, 204, "{headers}\n{body}");

    let discord_json = serde_json::json!({
        "addr": "https://discord-api.example/v10/",
        "tls": true,
        "nick": "",
        "autojoin": ["200", "201"],
        "credentials": { "action": "set", "password": "discord-new-token" },
        "server_password": { "action": "keep" }
    })
    .to_string();
    let discord_put = format!(
        "PUT /api/v1/me/networks/discord-main HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {api_token}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{discord_json}",
        discord_json.len()
    );
    let (status, headers, body) = request(http, &discord_put).await;
    assert_eq!(status, 204, "{headers}\n{body}");

    // Only the Slack app token is replaced. The bot-token ciphertext must stay
    // byte-for-byte identical, proving omission means keep rather than reseal.
    let slack_update = serde_json::json!({
        "addr": "",
        "tls": true,
        "nick": "",
        "autojoin": ["C200", "C201"],
        "credentials": { "action": "set", "password": "slack-new-app" },
        "server_password": { "action": "keep" }
    })
    .to_string();
    let slack_request = format!(
        "PUT /api/v1/me/networks/slack-main HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {api_token}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{slack_update}",
        slack_update.len()
    );
    let (status, headers, body) = request(http, &slack_request).await;
    assert_eq!(status, 204, "{headers}\n{body}");

    let verification = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("verification connection");
    let matrix = e6ircd::db::get_bnc_network(&verification, "alice", "matrix-main")
        .await
        .expect("matrix read")
        .expect("matrix row");
    assert_eq!(matrix.addr, "https://matrix.new.example");
    assert_eq!(matrix.nick, "@alice:new.example");
    assert_eq!(matrix.autojoin, ["!one:new.example", "!two:new.example"]);
    assert_eq!(
        secret_key
            .open(
                matrix
                    .sasl_password_sealed
                    .as_deref()
                    .expect("matrix secret"),
                &context,
            )
            .expect("open matrix secret"),
        "matrix-new-password"
    );
    let discord = e6ircd::db::get_bnc_network(&verification, "alice", "discord-main")
        .await
        .expect("discord read")
        .expect("discord row");
    assert_eq!(discord.addr, "https://discord-api.example/v10/");
    assert_eq!(discord.autojoin, ["200", "201"]);
    assert_eq!(
        secret_key
            .open(
                discord
                    .sasl_password_sealed
                    .as_deref()
                    .expect("discord token"),
                &context,
            )
            .expect("open Discord token"),
        "discord-new-token"
    );
    let slack = e6ircd::db::get_bnc_network(&verification, "alice", "slack-main")
        .await
        .expect("slack read")
        .expect("slack row");
    assert_eq!(
        slack.sasl_account.as_deref(),
        Some(slack_bot_token.as_str())
    );
    assert_eq!(slack.autojoin, ["C200", "C201"]);
    assert_eq!(
        secret_key
            .open(
                slack
                    .sasl_password_sealed
                    .as_deref()
                    .expect("Slack app token"),
                &context,
            )
            .expect("open Slack app token"),
        "slack-new-app"
    );

    // A malformed replacement is rendered next to the submitted non-secret
    // fields, never echoes its submitted token, and cannot alter durable state.
    let invalid_update = serde_json::json!({
        "addr": "ftp://matrix.invalid",
        "tls": true,
        "nick": "@alice:new.example",
        "autojoin": [],
        "credentials": { "action": "set", "password": "do-not-echo" },
        "server_password": { "action": "keep" }
    })
    .to_string();
    let invalid_request = format!(
        "PUT /api/v1/me/networks/matrix-main HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {api_token}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{invalid_update}",
        invalid_update.len()
    );
    let (status, _, body) = request(http, &invalid_request).await;
    assert_eq!(status, 400, "{body}");
    assert!(!body.contains("do-not-echo"), "{body}");
    let unchanged = e6ircd::db::get_bnc_network(&verification, "alice", "matrix-main")
        .await
        .expect("unchanged read")
        .expect("unchanged row");
    assert_eq!(unchanged.addr, "https://matrix.new.example");

    // The bridge-specific delete route cannot be used to delete an IRC row.
    let irc = e6ircd::db::BncNetworkRow {
        kind: e6ircd::config::NetworkKind::Irc,
        name: "irc-main".into(),
        addr: "irc.example:6697".into(),
        tls: true,
        nick: "alice".into(),
        username: Some("tester".into()),
        realname: Some("Alice".into()),
        autojoin: vec![],
        sasl_account: None,
        sasl_password_sealed: None,
        enabled: false,
        server_password_sealed: None,
    };
    e6ircd::db::create_bnc_network(
        &verification,
        "alice",
        &irc,
        e6ircd::db::NetworkAudit {
            actor: "alice",
            detail: "",
        },
    )
    .await
    .expect("IRC fixture");
    let delete_fields = format!("csrf={csrf}&name=irc-main");
    let delete_post = format!(
        "POST /console/integrations/delete HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{delete_fields}",
        delete_fields.len()
    );
    let (status, _, body) = request(http, &delete_post).await;
    assert_eq!(status, 404, "{body}");
    assert!(
        e6ircd::db::get_bnc_network(&verification, "alice", "irc-main")
            .await
            .expect("IRC read")
            .is_some()
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn account_console_manages_credentials_tokens_and_identities() {
    let url = support::test_db("account_console_manages_credentials_tokens_and_identities").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("acct");
    e6ircd::db::link_oidc_identity(&pool, "alice", "https://idp.example", "alice-primary")
        .await
        .expect("primary identity");
    e6ircd::db::link_oidc_identity(&pool, "alice", "https://idp.example", "alice-secondary")
        .await
        .expect("secondary identity");
    let session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("session");

    let config = Config {
        server_name: "irc.form.example".into(),
        network_name: "FormNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }),
        internal_upstreams: e6ircd::egress::InternalUpstreams::Allow,
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");

    // The account console is a static API client: private credentials and OIDC
    // identities must never be embedded in the document before its API reads.
    let page_req = format!(
        "GET /console/account HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, headers, page) = request(http, &page_req).await;
    assert_eq!(status, 200, "{headers}");
    assert!(page.contains("data-api-account-read"), "{page}");
    assert!(page.contains("data-api-account-credential-list"), "{page}");
    assert!(page.contains("data-api-account-identity-list"), "{page}");
    assert!(!page.contains("alice-primary"), "{page}");
    assert!(!page.contains("alice-secondary"), "{page}");
    let csrf = csrf_from_html(&page).to_string();
    assert!(!csrf.is_empty());

    assert!(page.contains("data-api-account-profile"), "{page}");
    assert!(page.contains("data-api-account-app-password"), "{page}");
    assert!(
        page.contains("data-api-account-security-activity-list"),
        "{page}"
    );
    assert!(page.contains("data-api-account-read-marker-list"), "{page}");
    assert!(page.contains("data-api-account-token-list"), "{page}");
    let initial_profile = r#"{"contact_email":"Alice+IRC@Example.COM"}"#;
    let update_contact = format!(
        "PATCH /api/v1/me/profile HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-E6IRC-CSRF: {csrf}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{initial_profile}",
        initial_profile.len()
    );
    let (status, _, body) = request(http, &update_contact).await;
    assert_eq!(status, 204, "{body}");
    assert_eq!(
        e6ircd::db::account_contact_email(&pool, "alice")
            .await
            .expect("contact email"),
        Some("Alice+IRC@example.com".into())
    );
    let profile_get = format!(
        "GET /api/v1/me/profile HTTP/1.1\r\nHost: t\r\n\
         Cookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, headers, body) = request(http, &profile_get).await;
    assert_eq!(status, 200, "{body}");
    assert!(headers.contains("cache-control: no-store"), "{headers}");
    let profile: serde_json::Value = serde_json::from_str(&body).expect("private profile");
    assert_eq!(profile["account"], "alice");
    assert_eq!(profile["contact_email"], "Alice+IRC@example.com");

    let missing_profile_field = "{}";
    let missing_profile_field_request = format!(
        "PATCH /api/v1/me/profile HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-E6IRC-CSRF: {csrf}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{missing_profile_field}",
        missing_profile_field.len()
    );
    let (status, _, body) = request(http, &missing_profile_field_request).await;
    assert_eq!(
        status, 400,
        "a profile update must name contact_email: {body}"
    );
    assert_eq!(
        e6ircd::db::account_contact_email(&pool, "alice")
            .await
            .expect("contact email after rejected update"),
        Some("Alice+IRC@example.com".into())
    );

    let api_profile = r#"{"contact_email":"Second@New.Example"}"#;
    let missing_csrf = format!(
        "PATCH /api/v1/me/profile HTTP/1.1\r\nHost: t\r\n\
         Cookie: e6irc_session={session}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{api_profile}",
        api_profile.len()
    );
    let (status, _, body) = request(http, &missing_csrf).await;
    assert_eq!(status, 403, "{body}");
    let patch_profile = format!(
        "PATCH /api/v1/me/profile HTTP/1.1\r\nHost: t\r\n\
         Cookie: e6irc_session={session}\r\nX-E6IRC-CSRF: {csrf}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{api_profile}",
        api_profile.len()
    );
    let (status, _, body) = request(http, &patch_profile).await;
    assert_eq!(status, 204, "{body}");
    assert_eq!(
        e6ircd::db::account_contact_email(&pool, "alice")
            .await
            .expect("updated contact email"),
        Some("Second@new.example".into())
    );

    let api_password = r#"{"current_password":"pw","new_password":"api-pw"}"#;
    let api_change_without_csrf = format!(
        "PUT /api/v1/me/password HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{api_password}",
        api_password.len()
    );
    let (status, _, body) = request(http, &api_change_without_csrf).await;
    assert_eq!(status, 403, "{body}");
    let api_change = format!(
        "PUT /api/v1/me/password HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-E6IRC-CSRF: {csrf}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{api_password}",
        api_password.len()
    );
    let (status, _, body) = request(http, &api_change).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains(
            "Other browser sessions were signed out; app passwords and access tokens are unchanged"
        ),
        "{body}"
    );
    assert_eq!(
        e6ircd::db::verify_local_password(&pool, "alice", "api-pw")
            .await
            .expect("API password verify"),
        Some("alice".into())
    );

    let app_body = r#"{"label":"Laptop"}"#;
    let create_app_without_csrf = format!(
        "POST /api/v1/me/credentials HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{app_body}",
        app_body.len()
    );
    let (status, _, body) = request(http, &create_app_without_csrf).await;
    assert_eq!(status, 403, "{body}");
    let create_app = format!(
        "POST /api/v1/me/credentials HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-E6IRC-CSRF: {csrf}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{app_body}",
        app_body.len()
    );
    let (status, headers, body) = request(http, &create_app).await;
    assert_eq!(status, 201, "{body}");
    // The secret is shown exactly once; no cache may keep a second copy.
    assert_eq!(
        response_header(&headers, "cache-control"),
        Some("no-store"),
        "{headers}"
    );
    assert!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["app_password"]
            .as_str()
            .is_some_and(|secret| !secret.is_empty()),
        "{body}"
    );
    let credentials = e6ircd::db::list_credentials(&pool, "alice")
        .await
        .expect("credentials");
    let app_id = credentials
        .iter()
        .find(|row| row.kind == "app_password" && row.label.as_deref() == Some("Laptop"))
        .map(|row| row.id)
        .expect("created app password");

    let token_body = r#"{"label":"Automation","expires_in_days":90,"scopes":["read","irc"]}"#;
    let create_token = format!(
        "POST /api/v1/me/tokens HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-E6IRC-CSRF: {csrf}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{token_body}",
        token_body.len()
    );
    let (status, headers, body) = request(http, &create_token).await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(
        response_header(&headers, "cache-control"),
        Some("no-store"),
        "{headers}"
    );
    assert!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["token"]
            .as_str()
            .is_some_and(|secret| secret.starts_with("e6p_")),
        "{body}"
    );
    let tokens = e6ircd::db::list_api_tokens(&pool, "alice")
        .await
        .expect("tokens");
    let token_id = tokens
        .iter()
        .find(|row| row.label == "Automation")
        .map(|row| row.id)
        .expect("created token");
    let token = tokens
        .iter()
        .find(|row| row.id == token_id)
        .expect("created token metadata");
    assert!(token.scopes.contains(e6ircd::identity::ApiTokenScope::Read));
    assert!(token.scopes.contains(e6ircd::identity::ApiTokenScope::Irc));
    assert!(
        !token
            .scopes
            .contains(e6ircd::identity::ApiTokenScope::Write)
    );

    let bad_body = r#"{"label":"Rejected","expires_in_days":30,"scopes":["read"]}"#;
    let bad_create = format!(
        "POST /api/v1/me/tokens HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{bad_body}",
        bad_body.len()
    );
    let (status, _, _) = request(http, &bad_create).await;
    assert_eq!(status, 403);

    for (path, id) in [
        ("/api/v1/me/credentials", app_id),
        ("/api/v1/me/tokens", token_id),
    ] {
        let revoke = format!(
            "DELETE {path}/{id} HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
             X-E6IRC-CSRF: {csrf}\r\nConnection: close\r\n\r\n"
        );
        let (status, _, body) = request(http, &revoke).await;
        assert_eq!(status, 204, "{body}");
    }
    assert!(
        e6ircd::db::list_credentials(&pool, "alice")
            .await
            .expect("credentials after revoke")
            .iter()
            .all(|row| row.id != app_id)
    );
    assert!(
        e6ircd::db::list_api_tokens(&pool, "alice")
            .await
            .expect("tokens after revoke")
            .iter()
            .all(|row| row.id != token_id)
    );

    let identities = e6ircd::db::list_oidc_identities(&pool, "alice")
        .await
        .expect("identities");
    let unlink_id = identities
        .iter()
        .find(|row| row.subject == "alice-secondary")
        .map(|row| row.id)
        .expect("secondary identity");
    let unlink = format!(
        "DELETE /api/v1/me/identities/{unlink_id} HTTP/1.1\r\nHost: t\r\n\
         Cookie: e6irc_session={session}\r\nX-E6IRC-CSRF: {csrf}\r\nConnection: close\r\n\r\n"
    );
    let (status, headers, body) = request(http, &unlink).await;
    assert_eq!(status, 204, "{headers}: {body}");
    assert!(
        !headers.contains("Max-Age=0"),
        "a valid local session must not be cleared: {headers}"
    );

    let remaining = e6ircd::db::list_oidc_identities(&pool, "alice")
        .await
        .expect("remaining identity");
    assert_eq!(remaining.len(), 1);
    let last_delete = format!(
        "DELETE /api/v1/me/identities/{} HTTP/1.1\r\nHost: t\r\n\
         Cookie: e6irc_session={session}\r\nX-E6IRC-CSRF: {csrf}\r\n\
         Connection: close\r\n\r\n",
        remaining[0].id
    );
    let (status, _, body) = request(http, &last_delete).await;
    assert_eq!(status, 204, "{body}");
    assert!(
        e6ircd::db::list_oidc_identities(&pool, "alice")
            .await
            .expect("identities after final unlink")
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn device_authorization_grant_flow() {
    let url = support::test_db("device_authorization_grant_flow").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("acct");
    let session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("session");
    let bearer = issue_api_token(&pool, "alice", "device approval")
        .await
        .expect("bearer");
    drop(pool);

    let config = Config {
        server_name: "irc.dev.example".into(),
        network_name: "DevNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: Some("http://e6.example".into()),
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url: url.clone(),
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");

    let post = |path: &str, hdrs: &str, body: &str| {
        format!(
            "POST {path} HTTP/1.1\r\nHost: t\r\n{hdrs}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    };

    // start
    let (status, _, body) = request(http, &post("/api/v1/auth/device/start", "", "")).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let device_code = v["device_code"].as_str().unwrap().to_string();
    let user_code = v["user_code"].as_str().unwrap().to_string();
    assert_eq!(
        v["verification_uri"].as_str(),
        Some("http://e6.example/device")
    );

    let (status, _, _) = request(
        http,
        &post(
            "/api/v1/auth/device/token",
            "",
            &format!(r#"{{"device_code":"{device_code}","extra":true}}"#),
        ),
    )
    .await;
    assert_eq!(status, 400, "unknown device-token fields must be rejected");

    // poll before approval -> authorization_pending
    let tok_body = format!(r#"{{"device_code":"{device_code}"}}"#);
    let (status, _, body) = request(http, &post("/api/v1/auth/device/token", "", &tok_body)).await;
    assert_eq!(status, 400);
    assert!(body.contains("authorization_pending"), "{body}");

    // approve as alice (cookie), lowercased to prove normalization
    let ap_body = format!(r#"{{"user_code":"{}"}}"#, user_code.to_lowercase());
    let cookie = format!("Cookie: e6irc_session={session}\r\n");
    let me_request =
        format!("GET /api/v1/me HTTP/1.1\r\nHost: t\r\n{cookie}Connection: close\r\n\r\n");
    let (status, _, me_body) = request(http, &me_request).await;
    assert_eq!(status, 200, "{me_body}");
    let me_json: serde_json::Value = serde_json::from_str(&me_body).expect("me JSON");
    let csrf = me_json["csrf_token"].as_str().expect("session CSRF token");
    let browser_headers = format!("{cookie}X-E6IRC-CSRF: {csrf}\r\n");
    let (status, _, _) = request(
        http,
        &post("/api/v1/auth/device/approve", &cookie, &ap_body),
    )
    .await;
    assert_eq!(
        status, 403,
        "device approval requires the session CSRF token"
    );
    let (status, _, _) = request(
        http,
        &post(
            "/api/v1/auth/device/approve",
            &format!("Authorization: Bearer {bearer}\r\n"),
            &ap_body,
        ),
    )
    .await;
    assert_eq!(status, 401, "a bearer cannot approve a device grant");
    let (status, _, _) = request(
        http,
        &post(
            "/api/v1/auth/device/approve",
            &browser_headers,
            &format!(r#"{{"user_code":"{user_code}","extra":true}}"#),
        ),
    )
    .await;
    assert_eq!(
        status, 400,
        "unknown device-approval fields must be rejected"
    );
    let (status, _, _) = request(
        http,
        &post("/api/v1/auth/device/approve", &browser_headers, &ap_body),
    )
    .await;
    assert_eq!(status, 204);

    // poll after approval -> access_token
    let (status, _, body) = request(http, &post("/api/v1/auth/device/token", "", &tok_body)).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let token = v["access_token"].as_str().unwrap().to_string();

    // the minted token works as a PAT
    let me = format!(
        "GET /api/v1/me HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, body) = request(http, &me).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("alice"), "{body}");

    // grant consumed: polling again is invalid_grant
    let (status, _, body) = request(http, &post("/api/v1/auth/device/token", "", &tok_body)).await;
    assert_eq!(status, 400);
    assert!(body.contains("invalid_grant"), "{body}");

    // A device polling past expiry is told `expired_token` (RFC 8628 §3.5),
    // even after another start has run the expired-grant pruning.
    let (status, _, body) = request(http, &post("/api/v1/auth/device/start", "", "")).await;
    assert_eq!(status, 200, "{body}");
    let lapsed: serde_json::Value = serde_json::from_str(&body).expect("json");
    let lapsed_code = lapsed["device_code"].as_str().unwrap().to_string();
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    sqlx::query(
        "UPDATE device_grants SET expires_at = now() - interval '1 second'
         WHERE device_code = $1",
    )
    .bind(&lapsed_code)
    .execute(&pool)
    .await
    .expect("expire grant");
    let (status, _, body) = request(http, &post("/api/v1/auth/device/start", "", "")).await;
    assert_eq!(status, 200, "{body}");
    let lapsed_poll = format!(r#"{{"device_code":"{lapsed_code}"}}"#);
    let (status, _, body) =
        request(http, &post("/api/v1/auth/device/token", "", &lapsed_poll)).await;
    assert_eq!(status, 400);
    assert!(body.contains("expired_token"), "{body}");

    // A device token counts toward the per-account cap like any other. A grant
    // approved while a slot was free, then beaten to it, is denied once.
    let start_grant = || async {
        let (status, _, body) = request(http, &post("/api/v1/auth/device/start", "", "")).await;
        assert_eq!(status, 200, "{body}");
        let started: serde_json::Value = serde_json::from_str(&body).expect("json");
        (
            format!(
                r#"{{"device_code":"{}"}}"#,
                started["device_code"].as_str().unwrap()
            ),
            format!(
                r#"{{"user_code":"{}"}}"#,
                started["user_code"].as_str().unwrap()
            ),
        )
    };
    let (raced_poll, raced_approval) = start_grant().await;
    let (status, _, body) = request(
        http,
        &post(
            "/api/v1/auth/device/approve",
            &browser_headers,
            &raced_approval,
        ),
    )
    .await;
    assert_eq!(status, 204, "{body}");
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    // alice holds the approving bearer and the first device token.
    for index in 2..32 {
        e6ircd::db::issue_scoped_api_token(
            &pool,
            "alice",
            &format!("filler {index}"),
            e6ircd::identity::ApiTokenScopes::new(e6ircd::identity::ApiTokenScope::ALL)
                .expect("every scope is a non-empty set"),
            e6ircd::identity::ApiTokenLifetimeDays::DEFAULT,
        )
        .await
        .expect("under the cap");
    }
    let (status, _, body) =
        request(http, &post("/api/v1/auth/device/token", "", &raced_poll)).await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("access_denied"), "{body}");
    let (status, _, body) =
        request(http, &post("/api/v1/auth/device/token", "", &raced_poll)).await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body.contains("invalid_grant"),
        "a denied grant is consumed: {body}"
    );

    let (_, refused_approval) = start_grant().await;
    let (status, _, body) = request(
        http,
        &post(
            "/api/v1/auth/device/approve",
            &browser_headers,
            &refused_approval,
        ),
    )
    .await;
    assert_eq!(status, 409, "{body}");
    assert!(body.contains("Revoke one"), "{body}");

    // The verification page the start response advertises must actually
    // exist (it 404'd for 72 sweeps): unauthenticated → login redirect.
    let (status, headers, _) = request(
        http,
        "GET /device HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 303, "unauthenticated /device must redirect");
    assert!(
        headers.to_lowercase().contains("location: /login"),
        "{headers}"
    );

    // Signed in: the page renders the code form with a CSRF token.
    let (status, _, page) = request(
        http,
        &format!("GET /device HTTP/1.1\r\nHost: t\r\n{cookie}Connection: close\r\n\r\n"),
    )
    .await;
    assert_eq!(status, 200, "{page}");
    assert!(page.contains("name=\"user_code\""), "{page}");
    assert!(page.contains("Device code"), "{page}");
    let csrf = page
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .expect("csrf field")
        .split('"')
        .next()
        .expect("csrf value")
        .to_string();

    // At the cap the verification page says why, in the browser that can act.
    let refused_user_code = refused_approval
        .split('"')
        .nth(3)
        .expect("user code")
        .to_string();
    let form = format!("user_code={refused_user_code}&csrf={csrf}");
    let (status, _, page) = request(
        http,
        &format!(
            "POST /device HTTP/1.1\r\nHost: t\r\n{cookie}Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{form}",
            form.len()
        ),
    )
    .await;
    assert_eq!(status, 200, "{page}");
    assert!(page.contains("Revoke one"), "{page}");
    assert!(!page.contains("Device approved"), "{page}");
    sqlx::query("DELETE FROM api_tokens WHERE label LIKE 'filler %'")
        .execute(&pool)
        .await
        .expect("revoke the fillers");
    drop(pool);

    // A second grant, approved end-to-end through the page's form (lowercase
    // to prove the same normalization as the JSON path).
    let (status, _, body) = request(http, &post("/api/v1/auth/device/start", "", "")).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let device_code2 = v["device_code"].as_str().unwrap().to_string();
    let user_code2 = v["user_code"].as_str().unwrap().to_lowercase();
    let form = format!("user_code={user_code2}&csrf={csrf}");
    let (status, _, page) = request(
        http,
        &format!(
            "POST /device HTTP/1.1\r\nHost: t\r\n{cookie}Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{form}",
            form.len()
        ),
    )
    .await;
    assert_eq!(status, 200, "{page}");
    assert!(page.contains("Device approved"), "{page}");
    // ...and a bad CSRF token is refused.
    let bad = format!("user_code={user_code2}&csrf=bogus");
    let (status, _, _) = request(
        http,
        &format!(
            "POST /device HTTP/1.1\r\nHost: t\r\n{cookie}Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{bad}",
            bad.len()
        ),
    )
    .await;
    assert_eq!(status, 403);
    let tok_body2 = format!(r#"{{"device_code":"{device_code2}"}}"#);
    let (status, _, body) = request(http, &post("/api/v1/auth/device/token", "", &tok_body2)).await;
    assert_eq!(status, 200, "form-approved grant must mint: {body}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn me_tokens_list_and_revoke() {
    let url = support::test_db("me_tokens_list_and_revoke").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("alice");
    let auth_token = issue_api_token(&pool, "alice", "auth").await.expect("t");
    let _extra = issue_api_token(&pool, "alice", "todelete")
        .await
        .expect("t2");
    drop(pool);

    let config = Config {
        server_name: "irc.tok.example".into(),
        network_name: "TokNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");

    let auth = |method: &str, path: &str| {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {auth_token}\r\nConnection: close\r\n\r\n"
        )
    };
    // List shows both tokens.
    let (status, _, body) = request(http, &auth("GET", "/api/v1/me/tokens")).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let tokens = v["tokens"].as_array().expect("array");
    assert_eq!(tokens.len(), 2, "{body}");
    let del_id = tokens
        .iter()
        .find(|t| t["label"] == "todelete")
        .and_then(|t| t["id"].as_i64())
        .expect("todelete id");

    // Revoke the other token → 204, then the list has one left.
    let (status, _, _) = request(
        http,
        &auth("DELETE", &format!("/api/v1/me/tokens/{del_id}")),
    )
    .await;
    assert_eq!(status, 204);
    let (_, _, body) = request(http, &auth("GET", "/api/v1/me/tokens")).await;
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["tokens"].as_array().unwrap().len(), 1, "{body}");

    // Revoking an unknown id → 404.
    let (status, _, _) = request(http, &auth("DELETE", "/api/v1/me/tokens/999999")).await;
    assert_eq!(status, 404);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn personal_access_token_scopes_gate_reads_writes_admin_and_irc() {
    use e6ircd::identity::{ApiTokenLifetimeDays, ApiTokenScope, ApiTokenScopes};

    let url =
        support::test_db("personal_access_token_scopes_gate_reads_writes_admin_and_irc").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("alice");
    let lifetime = ApiTokenLifetimeDays::new(7).expect("bounded lifetime");
    let read = e6ircd::db::issue_scoped_api_token(
        &pool,
        "alice",
        "read",
        ApiTokenScopes::new([ApiTokenScope::Read]).expect("scope"),
        lifetime,
    )
    .await
    .expect("read token");
    let write = e6ircd::db::issue_scoped_api_token(
        &pool,
        "alice",
        "write",
        ApiTokenScopes::new([ApiTokenScope::Write]).expect("scope"),
        lifetime,
    )
    .await
    .expect("write token");
    let admin_read = e6ircd::db::issue_scoped_api_token(
        &pool,
        "alice",
        "admin read",
        ApiTokenScopes::new([ApiTokenScope::Read, ApiTokenScope::Administrator]).expect("scopes"),
        lifetime,
    )
    .await
    .expect("admin token");
    let irc = e6ircd::db::issue_scoped_api_token(
        &pool,
        "alice",
        "irc",
        ApiTokenScopes::new([ApiTokenScope::Irc]).expect("scope"),
        lifetime,
    )
    .await
    .expect("IRC token");
    assert_eq!(
        e6ircd::db::api_token_account(&pool, &read)
            .await
            .expect("read token lookup"),
        None,
        "a read-only API grant must not silently gain IRC authentication"
    );
    assert_eq!(
        e6ircd::db::api_token_account(&pool, &irc)
            .await
            .expect("IRC token lookup"),
        Some("alice".into())
    );
    drop(pool);

    let config = Config {
        server_name: "irc.scopes.example".into(),
        network_name: "ScopeNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec!["alice".into()],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");
    let bearer = |method: &str, path: &str, token: &str| {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        )
    };

    let (status, _, _) = request(http, &bearer("GET", "/api/v1/me", &read)).await;
    assert_eq!(status, 200);
    let (status, _, body) = request(http, &bearer("DELETE", "/api/v1/me/tokens/999", &read)).await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("write"), "{body}");

    let (status, _, body) = request(http, &bearer("GET", "/api/v1/me", &write)).await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("read"), "{body}");
    let token_body = r#"{"label":"scope escalation","scopes":["administrator"]}"#;
    let mint_with_bearer = format!(
        "POST /api/v1/me/tokens HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {write}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n\
         {token_body}",
        token_body.len()
    );
    let (status, _, body) = request(http, &mint_with_bearer).await;
    assert_eq!(status, 401, "{body}");
    assert!(
        body.contains("Browser session required"),
        "a narrow bearer must not mint a broader bearer: {body}"
    );

    let (status, _, body) = request(http, &bearer("GET", "/api/v1/admin/stats", &read)).await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("administrator"), "{body}");
    let (status, _, body) = request(http, &bearer("GET", "/api/v1/admin/stats", &admin_read)).await;
    assert_eq!(status, 200, "{body}");

    let (status, _, body) = request(http, &bearer("GET", "/api/v1/me", &irc)).await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("read"), "{body}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn authenticated_api_limit_is_per_account_shared_across_bearers_and_bounded() {
    let url = support::test_db(
        "authenticated_api_limit_is_per_account_shared_across_bearers_and_bounded",
    )
    .await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("alice");
    e6ircd::db::create_account_with_contact(&pool, "bob", "pw", None)
        .await
        .expect("bob");
    let alice_token = issue_api_token(&pool, "alice", "automation")
        .await
        .expect("Alice token");
    let alice_session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("Alice session");
    let bob_token = issue_api_token(&pool, "bob", "automation")
        .await
        .expect("Bob token");
    drop(pool);

    let config = Config {
        server_name: "irc.api-rate.example".into(),
        network_name: "RateNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        limits: e6ircd::config::LimitsConfig {
            api_rate_burst: 2,
            ..Default::default()
        },
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");
    let bearer = |token: &str| {
        format!(
            "GET /api/v1/me HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        )
    };
    let cookie = format!(
        "GET /api/v1/me HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={alice_session}\r\nConnection: close\r\n\r\n"
    );

    assert_eq!(request(http, &bearer(&alice_token)).await.0, 200);
    assert_eq!(
        request(http, &cookie).await.0,
        200,
        "cookie and token authentication share the same account budget"
    );
    let (status, headers, body) = request(http, &bearer(&alice_token)).await;
    assert_eq!(status, 429, "{body}");
    assert!(
        headers.to_ascii_lowercase().contains("retry-after:"),
        "{headers}"
    );
    assert_eq!(
        request(http, &bearer(&bob_token)).await.0,
        200,
        "another account has an independent bounded bucket"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn network_buffer_read() {
    let url = support::test_db("network_buffer_read").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("alice");
    let token = issue_api_token(&pool, "alice", "t").await.expect("token");
    // A network the caller owns, disabled so boot starts no driver — the
    // buffer read is pure DB and must work for a paused network too.
    e6ircd::db::create_bnc_network(
        &pool,
        "alice",
        &e6ircd::db::BncNetworkRow {
            kind: e6ircd::config::NetworkKind::Irc,
            name: "work".into(),
            addr: "127.0.0.1:1".into(),
            tls: false,
            nick: "alice_".into(),
            username: Some("tester".into()),
            realname: Some("Alice".into()),
            autojoin: vec![],
            sasl_account: None,
            sasl_password_sealed: None,
            enabled: false,
            server_password_sealed: None,
        },
        e6ircd::db::NetworkAudit {
            actor: "alice",
            detail: "",
        },
    )
    .await
    .expect("create");
    for line in [
        ":srv 001 alice :hi",
        ":a!u@h PRIVMSG #x :one",
        ":a!u@h PRIVMSG #x :two",
    ] {
        e6ircd::db::persist_bnc_line(
            &pool,
            &e6ircd::db::open_bnc_buffer(
                &pool,
                Some("alice"),
                "work",
                e6ircd::db::BncNetworkDefinition::Configured,
            )
            .await
            .expect("open buffer"),
            Some("alice"),
            line,
        )
        .await
        .expect("seed");
    }
    drop(pool);

    let config = Config {
        server_name: "irc.buf.example".into(),
        network_name: "BufNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }),
        internal_upstreams: e6ircd::egress::InternalUpstreams::Allow,
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");

    let auth = |path: &str| {
        format!(
            "GET {path} HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        )
    };
    // Full buffer, oldest-first.
    let (status, _, body) = request(http, &auth("/api/v1/me/networks/work/buffer")).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let lines = v["lines"].as_array().expect("array");
    assert_eq!(lines.len(), 3, "{body}");
    assert_eq!(lines[0], ":srv 001 alice :hi", "{body}");
    assert_eq!(lines[2], ":a!u@h PRIVMSG #x :two", "{body}");

    // The network lookup and buffer lookup use the same case-insensitive
    // selector: a URL case variant must not resolve the row and then miss its
    // canonically keyed backlog.
    let (status, _, body) = request(http, &auth("/api/v1/me/networks/WoRk/buffer")).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["lines"].as_array().unwrap().len(), 3, "{body}");

    // limit returns the most recent N (still oldest-first within that slice).
    let (_, _, body) = request(http, &auth("/api/v1/me/networks/work/buffer?limit=1")).await;
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["lines"].as_array().unwrap().len(), 1, "{body}");
    assert_eq!(v["lines"][0], ":a!u@h PRIVMSG #x :two", "{body}");

    // Limits outside the documented contract fail instead of silently
    // returning a different window than the caller requested.
    for limit in [0, 1001] {
        let (status, headers, body) = request(
            http,
            &auth(&format!("/api/v1/me/networks/work/buffer?limit={limit}")),
        )
        .await;
        assert_eq!(status, 400, "{body}");
        assert_eq!(
            headers
                .lines()
                .find(|line| line.to_ascii_lowercase().starts_with("content-type:"))
                .map(|line| line
                    .split_once(':')
                    .expect("content-type separator")
                    .1
                    .trim()),
            Some("application/problem+json"),
            "{headers:?}"
        );
        assert!(body.contains("Invalid buffer limit"), "{body}");
    }

    // A network the caller doesn't own → 404.
    let (status, _, _) = request(http, &auth("/api/v1/me/networks/nope/buffer")).await;
    assert_eq!(status, 404);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn me_read_markers_list() {
    let url = support::test_db("me_read_markers_list").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("alice");
    let token = issue_api_token(&pool, "alice", "t").await.expect("token");
    for (target, ts) in [
        ("#rust", "2026-01-02T03:04:05.678Z"),
        ("#e6irc", "2026-02-03T04:05:06.001Z"),
    ] {
        sqlx::query(
            "INSERT INTO read_markers (account_id, target, marker_ts)
             SELECT id, $1, $2::timestamptz FROM accounts WHERE name_folded = 'alice'",
        )
        .bind(target)
        .bind(ts)
        .execute(&pool)
        .await
        .expect("seed marker");
    }
    drop(pool);

    let config = Config {
        server_name: "irc.rm.example".into(),
        network_name: "RmNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");

    // Unauthenticated → 401.
    let unauth = "GET /api/v1/me/read-markers HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
    let (status, _, _) = request(http, unauth).await;
    assert_eq!(status, 401);

    let auth = format!(
        "GET /api/v1/me/read-markers HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
    let (status, headers, body) = request(http, &auth).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("cache-control: no-store"),
        "{headers}"
    );
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let markers = v["markers"].as_array().expect("array");
    assert_eq!(markers.len(), 2, "{body}");
    // Ordered by target: "#e6irc" precedes "#rust".
    assert_eq!(markers[0]["target"], "#e6irc", "{body}");
    assert_eq!(
        markers[0]["timestamp"], "2026-02-03T04:05:06.001Z",
        "{body}"
    );
    assert_eq!(markers[1]["target"], "#rust", "{body}");
    assert_eq!(
        markers[1]["timestamp"], "2026-01-02T03:04:05.678Z",
        "{body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn rp_initiated_logout_redirects_to_provider() {
    use e6ircd::config::{DatabaseConfig, OidcProviderConfig};
    let url = support::test_db("rp_initiated_logout_redirects_to_provider").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("acct");
    let session = e6ircd::db::create_web_session_with_identity(
        &pool,
        "alice",
        e6ircd::db::OidcSessionIdentity {
            id_token: Some("the.id.token"),
            provider: Some("shauth"),
            issuer: Some("https://auth.example"),
            subject: Some("alice-subject"),
            sid: Some("alice-session"),
            email: Some("alice@example.test"),
            role: Some("developer"),
        },
        None,
    )
    .await
    .expect("sso session");
    let local_session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("local session");
    drop(pool);

    let config = Config {
        server_name: "irc.logout.example".into(),
        network_name: "LogoutNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: Some("http://e6irc.example".into()),
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        oidc_providers: vec![OidcProviderConfig {
            name: "shauth".into(),
            issuer_url: "https://auth.example".into(),
            client_id: "e6irc".into(),
            client_secret: "x".repeat(32),
            account_claim: e6ircd::config::OidcAccountClaim::PreferredUsername,
            scopes: vec![],
            allowed_email_domains: vec![],
            end_session_endpoint: Some("https://auth.example/oauth2/sessions/logout".into()),
            token_endpoint_auth_method: e6ircd::config::TokenEndpointAuthMethod::ClientSecretBasic,
        }],
        application_release_revision: Some("0123456789ab".into()),
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");

    let (validation_status, validation_headers, validation_body) = request(
        http,
        &format!(
            "GET /auth/validation HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_eq!(validation_status, 200, "{validation_headers}");
    let lowered_validation_headers = validation_headers.to_ascii_lowercase();
    assert!(
        lowered_validation_headers.contains("cache-control: no-store"),
        "{validation_headers}"
    );
    for exact in [
        "data-testid=\"validation-username\">alice</dd>",
        "data-testid=\"validation-email\">alice@example.test</dd>",
        "data-testid=\"validation-role\">developer</dd>",
        "data-testid=\"validation-release\">0123456789ab</code>",
        "data-shauth-user=\"alice\"",
        "data-shauth-sign-out",
    ] {
        assert!(
            validation_body.contains(exact),
            "missing {exact}: {validation_body}"
        );
    }

    // The logout GET now requires the session's CSRF token (anti-forced-logout);
    // fetch it from the account page the way a browser would.
    let (_, _, page) = request(
        http,
        &format!(
            "GET /console/account HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    let csrf = csrf_from_html(&page).to_string();
    // Without the token, the destructive logout GET is refused (a cross-site
    // navigation can't forge it): anti-forced-logout CSRF.
    let (no_csrf, _, _) = request(
        http,
        &format!(
            "GET /api/v1/auth/logout HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_eq!(no_csrf, 403, "logout without CSRF token must be refused");
    // A GET logout on an OIDC session redirects to the provider's end-session
    // endpoint with an id_token_hint and post_logout_redirect_uri.
    let req = format!(
        "GET /api/v1/auth/logout?csrf={csrf} HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, headers, _) = request(http, &req).await;
    assert_eq!(status, 303, "{headers}");
    let location = headers
        .lines()
        .find_map(|l| {
            l.strip_prefix("location: ")
                .or_else(|| l.strip_prefix("Location: "))
        })
        .expect("location header")
        .trim();
    assert!(
        location.starts_with("https://auth.example/oauth2/sessions/logout?"),
        "not RP-initiated: {location}"
    );
    assert!(
        location.contains("id_token_hint=the.id.token"),
        "{location}"
    );
    assert!(location.contains("client_id=e6irc"), "{location}");
    let location_url = reqwest::Url::parse(location).expect("logout URL");
    let post_logout_redirect = location_url
        .query_pairs()
        .find_map(|(name, value)| (name == "post_logout_redirect_uri").then(|| value.into_owned()))
        .expect("post_logout_redirect_uri");
    assert_eq!(
        post_logout_redirect,
        "http://e6irc.example/auth/shauth/logout/complete"
    );

    // The registered bridge ignores every caller-supplied redirect and
    // credential-like query value and forwards only to Shauth's fixed
    // completion coordinate.
    let (bridge_status, bridge_headers, _) = request(
        http,
        &get(
            "/auth/shauth/logout/complete?next=https%3A%2F%2Fattacker.example&redirect_uri=https%3A%2F%2Fattacker.example&code=secret",
        ),
    )
    .await;
    assert_eq!(bridge_status, 303, "{bridge_headers}");
    let bridge_headers = bridge_headers.to_ascii_lowercase();
    assert!(
        bridge_headers.contains("location: https://auth.example/oauth/logout/complete"),
        "{bridge_headers}"
    );
    assert!(
        bridge_headers.contains("cache-control: no-store"),
        "{bridge_headers}"
    );
    assert!(
        bridge_headers.contains("pragma: no-cache"),
        "{bridge_headers}"
    );
    assert!(
        bridge_headers.contains("referrer-policy: no-referrer"),
        "{bridge_headers}"
    );

    // The local session is gone: the same cookie no longer authenticates.
    let me = format!(
        "GET /api/v1/me HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, _) = request(http, &me).await;
    assert_eq!(status, 401, "session survived logout");
    let (anonymous_validation, anonymous_headers, _) =
        request(http, &get("/auth/validation")).await;
    assert_eq!(anonymous_validation, 303, "{anonymous_headers}");
    assert!(
        anonymous_headers.contains("location: /auth/signed-out")
            || anonymous_headers.contains("Location: /auth/signed-out"),
        "{anonymous_headers}"
    );

    // The provider returns to a public, persistent app-local page. It keeps
    // the exact Shauth starter after a reload instead of silently probing SSO.
    for attempt in 1..=2 {
        let (status, headers, body) = request(http, &get("/auth/signed-out")).await;
        assert_eq!(status, 200, "attempt {attempt}: {headers}");
        assert_visible_e6irc_brand(&body);
        assert!(body.contains("You are signed out"), "{body}");
        // The control text is the provider's proper name (capitalized), which is
        // the exact accessible name Shauth's SSO validator matches
        // ("Sign in with Shauth"); the starter path keeps the configured
        // lowercase provider name. (Regression: issue #129 — a lowercase
        // "Sign in with shauth" failed the validator's exact-name match.)
        assert!(
            body.contains("href=\"/api/v1/auth/oidc/shauth/start\">Sign in with Shauth</a>"),
            "{body}"
        );
    }

    // Local-account and already-signed-out browser navigations use the same
    // app-local landing, and stale cookies are expired idempotently.
    for cookie in [Some(local_session.as_str()), None] {
        let cookie_header = cookie
            .map(|value| format!("Cookie: e6irc_session={value}\r\n"))
            .unwrap_or_default();
        // A session-bearing logout carries its CSRF token; a cookieless
        // navigation has no session to protect and needs none.
        let csrf_q = match cookie {
            Some(value) => {
                let (_, _, page) = request(
                    http,
                    &format!(
                        "GET /console/account HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={value}\r\nConnection: close\r\n\r\n"
                    ),
                )
                .await;
                let token = csrf_from_html(&page);
                format!("?csrf={token}")
            }
            None => String::new(),
        };
        let logout = format!(
            "GET /api/v1/auth/logout{csrf_q} HTTP/1.1\r\nHost: t\r\n{cookie_header}Connection: close\r\n\r\n"
        );
        let (status, headers, _) = request(http, &logout).await;
        assert_eq!(status, 303, "{headers}");
        assert!(
            headers.contains("location: /auth/signed-out")
                || headers.contains("Location: /auth/signed-out"),
            "{headers}"
        );
        assert!(headers.contains("Max-Age=0"), "{headers}");
    }
}

#[cfg(feature = "embed-web")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn application_entry_starts_shauth_when_configured() {
    use e6ircd::config::{DatabaseConfig, OidcProviderConfig};
    let url =
        support::test_db("application_entry_redirects_anonymous_visitors_to_the_login_page").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("acct");
    let session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("session");
    drop(pool);

    let config = Config {
        server_name: "irc.entry.example".into(),
        network_name: "EntryNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: Some("http://chat.example".into()),
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        oidc_providers: vec![OidcProviderConfig {
            name: "shauth".into(),
            issuer_url: "https://auth.example".into(),
            client_id: "e6irc".into(),
            client_secret: "x".repeat(32),
            account_claim: e6ircd::config::OidcAccountClaim::PreferredUsername,
            scopes: vec![],
            allowed_email_domains: vec![],
            end_session_endpoint: Some("https://auth.example/oauth2/sessions/logout".into()),
            token_endpoint_auth_method: e6ircd::config::TokenEndpointAuthMethod::ClientSecretBasic,
        }],
        application_release_revision: Some("0123456789ab".into()),
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");

    let (status, headers, _) = request(http, &get("/")).await;
    assert_eq!(status, 303, "{headers}");
    assert!(
        headers.contains("location: /api/v1/auth/oidc/shauth/start")
            || headers.contains("Location: /api/v1/auth/oidc/shauth/start")
    );

    let (status, _, body) = request(http, &get("/login")).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains("href=\"/api/v1/auth/oidc/shauth/start\""),
        "{body}"
    );
    assert!(!body.contains("type=\"password\""), "{body}");

    let (status, headers, _) = request(http, &get("/?sso=none")).await;
    assert_eq!(status, 303, "{headers}");
    assert!(
        headers.contains("location: /api/v1/auth/oidc/shauth/start")
            || headers.contains("Location: /api/v1/auth/oidc/shauth/start")
    );

    let req = format!(
        "GET / HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, headers, body) = request(http, &req).await;
    assert_eq!(status, 200, "{headers}");
    // An authenticated entry is admitted straight into the SPA chat shell
    // (`index.html`), not redirected — the account section lives at /account.
    assert!(body.contains("id=\"app\""), "{body}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn oidc_logout_without_end_session_configuration_fails_closed() {
    use e6ircd::config::{DatabaseConfig, OidcProviderConfig};
    let url = support::test_db("oidc_logout_without_end_session_configuration_fails_closed").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("acct");
    let session = e6ircd::db::create_web_session_with_identity(
        &pool,
        "alice",
        e6ircd::db::OidcSessionIdentity {
            id_token: Some("the.id.token"),
            provider: Some("corp"),
            issuer: Some("https://auth.example"),
            subject: Some("alice-subject"),
            sid: Some("alice-session"),
            email: Some("alice@example.test"),
            role: Some("developer"),
        },
        None,
    )
    .await
    .expect("session");
    drop(pool);

    let config = Config {
        server_name: "irc.fail-closed.example".into(),
        network_name: "FailClosedNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: Some("http://chat.example".into()),
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        oidc_providers: vec![OidcProviderConfig {
            name: "corp".into(),
            issuer_url: "https://auth.example".into(),
            client_id: "e6irc".into(),
            client_secret: "x".repeat(32),
            account_claim: e6ircd::config::OidcAccountClaim::PreferredUsername,
            scopes: vec![],
            allowed_email_domains: vec![],
            end_session_endpoint: None,
            token_endpoint_auth_method: e6ircd::config::TokenEndpointAuthMethod::ClientSecretBasic,
        }],
        application_release_revision: Some("0123456789ab".into()),
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");
    let (_, _, page) = request(
        http,
        &format!(
            "GET /console/account HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    let csrf = csrf_from_html(&page).to_string();
    let logout = format!(
        "GET /api/v1/auth/logout?csrf={csrf} HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, body) = request(http, &logout).await;
    assert_eq!(status, 503, "{body}");

    let me = format!(
        "GET /api/v1/me HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, _) = request(http, &me).await;
    assert_eq!(
        status, 200,
        "logout failure must preserve the local session"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn admin_networks_fleet_view_and_toggle() {
    let url = support::test_db("admin_networks_fleet_view_and_toggle").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("alice");
    e6ircd::db::create_account_with_contact(&pool, "bob", "pw", None)
        .await
        .expect("bob");
    let alice_token = issue_api_token(&pool, "alice", "t").await.expect("tok");
    let bob_token = issue_api_token(&pool, "bob", "t").await.expect("tok");
    let session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("session");
    // Bob owns an enabled network; its driver cannot dial 127.0.0.1:1, which
    // is exactly the "misbehaving upstream" the admin lever exists for.
    e6ircd::db::create_bnc_network(
        &pool,
        "bob",
        &e6ircd::db::BncNetworkRow {
            kind: e6ircd::config::NetworkKind::Irc,
            name: "work".into(),
            addr: "127.0.0.1:1".into(),
            tls: false,
            nick: "bob_".into(),
            username: Some("tester".into()),
            realname: Some("Bob".into()),
            autojoin: vec![],
            sasl_account: None,
            sasl_password_sealed: None,
            enabled: true,
            server_password_sealed: None,
        },
        e6ircd::db::NetworkAudit {
            actor: "bob",
            detail: "",
        },
    )
    .await
    .expect("create bob's network");
    drop(pool);

    let config = Config {
        server_name: "irc.admin.example".into(),
        network_name: "AdminNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec!["alice".into()],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url: url.clone(),
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }),
        internal_upstreams: e6ircd::egress::InternalUpstreams::Allow,
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");

    let bearer = |token: &str| {
        format!(
            "GET /api/v1/admin/networks HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        )
    };
    // no auth -> 401, non-admin -> 403
    let (status, _, _) = request(http, &get("/api/v1/admin/networks")).await;
    assert_eq!(status, 401);
    let (status, _, _) = request(http, &bearer(&bob_token)).await;
    assert_eq!(status, 403);
    // admin -> the fleet row, credentials as booleans only
    let (status, _, body) = request(http, &bearer(&alice_token)).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let networks = v["networks"].as_array().expect("networks array");
    assert_eq!(networks.len(), 1, "{body}");
    assert_eq!(networks[0]["owner"], "bob", "{body}");
    assert_eq!(networks[0]["name"], "work", "{body}");
    assert_eq!(networks[0]["enabled"], true, "{body}");

    // The console page remains a rendered admin view.
    let page_req = format!(
        "GET /console/admin/networks HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, page) = request(http, &page_req).await;
    assert_eq!(status, 200, "{page}");
    assert!(page.contains("data-api-admin-network-list"), "{page}");
    // Admin disables the misbehaving network through the API; the row flips
    // and the privileged action retains the administrator's audit identity.
    let body = r#"{"enabled":false}"#;
    let toggle = format!(
        "PATCH /api/v1/admin/networks/bob/work HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {alice_token}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let (status, _, _) = request(http, &toggle).await;
    assert_eq!(status, 200, "{status}");

    let pool = e6ircd::db::connect_and_migrate(&url).await.expect("pool");
    let row = e6ircd::db::get_bnc_network(&pool, "bob", "work")
        .await
        .expect("lookup")
        .expect("row");
    assert!(!row.enabled, "the admin toggle must disable the network");
    let detail: Option<String> = sqlx::query_scalar(
        "SELECT detail FROM audit_log WHERE actor = 'alice' AND action = 'NETWORK_TOGGLE' AND target = 'bob/work'",
    )
    .fetch_optional(&pool)
    .await
    .expect("audit query");
    assert_eq!(
        detail.as_deref(),
        Some("disabled"),
        "toggle must be audited"
    );
}

/// A database-backed server with the HTTP listener and nothing else.
async fn start_with_database(url: &str, administrators: &[&str]) -> net::Running {
    let config = Config {
        database: Some(DatabaseConfig {
            url: url.into(),
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: administrators.iter().map(|name| (*name).into()).collect(),
            hsts_include_subdomains: false,
        }),
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }),
        internal_upstreams: e6ircd::egress::InternalUpstreams::Allow,
        ..test_config()
    };
    net::start(config).await.expect("start")
}

/// One request line plus the credential headers a caller chose, with an
/// optional JSON body.
fn api_request(method: &str, path: &str, credential_headers: &str, body: Option<&str>) -> String {
    let body_headers = body.map_or_else(String::new, |body| {
        format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        )
    });
    format!(
        "{method} {path} HTTP/1.1\r\nHost: t\r\n{credential_headers}{body_headers}Connection: close\r\n\r\n{}",
        body.unwrap_or_default()
    )
}

fn bearer_headers(token: &str) -> String {
    format!("Authorization: Bearer {token}\r\n")
}

/// The cookie plus the session-bound CSRF value `GET /api/v1/me` publishes.
async fn session_headers(http: std::net::SocketAddr, session: &str) -> String {
    let cookie = format!("Cookie: e6irc_session={session}\r\n");
    let (status, _, body) = request(http, &api_request("GET", "/api/v1/me", &cookie, None)).await;
    assert_eq!(status, 200, "{body}");
    let identity: serde_json::Value = serde_json::from_str(&body).expect("identity JSON");
    let csrf = identity["csrf_token"].as_str().expect("CSRF value");
    format!("{cookie}X-E6IRC-CSRF: {csrf}\r\n")
}

/// A leaked write-scoped bearer must not be able to become the account: it can
/// neither install a primary password on an OpenID Connect-only account, nor
/// remove the owner's login identity, nor start linking a new one.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn bearer_cannot_install_a_password_or_change_login_identities() {
    let url = support::test_db("bearer_cannot_install_a_password_or_change_login_identities").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    let account = e6ircd::db::find_or_create_oidc_account(
        &pool,
        "https://issuer.example",
        "subject-1",
        "alice",
    )
    .await
    .expect("OpenID Connect account");
    let token = issue_api_token(&pool, &account, "leaked")
        .await
        .expect("token");
    let session = e6ircd::db::create_web_session(&pool, &account, None)
        .await
        .expect("session");
    let identity = e6ircd::db::list_oidc_identities(&pool, &account)
        .await
        .expect("identities")[0]
        .id;
    let http = start_with_database(&url, &[])
        .await
        .http_addr
        .expect("http");

    let password = r#"{"new_password":"attacker-chosen"}"#;
    let (status, _, body) = request(
        http,
        &api_request(
            "PUT",
            "/api/v1/me/password",
            &bearer_headers(&token),
            Some(password),
        ),
    )
    .await;
    assert_eq!(status, 401, "{body}");
    assert!(body.contains("Browser session required"), "{body}");
    assert_eq!(
        e6ircd::db::verify_local_password(&pool, &account, "attacker-chosen")
            .await
            .expect("password check"),
        None,
        "a bearer installed a primary password"
    );

    let unlink = format!("/api/v1/me/identities/{identity}");
    let (status, _, body) = request(
        http,
        &api_request("DELETE", &unlink, &bearer_headers(&token), None),
    )
    .await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(
        e6ircd::db::list_oidc_identities(&pool, &account)
            .await
            .expect("identities")
            .len(),
        1
    );

    let (status, _, body) = request(
        http,
        &api_request(
            "GET",
            "/api/v1/auth/oidc/any/link",
            &bearer_headers(&token),
            None,
        ),
    )
    .await;
    assert_eq!(status, 401, "{body}");
    assert!(body.contains("Browser session required"), "{body}");

    let email = r#"{"contact_email":"attacker@example.test"}"#;
    let (status, _, body) = request(
        http,
        &api_request(
            "PATCH",
            "/api/v1/me/profile",
            &bearer_headers(&token),
            Some(email),
        ),
    )
    .await;
    assert_eq!(status, 401, "{body}");

    // The owner's browser session keeps every one of those abilities.
    let owner = session_headers(http, &session).await;
    // Linking is a top-level navigation and cannot carry the CSRF header, so
    // the session's value rides the query. The owner's cookie alone — all a
    // cross-site link sends — is refused before any flow begins.
    let cookie_only = format!("Cookie: e6irc_session={session}\r\n");
    let (status, _, body) = request(
        http,
        &api_request("GET", "/api/v1/auth/oidc/any/link", &cookie_only, None),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("Invalid or missing CSRF token"), "{body}");
    let csrf = owner
        .split("X-E6IRC-CSRF: ")
        .nth(1)
        .expect("CSRF header")
        .trim_end();
    let (status, _, body) = request(
        http,
        &api_request(
            "GET",
            &format!("/api/v1/auth/oidc/any/link?csrf={csrf}"),
            &cookie_only,
            None,
        ),
    )
    .await;
    assert_eq!(status, 404, "the checked link reaches the provider: {body}");
    let (status, _, body) = request(
        http,
        &api_request("PUT", "/api/v1/me/password", &owner, Some(password)),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, _, body) = request(http, &api_request("DELETE", &unlink, &owner, None)).await;
    assert_eq!(status, 204, "{body}");
}

/// Console pages are cookie-only. A read-scoped bearer of an administrator is
/// refused with `401`, not sent to the sign-in page (it is not a browser) and
/// not rendered an administrator shell; a browser with no session goes to
/// `/login`; a suspended account's cookie gets the `403` it would get from any
/// JSON route, not a misleading redirect.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn console_pages_are_cookie_only_and_report_their_refusals() {
    let url = support::test_db("console_pages_are_cookie_only_and_report_their_refusals").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("alice");
    e6ircd::db::create_account_with_contact(&pool, "mallory", "pw", None)
        .await
        .expect("mallory");
    let read_only = e6ircd::db::issue_scoped_api_token(
        &pool,
        "alice",
        "reader",
        e6ircd::identity::ApiTokenScopes::new([e6ircd::identity::ApiTokenScope::Read])
            .expect("read scope"),
        e6ircd::identity::ApiTokenLifetimeDays::DEFAULT,
    )
    .await
    .expect("read token");
    let alice_session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("alice session");
    let mallory_session = e6ircd::db::create_web_session(&pool, "mallory", None)
        .await
        .expect("mallory session");
    let http = start_with_database(&url, &["alice"])
        .await
        .http_addr
        .expect("http");

    let (status, headers, body) = request(
        http,
        &api_request(
            "GET",
            "/console/accounts",
            &bearer_headers(&read_only),
            None,
        ),
    )
    .await;
    assert_eq!(status, 401, "{body}");
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("application/problem+json"),
        "{headers}"
    );
    assert!(body.contains("Browser session required"), "{body}");

    let (status, headers, _) = request(http, &get("/console/accounts")).await;
    assert_eq!(status, 303, "{headers}");
    assert!(headers.contains("location: /login"), "{headers}");

    let cookie = format!("Cookie: e6irc_session={alice_session}\r\n");
    let (status, _, body) = request(
        http,
        &api_request("GET", "/console/accounts", &cookie, None),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    let mallory_id = e6ircd::db::account_id_by_name(&pool, "mallory")
        .await
        .expect("mallory id")
        .expect("mallory exists");
    // A suspension ends the session; the cookie is then simply unknown and a
    // browser is sent to sign in. Reactivate and suspend the row directly so
    // the session survives and the suspended posture itself is what answers.
    let cookie = format!("Cookie: e6irc_session={mallory_session}\r\n");
    sqlx::query("UPDATE accounts SET flags = flags | 2 WHERE id = $1")
        .bind(mallory_id)
        .execute(&pool)
        .await
        .expect("suspend mallory in place");
    let (status, headers, body) =
        request(http, &api_request("GET", "/console/account", &cookie, None)).await;
    assert_eq!(status, 403, "{body}");
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("application/problem+json"),
        "{headers}"
    );
    assert!(body.contains("Account suspended"), "{body}");

    // An empty label is refused by the same rule the contract states
    // (`minLength: 1`).
    let owner = session_headers(http, &alice_session).await;
    let (status, _, body) = request(
        http,
        &api_request("POST", "/api/v1/me/tokens", &owner, Some(r#"{"label":""}"#)),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("Labels must not be empty"), "{body}");
}

/// The operator's way back in, end to end against a running daemon: the
/// subcommand grants authority the daemon honours on the next request — no
/// restart — and revokes every credential the account held, while the printed
/// password signs in at `/login`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn recover_administrator_subcommand_is_honoured_by_a_running_daemon() {
    let url =
        support::test_db("recover_administrator_subcommand_is_honoured_by_a_running_daemon").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "bob", "lost", None)
        .await
        .expect("bob");
    let old_token = issue_api_token(&pool, "bob", "automation")
        .await
        .expect("token");
    let http = start_with_database(&url, &[])
        .await
        .http_addr
        .expect("http");
    let admin_route = |credential_headers: &str| {
        api_request("GET", "/api/v1/admin/accounts", credential_headers, None)
    };
    let (status, _, _) = request(http, &admin_route(&bearer_headers(&old_token))).await;
    assert_eq!(status, 403, "bob is nobody's administrator yet");

    let config_path = temporary_path("recover-config");
    let _config_file = TemporaryFile(config_path.clone());
    std::fs::write(
        &config_path,
        format!(
            "server_name = \"irc.recover.example\"\nnetwork_name = \"RecoverNet\"\n\
             [[listeners]]\naddr = \"127.0.0.1:0\"\n[database]\nurl = \"{url}\"\n"
        ),
    )
    .expect("write config");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_e6ircd"))
        .args([
            "recover-administrator",
            "--account",
            "BOB",
            "--config",
            config_path.to_str().expect("utf-8 path"),
        ])
        .env_clear()
        .output()
        .expect("run e6ircd recover-administrator");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        !stderr.to_ascii_lowercase().contains("restart"),
        "no restart is needed: {stderr}"
    );
    let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert!(
        !password.is_empty(),
        "the password is printed once, on stdout"
    );

    let (status, _, _) = request(http, &admin_route(&bearer_headers(&old_token))).await;
    assert_eq!(status, 401, "the lost credential's token is revoked");

    let (_, _, body) = request(http, &get("/login")).await;
    let state = login_state_from_html(&body).to_string();
    let form = format!(
        "login_state={state}&account=bob&password={}",
        form_value(&password)
    );
    let login = format!(
        "POST /login HTTP/1.1\r\nHost: t\r\nCookie: e6irc_login_state={state}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{form}",
        form.len()
    );
    let (status, headers, body) = request(http, &login).await;
    assert_eq!(status, 303, "the printed password signs in: {body}");
    let session = headers
        .lines()
        .find_map(|line| line.strip_prefix("set-cookie: e6irc_session="))
        .and_then(|value| value.split(';').next())
        .expect("session cookie");
    let (status, _, body) = request(
        http,
        &admin_route(&format!("Cookie: e6irc_session={session}\r\n")),
    )
    .await;
    assert_eq!(
        status, 200,
        "the running daemon honours the recovered authority without a restart: {body}"
    );
}

/// `except=current` names the browser session that authorized the request. A
/// bearer beside a cookie nobody verified names nothing, and must not turn the
/// selector into "every session".
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn bearer_with_an_unverified_cookie_cannot_revoke_browser_sessions() {
    let url =
        support::test_db("bearer_with_an_unverified_cookie_cannot_revoke_browser_sessions").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("alice");
    let token = issue_api_token(&pool, "alice", "automation")
        .await
        .expect("token");
    let session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("session");
    let http = start_with_database(&url, &[])
        .await
        .http_addr
        .expect("http");

    let forged = format!("{}Cookie: e6irc_session=x\r\n", bearer_headers(&token));
    let (status, _, body) = request(
        http,
        &api_request(
            "DELETE",
            "/api/v1/me/sessions?except=current",
            &forged,
            None,
        ),
    )
    .await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(
        e6ircd::db::session_account(&pool, &session)
            .await
            .expect("session lookup"),
        Some("alice".into()),
        "the owner's browser session was revoked"
    );
}

fn preflight_body(addr: std::net::SocketAddr) -> String {
    serde_json::json!({
        "addr": addr.to_string(), "tls": false, "nick": "tester", "username": "tester", "realname": "Tester",
    })
    .to_string()
}

/// A connection test makes the shared daemon register with a third party, so
/// one account gets one at a time and a handful per minute.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn connection_tests_are_bounded_per_account() {
    let url = support::test_db("connection_tests_are_bounded_per_account").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    let mut tokens = Vec::new();
    for account in ["alice", "bob"] {
        e6ircd::db::create_account_with_contact(&pool, account, "pw", None)
            .await
            .expect("account");
        tokens.push(
            issue_api_token(&pool, account, "automation")
                .await
                .expect("token"),
        );
    }
    let http = start_with_database(&url, &[])
        .await
        .http_addr
        .expect("http");

    // An upstream that accepts and then says nothing holds Alice's first test
    // in its registration phase.
    let silent = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("silent upstream");
    let silent_addr = silent.local_addr().expect("silent upstream address");
    let alice = bearer_headers(&tokens[0]);
    let first = tokio::spawn({
        let request_text = api_request(
            "POST",
            "/api/v1/me/network-preflight",
            &alice,
            Some(&preflight_body(silent_addr)),
        );
        async move { request(http, &request_text).await }
    });
    let _held = tokio::time::timeout(deadline::HANG, silent.accept())
        .await
        .expect("the first connection test never dialed")
        .expect("accept");
    let (status, headers, body) = request(
        http,
        &api_request(
            "POST",
            "/api/v1/me/network-preflight",
            &alice,
            Some(&preflight_body(silent_addr)),
        ),
    )
    .await;
    assert_eq!(status, 429, "{body}");
    assert!(
        response_header(&headers, "retry-after").is_some(),
        "{headers}"
    );
    assert_eq!(
        response_header(&headers, "content-type"),
        Some("application/problem+json"),
        "{headers}"
    );
    first.abort();

    // Bob's tests finish at once (nothing listens on port 1), so only the
    // per-minute allowance can refuse him.
    let bob = bearer_headers(&tokens[1]);
    let refused: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    for attempt in 1..=6 {
        let (status, _, body) = request(
            http,
            &api_request(
                "POST",
                "/api/v1/me/network-preflight",
                &bob,
                Some(&preflight_body(refused)),
            ),
        )
        .await;
        assert_eq!(status, 502, "attempt {attempt}: {body}");
        assert!(body.contains("connection_failed"), "{body}");
    }
    let (status, headers, body) = request(
        http,
        &api_request(
            "POST",
            "/api/v1/me/network-preflight",
            &bob,
            Some(&preflight_body(refused)),
        ),
    )
    .await;
    assert_eq!(status, 429, "{body}");
    assert!(
        response_header(&headers, "retry-after").is_some(),
        "{headers}"
    );
}

/// Every name `valid_network_name` admits is addressable: no verb shares the
/// `{name}` position.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn a_network_named_preflight_is_reachable_on_its_own_url() {
    let url = support::test_db("a_network_named_preflight_is_reachable_on_its_own_url").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("alice");
    let token = issue_api_token(&pool, "alice", "automation")
        .await
        .expect("token");
    let http = start_with_database(&url, &[])
        .await
        .http_addr
        .expect("http");
    let alice = bearer_headers(&token);

    let create = r#"{"kind":"irc","name":"Preflight","addr":"127.0.0.1:1","tls":false,"nick":"alice","username":"alice","realname":"Alice","autojoin":[]}"#;
    let (status, _, body) = request(
        http,
        &api_request("POST", "/api/v1/me/networks", &alice, Some(create)),
    )
    .await;
    assert_eq!(status, 201, "{body}");

    let (status, _, body) = request(
        http,
        &api_request("GET", "/api/v1/me/networks/preflight", &alice, None),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    // The response names the network as stored, not as the URL spelled it.
    let (status, _, body) = request(
        http,
        &api_request(
            "PATCH",
            "/api/v1/me/networks/preflight",
            &alice,
            Some(r#"{"enabled":false}"#),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let patched: serde_json::Value = serde_json::from_str(&body).expect("patch JSON");
    assert_eq!(patched["name"], "Preflight", "{body}");

    let (status, _, body) = request(
        http,
        &api_request("DELETE", "/api/v1/me/networks/preflight", &alice, None),
    )
    .await;
    assert_eq!(status, 204, "{body}");
}

/// The `runtime` member of one administrator fleet row; `null` means no driver
/// is registered for that network.
async fn fleet_runtime(
    http: std::net::SocketAddr,
    administrator: &str,
    owner: &str,
    name: &str,
) -> serde_json::Value {
    let (status, _, body) = request(
        http,
        &api_request("GET", "/api/v1/admin/networks", administrator, None),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let fleet: serde_json::Value = serde_json::from_str(&body).expect("fleet JSON");
    fleet["networks"]
        .as_array()
        .expect("networks")
        .iter()
        .find(|row| row["owner"] == owner && row["name"] == name)
        .unwrap_or_else(|| panic!("{owner}/{name} missing from {body}"))["runtime"]
        .clone()
}

async fn account_with_enabled_network(pool: &sqlx::PgPool, owner: &str) -> i64 {
    e6ircd::db::create_account_with_contact(pool, owner, "pw", None)
        .await
        .expect("owner");
    e6ircd::db::create_bnc_network(
        pool,
        owner,
        &e6ircd::db::BncNetworkRow {
            kind: e6ircd::config::NetworkKind::Irc,
            name: "work".into(),
            addr: "127.0.0.1:1".into(),
            tls: false,
            nick: "worker".into(),
            username: Some("tester".into()),
            realname: Some("Worker".into()),
            autojoin: vec![],
            sasl_account: None,
            sasl_password_sealed: None,
            enabled: true,
            server_password_sealed: None,
        },
        e6ircd::db::NetworkAudit {
            actor: owner,
            detail: "",
        },
    )
    .await
    .expect("network");
    e6ircd::db::account_id_by_name(pool, owner)
        .await
        .expect("owner id lookup")
        .expect("owner id")
}

/// Suspension stops an owner's drivers but leaves `enabled` set so that
/// reactivation restores them. Nothing else may read that flag as "start it".
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn a_suspended_owners_network_cannot_be_started() {
    let url = support::test_db("a_suspended_owners_network_cannot_be_started").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("alice");
    let token = issue_api_token(&pool, "alice", "administration")
        .await
        .expect("token");
    let bob = account_with_enabled_network(&pool, "bob").await;
    let carol = account_with_enabled_network(&pool, "carol").await;
    // Carol was suspended before this process existed.
    e6ircd::db::set_account_suspended(&pool, carol, true, "alice", &["alice".into()])
        .await
        .expect("suspend carol")
        .expect("carol exists");
    let http = start_with_database(&url, &["alice"])
        .await
        .http_addr
        .expect("http");
    let alice = bearer_headers(&token);

    assert!(
        !fleet_runtime(http, &alice, "bob", "work").await.is_null(),
        "an active owner's enabled network runs from boot"
    );
    assert!(
        fleet_runtime(http, &alice, "carol", "work").await.is_null(),
        "boot started a suspended owner's network"
    );

    let (status, _, body) = request(
        http,
        &api_request(
            "PATCH",
            &format!("/api/v1/admin/accounts/{bob}"),
            &alice,
            Some(r#"{"suspended":true}"#),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    for owner in ["bob", "carol"] {
        let path = format!("/api/v1/admin/networks/{owner}/work");
        let (status, _, body) = request(
            http,
            &api_request("PATCH", &path, &alice, Some(r#"{"enabled":false}"#)),
        )
        .await;
        assert_eq!(status, 200, "{owner}: {body}");
        let (status, _, body) = request(
            http,
            &api_request("PATCH", &path, &alice, Some(r#"{"enabled":true}"#)),
        )
        .await;
        assert_eq!(status, 409, "{owner}: {body}");
        assert!(body.contains("suspended"), "{owner}: {body}");
        assert!(
            fleet_runtime(http, &alice, owner, "work").await.is_null(),
            "{owner}: a suspended owner's driver is running"
        );
    }
}

/// A cross-site form can make a browser POST with its cookie, but cannot set a
/// custom header: logout asks for the session-bound value like every other
/// unsafe cookie-authenticated method.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn logout_post_requires_the_session_csrf_value() {
    let url = support::test_db("logout_post_requires_the_session_csrf_value").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("alice");
    let session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("session");
    let http = start_with_database(&url, &[])
        .await
        .http_addr
        .expect("http");

    let forged = format!("Cookie: e6irc_session={session}\r\n");
    let (status, _, body) = request(
        http,
        &api_request("POST", "/api/v1/auth/logout", &forged, None),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(
        e6ircd::db::session_account(&pool, &session)
            .await
            .expect("session lookup"),
        Some("alice".into()),
        "a request without the CSRF value logged the owner out"
    );

    let owner = session_headers(http, &session).await;
    let (status, headers, body) = request(
        http,
        &api_request("POST", "/api/v1/auth/logout", &owner, None),
    )
    .await;
    assert_eq!(status, 204, "{body}");
    assert!(headers.contains("e6irc_session=;"), "{headers}");
    assert_eq!(
        e6ircd::db::session_account(&pool, &session)
            .await
            .expect("session lookup"),
        None
    );

    // With no session there is nothing to forge: clearing the cookie is all
    // that is left to do.
    let (status, _, body) =
        request(http, &api_request("POST", "/api/v1/auth/logout", "", None)).await;
    assert_eq!(status, 204, "{body}");
}

/// An identity provider that serves only its discovery document (and an empty
/// key set). Without `token_endpoint` it is what OpenID Connect Discovery
/// allows for an implicit-flow-only provider.
async fn discovery_only_identity_provider(token_endpoint: bool) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("identity provider");
    let addr = listener.local_addr().expect("identity provider address");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut head = vec![0u8; 4096];
                let read = stream.read(&mut head).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&head[..read]).to_string();
                let body = if head.starts_with("GET /.well-known/openid-configuration ") {
                    let mut document = serde_json::json!({
                        "issuer": format!("http://{addr}"),
                        "authorization_endpoint": format!("http://{addr}/authorize"),
                        "jwks_uri": format!("http://{addr}/jwks"),
                        "response_types_supported": ["code"],
                        "subject_types_supported": ["public"],
                        "id_token_signing_alg_values_supported": ["RS256"],
                    });
                    if token_endpoint {
                        document["token_endpoint"] = format!("http://{addr}/token").into();
                    }
                    document
                } else {
                    serde_json::json!({ "keys": [] })
                }
                .to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.ok();
            });
        }
    });
    addr
}

/// A provider that cannot exchange a code cannot complete a login, so the login
/// is refused where it starts — not by a handler panic when the browser returns.
#[tokio::test(flavor = "multi_thread")]
async fn a_provider_without_a_token_endpoint_is_a_bad_gateway() {
    let provider = discovery_only_identity_provider(false).await;
    let mut config = test_config();
    config.http.as_mut().expect("http").public_url = Some("http://e6irc.example".into());
    config.oidc_providers = vec![e6ircd::config::OidcProviderConfig {
        name: "implicit".into(),
        issuer_url: format!("http://{provider}"),
        client_id: "e6irc".into(),
        client_secret: "x".repeat(32),
        account_claim: e6ircd::config::OidcAccountClaim::PreferredUsername,
        scopes: vec![],
        allowed_email_domains: vec![],
        end_session_endpoint: None,
        token_endpoint_auth_method: e6ircd::config::TokenEndpointAuthMethod::ClientSecretBasic,
    }];
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");

    let (status, headers, body) = request(http, &get("/api/v1/auth/oidc/implicit/start")).await;
    assert_eq!(status, 502, "{headers}\n{body}");
    assert_eq!(
        response_header(&headers, "content-type"),
        Some("application/problem+json"),
        "{headers}"
    );
    assert!(body.contains("OIDC provider unavailable"), "{body}");
}

/// An in-flight OpenID Connect login is carried by the browser, sealed into its
/// state cookie; the server holds nothing per flow. So no number of anonymous
/// starts crowds out a real login, only the browser that began a flow can
/// finish it, and every callback that proves the binding spends the flow.
#[tokio::test(flavor = "multi_thread")]
async fn oidc_login_state_is_sealed_into_the_browser() {
    let provider = discovery_only_identity_provider(true).await;
    let mut config = test_config();
    config.http.as_mut().expect("http").public_url = Some("http://e6irc.example".into());
    config.oidc_providers = vec![e6ircd::config::OidcProviderConfig {
        name: "corp".into(),
        issuer_url: format!("http://{provider}"),
        client_id: "e6irc".into(),
        client_secret: "x".repeat(32),
        account_claim: e6ircd::config::OidcAccountClaim::PreferredUsername,
        scopes: vec![],
        allowed_email_domains: vec![],
        end_session_endpoint: None,
        token_endpoint_auth_method: e6ircd::config::TokenEndpointAuthMethod::ClientSecretBasic,
    }];
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");

    async fn begin(http: std::net::SocketAddr, path: &str) -> (String, String) {
        let (status, headers, body) = request(http, &get(path)).await;
        assert_eq!(status, 307, "{headers}\n{body}");
        let cookie = response_header(&headers, "set-cookie")
            .and_then(|value| value.split(';').next())
            .expect("flow cookie")
            .to_string();
        let state = response_header(&headers, "location")
            .expect("location")
            .split(['?', '&'])
            .find_map(|parameter| parameter.strip_prefix("state="))
            .expect("state parameter")
            .to_string();
        (cookie, state)
    }
    fn callback(query: &str, cookie: &str) -> String {
        format!(
            "GET /api/v1/auth/oidc/corp/callback?{query} HTTP/1.1\r\nHost: t\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n"
        )
    }
    let spent = Some("e6irc_oidc_state=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");

    // Well past the 4096 flows the server once held before refusing every
    // login with a 503.
    for _ in 0..4200 {
        begin(http, "/api/v1/auth/oidc/corp/start").await;
    }

    let (cookie, state) = begin(http, "/api/v1/auth/oidc/corp/start").await;
    assert!(cookie.starts_with("e6irc_oidc_state=enc:v2:"), "{cookie}");
    assert!(!cookie.contains(&state), "the flow is sealed: {cookie}");

    // Another login's response (an attacker's own) is not this browser's, and
    // does not spend its flow; nor does this flow's state without its cookie.
    let (status, headers, body) = request(http, &callback("code=c&state=forged", &cookie)).await;
    assert_eq!(status, 401, "{body}");
    assert!(
        body.contains("Login state not bound to this browser"),
        "{body}"
    );
    assert_eq!(response_header(&headers, "set-cookie"), None, "{headers}");
    let (status, _, body) = request(
        http,
        &get(&format!(
            "/api/v1/auth/oidc/corp/callback?code=c&state={state}"
        )),
    )
    .await;
    assert_eq!(status, 401, "{body}");
    let (status, headers, body) =
        request(http, &callback("error=access_denied&state=forged", &cookie)).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(response_header(&headers, "set-cookie"), None, "{headers}");

    // The browser's own response is admitted with what Google appends and a
    // granted scope other than the one requested (RFC 6749 §4.1.2, §3.3).
    // This server has no database, so the admitted flow ends at account
    // storage, and is spent.
    let query = format!(
        "code=c&state={state}&scope=email%20openid&authuser=0&hd=example.com&prompt=consent&session_state=abc"
    );
    let (status, headers, body) = request(http, &callback(&query, &cookie)).await;
    assert_eq!(status, 503, "{body}");
    assert!(body.contains("No database configured"), "{body}");
    assert_eq!(response_header(&headers, "set-cookie"), spent, "{headers}");

    let (status, _, body) = request(
        http,
        &callback("authuser=0&session_state=abc", "e6irc_oidc_state=x"),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("Missing code or state"), "{body}");

    // The provider's refusal of this browser's flow spends it too.
    let (cookie, state) = begin(http, "/api/v1/auth/oidc/corp/start").await;
    let (status, headers, body) = request(
        http,
        &callback(&format!("error=access_denied&state={state}"), &cookie),
    )
    .await;
    assert_eq!(status, 401, "{body}");
    assert!(body.contains("OIDC login refused"), "{body}");
    assert_eq!(response_header(&headers, "set-cookie"), spent, "{headers}");

    // The sealed flow remembers it was a silent probe: no provider session
    // bounces to interactive sign-in, and missing consent begins an ordinary
    // authorization request with a fresh flow.
    let (cookie, state) = begin(http, "/api/v1/auth/oidc/corp/sso").await;
    let (status, headers, _) = request(
        http,
        &callback(&format!("error=login_required&state={state}"), &cookie),
    )
    .await;
    assert_eq!(status, 303, "{headers}");
    assert_eq!(response_header(&headers, "location"), Some("/?sso=none"));
    assert_eq!(response_header(&headers, "set-cookie"), spent, "{headers}");
    let (cookie, state) = begin(http, "/api/v1/auth/oidc/corp/sso").await;
    let (status, headers, _) = request(
        http,
        &callback(&format!("error=consent_required&state={state}"), &cookie),
    )
    .await;
    assert_eq!(status, 307, "{headers}");
    let fresh = response_header(&headers, "set-cookie").expect("a fresh flow");
    assert!(fresh.starts_with("e6irc_oidc_state=enc:v2:"), "{fresh}");
    assert!(
        !response_header(&headers, "location")
            .expect("location")
            .contains("prompt=none"),
        "{headers}"
    );
}

/// A running network's driver holds the configured nickname, so a connection
/// test of the same upstream and nickname could only end `nickname_in_use`,
/// which says nothing about the settings. It is refused with the way out; once
/// the network is disabled the same test runs.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn a_connection_test_of_a_running_network_is_refused() {
    let url = support::test_db("a_connection_test_of_a_running_network_is_refused").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("account");
    let token = issue_api_token(&pool, "alice", "automation")
        .await
        .expect("token");
    let up = upstream_server().await.addrs[0];
    let running = start_with_database(&url, &[]).await;
    let http = running.http_addr.expect("http");
    wait_http_ready(http).await;

    let (status, body) = post_json(
        http,
        "/api/v1/me/networks",
        &token,
        &format!(r#"{{"kind":"irc","name":"lan","addr":"{up}","tls":false,"nick":"probe","username":"probe","realname":"Probe","autojoin":[]}}"#),
    )
    .await;
    assert_eq!(status, 201, "{body}");

    let test_body = format!(
        r#"{{"addr":"{up}","tls":false,"nick":"Probe","username":"probe","realname":"Probe","autojoin":[]}}"#
    );
    let (status, body) = post_json(http, "/api/v1/me/network-preflight", &token, &test_body).await;
    assert_eq!(status, 409, "{body}");
    let problem: serde_json::Value = serde_json::from_str(&body).expect("problem json");
    assert_eq!(problem["title"], "Network is running", "{body}");
    assert_eq!(
        problem["detail"], "network 'lan' is running; disable it to test its settings",
        "{body}"
    );
    assert!(problem.get("field").is_none(), "{body}");

    // Another nickname on the same upstream is not held by that driver.
    let other = format!(
        r#"{{"addr":"{up}","tls":false,"nick":"probe2","username":"probe","realname":"Probe","autojoin":[]}}"#
    );
    let (status, body) = post_json(http, "/api/v1/me/network-preflight", &token, &other).await;
    assert_eq!(status, 200, "{body}");

    let (status, body) = patch_json(
        http,
        "/api/v1/me/networks/lan",
        &token,
        r#"{"enabled":false}"#,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = post_json(http, "/api/v1/me/network-preflight", &token, &test_body).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        running.shutdown.run().await,
        e6ircd::net::ShutdownOutcome::Flushed
    );
}

// ---- a deleted network's driver writes nothing afterwards ------------------

/// A peer on the upstream that keeps talking in `#lobby` until dropped, so the
/// bouncer's persistence task is writing backlog at the moment of a deletion.
async fn chatty_upstream_peer(up: std::net::SocketAddr) -> tokio::task::JoinHandle<()> {
    let mut peer = e6irc_client::Connection::connect(&up.to_string())
        .await
        .expect("peer connect");
    peer.register(&e6irc_client::Identity {
        nick: "chatter",
        username: "chatter",
        realname: "chatter",
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
    tokio::spawn(async move {
        for n in 0u64.. {
            if peer
                .send_line(&format!("PRIVMSG #lobby :line {n}"))
                .await
                .is_err()
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    })
}

async fn backlog_rows(pool: &sqlx::PgPool, owner: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM bnc_buffer WHERE owner = $1")
        .bind(owner)
        .fetch_one(pool)
        .await
        .expect("count backlog")
}

/// Deleting a network — or its whole account — stops the driver before the
/// rows go, so no late backlog line from the persistence task survives the
/// deletion: the count is zero when the response arrives and stays zero.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn deleting_a_busy_network_or_account_leaves_no_backlog_behind() {
    let url = support::test_db("deleting_a_busy_network_or_account_leaves_no_backlog").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::bootstrap_first_admin(&pool, "root", "root password")
        .await
        .expect("root");
    let root_token = issue_api_token(&pool, "root", "admin")
        .await
        .expect("root token");
    let alice_id = e6ircd::db::create_account_with_contact(&pool, "alice", "s3cr3t", None)
        .await
        .expect("alice");
    let alice_token = issue_api_token(&pool, "alice", "owner")
        .await
        .expect("alice token");

    // The chatter pipelines lines faster than a client's default flood
    // allowance; the stand-in upstream must relay them all.
    let upstream = net::start(Config {
        server_name: "irc.up.example".into(),
        network_name: "Up".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        limits: e6ircd::config::LimitsConfig {
            command_burst: 10_000,
            command_rate: 10_000,
            ..e6ircd::config::LimitsConfig::default()
        },
        ..Config::default()
    })
    .await
    .expect("upstream start");
    let up = upstream.addrs[0];
    let config = Config {
        server_name: "irc.busy.example".into(),
        network_name: "Busy".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        http: Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url: url.clone(),
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }),
        internal_upstreams: e6ircd::egress::InternalUpstreams::Allow,
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let http = running.http_addr.expect("http bound");
    wait_http_ready(http).await;
    let chatter = chatty_upstream_peer(up).await;

    let create = |name: &str| {
        format!(
            r##"{{"kind":"irc","name":"{name}","addr":"{up}","tls":false,"nick":"{name}_bnc","username":"alice","realname":"Alice","autojoin":["#lobby"]}}"##
        )
    };
    for name in ["work", "play"] {
        let (status, body) =
            post_json(http, "/api/v1/me/networks", &alice_token, &create(name)).await;
        assert_eq!(status, 201, "{body}");
    }
    let persisting = |network: &'static str| {
        let pool = pool.clone();
        async move {
            tokio::time::timeout(deadline::HANG, async {
                loop {
                    let rows: i64 = sqlx::query_scalar(
                        "SELECT count(*) FROM bnc_buffer
                         WHERE owner = 'alice' AND network = $1 AND line LIKE '%PRIVMSG #lobby%'",
                    )
                    .bind(network)
                    .fetch_one(&pool)
                    .await
                    .expect("count");
                    if rows > 20 {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("{network} never persisted the chatter"));
        }
    };
    persisting("work").await;
    persisting("play").await;
    assert!(!chatter.is_finished(), "the chatter must still be talking");

    let (status, _, body) = request(
        http,
        &format!(
            "DELETE /api/v1/me/networks/work HTTP/1.1\r\nHost: t\r\n\
             Authorization: Bearer {alice_token}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_eq!(status, 204, "{body}");
    let work_rows = || {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM bnc_buffer WHERE owner = 'alice' AND network = 'work'",
            )
            .fetch_one(&pool)
            .await
            .expect("count")
        }
    };
    assert_eq!(work_rows().await, 0, "backlog left at the response");
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    assert_eq!(work_rows().await, 0, "backlog written after the deletion");

    let confirmation = r#"{"confirmation":"alice"}"#;
    let (status, _, body) = request(
        http,
        &format!(
            "DELETE /api/v1/admin/accounts/{alice_id} HTTP/1.1\r\nHost: t\r\n\
             Authorization: Bearer {root_token}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{confirmation}",
            confirmation.len()
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        backlog_rows(&pool, "alice").await,
        0,
        "backlog left at the response"
    );
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    assert_eq!(
        backlog_rows(&pool, "alice").await,
        0,
        "backlog written after the account deletion"
    );
    chatter.abort();
    drop(running);
}
