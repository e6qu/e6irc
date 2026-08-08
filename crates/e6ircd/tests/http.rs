//! e2e tests for the HTTP layer, over real sockets with a raw
//! HTTP/1.1 client (no client library needed for these shapes).

use e6ircd::config::{
    BootstrapConfig, Config, DatabaseConfig, HttpConfig, ListenerConfig, SecretsConfig,
};
use e6ircd::net;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

mod support;

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
        }),
        ..Config::default()
    }
}

async fn request(addr: std::net::SocketAddr, req: &str) -> (u16, String, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read");
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = text.split_once("\r\n\r\n").expect("http response split");
    let status: u16 = head
        .lines()
        .next()
        .expect("status line")
        .split(' ')
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status");
    (status, head.to_string(), body.to_string())
}

fn get(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
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
    let running = net::start(test_config()).await.expect("start");
    let http = running.http_addr.expect("http bound");
    let (status, _, body) = request(http, &get("/healthz")).await;
    assert_eq!(status, 200);
    assert_eq!(body, "ok");
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
    assert_eq!(
        response_header(&first_headers, "strict-transport-security"),
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
    config.database = Some(DatabaseConfig { url: database_url });
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
        assert!(body.contains("aria-label=\"e6irc\">e6irc</span>"), "{body}");
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
async fn upstream_server() -> std::net::SocketAddr {
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
    net::start(cfg).await.expect("upstream start").addrs[0]
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

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn bnc_network_management_lifecycle() {
    let url = support::test_db("bnc_network_management_lifecycle").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account(&pool, "alice", "s3cr3t")
        .await
        .expect("acct");
    let token = e6ircd::db::issue_api_token(&pool, "alice", "test")
        .await
        .expect("token");
    drop(pool);

    let up = upstream_server().await;

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
        }),
        database: Some(DatabaseConfig { url }),
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
        }),
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let http = running.http_addr.expect("http bound");
    let bnc = running.bnc_addr.expect("bnc bound");

    // Qualifying a network uses the production resolver, transport, and IRC
    // registration path, but does not persist or start it.
    let (status, body) = post_json(
        http,
        "/api/v1/me/networks/preflight",
        &token,
        &format!(r#"{{"addr":"{up}","nick":"probe"}}"#),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let qualified: serde_json::Value = serde_json::from_str(&body).expect("preflight json");
    assert_eq!(qualified["ok"], true, "{body}");
    assert_eq!(qualified["confirmed_nick"], "probe", "{body}");
    assert_eq!(qualified["resolved_addresses"], 1, "{body}");
    for stage in ["dns_ms", "connect_ms", "registration_ms"] {
        assert!(qualified[stage].is_u64(), "missing {stage}: {body}");
    }

    let (status, body) = post_json(
        http,
        "/api/v1/me/networks/preflight",
        &token,
        &format!(r#"{{"addr":"{up}","nick":"probe","sasl_account":"alice"}}"#),
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
        &format!(r##"{{"name":"work","addr":"{up}","nick":"alice_","autojoin":["#lobby"]}}"##),
    )
    .await;
    assert_eq!(status, 201, "create should succeed");

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
            r#"{{"name":"big","addr":"up.example:1","nick":"n","sasl_account":"a","sasl_password":"{big}"}}"#
        ),
    )
    .await;
    assert_eq!(status, 400, "oversized sasl_password must be refused");
    let (status, _) = post_json(
        http,
        "/api/v1/me/networks",
        &token,
        r#"{"name":"nul","addr":"up.example:1","nick":"n","sasl_account":"a\u0000b","sasl_password":"p"}"#,
    )
    .await;
    assert_eq!(status, 400, "NUL in sasl_account must be refused");

    // it appears in the list
    let (status, _, body) = request(http, &list_req).await;
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["networks"][0]["name"], "work");
    assert_eq!(v["networks"][0]["has_sasl_password"], false);

    // the driver started: alice can attach to it via the BNC port
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let mut client = e6irc_client::Connection::connect(&bnc.to_string())
        .await
        .unwrap();
    let confirmed = client
        .register_sasl("alice/work", "Me", "alice", "s3cr3t")
        .await
        .expect("attach to the just-created network");
    assert!(confirmed.starts_with("alice/work"), "{confirmed}");
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
        r##"{{"addr":"{up}","tls":false,"nick":"alice_updated","realname":"Alice","autojoin":["#other"],"credentials":{{"action":"keep"}}}}"##
    );
    let update_req = format!(
        "PUT /api/v1/me/networks/work HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{update}",
        update.len()
    );
    let (status, _, body) = request(http, &update_req).await;
    assert_eq!(status, 204, "update: {body}");
    let (status, _, detail) = request(http, &detail_req).await;
    assert_eq!(status, 200, "{detail}");
    let detail: serde_json::Value = serde_json::from_str(&detail).expect("updated detail json");
    assert_eq!(detail["nick"], "alice_updated");
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
    for _ in 0..30 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let (_, _, body) = request(http, &list_req).await;
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["networks"][0]["enabled"], true, "{body}");
        if v["networks"][0]["connected"] == true {
            reconnected = true;
            break;
        }
    }
    assert!(reconnected, "re-enabled driver never reconnected");

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

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn bnc_network_upstream_secret_requires_master_key() {
    let url = support::test_db("bnc_network_upstream_secret_requires_master_key").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account(&pool, "alice", "s3cr3t")
        .await
        .expect("acct");
    let token = e6ircd::db::issue_api_token(&pool, "alice", "test")
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
            realname: None,
            autojoin: vec![],
            sasl_account: Some("alice".into()),
            // Simulates a deployment whose key was removed after credentials
            // had already been stored. Boot cannot open it, but explicit
            // credential removal must still recover the network.
            sasl_password_sealed: Some("enc:v2:unavailable-without-key".into()),
            enabled: true,
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
        }),
        database: Some(DatabaseConfig { url }),
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
        }),
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
        r#"{"name":"work","addr":"irc.example:6697","nick":"alice_","sasl_account":"alice","sasl_password":"upstreampass"}"#,
    )
    .await;
    assert_eq!(
        status, 409,
        "must refuse to store an upstream secret unsealed"
    );

    let remove = r#"{"addr":"up.example:6697","tls":true,"nick":"alice_","credentials":{"action":"remove"}}"#;
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
    assert!(body.contains("data-api-network-operations"), "{body}");
    assert!(body.contains("data-api-network-create"), "{body}");
    assert!(body.contains("data-api-oper-create"), "{body}");
    assert!(body.contains("data-api-oidc-create"), "{body}");
    assert!(body.contains("data-api-configuration-patch"), "{body}");
    assert!(body.contains("data-api-ban-create"), "{body}");
    assert!(body.contains("data-api-session-page"), "{body}");
    assert!(body.contains("data-api-account-app-password"), "{body}");
    assert!(body.contains("data-api-channel-register"), "{body}");
    assert!(body.contains("SETTINGS_KEY = \"e6irc.settings\""), "{body}");
    assert!(body.contains("data-api-owner-network-create"), "{body}");
    assert!(body.contains("data-api-admin-account-create"), "{body}");
    assert!(body.contains("X-E6IRC-CSRF"), "{body}");
    assert!(
        body.contains("/api/v1/admin/configuration/networks"),
        "{body}"
    );
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
    assert!(v["paths"]["/api/v1/admin/observability"]["get"].is_object());
    assert!(v["paths"]["/api/v1/admin/monitoring"]["get"].is_object());
    assert!(v["paths"]["/api/v1/admin/metrics"]["get"].is_object());
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
    e6ircd::db::create_account(&pool, "Alice", "primary")
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
        }),
        database: Some(DatabaseConfig { url }),
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

#[tokio::test]
async fn account_page_redirects_when_unauthenticated() {
    let running = net::start(test_config()).await.expect("start");
    let http = running.http_addr.expect("http bound");
    let (status, head, _) = request(http, &get("/account")).await;
    assert_eq!(status, 303); // See Other -> /login
    assert!(head.to_lowercase().contains("location: /login"), "{head}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn account_url_redirects_to_the_complete_account_console() {
    let url = support::test_db("account_url_redirects_to_the_complete_account_console").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account(&pool, "alice", "pw")
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
        }),
        database: Some(DatabaseConfig { url }),
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
    assert!(
        body.contains("prefers-reduced-motion: no-preference"),
        "{body}"
    );
    assert!(body.contains("forced-colors: active"), "{body}");
    assert!(
        head.to_ascii_lowercase()
            .contains("content-security-policy: default-src 'none'; script-src 'self'"),
        "{head}"
    );
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
    e6ircd::db::create_account(&pool, "alice", "pw")
        .await
        .expect("acct");
    e6ircd::db::create_bnc_network(
        &pool,
        "alice",
        &e6ircd::db::BncNetworkRow {
            kind: Default::default(),
            name: "libera".into(),
            addr: "irc.libera.chat:6697".into(),
            tls: true,
            nick: "alice_".into(),
            realname: None,
            autojoin: vec!["#e6irc".into()],
            sasl_account: None,
            sasl_password_sealed: None,
            enabled: true,
        },
    )
    .await
    .expect("network");
    e6ircd::db::persist_bnc_line(
        &pool,
        "alice",
        "libera",
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
        }),
        database: Some(DatabaseConfig { url }),
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
    let editor_req = format!(
        "GET /console/networks/libera/edit HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, editor) = request(http, &editor_req).await;
    assert_eq!(status, 200, "{editor}");
    assert!(editor.contains("data-api-owner-network-editor"), "{editor}");
    assert!(editor.contains("Loading network…"), "{editor}");
    assert!(!editor.contains("irc.libera.chat:6697"), "{editor}");
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
    assert!(
        operations["state"]
            .as_str()
            .is_some_and(|state| !state.is_empty()),
        "{operations}"
    );
    assert_eq!(operations["stored_lines"], 1);
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
    e6ircd::db::create_account(&pool, "alice", "pw")
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
        }),
        database: Some(DatabaseConfig { url: url.clone() }),
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
    assert!(body["current"]["queues"]["core"]["depth"].is_u64());
    assert_eq!(body["current"]["queues"]["core"]["capacity"], 65_536);
    assert_eq!(body["current"]["queues"]["db"]["capacity"], 1_024);
    assert_eq!(body["current"]["queues"]["core"]["mode"], "fifo");
    assert!(body["history"].is_array());
    let monitoring_api = format!(
        "GET /api/v1/admin/monitoring?minutes=60 HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, monitoring_headers, monitoring_body) = request(http, &monitoring_api).await;
    assert_eq!(status, 200, "{monitoring_body}");
    assert!(
        monitoring_headers
            .to_ascii_lowercase()
            .contains("cache-control: no-store"),
        "{monitoring_headers}"
    );
    let monitoring_body: serde_json::Value =
        serde_json::from_str(&monitoring_body).expect("monitoring JSON");
    assert_eq!(monitoring_body["window_minutes"], 60);
    assert!(monitoring_body["active_connections"].is_u64());
    assert!(monitoring_body["traffic_bars"].is_array());
    assert!(monitoring_body["window_links"].is_array());
    let invalid_monitoring_api = format!(
        "GET /api/v1/admin/monitoring?minutes=17 HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, invalid_monitoring_body) = request(http, &invalid_monitoring_api).await;
    assert_eq!(status, 400, "{invalid_monitoring_body}");
    assert!(
        invalid_monitoring_body.contains("Invalid monitoring window"),
        "{invalid_monitoring_body}"
    );
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
    assert!(body.contains("e6irc_queue_depth{queue=\"core\"}"));
    assert!(body.contains("e6irc_queue_capacity{queue=\"db\"} 1024"));
    assert!(body.contains("e6irc_queue_mode{queue=\"core\",mode=\"fifo\"} 1"));

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
    let mut settings = current["settings"].clone();
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
        serde_json::json!({ "revision": current["revision"], "settings": settings }).to_string();
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
        2
    );
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
    let expired_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM observability_samples WHERE sampled_at_ms = $1")
            .bind(i64::try_from(old_sampled_at).unwrap())
            .fetch_one(&verification_pool)
            .await
            .expect("expired sample count");
    assert_eq!(expired_count, 0, "sampler did not prune expired history");

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
    assert_eq!(snapshot.revision, 2);
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
    e6ircd::db::create_account(&pool, "alice", "pw")
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
        }),
        database: Some(e6ircd::config::DatabaseConfig { url: url.clone() }),
        secrets: Some(SecretsConfig {
            key_file: key_path,
            previous_key_files: Vec::new(),
        }),
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let http = running.http_addr.expect("http");
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

    let oidc_secret = "provider-secret-must-not-render";
    let oidc_body = format!(
        r#"{{"revision":2,"name":"workforce","issuer_url":"https://id.example","client_id":"e6irc","client_secret":"{oidc_secret}","scopes":["openid","profile"],"allowed_email_domains":[],"end_session_endpoint":"https://id.example/logout","token_endpoint_auth_method":"client_secret_post"}}"#
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
        r##"{{"revision":3,"name":"staffnet","owner":"alice","kind":"irc","addr":"irc.example:6697","tls":true,"nick":"alice","realname":"Alice","autojoin":["#staff"],"buffer_cap":321,"sasl_account":"alice-login","sasl_password":"{upstream_secret}"}}"##
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
    assert_eq!(api["revision"], 4);
    assert_eq!(api["runtime"]["has_master_key"], true);
    assert_eq!(api["runtime"]["master_key_count"], 1);
    assert_eq!(api["settings"]["opers"][0]["password"], "");
    assert_eq!(api["settings"]["oidc_providers"][0]["client_secret"], "");
    assert!(api["settings"]["networks"][0]["sasl_password"].is_null());
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
    let patch_body = serde_json::json!({ "revision": 4, "settings": scalar_settings }).to_string();
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
        5
    );

    let verification_pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("verification pool");
    let snapshot = e6ircd::db::load_managed_config(&verification_pool)
        .await
        .expect("managed configuration");
    assert_eq!(snapshot.revision, 5);
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
    assert_eq!(snapshot.settings.networks.len(), 1);
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

    let audit_details: Vec<String> =
        sqlx::query_scalar("SELECT detail FROM audit_log WHERE action = 'CONFIG' ORDER BY id")
            .fetch_all(&verification_pool)
            .await
            .expect("configuration audit");
    assert_eq!(audit_details.len(), 4);
    assert!(audit_details[0].contains("added IRC operator netop"));
    assert!(audit_details[1].contains("added OpenID Connect provider workforce"));
    assert!(audit_details[2].contains("added server network staffnet"));
    for detail in &audit_details {
        assert!(!detail.contains(oper_secret), "{detail}");
        assert!(!detail.contains(oidc_secret), "{detail}");
        assert!(!detail.contains(upstream_secret), "{detail}");
    }

    let delete_oper_body = r#"{"revision":5}"#;
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
        6
    );

    let delete_oidc_body = r#"{"revision":6}"#;
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
        7
    );
    let delete_network_body = r#"{"revision":7,"owner":"alice"}"#;
    let delete_network = format!(
        "DELETE /api/v1/admin/configuration/networks/staffnet HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-E6IRC-CSRF: {csrf}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{delete_network_body}",
        delete_network_body.len()
    );
    let (status, _, body) = request(http, &delete_network).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["revision"],
        8
    );
    let snapshot = e6ircd::db::load_managed_config(&verification_pool)
        .await
        .expect("managed configuration after deletes");
    assert_eq!(snapshot.revision, 8);
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
        e6ircd::db::create_account(&pool, account, "pw")
            .await
            .expect("account");
    }
    let boss_token = e6ircd::db::issue_api_token(&pool, "boss", "test")
        .await
        .expect("boss token");
    let alice_token = e6ircd::db::issue_api_token(&pool, "alice", "test")
        .await
        .expect("alice token");
    let mallory_token = e6ircd::db::issue_api_token(&pool, "mallory", "test")
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
        }),
        database: Some(DatabaseConfig { url }),
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
        .register_sasl("boss-live", "Boss", "boss", "pw")
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
        e6ircd::db::create_account(&pool, account, "pw")
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
        }),
        database: Some(DatabaseConfig { url }),
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let http = running.http_addr.expect("http");
    let page_request = |session: &str| {
        format!(
            "GET /console/channels HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
        )
    };

    let (status, _, page) = request(http, &page_request(&boss_session)).await;
    assert_eq!(status, 200, "{page}");
    for needle in [
        "Registered channels",
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
        .register_sasl("boss-console", "Boss", "boss", "pw")
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
    e6ircd::db::create_account(&pool, "alice", "pw")
        .await
        .expect("alice");
    e6ircd::db::create_account(&pool, "bob", "pw")
        .await
        .expect("bob");
    let alice_token = e6ircd::db::issue_api_token(&pool, "alice", "t")
        .await
        .expect("tok");
    let bob_token = e6ircd::db::issue_api_token(&pool, "bob", "t")
        .await
        .expect("tok");
    // Seed data for the other admin read endpoints.
    e6ircd::db::add_server_ban(&pool, "spammer@*", "spammer@*", "spam", "alice", "kline")
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
        }),
        database: Some(DatabaseConfig { url }),
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
    e6ircd::db::create_account(&pool, "alice", "pw")
        .await
        .expect("alice");
    e6ircd::db::create_account(&pool, "bob", "pw")
        .await
        .expect("bob");
    let alice_token = e6ircd::db::issue_api_token(&pool, "alice", "t")
        .await
        .expect("tok");
    let bob_token = e6ircd::db::issue_api_token(&pool, "bob", "t")
        .await
        .expect("tok");
    e6ircd::db::add_server_ban(&pool, "spammer@*", "spammer@*", "spam", "alice", "kline")
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
        }),
        database: Some(DatabaseConfig { url }),
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");

    let auth = |token: &str| {
        format!(
            "GET /console HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        )
    };
    // Anonymous -> redirect to /login (a page, not a 401 like the JSON API).
    let (status, head, _) = request(http, &get("/console")).await;
    assert_eq!(status, 303, "{head}");
    assert!(head.to_lowercase().contains("location: /login"), "{head}");
    // Signed-in non-admin -> 403.
    let (status, _, _) = request(http, &auth(&bob_token)).await;
    assert_eq!(status, 403);
    // Admin -> API-hydrated 200 shell; the seeded data must not be embedded.
    let (status, _, body) = request(http, &auth(&alice_token)).await;
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
        e6ircd::db::create_account(&pool, name, "pw")
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
    let api_secret = e6ircd::db::issue_api_token(&pool, "Alice", "automation")
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
             INSERT INTO bnc_networks (account_id, name, addr, nick, kind)
             SELECT id, 'local', '', 'Alice', 'irc' FROM account
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
        }),
        database: Some(DatabaseConfig { url }),
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

    e6ircd::db::create_account(&pool, "Dave", "pw")
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
    let bob_id = e6ircd::db::create_account(&pool, "Bob", "bob password")
        .await
        .expect("Bob");
    let alice_token = e6ircd::db::issue_api_token(&pool, "Alice", "administrator API")
        .await
        .expect("Alice token");
    let bob_token = e6ircd::db::issue_api_token(&pool, "Bob", "Bob API")
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
        }),
        database: Some(DatabaseConfig { url: url.clone() }),
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
    assert!(body.contains("exactly one"), "{body}");

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
    let new_bob_token = e6ircd::db::issue_api_token(&verification, "Bob", "reactivated API")
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
    let alice_token = e6ircd::db::issue_api_token(&pool, "Alice", "administrator API")
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
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![],
        }),
        database: Some(DatabaseConfig { url: url.clone() }),
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
        }),
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
    assert!(invitation_url.starts_with("/invite/e6i_"), "{body}");
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

    let (status, invite_headers, invite_page) = request(http, &get(invitation_url)).await;
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
        "POST {invitation_url} HTTP/1.1\r\nHost: t\r\nCookie: {invitation_cookie}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{bad_accept}",
        bad_accept.len()
    );
    let (status, _, body) = request(http, &bad_request).await;
    assert_eq!(status, 403, "{body}");

    let (status, invite_headers, invite_page) = request(http, &get(invitation_url)).await;
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
        "POST {invitation_url} HTTP/1.1\r\nHost: t\r\nCookie: {invitation_cookie}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{accept_body}",
        accept_body.len()
    );
    let (status, accept_headers, body) = request(http, &accept_request).await;
    assert_eq!(status, 303, "{body}");
    assert_eq!(
        response_header(&accept_headers, "location"),
        Some("/console")
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
    assert_eq!(
        e6ircd::db::verify_local_password(&pool, "Bob", "bob-password")
            .await
            .expect("Bob password"),
        Some("Bob".into())
    );
    let (status, _, body) = request(http, &get(invitation_url)).await;
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
        e6ircd::db::create_account(&pool, "carol", "replacement").await,
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
        e6ircd::db::set_channel_founder(&pool, "#bob", "alice")
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
        e6ircd::db::create_account(&pool, name, "pw")
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
        e6ircd::db::add_server_ban(&pool, mask, display, reason, setter, kind)
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
        }),
        database: Some(DatabaseConfig { url }),
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
    e6ircd::db::add_server_ban(
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
    e6ircd::db::create_account(&pool, "alice", "pw")
        .await
        .expect("alice");
    e6ircd::db::create_account(&pool, "bob", "pw")
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
        }),
        database: Some(DatabaseConfig { url }),
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
    assert!(page.contains("Exact filters"), "{page}");
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
    e6ircd::db::create_account(&pool, "alice", "pw")
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
        }),
        database: Some(DatabaseConfig { url }),
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
    e6ircd::db::create_account(&pool, "alice", "pw")
        .await
        .expect("alice");
    e6ircd::db::create_account(&pool, "bob", "pw")
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
        }),
        database: Some(DatabaseConfig { url }),
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
    victim.register("victim", "v").await.expect("register");
    let mut peer = e6irc_client::Connection::connect(&irc.to_string())
        .await
        .expect("peer tcp");
    peer.register("peer", "p").await.expect("register peer");

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
    let killed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
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
        .register("api-victim", "v")
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
    e6ircd::db::create_account(&pool, "alice", "s3cr3t")
        .await
        .expect("alice");
    e6ircd::db::create_account(&pool, "bob", "s3cr3t")
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
            admin_accounts: vec![], // alice is NOT an admin: this is self-service
        }),
        database: Some(DatabaseConfig { url }),
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
        .register_sasl("alicecli", "A", "alice", "s3cr3t")
        .await
        .expect("alice sasl");
    let mut bob_cli = e6irc_client::Connection::connect(&irc.to_string())
        .await
        .expect("tcp b");
    bob_cli
        .register_sasl("bobcli", "B", "bob", "s3cr3t")
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
    let bob_alive = tokio::time::timeout(std::time::Duration::from_secs(3), async {
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
        .register_sasl("aliceapi", "A", "alice", "s3cr3t")
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
    e6ircd::db::create_account(&pool, "alice", "pw")
        .await
        .expect("alice");
    e6ircd::db::create_account(&pool, "bob", "pw")
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
        }),
        database: Some(DatabaseConfig { url }),
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
    e6ircd::db::create_account(&pool, "alice", "pw")
        .await
        .expect("alice");
    e6ircd::db::create_account(&pool, "bob", "pw")
        .await
        .expect("bob");
    let alice_token = e6ircd::db::issue_api_token(&pool, "alice", "t")
        .await
        .expect("tok");
    let bob_token = e6ircd::db::issue_api_token(&pool, "bob", "t")
        .await
        .expect("tok");
    e6ircd::db::create_bnc_network(
        &pool,
        "alice",
        &e6ircd::db::BncNetworkRow {
            kind: e6ircd::config::NetworkKind::Matrix,
            name: "matrix-archive".into(),
            addr: "https://matrix.example".into(),
            tls: true,
            nick: "alice".into(),
            realname: None,
            autojoin: vec![],
            sasl_account: None,
            sasl_password_sealed: Some("enc:v1:test".into()),
            enabled: false,
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
        }),
        database: Some(DatabaseConfig { url }),
        ..Config::default()
    };
    let http = net::start(config)
        .await
        .expect("start")
        .http_addr
        .expect("http");

    let auth = |token: &str| {
        format!(
            "GET /console/integrations HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        )
    };
    // Anonymous -> redirect to /login.
    let (status, head, _) = request(http, &get("/console/integrations")).await;
    assert_eq!(status, 303, "{head}");
    // Signed-in non-admin -> 403.
    let (status, _, _) = request(http, &auth(&bob_token)).await;
    assert_eq!(status, 403);
    // Admin -> 200 with static bridge capabilities; the stored bridge inventory
    // is hydrated from the administrator API rather than rendered into HTML.
    let (status, _, body) = request(http, &auth(&alice_token)).await;
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
    e6ircd::db::create_account(&pool, "alice", "pw")
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
            realname: None,
            autojoin: vec![],
            sasl_account: None,
            sasl_password_sealed: Some("enc:v1:test".into()),
            enabled: false,
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
        }),
        database: Some(DatabaseConfig { url: url.clone() }),
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
        }),
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
    e6ircd::db::create_account(&pool, "alice", "pw")
        .await
        .expect("alice");
    let session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("session");
    let api_token = e6ircd::db::issue_api_token(&pool, "alice", "bridge-edit")
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
            realname: None,
            autojoin: vec!["!old:example".into()],
            sasl_account: None,
            sasl_password_sealed: Some(matrix_password),
            enabled: false,
        },
        e6ircd::db::BncNetworkRow {
            kind: e6ircd::config::NetworkKind::Discord,
            name: "discord-main".into(),
            addr: String::new(),
            tls: true,
            nick: String::new(),
            realname: None,
            autojoin: vec!["100".into()],
            sasl_account: None,
            sasl_password_sealed: Some(discord_token),
            enabled: false,
        },
        e6ircd::db::BncNetworkRow {
            kind: e6ircd::config::NetworkKind::Slack,
            name: "slack-main".into(),
            addr: String::new(),
            tls: true,
            nick: String::new(),
            realname: None,
            autojoin: vec!["C100".into()],
            sasl_account: Some(slack_bot_token.clone()),
            sasl_password_sealed: Some(slack_app_token),
            enabled: false,
        },
    ] {
        e6ircd::db::create_bnc_network(&pool, "alice", &row)
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
        }),
        database: Some(DatabaseConfig { url: url.clone() }),
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
        }),
        secrets: Some(SecretsConfig {
            key_file: key_path,
            previous_key_files: Vec::new(),
        }),
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
        "credentials": { "action": "set", "password": "matrix-new-password" }
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
        "credentials": { "action": "set", "password": "discord-new-token" }
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
        "credentials": { "action": "set", "password": "slack-new-app" }
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
        "credentials": { "action": "set", "password": "do-not-echo" }
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
        realname: None,
        autojoin: vec![],
        sasl_account: None,
        sasl_password_sealed: None,
        enabled: false,
    };
    e6ircd::db::create_bnc_network(&verification, "alice", &irc)
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
    e6ircd::db::create_account(&pool, "alice", "pw")
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
        }),
        database: Some(DatabaseConfig { url }),
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
        }),
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
    assert_eq!(status, 204, "{body}");
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
    let (status, _, body) = request(http, &create_app).await;
    assert_eq!(status, 201, "{body}");
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
    let (status, _, body) = request(http, &create_token).await;
    assert_eq!(status, 201, "{body}");
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
    e6ircd::db::create_account(&pool, "alice", "pw")
        .await
        .expect("acct");
    let session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("session");
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
            public_url: Some("https://e6.example".into()),
            secure_cookies: false,
            admin_accounts: vec![],
        }),
        database: Some(DatabaseConfig { url }),
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
    assert!(v["verification_uri"].as_str().unwrap().ends_with("/device"));

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
    let csrf = page
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .expect("csrf field")
        .split('"')
        .next()
        .expect("csrf value")
        .to_string();

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
    e6ircd::db::create_account(&pool, "alice", "pw")
        .await
        .expect("alice");
    let auth_token = e6ircd::db::issue_api_token(&pool, "alice", "auth")
        .await
        .expect("t");
    let _extra = e6ircd::db::issue_api_token(&pool, "alice", "todelete")
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
        }),
        database: Some(DatabaseConfig { url }),
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
    e6ircd::db::create_account(&pool, "alice", "pw")
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
        }),
        database: Some(DatabaseConfig { url }),
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
    e6ircd::db::create_account(&pool, "alice", "pw")
        .await
        .expect("alice");
    e6ircd::db::create_account(&pool, "bob", "pw")
        .await
        .expect("bob");
    let alice_token = e6ircd::db::issue_api_token(&pool, "alice", "automation")
        .await
        .expect("Alice token");
    let alice_session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("Alice session");
    let bob_token = e6ircd::db::issue_api_token(&pool, "bob", "automation")
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
        }),
        database: Some(DatabaseConfig { url }),
        limits: e6ircd::config::LimitsConfig {
            api_rate_burst: Some(2),
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
    e6ircd::db::create_account(&pool, "alice", "pw")
        .await
        .expect("alice");
    let token = e6ircd::db::issue_api_token(&pool, "alice", "t")
        .await
        .expect("token");
    // A network the caller owns, disabled so boot starts no driver — the
    // buffer read is pure DB and must work for a paused network too.
    e6ircd::db::create_bnc_network(
        &pool,
        "alice",
        &e6ircd::db::BncNetworkRow {
            kind: Default::default(),
            name: "work".into(),
            addr: "127.0.0.1:1".into(),
            tls: false,
            nick: "alice_".into(),
            realname: None,
            autojoin: vec![],
            sasl_account: None,
            sasl_password_sealed: None,
            enabled: false,
        },
    )
    .await
    .expect("create");
    for line in [
        ":srv 001 alice :hi",
        ":a!u@h PRIVMSG #x :one",
        ":a!u@h PRIVMSG #x :two",
    ] {
        e6ircd::db::persist_bnc_line(&pool, "alice", "work", line)
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
        }),
        database: Some(DatabaseConfig { url }),
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
        }),
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
    e6ircd::db::create_account(&pool, "alice", "pw")
        .await
        .expect("alice");
    let token = e6ircd::db::issue_api_token(&pool, "alice", "t")
        .await
        .expect("token");
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
        }),
        database: Some(DatabaseConfig { url }),
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
    e6ircd::db::create_account(&pool, "alice", "pw")
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
            public_url: Some("https://e6irc.example".into()),
            secure_cookies: false,
            admin_accounts: vec![],
        }),
        database: Some(DatabaseConfig { url }),
        oidc_providers: vec![OidcProviderConfig {
            name: "shauth".into(),
            issuer_url: "https://auth.example".into(),
            client_id: "e6irc".into(),
            client_secret: "x".repeat(32),
            scopes: vec![],
            allowed_email_domains: vec![],
            end_session_endpoint: Some("https://auth.example/oauth2/sessions/logout".into()),
            token_endpoint_auth_method: Default::default(),
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
        "https://e6irc.example/auth/shauth/logout/complete"
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
        assert!(body.contains("aria-label=\"e6irc\">e6irc</span>"), "{body}");
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
    e6ircd::db::create_account(&pool, "alice", "pw")
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
            public_url: Some("https://chat.example".into()),
            secure_cookies: false,
            admin_accounts: vec![],
        }),
        database: Some(DatabaseConfig { url }),
        oidc_providers: vec![OidcProviderConfig {
            name: "shauth".into(),
            issuer_url: "https://auth.example".into(),
            client_id: "e6irc".into(),
            client_secret: "x".repeat(32),
            scopes: vec![],
            allowed_email_domains: vec![],
            end_session_endpoint: Some("https://auth.example/oauth2/sessions/logout".into()),
            token_endpoint_auth_method: Default::default(),
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
    e6ircd::db::create_account(&pool, "alice", "pw")
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
            public_url: Some("https://chat.example".into()),
            secure_cookies: false,
            admin_accounts: vec![],
        }),
        database: Some(DatabaseConfig { url }),
        oidc_providers: vec![OidcProviderConfig {
            name: "corp".into(),
            issuer_url: "https://auth.example".into(),
            client_id: "e6irc".into(),
            client_secret: "x".repeat(32),
            scopes: vec![],
            allowed_email_domains: vec![],
            end_session_endpoint: None,
            token_endpoint_auth_method: Default::default(),
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
    e6ircd::db::create_account(&pool, "alice", "pw")
        .await
        .expect("alice");
    e6ircd::db::create_account(&pool, "bob", "pw")
        .await
        .expect("bob");
    let alice_token = e6ircd::db::issue_api_token(&pool, "alice", "t")
        .await
        .expect("tok");
    let bob_token = e6ircd::db::issue_api_token(&pool, "bob", "t")
        .await
        .expect("tok");
    let session = e6ircd::db::create_web_session(&pool, "alice", None)
        .await
        .expect("session");
    // Bob owns an enabled network; its driver cannot dial 127.0.0.1:1, which
    // is exactly the "misbehaving upstream" the admin lever exists for.
    e6ircd::db::create_bnc_network(
        &pool,
        "bob",
        &e6ircd::db::BncNetworkRow {
            kind: Default::default(),
            name: "work".into(),
            addr: "127.0.0.1:1".into(),
            tls: false,
            nick: "bob_".into(),
            realname: None,
            autojoin: vec![],
            sasl_account: None,
            sasl_password_sealed: None,
            enabled: true,
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
        }),
        database: Some(DatabaseConfig { url: url.clone() }),
        bnc: Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
        }),
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
