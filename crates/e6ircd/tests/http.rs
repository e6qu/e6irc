//! e2e tests for the HTTP layer, over real sockets with a raw
//! HTTP/1.1 client (no client library needed for these shapes).

use e6ircd::config::{Config, HttpConfig, ListenerConfig};
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

#[tokio::test]
async fn healthz_is_public_and_ok() {
    let running = net::start(test_config()).await.expect("start");
    let http = running.http_addr.expect("http bound");
    let (status, _, body) = request(http, &get("/healthz")).await;
    assert_eq!(status, 200);
    assert_eq!(body, "ok");
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
            headers.contains("content-security-policy: default-src 'none'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
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

use e6ircd::config::{BncConfig, DatabaseConfig};

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
    let list_req = format!(
        "GET /api/v1/me/networks HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
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

    // Public runtime assets remain available so the login and account pages
    // can use the same vendored client code without opening the application.
    let (status, head, _) = request(http, &get("/htmx.min.js")).await;
    assert_eq!(status, 200);
    assert!(head.to_lowercase().contains("javascript"), "{head}");
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
async fn openapi_spec_is_served() {
    let running = net::start(test_config()).await.expect("start");
    let http = running.http_addr.expect("http bound");
    let (status, head, body) = request(http, &get("/api/v1/openapi.json")).await;
    assert_eq!(status, 200);
    assert!(head.to_lowercase().contains("application/json"), "{head}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON spec");
    assert_eq!(v["openapi"], "3.1.0");
    // A couple of representative paths are documented.
    assert!(
        v["paths"]["/api/v1/me/networks"]["post"].is_object(),
        "{body}"
    );
    assert!(v["paths"]["/healthz"]["get"].is_object());
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
    // No providers configured in the bare test config.
    assert!(body.contains("No login providers"), "{body}");
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
async fn account_page_lists_networks_for_a_session() {
    let url = support::test_db("account_page_lists_networks_for_a_session").await;
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
            autojoin: vec![],
            sasl_account: None,
            sasl_password_sealed: None,
            enabled: true,
        },
    )
    .await
    .expect("network");
    let session = e6ircd::db::create_web_session(&pool, "alice")
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

    let req = format!(
        "GET /account HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, head, body) = request(http, &req).await;
    assert_eq!(status, 200, "{head}");
    assert!(body.contains("alice"), "account name: {body}");
    assert!(body.contains("libera"), "network listed: {body}");
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
    let session = e6ircd::db::create_web_session(&pool, "alice")
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

    // Authenticated -> the console shell with the caller's network and its
    // status column.
    let req = format!(
        "GET /console/networks HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, head, body) = request(http, &req).await;
    assert_eq!(status, 200, "{head}");
    for needle in [
        "e6irc console",
        "BNC networks",
        "libera",
        "irc.libera.chat:6697",
        "#e6irc",
    ] {
        assert!(
            body.contains(needle),
            "console networks missing {needle:?}: {body}"
        );
    }
}

/// The console networks page can add and remove a network via htmx even before
/// the raw attach listener is enabled. Network management depends on the
/// database-backed registry, not on an unrelated startup listener flag.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn console_add_and_delete_network_via_the_console() {
    let url = support::test_db("console_add_and_delete_network_via_the_console").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account(&pool, "alice", "pw")
        .await
        .expect("acct");
    let session = e6ircd::db::create_web_session(&pool, "alice")
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
        .expect("http");

    // Load the page and extract the session-bound CSRF token.
    let page_req = format!(
        "GET /console/networks HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (_, _, page) = request(http, &page_req).await;
    assert!(
        page.contains("Raw IRC attachment is currently off"),
        "{page}"
    );
    let csrf = page
        .split("X-CSRF-Token\": \"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("csrf token in page")
        .to_string();
    assert!(!csrf.is_empty());

    // Add a network with the CSRF header -> 200 rows fragment carrying it.
    let body = "name=work&addr=irc.example:6667&nick=alice_&autojoin=%23lobby&tls=on";
    let add = format!(
        "POST /console/networks HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-CSRF-Token: {csrf}\r\nContent-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let (status, _, frag) = request(http, &add).await;
    assert_eq!(status, 200, "{frag}");
    assert!(
        frag.contains("work") && frag.contains("irc.example:6667"),
        "{frag}"
    );

    // Disable the network via the toggle button -> 200 fragment showing it
    // stopped and offering to Enable it again.
    let off = "enabled=false";
    let toggle_off = format!(
        "POST /console/networks/work/toggle HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-CSRF-Token: {csrf}\r\nContent-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{off}",
        off.len()
    );
    let (status, _, frag) = request(http, &toggle_off).await;
    assert_eq!(status, 200, "{frag}");
    assert!(
        frag.contains("Enable") && frag.contains("stopped"),
        "{frag}"
    );

    // Re-enable it -> 200 fragment offering to Disable.
    let on = "enabled=true";
    let toggle_on = format!(
        "POST /console/networks/work/toggle HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-CSRF-Token: {csrf}\r\nContent-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{on}",
        on.len()
    );
    let (status, _, frag) = request(http, &toggle_on).await;
    assert_eq!(status, 200, "{frag}");
    assert!(frag.contains("Disable"), "{frag}");

    // A name outside the token charset is refused (this is what breaks the htmx
    // delete path and the JS-string confirm) -> 400, nothing created.
    let bad = "name=bad%3Fname&addr=irc.example:6667&nick=z";
    let add_bad = format!(
        "POST /console/networks HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-CSRF-Token: {csrf}\r\nContent-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{bad}",
        bad.len()
    );
    let (status, _, _) = request(http, &add_bad).await;
    assert_eq!(status, 400);

    // Without the CSRF header -> 403.
    let no_csrf = format!(
        "POST /console/networks HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    let (status, _, _) = request(http, &no_csrf).await;
    assert_eq!(status, 403);

    // Delete it with the CSRF header -> 200 rows fragment without it.
    let del = format!(
        "DELETE /console/networks/work HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-CSRF-Token: {csrf}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, frag) = request(http, &del).await;
    assert_eq!(status, 200, "{frag}");
    assert!(!frag.contains("irc.example:6667"), "still present: {frag}");
}

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
    let session = e6ircd::db::create_web_session(&pool, "alice")
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
    assert!(page.contains("Revision 1"), "{page}");
    let csrf = page
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("CSRF token");

    let form = format!(
        "csrf={csrf}&revision=1&server_name=irc.control.example&network_name=ControlNet&\
         description=e6irc+server&motd=&nicklen=16&sendq=1024&core_queue=65536&\
         max_hot_channels=8192&bnc_enabled=on&bnc_addr=127.0.0.1%3A0&\
         listeners=127.0.0.1%3A0+%7C+plain&admin_accounts=alice"
    );
    let post = format!(
        "POST /console/configuration HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{form}",
        form.len()
    );
    let (status, _, page) = request(http, &post).await;
    assert_eq!(status, 200, "{page}");
    assert!(page.contains("Configuration saved and applied"), "{page}");
    let bound = page
        .split("Accepting clients on <code>")
        .nth(1)
        .and_then(|rest| rest.split("</code>").next())
        .expect("bound BNC address");
    let _: tokio::net::TcpStream = tokio::net::TcpStream::connect(bound)
        .await
        .expect("runtime listener accepts");

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

/// Editing a network from the console: the pre-filled form, a successful field
/// update (persisted + reflected in the list), and the SSRF guard on a changed
/// address re-rendering with an error banner.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn console_edit_network_updates_fields() {
    let url = support::test_db("console_edit_network_updates_fields").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account(&pool, "alice", "pw")
        .await
        .expect("acct");
    let session = e6ircd::db::create_web_session(&pool, "alice")
        .await
        .expect("session");
    // A bridge network (kind=matrix), inserted directly (creating one needs the
    // feature build). enabled=false so boot doesn't try to build its driver.
    sqlx::query(
        "INSERT INTO bnc_networks
           (account_id, name, addr, tls, nick, realname, autojoin,
            sasl_account, sasl_password_sealed, kind, enabled)
         SELECT id, 'mtx', 'matrix.example', false, 'bot', NULL,
                ARRAY[]::text[], NULL, 'enc:v1:x', 'matrix', false
         FROM accounts WHERE name_folded = 'alice'",
    )
    .execute(&pool)
    .await
    .expect("bridge row");
    drop(pool);

    let config = Config {
        server_name: "irc.edit.example".into(),
        network_name: "EditNet".into(),
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

    // Extract the session CSRF from the networks page (add form's header value).
    let page_req = format!(
        "GET /console/networks HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (_, _, page) = request(http, &page_req).await;
    let csrf = page
        .split("X-CSRF-Token\": \"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("csrf")
        .to_string();

    // Create the network to edit.
    let body = "name=work&addr=irc.example:6667&nick=alice_&autojoin=%23lobby";
    let add = format!(
        "POST /console/networks HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-CSRF-Token: {csrf}\r\nContent-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let (status, _, _) = request(http, &add).await;
    assert_eq!(status, 200);

    // The edit form is pre-filled with the current values.
    let edit_get = format!(
        "GET /console/networks/work/edit HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, form) = request(http, &edit_get).await;
    assert_eq!(status, 200, "{form}");
    assert!(
        form.contains("value=\"alice_\"") && form.contains("irc.example:6667"),
        "{form}"
    );

    // Apply an edit (body CSRF; plain form) -> 303 back to the list.
    let edit =
        "csrf=CSRF&addr=irc.new.example:6697&nick=newbie&realname=Bob&autojoin=%23lobby&tls=on"
            .replace("CSRF", &csrf);
    let edit_post = format!(
        "POST /console/networks/work/edit HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{edit}",
        edit.len()
    );
    let (status, head, _) = request(http, &edit_post).await;
    assert_eq!(status, 303, "{head}");

    // The list now shows the new nick and address.
    let (_, _, page2) = request(http, &page_req).await;
    assert!(
        page2.contains("newbie") && page2.contains("irc.new.example:6697"),
        "{page2}"
    );

    // The SSRF guard applies to a changed address too: an internal IP is refused
    // and the form re-renders (200) with an error banner.
    let bad = "csrf=CSRF&addr=169.254.169.254:6667&nick=newbie".replace("CSRF", &csrf);
    let bad_post = format!(
        "POST /console/networks/work/edit HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{bad}",
        bad.len()
    );
    let (status, _, body) = request(http, &bad_post).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains("banner-error") && body.contains("Could not save"),
        "{body}"
    );

    // Wrong CSRF is refused.
    let wrong = "csrf=nope&addr=irc.x.example:6667&nick=z";
    let wrong_post = format!(
        "POST /console/networks/work/edit HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{wrong}",
        wrong.len()
    );
    let (status, _, _) = request(http, &wrong_post).await;
    assert_eq!(status, 403);

    // A bridge network is not editable via the IRC edit form: the GET redirects
    // away, and a direct POST does not clobber the bridge's stored fields.
    let bridge_get = format!(
        "GET /console/networks/mtx/edit HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, head, _) = request(http, &bridge_get).await;
    assert_eq!(status, 303, "{head}"); // redirected away, no IRC form for a bridge
    let bridge_edit = "csrf=CSRF&addr=irc.x.example:6667&nick=z".replace("CSRF", &csrf);
    let bridge_post = format!(
        "POST /console/networks/mtx/edit HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{bridge_edit}",
        bridge_edit.len()
    );
    let _ = request(http, &bridge_post).await; // refused (re-render); must not apply
    // The bridge's address is unchanged — the attempted overwrite was rejected.
    let (_, _, page3) = request(http, &page_req).await;
    assert!(
        page3.contains("matrix.example"),
        "bridge addr lost: {page3}"
    );
    assert!(
        !page3.contains("irc.x.example"),
        "bridge addr was clobbered: {page3}"
    );
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
    let (status, _, body) = request(http, &getauth(&alice_token)).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let names: Vec<&str> = v["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap())
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
        let (status, _, body) = request(http, &auth(&alice_token)).await;
        assert_eq!(status, 200, "{path}: {body}");
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        // Every admin read endpoint returns its keyed payload: a non-empty
        // array for the list endpoints, a present value for stats' counts.
        assert!(
            v[key].as_array().is_some_and(|a| !a.is_empty()) || v[key].is_number(),
            "{path} empty: {body}"
        );
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
/// and an admin gets a server-rendered dashboard carrying the seeded server data.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn admin_console_page_renders_server_data_for_admins_only() {
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
    // Admin -> 200 with the seeded server data rendered into the dashboard.
    let (status, _, body) = request(http, &auth(&alice_token)).await;
    assert_eq!(status, 200, "{body}");
    for needle in [
        "e6irc console",
        "irc.console.example",
        "ConsoleNet",
        "alice",
        "bob",
        "#lounge",
        "spammer@*",
        "KLINE",
    ] {
        assert!(body.contains(needle), "console missing {needle:?}: {body}");
    }
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
    let session = e6ircd::db::create_web_session(&pool, "alice")
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

    // Load the console and extract the session-bound CSRF token.
    let page_req = format!(
        "GET /console HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, page) = request(http, &page_req).await;
    assert_eq!(status, 200, "{page}");
    let csrf = page
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("csrf token in console")
        .to_string();
    assert!(!csrf.is_empty());

    // Fetch /console and test for a needle, retrying while the redirect's
    // committed core action becomes visible to the independent list query.
    let console_has = |needle: &'static str, want: bool| {
        let req = page_req.clone();
        async move {
            for _ in 0..40 {
                let (_, _, body) = request(http, &req).await;
                if body.contains(needle) == want {
                    return true;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            false
        }
    };

    // Add a K-line via the console -> 303 back to /console; the ban appears.
    let body = "csrf=CSRF&kind=kline&mask=*@bad.example&reason=spam";
    let body = body.replace("CSRF", &csrf);
    let add = format!(
        "POST /console/bans HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    let (status, head, _) = request(http, &add).await;
    assert_eq!(status, 303, "{head}");
    // Discriminate on the bans-table empty-state text, not the mask itself: the
    // mask also appears in the audit-log rows (KLINE/UNKLINE target), so a bare
    // substring check would false-match after removal.
    assert!(
        console_has("No server bans.", false).await,
        "ban not listed after add"
    );

    // Remove it -> 303; the bans table is empty again.
    let del = "csrf=CSRF&kind=kline&mask=*@bad.example".replace("CSRF", &csrf);
    let del_req = format!(
        "POST /console/bans/delete HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{del}",
        del.len()
    );
    let (status, _, _) = request(http, &del_req).await;
    assert_eq!(status, 303);
    assert!(
        console_has("No server bans.", true).await,
        "ban still listed after remove"
    );

    // Drop the registered channel -> 303; the channel list becomes empty.
    assert!(
        console_has("No registered channels.", false).await,
        "channel not listed to begin with"
    );
    let drop_body = "csrf=CSRF&channel=%23dropme".replace("CSRF", &csrf);
    let drop_req = format!(
        "POST /console/channels/drop HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{drop_body}",
        drop_body.len()
    );
    let (status, _, _) = request(http, &drop_req).await;
    assert_eq!(status, 303);
    assert!(
        console_has("No registered channels.", true).await,
        "channel still listed after drop"
    );

    // Gate: a wrong CSRF is refused (403); an anonymous POST redirects to login.
    let bad = "csrf=wrong&kind=kline&mask=*@x.example&reason=x";
    let bad_req = format!(
        "POST /console/bans HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{bad}",
        bad.len()
    );
    let (status, _, _) = request(http, &bad_req).await;
    assert_eq!(status, 403);
    let anon = format!(
        "POST /console/bans HTTP/1.1\r\nHost: t\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{bad}",
        bad.len()
    );
    let (status, head, _) = request(http, &anon).await;
    assert_eq!(status, 303, "{head}");
    assert!(head.to_lowercase().contains("location: /login"), "{head}");
}

/// Admin console live-sessions view + KILL: a connected IRC client shows up in
/// the sessions list and can be disconnected from the console.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn admin_console_lists_and_kills_sessions() {
    let url = support::test_db("admin_console_lists_and_kills_sessions").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account(&pool, "alice", "pw")
        .await
        .expect("alice");
    let session = e6ircd::db::create_web_session(&pool, "alice")
        .await
        .expect("session");
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

    // A client connects and registers, so it is a live session.
    let mut victim = e6irc_client::Connection::connect(&irc.to_string())
        .await
        .expect("tcp");
    victim.register("victim", "v").await.expect("register");

    let sessions_req = format!(
        "GET /console/sessions HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    // Wait for the session to appear (registration completes asynchronously).
    let mut csrf = String::new();
    let mut listed = false;
    for _ in 0..40 {
        let (status, _, body) = request(http, &sessions_req).await;
        assert_eq!(status, 200, "{body}");
        if body.contains("victim") {
            listed = true;
            csrf = body
                .split("name=\"csrf\" value=\"")
                .nth(1)
                .and_then(|s| s.split('"').next())
                .unwrap_or("")
                .to_string();
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(listed, "victim session not listed");
    assert!(!csrf.is_empty(), "no csrf on sessions page");

    // KILL it from the console -> 303 back to the sessions view.
    let body = "csrf=CSRF&nick=victim&reason=cleanup".replace("CSRF", &csrf);
    let kill = format!(
        "POST /console/sessions/kill HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    let (status, head, _) = request(http, &kill).await;
    assert_eq!(status, 303, "{head}");

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

    // It no longer appears in the sessions list.
    let mut gone = false;
    for _ in 0..40 {
        let (_, _, body) = request(http, &sessions_req).await;
        if !body.contains(">victim<") && !body.contains("<code>victim</code>") {
            gone = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(gone, "victim still listed after kill");
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
    let session = e6ircd::db::create_web_session(&pool, "alice")
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
    // Wait for alice's own client to be listed; bob's must never appear.
    let mut csrf = String::new();
    let mut ok = false;
    for _ in 0..40 {
        let (status, _, body) = request(http, &page_req).await;
        assert_eq!(status, 200, "{body}");
        if body.contains("alicecli") {
            assert!(
                !body.contains("bobcli"),
                "another account's session leaked: {body}"
            );
            csrf = body
                .split("name=\"csrf\" value=\"")
                .nth(1)
                .and_then(|s| s.split('"').next())
                .unwrap_or("")
                .to_string();
            ok = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(ok && !csrf.is_empty(), "alice's own session not listed");

    // Attempt to kill bob's session by nick -> refused (not the caller's); bob
    // stays connected.
    let kill_bob = format!("csrf={csrf}&nick=bobcli&reason=x");
    let kb = format!(
        "POST /console/my-sessions/kill HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{kill_bob}",
        kill_bob.len()
    );
    let (status, _, body) = request(http, &kb).await;
    assert_eq!(status, 200, "{body}"); // re-renders with a banner, not a redirect
    assert!(
        body.contains("banner-error"),
        "expected refusal banner: {body}"
    );
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

    // Killing alice's own session works -> 303 and the client is disconnected.
    let kill_me = format!("csrf={csrf}&nick=alicecli&reason=bye");
    let km = format!(
        "POST /console/my-sessions/kill HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{kill_me}",
        kill_me.len()
    );
    let (status, head, _) = request(http, &km).await;
    assert_eq!(status, 303, "{head}");
    let killed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match alice_cli.next_message().await {
                Ok(Some(m)) if m.command == "ERROR" => return true,
                Ok(Some(_)) => continue,
                _ => return true, // EOF
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(killed, "alice's own session was not disconnected");
}

/// The console Integrations page is admin-gated and lists every chat-platform
/// bridge with its build availability. This default (no-bridge-feature) build
/// reports all three as not built.
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
    // Admin -> 200 listing all three platforms; none is built in this binary.
    let (status, _, body) = request(http, &auth(&alice_token)).await;
    assert_eq!(status, 200, "{body}");
    for needle in ["Integrations", "Matrix", "Discord", "Slack", "not built"] {
        assert!(
            body.contains(needle),
            "integrations missing {needle:?}: {body}"
        );
    }
}

/// Adding a bridge from the console is admin + CSRF gated and refuses a kind
/// whose build feature is absent (this default build has none) — proving the
/// POST plumbing and the feature gate without needing a live bridge service.
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
    let session = e6ircd::db::create_web_session(&pool, "alice")
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
            admin_accounts: vec!["alice".into()],
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

    // The CSRF token is session-bound; read it from the account page.
    let page = format!(
        "GET /account HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (_, _, body) = request(http, &page).await;
    let csrf = body
        .split("X-CSRF-Token\": \"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("csrf token")
        .to_string();

    let form = format!(
        "csrf={csrf}&kind=matrix&name=hq&addr=https://matrix.example&nick=e6bot&sasl_password=secret"
    );
    let post = format!(
        "POST /console/integrations HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{form}",
        form.len()
    );
    // Feature not built in this binary -> the integrations page is re-rendered
    // (200) with an error banner naming the feature, rather than a raw
    // problem+json page.
    let (status, _, body) = request(http, &post).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains("feature") && body.contains("banner-error"),
        "{body}"
    );

    // A wrong CSRF token -> 403.
    let form_nocsrf = "csrf=wrong&kind=matrix&name=hq&sasl_password=x";
    let post_nocsrf = format!(
        "POST /console/integrations HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{form_nocsrf}",
        form_nocsrf.len()
    );
    let (status, _, _) = request(http, &post_nocsrf).await;
    assert_eq!(status, 403);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn account_page_add_network_form_with_csrf() {
    let url = support::test_db("account_page_add_network_form_with_csrf").await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account(&pool, "alice", "pw")
        .await
        .expect("acct");
    let session = e6ircd::db::create_web_session(&pool, "alice")
        .await
        .expect("session");
    drop(pool);

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

    // Load the account page and extract the session-bound CSRF token.
    let page_req = format!(
        "GET /account HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
    );
    let (_, _, page) = request(http, &page_req).await;
    let csrf = page
        .split("X-CSRF-Token\": \"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("csrf token in page")
        .to_string();
    assert!(!csrf.is_empty());

    // Add a network via the form with the CSRF header -> 200 fragment.
    let body = "name=work&addr=irc.example:6667&nick=alice_&autojoin=%23lobby&tls=on";
    let add = format!(
        "POST /account/networks HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         X-CSRF-Token: {csrf}\r\nContent-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let (status, _, frag) = request(http, &add).await;
    assert_eq!(status, 200, "{frag}");
    assert!(
        frag.contains("work") && frag.contains("irc.example:6667"),
        "{frag}"
    );

    // Same request without the CSRF header -> 403.
    let no_csrf = format!(
        "POST /account/networks HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    let (status, _, _) = request(http, &no_csrf).await;
    assert_eq!(status, 403);
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
    let session = e6ircd::db::create_web_session(&pool, "alice")
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
    let (status, _, _) = request(
        http,
        &post("/api/v1/auth/device/approve", &cookie, &ap_body),
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
    let (status, _, body) = request(http, &auth).await;
    assert_eq!(status, 200, "{body}");
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
    let session = e6ircd::db::create_oidc_web_session(
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
    )
    .await
    .expect("sso session");
    let local_session = e6ircd::db::create_web_session(&pool, "alice")
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
            "GET /account HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    let csrf = page
        .split("X-CSRF-Token\": \"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("csrf token in page")
        .to_string();
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
                        "GET /account HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={value}\r\nConnection: close\r\n\r\n"
                    ),
                )
                .await;
                let token = page
                    .split("X-CSRF-Token\": \"")
                    .nth(1)
                    .and_then(|s| s.split('"').next())
                    .expect("csrf token in page");
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
async fn application_entry_is_fail_closed_and_starts_provider_authorization() {
    use e6ircd::config::{DatabaseConfig, OidcProviderConfig};
    let url =
        support::test_db("application_entry_is_fail_closed_and_starts_provider_authorization")
            .await;
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    e6ircd::db::create_account(&pool, "alice", "pw")
        .await
        .expect("acct");
    let session = e6ircd::db::create_web_session(&pool, "alice")
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
    assert_eq!(status, 307, "{headers}");
    assert!(
        headers.contains("/api/v1/auth/oidc/shauth/start"),
        "{headers}"
    );

    let (status, headers, _) = request(http, &get("/?sso=none")).await;
    assert_eq!(status, 303, "{headers}");
    assert!(headers.contains("location: /login") || headers.contains("Location: /login"));

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
    let session = e6ircd::db::create_oidc_web_session(
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
            "GET /account HTTP/1.1\r\nHost: t\r\nCookie: e6irc_session={session}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    let csrf = page
        .split("X-CSRF-Token\": \"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("csrf token in page")
        .to_string();
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
