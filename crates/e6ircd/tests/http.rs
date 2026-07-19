//! e2e tests for the HTTP layer, over real sockets with a raw
//! HTTP/1.1 client (no client library needed for these shapes).

use e6ircd::config::{Config, HttpConfig, ListenerConfig};
use e6ircd::net;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn test_config() -> Config {
    Config {
        server_name: "irc.http.example".into(),
        network_name: "HttpNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
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
    let url = std::env::var("E6IRC_TEST_DATABASE_URL").expect("E6IRC_TEST_DATABASE_URL");
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    sqlx::query("TRUNCATE accounts CASCADE")
        .execute(&pool)
        .await
        .expect("clean");
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
    let url = std::env::var("E6IRC_TEST_DATABASE_URL").expect("E6IRC_TEST_DATABASE_URL");
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    sqlx::query("TRUNCATE accounts CASCADE")
        .execute(&pool)
        .await
        .expect("clean");
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
    assert_eq!(status, 200);
    assert!(head.to_lowercase().contains("text/html"), "{head}");
    // The built Vite index references a hashed asset bundle.
    assert!(body.contains("<title>e6irc</title>"), "{body}");
    let asset = body
        .split("/assets/")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("index should reference a built asset");
    // That hashed asset is served with an immutable cache header.
    let (status, head, _) = request(http, &get(&format!("/assets/{asset}"))).await;
    assert_eq!(status, 200, "asset /assets/{asset}");
    assert!(head.to_lowercase().contains("immutable"), "{head}");
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
    let url = std::env::var("E6IRC_TEST_DATABASE_URL").expect("E6IRC_TEST_DATABASE_URL");
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    sqlx::query("TRUNCATE accounts CASCADE")
        .execute(&pool)
        .await
        .expect("clean");
    sqlx::query("TRUNCATE bnc_networks")
        .execute(&pool)
        .await
        .ok();
    e6ircd::db::create_account(&pool, "alice", "pw")
        .await
        .expect("acct");
    e6ircd::db::create_bnc_network(
        &pool,
        "alice",
        &e6ircd::db::BncNetworkRow {
            name: "libera".into(),
            addr: "irc.libera.chat:6697".into(),
            tls: true,
            nick: "alice_".into(),
            realname: None,
            autojoin: vec![],
            sasl_account: None,
            sasl_password_sealed: None,
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

// ---- admin API (PG-gated) -----------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn admin_accounts_endpoint_is_gated() {
    let url = std::env::var("E6IRC_TEST_DATABASE_URL").expect("E6IRC_TEST_DATABASE_URL");
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    sqlx::query("TRUNCATE accounts CASCADE")
        .execute(&pool)
        .await
        .expect("clean");
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
    e6ircd::db::add_kline(&pool, "spammer@*", "spam", "alice")
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
        ("/api/v1/admin/klines", "klines"),
        ("/api/v1/admin/audit", "audit"),
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
        assert!(
            v[key].as_array().is_some_and(|a| !a.is_empty()),
            "{path} empty: {body}"
        );
    }

    // Stats reflects the seeded data (2 accounts, 1 channel, 1 kline).
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
    assert_eq!(v["klines"], 1, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn account_page_add_network_form_with_csrf() {
    let url = std::env::var("E6IRC_TEST_DATABASE_URL").expect("E6IRC_TEST_DATABASE_URL");
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    sqlx::query("TRUNCATE accounts CASCADE")
        .execute(&pool)
        .await
        .expect("clean");
    sqlx::query("TRUNCATE bnc_networks")
        .execute(&pool)
        .await
        .ok();
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
    let url = std::env::var("E6IRC_TEST_DATABASE_URL").expect("E6IRC_TEST_DATABASE_URL");
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    sqlx::query("TRUNCATE accounts CASCADE")
        .execute(&pool)
        .await
        .expect("clean");
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
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn me_tokens_list_and_revoke() {
    let url = std::env::var("E6IRC_TEST_DATABASE_URL").expect("E6IRC_TEST_DATABASE_URL");
    let pool = e6ircd::db::connect_and_migrate(&url)
        .await
        .expect("connect");
    sqlx::query("TRUNCATE accounts CASCADE")
        .execute(&pool)
        .await
        .expect("clean");
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
