//! OIDC login flow against a real provider (dex with the mock
//! connector). Ignored by default; needs PostgreSQL and dex:
//!   E6IRC_TEST_DATABASE_URL=... E6IRC_TEST_DEX_URL=http://127.0.0.1:15556/dex \
//!   cargo test --test oidc -- --ignored

use e6ircd::config::{Config, DatabaseConfig, HttpConfig, ListenerConfig, OidcProviderConfig};
use e6ircd::net;

#[tokio::test]
#[ignore = "needs PostgreSQL + dex; see module docs"]
async fn full_oidc_login_provisions_account_and_session() {
    let db_url = std::env::var("E6IRC_TEST_DATABASE_URL").expect("E6IRC_TEST_DATABASE_URL");
    let dex_url = std::env::var("E6IRC_TEST_DEX_URL").expect("E6IRC_TEST_DEX_URL");

    let pool = e6ircd::db::connect_and_migrate(&db_url)
        .await
        .expect("connect");
    sqlx::query("TRUNCATE accounts CASCADE")
        .execute(&pool)
        .await
        .expect("clean");
    drop(pool);

    // dex validates redirect URIs exactly, so the port is fixed and
    // registered in tools/dex-config.yaml.
    let http_addr: std::net::SocketAddr = "127.0.0.1:18080".parse().unwrap();

    let config = Config {
        server_name: "irc.oidc.example".into(),
        network_name: "OidcNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }],
        http: Some(HttpConfig {
            addr: http_addr,
            public_url: Some(format!("http://{http_addr}")),
            secure_cookies: false,
            admin_accounts: vec![],
        }),
        database: Some(DatabaseConfig { url: db_url }),
        oidc_providers: vec![OidcProviderConfig {
            name: "dex".into(),
            issuer_url: dex_url,
            client_id: "e6irc-test".into(),
            client_secret: "e6irc-test-secret".into(),
        }],
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let base = format!("http://{}", running.http_addr.expect("http"));

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .expect("client");

    // 1. start → redirect into dex
    let resp = client
        .get(format!("{base}/api/v1/auth/oidc/dex/start"))
        .send()
        .await
        .expect("start");
    assert_eq!(resp.status(), 307, "{:?}", resp.status());
    let mut location = resp
        .headers()
        .get("location")
        .expect("location")
        .to_str()
        .unwrap()
        .to_string();
    assert!(location.contains("/auth"), "{location}");

    // 2. follow redirects inside dex (mock connector auto-approves)
    //    until it sends us back to our callback.
    for _ in 0..10 {
        if location.starts_with(&base) {
            break;
        }
        let resp = client.get(&location).send().await.expect("dex hop");
        assert!(
            resp.status().is_redirection(),
            "dex answered {} at {location}",
            resp.status()
        );
        let next = resp
            .headers()
            .get("location")
            .expect("location")
            .to_str()
            .unwrap();
        // dex may redirect relative to its own origin
        location = if next.starts_with("http") {
            next.to_string()
        } else {
            let origin = location.split('/').take(3).collect::<Vec<_>>().join("/");
            format!("{origin}{next}")
        };
    }
    assert!(
        location.starts_with(&base),
        "never returned to callback: {location}"
    );

    // 3. our callback: session cookie + redirect home
    let resp = client.get(&location).send().await.expect("callback");
    assert_eq!(
        resp.status(),
        303,
        "{}",
        resp.text().await.unwrap_or_default()
    );

    // 4. /me sees the provisioned account (mock connector's user)
    let me: serde_json::Value = client
        .get(format!("{base}/api/v1/me"))
        .send()
        .await
        .expect("me")
        .json()
        .await
        .expect("json");
    let account = me["account"].as_str().expect("account");
    assert!(!account.is_empty());

    // 5. logout kills the session
    let resp = client
        .post(format!("{base}/api/v1/auth/logout"))
        .send()
        .await
        .expect("logout");
    assert_eq!(resp.status(), 204);
    let resp = client
        .get(format!("{base}/api/v1/me"))
        .send()
        .await
        .expect("me2");
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn pat_bearer_auth_works() {
    let db_url = std::env::var("E6IRC_TEST_DATABASE_URL").expect("E6IRC_TEST_DATABASE_URL");
    let pool = e6ircd::db::connect_and_migrate(&db_url)
        .await
        .expect("connect");
    sqlx::query("TRUNCATE accounts CASCADE")
        .execute(&pool)
        .await
        .expect("clean");
    e6ircd::db::create_account(&pool, "patuser", "pw")
        .await
        .expect("create");
    let session = e6ircd::db::create_web_session(&pool, "patuser")
        .await
        .expect("session");
    drop(pool);

    let config = Config {
        server_name: "irc.pat.example".into(),
        network_name: "PatNet".into(),
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
        database: Some(DatabaseConfig { url: db_url }),
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let base = format!("http://{}", running.http_addr.expect("http"));
    let client = reqwest::Client::new();

    // mint a PAT using the session cookie
    let resp = client
        .post(format!("{base}/api/v1/me/tokens"))
        .header("cookie", format!("e6irc_session={session}"))
        .json(&serde_json::json!({"label": "ci"}))
        .send()
        .await
        .expect("mint");
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.expect("json");
    let token = body["token"].as_str().expect("token");
    assert!(token.starts_with("e6p_"), "{token}");

    // Bearer auth on /me
    let me: serde_json::Value = client
        .get(format!("{base}/api/v1/me"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("me")
        .json()
        .await
        .expect("json");
    assert_eq!(me["account"], "patuser");

    // bad token → 401
    let resp = client
        .get(format!("{base}/api/v1/me"))
        .header("authorization", "Bearer e6p_bogus")
        .send()
        .await
        .expect("me");
    assert_eq!(resp.status(), 401);
}
