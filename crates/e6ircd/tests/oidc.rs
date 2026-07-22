//! OIDC login flow against a real provider (dex with the mock
//! connector). Ignored by default; needs PostgreSQL and dex:
//!   E6IRC_TEST_DATABASE_URL=... E6IRC_TEST_DEX_URL=http://127.0.0.1:15556/dex \
//!   cargo test --test oidc -- --ignored

use e6ircd::config::{Config, DatabaseConfig, HttpConfig, ListenerConfig, OidcProviderConfig};
use e6ircd::net;

mod support;

#[tokio::test]
#[ignore = "needs PostgreSQL + dex; see module docs"]
async fn full_oidc_login_provisions_account_and_session() {
    let db_url = support::test_db("full_oidc_login_provisions_account_and_session").await;
    let dex_url = std::env::var("E6IRC_TEST_DEX_URL").expect("E6IRC_TEST_DEX_URL");

    let pool = e6ircd::db::connect_and_migrate(&db_url)
        .await
        .expect("connect");
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
            scopes: vec![],
            end_session_endpoint: None,
            token_endpoint_auth_method: Default::default(),
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
    let db_url = support::test_db("pat_bearer_auth_works").await;
    let pool = e6ircd::db::connect_and_migrate(&db_url)
        .await
        .expect("connect");
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

/// Link a fresh OIDC identity to an existing password account, then prove
/// a *second* account can't claim the same identity. Uses a distinct fixed
/// port (18081) so it stays independent of the login flow above.
#[tokio::test]
#[ignore = "needs PostgreSQL + dex; see module docs"]
async fn oidc_identity_link_flow_and_conflict() {
    let db_url = support::test_db("oidc_identity_link_flow_and_conflict").await;
    let dex_url = std::env::var("E6IRC_TEST_DEX_URL").expect("E6IRC_TEST_DEX_URL");

    let pool = e6ircd::db::connect_and_migrate(&db_url)
        .await
        .expect("connect");
    e6ircd::db::create_account(&pool, "alice", "pw")
        .await
        .expect("alice");
    e6ircd::db::create_account(&pool, "bob", "pw")
        .await
        .expect("bob");
    let alice_session = e6ircd::db::create_web_session(&pool, "alice")
        .await
        .expect("s1");
    let bob_session = e6ircd::db::create_web_session(&pool, "bob")
        .await
        .expect("s2");
    drop(pool);

    let http_addr: std::net::SocketAddr = "127.0.0.1:18081".parse().unwrap();
    let config = Config {
        server_name: "irc.link.example".into(),
        network_name: "LinkNet".into(),
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
            scopes: vec![],
            end_session_endpoint: None,
            token_endpoint_auth_method: Default::default(),
        }],
        ..Config::default()
    };
    let running = net::start(config)
        .await
        .unwrap_or_else(|e| panic!("start failed: {e}"));
    let base = format!("http://{}", running.http_addr.expect("http"));

    // Drive one link flow as `session_account`, following dex's auto-approve
    // hops back to our callback. Returns the callback's HTTP status.
    async fn run_link(base: &str, session: &str) -> reqwest::StatusCode {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .cookie_store(true)
            .build()
            .expect("client");
        let cookie = format!("e6irc_session={session}");
        let resp = client
            .get(format!("{base}/api/v1/auth/oidc/dex/link"))
            .header("cookie", &cookie)
            .send()
            .await
            .expect("link start");
        assert_eq!(resp.status(), 307, "link start not a redirect");
        let mut location = resp
            .headers()
            .get("location")
            .expect("location")
            .to_str()
            .unwrap()
            .to_string();
        for _ in 0..10 {
            if location.starts_with(base) {
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
            location = if next.starts_with("http") {
                next.to_string()
            } else {
                let origin = location.split('/').take(3).collect::<Vec<_>>().join("/");
                format!("{origin}{next}")
            };
        }
        assert!(
            location.starts_with(base),
            "never returned to callback: {location}"
        );
        // The callback carries no auth of its own — the pending state does.
        client
            .get(&location)
            .send()
            .await
            .expect("callback")
            .status()
    }

    // alice links the mock identity: callback redirects home.
    assert_eq!(run_link(&base, &alice_session).await, 303);
    // it now shows up on her account.
    let ids: serde_json::Value = reqwest::Client::new()
        .get(format!("{base}/api/v1/me/identities"))
        .header("cookie", format!("e6irc_session={alice_session}"))
        .send()
        .await
        .expect("identities")
        .json()
        .await
        .expect("json");
    let list = ids["identities"].as_array().expect("array");
    assert_eq!(list.len(), 1, "{ids}");
    assert!(list[0]["issuer"].as_str().unwrap().contains("dex"), "{ids}");

    // bob tries to link the *same* dex identity → 409 conflict.
    assert_eq!(run_link(&base, &bob_session).await, 409);
}

/// prompt=none silent SSO: once the browser holds a provider session, a
/// silent probe logs in with no interactive UI; without a provider session
/// it bounces to /?sso=none instead of prompting (no redirect loop). Uses
/// fixed port 18082.
#[tokio::test]
#[ignore = "needs PostgreSQL + dex; see module docs"]
async fn oidc_silent_sso_reuses_provider_session() {
    let db_url = support::test_db("oidc_silent_sso_reuses_provider_session").await;
    let dex_url = std::env::var("E6IRC_TEST_DEX_URL").expect("E6IRC_TEST_DEX_URL");
    let pool = e6ircd::db::connect_and_migrate(&db_url)
        .await
        .expect("connect");
    drop(pool);

    let http_addr: std::net::SocketAddr = "127.0.0.1:18082".parse().unwrap();
    let config = Config {
        server_name: "irc.silent.example".into(),
        network_name: "SilentNet".into(),
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
            scopes: vec![],
            end_session_endpoint: None,
            token_endpoint_auth_method: Default::default(),
        }],
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let base = format!("http://{}", running.http_addr.expect("http"));

    // Follow a start endpoint's redirect chain through dex back to our
    // callback; return the callback's (status, location).
    async fn drive(client: &reqwest::Client, base: &str, start_path: &str) -> (u16, String) {
        let resp = client
            .get(format!("{base}{start_path}"))
            .send()
            .await
            .expect("start");
        assert_eq!(resp.status(), 307, "start not a redirect");
        let mut location = resp
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        for _ in 0..10 {
            if location.starts_with(base) {
                break;
            }
            let resp = client.get(&location).send().await.expect("dex hop");
            assert!(
                resp.status().is_redirection(),
                "dex answered {} at {location}",
                resp.status()
            );
            let next = resp.headers().get("location").unwrap().to_str().unwrap();
            location = if next.starts_with("http") {
                next.to_string()
            } else {
                let origin = location.split('/').take(3).collect::<Vec<_>>().join("/");
                format!("{origin}{next}")
            };
        }
        assert!(
            location.starts_with(base),
            "never returned to callback: {location}"
        );
        let resp = client.get(&location).send().await.expect("callback");
        let status = resp.status().as_u16();
        let loc = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        (status, loc)
    }

    // A client that first logs in interactively holds dex's SSO session; a
    // subsequent silent probe then logs in with NO interactive prompt (303
    // home, not /?sso=none).
    let member = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    let (status, _) = drive(&member, &base, "/api/v1/auth/oidc/dex/start").await;
    assert_eq!(status, 303, "interactive login should succeed");
    let (status, loc) = drive(&member, &base, "/api/v1/auth/oidc/dex/sso").await;
    assert_eq!(status, 303, "silent probe with a session should log in");
    assert!(
        !loc.contains("sso=none"),
        "silent probe wrongly reported no session: {loc:?}"
    );

    // The no-session branch: dex's mock connector always approves (even for
    // prompt=none), so drive the login_required path directly — register a
    // silent pending via /sso, then deliver the error a real provider (Hydra)
    // returns on prompt=none with no session. It must land on /?sso=none,
    // never a 401 and never a re-prompt loop.
    let anon = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    let probe = anon
        .get(format!("{base}/api/v1/auth/oidc/dex/sso"))
        .send()
        .await
        .expect("probe");
    assert_eq!(probe.status(), 307);
    let auth_url = probe.headers().get("location").unwrap().to_str().unwrap();
    let state = auth_url
        .split_once("state=")
        .and_then(|(_, rest)| rest.split('&').next())
        .expect("state param");
    let cb = anon
        .get(format!(
            "{base}/api/v1/auth/oidc/dex/callback?error=login_required&state={state}"
        ))
        .send()
        .await
        .expect("callback");
    assert_eq!(
        cb.status().as_u16(),
        303,
        "login_required should redirect, not error"
    );
    assert!(
        cb.headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("sso=none"),
        "expected /?sso=none on login_required"
    );
}
