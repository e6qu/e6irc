//! Database-worker integration tests against real PostgreSQL.
//!
//! Ignored by default; run with `--ignored` where PostgreSQL is
//! available (CI provides a service container):
//!   E6IRC_TEST_DATABASE_URL=postgres://... cargo test --test db -- --ignored

use e6irc_queue::{Config as QueueConfig, Policy, queue};
use e6ircd::config::{Config, DatabaseConfig, ListenerConfig};
use e6ircd::core::{DbReply, DbRequest, Input};
use e6ircd::{db, net};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

mod support;

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn verify_password_roundtrip() {
    let pool = db::connect_and_migrate(&support::test_db("verify_password_roundtrip").await)
        .await
        .expect("connect");

    db::create_account(&pool, "Alice", "correct horse")
        .await
        .expect("create");
    // duplicate registration fails loudly, case-insensitively
    let dup = db::create_account(&pool, "alice", "x").await;
    assert!(
        matches!(dup, Err(db::DbError::DuplicateAccount(_))),
        "{dup:?}"
    );

    let (req_tx, req_rx) = queue::<DbRequest>(QueueConfig {
        name: "t-db",
        capacity: 8,
        policy: Policy::Fifo,
    });
    let (core_tx, mut core_rx) = queue::<Input>(QueueConfig {
        name: "t-core",
        capacity: 8,
        policy: Policy::Fifo,
    });
    tokio::spawn(db::run_worker(pool, req_rx, core_tx));

    let conn = e6ircd::core::ConnId(7);
    // right password, case-insensitive account lookup
    req_tx
        .push(DbRequest::VerifyPassword {
            conn,
            account: "ALICE".into(),
            password: "correct horse".into(),
        })
        .await
        .expect("push");
    let Some(env) = core_rx.pop().await else {
        panic!("worker died")
    };
    let Input::DbReply {
        conn: got_conn,
        reply,
    } = env.payload
    else {
        panic!("unexpected input")
    };
    assert_eq!(got_conn, conn);
    assert_eq!(
        reply,
        DbReply::PasswordVerified {
            account: "Alice".into()
        }
    );

    // wrong password and unknown account are indistinguishable
    for (account, password) in [("alice", "wrong"), ("nobody", "whatever")] {
        req_tx
            .push(DbRequest::VerifyPassword {
                conn,
                account: account.into(),
                password: password.into(),
            })
            .await
            .expect("push");
        let Some(env) = core_rx.pop().await else {
            panic!("worker died")
        };
        let Input::DbReply { reply, .. } = env.payload else {
            panic!("unexpected")
        };
        assert_eq!(reply, DbReply::PasswordRejected, "{account}/{password}");
    }
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn sasl_over_real_socket() {
    let url = support::test_db("sasl_over_real_socket").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    db::create_account(&pool, "sasluser", "s3cret")
        .await
        .expect("create");
    drop(pool);

    let config = Config {
        server_name: "irc.sasl.example".into(),
        network_name: "SaslNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }],
        database: Some(DatabaseConfig { url }),
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");

    let stream = TcpStream::connect(running.addrs[0]).await.expect("connect");
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    let mut expect = async |needle: &str| {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).await.expect("read") > 0, "EOF");
                if line.contains(needle) {
                    return line.trim_end().to_string();
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timeout waiting for {needle}"))
    };

    w.write_all(b"CAP LS 302\r\n").await.unwrap();
    expect("sasl=PLAIN").await;
    w.write_all(b"CAP REQ :sasl\r\nAUTHENTICATE PLAIN\r\n")
        .await
        .unwrap();
    expect("AUTHENTICATE +").await;
    let payload = e6irc_proto::base64::encode(b"\0sasluser\0s3cret");
    w.write_all(format!("AUTHENTICATE {payload}\r\n").as_bytes())
        .await
        .unwrap();
    expect(" 903 ").await;
    w.write_all(b"NICK saslo\r\nUSER s 0 * :S\r\nCAP END\r\n")
        .await
        .unwrap();
    expect(" 001 ").await;
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn sasl_oauthbearer_with_api_token() {
    let url = support::test_db("sasl_oauthbearer_with_api_token").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    db::create_account(&pool, "tokuser", "pw")
        .await
        .expect("create");
    let token = db::issue_api_token(&pool, "tokuser", "cli")
        .await
        .expect("token");
    drop(pool);

    let config = Config {
        server_name: "irc.oauth.example".into(),
        network_name: "OauthNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }],
        database: Some(DatabaseConfig { url }),
        ..Config::default()
    };
    let addr = net::start(config).await.expect("start").addrs[0];

    // A valid API token authenticates via OAUTHBEARER.
    let mut c = e6irc_client::Connection::connect(&addr.to_string())
        .await
        .unwrap();
    let nick = c
        .register_oauthbearer("toknick", "T", &token)
        .await
        .expect("oauthbearer login");
    assert_eq!(nick, "toknick");
    // Confirm the login mapped to the token's account (self WHOIS 330).
    c.send_line("WHOIS toknick").await.unwrap();
    let logged = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let m = c.next_message().await.unwrap().unwrap();
            if m.command == "330" && m.params.get(2).map(String::as_str) == Some("tokuser") {
                return true;
            }
            if m.command == "318" {
                return false;
            }
        }
    })
    .await
    .expect("timeout");
    assert!(
        logged,
        "OAUTHBEARER did not log the client in as the token account"
    );

    // A bogus token is rejected.
    let mut bad = e6irc_client::Connection::connect(&addr.to_string())
        .await
        .unwrap();
    assert!(
        bad.register_oauthbearer("bad", "B", "not-a-real-token")
            .await
            .is_err(),
        "invalid token must be refused"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn app_password_issued_over_http_works_for_sasl() {
    use e6ircd::config::HttpConfig;
    use tokio::io::AsyncReadExt;

    let url = support::test_db("app_password_issued_over_http_works_for_sasl").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    db::create_account(&pool, "apppw", "mainpass")
        .await
        .expect("create");
    drop(pool);

    let config = Config {
        server_name: "irc.apw.example".into(),
        network_name: "ApwNet".into(),
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

    // 1. issue an app password over HTTP with the account password
    let body = r#"{"account":"apppw","password":"mainpass","label":"weechat"}"#;
    let req = format!(
        "POST /api/v1/auth/app-passwords HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let mut http = TcpStream::connect(running.http_addr.expect("http"))
        .await
        .expect("c");
    http.write_all(req.as_bytes()).await.expect("w");
    let mut resp = Vec::new();
    http.read_to_end(&mut resp).await.expect("r");
    let resp = String::from_utf8_lossy(&resp).to_string();
    assert!(resp.starts_with("HTTP/1.1 201"), "{resp}");
    let json_body = resp.split("\r\n\r\n").nth(1).expect("body");
    let v: serde_json::Value = serde_json::from_str(json_body).expect("json");
    let app_password = v["app_password"].as_str().expect("secret").to_string();

    // wrong account password must not mint one
    let bad = r#"{"account":"apppw","password":"wrong","label":"x"}"#;
    let req = format!(
        "POST /api/v1/auth/app-passwords HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{bad}",
        bad.len()
    );
    let mut http = TcpStream::connect(running.http_addr.expect("http"))
        .await
        .expect("c");
    http.write_all(req.as_bytes()).await.expect("w");
    let mut resp = Vec::new();
    http.read_to_end(&mut resp).await.expect("r");
    assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 401"));

    // 2. use the app password for SASL PLAIN on the IRC listener
    let stream = TcpStream::connect(running.addrs[0]).await.expect("irc");
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    let mut expect = async |needle: &str| {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).await.expect("read") > 0, "EOF");
                if line.contains(needle) {
                    return line.trim_end().to_string();
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timeout waiting for {needle}"))
    };
    w.write_all(b"CAP LS 302\r\nCAP REQ :sasl\r\nAUTHENTICATE PLAIN\r\n")
        .await
        .unwrap();
    expect("AUTHENTICATE +").await;
    let payload = e6irc_proto::base64::encode(format!("\0apppw\0{app_password}").as_bytes());
    w.write_all(format!("AUTHENTICATE {payload}\r\n").as_bytes())
        .await
        .unwrap();
    expect(" 903 ").await;
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn auth_endpoint_rate_limit_returns_429_after_burst() {
    use e6ircd::config::{HttpConfig, LimitsConfig};
    use tokio::io::AsyncReadExt;

    let url = support::test_db("auth_endpoint_rate_limit_returns_429_after_burst").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    db::create_account(&pool, "rluser", "mainpass")
        .await
        .expect("create");
    drop(pool);

    let config = Config {
        server_name: "irc.rl.example".into(),
        network_name: "RlNet".into(),
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
        limits: LimitsConfig {
            // Two requests per client IP, then the bucket is empty.
            auth_rate_burst: Some(2),
            ..LimitsConfig::default()
        },
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let http_addr = running.http_addr.expect("http");

    // The rate check runs before credential validation, so a valid body isn't
    // needed to exercise it — the same client IP is throttled regardless.
    let body = r#"{"account":"rluser","password":"mainpass","label":"c"}"#;
    let req = format!(
        "POST /api/v1/auth/app-passwords HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let post = async |req: &str| -> String {
        let mut http = TcpStream::connect(http_addr).await.expect("c");
        http.write_all(req.as_bytes()).await.expect("w");
        let mut resp = Vec::new();
        http.read_to_end(&mut resp).await.expect("r");
        String::from_utf8_lossy(&resp).to_string()
    };

    // First two succeed (201), the third from the same IP is 429.
    assert!(post(&req).await.starts_with("HTTP/1.1 201"), "1st");
    assert!(post(&req).await.starts_with("HTTP/1.1 201"), "2nd");
    let third = post(&req).await;
    assert!(
        third.starts_with("HTTP/1.1 429"),
        "3rd should be limited: {third}"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn channel_messages_are_persisted() {
    let url = support::test_db("channel_messages_are_persisted").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");

    let config = Config {
        server_name: "irc.hist.example".into(),
        network_name: "HistNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }],
        database: Some(DatabaseConfig { url }),
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");

    let stream = TcpStream::connect(running.addrs[0]).await.expect("irc");
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    let mut expect = async |needle: &str| {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).await.expect("read") > 0, "EOF");
                if line.contains(needle) {
                    return line.trim_end().to_string();
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timeout waiting for {needle}"))
    };
    w.write_all(b"NICK histy\r\nUSER h 0 * :H\r\nJOIN #logged\r\n")
        .await
        .unwrap();
    expect(" 366 ").await;
    w.write_all(b"PRIVMSG #logged :for the record\r\nPRIVMSG #logged :second\r\n")
        .await
        .unwrap();
    w.write_all(b"PING sync\r\n").await.unwrap();
    expect("PONG").await;

    // the flush is asynchronous; poll briefly
    let mut rows: Vec<(String, String, String)> = Vec::new();
    for _ in 0..50 {
        rows = sqlx::query_as(
            "SELECT msgid, kind, body FROM messages WHERE target = '#logged' ORDER BY id",
        )
        .fetch_all(&pool)
        .await
        .expect("query");
        if rows.len() == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0].1, "privmsg");
    assert_eq!(rows[0].2, "for the record");
    assert_eq!(rows[1].2, "second");
    assert_ne!(rows[0].0, rows[1].0, "msgids must be unique");
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn credential_list_and_revoke() {
    use e6ircd::config::HttpConfig;
    use tokio::io::AsyncReadExt;

    let url = support::test_db("credential_list_and_revoke").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    db::create_account(&pool, "creduser", "pw")
        .await
        .expect("create");
    // two app passwords
    db::issue_app_password(&pool, "creduser", "pw", "laptop")
        .await
        .expect("ap1");
    db::issue_app_password(&pool, "creduser", "pw", "phone")
        .await
        .expect("ap2");
    let session = db::create_web_session(&pool, "creduser")
        .await
        .expect("session");
    drop(pool);

    let config = Config {
        server_name: "irc.cred.example".into(),
        network_name: "CredNet".into(),
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

    async fn http_req(addr: std::net::SocketAddr, req: &str) -> (u16, String) {
        let mut c = TcpStream::connect(addr).await.expect("c");
        c.write_all(req.as_bytes()).await.expect("w");
        let mut buf = Vec::new();
        c.read_to_end(&mut buf).await.expect("r");
        let text = String::from_utf8_lossy(&buf).to_string();
        let (head, body) = text.split_once("\r\n\r\n").expect("split");
        let status = head
            .lines()
            .next()
            .unwrap()
            .split(' ')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        (status, body.to_string())
    }
    let http = running.http_addr.expect("http");
    let auth = format!("Cookie: e6irc_session={session}\r\n");

    // list → local_password + 2 app_passwords = 3
    let (status, body) = http_req(
        http,
        &format!(
            "GET /api/v1/me/credentials HTTP/1.1\r\nHost: t\r\nConnection: close\r\n{auth}\r\n"
        ),
    )
    .await;
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let creds = v["credentials"].as_array().expect("array");
    assert_eq!(creds.len(), 3, "{creds:?}");
    let app_id = creds
        .iter()
        .find(|c| c["kind"] == "app_password" && c["label"] == "phone")
        .map(|c| c["id"].as_i64().unwrap())
        .expect("phone cred");

    // unauthenticated revoke → 401
    let (status, _) = http_req(
        http,
        &format!("DELETE /api/v1/me/credentials/{app_id} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert_eq!(status, 401);

    // authenticated revoke → 204, then list shows 2
    let (status, _) = http_req(
        http,
        &format!("DELETE /api/v1/me/credentials/{app_id} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n{auth}\r\n"),
    )
    .await;
    assert_eq!(status, 204);
    let (_, body) = http_req(
        http,
        &format!(
            "GET /api/v1/me/credentials HTTP/1.1\r\nHost: t\r\nConnection: close\r\n{auth}\r\n"
        ),
    )
    .await;
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["credentials"].as_array().unwrap().len(), 2);

    // revoking again → 404
    let (status, _) = http_req(
        http,
        &format!("DELETE /api/v1/me/credentials/{app_id} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n{auth}\r\n"),
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn read_marker_persists() {
    let url = support::test_db("read_marker_persists").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    db::create_account(&pool, "mark", "pw")
        .await
        .expect("create");

    let config = Config {
        server_name: "irc.rm.example".into(),
        network_name: "RmNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }],
        database: Some(DatabaseConfig { url }),
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let stream = TcpStream::connect(running.addrs[0]).await.expect("irc");
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    async fn expect(
        reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
        needle: &str,
    ) -> String {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).await.expect("read") > 0, "EOF");
                if line.contains(needle) {
                    return line.trim_end().to_string();
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timeout waiting for {needle}"))
    }
    w.write_all(b"CAP LS 302\r\nCAP REQ :draft/read-marker sasl\r\nAUTHENTICATE PLAIN\r\n")
        .await
        .unwrap();
    expect(&mut reader, "AUTHENTICATE +").await;
    let mut sasl = vec![0u8];
    sasl.extend_from_slice(b"mark");
    sasl.push(0);
    sasl.extend_from_slice(b"pw");
    let payload = e6irc_proto::base64::encode(&sasl);
    w.write_all(format!("AUTHENTICATE {payload}\r\n").as_bytes())
        .await
        .unwrap();
    expect(&mut reader, " 903 ").await;
    w.write_all(b"NICK mark\r\nUSER m 0 * :M\r\nCAP END\r\n")
        .await
        .unwrap();
    expect(&mut reader, " 001 ").await;
    w.write_all(b"MARKREAD #chan timestamp=2026-07-18T12:00:00.000Z\r\n")
        .await
        .unwrap();
    expect(&mut reader, "MARKREAD #chan timestamp=").await;

    // durably stored?
    let mut got = None;
    for _ in 0..50 {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT to_char(marker_ts AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS')
             FROM read_markers WHERE target = '#chan'",
        )
        .fetch_optional(&pool)
        .await
        .expect("query");
        if let Some((ts,)) = row {
            got = Some(ts);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(got.as_deref(), Some("2026-07-18T12:00:00"));
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn history_rest_endpoint() {
    use e6ircd::config::HttpConfig;
    let url = support::test_db("history_rest_endpoint").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    db::create_account(&pool, "web", "pw")
        .await
        .expect("create");
    // The REST history read authorizes the target against a registered
    // relationship (an account can't read arbitrary channels' history), so
    // make `web` the founder of #web to exercise an authorized read.
    sqlx::query(
        "INSERT INTO channels (name, name_folded, founder_account_id)
         SELECT '#web', '#web', id FROM accounts WHERE name_folded = 'web'",
    )
    .execute(&pool)
    .await
    .expect("register #web");
    let session = db::create_web_session(&pool, "web").await.expect("session");
    // A second account with no relationship to #web must be refused (IDOR).
    db::create_account(&pool, "other", "pw")
        .await
        .expect("create other");
    let other_session = db::create_web_session(&pool, "other")
        .await
        .expect("other session");
    let pool2 = pool.clone();
    drop(pool);

    let config = Config {
        server_name: "irc.hr.example".into(),
        network_name: "HrNet".into(),
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
    let base = format!("http://{}", running.http_addr.expect("http"));

    // post a couple of channel messages over IRC so history exists
    let stream = TcpStream::connect(running.addrs[0]).await.expect("irc");
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    w.write_all(
        b"NICK hw
USER h 0 * :H
JOIN #web
",
    )
    .await
    .unwrap();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        if line.contains(" 366 ") {
            break;
        }
    }
    w.write_all(
        b"PRIVMSG #web :rest one
PRIVMSG #web :rest two
PING x
",
    )
    .await
    .unwrap();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        if line.contains("PONG") {
            break;
        }
    }

    let client = reqwest::Client::new();
    // unauthenticated → 401
    let resp = client
        .get(format!("{base}/api/v1/history?target=%23web"))
        .send()
        .await
        .expect("hist");
    assert_eq!(resp.status(), 401);

    // authenticated → both messages, oldest-first, retrying for the flush
    let mut messages = vec![];
    for _ in 0..50 {
        let v: serde_json::Value = client
            .get(format!("{base}/api/v1/history?target=%23web"))
            .header("cookie", format!("e6irc_session={session}"))
            .send()
            .await
            .expect("hist")
            .json()
            .await
            .expect("json");
        messages = v["messages"].as_array().cloned().unwrap_or_default();
        if messages.len() == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(messages.len(), 2, "{messages:?}");
    assert_eq!(messages[0]["body"], "rest one");
    assert_eq!(messages[1]["body"], "rest two");
    assert!(messages[0]["msgid"].as_str().is_some());
    // The timestamp must be the moment the message was sent. Asserting only on
    // the body let a unit mismatch (milliseconds scaled a second time) put every
    // REST timestamp a thousand-fold into the future unnoticed.
    let reported = messages[0]["time"].as_str().expect("time");
    let reported_ms = e6irc_proto::time::parse_server_time_millis(reported)
        .unwrap_or_else(|| panic!("unparseable time {reported}"));
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64;
    assert!(
        reported_ms.as_millis().abs_diff(now_ms) < 60 * 60 * 1000,
        "history timestamp {reported} is not close to now"
    );

    // An account with no relationship to #web is refused (IDOR guard).
    let forbidden = client
        .get(format!("{base}/api/v1/history?target=%23web"))
        .header("cookie", format!("e6irc_session={other_session}"))
        .send()
        .await
        .expect("hist");
    assert_eq!(
        forbidden.status(),
        403,
        "unrelated account must be forbidden"
    );

    // Direct-message history is readable over REST too — DESIGN §11.2 says the
    // web and IRC hit one history, and it used to serve channels only.
    // Conversations are keyed by *account*, so both parties authenticate.
    async fn dm_client(
        addr: std::net::SocketAddr,
        account: &str,
    ) -> (
        BufReader<tokio::net::tcp::OwnedReadHalf>,
        tokio::net::tcp::OwnedWriteHalf,
    ) {
        let stream = TcpStream::connect(addr).await.expect("irc");
        let (r, mut w) = stream.into_split();
        let mut reader = BufReader::new(r);
        let sasl = e6irc_proto::base64::encode(format!("\0{account}\0pw").as_bytes());
        w.write_all(
            format!("CAP LS 302\r\nCAP REQ :sasl\r\nAUTHENTICATE PLAIN\r\nAUTHENTICATE {sasl}\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        // Wait for the SASL verdict before finishing registration: the account
        // must be attached before any message, or the conversation is keyed to
        // an unauthenticated identity instead.
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            assert!(!line.contains(" 904 "), "SASL failed for {account}");
            if line.contains(" 903 ") {
                break;
            }
        }
        w.write_all(format!("NICK {account}\r\nUSER u 0 * :U\r\nCAP END\r\n").as_bytes())
            .await
            .unwrap();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            if line.contains(" 001 ") {
                break;
            }
        }
        (reader, w)
    }
    let (_r_other, _w_other) = dm_client(running.addrs[0], "other").await;
    let (mut r_web, mut w_web) = dm_client(running.addrs[0], "web").await;
    w_web
        .write_all(b"PRIVMSG other :a private word\r\nPING y\r\n")
        .await
        .unwrap();
    loop {
        let mut line = String::new();
        r_web.read_line(&mut line).await.unwrap();
        if line.contains("PONG") {
            break;
        }
    }
    let mut dm = vec![];
    for _ in 0..50 {
        let v: serde_json::Value = client
            .get(format!("{base}/api/v1/history?target=other"))
            .header("cookie", format!("e6irc_session={session}"))
            .send()
            .await
            .expect("dm hist")
            .json()
            .await
            .expect("json");
        dm = v["messages"].as_array().cloned().unwrap_or_default();
        if !dm.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(
        dm.len(),
        1,
        "own direct-message history is readable: {dm:?}"
    );
    assert_eq!(dm[0]["body"], "a private word");

    // The other participant sees the same conversation from their side.
    let v: serde_json::Value = client
        .get(format!("{base}/api/v1/history?target=web"))
        .header("cookie", format!("e6irc_session={other_session}"))
        .send()
        .await
        .expect("peer hist")
        .json()
        .await
        .expect("json");
    assert_eq!(
        v["messages"].as_array().map(Vec::len),
        Some(1),
        "both participants read one conversation"
    );

    // A third party cannot reach it, not even by passing the raw conversation
    // key: the key is derived from *their* account, so it can only ever name a
    // conversation they are part of.
    db::create_account(&pool2, "snoop", "pw")
        .await
        .expect("snoop");
    let snoop_session = db::create_web_session(&pool2, "snoop")
        .await
        .expect("snoop session");
    for probe in ["web", "other", "other!web", "web!other"] {
        let v: serde_json::Value = client
            .get(format!("{base}/api/v1/history?target={probe}"))
            .header("cookie", format!("e6irc_session={snoop_session}"))
            .send()
            .await
            .expect("probe")
            .json()
            .await
            .expect("json");
        let leaked = v["messages"].as_array().cloned().unwrap_or_default();
        assert!(
            leaked.is_empty(),
            "target={probe} leaked another account's conversation: {leaked:?}"
        );
    }
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn chathistory_pages_from_postgres_past_the_ring() {
    let url = support::test_db("chathistory_pages_from_postgres_past_the_ring").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");

    let config = Config {
        server_name: "irc.ch.example".into(),
        network_name: "ChNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }],
        database: Some(DatabaseConfig { url }),
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let stream = TcpStream::connect(running.addrs[0]).await.expect("irc");
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    async fn expect(
        reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
        needle: &str,
    ) -> String {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).await.expect("read") > 0, "EOF");
                if line.contains(needle) {
                    return line.trim_end().to_string();
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timeout waiting for {needle}"))
    }

    // capable client, join, then overflow the 500-entry ring
    w.write_all(
        b"CAP LS 302\r\nCAP REQ :batch draft/chathistory message-tags server-time\r\n\
          NICK histy\r\nUSER h 0 * :H\r\nCAP END\r\nJOIN #big\r\n",
    )
    .await
    .unwrap();
    expect(&mut reader, " 366 ").await;

    for i in 0..600 {
        w.write_all(format!("PRIVMSG #big :m{i}\r\n").as_bytes())
            .await
            .unwrap();
    }
    w.write_all(b"PING flushed\r\n").await.unwrap();
    expect(&mut reader, "PONG").await;

    // wait until all 600 are durably in PG
    for _ in 0..100 {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM messages WHERE target = '#big'")
            .fetch_one(&pool)
            .await
            .expect("count");
        if n == 600 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // BEFORE a timestamp past the ring must be served from PG
    let ts = e6irc_proto::time::server_time(e6irc_proto::time::Millis::from_millis(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            * 1000
            + 60_000,
    ));
    w.write_all(format!("CHATHISTORY BEFORE #big timestamp={ts} 50\r\n").as_bytes())
        .await
        .unwrap();
    let batch_open = expect(&mut reader, "BATCH +").await;
    let batch_ref = batch_open
        .split(" BATCH +")
        .nth(1)
        .and_then(|s| s.split(' ').next())
        .expect("batch ref")
        .to_string();
    // The async QueryHistory -> PG -> HistoryPage path served this page;
    // BEFORE a future timestamp with limit 50 is the newest 50 rows.
    let mut bodies = Vec::new();
    let mut lines = 0;
    loop {
        let line = expect(&mut reader, "").await;
        if line.contains("BATCH -") {
            break;
        }
        assert!(
            line.contains(&format!("batch={batch_ref}")),
            "stray line: {line}"
        );
        if let Some((_, body)) = line.rsplit_once(" :") {
            bodies.push(body.to_string());
        }
        lines += 1;
        assert!(lines < 200, "runaway batch");
    }
    assert_eq!(bodies.len(), 50, "expected a 50-message page");
    assert!(
        bodies.contains(&"m599".to_string()),
        "newest missing: {bodies:?}"
    );
    assert!(
        bodies.contains(&"m550".to_string()),
        "window start missing: {bodies:?}"
    );
}

async fn expect_line(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    needle: &str,
) -> String {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let mut line = String::new();
            assert!(reader.read_line(&mut line).await.expect("read") > 0, "EOF");
            if line.contains(needle) {
                return line.trim_end().to_string();
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timeout waiting for {needle}"))
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn chathistory_recreated_channel_serves_persisted_history_with_label() {
    // Regression: a channel that empties is dropped from memory; when re-created
    // its ring is empty but PostgreSQL still holds the old rows. It must NOT be
    // marked history-complete (which would make CHATHISTORY return an empty
    // batch), and a labeled request's deferred DB batch must carry the label.
    let url =
        support::test_db("chathistory_recreated_channel_serves_persisted_history_with_label").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");

    let config = Config {
        server_name: "irc.recreate.example".into(),
        network_name: "RecNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }],
        database: Some(DatabaseConfig { url }),
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let stream = TcpStream::connect(running.addrs[0]).await.expect("irc");
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);

    w.write_all(
        b"CAP LS 302\r\n\
          CAP REQ :batch draft/chathistory message-tags server-time labeled-response\r\n\
          NICK rec\r\nUSER r 0 * :R\r\nCAP END\r\nJOIN #r\r\n",
    )
    .await
    .unwrap();
    expect_line(&mut reader, " 366 ").await;
    for i in 0..5 {
        w.write_all(format!("PRIVMSG #r :m{i}\r\n").as_bytes())
            .await
            .unwrap();
    }
    w.write_all(b"PING flushed\r\n").await.unwrap();
    expect_line(&mut reader, "PONG").await;

    // Wait until all 5 are durably in PG, then leave so the channel is dropped.
    for _ in 0..100 {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM messages WHERE target = '#r'")
            .fetch_one(&pool)
            .await
            .expect("count");
        if n == 5 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    w.write_all(b"PART #r\r\nPING parted\r\n").await.unwrap();
    expect_line(&mut reader, "PONG").await;

    // Re-create the channel: its ring is empty, PG still holds m0..m4.
    w.write_all(b"JOIN #r\r\n").await.unwrap();
    expect_line(&mut reader, " 366 ").await;

    // Labeled CHATHISTORY: the batch is served from PG (empty ring) and its
    // opening BATCH line must carry the label.
    w.write_all(b"@label=zz CHATHISTORY LATEST #r * 10\r\n")
        .await
        .unwrap();
    let batch_open = expect_line(&mut reader, "BATCH +").await;
    assert!(
        batch_open.contains("label=zz"),
        "deferred DB batch must carry the label: {batch_open}"
    );
    let batch_ref = batch_open
        .split(" BATCH +")
        .nth(1)
        .and_then(|s| s.split(' ').next())
        .expect("batch ref")
        .to_string();
    let mut bodies = Vec::new();
    loop {
        let line = expect_line(&mut reader, "").await;
        if line.contains("BATCH -") {
            break;
        }
        if line.contains(&format!("batch={batch_ref}")) {
            // Verb is canonical uppercase even when served from PG.
            assert!(
                line.contains("PRIVMSG"),
                "DB replay verb must be uppercase: {line}"
            );
            if let Some((_, body)) = line.rsplit_once(" :") {
                bodies.push(body.to_string());
            }
        }
    }
    for i in 0..5 {
        assert!(
            bodies.contains(&format!("m{i}")),
            "recreated channel lost persisted history: {bodies:?}"
        );
    }
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn read_marker_preloaded_after_restart() {
    // The read-marker mirror must be seeded from PostgreSQL at boot; otherwise a
    // MARKREAD query returns `*` after a restart even though a marker persists.
    let url = support::test_db("read_marker_preloaded_after_restart").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    db::create_account(&pool, "marky", "pw")
        .await
        .expect("acct");
    drop(pool);

    let make_config = || Config {
        server_name: "irc.rm.example".into(),
        network_name: "RmNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }],
        database: Some(DatabaseConfig { url: url.clone() }),
        ..Config::default()
    };

    // Authenticate with SASL PLAIN and the read-marker cap, sequencing each
    // step (the payload only after the server's `AUTHENTICATE +` challenge).
    async fn login_marky(
        reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
        w: &mut tokio::net::tcp::OwnedWriteHalf,
    ) {
        w.write_all(b"CAP LS 302\r\nCAP REQ :sasl draft/read-marker\r\nAUTHENTICATE PLAIN\r\n")
            .await
            .unwrap();
        expect_line(reader, "AUTHENTICATE +").await;
        let payload = e6irc_proto::base64::encode(b"\0marky\0pw");
        w.write_all(format!("AUTHENTICATE {payload}\r\n").as_bytes())
            .await
            .unwrap();
        expect_line(reader, " 903 ").await;
        w.write_all(b"NICK marky\r\nUSER m 0 * :M\r\nCAP END\r\n")
            .await
            .unwrap();
        expect_line(reader, " 001 ").await;
    }

    // First boot: authenticate, set a marker, confirm it persisted.
    let running = net::start(make_config()).await.expect("start");
    {
        let stream = TcpStream::connect(running.addrs[0]).await.expect("irc");
        let (r, mut w) = stream.into_split();
        let mut reader = BufReader::new(r);
        login_marky(&mut reader, &mut w).await;
        w.write_all(b"MARKREAD #chan timestamp=2020-01-01T00:00:00.000Z\r\n")
            .await
            .unwrap();
        expect_line(&mut reader, "MARKREAD #chan timestamp=2020-01-01").await;
    }

    // Second boot on the same database: the marker must be present immediately.
    let running2 = net::start(make_config()).await.expect("restart");
    let stream = TcpStream::connect(running2.addrs[0]).await.expect("irc");
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    login_marky(&mut reader, &mut w).await;
    w.write_all(b"MARKREAD #chan\r\n").await.unwrap();
    let reply = expect_line(&mut reader, "MARKREAD #chan").await;
    assert!(
        reply.contains("timestamp=2020-01-01T00:00:00.000Z"),
        "preloaded marker missing after restart: {reply}"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn sasl_registration_fails_loudly_on_nick_in_use() {
    // Regression: the shared SASL epilogue must treat a post-auth 433 (nick in
    // use, reported after CAP END) as terminal instead of blocking forever.
    let url = support::test_db("sasl_registration_fails_loudly_on_nick_in_use").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    db::create_account(&pool, "dupacct", "pw")
        .await
        .expect("acct");
    drop(pool);

    let config = Config {
        server_name: "irc.dup.example".into(),
        network_name: "DupNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }],
        database: Some(DatabaseConfig { url }),
        ..Config::default()
    };
    let addr = net::start(config).await.expect("start").addrs[0];

    // Client 1 reserves the nick "dup".
    let mut c1 = e6irc_client::Connection::connect(&addr.to_string())
        .await
        .unwrap();
    c1.register("dup", "First").await.expect("register");

    // Client 2 authenticates via SASL but requests the same nick. After 903 the
    // server refuses registration with 433; register_sasl must return an error,
    // not hang — the timeout guard fails the test if it hangs.
    let mut c2 = e6irc_client::Connection::connect(&addr.to_string())
        .await
        .unwrap();
    let res = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        c2.register_sasl("dup", "Second", "dupacct", "pw"),
    )
    .await
    .expect("register_sasl must not hang on an in-use nick");
    assert!(
        res.is_err(),
        "SASL registration with an in-use nick must fail loudly"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn labeled_chathistory_targets_carries_label_on_db_path() {
    // Regression: a labeled CHATHISTORY TARGETS that resolves via PostgreSQL
    // must tag its deferred batch with the label (and not ACK it empty first).
    let url = support::test_db("labeled_chathistory_targets_carries_label_on_db_path").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");

    let config = Config {
        server_name: "irc.tgt.example".into(),
        network_name: "TgtNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        }],
        database: Some(DatabaseConfig { url }),
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let stream = TcpStream::connect(running.addrs[0]).await.expect("irc");
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);

    w.write_all(
        b"CAP LS 302\r\n\
          CAP REQ :batch draft/chathistory message-tags server-time labeled-response\r\n\
          NICK tgt\r\nUSER t 0 * :T\r\nCAP END\r\nJOIN #a\r\nJOIN #b\r\n",
    )
    .await
    .unwrap();
    expect_line(&mut reader, "JOIN #b").await;
    w.write_all(b"PRIVMSG #a :ma\r\nPRIVMSG #b :mb\r\nPING flush\r\n")
        .await
        .unwrap();
    expect_line(&mut reader, "PONG").await;
    for _ in 0..100 {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM messages")
            .fetch_one(&pool)
            .await
            .expect("count");
        if n >= 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // A wide timestamp window forces the DB (QueryTargets) path.
    let lo = e6irc_proto::time::server_time(e6irc_proto::time::Millis::from_millis(1000));
    let hi = e6irc_proto::time::server_time(e6irc_proto::time::Millis::from_millis(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            * 1000
            + 60_000,
    ));
    w.write_all(
        format!("@label=tt CHATHISTORY TARGETS timestamp={lo} timestamp={hi} 50\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let batch_open = expect_line(&mut reader, "chathistory-targets").await;
    assert!(
        batch_open.contains("label=tt"),
        "deferred TARGETS batch must carry the label: {batch_open}"
    );
    assert!(
        batch_open.contains("BATCH +"),
        "expected a BATCH open line: {batch_open}"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn bnc_networks_crud() {
    let pool = db::connect_and_migrate(&support::test_db("bnc_networks_crud").await)
        .await
        .expect("connect");
    db::create_account(&pool, "alice", "pw")
        .await
        .expect("acct");
    db::create_account(&pool, "bob", "pw").await.expect("acct");

    let libera = db::BncNetworkRow {
        name: "libera".into(),
        addr: "irc.libera.chat:6697".into(),
        tls: true,
        nick: "alice_".into(),
        realname: Some("Alice".into()),
        autojoin: vec!["#rust".into(), "#e6irc".into()],
        sasl_account: Some("alice".into()),
        sasl_password_sealed: Some("enc:v1:abc".into()),
        enabled: true,
    };
    db::create_bnc_network(&pool, "alice", &libera)
        .await
        .expect("create");

    // duplicate (owner, name) is rejected loudly
    let dup = db::create_bnc_network(&pool, "alice", &libera).await;
    assert!(
        matches!(dup, Err(db::DbError::DuplicateNetwork(_))),
        "{dup:?}"
    );

    // bob may reuse the same network name (distinct owner)
    db::create_bnc_network(&pool, "bob", &libera)
        .await
        .expect("bob create");

    // unknown account is rejected
    let bad = db::create_bnc_network(&pool, "nobody", &libera).await;
    assert!(matches!(bad, Err(db::DbError::BadCredentials)), "{bad:?}");

    // list scopes to the owner and preserves fields
    let alice_nets = db::list_bnc_networks(&pool, "alice").await.expect("list");
    assert_eq!(alice_nets.len(), 1);
    assert_eq!(alice_nets[0].name, "libera");
    assert_eq!(alice_nets[0].autojoin, vec!["#rust", "#e6irc"]);
    assert_eq!(
        alice_nets[0].sasl_password_sealed.as_deref(),
        Some("enc:v1:abc")
    );

    // list_all pairs each network with its owner (two rows: alice+bob)
    let all = db::list_all_bnc_networks(&pool).await.expect("all");
    assert_eq!(all.len(), 2);
    assert!(all.iter().any(|(o, n)| o == "alice" && n.name == "libera"));
    assert!(all.iter().any(|(o, n)| o == "bob" && n.name == "libera"));

    // delete is owner-scoped
    assert!(
        db::delete_bnc_network(&pool, "alice", "libera")
            .await
            .unwrap()
    );
    assert!(
        !db::delete_bnc_network(&pool, "alice", "libera")
            .await
            .unwrap()
    );
    assert_eq!(
        db::list_bnc_networks(&pool, "alice").await.unwrap().len(),
        0
    );
    // bob's copy survives alice's delete
    assert_eq!(db::list_bnc_networks(&pool, "bob").await.unwrap().len(), 1);
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn query_targets_enumerates_active_buffers() {
    let pool =
        db::connect_and_migrate(&support::test_db("query_targets_enumerates_active_buffers").await)
            .await
            .expect("connect");

    // Epoch milliseconds (see above).
    for (target, ts) in [("#a", 1000_i64), ("#a", 2000), ("#b", 1500), ("#c", 3000)] {
        sqlx::query(
            "INSERT INTO messages (msgid, target, sender_prefix, sender_account, kind, body, ts)
             VALUES ($1, $2, 'x!x@h', NULL, 'privmsg', 'hi',
                     to_timestamp($3::double precision / 1000))",
        )
        .bind(format!("m-{target}-{ts}"))
        .bind(target)
        .bind(ts)
        .execute(&pool)
        .await
        .expect("insert");
    }

    // Visible targets #a and #b; window [1200,2500] excludes #a@1000 but
    // keeps #a@2000 and #b@1500; #c is not a member so never appears.
    // Result is newest-first by each target's latest in-window message.
    // Oldest activity first: #b's latest in-window message precedes #a's.
    let targets = db::query_targets(
        &pool,
        &["#a".into(), "#b".into()],
        "nobody",
        e6irc_proto::time::Millis::from_millis(1200),
        e6irc_proto::time::Millis::from_millis(2500),
        10,
    )
    .await;
    assert_eq!(
        targets,
        vec![
            (
                "#b".to_string(),
                e6irc_proto::time::Millis::from_millis(1500)
            ),
            (
                "#a".to_string(),
                e6irc_proto::time::Millis::from_millis(2000)
            )
        ]
    );

    // A window that excludes everything yields nothing.
    assert!(
        db::query_targets(
            &pool,
            &["#a".into()],
            "nobody",
            e6irc_proto::time::Millis::from_millis(5000),
            e6irc_proto::time::Millis::from_millis(6000),
            10
        )
        .await
        .is_empty()
    );

    // A buffer matches on its *latest* message: #a has a message inside
    // (500, 1500) but its newest is at 2000, so it has been read past.
    assert!(
        db::query_targets(
            &pool,
            &["#a".into()],
            "nobody",
            e6irc_proto::time::Millis::from_millis(500),
            e6irc_proto::time::Millis::from_millis(1500),
            10
        )
        .await
        .is_empty(),
        "a buffer whose latest message is outside the window must not match"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn msgid_pivot_is_scoped_to_its_own_target() {
    use e6ircd::core::HistoryQuery;
    let pool =
        db::connect_and_migrate(&support::test_db("msgid_pivot_is_scoped_to_its_own_target").await)
            .await
            .expect("connect");
    // A public channel either side of a message in a private conversation.
    for (msgid, target, body, ts) in [
        ("pub-1", "#public", "public one", 1000_i64),
        ("priv-1", "alice!bob", "SECRET", 1500),
        ("pub-2", "#public", "public two", 2000),
    ] {
        sqlx::query(
            "INSERT INTO messages (msgid, target, sender_prefix, sender_account, kind, body, ts)
             VALUES ($1, $2, 'x!x@h', NULL, 'privmsg', $3,
                     to_timestamp($4::double precision / 1000))",
        )
        .bind(msgid)
        .bind(target)
        .bind(body)
        .bind(ts)
        .execute(&pool)
        .await
        .expect("insert");
    }

    // Paging #public from a msgid that lives in someone else's conversation
    // must find nothing: that position does not exist in this buffer, and
    // answering anyway makes any known msgid an oracle for when it was sent.
    for query in [
        HistoryQuery::AfterMsgid {
            msgid: "priv-1".into(),
            limit: 10,
        },
        HistoryQuery::BeforeMsgid {
            msgid: "priv-1".into(),
            limit: 10,
        },
        HistoryQuery::LatestAfterMsgid {
            msgid: "priv-1".into(),
            limit: 10,
        },
        HistoryQuery::AroundMsgid {
            msgid: "priv-1".into(),
            limit: 10,
        },
    ] {
        let rows = db::query_history(&pool, "#public", query.clone()).await;
        assert!(
            rows.is_empty(),
            "a foreign msgid must not position a query: {query:?} returned {:?}",
            rows.iter().map(|r| &r.body).collect::<Vec<_>>()
        );
    }
    // A pivot that does belong to the target still works.
    let rows = db::query_history(
        &pool,
        "#public",
        HistoryQuery::AfterMsgid {
            msgid: "pub-1".into(),
            limit: 10,
        },
    )
    .await;
    assert_eq!(
        rows.iter().map(|r| r.body.as_str()).collect::<Vec<_>>(),
        vec!["public two"]
    );
    // And the private conversation still pages from its own msgid.
    let rows = db::query_history(
        &pool,
        "alice!bob",
        HistoryQuery::BeforeMsgid {
            msgid: "priv-1".into(),
            limit: 10,
        },
    )
    .await;
    assert!(rows.is_empty(), "nothing precedes it in that conversation");
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn query_targets_includes_direct_message_correspondents() {
    let pool = db::connect_and_migrate(
        &support::test_db("query_targets_includes_direct_message_correspondents").await,
    )
    .await
    .expect("connect");

    // One conversation between alice and bob, stored once under the sorted
    // pair, and one channel alice is in. Epoch milliseconds throughout.
    for (target, peers, ts) in [
        ("#room", None, 1000_i64),
        (
            "alice!bob",
            Some(vec!["alice".to_string(), "bob".to_string()]),
            2000,
        ),
    ] {
        sqlx::query(
            "INSERT INTO messages (msgid, target, sender_prefix, sender_account, kind, body, ts, dm_peers)
             VALUES ($1, $2, 'x!x@h', NULL, 'privmsg', 'hi',
                     to_timestamp($3::double precision / 1000), $4)",
        )
        .bind(format!("m-{target}-{ts}"))
        .bind(target)
        .bind(ts)
        .bind(peers)
        .execute(&pool)
        .await
        .expect("insert");
    }

    // alice sees the channel and the conversation, reported under bob's name.
    let targets = db::query_targets(
        &pool,
        &["#room".into()],
        "alice",
        e6irc_proto::time::Millis::from_millis(0),
        e6irc_proto::time::Millis::from_millis(9999),
        10,
    )
    .await;
    assert_eq!(
        targets,
        vec![
            (
                "#room".to_string(),
                e6irc_proto::time::Millis::from_millis(1000)
            ),
            (
                "bob".to_string(),
                e6irc_proto::time::Millis::from_millis(2000)
            )
        ]
    );

    // bob is not in #room, but still sees the conversation, under alice.
    let targets = db::query_targets(
        &pool,
        &[],
        "bob",
        e6irc_proto::time::Millis::from_millis(0),
        e6irc_proto::time::Millis::from_millis(9999),
        10,
    )
    .await;
    assert_eq!(
        targets,
        vec![(
            "alice".to_string(),
            e6irc_proto::time::Millis::from_millis(2000)
        )]
    );

    // A stranger sees neither.
    assert!(
        db::query_targets(
            &pool,
            &[],
            "mallory",
            e6irc_proto::time::Millis::from_millis(0),
            e6irc_proto::time::Millis::from_millis(9999),
            10
        )
        .await
        .is_empty(),
        "a non-participant must not see the conversation"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn query_history_around_and_between() {
    use e6ircd::core::HistoryQuery;
    let pool = db::connect_and_migrate(&support::test_db("query_history_around_and_between").await)
        .await
        .expect("connect");
    // Epoch milliseconds throughout: the ts column is a timestamptz and the
    // Rust layer converts to/from milliseconds.
    for ts in [1000_i64, 2000, 3000, 4000, 5000] {
        sqlx::query(
            "INSERT INTO messages (msgid, target, sender_prefix, sender_account, kind, body, ts)
             VALUES ($1, '#h', 'x!x@h', NULL, 'privmsg', $2,
                     to_timestamp($3::double precision / 1000))",
        )
        .bind(format!("m{ts}"))
        .bind(format!("b{ts}"))
        .bind(ts)
        .execute(&pool)
        .await
        .expect("insert");
    }

    // AROUND 3000, limit 4 → 2 older (1000,2000) + 3000 + 1 newer (4000).
    let around = db::query_history(
        &pool,
        "#h",
        HistoryQuery::Around {
            around_ts: e6irc_proto::time::Millis::from_millis(3000),
            limit: 4,
        },
    )
    .await;
    assert_eq!(
        around.iter().map(|r| r.ts.as_millis()).collect::<Vec<_>>(),
        vec![1000, 2000, 3000, 4000]
    );

    // BETWEEN (2000, 5000) exclusive → 3000, 4000.
    let between = db::query_history(
        &pool,
        "#h",
        HistoryQuery::Between {
            after_ts: e6irc_proto::time::Millis::from_millis(2000),
            before_ts: e6irc_proto::time::Millis::from_millis(5000),
            limit: 10,
            newest_first: false,
        },
    )
    .await;
    assert_eq!(
        between.iter().map(|r| r.ts.as_millis()).collect::<Vec<_>>(),
        vec![3000, 4000]
    );

    // Same window, but a limit smaller than the span: the direction decides
    // which end is kept, and the result stays oldest-first either way.
    let oldest = db::query_history(
        &pool,
        "#h",
        HistoryQuery::Between {
            after_ts: e6irc_proto::time::Millis::from_millis(2000),
            before_ts: e6irc_proto::time::Millis::from_millis(5000),
            limit: 1,
            newest_first: false,
        },
    )
    .await;
    assert_eq!(
        oldest.iter().map(|r| r.ts.as_millis()).collect::<Vec<_>>(),
        vec![3000]
    );
    let newest = db::query_history(
        &pool,
        "#h",
        HistoryQuery::Between {
            after_ts: e6irc_proto::time::Millis::from_millis(2000),
            before_ts: e6irc_proto::time::Millis::from_millis(5000),
            limit: 1,
            newest_first: true,
        },
    )
    .await;
    assert_eq!(
        newest.iter().map(|r| r.ts.as_millis()).collect::<Vec<_>>(),
        vec![4000]
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn query_history_msgid_paginates_within_a_single_second() {
    use e6ircd::core::HistoryQuery;
    let pool = db::connect_and_migrate(
        &support::test_db("query_history_msgid_paginates_within_a_single_second").await,
    )
    .await
    .expect("connect");
    // Five messages that all share the SAME whole second. Timestamp-only
    // paging cannot separate them; composite `(ts, id)` paging must, ordering
    // them by the monotonically-increasing insertion id.
    for tag in ["a", "b", "c", "d", "e"] {
        sqlx::query(
            "INSERT INTO messages (msgid, target, sender_prefix, sender_account, kind, body, ts)
             VALUES ($1, '#s', 'x!x@h', NULL, 'privmsg', $1,
                     to_timestamp(3000::double precision))",
        )
        .bind(tag)
        .execute(&pool)
        .await
        .expect("insert");
    }

    // BEFORE msgid=c → the same-second messages inserted before c.
    let before = db::query_history(
        &pool,
        "#s",
        HistoryQuery::BeforeMsgid {
            msgid: "c".into(),
            limit: 10,
        },
    )
    .await;
    assert_eq!(
        before.iter().map(|r| r.body.as_str()).collect::<Vec<_>>(),
        vec!["a", "b"],
        "BEFORE must page by (ts,id), not skip the whole second"
    );

    // AFTER msgid=c → the same-second messages inserted after c.
    let after = db::query_history(
        &pool,
        "#s",
        HistoryQuery::AfterMsgid {
            msgid: "c".into(),
            limit: 10,
        },
    )
    .await;
    assert_eq!(
        after.iter().map(|r| r.body.as_str()).collect::<Vec<_>>(),
        vec!["d", "e"]
    );

    // BETWEEN (a, e) exclusive → the interior of the same second.
    let between = db::query_history(
        &pool,
        "#s",
        HistoryQuery::BetweenMsgid {
            after_msgid: "a".into(),
            before_msgid: "e".into(),
            limit: 10,
            newest_first: false,
        },
    )
    .await;
    assert_eq!(
        between.iter().map(|r| r.body.as_str()).collect::<Vec<_>>(),
        vec!["b", "c", "d"]
    );

    // A limit shorter than the span keeps the end the direction points at.
    let newest = db::query_history(
        &pool,
        "#s",
        HistoryQuery::BetweenMsgid {
            after_msgid: "a".into(),
            before_msgid: "e".into(),
            limit: 1,
            newest_first: true,
        },
    )
    .await;
    assert_eq!(
        newest.iter().map(|r| r.body.as_str()).collect::<Vec<_>>(),
        vec!["d"]
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn channel_topic_persist_and_load() {
    let pool = db::connect_and_migrate(&support::test_db("channel_topic_persist_and_load").await)
        .await
        .expect("connect");
    db::create_account(&pool, "boss", "pw")
        .await
        .expect("account");
    sqlx::query(
        "INSERT INTO channels (name, name_folded, founder_account_id)
         SELECT '#c', '#c', id FROM accounts WHERE name_folded = 'boss'",
    )
    .execute(&pool)
    .await
    .expect("channel");

    // Set → it loads back with the same fields.
    db::set_channel_topic(
        &pool,
        "#c",
        Some(("hi there".into(), "boss!b@h".into(), 1000)),
    )
    .await
    .expect("set");
    assert_eq!(
        db::list_channel_topics(&pool).await.expect("list"),
        vec![(
            "#c".to_string(),
            "hi there".to_string(),
            "boss!b@h".to_string(),
            1000
        )]
    );

    // Clear → it no longer loads.
    db::set_channel_topic(&pool, "#c", None)
        .await
        .expect("clear");
    assert!(
        db::list_channel_topics(&pool)
            .await
            .expect("list")
            .is_empty()
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn channel_keeptopic_persist_and_load() {
    let pool =
        db::connect_and_migrate(&support::test_db("channel_keeptopic_persist_and_load").await)
            .await
            .expect("connect");
    db::create_account(&pool, "boss", "pw")
        .await
        .expect("account");
    sqlx::query(
        "INSERT INTO channels (name, name_folded, founder_account_id)
         SELECT '#c', '#c', id FROM accounts WHERE name_folded = 'boss'",
    )
    .execute(&pool)
    .await
    .expect("channel");

    // Default is on, so nothing is listed as an exception.
    assert!(
        db::list_keeptopic_off(&pool)
            .await
            .expect("list")
            .is_empty()
    );

    // Turn it off → it appears in the off-list.
    db::set_channel_keeptopic(&pool, "#c", false)
        .await
        .expect("off");
    assert_eq!(
        db::list_keeptopic_off(&pool).await.expect("list"),
        vec!["#c".to_string()]
    );

    // Back on → the exception clears.
    db::set_channel_keeptopic(&pool, "#c", true)
        .await
        .expect("on");
    assert!(
        db::list_keeptopic_off(&pool)
            .await
            .expect("list")
            .is_empty()
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn channel_mlock_persist_and_load() {
    let pool = db::connect_and_migrate(&support::test_db("channel_mlock_persist_and_load").await)
        .await
        .expect("connect");
    db::create_account(&pool, "boss", "pw")
        .await
        .expect("account");
    sqlx::query(
        "INSERT INTO channels (name, name_folded, founder_account_id)
         SELECT '#c', '#c', id FROM accounts WHERE name_folded = 'boss'",
    )
    .execute(&pool)
    .await
    .expect("channel");

    // No lock by default.
    assert!(
        db::list_channel_mlock(&pool)
            .await
            .expect("list")
            .is_empty()
    );

    // Set → loads back with the same spec.
    db::set_channel_mlock(&pool, "#c", Some("+nt-i".into()))
        .await
        .expect("set");
    assert_eq!(
        db::list_channel_mlock(&pool).await.expect("list"),
        vec![("#c".to_string(), "+nt-i".to_string())]
    );

    // Clear → it no longer loads.
    db::set_channel_mlock(&pool, "#c", None)
        .await
        .expect("clear");
    assert!(
        db::list_channel_mlock(&pool)
            .await
            .expect("list")
            .is_empty()
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn channel_access_persist_and_load() {
    let pool = db::connect_and_migrate(&support::test_db("channel_access_persist_and_load").await)
        .await
        .expect("connect");
    db::create_account(&pool, "boss", "pw").await.expect("boss");
    db::create_account(&pool, "alice", "pw")
        .await
        .expect("alice");
    sqlx::query(
        "INSERT INTO channels (name, name_folded, founder_account_id)
         SELECT '#c', '#c', id FROM accounts WHERE name_folded = 'boss'",
    )
    .execute(&pool)
    .await
    .expect("channel");

    db::set_channel_access(&pool, "#c", "alice", Some("ov".into()))
        .await
        .expect("set");
    assert_eq!(
        db::list_channel_access(&pool).await.expect("list"),
        vec![("#c".to_string(), "alice".to_string(), "ov".to_string())]
    );

    db::set_channel_access(&pool, "#c", "alice", None)
        .await
        .expect("clear");
    assert!(
        db::list_channel_access(&pool)
            .await
            .expect("list")
            .is_empty()
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn channel_founder_transfer() {
    let pool = db::connect_and_migrate(&support::test_db("channel_founder_transfer").await)
        .await
        .expect("connect");
    db::create_account(&pool, "boss", "pw").await.expect("boss");
    db::create_account(&pool, "alice", "pw")
        .await
        .expect("alice");
    sqlx::query(
        "INSERT INTO channels (name, name_folded, founder_account_id)
         SELECT '#c', '#c', id FROM accounts WHERE name_folded = 'boss'",
    )
    .execute(&pool)
    .await
    .expect("channel");
    assert_eq!(
        db::list_registered_channels(&pool).await.expect("list"),
        vec![("#c".to_string(), "boss".to_string())]
    );

    // Transfer to an existing account succeeds and moves ownership.
    assert!(db::set_channel_founder(&pool, "#c", "alice").await);
    assert_eq!(
        db::list_registered_channels(&pool).await.expect("list"),
        vec![("#c".to_string(), "alice".to_string())]
    );

    // Transfer to a nonexistent account fails and leaves ownership intact.
    assert!(!db::set_channel_founder(&pool, "#c", "nobody").await);
    assert_eq!(
        db::list_registered_channels(&pool).await.expect("list"),
        vec![("#c".to_string(), "alice".to_string())]
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn server_bans_persist_and_load() {
    let pool = db::connect_and_migrate(&support::test_db("server_bans_persist_and_load").await)
        .await
        .expect("connect");

    db::add_server_ban(&pool, "baddie@*", "spam", "god", "kline")
        .await
        .expect("add1");
    db::add_server_ban(&pool, "203.0.113.0", "netblock", "god", "dline")
        .await
        .expect("add2");
    // Same textual mask as the K-line but a different kind coexists.
    db::add_server_ban(&pool, "baddie@*", "gecos", "god", "xline")
        .await
        .expect("add3");
    let mut list = db::list_server_bans(&pool).await.expect("list");
    list.sort();
    assert_eq!(
        list,
        vec![
            (
                "203.0.113.0".to_string(),
                "netblock".to_string(),
                "god".to_string(),
                "dline".to_string(),
            ),
            (
                "baddie@*".to_string(),
                "gecos".to_string(),
                "god".to_string(),
                "xline".to_string(),
            ),
            (
                "baddie@*".to_string(),
                "spam".to_string(),
                "god".to_string(),
                "kline".to_string(),
            ),
        ]
    );

    // Re-banning the same (mask, kind) upserts (new reason/setter, no dup).
    db::add_server_ban(&pool, "baddie@*", "spam again", "root", "kline")
        .await
        .expect("upsert");
    let list = db::list_server_bans(&pool).await.expect("list");
    assert_eq!(
        list.iter()
            .filter(|(m, _, _, k)| m == "baddie@*" && k == "kline")
            .count(),
        1
    );

    // Removal is scoped to the kind — the X-line on the same mask survives.
    db::remove_server_ban(&pool, "baddie@*", "kline")
        .await
        .expect("remove");
    let mut list = db::list_server_bans(&pool).await.expect("list");
    list.sort();
    assert_eq!(
        list,
        vec![
            (
                "203.0.113.0".to_string(),
                "netblock".to_string(),
                "god".to_string(),
                "dline".to_string(),
            ),
            (
                "baddie@*".to_string(),
                "gecos".to_string(),
                "god".to_string(),
                "xline".to_string(),
            ),
        ]
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn audit_log_records_and_lists() {
    let pool = db::connect_and_migrate(&support::test_db("audit_log_records_and_lists").await)
        .await
        .expect("connect");
    db::insert_audit_log(&pool, "god", "OPER", "god", "")
        .await
        .expect("a1");
    db::insert_audit_log(&pool, "god", "KLINE", "baddie@*", "spam")
        .await
        .expect("a2");
    let list = db::list_audit_log(&pool, 10).await.expect("list");
    // newest-first
    assert_eq!(list.len(), 2);
    assert_eq!(
        (&list[0].1, &list[0].2),
        (&"KLINE".to_string(), &"baddie@*".to_string())
    );
    assert_eq!(&list[1].1, &"OPER".to_string());
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn oidc_identity_link_list_and_conflict() {
    use e6ircd::db::LinkOutcome;
    let pool =
        db::connect_and_migrate(&support::test_db("oidc_identity_link_list_and_conflict").await)
            .await
            .expect("connect");
    db::create_account(&pool, "alice", "pw")
        .await
        .expect("alice");
    db::create_account(&pool, "bob", "pw").await.expect("bob");

    // First link attaches; a repeat for the same account is idempotent.
    assert_eq!(
        db::link_oidc_identity(&pool, "alice", "https://idp.example", "sub-1")
            .await
            .expect("link"),
        LinkOutcome::Linked
    );
    assert_eq!(
        db::link_oidc_identity(&pool, "alice", "https://idp.example", "sub-1")
            .await
            .expect("relink"),
        LinkOutcome::AlreadyYours
    );
    // The same identity cannot be claimed by another account.
    assert_eq!(
        db::link_oidc_identity(&pool, "bob", "https://idp.example", "sub-1")
            .await
            .expect("steal"),
        LinkOutcome::Conflict
    );

    // A second identity for alice; listing is issuer/subject-ordered.
    db::link_oidc_identity(&pool, "alice", "https://idp.example", "sub-0")
        .await
        .expect("link2");
    assert_eq!(
        db::list_oidc_identities(&pool, "alice")
            .await
            .expect("list"),
        vec![
            ("https://idp.example".to_string(), "sub-0".to_string()),
            ("https://idp.example".to_string(), "sub-1".to_string()),
        ]
    );
    // bob got nothing.
    assert!(
        db::list_oidc_identities(&pool, "bob")
            .await
            .expect("list")
            .is_empty()
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn oidc_web_session_records_logout_hint() {
    let pool =
        db::connect_and_migrate(&support::test_db("oidc_web_session_records_logout_hint").await)
            .await
            .expect("connect");
    db::create_account(&pool, "alice", "pw")
        .await
        .expect("acct");

    // A plain session carries no logout hint.
    let plain = db::create_web_session(&pool, "alice").await.expect("plain");
    assert_eq!(
        db::session_logout_hint(&pool, &plain).await.expect("hint"),
        (None, None)
    );

    // An OIDC session records the id token + provider for RP-initiated logout.
    let sso = db::create_oidc_web_session(
        &pool,
        "alice",
        db::OidcSessionIdentity {
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
    .expect("sso");
    assert_eq!(
        db::session_logout_hint(&pool, &sso).await.expect("hint"),
        (Some("the.id.token".to_string()), Some("shauth".to_string()))
    );
    assert_eq!(
        db::session_identity(&pool, &sso).await.expect("identity"),
        Some(db::WebSessionIdentity {
            account: "alice".to_string(),
            email: Some("alice@example.test".to_string()),
            role: Some("developer".to_string()),
            provider: Some("shauth".to_string()),
        })
    );
    // Both resolve to the account.
    assert_eq!(
        db::session_account(&pool, &sso).await.expect("acct"),
        Some("alice".to_string())
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn oidc_logout_revokes_correlated_sessions_and_rejects_replay() {
    let pool = db::connect_and_migrate(
        &support::test_db("oidc_logout_revokes_correlated_sessions_and_rejects_replay").await,
    )
    .await
    .expect("connect");
    db::create_account(&pool, "alice", "pw")
        .await
        .expect("acct");
    let first = db::create_oidc_web_session(
        &pool,
        "alice",
        db::OidcSessionIdentity {
            id_token: Some("first.id.token"),
            provider: Some("shauth"),
            issuer: Some("https://auth.example"),
            subject: Some("alice-subject"),
            sid: Some("first-session"),
            email: Some("alice@example.test"),
            role: Some("developer"),
        },
    )
    .await
    .expect("first session");
    let second = db::create_oidc_web_session(
        &pool,
        "alice",
        db::OidcSessionIdentity {
            id_token: Some("second.id.token"),
            provider: Some("shauth"),
            issuer: Some("https://auth.example"),
            subject: Some("alice-subject"),
            sid: Some("second-session"),
            email: Some("alice@example.test"),
            role: Some("developer"),
        },
    )
    .await
    .expect("second session");

    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_secs() as i64
        + 600;
    let logout_token_id = format!(
        "logout-token-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    assert_eq!(
        db::consume_oidc_backchannel_logout(
            &pool,
            "https://auth.example",
            Some("alice-subject"),
            Some("first-session"),
            &logout_token_id,
            expires,
        )
        .await
        .expect("consume logout"),
        1
    );
    assert_eq!(
        db::session_account(&pool, &first).await.expect("first"),
        None
    );
    assert_eq!(
        db::session_account(&pool, &second).await.expect("second"),
        Some("alice".to_string())
    );
    assert!(matches!(
        db::consume_oidc_backchannel_logout(
            &pool,
            "https://auth.example",
            Some("alice-subject"),
            Some("first-session"),
            &logout_token_id,
            expires,
        )
        .await,
        Err(db::DbError::ReplayedLogoutToken)
    ));
    assert_eq!(
        db::revoke_oidc_frontchannel_sessions(&pool, "https://auth.example", "second-session")
            .await
            .expect("front-channel logout"),
        1
    );
    assert_eq!(
        db::session_account(&pool, &second).await.expect("second"),
        None
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn history_read_authorization_is_scoped() {
    let pool =
        db::connect_and_migrate(&support::test_db("history_read_authorization_is_scoped").await)
            .await
            .expect("connect");
    db::create_account(&pool, "alice", "pw")
        .await
        .expect("alice");
    db::create_account(&pool, "bob", "pw").await.expect("bob");
    db::create_account(&pool, "carol", "pw")
        .await
        .expect("carol");
    // Register #chan with alice as founder.
    sqlx::query(
        "INSERT INTO channels (name, name_folded, founder_account_id)
         SELECT '#chan', '#chan', id FROM accounts WHERE name_folded = 'alice'",
    )
    .execute(&pool)
    .await
    .expect("register channel");

    // Founder may read.
    assert!(
        db::account_may_read_channel(&pool, "#chan", "alice")
            .await
            .unwrap()
    );
    // An unrelated account may NOT read another channel's history (IDOR guard).
    assert!(
        !db::account_may_read_channel(&pool, "#chan", "bob")
            .await
            .unwrap()
    );
    // Granting access lets them read.
    db::set_channel_access(&pool, "#chan", "bob", Some("v".into()))
        .await
        .expect("grant");
    assert!(
        db::account_may_read_channel(&pool, "#chan", "bob")
            .await
            .unwrap()
    );
    // An unregistered channel exposes nothing via this path.
    assert!(
        !db::account_may_read_channel(&pool, "#unreg", "alice")
            .await
            .unwrap()
    );
    // A third account with no relationship stays denied.
    assert!(
        !db::account_may_read_channel(&pool, "#chan", "carol")
            .await
            .unwrap()
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn device_grants_are_pruned_on_create() {
    let pool =
        db::connect_and_migrate(&support::test_db("device_grants_are_pruned_on_create").await)
            .await
            .expect("connect");
    // An already-expired grant, as a never-approved /device/start flood leaves.
    sqlx::query(
        "INSERT INTO device_grants (device_code, user_code, expires_at)
         VALUES ('dead', 'DEADDEAD', now() - interval '1 minute')",
    )
    .execute(&pool)
    .await
    .expect("insert expired");
    // Creating a new grant prunes expired ones (unauthenticated growth guard).
    db::create_device_grant(&pool).await.expect("create");
    let expired: i64 =
        sqlx::query_scalar("SELECT count(*) FROM device_grants WHERE device_code = 'dead'")
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(expired, 0, "expired grant must be pruned on create");
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM device_grants")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(total, 1, "only the fresh grant should remain");
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn approved_device_grant_polls_to_a_working_token_then_is_consumed() {
    let pool = db::connect_and_migrate(
        &support::test_db("approved_device_grant_polls_to_a_working_token_then_is_consumed").await,
    )
    .await
    .expect("connect");
    db::create_account(&pool, "devacct", "pw")
        .await
        .expect("create account");
    // A pre-approval poll is Pending, not consumed.
    sqlx::query(
        "INSERT INTO device_grants (device_code, user_code, expires_at)
         VALUES ('dc', 'USERCODE1', now() + interval '10 minutes')",
    )
    .execute(&pool)
    .await
    .expect("insert grant");
    assert_eq!(
        db::poll_device_grant(&pool, "dc", "device")
            .await
            .expect("poll"),
        db::DeviceStatus::Pending,
        "unapproved grant is pending and left intact"
    );
    assert!(
        db::approve_device_grant(&pool, "USERCODE1", "devacct")
            .await
            .expect("approve"),
        "a fresh grant approves"
    );
    // Approved poll: consume + mint atomically, and the token must actually work.
    let token = match db::poll_device_grant(&pool, "dc", "device")
        .await
        .expect("poll approved")
    {
        db::DeviceStatus::Approved(token) => token,
        other => panic!("expected Approved, got {other:?}"),
    };
    assert_eq!(
        db::api_token_account(&pool, &token)
            .await
            .expect("resolve token")
            .as_deref(),
        Some("devacct"),
        "the minted token resolves to the approving account"
    );
    // The grant is gone: a replayed poll finds nothing (single-use), and no
    // second token was minted.
    assert_eq!(
        db::poll_device_grant(&pool, "dc", "device")
            .await
            .expect("poll consumed"),
        db::DeviceStatus::Unknown,
        "a consumed grant is single-use"
    );
    let tokens: i64 = sqlx::query_scalar("SELECT count(*) FROM api_tokens")
        .fetch_one(&pool)
        .await
        .expect("count tokens");
    assert_eq!(tokens, 1, "exactly one token minted for the approved grant");
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn bnc_buffer_trim_is_scoped_to_one_network() {
    // An upstream decides how many lines arrive, so an untrimmed network grows
    // the table until the disk is full. Two networks here because the trim must
    // bound the one it is asked about and leave the other's backlog alone.
    let url = support::test_db("bnc_buffer_trim_is_scoped_to_one_network").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");

    let count = async |network: &str| -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM bnc_buffer WHERE owner = 'owner' AND network = $1")
            .bind(network)
            .fetch_one(&pool)
            .await
            .expect("count")
    };

    for i in 0..6_000 {
        for network in ["alpha", "beta"] {
            db::persist_bnc_line(&pool, "owner", network, &format!("line {i}"))
                .await
                .expect("persist");
        }
    }
    db::trim_bnc_buffer(&pool, "owner", "alpha")
        .await
        .expect("trim");

    assert_eq!(count("alpha").await, 5_000, "alpha trimmed to the cap");
    assert_eq!(count("beta").await, 6_000, "beta untouched");
    // The newest lines are what survive — a trim that kept the oldest would
    // leave the buffer bounded and useless.
    let kept = db::recent_bnc_lines(&pool, "owner", "alpha", 1)
        .await
        .expect("read");
    assert_eq!(kept, vec!["line 5999"]);
}
