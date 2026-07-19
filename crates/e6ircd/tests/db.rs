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

fn test_db_url() -> String {
    std::env::var("E6IRC_TEST_DATABASE_URL")
        .expect("E6IRC_TEST_DATABASE_URL must be set for --ignored db tests")
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn verify_password_roundtrip() {
    let pool = db::connect_and_migrate(&test_db_url())
        .await
        .expect("connect");
    sqlx::query("TRUNCATE accounts CASCADE")
        .execute(&pool)
        .await
        .expect("clean");

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
    let url = test_db_url();
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    sqlx::query("TRUNCATE accounts CASCADE")
        .execute(&pool)
        .await
        .expect("clean");
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
    let url = test_db_url();
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    sqlx::query("TRUNCATE accounts CASCADE")
        .execute(&pool)
        .await
        .expect("clean");
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

    let url = test_db_url();
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    sqlx::query("TRUNCATE accounts CASCADE")
        .execute(&pool)
        .await
        .expect("clean");
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
async fn channel_messages_are_persisted() {
    let url = test_db_url();
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    sqlx::query("TRUNCATE messages, accounts CASCADE")
        .execute(&pool)
        .await
        .expect("clean");

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

    let url = test_db_url();
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    sqlx::query("TRUNCATE accounts CASCADE")
        .execute(&pool)
        .await
        .expect("clean");
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
    let url = test_db_url();
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    sqlx::query("TRUNCATE accounts CASCADE")
        .execute(&pool)
        .await
        .expect("clean");
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
    let url = test_db_url();
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    sqlx::query("TRUNCATE messages, accounts CASCADE")
        .execute(&pool)
        .await
        .expect("clean");
    db::create_account(&pool, "web", "pw")
        .await
        .expect("create");
    let session = db::create_web_session(&pool, "web").await.expect("session");
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
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn chathistory_pages_from_postgres_past_the_ring() {
    let url = test_db_url();
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    sqlx::query("TRUNCATE messages, accounts CASCADE")
        .execute(&pool)
        .await
        .expect("clean");

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
    let ts = e6irc_proto::time::server_time(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            * 1000
            + 60_000,
    );
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

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn bnc_networks_crud() {
    let pool = db::connect_and_migrate(&test_db_url())
        .await
        .expect("connect");
    sqlx::query("TRUNCATE accounts CASCADE")
        .execute(&pool)
        .await
        .expect("clean");
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
    let pool = db::connect_and_migrate(&test_db_url())
        .await
        .expect("connect");
    sqlx::query("TRUNCATE messages, accounts CASCADE")
        .execute(&pool)
        .await
        .expect("clean");

    for (target, ts) in [("#a", 1000_i64), ("#a", 2000), ("#b", 1500), ("#c", 3000)] {
        sqlx::query(
            "INSERT INTO messages (msgid, target, sender_prefix, sender_account, kind, body, ts)
             VALUES ($1, $2, 'x!x@h', NULL, 'privmsg', 'hi',
                     to_timestamp($3::double precision))",
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
    let targets = db::query_targets(&pool, &["#a".into(), "#b".into()], 1200, 2500, 10).await;
    assert_eq!(
        targets,
        vec![("#a".to_string(), 2000), ("#b".to_string(), 1500)]
    );

    // A window that excludes everything yields nothing.
    assert!(
        db::query_targets(&pool, &["#a".into()], 5000, 6000, 10)
            .await
            .is_empty()
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn query_history_around_and_between() {
    use e6ircd::core::HistoryQuery;
    let pool = db::connect_and_migrate(&test_db_url())
        .await
        .expect("connect");
    sqlx::query("TRUNCATE messages, accounts CASCADE")
        .execute(&pool)
        .await
        .expect("clean");
    for ts in [1000_i64, 2000, 3000, 4000, 5000] {
        sqlx::query(
            "INSERT INTO messages (msgid, target, sender_prefix, sender_account, kind, body, ts)
             VALUES ($1, '#h', 'x!x@h', NULL, 'privmsg', $2,
                     to_timestamp($3::double precision))",
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
            around_ts: 3000,
            limit: 4,
        },
    )
    .await;
    assert_eq!(
        around.iter().map(|r| r.ts).collect::<Vec<_>>(),
        vec![1000, 2000, 3000, 4000]
    );

    // BETWEEN (2000, 5000) exclusive → 3000, 4000.
    let between = db::query_history(
        &pool,
        "#h",
        HistoryQuery::Between {
            after_ts: 2000,
            before_ts: 5000,
            limit: 10,
        },
    )
    .await;
    assert_eq!(
        between.iter().map(|r| r.ts).collect::<Vec<_>>(),
        vec![3000, 4000]
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn channel_topic_persist_and_load() {
    let pool = db::connect_and_migrate(&test_db_url())
        .await
        .expect("connect");
    sqlx::query("TRUNCATE messages, accounts CASCADE")
        .execute(&pool)
        .await
        .expect("clean");
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
async fn channel_access_persist_and_load() {
    let pool = db::connect_and_migrate(&test_db_url())
        .await
        .expect("connect");
    sqlx::query("TRUNCATE messages, accounts CASCADE")
        .execute(&pool)
        .await
        .expect("clean");
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
    let pool = db::connect_and_migrate(&test_db_url())
        .await
        .expect("connect");
    sqlx::query("TRUNCATE messages, accounts CASCADE")
        .execute(&pool)
        .await
        .expect("clean");
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
    let pool = db::connect_and_migrate(&test_db_url())
        .await
        .expect("connect");
    sqlx::query("TRUNCATE server_bans")
        .execute(&pool)
        .await
        .expect("clean");

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
    let pool = db::connect_and_migrate(&test_db_url())
        .await
        .expect("connect");
    sqlx::query("TRUNCATE audit_log")
        .execute(&pool)
        .await
        .expect("clean");
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
