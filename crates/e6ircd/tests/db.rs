//! Database-worker integration tests against real PostgreSQL.
//!
//! Ignored by default; run with `--ignored` where PostgreSQL is
//! available (CI provides a service container):
//!   E6IRC_TEST_DATABASE_URL=postgres://... cargo test --test db -- --ignored

use e6irc_queue::{Config as QueueConfig, Policy, queue};
use e6ircd::config::{Config, DatabaseConfig, ListenerConfig, NetworkKind};
use e6ircd::core::{CoreIngress, DbReply, DbRequest, HistoryTargets, Input};
use e6ircd::{db, net};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

mod support;

static MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

const MANAGED_CONFIG_0052_FIELDS: &[&str] = &[
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
    "public_url",
    "secure_cookies",
    "admin_accounts",
    "oidc_providers",
    "opers",
    "networks",
    "credentials_from_bootstrap",
];

fn audit_page_size(value: usize) -> db::AuditLogPageSize {
    db::AuditLogPageSize::new(value).expect("test audit page size is in range")
}

fn account_page_size(value: usize) -> db::AccountDirectoryPageSize {
    db::AccountDirectoryPageSize::new(value).expect("test account page size is in range")
}

fn registered_channel_page_size(value: usize) -> db::RegisteredChannelDirectoryPageSize {
    db::RegisteredChannelDirectoryPageSize::new(value)
        .expect("test registered-channel page size is in range")
}

fn server_ban_page_size(value: usize) -> db::ServerBanDirectoryPageSize {
    db::ServerBanDirectoryPageSize::new(value).expect("test server-ban page size is in range")
}

/// `query_history` now returns `Result` (a DB fault is surfaced, not folded
/// into an empty page); these tests exercise the happy path, so a query error
/// is a test failure — unwrap it here rather than at every call site.
async fn hist(
    pool: &sqlx::PgPool,
    target: &str,
    query: e6ircd::core::HistoryQuery,
) -> Vec<e6ircd::core::HistoryRow> {
    db::query_history(pool, target, query)
        .await
        .expect("history query")
}

/// `query_targets` likewise now returns `Result`; unwrap for the happy-path
/// tests (a query error is a test failure).
async fn tgts(
    pool: &sqlx::PgPool,
    channels: &[String],
    me: &str,
    min_ts: e6irc_proto::time::Millis,
    max_ts: e6irc_proto::time::Millis,
    limit: usize,
) -> Vec<(String, e6irc_proto::time::Millis)> {
    db::query_targets(pool, channels, me, min_ts, max_ts, limit)
        .await
        .expect("targets query")
}

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
    tokio::spawn(db::run_worker(pool, req_rx, CoreIngress::single(core_tx)));

    let conn = e6ircd::core::ConnId(7);
    // right password, case-insensitive account lookup
    req_tx
        .push(DbRequest::VerifyPassword {
            conn,
            account: "ALICE".into(),
            password: "correct horse".into(),
            origin: e6ircd::core::CredentialOrigin::Sasl,
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
            account: "Alice".into(),
            origin: e6ircd::core::CredentialOrigin::Sasl,
        }
    );

    // wrong password and unknown account are indistinguishable
    for (account, password) in [("alice", "wrong"), ("nobody", "whatever")] {
        req_tx
            .push(DbRequest::VerifyPassword {
                conn,
                account: account.into(),
                password: password.into(),
                origin: e6ircd::core::CredentialOrigin::Sasl,
            })
            .await
            .expect("push");
        let Some(env) = core_rx.pop().await else {
            panic!("worker died")
        };
        let Input::DbReply { reply, .. } = env.payload else {
            panic!("unexpected")
        };
        assert_eq!(
            reply,
            DbReply::PasswordRejected {
                origin: e6ircd::core::CredentialOrigin::Sasl,
            },
            "{account}/{password}"
        );
    }
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn account_contact_email_is_stored_normalized_and_private_by_default() {
    let pool = db::connect_and_migrate(
        &support::test_db("account_contact_email_is_stored_normalized_and_private_by_default")
            .await,
    )
    .await
    .expect("connect");
    let email =
        e6ircd::identity::ContactEmail::parse("Alice+IRC@Example.COM").expect("valid email");
    db::create_account_with_contact(&pool, "Alice", "password", Some(&email))
        .await
        .expect("create");

    let stored: Option<String> =
        sqlx::query_scalar("SELECT contact_email FROM accounts WHERE name_folded = 'alice'")
            .fetch_one(&pool)
            .await
            .expect("contact email");
    assert_eq!(stored.as_deref(), Some("Alice+IRC@example.com"));

    let directory = db::query_account_directory(
        &pool,
        db::AccountDirectoryFilter {
            before_id: None,
            exact_name: None,
            page_size: account_page_size(10),
        },
    )
    .await
    .expect("account directory");
    let serialized = format!("{:?}", directory.entries);
    assert!(
        !serialized.contains("Alice+IRC"),
        "contact email is private and must not leak through the administrator directory"
    );

    let replacement =
        e6ircd::identity::ContactEmail::parse("new-contact@example.net").expect("valid email");
    db::set_account_contact_email(&pool, "Alice", Some(&replacement))
        .await
        .expect("replace");
    assert_eq!(
        db::account_contact_email(&pool, "alice")
            .await
            .expect("contact email"),
        Some("new-contact@example.net".into())
    );
    let audit: (String, String) = sqlx::query_as(
        "SELECT action, detail FROM audit_log
         WHERE action = 'ACCOUNT_CONTACT_UPDATE'
         ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .expect("contact audit");
    assert_eq!(audit.0, "ACCOUNT_CONTACT_UPDATE");
    assert_eq!(audit.1, "contact email replaced");
    assert!(
        !audit.1.contains("example"),
        "the private address must not enter audit detail"
    );
    db::set_account_contact_email(&pool, "alice", None)
        .await
        .expect("remove");
    assert_eq!(
        db::account_contact_email(&pool, "alice")
            .await
            .expect("contact email"),
        None
    );
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
            websocket: false,
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
            websocket: false,
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
            websocket: false,
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
            websocket: false,
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

/// The correctness heart of graceful shutdown (DESIGN §18): buffered history
/// must never be lost when the server stops. On shutdown the core is dropped,
/// which drops the sole `Sender<DbRequest>` and closes the worker's queue; the
/// worker's job is then to drain and flush its buffered `log_batch` before its
/// task ends. This test drives exactly that contract at the worker boundary —
/// enqueue rows, drop the sender, *await the worker's JoinHandle*, and require
/// every row to be in PostgreSQL — so a regression that abandons the buffer
/// (or exits before flushing) fails here rather than silently losing chat.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn buffered_history_flushes_when_the_sender_is_dropped() {
    let pool = db::connect_and_migrate(&support::test_db("shutdown_flush").await)
        .await
        .expect("connect");

    let (req_tx, req_rx) = queue::<DbRequest>(QueueConfig {
        name: "t-db",
        capacity: 64,
        policy: Policy::Fifo,
    });
    // The worker also holds a core sender; keep its receiver alive so pushes it
    // makes (none are expected for LogMessage) never fail for the wrong reason.
    let (core_tx, _core_rx) = queue::<Input>(QueueConfig {
        name: "t-core",
        capacity: 8,
        policy: Policy::Fifo,
    });
    let worker = tokio::spawn(db::run_worker(
        pool.clone(),
        req_rx,
        CoreIngress::single(core_tx),
    ));

    for i in 0..5 {
        req_tx
            .push(DbRequest::LogMessage {
                msgid: format!("shutdown-msg-{i}"),
                target: "#shutdown".into(),
                dm_peers: Vec::new(),
                sender_prefix: "alice!a@host".into(),
                sender_account: None,
                kind: e6ircd::core::MessageKind::Privmsg,
                body: format!("line {i}"),
                sender_is_bot: false,
                multiline: None,
                ts: e6irc_proto::time::Millis::from_millis(1_700_000_000_000 + i),
            })
            .await
            .expect("enqueue log");
    }

    // Drop the sender (what dropping the core does) and wait for the worker to
    // finish. Awaiting the JoinHandle is the guarantee shutdown depends on.
    drop(req_tx);
    tokio::time::timeout(std::time::Duration::from_secs(10), worker)
        .await
        .expect("worker drains and flushes before the timeout")
        .expect("worker task");

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE target = $1")
        .bind("#shutdown")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(
        count, 5,
        "all buffered history rows must be flushed on shutdown"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn history_worker_resolves_offline_direct_message_candidates() {
    let pool = db::connect_and_migrate(
        &support::test_db("history_worker_resolves_offline_direct_message_candidates").await,
    )
    .await
    .expect("connect");
    for (msgid, target, body) in [
        ("account-message", "alice!bob", "registered"),
        ("anonymous-message", "bob!~carol", "unauthenticated"),
    ] {
        sqlx::query(
            "INSERT INTO messages
                 (msgid, target, sender_prefix, kind, body, ts, dm_peers)
             VALUES ($1, $2, 'peer!u@host', 'privmsg', $3, now(),
                     string_to_array($2, '!'))",
        )
        .bind(msgid)
        .bind(target)
        .bind(body)
        .execute(&pool)
        .await
        .expect("insert history");
    }

    let (request_tx, request_rx) = queue::<DbRequest>(QueueConfig {
        name: "history-target-request",
        capacity: 8,
        policy: Policy::Fifo,
    });
    let (core_tx, mut core_rx) = queue::<Input>(QueueConfig {
        name: "history-target-reply",
        capacity: 8,
        policy: Policy::Fifo,
    });
    tokio::spawn(db::run_worker(
        pool,
        request_rx,
        CoreIngress::single(core_tx),
    ));

    for (targets, expected) in [
        (
            HistoryTargets::PreferExisting {
                primary: "alice!bob".into(),
                fallback: "bob!~alice".into(),
            },
            "registered",
        ),
        (
            HistoryTargets::PreferExisting {
                primary: "bob!carol".into(),
                fallback: "bob!~carol".into(),
            },
            "unauthenticated",
        ),
    ] {
        request_tx
            .push(DbRequest::QueryHistory {
                conn: e6ircd::core::ConnId(9),
                targets,
                display: "peer".into(),
                batch_ref: "batch".into(),
                query: e6ircd::core::HistoryQuery::Latest { limit: 10 },
                label: None,
            })
            .await
            .expect("enqueue query");
        let Some(reply) = core_rx.pop().await else {
            panic!("worker stopped before replying")
        };
        let Input::HistoryPage { rows, .. } = reply.payload else {
            panic!("unexpected worker reply")
        };
        let rows = rows.expect("history page");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].body, expected);
    }
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
    let session = db::create_web_session(&pool, "creduser", None)
        .await
        .expect("session");
    drop(pool);

    let config = Config {
        server_name: "irc.cred.example".into(),
        network_name: "CredNet".into(),
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
    let (status, body) = http_req(
        http,
        &format!("GET /api/v1/me HTTP/1.1\r\nHost: t\r\nConnection: close\r\n{auth}\r\n"),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let me: serde_json::Value = serde_json::from_str(&body).expect("current account JSON");
    let csrf = me["csrf_token"].as_str().expect("session CSRF token");
    let mutation_auth = format!("{auth}X-E6IRC-CSRF: {csrf}\r\n");

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
        &format!("DELETE /api/v1/me/credentials/{app_id} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n{mutation_auth}\r\n"),
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
        &format!("DELETE /api/v1/me/credentials/{app_id} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n{mutation_auth}\r\n"),
    )
    .await;
    assert_eq!(status, 404);
}

/// A successful credential verification records `last_used_at` for the matched
/// credential, so the credential list reflects real use instead of a
/// permanently-null column that misleads an account audit.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn verify_records_credential_last_used() {
    let url = support::test_db("verify_records_credential_last_used").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    db::create_account(&pool, "lu", "pw").await.expect("create");
    let app = db::issue_app_password(&pool, "lu", "pw", "laptop")
        .await
        .expect("app pw");

    // The app-password credential is unused until authenticated with. (The
    // account password legitimately shows use already: issuing the app password
    // verified it — proof the stamping targets exactly the matched row.)
    let app_last_used = |creds: &[db::CredentialRow]| -> Option<Option<String>> {
        creds
            .iter()
            .find(|row| row.kind == "app_password")
            .map(|row| row.last_used_at.clone())
    };
    let before = db::list_credentials(&pool, "lu").await.expect("list");
    assert_eq!(
        app_last_used(&before),
        Some(None),
        "the freshly issued app password must have no last-used time: {before:?}"
    );

    // Authenticate with the app password; it now records use.
    assert_eq!(
        db::verify_credentials(&pool, "lu", &app)
            .await
            .expect("verify"),
        Some("lu".to_string())
    );
    let after = db::list_credentials(&pool, "lu").await.expect("list");
    assert!(
        matches!(app_last_used(&after), Some(Some(_))),
        "a successful verify must stamp the app password's last-used: {after:?}"
    );

    // A rejected verify records nothing.
    assert_eq!(
        db::verify_credentials(&pool, "lu", "wrong")
            .await
            .expect("verify"),
        None
    );
}

/// `revoke_credential` deletes only app passwords, never the account's primary
/// `local_password` — the endpoint is documented to revoke app passwords, and
/// deleting the primary would silently lock the account out of password login.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn revoke_credential_cannot_delete_the_primary_password() {
    let url = support::test_db("revoke_credential_cannot_delete_the_primary_password").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    db::create_account(&pool, "rc", "pw").await.expect("create");
    db::issue_app_password(&pool, "rc", "pw", "laptop")
        .await
        .expect("app pw");
    let creds = db::list_credentials(&pool, "rc").await.expect("list");
    let local_id = creds
        .iter()
        .find(|row| row.kind == "local_password")
        .map(|row| row.id)
        .expect("local_password present");
    let app_id = creds
        .iter()
        .find(|row| row.kind == "app_password")
        .map(|row| row.id)
        .expect("app_password present");

    // Attempting to revoke the primary password is a no-op.
    assert!(
        !db::revoke_credential(&pool, "rc", local_id)
            .await
            .expect("revoke"),
        "the primary local_password must not be revocable here"
    );
    // ...and password login still works.
    assert_eq!(
        db::verify_credentials(&pool, "rc", "pw")
            .await
            .expect("verify"),
        Some("rc".to_string())
    );
    // The app password IS revocable.
    assert!(
        db::revoke_credential(&pool, "rc", app_id)
            .await
            .expect("revoke"),
        "an app password must be revocable"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn primary_password_rotation_is_single_and_rejects_app_passwords() {
    let url =
        support::test_db("primary_password_rotation_is_single_and_rejects_app_passwords").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    db::create_account(&pool, "rotate", "old")
        .await
        .expect("create");
    let app = db::issue_app_password(&pool, "rotate", "old", "client")
        .await
        .expect("app password");

    assert_eq!(
        db::verify_local_password(&pool, "rotate", &app)
            .await
            .expect("local verify"),
        None,
        "an IRC app password must not become a browser or rotation credential"
    );
    assert!(matches!(
        db::issue_app_password(&pool, "rotate", &app, "chained").await,
        Err(db::DbError::BadCredentials)
    ));
    assert!(matches!(
        db::change_local_password(&pool, "rotate", &app, "attacker-choice").await,
        Err(db::DbError::BadCredentials)
    ));

    db::change_local_password(&pool, "ROTATE", "old", "new")
        .await
        .expect("rotate");
    assert_eq!(
        db::verify_local_password(&pool, "rotate", "old")
            .await
            .expect("old verify"),
        None
    );
    assert_eq!(
        db::verify_local_password(&pool, "rotate", "new")
            .await
            .expect("new verify"),
        Some("rotate".into())
    );
    assert_eq!(
        db::verify_credentials(&pool, "rotate", &app)
            .await
            .expect("app verify"),
        Some("rotate".into()),
        "rotating the primary must not silently revoke independent app passwords"
    );

    let account_id: i64 =
        sqlx::query_scalar("SELECT id FROM accounts WHERE name_folded = 'rotate'")
            .fetch_one(&pool)
            .await
            .expect("account id");
    let duplicate = sqlx::query(
        "INSERT INTO account_credentials (account_id, kind, argon2_hash)
         VALUES ($1, 'local_password', 'not-a-real-hash')",
    )
    .bind(account_id)
    .execute(&pool)
    .await;
    assert!(
        duplicate.is_err(),
        "storage must reject a second primary password"
    );

    let oidc_account = db::find_or_create_oidc_account(
        &pool,
        "https://idp.example",
        "password-bootstrap",
        "oidc-only",
    )
    .await
    .expect("OIDC account");
    db::set_local_password(&pool, &oidc_account, "first-local")
        .await
        .expect("set first password");
    assert_eq!(
        db::verify_local_password(&pool, &oidc_account, "first-local")
            .await
            .expect("verify first password"),
        Some(oidc_account.clone())
    );
    assert!(matches!(
        db::set_local_password(&pool, &oidc_account, "second-local").await,
        Err(db::DbError::LocalPasswordExists)
    ));
}

/// Per-account app passwords are capped, so an authenticated account can't flood
/// the credential table.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn app_passwords_are_capped_per_account() {
    let url = support::test_db("app_passwords_are_capped_per_account").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    db::create_account(&pool, "cap", "pw")
        .await
        .expect("create");
    // Mint the maximum (32); each succeeds.
    for i in 0..32 {
        db::issue_app_password(&pool, "cap", "pw", &format!("dev{i}"))
            .await
            .unwrap_or_else(|e| panic!("app pw {i} should succeed: {e}"));
    }
    // The 33rd is refused with the dedicated error, not silently stored.
    let over = db::issue_app_password(&pool, "cap", "pw", "one too many").await;
    assert!(
        matches!(over, Err(db::DbError::TooManyCredentials)),
        "the 33rd app password must be refused: {over:?}"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn api_tokens_are_capped_per_account() {
    let url = support::test_db("api_tokens_are_capped_per_account").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    db::create_account(&pool, "tcap", "pw")
        .await
        .expect("create");
    // Mint the maximum (32) through the capped REST path; each succeeds.
    for i in 0..32 {
        db::issue_api_token(&pool, "tcap", &format!("cli{i}"))
            .await
            .unwrap_or_else(|e| panic!("token {i} should succeed: {e}"));
    }
    // The 33rd is refused with the dedicated error — the cap is enforced
    // atomically in the DB layer, not by a racy list-then-insert in the handler.
    let over = db::issue_api_token(&pool, "tcap", "one too many").await;
    assert!(
        matches!(over, Err(db::DbError::TooManyCredentials)),
        "the 33rd PAT must be refused: {over:?}"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn api_token_storage_rejects_invalid_grants_and_lifetimes() {
    let url = support::test_db("api_token_storage_rejects_invalid_grants_and_lifetimes").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    db::create_account(&pool, "token-shape", "pw")
        .await
        .expect("create");
    let account_id: i64 =
        sqlx::query_scalar("SELECT id FROM accounts WHERE name_folded = 'token-shape'")
            .fetch_one(&pool)
            .await
            .expect("account id");

    for (index, scopes) in [
        Vec::<String>::new(),
        vec!["read".into(), "read".into()],
        vec!["future".into()],
    ]
    .into_iter()
    .enumerate()
    {
        let result = sqlx::query(
            "INSERT INTO api_tokens (
                 token_hash, account_id, label, scopes, expires_at
             )
             VALUES ($1, $2, 'invalid', $3, now() + interval '1 day')",
        )
        .bind(vec![index as u8])
        .bind(account_id)
        .bind(scopes)
        .execute(&pool)
        .await;
        assert!(result.is_err(), "invalid scope set {index} was stored");
    }

    let invalid_lifetime = sqlx::query(
        "INSERT INTO api_tokens (
             token_hash, account_id, label, scopes, created_at, expires_at
         )
         VALUES (
             decode('ff', 'hex'), $1, 'invalid lifetime', ARRAY['read'],
             now(), now() - interval '1 second'
         )",
    )
    .bind(account_id)
    .execute(&pool)
    .await;
    assert!(
        invalid_lifetime.is_err(),
        "expiry at or before creation was stored"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn bnc_networks_are_capped_per_account() {
    let url = support::test_db("bnc_networks_are_capped_per_account").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    db::create_account(&pool, "ncap", "pw")
        .await
        .expect("create");
    let row = |i: usize| db::BncNetworkRow {
        kind: NetworkKind::Irc,
        name: format!("net{i}"),
        addr: "irc.example:6697".into(),
        tls: true,
        nick: "ncap".into(),
        realname: Some("Network Cap".into()),
        autojoin: vec![],
        sasl_account: None,
        sasl_password_sealed: None,
        enabled: true,
    };
    // Mint the maximum (32); each succeeds.
    for i in 0..32 {
        db::create_bnc_network(&pool, "ncap", &row(i))
            .await
            .unwrap_or_else(|e| panic!("network {i} should succeed: {e}"));
    }
    // The 33rd is refused with the dedicated error, enforced atomically — each
    // network spawns an always-on driver, so an overshoot is real amplification.
    let over = db::create_bnc_network(&pool, "ncap", &row(99)).await;
    assert!(
        matches!(over, Err(db::DbError::TooManyNetworks)),
        "the 33rd network must be refused: {over:?}"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn channel_access_is_capped_per_channel() {
    let url = support::test_db("channel_access_is_capped_per_channel").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    // A founder and a registered channel. Insert account rows directly (no argon2
    // needed — the cap counts registered accounts, not credentials), so 256+
    // accounts don't cost 256 password hashes.
    sqlx::query("INSERT INTO accounts (name, name_folded) VALUES ('founder', 'founder')")
        .execute(&pool)
        .await
        .expect("founder");
    sqlx::query(
        "INSERT INTO channels (name, name_folded, founder_account_id)
         SELECT '#c', '#c', id FROM accounts WHERE name_folded = 'founder'",
    )
    .execute(&pool)
    .await
    .expect("channel");

    // Fill the access list to the cap (256); each grant to a distinct registered
    // account succeeds.
    for i in 0..256 {
        let name = format!("t{i}");
        sqlx::query("INSERT INTO accounts (name, name_folded) VALUES ($1, $1)")
            .bind(&name)
            .execute(&pool)
            .await
            .expect("target account");
        db::set_channel_access(&pool, "#c", &name, Some("v".into()))
            .await
            .unwrap_or_else(|e| panic!("grant {i} should succeed: {e}"));
    }

    // The 257th distinct account is refused with the dedicated error.
    sqlx::query("INSERT INTO accounts (name, name_folded) VALUES ('t256', 't256')")
        .execute(&pool)
        .await
        .expect("target account");
    let over = db::set_channel_access(&pool, "#c", "t256", Some("v".into())).await;
    assert!(
        matches!(over, Err(db::DbError::TooManyAccessEntries)),
        "the 257th access entry must be refused: {over:?}"
    );

    // Re-flagging an EXISTING entry is still allowed — it replaces, not grows.
    let reflag = db::set_channel_access(&pool, "#c", "t0", Some("o".into())).await;
    assert!(
        matches!(reflag, Ok(true)),
        "re-flagging an existing entry stays allowed at the cap: {reflag:?}"
    );
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
            websocket: false,
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
    // Pipeline a newer marker and then an older one before either DB verdict
    // reaches the core. Both requests are written, and PostgreSQL's GREATEST
    // result—not the requested older value—must drive the second reply.
    w.write_all(
        b"MARKREAD #chan timestamp=2026-07-18T12:00:00.000Z\r\n\
          MARKREAD #chan timestamp=2020-01-01T00:00:00.000Z\r\n",
    )
    .await
    .unwrap();
    for _ in 0..2 {
        let reply = expect(&mut reader, "MARKREAD #chan timestamp=").await;
        assert!(
            reply.contains("timestamp=2026-07-18T12:00:00.000Z"),
            "the acknowledgement must carry the committed monotonic value: {reply}"
        );
    }

    // Receiving the acknowledgement means the row is already durable.
    let got: Option<(String,)> = sqlx::query_as(
        "SELECT to_char(marker_ts AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS')
         FROM read_markers WHERE target = '#chan'",
    )
    .fetch_optional(&pool)
    .await
    .expect("query");
    assert_eq!(
        got.as_ref().map(|row| row.0.as_str()),
        Some("2026-07-18T12:00:00")
    );
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
    let session = db::create_web_session(&pool, "web", None)
        .await
        .expect("session");
    // A second account with no relationship to #web must be refused (IDOR).
    db::create_account(&pool, "other", "pw")
        .await
        .expect("create other");
    let other_session = db::create_web_session(&pool, "other", None)
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
    let snoop_session = db::create_web_session(&pool2, "snoop", None)
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
            websocket: false,
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
            websocket: false,
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
            websocket: false,
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
            websocket: false,
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
            websocket: false,
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
async fn chathistory_targets_db_path_shows_dm_correspondent_as_a_nick() {
    // Regression: over the PostgreSQL TARGETS path a DM buffer must be reported
    // by the correspondent's display *nick*, not the raw stored identity
    // (`~nick` / folded account) — the no-DB path already converts, and the two
    // must agree.
    let url =
        support::test_db("chathistory_targets_db_path_shows_dm_correspondent_as_a_nick").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    let config = Config {
        server_name: "irc.dm.example".into(),
        network_name: "DmNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        database: Some(DatabaseConfig { url }),
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");

    // bob is the one who will query; alice sends him a DM.
    let bob_stream = TcpStream::connect(running.addrs[0]).await.expect("bob");
    let (br, mut bw) = bob_stream.into_split();
    let mut breader = BufReader::new(br);
    bw.write_all(
        b"CAP LS 302\r\nCAP REQ :batch draft/chathistory message-tags server-time\r\n\
          NICK bob\r\nUSER b 0 * :B\r\nCAP END\r\n",
    )
    .await
    .unwrap();
    expect_line(&mut breader, "001").await;

    let alice_stream = TcpStream::connect(running.addrs[0]).await.expect("alice");
    let (ar, mut aw) = alice_stream.into_split();
    let mut areader = BufReader::new(ar);
    aw.write_all(b"NICK alice\r\nUSER a 0 * :A\r\n")
        .await
        .unwrap();
    expect_line(&mut areader, "001").await;
    aw.write_all(b"PRIVMSG bob :hi there\r\n").await.unwrap();
    expect_line(&mut breader, "PRIVMSG bob :hi there").await;

    // Wait for the DM to land in the messages table.
    for _ in 0..100 {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM messages WHERE dm_peers IS NOT NULL")
            .fetch_one(&pool)
            .await
            .expect("count");
        if n >= 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let lo = e6irc_proto::time::server_time(e6irc_proto::time::Millis::from_millis(1000));
    let hi = e6irc_proto::time::server_time(e6irc_proto::time::Millis::from_millis(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            * 1000
            + 60_000,
    ));
    bw.write_all(format!("CHATHISTORY TARGETS timestamp={lo} timestamp={hi} 50\r\n").as_bytes())
        .await
        .unwrap();
    let target_line = expect_line(&mut breader, "CHATHISTORY TARGETS ").await;
    assert!(
        target_line.contains("CHATHISTORY TARGETS alice "),
        "DM target must be the display nick `alice`, not a raw identity: {target_line}"
    );
    assert!(
        !target_line.contains("~alice"),
        "the raw `~`-prefixed identity must not leak: {target_line}"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn chathistory_dm_with_a_disconnected_unauthenticated_peer_is_readable() {
    // Regression: an *unauthenticated* peer's DM is stored under `~nick`, but the
    // offline read resolves the nick to the bare (account) form. Once the peer
    // disconnects, the account-form key names no stored conversation, so
    // without the `~nick` fallback `CHATHISTORY LATEST <nick>` returned an empty
    // batch for backlog `CHATHISTORY TARGETS` still advertises.
    let url = support::test_db("chathistory_dm_disconnected_unauth_peer").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    let config = Config {
        server_name: "irc.dm2.example".into(),
        network_name: "DmNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        database: Some(DatabaseConfig { url }),
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");

    // bob is the querier; alice (unauthenticated) sends him a DM then quits.
    let bob_stream = TcpStream::connect(running.addrs[0]).await.expect("bob");
    let (br, mut bw) = bob_stream.into_split();
    let mut breader = BufReader::new(br);
    bw.write_all(
        b"CAP LS 302\r\nCAP REQ :batch draft/chathistory message-tags server-time\r\n\
          NICK bob\r\nUSER b 0 * :B\r\nCAP END\r\n",
    )
    .await
    .unwrap();
    expect_line(&mut breader, "001").await;

    let alice_stream = TcpStream::connect(running.addrs[0]).await.expect("alice");
    let (ar, mut aw) = alice_stream.into_split();
    let mut areader = BufReader::new(ar);
    aw.write_all(b"NICK alice\r\nUSER a 0 * :A\r\n")
        .await
        .unwrap();
    expect_line(&mut areader, "001").await;
    aw.write_all(b"PRIVMSG bob :hi there\r\n").await.unwrap();
    expect_line(&mut breader, "PRIVMSG bob :hi there").await;

    // Wait for the DM to persist before switching the lookup to the offline
    // identity path.
    for _ in 0..100 {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM messages WHERE dm_peers IS NOT NULL")
            .fetch_one(&pool)
            .await
            .expect("count");
        if n >= 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // alice disconnects; poll until she is fully offline, so bob's read resolves
    // her nick to the bare form (exercising the fallback, not the live-session
    // path — which would resolve the correct `~alice` key directly and pass
    // trivially).
    aw.write_all(b"QUIT :bye\r\n").await.unwrap();
    drop(aw);
    drop(areader);
    loop {
        bw.write_all(b"ISON alice\r\n").await.unwrap();
        let line = expect_line(&mut breader, " 303 ").await;
        let present = line
            .rsplit_once(" :")
            .map(|(_, t)| t.contains("alice"))
            .unwrap_or(false);
        if !present {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // bob reads the DM history by alice's nick. The account-form key names no
    // stored conversation; the `~alice` fallback must resolve the backlog.
    bw.write_all(b"CHATHISTORY LATEST alice * 10\r\n")
        .await
        .unwrap();
    let batch_open = expect_line(&mut breader, "BATCH +").await;
    let batch_ref = batch_open
        .split(" BATCH +")
        .nth(1)
        .and_then(|s| s.split(' ').next())
        .expect("batch ref")
        .to_string();
    let mut found = false;
    loop {
        let line = expect_line(&mut breader, "").await;
        if line.contains("BATCH -") {
            break;
        }
        if line.contains(&format!("batch={batch_ref}")) && line.contains("hi there") {
            found = true;
        }
    }
    assert!(
        found,
        "the disconnected unauthenticated peer's DM must be replayed, not an empty batch"
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
        kind: NetworkKind::Irc,
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
    assert_eq!(alice_nets[0].kind, e6ircd::config::NetworkKind::Irc);
    assert_eq!(alice_nets[0].autojoin, vec!["#rust", "#e6irc"]);
    assert_eq!(
        alice_nets[0].sasl_password_sealed.as_deref(),
        Some("enc:v1:abc")
    );

    // Updating one owner's mutable configuration includes the sealed
    // credentials and cannot touch another owner's same-named network.
    let mut updated = libera.clone();
    updated.addr = "irc.eu.libera.chat:6697".into();
    updated.nick = "alice_new".into();
    updated.sasl_account = Some("alice-login".into());
    updated.sasl_password_sealed = Some("enc:v2:replacement".into());
    assert!(
        db::update_bnc_network(&pool, "alice", "LIBERA", &updated)
            .await
            .expect("update")
    );
    let stored = db::get_bnc_network(&pool, "alice", "libera")
        .await
        .expect("get updated")
        .expect("updated network");
    assert_eq!(stored.addr, "irc.eu.libera.chat:6697");
    assert_eq!(stored.nick, "alice_new");
    assert_eq!(stored.sasl_account.as_deref(), Some("alice-login"));
    assert_eq!(
        stored.sasl_password_sealed.as_deref(),
        Some("enc:v2:replacement")
    );
    let bob = db::get_bnc_network(&pool, "bob", "libera")
        .await
        .expect("get bob")
        .expect("bob network");
    assert_eq!(bob.addr, libera.addr);
    assert_eq!(bob.sasl_account, libera.sasl_account);

    // A bridge kind round-trips through the new `kind` column (the generic
    // columns carry the bridge's fields: here a Matrix homeserver/user).
    let matrix = db::BncNetworkRow {
        kind: e6ircd::config::NetworkKind::Matrix,
        name: "hq".into(),
        addr: "https://matrix.example".into(),
        tls: true,
        nick: "e6bot".into(),
        realname: Some("Alice".into()),
        autojoin: vec!["#room:matrix.example".into()],
        sasl_account: None,
        sasl_password_sealed: Some("enc:v2:sealed".into()),
        enabled: true,
    };
    db::create_bnc_network(&pool, "alice", &matrix)
        .await
        .expect("matrix");
    let hq = db::get_bnc_network(&pool, "alice", "hq")
        .await
        .expect("get")
        .expect("present");
    assert_eq!(hq.kind, e6ircd::config::NetworkKind::Matrix);
    assert_eq!(hq.addr, "https://matrix.example");
    db::set_bnc_network_enabled(&pool, "alice", "hq", false)
        .await
        .expect("disable matrix");
    let inventory = db::list_bnc_network_inventory(&pool)
        .await
        .expect("admin inventory");
    assert_eq!(inventory.len(), 3);
    assert!(
        inventory.iter().any(|row| {
            row.owner == "alice" && row.network.name == "hq" && !row.network.enabled
        })
    );
    db::delete_bnc_network(&pool, "alice", "hq")
        .await
        .expect("cleanup");

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
async fn bnc_network_name_selection_is_case_insensitive() {
    // A network name is an IRC-identifier-like selector, folded end-to-end
    // (registry key + DB, migration 0034). Without this a user who owns `libera`
    // and typed `/network Libera` would miss their own network and could fall
    // through to an operator's shared network of that name (DESIGN §2).
    let pool =
        db::connect_and_migrate(&support::test_db("bnc_network_name_case_insensitive").await)
            .await
            .expect("connect");
    db::create_account(&pool, "alice", "pw")
        .await
        .expect("acct");

    let libera = db::BncNetworkRow {
        kind: NetworkKind::Irc,
        name: "libera".into(),
        addr: "irc.libera.chat:6697".into(),
        tls: true,
        nick: "alice_".into(),
        realname: Some("Mixed Case".into()),
        autojoin: vec![],
        sasl_account: None,
        sasl_password_sealed: None,
        enabled: true,
    };
    db::create_bnc_network(&pool, "alice", &libera)
        .await
        .expect("create");

    // A case-variant of an existing name is the *same* network, not a new one.
    let mut variant = libera.clone();
    variant.name = "Libera".into();
    let dup = db::create_bnc_network(&pool, "alice", &variant).await;
    assert!(
        matches!(dup, Err(db::DbError::DuplicateNetwork(_))),
        "case-variant create must collide with the existing network: {dup:?}"
    );

    // Lookups by any casing resolve to the one stored network (display case
    // preserved), and enable/disable + delete hit it regardless of typed case.
    for typed in ["libera", "Libera", "LIBERA", "lIbErA"] {
        let got = db::get_bnc_network(&pool, "alice", typed)
            .await
            .expect("get")
            .unwrap_or_else(|| panic!("`{typed}` should resolve to the owned network"));
        assert_eq!(got.name, "libera", "display casing is preserved");
    }
    // Buffer APIs share that same composite-key fold. A producer using display
    // casing and a reader using a different selector spelling must still meet.
    db::persist_bnc_line(&pool, "ALICE", "LiBeRa", ":s NOTICE * :backlog")
        .await
        .expect("persist case variant");
    assert_eq!(
        db::recent_bnc_lines(&pool, "alice", "LIBERA", 10)
            .await
            .expect("read case variant"),
        vec![":s NOTICE * :backlog"]
    );
    let summary = db::bnc_buffer_summary(&pool, "Alice", "libera")
        .await
        .expect("buffer summary");
    assert_eq!(summary.lines, 1);
    assert!(summary.oldest_at.is_some());
    assert!(summary.newest_at.is_some());
    assert!(
        db::set_bnc_network_enabled(&pool, "alice", "LIBERA", false)
            .await
            .expect("disable"),
        "disable by a different casing must match the stored network"
    );
    assert!(
        db::delete_bnc_network(&pool, "alice", "LiBeRa")
            .await
            .expect("delete"),
        "delete by a different casing must match the stored network"
    );
    assert_eq!(
        db::list_bnc_networks(&pool, "alice").await.unwrap().len(),
        0,
        "the network is gone after a case-insensitive delete"
    );
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM bnc_buffer")
        .fetch_one(&pool)
        .await
        .expect("buffer count");
    assert_eq!(
        remaining, 0,
        "a case-variant delete must purge the canonical buffer rows"
    );

    let invalid_kind = sqlx::query(
        "INSERT INTO bnc_networks
           (account_id, name, addr, tls, nick, autojoin, kind)
         SELECT id, 'bad-kind', 'example.test:6697', true, 'alice_', ARRAY[]::text[], 'smtp'
         FROM accounts WHERE name_folded = 'alice'",
    )
    .execute(&pool)
    .await;
    assert!(
        invalid_kind.is_err(),
        "the database must reject values outside the closed driver-kind set"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn deleting_a_bnc_network_purges_its_casefolded_buffer() {
    // bnc_buffer is keyed by the *casefolded* owner (the persistence task folds
    // it). Deleting a network by the raw account name must still remove the
    // buffer rows — otherwise a mixed-case owner's backlog is orphaned forever
    // and a same-named network recreated later replays it.
    let pool = db::connect_and_migrate(
        &support::test_db("deleting_a_bnc_network_purges_its_casefolded_buffer").await,
    )
    .await
    .expect("connect");
    db::create_account(&pool, "MixedCase", "pw")
        .await
        .expect("acct");
    let net = db::BncNetworkRow {
        kind: NetworkKind::Irc,
        name: "libera".into(),
        addr: "irc.libera.chat:6697".into(),
        tls: true,
        nick: "mc".into(),
        realname: Some("Mixed Case".into()),
        autojoin: vec![],
        sasl_account: None,
        sasl_password_sealed: None,
        enabled: true,
    };
    db::create_bnc_network(&pool, "MixedCase", &net)
        .await
        .expect("create");
    // The live persistence path writes under the folded owner.
    let folded = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold("MixedCase");
    for i in 0..3 {
        db::persist_bnc_line(&pool, &folded, "libera", &format!(":s PRIVMSG #x :m{i}"))
            .await
            .expect("persist");
    }
    // Delete by the raw (display-cased) account name, as the HTTP handler does.
    assert!(
        db::delete_bnc_network(&pool, "MixedCase", "libera")
            .await
            .expect("delete")
    );
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM bnc_buffer")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(
        remaining, 0,
        "the folded-owner buffer rows must be purged on delete, not orphaned"
    );
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
    let targets = tgts(
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
        tgts(
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
        tgts(
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
        let rows = hist(&pool, "#public", query.clone()).await;
        assert!(
            rows.is_empty(),
            "a foreign msgid must not position a query: {query:?} returned {:?}",
            rows.iter().map(|r| &r.body).collect::<Vec<_>>()
        );
    }
    // A pivot that does belong to the target still works.
    let rows = hist(
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
    let rows = hist(
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
    let targets = tgts(
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
    let targets = tgts(
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
        tgts(
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
    let around = hist(
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
    let ts =
        |ms| e6ircd::core::SelectorBound::Timestamp(e6irc_proto::time::Millis::from_millis(ms));
    let between = hist(
        &pool,
        "#h",
        HistoryQuery::BetweenSelectors {
            first: ts(2000),
            second: ts(5000),
            limit: 10,
        },
    )
    .await;
    assert_eq!(
        between.iter().map(|r| r.ts.as_millis()).collect::<Vec<_>>(),
        vec![3000, 4000]
    );

    // Same window, but a limit smaller than the span: the argument order decides
    // which end is kept, and the result stays oldest-first either way. Older
    // selector first → keep the oldest.
    let oldest = hist(
        &pool,
        "#h",
        HistoryQuery::BetweenSelectors {
            first: ts(2000),
            second: ts(5000),
            limit: 1,
        },
    )
    .await;
    assert_eq!(
        oldest.iter().map(|r| r.ts.as_millis()).collect::<Vec<_>>(),
        vec![3000]
    );
    // Newer selector first → keep the newest.
    let newest = hist(
        &pool,
        "#h",
        HistoryQuery::BetweenSelectors {
            first: ts(5000),
            second: ts(2000),
            limit: 1,
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
async fn between_selectors_resolve_pivots_in_the_db() {
    // The DB path resolves each BETWEEN pivot's (ts, id) itself, so a msgid pivot
    // that has scrolled out of the ring is still paged correctly — where the old
    // ring-only resolution lost a mixed msgid bound or inverted a reversed-order
    // two-msgid range to empty.
    use e6ircd::core::{HistoryQuery, SelectorBound};
    let pool = db::connect_and_migrate(
        &support::test_db("between_selectors_resolve_pivots_in_the_db").await,
    )
    .await
    .expect("connect");
    for ts in [1000_i64, 2000, 3000, 4000, 5000] {
        sqlx::query(
            "INSERT INTO messages (msgid, target, sender_prefix, sender_account, kind, body, ts)
             VALUES ($1, '#b', 'x!x@h', NULL, 'privmsg', $2,
                     to_timestamp($3::double precision / 1000))",
        )
        .bind(format!("m{ts}"))
        .bind(format!("b{ts}"))
        .bind(ts)
        .execute(&pool)
        .await
        .expect("insert");
    }
    let bodies = |rows: Vec<e6ircd::core::HistoryRow>| -> Vec<String> {
        rows.into_iter().map(|r| r.body).collect()
    };
    let mid = |m: &str| SelectorBound::Msgid(m.to_string());
    let ts = |ms| SelectorBound::Timestamp(e6irc_proto::time::Millis::from_millis(ms));

    // Two msgids given newest-first (m4000 before m1000): the span is m2000,
    // m3000 — the old ring-only direction collapsed this to an inverted empty
    // range. Always oldest-first.
    let reversed = hist(
        &pool,
        "#b",
        HistoryQuery::BetweenSelectors {
            first: mid("m4000"),
            second: mid("m1000"),
            limit: 10,
        },
    )
    .await;
    assert_eq!(bodies(reversed), vec!["b2000", "b3000"]);

    // Mixed msgid + timestamp: between m4000 and the instant 1500 → m2000, m3000
    // (m4000 itself excluded). The old code lost the msgid bound and returned a
    // wrong window.
    let mixed = hist(
        &pool,
        "#b",
        HistoryQuery::BetweenSelectors {
            first: mid("m4000"),
            second: ts(1500),
            limit: 10,
        },
    )
    .await;
    assert_eq!(bodies(mixed), vec!["b2000", "b3000"]);

    // A pivot msgid not in this buffer → empty (like the other msgid pivots),
    // not a plausible-but-wrong window.
    let unknown = hist(
        &pool,
        "#b",
        HistoryQuery::BetweenSelectors {
            first: mid("nope"),
            second: ts(9999),
            limit: 10,
        },
    )
    .await;
    assert!(bodies(unknown).is_empty());
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
    let before = hist(
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
    let after = hist(
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
    let mid = |m: &str| e6ircd::core::SelectorBound::Msgid(m.to_string());
    let between = hist(
        &pool,
        "#s",
        HistoryQuery::BetweenSelectors {
            first: mid("a"),
            second: mid("e"),
            limit: 10,
        },
    )
    .await;
    assert_eq!(
        between.iter().map(|r| r.body.as_str()).collect::<Vec<_>>(),
        vec!["b", "c", "d"]
    );

    // A limit shorter than the span keeps the end the argument order points at.
    // Newer selector first → keep the newest.
    let newest = hist(
        &pool,
        "#s",
        HistoryQuery::BetweenSelectors {
            first: mid("e"),
            second: mid("a"),
            limit: 1,
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
async fn channel_registration_stores_initial_topic_in_its_insert() {
    let pool = db::connect_and_migrate(
        &support::test_db("channel_registration_stores_initial_topic_in_its_insert").await,
    )
    .await
    .expect("connect");
    db::create_account(&pool, "boss", "pw")
        .await
        .expect("account");
    let topic = ("initial".to_string(), "boss!b@h".to_string(), 1000);
    let result = db::persist_channel_registration(&pool, "#c", "boss", &Some(topic.clone()))
        .await
        .expect("registration");
    assert_eq!(result, e6ircd::core::ChannelRegistrationResult::Registered);
    assert_eq!(
        db::list_channel_topics(&pool).await.expect("topics"),
        vec![(
            "#c".to_string(),
            "initial".to_string(),
            "boss!b@h".to_string(),
            1000
        )]
    );
    let audit = db::list_audit_log(&pool, audit_page_size(1))
        .await
        .expect("audit");
    let entry = &audit[0];
    assert_eq!(
        (
            entry.actor.as_str(),
            entry.action.as_str(),
            entry.target.as_str(),
            entry.detail.as_str()
        ),
        ("boss", "CHANNEL_REGISTER", "#c", "")
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
    assert_eq!(
        db::set_channel_topic(
            &pool,
            "#c",
            Some(("hi there".into(), "boss!b@h".into(), 1000)),
        )
        .await
        .expect("set"),
        Some(true)
    );
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
    assert_eq!(
        db::set_channel_topic(&pool, "#c", None)
            .await
            .expect("clear"),
        Some(true)
    );
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

    db::set_channel_topic(&pool, "#c", Some(("old".into(), "boss!b@h".into(), 1000)))
        .await
        .expect("topic");

    // Turn it off → it appears in the off-list and clears all retained-topic
    // columns in the same UPDATE.
    assert!(
        db::set_channel_keeptopic(&pool, "#c", false, None)
            .await
            .expect("off")
    );
    assert_eq!(
        db::list_keeptopic_off(&pool).await.expect("list"),
        vec!["#c".to_string()]
    );
    assert!(
        db::list_channel_topics(&pool)
            .await
            .expect("topics")
            .is_empty()
    );

    // Back on → the exception clears and the supplied live topic is captured
    // atomically, without a second write that can fail independently.
    assert!(
        db::set_channel_keeptopic(
            &pool,
            "#c",
            true,
            Some(("current".into(), "boss!b@h".into(), 2000)),
        )
        .await
        .expect("on")
    );
    assert!(
        db::list_keeptopic_off(&pool)
            .await
            .expect("list")
            .is_empty()
    );
    assert_eq!(
        db::list_channel_topics(&pool).await.expect("topics"),
        vec![(
            "#c".to_string(),
            "current".to_string(),
            "boss!b@h".to_string(),
            2000
        )]
    );
    assert!(
        !db::set_channel_keeptopic(&pool, "#missing", true, None)
            .await
            .expect("missing option row")
    );
    assert_eq!(
        db::set_channel_topic(&pool, "#missing", None)
            .await
            .expect("missing topic row"),
        None
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

    // The database boundary rejects a semantically valid but non-canonical
    // spelling; every shipped writer canonicalizes before it reaches storage.
    assert!(
        db::set_channel_mlock(&pool, "#c", Some("+tn-i".into()))
            .await
            .is_err()
    );
    for noncanonical in ["+-i", "+i-i"] {
        assert!(
            db::set_channel_mlock(&pool, "#c", Some(noncanonical.into()))
                .await
                .is_err(),
            "database accepted non-canonical MLOCK {noncanonical}"
        );
    }

    // Canonical set → loads back with the same spec.
    assert!(
        db::set_channel_mlock(&pool, "#c", Some("+nt-i".into()))
            .await
            .expect("set")
    );
    assert_eq!(
        db::list_channel_mlock(&pool).await.expect("list"),
        vec![("#c".to_string(), "+nt-i".to_string())]
    );

    // Clear → it no longer loads.
    assert!(
        db::set_channel_mlock(&pool, "#c", None)
            .await
            .expect("clear")
    );
    assert!(
        db::list_channel_mlock(&pool)
            .await
            .expect("list")
            .is_empty()
    );
    assert!(
        !db::set_channel_mlock(&pool, "#missing", Some("+m".into()))
            .await
            .expect("missing row")
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn channel_mlock_migration_normalizes_historical_rows() {
    let url = support::test_db("channel_mlock_migration_normalizes_historical_rows").await;
    let pool = sqlx::PgPool::connect(&url).await.expect("connect");
    MIGRATIONS
        .run_to(37, &pool)
        .await
        .expect("migrate through 0037");
    sqlx::query("INSERT INTO accounts (name, name_folded) VALUES ('boss', 'boss')")
        .execute(&pool)
        .await
        .expect("account");
    sqlx::query(
        "INSERT INTO channels (name, name_folded, founder_account_id, mlock)
         SELECT spelling, spelling, id, mlock
         FROM accounts
         CROSS JOIN (VALUES
             ('#reordered', '+tn-i'),
             ('#contradictory', '+i-i'),
             ('#empty', '+-')
         ) historical(spelling, mlock)
         WHERE name_folded = 'boss'",
    )
    .execute(&pool)
    .await
    .expect("historical locks");

    MIGRATIONS.run(&pool).await.expect("migrate through 0038");
    let locks: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT name, mlock FROM channels ORDER BY name")
            .fetch_all(&pool)
            .await
            .expect("normalized locks");
    assert_eq!(
        locks,
        vec![
            ("#contradictory".into(), Some("-i".into())),
            ("#empty".into(), None),
            ("#reordered".into(), Some("+nt-i".into())),
        ]
    );
}

fn managed_settings_with_oidc_providers(
    providers: Option<Vec<serde_json::Value>>,
) -> serde_json::Value {
    let managed = e6ircd::config::ManagedConfig::from_config(&Config::default(), None)
        .expect("bootstrap managed settings");
    let mut settings = serde_json::to_value(managed).expect("serialize managed settings");
    settings
        .as_object_mut()
        .expect("managed settings object")
        .retain(|field, _| MANAGED_CONFIG_0052_FIELDS.contains(&field.as_str()));
    match providers {
        Some(providers) => settings["oidc_providers"] = serde_json::Value::Array(providers),
        None => {
            settings
                .as_object_mut()
                .expect("managed settings object")
                .remove("oidc_providers");
        }
    }
    settings
}

fn oidc_provider(name: &str, account_claim: Option<&str>) -> serde_json::Value {
    let mut provider = serde_json::json!({
        "name": name,
        "issuer_url": format!("https://{name}.example"),
        "client_id": "e6irc",
        "client_secret": "sealed",
        "scopes": ["openid", "profile"],
        "allowed_email_domains": [],
        "end_session_endpoint": null,
        "token_endpoint_auth_method": "client_secret_basic"
    });
    if let Some(account_claim) = account_claim {
        provider["account_claim"] = serde_json::Value::String(account_claim.into());
    }
    provider
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn managed_config_migration_backfills_legacy_oidc_claims() {
    let pool = sqlx::PgPool::connect(
        &support::test_db("managed_config_migration_backfills_legacy_oidc_claims").await,
    )
    .await
    .expect("connect");
    MIGRATIONS
        .run_to(52, &pool)
        .await
        .expect("migrate through 0052");
    let settings = managed_settings_with_oidc_providers(Some(vec![
        oidc_provider("legacy-first", None),
        oidc_provider("explicit-email", Some("email")),
        oidc_provider("legacy-last", None),
    ]));
    sqlx::query(
        "INSERT INTO server_settings (singleton, revision, settings, updated_by)
         VALUES (TRUE, 1, $1, 'legacy')",
    )
    .bind(settings)
    .execute(&pool)
    .await
    .expect("legacy settings");

    MIGRATIONS.run(&pool).await.expect("migrate current");
    let loaded = db::load_managed_config(&pool)
        .await
        .expect("typed settings after migration");
    assert_eq!(
        loaded
            .settings
            .oidc_providers
            .iter()
            .map(|provider| (provider.name.clone(), provider.account_claim))
            .collect::<Vec<_>>(),
        vec![
            (
                "legacy-first".to_string(),
                e6ircd::config::OidcAccountClaim::PreferredUsername,
            ),
            (
                "explicit-email".to_string(),
                e6ircd::config::OidcAccountClaim::Email,
            ),
            (
                "legacy-last".to_string(),
                e6ircd::config::OidcAccountClaim::PreferredUsername,
            ),
        ]
    );

    let before: serde_json::Value =
        sqlx::query_scalar("SELECT settings FROM server_settings WHERE singleton")
            .fetch_one(&pool)
            .await
            .expect("migrated settings");
    sqlx::raw_sql(include_str!(
        "../../../migrations/0053_oidc_account_claim_backfill.sql"
    ))
    .execute(&pool)
    .await
    .expect("repeat migration");
    let after: serde_json::Value =
        sqlx::query_scalar("SELECT settings FROM server_settings WHERE singleton")
            .fetch_one(&pool)
            .await
            .expect("repeated settings");
    assert_eq!(after, before, "backfill is idempotent");
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn managed_config_migration_leaves_empty_or_absent_provider_lists_unchanged() {
    let pool = sqlx::PgPool::connect(
        &support::test_db(
            "managed_config_migration_leaves_empty_or_absent_provider_lists_unchanged",
        )
        .await,
    )
    .await
    .expect("connect");
    MIGRATIONS
        .run_to(52, &pool)
        .await
        .expect("migrate through 0052");
    let empty = managed_settings_with_oidc_providers(Some(Vec::new()));
    sqlx::query(
        "INSERT INTO server_settings (singleton, revision, settings, updated_by)
         VALUES (TRUE, 1, $1, 'legacy')",
    )
    .bind(empty)
    .execute(&pool)
    .await
    .expect("empty provider list");
    MIGRATIONS.run(&pool).await.expect("migrate current");
    let empty_after: serde_json::Value =
        sqlx::query_scalar("SELECT settings FROM server_settings WHERE singleton")
            .fetch_one(&pool)
            .await
            .expect("empty settings");
    assert_eq!(empty_after["oidc_providers"], serde_json::json!([]));

    let absent = managed_settings_with_oidc_providers(None);
    sqlx::query("UPDATE server_settings SET settings = $1 WHERE singleton")
        .bind(absent)
        .execute(&pool)
        .await
        .expect("absent provider list");
    sqlx::raw_sql(include_str!(
        "../../../migrations/0053_oidc_account_claim_backfill.sql"
    ))
    .execute(&pool)
    .await
    .expect("repeat migration for absent list");
    let absent_after: serde_json::Value =
        sqlx::query_scalar("SELECT settings FROM server_settings WHERE singleton")
            .fetch_one(&pool)
            .await
            .expect("absent settings");
    assert!(absent_after.get("oidc_providers").is_none());
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

    let applied = db::set_channel_access(&pool, "#c", "alice", Some("ov".into()))
        .await
        .expect("set");
    assert!(applied, "granting a registered account must apply");
    assert_eq!(
        db::list_channel_access(&pool).await.expect("list"),
        vec![("#c".to_string(), "alice".to_string(), "ov".to_string())]
    );

    // Granting to an account that isn't registered writes no row and reports
    // that nothing applied — the caller must not create a hot entry for it.
    let phantom = db::set_channel_access(&pool, "#c", "ghost", Some("o".into()))
        .await
        .expect("phantom grant");
    assert!(!phantom, "granting an unregistered account must not apply");
    assert_eq!(
        db::list_channel_access(&pool).await.expect("list"),
        vec![("#c".to_string(), "alice".to_string(), "ov".to_string())],
        "phantom grant leaked a row"
    );

    let cleared = db::set_channel_access(&pool, "#c", "alice", None)
        .await
        .expect("clear");
    assert!(cleared, "clearing access always applies");
    assert!(
        db::list_channel_access(&pool)
            .await
            .expect("list")
            .is_empty()
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn owned_channel_control_is_scoped_and_complete() {
    use e6ircd::core::{ChannelControlResult, PersistedChannelMutation};

    let pool = db::connect_and_migrate(
        &support::test_db("owned_channel_control_is_scoped_and_complete").await,
    )
    .await
    .expect("connect");
    for account in ["boss", "alice", "mallory"] {
        db::create_account(&pool, account, "pw")
            .await
            .expect("account");
    }
    sqlx::query(
        "INSERT INTO channels (name, name_folded, founder_account_id)
         SELECT '#Control', '#control', id FROM accounts WHERE name_folded = 'boss'",
    )
    .execute(&pool)
    .await
    .expect("channel");

    let topic = PersistedChannelMutation::SetTopic {
        topic: Some(("Welcome".into(), "boss".into(), 123)),
    };
    assert_eq!(
        db::persist_owned_channel_mutation(&pool, "#control", "mallory", &topic)
            .await
            .expect("scope verdict"),
        ChannelControlResult::MissingOrNotOwner
    );
    assert_eq!(
        db::persist_owned_channel_mutation(&pool, "#control", "boss", &topic)
            .await
            .expect("topic"),
        ChannelControlResult::Applied
    );
    for mutation in [
        PersistedChannelMutation::SetMlock {
            mlock: Some("+nt-i".into()),
        },
        PersistedChannelMutation::SetAccess {
            account: "alice".into(),
            flags: Some("ov".into()),
        },
    ] {
        assert_eq!(
            db::persist_owned_channel_mutation(&pool, "#control", "boss", &mutation)
                .await
                .expect("mutation"),
            ChannelControlResult::Applied
        );
    }

    assert!(
        db::list_owned_channels(&pool, "mallory")
            .await
            .expect("mallory inventory")
            .is_empty()
    );
    let channels = db::list_owned_channels(&pool, "BOSS")
        .await
        .expect("owner inventory");
    assert_eq!(channels.len(), 1);
    let channel = &channels[0];
    assert_eq!(channel.name, "#Control");
    assert_eq!(channel.founder, "boss");
    assert!(channel.keeptopic);
    assert_eq!(channel.topic.as_deref(), Some("Welcome"));
    assert_eq!(channel.topic_setter.as_deref(), Some("boss"));
    assert_eq!(channel.topic_set_at_millis, Some(123_000));
    assert_eq!(channel.mlock.as_deref(), Some("+nt-i"));
    assert_eq!(
        channel.access,
        vec![db::ChannelAccessEntry {
            account: "alice".into(),
            flags: "ov".into(),
        }]
    );

    assert_eq!(
        db::persist_owned_channel_mutation(
            &pool,
            "#control",
            "boss",
            &PersistedChannelMutation::SetKeeptopic {
                enabled: false,
                topic: None,
            },
        )
        .await
        .expect("disable retention"),
        ChannelControlResult::Applied
    );
    assert_eq!(
        db::persist_owned_channel_mutation(&pool, "#control", "boss", &topic)
            .await
            .expect("topic while disabled"),
        ChannelControlResult::KeeptopicDisabled
    );
    assert_eq!(
        db::persist_owned_channel_mutation(
            &pool,
            "#control",
            "boss",
            &PersistedChannelMutation::TransferFounder {
                account: "alice".into(),
            },
        )
        .await
        .expect("transfer"),
        ChannelControlResult::Applied
    );
    assert!(
        db::list_owned_channels(&pool, "boss")
            .await
            .expect("old owner")
            .is_empty()
    );
    assert_eq!(
        db::list_owned_channels(&pool, "alice")
            .await
            .expect("new owner")
            .len(),
        1
    );
    let audit = db::list_audit_log(&pool, audit_page_size(20))
        .await
        .expect("audit");
    for action in [
        "CHANNEL_TOPIC",
        "CHANNEL_MLOCK",
        "CHANNEL_ACCESS",
        "CHANNEL_KEEPTOPIC",
        "CHANNEL_FOUNDER",
    ] {
        assert!(
            audit.iter().any(|entry| entry.action == action),
            "missing atomic owner-channel audit action {action}: {audit:#?}"
        );
    }
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
    assert!(
        db::set_channel_founder(&pool, "#c", "alice")
            .await
            .expect("transfer")
    );
    assert_eq!(
        db::list_registered_channels(&pool).await.expect("list"),
        vec![("#c".to_string(), "alice".to_string())]
    );

    // Transfer to a nonexistent account fails and leaves ownership intact.
    assert!(
        !db::set_channel_founder(&pool, "#c", "nobody")
            .await
            .expect("transfer")
    );
    assert_eq!(
        db::list_registered_channels(&pool).await.expect("list"),
        vec![("#c".to_string(), "alice".to_string())]
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn server_ban_worker_mutates_and_audits_atomically() {
    let pool = db::connect_and_migrate(
        &support::test_db("server_ban_worker_mutates_and_audits_atomically").await,
    )
    .await
    .expect("connect");
    let (request_tx, request_rx) = queue::<DbRequest>(QueueConfig {
        name: "server-ban-db",
        capacity: 8,
        policy: Policy::Fifo,
    });
    let (core_tx, mut core_rx) = queue::<Input>(QueueConfig {
        name: "server-ban-core",
        capacity: 8,
        policy: Policy::Fifo,
    });
    tokio::spawn(db::run_worker(
        pool.clone(),
        request_rx,
        CoreIngress::single(core_tx),
    ));
    let conn = e6ircd::core::ConnId(9);
    let add = e6ircd::core::ServerBanMutation::Add {
        mask: "baddie@*".into(),
        mask_display: "Baddie@*".into(),
        reason: "spam".into(),
        set_by: "god".into(),
        kind: "kline".into(),
    };
    let requester = e6ircd::core::ServerBanRequester::Oper {
        session: e6ircd::core::CoreShardCount::single().session_owner(conn),
        label: None,
    };
    request_tx
        .push(DbRequest::MutateServerBan {
            mutation: add.clone(),
            requester: requester.clone(),
        })
        .await
        .expect("push add");
    let Some(envelope) = core_rx.pop().await else {
        panic!("worker died")
    };
    assert!(matches!(
        envelope.payload,
        Input::ServerBanResult {
            mutation,
            requester: got_requester,
            result: e6ircd::core::ServerBanResult::Stored,
        } if mutation == add && got_requester == requester
    ));
    assert_eq!(
        db::list_server_bans(&pool).await.expect("bans"),
        vec![(
            "Baddie@*".to_string(),
            "spam".to_string(),
            "god".to_string(),
            "kline".to_string(),
        )]
    );
    let audit = db::list_audit_log(&pool, audit_page_size(10))
        .await
        .expect("audit");
    assert_eq!(
        (
            &audit[0].actor,
            &audit[0].action,
            &audit[0].target,
            &audit[0].detail
        ),
        (
            &"god".to_string(),
            &"KLINE".to_string(),
            &"Baddie@*".to_string(),
            &"spam".to_string()
        )
    );

    let remove = e6ircd::core::ServerBanMutation::Remove {
        expected_id: None,
        mask: "baddie@*".into(),
        mask_display: "Baddie@*".into(),
        kind: "kline".into(),
        actor: "god".into(),
    };
    request_tx
        .push(DbRequest::MutateServerBan {
            mutation: remove,
            requester,
        })
        .await
        .expect("push remove");
    let Some(envelope) = core_rx.pop().await else {
        panic!("worker died")
    };
    assert!(matches!(
        envelope.payload,
        Input::ServerBanResult {
            result: e6ircd::core::ServerBanResult::Stored,
            ..
        }
    ));
    assert!(db::list_server_bans(&pool).await.expect("bans").is_empty());
    let audit = db::list_audit_log(&pool, audit_page_size(10))
        .await
        .expect("audit");
    assert_eq!(audit[0].action, "UNKLINE");
    assert_eq!(audit[0].target, "Baddie@*");
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn server_bans_persist_and_load() {
    let pool = db::connect_and_migrate(&support::test_db("server_bans_persist_and_load").await)
        .await
        .expect("connect");

    let invalid =
        sqlx::query("INSERT INTO server_bans (mask, reason, set_by, kind) VALUES ($1, $2, $3, $4)")
            .bind("invalid@*")
            .bind("invalid")
            .bind("test")
            .bind("unknown")
            .execute(&pool)
            .await;
    assert!(invalid.is_err(), "server-ban kind must be constrained");

    db::add_server_ban(&pool, "baddie@*", "baddie@*", "spam", "god", "kline")
        .await
        .expect("add1");
    db::add_server_ban(
        &pool,
        "203.0.113.0",
        "203.0.113.0",
        "netblock",
        "god",
        "dline",
    )
    .await
    .expect("add2");
    // Same textual mask as the K-line but a different kind coexists.
    db::add_server_ban(&pool, "baddie@*", "baddie@*", "gecos", "god", "xline")
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
    db::add_server_ban(&pool, "baddie@*", "baddie@*", "spam again", "root", "kline")
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
    let list = db::list_audit_log(&pool, audit_page_size(10))
        .await
        .expect("list");
    // newest-first
    assert_eq!(list.len(), 2);
    assert_eq!(
        (&list[0].action, &list[0].target),
        (&"KLINE".to_string(), &"baddie@*".to_string())
    );
    assert_eq!(&list[1].action, &"OPER".to_string());
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn account_directory_posture_filters_and_cursor_pages_are_stable() {
    let pool = db::connect_and_migrate(
        &support::test_db("account_directory_posture_filters_and_cursor_pages_are_stable").await,
    )
    .await
    .expect("connect");
    for name in ["Alice", "Bob", "Carol"] {
        db::create_account(&pool, name, "pw")
            .await
            .unwrap_or_else(|error| panic!("create {name}: {error}"));
    }
    db::issue_app_password_for_account(&pool, "Alice", "desktop")
        .await
        .expect("app password");
    db::issue_api_token(&pool, "Alice", "active")
        .await
        .expect("API token");
    db::create_web_session(&pool, "Alice", None)
        .await
        .expect("browser session");
    assert_eq!(
        db::link_oidc_identity(&pool, "Alice", "https://issuer.example", "alice-subject")
            .await
            .expect("OIDC link"),
        db::LinkOutcome::Linked
    );
    sqlx::query(
        "WITH account AS (
             SELECT id FROM accounts WHERE name_folded = 'alice'
         ), expired_token AS (
             INSERT INTO api_tokens (
                 token_hash, account_id, label, created_at, expires_at
             )
             SELECT decode(repeat('ab', 32), 'hex'), id, 'expired',
                    now() - interval '2 hours', now() - interval '1 hour'
             FROM account
         ), expired_session AS (
             INSERT INTO web_sessions (token_hash, account_id, expires_at)
             SELECT decode(repeat('cd', 32), 'hex'), id,
                    now() - interval '1 hour' FROM account
         ), network AS (
             INSERT INTO bnc_networks (account_id, name, addr, nick, kind)
             SELECT id, 'local', '', 'Alice', 'irc' FROM account
         )
         INSERT INTO channels (name, name_folded, founder_account_id)
         SELECT '#alice', '#alice', id FROM account",
    )
    .execute(&pool)
    .await
    .expect("posture fixtures");

    let first = db::query_account_directory(
        &pool,
        db::AccountDirectoryFilter {
            before_id: None,
            exact_name: None,
            page_size: account_page_size(2),
        },
    )
    .await
    .expect("first page");
    assert_eq!(
        first
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        ["Carol", "Bob"]
    );
    let cursor = first.next_before_id.expect("older page cursor");
    assert_eq!(cursor, first.entries[1].id);

    db::create_account(&pool, "Dave", "pw")
        .await
        .expect("concurrent account");
    let second = db::query_account_directory(
        &pool,
        db::AccountDirectoryFilter {
            before_id: Some(cursor),
            exact_name: None,
            page_size: account_page_size(2),
        },
    )
    .await
    .expect("second page");
    assert_eq!(second.entries.len(), 1);
    assert_eq!(second.entries[0].name, "Alice");
    assert!(
        second.entries.iter().all(|entry| entry.id < cursor),
        "cursor admitted a newer or duplicate row: {second:#?}"
    );

    let exact = db::query_account_directory(
        &pool,
        db::AccountDirectoryFilter {
            before_id: None,
            exact_name: Some("aLiCe"),
            page_size: account_page_size(10),
        },
    )
    .await
    .expect("exact account");
    assert_eq!(exact.entries.len(), 1);
    let alice = &exact.entries[0];
    assert!(alice.has_local_password);
    assert_eq!(alice.app_passwords, 1);
    assert_eq!(alice.api_tokens, 1, "expired token must not count");
    assert_eq!(alice.oidc_identities, 1);
    assert_eq!(
        alice.browser_sessions, 1,
        "expired browser session must not count"
    );
    assert_eq!(alice.networks, 1);
    assert_eq!(alice.founded_channels, 1);
    assert_eq!(exact.next_before_id, None);
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn policy_directories_filter_posture_and_cursor_pages_are_stable() {
    let pool = db::connect_and_migrate(
        &support::test_db("policy_directories_filter_posture_and_cursor_pages_are_stable").await,
    )
    .await
    .expect("connect");
    for name in ["Alice", "Bob"] {
        db::create_account(&pool, name, "pw")
            .await
            .unwrap_or_else(|error| panic!("create {name}: {error}"));
    }
    for (channel, founder) in [
        ("#Alpha", "alice"),
        ("#Bravo", "bob"),
        ("#Charlie", "alice"),
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
    .expect("channel retained policy");
    sqlx::query(
        "INSERT INTO channel_access (channel_id, account_id, flags)
         SELECT c.id, a.id, 'ov'
         FROM channels c, accounts a
         WHERE c.name_folded = '#alpha' AND a.name_folded = 'bob'",
    )
    .execute(&pool)
    .await
    .expect("channel posture");

    let first_channels = db::query_registered_channel_directory(
        &pool,
        db::RegisteredChannelDirectoryFilter {
            before_id: None,
            exact_name: None,
            exact_founder: None,
            page_size: registered_channel_page_size(2),
        },
    )
    .await
    .expect("first channel page");
    assert_eq!(
        first_channels
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        ["#Charlie", "#Bravo"]
    );
    let channel_cursor = first_channels.next_before_id.expect("older channel cursor");
    sqlx::query(
        "INSERT INTO channels (name, name_folded, founder_account_id)
         SELECT '#Delta', '#delta', id FROM accounts WHERE name_folded = 'alice'",
    )
    .execute(&pool)
    .await
    .expect("concurrent channel");
    let older_channels = db::query_registered_channel_directory(
        &pool,
        db::RegisteredChannelDirectoryFilter {
            before_id: Some(channel_cursor),
            exact_name: None,
            exact_founder: None,
            page_size: registered_channel_page_size(2),
        },
    )
    .await
    .expect("older channel page");
    assert_eq!(older_channels.entries.len(), 1);
    assert_eq!(older_channels.entries[0].name, "#Alpha");
    assert!(
        older_channels
            .entries
            .iter()
            .all(|entry| entry.id < channel_cursor),
        "channel cursor admitted a newer or duplicate row: {older_channels:#?}"
    );
    let exact_channel = db::query_registered_channel_directory(
        &pool,
        db::RegisteredChannelDirectoryFilter {
            before_id: None,
            exact_name: Some("#aLPHa"),
            exact_founder: Some("aLiCe"),
            page_size: registered_channel_page_size(10),
        },
    )
    .await
    .expect("exact channel");
    assert_eq!(exact_channel.entries.len(), 1);
    let alpha = &exact_channel.entries[0];
    assert_eq!(alpha.founder, "Alice");
    assert!(!alpha.keeptopic);
    assert!(alpha.topic_retained);
    assert_eq!(alpha.mlock.as_deref(), Some("+nt"));
    assert_eq!(alpha.access_entries, 1);

    for (mask, display, reason, setter, kind) in [
        ("bad@host", "Bad@Host", "spam", "Alice", "kline"),
        ("192.0.2.*", "192.0.2.*", "proxy", "Bob", "dline"),
        ("*bot*", "*Bot*", "automation", "Alice", "xline"),
    ] {
        db::add_server_ban(&pool, mask, display, reason, setter, kind)
            .await
            .unwrap_or_else(|error| panic!("add {kind} {display}: {error}"));
    }
    let first_bans = db::query_server_ban_directory(
        &pool,
        db::ServerBanDirectoryFilter {
            before_id: None,
            exact_kind: None,
            exact_mask: None,
            page_size: server_ban_page_size(2),
        },
    )
    .await
    .expect("first ban page");
    assert_eq!(
        first_bans
            .entries
            .iter()
            .map(|entry| entry.kind.as_str())
            .collect::<Vec<_>>(),
        ["xline", "dline"]
    );
    let ban_cursor = first_bans.next_before_id.expect("older ban cursor");
    db::add_server_ban(
        &pool,
        "new@host",
        "New@Host",
        "concurrent",
        "Alice",
        "kline",
    )
    .await
    .expect("concurrent ban");
    let older_bans = db::query_server_ban_directory(
        &pool,
        db::ServerBanDirectoryFilter {
            before_id: Some(ban_cursor),
            exact_kind: None,
            exact_mask: None,
            page_size: server_ban_page_size(2),
        },
    )
    .await
    .expect("older ban page");
    assert_eq!(older_bans.entries.len(), 1);
    assert_eq!(older_bans.entries[0].mask, "Bad@Host");
    assert!(
        older_bans.entries.iter().all(|entry| entry.id < ban_cursor),
        "server-ban cursor admitted a newer or duplicate row: {older_bans:#?}"
    );
    let exact_ban = db::query_server_ban_directory(
        &pool,
        db::ServerBanDirectoryFilter {
            before_id: None,
            exact_kind: Some("kline"),
            exact_mask: Some("BAD@HOST"),
            page_size: server_ban_page_size(10),
        },
    )
    .await
    .expect("exact ban");
    assert_eq!(exact_ban.entries.len(), 1);
    assert_eq!(exact_ban.entries[0].mask, "Bad@Host");
    assert_eq!(exact_ban.entries[0].reason, "spam");
    assert_eq!(exact_ban.entries[0].set_by, "Alice");
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn audit_log_filters_and_cursor_pages_are_stable() {
    let pool = db::connect_and_migrate(
        &support::test_db("audit_log_filters_and_cursor_pages_are_stable").await,
    )
    .await
    .expect("connect");
    for (actor, action, target, detail) in [
        ("alice", "OPER", "alice", ""),
        ("bob", "KLINE", "first@host", "spam"),
        ("alice", "KLINE", "second@host", "abuse"),
        ("alice", "CONFIG", "server", "revision 2"),
    ] {
        db::insert_audit_log(&pool, actor, action, target, detail)
            .await
            .expect("seed audit entry");
    }

    let first = db::query_audit_log(
        &pool,
        db::AuditLogFilter {
            before_id: None,
            actor: None,
            action: None,
            target: None,
            page_size: audit_page_size(2),
        },
    )
    .await
    .expect("first page");
    assert_eq!(first.entries.len(), 2);
    let cursor = first.next_before_id.expect("older page cursor");
    assert_eq!(cursor, first.entries[1].id);

    db::insert_audit_log(&pool, "bob", "OPER", "bob", "concurrent")
        .await
        .expect("concurrent append");
    let second = db::query_audit_log(
        &pool,
        db::AuditLogFilter {
            before_id: Some(cursor),
            actor: None,
            action: None,
            target: None,
            page_size: audit_page_size(2),
        },
    )
    .await
    .expect("second page");
    assert!(
        second.entries.iter().all(|entry| entry.id < cursor),
        "cursor page admitted a newer or duplicate row: {second:#?}"
    );
    assert!(
        first
            .entries
            .iter()
            .all(|first| second.entries.iter().all(|second| first.id != second.id)),
        "cursor pages overlapped"
    );

    let filtered = db::query_audit_log(
        &pool,
        db::AuditLogFilter {
            before_id: None,
            actor: Some("alice"),
            action: Some("KLINE"),
            target: Some("second@host"),
            page_size: audit_page_size(10),
        },
    )
    .await
    .expect("filtered page");
    assert_eq!(filtered.entries.len(), 1);
    assert_eq!(filtered.entries[0].detail, "abuse");
    assert_eq!(filtered.next_before_id, None);
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn managed_configuration_rejects_stale_writes_without_auditing_them() {
    let pool = db::connect_and_migrate(
        &support::test_db("managed_configuration_rejects_stale_writes_without_auditing_them").await,
    )
    .await
    .expect("connect");
    let bootstrap =
        e6ircd::config::ManagedConfig::from_config(&Config::default(), None).expect("bootstrap");
    let initial = db::load_or_initialize_managed_config(&pool, &bootstrap)
        .await
        .expect("initialize");
    let mut changed = initial.settings.clone();
    changed.description = "saved revision".into();

    let saved = db::save_managed_config(&pool, initial.revision, &changed, "alice", "first update")
        .await
        .expect("save current revision");
    let stale = db::save_managed_config(
        &pool,
        initial.revision,
        &initial.settings,
        "bob",
        "stale update",
    )
    .await;

    assert!(
        matches!(stale, Err(db::DbError::StaleServerSettings)),
        "{stale:?}"
    );
    let loaded = db::load_managed_config(&pool).await.expect("reload");
    assert_eq!(loaded.revision, saved.revision);
    assert_eq!(loaded.settings, changed);
    assert_eq!(loaded.updated_by, "alice");
    let audit = db::list_audit_log(&pool, audit_page_size(10))
        .await
        .expect("audit");
    assert_eq!(
        audit.len(),
        1,
        "the failed compare-and-swap must not leave an audit record"
    );
    assert_eq!(
        (
            &audit[0].actor,
            &audit[0].action,
            &audit[0].target,
            &audit[0].detail
        ),
        (
            &"alice".to_string(),
            &"CONFIG".to_string(),
            &"server".to_string(),
            &"first update".to_string(),
        )
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn secret_rotation_reseals_every_database_secret_atomically() {
    use e6ircd::config::{NetworkEntry, NetworkKind, OidcProviderConfig, OperConfig};
    use e6ircd::secret::{CONFIG_CONTEXT, SecretKey, SecretKeyring};

    let pool = db::connect_and_migrate(
        &support::test_db("secret_rotation_reseals_every_database_secret_atomically").await,
    )
    .await
    .expect("connect");
    db::create_account(&pool, "alice", "pw")
        .await
        .expect("account");

    let old = SecretKey::generate();
    let old_base64 = old.to_base64();
    let old_verifier = SecretKey::from_base64(&old_base64).unwrap();
    let mut managed = e6ircd::config::ManagedConfig::from_config(&Config::default(), None).unwrap();
    managed.opers.push(OperConfig {
        name: "root".into(),
        password: old.seal("oper-password", CONFIG_CONTEXT),
    });
    managed.oidc_providers.push(OidcProviderConfig {
        name: "corp".into(),
        issuer_url: "https://issuer.example".into(),
        client_id: "e6irc".into(),
        client_secret: old.seal("oidc-secret", CONFIG_CONTEXT),
        account_claim: e6ircd::config::OidcAccountClaim::PreferredUsername,
        scopes: vec!["openid".into()],
        allowed_email_domains: Vec::new(),
        end_session_endpoint: None,
        token_endpoint_auth_method: e6ircd::config::TokenEndpointAuthMethod::ClientSecretBasic,
    });
    managed.networks.push(NetworkEntry {
        name: "workspace".into(),
        kind: NetworkKind::Slack,
        owner: None,
        addr: "https://slack.com/api".into(),
        tls: true,
        nick: String::new(),
        realname: None,
        autojoin: vec!["C123".into()],
        buffer_cap: 100,
        sasl_account: Some(old.seal("xoxb-old", CONFIG_CONTEXT)),
        sasl_password: Some(old.seal("xapp-old", CONFIG_CONTEXT)),
    });
    db::load_or_initialize_managed_config(&pool, &managed)
        .await
        .expect("managed settings");

    let owner_context = e6ircd::bouncer::bnc_secret_context("alice");
    let account_network = db::BncNetworkRow {
        kind: NetworkKind::Slack,
        name: "team".into(),
        addr: "https://slack.com/api".into(),
        tls: true,
        nick: String::new(),
        realname: None,
        autojoin: vec!["C456".into()],
        sasl_account: Some(old.seal("xoxb-account", &owner_context)),
        sasl_password_sealed: Some(old.seal("xapp-account", &owner_context)),
        enabled: false,
    };
    db::create_bnc_network(&pool, "alice", &account_network)
        .await
        .expect("account network");

    let new = SecretKey::generate();
    let new_base64 = new.to_base64();
    let keys = SecretKeyring::new(new, vec![old]).unwrap();
    let report = db::rotate_database_secrets(&pool, &keys, "operator")
        .await
        .expect("rotate");
    assert_eq!(
        report,
        db::SecretRotationReport {
            managed_config_secrets: 4,
            account_network_secrets: 2,
        }
    );

    let new_verifier = SecretKey::from_base64(&new_base64).unwrap();
    let rotated = db::load_managed_config(&pool).await.expect("settings");
    assert_eq!(rotated.updated_by, "operator");
    assert_eq!(
        new_verifier
            .open(&rotated.settings.opers[0].password, CONFIG_CONTEXT)
            .unwrap(),
        "oper-password"
    );
    assert!(
        old_verifier
            .open(&rotated.settings.opers[0].password, CONFIG_CONTEXT)
            .is_err(),
        "old key still opened a rotated managed secret"
    );
    let rotated_network = db::get_bnc_network(&pool, "alice", "team")
        .await
        .expect("network query")
        .expect("network");
    assert_eq!(
        new_verifier
            .open(
                rotated_network.sasl_password_sealed.as_deref().unwrap(),
                &owner_context,
            )
            .unwrap(),
        "xapp-account"
    );
    assert!(
        old_verifier
            .open(
                rotated_network.sasl_password_sealed.as_deref().unwrap(),
                &owner_context,
            )
            .is_err(),
        "old key still opened a rotated account-network secret"
    );
    let audit = db::list_audit_log(&pool, audit_page_size(10))
        .await
        .expect("audit");
    assert_eq!(audit[0].action, "SECRET_ROTATE");
    assert!(!audit[0].detail.contains("xox"), "{:?}", audit[0].detail);
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn unreadable_secret_rolls_back_the_entire_rotation() {
    use e6ircd::config::{NetworkKind, OperConfig};
    use e6ircd::secret::{CONFIG_CONTEXT, SecretKey, SecretKeyring};

    let pool = db::connect_and_migrate(
        &support::test_db("unreadable_secret_rolls_back_the_entire_rotation").await,
    )
    .await
    .expect("connect");
    db::create_account(&pool, "alice", "pw")
        .await
        .expect("account");
    let old = SecretKey::generate();
    let mut managed = e6ircd::config::ManagedConfig::from_config(&Config::default(), None).unwrap();
    managed.opers.push(OperConfig {
        name: "root".into(),
        password: old.seal("still-old", CONFIG_CONTEXT),
    });
    let initial = db::load_or_initialize_managed_config(&pool, &managed)
        .await
        .expect("settings");
    db::create_bnc_network(
        &pool,
        "alice",
        &db::BncNetworkRow {
            kind: NetworkKind::Irc,
            name: "broken".into(),
            addr: "irc.example:6697".into(),
            tls: true,
            nick: "alice".into(),
            realname: Some("Alice".into()),
            autojoin: Vec::new(),
            sasl_account: Some("alice".into()),
            sasl_password_sealed: Some("enc:v2:not-base64".into()),
            enabled: false,
        },
    )
    .await
    .expect("broken row");

    let keys = SecretKeyring::new(SecretKey::generate(), vec![old]).unwrap();
    let error = db::rotate_database_secrets(&pool, &keys, "operator")
        .await
        .expect_err("corrupt row must abort rotation");
    assert!(error.to_string().contains("cannot be decrypted"), "{error}");

    let after = db::load_managed_config(&pool).await.expect("settings");
    assert_eq!(after.revision, initial.revision);
    assert_eq!(
        after.settings.opers[0].password, initial.settings.opers[0].password,
        "the earlier settings update escaped the failed transaction"
    );
    assert!(
        db::list_audit_log(&pool, audit_page_size(10))
            .await
            .expect("audit")
            .is_empty(),
        "a rolled-back rotation left an audit success"
    );
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
    let identities = db::list_oidc_identities(&pool, "alice")
        .await
        .expect("list");
    assert_eq!(identities.len(), 2);
    assert_eq!(identities[0].issuer, "https://idp.example");
    assert_eq!(identities[0].subject, "sub-0");
    assert!(identities[0].created_at.ends_with('Z'), "{identities:?}");
    assert_eq!(identities[1].issuer, "https://idp.example");
    assert_eq!(identities[1].subject, "sub-1");
    assert!(identities[1].created_at.ends_with('Z'), "{identities:?}");
    // bob got nothing.
    assert!(
        db::list_oidc_identities(&pool, "bob")
            .await
            .expect("list")
            .is_empty()
    );

    // Removing an identity also revokes only the sessions asserted by that
    // identity. A local session and the other identity's session survive.
    let removed_session = db::create_web_session_with_identity(
        &pool,
        "alice",
        db::OidcSessionIdentity {
            issuer: Some("https://idp.example"),
            subject: Some("sub-0"),
            ..Default::default()
        },
        None,
    )
    .await
    .expect("removed identity session");
    let retained_session = db::create_web_session_with_identity(
        &pool,
        "alice",
        db::OidcSessionIdentity {
            issuer: Some("https://idp.example"),
            subject: Some("sub-1"),
            ..Default::default()
        },
        None,
    )
    .await
    .expect("retained identity session");
    let local_session = db::create_web_session(&pool, "alice", None)
        .await
        .expect("local session");
    assert_eq!(
        db::unlink_oidc_identity(&pool, "alice", identities[0].id)
            .await
            .expect("unlink"),
        db::UnlinkIdentityOutcome::Unlinked
    );
    assert_eq!(
        db::session_account(&pool, &removed_session)
            .await
            .expect("removed session"),
        None
    );
    for session in [&retained_session, &local_session] {
        assert_eq!(
            db::session_account(&pool, session)
                .await
                .expect("retained session"),
            Some("alice".to_string())
        );
    }
    assert_eq!(
        db::unlink_oidc_identity(&pool, "alice", identities[1].id)
            .await
            .expect("last identity"),
        db::UnlinkIdentityOutcome::Unlinked,
        "the local password remains a login method"
    );
    assert_eq!(
        db::session_account(&pool, &retained_session)
            .await
            .expect("final identity session"),
        None
    );
    assert_eq!(
        db::unlink_oidc_identity(&pool, "alice", i64::MAX)
            .await
            .expect("missing identity"),
        db::UnlinkIdentityOutcome::NotFound
    );

    // For an OIDC-only account, the account-row lock makes the last-login-method
    // rule hold under concurrent requests: exactly one of two removals succeeds.
    let oidc_only =
        db::find_or_create_oidc_account(&pool, "https://idp.example", "oidc-only-0", "oidc-only")
            .await
            .expect("OIDC-only account");
    db::link_oidc_identity(&pool, &oidc_only, "https://idp.example", "oidc-only-1")
        .await
        .expect("second OIDC-only identity");
    let oidc_identities = db::list_oidc_identities(&pool, &oidc_only)
        .await
        .expect("OIDC-only identities");
    let (first, second) = tokio::join!(
        db::unlink_oidc_identity(&pool, &oidc_only, oidc_identities[0].id),
        db::unlink_oidc_identity(&pool, &oidc_only, oidc_identities[1].id),
    );
    let outcomes = [first.expect("first unlink"), second.expect("second unlink")];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == db::UnlinkIdentityOutcome::Unlinked)
            .count(),
        1,
        "{outcomes:?}"
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == db::UnlinkIdentityOutcome::LastLoginMethod)
            .count(),
        1,
        "{outcomes:?}"
    );
    assert_eq!(
        db::list_oidc_identities(&pool, &oidc_only)
            .await
            .expect("bob remaining")
            .len(),
        1
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
    let plain = db::create_web_session(&pool, "alice", None)
        .await
        .expect("plain");
    assert_eq!(
        db::session_logout_hint(&pool, &plain).await.expect("hint"),
        db::SessionLogoutHint {
            id_token: None,
            provider: None,
        }
    );

    // An OIDC session records the id token + provider for RP-initiated logout.
    let sso = db::create_web_session_with_identity(
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
        None,
    )
    .await
    .expect("sso");
    assert_eq!(
        db::session_logout_hint(&pool, &sso).await.expect("hint"),
        db::SessionLogoutHint {
            id_token: Some("the.id.token".to_string()),
            provider: Some("shauth".to_string()),
        }
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
    let first = db::create_web_session_with_identity(
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
        None,
    )
    .await
    .expect("first session");
    let second = db::create_web_session_with_identity(
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
        None,
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

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn web_session_inventory_and_revocation_are_owner_scoped() {
    let pool = db::connect_and_migrate(
        &support::test_db("web_session_inventory_and_revocation_are_owner_scoped").await,
    )
    .await
    .expect("connect");
    db::create_account(&pool, "alice", "pw")
        .await
        .expect("alice");
    db::create_account(&pool, "bob", "pw").await.expect("bob");

    let desktop_agent = db::SessionUserAgent::from_header(" Desktop\tBrowser ")
        .expect("normalized desktop user agent");
    let first = db::create_web_session(&pool, "alice", Some(&desktop_agent))
        .await
        .expect("first session");
    let second = db::create_web_session(&pool, "alice", None)
        .await
        .expect("second session");
    let bob = db::create_web_session(&pool, "bob", None)
        .await
        .expect("bob session");

    let sessions = db::list_web_sessions(&pool, "alice", Some(&second))
        .await
        .expect("list alice sessions");
    assert_eq!(sessions.len(), 2);
    assert!(sessions[0].current, "current session sorts first");
    assert_eq!(sessions[0].user_agent, None);
    assert!(!sessions[1].current);
    assert_eq!(sessions[1].user_agent.as_deref(), Some("Desktop�Browser"));

    let bob_id = db::list_web_sessions(&pool, "bob", Some(&bob))
        .await
        .expect("list bob sessions")[0]
        .id;
    assert_eq!(
        db::delete_web_session_by_id(&pool, "alice", bob_id, Some(&second))
            .await
            .expect("cross-account delete"),
        None,
        "an owner-scoped delete cannot revoke another account's session"
    );

    let first_id = sessions[1].id;
    assert_eq!(
        db::delete_web_session_by_id(&pool, "alice", first_id, Some(&second))
            .await
            .expect("delete first"),
        Some(false)
    );
    assert_eq!(
        db::session_account(&pool, &first)
            .await
            .expect("resolve deleted session"),
        None
    );
    assert_eq!(
        db::delete_other_web_sessions(&pool, "alice", &second)
            .await
            .expect("delete others"),
        0
    );
    assert_eq!(
        db::session_account(&pool, &second)
            .await
            .expect("current session survives"),
        Some("alice".into())
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn concurrent_browser_session_issuance_enforces_the_active_cap() {
    let pool = db::connect_and_migrate(
        &support::test_db("concurrent_browser_session_issuance_enforces_the_active_cap").await,
    )
    .await
    .expect("connect");
    db::create_account(&pool, "alice", "pw")
        .await
        .expect("alice");

    let mut issuers = tokio::task::JoinSet::new();
    for _ in 0..(db::MAX_BROWSER_SESSIONS_PER_ACCOUNT + 8) {
        let pool = pool.clone();
        issuers.spawn(async move {
            db::create_web_session(&pool, "alice", None)
                .await
                .expect("concurrent session issuance")
        });
    }
    let mut tokens = Vec::new();
    while let Some(result) = issuers.join_next().await {
        tokens.push(result.expect("issuer task"));
    }

    let sessions = db::list_web_sessions(&pool, "alice", None)
        .await
        .expect("bounded inventory");
    assert_eq!(
        sessions.len(),
        db::MAX_BROWSER_SESSIONS_PER_ACCOUNT,
        "the owner inventory is bounded at the issuance invariant"
    );
    let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM web_sessions s
         JOIN accounts a ON a.id = s.account_id
         WHERE a.name_folded = 'alice' AND s.expires_at > now()",
    )
    .fetch_one(&pool)
    .await
    .expect("active session count");
    assert_eq!(
        active as usize,
        db::MAX_BROWSER_SESSIONS_PER_ACCOUNT,
        "serialized issuance must keep storage itself at the cap"
    );

    let mut retained = 0;
    for token in tokens {
        if db::session_account(&pool, &token)
            .await
            .expect("token lookup")
            .is_some()
        {
            retained += 1;
        }
    }
    assert_eq!(retained, db::MAX_BROWSER_SESSIONS_PER_ACCOUNT);
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn every_pooled_connection_has_statement_and_lock_deadlines() {
    let pool = db::connect_and_migrate(
        &support::test_db("every_pooled_connection_has_statement_and_lock_deadlines").await,
    )
    .await
    .expect("connect");

    let statement_timeout: String = sqlx::query_scalar("SHOW statement_timeout")
        .fetch_one(&pool)
        .await
        .expect("statement timeout");
    let lock_timeout: String = sqlx::query_scalar("SHOW lock_timeout")
        .fetch_one(&pool)
        .await
        .expect("lock timeout");
    assert_eq!(statement_timeout, "15s");
    assert_eq!(lock_timeout, "5s");
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn first_admin_bootstrap_is_atomic_audited_and_one_time() {
    let pool = db::connect_and_migrate(
        &support::test_db("first_admin_bootstrap_is_atomic_audited_and_one_time").await,
    )
    .await
    .expect("connect");
    assert!(!db::has_accounts(&pool).await.expect("empty account store"));

    db::bootstrap_first_admin(&pool, "Alice", "correct horse battery staple")
        .await
        .expect("first administrator");
    assert!(db::has_accounts(&pool).await.expect("initialized store"));
    let flags = db::account_flags(&pool, "alice")
        .await
        .expect("flags query")
        .expect("account flags");
    assert!(flags.is_admin());
    assert!(!flags.is_suspended());
    assert!(matches!(
        db::bootstrap_first_admin(&pool, "Mallory", "another strong password").await,
        Err(db::DbError::AlreadyInitialized)
    ));
    let account_count: i64 = sqlx::query_scalar("SELECT count(*) FROM accounts")
        .fetch_one(&pool)
        .await
        .expect("account count");
    assert_eq!(account_count, 1);
    let audit_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = 'ACCOUNT_BOOTSTRAP'")
            .fetch_one(&pool)
            .await
            .expect("audit count");
    assert_eq!(audit_count, 1);
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn concurrent_first_admin_bootstraps_have_exactly_one_winner() {
    let pool = db::connect_and_migrate(
        &support::test_db("concurrent_first_admin_bootstraps_have_exactly_one_winner").await,
    )
    .await
    .expect("connect");
    let alice_pool = pool.clone();
    let bob_pool = pool.clone();
    let (alice, bob) = tokio::join!(
        async move {
            db::bootstrap_first_admin(&alice_pool, "Alice", "alice administrator password").await
        },
        async move { db::bootstrap_first_admin(&bob_pool, "Bob", "bob administrator password").await }
    );
    let outcomes = [alice, bob];
    assert_eq!(
        outcomes.iter().filter(|result| result.is_ok()).count(),
        1,
        "{outcomes:?}"
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(db::DbError::AlreadyInitialized)))
            .count(),
        1,
        "{outcomes:?}"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM accounts")
            .fetch_one(&pool)
            .await
            .expect("account count"),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM accounts WHERE (flags & 1) = 1")
            .fetch_one(&pool)
            .await
            .expect("administrator count"),
        1
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn suspension_revokes_every_bearer_and_blocks_new_credential_issuance() {
    let pool = db::connect_and_migrate(
        &support::test_db("suspension_revokes_every_bearer_and_blocks_new_credential_issuance")
            .await,
    )
    .await
    .expect("connect");
    db::bootstrap_first_admin(&pool, "Alice", "correct horse battery staple")
        .await
        .expect("administrator");
    let bob_id = db::create_account(&pool, "Bob", "bob password")
        .await
        .expect("Bob");
    let session = db::create_web_session(&pool, "Bob", None)
        .await
        .expect("browser session");
    let token = db::issue_api_token(&pool, "Bob", "automation")
        .await
        .expect("personal access token");
    let (device_code, user_code) = db::create_device_grant(&pool).await.expect("device grant");
    assert!(
        db::approve_device_grant(&pool, &user_code, "Bob")
            .await
            .expect("approve device")
    );

    let change = db::set_account_suspended(&pool, bob_id, true, "Alice", &[])
        .await
        .expect("suspend")
        .expect("Bob exists");
    assert_eq!(change.name, "Bob");
    assert!(change.suspended);
    assert!(
        db::account_flags(&pool, "bob")
            .await
            .expect("flags")
            .expect("Bob")
            .is_suspended()
    );
    assert_eq!(
        db::list_suspended_accounts(&pool)
            .await
            .expect("suspended accounts"),
        vec!["bob"]
    );
    assert_eq!(
        db::verify_credentials(&pool, "Bob", "bob password")
            .await
            .expect("credential query"),
        None
    );
    assert_eq!(
        db::verify_local_password(&pool, "Bob", "bob password")
            .await
            .expect("local credential query"),
        None
    );
    assert_eq!(
        db::session_account(&pool, &session)
            .await
            .expect("session lookup"),
        None
    );
    assert_eq!(
        db::api_token_account(&pool, &token)
            .await
            .expect("token lookup"),
        None
    );
    assert!(matches!(
        db::poll_device_grant(&pool, &device_code, "device")
            .await
            .expect("device lookup"),
        db::DeviceStatus::Unknown
    ));
    assert!(matches!(
        db::create_web_session(&pool, "Bob", None).await,
        Err(db::DbError::BadCredentials)
    ));
    assert!(matches!(
        db::issue_api_token(&pool, "Bob", "forbidden").await,
        Err(db::DbError::BadCredentials)
    ));

    db::set_account_suspended(&pool, bob_id, false, "Alice", &[])
        .await
        .expect("reactivate")
        .expect("Bob exists");
    assert_eq!(
        db::verify_credentials(&pool, "Bob", "bob password")
            .await
            .expect("credential query"),
        Some("Bob".into()),
        "reactivation restores durable credentials but not revoked bearers"
    );
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_log
         WHERE target = 'bob' AND action IN ('ACCOUNT_SUSPEND', 'ACCOUNT_REACTIVATE')
         ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("lifecycle audit");
    assert_eq!(actions, ["ACCOUNT_SUSPEND", "ACCOUNT_REACTIVATE"]);
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn suspension_preserves_an_active_administrator_and_rejects_self_targeting() {
    let pool = db::connect_and_migrate(
        &support::test_db(
            "suspension_preserves_an_active_administrator_and_rejects_self_targeting",
        )
        .await,
    )
    .await
    .expect("connect");
    let alice_id = db::bootstrap_first_admin(&pool, "Alice", "administrator password")
        .await
        .expect("Alice");
    let bob_id = db::create_account(&pool, "Bob", "second administrator password")
        .await
        .expect("Bob");
    let carol_id = db::create_account(&pool, "Carol", "configured administrator password")
        .await
        .expect("Carol");
    assert!(matches!(
        db::set_account_administrator(&pool, alice_id, false, "Alice", &[]).await,
        Err(db::DbError::CannotDemoteSelf)
    ));
    db::set_account_administrator(&pool, bob_id, true, "Alice", &[])
        .await
        .expect("grant Bob")
        .expect("Bob");
    assert_eq!(
        db::list_admin_accounts(&pool)
            .await
            .expect("administrators"),
        ["alice", "bob"]
    );

    assert!(matches!(
        db::set_account_suspended(&pool, alice_id, true, "ALICE", &[]).await,
        Err(db::DbError::CannotSuspendSelf)
    ));
    db::set_account_suspended(&pool, alice_id, true, "Bob", &[])
        .await
        .expect("Bob suspends Alice")
        .expect("Alice");
    assert!(matches!(
        db::set_account_suspended(&pool, bob_id, true, "Alice", &[]).await,
        Err(db::DbError::LastAdministrator)
    ));
    assert!(matches!(
        db::set_account_administrator(&pool, bob_id, false, "Alice", &[]).await,
        Err(db::DbError::LastAdministrator)
    ));
    db::set_account_suspended(&pool, alice_id, false, "Bob", &[])
        .await
        .expect("reactivate Alice")
        .expect("Alice");
    db::set_account_suspended(&pool, bob_id, true, "Alice", &[])
        .await
        .expect("Alice can now suspend Bob")
        .expect("Bob");
    db::set_account_administrator(&pool, bob_id, false, "Alice", &[])
        .await
        .expect("Alice can revoke Bob")
        .expect("Bob");
    assert_eq!(
        db::list_admin_accounts(&pool)
            .await
            .expect("administrators"),
        ["alice"]
    );
    let configured = ["carol".to_string()];
    db::set_account_suspended(&pool, alice_id, true, "Bob", &configured)
        .await
        .expect("configured Carol preserves effective authority")
        .expect("Alice");
    db::set_account_administrator(&pool, alice_id, false, "Bob", &configured)
        .await
        .expect("configured Carol permits durable succession")
        .expect("Alice");
    assert!(
        db::list_admin_accounts(&pool)
            .await
            .expect("durable administrators")
            .is_empty()
    );
    assert!(matches!(
        db::set_account_suspended(&pool, carol_id, true, "Bob", &configured).await,
        Err(db::DbError::LastAdministrator)
    ));
    db::set_account_administrator(&pool, carol_id, true, "Bob", &configured)
        .await
        .expect("grant Carol durable authority")
        .expect("Carol");
    db::set_account_administrator(&pool, carol_id, false, "Bob", &configured)
        .await
        .expect("configuration keeps Carol effective after durable revocation")
        .expect("Carol");
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_log
         WHERE target = 'bob'
           AND action IN ('ACCOUNT_ADMIN_GRANT', 'ACCOUNT_ADMIN_REVOKE')
         ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("authority audit");
    assert_eq!(actions, ["ACCOUNT_ADMIN_GRANT", "ACCOUNT_ADMIN_REVOKE"]);
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn account_invitations_are_single_use_expiring_and_digest_only() {
    let pool = db::connect_and_migrate(
        &support::test_db("account_invitations_are_single_use_expiring_and_digest_only").await,
    )
    .await
    .expect("connect");
    db::bootstrap_first_admin(&pool, "Alice", "administrator password")
        .await
        .expect("Alice");
    let email = e6ircd::identity::ContactEmail::parse("Bob@Example.COM").expect("email");
    let token = db::issue_account_invitation(
        &pool,
        "Bob",
        Some(&email),
        true,
        e6ircd::identity::AccountInvitationLifetimeDays::new(7).expect("lifetime"),
        "Alice",
    )
    .await
    .expect("issue");
    let carol_token = db::issue_account_invitation(
        &pool,
        "Carol",
        None,
        false,
        e6ircd::identity::AccountInvitationLifetimeDays::new(1).expect("lifetime"),
        "Alice",
    )
    .await
    .expect("issue second invitation");
    assert!(token.starts_with("e6i_"));
    let invitations = db::list_account_invitations(
        &pool,
        None,
        db::AccountInvitationPageSize::new(1).expect("page size"),
    )
    .await
    .expect("invitations");
    assert_eq!(invitations.entries.len(), 1);
    assert_eq!(invitations.entries[0].account_name, "Carol");
    let second_page = db::list_account_invitations(
        &pool,
        invitations.next_before_id,
        db::AccountInvitationPageSize::new(1).expect("page size"),
    )
    .await
    .expect("second page");
    assert_eq!(second_page.entries.len(), 1);
    assert_eq!(second_page.entries[0].account_name, "Bob");
    assert_eq!(second_page.next_before_id, None);
    assert_eq!(
        second_page.entries[0].contact_email.as_deref(),
        Some("Bob@example.com")
    );
    assert!(
        !format!("{invitations:?}").contains(&token),
        "directory must never expose the invitation bearer"
    );
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT token_hash FROM account_invitations WHERE id = $1")
            .bind(second_page.entries[0].id)
            .fetch_one(&pool)
            .await
            .expect("digest");
    assert_eq!(stored.len(), 32);
    assert_ne!(stored, token.as_bytes());
    assert!(
        db::account_invitation_preview(&pool, "e6i_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .await
            .expect("unknown preview")
            .is_none()
    );

    let account = db::accept_account_invitation(&pool, &token, "invited password")
        .await
        .expect("accept");
    assert_eq!(account, "Bob");
    assert_eq!(
        db::verify_local_password(&pool, "bob", "invited password")
            .await
            .expect("password"),
        Some("Bob".into())
    );
    assert!(
        db::account_flags(&pool, "Bob")
            .await
            .expect("flags")
            .expect("Bob")
            .is_admin()
    );
    assert!(matches!(
        db::accept_account_invitation(&pool, &token, "other password").await,
        Err(db::DbError::InvitationUnavailable)
    ));
    assert!(
        db::revoke_account_invitation(&pool, invitations.entries[0].id, "Alice")
            .await
            .expect("revoke Carol")
    );
    assert!(
        db::account_invitation_preview(&pool, &carol_token)
            .await
            .expect("Carol preview")
            .is_none()
    );
    assert!(
        db::list_account_invitations(
            &pool,
            None,
            db::AccountInvitationPageSize::new(100).expect("page size"),
        )
        .await
        .expect("invitations")
        .entries
        .is_empty()
    );
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_log
         WHERE target = 'bob' AND action LIKE 'ACCOUNT_INVITATION_%'
         ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("audit");
    assert_eq!(
        actions,
        ["ACCOUNT_INVITATION_CREATE", "ACCOUNT_INVITATION_ACCEPT"]
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn permanent_account_deletion_requires_succession_purges_and_retires() {
    let pool = db::connect_and_migrate(
        &support::test_db("permanent_account_deletion_requires_succession_purges_and_retires")
            .await,
    )
    .await
    .expect("connect");
    let alice_id = db::bootstrap_first_admin(&pool, "Alice", "administrator password")
        .await
        .expect("Alice");
    let bob_id = db::create_account(&pool, "Bob", "member password")
        .await
        .expect("Bob");
    sqlx::query(
        "INSERT INTO channels (name, name_folded, founder_account_id)
         VALUES ('#bob', '#bob', $1)",
    )
    .bind(bob_id)
    .execute(&pool)
    .await
    .expect("channel");
    assert!(matches!(
        db::account_deletion_target(&pool, bob_id, &[]).await,
        Err(db::DbError::AccountOwnsChannels(1))
    ));
    assert!(matches!(
        db::delete_account_permanently(&pool, bob_id, "Alice", &[]).await,
        Err(db::DbError::AccountOwnsChannels(1))
    ));
    assert!(
        db::set_channel_founder(&pool, "#bob", "alice")
            .await
            .expect("transfer")
    );
    let session = db::create_web_session(&pool, "Bob", None)
        .await
        .expect("session");
    let api_token = db::issue_api_token(&pool, "Bob", "automation")
        .await
        .expect("token");
    sqlx::query(
        "INSERT INTO bnc_networks (account_id, name, addr, nick)
         VALUES ($1, 'libera', 'irc.libera.chat:6697', 'Bob')",
    )
    .bind(bob_id)
    .execute(&pool)
    .await
    .expect("network");
    sqlx::query(
        "INSERT INTO bnc_buffer (owner, network, line)
         VALUES ('bob', 'libera', ':server NOTICE Bob :private backlog')",
    )
    .execute(&pool)
    .await
    .expect("buffer");
    sqlx::query(
        "INSERT INTO messages
            (msgid, target, sender_prefix, sender_account, kind, body, ts, dm_peers)
         VALUES
            ('bob-sent', '#test', 'Bob!u@h', 'bob', 'privmsg', 'sent', now(), NULL),
            ('bob-dm', 'alice!bob', 'Alice!u@h', 'alice', 'privmsg', 'private',
             now(), ARRAY['alice', 'bob'])",
    )
    .execute(&pool)
    .await
    .expect("messages");
    let (_device_code, user_code) = db::create_device_grant(&pool).await.expect("device");
    assert!(
        db::approve_device_grant(&pool, &user_code, "Bob")
            .await
            .expect("approve")
    );

    let deleted = db::delete_account_permanently(&pool, bob_id, "Alice", &[])
        .await
        .expect("delete")
        .expect("Bob");
    assert_eq!(deleted.name, "Bob");
    assert_eq!(
        db::account_name_by_id(&pool, bob_id).await.expect("lookup"),
        None
    );
    assert_eq!(
        db::session_account(&pool, &session).await.expect("session"),
        None
    );
    assert_eq!(
        db::api_token_account(&pool, &api_token)
            .await
            .expect("token"),
        None
    );
    let residues: (i64, i64, i64) = sqlx::query_as(
        "SELECT
            (SELECT count(*) FROM bnc_buffer WHERE owner = 'bob'),
            (SELECT count(*) FROM messages
             WHERE sender_account = 'bob' OR dm_peers @> ARRAY['bob']),
            (SELECT count(*) FROM device_grants WHERE account = 'Bob')",
    )
    .fetch_one(&pool)
    .await
    .expect("residues");
    assert_eq!(residues, (0, 0, 0));
    assert!(matches!(
        db::create_account(&pool, "bOB", "new owner").await,
        Err(db::DbError::DuplicateAccount(_))
    ));
    let direct = sqlx::query("INSERT INTO accounts (name, name_folded) VALUES ('BOB', 'bob')")
        .execute(&pool)
        .await;
    assert!(direct.is_err(), "storage trigger must reject retired names");
    sqlx::query("DELETE FROM channels WHERE name_folded = '#bob'")
        .execute(&pool)
        .await
        .expect("drop transferred channel");
    assert!(matches!(
        db::account_deletion_target(&pool, alice_id, &[]).await,
        Err(db::DbError::LastAdministrator)
    ));
    sqlx::query("UPDATE accounts SET flags = 0 WHERE id = $1")
        .bind(alice_id)
        .execute(&pool)
        .await
        .expect("make Alice configuration-only administrator");
    assert!(matches!(
        db::account_deletion_target(&pool, alice_id, &["alice".into(), "ghost".into()]).await,
        Err(db::DbError::LastAdministrator)
    ));
    db::create_account(&pool, "Dana", "administrator candidate")
        .await
        .expect("Dana");
    assert!(
        db::account_deletion_target(&pool, alice_id, &["alice".into(), "dana".into()])
            .await
            .expect("effective administrator check")
            .is_some(),
        "a second existing active configuration-backed administrator is a recovery path"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn account_export_and_security_activity_are_owner_scoped_and_secret_free() {
    let pool = db::connect_and_migrate(
        &support::test_db("account_export_and_security_activity_are_owner_scoped_and_secret_free")
            .await,
    )
    .await
    .expect("connect");
    let email = e6ircd::identity::ContactEmail::parse("Alice@Example.COM").expect("email");
    let alice_id = db::create_account_with_contact(
        &pool,
        "Alice",
        "highly confidential password",
        Some(&email),
    )
    .await
    .expect("Alice");
    db::create_account(&pool, "Bob", "other password")
        .await
        .expect("Bob");
    let session = db::create_web_session(&pool, "Alice", None)
        .await
        .expect("session");
    let bearer = db::issue_api_token(&pool, "Alice", "secret-token-label")
        .await
        .expect("token");
    sqlx::query(
        "INSERT INTO bnc_networks
            (account_id, name, addr, tls, nick, sasl_account, sasl_password_sealed)
         VALUES ($1, 'libera', 'irc.libera.chat:6697', true, 'Alice',
                 'alice', 'enc:v1:must-not-export')",
    )
    .bind(alice_id)
    .execute(&pool)
    .await
    .expect("network");
    db::insert_audit_log(&pool, "bob", "ACCOUNT_SUSPEND", "alice", "")
        .await
        .expect("admin event");
    db::insert_audit_log(&pool, "bob", "OTHER_EVENT", "bob", "private to Bob")
        .await
        .expect("other event");

    let export = db::export_account_json(&pool, "ALICE")
        .await
        .expect("export")
        .expect("Alice");
    let value: serde_json::Value = serde_json::from_str(&export).expect("valid JSON");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["account"]["name"], "Alice");
    assert_eq!(value["account"]["contact_email"], "Alice@example.com");
    assert_eq!(value["networks"][0]["has_sasl_password"], true);
    assert!(
        !export.contains("enc:v1:must-not-export")
            && !export.contains("highly confidential password")
            && !export.contains(&session)
            && !export.contains(&bearer),
        "export must contain metadata and personal data, never live or stored secrets"
    );
    let activity = db::query_account_security_activity(&pool, "Alice", None, audit_page_size(100))
        .await
        .expect("activity");
    assert!(
        activity
            .entries
            .iter()
            .any(|entry| entry.action == "ACCOUNT_LOGIN")
    );
    assert!(
        activity
            .entries
            .iter()
            .any(|entry| entry.action == "ACCOUNT_SUSPEND")
    );
    assert!(
        activity
            .entries
            .iter()
            .all(|entry| entry.detail != "private to Bob"),
        "another account's activity must not leak"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn storage_maintenance_bounds_history_audit_and_expired_bearers() {
    let pool = db::connect_and_migrate(
        &support::test_db("storage_maintenance_bounds_history_audit_and_expired_bearers").await,
    )
    .await
    .expect("connect");
    let account_id = db::create_account(&pool, "Alice", "password")
        .await
        .expect("account");
    sqlx::query(
        "INSERT INTO messages (msgid, target, sender_prefix, kind, body, ts)
         VALUES
           ('old-message', '#test', 'Alice!u@h', 'privmsg', 'old', now() - interval '31 days'),
           ('new-message', '#test', 'Alice!u@h', 'privmsg', 'new', now())",
    )
    .execute(&pool)
    .await
    .expect("messages");
    sqlx::query(
        "INSERT INTO audit_log (actor, action, target, detail, created_at)
         VALUES
           ('alice', 'OLD', 'server', '', now() - interval '366 days'),
           ('alice', 'NEW', 'server', '', now())",
    )
    .execute(&pool)
    .await
    .expect("audit");
    sqlx::query(
        "INSERT INTO web_sessions (token_hash, account_id, expires_at)
         VALUES
           (decode('01', 'hex'), $1, now() - interval '1 second'),
           (decode('02', 'hex'), $1, now() + interval '1 day')",
    )
    .bind(account_id)
    .execute(&pool)
    .await
    .expect("sessions");
    sqlx::query(
        "INSERT INTO api_tokens (token_hash, account_id, label, created_at, expires_at)
         VALUES
           (decode('03', 'hex'), $1, 'old',
            now() - interval '2 seconds', now() - interval '1 second'),
           (decode('04', 'hex'), $1, 'new', now(), now() + interval '1 day')",
    )
    .bind(account_id)
    .execute(&pool)
    .await
    .expect("API tokens");
    sqlx::query(
        "INSERT INTO device_grants (device_code, user_code, expires_at)
         VALUES
           ('old-device', 'OLDDEV01', now() - interval '1 second'),
           ('new-device', 'NEWDEV01', now() + interval '1 day')",
    )
    .execute(&pool)
    .await
    .expect("device grants");
    sqlx::query(
        "INSERT INTO oidc_logout_tokens (issuer, jti, expires_at)
         VALUES
           ('https://issuer.example', 'old', now() - interval '1 second'),
           ('https://issuer.example', 'new', now() + interval '1 day')",
    )
    .execute(&pool)
    .await
    .expect("logout tokens");
    sqlx::query(
        "INSERT INTO account_invitations
            (token_hash, account_name, name_folded, created_by, created_at, expires_at)
         VALUES
            (decode('05', 'hex'), 'Expired', 'expired', 'alice',
             now() - interval '2 days', now() - interval '1 day')",
    )
    .execute(&pool)
    .await
    .expect("account invitations");

    let report = db::run_storage_maintenance(&pool, 30, 365)
        .await
        .expect("maintenance");
    assert_eq!(report.messages, 1);
    assert_eq!(report.audit_events, 1);
    assert_eq!(report.web_sessions, 1);
    assert_eq!(report.api_tokens, 1);
    assert_eq!(report.device_grants, 1);
    assert_eq!(report.logout_tokens, 1);
    assert_eq!(report.account_invitations, 1);
    assert!(!report.saturated);
    let counts: (i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT count(*) FROM messages),
           (SELECT count(*) FROM audit_log),
           (SELECT count(*) FROM web_sessions),
           (SELECT count(*) FROM api_tokens),
           (SELECT count(*) FROM device_grants),
           (SELECT count(*) FROM oidc_logout_tokens),
           (SELECT count(*) FROM account_invitations)",
    )
    .fetch_one(&pool)
    .await
    .expect("retained row counts");
    assert_eq!(
        counts,
        (1, 1, 1, 1, 1, 1, 0),
        "every collection retained only its live/recent row"
    );
}
