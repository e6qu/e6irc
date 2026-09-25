//! Database-worker integration tests against real PostgreSQL.
//!
//! Ignored by default; run with `--ignored` where PostgreSQL is
//! available (CI provides a service container):
//!   E6IRC_TEST_DATABASE_URL=postgres://... cargo test --test db -- --ignored

use e6irc_queue::{Config as QueueConfig, Policy, queue};
use e6ircd::config::{Config, DatabaseConfig, ListenerConfig, NetworkKind};
use e6ircd::core::{CoreIngress, DbReply, DbRequest, Input};
use e6ircd::{db, net};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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
        &e6ircd::db::AuditPrincipal::operator(set_by),
    )
    .await
    .map(|_| ())
}

/// An account's whole export document, read page by page as the HTTP handler
/// streams it.
async fn export_account(pool: &sqlx::PgPool, account: &str) -> Option<String> {
    let mut export = db::begin_account_export(pool, account)
        .await
        .expect("begin export")?;
    let mut document = String::new();
    while let Some(chunk) = export.next_chunk().await.expect("export page") {
        document.push_str(&chunk);
    }
    Some(document)
}

/// The newest audit entries, unfiltered, through the query the console uses.
async fn list_audit_log(
    pool: &sqlx::PgPool,
    page_size: db::AuditLogPageSize,
) -> Result<Vec<db::AuditLogRow>, db::DbError> {
    Ok(db::query_audit_log(
        pool,
        db::AuditLogFilter {
            before_id: None,
            actor: None,
            action: None,
            target: None,
            page_size,
        },
    )
    .await?
    .entries)
}

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
    db::query_history(pool, target, e6ircd::core::HistoryFloor::Whole, query)
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
    let channels: Vec<(String, e6ircd::core::HistoryFloor)> = channels
        .iter()
        .map(|channel| (channel.clone(), e6ircd::core::HistoryFloor::Whole))
        .collect();
    db::query_targets(pool, &channels, Some(me), min_ts, max_ts, limit)
        .await
        .expect("targets query")
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn verify_password_roundtrip() {
    let pool = db::connect_and_migrate(&support::test_db("verify_password_roundtrip").await)
        .await
        .expect("connect");

    db::create_account_with_contact(&pool, "Alice", "correct horse", None)
        .await
        .expect("create");
    // duplicate registration fails loudly, case-insensitively
    let dup = db::create_account_with_contact(&pool, "alice", "x", None).await;
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
    db::create_account_with_contact(&pool, "sasluser", "s3cret", None)
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
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");

    let stream = TcpStream::connect(running.addrs[0]).await.expect("connect");
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    let mut expect = async |needle: &str| {
        tokio::time::timeout(deadline::HANG, async {
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
    db::create_account_with_contact(&pool, "tokuser", "pw", None)
        .await
        .expect("create");
    let token = issue_api_token(&pool, "tokuser", "cli")
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
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let addr = net::start(config).await.expect("start").addrs[0];

    // A valid API token authenticates via OAUTHBEARER.
    let mut c = e6irc_client::Connection::connect(&addr.to_string())
        .await
        .unwrap();
    let nick = c
        .register_oauthbearer(
            &e6irc_client::Identity {
                nick: "toknick",
                username: "toknick",
                realname: "T",
                server_password: None,
            },
            &token,
        )
        .await
        .expect("oauthbearer login");
    assert_eq!(nick, "toknick");
    // Confirm the login mapped to the token's account (self WHOIS 330).
    c.send_line("WHOIS toknick").await.unwrap();
    let logged = tokio::time::timeout(deadline::HANG, async {
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
        bad.register_oauthbearer(
            &e6irc_client::Identity {
                nick: "bad",
                username: "bad",
                realname: "B",
                server_password: None,
            },
            "not-a-real-token"
        )
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
    db::create_account_with_contact(&pool, "apppw", "mainpass", None)
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
        tokio::time::timeout(deadline::HANG, async {
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
    db::create_account_with_contact(&pool, "rluser", "mainpass", None)
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
            hsts_include_subdomains: false,
        }),
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
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
    assert!(
        third.to_ascii_lowercase().contains("\r\nretry-after: "),
        "a 429 says when to retry: {third}"
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
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");

    let stream = TcpStream::connect(running.addrs[0]).await.expect("irc");
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    let mut expect = async |needle: &str| {
        tokio::time::timeout(deadline::HANG, async {
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
                kind: e6ircd::core::HistoryKind::Privmsg,
                body: format!("line {i}"),
                sender_is_bot: false,
                multiline: None,
                client_tags: String::new(),
                ts: e6irc_proto::time::Millis::from_millis(1_700_000_000_000 + i),
            })
            .await
            .expect("enqueue log");
    }

    // Drop the sender (what dropping the core does) and wait for the worker to
    // finish. Awaiting the JoinHandle is the guarantee shutdown depends on.
    drop(req_tx);
    tokio::time::timeout(deadline::HANG, worker)
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

/// A drain of nothing but messages contains no await, so the batch used to
/// grow for as long as producers kept the queue full — one statement sized to
/// the burst, and no yield to the runtime. Writing at a bound holds both.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn a_flood_of_messages_is_written_in_bounded_batches() {
    let pool = db::connect_and_migrate(&support::test_db("a_flood_of_messages_is_written").await)
        .await
        .expect("connect");
    let (req_tx, req_rx) = queue::<DbRequest>(QueueConfig {
        name: "t-db-flood",
        capacity: 8192,
        policy: Policy::Fifo,
    });
    let (core_tx, _core_rx) = queue::<Input>(QueueConfig {
        name: "t-core-flood",
        capacity: 8,
        policy: Policy::Fifo,
    });
    let worker = tokio::spawn(db::run_worker(
        pool.clone(),
        req_rx,
        CoreIngress::single(core_tx),
    ));
    // More than one bound's worth, queued before the worker can drain them.
    let flood = 2_500;
    for i in 0..flood {
        req_tx
            .push(DbRequest::LogMessage {
                msgid: format!("flood-{i}"),
                target: "#flood".into(),
                dm_peers: Vec::new(),
                sender_prefix: "alice!a@host".into(),
                sender_account: None,
                kind: e6ircd::core::HistoryKind::Privmsg,
                body: format!("line {i}"),
                sender_is_bot: false,
                multiline: None,
                client_tags: String::new(),
                ts: e6irc_proto::time::Millis::from_millis(1_700_000_000_000 + i as u64),
            })
            .await
            .expect("enqueue log");
    }
    drop(req_tx);
    tokio::time::timeout(deadline::HANG, worker)
        .await
        .expect("the worker drains the flood")
        .expect("worker task");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE target = $1")
        .bind("#flood")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(count, flood as i64, "every flooded row is written");
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn history_worker_tells_an_unknown_msgid_from_an_empty_page() {
    let pool = db::connect_and_migrate(
        &support::test_db("history_worker_tells_an_unknown_msgid_from_an_empty_page").await,
    )
    .await
    .expect("connect");
    for (msgid, target) in [("newest-here", "#here"), ("elsewhere", "#other")] {
        sqlx::query(
            "INSERT INTO messages (msgid, target, sender_prefix, kind, body, ts)
             VALUES ($1, $2, 'peer!u@host', 'privmsg', 'text', now())",
        )
        .bind(msgid)
        .bind(target)
        .execute(&pool)
        .await
        .expect("insert history");
    }
    let (request_tx, request_rx) = queue::<DbRequest>(QueueConfig {
        name: "history-msgid-request",
        capacity: 8,
        policy: Policy::Fifo,
    });
    let (core_tx, mut core_rx) = queue::<Input>(QueueConfig {
        name: "history-msgid-reply",
        capacity: 8,
        policy: Policy::Fifo,
    });
    tokio::spawn(db::run_worker(
        pool,
        request_rx,
        CoreIngress::single(core_tx),
    ));
    let unknown = || {
        Err(e6ircd::core::HistoryFault::UnknownMsgid {
            subcommand: "AFTER",
        })
    };
    for (msgid, expected) in [
        // Known here, nothing after it: a real, empty page.
        ("newest-here", Ok(Vec::new())),
        ("never-existed", unknown()),
        // Another buffer's msgid is unknown *here*; it must not position this one.
        ("elsewhere", unknown()),
    ] {
        request_tx
            .push(DbRequest::QueryHistory {
                conn: e6ircd::core::ConnId(9),
                target: "#here".into(),
                floor: e6ircd::core::HistoryFloor::Whole,
                display: "#here".into(),
                batch_ref: "batch".into(),
                caps: e6ircd::core::HistoryResponseCaps {
                    batch: true,
                    ..Default::default()
                },
                query: e6ircd::core::HistoryQuery::AfterMsgid {
                    msgid: msgid.into(),
                    limit: 10,
                },
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
        assert_eq!(rows, expected, "{msgid}");
    }
}

/// Client-only tags and TAGMSG reactions are stored with history, and a page
/// is cut in its reader's scope: a `message-tags` reader pages through them, one
/// without (and the REST API, which serves text) gets full pages of text.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn history_keeps_client_tags_and_reactions_in_each_readers_scope() {
    let pool = db::connect_and_migrate(&support::test_db("history_keeps_client_tags").await)
        .await
        .expect("connect");
    let (request_tx, request_rx) = queue::<DbRequest>(QueueConfig {
        name: "history-tags-request",
        capacity: 16,
        policy: Policy::Fifo,
    });
    let (core_tx, mut core_rx) = queue::<Input>(QueueConfig {
        name: "history-tags-reply",
        capacity: 8,
        policy: Policy::Fifo,
    });
    tokio::spawn(db::run_worker(
        pool.clone(),
        request_rx,
        CoreIngress::single(core_tx),
    ));
    let rows = [
        ("t-parent", e6ircd::core::HistoryKind::Privmsg, "parent", ""),
        (
            "t-child",
            e6ircd::core::HistoryKind::Privmsg,
            "child",
            "+draft/reply=t-parent",
        ),
        (
            "t-react",
            e6ircd::core::HistoryKind::Tagmsg,
            "",
            "+draft/react=\\s;+draft/reply=t-child",
        ),
    ];
    for (i, (msgid, kind, body, client_tags)) in rows.into_iter().enumerate() {
        request_tx
            .push(DbRequest::LogMessage {
                msgid: msgid.into(),
                target: "#tags".into(),
                dm_peers: Vec::new(),
                sender_prefix: "alice!a@host".into(),
                sender_account: None,
                kind,
                body: body.into(),
                sender_is_bot: false,
                multiline: None,
                client_tags: client_tags.into(),
                ts: e6irc_proto::time::Millis::from_millis(1_700_000_000_000 + i as u64),
            })
            .await
            .expect("enqueue log");
    }
    let mut page = async |message_tags: bool| {
        request_tx
            .push(DbRequest::QueryHistory {
                conn: e6ircd::core::ConnId(9),
                target: "#tags".into(),
                floor: e6ircd::core::HistoryFloor::Whole,
                display: "#tags".into(),
                batch_ref: "batch".into(),
                caps: e6ircd::core::HistoryResponseCaps {
                    batch: true,
                    message_tags,
                    ..Default::default()
                },
                query: e6ircd::core::HistoryQuery::Latest { limit: 2 },
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
        rows.expect("history page")
            .into_iter()
            .map(|row| (row.msgid, row.kind, row.client_tags))
            .collect::<Vec<_>>()
    };
    // The worker writes messages in batches; the reply is behind them.
    assert_eq!(
        page(true).await,
        [
            (
                "t-child".to_string(),
                e6ircd::core::HistoryKind::Privmsg,
                "+draft/reply=t-parent".to_string()
            ),
            (
                "t-react".to_string(),
                e6ircd::core::HistoryKind::Tagmsg,
                "+draft/react=\\s;+draft/reply=t-child".to_string()
            ),
        ]
    );
    let text_only = [
        (
            "t-parent".to_string(),
            e6ircd::core::HistoryKind::Privmsg,
            String::new(),
        ),
        (
            "t-child".to_string(),
            e6ircd::core::HistoryKind::Privmsg,
            "+draft/reply=t-parent".to_string(),
        ),
    ];
    assert_eq!(
        page(false).await,
        text_only,
        "the TAGMSG is cut before the limit"
    );
    let rest: Vec<_> = hist(
        &pool,
        "#tags",
        e6ircd::core::HistoryQuery::Latest { limit: 2 },
    )
    .await
    .into_iter()
    .map(|row| (row.msgid, row.kind, row.client_tags))
    .collect();
    assert_eq!(rest, text_only, "REST serves text");

    // A TAGMSG row is tags and nothing else.
    let malformed = sqlx::query(
        "INSERT INTO messages (msgid, target, sender_prefix, kind, body, ts, client_tags)
         VALUES ('bad', '#tags', 'a!a@h', 'tagmsg', 'text', now(), '+draft/react=x')",
    )
    .execute(&pool)
    .await;
    assert!(malformed.is_err(), "a TAGMSG with text is refused");
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn credential_list_and_revoke() {
    use e6ircd::config::HttpConfig;
    use tokio::io::AsyncReadExt;

    let url = support::test_db("credential_list_and_revoke").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    db::create_account_with_contact(&pool, "creduser", "pw", None)
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
    db::create_account_with_contact(&pool, "lu", "pw", None)
        .await
        .expect("create");
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
    db::create_account_with_contact(&pool, "rc", "pw", None)
        .await
        .expect("create");
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
    db::create_account_with_contact(&pool, "rotate", "old", None)
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
        db::change_local_password(&pool, "rotate", &app, "attacker-choice", "no-session").await,
        Err(db::DbError::BadCredentials)
    ));

    // The browser making the change keeps its session; every other one ends —
    // the old password may be in someone else's hands, and they may be signed
    // in with it.
    let changing_session = db::create_web_session(&pool, "rotate", None)
        .await
        .expect("changing session");
    let other_session = db::create_web_session(&pool, "rotate", None)
        .await
        .expect("other session");
    db::change_local_password(&pool, "ROTATE", "old", "new", &changing_session)
        .await
        .expect("rotate");
    assert_eq!(
        db::session_account(&pool, &changing_session)
            .await
            .expect("changing session lookup")
            .as_deref(),
        Some("rotate"),
        "the session that changed the password stays signed in"
    );
    assert_eq!(
        db::session_account(&pool, &other_session)
            .await
            .expect("other session lookup"),
        None,
        "every other browser session ended with the password change"
    );
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
    let adding_session = db::create_web_session(&pool, &oidc_account, None)
        .await
        .expect("adding session");
    let stale_session = db::create_web_session(&pool, &oidc_account, None)
        .await
        .expect("stale session");
    db::set_local_password(&pool, &oidc_account, "first-local", &adding_session)
        .await
        .expect("set first password");
    assert_eq!(
        db::verify_local_password(&pool, &oidc_account, "first-local")
            .await
            .expect("verify first password"),
        Some(oidc_account.clone())
    );
    assert_eq!(
        db::list_web_sessions(&pool, &oidc_account, Some(&adding_session))
            .await
            .expect("session inventory")
            .len(),
        1,
        "adding a password ends every other browser session"
    );
    assert_eq!(
        db::session_account(&pool, &stale_session)
            .await
            .expect("stale session lookup"),
        None
    );
    assert!(matches!(
        db::set_local_password(&pool, &oidc_account, "second-local", &adding_session).await,
        Err(db::DbError::LocalPasswordExists)
    ));
}

/// A first login provisions the account the provider's claim names, exactly.
/// A name that is already someone's, or retired, is refused by name — the
/// server never picks a different name for a person.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn oidc_first_login_refuses_a_taken_or_retired_name() {
    let pool = db::connect_and_migrate(
        &support::test_db("oidc_first_login_refuses_a_taken_or_retired_name").await,
    )
    .await
    .expect("connect");
    db::create_account_with_contact(&pool, "Kilgore", "pw", None)
        .await
        .expect("kilgore");
    sqlx::query("INSERT INTO retired_account_names (name_folded) VALUES ('trout')")
        .execute(&pool)
        .await
        .expect("retire a name");

    for (subject, claim) in [
        ("sub-taken", "kilgore"),
        ("sub-taken-case", "KILGORE"),
        ("sub-retired", "trout"),
    ] {
        let refusal =
            db::find_or_create_oidc_account(&pool, "https://idp.example", subject, claim).await;
        assert!(
            matches!(&refusal, Err(db::DbError::DuplicateAccount(name)) if name == claim),
            "{claim}: {refusal:?}"
        );
    }
    let accounts: i64 = sqlx::query_scalar("SELECT count(*) FROM accounts")
        .fetch_one(&pool)
        .await
        .expect("account count");
    assert_eq!(accounts, 1, "no account was provisioned under another name");
    let identities: i64 = sqlx::query_scalar("SELECT count(*) FROM oidc_identities")
        .fetch_one(&pool)
        .await
        .expect("identity count");
    assert_eq!(identities, 0);

    // A free name is provisioned exactly as the claim spells it, and the same
    // identity resolves to it afterwards whatever the claim says then.
    assert_eq!(
        db::find_or_create_oidc_account(&pool, "https://idp.example", "sub-free", "Eliot")
            .await
            .expect("provision"),
        "Eliot"
    );
    assert_eq!(
        db::find_or_create_oidc_account(&pool, "https://idp.example", "sub-free", "kilgore")
            .await
            .expect("resolve linked identity"),
        "Eliot"
    );
}

/// Per-account app passwords are capped, so an authenticated account can't flood
/// the credential table.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn app_passwords_are_capped_per_account() {
    let url = support::test_db("app_passwords_are_capped_per_account").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    db::create_account_with_contact(&pool, "cap", "pw", None)
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
    db::create_account_with_contact(&pool, "tcap", "pw", None)
        .await
        .expect("create");
    // Mint the maximum (32) through the capped REST path; each succeeds.
    for i in 0..32 {
        issue_api_token(&pool, "tcap", &format!("cli{i}"))
            .await
            .unwrap_or_else(|e| panic!("token {i} should succeed: {e}"));
    }
    // The 33rd is refused with the dedicated error — the cap is enforced
    // atomically in the DB layer, not by a racy list-then-insert in the handler.
    let over = issue_api_token(&pool, "tcap", "one too many").await;
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
    db::create_account_with_contact(&pool, "token-shape", "pw", None)
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
    db::create_account_with_contact(&pool, "ncap", "pw", None)
        .await
        .expect("create");
    let row = |i: usize| db::BncNetworkRow {
        kind: NetworkKind::Irc,
        name: format!("net{i}"),
        addr: "irc.example:6697".into(),
        tls: true,
        nick: "ncap".into(),
        username: Some("tester".into()),
        realname: Some("Network Cap".into()),
        autojoin: vec![],
        sasl_account: None,
        sasl_password_sealed: None,
        enabled: true,
        server_password_sealed: None,
    };
    // Mint the maximum (32); each succeeds.
    for i in 0..32 {
        db::create_bnc_network(
            &pool,
            "ncap",
            &row(i),
            e6ircd::db::NetworkAudit {
                actor: "ncap",
                detail: "",
            },
        )
        .await
        .unwrap_or_else(|e| panic!("network {i} should succeed: {e}"));
    }
    // The 33rd is refused with the dedicated error, enforced atomically — each
    // network spawns an always-on driver, so an overshoot is real amplification.
    let over = db::create_bnc_network(
        &pool,
        "ncap",
        &row(99),
        e6ircd::db::NetworkAudit {
            actor: "ncap",
            detail: "",
        },
    )
    .await;
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
        db::set_channel_access(&pool, "#c", &name, Some("v".into()), "founder")
            .await
            .unwrap_or_else(|e| panic!("grant {i} should succeed: {e}"));
    }

    // The 257th distinct account is refused with the dedicated error.
    sqlx::query("INSERT INTO accounts (name, name_folded) VALUES ('t256', 't256')")
        .execute(&pool)
        .await
        .expect("target account");
    let over = db::set_channel_access(&pool, "#c", "t256", Some("v".into()), "founder").await;
    assert!(
        matches!(over, Ok(db::AccessChange::LimitReached)),
        "the 257th access entry must be refused: {over:?}"
    );

    // Re-flagging an EXISTING entry is still allowed — it replaces, not grows.
    let reflag = db::set_channel_access(&pool, "#c", "t0", Some("o".into()), "founder").await;
    assert_eq!(
        reflag.expect("re-flag"),
        db::AccessChange::Applied {
            account: "t0".into(),
            previous: Some("v".into()),
        },
        "re-flagging an existing entry stays allowed at the cap"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn read_marker_persists() {
    let url = support::test_db("read_marker_persists").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    db::create_account_with_contact(&pool, "mark", "pw", None)
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
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
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
        tokio::time::timeout(deadline::HANG, async {
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
    db::create_account_with_contact(&pool, "web", "pw", None)
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
    db::create_account_with_contact(&pool, "other", "pw", None)
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
    db::create_account_with_contact(&pool2, "snoop", "pw", None)
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
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        // This client pipelines 600 messages in one instant to overflow the
        // ring, which the default command-flood bucket (40 then 20/s) would
        // rightly answer with Excess Flood; the bucket is not what is under test.
        limits: e6ircd::config::LimitsConfig {
            command_burst: 10_000,
            command_rate: 10_000,
            ..e6ircd::config::LimitsConfig::default()
        },
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
        tokio::time::timeout(deadline::HANG, async {
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
    tokio::time::timeout(deadline::HANG, async {
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
async fn chathistory_recreated_channel_serves_only_its_own_incarnation_with_label() {
    // A channel that empties is dropped from memory; when re-created its ring
    // is empty while PostgreSQL still holds the old incarnation's rows. Those
    // belong to whoever was there before: a member without a registered
    // relationship to the channel reads only what was said since it was
    // re-created — which, the ring being incomplete, is served from the
    // database, and a labeled request's deferred batch carries the label.
    let url =
        support::test_db("chathistory_recreated_channel_serves_only_its_own_incarnation").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");

    let config = Config {
        server_name: "irc.recreate.example".into(),
        network_name: "RecNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
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
    w.write_all(b"PRIVMSG #r :since re-creation\r\nPING said\r\n")
        .await
        .unwrap();
    expect_line(&mut reader, "PONG").await;
    for _ in 0..100 {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM messages WHERE target = '#r'")
            .fetch_one(&pool)
            .await
            .expect("count");
        if n == 6 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

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
    assert_eq!(
        bodies,
        ["since re-creation"],
        "the re-created channel serves its own incarnation only"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn read_marker_preloaded_after_restart() {
    // The read-marker mirror must be seeded from PostgreSQL at boot; otherwise a
    // MARKREAD query returns `*` after a restart even though a marker persists.
    let url = support::test_db("read_marker_preloaded_after_restart").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    db::create_account_with_contact(&pool, "marky", "pw", None)
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
        database: Some(DatabaseConfig {
            url: url.clone(),
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
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
    db::create_account_with_contact(&pool, "dupacct", "pw", None)
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
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let addr = net::start(config).await.expect("start").addrs[0];

    // Client 1 reserves the nick "dup".
    let mut c1 = e6irc_client::Connection::connect(&addr.to_string())
        .await
        .unwrap();
    c1.register(&e6irc_client::Identity {
        nick: "dup",
        username: "dup",
        realname: "First",
        server_password: None,
    })
    .await
    .expect("register");

    // Client 2 authenticates via SASL but requests the same nick. After 903 the
    // server refuses registration with 433; register_sasl must return an error,
    // not hang — the timeout guard fails the test if it hangs.
    let mut c2 = e6irc_client::Connection::connect(&addr.to_string())
        .await
        .unwrap();
    let res = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        c2.register_sasl(
            &e6irc_client::Identity {
                nick: "dup",
                username: "dup",
                realname: "Second",
                server_password: None,
            },
            "dupacct",
            "pw",
        ),
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
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
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
    db::connect_and_migrate(&url).await.expect("connect");
    let config = Config {
        server_name: "irc.dm.example".into(),
        network_name: "DmNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
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

    // Both parties are unauthenticated, so the conversation is in the ring
    // only; TARGETS must still list it, merged into the database's answer.
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
async fn a_stranger_taking_a_nick_gets_none_of_its_previous_conversations() {
    // `~nick` is whoever holds the nick now. A conversation with an
    // unauthenticated party is therefore never stored and never served from
    // storage: unauthenticated bob messages alice and quits; the next `bob`
    // must find neither the conversation nor the correspondent.
    let url = support::test_db("a_stranger_taking_a_nick_gets_none_of_its_previous").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    let config = Config {
        server_name: "irc.dm2.example".into(),
        network_name: "DmNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let connect = |nick: &'static str| {
        let addr = running.addrs[0];
        async move {
            let (read, mut write) = TcpStream::connect(addr).await.expect(nick).into_split();
            let mut reader = BufReader::new(read);
            write
                .write_all(
                    format!(
                        "CAP LS 302\r\nCAP REQ :batch draft/chathistory message-tags \
                         server-time\r\nNICK {nick}\r\nUSER u 0 * :U\r\nCAP END\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            expect_line(&mut reader, "001").await;
            (reader, write)
        }
    };
    let (mut alice_reader, mut alice) = connect("alice").await;
    let (bob_reader, mut bob) = connect("bob").await;
    alice.write_all(b"JOIN #sentinel\r\n").await.unwrap();
    bob.write_all(b"PRIVMSG alice :for your eyes only\r\n")
        .await
        .unwrap();
    expect_line(&mut alice_reader, "for your eyes only").await;
    // The log queue is first-in first-out: once this later channel message is
    // stored, the direct message before it would have been too.
    alice
        .write_all(b"PRIVMSG #sentinel :after the direct message\r\n")
        .await
        .unwrap();
    for _ in 0..100 {
        let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM messages")
            .fetch_one(&pool)
            .await
            .expect("count");
        if stored >= 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let direct: i64 =
        sqlx::query_scalar("SELECT count(*) FROM messages WHERE dm_peers IS NOT NULL")
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(direct, 0, "a conversation with a `~` party was stored");

    bob.write_all(b"QUIT :bye\r\n").await.unwrap();
    drop((bob, bob_reader));
    loop {
        alice.write_all(b"ISON bob\r\n").await.unwrap();
        let line = expect_line(&mut alice_reader, " 303 ").await;
        if !line
            .rsplit_once(" :")
            .is_some_and(|(_, nicks)| nicks.contains("bob"))
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let (mut stranger_reader, mut stranger) = connect("bob").await;
    stranger
        .write_all(
            b"CHATHISTORY LATEST alice * 10\r\n\
              CHATHISTORY TARGETS timestamp=2000-01-01T00:00:00.000Z \
              timestamp=2999-01-01T00:00:00.000Z 10\r\n",
        )
        .await
        .unwrap();
    for batch in ["chathistory alice", "draft/chathistory-targets"] {
        expect_line(&mut stranger_reader, batch).await;
        let next = expect_line(&mut stranger_reader, "").await;
        assert!(
            next.contains("BATCH -"),
            "the new `bob` was served the previous one's {batch}: {next}"
        );
    }
}

/// Migration 0058 removes what was stored before the rule existed, and only that.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn stored_conversations_with_an_unauthenticated_party_are_purged() {
    let pool = db::connect_and_migrate(
        &support::test_db("stored_conversations_with_an_unauthenticated_party_are_purged").await,
    )
    .await
    .expect("connect");
    for (msgid, target) in [
        ("legacy-anonymous", "alice!~bob"),
        ("accounts", "alice!carol"),
        ("channel", "#room"),
    ] {
        sqlx::query(
            "INSERT INTO messages (msgid, target, sender_prefix, kind, body, ts, dm_peers)
             VALUES ($1, $2, 'peer!u@host', 'privmsg', 'text', now(),
                     CASE WHEN left($2, 1) = '#' THEN NULL ELSE string_to_array($2, '!') END)",
        )
        .bind(msgid)
        .bind(target)
        .execute(&pool)
        .await
        .expect("insert history");
    }
    // Even before the purge runs, a stored `~` conversation is never listed.
    let ever = e6irc_proto::time::Millis::from_millis;
    assert!(
        tgts(&pool, &[], "~bob", ever(0), ever(4_000_000_000_000), 10)
            .await
            .is_empty()
    );
    sqlx::raw_sql(include_str!(
        "../../../migrations/0058_purge_unauthenticated_direct_messages.sql"
    ))
    .execute(&pool)
    .await
    .expect("purge");
    let kept: Vec<String> = sqlx::query_scalar("SELECT msgid FROM messages ORDER BY msgid")
        .fetch_all(&pool)
        .await
        .expect("remaining");
    assert_eq!(kept, ["accounts", "channel"]);
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn bnc_networks_crud() {
    let pool = db::connect_and_migrate(&support::test_db("bnc_networks_crud").await)
        .await
        .expect("connect");
    db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("acct");
    let bob_id = db::create_account_with_contact(&pool, "bob", "pw", None)
        .await
        .expect("acct");

    let libera = db::BncNetworkRow {
        kind: NetworkKind::Irc,
        name: "libera".into(),
        addr: "irc.libera.chat:6697".into(),
        tls: true,
        nick: "alice_".into(),
        username: Some("tester".into()),
        realname: Some("Alice".into()),
        autojoin: vec!["#rust".into(), "#e6irc".into()],
        sasl_account: Some("alice".into()),
        sasl_password_sealed: Some("enc:v1:abc".into()),
        enabled: true,
        server_password_sealed: None,
    };
    db::create_bnc_network(
        &pool,
        "alice",
        &libera,
        e6ircd::db::NetworkAudit {
            actor: "alice",
            detail: "",
        },
    )
    .await
    .expect("create");

    // duplicate (owner, name) is rejected loudly
    let dup = db::create_bnc_network(
        &pool,
        "alice",
        &libera,
        e6ircd::db::NetworkAudit {
            actor: "alice",
            detail: "",
        },
    )
    .await;
    assert!(
        matches!(dup, Err(db::DbError::DuplicateNetwork(_))),
        "{dup:?}"
    );

    // bob may reuse the same network name (distinct owner)
    db::create_bnc_network(
        &pool,
        "bob",
        &libera,
        e6ircd::db::NetworkAudit {
            actor: "bob",
            detail: "",
        },
    )
    .await
    .expect("bob create");

    // unknown account is rejected
    let bad = db::create_bnc_network(
        &pool,
        "nobody",
        &libera,
        e6ircd::db::NetworkAudit {
            actor: "nobody",
            detail: "",
        },
    )
    .await;
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
        db::update_bnc_network(
            &pool,
            "alice",
            "LIBERA",
            &updated,
            e6ircd::db::NetworkAudit {
                actor: "alice",
                detail: ""
            }
        )
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
        username: None,
        realname: Some("Alice".into()),
        autojoin: vec!["#room:matrix.example".into()],
        sasl_account: None,
        sasl_password_sealed: Some("enc:v2:sealed".into()),
        enabled: true,
        server_password_sealed: None,
    };
    db::create_bnc_network(
        &pool,
        "alice",
        &matrix,
        e6ircd::db::NetworkAudit {
            actor: "alice",
            detail: "",
        },
    )
    .await
    .expect("matrix");
    let hq = db::get_bnc_network(&pool, "alice", "hq")
        .await
        .expect("get")
        .expect("present");
    assert_eq!(hq.kind, e6ircd::config::NetworkKind::Matrix);
    assert_eq!(hq.addr, "https://matrix.example");
    db::set_bnc_network_enabled(
        &pool,
        "alice",
        "hq",
        false,
        e6ircd::db::NetworkAudit {
            actor: "alice",
            detail: "",
        },
    )
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
    db::delete_bnc_network(
        &pool,
        "alice",
        "hq",
        e6ircd::db::NetworkAudit {
            actor: "alice",
            detail: "",
        },
    )
    .await
    .expect("cleanup");

    // list_all pairs each network with its owner (two rows: alice+bob)
    let all = db::list_startable_bnc_networks(&pool).await.expect("all");
    assert_eq!(all.len(), 2);
    assert!(all.iter().any(|(o, n)| o == "alice" && n.name == "libera"));
    assert!(all.iter().any(|(o, n)| o == "bob" && n.name == "libera"));

    // Suspension leaves `enabled` set so reactivation restores the network,
    // which is exactly why the boot list must ask about the owner too.
    db::set_account_suspended(&pool, bob_id, true, "alice", &[])
        .await
        .expect("suspend bob");
    let startable = db::list_startable_bnc_networks(&pool)
        .await
        .expect("startable");
    assert_eq!(
        startable.len(),
        1,
        "a suspended owner's network would restart at boot"
    );
    assert_eq!(startable[0].0, "alice");
    assert!(
        db::get_bnc_network(&pool, "bob", "libera")
            .await
            .expect("bob's network")
            .expect("kept")
            .enabled
    );
    db::set_account_suspended(&pool, bob_id, false, "alice", &[])
        .await
        .expect("reactivate bob");
    assert_eq!(
        db::list_startable_bnc_networks(&pool)
            .await
            .expect("startable")
            .len(),
        2
    );

    // delete is owner-scoped
    assert!(
        db::delete_bnc_network(
            &pool,
            "alice",
            "libera",
            e6ircd::db::NetworkAudit {
                actor: "alice",
                detail: ""
            }
        )
        .await
        .unwrap()
    );
    assert!(
        !db::delete_bnc_network(
            &pool,
            "alice",
            "libera",
            e6ircd::db::NetworkAudit {
                actor: "alice",
                detail: ""
            }
        )
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
    db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("acct");

    let libera = db::BncNetworkRow {
        kind: NetworkKind::Irc,
        name: "libera".into(),
        addr: "irc.libera.chat:6697".into(),
        tls: true,
        nick: "alice_".into(),
        username: Some("tester".into()),
        realname: Some("Mixed Case".into()),
        autojoin: vec![],
        sasl_account: None,
        sasl_password_sealed: None,
        enabled: true,
        server_password_sealed: None,
    };
    db::create_bnc_network(
        &pool,
        "alice",
        &libera,
        e6ircd::db::NetworkAudit {
            actor: "alice",
            detail: "",
        },
    )
    .await
    .expect("create");

    // A case-variant of an existing name is the *same* network, not a new one.
    let mut variant = libera.clone();
    variant.name = "Libera".into();
    let dup = db::create_bnc_network(
        &pool,
        "alice",
        &variant,
        e6ircd::db::NetworkAudit {
            actor: "alice",
            detail: "",
        },
    )
    .await;
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
    db::persist_bnc_line(
        &pool,
        &e6ircd::db::open_bnc_buffer(
            &pool,
            Some("ALICE"),
            "LiBeRa",
            e6ircd::db::BncNetworkDefinition::Configured,
        )
        .await
        .expect("open buffer"),
        None,
        ":s NOTICE * :backlog",
        &e6irc_client::NetworkNames::default(),
    )
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
        db::set_bnc_network_enabled(
            &pool,
            "alice",
            "LIBERA",
            false,
            e6ircd::db::NetworkAudit {
                actor: "alice",
                detail: ""
            }
        )
        .await
        .expect("disable"),
        "disable by a different casing must match the stored network"
    );
    assert!(
        db::delete_bnc_network(
            &pool,
            "alice",
            "LiBeRa",
            e6ircd::db::NetworkAudit {
                actor: "alice",
                detail: ""
            }
        )
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
    db::create_account_with_contact(&pool, "MixedCase", "pw", None)
        .await
        .expect("acct");
    let net = db::BncNetworkRow {
        kind: NetworkKind::Irc,
        name: "libera".into(),
        addr: "irc.libera.chat:6697".into(),
        tls: true,
        nick: "mc".into(),
        username: Some("tester".into()),
        realname: Some("Mixed Case".into()),
        autojoin: vec![],
        sasl_account: None,
        sasl_password_sealed: None,
        enabled: true,
        server_password_sealed: None,
    };
    db::create_bnc_network(
        &pool,
        "MixedCase",
        &net,
        e6ircd::db::NetworkAudit {
            actor: "MixedCase",
            detail: "",
        },
    )
    .await
    .expect("create");
    // The live persistence path writes under the folded owner.
    let folded = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold("MixedCase");
    for i in 0..3 {
        db::persist_bnc_line(
            &pool,
            &e6ircd::db::open_bnc_buffer(
                &pool,
                Some(&folded),
                "libera",
                e6ircd::db::BncNetworkDefinition::Configured,
            )
            .await
            .expect("open buffer"),
            Some("mc"),
            &format!(":s PRIVMSG #x :m{i}"),
            &e6irc_client::NetworkNames::default(),
        )
        .await
        .expect("persist");
    }
    db::set_bnc_read_marker(
        &pool,
        "MixedCase",
        "libera",
        "#x",
        e6irc_proto::casemap::CaseMapping::Rfc1459,
        "2026-01-01T00:00:00.000Z",
    )
    .await
    .expect("persist read marker");
    // Delete by the raw (display-cased) account name, as the HTTP handler does.
    assert!(
        db::delete_bnc_network(
            &pool,
            "MixedCase",
            "libera",
            e6ircd::db::NetworkAudit {
                actor: "MixedCase",
                detail: ""
            }
        )
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
    let markers: i64 = sqlx::query_scalar("SELECT count(*) FROM bnc_read_markers")
        .fetch_one(&pool)
        .await
        .expect("marker count");
    assert_eq!(
        markers, 0,
        "a deleted network must not leave markers for a later same-named network"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn concurrent_bnc_read_markers_cannot_exceed_the_account_cap() {
    let pool = db::connect_and_migrate(
        &support::test_db("concurrent_bnc_read_markers_cannot_exceed_the_account_cap").await,
    )
    .await
    .expect("connect");
    db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("account");
    for index in 0..250 {
        sqlx::query(
            "INSERT INTO bnc_read_markers
                 (account_id, network, target, timestamp, target_display, target_casemapping)
             SELECT id, 'net', $1, '2026-01-01T00:00:00.000Z', $1, 'rfc1459'
             FROM accounts WHERE name_folded = 'alice'",
        )
        .bind(format!("#existing{index}"))
        .execute(&pool)
        .await
        .expect("seed marker");
    }

    let mut writes = tokio::task::JoinSet::new();
    for index in 0..16 {
        let pool = pool.clone();
        writes.spawn(async move {
            db::set_bnc_read_marker(
                &pool,
                "alice",
                "net",
                &format!("#new{index}"),
                e6irc_proto::casemap::CaseMapping::Rfc1459,
                "2026-01-02T00:00:00.000Z",
            )
            .await
        });
    }
    let mut stored = 0;
    let mut limited = 0;
    while let Some(result) = writes.join_next().await {
        match result.expect("marker task").expect("marker write") {
            db::BncReadMarkerWrite::Stored(_) => stored += 1,
            db::BncReadMarkerWrite::LimitReached => limited += 1,
        }
    }
    assert_eq!(stored, 6);
    assert_eq!(limited, 10);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM bnc_read_markers")
        .fetch_one(&pool)
        .await
        .expect("marker count");
    assert_eq!(count, db::BNC_READ_MARKER_LIMIT);
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn a_history_page_counts_only_lines_the_client_can_receive() {
    let pool = db::connect_and_migrate(&support::test_db("bnc_history_scope").await)
        .await
        .expect("connect");
    let buffer = db::open_bnc_buffer(
        &pool,
        Some("alice"),
        "libera",
        db::BncNetworkDefinition::Configured,
    )
    .await
    .expect("open buffer");
    // Alternating messages and tag-only typing notifications, as a busy channel
    // produces them: six of the ten stored lines are TAGMSG.
    for id in 1..=10 {
        let line = if id % 2 == 0 {
            format!(
                "@msgid=m{id};time=2026-01-01T00:00:{id:02}.000Z :n!u@h PRIVMSG #room :body {id}"
            )
        } else {
            format!(
                "@msgid=m{id};time=2026-01-01T00:00:{id:02}.000Z;+typing=active :n!u@h TAGMSG #room"
            )
        };
        db::persist_bnc_line(
            &pool,
            &buffer,
            Some("alice"),
            &line,
            &e6irc_client::NetworkNames::default(),
        )
        .await
        .expect("persist");
    }
    let page = async |scope, limit| {
        db::bnc_history_window(
            &pool,
            "alice",
            "libera",
            "#room",
            e6irc_proto::casemap::CaseMapping::Rfc1459,
            db::BncHistoryPaging::Latest,
            scope,
            &db::BncHistorySelector::Star,
            &db::BncHistorySelector::Star,
            limit,
        )
        .await
        .expect("query")
        .expect("LATEST * has no msgid to miss")
        .into_iter()
        .map(|row| row.msgid.expect("msgid"))
        .collect::<Vec<_>>()
    };
    // A client with message-tags receives every kind of line, so its page is
    // the newest four rows whatever they are.
    assert_eq!(
        page(db::BncHistoryScope::EveryLine, 4).await,
        ["m7", "m8", "m9", "m10"],
    );
    // A client without it cannot receive a TAGMSG at all. Asking for four must
    // still yield four lines it can read -- before the scope reached the query,
    // the TAGMSG rows were cut after the LIMIT and the page came back short.
    assert_eq!(
        page(db::BncHistoryScope::ExceptTagOnly, 4).await,
        ["m4", "m6", "m8", "m10"],
    );
    assert_eq!(
        db::BncHistoryScope::for_message_tags(false),
        db::BncHistoryScope::ExceptTagOnly,
    );
    // The generated column reads the command out of the frame, not out of the
    // body: a message that merely talks about TAGMSG is still deliverable.
    db::persist_bnc_line(
        &pool,
        &buffer,
        Some("alice"),
        "@msgid=m11;time=2026-01-01T00:00:11.000Z :n!u@h PRIVMSG #room :TAGMSG is a command",
        &e6irc_client::NetworkNames::default(),
    )
    .await
    .expect("persist");
    assert_eq!(page(db::BncHistoryScope::ExceptTagOnly, 1).await, ["m11"]);
    // TARGETS answers in the same scope: a conversation whose only backlog is
    // tag-only messages would otherwise be named and then page back empty.
    db::persist_bnc_line(
        &pool,
        &buffer,
        Some("alice"),
        "@msgid=t1;time=2026-01-01T00:00:12.000Z;+typing=active :n!u@h TAGMSG #quiet",
        &e6irc_client::NetworkNames::default(),
    )
    .await
    .expect("persist");
    let targets = async |scope| {
        db::bnc_history_targets(&pool, "alice", "libera", scope, "0000", "9999", 50)
            .await
            .expect("targets")
            .into_iter()
            .map(|(target, _)| target)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        targets(db::BncHistoryScope::EveryLine).await,
        ["#room", "#quiet"],
    );
    assert_eq!(targets(db::BncHistoryScope::ExceptTagOnly).await, ["#room"]);
}

/// A stored conversation is keyed the way its network folds names, and is
/// named as the network spelled it. On an `ascii` network `#a[` and `#a{` are
/// two channels and `dev[m]` is not `dev{m}`: two histories, and TARGETS names
/// each as it was spelled — never a folded key that names someone else there.
/// Rows keyed under another mapping (before the network said, or before it
/// changed) are re-keyed from their spelling, and the mapping is remembered.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn bnc_conversations_are_keyed_the_networks_way_and_named_as_spelled() {
    let pool = db::connect_and_migrate(&support::test_db("bnc_history_casemapping").await)
        .await
        .expect("connect");
    let buffer = db::open_bnc_buffer(
        &pool,
        Some("alice"),
        "unreal",
        db::BncNetworkDefinition::Configured,
    )
    .await
    .expect("open buffer");
    let rfc1459 = e6irc_client::NetworkNames::default();
    let mut ascii = e6irc_client::NetworkNames::default();
    ascii.adopt_tokens(["CASEMAPPING=ascii"]);
    // Stored before the network said how it compares names.
    db::persist_bnc_line(
        &pool,
        &buffer,
        Some("dev[m]"),
        "@time=2026-01-01T00:00:01.000Z :Alice[m]!u@h PRIVMSG dev[m] :hello",
        &rfc1459,
    )
    .await
    .expect("persist");
    assert_eq!(
        db::rekey_bnc_targets(&pool, &buffer, ascii.casemapping())
            .await
            .expect("rekey"),
        1
    );
    for (time, line) in [
        (2, ":x!u@h PRIVMSG #a[ :square"),
        (3, ":x!u@h PRIVMSG #a{ :curly"),
        (4, ":dev[m]!u@h PRIVMSG Alice[m] :back"),
    ] {
        db::persist_bnc_line(
            &pool,
            &buffer,
            Some("dev[m]"),
            &format!("@time=2026-01-01T00:00:0{time}.000Z {line}"),
            &ascii,
        )
        .await
        .expect("persist");
    }
    let page = async |target: &str| {
        db::bnc_history_window(
            &pool,
            "alice",
            "unreal",
            target,
            ascii.casemapping(),
            db::BncHistoryPaging::Latest,
            db::BncHistoryScope::EveryLine,
            &db::BncHistorySelector::Star,
            &db::BncHistorySelector::Star,
            50,
        )
        .await
        .expect("query")
        .expect("LATEST * has no msgid to miss")
        .into_iter()
        .map(|row| row.line)
        .collect::<Vec<_>>()
    };
    assert_eq!(page("#A[").await.len(), 1);
    assert!(page("#a[").await[0].ends_with(":square"));
    assert!(page("#a{").await[0].ends_with(":curly"));
    assert_eq!(page("ALICE[M]").await.len(), 2, "both directions, one peer");
    assert!(
        page("alice{m}").await.is_empty(),
        "another person on this network"
    );
    let targets: Vec<String> = db::bnc_history_targets(
        &pool,
        "alice",
        "unreal",
        db::BncHistoryScope::EveryLine,
        "0000",
        "9999",
        50,
    )
    .await
    .expect("targets")
    .into_iter()
    .map(|(target, _)| target)
    .collect();
    assert_eq!(targets, ["#a[", "#a{", "Alice[m]"]);
    assert_eq!(
        db::bnc_buffer_casemapping(&pool, "alice", "unreal")
            .await
            .expect("stored mapping"),
        Some(e6irc_proto::casemap::CaseMapping::Ascii)
    );
}

/// A read marker is keyed like the backlog it marks, and follows the network's
/// mapping the same way: markers set before an `ascii` network said so (folded
/// the RFC 1459 way, `#dev[m]` as `#dev{m}`) are found under the network's own
/// keys afterwards, `#a[` and `#a{` keep two positions there, and a change back
/// to RFC 1459 makes the two one conversation at the later position.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn bnc_read_markers_follow_the_networks_case_mapping() {
    use e6irc_proto::casemap::CaseMapping;
    let pool = db::connect_and_migrate(&support::test_db("bnc_read_marker_casemapping").await)
        .await
        .expect("connect");
    db::create_account_with_contact(&pool, "alice", "password", None)
        .await
        .expect("account");
    let set = async |target: &str, mapping: CaseMapping, stamp: &str| {
        let stored = db::set_bnc_read_marker(&pool, "alice", "unreal", target, mapping, stamp)
            .await
            .expect("set marker");
        assert!(matches!(stored, db::BncReadMarkerWrite::Stored(_)));
    };
    let get = async |target: &str, mapping: CaseMapping| {
        db::get_bnc_read_marker(&pool, "alice", "unreal", target, mapping)
            .await
            .expect("get marker")
    };
    // Before the network's 005, as the first attach of a restart is.
    set("#Dev[m]", CaseMapping::Rfc1459, "2026-01-01T00:00:01.000Z").await;
    set("Guest\\~", CaseMapping::Rfc1459, "2026-01-01T00:00:02.000Z").await;
    // The network says it is `ascii`: the markers are its keys now.
    assert_eq!(
        get("#dev[m]", CaseMapping::Ascii).await.as_deref(),
        Some("2026-01-01T00:00:01.000Z")
    );
    assert_eq!(get("#dev{m}", CaseMapping::Ascii).await, None);
    assert_eq!(
        get("GUEST\\~", CaseMapping::Ascii).await.as_deref(),
        Some("2026-01-01T00:00:02.000Z")
    );
    set("#a[", CaseMapping::Ascii, "2026-01-01T00:00:03.000Z").await;
    set("#a{", CaseMapping::Ascii, "2026-01-01T00:00:04.000Z").await;
    let mut listed = db::bnc_read_markers(&pool, "alice", "unreal", CaseMapping::Ascii)
        .await
        .expect("list markers");
    listed.sort();
    assert_eq!(
        listed,
        [
            ("#a[".to_string(), "2026-01-01T00:00:03.000Z".to_string()),
            ("#a{".to_string(), "2026-01-01T00:00:04.000Z".to_string()),
            ("#dev[m]".to_string(), "2026-01-01T00:00:01.000Z".to_string()),
            ("guest\\~".to_string(), "2026-01-01T00:00:02.000Z".to_string()),
        ]
    );
    // Back to RFC 1459: `#a[` and `#a{` are one channel, read to the later
    // of the two positions, and nothing is lost or left under an old key.
    let mut listed = db::bnc_read_markers(&pool, "alice", "unreal", CaseMapping::Rfc1459)
        .await
        .expect("list markers");
    listed.sort();
    assert_eq!(
        listed,
        [
            ("#a{".to_string(), "2026-01-01T00:00:04.000Z".to_string()),
            ("#dev{m}".to_string(), "2026-01-01T00:00:01.000Z".to_string()),
            ("guest|^".to_string(), "2026-01-01T00:00:02.000Z".to_string()),
        ]
    );
    assert_eq!(
        get("#DEV[M]", CaseMapping::Rfc1459).await.as_deref(),
        Some("2026-01-01T00:00:01.000Z")
    );
}

/// Migration 0083 names every stored read marker from what the backlog knows:
/// the spelling and mapping of the newest stored line of its conversation, or,
/// with none left, its own key under the mapping the network last used.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn read_marker_display_migration_backfills_from_the_backlog() {
    let url = support::test_db("read_marker_display_migration").await;
    let pool = sqlx::PgPool::connect(&url).await.expect("connect");
    MIGRATIONS
        .run_to(81, &pool)
        .await
        .expect("migrate through 0081");
    let account: i64 = sqlx::query_scalar(
        "INSERT INTO accounts (name, name_folded) VALUES ('alice', 'alice') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("account");
    sqlx::query(
        "INSERT INTO bnc_buffer (owner, network, line, target, sent_at, target_display,
                                 target_casemapping)
         VALUES ('alice', 'unreal', ':x!u@h PRIVMSG #Dev[m] :hi', '#dev[m]',
                 '2026-01-01T00:00:00.000Z', '#Dev[m]', 'ascii'),
                ('*', 'shared', ':x!u@h PRIVMSG #Ops :hi', '#ops',
                 '2026-01-01T00:00:00.000Z', '#Ops', 'rfc1459')",
    )
    .execute(&pool)
    .await
    .expect("buffer");
    sqlx::query(
        "INSERT INTO bnc_read_markers (account_id, network, target, timestamp)
         VALUES ($1, 'unreal', '#dev[m]', '2026-01-01T00:00:01.000Z'),
                ($1, 'unreal', '#gone[', '2026-01-01T00:00:02.000Z'),
                ($1, 'shared', '#ops', '2026-01-01T00:00:03.000Z'),
                ($1, 'quiet', '#none', '2026-01-01T00:00:04.000Z')",
    )
    .bind(account)
    .execute(&pool)
    .await
    .expect("markers");
    MIGRATIONS.run(&pool).await.expect("migrate");
    let named: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT target, target_display, target_casemapping FROM bnc_read_markers
         ORDER BY network, target",
    )
    .fetch_all(&pool)
    .await
    .expect("markers");
    let named: Vec<(&str, &str, &str)> = named
        .iter()
        .map(|(a, b, c)| (a.as_str(), b.as_str(), c.as_str()))
        .collect();
    assert_eq!(
        named,
        [
            ("#none", "#none", "rfc1459"),
            ("#ops", "#Ops", "rfc1459"),
            ("#dev[m]", "#Dev[m]", "ascii"),
            ("#gone[", "#gone[", "ascii"),
        ]
    );
}

/// Every retained line of one alice/libera target, oldest first.
async fn history_latest(
    pool: &sqlx::PgPool,
    target: &str,
) -> Result<Vec<db::BncHistoryLine>, db::DbError> {
    Ok(db::bnc_history_window(
        pool,
        "alice",
        "libera",
        target,
        e6irc_proto::casemap::CaseMapping::Rfc1459,
        db::BncHistoryPaging::Latest,
        db::BncHistoryScope::EveryLine,
        &db::BncHistorySelector::Star,
        &db::BncHistorySelector::Star,
        500,
    )
    .await?
    .expect("LATEST * has no msgid to miss"))
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn bnc_history_queries_are_target_scoped_and_merge_direct_messages() {
    let pool =
        db::connect_and_migrate(&support::test_db("bnc_history_queries_are_target_scoped").await)
            .await
            .expect("connect");
    db::persist_bnc_line(
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
        "@msgid=shared :a!u@h PRIVMSG #one :first",
        &e6irc_client::NetworkNames::default(),
    )
    .await
    .expect("persist first target");
    db::persist_bnc_line(
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
        "@msgid=shared :a!u@h PRIVMSG #two :second",
        &e6irc_client::NetworkNames::default(),
    )
    .await
    .expect("persist second target");

    let one = history_latest(&pool, "#ONE")
        .await
        .expect("first target history");
    let two = history_latest(&pool, "#two")
        .await
        .expect("second target history");
    assert_eq!(one.len(), 1);
    assert_eq!(two.len(), 1);
    assert_ne!(one[0].id, two[0].id, "each target resolves its own row");
    assert!(
        history_latest(&pool, "#three")
            .await
            .expect("missing target history")
            .is_empty(),
        "a msgid in another target cannot position this page"
    );

    for line in [
        "@msgid=out :alice!u@h PRIVMSG Bob :outbound",
        "@msgid=in :Bob!u@h PRIVMSG alice :inbound",
    ] {
        db::persist_bnc_line(
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
            line,
            &e6irc_client::NetworkNames::default(),
        )
        .await
        .expect("persist direct message");
    }
    let direct = history_latest(&pool, "bOB")
        .await
        .expect("direct-message history");
    assert_eq!(
        direct
            .iter()
            .map(|row| row.msgid.as_deref())
            .collect::<Vec<_>>(),
        vec![Some("out"), Some("in")],
        "both directions must share the correspondent's target"
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
    db::create_account_with_contact(&pool, "boss", "pw", None)
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
    let audit = list_audit_log(&pool, audit_page_size(1))
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
    db::create_account_with_contact(&pool, "boss", "pw", None)
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
    db::create_account_with_contact(&pool, "boss", "pw", None)
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
    assert_eq!(
        db::set_channel_keeptopic(&pool, "#c", false, None, "boss")
            .await
            .expect("off"),
        Ok(())
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
    assert_eq!(
        db::set_channel_keeptopic(
            &pool,
            "#c",
            true,
            Some(("current".into(), "boss!b@h".into(), 2000)),
            "boss"
        )
        .await
        .expect("on"),
        Ok(())
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
    assert_eq!(
        db::set_channel_keeptopic(&pool, "#missing", true, None, "boss")
            .await
            .expect("missing option row"),
        Err(db::ChannelRefusal::ChannelMissing)
    );
    // Only the founder may change it: the check runs with the row locked.
    assert_eq!(
        db::set_channel_keeptopic(&pool, "#c", false, None, "mallory")
            .await
            .expect("not founder"),
        Err(db::ChannelRefusal::NotFounder)
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
    db::create_account_with_contact(&pool, "boss", "pw", None)
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
        db::set_channel_mlock(&pool, "#c", Some("+tn-i".into()), "boss")
            .await
            .is_err()
    );
    for noncanonical in ["+-i", "+i-i"] {
        assert!(
            db::set_channel_mlock(&pool, "#c", Some(noncanonical.into()), "boss")
                .await
                .is_err(),
            "database accepted non-canonical MLOCK {noncanonical}"
        );
    }

    // Only the founder may change it: the check runs with the row locked.
    assert_eq!(
        db::set_channel_mlock(&pool, "#c", Some("+nt-i".into()), "mallory")
            .await
            .expect("not founder"),
        Err(db::ChannelRefusal::NotFounder)
    );

    // Canonical set → loads back with the same spec.
    assert_eq!(
        db::set_channel_mlock(&pool, "#c", Some("+nt-i".into()), "boss")
            .await
            .expect("set"),
        Ok(())
    );
    assert_eq!(
        db::list_channel_mlock(&pool).await.expect("list"),
        vec![("#c".to_string(), "+nt-i".to_string())]
    );

    // Clear → it no longer loads.
    assert_eq!(
        db::set_channel_mlock(&pool, "#c", None, "boss")
            .await
            .expect("clear"),
        Ok(())
    );
    assert!(
        db::list_channel_mlock(&pool)
            .await
            .expect("list")
            .is_empty()
    );
    assert_eq!(
        db::set_channel_mlock(&pool, "#missing", Some("+m".into()), "boss")
            .await
            .expect("missing row"),
        Err(db::ChannelRefusal::ChannelMissing)
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

/// 0057 states the user name every existing IRC network has been sending: the
/// old derivation (the first ten bytes of the nick), repaired only where the
/// grammar no longer admits it. A network that worked keeps its identity; new
/// configuration still gets no default.
/// Migration 0061 adds the server password as a nullable sealed column: every
/// network that existed keeps working without one, and only an IRC network
/// can ever hold one.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn server_password_migration_adds_a_sealed_column_only_irc_may_fill() {
    let pool = sqlx::PgPool::connect(
        &support::test_db("server_password_migration_adds_a_sealed_column").await,
    )
    .await
    .expect("connect");
    MIGRATIONS
        .run_to(60, &pool)
        .await
        .expect("migrate through 0060");
    let account: i64 = sqlx::query_scalar(
        "INSERT INTO accounts (name, name_folded) VALUES ('owner', 'owner') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("account");
    sqlx::query(
        "INSERT INTO bnc_networks (account_id, name, addr, nick, username, kind)
         VALUES ($1, 'private', 'irc.example:6697', 'alice', 'alice', 'irc'),
                ($1, 'bridge', '', '', NULL, 'discord')",
    )
    .bind(account)
    .execute(&pool)
    .await
    .expect("networks before 0061");
    MIGRATIONS.run(&pool).await.expect("migrate to latest");

    let stored: Vec<Option<String>> =
        sqlx::query_scalar("SELECT server_password_sealed FROM bnc_networks ORDER BY name")
            .fetch_all(&pool)
            .await
            .expect("read column");
    assert_eq!(stored, [None, None], "nothing is backfilled");
    sqlx::query(
        "UPDATE bnc_networks SET server_password_sealed = 'enc:v2:x' WHERE name = 'private'",
    )
    .execute(&pool)
    .await
    .expect("an IRC network may hold one");
    let bridge = sqlx::query(
        "UPDATE bnc_networks SET server_password_sealed = 'enc:v2:x' WHERE name = 'bridge'",
    )
    .execute(&pool)
    .await;
    assert!(bridge.is_err(), "a bridge sends no PASS: {bridge:?}");
}

/// The server password is stored sealed under the owner's context, read back
/// by every network query, and resealed by key rotation's reader like the
/// SASL password.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn a_sealed_server_password_round_trips_through_every_network_query() {
    let pool =
        db::connect_and_migrate(&support::test_db("sealed_server_password_round_trip").await)
            .await
            .expect("connect");
    db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("acct");
    let keyring = e6ircd::secret::SecretKeyring::single(e6ircd::secret::SecretKey::generate());
    let sealed = keyring.seal("open sesame", &e6ircd::bouncer::bnc_secret_context("alice"));
    assert!(!sealed.contains("open sesame"));
    let network = db::BncNetworkRow {
        kind: NetworkKind::Irc,
        name: "private".into(),
        addr: "irc.example:6697".into(),
        tls: true,
        nick: "alice".into(),
        username: Some("alice".into()),
        realname: Some("Alice".into()),
        autojoin: vec![],
        sasl_account: None,
        sasl_password_sealed: None,
        server_password_sealed: Some(sealed.clone()),
        enabled: true,
    };
    db::create_bnc_network(
        &pool,
        "alice",
        &network,
        e6ircd::db::NetworkAudit {
            actor: "alice",
            detail: "",
        },
    )
    .await
    .expect("create");
    let listed = db::list_bnc_networks(&pool, "alice").await.expect("list");
    let got = db::get_bnc_network(&pool, "alice", "private")
        .await
        .expect("get")
        .expect("network");
    let inventory = db::list_bnc_network_inventory(&pool)
        .await
        .expect("inventory");
    let startable = db::list_startable_bnc_networks(&pool)
        .await
        .expect("startable");
    for (query, value) in [
        ("list", &listed[0].server_password_sealed),
        ("get", &got.server_password_sealed),
        ("inventory", &inventory[0].network.server_password_sealed),
        ("startable", &startable[0].1.server_password_sealed),
    ] {
        assert_eq!(value.as_deref(), Some(sealed.as_str()), "{query}");
    }
    assert_eq!(
        keyring
            .open(&sealed, &e6ircd::bouncer::bnc_secret_context("alice"))
            .expect("opens under the owner's context"),
        "open sesame"
    );
    assert!(
        keyring
            .open(&sealed, &e6ircd::bouncer::bnc_secret_context("mallory"))
            .is_err(),
        "a blob cannot be opened for another account"
    );

    let mut removed = network.clone();
    removed.server_password_sealed = None;
    assert!(
        db::update_bnc_network(
            &pool,
            "alice",
            "private",
            &removed,
            e6ircd::db::NetworkAudit {
                actor: "alice",
                detail: ""
            }
        )
        .await
        .expect("update")
    );
    assert_eq!(
        db::get_bnc_network(&pool, "alice", "private")
            .await
            .expect("get")
            .expect("network")
            .server_password_sealed,
        None
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn username_migration_backfills_what_each_network_was_already_sending() {
    let pool = sqlx::PgPool::connect(
        &support::test_db("username_migration_backfills_what_each_network_was_sending").await,
    )
    .await
    .expect("connect");
    MIGRATIONS
        .run_to(56, &pool)
        .await
        .expect("migrate through 0056");
    let cases = [
        ("alice", "alice"),
        ("alice_updated", "alice_upda"),
        ("_bot", "bot"),
        ("|me|", "me"),
        ("[away]x", "awayx"),
        ("a.b`c", "abc"),
        ("zoë-ß", "zo-"),
        ("ééééééééééx", "e6irc"),
        ("___", "e6irc"),
    ];
    let account: i64 = sqlx::query_scalar(
        "INSERT INTO accounts (name, name_folded) VALUES ('owner', 'owner') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("legacy account");
    for (index, (nick, _)) in cases.iter().enumerate() {
        sqlx::query(
            "INSERT INTO bnc_networks (account_id, name, addr, nick, kind)
             VALUES ($1, $2, 'irc.example:6697', $3, 'irc')",
        )
        .bind(account)
        .bind(format!("irc{index}"))
        .bind(nick)
        .execute(&pool)
        .await
        .expect("legacy irc network");
    }
    sqlx::query(
        "INSERT INTO bnc_networks (account_id, name, addr, nick, kind)
         VALUES ($1, 'bridge', '', '', 'discord')",
    )
    .bind(account)
    .execute(&pool)
    .await
    .expect("legacy bridge");

    let managed = e6ircd::config::ManagedConfig::from_config(&Config::default(), None)
        .expect("bootstrap managed settings");
    let mut settings = serde_json::to_value(managed).expect("serialize managed settings");
    settings
        .as_object_mut()
        .expect("managed settings object")
        .retain(|field, _| MANAGED_CONFIG_0052_FIELDS.contains(&field.as_str()));
    let legacy_entry = |kind: &str, name: &str, nick: &str| {
        serde_json::json!({
            "name": name, "kind": kind, "owner": null, "addr": "irc.example:6697",
            "tls": true, "nick": nick, "realname": "Real", "autojoin": [],
            "buffer_cap": 1000, "sasl_account": null, "sasl_password": null
        })
    };
    let mut stated = legacy_entry("irc", "stated", "_bot");
    stated["username"] = "chosen".into();
    settings["networks"] = serde_json::json!([
        legacy_entry("irc", "legacy-irc", "_bot"),
        legacy_entry("local", "legacy-local", "alice_updated"),
        stated,
    ]);
    settings["oidc_providers"] = serde_json::json!([]);
    sqlx::query(
        "INSERT INTO server_settings (singleton, revision, settings, updated_by)
         VALUES (TRUE, 1, $1, 'legacy')",
    )
    .bind(settings)
    .execute(&pool)
    .await
    .expect("legacy settings");

    MIGRATIONS.run(&pool).await.expect("migrate current");

    let stored: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT nick, username FROM bnc_networks ORDER BY id")
            .fetch_all(&pool)
            .await
            .expect("backfilled networks");
    let mut expected: Vec<(String, Option<String>)> = cases
        .iter()
        .map(|(nick, username)| (nick.to_string(), Some(username.to_string())))
        .collect();
    expected.push((String::new(), None));
    assert_eq!(stored, expected);
    for (_, username) in &stored {
        if let Some(username) = username {
            username
                .parse::<e6ircd::bouncer::UpstreamUsername>()
                .unwrap_or_else(|error| panic!("backfilled {username:?}: {error}"));
        }
    }
    // A bridge cannot be given a user name, nor an IRC network lose its own.
    for violation in [
        "UPDATE bnc_networks SET username = 'x' WHERE kind = 'discord'",
        "UPDATE bnc_networks SET username = NULL WHERE kind = 'irc'",
    ] {
        assert!(
            sqlx::query(violation).execute(&pool).await.is_err(),
            "{violation}"
        );
    }

    let loaded = db::load_managed_config(&pool)
        .await
        .expect("typed settings after migration");
    assert_eq!(
        loaded
            .settings
            .networks
            .iter()
            .map(|network| (network.name.as_str(), network.username.as_deref()))
            .collect::<Vec<_>>(),
        [
            ("legacy-irc", Some("bot")),
            ("legacy-local", Some("alice_upda")),
            ("stated", Some("chosen")),
        ]
    );

    let before: serde_json::Value =
        sqlx::query_scalar("SELECT settings FROM server_settings WHERE singleton")
            .fetch_one(&pool)
            .await
            .expect("migrated settings");
    sqlx::raw_sql(include_str!(
        "../../../migrations/0057_bnc_network_username.sql"
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
    let repeated: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT nick, username FROM bnc_networks ORDER BY id")
            .fetch_all(&pool)
            .await
            .expect("repeated networks");
    assert_eq!(repeated, stored);
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
    db::create_account_with_contact(&pool, "boss", "pw", None)
        .await
        .expect("boss");
    db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("alice");
    sqlx::query(
        "INSERT INTO channels (name, name_folded, founder_account_id)
         SELECT '#c', '#c', id FROM accounts WHERE name_folded = 'boss'",
    )
    .execute(&pool)
    .await
    .expect("channel");

    let applied = db::set_channel_access(&pool, "#c", "alice", Some("ov".into()), "boss")
        .await
        .expect("set");
    assert_eq!(
        applied,
        db::AccessChange::Applied {
            account: "alice".into(),
            previous: None,
        },
        "granting a registered account must apply"
    );
    assert_eq!(
        db::list_channel_access(&pool).await.expect("list"),
        vec![("#c".to_string(), "alice".to_string(), "ov".to_string())]
    );

    // Granting to an account that isn't registered writes no row and reports
    // that nothing applied — the caller must not create a hot entry for it.
    let phantom = db::set_channel_access(&pool, "#c", "ghost", Some("o".into()), "boss")
        .await
        .expect("phantom grant");
    assert_eq!(
        phantom,
        db::AccessChange::AccountMissing,
        "granting an unregistered account must not apply"
    );
    assert_eq!(
        db::list_channel_access(&pool).await.expect("list"),
        vec![("#c".to_string(), "alice".to_string(), "ov".to_string())],
        "phantom grant leaked a row"
    );

    // Only the founder changes the list, checked with the row locked.
    assert_eq!(
        db::set_channel_access(&pool, "#c", "alice", None, "alice")
            .await
            .expect("not founder"),
        db::AccessChange::Refused(db::ChannelRefusal::NotFounder)
    );

    let cleared = db::set_channel_access(&pool, "#c", "alice", None, "boss")
        .await
        .expect("clear");
    assert_eq!(
        cleared,
        db::AccessChange::Applied {
            account: "alice".into(),
            previous: Some("ov".into()),
        },
        "clearing reports what the entry held"
    );
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
        db::create_account_with_contact(&pool, account, "pw", None)
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
        ChannelControlResult::Applied { account: None }
    );
    for (mutation, account) in [
        (
            PersistedChannelMutation::SetMlock {
                mlock: Some("+nt-i".into()),
            },
            None,
        ),
        (
            PersistedChannelMutation::SetAccess {
                account: "alice".into(),
                flags: Some("ov".into()),
            },
            Some("alice".to_string()),
        ),
    ] {
        assert_eq!(
            db::persist_owned_channel_mutation(&pool, "#control", "boss", &mutation)
                .await
                .expect("mutation"),
            ChannelControlResult::Applied { account }
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
        ChannelControlResult::Applied { account: None }
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
        ChannelControlResult::Applied {
            account: Some("alice".into())
        }
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
    let audit = list_audit_log(&pool, audit_page_size(20))
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
    db::create_account_with_contact(&pool, "boss", "pw", None)
        .await
        .expect("boss");
    db::create_account_with_contact(&pool, "alice", "pw", None)
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

    // Someone who does not found the channel cannot transfer it.
    assert_eq!(
        db::set_channel_founder(&pool, "#c", "alice", "alice")
            .await
            .expect("transfer"),
        db::FounderTransfer::Refused(db::ChannelRefusal::NotFounder)
    );

    // Transfer to an existing account succeeds and moves ownership.
    assert_eq!(
        db::set_channel_founder(&pool, "#c", "alice", "boss")
            .await
            .expect("transfer"),
        db::FounderTransfer::Transferred {
            founder: "alice".into()
        }
    );
    assert_eq!(
        db::list_registered_channels(&pool).await.expect("list"),
        vec![("#c".to_string(), "alice".to_string())]
    );

    // The former founder cannot transfer it any more: the check is made with
    // the row locked, whatever the core believed when it queued the request.
    assert_eq!(
        db::set_channel_founder(&pool, "#c", "boss", "boss")
            .await
            .expect("transfer"),
        db::FounderTransfer::Refused(db::ChannelRefusal::NotFounder)
    );

    // Transfer to a nonexistent account fails and leaves ownership intact.
    assert_eq!(
        db::set_channel_founder(&pool, "#c", "nobody", "alice")
            .await
            .expect("transfer"),
        db::FounderTransfer::AccountMissing
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
        set_by: "godnick".into(),
        kind: "kline".into(),
    };
    // The operator block `god`, using the nick `godnick`: STATS shows the
    // nick, the audit trail the operator.
    let requester = e6ircd::core::ServerBanRequester::Oper {
        session: e6ircd::core::CoreShardCount::single().session_owner(conn),
        label: None,
        operator: "god".into(),
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
            "godnick".to_string(),
            "kline".to_string(),
        )]
    );
    let kinds: (String, String) =
        sqlx::query_as("SELECT actor_kind, target_kind FROM audit_log WHERE action = 'KLINE'")
            .fetch_one(&pool)
            .await
            .expect("kinds");
    assert_eq!(kinds, ("operator".to_string(), "mask".to_string()));
    let audit = list_audit_log(&pool, audit_page_size(10))
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
    let audit = list_audit_log(&pool, audit_page_size(10))
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

    add_server_ban(&pool, "baddie@*", "baddie@*", "spam", "god", "kline")
        .await
        .expect("add1");
    add_server_ban(
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
    add_server_ban(&pool, "baddie@*", "baddie@*", "gecos", "god", "xline")
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
    add_server_ban(&pool, "baddie@*", "baddie@*", "spam again", "root", "kline")
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
    assert!(
        db::mutate_server_ban_audited(
            &pool,
            &e6ircd::core::ServerBanMutation::Remove {
                expected_id: None,
                mask: "baddie@*".into(),
                mask_display: "baddie@*".into(),
                kind: "kline".into(),
                actor: "god".into(),
            },
            &e6ircd::db::AuditPrincipal::operator("god"),
        )
        .await
        .expect("remove"),
        "the K-line existed"
    );
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
    db::insert_audit_log(
        &pool,
        &e6ircd::db::AuditPrincipal::operator("god"),
        "OPER",
        &e6ircd::db::AuditPrincipal::operator("god"),
        "",
    )
    .await
    .expect("a1");
    db::insert_audit_log(
        &pool,
        &e6ircd::db::AuditPrincipal::account("god"),
        "KLINE",
        &e6ircd::db::AuditPrincipal::mask("baddie@*"),
        "spam",
    )
    .await
    .expect("a2");
    let list = list_audit_log(&pool, audit_page_size(10))
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
        db::create_account_with_contact(&pool, name, "pw", None)
            .await
            .unwrap_or_else(|error| panic!("create {name}: {error}"));
    }
    db::issue_app_password_for_account(&pool, "Alice", "desktop")
        .await
        .expect("app password");
    issue_api_token(&pool, "Alice", "active")
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
             INSERT INTO bnc_networks (account_id, name, addr, nick, username, kind)
             SELECT id, 'local', '', 'Alice', 'alice', 'irc' FROM account
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

    db::create_account_with_contact(&pool, "Dave", "pw", None)
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
        db::create_account_with_contact(&pool, name, "pw", None)
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
        add_server_ban(&pool, mask, display, reason, setter, kind)
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
        db::insert_audit_log(
            &pool,
            &e6ircd::db::AuditPrincipal::account(actor),
            action,
            &seeded_target(action, target),
            detail,
        )
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

    db::insert_audit_log(
        &pool,
        &e6ircd::db::AuditPrincipal::operator("bob"),
        "OPER",
        &e6ircd::db::AuditPrincipal::operator("bob"),
        "concurrent",
    )
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

    let saved = db::save_managed_config(
        &pool,
        initial.revision,
        &changed,
        &db::AuditPrincipal::account("alice"),
        "first update",
    )
    .await
    .expect("save current revision");
    let stale = db::save_managed_config(
        &pool,
        initial.revision,
        &initial.settings,
        &db::AuditPrincipal::account("bob"),
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
    let audit = list_audit_log(&pool, audit_page_size(10))
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
    db::create_account_with_contact(&pool, "alice", "pw", None)
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
        username: None,
        realname: None,
        autojoin: vec!["C123".into()],
        buffer_cap: 100,
        sasl_account: Some(old.seal("xoxb-old", CONFIG_CONTEXT)),
        sasl_password: Some(old.seal("xapp-old", CONFIG_CONTEXT)),
        server_password: None,
    });
    managed.networks.push(NetworkEntry {
        name: "private-shared".into(),
        kind: NetworkKind::Irc,
        owner: None,
        addr: "irc.example:6697".into(),
        tls: true,
        nick: "shared".into(),
        username: Some("shared".into()),
        realname: Some("Shared".into()),
        autojoin: vec![],
        buffer_cap: 100,
        sasl_account: None,
        sasl_password: None,
        server_password: Some(old.seal("managed-pass", CONFIG_CONTEXT)),
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
        username: None,
        realname: None,
        autojoin: vec!["C456".into()],
        sasl_account: Some(old.seal("xoxb-account", &owner_context)),
        sasl_password_sealed: Some(old.seal("xapp-account", &owner_context)),
        enabled: false,
        server_password_sealed: None,
    };
    db::create_bnc_network(
        &pool,
        "alice",
        &account_network,
        e6ircd::db::NetworkAudit {
            actor: "alice",
            detail: "",
        },
    )
    .await
    .expect("account network");
    let private_network = db::BncNetworkRow {
        kind: NetworkKind::Irc,
        name: "private".into(),
        addr: "irc.example:6697".into(),
        tls: true,
        nick: "alice".into(),
        username: Some("alice".into()),
        realname: Some("Alice".into()),
        autojoin: vec![],
        sasl_account: None,
        sasl_password_sealed: None,
        server_password_sealed: Some(old.seal("account-pass", &owner_context)),
        enabled: false,
    };
    db::create_bnc_network(
        &pool,
        "alice",
        &private_network,
        e6ircd::db::NetworkAudit {
            actor: "alice",
            detail: "",
        },
    )
    .await
    .expect("private account network");

    let new = SecretKey::generate();
    let new_base64 = new.to_base64();
    let keys = SecretKeyring::new(new, vec![old]).unwrap();
    let report = db::rotate_database_secrets(&pool, &keys, "operator")
        .await
        .expect("rotate");
    assert_eq!(
        report,
        db::SecretRotationReport {
            managed_config_secrets: 5,
            account_network_secrets: 3,
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
    let rotated_private = db::get_bnc_network(&pool, "alice", "private")
        .await
        .expect("network query")
        .expect("network");
    assert_eq!(
        new_verifier
            .open(
                rotated_private.server_password_sealed.as_deref().unwrap(),
                &owner_context,
            )
            .unwrap(),
        "account-pass",
        "an account network's server password is resealed"
    );
    let managed_pass = rotated.settings.networks[1]
        .server_password
        .as_deref()
        .unwrap();
    assert_eq!(
        new_verifier.open(managed_pass, CONFIG_CONTEXT).unwrap(),
        "managed-pass",
        "a managed network's server password is resealed"
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
    let audit = list_audit_log(&pool, audit_page_size(10))
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
    db::create_account_with_contact(&pool, "alice", "pw", None)
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
            username: Some("tester".into()),
            realname: Some("Alice".into()),
            autojoin: Vec::new(),
            sasl_account: Some("alice".into()),
            sasl_password_sealed: Some("enc:v2:not-base64".into()),
            enabled: false,
            server_password_sealed: None,
        },
        e6ircd::db::NetworkAudit {
            actor: "alice",
            detail: "",
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
    // Alice's self-registration and her network's creation are the only
    // audit entries: the rotation's success row was rolled back with it.
    assert!(
        list_audit_log(&pool, audit_page_size(10))
            .await
            .expect("audit")
            .iter()
            .all(|entry| matches!(entry.action.as_str(), "ACCOUNT_CREATE" | "NETWORK_CREATE")),
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
    db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("alice");
    db::create_account_with_contact(&pool, "bob", "pw", None)
        .await
        .expect("bob");

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
    // A suspended account cannot gain a login identity.
    let bob_id = db::account_id_by_name(&pool, "bob")
        .await
        .expect("bob id")
        .expect("bob exists");
    db::set_account_suspended(&pool, bob_id, true, "alice", &[])
        .await
        .expect("suspend bob");
    assert!(matches!(
        db::link_oidc_identity(&pool, "bob", "https://idp.example", "sub-9").await,
        Err(db::DbError::BadCredentials)
    ));
    db::set_account_suspended(&pool, bob_id, false, "alice", &[])
        .await
        .expect("reactivate bob");

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
    db::create_account_with_contact(&pool, "alice", "pw", None)
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
    db::create_account_with_contact(&pool, "alice", "pw", None)
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
        db::revoke_oidc_frontchannel_sessions(
            &pool,
            "https://auth.example",
            "second-session",
            Some(&first),
        )
        .await
        .expect("front-channel logout"),
        db::FrontchannelRevocation {
            revoked: 1,
            presented_session_revoked: false,
        },
        "a cookie naming another session is not one this logout revoked"
    );
    assert_eq!(
        db::session_account(&pool, &second).await.expect("second"),
        None
    );
    let third = db::create_web_session_with_identity(
        &pool,
        "alice",
        db::OidcSessionIdentity {
            id_token: Some("third.id.token"),
            provider: Some("shauth"),
            issuer: Some("https://auth.example"),
            subject: Some("alice-subject"),
            sid: Some("third-session"),
            email: Some("alice@example.test"),
            role: Some("developer"),
        },
        None,
    )
    .await
    .expect("third session");
    assert_eq!(
        db::revoke_oidc_frontchannel_sessions(
            &pool,
            "https://auth.example",
            "third-session",
            Some(&third),
        )
        .await
        .expect("front-channel logout"),
        db::FrontchannelRevocation {
            revoked: 1,
            presented_session_revoked: true,
        }
    );
    assert_eq!(
        db::revoke_oidc_frontchannel_sessions(&pool, "https://auth.example", "unknown-sid", None)
            .await
            .expect("front-channel logout"),
        db::FrontchannelRevocation {
            revoked: 0,
            presented_session_revoked: false,
        }
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn history_read_authorization_is_scoped() {
    let pool =
        db::connect_and_migrate(&support::test_db("history_read_authorization_is_scoped").await)
            .await
            .expect("connect");
    db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("alice");
    db::create_account_with_contact(&pool, "bob", "pw", None)
        .await
        .expect("bob");
    db::create_account_with_contact(&pool, "carol", "pw", None)
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
    assert!(matches!(
        db::set_channel_access(&pool, "#chan", "bob", Some("v".into()), "alice")
            .await
            .expect("grant"),
        db::AccessChange::Applied { .. }
    ));
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
    // A grant expired past the grace period, as a never-approved /device/start
    // flood leaves.
    sqlx::query(
        "INSERT INTO device_grants (device_code, user_code, expires_at)
         VALUES ('dead', 'DEADDEAD', now() - interval '1 day')",
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
    db::create_account_with_contact(&pool, "devacct", "pw", None)
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
    assert_eq!(
        db::approve_device_grant(&pool, "USERCODE1", "devacct")
            .await
            .expect("approve"),
        db::DeviceApproval::Approved,
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

/// The per-account token cap has no side door: a device grant mints through
/// the same capped path the REST endpoint uses. Over the cap the approving
/// browser is told so, and a grant approved before the cap was reached is
/// consumed and denied at the poll — the device is never left polling.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn device_grants_mint_under_the_per_account_token_cap() {
    let pool = db::connect_and_migrate(
        &support::test_db("device_grants_mint_under_the_per_account_token_cap").await,
    )
    .await
    .expect("connect");
    db::create_account_with_contact(&pool, "devacct", "pw", None)
        .await
        .expect("create account");
    let mint = |label: String| {
        let pool = pool.clone();
        async move {
            db::issue_scoped_api_token(
                &pool,
                "devacct",
                &label,
                e6ircd::identity::ApiTokenScopes::new(e6ircd::identity::ApiTokenScope::ALL)
                    .expect("every scope is a non-empty set"),
                e6ircd::identity::ApiTokenLifetimeDays::DEFAULT,
            )
            .await
        }
    };
    for index in 0..31 {
        mint(format!("token {index}")).await.expect("under the cap");
    }

    // Approved with one slot left, which is then taken before the device polls.
    let (raced_device, raced_user) = db::create_device_grant(&pool).await.expect("grant");
    assert_eq!(
        db::approve_device_grant(&pool, &raced_user, "devacct")
            .await
            .expect("approve"),
        db::DeviceApproval::Approved
    );
    mint("token 31".into()).await.expect("the last slot");

    // At the cap, approval is refused where a person can read why.
    let (refused_device, refused_user) = db::create_device_grant(&pool).await.expect("grant");
    assert_eq!(
        db::approve_device_grant(&pool, &refused_user, "devacct")
            .await
            .expect("approve at the cap"),
        db::DeviceApproval::TokenLimitReached
    );
    assert_eq!(
        db::poll_device_grant(&pool, &refused_device, "device")
            .await
            .expect("poll"),
        db::DeviceStatus::Pending,
        "a refused approval leaves the grant for another account or a later try"
    );

    // The grant approved earlier cannot mint past the cap, and says so once.
    assert_eq!(
        db::poll_device_grant(&pool, &raced_device, "device")
            .await
            .expect("poll"),
        db::DeviceStatus::Denied
    );
    assert_eq!(
        db::poll_device_grant(&pool, &raced_device, "device")
            .await
            .expect("poll again"),
        db::DeviceStatus::Unknown,
        "a denied grant is consumed"
    );
    let tokens: i64 = sqlx::query_scalar("SELECT count(*) FROM api_tokens")
        .fetch_one(&pool)
        .await
        .expect("count tokens");
    assert_eq!(tokens, 32, "no minting path exceeds the cap");
    let denied: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action = 'ACCOUNT_DEVICE_TOKEN_DENIED'",
    )
    .fetch_one(&pool)
    .await
    .expect("audit");
    assert_eq!(denied, 1, "the denial is on the record");
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
            db::persist_bnc_line(
                &pool,
                &e6ircd::db::open_bnc_buffer(
                    &pool,
                    Some("owner"),
                    network,
                    e6ircd::db::BncNetworkDefinition::Configured,
                )
                .await
                .expect("open buffer"),
                None,
                &format!("line {i}"),
                &e6irc_client::NetworkNames::default(),
            )
            .await
            .expect("persist");
        }
    }
    let alpha = db::open_bnc_buffer(
        &pool,
        Some("owner"),
        "alpha",
        db::BncNetworkDefinition::Configured,
    )
    .await
    .expect("open buffer");
    db::trim_bnc_buffer(&pool, &alpha).await.expect("trim");

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
    db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("alice");
    db::create_account_with_contact(&pool, "bob", "pw", None)
        .await
        .expect("bob");

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
    db::create_account_with_contact(&pool, "alice", "pw", None)
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
    let bob_id = db::create_account_with_contact(&pool, "Bob", "bob password", None)
        .await
        .expect("Bob");
    let session = db::create_web_session(&pool, "Bob", None)
        .await
        .expect("browser session");
    let token = issue_api_token(&pool, "Bob", "automation")
        .await
        .expect("personal access token");
    let (device_code, user_code) = db::create_device_grant(&pool).await.expect("device grant");
    assert_eq!(
        db::approve_device_grant(&pool, &user_code, "Bob")
            .await
            .expect("approve device"),
        db::DeviceApproval::Approved
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
        issue_api_token(&pool, "Bob", "forbidden").await,
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

/// Whether the account row itself carries administrator authority — what the
/// server reads on every request.
async fn is_durable_administrator(pool: &sqlx::PgPool, account: &str) -> bool {
    db::account_flags(pool, account)
        .await
        .expect("account flags")
        .expect("account exists")
        .is_admin()
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
    let bob_id =
        db::create_account_with_contact(&pool, "Bob", "second administrator password", None)
            .await
            .expect("Bob");
    let carol_id =
        db::create_account_with_contact(&pool, "Carol", "configured administrator password", None)
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
    assert!(is_durable_administrator(&pool, "alice").await);
    assert!(is_durable_administrator(&pool, "bob").await);

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
    assert!(is_durable_administrator(&pool, "alice").await);
    assert!(!is_durable_administrator(&pool, "bob").await);
    let configured = ["carol".to_string()];
    db::set_account_suspended(&pool, alice_id, true, "Bob", &configured)
        .await
        .expect("configured Carol preserves effective authority")
        .expect("Alice");
    db::set_account_administrator(&pool, alice_id, false, "Bob", &configured)
        .await
        .expect("configured Carol permits durable succession")
        .expect("Alice");
    assert!(!is_durable_administrator(&pool, "alice").await);
    assert!(!is_durable_administrator(&pool, "bob").await);
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

    let account = db::accept_account_invitation(&pool, &token, "invited password", &[])
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
        db::accept_account_invitation(&pool, &token, "other password", &[]).await,
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
    let bob_id = db::create_account_with_contact(&pool, "Bob", "member password", None)
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
    assert!(matches!(
        db::set_channel_founder(&pool, "#bob", "alice", "Bob")
            .await
            .expect("transfer"),
        db::FounderTransfer::Transferred { .. }
    ));
    let session = db::create_web_session(&pool, "Bob", None)
        .await
        .expect("session");
    let api_token = issue_api_token(&pool, "Bob", "automation")
        .await
        .expect("token");
    sqlx::query(
        "INSERT INTO bnc_networks (account_id, name, addr, nick, username)
         VALUES ($1, 'libera', 'irc.libera.chat:6697', 'Bob', 'bob')",
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
    // A BNC MARKREAD leaves a marker row that references the account.
    sqlx::query(
        "INSERT INTO bnc_read_markers
             (account_id, network, target, timestamp, target_display, target_casemapping)
         VALUES ($1, 'libera', '#rust', '2026-01-01T00:00:00.000Z', '#rust', 'rfc1459')",
    )
    .bind(bob_id)
    .execute(&pool)
    .await
    .expect("bouncer read marker");
    // The core stamps a message with the sender's account as the session
    // holds it — the display name — while conversation peers are casefolded.
    sqlx::query(
        "INSERT INTO messages
            (msgid, target, sender_prefix, sender_account, kind, body, ts, dm_peers)
         VALUES
            ('bob-sent', '#test', 'Bob!u@h', 'Bob', 'privmsg', 'sent', now(), NULL),
            ('bob-dm', 'alice!bob', 'Alice!u@h', 'Alice', 'privmsg', 'private',
             now(), ARRAY['alice', 'bob'])",
    )
    .execute(&pool)
    .await
    .expect("messages");
    let (_device_code, user_code) = db::create_device_grant(&pool).await.expect("device");
    assert_eq!(
        db::approve_device_grant(&pool, &user_code, "Bob")
            .await
            .expect("approve"),
        db::DeviceApproval::Approved
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
    let residues: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
            (SELECT count(*) FROM bnc_buffer WHERE owner = 'bob'),
            (SELECT count(*) FROM messages
             WHERE sender_account IN ('Bob', 'bob') OR dm_peers @> ARRAY['bob']),
            (SELECT count(*) FROM device_grants g JOIN accounts a ON a.id = g.account_id
              WHERE a.name = 'Bob'),
            (SELECT count(*) FROM bnc_read_markers WHERE account_id = $1)",
    )
    .bind(bob_id)
    .fetch_one(&pool)
    .await
    .expect("residues");
    assert_eq!(residues, (0, 0, 0, 0));
    assert!(matches!(
        db::create_account_with_contact(&pool, "bOB", "new owner", None).await,
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
    db::create_account_with_contact(&pool, "Dana", "administrator candidate", None)
        .await
        .expect("Dana");
    let target = db::account_deletion_target(&pool, alice_id, &["alice".into(), "dana".into()])
        .await
        .expect("effective administrator check")
        .expect("a second existing active configuration-backed administrator is a recovery path");
    assert!(!target.suspended);
    sqlx::query("UPDATE accounts SET flags = 2 WHERE id = $1")
        .bind(alice_id)
        .execute(&pool)
        .await
        .expect("suspend Alice");
    // A deletion that does not commit must leave this suspension standing.
    assert!(
        db::account_deletion_target(&pool, alice_id, &["alice".into(), "dana".into()])
            .await
            .expect("suspended target")
            .expect("Alice")
            .suspended
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
    db::create_account_with_contact(&pool, "Bob", "other password", None)
        .await
        .expect("Bob");
    let session = db::create_web_session(&pool, "Alice", None)
        .await
        .expect("session");
    let bearer = issue_api_token(&pool, "Alice", "secret-token-label")
        .await
        .expect("token");
    sqlx::query(
        "INSERT INTO bnc_networks
            (account_id, name, addr, tls, nick, username, sasl_account, sasl_password_sealed,
             server_password_sealed)
         VALUES ($1, 'libera', 'irc.libera.chat:6697', true, 'Alice', 'alice',
                 'alice', 'enc:v1:must-not-export', 'enc:v2:server-password-must-not-export')",
    )
    .bind(alice_id)
    .execute(&pool)
    .await
    .expect("network");
    sqlx::query(
        "INSERT INTO bnc_read_markers
             (account_id, network, target, timestamp, target_display, target_casemapping)
         VALUES ($1, 'libera', '#rust', '2026-01-01T00:00:00.000Z', '#rust', 'rfc1459')",
    )
    .bind(alice_id)
    .execute(&pool)
    .await
    .expect("bouncer read marker");
    // Stored as the core stores it: the sender's display name.
    sqlx::query(
        "INSERT INTO messages (msgid, target, sender_prefix, sender_account, kind, body, ts)
         VALUES ('alice-sent', '#test', 'Alice!u@h', 'Alice', 'privmsg', 'hello room', now())",
    )
    .execute(&pool)
    .await
    .expect("message");
    db::insert_audit_log(
        &pool,
        &e6ircd::db::AuditPrincipal::account("bob"),
        "ACCOUNT_SUSPEND",
        &e6ircd::db::AuditPrincipal::account("alice"),
        "",
    )
    .await
    .expect("admin event");
    db::insert_audit_log(
        &pool,
        &e6ircd::db::AuditPrincipal::account("bob"),
        "OTHER_EVENT",
        &e6ircd::db::AuditPrincipal::account("bob"),
        "private to Bob",
    )
    .await
    .expect("other event");

    let export = export_account(&pool, "ALICE").await.expect("Alice");
    let value: serde_json::Value = serde_json::from_str(&export).expect("valid JSON");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["account"]["name"], "Alice");
    assert_eq!(value["account"]["contact_email"], "Alice@example.com");
    assert_eq!(value["networks"][0]["has_sasl_password"], true);
    assert_eq!(value["networks"][0]["has_server_password"], true);
    assert!(!export.contains("server-password-must-not-export"));
    assert_eq!(
        value["messages"][0]["message_id"], "alice-sent",
        "a channel message is stored under the display name and is still the account's"
    );
    assert_eq!(
        value["bouncer_read_markers"][0],
        serde_json::json!({
            "network": "libera",
            "target": "#rust",
            "timestamp": "2026-01-01T00:00:00.000Z",
        })
    );
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

/// An operator block, a nick, or a reserved name can be spelled like an
/// account. Their rows are not the account's: registering `root` must not
/// reveal what the operator `root` did, nor whom it killed, nor what someone
/// using the nick `root` was subjected to.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn an_account_sees_only_rows_naming_it_as_an_account() {
    use e6ircd::db::AuditPrincipal;
    let pool = db::connect_and_migrate(
        &support::test_db("an_account_sees_only_rows_naming_it_as_an_account").await,
    )
    .await
    .expect("connect");
    db::create_account_with_contact(&pool, "Root", "s3cr3t", None)
        .await
        .expect("root");
    for (actor, action, target, detail) in [
        (
            AuditPrincipal::operator("root"),
            "OPER",
            AuditPrincipal::operator("root"),
            "operator block",
        ),
        (
            AuditPrincipal::operator("root"),
            "KILL",
            AuditPrincipal::nick("victim"),
            "operator kill",
        ),
        (
            AuditPrincipal::operator("root"),
            "KLINE",
            AuditPrincipal::mask("*@198.51.100.7"),
            "operator ban",
        ),
        (
            AuditPrincipal::operator("oper2"),
            "SETHOST",
            AuditPrincipal::nick("root"),
            "someone using the nick",
        ),
        (
            AuditPrincipal::account("admin"),
            "ACCOUNT_INVITATION_CREATE",
            AuditPrincipal::invitation("root"),
            "reserved before the account existed",
        ),
        (
            AuditPrincipal::account("admin"),
            "ACCOUNT_SUSPEND",
            AuditPrincipal::account("ROOT"),
            "about the account",
        ),
    ] {
        db::insert_audit_log(&pool, &actor, action, &target, detail)
            .await
            .expect("seed");
    }
    // A row written before principals were recorded, whose name cannot be
    // proven to be the account's.
    sqlx::query(
        "INSERT INTO audit_log (actor, actor_kind, action, target, target_kind, detail)
         VALUES ('root', 'legacy', 'KLINE', '*@203.0.113.9', 'mask', 'legacy ban')",
    )
    .execute(&pool)
    .await
    .expect("legacy row");

    let activity = db::query_account_security_activity(&pool, "root", None, audit_page_size(100))
        .await
        .expect("activity");
    let details: Vec<&str> = activity
        .entries
        .iter()
        .map(|entry| entry.detail.as_str())
        .collect();
    assert!(details.contains(&"about the account"), "{details:?}");
    let export = export_account(&pool, "root").await.expect("root");
    for foreign in [
        "operator block",
        "operator kill",
        "operator ban",
        "someone using the nick",
        "reserved before the account existed",
        "legacy ban",
    ] {
        assert!(!details.contains(&foreign), "activity leaked {foreign}");
        assert!(!export.contains(foreign), "export leaked {foreign}");
    }
    assert!(export.contains("about the account"));
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn storage_maintenance_bounds_history_audit_and_expired_bearers() {
    let pool = db::connect_and_migrate(
        &support::test_db("storage_maintenance_bounds_history_audit_and_expired_bearers").await,
    )
    .await
    .expect("connect");
    let account_id = db::create_account_with_contact(&pool, "Alice", "password", None)
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
        "INSERT INTO audit_log (actor, actor_kind, action, target, target_kind, detail, created_at)
         VALUES
           ('alice', 'account', 'OLD', 'server', 'server', '', now() - interval '366 days'),
           ('alice', 'account', 'NEW', 'server', 'server', '', now())",
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
    // An expired grant is kept for a grace period (a late poll is answered
    // `expired_token`); one past it is pruned.
    sqlx::query(
        "INSERT INTO device_grants (device_code, user_code, expires_at)
         VALUES
           ('old-device', 'OLDDEV01', now() - interval '1 day'),
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

    // Bouncer history is under the same retention as `messages`: an old line
    // of an always-on network (a direct message included) expires by storage
    // age, while the recent line and the newest-N ring it belongs to stay.
    sqlx::query(
        "INSERT INTO bnc_buffer (owner, network, line, created_at)
         VALUES
           ('alice', 'libera', ':x!u@h PRIVMSG alice :old dm', now() - interval '31 days'),
           ('alice', 'libera', ':x!u@h PRIVMSG alice :new dm', now())",
    )
    .execute(&pool)
    .await
    .expect("bnc_buffer");
    let now_ms = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    sqlx::query(
        "INSERT INTO observability_samples (sampled_at_ms, snapshot)
         VALUES ($1, '{}'::jsonb), ($2, '{}'::jsonb)",
    )
    .bind(now_ms - 2 * 60 * 60 * 1_000)
    .bind(now_ms)
    .execute(&pool)
    .await
    .expect("observability samples");

    // A marker is a position in history: once history retention has removed
    // every message that old, it points where nothing can be read from.
    sqlx::query(
        "INSERT INTO read_markers (account_id, target, marker_ts)
         VALUES ($1, '#old', now() - interval '31 days'),
                ($1, '#new', now())",
    )
    .bind(account_id)
    .execute(&pool)
    .await
    .expect("read markers");
    sqlx::query(
        "INSERT INTO bnc_read_markers
             (account_id, network, target, timestamp, target_display, target_casemapping)
         VALUES ($1, 'libera', '#old',
                 to_char((now() - interval '31 days') AT TIME ZONE 'UTC',
                         'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), '#old', 'rfc1459'),
                ($1, 'libera', '#new',
                 to_char(now() AT TIME ZONE 'UTC',
                         'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), '#new', 'rfc1459')",
    )
    .bind(account_id)
    .execute(&pool)
    .await
    .expect("bouncer read markers");

    let retention = db::StorageRetention {
        history_days: 30,
        audit_days: 365,
        observability_hours: 1,
    };
    let report = db::run_storage_maintenance(&pool, retention)
        .await
        .expect("maintenance");
    assert_eq!(report.messages, 1);
    assert_eq!(report.bnc_buffer, 1);
    assert_eq!(report.audit_events, 1);
    assert_eq!(report.web_sessions, 1);
    assert_eq!(report.api_tokens, 1);
    assert_eq!(report.device_grants, 1);
    assert_eq!(report.logout_tokens, 1);
    assert_eq!(report.account_invitations, 1);
    assert_eq!(report.observability_samples, 1);
    // One from each marker table: the counter covers both.
    assert_eq!(report.read_markers, 2);
    // The core's row is also returned, as deleted, for the core's mirror.
    assert_eq!(
        report
            .expired_read_markers
            .iter()
            .map(|marker| (marker.account.as_str(), marker.target.as_str()))
            .collect::<Vec<_>>(),
        [("Alice", "#old")]
    );
    assert!(!report.saturated);
    let counts: (i64, i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT count(*) FROM messages),
           (SELECT count(*) FROM bnc_buffer),
           (SELECT count(*) FROM audit_log),
           (SELECT count(*) FROM web_sessions),
           (SELECT count(*) FROM api_tokens),
           (SELECT count(*) FROM device_grants),
           (SELECT count(*) FROM oidc_logout_tokens),
           (SELECT count(*) FROM account_invitations),
           (SELECT count(*) FROM observability_samples)",
    )
    .fetch_one(&pool)
    .await
    .expect("retained row counts");
    // Two audit rows remain: the recent seeded one and Alice's own
    // ACCOUNT_CREATE, written by her self-registration above.
    assert_eq!(
        counts,
        (1, 1, 2, 1, 1, 1, 1, 0, 1),
        "every collection retained only its live/recent row"
    );
    let remaining: String = sqlx::query_scalar("SELECT line FROM bnc_buffer")
        .fetch_one(&pool)
        .await
        .expect("remaining bouncer line");
    assert!(remaining.ends_with("new dm"), "{remaining}");
    let markers: (String, String) = sqlx::query_as(
        "SELECT (SELECT target FROM read_markers),
                (SELECT target FROM bnc_read_markers)",
    )
    .fetch_one(&pool)
    .await
    .expect("remaining markers");
    assert_eq!(
        markers,
        ("#new".to_string(), "#new".to_string()),
        "a marker survives exactly as long as history it could resume from"
    );
}

/// A saturated batch every five minutes never catches up with a backlog of
/// hundreds of thousands of rows (a retention lowered by months); one tick must
/// drain what it can in bounded steps.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn storage_maintenance_drains_a_backlog_in_one_tick() {
    let pool = db::connect_and_migrate(
        &support::test_db("storage_maintenance_drains_a_backlog_in_one_tick").await,
    )
    .await
    .expect("connect");
    sqlx::query(
        "INSERT INTO messages (msgid, target, sender_prefix, kind, body, ts)
         SELECT 'expired-' || n, '#test', 'Alice!u@h', 'privmsg', 'old',
                now() - interval '31 days' - (n || ' seconds')::interval
         FROM generate_series(1, 25000) AS n",
    )
    .execute(&pool)
    .await
    .expect("25k expired messages");
    let retention = db::StorageRetention {
        history_days: 30,
        audit_days: 365,
        observability_hours: 1,
    };
    let single = db::run_storage_maintenance(&pool, retention)
        .await
        .expect("one batch");
    assert_eq!(single.messages, 10_000);
    assert!(single.saturated, "one batch cannot drain 25k rows");
    let drain = db::drain_storage_maintenance(
        &pool,
        retention,
        db::MaintenanceDrainPlan {
            batches: std::num::NonZeroUsize::new(21).unwrap(),
            pause: std::time::Duration::ZERO,
        },
    )
    .await
    .expect("drain");
    assert_eq!(drain.totals.messages, 15_000, "{drain:?}");
    assert_eq!(
        drain.batches_run, 2,
        "10k, then the 5k remainder: {drain:?}"
    );
    assert!(!drain.totals.saturated, "{drain:?}");
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM messages")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(remaining, 0);
    // A bounded plan stops at its budget and says the backlog remains.
    sqlx::query(
        "INSERT INTO messages (msgid, target, sender_prefix, kind, body, ts)
         SELECT 'again-' || n, '#test', 'Alice!u@h', 'privmsg', 'old', now() - interval '31 days'
         FROM generate_series(1, 20001) AS n",
    )
    .execute(&pool)
    .await
    .expect("expired messages again");
    let capped = db::drain_storage_maintenance(
        &pool,
        retention,
        db::MaintenanceDrainPlan {
            batches: std::num::NonZeroUsize::new(2).unwrap(),
            pause: std::time::Duration::ZERO,
        },
    )
    .await
    .expect("capped drain");
    assert_eq!(capped.batches_run, 2);
    assert_eq!(capped.totals.messages, 20_000);
    assert!(
        capped.totals.saturated,
        "the last batch filled, so the plan must report the backlog: {capped:?}"
    );
}

/// Every way an account comes to exist is audited. Self-registration over IRC
/// and first-login provisioning from an identity provider used to leave no
/// row, unlike administrator creation, invitation and bootstrap.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn self_registration_and_oidc_provisioning_are_audited() {
    let pool = db::connect_and_migrate(
        &support::test_db("self_registration_and_oidc_provisioning_are_audited").await,
    )
    .await
    .expect("connect");
    db::create_account_with_contact(&pool, "Alice", "password", None)
        .await
        .expect("self-registered account");
    let created = db::find_or_create_oidc_account(&pool, "https://idp.example", "sub-1", "Bob")
        .await
        .expect("provisioned account");
    assert_eq!(created, "Bob");
    let again = db::find_or_create_oidc_account(&pool, "https://idp.example", "sub-1", "Bob")
        .await
        .expect("existing account");
    assert_eq!(again, "Bob");
    let rows: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT actor, action, target, detail FROM audit_log
         WHERE action = 'ACCOUNT_CREATE' ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("audit rows");
    assert_eq!(
        rows,
        [
            (
                "alice".to_string(),
                "ACCOUNT_CREATE".to_string(),
                "alice".to_string(),
                "self-registered over IRC".to_string()
            ),
            (
                "oidc:https://idp.example".to_string(),
                "ACCOUNT_CREATE".to_string(),
                "bob".to_string(),
                "provisioned from OpenID Connect".to_string()
            ),
        ],
        "one row per creation, none for a returning identity"
    );
}

/// A port nobody listens on: bound, read, and released, so a connection to it
/// is refused rather than black-holed.
fn refusing_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").port()
}

/// Startup keeps trying a refused database, one reported attempt at a time,
/// and gives up with a typed error once its wait is spent.
#[tokio::test]
async fn startup_database_wait_retries_a_refused_port_then_gives_up() {
    let url = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/x",
        refusing_port()
    );
    // Eight seconds, not two: on Windows a connect to a closed loopback port
    // can run into the two-second probe bound instead of failing at once, and
    // the wait must still fit an attempt, the one-second pause, and a retry.
    let wait = db::StartupDatabaseWait::from_seconds(8).expect("bounded");
    let mut reported: Vec<(u32, Option<std::time::Duration>)> = Vec::new();
    let started = std::time::Instant::now();
    let error = db::connect_and_migrate_with_retry(
        &url,
        wait,
        db::DatabasePoolSize::for_this_host(),
        |attempt| {
            assert!(
                matches!(attempt.error, db::DbError::Connect(_)),
                "{}",
                attempt.error
            );
            reported.push((attempt.attempt, attempt.retry_in));
        },
    )
    .await
    .expect_err("nothing listens there");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= std::time::Duration::from_secs(2)
            && elapsed < std::time::Duration::from_secs(20),
        "the wait is the budget: {elapsed:?}"
    );
    let db::DbError::StartupWaitExhausted { attempts, last, .. } = error else {
        panic!("expected the exhausted-wait error, got {error}");
    };
    assert!(
        attempts >= 2,
        "at least the first attempt and one retry: {attempts}"
    );
    assert!(matches!(*last, db::DbError::Connect(_)), "{last}");
    assert_eq!(reported.len() as u32, attempts, "every attempt is reported");
    assert!(
        reported[..reported.len() - 1]
            .iter()
            .all(|(_, retry_in)| retry_in.is_some()),
        "every attempt but the last announces its retry: {reported:?}"
    );
    assert_eq!(
        reported.last().unwrap().1,
        None,
        "the last one says it gives up"
    );
    assert_eq!(reported[0].1, Some(std::time::Duration::from_secs(1)));
}

/// `startup_wait_seconds = 0` is exactly one attempt.
#[tokio::test]
async fn startup_database_wait_of_zero_is_a_single_attempt() {
    let url = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/x",
        refusing_port()
    );
    let wait = db::StartupDatabaseWait::from_seconds(0).expect("bounded");
    let mut attempts = 0;
    let error = db::connect_and_migrate_with_retry(
        &url,
        wait,
        db::DatabasePoolSize::for_this_host(),
        |_| attempts += 1,
    )
    .await
    .expect_err("refused");
    assert_eq!(attempts, 1);
    assert!(matches!(
        error,
        db::DbError::StartupWaitExhausted { attempts: 1, .. }
    ));
}

/// The daemon itself: a refused database is retried with one line per attempt
/// on stderr, then the process exits non-zero.
#[test]
fn daemon_exits_non_zero_after_its_startup_database_wait() {
    let directory = std::env::temp_dir().join(format!(
        "e6irc-startup-wait-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory).expect("temp dir");
    let config = directory.join("e6ircd.toml");
    std::fs::write(
        &config,
        format!(
            "server_name = \"irc.wait.test\"\nnetwork_name = \"WaitNet\"\n\
             [[listeners]]\naddr = \"127.0.0.1:0\"\n\
             [database]\nurl = \"postgres://postgres:postgres@127.0.0.1:{}/x\"\n\
             startup_wait_seconds = 8\n",
            refusing_port()
        ),
    )
    .expect("config");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_e6ircd"))
        .arg("--config")
        .arg(&config)
        .output()
        .expect("run e6ircd");
    let _ = std::fs::remove_dir_all(&directory);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    // The reason is the operating system's (refused here, a timed-out probe
    // where a closed loopback port answers slowly); the shape is ours.
    assert!(
        stderr.contains("database connection attempt 1 failed")
            && stderr.contains("database connect failed")
            && stderr.contains("retrying in"),
        "{stderr}"
    );
    assert!(
        stderr.contains("database connection attempt 2 failed"),
        "at least one retry within the eight-second wait: {stderr}"
    );
    assert!(stderr.contains("giving up"), "{stderr}");
    assert!(
        stderr.contains("did not accept a connection in"),
        "the final error names the exhausted wait: {stderr}"
    );
}

/// A database that starts listening during the wait is used: the retry is for
/// the container that comes up after this one.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn startup_database_wait_uses_a_database_that_appears_in_the_window() {
    let real = support::test_db("startup_database_wait_uses_a_database_that_appears").await;
    // `postgres://user:pass@host:port/name?...` -> the host:port to proxy to.
    let authority = real
        .split_once('@')
        .map(|(_, rest)| rest)
        .and_then(|rest| rest.split_once('/'))
        .map(|(authority, _)| authority.to_string())
        .expect("database URL has an authority");
    let port = refusing_port();
    let proxied = real.replacen(&authority, &format!("127.0.0.1:{port}"), 1);
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("proxy bind");
        loop {
            let (mut downstream, _) = listener.accept().await.expect("proxy accept");
            let upstream = authority.clone();
            tokio::spawn(async move {
                let mut upstream = tokio::net::TcpStream::connect(upstream)
                    .await
                    .expect("proxy dial");
                let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
            });
        }
    });
    let mut attempts = 0;
    let pool = db::connect_and_migrate_with_retry(
        &proxied,
        db::StartupDatabaseWait::from_seconds(20).expect("bounded"),
        db::DatabasePoolSize::for_this_host(),
        |_| attempts += 1,
    )
    .await
    .expect("the database appeared inside the wait");
    assert!(attempts >= 1, "the first attempt was refused");
    let one: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&pool)
        .await
        .expect("query through the late database");
    assert_eq!(one, 1);
}

/// Two administrators demoting each other at the same moment must not both
/// succeed: each transaction alone sees the other as the remaining
/// administrator, so without one ordering of authority changes both commit and
/// no durable administrator is left.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn concurrent_mutual_demotion_keeps_one_administrator() {
    let pool = db::connect_and_migrate(
        &support::test_db("concurrent_mutual_demotion_keeps_one_administrator").await,
    )
    .await
    .expect("connect");
    let alice_id = db::bootstrap_first_admin(&pool, "Alice", "administrator password")
        .await
        .expect("Alice");
    let bob_id = db::create_account_with_contact(&pool, "Bob", "second administrator", None)
        .await
        .expect("Bob");
    db::set_account_administrator(&pool, bob_id, true, "Alice", &[])
        .await
        .expect("grant")
        .expect("Bob");

    // Hold both rows so the two demotions are in flight together, then let
    // them go at once.
    let mut gate = pool.begin().await.expect("gate");
    sqlx::query("SELECT id FROM accounts WHERE id = ANY($1) FOR UPDATE")
        .bind(&[alice_id, bob_id][..])
        .execute(&mut *gate)
        .await
        .expect("hold both rows");
    let demote = |target: i64, actor: &'static str| {
        let pool = pool.clone();
        tokio::spawn(async move {
            db::set_account_administrator(&pool, target, false, actor, &[]).await
        })
    };
    let alice_demotes_bob = demote(bob_id, "Alice");
    let bob_demotes_alice = demote(alice_id, "Bob");
    // Release only once both are queued on the held rows; before that, one
    // could simply run after the other.
    tokio::time::timeout(deadline::HANG, async {
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity
                 WHERE datname = current_database() AND wait_event_type = 'Lock'",
            )
            .fetch_one(&pool)
            .await
            .expect("lock waiters");
            if waiting >= 2 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("both demotions never queued on the held rows");
    gate.commit().await.expect("release");

    let outcomes = [
        alice_demotes_bob.await.expect("task"),
        bob_demotes_alice.await.expect("task"),
    ];
    let refused = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Err(db::DbError::LastAdministrator)))
        .count();
    let administrators: i64 =
        sqlx::query_scalar("SELECT count(*) FROM accounts WHERE (flags & 1) = 1")
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(
        (refused, administrators),
        (1, 1),
        "exactly one demotion is refused and one administrator remains: {outcomes:?}"
    );
}

/// A stored hash that no longer parses is damaged data, not a wrong password:
/// the login still fails, but as a loud store fault an operator will see, not
/// as a credential rejection indistinguishable from a typo.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn corrupt_stored_password_hash_is_a_store_fault_not_a_wrong_password() {
    let pool = db::connect_and_migrate(
        &support::test_db("corrupt_stored_password_hash_is_a_store_fault_not_a_wrong_password")
            .await,
    )
    .await
    .expect("connect");
    let alice_id = db::create_account_with_contact(&pool, "Alice", "correct password", None)
        .await
        .expect("Alice");
    sqlx::query("UPDATE account_credentials SET argon2_hash = 'not-a-hash' WHERE account_id = $1")
        .bind(alice_id)
        .execute(&pool)
        .await
        .expect("corrupt the stored hash");

    for password in ["correct password", "wrong password"] {
        assert!(
            matches!(
                db::verify_credentials(&pool, "Alice", password).await,
                Err(db::DbError::Hash(_))
            ),
            "SASL/IDENTIFY verification must report the damaged hash"
        );
        assert!(
            matches!(
                db::verify_local_password(&pool, "Alice", password).await,
                Err(db::DbError::Hash(_))
            ),
            "primary-password verification must report the damaged hash"
        );
    }
}

/// The operator's way back in when every administrator credential is lost or
/// the identity provider is broken: run on the host, against the database the
/// configuration names. It acts once, on one named account, and is on the
/// record.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn administrator_recovery_restores_one_named_account_and_is_audited() {
    let pool = db::connect_and_migrate(
        &support::test_db("administrator_recovery_restores_one_named_account_and_is_audited").await,
    )
    .await
    .expect("connect");
    let alice_id = db::create_account_with_contact(&pool, "Alice", "forgotten", None)
        .await
        .expect("alice");
    let mallory_id = db::create_account_with_contact(&pool, "mallory", "pw", None)
        .await
        .expect("mallory");
    db::create_account_with_contact(&pool, "root", "pw", None)
        .await
        .expect("root");
    let stale_session = db::create_web_session(&pool, "alice", None)
        .await
        .expect("session");
    // Everything else the lost credential could have been used to mint is
    // revoked with it: an app password, a personal access token, a device
    // grant.
    let app_password = db::issue_app_password(&pool, "Alice", "forgotten", "phone")
        .await
        .expect("app password");
    let api_token = db::issue_scoped_api_token(
        &pool,
        "Alice",
        "automation",
        e6ircd::identity::ApiTokenScopes::new(e6ircd::identity::ApiTokenScope::ALL)
            .expect("scopes"),
        e6ircd::identity::ApiTokenLifetimeDays::DEFAULT,
    )
    .await
    .expect("api token");
    let (_device_code, user_code) = db::create_device_grant(&pool).await.expect("device grant");
    assert_eq!(
        db::approve_device_grant(&pool, &user_code, "Alice")
            .await
            .expect("approve"),
        db::DeviceApproval::Approved
    );

    let recovered = db::recover_administrator(&pool, "ALICE")
        .await
        .expect("recover");
    assert_eq!(
        db::verify_credentials(&pool, "alice", &app_password)
            .await
            .expect("app password verify"),
        None,
        "the app password no longer opens the account"
    );
    assert!(
        db::api_token_principal(&pool, &api_token)
            .await
            .expect("token lookup")
            .is_none(),
        "the personal access token is revoked"
    );
    let credentials = db::list_credentials(&pool, "alice")
        .await
        .expect("credential inventory");
    assert_eq!(
        credentials
            .iter()
            .map(|credential| credential.kind.as_str())
            .collect::<Vec<_>>(),
        vec!["local_password"],
        "only the new local password remains"
    );
    assert!(
        db::list_api_tokens(&pool, "alice")
            .await
            .expect("token inventory")
            .is_empty()
    );
    let device_grants: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM device_grants g JOIN accounts a ON a.id = g.account_id
             WHERE a.name = 'Alice'",
    )
    .fetch_one(&pool)
    .await
    .expect("device grant count");
    assert_eq!(device_grants, 0, "the approved device grant is revoked");
    assert_eq!(
        recovered.account, "Alice",
        "the stored name, not the typed one"
    );
    assert_eq!(
        db::verify_local_password(&pool, "alice", &recovered.password)
            .await
            .expect("verify")
            .as_deref(),
        Some("Alice")
    );
    assert_eq!(
        db::verify_local_password(&pool, "alice", "forgotten")
            .await
            .expect("verify"),
        None,
        "the lost password no longer opens the account"
    );
    let flags = db::account_flags(&pool, "alice")
        .await
        .expect("flags")
        .expect("alice");
    assert!(flags.is_admin());
    assert!(
        db::session_identity(&pool, &stale_session)
            .await
            .expect("session lookup")
            .is_none(),
        "whoever held the old credential is signed out"
    );
    let _ = alice_id;

    // An account that was only ever provisioned by an identity provider has no
    // password to replace; it gains one.
    sqlx::query("DELETE FROM account_credentials WHERE account_id = (SELECT id FROM accounts WHERE name_folded = 'root')")
        .execute(&pool)
        .await
        .expect("drop root's password");
    let root = db::recover_administrator(&pool, "root")
        .await
        .expect("recover root");
    assert_eq!(
        db::verify_local_password(&pool, "root", &root.password)
            .await
            .expect("verify")
            .as_deref(),
        Some("root")
    );

    // Nothing is guessed: an unknown name and a suspended account are refused.
    assert!(matches!(
        db::recover_administrator(&pool, "nobody").await,
        Err(db::DbError::UnknownAccount(name)) if name == "nobody"
    ));
    db::set_account_suspended(&pool, mallory_id, true, "alice", &[])
        .await
        .expect("suspend mallory");
    assert!(matches!(
        db::recover_administrator(&pool, "mallory").await,
        Err(db::DbError::RecoveryOfSuspendedAccount(name)) if name == "mallory"
    ));
    assert!(
        !db::account_flags(&pool, "mallory")
            .await
            .expect("flags")
            .expect("mallory")
            .is_admin()
    );

    let recoveries: Vec<(String, String)> = sqlx::query_as(
        "SELECT actor, target FROM audit_log WHERE action = 'ADMINISTRATOR_RECOVERY' ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("audit");
    assert_eq!(
        recoveries,
        [
            (
                "host:recover-administrator".to_string(),
                "alice".to_string()
            ),
            ("host:recover-administrator".to_string(), "root".to_string()),
        ]
    );
}

/// The same recovery, as the operator runs it: the binary, the configuration
/// file, and an account name — nothing else, and nothing over the network.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn recover_administrator_subcommand_prints_the_password_once() {
    let url = support::test_db("recover_administrator_subcommand_prints_the_password_once").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    db::create_account_with_contact(&pool, "alice", "forgotten", None)
        .await
        .expect("alice");
    let config_path = std::env::temp_dir().join(format!(
        "e6irc-recover-administrator-{}.toml",
        std::process::id()
    ));
    std::fs::write(
        &config_path,
        format!(
            "server_name = \"irc.recover.example\"\nnetwork_name = \"Recover\"\n\n[[listeners]]\naddr = \"127.0.0.1:0\"\n\n[database]\nurl = \"{url}\"\n"
        ),
    )
    .expect("write config");
    let run = |arguments: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_e6ircd"))
            .arg("recover-administrator")
            .args(arguments)
            .arg("--config")
            .arg(&config_path)
            .output()
            .expect("run e6ircd recover-administrator")
    };

    let refused = run(&["--account", "nobody"]);
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty(), "a refusal prints no password");
    let complaint = String::from_utf8_lossy(&refused.stderr);
    assert!(
        complaint.contains("no such account: nobody") && complaint.contains("nothing was changed"),
        "{complaint}"
    );
    assert!(!run(&[]).status.success(), "the account must be named");

    let recovered = run(&["--account", "alice"]);
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    let password = String::from_utf8(recovered.stdout).expect("password");
    assert_eq!(
        db::verify_local_password(&pool, "alice", password.trim())
            .await
            .expect("verify")
            .as_deref(),
        Some("alice")
    );
    assert!(
        db::account_flags(&pool, "alice")
            .await
            .expect("flags")
            .expect("alice")
            .is_admin()
    );
    std::fs::remove_file(&config_path).expect("remove config");
}

/// App passwords minted before lookups existed cannot be given one (their
/// secrets were never stored), so migration 0059 revokes them, audited.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn migration_0059_revokes_app_passwords_it_cannot_name_and_says_so() {
    let pool = db::connect_and_migrate(
        &support::test_db("migration_0059_revokes_app_passwords_it_cannot_name_and_says_so").await,
    )
    .await
    .expect("connect");
    db::create_account_with_contact(&pool, "Alice", "primary", None)
        .await
        .expect("alice");
    // The table as it was before the migration, holding an app password.
    sqlx::raw_sql(
        "DROP INDEX account_credentials_secret_lookup_idx;
         ALTER TABLE account_credentials
             DROP CONSTRAINT account_credentials_lookup_names_app_passwords,
             DROP COLUMN secret_lookup;
         INSERT INTO account_credentials (account_id, kind, argon2_hash, label)
         SELECT id, 'app_password', 'unused-hash', 'old laptop' FROM accounts;
         ALTER TABLE audit_log
             DROP COLUMN actor_kind,
             DROP COLUMN target_kind;",
    )
    .execute(&pool)
    .await
    .expect("restore the earlier tables");

    sqlx::raw_sql(include_str!(
        "../../../migrations/0059_app_password_lookup.sql"
    ))
    .execute(&pool)
    .await
    .expect("migration 0059");
    sqlx::raw_sql(include_str!(
        "../../../migrations/0078_audit_principal_kinds.sql"
    ))
    .execute(&pool)
    .await
    .expect("migration 0078");
    let classified: Vec<(String, String)> = sqlx::query_as(
        "SELECT actor_kind, target_kind FROM audit_log WHERE actor = 'migration:0059'",
    )
    .fetch_all(&pool)
    .await
    .expect("classified audit");
    assert_eq!(
        classified,
        [("host".to_string(), "account".to_string())],
        "a migration's row is the host's, about an account"
    );

    let kinds: Vec<String> = sqlx::query_scalar("SELECT kind FROM account_credentials")
        .fetch_all(&pool)
        .await
        .expect("credentials");
    assert_eq!(kinds, ["local_password"], "the primary password is kept");
    let audited: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT actor, action, target FROM audit_log WHERE actor = 'migration:0059'",
    )
    .fetch_all(&pool)
    .await
    .expect("audit");
    assert_eq!(
        audited,
        [(
            "migration:0059".to_string(),
            "ACCOUNT_APP_PASSWORD_REVOKE".to_string(),
            "Alice".to_string()
        )]
    );
    assert_eq!(
        db::verify_credentials(&pool, "alice", "primary")
            .await
            .expect("verify")
            .as_deref(),
        Some("Alice")
    );
}

/// A login attempt verifies the primary password and the one app password the
/// presented secret names; the schema lets no app password exist without the
/// lookup that names it.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn app_passwords_are_found_by_lookup_and_none_can_exist_without_one() {
    let pool = db::connect_and_migrate(
        &support::test_db("app_passwords_are_found_by_lookup_and_none_can_exist_without_one").await,
    )
    .await
    .expect("connect");
    db::create_account_with_contact(&pool, "Alice", "primary", None)
        .await
        .expect("alice");
    let mut secrets = Vec::new();
    for index in 0..3 {
        secrets.push(
            db::issue_app_password_for_account(&pool, "alice", &format!("device {index}"))
                .await
                .expect("app password"),
        );
    }
    for secret in secrets.iter().chain([&"primary".to_string()]) {
        assert_eq!(
            db::verify_credentials(&pool, "ALICE", secret)
                .await
                .expect("verify")
                .as_deref(),
            Some("Alice")
        );
    }

    // An app password that names no row would have to be tried blind on every
    // attempt, so the schema does not let one exist -- nor a fast hash of a
    // chosen password.
    for (statement, what) in [
        (
            "UPDATE account_credentials SET secret_lookup = NULL WHERE label = 'device 1'",
            "an app password without a lookup",
        ),
        (
            "UPDATE account_credentials SET secret_lookup = '\\x00' WHERE kind = 'local_password'",
            "a primary password with a lookup",
        ),
    ] {
        let refused = sqlx::query(statement).execute(&pool).await;
        let error = refused.expect_err(what).to_string();
        assert!(
            error.contains("account_credentials_lookup_names_app_passwords"),
            "{what}: {error}"
        );
    }
    for wrong in [
        "",
        "primary ",
        "bm90IGFuIGFwcCBwYXNzd29yZCwganVzdCBiYXNlNjQgdGV4dA==",
    ] {
        assert_eq!(
            db::verify_credentials(&pool, "alice", wrong)
                .await
                .expect("verify"),
            None
        );
    }
    assert_eq!(
        db::verify_credentials(&pool, "nobody", &secrets[0])
            .await
            .expect("verify"),
        None,
        "an app password opens only its own account"
    );
    let primary_has_lookup: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM account_credentials
                       WHERE kind = 'local_password' AND secret_lookup IS NOT NULL)",
    )
    .fetch_one(&pool)
    .await
    .expect("primary");
    assert!(
        !primary_has_lookup,
        "a chosen password is never stored under a fast hash"
    );
}

// ---- privilege persistence across suspension, demotion and recovery -------

/// An administrator account and the pending invitations it issued: one that
/// grants durable administrator authority, one that does not.
async fn administrator_with_pending_invitations(pool: &sqlx::PgPool) -> (i64, String, String) {
    db::bootstrap_first_admin(pool, "Alice", "administrator password")
        .await
        .expect("Alice");
    let mallory = db::create_account_by_administrator(
        pool,
        "Mallory",
        "mallory password",
        None,
        true,
        "Alice",
    )
    .await
    .expect("Mallory");
    let lifetime = e6ircd::identity::AccountInvitationLifetimeDays::new(7).expect("lifetime");
    let administrator = db::issue_account_invitation(pool, "Eve", None, true, lifetime, "Mallory")
        .await
        .expect("administrator invitation");
    let ordinary = db::issue_account_invitation(pool, "Frank", None, false, lifetime, "Mallory")
        .await
        .expect("ordinary invitation");
    (mallory, administrator, ordinary)
}

async fn invitation_revocations(pool: &sqlx::PgPool) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT actor, target FROM audit_log
         WHERE action = 'ACCOUNT_INVITATION_REVOKE' ORDER BY target",
    )
    .fetch_all(pool)
    .await
    .expect("revocation audit")
}

/// Suspending an account ends every invitation it issued, in the suspension's
/// own transaction: an intruder who minted administrator invitations with a
/// stolen administrator session cannot come back through them afterwards.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn suspension_revokes_the_suspended_accounts_pending_invitations() {
    let pool = db::connect_and_migrate(
        &support::test_db("suspension_revokes_the_suspended_accounts_invitations").await,
    )
    .await
    .expect("connect");
    let (mallory, administrator, ordinary) = administrator_with_pending_invitations(&pool).await;
    db::set_account_suspended(&pool, mallory, true, "Alice", &[])
        .await
        .expect("suspend")
        .expect("Mallory");
    for token in [&administrator, &ordinary] {
        let accepted = db::accept_account_invitation(&pool, token, "invited password", &[]).await;
        assert!(
            matches!(accepted, Err(db::DbError::InvitationUnavailable)),
            "a suspended issuer's invitation must not open an account: {accepted:?}"
        );
    }
    assert_eq!(
        invitation_revocations(&pool).await,
        [
            ("alice".to_string(), "eve".to_string()),
            ("alice".to_string(), "frank".to_string())
        ]
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn demotion_revokes_the_demoted_accounts_pending_invitations() {
    let pool = db::connect_and_migrate(
        &support::test_db("demotion_revokes_the_demoted_accounts_invitations").await,
    )
    .await
    .expect("connect");
    let (mallory, administrator, ordinary) = administrator_with_pending_invitations(&pool).await;
    db::set_account_administrator(&pool, mallory, false, "Alice", &[])
        .await
        .expect("demote")
        .expect("Mallory");
    for token in [&administrator, &ordinary] {
        let accepted = db::accept_account_invitation(&pool, token, "invited password", &[]).await;
        assert!(
            matches!(accepted, Err(db::DbError::InvitationUnavailable)),
            "a demoted issuer's invitation must not open an account: {accepted:?}"
        );
    }
    assert_eq!(invitation_revocations(&pool).await.len(), 2);
}

#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn administrator_recovery_revokes_the_recovered_accounts_invitations() {
    let pool = db::connect_and_migrate(
        &support::test_db("administrator_recovery_revokes_the_recovered_invitations").await,
    )
    .await
    .expect("connect");
    let (_mallory, administrator, ordinary) = administrator_with_pending_invitations(&pool).await;
    db::recover_administrator(&pool, "MALLORY")
        .await
        .expect("recover");
    for token in [&administrator, &ordinary] {
        let accepted = db::accept_account_invitation(&pool, token, "invited password", &[]).await;
        assert!(
            matches!(accepted, Err(db::DbError::InvitationUnavailable)),
            "an invitation minted with lost credentials must not survive recovery: {accepted:?}"
        );
    }
    assert_eq!(
        invitation_revocations(&pool).await,
        [
            ("host:recover-administrator".to_string(), "eve".to_string()),
            (
                "host:recover-administrator".to_string(),
                "frank".to_string()
            )
        ]
    );
}

/// Acceptance re-checks the issuer: an administrator invitation opens an
/// administrator account only while its issuer still holds that authority —
/// durably or by configuration — and is active.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn administrator_invitation_requires_an_issuer_who_is_still_an_active_administrator() {
    let pool = db::connect_and_migrate(
        &support::test_db("administrator_invitation_requires_active_issuer").await,
    )
    .await
    .expect("connect");
    let (_mallory, administrator, ordinary) = administrator_with_pending_invitations(&pool).await;
    // Authority removed by a path that knows nothing of invitations.
    sqlx::query("UPDATE accounts SET flags = 0 WHERE name_folded = 'mallory'")
        .execute(&pool)
        .await
        .expect("strip authority");
    let accepted =
        db::accept_account_invitation(&pool, &administrator, "invited password", &[]).await;
    assert!(
        matches!(accepted, Err(db::DbError::InvitationUnavailable)),
        "{accepted:?}"
    );
    // A configured grant is authority too.
    let configured = ["mallory".to_string()];
    assert_eq!(
        db::accept_account_invitation(&pool, &administrator, "invited password", &configured)
            .await
            .expect("configured issuer"),
        "Eve"
    );
    // An ordinary invitation carries no authority to re-check.
    assert_eq!(
        db::accept_account_invitation(&pool, &ordinary, "invited password", &[])
            .await
            .expect("ordinary"),
        "Frank"
    );
    // A suspended configured administrator's invitation is refused.
    let lifetime = e6ircd::identity::AccountInvitationLifetimeDays::new(7).expect("lifetime");
    let later = db::issue_account_invitation(&pool, "Grace", None, true, lifetime, "Mallory")
        .await
        .expect("issue");
    sqlx::query("UPDATE accounts SET flags = 2 WHERE name_folded = 'mallory'")
        .execute(&pool)
        .await
        .expect("suspend by flag");
    let accepted =
        db::accept_account_invitation(&pool, &later, "invited password", &configured).await;
    assert!(
        matches!(accepted, Err(db::DbError::InvitationUnavailable)),
        "{accepted:?}"
    );
}

/// Expired invitations no longer count against the issuer's pending cap.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn expired_invitations_do_not_count_against_the_pending_cap() {
    let pool = db::connect_and_migrate(
        &support::test_db("expired_invitations_do_not_count_against_the_cap").await,
    )
    .await
    .expect("connect");
    db::bootstrap_first_admin(&pool, "Alice", "administrator password")
        .await
        .expect("Alice");
    sqlx::query(
        "INSERT INTO account_invitations
            (token_hash, account_name, name_folded, created_by, created_at, expires_at)
         SELECT sha256(convert_to('t' || n, 'UTF8')), 'x' || n, 'x' || n, 'alice',
                now() - interval '10 days', now() - interval '1 day'
         FROM generate_series(1, $1) n",
    )
    .bind(db::MAX_PENDING_ACCOUNT_INVITATIONS_PER_ADMINISTRATOR as i32)
    .execute(&pool)
    .await
    .expect("expired invitations");
    db::issue_account_invitation(
        &pool,
        "Bob",
        None,
        false,
        e6ircd::identity::AccountInvitationLifetimeDays::new(1).expect("lifetime"),
        "Alice",
    )
    .await
    .expect("expired invitations are not pending");
}

// ---- migrations outside the pool's statement timeout ----------------------

/// A migration that runs longer than the pool's statement timeout still
/// completes: the migrator runs on its own connection with no statement
/// timeout, so a large deployment does not crash-loop on upgrade.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn a_migration_longer_than_the_statement_timeout_completes() {
    let url = support::test_db("a_migration_longer_than_the_statement_timeout").await;
    let directory = std::env::temp_dir().join(format!(
        "e6irc-slow-migration-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory).expect("migration directory");
    std::fs::write(
        directory.join("0001_slow.sql"),
        "SELECT pg_sleep(16);\nCREATE TABLE slow_migration_done (id INT);\n",
    )
    .expect("slow migration");
    let migrator = sqlx::migrate::Migrator::new(directory.as_path())
        .await
        .expect("migrator");
    db::run_migrations(&url, &migrator)
        .await
        .expect("a slow migration completes");
    std::fs::remove_dir_all(&directory).expect("clean up");
    let pool = sqlx::PgPool::connect(&url).await.expect("connect");
    let done: bool = sqlx::query_scalar("SELECT to_regclass('slow_migration_done') IS NOT NULL")
        .fetch_one(&pool)
        .await
        .expect("check");
    assert!(done);
}

// ---- account purge is indexed ---------------------------------------------

/// Both halves of the account-message predicate that deletion and export use
/// are index-served: with sequential scans disabled, the plan still contains
/// none (a predicate half with no index would force one regardless).
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn the_account_message_predicate_is_index_served() {
    let pool = db::connect_and_migrate(
        &support::test_db("the_account_message_predicate_is_index_served").await,
    )
    .await
    .expect("connect");
    let mut connection = pool.acquire().await.expect("connection");
    sqlx::query("SET enable_seqscan = off")
        .execute(&mut *connection)
        .await
        .expect("disable seqscan");
    let sql = format!(
        "EXPLAIN (FORMAT TEXT) SELECT id FROM messages WHERE {}",
        db::ACCOUNT_MESSAGES_PREDICATE
    );
    let plan: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .bind("alice")
        .bind("Alice")
        .fetch_all(&mut *connection)
        .await
        .expect("explain");
    let plan = plan.join("\n");
    assert!(!plan.contains("Seq Scan"), "{plan}");
    assert!(plan.contains("messages_sender_account_idx"), "{plan}");
    assert!(plan.contains("messages_dm_peers_idx"), "{plan}");
}

// ---- Argon2 outside row locks ----------------------------------------------

/// A password change waits for an Argon2 permit without holding the account
/// row: while every permit is busy, a read-marker write for the same account
/// (whose foreign-key check needs a share lock on that row) is not blocked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn a_password_change_waiting_for_argon2_does_not_block_the_account_row() {
    let pool = db::connect_and_migrate(
        &support::test_db("a_password_change_waiting_for_argon2_does_not_block").await,
    )
    .await
    .expect("connect");
    db::create_account_with_contact(&pool, "alice", "current password", None)
        .await
        .expect("alice");
    let session = db::create_web_session(&pool, "alice", None)
        .await
        .expect("session");

    // Keep every Argon2 permit busy for the whole test.
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut flood = tokio::task::JoinSet::new();
    for worker in 0..12 {
        let pool = pool.clone();
        let stop = stop.clone();
        flood.spawn(async move {
            // A fresh name each time: one name's attempts are throttled before
            // any Argon2 work, and the point here is to keep Argon2 busy.
            let mut attempt = 0u64;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                attempt += 1;
                let name = format!("nobody{worker}x{attempt}");
                let _ = db::verify_credentials(&pool, &name, "guess").await;
            }
        });
    }

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
    tokio::spawn(db::run_worker(
        pool.clone(),
        req_rx,
        CoreIngress::single(core_tx),
    ));

    let change = tokio::spawn({
        let pool = pool.clone();
        async move {
            db::change_local_password(
                &pool,
                "alice",
                "current password",
                "a brand new password",
                &session,
            )
            .await
        }
    });
    let mut slowest = std::time::Duration::ZERO;
    let mut probes = 0u64;
    while !change.is_finished() {
        let started = std::time::Instant::now();
        req_tx
            .push(DbRequest::SetReadMarker {
                conn: e6ircd::core::ConnId(1),
                account: "alice".into(),
                target: format!("#probe{probes}"),
                display: format!("#probe{probes}"),
                marker_ms: e6irc_proto::time::Millis::from_millis(1_000),
                label: None,
            })
            .await
            .expect("push");
        let reply = core_rx.pop().await.expect("worker reply");
        slowest = slowest.max(started.elapsed());
        assert!(
            matches!(
                reply.payload,
                Input::DbReply {
                    reply: DbReply::ReadMarkerStored { .. },
                    ..
                }
            ),
            "{:?}",
            reply.payload
        );
        probes += 1;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    change.await.expect("join").expect("password changed");
    while flood.join_next().await.is_some() {}
    assert!(probes > 0, "the change finished before any probe ran");
    assert!(
        slowest < std::time::Duration::from_secs(1),
        "a read-marker write waited {slowest:?} behind a password change"
    );
}

// ---- storage maintenance collections are independent -----------------------

/// Each maintenance collection commits on its own: one table failing to delete
/// (here, a trigger that refuses) is reported, and does not roll back the
/// expired history the other collections removed.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn one_failing_maintenance_collection_does_not_roll_back_the_others() {
    let pool = db::connect_and_migrate(
        &support::test_db("one_failing_maintenance_collection_does_not_roll_back").await,
    )
    .await
    .expect("connect");
    let account = db::create_account_with_contact(&pool, "alice", "password", None)
        .await
        .expect("alice");
    sqlx::query(
        "INSERT INTO messages (msgid, target, sender_prefix, kind, body, ts)
         VALUES ('old', '#test', 'a!u@h', 'privmsg', 'old', now() - interval '31 days')",
    )
    .execute(&pool)
    .await
    .expect("old message");
    sqlx::query(
        "INSERT INTO web_sessions (token_hash, account_id, expires_at)
         VALUES ('\\x00'::bytea, $1, now() - interval '1 day')",
    )
    .bind(account)
    .execute(&pool)
    .await
    .expect("expired session");
    sqlx::raw_sql(
        "CREATE FUNCTION refuse_delete() RETURNS trigger LANGUAGE plpgsql AS
             $$ BEGIN RAISE EXCEPTION 'refused by test'; END $$;
         CREATE TRIGGER refuse_session_delete BEFORE DELETE ON web_sessions
             FOR EACH ROW EXECUTE FUNCTION refuse_delete();",
    )
    .execute(&pool)
    .await
    .expect("trigger");
    let outcome = db::run_storage_maintenance(
        &pool,
        db::StorageRetention {
            history_days: 30,
            audit_days: 365,
            observability_hours: 24,
        },
    )
    .await;
    let error = outcome.expect_err("a failing collection is reported");
    assert!(error.to_string().contains("web_sessions"), "{error}");
    let messages: i64 = sqlx::query_scalar("SELECT count(*) FROM messages")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(messages, 0, "expired history was still collected");
}

// ---- durable read-marker cap -----------------------------------------------

/// The per-account read-marker cap holds in the database, where every core
/// shard's writes meet: the 257th target is refused, re-writing a held target
/// is not.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn the_read_marker_cap_is_enforced_by_the_database() {
    let pool = db::connect_and_migrate(
        &support::test_db("the_read_marker_cap_is_enforced_by_the_database").await,
    )
    .await
    .expect("connect");
    db::create_account_with_contact(&pool, "alice", "password", None)
        .await
        .expect("alice");
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
    let mut write = async |target: String| {
        req_tx
            .push(DbRequest::SetReadMarker {
                conn: e6ircd::core::ConnId(1),
                account: "Alice".into(),
                target: target.clone(),
                display: target,
                marker_ms: e6irc_proto::time::Millis::from_millis(1_000),
                label: None,
            })
            .await
            .expect("push");
        match core_rx.pop().await.expect("reply").payload {
            Input::DbReply { reply, .. } => reply,
            other => panic!("unexpected {other:?}"),
        }
    };
    for index in 0..256 {
        let reply = write(format!("#t{index}")).await;
        assert!(
            matches!(reply, DbReply::ReadMarkerStored { .. }),
            "{index}: {reply:?}"
        );
    }
    let refused = write("#one-too-many".into()).await;
    assert!(
        matches!(refused, DbReply::ReadMarkerLimitReached { .. }),
        "{refused:?}"
    );
    let again = write("#t7".into()).await;
    assert!(
        matches!(again, DbReply::ReadMarkerStored { .. }),
        "{again:?}"
    );
}

// ---- corrective and backfilling migrations ---------------------------------

/// Every settings row a released e6irc wrote must still load after today's
/// migrations. Each fixture in `tests/fixtures/server_settings/` is the managed
/// configuration a release stored, captured by that release's own code, named
/// `<its last migration>-<release>.json`. When a change alters the stored shape
/// (a field made required, renamed or retyped), add the previous release's
/// fixture; the deploy of c51261725b5d crash-looped because no test held an
/// old row.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn settings_rows_written_by_released_versions_load_after_migrating() {
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/server_settings");
    let mut fixtures: Vec<_> = std::fs::read_dir(&directory)
        .expect("settings fixtures")
        .map(|entry| entry.expect("fixture entry").path())
        .collect();
    fixtures.sort();
    assert!(
        !fixtures.is_empty(),
        "no settings fixtures in {directory:?}"
    );
    for fixture in fixtures {
        let name = fixture
            .file_stem()
            .and_then(|stem| stem.to_str())
            .expect("fixture name")
            .to_owned();
        let level: i64 = name
            .split_once('-')
            .and_then(|(level, _)| level.parse().ok())
            .unwrap_or_else(|| panic!("{name}: fixtures are named <migration>-<release>.json"));
        let settings: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&fixture).expect("read fixture"))
                .expect("fixture JSON");
        let pool =
            sqlx::PgPool::connect(&support::test_db(&format!("settings_fixture_{name}")).await)
                .await
                .expect("connect");
        MIGRATIONS
            .run_to(level, &pool)
            .await
            .unwrap_or_else(|error| panic!("{name}: migrate to {level}: {error}"));
        sqlx::query(
            "INSERT INTO server_settings (singleton, revision, settings, updated_by)
             VALUES (TRUE, 1, $1, 'fixture')",
        )
        .bind(&settings)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("{name}: store the release's row: {error}"));
        MIGRATIONS
            .run(&pool)
            .await
            .unwrap_or_else(|error| panic!("{name}: migrate to latest: {error}"));
        db::load_managed_config(&pool)
            .await
            .unwrap_or_else(|error| panic!("{name}: the release's row no longer loads: {error}"));
        pool.close().await;
    }
}

/// A settings row saved while `limits.command_burst` was optional stores it as
/// `null`, which the required field cannot read: the daemon refused to start on
/// the deployed row. 0067 turns that `null` into the documented default.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn a_settings_row_with_a_null_command_burst_loads_after_0067() {
    let pool = sqlx::PgPool::connect(
        &support::test_db("a_settings_row_with_a_null_command_burst_loads").await,
    )
    .await
    .expect("connect");
    MIGRATIONS.run_to(66, &pool).await.expect("through 0066");
    let bootstrap =
        e6ircd::config::ManagedConfig::from_config(&Config::default(), None).expect("bootstrap");
    db::load_or_initialize_managed_config(&pool, &bootstrap)
        .await
        .expect("initialize");
    sqlx::query(
        "UPDATE server_settings
         SET settings = jsonb_set(settings, '{limits,command_burst}', 'null'::jsonb)",
    )
    .execute(&pool)
    .await
    .expect("store the old shape");
    assert!(
        matches!(
            db::load_managed_config(&pool).await,
            Err(db::DbError::InvalidServerSettings(_))
        ),
        "the old shape must be what failed"
    );
    MIGRATIONS.run(&pool).await.expect("migrate to latest");
    let loaded = db::load_managed_config(&pool)
        .await
        .expect("loads after 0067");
    assert_eq!(
        loaded.settings.limits.command_burst,
        e6ircd::config::DEFAULT_COMMAND_BURST
    );
}

/// 0066 folds the targets 0059 wrote under display names, so a mixed-case
/// account sees its own revocations.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn app_password_revocations_from_0059_become_visible_to_their_account() {
    let pool = sqlx::PgPool::connect(
        &support::test_db("app_password_revocations_from_0059_become_visible").await,
    )
    .await
    .expect("connect");
    MIGRATIONS.run_to(58, &pool).await.expect("through 0058");
    let account: i64 = sqlx::query_scalar(
        "INSERT INTO accounts (name, name_folded) VALUES ('Mixed[Case]', 'mixed{case}')
         RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("account");
    sqlx::query(
        "INSERT INTO account_credentials (account_id, kind, argon2_hash, label)
         VALUES ($1, 'app_password', 'hash', 'phone')",
    )
    .bind(account)
    .execute(&pool)
    .await
    .expect("app password");
    MIGRATIONS.run(&pool).await.expect("migrate to latest");
    let page = db::query_account_security_activity(&pool, "MIXED[CASE]", None, audit_page_size(10))
        .await
        .expect("activity");
    assert!(
        page.entries
            .iter()
            .any(|entry| entry.action == "ACCOUNT_APP_PASSWORD_REVOKE"
                && entry.target == "mixed{case}"),
        "{:?}",
        page.entries
    );
}

/// 0062 backfills each database network's backlog with its row id, leaves
/// configuration networks' rows without one, and the key cascades.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn bouncer_backlog_is_backfilled_with_its_network_and_cascades() {
    let pool = sqlx::PgPool::connect(
        &support::test_db("bouncer_backlog_is_backfilled_with_its_network").await,
    )
    .await
    .expect("connect");
    MIGRATIONS.run_to(61, &pool).await.expect("through 0061");
    let account: i64 = sqlx::query_scalar(
        "INSERT INTO accounts (name, name_folded) VALUES ('Alice', 'alice') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("account");
    let network: i64 = sqlx::query_scalar(
        "INSERT INTO bnc_networks (account_id, name, addr, nick, username, kind)
         VALUES ($1, 'Libera', 'irc.libera.chat:6697', 'alice', 'alice', 'irc') RETURNING id",
    )
    .bind(account)
    .fetch_one(&pool)
    .await
    .expect("network");
    sqlx::query(
        "INSERT INTO bnc_buffer (owner, network, line) VALUES
           ('alice', 'libera', 'owned'),
           ('alice', 'configured', 'configured'),
           ('*', 'shared', 'shared')",
    )
    .execute(&pool)
    .await
    .expect("lines");
    MIGRATIONS.run(&pool).await.expect("migrate to latest");
    let rows: Vec<(String, Option<i64>)> =
        sqlx::query_as("SELECT line, network_id FROM bnc_buffer ORDER BY line")
            .fetch_all(&pool)
            .await
            .expect("rows");
    assert_eq!(
        rows,
        [
            ("configured".to_string(), None),
            ("owned".to_string(), Some(network)),
            ("shared".to_string(), None)
        ]
    );
    let refused = sqlx::query(
        "INSERT INTO bnc_buffer (owner, network, line, network_id) VALUES ('*', 'shared', 'x', $1)",
    )
    .bind(network)
    .execute(&pool)
    .await;
    assert!(refused.is_err(), "a server-level line never names a row");
    sqlx::query("DELETE FROM bnc_networks WHERE id = $1")
        .bind(network)
        .execute(&pool)
        .await
        .expect("delete network");
    let late = sqlx::query(
        "INSERT INTO bnc_buffer (owner, network, line, network_id)
         VALUES ('alice', 'libera', 'late', $1)",
    )
    .bind(network)
    .execute(&pool)
    .await;
    assert!(late.is_err(), "a line for a deleted network fails loudly");
    let left: Vec<String> = sqlx::query_scalar("SELECT line FROM bnc_buffer ORDER BY line")
        .fetch_all(&pool)
        .await
        .expect("left");
    assert_eq!(left, ["configured", "shared"]);
}

/// 0065 moves an approved device grant from a display-name string to the
/// account's id, which cascades.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn device_grants_name_their_account_by_id() {
    let pool =
        sqlx::PgPool::connect(&support::test_db("device_grants_name_their_account_by_id").await)
            .await
            .expect("connect");
    MIGRATIONS.run_to(64, &pool).await.expect("through 0064");
    let account: i64 = sqlx::query_scalar(
        "INSERT INTO accounts (name, name_folded) VALUES ('Alice', 'alice') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("account");
    sqlx::query(
        "INSERT INTO device_grants (device_code, user_code, account, expires_at) VALUES
           ('d1', 'U1', 'Alice', now() + interval '5 minutes'),
           ('d2', 'U2', 'Gone', now() + interval '5 minutes'),
           ('d3', 'U3', NULL, now() + interval '5 minutes')",
    )
    .execute(&pool)
    .await
    .expect("grants");
    MIGRATIONS.run(&pool).await.expect("migrate to latest");
    let rows: Vec<(String, Option<i64>)> =
        sqlx::query_as("SELECT device_code, account_id FROM device_grants ORDER BY device_code")
            .fetch_all(&pool)
            .await
            .expect("rows");
    assert_eq!(
        rows,
        [("d1".to_string(), Some(account)), ("d3".to_string(), None)]
    );
    sqlx::query("DELETE FROM accounts WHERE id = $1")
        .bind(account)
        .execute(&pool)
        .await
        .expect("delete account");
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM device_grants")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(left, 1, "the account's approved grant went with it");
}

// ---- audit rows commit with their mutations --------------------------------

fn audit_test_network(name: &str) -> db::BncNetworkRow {
    db::BncNetworkRow {
        kind: NetworkKind::Irc,
        name: name.into(),
        addr: "irc.example:6697".into(),
        tls: true,
        nick: "alice".into(),
        username: Some("alice".into()),
        realname: Some("Alice".into()),
        autojoin: vec![],
        sasl_account: None,
        sasl_password_sealed: None,
        enabled: true,
        server_password_sealed: None,
    }
}

/// A network change and its audit row are one transaction: when the audit row
/// cannot be written, the change does not happen; when it happens, the row
/// names the folded actor and the stored network.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn network_mutations_commit_only_with_their_audit_rows() {
    let pool = db::connect_and_migrate(
        &support::test_db("network_mutations_commit_only_with_their_audit").await,
    )
    .await
    .expect("connect");
    db::create_account_with_contact(&pool, "Alice", "password", None)
        .await
        .expect("alice");
    let audit = db::NetworkAudit {
        actor: "Alice",
        detail: "irc; fields: addr",
    };
    db::create_bnc_network(&pool, "alice", &audit_test_network("Work"), audit)
        .await
        .expect("create");
    let recorded: Vec<(String, String, String)> =
        sqlx::query_as("SELECT actor, action, target FROM audit_log WHERE action LIKE 'NETWORK_%'")
            .fetch_all(&pool)
            .await
            .expect("audit");
    assert_eq!(
        recorded,
        [(
            "alice".to_string(),
            "NETWORK_CREATE".to_string(),
            "alice/Work".to_string()
        )]
    );

    sqlx::raw_sql(
        "CREATE FUNCTION refuse_network_audit() RETURNS trigger LANGUAGE plpgsql AS
             $$ BEGIN
                 IF NEW.action LIKE 'NETWORK_%' THEN RAISE EXCEPTION 'audit refused'; END IF;
                 RETURN NEW;
             END $$;
         CREATE TRIGGER refuse_network_audit BEFORE INSERT ON audit_log
             FOR EACH ROW EXECUTE FUNCTION refuse_network_audit();",
    )
    .execute(&pool)
    .await
    .expect("trigger");
    assert!(
        db::create_bnc_network(&pool, "alice", &audit_test_network("Play"), audit)
            .await
            .is_err()
    );
    assert!(
        db::set_bnc_network_enabled(&pool, "alice", "work", false, audit)
            .await
            .is_err()
    );
    assert!(
        db::delete_bnc_network(&pool, "alice", "work", audit)
            .await
            .is_err()
    );
    let networks = db::list_bnc_networks(&pool, "alice").await.expect("list");
    assert_eq!(
        networks.len(),
        1,
        "no unaudited network was created or deleted"
    );
    assert!(networks[0].enabled, "no unaudited toggle committed");
}

/// ChanServ's founder changes are audited like the owner console's, inside
/// their own transactions, with the founder's folded account as the actor.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn chanserv_changes_are_audited_with_the_founder_as_actor() {
    let pool = db::connect_and_migrate(
        &support::test_db("chanserv_changes_are_audited_with_the_founder").await,
    )
    .await
    .expect("connect");
    for name in ["Founder", "bob"] {
        db::create_account_with_contact(&pool, name, "password", None)
            .await
            .expect("account");
    }
    db::persist_channel_registration(&pool, "#Room", "Founder", &None)
        .await
        .expect("register");
    assert!(matches!(
        db::set_channel_access(&pool, "#room", "Bob", Some("v".into()), "Founder")
            .await
            .expect("access"),
        db::AccessChange::Applied { .. }
    ));
    assert_eq!(
        db::set_channel_keeptopic(&pool, "#room", false, None, "Founder")
            .await
            .expect("keeptopic"),
        Ok(())
    );
    assert_eq!(
        db::set_channel_mlock(&pool, "#room", Some("+nt".into()), "Founder")
            .await
            .expect("mlock"),
        Ok(())
    );
    assert!(matches!(
        db::set_channel_founder(&pool, "#room", "bob", "Founder")
            .await
            .expect("founder"),
        db::FounderTransfer::Transferred { .. }
    ));

    // The former founder can no longer drop it.
    assert_eq!(
        db::drop_channel(&pool, "#room", db::ChannelDropper::Founder("Founder"))
            .await
            .expect("drop"),
        Err(db::ChannelRefusal::NotFounder)
    );
    assert_eq!(
        db::drop_channel(&pool, "#room", db::ChannelDropper::Founder("BOB"))
            .await
            .expect("drop"),
        Ok(())
    );

    let recorded: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT actor, action, target, detail FROM audit_log
         WHERE action LIKE 'CHANNEL_%' AND action <> 'CHANNEL_REGISTER' ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("audit");
    let row = |actor: &str, action: &str, detail: &str| {
        (
            actor.to_string(),
            action.to_string(),
            "#room".to_string(),
            detail.to_string(),
        )
    };
    assert_eq!(
        recorded,
        [
            row("founder", "CHANNEL_ACCESS", "account=bob flags=v"),
            row("founder", "CHANNEL_KEEPTOPIC", "off"),
            row("founder", "CHANNEL_MLOCK", "+nt"),
            row("founder", "CHANNEL_FOUNDER", "bob"),
            row("bob", "CHANNEL_DROP", ""),
        ]
    );
}

/// Every CHATHISTORY window on the attach listener has the specified boundary
/// and direction, resolved in PostgreSQL.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn every_bouncer_history_window_has_the_specified_boundary_and_direction() {
    let pool = db::connect_and_migrate(
        &support::test_db("every_bouncer_history_window_has_the_boundary").await,
    )
    .await
    .expect("connect");
    let buffer = db::open_bnc_buffer(
        &pool,
        Some("alice"),
        "libera",
        db::BncNetworkDefinition::Configured,
    )
    .await
    .expect("buffer");
    for id in 1..=6 {
        db::persist_bnc_line(
            &pool,
            &buffer,
            Some("alice"),
            &format!("@msgid=m{id};time=2026-01-01T00:00:0{id}.000Z :n!u@h PRIVMSG #room :{id}"),
            &e6irc_client::NetworkNames::default(),
        )
        .await
        .expect("persist");
    }
    let window =
        async |paging, first: db::BncHistorySelector, second: db::BncHistorySelector, limit| {
            db::bnc_history_window(
                &pool,
                "alice",
                "libera",
                "#ROOM",
                e6irc_proto::casemap::CaseMapping::Rfc1459,
                paging,
                db::BncHistoryScope::EveryLine,
                &first,
                &second,
                limit,
            )
            .await
            .expect("query")
            .map(|rows| {
                rows.into_iter()
                    .map(|row| row.msgid.expect("msgid"))
                    .collect::<Vec<_>>()
            })
        };
    let ids = |ids: &[u8]| -> Result<Vec<String>, db::UnknownBncMsgid> {
        Ok(ids.iter().map(|id| format!("m{id}")).collect())
    };
    let star = db::BncHistorySelector::Star;
    let msgid = |id: u8| db::BncHistorySelector::Msgid(format!("m{id}"));
    use db::BncHistoryPaging::{After, Around, Before, Between, Latest};
    assert_eq!(
        window(Latest, star.clone(), star.clone(), 2).await,
        ids(&[5, 6])
    );
    assert_eq!(
        window(Latest, msgid(2).clone(), star.clone(), 2).await,
        ids(&[5, 6]),
        "bounded LATEST keeps the newest messages after its pivot"
    );
    assert_eq!(
        window(Before, msgid(5).clone(), star.clone(), 2).await,
        ids(&[3, 4])
    );
    assert_eq!(
        window(After, msgid(2).clone(), star.clone(), 2).await,
        ids(&[3, 4])
    );
    assert_eq!(
        window(Around, msgid(4).clone(), star.clone(), 4).await,
        ids(&[2, 3, 4, 5])
    );
    assert_eq!(
        window(Between, msgid(2).clone(), msgid(6).clone(), 2).await,
        ids(&[3, 4])
    );
    assert_eq!(
        window(Between, msgid(6).clone(), msgid(2).clone(), 2).await,
        ids(&[4, 5]),
        "a reverse BETWEEN window limits from its first, newer endpoint"
    );
    let at =
        |second: u8| db::BncHistorySelector::Timestamp(format!("2026-01-01T00:00:0{second}.000Z"));
    assert_eq!(
        window(After, at(3).clone(), star.clone(), 10).await,
        ids(&[4, 5, 6]),
        "AFTER a timestamp excludes the message at it"
    );
    assert_eq!(
        window(Before, at(3).clone(), star.clone(), 10).await,
        ids(&[1, 2]),
        "BEFORE a timestamp excludes the message at it"
    );
    assert_eq!(
        window(Around, at(3).clone(), star.clone(), 2).await,
        ids(&[2, 3]),
        "AROUND a timestamp includes the message at it in its newer half"
    );
    for paging in [Latest, Before, After, Around] {
        assert_eq!(
            window(paging, msgid(9).clone(), star.clone(), 2).await,
            Err(db::UnknownBncMsgid)
        );
    }
    for (first, second) in [(msgid(9), msgid(2)), (msgid(2), msgid(9))] {
        assert_eq!(
            window(Between, first.clone(), second.clone(), 2).await,
            Err(db::UnknownBncMsgid)
        );
    }
    let late = db::BncHistorySelector::Timestamp("2027-01-01T00:00:00.000Z".into());
    assert_eq!(window(After, late.clone(), star.clone(), 2).await, ids(&[]));

    // Each window is an index range scan under its LIMIT, never a load of the
    // whole target.
    let mut connection = pool.acquire().await.expect("connection");
    sqlx::query("SET enable_seqscan = off")
        .execute(&mut *connection)
        .await
        .expect("disable seqscan");
    let plan: Vec<String> = sqlx::query_scalar(
        "EXPLAIN SELECT id, line, msgid, sent_at FROM bnc_buffer
         WHERE owner = 'alice' AND network = 'libera' AND target = '#room'
           AND (sent_at, id) > ('2026-01-01T00:00:02.000Z', 2)
         ORDER BY sent_at ASC, id ASC LIMIT 2",
    )
    .fetch_all(&mut *connection)
    .await
    .expect("explain");
    let plan = plan.join("\n");
    assert!(plan.contains("Limit"), "{plan}");
    assert!(plan.contains("bnc_buffer_sent_at_idx"), "{plan}");
}

/// The export's growing sections are read a page at a time and still form one
/// JSON document holding every row, in order.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn the_account_export_pages_its_history_into_one_document() {
    let pool = db::connect_and_migrate(
        &support::test_db("the_account_export_pages_its_history_into_one").await,
    )
    .await
    .expect("connect");
    db::create_account_with_contact(&pool, "Alice", "password", None)
        .await
        .expect("alice");
    sqlx::query(
        "INSERT INTO messages (msgid, target, sender_prefix, sender_account, kind, body, ts)
         SELECT 'm' || n, '#room', 'Alice!u@h', 'Alice', 'privmsg', 'line ' || n,
                now() - make_interval(secs => 2000 - n)
         FROM generate_series(1, 1234) n",
    )
    .execute(&pool)
    .await
    .expect("messages");
    sqlx::query(
        "INSERT INTO bnc_buffer (owner, network, line)
         SELECT 'alice', 'configured', 'backlog ' || n FROM generate_series(1, 777) n",
    )
    .execute(&pool)
    .await
    .expect("backlog");
    let export = export_account(&pool, "alice").await.expect("Alice");
    let value: serde_json::Value = serde_json::from_str(&export).expect("one JSON document");
    let messages = value["messages"].as_array().expect("messages");
    assert_eq!(messages.len(), 1234);
    assert_eq!(messages[0]["message_id"], "m1");
    assert_eq!(messages[1233]["message_id"], "m1234");
    let backlog = value["bouncer_buffer"].as_array().expect("backlog");
    assert_eq!(backlog.len(), 777);
    assert_eq!(backlog[776]["line"], "backlog 777");
    assert_eq!(value["account"]["name"], "Alice");
    assert!(export_account(&pool, "nobody").await.is_none());
}

/// Maintenance trims whatever buffer is over the per-network cap, a bounded
/// batch at a time, walking every buffer in turn.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn maintenance_trims_buffers_over_the_backlog_cap() {
    let pool = db::connect_and_migrate(
        &support::test_db("maintenance_trims_buffers_over_the_backlog_cap").await,
    )
    .await
    .expect("connect");
    sqlx::query(
        "INSERT INTO bnc_buffer (owner, network, line)
         SELECT 'alice', 'over', 'over ' || n FROM generate_series(1, 5200) n
         UNION ALL
         SELECT 'bob', 'under', 'under ' || n FROM generate_series(1, 300) n",
    )
    .execute(&pool)
    .await
    .expect("seed");
    let mut sweep = db::BncCapSweep::default();
    assert_eq!(
        db::trim_bnc_buffers_over_cap(&pool, &mut sweep)
            .await
            .expect("sweep"),
        200
    );
    let rows: Vec<(String, i64)> =
        sqlx::query_as("SELECT owner, count(*) FROM bnc_buffer GROUP BY owner ORDER BY owner")
            .fetch_all(&pool)
            .await
            .expect("count");
    assert_eq!(
        rows,
        [("alice".to_string(), 5_000), ("bob".to_string(), 300)]
    );
    let oldest: String =
        sqlx::query_scalar("SELECT line FROM bnc_buffer WHERE owner = 'alice' ORDER BY id LIMIT 1")
            .fetch_one(&pool)
            .await
            .expect("oldest");
    assert_eq!(oldest, "over 201", "the oldest lines go, the newest stay");
    assert_eq!(
        db::trim_bnc_buffers_over_cap(&pool, &mut sweep)
            .await
            .expect("second sweep"),
        0
    );
}

/// Wait until some session of this test's database is blocked on a lock: the
/// point an interleaving test has arranged for.
async fn wait_for_lock_wait(pool: &sqlx::PgPool) {
    tokio::time::timeout(deadline::HANG, async {
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity
                 WHERE datname = current_database() AND wait_event_type = 'Lock'",
            )
            .fetch_one(pool)
            .await
            .expect("lock waits");
            if waiting > 0 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("no session ever waited on a lock");
}

/// Alice (the administrator) and Bob, for the deletion interleavings below.
async fn alice_and_bob(test: &str) -> (sqlx::PgPool, i64) {
    let pool = db::connect_and_migrate(&support::test_db(test).await)
        .await
        .expect("connect");
    db::bootstrap_first_admin(&pool, "Alice", "administrator password")
        .await
        .expect("Alice");
    let bob_id = db::create_account_with_contact(&pool, "Bob", "member password", None)
        .await
        .expect("Bob");
    (pool, bob_id)
}

/// A founder transfer to an account being deleted, still uncommitted when the
/// deletion counts founded channels, used to be invisible to that count while
/// its foreign-key lock did not conflict with deletion's row lock: the DELETE
/// then waited for the transfer to commit and its cascade removed the channel.
/// Deletion now waits for the transfer before counting, and refuses.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn account_deletion_never_cascades_through_a_concurrent_founder_transfer() {
    let (pool, bob_id) =
        alice_and_bob("account_deletion_never_cascades_through_a_concurrent_founder_transfer")
            .await;
    sqlx::query(
        "INSERT INTO channels (name, name_folded, founder_account_id)
         SELECT '#room', '#room', id FROM accounts WHERE name_folded = 'alice'",
    )
    .execute(&pool)
    .await
    .expect("channel");
    let mut transfer = pool.begin().await.expect("transfer transaction");
    sqlx::query("UPDATE channels SET founder_account_id = $1 WHERE name_folded = '#room'")
        .bind(bob_id)
        .execute(&mut *transfer)
        .await
        .expect("transfer to Bob");
    let deletion = tokio::spawn({
        let pool = pool.clone();
        async move { db::delete_account_permanently(&pool, bob_id, "Alice", &[]).await }
    });
    wait_for_lock_wait(&pool).await;
    transfer.commit().await.expect("commit transfer");
    let outcome = tokio::time::timeout(deadline::HANG, deletion)
        .await
        .expect("deletion finished")
        .expect("deletion task");
    assert!(
        matches!(outcome, Err(db::DbError::AccountOwnsChannels(1))),
        "{outcome:?}"
    );
    let founder: Option<String> = sqlx::query_scalar(
        "SELECT a.name FROM channels c JOIN accounts a ON a.id = c.founder_account_id
         WHERE c.name_folded = '#room'",
    )
    .fetch_optional(&pool)
    .await
    .expect("channel lookup");
    assert_eq!(founder.as_deref(), Some("Bob"), "the channel must survive");
}

/// However the application counts, storage refuses to delete a founder: the
/// founder reference restricts rather than cascading the channel away.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn storage_refuses_to_delete_a_channel_founder() {
    let (pool, bob_id) = alice_and_bob("storage_refuses_to_delete_a_channel_founder").await;
    sqlx::query(
        "INSERT INTO channels (name, name_folded, founder_account_id) VALUES ('#bob', '#bob', $1)",
    )
    .bind(bob_id)
    .execute(&pool)
    .await
    .expect("channel");
    let error = sqlx::query("DELETE FROM accounts WHERE id = $1")
        .bind(bob_id)
        .execute(&pool)
        .await
        .expect_err("deleting a founder must fail");
    // Named by constraint, not SQLSTATE: PostgreSQL 18 reports a RESTRICT
    // violation as 23001 (restrict_violation) where earlier releases say 23503.
    assert_eq!(
        error.as_database_error().and_then(|e| e.constraint()),
        Some("channels_founder_account_id_fkey"),
        "{error}"
    );
    let channels: i64 = sqlx::query_scalar("SELECT count(*) FROM channels")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(channels, 1);
}

async fn messages_naming_bob(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM messages
         WHERE sender_account IN ('Bob', 'bob') OR dm_peers @> ARRAY['bob']",
    )
    .fetch_one(pool)
    .await
    .expect("count")
}

/// Write one message the way the database worker's batch does (a plain
/// INSERT; the storage trigger is what decides).
async fn log_message<'e, E>(executor: E, msgid: &str, sender: &str, dm_peers: Option<&[&str]>)
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query(
        "INSERT INTO messages (msgid, target, sender_prefix, sender_account, kind, body, ts, dm_peers)
         VALUES ($1, '#test', $2 || '!u@h', $2, 'privmsg', 'late', now(), $3)",
    )
    .bind(msgid)
    .bind(sender)
    .bind(dm_peers)
    .execute(executor)
    .await
    .expect("insert message");
}

/// Messages reach PostgreSQL asynchronously -- batched by the database worker,
/// from shards that apply an account's suspension at their own pace -- so one
/// naming an account could commit after deletion's purge. Storage now refuses
/// every such row, whatever its timing: in flight when deletion starts (the
/// purge waits for it and removes it), written while deletion holds the
/// account (dropped), or after it committed (dropped).
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn messages_naming_a_deleted_account_never_outlive_the_purge() {
    let (pool, bob_id) =
        alice_and_bob("messages_naming_a_deleted_account_never_outlive_the_purge").await;

    // While deletion holds the account row, a row naming it is not stored;
    // once the lock is gone without a deletion, it is.
    let mut deleting = pool.begin().await.expect("deletion stand-in");
    sqlx::query("SELECT 1 FROM accounts WHERE id = $1 FOR UPDATE")
        .bind(bob_id)
        .execute(&mut *deleting)
        .await
        .expect("lock Bob");
    log_message(&pool, "during", "Bob", None).await;
    assert_eq!(messages_naming_bob(&pool).await, 0);
    deleting.rollback().await.expect("release");
    log_message(&pool, "kept", "Bob", None).await;
    assert_eq!(messages_naming_bob(&pool).await, 1);

    // A batch still uncommitted when deletion starts: deletion waits for it,
    // and its purge removes the row.
    let mut batch = pool.begin().await.expect("batch transaction");
    log_message(&mut *batch, "in-flight", "Bob", None).await;
    let deletion = tokio::spawn({
        let pool = pool.clone();
        async move { db::delete_account_permanently(&pool, bob_id, "Alice", &[]).await }
    });
    wait_for_lock_wait(&pool).await;
    batch.commit().await.expect("commit batch");
    tokio::time::timeout(deadline::HANG, deletion)
        .await
        .expect("deletion finished")
        .expect("deletion task")
        .expect("delete")
        .expect("Bob");
    assert_eq!(messages_naming_bob(&pool).await, 0);

    // After the deletion committed: neither as sender nor as a peer.
    log_message(&pool, "late-sent", "Bob", None).await;
    log_message(&pool, "late-dm", "Alice", Some(&["alice", "bob"])).await;
    assert_eq!(messages_naming_bob(&pool).await, 0);
    // Rows naming a live account, or a name no account ever held, are kept.
    log_message(&pool, "alice", "Alice", None).await;
    log_message(&pool, "service", "SomeService", None).await;
    let kept: i64 = sqlx::query_scalar("SELECT count(*) FROM messages")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(kept, 2);
}

/// RFC 8628 has a device that polls past expiry told `expired_token`, its cue
/// to start over. Grants were pruned the moment they expired, so the poll
/// found no row and answered as for an unknown code; they are now kept for a
/// grace period, through both pruning paths.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn an_expired_device_grant_polls_as_expired_until_pruned() {
    let pool = db::connect_and_migrate(
        &support::test_db("an_expired_device_grant_polls_as_expired_until_pruned").await,
    )
    .await
    .expect("connect");
    let (expired, _) = db::create_device_grant(&pool).await.expect("grant");
    let (stale, _) = db::create_device_grant(&pool).await.expect("grant");
    sqlx::query(
        "UPDATE device_grants SET expires_at = CASE device_code
             WHEN $1 THEN now() - interval '1 second'
             ELSE now() - interval '1 day' END
         WHERE device_code IN ($1, $2)",
    )
    .bind(&expired)
    .bind(&stale)
    .execute(&pool)
    .await
    .expect("expire");
    // Both pruning paths: a new grant, and storage maintenance.
    db::create_device_grant(&pool).await.expect("grant");
    let report = db::run_storage_maintenance(
        &pool,
        db::StorageRetention {
            history_days: 30,
            audit_days: 365,
            observability_hours: 1,
        },
    )
    .await
    .expect("maintenance");
    assert_eq!(report.device_grants, 0, "the stale grant went at start");
    assert_eq!(
        db::poll_device_grant(&pool, &expired, "device")
            .await
            .expect("poll"),
        db::DeviceStatus::Expired
    );
    assert_eq!(
        db::poll_device_grant(&pool, &stale, "device")
            .await
            .expect("poll"),
        db::DeviceStatus::Unknown,
        "past the grace period the grant is pruned"
    );
}

/// Password guessing against one account is bounded whatever addresses it
/// comes from: past `LOGIN_ATTEMPT_LIMIT` attempts in the window every check —
/// the correct password included — is refused unverified, on every path that
/// checks a password, and the refusal is the same for a name no account holds.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn password_attempts_are_bounded_per_account_name() {
    let pool = db::connect_and_migrate(
        &support::test_db("password_attempts_are_bounded_per_account_name").await,
    )
    .await
    .expect("connect");
    db::create_account_with_contact(&pool, "alice", "correct horse", None)
        .await
        .expect("alice");
    db::create_account_with_contact(&pool, "bob", "bob password", None)
        .await
        .expect("bob");
    // A verified password ends the window: a user who mistypes and then gets
    // it right is not left counting towards a lockout.
    for _ in 0..3 {
        assert_eq!(
            db::verify_credentials(&pool, "alice", "typo")
                .await
                .expect("verify"),
            None
        );
    }
    assert_eq!(
        db::verify_local_password(&pool, "ALICE", "correct horse")
            .await
            .expect("verify")
            .as_deref(),
        Some("alice")
    );
    for _ in 0..db::LOGIN_ATTEMPT_LIMIT {
        assert_eq!(
            db::verify_credentials(&pool, "alice", "guess")
                .await
                .expect("verify"),
            None
        );
    }
    let throttled = |result: Result<Option<String>, db::DbError>| match result {
        Err(db::DbError::LoginThrottled(retry)) => {
            assert!(
                (1..=db::LOGIN_ATTEMPT_WINDOW.as_secs()).contains(&retry.seconds()),
                "{retry:?}"
            );
            true
        }
        _ => false,
    };
    assert!(throttled(
        db::verify_credentials(&pool, "Alice", "correct horse").await
    ));
    assert!(throttled(
        db::verify_local_password(&pool, "alice", "correct horse").await
    ));
    assert!(matches!(
        db::issue_app_password(&pool, "alice", "correct horse", "laptop").await,
        Err(db::DbError::LoginThrottled(_))
    ));
    let session = db::create_web_session(&pool, "alice", None)
        .await
        .expect("session");
    assert!(matches!(
        db::change_local_password(&pool, "alice", "correct horse", "new password", &session).await,
        Err(db::DbError::LoginThrottled(_))
    ));
    // Another account is untouched.
    assert_eq!(
        db::verify_credentials(&pool, "bob", "bob password")
            .await
            .expect("verify")
            .as_deref(),
        Some("bob")
    );
    // A name no account holds is throttled the same way, so a refusal says
    // nothing about which names exist.
    for _ in 0..db::LOGIN_ATTEMPT_LIMIT {
        assert_eq!(
            db::verify_credentials(&pool, "nobody", "guess")
                .await
                .expect("verify"),
            None
        );
    }
    assert!(throttled(
        db::verify_credentials(&pool, "nobody", "guess").await
    ));
    // Once the window has passed the account is admitted again.
    sqlx::query(
        "UPDATE login_attempts SET window_started_at = now() - interval '1 hour'
         WHERE name_folded = 'alice'",
    )
    .execute(&pool)
    .await
    .expect("age the window");
    assert_eq!(
        db::verify_credentials(&pool, "alice", "correct horse")
            .await
            .expect("verify")
            .as_deref(),
        Some("alice")
    );
}

/// A history read never reaches below its floor: not in a window, not through
/// a pivot older than the floor, and not in the activity TARGETS reports.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn history_reads_stop_at_their_floor() {
    use e6ircd::core::{HistoryFloor, HistoryQuery, SelectorBound};
    let pool =
        db::connect_and_migrate(&support::test_db("history_reads_stop_at_their_floor").await)
            .await
            .expect("connect");
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
    let millis = e6irc_proto::time::Millis::from_millis;
    let floor = HistoryFloor::Since(millis(3000));
    let read = |query: HistoryQuery| {
        let pool = pool.clone();
        async move {
            db::query_history(&pool, "#h", floor, query)
                .await
                .expect("history")
                .into_iter()
                .map(|row| row.msgid)
                .collect::<Vec<_>>()
        }
    };
    assert_eq!(
        read(HistoryQuery::Latest { limit: 10 }).await,
        ["m3000", "m4000", "m5000"]
    );
    assert_eq!(
        read(HistoryQuery::Before {
            before_ts: millis(5000),
            limit: 10
        })
        .await,
        ["m3000", "m4000"]
    );
    assert_eq!(
        read(HistoryQuery::Around {
            around_ts: millis(3000),
            limit: 4
        })
        .await,
        ["m3000", "m4000"]
    );
    assert_eq!(
        read(HistoryQuery::BeforeMsgid {
            msgid: "m4000".into(),
            limit: 10
        })
        .await,
        ["m3000"]
    );
    // A pivot from below the floor positions nothing.
    for query in [
        HistoryQuery::AfterMsgid {
            msgid: "m1000".into(),
            limit: 10,
        },
        HistoryQuery::BetweenSelectors {
            first: SelectorBound::Msgid("m1000".into()),
            second: SelectorBound::Timestamp(millis(9000)),
            limit: 10,
        },
    ] {
        assert!(read(query.clone()).await.is_empty(), "{query:?}");
    }
    assert_eq!(
        read(HistoryQuery::BetweenSelectors {
            first: SelectorBound::Timestamp(millis(0)),
            second: SelectorBound::Timestamp(millis(9000)),
            limit: 10,
        })
        .await,
        ["m3000", "m4000", "m5000"]
    );
    // The whole record is still there for a reader who may see it.
    assert_eq!(
        db::query_history(
            &pool,
            "#h",
            HistoryFloor::Whole,
            HistoryQuery::Latest { limit: 10 }
        )
        .await
        .expect("history")
        .len(),
        5
    );
    let targets = |floor: HistoryFloor| {
        let pool = pool.clone();
        async move {
            db::query_targets(
                &pool,
                &[("#h".to_string(), floor)],
                None,
                millis(0),
                millis(99_000),
                10,
            )
            .await
            .expect("targets")
        }
    };
    assert_eq!(
        targets(HistoryFloor::Since(millis(3000))).await,
        [("#h".to_string(), millis(5000))]
    );
    assert!(
        targets(HistoryFloor::Since(millis(6000))).await.is_empty(),
        "a channel whose activity all predates the floor is not a buffer"
    );
}

/// A configured administrator's name cannot be claimed by an invitation, even
/// one issued before the name was configured; startup can name the configured
/// administrators no account holds yet.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn configured_administrator_names_are_not_claimable_by_invitation() {
    let pool = db::connect_and_migrate(
        &support::test_db("configured_administrator_names_are_not_claimable").await,
    )
    .await
    .expect("connect");
    db::create_account_with_contact(&pool, "Alice", "pw", None)
        .await
        .expect("alice");
    let token = db::issue_account_invitation(
        &pool,
        "Root",
        None,
        false,
        e6ircd::identity::AccountInvitationLifetimeDays::new(1).expect("lifetime"),
        "Alice",
    )
    .await
    .expect("issued before the name was configured");
    assert!(matches!(
        db::accept_account_invitation(&pool, &token, "chosen password", &["root".to_string()])
            .await,
        Err(db::DbError::InvitationUnavailable)
    ));
    assert_eq!(
        db::unclaimed_account_names(&pool, &["ALICE".to_string(), "Root".to_string()])
            .await
            .expect("unclaimed"),
        ["Root"]
    );
}

/// The console owns the settings the first database-backed start imports. A
/// later start whose configuration states one of them with another value is
/// refused naming it — never applying the stored value over it in silence, the
/// way a name removed from `http.admin_accounts` once kept its authority and a
/// rotated client secret was never used — and a setting it does not state is
/// the console's alone.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn a_stated_console_setting_must_agree_with_the_stored_revision() {
    let url =
        support::test_db("a_stated_console_setting_must_agree_with_the_stored_revision").await;
    let key_path =
        std::env::temp_dir().join(format!("e6irc-db-managed-drift-key-{}", std::process::id()));
    std::fs::write(&key_path, e6ircd::secret::SecretKey::generate().to_base64())
        .expect("write key");
    let document = |admin_accounts: Option<&str>, client_secret: &str| -> Config {
        let admin_accounts = admin_accounts
            .map(|accounts| format!("admin_accounts = {accounts}"))
            .unwrap_or_default();
        let text = format!(
            r#"
            server_name = "irc.drift.example"
            network_name = "DriftNet"
            [[listeners]]
            addr = "127.0.0.1:0"
            [database]
            url = {url:?}
            [secrets]
            key_file = {key_path:?}
            [http]
            addr = "127.0.0.1:0"
            public_url = "http://irc.drift.example"
            secure_cookies = false
            {admin_accounts}
            [[oidc]]
            name = "idp"
            issuer_url = "https://idp.drift.example"
            client_id = "e6irc"
            client_secret = "{client_secret}"
            account_claim = "preferred_username"
            token_endpoint_auth_method = "client_secret_post"
            "#
        );
        Config::from_table(toml::from_str(&text).expect("document"), &[]).expect("valid")
    };
    let refusal = |config: Config| async move {
        match net::start(config).await {
            Ok(_) => panic!("a conflicting start was not refused"),
            Err(error) => error.to_string(),
        }
    };
    const ADMINS: &str = r#"["alice", "bob"]"#;

    // First start: the stated values are imported, the secret sealed.
    let running = net::start(document(Some(ADMINS), "first-client-secret"))
        .await
        .expect("first start");
    running.shutdown.run().await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    let imported = db::load_managed_config(&pool).await.expect("imported");
    assert_eq!(imported.revision, 1);
    assert_eq!(imported.settings.admin_accounts, ["alice", "bob"]);
    assert!(e6ircd::secret::is_sealed(
        &imported.settings.oidc_providers[0].client_secret
    ));

    // The same statement again agrees with what it imported.
    let running = net::start(document(Some(ADMINS), "first-client-secret"))
        .await
        .expect("unchanged restart");
    running.shutdown.run().await;

    // Removing an administrator from the statement cannot quietly keep them.
    let refused = refusal(document(Some(r#"["alice"]"#), "first-client-secret")).await;
    assert!(refused.contains("http.admin_accounts"), "{refused}");
    assert!(!refused.contains("oidc"), "{refused}");

    // A rotated client secret is named, and neither value is printed.
    let refused = refusal(document(Some(ADMINS), "second-client-secret")).await;
    assert!(refused.contains("oidc[0].client_secret"), "{refused}");
    assert!(
        !refused.contains("first-client") && !refused.contains("second-client"),
        "{refused}"
    );
    assert!(!refused.contains("http.admin_accounts"), "{refused}");

    // The console changes the list; a configuration that no longer states it
    // starts, and the console's list is the one in force.
    let mut edited = imported.settings.clone();
    edited.admin_accounts = vec!["carol".into()];
    db::save_managed_config(
        &pool,
        imported.revision,
        &edited,
        &db::AuditPrincipal::account("alice"),
        "admins",
    )
    .await
    .expect("console edit");
    let refused = refusal(document(Some(ADMINS), "first-client-secret")).await;
    assert!(refused.contains("http.admin_accounts"), "{refused}");
    let running = net::start(document(None, "first-client-secret"))
        .await
        .expect("an unstated setting is not a conflict");
    running.shutdown.run().await;
    let current = db::load_managed_config(&pool).await.expect("current");
    assert_eq!(current.settings.admin_accounts, ["carol"]);
    assert_eq!(
        current.revision,
        imported.revision + 1,
        "nothing was rewritten"
    );
    std::fs::remove_file(&key_path).ok();
}

// ---- NickServ nicks and the ChanServ successor (DESIGN §7.6) ---------------

/// A grouped nick belongs to exactly one account: GROUP refuses another
/// account's name or nick and a retired name, account creation refuses a
/// grouped nick (storage refuses both even when asked directly), the group is
/// capped, and any of an account's nicks signs in to it.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn grouped_nicks_belong_to_one_account_and_sign_in_to_it() {
    let (pool, bob_id) =
        alice_and_bob("grouped_nicks_belong_to_one_account_and_sign_in_to_it").await;
    use db::NickGroupOutcome::{AlreadyYours, Grouped, Taken, TooMany};
    let group = |account: &'static str, nick: &'static str| {
        let pool = pool.clone();
        async move { db::group_nick(&pool, account, nick).await.expect("group") }
    };
    assert_eq!(group("alice", "Alice_Away").await, Grouped);
    assert_eq!(group("ALICE", "alice_away").await, AlreadyYours);
    assert_eq!(group("alice", "alice").await, AlreadyYours);
    assert_eq!(group("bob", "alice_away").await, Taken);
    assert_eq!(group("alice", "Bob").await, Taken);
    assert_eq!(
        db::group_nick(&pool, "nobody", "free")
            .await
            .expect("group"),
        db::NickGroupOutcome::AccountMissing
    );

    // Five nicks at most, the account's name among them.
    for nick in ["a2", "a3", "a4"] {
        assert_eq!(group("alice", nick).await, Grouped);
    }
    assert_eq!(group("alice", "a5").await, TooMany);

    assert_eq!(
        db::verify_credentials(&pool, "ALICE_AWAY", "administrator password")
            .await
            .expect("verify"),
        Some("Alice".to_string())
    );
    assert_eq!(
        db::verify_local_password(&pool, "a2", "administrator password")
            .await
            .expect("verify"),
        Some("Alice".to_string())
    );
    assert!(matches!(
        db::create_account_with_contact(&pool, "Alice_away", "pw", None).await,
        Err(db::DbError::DuplicateAccount(_))
    ));
    // A services nick is no account's name, whichever path creates it.
    assert!(matches!(
        db::create_account_with_contact(&pool, "NickServ", "pw", None).await,
        Err(db::DbError::DuplicateAccount(_))
    ));
    assert!(matches!(
        db::find_or_create_oidc_account(&pool, "https://issuer.example", "subject", "ChanServ")
            .await,
        Err(db::DbError::DuplicateAccount(_))
    ));
    // The storage triggers refuse a direct write too, by their own names: any
    // other failure would not prove the invariant.
    let refused_by = |result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>| {
        result
            .expect_err("storage accepted the write")
            .as_database_error()
            .and_then(|error| error.constraint().map(str::to_string))
    };
    let direct = sqlx::query("INSERT INTO accounts (name, name_folded) VALUES ('a3', 'a3')")
        .execute(&pool)
        .await;
    assert_eq!(
        refused_by(direct).as_deref(),
        Some("accounts_name_not_grouped"),
        "storage must refuse an account named like a grouped nick"
    );
    let direct = sqlx::query(
        "INSERT INTO account_nicks (nick_folded, nick, account_id) VALUES ('bob', 'bob', $1)",
    )
    .bind(bob_id)
    .execute(&pool)
    .await;
    assert_eq!(
        refused_by(direct).as_deref(),
        Some("account_nicks_not_an_account_name"),
        "storage must refuse grouping an account's name"
    );

    assert!(
        db::ungroup_nick(&pool, "alice", "A4")
            .await
            .expect("ungroup")
    );
    assert!(
        !db::ungroup_nick(&pool, "alice", "a4")
            .await
            .expect("ungroup")
    );
    assert!(!db::ungroup_nick(&pool, "bob", "a2").await.expect("ungroup"));

    use db::NickEnforceChange::{AccountMissing, Changed, Unchanged};
    assert_eq!(
        db::set_nick_enforce(&pool, "ALICE", true)
            .await
            .expect("set"),
        Changed
    );
    assert_eq!(
        db::set_nick_enforce(&pool, "alice", true)
            .await
            .expect("set"),
        Unchanged
    );
    assert_eq!(
        db::set_nick_enforce(&pool, "nobody", true)
            .await
            .expect("set"),
        AccountMissing
    );
    assert_eq!(
        db::list_nick_registrations(&pool).await.expect("list"),
        db::NickRegistrations {
            grouped: vec![
                ("a2".into(), "alice".into()),
                ("a3".into(), "alice".into()),
                ("alice_away".into(), "alice".into()),
            ],
            enforced: vec!["alice".into()],
        }
    );

    let info = db::nickserv_account_info(&pool, "A3")
        .await
        .expect("info")
        .expect("alice");
    assert_eq!(info.name, "Alice");
    assert_eq!(info.nicks, ["Alice", "Alice_Away", "a2", "a3"]);
    assert!(info.enforce);
    assert_eq!(
        db::nickserv_account_info(&pool, "nobody")
            .await
            .expect("info"),
        None
    );
    let audited: Vec<String> =
        sqlx::query_scalar("SELECT action FROM audit_log WHERE action LIKE 'NICK_%' ORDER BY id")
            .fetch_all(&pool)
            .await
            .expect("audit");
    assert_eq!(
        audited,
        [
            "NICK_GROUP",
            "NICK_GROUP",
            "NICK_GROUP",
            "NICK_GROUP",
            "NICK_UNGROUP",
            "NICK_ENFORCE"
        ]
    );

    // A retired name cannot be grouped; a deleted account's nicks go with it.
    db::delete_account_permanently(&pool, bob_id, "Alice", &[])
        .await
        .expect("delete")
        .expect("Bob");
    assert_eq!(group("alice", "bob").await, Taken);
    let alice_id = db::account_id_by_name(&pool, "alice")
        .await
        .expect("lookup")
        .expect("alice");
    sqlx::query("UPDATE accounts SET flags = 0 WHERE id = $1")
        .bind(alice_id)
        .execute(&pool)
        .await
        .expect("demote");
    db::create_account_with_contact(&pool, "Carol", "pw", None)
        .await
        .expect("Carol");
    sqlx::query("UPDATE accounts SET flags = 1 WHERE name_folded = 'carol'")
        .execute(&pool)
        .await
        .expect("promote");
    db::delete_account_permanently(&pool, alice_id, "Carol", &[])
        .await
        .expect("delete")
        .expect("Alice");
    assert_eq!(
        db::list_nick_registrations(&pool).await.expect("list"),
        db::NickRegistrations::default()
    );
}

/// ChanServ SET SUCCESSOR: the successor must be an account other than the
/// founder; deleting the founder passes each channel with a successor to it
/// (audited) and still refuses while one without a successor remains; a
/// transfer to the successor, or the successor's own deletion, clears it.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn a_deleted_founders_channels_pass_to_their_successors() {
    let (pool, bob_id) =
        alice_and_bob("a_deleted_founders_channels_pass_to_their_successors").await;
    db::create_account_with_contact(&pool, "Carol", "pw", None)
        .await
        .expect("Carol");
    let dave_id = db::create_account_with_contact(&pool, "Dave", "pw", None)
        .await
        .expect("Dave");
    sqlx::query(
        "INSERT INTO channels (name, name_folded, founder_account_id)
         SELECT c.name, c.name, a.id FROM accounts a,
             (VALUES ('#a', 'bob'), ('#b', 'bob'), ('#c', 'alice'), ('#d', 'alice'))
                 AS c (name, founder)
         WHERE a.name_folded = c.founder",
    )
    .execute(&pool)
    .await
    .expect("channels");
    use db::ChannelRefusal::{ChannelMissing, NotFounder};
    use db::SuccessorChange::{AccountMissing, IsFounder, Refused};
    let applied = |successor: &str| db::SuccessorChange::Applied {
        successor: Some(successor.to_string()),
    };
    let set = |channel: &'static str, successor: Option<&'static str>, actor: &'static str| {
        let pool = pool.clone();
        async move {
            db::set_channel_successor(&pool, channel, successor, actor)
                .await
                .expect("successor")
        }
    };
    assert_eq!(set("#A", Some("carol"), "bob").await, applied("Carol"));
    assert_eq!(set("#a", Some("bob"), "bob").await, IsFounder);
    assert_eq!(set("#a", Some("nobody"), "bob").await, AccountMissing);
    assert_eq!(
        set("#nope", Some("carol"), "bob").await,
        Refused(ChannelMissing)
    );
    // Only the founder names the successor, checked with the row locked.
    assert_eq!(set("#a", Some("dave"), "alice").await, Refused(NotFounder));
    let successor = |channel: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Option<String>>(
                "SELECT a.name_folded FROM channels c
                 LEFT JOIN accounts a ON a.id = c.successor_account_id
                 WHERE c.name_folded = $1",
            )
            .bind(channel)
            .fetch_one(&pool)
            .await
            .expect("successor")
        }
    };
    assert_eq!(successor("#a").await.as_deref(), Some("carol"));

    // #b has no successor: the deletion is refused whole, #a included.
    assert!(matches!(
        db::account_deletion_target(&pool, bob_id, &[]).await,
        Err(db::DbError::AccountOwnsChannels(1))
    ));
    assert!(matches!(
        db::delete_account_permanently(&pool, bob_id, "Alice", &[]).await,
        Err(db::DbError::AccountOwnsChannels(1))
    ));
    assert_eq!(successor("#a").await.as_deref(), Some("carol"));

    assert_eq!(set("#b", Some("dave"), "bob").await, applied("Dave"));
    let deleted = db::delete_account_permanently(&pool, bob_id, "Alice", &[])
        .await
        .expect("delete")
        .expect("Bob");
    let mut successions = deleted.successions.clone();
    successions.sort_by(|a, b| a.channel.cmp(&b.channel));
    assert_eq!(
        successions,
        [
            db::ChannelSuccession {
                channel: "#a".into(),
                founder: "carol".into(),
            },
            db::ChannelSuccession {
                channel: "#b".into(),
                founder: "dave".into(),
            },
        ]
    );
    let founders: Vec<(String, String)> = sqlx::query_as(
        "SELECT c.name_folded, a.name_folded FROM channels c
         JOIN accounts a ON a.id = c.founder_account_id ORDER BY c.name_folded",
    )
    .fetch_all(&pool)
    .await
    .expect("founders");
    assert_eq!(
        founders,
        [
            ("#a".to_string(), "carol".to_string()),
            ("#b".into(), "dave".into()),
            ("#c".into(), "alice".into()),
            ("#d".into(), "alice".into()),
        ]
    );
    assert_eq!(successor("#a").await, None, "the successor became founder");
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action = 'CHANNEL_SUCCESSION' AND actor = 'alice'",
    )
    .fetch_one(&pool)
    .await
    .expect("audit");
    assert_eq!(audited, 2);

    // A transfer to the successor leaves no successor; deleting a successor
    // clears it.
    assert_eq!(set("#c", Some("carol"), "alice").await, applied("Carol"));
    assert!(matches!(
        db::set_channel_founder(&pool, "#c", "carol", "alice")
            .await
            .expect("transfer"),
        db::FounderTransfer::Transferred { .. }
    ));
    assert_eq!(successor("#c").await, None);
    assert_eq!(set("#d", Some("dave"), "alice").await, applied("Dave"));
    assert_eq!(set("#b", Some("carol"), "dave").await, applied("Carol"));
    assert!(matches!(
        db::set_channel_founder(&pool, "#b", "alice", "dave")
            .await
            .expect("transfer"),
        db::FounderTransfer::Transferred { .. }
    ));
    // Any transfer clears the successor: the new founder names their own.
    assert_eq!(successor("#b").await, None, "a transfer kept the successor");
    let deleted = db::delete_account_permanently(&pool, dave_id, "Alice", &[])
        .await
        .expect("delete")
        .expect("Dave");
    assert!(deleted.successions.is_empty());
    assert_eq!(
        successor("#d").await,
        None,
        "a deleted successor is cleared"
    );
}

/// ChanServ names accounts the way Atheme does: a grouped nick stands for its
/// account in access changes, founder transfers and the successor, and the
/// verdict names the account it resolved to. The successor shows wherever the
/// console shows who holds a channel.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn chanserv_resolves_grouped_nicks_and_the_console_shows_the_successor() {
    let (pool, _) =
        alice_and_bob("chanserv_resolves_grouped_nicks_and_the_console_shows_the").await;
    db::create_account_with_contact(&pool, "Carol", "pw", None)
        .await
        .expect("Carol");
    assert_eq!(
        db::group_nick(&pool, "bob", "Bob_Away")
            .await
            .expect("group"),
        db::NickGroupOutcome::Grouped
    );
    assert_eq!(
        db::group_nick(&pool, "carol", "carol_alt")
            .await
            .expect("group"),
        db::NickGroupOutcome::Grouped
    );
    db::persist_channel_registration(&pool, "#Room", "Alice", &None)
        .await
        .expect("register");

    assert_eq!(
        db::set_channel_access(&pool, "#room", "bob_away", Some("o".into()), "alice")
            .await
            .expect("access"),
        db::AccessChange::Applied {
            account: "Bob".into(),
            previous: None,
        }
    );
    assert_eq!(
        db::list_channel_access(&pool).await.expect("list"),
        [("#room".to_string(), "bob".to_string(), "o".to_string())]
    );
    assert_eq!(
        db::set_channel_access(&pool, "#room", "BOB", Some("v".into()), "alice")
            .await
            .expect("access"),
        db::AccessChange::Applied {
            account: "Bob".into(),
            previous: Some("o".into()),
        },
        "a change of an existing entry reports what it held"
    );
    assert_eq!(
        db::set_channel_successor(&pool, "#room", Some("CAROL_ALT"), "alice")
            .await
            .expect("successor"),
        db::SuccessorChange::Applied {
            successor: Some("Carol".into())
        }
    );

    let owned = db::list_owned_channels(&pool, "alice")
        .await
        .expect("owned");
    assert_eq!(owned.len(), 1);
    assert_eq!(owned[0].successor.as_deref(), Some("Carol"));
    let directory = db::query_registered_channel_directory(
        &pool,
        db::RegisteredChannelDirectoryFilter {
            before_id: None,
            exact_name: None,
            exact_founder: None,
            page_size: registered_channel_page_size(10),
        },
    )
    .await
    .expect("directory");
    assert_eq!(directory.entries[0].successor.as_deref(), Some("Carol"));
    assert_eq!(
        db::list_channel_successors(&pool)
            .await
            .expect("successors"),
        [("#room".to_string(), "carol".to_string())]
    );

    // A founder transfer by grouped nick clears the successor.
    assert_eq!(
        db::set_channel_founder(&pool, "#room", "Bob_Away", "alice")
            .await
            .expect("transfer"),
        db::FounderTransfer::Transferred {
            founder: "Bob".into()
        }
    );
    assert_eq!(
        db::list_channel_successors(&pool)
            .await
            .expect("successors"),
        []
    );
    // The owner console resolves a grouped nick the same way, and its
    // transfer clears the successor too.
    assert_eq!(
        db::set_channel_successor(&pool, "#room", Some("carol_alt"), "bob")
            .await
            .expect("successor"),
        db::SuccessorChange::Applied {
            successor: Some("Carol".into())
        }
    );
    use e6ircd::core::{ChannelControlResult, PersistedChannelMutation};
    assert_eq!(
        db::persist_owned_channel_mutation(
            &pool,
            "#room",
            "bob",
            &PersistedChannelMutation::SetAccess {
                account: "CAROL_ALT".into(),
                flags: Some("v".into()),
            },
        )
        .await
        .expect("console access"),
        ChannelControlResult::Applied {
            account: Some("Carol".into())
        }
    );
    assert!(
        db::list_channel_access(&pool)
            .await
            .expect("list")
            .contains(&("#room".to_string(), "carol".to_string(), "v".to_string()))
    );
    assert_eq!(
        db::persist_owned_channel_mutation(
            &pool,
            "#room",
            "bob",
            &PersistedChannelMutation::TransferFounder {
                account: "alice".into(),
            },
        )
        .await
        .expect("console transfer"),
        ChannelControlResult::Applied {
            account: Some("Alice".into())
        }
    );
    assert_eq!(
        db::list_channel_successors(&pool)
            .await
            .expect("successors"),
        []
    );
}

/// One IRC client of a running server, for the end-to-end services tests.
struct ServicesClient {
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
}

impl ServicesClient {
    async fn register(addr: std::net::SocketAddr, nick: &str) -> Self {
        let stream = TcpStream::connect(addr).await.expect("connect");
        let (reader, writer) = stream.into_split();
        let mut client = Self {
            reader: BufReader::new(reader),
            writer,
        };
        client
            .send(&format!("NICK {nick}\r\nUSER {nick} 0 * :{nick}"))
            .await;
        client.expect(" 001 ").await;
        client
    }

    async fn send(&mut self, line: &str) {
        self.writer
            .write_all(format!("{line}\r\n").as_bytes())
            .await
            .expect("write");
    }

    /// The next line containing `needle`; `None` if the server closes first.
    async fn next_with(&mut self, needle: &str) -> Option<String> {
        tokio::time::timeout(deadline::HANG, async {
            loop {
                let mut line = String::new();
                if self.reader.read_line(&mut line).await.expect("read") == 0 {
                    return None;
                }
                if line.contains(needle) {
                    return Some(line.trim_end().to_string());
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timeout waiting for {needle}"))
    }

    async fn expect(&mut self, needle: &str) -> String {
        self.next_with(needle)
            .await
            .unwrap_or_else(|| panic!("closed before {needle}"))
    }
}

/// The services a user reaches over IRC, against real storage: a nick grouped
/// and protected before a restart is enforced after it; GROUP and INFO read
/// PostgreSQL; ChanServ SET SUCCESSOR persists; NickServ DROP deletes the
/// account through the console's deletion procedure — disconnecting it,
/// passing its channel to the successor in storage and in the live core.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn nickserv_and_chanserv_services_over_a_real_server() {
    let url = support::test_db("nickserv_and_chanserv_services_over_a_real_server").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    db::bootstrap_first_admin(&pool, "root", "root password")
        .await
        .expect("root");
    db::create_account_with_contact(&pool, "keeper", "keeper password", None)
        .await
        .expect("keeper");
    assert_eq!(
        db::group_nick(&pool, "keeper", "keeper_")
            .await
            .expect("group"),
        db::NickGroupOutcome::Grouped
    );
    db::set_nick_enforce(&pool, "keeper", true)
        .await
        .expect("enforce");
    db::create_account_with_contact(&pool, "carol", "carol-password", None)
        .await
        .expect("carol");

    let config = Config {
        server_name: "irc.services.example".into(),
        network_name: "ServicesNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        database: Some(DatabaseConfig {
            url,
            startup_wait_seconds: e6ircd::config::DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        }),
        ..Config::default()
    };
    let running = net::start(config).await.expect("start");
    let addr = running.addrs[0];

    // Boot-loaded protection.
    let mut intruder = ServicesClient::register(addr, "intruder").await;
    intruder.send("NICK Keeper_").await;
    intruder
        .expect("identify via \x02/msg NickServ IDENTIFY keeper <password>\x02")
        .await;

    let mut dave = ServicesClient::register(addr, "dave").await;
    dave.send("PRIVMSG NickServ :REGISTER dave-password").await;
    dave.expect("is now registered to your connection").await;
    dave.send("NICK dave_away\r\nPRIVMSG NickServ :GROUP").await;
    dave.expect("Nick \x02dave_away\x02 is now registered to your account.")
        .await;
    dave.send("PRIVMSG NickServ :INFO dave").await;
    dave.expect("Nicks      : dave dave_away").await;
    dave.expect("End of Info").await;
    dave.send("PRIVMSG NickServ :SET ENFORCE ON").await;
    dave.expect("The \x02ENFORCE\x02 flag has been set for account \x02dave\x02.")
        .await;
    dave.send("PRIVMSG NickServ :UNGROUP").await;
    dave.expect("Nick \x02dave_away\x02 has been removed from your account.")
        .await;

    dave.send("JOIN #keep").await;
    dave.expect(" 366 ").await;
    dave.send("PRIVMSG ChanServ :REGISTER #keep").await;
    dave.expect("is now registered to your account").await;
    dave.send("PRIVMSG ChanServ :SET #keep SUCCESSOR carol")
        .await;
    dave.expect("\x02carol\x02 is now the successor of \x02#keep\x02.")
        .await;
    dave.send("PART #keep").await;
    dave.expect(" PART #keep").await;

    dave.send("PRIVMSG NickServ :DROP dave wrong-password")
        .await;
    let reminder = dave.expect("Please confirm by replying with").await;
    let key = reminder
        .trim_end_matches('\x02')
        .rsplit(' ')
        .next()
        .expect("key")
        .to_string();
    dave.send(&format!("PRIVMSG NickServ :DROP dave wrong-password {key}"))
        .await;
    dave.expect("Invalid password for \x02dave\x02.").await;
    dave.send("PRIVMSG NickServ :DROP dave dave-password").await;
    let reminder = dave.expect("Please confirm by replying with").await;
    let key = reminder
        .trim_end_matches('\x02')
        .rsplit(' ')
        .next()
        .expect("key")
        .to_string();
    dave.send(&format!("PRIVMSG NickServ :DROP dave dave-password {key}"))
        .await;
    dave.expect("Account permanently deleted").await;
    assert_eq!(dave.next_with("never sent").await, None, "not disconnected");

    // The live gate disconnects the account before its rows go.
    tokio::time::timeout(deadline::HANG, async {
        while db::account_id_by_name(&pool, "dave")
            .await
            .expect("lookup")
            .is_some()
        {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the account was deleted");
    let founder: String = sqlx::query_scalar(
        "SELECT a.name_folded FROM channels c JOIN accounts a ON a.id = c.founder_account_id
         WHERE c.name_folded = '#keep'",
    )
    .fetch_one(&pool)
    .await
    .expect("founder");
    assert_eq!(founder, "carol");
    let grouped: i64 = sqlx::query_scalar("SELECT count(*) FROM account_nicks")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(grouped, 1, "only keeper_ is left");

    // The live core moved the founder too: carol's ChanServ rights are the
    // founder's, and dave's name is gone from every mirror.
    let mut carol = ServicesClient::register(addr, "carol").await;
    carol
        .send("PRIVMSG NickServ :IDENTIFY carol-password")
        .await;
    carol.expect("You are now identified for").await;
    // The core hears of the deletion just after its commit.
    tokio::time::timeout(deadline::HANG, async {
        loop {
            carol.send("PRIVMSG ChanServ :FLAGS #keep").await;
            let answer = carol.expect("NOTICE carol :").await;
            if answer.contains("Access list for \x02#keep\x02:") {
                return;
            }
            assert!(answer.contains("You are not the founder"), "{answer}");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("carol became founder in the live core");
    carol.send("PRIVMSG NickServ :INFO dave").await;
    carol.expect("\x02dave\x02 is not registered.").await;
    running.shutdown.run().await;
}

/// The target principal a seeded audit row names, by the kind its action
/// records: a ban's mask, the server's configuration, or an account.
fn seeded_target(action: &str, target: &str) -> e6ircd::db::AuditPrincipal {
    match action {
        "KLINE" => e6ircd::db::AuditPrincipal::mask(target),
        "CONFIG" => e6ircd::db::AuditPrincipal::server(),
        "OPER" => e6ircd::db::AuditPrincipal::operator(target),
        _ => e6ircd::db::AuditPrincipal::account(target),
    }
}

/// Insert one stored message the way the history flush does, `peers` naming a
/// direct message's folded participants (`None` for a channel's).
async fn insert_message(
    pool: &sqlx::PgPool,
    msgid: &str,
    target: &str,
    peers: Option<&[&str]>,
    ts_millis: i64,
) {
    sqlx::query(
        "INSERT INTO messages (msgid, target, sender_prefix, sender_account, kind, body, ts, dm_peers)
         VALUES ($1, $2, 'x!x@h', NULL, 'privmsg', 'hi',
                 to_timestamp($3::double precision / 1000), $4)
         ON CONFLICT (msgid) DO NOTHING",
    )
    .bind(msgid)
    .bind(target)
    .bind(ts_millis)
    .bind(peers.map(|peers| peers.iter().map(|p| p.to_string()).collect::<Vec<_>>()))
    .execute(pool)
    .await
    .expect("insert message");
}

async fn dm_summary(pool: &sqlx::PgPool) -> Vec<(String, String, i64)> {
    sqlx::query_as(
        "SELECT account, peer, (EXTRACT(EPOCH FROM latest_ts) * 1000)::bigint
         FROM dm_conversations ORDER BY account, peer",
    )
    .fetch_all(pool)
    .await
    .expect("summary")
}

fn millis(value: u64) -> e6irc_proto::time::Millis {
    e6irc_proto::time::Millis::from_millis(value)
}

/// CHATHISTORY TARGETS' direct-message half reads the conversation summary,
/// which every writer of `messages` keeps exact: inserts advance it, a
/// duplicate msgid does not, deleting a conversation's newest message
/// recomputes it, deleting the whole conversation or an account forgets it.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn direct_message_targets_come_from_a_summary_every_writer_keeps() {
    let pool = db::connect_and_migrate(
        &support::test_db("direct_message_targets_come_from_a_summary").await,
    )
    .await
    .expect("connect");
    let carol_id = db::create_account_with_contact(&pool, "carol", "pw", None)
        .await
        .expect("carol");
    insert_message(&pool, "c1", "#room", None, 500).await;
    insert_message(&pool, "ab1", "alice!bob", Some(&["alice", "bob"]), 1000).await;
    insert_message(&pool, "ab2", "alice!bob", Some(&["alice", "bob"]), 3000).await;
    insert_message(&pool, "ac1", "alice!carol", Some(&["alice", "carol"]), 2000).await;
    insert_message(&pool, "aa1", "alice!alice", Some(&["alice"]), 2500).await;
    // A replayed msgid is not stored, so it cannot advance the summary.
    insert_message(&pool, "ac1", "alice!carol", Some(&["alice", "carol"]), 9000).await;
    assert_eq!(
        dm_summary(&pool).await,
        [
            ("alice".to_string(), "alice".to_string(), 2500),
            ("alice".into(), "bob".into(), 3000),
            ("alice".into(), "carol".into(), 2000),
            ("bob".into(), "alice".into(), 3000),
            ("carol".into(), "alice".into(), 2000),
        ]
    );
    assert_eq!(
        tgts(&pool, &[], "alice", millis(0), millis(9999), 10).await,
        [
            ("carol".to_string(), millis(2000)),
            ("alice".into(), millis(2500)),
            ("bob".into(), millis(3000)),
        ]
    );
    // The limit and the window bound the summary read itself.
    assert_eq!(
        tgts(&pool, &[], "alice", millis(0), millis(9999), 2).await,
        [
            ("carol".to_string(), millis(2000)),
            ("alice".into(), millis(2500))
        ]
    );
    assert_eq!(
        tgts(&pool, &[], "alice", millis(2000), millis(2600), 10).await,
        [("alice".to_string(), millis(2500))]
    );
    // Retention removes the oldest rows, a purge the rest.
    sqlx::query("DELETE FROM messages WHERE msgid = 'ab2'")
        .execute(&pool)
        .await
        .expect("delete newest");
    assert_eq!(
        tgts(&pool, &[], "bob", millis(0), millis(9999), 10).await,
        [("alice".to_string(), millis(1000))]
    );
    sqlx::query("DELETE FROM messages WHERE target = 'alice!bob'")
        .execute(&pool)
        .await
        .expect("delete conversation");
    assert!(
        tgts(&pool, &[], "bob", millis(0), millis(9999), 10)
            .await
            .is_empty()
    );
    db::delete_account_permanently(&pool, carol_id, "admin", &[])
        .await
        .expect("delete carol")
        .expect("carol existed");
    assert_eq!(
        dm_summary(&pool).await,
        [("alice".to_string(), "alice".to_string(), 2500)]
    );
}

/// Migration 0080 builds the summary from the direct messages already stored,
/// leaving out a conversation with an unauthenticated `~` party.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn dm_conversation_summary_is_backfilled_from_stored_history() {
    let url = support::test_db("dm_conversation_summary_is_backfilled").await;
    let pool = sqlx::PgPool::connect(&url).await.expect("connect");
    MIGRATIONS
        .run_to(75, &pool)
        .await
        .expect("migrate through 0075");
    insert_message(&pool, "ab1", "alice!bob", Some(&["alice", "bob"]), 1000).await;
    insert_message(&pool, "ab2", "alice!bob", Some(&["alice", "bob"]), 4000).await;
    insert_message(&pool, "bb1", "bob!bob", Some(&["bob"]), 2000).await;
    insert_message(&pool, "anon", "~x!alice", Some(&["~x", "alice"]), 3000).await;
    insert_message(&pool, "c1", "#room", None, 5000).await;
    MIGRATIONS.run(&pool).await.expect("migrate through 0080");
    assert_eq!(
        dm_summary(&pool).await,
        [
            ("alice".to_string(), "bob".to_string(), 4000),
            ("bob".into(), "alice".into(), 4000),
            ("bob".into(), "bob".into(), 2000),
        ]
    );
    assert_eq!(
        tgts(&pool, &[], "bob", millis(0), millis(9999), 10).await,
        [
            ("bob".to_string(), millis(2000)),
            ("alice".into(), millis(4000))
        ]
    );
}

/// Accounts `names`, each founding `founded` channels named `#<name><n>`.
async fn accounts_founding(pool: &sqlx::PgPool, names: &[&str], founded: i64) -> Vec<i64> {
    let mut ids = Vec::new();
    for name in names {
        let id = db::create_account_with_contact(pool, name, "password", None)
            .await
            .expect("account");
        sqlx::query(
            "INSERT INTO channels (name, name_folded, founder_account_id)
             SELECT '#' || $1 || n, '#' || $1 || n, $2 FROM generate_series(1, $3) n",
        )
        .bind(name)
        .bind(id)
        .bind(founded)
        .execute(pool)
        .await
        .expect("founded channels");
        ids.push(id);
    }
    ids
}

/// The per-account founder cap holds where every shard's writes meet: two
/// concurrent registrations one below it cannot both pass, and no founder
/// transfer — ChanServ SET FOUNDER, the owner console's, or a deletion's
/// succession — takes the receiving account past it.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn founder_cap_is_held_by_storage_for_registrations_and_transfers() {
    use e6ircd::core::{ChannelControlResult, ChannelRegistrationResult, PersistedChannelMutation};
    let pool = db::connect_and_migrate(&support::test_db("founder_cap_is_held_by_storage").await)
        .await
        .expect("connect");
    let limit = db::CHANNEL_FOUNDER_LIMIT;
    let bob_id = accounts_founding(&pool, &["bob"], limit - 1).await[0];
    let alice_id = accounts_founding(&pool, &["alice"], 0).await[0];

    // Two shards' registrations, one slot left: exactly one is stored.
    let (first, second) = tokio::join!(
        db::persist_channel_registration(&pool, "#race1", "bob", &None),
        db::persist_channel_registration(&pool, "#race2", "bob", &None),
    );
    let mut verdicts = [first.expect("first"), second.expect("second")];
    verdicts.sort_by_key(|verdict| format!("{verdict:?}"));
    assert_eq!(
        verdicts,
        [
            ChannelRegistrationResult::LimitReached,
            ChannelRegistrationResult::Registered
        ]
    );
    let founded = |id: i64| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM channels WHERE founder_account_id = $1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("count")
        }
    };
    assert_eq!(founded(bob_id).await, limit);

    // Transfers to an account at the cap are refused, and change nothing.
    assert_eq!(
        db::persist_channel_registration(&pool, "#mine", "alice", &None)
            .await
            .expect("register"),
        ChannelRegistrationResult::Registered
    );
    assert_eq!(
        db::set_channel_founder(&pool, "#mine", "bob", "alice")
            .await
            .expect("chanserv transfer"),
        db::FounderTransfer::LimitReached
    );
    assert_eq!(
        db::persist_owned_channel_mutation(
            &pool,
            "#mine",
            "alice",
            &PersistedChannelMutation::TransferFounder {
                account: "bob".into()
            },
        )
        .await
        .expect("console transfer"),
        ChannelControlResult::FounderLimitReached
    );
    assert_eq!(founded(alice_id).await, 1);
    // A transfer to the founder the channel already has moves nothing.
    assert!(matches!(
        db::set_channel_founder(&pool, "#bob1", "bob", "bob")
            .await
            .expect("self transfer"),
        db::FounderTransfer::Transferred { .. }
    ));

    // A deletion whose succession would take bob past the cap is refused,
    // before the gate and in the transaction, naming the channel.
    assert!(matches!(
        db::set_channel_successor(&pool, "#mine", Some("bob"), "alice")
            .await
            .expect("successor"),
        db::SuccessorChange::Applied { .. }
    ));
    let refused = |outcome: Result<(), db::DbError>| match outcome {
        Err(db::DbError::SuccessorChannelLimit(channels)) => channels,
        other => panic!("deletion was not refused at the founder cap: {other:?}"),
    };
    assert_eq!(
        refused(
            db::account_deletion_target(&pool, alice_id, &[])
                .await
                .map(|_| ())
        ),
        ["#mine"]
    );
    let error = db::delete_account_permanently(&pool, alice_id, "alice", &[])
        .await
        .map(|_| ());
    assert!(
        error
            .as_ref()
            .is_err_and(|e| e.to_string().contains("#mine")),
        "the refusal names the channel: {error:?}"
    );
    assert_eq!(refused(error), ["#mine"]);
    assert_eq!(
        founded(alice_id).await,
        1,
        "a refused deletion moved nothing"
    );

    // With a slot free, the same deletion passes the channel on.
    sqlx::query("DELETE FROM channels WHERE name_folded = '#bob1'")
        .execute(&pool)
        .await
        .expect("free a slot");
    let deleted = db::delete_account_permanently(&pool, alice_id, "alice", &[])
        .await
        .expect("delete")
        .expect("alice existed");
    assert_eq!(
        deleted.successions,
        [db::ChannelSuccession {
            channel: "#mine".into(),
            founder: "bob".into()
        }]
    );
    assert_eq!(founded(bob_id).await, limit);
}

/// An expired personal access token authenticates nothing and is not counted
/// by the account directory; it does not hold one of the account's slots.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn expired_api_tokens_do_not_count_against_the_cap() {
    let url = support::test_db("expired_api_tokens_do_not_count_against_the_cap").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    db::create_account_with_contact(&pool, "tcap", "pw", None)
        .await
        .expect("create");
    for i in 0..32 {
        issue_api_token(&pool, "tcap", &format!("cli{i}"))
            .await
            .unwrap_or_else(|e| panic!("token {i} should succeed: {e}"));
    }
    sqlx::query(
        "UPDATE api_tokens
         SET created_at = now() - interval '2 days', expires_at = now() - interval '1 day'
         WHERE id = (SELECT min(id) FROM api_tokens)",
    )
    .execute(&pool)
    .await
    .expect("expire one");
    issue_api_token(&pool, "tcap", "replacement")
        .await
        .expect("an expired token frees its slot");
    assert!(matches!(
        issue_api_token(&pool, "tcap", "one too many").await,
        Err(db::DbError::TooManyCredentials)
    ));
}

/// Recording a credential's use is part of verifying it, on both password
/// paths: a failed write fails the check instead of being logged past.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn a_failed_credential_use_record_fails_both_password_checks() {
    let url = support::test_db("a_failed_credential_use_record_fails_both").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    db::create_account_with_contact(&pool, "user", "primary-pw", None)
        .await
        .expect("create");
    let app_password = db::issue_app_password(&pool, "user", "primary-pw", "client")
        .await
        .expect("app password");
    sqlx::query(
        "CREATE FUNCTION refuse_use_record() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN RAISE EXCEPTION 'last_used_at is not writable'; END $$",
    )
    .execute(&pool)
    .await
    .expect("function");
    sqlx::query(
        "CREATE TRIGGER refuse_use_record BEFORE UPDATE OF last_used_at ON account_credentials
         FOR EACH ROW EXECUTE FUNCTION refuse_use_record()",
    )
    .execute(&pool)
    .await
    .expect("trigger");
    let failed_write = |outcome: Result<Option<String>, db::DbError>| matches!(outcome, Err(error) if error.to_string().contains("last_used_at is not writable"));
    assert!(
        failed_write(db::verify_credentials(&pool, "user", &app_password).await),
        "an app-password login reported success past a failed write"
    );
    assert!(
        failed_write(db::verify_local_password(&pool, "user", "primary-pw").await),
        "a primary-password check reported success past a failed write"
    );
}

/// Storage refuses what the application's writers never produce but its
/// comparisons depend on: a BNC network name outside the folded-token charset,
/// and a non-canonical bouncer timestamp. The dead invitation column and the
/// redundant network index are gone.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn storage_constrains_bnc_names_and_timestamps() {
    let url = support::test_db("storage_constrains_bnc_names_and_timestamps").await;
    let pool = db::connect_and_migrate(&url).await.expect("connect");
    let account = db::create_account_with_contact(&pool, "alice", "pw", None)
        .await
        .expect("create");
    // Which check refused a write (`None`: it was stored).
    let refused_by = |result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>| match result {
        Ok(_) => None,
        Err(sqlx::Error::Database(error)) => error.constraint().map(str::to_string),
        Err(other) => panic!("unexpected failure: {other}"),
    };
    let network = |name: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO bnc_networks (account_id, name, addr, nick, username, kind)
                 VALUES ($1, $2, 'irc.example:6697', 'alice', 'alice', 'irc')",
            )
            .bind(account)
            .bind(name)
            .execute(&pool)
            .await
        }
    };
    for name in ["net[", "net{", ".", "..", "", "has space"] {
        assert_eq!(
            refused_by(network(name).await).as_deref(),
            Some("bnc_networks_name_token"),
            "network name {name:?}"
        );
    }
    assert_eq!(refused_by(network("Libera.Chat_2-x").await), None);
    let line = |stamp: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO bnc_buffer (owner, network, line, sent_at)
                 VALUES ('alice', 'libera', ':s NOTICE a :x', $1)",
            )
            .bind(stamp)
            .execute(&pool)
            .await
        }
    };
    let marker = |stamp: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO bnc_read_markers
                     (account_id, network, target, timestamp, target_display, target_casemapping)
                 VALUES ($1, 'libera', $2, $2, $2, 'rfc1459')",
            )
            .bind(account)
            .bind(stamp)
            .execute(&pool)
            .await
        }
    };
    for stamp in [
        "2026-01-01T00:00:00Z",
        "2026-01-01 00:00:00.000Z",
        "yesterday",
    ] {
        assert_eq!(
            refused_by(line(stamp).await).as_deref(),
            Some("bnc_buffer_sent_at_canonical"),
            "bnc_buffer.sent_at {stamp:?}"
        );
        assert_eq!(
            refused_by(marker(stamp).await).as_deref(),
            Some("bnc_read_markers_timestamp_canonical"),
            "bnc_read_markers.timestamp {stamp:?}"
        );
    }
    assert_eq!(refused_by(line("2026-01-01T00:00:00.000Z").await), None);
    assert_eq!(refused_by(marker("2026-01-01T00:00:00.000Z").await), None);
    let accepted_account_column: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'account_invitations'
                          AND column_name = 'accepted_account_id')",
    )
    .fetch_one(&pool)
    .await
    .expect("columns");
    assert!(!accepted_account_column);
    let redundant_index: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'bnc_networks_account_idx')",
    )
    .fetch_one(&pool)
    .await
    .expect("indexes");
    assert!(!redundant_index);
}

/// Migration 0080 brings existing bouncer rows onto the canonical timestamp
/// form (a line is rebased onto its arrival time, an unorderable marker is
/// removed) and refuses, naming it, a network name it cannot rewrite safely.
#[tokio::test]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn storage_constraint_migration_normalizes_or_names_existing_rows() {
    let url = support::test_db("storage_constraint_migration_normalizes").await;
    let pool = sqlx::PgPool::connect(&url).await.expect("connect");
    MIGRATIONS
        .run_to(75, &pool)
        .await
        .expect("migrate through 0075");
    let account: i64 = sqlx::query_scalar(
        "INSERT INTO accounts (name, name_folded) VALUES ('alice', 'alice') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("account");
    sqlx::query(
        "INSERT INTO bnc_buffer (owner, network, line, target, sent_at, created_at)
         VALUES ('alice', 'libera', ':s PRIVMSG #rust :old', '#rust', '2026-01-01T00:00:00Z',
                 '2026-01-02T03:04:05.678Z'),
                ('alice', 'libera', ':s PRIVMSG #rust :ok', '#rust', '2026-02-01T00:00:00.000Z',
                 '2026-02-01T00:00:00.000Z')",
    )
    .execute(&pool)
    .await
    .expect("buffer");
    sqlx::query(
        "INSERT INTO bnc_read_markers (account_id, network, target, timestamp)
         VALUES ($1, 'libera', '#rust', '2026-01-01T00:00:00Z'),
                ($1, 'libera', '#ok', '2026-02-01T00:00:00.000Z')",
    )
    .bind(account)
    .execute(&pool)
    .await
    .expect("markers");
    sqlx::query(
        "INSERT INTO bnc_networks (account_id, name, addr, nick, username, kind)
         VALUES ($1, 'net[', 'irc.example:6697', 'alice', 'alice', 'irc')",
    )
    .bind(account)
    .execute(&pool)
    .await
    .expect("hand-written network");

    let refused = MIGRATIONS
        .run(&pool)
        .await
        .expect_err("an unsafe name refuses");
    assert!(
        refused.to_string().contains("'net['"),
        "the refusal names the row: {refused}"
    );
    sqlx::query("UPDATE bnc_networks SET name = 'net' WHERE name = 'net['")
        .execute(&pool)
        .await
        .expect("operator renames it");
    MIGRATIONS.run(&pool).await.expect("migrate through 0080");

    let sent_at: Vec<String> = sqlx::query_scalar("SELECT sent_at FROM bnc_buffer ORDER BY id")
        .fetch_all(&pool)
        .await
        .expect("buffer");
    assert_eq!(
        sent_at,
        ["2026-01-02T03:04:05.678Z", "2026-02-01T00:00:00.000Z"]
    );
    let markers: Vec<String> =
        sqlx::query_scalar("SELECT target FROM bnc_read_markers ORDER BY target")
            .fetch_all(&pool)
            .await
            .expect("markers");
    assert_eq!(markers, ["#ok"]);
}
