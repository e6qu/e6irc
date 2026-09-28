//! One serving process per database, and standbys that take over (DESIGN
//! §18): the serving lease, its fence, and the handoff between processes.

mod support;

use std::time::{Duration, Instant};

use e6ircd::config::{Config, DatabaseConfig, HttpConfig, ListenerConfig};
use e6ircd::db;
use e6ircd::net;
use e6ircd::serving_lease::{self, FENCE_AFTER, LEASE_TTL, RENEW_INTERVAL};

/// A port that was free a moment ago: bound, read, and released.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("address")
        .port()
}

fn server_config(url: &db::DatabaseUrl, http_port: u16) -> Config {
    Config {
        server_name: "irc.ha.example".into(),
        network_name: "HaNet".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().expect("address"),
            tls: None,
            websocket: false,
        }],
        database: Some(DatabaseConfig {
            url: url.clone(),
            startup_wait_seconds: 0,
            max_connections: None,
        }),
        http: Some(HttpConfig {
            addr: format!("127.0.0.1:{http_port}").parse().expect("address"),
            public_url: Some("http://irc.ha.example".into()),
            secure_cookies: false,
            admin_accounts: Vec::new(),
            hsts_include_subdomains: false,
        }),
        ..Config::default()
    }
}

/// One HTTP/1.1 GET: the status and the body.
async fn http_get(port: u16, path: &str) -> std::io::Result<(u16, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: irc.ha.example\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "no answer"))??;
    let text = String::from_utf8_lossy(&response).into_owned();
    let status = text
        .get(9..12)
        .and_then(|status| status.parse().ok())
        .ok_or_else(|| std::io::Error::other(format!("not HTTP: {text:?}")))?;
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    Ok((status, body))
}

/// Poll `path` until it answers `status`, within `bound`; the last body.
async fn until_status(port: u16, path: &str, status: u16, bound: Duration) -> String {
    let deadline = Instant::now() + bound;
    loop {
        let answer = http_get(port, path).await;
        if let Ok((got, body)) = &answer
            && *got == status
        {
            return body.clone();
        }
        assert!(
            Instant::now() < deadline,
            "{path} on port {port} did not answer {status} within {bound:?}: {answer:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn register_on(addr: std::net::SocketAddr, nick: &str) {
    let mut client = e6irc_client::Connection::connect(&addr.to_string())
        .await
        .expect("connect to the serving process");
    client
        .register(&e6irc_client::Identity {
            nick,
            username: nick,
            realname: nick,
            server_password: None,
        })
        .await
        .expect("register on the serving process");
}

/// Poll `/readyz` until its `lease` is `lease` and its `ready` is `ready`,
/// within `bound`; the body.
async fn until_readiness(
    port: u16,
    lease: &str,
    ready: bool,
    bound: Duration,
) -> serde_json::Value {
    let deadline = Instant::now() + bound;
    loop {
        let answer = http_get(port, "/readyz").await;
        if let Ok((_, body)) = &answer
            && let Ok(readiness) = serde_json::from_str::<serde_json::Value>(body)
            && readiness["lease"] == lease
            && readiness["ready"] == ready
        {
            let status = answer.as_ref().map(|(status, _)| *status).unwrap_or(0);
            assert_eq!(
                status == 200,
                readiness["ready"] == true,
                "the status and `ready` agree: {readiness}"
            );
            return readiness;
        }
        assert!(
            Instant::now() < deadline,
            "/readyz on port {port} did not report the lease {lease} (ready: {ready}) within \
             {bound:?}: {answer:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// No critical failure (a lost lease among them) within a second.
async fn no_critical_failure(shutdown: &mut net::ShutdownHandle) {
    if let Ok(failure) =
        tokio::time::timeout(Duration::from_secs(1), shutdown.wait_for_critical_failure()).await
    {
        panic!("the server stopped serving: {failure}");
    }
}

/// A registered client in `channel`, kept connected.
async fn joined_client(
    addr: std::net::SocketAddr,
    nick: &str,
    channel: &str,
) -> e6irc_client::Connection {
    let mut client = e6irc_client::Connection::connect(&addr.to_string())
        .await
        .expect("connect to the serving process");
    client
        .register(&e6irc_client::Identity {
            nick,
            username: nick,
            realname: nick,
            server_password: None,
        })
        .await
        .expect("register on the serving process");
    client
        .send_line(&format!("JOIN {channel}"))
        .await
        .expect("join");
    until_message(&mut client, |message| message.command == "366").await;
    client
}

/// Read until a message `wanted` accepts, within ten seconds.
async fn until_message(
    client: &mut e6irc_client::Connection,
    wanted: impl Fn(&e6irc_client::OwnedMessage) -> bool,
) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let message = client
                .next_message()
                .await
                .expect("read")
                .expect("the server keeps the connection");
            if wanted(&message) {
                return;
            }
        }
    })
    .await
    .expect("the awaited message within ten seconds");
}

/// The client is still connected and answered: a `PING` comes back.
async fn still_talks(client: &mut e6irc_client::Connection, token: &str) {
    client
        .send_line(&format!("PING :{token}"))
        .await
        .expect("send");
    until_message(client, |message| {
        message.command == "PONG" && message.params.last().is_some_and(|last| last == token)
    })
    .await;
}

async fn lease_epoch(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar("SELECT epoch FROM serving_lease WHERE id = 1")
        .fetch_one(pool)
        .await
        .expect("the lease row")
}

/// A relay in front of PostgreSQL whose every connection can be cut at once:
/// a database outage as the serving process sees it. While cut, a new
/// connection is closed as it is accepted.
struct CuttableProxy {
    /// The test database's URL through the relay.
    url: db::DatabaseUrl,
    state: std::sync::Arc<std::sync::Mutex<ProxyState>>,
}

struct ProxyState {
    up: bool,
    relays: Vec<tokio::task::JoinHandle<()>>,
}

impl CuttableProxy {
    /// A relay to the database `real` names, and `real` through it.
    async fn to(real: &str) -> Self {
        let (_, after_scheme) = real.split_once("://").expect("a URL");
        let authority = after_scheme.split(['/', '?']).next().expect("an authority");
        let host_port = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host_port)| host_port)
            .to_owned();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("relay");
        let relayed = format!(
            "127.0.0.1:{}",
            listener.local_addr().expect("relay address").port()
        );
        let url = real
            .replacen(&host_port, &relayed, 1)
            .parse()
            .expect("the relayed URL");
        let state = std::sync::Arc::new(std::sync::Mutex::new(ProxyState {
            up: true,
            relays: Vec::new(),
        }));
        let accepting = state.clone();
        tokio::spawn(async move {
            loop {
                let (mut downstream, _) = listener.accept().await.expect("relay accept");
                let mut state = accepting.lock().expect("relay state");
                if !state.up {
                    drop(downstream);
                    continue;
                }
                let upstream = host_port.clone();
                state.relays.retain(|relay| !relay.is_finished());
                state.relays.push(tokio::spawn(async move {
                    let Ok(mut upstream) = tokio::net::TcpStream::connect(upstream).await else {
                        return;
                    };
                    drop(tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await);
                }));
            }
        });
        Self { url, state }
    }

    /// End every relayed connection and refuse new ones.
    fn cut(&self) {
        let mut state = self.state.lock().expect("relay state");
        state.up = false;
        for relay in state.relays.drain(..) {
            relay.abort();
        }
    }

    /// Relay new connections again.
    fn restore(&self) {
        self.state.lock().expect("relay state").up = true;
    }
}

async fn stored_holder(pool: &sqlx::PgPool) -> Option<String> {
    sqlx::query_scalar("SELECT holder_label FROM serving_lease WHERE id = 1")
        .fetch_one(pool)
        .await
        .expect("the lease row")
}

/// A second server started on the database another serves stands by: it says
/// so, answers `/healthz` 200 and `/readyz` 503 naming the holder, binds no
/// IRC listener, and serves as soon as the holder stops and gives the lease
/// back.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn a_second_server_on_one_database_stands_by_naming_the_holder() {
    // The standby's start is awaited beside the test, on this thread: what it
    // spawns runs on the runtime as usual.
    tokio::task::LocalSet::new()
        .run_until(second_server_stands_by())
        .await;
}

async fn second_server_stands_by() {
    let url = support::test_db("a_second_server_on_one_database_stands_by_naming_the").await;
    let first = net::start(server_config(&url, 0))
        .await
        .expect("the first server serves");
    let observer = db::connect_and_migrate(&url).await.expect("observer");
    let holder = stored_holder(&observer).await.expect("the first holds it");
    assert!(
        holder.contains(&format!("pid {}", std::process::id())),
        "{holder}"
    );

    let standby_port = free_port();
    let second = tokio::task::spawn_local(net::start(server_config(&url, standby_port)));
    let readiness = until_status(standby_port, "/readyz", 503, Duration::from_secs(30)).await;
    let readiness: serde_json::Value = serde_json::from_str(&readiness).expect("JSON");
    assert_eq!(readiness["role"], "standby", "{readiness}");
    assert_eq!(readiness["ready"], false, "{readiness}");
    assert_eq!(readiness["holder"], holder.as_str(), "{readiness}");
    let (status, body) = http_get(standby_port, "/healthz").await.expect("health");
    assert_eq!((status, body.as_str()), (200, "ok"));
    let (status, _) = http_get(standby_port, "/api/v1/server")
        .await
        .expect("any other path");
    assert_eq!(status, 503, "a standby serves nothing else");
    assert!(!second.is_finished(), "the standby waits for the lease");

    // The holder stops; its release is announced and the standby serves.
    let epoch_before: i64 = sqlx::query_scalar("SELECT epoch FROM serving_lease")
        .fetch_one(&observer)
        .await
        .expect("epoch");
    assert_eq!(
        first.shutdown.run(net::StopMode::Final).await,
        net::ShutdownOutcome::Flushed
    );
    let second = tokio::time::timeout(Duration::from_secs(30), second)
        .await
        .expect("the standby took over at the release, not at the lease's expiry")
        .expect("join")
        .expect("the standby serves");
    let epoch_after: i64 = sqlx::query_scalar("SELECT epoch FROM serving_lease")
        .fetch_one(&observer)
        .await
        .expect("epoch");
    assert_eq!(epoch_after, epoch_before + 1);
    let readiness = until_status(standby_port, "/readyz", 200, Duration::from_secs(30)).await;
    assert!(readiness.contains("\"role\":\"serving\""), "{readiness}");
    register_on(second.addrs[0], "afterhandoff").await;
    let audit: Vec<String> = sqlx::query_scalar(
        "SELECT detail FROM audit_log WHERE action = 'SERVING_LEASE_ACQUIRE' ORDER BY id",
    )
    .fetch_all(&observer)
    .await
    .expect("audit");
    assert_eq!(audit.len(), 2, "each acquisition is audited: {audit:?}");
    assert!(
        audit[1].contains("previously nobody (released)"),
        "{audit:?}"
    );
    assert_eq!(
        second.shutdown.run(net::StopMode::Final).await,
        net::ShutdownOutcome::Flushed
    );
    assert_eq!(stored_holder(&observer).await, None, "released at the end");
}

/// A renewal that finds the lease in another's hands ends the serving: the
/// critical failure names the lease and the new holder, and the drain runs.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn a_server_whose_lease_is_taken_drains_and_stops() {
    let url = support::test_db("a_server_whose_lease_is_taken_drains_and_stops").await;
    let mut running = net::start(server_config(&url, 0)).await.expect("serves");
    let observer = db::connect_and_migrate(&url).await.expect("observer");
    sqlx::query(
        "UPDATE serving_lease SET holder = gen_random_uuid(), holder_label = 'the thief',
                epoch = epoch + 1, renewed_at = now()",
    )
    .execute(&observer)
    .await
    .expect("steal the lease");
    let failure = tokio::time::timeout(
        RENEW_INTERVAL + Duration::from_secs(10),
        running.shutdown.wait_for_critical_failure(),
    )
    .await
    .expect("the next renewal notices");
    assert_eq!(failure.task, "serving lease");
    assert!(failure.reason.contains("the thief"), "{failure}");
    tokio::time::timeout(
        Duration::from_secs(60),
        running.shutdown.run(net::StopMode::Final),
    )
    .await
    .expect("the bounded drain ends");
    assert_eq!(
        stored_holder(&observer).await.as_deref(),
        Some("the thief"),
        "a lost lease is not released over its new holder"
    );
}

/// A holder that cannot confirm a renewal — here the lease row is held locked,
/// so every renewal waits — is fenced by its deadline, before the lease could
/// expire and be taken: `/readyz` says the lease is unconfirmed, and the
/// process keeps serving. Once the row is let go the next renewal finds the
/// lease still its own, at the same epoch, and it resumes.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn a_server_whose_renewals_stall_fences_itself_by_its_deadline() {
    let url = support::test_db("a_server_whose_renewals_stall_fences_itself_by_its").await;
    let http_port = free_port();
    let mut running = net::start(server_config(&url, http_port))
        .await
        .expect("serves");
    let observer = db::connect_and_migrate(&url).await.expect("observer");
    until_readiness(http_port, "held", true, Duration::from_secs(30)).await;
    let epoch_before = lease_epoch(&observer).await;
    let mut lock = observer.begin().await.expect("transaction");
    sqlx::query("SELECT * FROM serving_lease FOR UPDATE")
        .execute(&mut *lock)
        .await
        .expect("hold the lease row");
    let locked = Instant::now();
    let readiness = until_readiness(
        http_port,
        "unconfirmed",
        false,
        FENCE_AFTER + Duration::from_secs(10),
    )
    .await;
    let fenced = locked.elapsed();
    assert_eq!(readiness["ready"], false, "{readiness}");
    // The last confirmed renewal was at most one interval before the lock,
    // and the fence falls FENCE_AFTER after it — before the TTL. `/readyz`
    // shows it within its own database probe's bound.
    assert!(
        fenced + RENEW_INTERVAL >= FENCE_AFTER - Duration::from_secs(1)
            && fenced <= FENCE_AFTER + Duration::from_secs(3),
        "fenced {fenced:?} after the lock"
    );
    assert!(fenced < LEASE_TTL, "fenced {fenced:?}");
    no_critical_failure(&mut running.shutdown).await;
    register_on(running.addrs[0], "whilefenced").await;

    lock.rollback().await.expect("let the row go");
    until_readiness(
        http_port,
        "held",
        true,
        RENEW_INTERVAL + Duration::from_secs(20),
    )
    .await;
    assert_eq!(lease_epoch(&observer).await, epoch_before, "the same lease");
    no_critical_failure(&mut running.shutdown).await;
    tokio::time::timeout(
        Duration::from_secs(60),
        running.shutdown.run(net::StopMode::Final),
    )
    .await
    .expect("the bounded drain ends");
    assert_eq!(stored_holder(&observer).await, None, "released at the end");
}

/// A holder whose database becomes unreachable — every connection through a
/// relay cut, for longer than the fence and the lease's TTL — keeps its IRC
/// clients and answers `/readyz` 503 with the lease unconfirmed. Nobody took
/// the lease, so when the database answers again the next renewal finds it
/// still this holder's: it resumes, `/readyz` answers 200, and a write lands.
/// What another process committed meanwhile is not missed: a suspension
/// written during the outage, announced while nothing listened, is read again
/// once the listener is back, and ends the account's session.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn a_holder_cut_off_from_its_database_keeps_its_clients_and_resumes() {
    let real = support::test_db_text("a_holder_cut_off_from_its_database_keeps_its_clien").await;
    let proxy = CuttableProxy::to(&real).await;
    let http_port = free_port();
    let mut running = net::start(server_config(&proxy.url, http_port))
        .await
        .expect("serves");
    let observer = db::connect_and_migrate(&real.parse().expect("URL"))
        .await
        .expect("observer");
    let carol = db::create_account_with_contact(&observer, "carol", "carols-password", None)
        .await
        .expect("carol's account");
    until_readiness(http_port, "held", true, Duration::from_secs(30)).await;
    let epoch_before = lease_epoch(&observer).await;
    let mut client = joined_client(running.addrs[0], "throughit", "#ha").await;
    let mut carols = e6irc_client::Connection::connect(&running.addrs[0].to_string())
        .await
        .expect("connect");
    carols
        .register_sasl(
            &e6irc_client::Identity {
                nick: "carol",
                username: "carol",
                realname: "Carol",
                server_password: None,
            },
            "carol",
            "carols-password",
        )
        .await
        .expect("carol signs in");

    proxy.cut();
    let cut = Instant::now();
    let readiness = until_readiness(
        http_port,
        "unconfirmed",
        false,
        FENCE_AFTER + Duration::from_secs(10),
    )
    .await;
    assert_eq!(readiness["database"], "unavailable", "{readiness}");
    // Another process suspends carol while the holder cannot hear it.
    db::set_account_suspended(&observer, carol, true, "the operator", &[])
        .await
        .expect("suspended elsewhere")
        .expect("carol");
    still_talks(&mut carols, "unheard").await;
    // Past the lease's TTL too: an expired lease nobody took is still this
    // holder's.
    while cut.elapsed() < LEASE_TTL + Duration::from_secs(1) {
        still_talks(&mut client, "fenced").await;
        no_critical_failure(&mut running.shutdown).await;
    }

    proxy.restore();
    let readiness = until_readiness(
        http_port,
        "held",
        true,
        RENEW_INTERVAL + Duration::from_secs(30),
    )
    .await;
    assert_eq!(readiness["ready"], true, "{readiness}");
    assert_eq!(readiness["database"], "ready", "{readiness}");
    assert_eq!(lease_epoch(&observer).await, epoch_before, "the same lease");
    still_talks(&mut client, "resumed").await;
    client
        .send_line("PRIVMSG #ha :written after the outage")
        .await
        .expect("send");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let landed: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM messages WHERE body = 'written after the outage'",
        )
        .fetch_one(&observer)
        .await
        .expect("count");
        if landed == 1 {
            break;
        }
        assert!(Instant::now() < deadline, "the write never landed");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // The announcement listener reconnects on its own backoff (at most 30 s)
    // and reads every account's authority again.
    let said = tokio::time::timeout(Duration::from_secs(60), async {
        let mut said = Vec::new();
        loop {
            match carols.next_message().await {
                Ok(Some(message)) => said.push(message.params.join(" ")),
                Ok(None) | Err(_) => return said,
            }
        }
    })
    .await
    .expect("carol's session ends once the suspension is read again");
    assert!(
        said.iter().any(|text| text.contains("Account suspended")),
        "{said:#?}"
    );
    no_critical_failure(&mut running.shutdown).await;
    tokio::time::timeout(
        Duration::from_secs(60),
        running.shutdown.run(net::StopMode::Final),
    )
    .await
    .expect("the bounded drain ends");
    assert_eq!(stored_holder(&observer).await, None, "released at the end");
}

/// A holder fenced by an outage whose lease another process took meanwhile
/// finds that out when the database answers again, and only then stops
/// serving: the drain, naming the new holder, which it does not release.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn a_holder_fenced_by_an_outage_that_finds_a_takeover_drains() {
    let real = support::test_db_text("a_holder_fenced_by_an_outage_that_finds_a_takeove").await;
    let real_url: db::DatabaseUrl = real.parse().expect("URL");
    let proxy = CuttableProxy::to(&real).await;
    let http_port = free_port();
    let mut running = net::start(server_config(&proxy.url, http_port))
        .await
        .expect("serves");
    let observer = db::connect_and_migrate(&real_url).await.expect("observer");
    until_readiness(http_port, "held", true, Duration::from_secs(30)).await;
    let mut client = joined_client(running.addrs[0], "splitbrain", "#ha").await;

    proxy.cut();
    until_readiness(
        http_port,
        "unconfirmed",
        false,
        FENCE_AFTER + Duration::from_secs(10),
    )
    .await;
    let deadline = Instant::now() + LEASE_TTL + Duration::from_secs(10);
    while serving_lease::current_holder(&real_url)
        .await
        .expect("the lease row")
        .is_some()
    {
        assert!(Instant::now() < deadline, "the lease never expired");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let successor = serving_lease::acquire(
        &real_url,
        &serving_lease::HolderId::generate(),
        "the successor",
    )
    .await
    .expect("an expired lease is taken");
    // Cut off, the old holder cannot know: it still serves its clients.
    still_talks(&mut client, "unaware").await;
    no_critical_failure(&mut running.shutdown).await;

    proxy.restore();
    let failure = tokio::time::timeout(
        RENEW_INTERVAL + Duration::from_secs(30),
        running.shutdown.wait_for_critical_failure(),
    )
    .await
    .expect("the first renewal that reaches the database finds the takeover");
    assert_eq!(failure.task, "serving lease");
    assert!(failure.reason.contains("the successor"), "{failure}");
    tokio::time::timeout(
        Duration::from_secs(60),
        running.shutdown.run(net::StopMode::Final),
    )
    .await
    .expect("the bounded drain ends");
    assert!(
        stored_holder(&observer)
            .await
            .is_some_and(|holder| holder.contains("the successor")),
        "a lost lease is not released over its new holder"
    );
    assert!(
        successor
            .release(Duration::from_secs(5))
            .await
            .expect("release"),
        "the successor still held it"
    );
}

/// The database fences a holder too: once another process has taken the
/// lease, a write the old holder had in flight fails and never lands, and the
/// old holder's pool cannot open another connection.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn a_write_the_old_holder_had_queued_fails_after_takeover() {
    let url = support::test_db("a_write_the_old_holder_had_queued_fails_after_take").await;
    let observer = db::connect_and_migrate(&url).await.expect("migrated");
    // The old holder: its lease has expired (it stalled), but it still has a
    // connection open and a transaction in it.
    let old = serving_lease::HolderId::generate();
    sqlx::query(
        "UPDATE serving_lease SET holder = $1::uuid, holder_label = 'the old holder',
                epoch = epoch + 1, acquired_at = now() - interval '1 minute',
                renewed_at = now() - interval '1 minute'",
    )
    .bind(old.as_str())
    .execute(&observer)
    .await
    .expect("the old holder's lease");
    let old_pool = db::connect_pool(
        &url,
        db::DatabasePoolSize::new(2).expect("size"),
        Some(&old),
    )
    .await
    .expect("the old holder's pool");
    let mut queued = old_pool.begin().await.expect("a transaction");
    sqlx::query(
        "INSERT INTO audit_log (actor, actor_kind, action, target, target_kind, detail)
         VALUES ('old', 'host', 'QUEUED', 'server', 'server', 'queued before the takeover')",
    )
    .execute(&mut *queued)
    .await
    .expect("the write is in flight");

    let new = serving_lease::HolderId::generate();
    let lease = serving_lease::acquire(&url, &new, "the new holder")
        .await
        .expect("an expired lease is taken");
    let committed = queued.commit().await;
    assert!(
        committed.is_err(),
        "the old holder's connection was ended at the takeover"
    );
    sqlx::query(
        "INSERT INTO audit_log (actor, actor_kind, action, target, target_kind, detail)
         VALUES ('old', 'host', 'QUEUED', 'server', 'server', 'written after the takeover')",
    )
    .execute(&old_pool)
    .await
    .expect_err("the old holder cannot open a connection any more");
    // What its pool's every new connection is told (the pool itself reports
    // only that it found none within its acquire timeout).
    let mut connection =
        <sqlx::PgConnection as sqlx::Connection>::connect_with(&url.connect_options())
            .await
            .expect("a plain connection");
    let refused = sqlx::query("SELECT serving_lease_register_backend($1::uuid)")
        .bind(old.as_str())
        .execute(&mut connection)
        .await
        .expect_err("the fence refuses the old holder");
    assert!(
        refused
            .to_string()
            .contains("does not hold the serving lease"),
        "{refused}"
    );
    let landed: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = 'QUEUED'")
        .fetch_one(&observer)
        .await
        .expect("count");
    assert_eq!(landed, 0, "nothing the old holder wrote landed");
    assert!(
        lease
            .release(Duration::from_secs(5))
            .await
            .expect("release"),
        "the new holder still held it"
    );
}

/// A command-line process never migrates under a serving process: against a
/// schema older than its binary, with a holder serving, it refuses and says
/// to upgrade the serving process. A schema newer than its binary is refused
/// whoever serves.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
async fn a_command_never_migrates_under_a_serving_process() {
    let url = support::test_db("a_command_never_migrates_under_a_serving_process").await;
    let running = net::start(server_config(&url, 0)).await.expect("serves");
    let observer = db::connect_and_migrate(&url).await.expect("up to date");
    // As if this binary were one release newer than the serving one.
    let latest: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&observer)
        .await
        .expect("latest");
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = $1")
        .bind(latest)
        .execute(&observer)
        .await
        .expect("hide the latest migration");
    let refused = db::connect_and_migrate(&url)
        .await
        .expect_err("a command does not migrate under the serving process");
    assert!(
        refused
            .to_string()
            .contains("upgrade the serving process first"),
        "{refused}"
    );
    let applied: i64 =
        sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE version = $1")
            .bind(latest)
            .fetch_one(&observer)
            .await
            .expect("count");
    assert_eq!(applied, 0, "nothing was migrated");
    sqlx::query(
        "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time)
         VALUES (99999, 'a later release', true, '\\x00', 0)",
    )
    .execute(&observer)
    .await
    .expect("a later release migrated");
    let refused = db::connect_and_migrate(&url)
        .await
        .expect_err("a later release's schema");
    assert!(
        refused.to_string().contains("newer than this binary knows"),
        "{refused}"
    );
    assert_eq!(
        running.shutdown.run(net::StopMode::Final).await,
        net::ShutdownOutcome::Flushed
    );
}

#[cfg(unix)]
mod processes {
    //! The same, between real `e6ircd` processes: signals, a crash, and a
    //! bouncer upstream that sees who dials it.

    use super::*;
    use std::io::{BufRead, BufReader};
    use std::process::{Child, Command, Stdio};
    use std::sync::{Arc, Mutex};

    /// A running `e6ircd` and every line it writes.
    struct Daemon {
        child: Child,
        lines: Arc<Mutex<Vec<String>>>,
    }

    impl Daemon {
        fn spawn(config: &std::path::Path) -> Self {
            let mut command = Command::new(env!("CARGO_BIN_EXE_e6ircd"));
            for variable in db::LIBPQ_ENVIRONMENT {
                command.env_remove(variable);
            }
            let mut child = command
                .arg("--config")
                .arg(config)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("start e6ircd");
            let lines = Arc::new(Mutex::new(Vec::new()));
            for output in [
                Box::new(child.stdout.take().expect("stdout")) as Box<dyn std::io::Read + Send>,
                Box::new(child.stderr.take().expect("stderr")),
            ] {
                let lines = lines.clone();
                std::thread::spawn(move || {
                    for line in BufReader::new(output).lines() {
                        let Ok(line) = line else { break };
                        lines.lock().expect("lines").push(line);
                    }
                });
            }
            Self { child, lines }
        }

        fn said(&self) -> String {
            self.lines.lock().expect("lines").join("\n")
        }

        /// [`until_status`], failing with everything the daemon said.
        async fn until_status(&mut self, port: u16, path: &str, status: u16, bound: Duration) {
            let deadline = Instant::now() + bound;
            loop {
                if let Ok((got, _)) = http_get(port, path).await
                    && got == status
                {
                    return;
                }
                let exited = self.child.try_wait().expect("poll the daemon");
                assert!(
                    exited.is_none() && Instant::now() < deadline,
                    "{path} on port {port} did not answer {status} within {bound:?} \
                     (exited: {exited:?}):\n{}",
                    self.said()
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        async fn until_said(&self, needle: &str, bound: Duration) {
            let deadline = Instant::now() + bound;
            while !self.said().contains(needle) {
                assert!(
                    Instant::now() < deadline,
                    "the daemon never said {needle:?}:\n{}",
                    self.said()
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        fn signal(&self, signal: &str) {
            let sent = Command::new("kill")
                .args([signal, &self.child.id().to_string()])
                .status()
                .expect("run kill");
            assert!(sent.success(), "kill {signal}: {sent}");
        }

        async fn exited(&mut self, bound: Duration) -> std::process::ExitStatus {
            let deadline = Instant::now() + bound;
            loop {
                if let Some(status) = self.child.try_wait().expect("poll the daemon") {
                    return status;
                }
                assert!(
                    Instant::now() < deadline,
                    "the daemon did not exit within {bound:?}:\n{}",
                    self.said()
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }

    impl Drop for Daemon {
        fn drop(&mut self) {
            if matches!(self.child.try_wait(), Ok(None)) {
                drop(self.child.kill());
                drop(self.child.wait());
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Seen {
        Dialled(usize),
        Quit(usize),
        Closed(usize),
    }

    /// A TCP relay in front of an upstream IRC server that records, in order,
    /// every session a bouncer opens through it, its QUIT, and its close.
    async fn recording_upstream() -> (std::net::SocketAddr, Arc<Mutex<Vec<Seen>>>) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        let upstream = net::start(Config {
            server_name: "irc.upstream.example".into(),
            network_name: "Upstream".into(),
            listeners: vec![ListenerConfig {
                addr: "127.0.0.1:0".parse().expect("address"),
                tls: None,
                websocket: false,
            }],
            ..Config::default()
        })
        .await
        .expect("upstream")
        .addrs[0];
        let relay = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("relay");
        let addr = relay.local_addr().expect("relay address");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            let mut sessions = 0usize;
            loop {
                let (bouncer, _) = relay.accept().await.expect("accept");
                let session = sessions;
                sessions += 1;
                log.lock().expect("log").push(Seen::Dialled(session));
                let log = log.clone();
                tokio::spawn(async move {
                    let server = tokio::net::TcpStream::connect(upstream)
                        .await
                        .expect("dial the upstream");
                    let (bouncer_read, mut bouncer_write) = bouncer.into_split();
                    let (server_read, mut server_write) = server.into_split();
                    let down = tokio::spawn(async move {
                        let mut server_read = server_read;
                        drop(tokio::io::copy(&mut server_read, &mut bouncer_write).await);
                    });
                    let mut lines = tokio::io::BufReader::new(bouncer_read).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        if line.starts_with("QUIT") {
                            log.lock().expect("log").push(Seen::Quit(session));
                        }
                        if server_write
                            .write_all(format!("{line}\r\n").as_bytes())
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    log.lock().expect("log").push(Seen::Closed(session));
                    down.abort();
                });
            }
        });
        (addr, seen)
    }

    /// At no instant were two sessions open.
    fn at_most_one_live_session(seen: &[Seen]) {
        let mut live = 0usize;
        for event in seen {
            match event {
                Seen::Dialled(_) => live += 1,
                Seen::Closed(_) => live -= 1,
                Seen::Quit(_) => {}
            }
            assert!(live <= 1, "two upstream sessions at once: {seen:?}");
        }
    }

    async fn until_dialled(seen: &Arc<Mutex<Vec<Seen>>>, session: usize) {
        let deadline = Instant::now() + Duration::from_secs(60);
        while !seen.lock().expect("log").contains(&Seen::Dialled(session)) {
            assert!(
                Instant::now() < deadline,
                "session {session} was never dialled: {:?}",
                seen.lock().expect("log")
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Everything the two processes share: the database, the IRC and attach
    /// ports (one binds them at a time), and the network they bounce.
    struct Pair {
        url: String,
        irc: u16,
        bnc: u16,
        upstream: std::net::SocketAddr,
        directory: std::path::PathBuf,
    }

    impl Pair {
        async fn new(test: &str, upstream: std::net::SocketAddr) -> Self {
            let directory = std::env::temp_dir().join(format!(
                "e6irc-ha-{test}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ));
            std::fs::create_dir_all(&directory).expect("directory");
            Self {
                url: support::test_db_text(test).await,
                irc: free_port(),
                bnc: free_port(),
                upstream,
                directory,
            }
        }

        /// A process's configuration: everything shared, and its own HTTP port.
        fn config(&self, name: &str, http: u16) -> std::path::PathBuf {
            let path = self.directory.join(format!("{name}.toml"));
            std::fs::write(
                &path,
                format!(
                    r#"
                    server_name = "irc.ha.example"
                    network_name = "HaNet"
                    internal_upstreams = "allow"
                    [[listeners]]
                    addr = "127.0.0.1:{irc}"
                    [database]
                    url = {url:?}
                    startup_wait_seconds = 0
                    [http]
                    addr = "127.0.0.1:{http}"
                    public_url = "http://irc.ha.example"
                    secure_cookies = false
                    [bnc]
                    addr = "127.0.0.1:{bnc}"
                    [[network]]
                    name = "up"
                    kind = "irc"
                    addr = "{upstream}"
                    tls = false
                    nick = "habouncer"
                    username = "habouncer"
                    realname = "habouncer"
                    autojoin = []
                    buffer_cap = 100
                    "#,
                    irc = self.irc,
                    url = self.url,
                    bnc = self.bnc,
                    upstream = self.upstream,
                ),
            )
            .expect("write the configuration");
            path
        }
    }

    impl Drop for Pair {
        fn drop(&mut self) {
            drop(std::fs::remove_dir_all(&self.directory));
        }
    }

    /// SIGTERM to the serving process hands over to the standby: the standby
    /// names the holder until then, serves IRC on the same port after, and
    /// the upstream never sees two sessions — the old one's QUIT comes before
    /// the new one's dial.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
    async fn a_graceful_stop_hands_over_to_the_standby_one_upstream_session_at_a_time() {
        let (upstream, seen) = recording_upstream().await;
        let pair = Pair::new(
            "a_graceful_stop_hands_over_to_the_standby_one_upstream",
            upstream,
        )
        .await;
        let (http_a, http_b) = (free_port(), free_port());
        let mut a = Daemon::spawn(&pair.config("a", http_a));
        a.until_status(http_a, "/readyz", 200, Duration::from_secs(60))
            .await;
        until_dialled(&seen, 0).await;

        let mut b = Daemon::spawn(&pair.config("b", http_b));
        b.until_said("standing by", Duration::from_secs(60)).await;
        let readiness = until_status(http_b, "/readyz", 503, Duration::from_secs(30)).await;
        assert!(
            readiness.contains("\"role\":\"standby\"")
                && readiness.contains(&format!("pid {}", a.child.id())),
            "{readiness}"
        );
        let (status, _) = http_get(http_b, "/healthz").await.expect("health");
        assert_eq!(status, 200);

        a.signal("-TERM");
        let stopped = Instant::now();
        let status = a.exited(Duration::from_secs(90)).await;
        assert!(status.success(), "{status}:\n{}", a.said());
        assert!(
            a.said().contains("released the serving lease"),
            "{}",
            a.said()
        );
        b.until_status(http_b, "/readyz", 200, Duration::from_secs(30))
            .await;
        assert!(
            stopped.elapsed() < LEASE_TTL,
            "taken at the release, not at the expiry: {:?}",
            stopped.elapsed()
        );
        register_on(
            format!("127.0.0.1:{}", pair.irc).parse().expect("address"),
            "onthestandby",
        )
        .await;
        until_dialled(&seen, 1).await;
        let seen = seen.lock().expect("log").clone();
        at_most_one_live_session(&seen);
        let quit = seen.iter().position(|event| *event == Seen::Quit(0));
        let dialled = seen.iter().position(|event| *event == Seen::Dialled(1));
        assert!(
            matches!((quit, dialled), (Some(quit), Some(dialled)) if quit < dialled),
            "the old session's QUIT precedes the new dial: {seen:?}"
        );
        drop(b);
    }

    /// A serving process that dies without a word (SIGKILL) is replaced once
    /// its lease expires: not before the TTL, and soon after.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
    async fn a_standby_serves_once_a_killed_holder_s_lease_expires() {
        let (upstream, seen) = recording_upstream().await;
        let pair = Pair::new("a_standby_serves_once_a_killed_holder_s_lease", upstream).await;
        let (http_a, http_b) = (free_port(), free_port());
        let mut a = Daemon::spawn(&pair.config("a", http_a));
        a.until_status(http_a, "/readyz", 200, Duration::from_secs(60))
            .await;
        until_dialled(&seen, 0).await;
        let mut b = Daemon::spawn(&pair.config("b", http_b));
        b.until_status(http_b, "/readyz", 503, Duration::from_secs(60))
            .await;

        a.signal("-KILL");
        let killed = Instant::now();
        a.exited(Duration::from_secs(10)).await;
        b.until_status(
            http_b,
            "/readyz",
            200,
            LEASE_TTL + serving_lease::STANDBY_POLL + Duration::from_secs(30),
        )
        .await;
        let taken = killed.elapsed();
        assert!(
            taken + RENEW_INTERVAL + Duration::from_secs(1) >= LEASE_TTL,
            "taken over {taken:?} after the kill, before the lease could expire"
        );
        register_on(
            format!("127.0.0.1:{}", pair.irc).parse().expect("address"),
            "afterthecrash",
        )
        .await;
        until_dialled(&seen, 1).await;
        at_most_one_live_session(&seen.lock().expect("log"));
        drop(b);
    }

    /// A standby whose binary is older than the schema refuses at boot: it
    /// could never serve, so it must not stand by to take the lease.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
    async fn a_standby_older_than_the_schema_refuses_at_boot() {
        let (upstream, _seen) = recording_upstream().await;
        let pair = Pair::new("a_standby_older_than_the_schema_refuses_at_boot", upstream).await;
        let (http_a, http_b) = (free_port(), free_port());
        let mut a = Daemon::spawn(&pair.config("a", http_a));
        a.until_status(http_a, "/readyz", 200, Duration::from_secs(60))
            .await;
        let url: db::DatabaseUrl = pair.url.parse().expect("URL");
        let pool = sqlx::PgPool::connect_with(url.connect_options())
            .await
            .expect("observer");
        sqlx::query(
            "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time)
             VALUES (99999, 'a later release', true, '\\x00', 0)",
        )
        .execute(&pool)
        .await
        .expect("a later release migrated");
        let mut b = Daemon::spawn(&pair.config("b", http_b));
        let status = b.exited(Duration::from_secs(60)).await;
        assert!(!status.success(), "{}", b.said());
        assert!(
            b.said().contains("newer than this binary knows"),
            "{}",
            b.said()
        );
        a.signal("-TERM");
        assert!(
            a.exited(Duration::from_secs(90)).await.success(),
            "{}",
            a.said()
        );
    }

    /// `recover-administrator` (any command) against a schema older than its
    /// binary, while a process serves, refuses and names the fix.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs PostgreSQL; run with --ignored and E6IRC_TEST_DATABASE_URL"]
    async fn a_command_under_a_serving_process_refuses_an_older_schema() {
        let (upstream, _seen) = recording_upstream().await;
        let pair = Pair::new(
            "a_command_under_a_serving_process_refuses_an_older",
            upstream,
        )
        .await;
        let http_a = free_port();
        let config = pair.config("a", http_a);
        let mut a = Daemon::spawn(&config);
        a.until_status(http_a, "/readyz", 200, Duration::from_secs(60))
            .await;
        let url: db::DatabaseUrl = pair.url.parse().expect("URL");
        let pool = sqlx::PgPool::connect_with(url.connect_options())
            .await
            .expect("observer");
        sqlx::query(
            "DELETE FROM _sqlx_migrations
             WHERE version = (SELECT max(version) FROM _sqlx_migrations)",
        )
        .execute(&pool)
        .await
        .expect("as if the command's binary were newer");
        let mut command = Command::new(env!("CARGO_BIN_EXE_e6ircd"));
        for variable in db::LIBPQ_ENVIRONMENT {
            command.env_remove(variable);
        }
        let output = command
            .args(["recover-administrator", "--account", "nobody", "--config"])
            .arg(&config)
            .output()
            .expect("run the command");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{stderr}");
        assert!(
            stderr.contains("upgrade the serving process first"),
            "{stderr}"
        );
        a.signal("-TERM");
        assert!(
            a.exited(Duration::from_secs(90)).await.success(),
            "{}",
            a.said()
        );
    }
}
