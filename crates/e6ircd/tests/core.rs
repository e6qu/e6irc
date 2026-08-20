//! Core worker tests: drive `Core::handle` directly with events and
//! assert on per-connection output queues. No sockets, no runtime —
//! fully deterministic.

use e6irc_proto::time::{Millis, MonoMillis};
use e6irc_queue::{Config, Policy, Receiver, queue};

/// Fixed monotonic clock for the deterministic tests, sharing the same base as
/// the default fixed wall clock (1_000_000_000) so a `Tick` at base+Δ yields a
/// Δ-millisecond elapsed time against a session opened/active at the base.
fn test_mono() -> MonoMillis {
    MonoMillis::from_millis(1_000_000_000)
}
use e6ircd::core::{ConnId, Core, CoreConfig, Input, Output};

struct TestServer {
    core: Core,
    conns: Vec<(ConnId, Receiver<Output>)>,
    db_rx: Receiver<e6ircd::core::DbRequest>,
    channel_service_route: Option<(e6ircd::core::ChannelOwner, e6ircd::core::SessionOwner)>,
}

impl TestServer {
    fn new() -> Self {
        Self::with_persistence(true)
    }

    /// A server with no database configured (`sasl_enabled = false`), so the
    /// in-memory ring is the entire record and CHATHISTORY never defers to a
    /// (fake, non-replying) DB worker. Use this for pure-ring behavior tests;
    /// the DB fallback path is covered by the PostgreSQL suite in tests/db.rs.
    fn new_no_persistence() -> Self {
        Self::with_persistence(false)
    }

    /// Like [`TestServer::new_no_persistence`], but the clock advances on
    /// every read. A fixed clock cannot detect code that reads it more than
    /// once for a single event — the two reads simply return the same value —
    /// so tests that assert one-timestamp-per-message need this one.
    fn new_with_advancing_clock() -> Self {
        fn advancing() -> Millis {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NOW_MS: AtomicU64 = AtomicU64::new(1_000_000_000);
            Millis::from_millis(NOW_MS.fetch_add(1, Ordering::Relaxed))
        }
        Self::with_config(false, advancing, 256)
    }

    /// A database-backed server with a deliberately small per-connection
    /// output bound, for exercising SendQ-style limits.
    fn with_sendq(sendq: usize) -> Self {
        Self::with_config(true, || Millis::from_millis(1_000_000_000), sendq)
    }

    fn with_persistence(sasl_enabled: bool) -> Self {
        Self::with_config(sasl_enabled, || Millis::from_millis(1_000_000_000), 256)
    }

    fn with_config(sasl_enabled: bool, clock: fn() -> Millis, sendq: usize) -> Self {
        Self::with_full_config(sasl_enabled, clock, sendq, "irc.test.example", 16)
    }

    fn with_full_config(
        sasl_enabled: bool,
        clock: fn() -> Millis,
        sendq: usize,
        server_name: &str,
        nicklen: usize,
    ) -> Self {
        let (db_tx, db_rx) = queue(Config {
            name: "test-db",
            capacity: 64,
            policy: Policy::Fifo,
        });
        Self {
            core: Core::new(
                CoreConfig {
                    server_name: server_name.into(),
                    network_name: "TestNet".into(),
                    description: "test server".into(),
                    registration_before_connect: false,
                    registration_require_email: false,
                    sendq,
                    motd: vec!["Welcome to the test net".into()],
                    nicklen,
                    sasl_enabled,
                    max_hot_channels: 8192,
                    opers: vec![("god".into(), "letmein".into())],
                    clock,
                    mono_clock: test_mono,
                    command_burst: None,
                    registration_burst: None,
                },
                db_tx,
            ),
            conns: Vec::new(),
            db_rx,
            channel_service_route: None,
        }
    }

    /// Drain requests the core sent to the (fake) DB worker.
    fn db_requests(&mut self) -> Vec<e6ircd::core::DbRequest> {
        let mut out = Vec::new();
        while let Some(env) = self.db_rx.try_pop() {
            match &env.payload {
                e6ircd::core::DbRequest::SetChannelFounder { owner, session, .. }
                | e6ircd::core::DbRequest::SetChannelKeeptopic { owner, session, .. }
                | e6ircd::core::DbRequest::SetChannelMlock { owner, session, .. }
                | e6ircd::core::DbRequest::SetChannelAccess { owner, session, .. } => {
                    self.channel_service_route = Some((owner.clone(), *session));
                }
                _ => {}
            }
            out.push(env.payload);
        }
        out
    }

    fn channel_service_persisted(&mut self, result: e6ircd::core::ChannelServicePersistence) {
        let (owner, session) = self
            .channel_service_route
            .take()
            .expect("ChanServ persistence request");
        self.core.handle(Input::ChannelServicePersisted {
            owner,
            session,
            result: result.clone(),
        });
        self.core
            .handle(Input::ChannelServiceResult { session, result });
    }

    fn connect(&mut self, id: u64) -> ConnId {
        self.connect_with_transport(id, e6ircd::core::ConnectionTransport::Tcp)
    }

    fn connect_with_transport(
        &mut self,
        id: u64,
        transport: e6ircd::core::ConnectionTransport,
    ) -> ConnId {
        let conn = ConnId(id);
        let (tx, rx) = queue(Config {
            name: "test-sendq",
            capacity: 256,
            policy: Policy::Fifo,
        });
        self.core.handle(Input::Open {
            conn,
            tx,
            host: format!("host{id}.example"),
            transport,
        });
        self.conns.push((conn, rx));
        conn
    }

    fn line(&mut self, conn: ConnId, s: &str) {
        self.core.handle(Input::Line {
            conn,
            line: s.as_bytes().to_vec(),
        });
    }

    /// Register a user the conventional way and drain the burst.
    fn register(&mut self, id: u64, nick: &str) -> ConnId {
        let conn = self.connect(id);
        self.line(conn, &format!("NICK {nick}"));
        self.line(conn, &format!("USER {nick} 0 * :Real {nick}"));
        self.drain(conn);
        conn
    }

    /// All queued output lines for a connection, CRLF stripped.
    fn drain(&mut self, conn: ConnId) -> Vec<String> {
        let rx = &mut self
            .conns
            .iter_mut()
            .find(|(c, _)| *c == conn)
            .expect("conn")
            .1;
        let mut out = Vec::new();
        while let Some(env) = rx.try_pop() {
            let s = String::from_utf8(env.payload.0.to_vec()).expect("utf8");
            assert!(s.ends_with("\r\n"), "line missing CRLF: {s:?}");
            out.push(s.trim_end().to_string());
        }
        out
    }
}

/// Identify a connection to an account via the NickServ flow.
fn identify(s: &mut TestServer, conn: ConnId, account: &str) {
    s.line(conn, &format!("PRIVMSG NickServ :IDENTIFY {account} pw"));
    s.db_requests();
    s.core.handle(Input::DbReply {
        conn,
        reply: e6ircd::core::DbReply::PasswordVerified {
            account: account.into(),
            origin: e6ircd::core::CredentialOrigin::NickServIdentify,
        },
    });
    s.drain(conn);
}

fn core_admin(
    server: &mut TestServer,
    request: e6ircd::core::AdminRequest,
) -> e6ircd::core::AdminReply {
    let (reply, mut result) = tokio::sync::oneshot::channel();
    server.core.handle(Input::Admin {
        req: request,
        reply,
    });
    result.try_recv().expect("synchronous admin reply")
}

fn commit_server_ban(s: &mut TestServer) -> e6ircd::core::ServerBanMutation {
    let mut pending = None;
    for request in s.db_requests() {
        if let e6ircd::core::DbRequest::MutateServerBan {
            mutation,
            requester,
        } = request
        {
            assert!(pending.is_none(), "expected one server-ban mutation");
            pending = Some((mutation, requester));
        }
    }
    let (mutation, requester) = pending.expect("server-ban mutation not queued");
    s.core.handle(Input::ServerBanResult {
        mutation: mutation.clone(),
        requester,
        result: e6ircd::core::ServerBanResult::Stored,
    });
    mutation
}

#[derive(Debug)]
struct PendingReadMarker {
    conn: ConnId,
    account: String,
    target: String,
    display: String,
    marker_ms: Millis,
    label: Option<String>,
}

fn take_read_marker_request(s: &mut TestServer) -> PendingReadMarker {
    let requests = s.db_requests();
    let [
        e6ircd::core::DbRequest::SetReadMarker {
            conn,
            account,
            target,
            display,
            marker_ms,
            label,
        },
    ] = requests.as_slice()
    else {
        panic!("expected exactly one read-marker request, got {requests:#?}");
    };
    PendingReadMarker {
        conn: *conn,
        account: account.clone(),
        target: target.clone(),
        display: display.clone(),
        marker_ms: *marker_ms,
        label: label.clone(),
    }
}

fn confirm_read_marker(s: &mut TestServer) -> PendingReadMarker {
    let request = take_read_marker_request(s);
    confirm_read_marker_as(s, &request, request.marker_ms);
    request
}

fn confirm_read_marker_as(s: &mut TestServer, request: &PendingReadMarker, marker_ms: Millis) {
    s.core.handle(Input::DbReply {
        conn: request.conn,
        reply: e6ircd::core::DbReply::ReadMarkerStored {
            account: request.account.clone(),
            target: request.target.clone(),
            display: request.display.clone(),
            marker_ms,
            label: request.label.clone(),
        },
    });
}

fn reject_read_marker(s: &mut TestServer) -> PendingReadMarker {
    let request = take_read_marker_request(s);
    s.core.handle(Input::DbReply {
        conn: request.conn,
        reply: e6ircd::core::DbReply::ReadMarkerUnavailable {
            account: request.account.clone(),
            target: request.target.clone(),
            display: request.display.clone(),
            label: request.label.clone(),
        },
    });
    request
}

fn has_numeric(lines: &[String], code: &str) -> bool {
    lines.iter().any(|l| l.split(' ').nth(1) == Some(code))
}

#[test]
fn registration_burst() {
    let mut s = TestServer::new();
    let c = s.connect(1);
    s.line(c, "NICK alice");
    s.line(c, "USER alice 0 * :Alice A");
    let out = s.drain(c);

    assert_eq!(
        out[0],
        ":irc.test.example 001 alice :Welcome to the TestNet Network, alice!alice@host1.example"
    );
    for code in [
        "002", "003", "004", "005", "251", "255", "375", "372", "376",
    ] {
        assert!(
            has_numeric(&out, code),
            "missing numeric {code} in {out:#?}"
        );
    }
    // ISUPPORT advertises the Libera-compatible basics
    let isupport: Vec<_> = out.iter().filter(|l| l.contains(" 005 ")).collect();
    let all = isupport
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    for token in [
        "CASEMAPPING=rfc1459",
        "NICKLEN=16",
        "PREFIX=(ov)@+",
        "NETWORK=TestNet",
    ] {
        assert!(all.contains(token), "missing {token} in {all}");
    }
}

#[test]
fn user_first_then_nick_also_registers() {
    let mut s = TestServer::new();
    let c = s.connect(1);
    s.line(c, "USER u 0 * :U");
    assert!(s.drain(c).is_empty(), "no burst before NICK");
    s.line(c, "NICK bob");
    assert!(has_numeric(&s.drain(c), "001"));
}

#[test]
fn nick_collision_and_validation() {
    let mut s = TestServer::new();
    s.register(1, "alice");
    let c2 = s.connect(2);
    s.line(c2, "NICK alice");
    assert!(has_numeric(&s.drain(c2), "433"));
    // case-insensitive collision under rfc1459: ALICE, and {}| vs []\
    s.line(c2, "NICK ALICE");
    assert!(has_numeric(&s.drain(c2), "433"));
    s.line(c2, "NICK 1abc");
    assert!(
        has_numeric(&s.drain(c2), "432"),
        "leading digit is erroneous"
    );
    s.line(c2, "NICK");
    assert!(has_numeric(&s.drain(c2), "431"));
    // An empty nick (`NICK :`) is "no nickname given" (431), not an erroneous
    // one: echoing the empty nick into a 432 middle would emit a collapsing
    // empty parameter (`432 *  :…`), which the numeric funnel now rejects.
    s.line(c2, "NICK :");
    let out = s.drain(c2);
    assert!(has_numeric(&out, "431"), "empty nick must be 431: {out:#?}");
    assert!(
        !has_numeric(&out, "432"),
        "empty nick must not be a 432: {out:#?}"
    );
    s.line(c2, "NICK this-nick-is-way-too-long-for-us");
    assert!(has_numeric(&s.drain(c2), "432"), "over nicklen");
}

#[test]
fn commands_require_registration() {
    let mut s = TestServer::new();
    let c = s.connect(1);
    s.line(c, "JOIN #chan");
    assert!(has_numeric(&s.drain(c), "451"));
    s.line(c, "PRIVMSG x :hi");
    assert!(has_numeric(&s.drain(c), "451"));
}

/// An empty first parameter must not be a silent no-op: `JOIN :`, `PART :`,
/// and `WALLOPS :` were passing the presence check, then the comma-split /
/// empty-body left nothing to do and *no reply was sent*. Treat empty as
/// absent (the same class sweep 75 fixed for NICK/WHO). `NAMES :` must still
/// send its terminating 366, or a client waiting on it hangs.
#[test]
fn empty_first_param_is_not_a_silent_noop() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.drain(alice);

    for (cmd, expected) in [("JOIN :", "461"), ("PART :", "461"), ("JOIN ,", "461")] {
        s.line(alice, cmd);
        let out = s.drain(alice);
        assert!(
            has_numeric(&out, expected),
            "`{cmd}` must reply {expected}, not nothing: {out:#?}"
        );
    }
    // NAMES with an empty target falls back to the no-arg form: a 366.
    s.line(alice, "NAMES :");
    assert!(
        has_numeric(&s.drain(alice), "366"),
        "`NAMES :` must still send its ENDOFNAMES terminator"
    );

    // WALLOPS needs oper; an empty text is 461, not an empty broadcast.
    s.line(alice, "OPER god letmein");
    s.drain(alice);
    s.line(alice, "WALLOPS :");
    assert!(
        has_numeric(&s.drain(alice), "461"),
        "empty WALLOPS must be 461, not an empty broadcast"
    );
}

#[test]
fn unknown_command_is_421() {
    let mut s = TestServer::new();
    let c = s.register(1, "alice");
    s.line(c, "FROBNICATE x");
    let out = s.drain(c);
    assert!(has_numeric(&out, "421"));
    assert!(out[0].contains("FROBNICATE"));
}

#[test]
fn ping_pong() {
    let mut s = TestServer::new();
    let c = s.register(1, "alice");
    s.line(c, "PING :token123");
    assert_eq!(
        s.drain(c),
        vec![":irc.test.example PONG irc.test.example :token123"]
    );
    s.line(c, "PING");
    assert!(has_numeric(&s.drain(c), "409"));
    // PING works pre-registration too
    let c2 = s.connect(2);
    s.line(c2, "PING x");
    assert_eq!(
        s.drain(c2),
        vec![":irc.test.example PONG irc.test.example :x"]
    );
}

#[test]
fn join_broadcasts_and_names() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");

    s.line(alice, "JOIN #room");
    let out = s.drain(alice);
    assert_eq!(out[0], ":alice!alice@host1.example JOIN #room");
    // first joiner is op; NAMES shows @alice
    let names = out.iter().find(|l| l.contains(" 353 ")).expect("353");
    assert!(names.ends_with(":@alice"), "{names}");
    assert!(has_numeric(&out, "366"));

    s.line(bob, "JOIN #room");
    let bob_out = s.drain(bob);
    assert_eq!(bob_out[0], ":bob!bob@host2.example JOIN #room");
    let names = bob_out.iter().find(|l| l.contains(" 353 ")).expect("353");
    // member list contains both, op-prefixed alice
    assert!(names.contains("@alice") && names.contains("bob"));
    // alice sees bob's join
    assert_eq!(s.drain(alice), vec![":bob!bob@host2.example JOIN #room"]);
}

#[test]
fn privmsg_fanout_excludes_sender() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    let carol = s.register(3, "carol");
    for c in [alice, bob, carol] {
        s.line(c, "JOIN #room");
        s.drain(c);
    }
    s.drain(alice);
    s.drain(bob);

    s.line(alice, "PRIVMSG #room :hello all");
    assert!(s.drain(alice).is_empty(), "no echo without echo-message");
    let expect = ":alice!alice@host1.example PRIVMSG #room :hello all";
    assert_eq!(s.drain(bob), vec![expect]);
    assert_eq!(s.drain(carol), vec![expect]);
}

#[test]
fn privmsg_to_nick_and_errors() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");

    s.line(alice, "PRIVMSG bob :psst");
    assert_eq!(
        s.drain(bob),
        vec![":alice!alice@host1.example PRIVMSG bob :psst"]
    );
    // case-insensitive target
    s.line(alice, "PRIVMSG BOB :again");
    assert_eq!(
        s.drain(bob),
        vec![":alice!alice@host1.example PRIVMSG BOB :again"]
    );

    s.line(alice, "PRIVMSG ghost :anyone?");
    assert!(has_numeric(&s.drain(alice), "401"));
    s.line(alice, "PRIVMSG #nochan :hi");
    assert!(has_numeric(&s.drain(alice), "403"));
    s.line(alice, "PRIVMSG");
    assert!(has_numeric(&s.drain(alice), "411"));
    s.line(alice, "PRIVMSG bob");
    assert!(has_numeric(&s.drain(alice), "412"));
    // not on channel => cannot send (+n behavior)
    s.line(bob, "JOIN #priv");
    s.drain(bob);
    s.line(alice, "PRIVMSG #priv :intrude");
    assert!(has_numeric(&s.drain(alice), "404"));
}

#[test]
fn notice_never_generates_errors() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    // Protocol rule (Modern IRC): no automatic replies to NOTICE —
    // this silence is spec-mandated, not a swallowed failure.
    s.line(alice, "NOTICE ghost :hello?");
    assert!(s.drain(alice).is_empty());
}

#[test]
fn part_and_quit_broadcast() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    for c in [alice, bob] {
        s.line(c, "JOIN #room");
        s.drain(c);
    }
    s.drain(alice);

    s.line(bob, "PART #room :gotta go");
    assert_eq!(
        s.drain(alice),
        vec![":bob!bob@host2.example PART #room :gotta go"]
    );
    assert_eq!(
        s.drain(bob),
        vec![":bob!bob@host2.example PART #room :gotta go"]
    );

    // parting when not on channel
    s.line(bob, "PART #room");
    assert!(has_numeric(&s.drain(bob), "442"));

    s.line(bob, "JOIN #room");
    s.drain(bob);
    s.drain(alice);
    s.line(bob, "QUIT :bye");
    let bob_out = s.drain(bob);
    assert!(
        bob_out.iter().any(|l| l.starts_with("ERROR :")),
        "{bob_out:#?}"
    );
    assert_eq!(
        s.drain(alice),
        vec![":bob!bob@host2.example QUIT :Quit: bye"]
    );

    // bob's nick is free again
    let c3 = s.connect(3);
    s.line(c3, "NICK bob");
    s.line(c3, "USER b 0 * :B");
    assert!(has_numeric(&s.drain(c3), "001"));
}

#[test]
fn abrupt_disconnect_broadcasts_quit() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    for c in [alice, bob] {
        s.line(c, "JOIN #room");
        s.drain(c);
    }
    s.drain(alice);
    s.core.handle(Input::Closed {
        conn: bob,
        reason: "Connection reset".into(),
    });
    assert_eq!(
        s.drain(alice),
        vec![":bob!bob@host2.example QUIT :Connection reset"]
    );
}

#[test]
fn nick_change_propagates() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    for c in [alice, bob] {
        s.line(c, "JOIN #room");
        s.drain(c);
    }
    s.drain(alice);
    s.line(alice, "NICK alicia");
    let expect = ":alice!alice@host1.example NICK alicia";
    assert_eq!(s.drain(alice), vec![expect]);
    assert_eq!(s.drain(bob), vec![expect]);
    // old nick free, new nick taken
    s.line(bob, "PRIVMSG alicia :hi");
    assert_eq!(
        s.drain(alice),
        vec![":bob!bob@host2.example PRIVMSG alicia :hi"]
    );
    s.line(bob, "PRIVMSG alice :hi");
    assert!(has_numeric(&s.drain(bob), "401"));
}

#[test]
fn topic_flow() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    s.line(alice, "JOIN #room");
    s.drain(alice);

    s.line(alice, "TOPIC #room");
    assert!(has_numeric(&s.drain(alice), "331"), "no topic yet");

    s.line(alice, "TOPIC #room :the topic");
    assert_eq!(
        s.drain(alice),
        vec![":alice!alice@host1.example TOPIC #room :the topic"]
    );

    // topic visible on join (332 + 333)
    s.line(bob, "JOIN #room");
    let out = s.drain(bob);
    let t332 = out.iter().find(|l| l.contains(" 332 ")).expect("332");
    assert!(t332.ends_with("#room :the topic"));
    assert!(has_numeric(&out, "333"));
    s.drain(alice);

    // non-op cannot set topic on +t channel
    s.line(bob, "TOPIC #room :bob's topic");
    assert!(has_numeric(&s.drain(bob), "482"));
}

#[test]
fn channel_mode_and_ops() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    for c in [alice, bob] {
        s.line(c, "JOIN #room");
        s.drain(c);
    }
    s.drain(alice);

    // default modes on creation are +nt
    s.line(alice, "MODE #room");
    let out = s.drain(alice);
    let m324 = out.iter().find(|l| l.contains(" 324 ")).expect("324");
    assert!(m324.contains("+nt"), "{m324}");
    assert!(has_numeric(&out, "329"), "creation time");

    // op grants op
    s.line(alice, "MODE #room +o bob");
    let expect = ":alice!alice@host1.example MODE #room +o bob";
    assert_eq!(s.drain(alice), vec![expect]);
    assert_eq!(s.drain(bob), vec![expect]);

    // non-op denied: carol, who has no channel status at all
    let carol = s.register(3, "carol");
    s.line(carol, "JOIN #room");
    s.drain(carol);
    s.drain(alice);
    s.drain(bob);
    s.line(carol, "MODE #room +m");
    assert!(has_numeric(&s.drain(carol), "482"));

    // +m: carol (no voice) cannot speak, voiced can
    s.line(alice, "MODE #room +m");
    s.drain(alice);
    s.drain(bob);
    s.drain(carol);
    s.line(carol, "PRIVMSG #room :muted?");
    assert!(has_numeric(&s.drain(carol), "404"));
    s.line(alice, "MODE #room +v carol");
    s.drain(alice);
    s.drain(bob);
    s.drain(carol);
    s.line(carol, "PRIVMSG #room :can speak");
    assert_eq!(s.drain(alice).len(), 1);
}

#[test]
fn mode_partial_application_is_announced_not_silent() {
    // A mode that runs out of arguments must not discard the modes already
    // applied earlier in the same command: `+mo` with no nick applies +m, so
    // the +m must be broadcast (not silently mutate state) alongside the error.
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    for c in [alice, bob] {
        s.line(c, "JOIN #room");
        s.drain(c);
    }
    s.drain(alice);

    s.line(alice, "MODE #room +mo");
    let out = s.drain(alice);
    // The error for the arg-less +o is sent...
    assert!(
        has_numeric(&out, "461"),
        "expected ERR_NEEDMOREPARAMS: {out:#?}"
    );
    // ...and the +m that DID apply is announced, not silently swallowed.
    let announced = out
        .iter()
        .find(|l| l.contains("MODE #room") && l.contains("+m"))
        .unwrap_or_else(|| panic!("applied +m must be broadcast: {out:#?}"));
    // Only +m applied — the arg-less +o must not appear in the mode string.
    assert!(
        announced.trim_end().ends_with("+m"),
        "broadcast must be exactly +m, not +mo: {announced}"
    );
    // Bob (a member) also saw the +m broadcast.
    assert!(
        s.drain(bob)
            .iter()
            .any(|l| l.contains("MODE #room") && l.contains("+m")),
        "members must see the applied +m"
    );

    // State really is +m: an unvoiced non-op cannot speak.
    let carol = s.register(3, "carol");
    s.line(carol, "JOIN #room");
    s.drain(carol);
    s.line(carol, "PRIVMSG #room :muted?");
    assert!(has_numeric(&s.drain(carol), "404"), "channel must be +m");
}

/// A param-less mode *after* a param mode that ran out of arguments must still
/// apply — the arg-exhausted mode used to `break` the whole loop, silently
/// dropping the later mode (`+ki` with no key lost the `+i`), an order-dependent
/// divergence from `+ik`.
#[test]
fn param_less_mode_after_an_argless_param_mode_still_applies() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "JOIN #room"); // op as first joiner
    s.drain(alice);
    // +k needs a key, +i needs nothing. With no key given, +k errors but +i
    // must still be set.
    s.line(alice, "MODE #room +ki");
    let out = s.drain(alice);
    assert!(
        has_numeric(&out, "461"),
        "the arg-less +k must still error: {out:#?}"
    );
    assert!(
        out.iter()
            .any(|l| l.contains("MODE #room") && l.contains("+i")),
        "the param-less +i after +k must be applied and broadcast: {out:#?}"
    );
    // The channel really is +i: a non-invited user is refused.
    let bob = s.register(2, "bob");
    s.line(bob, "JOIN #room");
    assert!(
        has_numeric(&s.drain(bob), "473"),
        "channel must be +i (invite-only)"
    );
}

/// `+o`/`+v` broadcasts the target's canonical nick, not the raw input casing,
/// so a state-tracking client sees the same nick everywhere.
#[test]
fn op_mode_broadcasts_the_targets_canonical_nick() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "Bob"); // registered with capital B
    s.line(alice, "JOIN #room");
    s.drain(alice);
    s.line(bob, "JOIN #room");
    s.drain(bob);
    s.drain(alice);
    // Op using lowercase "bob"; the broadcast must carry canonical "Bob".
    s.line(alice, "MODE #room +o bob");
    let out = s.drain(alice);
    let mode = out
        .iter()
        .find(|l| l.contains("MODE #room +o"))
        .unwrap_or_else(|| panic!("no +o broadcast: {out:#?}"));
    assert!(
        mode.trim_end().ends_with("+o Bob"),
        "must echo the canonical nick 'Bob', not 'bob': {mode}"
    );
}

/// `+l` broadcasts the parsed limit value, not the raw token: `+l 007` is
/// stored and announced as `+l 7` (what is enforced).
#[test]
fn limit_mode_broadcasts_the_parsed_value() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "JOIN #room");
    s.drain(alice);
    s.line(alice, "MODE #room +l 007");
    let out = s.drain(alice);
    let mode = out
        .iter()
        .find(|l| l.contains("MODE #room +l"))
        .unwrap_or_else(|| panic!("no +l broadcast: {out:#?}"));
    assert!(
        mode.trim_end().ends_with("+l 7"),
        "must broadcast the parsed value '7', not '007': {mode}"
    );
}

#[test]
fn whois_channels_split_to_respect_512_byte_limit() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    // Join enough long-named channels that the RPL_WHOISCHANNELS list cannot
    // fit one 512-byte line, forcing the same split send_names applies to 353.
    for i in 0..40 {
        s.line(
            alice,
            &format!("JOIN #channel-with-a-fairly-long-name-{i:02}"),
        );
    }
    s.drain(alice);

    let bob = s.register(2, "bob");
    s.line(bob, "WHOIS alice");
    let out = s.drain(bob);
    let lines_319: Vec<&String> = out.iter().filter(|l| l.contains(" 319 ")).collect();
    assert!(
        lines_319.len() > 1,
        "319 must split across multiple lines, got {}",
        lines_319.len()
    );
    for l in &lines_319 {
        // +2 for the CRLF the transport appends.
        assert!(
            l.len() + 2 <= 512,
            "319 line exceeds 512 bytes: {} bytes",
            l.len() + 2
        );
    }
}

#[test]
fn mode_key_already_set_is_rejected_with_467() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "JOIN #k");
    s.drain(alice);
    s.line(alice, "MODE #k +k secret");
    s.drain(alice);
    // A second +k must not silently overwrite: reply 467 and keep the old key.
    s.line(alice, "MODE #k +k other");
    let out = s.drain(alice);
    assert!(has_numeric(&out, "467"), "expected ERR_KEYSET: {out:#?}");
    assert!(
        !out.iter()
            .any(|l| l.contains("MODE") && l.contains("other")),
        "key must not change: {out:#?}"
    );
}

#[test]
fn overlong_channel_key_is_clipped_not_a_wire_overflow() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "JOIN #x");
    s.drain(alice);
    // A ~497-byte key: unclipped, the resulting `MODE #x +k <key>` broadcast is
    // ~556 bytes and cannot be split (one change, no flush point) — the debug
    // wire-check would panic the shared core worker (a one-connection DoS). The
    // fix clips at KEYLEN=24, so this must NOT panic and the echo carries the
    // clipped key.
    let key = "K".repeat(497);
    s.line(alice, &format!("MODE #x +k {key}"));
    let out = s.drain(alice);
    let mode = out
        .iter()
        .find(|l| l.contains("MODE #x") && l.contains("+k"))
        .expect("expected the +k mode echo");
    let echoed = mode.trim_end().rsplit(' ').next().unwrap_or("");
    assert!(echoed.len() <= 24, "key not clipped to KEYLEN: {echoed:?}");
    for l in &out {
        assert!(
            l.trim_end_matches(['\r', '\n']).len() <= 512,
            "over-length line ({} bytes): {l}",
            l.trim_end_matches(['\r', '\n']).len()
        );
    }
    // The mode query (RPL_CHANNELMODEIS) also fits, since the stored key is bounded.
    s.line(alice, "MODE #x");
    for l in &s.drain(alice) {
        assert!(
            l.trim_end_matches(['\r', '\n']).len() <= 512,
            "324 over-length: {l}"
        );
    }
}

#[test]
fn banned_external_cannot_speak_to_unmoderated_channel() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice"); // founder → opped on #x
    let bob = s.register(2, "bob"); // external
    s.line(alice, "JOIN #x");
    s.drain(alice);
    // -n lets externals speak; but a banned external still cannot.
    s.line(alice, "MODE #x -n");
    s.line(alice, "MODE #x +b bob!*@*");
    s.drain(alice);
    s.line(bob, "PRIVMSG #x :hi");
    assert!(
        has_numeric(&s.drain(bob), "404"),
        "banned external sender must be blocked even on a -n channel"
    );
    // A non-banned external may still speak (proves -n is honored otherwise).
    let carol = s.register(3, "carol");
    s.line(carol, "PRIVMSG #x :hello");
    assert!(
        !has_numeric(&s.drain(carol), "404"),
        "unbanned external must be allowed on a -n channel"
    );
    assert!(s.drain(alice).iter().any(|l| l.contains("hello")));
}

#[test]
fn mode_multichar_list_query_dumps_each_list() {
    // A list-mode char given no argument inside a multi-char modestring
    // (Solanum's `MODE #c be` views bans and exceptions together) must dump each
    // list, not silently no-op — the char used to fall through the query gate
    // (which only matched a single-char modestring) into the apply loop and hit
    // a bare `continue`.
    let mut s = TestServer::new();
    let alice = s.register(1, "alice"); // founder → op on #ml
    s.line(alice, "JOIN #ml");
    s.line(alice, "MODE #ml +b baddie!*@*");
    s.line(alice, "MODE #ml +e friend!*@*");
    s.drain(alice);

    s.line(alice, "MODE #ml be");
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|l| l.contains("367") && l.contains("baddie")),
        "ban list (367) must be dumped: {out:#?}"
    );
    assert!(
        out.iter()
            .any(|l| l.contains("348") && l.contains("friend")),
        "exception list (348) must be dumped: {out:#?}"
    );
    assert!(has_numeric(&out, "368"), "end of ban list: {out:#?}");
    assert!(has_numeric(&out, "349"), "end of exception list: {out:#?}");
}

#[test]
fn ban_removal_is_case_insensitive_like_matching() {
    // A ban matches subjects case-insensitively, so removing it must compare
    // the same way: `-b` in a different case than the stored `+b` must lift it,
    // not leave it silently enforced.
    let mut s = TestServer::new();
    let alice = s.register(1, "alice"); // founder → op on #x
    s.line(alice, "JOIN #x");
    s.drain(alice);
    s.line(alice, "MODE #x +b BOB!*@*");
    s.drain(alice);
    // Remove it with a different case; the ban must actually be gone.
    s.line(alice, "MODE #x -b bob!*@*");
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|l| l.contains("MODE #x") && l.contains("-b")),
        "the differently-cased removal is announced: {out:#?}"
    );
    let bob = s.register(2, "bob");
    s.line(bob, "JOIN #x");
    assert!(
        s.drain(bob).iter().any(|l| l.contains("JOIN")),
        "bob joins because the ban was truly removed, not just announced"
    );
}

#[test]
fn no_op_mode_changes_are_not_broadcast() {
    // Re-setting a mode already in that state must not emit a phantom change —
    // state-tracking clients desync on a transition that did not occur.
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "JOIN #c");
    s.line(alice, "MODE #c +n"); // #c is +n by default; this is a no-op
    s.drain(alice);
    s.line(alice, "MODE #c +n"); // still a no-op
    assert!(
        !s.drain(alice).iter().any(|l| l.contains("MODE #c")),
        "a no-op +n must not broadcast"
    );
    let bob = s.register(2, "bob");
    s.line(bob, "JOIN #c");
    s.drain(alice);
    s.drain(bob);
    s.line(alice, "MODE #c +o bob");
    assert!(
        s.drain(alice).iter().any(|l| l.contains("+o")),
        "the first +o is a real change and is announced"
    );
    s.line(alice, "MODE #c +o bob"); // bob is already op
    assert!(
        !s.drain(alice).iter().any(|l| l.contains("MODE #c")),
        "re-opping an existing op must not broadcast"
    );
    // A duplicate ban add is likewise suppressed.
    s.line(alice, "MODE #c +b dup!*@*");
    s.drain(alice);
    s.line(alice, "MODE #c +b dup!*@*");
    assert!(
        !s.drain(alice).iter().any(|l| l.contains("MODE #c")),
        "adding an already-present ban must not broadcast"
    );
}

#[test]
fn topic_query_on_secret_channel_hidden_from_nonmembers() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "JOIN #sec");
    s.line(alice, "MODE #sec +s");
    s.line(alice, "TOPIC #sec :hush hush");
    s.drain(alice);

    let bob = s.register(2, "bob"); // not a member
    s.line(bob, "TOPIC #sec");
    let out = s.drain(bob);
    // A +s channel must look *non-existent* (403), not "you're not on it"
    // (442): 442 confirms the channel exists, an existence oracle. This matches
    // MODE/KNOCK, which report a hidden channel the same way.
    assert!(
        has_numeric(&out, "403"),
        "non-member must get ERR_NOSUCHCHANNEL, not an existence-confirming 442: {out:#?}"
    );
    assert!(
        !has_numeric(&out, "442"),
        "442 would confirm the secret channel exists: {out:#?}"
    );
    assert!(
        !out.iter().any(|l| l.contains("hush")),
        "secret topic must not leak: {out:#?}"
    );

    // A member still sees it.
    s.line(alice, "TOPIC #sec");
    assert!(
        s.drain(alice).iter().any(|l| l.contains("hush hush")),
        "member must see the topic"
    );
}

/// A +s channel's RPL_ENDOFNAMES to a non-member must echo the caller's input
/// casing, not the channel's canonical name — otherwise `NAMES #secret` on an
/// existing `#Secret` returns a different casing than a non-existent channel,
/// letting an outsider confirm the secret channel exists.
#[test]
fn names_on_secret_channel_does_not_leak_existence_via_casing() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "JOIN #Secret"); // canonical casing
    s.line(alice, "MODE #Secret +s");
    s.drain(alice);

    let bob = s.register(2, "bob"); // not a member
    s.line(bob, "NAMES #secret"); // deliberately different casing
    let out = s.drain(bob);
    let end = out
        .iter()
        .find(|l| l.contains(" 366 "))
        .expect("RPL_ENDOFNAMES");
    assert!(
        end.contains("#secret") && !end.contains("#Secret"),
        "the +s NAMES terminator must echo the caller's input, not the canonical \
         casing (an existence oracle): {end}"
    );
    assert!(
        !out.iter().any(|l| l.contains(" 353 ")),
        "a non-member must not receive a +s channel's member list: {out:#?}"
    );
}

#[test]
fn names_on_missing_channel_terminates() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "NAMES #missing");
    assert!(
        s.drain(alice)
            .iter()
            .any(|line| line.contains(" 366 ") && line.contains("#missing")),
    );
}

#[test]
fn service_nicks_are_reserved() {
    let mut s = TestServer::new();
    let c = s.connect(1);
    s.line(c, "NICK NickServ");
    s.line(c, "USER x 0 * :X");
    let out = s.drain(c);
    assert!(
        has_numeric(&out, "432"),
        "a reserved service nick must be refused: {out:#?}"
    );
    assert!(!has_numeric(&out, "001"), "registration must not complete");
}

#[test]
fn nick_and_quit_broadcasts_carry_server_time() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "server-time");
    let bob = s.register(2, "bob");
    s.line(alice, "JOIN #t");
    s.line(bob, "JOIN #t");
    s.drain(alice);
    s.drain(bob);

    // bob renames; alice (server-time) must see an @time= tag on the NICK.
    s.line(bob, "NICK bobby");
    let out = s.drain(alice);
    let nick_line = out
        .iter()
        .find(|l| l.contains("NICK bobby"))
        .unwrap_or_else(|| panic!("no NICK broadcast: {out:#?}"));
    assert!(
        nick_line.starts_with("@time="),
        "NICK lacks server-time: {nick_line}"
    );

    // bob quits; alice must see @time= on the QUIT too.
    s.line(bob, "QUIT :bye");
    let out = s.drain(alice);
    let quit_line = out
        .iter()
        .find(|l| l.contains("QUIT"))
        .unwrap_or_else(|| panic!("no QUIT broadcast: {out:#?}"));
    assert!(
        quit_line.starts_with("@time="),
        "QUIT lacks server-time: {quit_line}"
    );
}

#[test]
fn who_and_whois() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    for c in [alice, bob] {
        s.line(c, "JOIN #room");
        s.drain(c);
    }
    s.drain(alice);

    s.line(alice, "WHO #room");
    let out = s.drain(alice);
    assert_eq!(out.iter().filter(|l| l.contains(" 352 ")).count(), 2);
    assert!(has_numeric(&out, "315"));

    s.line(alice, "WHOIS bob");
    let out = s.drain(alice);
    let w311 = out.iter().find(|l| l.contains(" 311 ")).expect("311");
    assert!(w311.contains("bob") && w311.contains("host2.example"));
    assert!(has_numeric(&out, "312"));
    assert!(has_numeric(&out, "319"));
    assert!(has_numeric(&out, "318"));

    s.line(alice, "WHOIS ghost");
    let out = s.drain(alice);
    assert!(has_numeric(&out, "401"));
    assert!(has_numeric(&out, "318"), "WHOIS always ends with 318");
}

#[test]
fn invisible_member_hidden_from_channel_who_and_names_by_outsider() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob"); // shares no channel with alice
    s.line(alice, "MODE alice +i");
    s.line(alice, "JOIN #public"); // public, not +s
    s.drain(alice);
    s.drain(bob);
    // An outsider WHOing/NAMESing a public channel must not see the invisible
    // member (the +s check alone doesn't cover a public channel).
    s.line(bob, "WHO #public");
    let out = s.drain(bob);
    assert!(
        !out.iter().any(|l| l.contains("alice")),
        "invisible alice leaked through channel WHO to a non-member: {out:#?}"
    );
    assert!(has_numeric(&out, "315"), "WHO still terminates");
    s.line(bob, "NAMES #public");
    let out = s.drain(bob);
    assert!(
        !out.iter().any(|l| l.contains("alice")),
        "invisible alice leaked through NAMES to a non-member: {out:#?}"
    );
    // A fellow member still sees the invisible user.
    let carol = s.register(3, "carol");
    s.line(carol, "JOIN #public");
    s.drain(carol);
    s.line(carol, "NAMES #public");
    assert!(
        s.drain(carol).iter().any(|l| l.contains("alice")),
        "a fellow channel member must still see the invisible member"
    );
}

#[test]
fn overlong_line_gets_417() {
    let mut s = TestServer::new();
    let c = s.register(1, "alice");
    s.core.handle(Input::OverlongLine { conn: c });
    assert!(has_numeric(&s.drain(c), "417"));
}

#[test]
fn malformed_line_fails_loudly() {
    let mut s = TestServer::new();
    let c = s.register(1, "alice");
    s.core.handle(Input::Line {
        conn: c,
        line: b"@bad".to_vec(),
    });
    let out = s.drain(c);
    assert!(
        out[0].contains(" FAIL "),
        "malformed input must be rejected loudly: {out:#?}"
    );
}

#[test]
fn case_insensitive_channels() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    s.line(alice, "JOIN #Room");
    s.drain(alice);
    s.line(bob, "JOIN #room");
    let out = s.drain(bob);
    // same channel: display name is the creator's casing
    assert_eq!(out[0], ":bob!bob@host2.example JOIN #Room");
    assert_eq!(s.drain(alice), vec![":bob!bob@host2.example JOIN #Room"]);
    // rfc1459: #x{} and #x[] are the same channel
    s.line(alice, "JOIN #x[]");
    s.drain(alice);
    s.line(bob, "JOIN #x{}");
    assert_eq!(s.drain(bob)[0], ":bob!bob@host2.example JOIN #x[]");
}

#[test]
fn motd_and_lusers_commands() {
    let mut s = TestServer::new();
    let c = s.register(1, "alice");
    s.line(c, "MOTD");
    let out = s.drain(c);
    assert!(has_numeric(&out, "375") && has_numeric(&out, "372") && has_numeric(&out, "376"));
    s.line(c, "LUSERS");
    let out = s.drain(c);
    assert!(has_numeric(&out, "251") && has_numeric(&out, "255"));
}

// ---- IRCv3 capability negotiation ---------------------------------------

#[test]
fn cap_ls_gates_registration_until_end() {
    let mut s = TestServer::new();
    let c = s.connect(1);
    s.line(c, "CAP LS 302");
    let out = s.drain(c);
    assert_eq!(out.len(), 1, "{out:#?}");
    assert!(
        out[0].starts_with(":irc.test.example CAP * LS :"),
        "{}",
        out[0]
    );
    for cap in ["server-time", "echo-message", "message-tags", "cap-notify"] {
        assert!(out[0].contains(cap), "missing {cap}: {}", out[0]);
    }
    s.line(c, "NICK alice");
    s.line(c, "USER a 0 * :A");
    assert!(s.drain(c).is_empty(), "registration must wait for CAP END");
    s.line(c, "CAP END");
    assert!(has_numeric(&s.drain(c), "001"));
}

#[test]
fn cap_req_ack_and_nak() {
    let mut s = TestServer::new();
    let c = s.connect(1);
    s.line(c, "CAP LS 302");
    s.drain(c);
    s.line(c, "CAP REQ :server-time echo-message");
    let out = s.drain(c);
    assert_eq!(
        out,
        vec![":irc.test.example CAP * ACK :server-time echo-message"]
    );
    // unknown cap in a REQ naks the whole request, changing nothing
    s.line(c, "CAP REQ :message-tags bogus-cap");
    let out = s.drain(c);
    assert_eq!(
        out,
        vec![":irc.test.example CAP * NAK :message-tags bogus-cap"]
    );
    // removal with -
    s.line(c, "CAP REQ :-echo-message");
    assert_eq!(
        s.drain(c),
        vec![":irc.test.example CAP * ACK :-echo-message"]
    );
    s.line(c, "CAP LIST");
    let out = s.drain(c);
    assert!(out[0].contains("server-time"), "{}", out[0]);
    assert!(!out[0].contains("echo-message"), "{}", out[0]);
    // registration proceeds
    s.line(c, "NICK capy");
    s.line(c, "USER c 0 * :C");
    s.line(c, "CAP END");
    assert!(has_numeric(&s.drain(c), "001"));
}

/// A CAP REQ whose reflected ACK/NAK would exceed the wire limit must not emit
/// an over-long line — that would be discarded by the recipient's framing and,
/// with debug assertions on (as under cargo-fuzz), abort the single core worker:
/// a client-triggerable, unauthenticated DoS. The reply is bounded (NAK, nothing
/// applied), and crucially never panics.
#[test]
fn cap_req_with_an_overlong_list_does_not_overflow_the_wire() {
    let mut s = TestServer::new();
    let c = s.connect(1);
    s.line(c, "CAP LS 302");
    s.drain(c);
    // ~489 bytes of a valid, repeated cap: it fits the input frame, but the old
    // code's ACK-echo (`:server CAP * ACK :<request>`) would overflow 512.
    let big = std::iter::repeat_n("sasl", 98)
        .collect::<Vec<_>>()
        .join(" ");
    s.line(c, &format!("CAP REQ :{big}"));
    let out = s.drain(c);
    assert_eq!(out.len(), 1, "exactly one CAP reply: {out:#?}");
    assert!(
        out[0].len() + 2 <= 512,
        "CAP reply exceeds the wire limit ({} bytes)",
        out[0].len()
    );
    assert!(
        out[0].contains(" CAP * NAK "),
        "an un-echoable REQ must be NAKed, not ACKed: {}",
        out[0]
    );
    // The server is still alive and serving (no panic): a normal REQ still works.
    s.line(c, "CAP REQ :server-time");
    assert_eq!(s.drain(c), vec![":irc.test.example CAP * ACK :server-time"]);
}

/// Aborting a SASL exchange (`AUTHENTICATE *`) while its verify is still in
/// flight, then starting a new one, must not let the stale reply complete the
/// new attempt. The new AUTHENTICATE is refused until the aborted verify's reply
/// drains, so a reply is never attributed to a different attempt.
#[test]
fn sasl_abort_then_reauth_does_not_cross_wire_the_stale_verify() {
    let mut s = TestServer::new();
    let c = s.connect(1);
    s.line(c, "CAP REQ :sasl");
    s.drain(c);
    s.line(c, "AUTHENTICATE PLAIN");
    s.line(c, &format!("AUTHENTICATE {}", b64("\0alice\0pw")));
    assert_eq!(s.db_requests().len(), 1, "first verify dispatched");
    s.drain(c);
    // Abort before the reply lands.
    s.line(c, "AUTHENTICATE *");
    s.drain(c);
    // A new SASL exchange must not dispatch a second verify while the aborted
    // one's reply is still outstanding.
    s.line(c, "AUTHENTICATE PLAIN");
    s.line(c, &format!("AUTHENTICATE {}", b64("\0bob\0pw")));
    assert!(
        s.db_requests().is_empty(),
        "a re-auth must wait for the aborted verify's reply, not race it"
    );
    // The aborted verify's stale reply lands: it is dropped (state is not
    // Verifying) and unblocks a fresh attempt.
    s.core.handle(Input::DbReply {
        conn: c,
        reply: e6ircd::core::DbReply::PasswordVerified {
            account: "alice".into(),
            origin: e6ircd::core::CredentialOrigin::Sasl,
        },
    });
    let out = s.drain(c);
    assert!(
        !out.iter()
            .any(|l| l.contains(" 900 ") || l.contains(" 903 ")),
        "a stale reply for an aborted attempt must not log the client in: {out:#?}"
    );
    // Now a fresh SASL exchange dispatches again.
    s.line(c, "AUTHENTICATE PLAIN");
    s.line(c, &format!("AUTHENTICATE {}", b64("\0alice\0pw")));
    assert_eq!(
        s.db_requests().len(),
        1,
        "a fresh verify dispatches once the stale reply has drained"
    );
}

#[test]
fn cap_list_enumerates_multiline_when_enabled() {
    // CAP LIST must report *every* enabled capability, including the ones
    // tracked outside CAP_NAMES (multiline, account-registration). A client
    // re-syncing via LIST would otherwise be told an enabled cap is off.
    let mut s = TestServer::new();
    let c = s.connect(1);
    s.line(c, "CAP LS 302");
    s.line(c, "CAP REQ :draft/multiline");
    assert!(
        s.drain(c)
            .iter()
            .any(|l| l.contains("ACK") && l.contains("draft/multiline")),
        "multiline is ACKed"
    );
    s.line(c, "CAP LIST");
    let out = s.drain(c);
    assert!(
        out[0].contains("draft/multiline"),
        "CAP LIST must enumerate the enabled multiline cap: {}",
        out[0]
    );
}

#[test]
fn cap_after_registration_works_without_gating() {
    let mut s = TestServer::new();
    let c = s.register(1, "alice");
    s.line(c, "CAP REQ :server-time");
    assert_eq!(
        s.drain(c),
        vec![":irc.test.example CAP alice ACK :server-time"]
    );
}

#[test]
fn invalid_cap_subcommand_is_410() {
    let mut s = TestServer::new();
    let c = s.register(1, "alice");
    s.line(c, "CAP FROB");
    assert!(has_numeric(&s.drain(c), "410"));
}

/// A `:`-leading CAP subcommand (`CAP ::` parses the subcommand as ":") must
/// not be echoed verbatim into ERR_INVALIDCAPCMD's middle — a ':'-leading
/// middle opens the trailing early and corrupts the reply's framing (found by
/// the core fuzzer once the numeric-middle check went in). It renders as the
/// safe "*" placeholder instead.
#[test]
fn invalid_cap_subcommand_with_leading_colon_is_safe() {
    let mut s = TestServer::new();
    let c = s.register(1, "alice");
    s.line(c, "CAP ::");
    let out = s.drain(c);
    let line = out.iter().find(|l| l.contains(" 410 ")).expect("410");
    // The middle after the target is the placeholder, not a bare ":".
    assert!(
        line.contains(" 410 alice * :"),
        "colon subcommand not rendered safely: {line}"
    );
}

fn register_with_caps(s: &mut TestServer, id: u64, nick: &str, caps: &str) -> ConnId {
    let c = s.connect(id);
    s.line(c, "CAP LS 302");
    s.line(c, &format!("CAP REQ :{caps}"));
    s.line(c, &format!("NICK {nick}"));
    s.line(c, &format!("USER {nick} 0 * :Real {nick}"));
    s.line(c, "CAP END");
    s.drain(c);
    c
}

#[test]
fn server_time_tag_on_delivery() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "server-time");
    let bob = s.register(2, "bob");
    for c in [alice, bob] {
        s.line(c, "JOIN #room");
        s.drain(c);
    }
    s.drain(alice);
    s.line(bob, "PRIVMSG #room :timed");
    // clock() = 1_000_000 s → 1970-01-12T13:46:40.000Z
    assert_eq!(
        s.drain(alice),
        vec!["@time=1970-01-12T13:46:40.000Z :bob!bob@host2.example PRIVMSG #room :timed"]
    );
    // bob himself has no cap: no echo, and alice's replies untagged
    s.line(alice, "PRIVMSG #room :untimed for bob");
    assert_eq!(
        s.drain(bob),
        vec![":alice!alice@host1.example PRIVMSG #room :untimed for bob"]
    );
}

#[test]
fn echo_message_returns_own_privmsg() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "echo-message");
    let bob = s.register(2, "bob");
    for c in [alice, bob] {
        s.line(c, "JOIN #room");
        s.drain(c);
    }
    s.drain(alice);
    s.line(alice, "PRIVMSG #room :echoed");
    assert_eq!(
        s.drain(alice),
        vec![":alice!alice@host1.example PRIVMSG #room :echoed"]
    );
    // direct messages echo too
    s.line(alice, "PRIVMSG bob :direct");
    assert_eq!(
        s.drain(alice),
        vec![":alice!alice@host1.example PRIVMSG bob :direct"]
    );
    assert_eq!(s.drain(bob).len(), 2);
}

#[test]
fn tagmsg_relays_client_tags_to_capable_members_only() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "message-tags");
    let bob = register_with_caps(&mut s, 2, "bob", "message-tags");
    let carol = s.register(3, "carol");
    for c in [alice, bob, carol] {
        s.line(c, "JOIN #room");
        s.drain(c);
    }
    s.drain(alice);
    s.drain(bob);
    s.line(alice, "@+typing=active TAGMSG #room");
    let got = s.drain(bob);
    assert_eq!(got.len(), 1);
    // msgid is generated per message; the client tag must ride along
    assert!(
        got[0].starts_with("@msgid=") && got[0].contains("+typing=active"),
        "{got:#?}"
    );
    assert!(
        got[0].ends_with(":alice!alice@host1.example TAGMSG #room"),
        "{got:#?}"
    );
    assert!(s.drain(carol).is_empty(), "no message-tags cap ⇒ no TAGMSG");
}

/// TAGMSG carries `account` (for account-tag recipients) and `bot` (for a bot
/// sender), exactly like PRIVMSG/NOTICE — the tags were previously omitted, so
/// identity/anti-spam tooling lost attribution for typing/reaction traffic.
#[test]
fn tagmsg_carries_account_and_bot_tags() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "message-tags account-tag");
    identify(&mut s, alice, "alice");
    let bob = register_with_caps(&mut s, 2, "bob", "message-tags account-tag");
    for c in [alice, bob] {
        s.line(c, "JOIN #room");
        s.drain(c);
    }
    s.drain(alice);
    s.drain(bob);
    // alice is identified: her TAGMSG to an account-tag recipient carries account=.
    s.line(alice, "@+typing=active TAGMSG #room");
    let got = s.drain(bob);
    assert_eq!(got.len(), 1, "{got:#?}");
    assert!(
        got[0].contains("account=alice"),
        "TAGMSG must carry the sender's account for account-tag recipients: {}",
        got[0]
    );
    // Now make alice a bot; her TAGMSG carries the bot tag.
    s.line(alice, "MODE alice +B");
    s.drain(alice);
    s.line(alice, "@+typing=active TAGMSG #room");
    let got = s.drain(bob);
    assert!(
        got[0].split(' ').next().unwrap().contains(";bot"),
        "a bot's TAGMSG must carry the bot tag: {}",
        got[0]
    );
}

#[test]
fn tagmsg_honors_statusmsg_sigil() {
    // `TAGMSG @#chan` is a valid STATUSMSG (message-tags spec): it must reach
    // only the ops, exactly like `PRIVMSG @#chan`, not fall through to the nick
    // branch and answer ERR_NOSUCHNICK.
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "message-tags"); // founder → op
    let bob = register_with_caps(&mut s, 2, "bob", "message-tags"); // plain member
    for c in [alice, bob] {
        s.line(c, "JOIN #room");
        s.drain(c);
    }
    s.drain(alice);
    s.drain(bob);
    // carol is another op so we can prove ops receive it.
    let carol = register_with_caps(&mut s, 3, "carol", "message-tags");
    s.line(carol, "JOIN #room");
    s.drain(carol);
    s.line(alice, "MODE #room +o carol");
    s.drain(alice);
    s.drain(bob);
    s.drain(carol);
    s.line(alice, "@+typing=active TAGMSG @#room");
    let out = s.drain(alice);
    assert!(
        !out.iter()
            .any(|l| l.contains("NOSUCHNICK") || l.contains(" 401 ")),
        "TAGMSG @#room must not answer ERR_NOSUCHNICK: {out:#?}"
    );
    assert!(
        s.drain(carol).iter().any(|l| l.contains("TAGMSG @#room")),
        "an op receives the STATUSMSG TAGMSG"
    );
    assert!(
        s.drain(bob).is_empty(),
        "a non-op must not receive an ops-only STATUSMSG TAGMSG"
    );
}

/// TAGMSG takes a comma-separated target list, exactly like PRIVMSG/NOTICE.
/// Before the fix it read only the first target, so `TAGMSG #a,#b` failed with
/// ERR_NOSUCHCHANNEL for the whole (unsplit) string.
#[test]
fn tagmsg_splits_a_comma_target_list() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "message-tags");
    let bob = register_with_caps(&mut s, 2, "bob", "message-tags");
    for c in [alice, bob] {
        s.line(c, "JOIN #a");
        s.line(c, "JOIN #b");
    }
    for c in [alice, bob] {
        s.drain(c);
    }
    s.line(alice, "@+typing=active TAGMSG #a,#b");
    let got = s.drain(bob);
    assert!(
        got.iter().any(|l| l.ends_with("TAGMSG #a")),
        "bob must receive the TAGMSG to #a: {got:#?}"
    );
    assert!(
        got.iter().any(|l| l.ends_with("TAGMSG #b")),
        "bob must receive the TAGMSG to #b (not just the first target): {got:#?}"
    );
    assert!(
        s.drain(alice)
            .iter()
            .all(|l| !l.contains("No such channel")),
        "neither target is unknown, so no ERR_NOSUCHCHANNEL"
    );
}

// ---- SASL PLAIN ---------------------------------------------------------

fn b64(s: &str) -> String {
    e6irc_proto::base64::encode(s.as_bytes())
}

#[test]
fn sasl_plain_success_flow() {
    let mut s = TestServer::new();
    let c = s.connect(1);
    s.line(c, "CAP LS 302");
    let ls = s.drain(c);
    assert!(ls[0].contains("sasl=PLAIN"), "{}", ls[0]);
    s.line(c, "CAP REQ :sasl");
    assert!(s.drain(c)[0].contains("ACK"));
    s.line(c, "AUTHENTICATE PLAIN");
    assert_eq!(s.drain(c), vec!["AUTHENTICATE +"]);
    s.line(c, &format!("AUTHENTICATE {}", b64("\0alice\0hunter2")));

    // the core must have asked the DB worker to verify
    let req = s.db_requests();
    assert_eq!(req.len(), 1);
    let e6ircd::core::DbRequest::VerifyPassword {
        conn,
        account,
        password,
        origin,
    } = &req[0]
    else {
        panic!("expected VerifyPassword, got {:?}", req[0]);
    };
    assert_eq!(*conn, c);
    assert_eq!(*origin, e6ircd::core::CredentialOrigin::Sasl);
    assert_eq!(account, "alice");
    assert_eq!(password, "hunter2");

    // inject the verification result
    s.core.handle(Input::DbReply {
        conn: c,
        reply: e6ircd::core::DbReply::PasswordVerified {
            account: "alice".into(),
            origin: e6ircd::core::CredentialOrigin::Sasl,
        },
    });
    let out = s.drain(c);
    assert!(has_numeric(&out, "900"), "{out:#?}");
    assert!(has_numeric(&out, "903"), "{out:#?}");

    s.line(c, "AUTHENTICATE PLAIN");
    let already = s.drain(c);
    assert!(has_numeric(&already, "907"), "{already:#?}");
    assert!(
        s.db_requests().is_empty(),
        "an authenticated session cannot replace its identity"
    );

    s.line(c, "NICK alice");
    s.line(c, "USER a 0 * :A");
    s.line(c, "CAP END");
    assert!(has_numeric(&s.drain(c), "001"));
}

#[test]
fn sasl_rejected_password_is_904() {
    let mut s = TestServer::new();
    let c = s.connect(1);
    s.line(c, "CAP LS 302");
    s.line(c, "CAP REQ :sasl");
    s.line(c, "AUTHENTICATE PLAIN");
    s.drain(c);
    s.line(c, &format!("AUTHENTICATE {}", b64("\0alice\0wrong")));
    s.db_requests();
    s.core.handle(Input::DbReply {
        conn: c,
        reply: e6ircd::core::DbReply::PasswordRejected {
            origin: e6ircd::core::CredentialOrigin::Sasl,
        },
    });
    assert!(has_numeric(&s.drain(c), "904"));
}

#[test]
fn sasl_verification_attempts_are_capped_per_connection() {
    let mut s = TestServer::new();
    let c = s.connect(1);
    s.line(c, "CAP LS 302");
    s.line(c, "CAP REQ :sasl");
    s.drain(c);
    // Eight attempts are allowed; each dispatches an argon2 verify and is
    // rejected, returning to Idle for the next try.
    for _ in 0..8 {
        s.line(c, "AUTHENTICATE PLAIN");
        s.drain(c);
        s.line(c, &format!("AUTHENTICATE {}", b64("\0alice\0wrong")));
        assert_eq!(s.db_requests().len(), 1, "attempt should dispatch a verify");
        s.core.handle(Input::DbReply {
            conn: c,
            reply: e6ircd::core::DbReply::PasswordRejected {
                origin: e6ircd::core::CredentialOrigin::Sasl,
            },
        });
        s.drain(c);
    }
    // The ninth exceeds the cap: no argon2 dispatched, connection closed.
    s.line(c, "AUTHENTICATE PLAIN");
    s.drain(c);
    s.line(c, &format!("AUTHENTICATE {}", b64("\0alice\0wrong")));
    assert!(
        s.db_requests().is_empty(),
        "over-cap attempt must not dispatch argon2 work"
    );
    assert!(
        s.drain(c)
            .iter()
            .any(|l| l.contains("too many authentication attempts")),
        "connection must be closed after too many attempts"
    );
}

#[test]
fn malformed_sasl_attempts_spend_the_same_connection_budget() {
    let mut s = TestServer::new();
    let c = s.connect(1);
    s.line(c, "CAP LS 302");
    s.line(c, "CAP REQ :sasl");
    s.drain(c);
    for _ in 0..8 {
        s.line(c, "AUTHENTICATE PLAIN");
        s.drain(c);
        s.line(c, "AUTHENTICATE not-base64!");
        assert!(has_numeric(&s.drain(c), "904"));
    }
    s.line(c, "AUTHENTICATE PLAIN");
    s.drain(c);
    s.line(c, "AUTHENTICATE not-base64!");
    let out = s.drain(c);
    assert!(
        out.iter().any(|line| line.contains("ERROR")
            && line.contains("too many authentication attempts")),
        "the malformed path must not bypass the connection budget: {out:?}"
    );
    assert!(s.db_requests().is_empty());
}

#[test]
fn unregistered_connection_is_reaped_after_registration_timeout() {
    let mut s = TestServer::new();
    let c = s.connect(1);
    s.line(c, "NICK half"); // never sends USER — registration never completes
    s.drain(c);
    // A tick past the registration deadline (the test clock is a constant
    // 1_000_000_000 ms, so `now` is supplied via the tick).
    s.core.handle(Input::Tick {
        now: MonoMillis::from_millis(1_000_000_000 + 60_000),
    });
    assert!(
        s.drain(c)
            .iter()
            .any(|l| l.contains("Registration timeout")),
        "an unregistered connection must be reaped"
    );
}

#[test]
fn idle_registered_client_is_pinged_then_reaped_without_pong() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.drain(alice);
    // Past the idle interval (120s) → server sends a liveness PING.
    s.core.handle(Input::Tick {
        now: MonoMillis::from_millis(1_000_000_000 + 121_000),
    });
    assert!(
        s.drain(alice).iter().any(|l| l.starts_with("PING ")),
        "idle client must be pinged"
    );
    // No PONG; past the pong deadline (60s) → reaped.
    s.core.handle(Input::Tick {
        now: MonoMillis::from_millis(1_000_000_000 + 121_000 + 61_000),
    });
    assert!(
        s.drain(alice).iter().any(|l| l.contains("Ping timeout")),
        "a client that never PONGs must be reaped"
    );
}

#[test]
fn pong_keeps_a_client_alive_across_reaper_ticks() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.drain(alice);
    s.core.handle(Input::Tick {
        now: MonoMillis::from_millis(1_000_000_000 + 121_000),
    });
    assert!(s.drain(alice).iter().any(|l| l.starts_with("PING ")));
    s.line(alice, "PONG :irc.test.example"); // client answers the ping
    s.core.handle(Input::Tick {
        now: MonoMillis::from_millis(1_000_000_000 + 300_000),
    });
    assert!(
        !s.drain(alice).iter().any(|l| l.contains("Ping timeout")),
        "a client that PONGs must not be reaped"
    );
}

/// Any inbound line — including the client's own keepalive PING — proves the
/// socket is alive and must answer an outstanding liveness PING. A client whose
/// only traffic is its own PINGs (a real class of minimal bots) was reaped as a
/// ping timeout despite a demonstrably live, actively-sending socket.
#[test]
fn inbound_ping_answers_the_liveness_ping_and_prevents_reaping() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.drain(alice);
    // Idle interval → the server sends its liveness PING (awaiting_pong set).
    s.core.handle(Input::Tick {
        now: MonoMillis::from_millis(1_000_000_000 + 121_000),
    });
    assert!(s.drain(alice).iter().any(|l| l.starts_with("PING ")));
    // The client sends its OWN PING (never a literal PONG) — the socket is
    // alive, so this must clear the outstanding liveness PING.
    s.line(alice, "PING :keepalive");
    s.drain(alice); // consume the PONG the server sends back
    // Past the pong deadline: a live, PINGing client must NOT be reaped.
    s.core.handle(Input::Tick {
        now: MonoMillis::from_millis(1_000_000_000 + 121_000 + 61_000),
    });
    assert!(
        !s.drain(alice).iter().any(|l| l.contains("Ping timeout")),
        "a client actively sending its own PINGs must not be ping-timeout reaped"
    );
}

#[test]
fn mode_query_on_secret_channel_hidden_from_nonmembers() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "JOIN #sec");
    s.line(alice, "MODE #sec +s");
    s.line(alice, "MODE #sec +b baddie!*@*");
    s.drain(alice);

    let bob = s.register(2, "bob"); // not a member
    s.line(bob, "MODE #sec");
    assert!(
        has_numeric(&s.drain(bob), "403"),
        "a +s channel must look non-existent to non-members"
    );
    s.line(bob, "MODE #sec +b");
    let out = s.drain(bob);
    assert!(has_numeric(&out, "403"), "ban list hidden on +s");
    assert!(
        !out.iter().any(|l| l.contains("baddie")),
        "ban masks must not leak: {out:#?}"
    );
}

#[test]
fn quieted_member_cannot_set_topic() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice"); // founder → op of #c
    let bob = s.register(2, "bob");
    s.line(alice, "JOIN #c");
    s.line(bob, "JOIN #c");
    s.drain(alice);
    s.drain(bob);
    s.line(alice, "MODE #c -t"); // any member may set the topic
    s.line(alice, "MODE #c +q bob!*@*"); // but bob is quieted
    s.drain(alice);
    s.drain(bob);
    s.line(bob, "TOPIC #c :hijacked");
    assert!(
        has_numeric(&s.drain(bob), "404"),
        "a quieted member must not be able to set the topic"
    );
}

#[test]
fn active_client_without_pong_is_not_reaped() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "JOIN #a");
    s.drain(alice);
    s.core.handle(Input::Tick {
        now: MonoMillis::from_millis(1_000_000_000 + 121_000),
    }); // liveness PING
    assert!(s.drain(alice).iter().any(|l| l.starts_with("PING ")));
    // The client sends a normal command instead of a literal PONG — still alive.
    s.line(alice, "PRIVMSG #a :still here");
    s.drain(alice);
    s.core.handle(Input::Tick {
        now: MonoMillis::from_millis(1_000_000_000 + 300_000),
    });
    assert!(
        !s.drain(alice).iter().any(|l| l.contains("Ping timeout")),
        "an actively-talking client must not be reaped for not PONGing"
    );
}

#[test]
fn version_admin_and_ison_reply() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.drain(alice);

    s.line(alice, "VERSION");
    assert!(has_numeric(&s.drain(alice), "351"), "VERSION → RPL_VERSION");

    s.line(alice, "ADMIN");
    let out = s.drain(alice);
    for code in ["256", "257", "258", "259"] {
        assert!(has_numeric(&out, code), "ADMIN missing {code}: {out:#?}");
    }

    s.line(alice, "ISON alice ghost");
    let ison = s
        .drain(alice)
        .into_iter()
        .find(|l| l.contains(" 303 "))
        .expect("RPL_ISON");
    assert!(ison.contains("alice"), "online nick present: {ison}");
    assert!(!ison.contains("ghost"), "offline nick absent: {ison}");

    // ISON echoes the server's canonical nick, not the caller's casing.
    s.line(alice, "ISON ALICE");
    let ison = s
        .drain(alice)
        .into_iter()
        .find(|l| l.contains(" 303 "))
        .expect("RPL_ISON");
    assert!(
        ison.contains("alice") && !ison.contains("ALICE"),
        "ISON must reply the canonical nick casing: {ison}"
    );

    s.line(alice, "USERIP alice");
    assert!(has_numeric(&s.drain(alice), "340"), "USERIP → RPL_USERIP");

    s.line(alice, "LINKS");
    let out = s.drain(alice);
    assert!(has_numeric(&out, "364"), "LINKS → RPL_LINKS");
    assert!(has_numeric(&out, "365"), "LINKS → RPL_ENDOFLINKS");
}

#[test]
fn ison_excludes_unregistered_nick_holders() {
    let mut s = TestServer::new();
    let asker = s.register(1, "asker");
    s.drain(asker);
    // A second connection sends NICK but never finishes registration.
    let half = s.connect(2);
    s.line(half, "NICK pending");
    s.drain(half);
    s.line(asker, "ISON pending");
    let ison = s
        .drain(asker)
        .into_iter()
        .find(|l| l.contains(" 303 "))
        .expect("RPL_ISON");
    assert!(
        !ison.contains("pending"),
        "an unregistered nick-holder must not be reported online: {ison}"
    );
}

#[test]
fn stats_uptime_and_terminator() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.drain(alice);

    s.line(alice, "STATS u");
    let out = s.drain(alice);
    assert!(
        has_numeric(&out, "242"),
        "STATS u → RPL_STATSUPTIME: {out:#?}"
    );
    assert!(has_numeric(&out, "219"), "STATS → RPL_ENDOFSTATS");

    // An unexposed letter still terminates with a (data-less) report.
    s.line(alice, "STATS z");
    let out = s.drain(alice);
    assert!(
        has_numeric(&out, "219"),
        "unknown STATS letter still terminates"
    );
    assert!(!has_numeric(&out, "242"), "no uptime for a non-u letter");

    // A multi-byte first character must not panic the worker: the letter is
    // taken on a char boundary, not by slicing byte index 1 (which is mid-char
    // for any non-ASCII lead byte). Regression for an unauthenticated DoS.
    s.line(alice, "STATS é");
    let out = s.drain(alice);
    assert!(
        has_numeric(&out, "219"),
        "STATS with a multi-byte argument still terminates without panic"
    );
    s.line(alice, "STATS €uro");
    let out = s.drain(alice);
    assert!(
        has_numeric(&out, "219"),
        "STATS with a leading 3-byte char still terminates without panic"
    );
}

#[test]
fn nick_to_exact_same_nick_is_a_silent_noop() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    s.line(alice, "JOIN #t");
    s.line(bob, "JOIN #t");
    s.drain(alice);
    s.drain(bob);

    // NICK to the exact current nick is a no-op: no reply, no broadcast.
    s.line(alice, "NICK alice");
    assert!(
        s.drain(alice).is_empty(),
        "no-op NICK must produce no reply"
    );
    assert!(s.drain(bob).is_empty(), "no-op NICK must not broadcast");

    // A case change is a real change and IS broadcast.
    s.line(alice, "NICK Alice");
    assert!(
        s.drain(alice).iter().any(|l| l.contains("NICK Alice")),
        "a case change must broadcast"
    );
    assert!(s.drain(bob).iter().any(|l| l.contains("NICK Alice")));
}

#[test]
fn knock_delivers_to_ops_of_invite_only_channel() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice"); // founder → op
    s.line(alice, "JOIN #vip");
    s.line(alice, "MODE #vip +i");
    s.drain(alice);

    let bob = s.register(2, "bob"); // outsider
    s.line(bob, "KNOCK #vip");
    assert!(
        has_numeric(&s.drain(bob), "711"),
        "the knocker gets RPL_KNOCKDLVR"
    );
    assert!(has_numeric(&s.drain(alice), "710"), "the op gets RPL_KNOCK");

    // Knocking an open (non-+i) channel is refused.
    s.line(alice, "JOIN #open");
    s.drain(alice);
    let carol = s.register(3, "carol");
    s.line(carol, "KNOCK #open");
    assert!(
        has_numeric(&s.drain(carol), "713"),
        "an open channel → ERR_CHANOPEN"
    );
}

#[test]
fn idle_client_is_not_repinged_every_tick() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.drain(alice);
    s.core.handle(Input::Tick {
        now: MonoMillis::from_millis(1_000_000_000 + 121_000),
    }); // first liveness PING
    assert_eq!(
        s.drain(alice)
            .iter()
            .filter(|l| l.starts_with("PING "))
            .count(),
        1
    );
    s.line(alice, "PONG :x"); // client answers
    s.drain(alice);
    // Only ~20s later: the ping cadence is 120s from the last PING, so no
    // re-ping — the bug was pinging on every 15s tick once idle.
    s.core.handle(Input::Tick {
        now: MonoMillis::from_millis(1_000_000_000 + 141_000),
    });
    assert!(
        s.drain(alice).iter().all(|l| !l.starts_with("PING ")),
        "an idle client must not be re-pinged every tick"
    );
}

#[test]
fn sasl_bad_base64_and_malformed_payload_fail() {
    let mut s = TestServer::new();
    let c = s.connect(1);
    s.line(c, "CAP LS 302");
    s.line(c, "CAP REQ :sasl");
    s.line(c, "AUTHENTICATE PLAIN");
    s.drain(c);
    s.line(c, "AUTHENTICATE !!!not-base64!!!");
    assert!(has_numeric(&s.drain(c), "904"));
    assert!(
        s.db_requests().is_empty(),
        "bad input must not reach the DB"
    );
    // well-formed base64, wrong structure (no NUL separators)
    s.line(c, "AUTHENTICATE PLAIN");
    s.drain(c);
    s.line(c, &format!("AUTHENTICATE {}", b64("no-separators")));
    assert!(has_numeric(&s.drain(c), "904"));
}

#[test]
fn sasl_chunk_overflow_fails_without_growing_the_buffer() {
    // A single over-long AUTHENTICATE line is ERR_SASLTOOLONG (905), but a
    // client can also drip 400-byte chunks forever to grow the buffer. That
    // is bounded, and ends as a plain authentication failure (904) — 905 is
    // specified for one over-long command, not an accumulated payload.
    let mut s = TestServer::new();
    let c = s.connect(1);
    s.line(c, "CAP LS 302");
    s.line(c, "CAP REQ :sasl");
    s.drain(c);

    // One line longer than the 400-byte chunk size: 905.
    s.line(c, "AUTHENTICATE PLAIN");
    s.drain(c);
    s.line(c, &format!("AUTHENTICATE {}", "x".repeat(401)));
    assert!(has_numeric(&s.drain(c), "905"));

    // Now drip full 400-byte chunks until the buffer cap is exceeded.
    s.line(c, "AUTHENTICATE PLAIN");
    let retry = s.drain(c);
    assert!(
        retry.iter().any(|line| line == "AUTHENTICATE +"),
        "905 must reset the exchange so the client can retry: {retry:?}"
    );
    let chunk = "x".repeat(400);
    let mut failed = false;
    for _ in 0..64 {
        s.line(c, &format!("AUTHENTICATE {chunk}"));
        if has_numeric(&s.drain(c), "904") {
            failed = true;
            break;
        }
    }
    assert!(failed, "an unbounded chunk stream must be cut off with 904");
    assert!(
        s.db_requests().is_empty(),
        "an overflowing payload must never reach the DB"
    );
}

#[test]
fn sasl_abort_is_906_and_without_cap_fails() {
    let mut s = TestServer::new();
    let c = s.connect(1);
    s.line(c, "CAP LS 302");
    s.line(c, "CAP REQ :sasl");
    s.line(c, "AUTHENTICATE PLAIN");
    s.drain(c);
    s.line(c, "AUTHENTICATE *");
    assert!(has_numeric(&s.drain(c), "906"));

    let c2 = s.connect(2);
    s.line(c2, "AUTHENTICATE PLAIN");
    assert!(has_numeric(&s.drain(c2), "904"), "sasl cap not requested");
}

#[test]
fn sasl_unknown_mechanism_gets_908() {
    let mut s = TestServer::new();
    let c = s.connect(1);
    s.line(c, "CAP LS 302");
    s.line(c, "CAP REQ :sasl");
    s.drain(c);
    s.line(c, "AUTHENTICATE EXTERNAL");
    let out = s.drain(c);
    assert!(has_numeric(&out, "908"), "{out:#?}");
    assert!(has_numeric(&out, "904"), "{out:#?}");
}

// ---- services (NickServ / ChanServ) -------------------------------------

#[test]
fn nickserv_register_creates_account() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "PRIVMSG NickServ :REGISTER hunter2");
    let req = s.db_requests();
    assert_eq!(
        req,
        vec![e6ircd::core::DbRequest::CreateAccount {
            conn: alice,
            name: "alice".into(),
            contact_email: None,
            password: "hunter2".into(),
            origin: e6ircd::core::AccountOrigin::NickServ,
        }]
    );
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::AccountCreated {
            account: "alice".into(),
            origin: e6ircd::core::AccountOrigin::NickServ,
        },
    });
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|l| l.starts_with(":NickServ!") && l.contains("registered")),
        "{out:#?}"
    );
    // identified state visible in WHOIS via 330
    let bob = s.register(2, "bob");
    s.line(bob, "WHOIS alice");
    assert!(has_numeric(&s.drain(bob), "330"));
}

#[test]
fn account_registration_persists_only_valid_normalized_contact_email() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "draft/account-registration");
    s.drain(alice);
    s.line(
        alice,
        "REGISTER * Alice+IRC@Example.COM correct-horse-battery",
    );
    assert_eq!(
        s.db_requests(),
        vec![e6ircd::core::DbRequest::CreateAccount {
            conn: alice,
            name: "alice".into(),
            contact_email: Some(
                e6ircd::identity::ContactEmail::parse("Alice+IRC@example.com")
                    .expect("valid contact email")
            ),
            password: "correct-horse-battery".into(),
            origin: e6ircd::core::AccountOrigin::RegisterCommand,
        }]
    );

    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::AccountExists {
            origin: e6ircd::core::AccountOrigin::RegisterCommand,
        },
    });
    s.drain(alice);
    s.line(alice, "REGISTER * not-an-email correct-horse-battery");
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|line| line.contains("FAIL REGISTER INVALID_EMAIL")),
        "{out:#?}"
    );
    assert!(
        s.db_requests().is_empty(),
        "invalid contact data must not reach storage"
    );
}

#[test]
fn nickserv_registration_stores_contact_email_and_rejects_extra_arguments() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(
        alice,
        "PRIVMSG NickServ :REGISTER hunter2 Alice@Example.COM",
    );
    assert_eq!(
        s.db_requests(),
        vec![e6ircd::core::DbRequest::CreateAccount {
            conn: alice,
            name: "alice".into(),
            contact_email: Some(
                e6ircd::identity::ContactEmail::parse("Alice@example.com")
                    .expect("valid contact email")
            ),
            password: "hunter2".into(),
            origin: e6ircd::core::AccountOrigin::NickServ,
        }]
    );

    s.line(
        alice,
        "PRIVMSG NickServ :REGISTER hunter2 alice@example.com ignored",
    );
    assert!(s.db_requests().is_empty());
    assert!(
        s.drain(alice)
            .iter()
            .any(|line| line.contains("Syntax: REGISTER")),
        "extra accepted-but-ignored arguments must fail loudly"
    );
}

#[test]
fn nickserv_register_duplicate_and_syntax() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "PRIVMSG NickServ :REGISTER");
    let out = s.drain(alice);
    assert!(out[0].contains("Syntax"), "{out:#?}");
    assert!(s.db_requests().is_empty());

    s.line(alice, "PRIVMSG NickServ :REGISTER pw");
    s.db_requests();
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::AccountExists {
            origin: e6ircd::core::AccountOrigin::NickServ,
        },
    });
    let out = s.drain(alice);
    assert!(out[0].contains("already registered"), "{out:#?}");
}

#[test]
fn overlapping_identify_is_refused_not_silently_dropped() {
    // Two IDENTIFYs in flight would share the single `pending_identify` flag;
    // the first verdict to land clears it, so the second (possibly the *valid*
    // one) would hit the stale-reply guard and be silently dropped — no login,
    // no notice. A second IDENTIFY must be refused while one is pending.
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.drain(alice);
    let _ = s.db_requests(); // clear any registration-time requests

    s.line(alice, "PRIVMSG NickServ :IDENTIFY first");
    s.line(alice, "PRIVMSG NickServ :IDENTIFY second");
    // Only ONE verify was dispatched — the second was refused, not queued behind
    // a shared flag.
    let reqs = s.db_requests();
    assert_eq!(
        reqs.len(),
        1,
        "a second IDENTIFY while one is pending must not dispatch a second verify: {reqs:#?}"
    );
    let out = s.drain(alice);
    assert!(
        out.iter().any(|l| l.contains("already in progress")),
        "the second IDENTIFY must be told it's refused, not silently dropped: {out:#?}"
    );

    // The first (still-pending) verify completes normally.
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::PasswordVerified {
            account: "alice".into(),
            origin: e6ircd::core::CredentialOrigin::NickServIdentify,
        },
    });
    let out = s.drain(alice);
    assert!(
        out.iter().any(|l| l.contains("identified")),
        "the first IDENTIFY still completes: {out:#?}"
    );
}

#[test]
fn nickserv_identify_flow() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "PRIVMSG NickServ :IDENTIFY hunter2");
    let req = s.db_requests();
    assert_eq!(
        req,
        vec![e6ircd::core::DbRequest::VerifyPassword {
            conn: alice,
            account: "alice".into(),
            password: "hunter2".into(),
            origin: e6ircd::core::CredentialOrigin::NickServIdentify,
        }]
    );
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::PasswordVerified {
            account: "alice".into(),
            origin: e6ircd::core::CredentialOrigin::NickServIdentify,
        },
    });
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|l| l.starts_with(":NickServ!") && l.contains("identified")),
        "{out:#?}"
    );
    // wrong password path
    s.line(alice, "PRIVMSG NickServ :IDENTIFY nope");
    s.db_requests();
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::PasswordRejected {
            origin: e6ircd::core::CredentialOrigin::NickServIdentify,
        },
    });
    let out = s.drain(alice);
    assert!(out[0].contains("Invalid password"), "{out:#?}");
}

#[test]
fn credential_verdict_routes_on_its_own_origin_not_session_flags() {
    // The verdict routes on the origin the *request* carried, never on the
    // session's `sasl`/`pending_identify` flags. A stray SASL-origin verdict
    // arriving while a NickServ IDENTIFY is outstanding must NOT complete that
    // IDENTIFY — the old flag-inference would have logged the client in as the
    // SASL verdict's account. This pins the routing as unrepresentable-by-origin
    // even if the single-outstanding-verify invariant were ever violated.
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "PRIVMSG NickServ :IDENTIFY pw"); // pending_identify = true
    s.db_requests();
    // A SASL verdict for a different account lands while IDENTIFY is pending.
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::PasswordVerified {
            account: "eve".into(),
            origin: e6ircd::core::CredentialOrigin::Sasl,
        },
    });
    let out = s.drain(alice);
    assert!(
        !out.iter()
            .any(|l| l.contains("identified") || l.contains("eve")),
        "a SASL-origin verdict must not complete a NickServ IDENTIFY: {out:#?}"
    );
    // The real IDENTIFY verdict still completes it — for alice, not eve.
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::PasswordVerified {
            account: "alice".into(),
            origin: e6ircd::core::CredentialOrigin::NickServIdentify,
        },
    });
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|l| l.contains("identified for \x02alice\x02")),
        "the IDENTIFY completes on its own origin's verdict: {out:#?}"
    );
}

/// A SASL verify and a NickServ IDENTIFY verify must never be in flight for one
/// connection at once: both are offloaded and their replies routed by ambient
/// flags, so allowing both would let an IDENTIFY reply be taken for the SASL
/// result (or vice-versa) and log the client in as the wrong account. The two
/// flows are mutually exclusive; a race is refused, not run.
#[test]
fn sasl_and_identify_verifies_are_mutually_exclusive() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    // Begin a SASL PLAIN verify: it dispatches a verify and leaves SASL in the
    // Verifying state (no reply fed yet).
    s.line(alice, "CAP REQ :sasl");
    s.line(alice, "AUTHENTICATE PLAIN");
    s.line(alice, &format!("AUTHENTICATE {}", b64("\0alice\0pw")));
    assert_eq!(s.db_requests().len(), 1, "SASL dispatched one verify");
    s.drain(alice);
    s.line(alice, "AUTHENTICATE PLAIN");
    let overlapping = s.drain(alice);
    assert!(has_numeric(&overlapping, "904"), "{overlapping:?}");
    assert!(
        !has_numeric(&overlapping, "907"),
        "907 is reserved for a connection whose authentication already succeeded"
    );
    // An IDENTIFY while the SASL verify is pending is refused and enqueues
    // nothing — no concurrent second verify to cross-attribute.
    s.line(alice, "PRIVMSG NickServ :IDENTIFY pw");
    assert!(
        s.db_requests().is_empty(),
        "IDENTIFY must not start a verify while SASL is pending"
    );
    assert!(
        s.drain(alice)
            .iter()
            .any(|l| l.contains("authentication is already in progress")),
        "the IDENTIFY must be told an authentication is in progress"
    );
    // The SASL result still resolves normally.
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::PasswordVerified {
            account: "alice".into(),
            origin: e6ircd::core::CredentialOrigin::Sasl,
        },
    });
    assert!(
        s.drain(alice).iter().any(|l| l.contains(" 903 ")),
        "the original SASL authentication still succeeds"
    );
}

/// The converse guard: a SASL verify started while a NickServ IDENTIFY verify is
/// pending is refused, so the two are never concurrent from either direction.
#[test]
fn sasl_verify_refused_while_identify_pending() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "PRIVMSG NickServ :IDENTIFY pw");
    assert_eq!(s.db_requests().len(), 1, "IDENTIFY dispatched one verify");
    s.drain(alice);
    // A SASL PLAIN verify while the IDENTIFY is pending must not dispatch.
    s.line(alice, "CAP REQ :sasl");
    s.line(alice, "AUTHENTICATE PLAIN");
    s.line(alice, &format!("AUTHENTICATE {}", b64("\0alice\0pw")));
    assert!(
        s.db_requests().is_empty(),
        "SASL must not start a verify while an IDENTIFY is pending"
    );
    assert!(
        s.drain(alice).iter().any(|l| l.contains(" 904 ")),
        "the SASL attempt fails (ERR_SASLFAIL) rather than racing the IDENTIFY"
    );
}

/// A SASL verify that can't be enqueued because the DB request queue is full
/// must not lock the connection out of authentication for good. The
/// verify-pending flag is set only *after* a successful push, so a failed push
/// leaves it clear and a later AUTHENTICATE (once the queue drains) proceeds —
/// where a set-then-maybe-fail order left the flag stuck true, and every
/// subsequent AUTHENTICATE/IDENTIFY was refused as "already in progress".
#[test]
fn sasl_survives_a_full_db_queue_and_can_retry() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "JOIN #flood");
    s.drain(alice);
    s.db_requests(); // clear registration/join enqueues

    // Fill the DB request queue (capacity 64) with channel LogMessages, without
    // draining, so the next push fails.
    for i in 0..80 {
        s.line(alice, &format!("PRIVMSG #flood :m{i}"));
        s.drain(alice);
    }

    // The verify push now fails on the full queue → 904, flag left clear.
    s.line(alice, "CAP REQ :sasl");
    s.drain(alice);
    s.line(alice, "AUTHENTICATE PLAIN");
    s.drain(alice);
    s.line(alice, &format!("AUTHENTICATE {}", b64("\0alice\0pw")));
    assert!(
        has_numeric(&s.drain(alice), "904"),
        "a full queue should fail the SASL attempt"
    );

    // Drain the queue and retry: the connection is NOT locked out.
    s.db_requests();
    s.line(alice, "AUTHENTICATE PLAIN");
    assert_eq!(
        s.drain(alice),
        vec!["AUTHENTICATE +"],
        "auth must not be locked out after a full-queue failure"
    );
    s.line(alice, &format!("AUTHENTICATE {}", b64("\0alice\0pw")));
    assert_eq!(
        s.db_requests().len(),
        1,
        "the retry must dispatch a verify once the queue has room"
    );
}

#[test]
fn deferred_register_reply_is_released_on_transient_db_failure() {
    // REGISTER holds the connection's output behind a deferred reply while the
    // DB write is in flight. A transient failure (AccountRegisterUnavailable,
    // carrying the RegisterCommand origin) must still be routed back to
    // REGISTER: the client gets its FAIL and the hold is released — otherwise
    // every later line is held and the reaper eventually ping-timeouts a live
    // client. Regression for that leak.
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.drain(alice);
    s.line(alice, "REGISTER * * hunter2");
    let req = s.db_requests();
    assert!(
        matches!(
            req.as_slice(),
            [e6ircd::core::DbRequest::CreateAccount {
                origin: e6ircd::core::AccountOrigin::RegisterCommand,
                ..
            }]
        ),
        "REGISTER enqueues a RegisterCommand CreateAccount: {req:#?}"
    );
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::AccountRegisterUnavailable {
            origin: e6ircd::core::AccountOrigin::RegisterCommand,
        },
    });
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|l| l.contains("FAIL REGISTER TEMPORARILY_UNAVAILABLE")),
        "the owed FAIL is delivered on a transient DB failure: {out:#?}"
    );
    // The hold is gone: a pipelined PING now gets its PONG instead of being
    // held behind a leaked defer.
    s.line(alice, "PING :liveness");
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|l| l.contains("PONG") && l.contains("liveness")),
        "output is not stuck behind a leaked deferred reply: {out:#?}"
    );
}

#[test]
fn second_register_while_first_pending_is_refused() {
    // Only one account creation may be in flight per connection. A second
    // REGISTER while the first still awaits its DB verdict must be refused, not
    // spawn a second argon2 hash / deferred reply whose label overwrites the
    // first's — which would frame the earlier reply under the wrong label.
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.drain(alice);
    s.line(alice, "REGISTER * * hunter2");
    let first = s.db_requests();
    assert_eq!(first.len(), 1, "first REGISTER enqueues one CreateAccount");
    // Second REGISTER before the first resolves.
    s.line(alice, "REGISTER * * hunter2");
    assert!(
        s.db_requests().is_empty(),
        "a duplicate in-flight REGISTER must not enqueue a second CreateAccount"
    );
    // Now resolve the first; its deferred FAIL is held behind the defer, and the
    // duplicate's refusal (a synchronous FAIL) was held too — both flush here.
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::AccountExists {
            origin: e6ircd::core::AccountOrigin::RegisterCommand,
        },
    });
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|l| l.contains("FAIL REGISTER TEMPORARILY_UNAVAILABLE")
                && l.contains("already in progress")),
        "the duplicate REGISTER is refused as already-in-progress: {out:#?}"
    );
}

#[test]
fn labeled_register_reply_carries_the_label() {
    // REGISTER's answer comes back from a database round trip, so the deferred
    // SUCCESS/FAIL is emitted long after the command was dispatched. A client
    // that labeled the REGISTER must still get that label back on the reply —
    // otherwise labeled-response is silently broken for the one command whose
    // answer is always asynchronous, and the client can never correlate it.
    let mut s = TestServer::new();
    let alice = register_with_caps(
        &mut s,
        1,
        "alice",
        "labeled-response draft/account-registration",
    );
    s.drain(alice);

    // A labeled REGISTER must not be ACKed synchronously as empty — the answer
    // is still in flight. Nothing should come back until the DB replies.
    s.line(alice, "@label=reg1 REGISTER * * hunter2");
    let out = s.drain(alice);
    assert!(
        out.is_empty(),
        "a labeled REGISTER is held for its async reply, not ACKed empty: {out:#?}"
    );

    // Success lands: the deferred REGISTER SUCCESS carries the label.
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::AccountCreated {
            account: "alice".into(),
            origin: e6ircd::core::AccountOrigin::RegisterCommand,
        },
    });
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|l| l.starts_with("@label=reg1 ") && l.contains("REGISTER SUCCESS alice")),
        "labeled REGISTER SUCCESS carries the label: {out:#?}"
    );

    // And the failure branch, on a fresh connection (alice is now logged in):
    // a labeled REGISTER whose DB verdict is a duplicate must return a FAIL
    // tagged with that request's label.
    let bob = register_with_caps(
        &mut s,
        2,
        "bob",
        "labeled-response draft/account-registration",
    );
    s.drain(bob);
    s.line(bob, "@label=reg2 REGISTER * * hunter2");
    assert!(
        s.drain(bob).is_empty(),
        "labeled REGISTER is held for its async reply"
    );
    s.core.handle(Input::DbReply {
        conn: bob,
        reply: e6ircd::core::DbReply::AccountExists {
            origin: e6ircd::core::AccountOrigin::RegisterCommand,
        },
    });
    let out = s.drain(bob);
    assert!(
        out.iter()
            .any(|l| l.starts_with("@label=reg2 ") && l.contains("FAIL REGISTER ACCOUNT_EXISTS")),
        "labeled REGISTER FAIL carries the label: {out:#?}"
    );
}

/// Like REGISTER, a labeled NickServ IDENTIFY's verdict comes from a DB round
/// trip. The labeled client must get its label back on the async verdict —
/// before, IDENTIFY answered the label with an empty ACK and the verdict NOTICE
/// arrived unlabeled, so a label-tracking client couldn't correlate it.
#[test]
fn labeled_identify_verdict_carries_the_label() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "labeled-response");
    s.drain(alice);
    s.db_requests();

    // A labeled IDENTIFY is not ACKed empty — the verdict is still in flight.
    s.line(alice, "@label=id7 PRIVMSG NickServ :IDENTIFY pw");
    assert!(
        s.drain(alice).is_empty(),
        "a labeled IDENTIFY is held for its async verdict, not ACKed empty"
    );

    // Success verdict carries the label.
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::PasswordVerified {
            account: "alice".into(),
            origin: e6ircd::core::CredentialOrigin::NickServIdentify,
        },
    });
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|l| l.starts_with("@label=id7 ") && l.contains("identified")),
        "the labeled IDENTIFY verdict carries the label: {out:#?}"
    );
}

/// The failure verdict is labeled too (not just success).
#[test]
fn labeled_identify_failure_carries_the_label() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "labeled-response");
    s.drain(alice);
    s.db_requests();
    s.line(alice, "@label=id8 PRIVMSG NickServ :IDENTIFY wrong");
    assert!(s.drain(alice).is_empty(), "held for the async verdict");
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::PasswordRejected {
            origin: e6ircd::core::CredentialOrigin::NickServIdentify,
        },
    });
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|l| l.starts_with("@label=id8 ") && l.contains("Invalid password")),
        "the labeled IDENTIFY failure carries the label: {out:#?}"
    );
}

#[test]
fn nickserv_identify_spends_the_shared_credential_budget() {
    // NickServ IDENTIFY drives argon2 just like SASL, so it must spend from the
    // same per-connection budget — otherwise it can be looped to brute-force or
    // burn CPU past the cap SASL enforces. The 9th attempt closes the link.
    // Only one verify may be in flight at a time (see
    // `overlapping_identify_is_refused_not_silently_dropped`), so each attempt's
    // verdict is injected before the next — the serial flow a real client sees.
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.drain(alice);
    for _ in 0..8 {
        s.line(alice, "PRIVMSG NickServ :IDENTIFY wrongpw");
        let _ = s.db_requests(); // this attempt's VerifyPassword
        // Verdict lands, clearing `pending_identify` so the next attempt is not
        // refused as "already in progress".
        s.core.handle(Input::DbReply {
            conn: alice,
            reply: e6ircd::core::DbReply::PasswordRejected {
                origin: e6ircd::core::CredentialOrigin::NickServIdentify,
            },
        });
        let out = s.drain(alice);
        assert!(
            !out.iter().any(|l| l.contains("ERROR")),
            "the first eight IDENTIFYs stay within budget: {out:#?}"
        );
    }
    s.line(alice, "PRIVMSG NickServ :IDENTIFY wrongpw"); // 9th
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|l| l.contains("ERROR") && l.contains("too many authentication attempts")),
        "the ninth credential attempt must close the connection: {out:#?}"
    );
}

#[test]
fn nickserv_case_insensitive_target_and_unknown_command() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "PRIVMSG nickserv :HELP");
    let out = s.drain(alice);
    assert!(out.iter().any(|l| l.starts_with(":NickServ!")), "{out:#?}");
    s.line(alice, "PRIVMSG NickServ :FROB");
    let out = s.drain(alice);
    assert!(out[0].contains("Invalid command"), "{out:#?}");
}

#[test]
fn channel_access_reply_for_unregistered_channel_is_not_phantom_inserted() {
    // A ChannelAccessSet grant reply for a channel that is no longer registered
    // (a DROP landed between the write and this reply; the DB cascade already
    // removed the access row) must NOT re-insert a hot access entry — that
    // phantom would silently auto-op the account if the name were later
    // re-registered by anyone. The grant is reported void instead.
    let mut s = TestServer::new();
    s.core
        .preload_founders(vec![("#ghost".to_string(), "alice".to_string())]);
    let alice = s.register(1, "alice");
    identify(&mut s, alice, "alice");
    s.line(alice, "PRIVMSG ChanServ :FLAGS #ghost bob +o");
    assert!(
        s.db_requests()
            .iter()
            .any(|request| matches!(request, e6ircd::core::DbRequest::SetChannelAccess { .. }))
    );
    // Models a DROP that committed after the FLAGS write but before its verdict.
    let owner = s
        .channel_service_route
        .as_ref()
        .expect("FLAGS persistence route")
        .0
        .clone();
    s.core.handle(Input::ChannelDropResult {
        owner,
        channel: "#ghost".into(),
        requester: e6ircd::core::ChannelDropRequester::Admin {
            request_id: 0,
            actor: "test".into(),
        },
        result: e6ircd::core::ChannelDropResult::Dropped,
    });
    s.core.preload_founders(vec![]);
    let (owner, session) = s
        .channel_service_route
        .take()
        .expect("FLAGS persistence route");
    s.core.handle(Input::ChannelServicePersisted {
        owner,
        session,
        result: e6ircd::core::ChannelServicePersistence::AccessSet {
            channel: "#ghost".into(),
            display: "#ghost".into(),
            account: "bob".into(),
            flags: Some("o".into()),
            applied: true,
            label: None,
        },
    });
    s.core.handle(Input::ChannelServiceResult {
        session,
        result: e6ircd::core::ChannelServicePersistence::AccessMissing {
            display: "#ghost".into(),
            label: None,
        },
    });
    let out = s.drain(alice);
    assert!(
        out.iter().any(|l| l.contains("no longer registered")),
        "a grant reply for an unregistered channel must be reported void, not \
         phantom-inserted: {out:#?}"
    );
    assert!(
        !out.iter().any(|l| l.contains("are now +o")),
        "it must not confirm a grant on a channel that no longer exists: {out:#?}"
    );
}

#[test]
fn chanserv_register_flow() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    // must be identified first
    s.line(alice, "JOIN #mine");
    s.drain(alice);
    s.line(alice, "PRIVMSG ChanServ :REGISTER #mine");
    let out = s.drain(alice);
    assert!(
        out[0].contains("identify"),
        "unidentified must be refused: {out:#?}"
    );
    assert!(s.db_requests().is_empty());

    // identify, then register
    s.line(alice, "PRIVMSG NickServ :IDENTIFY pw");
    s.db_requests();
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::PasswordVerified {
            account: "alice".into(),
            origin: e6ircd::core::CredentialOrigin::NickServIdentify,
        },
    });
    s.drain(alice);
    s.line(alice, "PRIVMSG ChanServ :REGISTER #mine");
    let req = s.db_requests();
    assert!(matches!(
        req.as_slice(),
        [e6ircd::core::DbRequest::RegisterChannel {
            channel,
            founder_account,
            topic: None,
            label: None,
            ..
        }] if channel == "#mine" && founder_account == "alice"
    ));
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::ChannelRegistered {
            channel: "#mine".into(),
            founder_account: "alice".into(),
            topic: None,
            label: None,
        },
    });
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|l| l.starts_with(":ChanServ!") && l.contains("registered")),
        "{out:#?}"
    );
}

#[test]
fn channel_registration_persists_its_initial_topic_atomically() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    identify(&mut s, alice, "alice");
    s.line(alice, "JOIN #mine");
    s.drain(alice);
    s.db_requests();
    // Before registration this is an ordinary live-only topic.
    s.line(alice, "TOPIC #mine :registration topic");
    s.drain(alice);

    s.line(alice, "PRIVMSG ChanServ :REGISTER #mine");
    assert!(
        s.drain(alice).is_empty(),
        "registration must wait for its durable verdict"
    );
    let requests = s.db_requests();
    let topic = match requests.as_slice() {
        [
            e6ircd::core::DbRequest::RegisterChannel {
                channel,
                founder_account,
                topic: Some(topic),
                ..
            },
        ] if channel == "#mine" && founder_account == "alice" => topic.clone(),
        other => panic!("registration did not carry its initial topic: {other:#?}"),
    };
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::ChannelRegistered {
            channel: "#mine".into(),
            founder_account: "alice".into(),
            topic: Some(topic),
            label: None,
        },
    });
    s.drain(alice);

    s.line(alice, "PART #mine");
    s.drain(alice);
    s.line(alice, "JOIN #mine");
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|line| line.contains(" 332 ") && line.ends_with(":registration topic")),
        "the atomically registered topic was not retained: {out:#?}"
    );
}

#[test]
fn pending_channel_registrations_count_toward_the_account_cap() {
    let mut s = TestServer::new();
    s.core.preload_founders(
        (0..199)
            .map(|i| (format!("#owned{i}"), "alice".to_string()))
            .collect(),
    );
    let alice = s.register(1, "alice");
    identify(&mut s, alice, "alice");
    s.line(alice, "JOIN #reserved,#over-cap");
    s.drain(alice);
    s.db_requests();

    s.line(alice, "PRIVMSG ChanServ :REGISTER #reserved");
    assert!(matches!(
        s.db_requests().as_slice(),
        [e6ircd::core::DbRequest::RegisterChannel { channel, .. }]
            if channel == "#reserved"
    ));
    // The first INSERT has not resolved, but its reservation is the 200th
    // permanent founder entry. A pipelined 201st registration is refused.
    s.line(alice, "PRIVMSG ChanServ :REGISTER #over-cap");
    assert!(
        s.db_requests().is_empty(),
        "an in-flight registration must consume a cap slot"
    );
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::ChannelRegisterUnavailable {
            channel: "#reserved".into(),
            label: None,
        },
    });
    let out = s.drain(alice);
    assert!(
        out.iter().any(|line| line.contains("too many channels")),
        "the pipelined over-cap command was not refused: {out:#?}"
    );
}

#[test]
fn reregistering_owned_channel_does_not_reserve_an_extra_cap_slot() {
    let mut s = TestServer::new();
    s.core.preload_founders(
        (0..199)
            .map(|i| (format!("#owned{i}"), "alice".to_string()))
            .collect(),
    );
    let alice = s.register(1, "alice");
    identify(&mut s, alice, "alice");
    s.line(alice, "JOIN #owned0,#last-slot");
    s.drain(alice);
    s.db_requests();

    s.line(alice, "PRIVMSG ChanServ :REGISTER #owned0");
    assert!(matches!(
        s.db_requests().as_slice(),
        [e6ircd::core::DbRequest::RegisterChannel { channel, .. }]
            if channel == "#owned0"
    ));

    s.line(alice, "PRIVMSG ChanServ :REGISTER #last-slot");
    assert!(
        matches!(
            s.db_requests().as_slice(),
            [e6ircd::core::DbRequest::RegisterChannel { channel, .. }]
                if channel == "#last-slot"
        ),
        "a pending re-registration of a committed channel must not consume a new founder slot"
    );
}

/// ChanServ FLAGS must reject an unrecognized flag char loudly. Before the fix
/// `apply_flag_changes` silently dropped unknown flags, so `FLAGS #c bob +q`
/// produced an empty set — a *revoke* the founder never asked for — and reported
/// it back as success (DESIGN §2, no silent no-ops).
#[test]
fn chanserv_flags_rejects_an_unknown_flag() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "PRIVMSG NickServ :IDENTIFY pw");
    s.db_requests();
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::PasswordVerified {
            account: "alice".into(),
            origin: e6ircd::core::CredentialOrigin::NickServIdentify,
        },
    });
    s.drain(alice);
    s.line(alice, "PRIVMSG ChanServ :REGISTER #mine");
    s.db_requests();
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::ChannelRegistered {
            channel: "#mine".into(),
            founder_account: "alice".into(),
            topic: None,
            label: None,
        },
    });
    s.drain(alice);

    // Unknown flag `q`: rejected loudly, and nothing is written.
    s.line(alice, "PRIVMSG ChanServ :FLAGS #mine bob +q");
    let out = s.drain(alice);
    assert!(
        out.iter().any(|l| l.contains("Unknown flag")),
        "an unknown flag must be rejected loudly: {out:#?}"
    );
    assert!(
        s.db_requests().is_empty(),
        "a rejected flag must write nothing (no silent revoke)"
    );

    // A recognized flag still works — proving the reject is specific, not blanket.
    s.line(alice, "PRIVMSG ChanServ :FLAGS #mine bob +o");
    assert!(
        matches!(
            s.db_requests().as_slice(),
            [e6ircd::core::DbRequest::SetChannelAccess { flags: Some(f), .. }] if f == "o"
        ),
        "a valid +o must enqueue a SetChannelAccess granting o"
    );
}

/// An account may register only up to a cap of channels: each registration
/// adds a permanent, restart-surviving founder-map entry and runs no argon2, so
/// without a cap a REGISTER loop grows that map without bound. At the cap, a new
/// registration is refused (nothing enqueued); re-registering an already-owned
/// channel stays a no-op path, not gated.
#[test]
fn chanserv_register_is_capped_per_account() {
    let mut s = TestServer::new();
    // Seed alice at the cap (MAX_CHANNELS_PER_ACCOUNT = 200 founder entries).
    let preloaded: Vec<(String, String)> = (0..200)
        .map(|i| (format!("#owned{i}"), "alice".to_string()))
        .collect();
    s.core.preload_founders(preloaded);
    let alice = s.register(1, "alice");
    identify(&mut s, alice, "alice");
    s.line(alice, "JOIN #one-too-many");
    s.drain(alice);
    s.db_requests();

    // A new registration at the cap is refused, and nothing is enqueued.
    s.line(alice, "PRIVMSG ChanServ :REGISTER #one-too-many");
    let out = s.drain(alice);
    assert!(
        out.iter().any(|l| l.contains("too many channels")),
        "over-cap registration must be refused: {out:#?}"
    );
    assert!(
        s.db_requests().is_empty(),
        "over-cap registration must not enqueue a RegisterChannel"
    );
}

#[test]
fn chanserv_register_requires_op() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    s.line(alice, "JOIN #theirs");
    s.drain(alice);
    s.line(bob, "JOIN #theirs");
    s.drain(bob);
    s.line(bob, "PRIVMSG NickServ :IDENTIFY pw");
    s.db_requests();
    s.core.handle(Input::DbReply {
        conn: bob,
        reply: e6ircd::core::DbReply::PasswordVerified {
            account: "bob".into(),
            origin: e6ircd::core::CredentialOrigin::NickServIdentify,
        },
    });
    s.drain(bob);
    s.line(bob, "PRIVMSG ChanServ :REGISTER #theirs");
    let out = s.drain(bob);
    assert!(out[0].contains("operator"), "non-op refused: {out:#?}");
    assert!(s.db_requests().is_empty());
}

// ---- channel protection modes (Libera/Solanum semantics) ----------------

#[test]
fn ban_blocks_join_and_exception_overrides() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    s.line(alice, "JOIN #guard");
    s.drain(alice);
    s.line(alice, "MODE #guard +b bob!*@*");
    s.drain(alice);

    s.line(bob, "JOIN #guard");
    assert!(has_numeric(&s.drain(bob), "474"), "banned join must 474");

    // +e exception lifts the ban
    s.line(alice, "MODE #guard +e bob!*@host2.example");
    s.drain(alice);
    s.line(bob, "JOIN #guard");
    assert!(has_numeric(&s.drain(bob), "366"), "exception must admit");
}

#[test]
fn quiet_mode_blocks_speaking_only() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    for c in [alice, bob] {
        s.line(c, "JOIN #q");
        s.drain(c);
    }
    s.drain(alice);
    s.line(alice, "MODE #q +q bob!*@*");
    s.drain(alice);
    s.drain(bob);
    s.line(bob, "PRIVMSG #q :muffled");
    assert!(has_numeric(&s.drain(bob), "404"), "quieted must 404");
    assert!(s.drain(alice).is_empty());
    // quiet list query with 728/729
    s.line(alice, "MODE #q +q");
    let out = s.drain(alice);
    assert!(
        has_numeric(&out, "728") && has_numeric(&out, "729"),
        "{out:#?}"
    );
    // voice overrides quiet
    s.line(alice, "MODE #q +v bob");
    s.drain(alice);
    s.drain(bob);
    s.line(bob, "PRIVMSG #q :audible");
    assert_eq!(s.drain(alice).len(), 1);
}

#[test]
fn invite_only_key_and_limit_enforced_on_join() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    s.line(alice, "JOIN #vip");
    s.drain(alice);

    s.line(alice, "MODE #vip +i");
    s.drain(alice);
    s.line(bob, "JOIN #vip");
    assert!(has_numeric(&s.drain(bob), "473"));
    // +I exception admits
    s.line(alice, "MODE #vip +I *!*@host2.example");
    s.drain(alice);
    s.line(bob, "JOIN #vip");
    assert!(has_numeric(&s.drain(bob), "366"));
    s.line(bob, "PART #vip");
    s.drain(bob);
    s.drain(alice);

    s.line(alice, "MODE #vip -i+k sekrit");
    s.drain(alice);
    s.line(bob, "JOIN #vip");
    assert!(has_numeric(&s.drain(bob), "475"), "wrong key");
    s.line(bob, "JOIN #vip wrongkey");
    assert!(has_numeric(&s.drain(bob), "475"));
    s.line(bob, "JOIN #vip sekrit");
    assert!(has_numeric(&s.drain(bob), "366"));
    s.line(bob, "PART #vip");
    s.drain(bob);
    s.drain(alice);

    s.line(alice, "MODE #vip -k+l * 1");
    s.drain(alice);
    s.line(bob, "JOIN #vip");
    assert!(has_numeric(&s.drain(bob), "471"), "over limit");
}

#[test]
fn ban_exception_and_invex_lists_query() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "JOIN #lists");
    s.drain(alice);
    s.line(alice, "MODE #lists +eI a!*@* b!*@*");
    s.drain(alice);
    s.line(alice, "MODE #lists +e");
    let out = s.drain(alice);
    assert!(
        has_numeric(&out, "348") && has_numeric(&out, "349"),
        "{out:#?}"
    );
    s.line(alice, "MODE #lists +I");
    let out = s.drain(alice);
    assert!(
        has_numeric(&out, "346") && has_numeric(&out, "347"),
        "{out:#?}"
    );
}

// ---- WHOX ---------------------------------------------------------------

#[test]
fn whox_fielded_reply() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    for c in [alice, bob] {
        s.line(c, "JOIN #wx");
        s.drain(c);
    }
    s.drain(alice);
    // token, nick, flags, account — fixed field order per WHOX spec
    s.line(alice, "WHO #wx %tnfa,42");
    let out = s.drain(alice);
    let rows: Vec<_> = out.iter().filter(|l| l.contains(" 354 ")).collect();
    assert_eq!(rows.len(), 2, "{out:#?}");
    // bob: no account → 0; flags H plus no sigil; token first
    let bob_row = rows.iter().find(|l| l.contains("bob")).expect("bob row");
    assert!(
        bob_row.ends_with("42 bob H 0"),
        "field order/values wrong: {bob_row}"
    );
    assert!(has_numeric(&out, "315"));
}

#[test]
fn whox_full_fields_with_account() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "JOIN #wx");
    s.drain(alice);
    // identify alice so the account column is real
    s.line(alice, "PRIVMSG NickServ :IDENTIFY pw");
    s.db_requests();
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::PasswordVerified {
            account: "alice".into(),
            origin: e6ircd::core::CredentialOrigin::NickServIdentify,
        },
    });
    s.drain(alice);

    s.line(alice, "WHO #wx %cuhsnfar");
    let out = s.drain(alice);
    let row = out.iter().find(|l| l.contains(" 354 ")).expect("354");
    // c u h s n f a r → channel user host server nick flags account :realname
    assert_eq!(
        *row,
        ":irc.test.example 354 alice #wx alice host1.example irc.test.example alice H@ alice :Real alice"
    );
}

#[test]
fn whox_reply_never_exceeds_the_wire_limit() {
    // WHOX packs up to a dozen middles whose *sum* — not just any single field or
    // the realname trailing — can exceed 512 at supported maxima: a 63-char
    // server_name and nicklen=64 put both in the head AND a middle (`s`/`n`), a
    // 64-char account is another wide middle (`a`), a 50-char channel another
    // (`c`), and the client token adds up to 100 (`t`). The numeric funnel must
    // bound the whole line — clipping middles once they'd overrun — or the
    // recipient's framing discards the 354 whole (the row silently vanishes) and
    // a debug build panics on the over-long line. This exercises that guard; the
    // weaker head sizes the trailing clip alone already handled did not.
    let server = "s".repeat(63);
    let mut s = TestServer::with_full_config(
        true, // SASL: lets us identify to a wide account for the `a` field
        || Millis::from_millis(1_000_000_000),
        512,
        &server,
        64,
    );
    let nick = "n".repeat(64);
    let alice = s.connect(1);
    s.line(alice, &format!("NICK {nick}"));
    s.line(
        alice,
        &format!("USER {} 0 * :{}", "u".repeat(10), "R".repeat(300)),
    );
    s.drain(alice);
    identify(&mut s, alice, &"a".repeat(64));
    let chan = format!("#{}", "c".repeat(49)); // 50 chars incl '#' (== CHANNELLEN)
    s.line(alice, &format!("JOIN {chan}"));
    s.drain(alice);
    // Every WHOX field, plus a maximal client token — the true worst case.
    let token = "T".repeat(120);
    s.line(alice, &format!("WHO {chan} %tcuihsnfdlaor,{token}"));
    let out = s.drain(alice);
    let row = out.iter().find(|l| l.contains(" 354 ")).expect("354 row");
    assert!(
        row.len() + 2 <= 512,
        "the 354 line (+CRLF) must fit 512 bytes, got {}: {row}",
        row.len() + 2
    );
}

#[test]
fn plain_who_still_works_alongside_whox() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "JOIN #wx");
    s.drain(alice);
    s.line(alice, "WHO #wx");
    let out = s.drain(alice);
    assert!(has_numeric(&out, "352") && has_numeric(&out, "315"));
}

/// A WHOX token that cannot stand as a middle parameter must not be echoed
/// verbatim: an empty token (`%tn,`) collapses into the adjacent space and
/// shifts every later field left one column, and a leading `:` (`%tn,:x`)
/// starts a premature trailing that swallows the rest of the row. Both are
/// treated as absent and echoed as the conventional "0". A fieldless `%`
/// falls back to plain WHO (charybdis behavior) instead of emitting
/// parameterless 354 rows.
#[test]
fn whox_token_that_breaks_framing_is_defaulted() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "JOIN #wx");
    s.drain(alice);
    // Empty token after the comma → "0", not a vanishing param.
    s.line(alice, "WHO #wx %tn,");
    let out = s.drain(alice);
    let row = out.iter().find(|l| l.contains(" 354 ")).expect("354");
    assert!(row.ends_with(" 0 alice"), "empty token mis-echoed: {row}");
    assert!(!row.contains("  "), "collapsed empty param: {row}");
    // A token opening a premature trailing → "0".
    s.line(alice, "WHO #wx %tn,:x");
    let out = s.drain(alice);
    let row = out.iter().find(|l| l.contains(" 354 ")).expect("354");
    assert!(row.ends_with(" 0 alice"), "colon token mis-echoed: {row}");
    // Fieldless % → plain WHO.
    s.line(alice, "WHO #wx %");
    let out = s.drain(alice);
    assert!(
        has_numeric(&out, "352") && !out.iter().any(|l| l.contains(" 354 ")),
        "fieldless WHOX must fall back to plain WHO: {out:#?}"
    );
}

/// The RFC 2812 `o` flag (`WHO <mask> o`) restricts matches to operators —
/// previously it was silently ignored and returned everyone.
#[test]
fn who_o_flag_restricts_to_opers() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    s.line(alice, "OPER god letmein");
    s.drain(alice);
    s.line(bob, "WHO * o");
    let out = s.drain(bob);
    // Exactly one row — the oper (the requester nick after 352 is bob; the
    // listed nick column is what matters).
    let rows: Vec<_> = out.iter().filter(|l| l.contains(" 352 ")).collect();
    assert_eq!(rows.len(), 1, "only the oper must be listed: {out:#?}");
    assert!(
        rows[0].contains(" alice "),
        "the oper must be the one listed: {}",
        rows[0]
    );
    // Combined with a WHOX spec, Solanum-style.
    s.line(bob, "WHO * o%nf");
    let out = s.drain(bob);
    let rows: Vec<_> = out.iter().filter(|l| l.contains(" 354 ")).collect();
    assert_eq!(rows.len(), 1, "only the oper: {out:#?}");
    assert!(rows[0].contains("alice"));
}

// ---- KICK / INVITE / AWAY / LIST / USERHOST -----------------------------

#[test]
fn kick_flow() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    for c in [alice, bob] {
        s.line(c, "JOIN #k");
        s.drain(c);
    }
    s.drain(alice);
    // non-op cannot kick
    s.line(bob, "KICK #k alice :no");
    assert!(has_numeric(&s.drain(bob), "482"));
    // op kicks with reason; both see it; bob is out
    s.line(alice, "KICK #k bob :begone");
    let expect = ":alice!alice@host1.example KICK #k bob :begone";
    assert_eq!(s.drain(alice), vec![expect]);
    assert_eq!(s.drain(bob), vec![expect]);
    s.line(bob, "PRIVMSG #k :still here?");
    assert!(has_numeric(&s.drain(bob), "404"));
    // kicking a non-member
    s.line(alice, "KICK #k bob");
    assert!(has_numeric(&s.drain(alice), "441"));
}

/// KICK takes a comma-separated *user* list on one channel (Modern IRC). Before
/// the fix only the first user was removed and the rest silently ignored.
#[test]
fn kick_removes_a_comma_user_list() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    let carol = s.register(3, "carol");
    for c in [alice, bob, carol] {
        s.line(c, "JOIN #k");
        s.drain(c);
    }
    s.drain(alice);
    // One KICK, two victims.
    s.line(alice, "KICK #k bob,carol :cleanup");
    let seen = s.drain(alice);
    assert!(
        seen.iter().any(|l| l.contains("KICK #k bob")),
        "bob is kicked: {seen:#?}"
    );
    assert!(
        seen.iter().any(|l| l.contains("KICK #k carol")),
        "carol is kicked too, not silently ignored: {seen:#?}"
    );
    // Both are actually out of the channel now.
    for victim in [bob, carol] {
        s.line(victim, "PRIVMSG #k :still here?");
        assert!(
            has_numeric(&s.drain(victim), "404"),
            "a kicked user can no longer speak to the channel"
        );
    }
}

/// The RFC2812/Modern matched multi-channel form: `KICK #a,#b u,v` kicks u from
/// #a and v from #b (equal-length lists pair positionally). A single-channel list
/// against many users kicks all from it; unequal multi-channel lists are refused.
#[test]
fn kick_pairs_matched_channel_and_user_lists() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    let carol = s.register(3, "carol");
    for c in [alice, bob, carol] {
        s.line(c, "JOIN #a");
        s.line(c, "JOIN #b");
    }
    for c in [alice, bob, carol] {
        s.drain(c);
    }
    // Matched lists: bob from #a, carol from #b.
    s.line(alice, "KICK #a,#b bob,carol :bye");
    let seen = s.drain(alice);
    assert!(
        seen.iter().any(|l| l.contains("KICK #a bob")),
        "bob kicked from #a: {seen:#?}"
    );
    assert!(
        seen.iter().any(|l| l.contains("KICK #b carol")),
        "carol kicked from #b: {seen:#?}"
    );
    // bob is still in #b (only kicked from #a); carol still in #a.
    s.line(bob, "PRIVMSG #b :hi");
    assert!(
        !has_numeric(&s.drain(bob), "404"),
        "bob was only kicked from #a, not #b"
    );

    // Unequal multi-channel/user lists are refused loudly (461), not guessed.
    s.line(alice, "KICK #a,#b bob :bye");
    assert!(
        has_numeric(&s.drain(alice), "461"),
        "an unequal multi-channel KICK must be refused"
    );
}

#[test]
fn invite_lets_target_through_invite_only() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    s.line(alice, "JOIN #inv");
    s.drain(alice);
    s.line(alice, "MODE #inv +i");
    s.drain(alice);

    s.line(bob, "JOIN #inv");
    assert!(has_numeric(&s.drain(bob), "473"));

    s.line(alice, "INVITE bob #inv");
    assert!(has_numeric(&s.drain(alice), "341"));
    assert_eq!(
        s.drain(bob),
        vec![":alice!alice@host1.example INVITE bob :#inv"]
    );
    s.line(bob, "JOIN #inv");
    assert!(has_numeric(&s.drain(bob), "366"), "invite must admit");

    // errors: not on channel / no such nick / already on
    let carol = s.register(3, "carol");
    s.line(carol, "INVITE bob #inv");
    assert!(has_numeric(&s.drain(carol), "442"));
    s.line(alice, "INVITE ghost #inv");
    assert!(has_numeric(&s.drain(alice), "401"));
    s.line(alice, "INVITE bob #inv");
    assert!(has_numeric(&s.drain(alice), "443"));
}

/// An invite is a grant by an op of a specific channel *incarnation*: when the
/// channel empties and is destroyed, the invite dies with it. Before invites
/// moved onto the channel, a session-side name-keyed invite survived teardown
/// and admitted its holder through +i on an unrelated later channel that
/// merely reused the name — a premeditated +i bypass (invite yourself via a
/// throwaway channel, drop it, wait for the victim to create it).
#[test]
fn invite_does_not_survive_channel_teardown() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    s.line(alice, "JOIN #re");
    s.drain(alice);
    s.line(alice, "INVITE bob #re");
    s.drain(alice);
    s.drain(bob);
    // The channel empties → destroyed, with bob's invite still pending.
    s.line(alice, "PART #re");
    s.drain(alice);
    // An unrelated user recreates the name and locks it down.
    let carol = s.register(3, "carol");
    s.line(carol, "JOIN #re");
    s.drain(carol);
    s.line(carol, "MODE #re +i");
    s.drain(carol);
    // bob's stale invite must not admit into carol's channel.
    s.line(bob, "JOIN #re");
    assert!(
        has_numeric(&s.drain(bob), "473"),
        "an invite into a destroyed channel admitted into its successor"
    );
}

/// A list-mode mask is clipped to BANMASKLEN at store time, so the stored mask
/// always fits the RPL_BANLIST middle (what the list displays is exactly what
/// is enforced — and thus removable by copying it into -b) and a single
/// `MODE +b <mask>` broadcast can never exceed the wire limit (unclipped, the
/// broadcast would be discarded whole by recipients' framing while the ban is
/// silently enforced — and the debug wire check would abort the core worker).
#[test]
fn overlong_ban_mask_is_clipped_and_stays_removable() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    for c in [alice, bob] {
        s.line(c, "JOIN #bm");
        s.drain(c);
    }
    s.drain(alice);
    let long_mask = format!("{}!*@*", "x".repeat(400));
    s.line(alice, &format!("MODE #bm +b {long_mask}"));
    // The broadcast announces the stored (clipped) form and fits the wire.
    let out = s.drain(alice);
    let mode = out.iter().find(|l| l.contains("MODE #bm +b")).expect("+b");
    assert!(
        mode.len() <= 512,
        "broadcast exceeds the wire limit: {mode}"
    );
    s.drain(bob);
    // The list shows the stored mask verbatim...
    s.line(alice, "MODE #bm +b");
    let list = s.drain(alice);
    let entry = list.iter().find(|l| l.contains(" 367 ")).expect("367");
    let shown = entry
        .split_whitespace()
        .nth(4)
        .expect("367 carries the mask");
    // ...and copying the shown mask into -b removes the ban.
    s.line(alice, &format!("MODE #bm -b {shown}"));
    assert!(
        s.drain(alice).iter().any(|l| l.contains("MODE #bm -b")),
        "the displayed mask must remove the ban it displays"
    );
    s.line(alice, "MODE #bm +b");
    assert!(
        !s.drain(alice).iter().any(|l| l.contains(" 367 ")),
        "ban list must be empty after removing via the displayed mask"
    );
}

/// A list-mode mask with an embedded space (reachable only via the trailing
/// form) must be rejected like a space-containing key: stored, it would split
/// into two tokens in the MODE broadcast and the RPL_BANLIST middle — a
/// malformed line for every state-tracking client — and copying the displayed
/// form into `-b` could never remove it (only the first token is consumed).
#[test]
fn list_mode_mask_with_space_is_rejected() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    for c in [alice, bob] {
        s.line(c, "JOIN #sp");
        s.drain(c);
    }
    s.drain(alice);
    s.line(alice, "MODE #sp +b :a b");
    let out = s.drain(alice);
    assert!(
        out.iter().any(|l| l.contains(" 696 ")),
        "no ERR_INVALIDMODEPARAM for a space-containing mask: {out:?}"
    );
    assert!(
        !out.iter().any(|l| l.contains("MODE #sp +b")),
        "space-containing mask was applied and broadcast: {out:?}"
    );
    assert_eq!(s.drain(bob), Vec::<String>::new(), "peers saw a broadcast");
    // Nothing was stored.
    s.line(alice, "MODE #sp +b");
    assert!(
        !s.drain(alice).iter().any(|l| l.contains(" 367 ")),
        "space-containing mask was stored"
    );
    // The other grouped list modes share the arm — spot-check one.
    s.line(alice, "MODE #sp +I :inv ex");
    assert!(
        s.drain(alice).iter().any(|l| l.contains(" 696 ")),
        "+I accepted a space-containing mask"
    );
}

#[test]
fn away_flow() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    s.line(alice, "AWAY :gone fishing");
    assert!(has_numeric(&s.drain(alice), "306"));
    s.line(bob, "PRIVMSG alice :you there?");
    let out = s.drain(bob);
    let away = out.iter().find(|l| l.contains(" 301 ")).expect("301");
    assert!(away.ends_with("alice :gone fishing"), "{away}");
    assert_eq!(s.drain(alice).len(), 1, "message still delivered");
    s.line(alice, "AWAY");
    assert!(has_numeric(&s.drain(alice), "305"));
}

#[test]
fn channel_who_reports_away_members() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    s.line(alice, "JOIN #room");
    s.line(bob, "JOIN #room");
    s.drain(alice);
    s.drain(bob);
    s.line(alice, "AWAY :brb");
    s.drain(alice);
    s.line(bob, "WHO #room");
    assert!(
        s.drain(bob)
            .iter()
            .any(|line| line.contains(" 352 ") && line.contains(" alice G")),
    );
}

/// Messaging yourself while away must not trigger an away auto-reply about
/// yourself — you already know you're away.
#[test]
fn away_self_message_gets_no_away_reply() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "AWAY :brb");
    s.drain(alice);
    s.line(alice, "PRIVMSG alice :note to self");
    let out = s.drain(alice);
    assert!(
        !out.iter().any(|l| l.contains(" 301 ")),
        "a self-message must not yield RPL_AWAY: {out:#?}"
    );
    // The message itself is still delivered to self.
    assert!(
        out.iter()
            .any(|l| l.contains("PRIVMSG alice :note to self")),
        "the self-message is still delivered: {out:#?}"
    );
}

#[test]
fn list_hides_secret_channels() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    s.line(alice, "JOIN #pub");
    s.drain(alice);
    s.line(alice, "JOIN #sec");
    s.drain(alice);
    s.line(alice, "MODE #sec +s");
    s.drain(alice);
    s.line(bob, "LIST");
    let out = s.drain(bob);
    assert!(
        out.iter()
            .any(|l| l.contains(" 322 ") && l.contains("#pub")),
        "{out:#?}"
    );
    assert!(
        !out.iter().any(|l| l.contains("#sec")),
        "secret leaked: {out:#?}"
    );
    assert!(has_numeric(&out, "323"));
    // members see their own secret channels
    s.line(alice, "LIST");
    let out = s.drain(alice);
    assert!(out.iter().any(|l| l.contains("#sec")));
}

#[test]
fn userhost_reply() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.register(2, "bob");
    s.line(alice, "USERHOST bob ghost");
    let out = s.drain(alice);
    assert_eq!(
        out,
        vec![":irc.test.example 302 alice :bob=+bob@host2.example"]
    );
}

// ---- modern client caps -------------------------------------------------

#[test]
fn multi_prefix_and_userhost_in_names() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "multi-prefix userhost-in-names");
    let bob = s.register(2, "bob");
    s.line(alice, "JOIN #mp");
    s.drain(alice);
    s.line(bob, "JOIN #mp");
    s.drain(bob);
    s.drain(alice);
    s.line(alice, "MODE #mp +v alice");
    s.drain(alice);
    s.drain(bob);
    s.line(alice, "NAMES #mp");
    let out = s.drain(alice);
    let names = out.iter().find(|l| l.contains(" 353 ")).expect("353");
    // op+voice shown together, and full userhost form
    assert!(names.contains("@+alice!alice@host1.example"), "{names}");
    assert!(names.contains("bob!bob@host2.example"), "{names}");
    // plain client sees classic form
    s.line(bob, "NAMES #mp");
    let out = s.drain(bob);
    let names = out.iter().find(|l| l.contains(" 353 ")).expect("353");
    assert!(
        names.contains("@alice") && !names.contains("!alice@"),
        "{names}"
    );
}

#[test]
fn extended_join_variant() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "extended-join");
    let bob = s.register(2, "bob");
    s.line(alice, "JOIN #ej");
    s.drain(alice);
    s.line(bob, "JOIN #ej");
    s.drain(bob);
    // alice (with cap): JOIN carries account (* = logged out) + realname
    assert_eq!(
        s.drain(alice),
        vec![":bob!bob@host2.example JOIN #ej * :Real bob"]
    );
}

#[test]
fn away_notify_broadcasts_to_peers() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "away-notify");
    let bob = s.register(2, "bob");
    for c in [alice, bob] {
        s.line(c, "JOIN #an");
        s.drain(c);
    }
    s.drain(alice);
    s.line(bob, "AWAY :brb");
    s.drain(bob);
    assert_eq!(s.drain(alice), vec![":bob!bob@host2.example AWAY :brb"]);
    s.line(bob, "AWAY");
    s.drain(bob);
    assert_eq!(s.drain(alice), vec![":bob!bob@host2.example AWAY"]);
}

/// Re-declaring an identical away state is a no-op and must not re-broadcast:
/// away-notify announces *transitions*, and an unconditional fan-out hands
/// every client an unmetered spam vector aimed at its channel peers (the same
/// "no phantom transitions" rule MODE no-op suppression enforces). The numeric
/// to self stays unconditional; a *changed* message while already away is a
/// real transition and still broadcasts.
#[test]
fn away_noop_is_not_rebroadcast() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "away-notify");
    let bob = s.register(2, "bob");
    for c in [alice, bob] {
        s.line(c, "JOIN #an");
        s.drain(c);
    }
    s.drain(alice);
    s.line(bob, "AWAY :brb");
    assert!(has_numeric(&s.drain(bob), "306"));
    s.drain(alice);
    // Identical away again: self numeric yes, peer broadcast no.
    s.line(bob, "AWAY :brb");
    assert!(has_numeric(&s.drain(bob), "306"));
    assert_eq!(s.drain(alice), Vec::<String>::new());
    // A changed message is a real transition.
    s.line(bob, "AWAY :lunch");
    s.drain(bob);
    assert_eq!(s.drain(alice), vec![":bob!bob@host2.example AWAY :lunch"]);
    // Unset once: broadcast; unset again: no phantom AWAY.
    s.line(bob, "AWAY");
    s.drain(bob);
    assert_eq!(s.drain(alice), vec![":bob!bob@host2.example AWAY"]);
    s.line(bob, "AWAY");
    assert!(has_numeric(&s.drain(bob), "305"));
    assert_eq!(s.drain(alice), Vec::<String>::new());
}

#[test]
fn account_notify_and_tag() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "account-notify account-tag");
    let bob = s.register(2, "bob");
    for c in [alice, bob] {
        s.line(c, "JOIN #acct");
        s.drain(c);
    }
    s.drain(alice);
    // bob identifies → alice (account-notify) sees ACCOUNT
    s.line(bob, "PRIVMSG NickServ :IDENTIFY pw");
    s.db_requests();
    s.core.handle(Input::DbReply {
        conn: bob,
        reply: e6ircd::core::DbReply::PasswordVerified {
            account: "bob".into(),
            origin: e6ircd::core::CredentialOrigin::NickServIdentify,
        },
    });
    s.drain(bob);
    assert_eq!(s.drain(alice), vec![":bob!bob@host2.example ACCOUNT bob"]);
    // bob's messages now carry account-tag for alice
    s.line(bob, "PRIVMSG #acct :tagged?");
    assert_eq!(
        s.drain(alice),
        vec!["@account=bob :bob!bob@host2.example PRIVMSG #acct :tagged?"]
    );
}

/// Post-registration SASL (cap-notify permits `CAP REQ :sasl` mid-session)
/// must broadcast ACCOUNT to account-notify peers exactly like the NickServ
/// IDENTIFY path — the two are the same state change through different doors,
/// and only the IDENTIFY door used to announce it.
#[test]
fn account_notify_fires_on_post_registration_sasl() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "account-notify");
    let bob = s.register(2, "bob");
    for c in [alice, bob] {
        s.line(c, "JOIN #acct2");
        s.drain(c);
    }
    s.drain(alice);
    // bob authenticates mid-session via SASL.
    s.line(bob, "CAP REQ :sasl");
    s.line(bob, "AUTHENTICATE PLAIN");
    s.line(bob, &format!("AUTHENTICATE {}", b64("\0bob\0hunter2")));
    s.drain(bob);
    s.db_requests();
    s.core.handle(Input::DbReply {
        conn: bob,
        reply: e6ircd::core::DbReply::PasswordVerified {
            account: "bob".into(),
            origin: e6ircd::core::CredentialOrigin::Sasl,
        },
    });
    s.drain(bob);
    assert_eq!(
        s.drain(alice),
        vec![":bob!bob@host2.example ACCOUNT bob"],
        "SASL login must notify account-notify peers like IDENTIFY does"
    );
}

#[test]
fn setname_flow() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "setname");
    let bob = register_with_caps(&mut s, 2, "bob", "setname");
    let carol = s.register(3, "carol");
    for c in [alice, bob, carol] {
        s.line(c, "JOIN #sn");
        s.drain(c);
    }
    s.drain(alice);
    s.drain(bob);
    s.line(bob, "SETNAME :Bob Prime");
    let expect = ":bob!bob@host2.example SETNAME :Bob Prime";
    assert_eq!(s.drain(bob), vec![expect], "setname echoes to the setter");
    assert_eq!(s.drain(alice), vec![expect]);
    assert!(s.drain(carol).is_empty(), "no cap, no SETNAME event");
    // realname actually changed
    s.line(carol, "WHOIS bob");
    let out = s.drain(carol);
    assert!(out.iter().any(|l| l.contains("Bob Prime")), "{out:#?}");
}

#[test]
fn invite_notify_to_ops() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "invite-notify");
    let bob = s.register(2, "bob");
    let carol = s.register(3, "carol");
    s.line(alice, "JOIN #in");
    s.drain(alice);
    s.line(bob, "JOIN #in");
    s.drain(bob);
    s.drain(alice);
    // bob (non-op, but +i off so members may invite) invites carol
    s.line(bob, "INVITE carol #in");
    s.drain(bob);
    s.drain(carol);
    assert_eq!(
        s.drain(alice),
        vec![":bob!bob@host2.example INVITE carol :#in"]
    );
}

#[test]
fn msgid_tag_on_live_delivery() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "message-tags echo-message");
    let bob = s.register(2, "bob");
    for c in [alice, bob] {
        s.line(c, "JOIN #ids");
        s.drain(c);
    }
    s.drain(alice);
    s.line(bob, "PRIVMSG #ids :with id");
    let got = s.drain(alice);
    assert_eq!(got.len(), 1);
    assert!(got[0].starts_with("@msgid="), "{got:#?}");
    // sender's echo carries the SAME msgid as the fan-out copy
    s.line(alice, "PRIVMSG #ids :mine");
    let echo = s.drain(alice);
    let echo_id = echo[0]
        .split('=')
        .nth(1)
        .unwrap()
        .split(' ')
        .next()
        .unwrap()
        .to_string();
    assert!(!echo_id.is_empty());
    // bob (no message-tags) sees no tags at all
    let bob_got = s.drain(bob);
    assert!(bob_got.iter().all(|l| !l.starts_with('@')), "{bob_got:#?}");
}

// ---- CHATHISTORY (hot ring) ---------------------------------------------

/// A draft/multiline message is stored as the one message it was, so CHATHISTORY
/// replays it under its original msgid — reconstructed as a nested batch for a
/// capable requester and flattened for one without the capability, mirroring
/// live delivery. Before the fix, replay minted a fresh msgid per line, so a
/// msgid-deduplicating client saw each line as a brand-new message.
#[test]
fn chathistory_replays_a_multiline_message_as_one_message() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "batch draft/multiline message-tags");
    let capable = register_with_caps(
        &mut s,
        2,
        "capable",
        "batch draft/multiline draft/chathistory server-time message-tags",
    );
    // Same as `capable` minus draft/multiline: it still gets the CHATHISTORY
    // batch (needs `batch`), but the message flattens to one line per line.
    let flat = register_with_caps(
        &mut s,
        3,
        "flat",
        "batch draft/chathistory server-time message-tags",
    );
    for c in [alice, capable, flat] {
        s.line(c, "JOIN #m");
    }
    for c in [alice, capable, flat] {
        s.drain(c);
    }
    s.line(alice, "BATCH +7 draft/multiline #m");
    s.line(alice, "@batch=7 PRIVMSG #m :hello");
    s.line(alice, "@batch=7 PRIVMSG #m :");
    s.line(alice, "@batch=7;draft/multiline-concat PRIVMSG #m :world");
    s.line(alice, "BATCH -7");
    s.drain(capable);
    s.drain(flat);

    // Capable requester: a nested draft/multiline batch, blank line kept, concat
    // preserved, and the msgid on the inner batch open only — exactly once.
    // `* 1` keeps the request inside the ring (the one message it holds) rather
    // than deferring to the DB, which the non-persistent test path never answers.
    s.line(capable, "CHATHISTORY LATEST #m * 1");
    let out = s.drain(capable);
    assert!(
        out[0].contains("BATCH +") && out[0].contains("chathistory #m"),
        "{out:#?}"
    );
    assert!(out.last().unwrap().contains("BATCH -"), "{out:#?}");
    let open = out
        .iter()
        .find(|l| l.contains("BATCH +") && l.contains("draft/multiline #m"))
        .unwrap_or_else(|| panic!("nested multiline batch open missing: {out:#?}"));
    let inner_ref = open
        .split(" BATCH +")
        .nth(1)
        .and_then(|r| r.split(' ').next())
        .expect("inner ref")
        .to_string();
    let content: Vec<_> = out
        .iter()
        .filter(|l| l.contains(&format!("batch={inner_ref}")) && l.contains("PRIVMSG"))
        .collect();
    assert_eq!(content.len(), 3, "blank line kept in the batch: {out:#?}");
    assert!(
        content[2].contains("draft/multiline-concat"),
        "{}",
        content[2]
    );
    for l in &content {
        assert!(!l.contains("msgid="), "content lines carry no msgid: {l}");
    }
    let cap_msgid = open
        .trim_start_matches('@')
        .split(' ')
        .next()
        .expect("tags")
        .split(';')
        .find_map(|t| t.strip_prefix("msgid="))
        .expect("msgid on the inner batch open")
        .to_string();
    assert_eq!(
        out.iter().filter(|l| l.contains("msgid=")).count(),
        1,
        "the message has exactly one msgid: {out:#?}"
    );

    // Flatten requester: no draft/multiline batch, blank line dropped, msgid on
    // the first line only — and it is the SAME msgid the capable form carried.
    s.line(flat, "CHATHISTORY LATEST #m * 1");
    let out = s.drain(flat);
    let lines: Vec<_> = out.iter().filter(|l| l.contains("PRIVMSG #m")).collect();
    assert_eq!(
        lines.len(),
        2,
        "blank line dropped when flattened: {out:#?}"
    );
    assert!(lines[0].ends_with(":hello"), "{}", lines[0]);
    assert!(lines[1].ends_with(":world"), "{}", lines[1]);
    assert!(
        !out.iter().any(|l| l.contains("draft/multiline")),
        "{out:#?}"
    );
    assert!(
        lines[0].contains(&format!("msgid={cap_msgid}")),
        "same message: {}",
        lines[0]
    );
    assert!(!lines[1].contains("msgid="), "{}", lines[1]);
}

#[test]
fn chathistory_latest_replays_from_ring() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = register_with_caps(
        &mut s,
        2,
        "bob",
        "batch draft/chathistory server-time message-tags",
    );
    for c in [alice, bob] {
        s.line(c, "JOIN #hist");
        s.drain(c);
    }
    s.drain(alice);
    for i in 1..=5 {
        s.line(alice, &format!("PRIVMSG #hist :msg {i}"));
    }
    s.drain(bob);

    s.line(bob, "CHATHISTORY LATEST #hist * 3");
    let out = s.drain(bob);
    // batch framing: +ref chathistory #hist ... -ref
    assert!(out[0].contains("BATCH +"), "{out:#?}");
    assert!(out[0].contains("chathistory #hist"), "{out:#?}");
    assert!(out.last().unwrap().contains("BATCH -"), "{out:#?}");
    let inner: Vec<_> = out[1..out.len() - 1].to_vec();
    assert_eq!(inner.len(), 3, "{out:#?}");
    // newest three, in order, with batch/msgid/time tags and PRIVMSG shape
    for (i, line) in inner.iter().enumerate() {
        assert!(line.contains("batch="), "{line}");
        assert!(line.contains("msgid="), "{line}");
        assert!(line.contains("time="), "{line}");
        assert!(
            line.ends_with(&format!("PRIVMSG #hist :msg {}", i + 3)),
            "{line}"
        );
    }
}

/// account-tag: a replayed message from an identified sender must carry
/// `account=` for a requester that negotiated account-tag, exactly as live
/// delivery does — otherwise the replay loses the sender attribution the live
/// line carried, breaking the byte-identical-to-live invariant.
#[test]
fn chathistory_replay_carries_the_account_tag() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    identify(&mut s, alice, "alice");
    let bob = register_with_caps(
        &mut s,
        2,
        "bob",
        "batch draft/chathistory server-time message-tags account-tag",
    );
    for c in [alice, bob] {
        s.line(c, "JOIN #hist");
        s.drain(c);
    }
    s.drain(alice);
    for i in 1..=5 {
        s.line(alice, &format!("PRIVMSG #hist :msg {i}"));
    }
    s.drain(bob);

    s.line(bob, "CHATHISTORY LATEST #hist * 3");
    let out = s.drain(bob);
    let row = out
        .iter()
        .find(|l| l.contains("PRIVMSG #hist :msg 5"))
        .unwrap_or_else(|| panic!("replayed message missing: {out:#?}"));
    assert!(
        row.contains("account=alice"),
        "replayed line must carry the sender's account: {row}"
    );
}

/// A replayed message from a bot (+B) must carry the `bot` tag for a
/// message-tags requester, exactly as live delivery does.
#[test]
fn chathistory_replay_carries_the_bot_tag() {
    let mut s = TestServer::new();
    let botc = register_with_caps(&mut s, 1, "botnick", "message-tags");
    s.line(botc, "MODE botnick +B");
    s.drain(botc);
    let bob = register_with_caps(
        &mut s,
        2,
        "bob",
        "batch draft/chathistory server-time message-tags",
    );
    for c in [botc, bob] {
        s.line(c, "JOIN #hist");
        s.drain(c);
    }
    s.drain(botc);
    for i in 1..=5 {
        s.line(botc, &format!("PRIVMSG #hist :beep {i}"));
    }
    s.drain(bob);

    s.line(bob, "CHATHISTORY LATEST #hist * 3");
    let out = s.drain(bob);
    let row = out
        .iter()
        .find(|l| l.contains("PRIVMSG #hist :beep 5"))
        .unwrap_or_else(|| panic!("replayed message missing: {out:#?}"));
    assert!(
        row.contains(";bot") || row.contains("@bot"),
        "replayed line from a bot must carry the bot tag: {row}"
    );
}

/// A DM row is re-addressed on replay by the sender's stable *identity*, not by
/// their historical nick — so a requester who renames mid-conversation still
/// sees their own sent lines addressed to the correspondent, not to themselves.
#[test]
fn chathistory_dm_replay_survives_a_requester_rename() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "batch draft/chathistory");
    identify(&mut s, alice, "alice");
    let bob = s.register(2, "bob");
    identify(&mut s, bob, "bob");
    s.drain(alice);
    s.drain(bob);
    // alice DMs bob; the row is recorded with sender_account = alice.
    s.line(alice, "PRIVMSG bob :hello bob");
    s.drain(alice);
    s.drain(bob);
    // alice renames — her identity (account) is unchanged.
    s.line(alice, "NICK alice2");
    s.drain(alice);
    // Reading the conversation with bob, her own line must still be addressed to
    // bob (not re-addressed to alice2 as a self-message). Limit 1 == the ring's
    // single entry, so the read is served synchronously from the ring.
    s.line(alice, "CHATHISTORY LATEST bob * 1");
    let out = s.drain(alice);
    let replayed: Vec<&String> = out.iter().filter(|l| l.contains("PRIVMSG")).collect();
    assert!(!replayed.is_empty(), "no replayed DM: {out:#?}");
    assert!(
        replayed.iter().all(|l| l.contains("PRIVMSG bob :")),
        "the requester's own line must replay addressed to bob: {replayed:#?}"
    );
    assert!(
        !replayed.iter().any(|l| l.contains("PRIVMSG alice2 :")),
        "must not re-address the requester's own line to their new nick: {replayed:#?}"
    );
}

#[test]
fn chathistory_requires_caps_and_membership() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "JOIN #h2");
    s.drain(alice);
    // no batch/chathistory caps → FAIL
    s.line(alice, "CHATHISTORY LATEST #h2 * 10");
    let out = s.drain(alice);
    assert!(out[0].contains("FAIL CHATHISTORY"), "{out:#?}");

    // capable but not a member → FAIL (history is member-only)
    let carol = register_with_caps(&mut s, 3, "carol", "batch draft/chathistory");
    s.line(carol, "CHATHISTORY LATEST #h2 * 10");
    let out = s.drain(carol);
    assert!(out[0].contains("FAIL CHATHISTORY"), "{out:#?}");
}

#[test]
fn chathistory_before_msgid() {
    let mut s = TestServer::new_no_persistence();
    let alice = s.register(1, "alice");
    let bob = register_with_caps(&mut s, 2, "bob", "batch draft/chathistory message-tags");
    for c in [alice, bob] {
        s.line(c, "JOIN #hb");
        s.drain(c);
    }
    s.drain(alice);
    for i in 1..=4 {
        s.line(alice, &format!("PRIVMSG #hb :m{i}"));
    }
    // capture msgid of m3 from bob's live delivery
    let live = s.drain(bob);
    let m3 = live.iter().find(|l| l.ends_with(":m3")).expect("m3");
    let msgid = m3
        .trim_start_matches('@')
        .split([';', ' '])
        .find_map(|t| t.strip_prefix("msgid="))
        .expect("msgid tag")
        .to_string();

    s.line(bob, &format!("CHATHISTORY BEFORE #hb msgid={msgid} 2"));
    let out = s.drain(bob);
    let inner: Vec<_> = out[1..out.len() - 1].to_vec();
    assert_eq!(inner.len(), 2, "{out:#?}");
    assert!(inner[0].ends_with(":m1"), "{inner:#?}");
    assert!(inner[1].ends_with(":m2"), "{inner:#?}");
}

#[test]
fn chathistory_star_selector_is_rejected_except_for_latest() {
    // `*` is the open bound, valid only for LATEST. For BEFORE/AFTER/AROUND and
    // both BETWEEN bounds it must be a hard INVALID_PARAMS, not a silent empty
    // batch (one-selector forms) or an unbounded full scan (BETWEEN).
    let mut s = TestServer::new_no_persistence();
    let alice = s.register(1, "alice");
    let bob = register_with_caps(&mut s, 2, "bob", "batch draft/chathistory message-tags");
    for c in [alice, bob] {
        s.line(c, "JOIN #hs");
        s.drain(c);
    }
    for sub in ["BEFORE", "AFTER", "AROUND"] {
        s.line(bob, &format!("CHATHISTORY {sub} #hs * 5"));
        let out = s.drain(bob);
        assert!(
            out.iter()
                .any(|l| l.contains("FAIL CHATHISTORY INVALID_PARAMS")),
            "{sub} with a `*` selector must FAIL INVALID_PARAMS: {out:#?}"
        );
    }
    // BETWEEN with `*` bounds would otherwise degenerate to a full scan.
    s.line(bob, "CHATHISTORY BETWEEN #hs * * 5");
    let out = s.drain(bob);
    assert!(
        out.iter()
            .any(|l| l.contains("FAIL CHATHISTORY INVALID_PARAMS")),
        "BETWEEN with `*` bounds must FAIL INVALID_PARAMS: {out:#?}"
    );
    // LATEST with `*` remains valid (a plain empty-or-populated batch, no FAIL).
    s.line(bob, "CHATHISTORY LATEST #hs * 5");
    let out = s.drain(bob);
    assert!(
        !out.iter().any(|l| l.contains("FAIL")),
        "LATEST with `*` must still be accepted: {out:#?}"
    );
}

#[test]
fn chathistory_malformed_reference_values_are_rejected() {
    // A `timestamp=` selector that doesn't parse must FAIL INVALID_PARAMS, not
    // silently default the window bound (which would return the latest N or an
    // empty window as if the client had asked for them).
    let mut s = TestServer::new_no_persistence();
    let alice = s.register(1, "alice");
    let bob = register_with_caps(&mut s, 2, "bob", "batch draft/chathistory message-tags");
    for c in [alice, bob] {
        s.line(c, "JOIN #ht");
        s.drain(c);
    }
    s.line(bob, "CHATHISTORY LATEST #ht timestamp=not-a-time 5");
    let out = s.drain(bob);
    assert!(
        out.iter()
            .any(|l| l.contains("FAIL CHATHISTORY INVALID_PARAMS")),
        "a malformed timestamp= must FAIL INVALID_PARAMS: {out:#?}"
    );
    for selector in ["msgid=", "msgid=:invalid"] {
        s.line(bob, &format!("CHATHISTORY LATEST #ht {selector} 5"));
        let out = s.drain(bob);
        assert!(
            out.iter()
                .any(|line| line.contains("FAIL CHATHISTORY INVALID_PARAMS")),
            "a malformed {selector} must FAIL INVALID_PARAMS: {out:#?}"
        );
    }
    // A well-formed timestamp is still accepted (no FAIL).
    s.line(
        bob,
        "CHATHISTORY LATEST #ht timestamp=2020-01-01T00:00:00.000Z 5",
    );
    let out = s.drain(bob);
    assert!(
        !out.iter().any(|l| l.contains("FAIL")),
        "a valid timestamp= must be accepted: {out:#?}"
    );
}

// ---- MONITOR ------------------------------------------------------------

#[test]
fn monitor_add_notify_and_remove() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    // watching an offline nick answers 731
    s.line(alice, "MONITOR + bob");
    let out = s.drain(alice);
    assert!(has_numeric(&out, "731"), "{out:#?}");

    // bob comes online → 730 to alice
    let bob = s.register(2, "bob");
    let out = s.drain(alice);
    assert!(has_numeric(&out, "730"), "{out:#?}");
    assert!(out[0].contains("bob!"), "{out:#?}");

    // bob quits → 731
    s.line(bob, "QUIT :bye");
    s.drain(bob);
    let out = s.drain(alice);
    assert!(has_numeric(&out, "731"), "{out:#?}");

    // remove: no further notifications
    s.line(alice, "MONITOR - bob");
    s.drain(alice);
    s.register(3, "bob");
    assert!(s.drain(alice).is_empty());
}

#[test]
fn monitor_list_status_clear_and_limit() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.register(2, "carol");
    s.line(alice, "MONITOR + carol,dave");
    let out = s.drain(alice);
    assert!(has_numeric(&out, "730"), "carol online: {out:#?}");
    assert!(has_numeric(&out, "731"), "dave offline: {out:#?}");

    s.line(alice, "MONITOR L");
    let out = s.drain(alice);
    assert!(
        has_numeric(&out, "732") && has_numeric(&out, "733"),
        "{out:#?}"
    );
    let list = out.iter().find(|l| l.contains(" 732 ")).expect("732");
    assert!(list.contains("carol") && list.contains("dave"), "{list}");

    s.line(alice, "MONITOR S");
    let out = s.drain(alice);
    assert!(
        has_numeric(&out, "730") && has_numeric(&out, "731"),
        "{out:#?}"
    );

    s.line(alice, "MONITOR C");
    s.drain(alice);
    s.line(alice, "MONITOR L");
    let out = s.drain(alice);
    let list = out.iter().find(|l| l.contains(" 732 "));
    assert!(
        list.is_none() || list.unwrap().ends_with(':'),
        "cleared: {out:#?}"
    );

    // limit: the 101st target is rejected with 734
    let targets: Vec<String> = (0..100).map(|i| format!("n{i}")).collect();
    for chunk in targets.chunks(20) {
        s.line(alice, &format!("MONITOR + {}", chunk.join(",")));
        s.drain(alice);
    }
    s.line(alice, "MONITOR + overflow");
    let out = s.drain(alice);
    assert!(has_numeric(&out, "734"), "{out:#?}");
}

#[test]
fn monitor_nick_change_notifies_both_ways() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    s.line(alice, "MONITOR + bob,robert");
    s.drain(alice);
    s.line(bob, "NICK robert");
    s.drain(bob);
    let out = s.drain(alice);
    assert!(has_numeric(&out, "731"), "old nick offline: {out:#?}");
    assert!(has_numeric(&out, "730"), "new nick online: {out:#?}");
}

// ---- extended-monitor ---------------------------------------------------

/// extended-monitor watchers see a monitored nick's AWAY even without a
/// shared channel, gated on the watcher holding away-notify too.
#[test]
fn extended_monitor_forwards_away() {
    let mut s = TestServer::new();
    let watcher = register_with_caps(&mut s, 1, "alice", "extended-monitor away-notify");
    let bob = s.register(2, "bob");
    s.line(watcher, "MONITOR + bob");
    s.drain(watcher);
    s.line(bob, "AWAY :afk");
    s.drain(bob);
    assert_eq!(s.drain(watcher), vec![":bob!bob@host2.example AWAY :afk"]);
    s.line(bob, "AWAY");
    s.drain(bob);
    assert_eq!(s.drain(watcher), vec![":bob!bob@host2.example AWAY"]);
}

/// Without the event's own cap the watcher gets nothing; without
/// extended-monitor the MONITOR subscription alone forwards nothing.
#[test]
fn extended_monitor_requires_both_caps() {
    let mut s = TestServer::new();
    let no_event_cap = register_with_caps(&mut s, 1, "alice", "extended-monitor");
    let no_monitor_cap = register_with_caps(&mut s, 2, "carol", "away-notify");
    let bob = s.register(3, "bob");
    for w in [no_event_cap, no_monitor_cap] {
        s.line(w, "MONITOR + bob");
        s.drain(w);
    }
    s.line(bob, "AWAY :afk");
    s.drain(bob);
    assert_eq!(s.drain(no_event_cap), Vec::<String>::new());
    assert_eq!(s.drain(no_monitor_cap), Vec::<String>::new());
}

/// A watcher who also shares a channel with the subject receives the AWAY
/// once — the channel fan-out and the monitor fan-out must not duplicate.
#[test]
fn extended_monitor_does_not_duplicate_channel_peers() {
    let mut s = TestServer::new();
    let watcher = register_with_caps(&mut s, 1, "alice", "extended-monitor away-notify");
    let bob = s.register(2, "bob");
    for c in [watcher, bob] {
        s.line(c, "JOIN #em");
        s.drain(c);
    }
    s.drain(watcher);
    s.line(watcher, "MONITOR + bob");
    s.drain(watcher);
    s.line(bob, "AWAY :afk");
    s.drain(bob);
    assert_eq!(s.drain(watcher), vec![":bob!bob@host2.example AWAY :afk"]);
}

/// SETNAME reaches extended-monitor watchers holding setname; ACCOUNT
/// reaches those holding account-notify.
#[test]
fn extended_monitor_forwards_setname_and_account() {
    let mut s = TestServer::new();
    let watcher = register_with_caps(
        &mut s,
        1,
        "alice",
        "extended-monitor setname account-notify",
    );
    let bob = register_with_caps(&mut s, 2, "bob", "setname");
    s.line(watcher, "MONITOR + bob");
    s.drain(watcher);
    s.line(bob, "SETNAME :Robert Example");
    s.drain(bob);
    assert_eq!(
        s.drain(watcher),
        vec![":bob!bob@host2.example SETNAME :Robert Example"]
    );
    identify(&mut s, bob, "bob");
    assert_eq!(s.drain(watcher), vec![":bob!bob@host2.example ACCOUNT bob"]);
}

// ---- INVITE account-tag ---------------------------------------------------

/// The account-tag contract covers INVITE: an identified inviter's INVITE
/// carries their account to recipients holding the cap (irctest's
/// AccountTagTestCase::testInvite asserts exactly this).
#[test]
fn invite_carries_account_tag() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "account-tag");
    let bob = s.register(2, "bob");
    s.line(bob, "JOIN #inv");
    s.drain(bob);
    identify(&mut s, bob, "bob");
    s.line(bob, "INVITE alice #inv");
    assert!(has_numeric(&s.drain(bob), "341"), "RPL_INVITING");
    assert_eq!(
        s.drain(alice),
        vec!["@account=bob :bob!bob@host2.example INVITE alice :#inv"]
    );
}

// ---- HELP / HELPOP --------------------------------------------------------

#[test]
fn help_index_topic_and_unknown_subject() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    // No argument: a 704/705/706 envelope whose body lists commands.
    s.line(alice, "HELP");
    let out = s.drain(alice);
    assert!(has_numeric(&out, "704"), "HELPSTART: {out:#?}");
    assert!(has_numeric(&out, "705"), "HELPTXT: {out:#?}");
    assert!(has_numeric(&out, "706"), "ENDOFHELP: {out:#?}");
    let index = out.iter().find(|l| l.contains(" 705 ")).expect("705");
    assert!(index.contains("PRIVMSG"), "index lists commands: {index}");
    assert!(
        !index.contains("KILL"),
        "HELP hides oper-only topics: {index}"
    );

    // A known subject, case-insensitively.
    s.line(alice, "HELP privmsg");
    let out = s.drain(alice);
    assert!(
        has_numeric(&out, "704") && has_numeric(&out, "706"),
        "{out:#?}"
    );
    assert!(
        out.iter().any(|l| l.contains("PRIVMSG <target>")),
        "topic body: {out:#?}"
    );

    // An unknown subject is a loud 524, never a silent no-op.
    s.line(alice, "HELP THISISNOTACOMMAND");
    let out = s.drain(alice);
    assert!(has_numeric(&out, "524"), "ERR_HELPNOTFOUND: {out:#?}");

    // HELPOP includes the oper-only topics in its index.
    s.line(alice, "HELPOP");
    let out = s.drain(alice);
    let index = out.iter().find(|l| l.contains(" 705 ")).expect("705");
    assert!(index.contains("KILL"), "HELPOP lists oper topics: {index}");
}

// ---- read-marker (MARKREAD) ---------------------------------------------

#[test]
fn markread_set_query_and_broadcast() {
    let mut s = TestServer::new();
    // two connections, same account (simulating multi-device)
    let a1 = register_with_caps(&mut s, 1, "alice", "draft/read-marker");
    identify(&mut s, a1, "alice");
    let a2 = register_with_caps(&mut s, 2, "alice2", "draft/read-marker");
    identify(&mut s, a2, "alice");

    // query before any marker → * (unset)
    s.line(a1, "MARKREAD #room");
    assert_eq!(s.drain(a1), vec![":irc.test.example MARKREAD #room *"]);

    // A marker is not visible or acknowledged until PostgreSQL confirms it.
    s.line(a1, "MARKREAD #room timestamp=2026-07-18T12:00:00.000Z");
    assert!(s.drain(a1).is_empty(), "no optimistic acknowledgement");
    assert!(s.drain(a2).is_empty(), "no optimistic sibling sync");
    s.line(a2, "MARKREAD #room");
    assert_eq!(
        s.drain(a2),
        vec![":irc.test.example MARKREAD #room *"],
        "an in-flight write is not part of the durable hot mirror"
    );
    confirm_read_marker(&mut s);
    assert_eq!(
        s.drain(a1),
        vec![":irc.test.example MARKREAD #room timestamp=2026-07-18T12:00:00.000Z"]
    );
    assert_eq!(
        s.drain(a2),
        vec![":irc.test.example MARKREAD #room timestamp=2026-07-18T12:00:00.000Z"]
    );

    // older timestamp is ignored (marker only moves forward)
    s.line(a1, "MARKREAD #room timestamp=2020-01-01T00:00:00.000Z");
    assert_eq!(
        s.drain(a1),
        vec![":irc.test.example MARKREAD #room timestamp=2026-07-18T12:00:00.000Z"]
    );

    // query now returns the stored marker
    s.line(a2, "MARKREAD #room");
    assert_eq!(
        s.drain(a2),
        vec![":irc.test.example MARKREAD #room timestamp=2026-07-18T12:00:00.000Z"]
    );
}

/// The sibling MARKREAD sync only reaches connections that negotiated
/// `draft/read-marker`. A logged-in device on an older client must not receive
/// an unsolicited MARKREAD line it never opted into.
#[test]
fn markread_sync_skips_siblings_without_the_cap() {
    let mut s = TestServer::new();
    let a1 = register_with_caps(&mut s, 1, "alice", "draft/read-marker");
    identify(&mut s, a1, "alice");
    // A second device on the same account that did NOT negotiate read-marker.
    let a2 = register_with_caps(&mut s, 2, "alice2", "server-time");
    identify(&mut s, a2, "alice");
    s.drain(a1);
    s.drain(a2);
    // a1 advances a marker; only a1 (capable) is notified.
    s.line(a1, "MARKREAD #room timestamp=2026-07-18T12:00:00.000Z");
    assert!(s.drain(a1).is_empty(), "the write is not yet confirmed");
    confirm_read_marker(&mut s);
    assert_eq!(
        s.drain(a1),
        vec![":irc.test.example MARKREAD #room timestamp=2026-07-18T12:00:00.000Z"],
        "the capable setter gets its confirmation"
    );
    assert!(
        s.drain(a2).is_empty(),
        "a sibling without draft/read-marker must not receive the sync"
    );
}

#[test]
fn markread_first_set_to_epoch_zero_is_persisted() {
    // The Unix epoch (1970-01-01T00:00:00.000Z → Millis(0)) is a legitimate
    // marker value. A first-ever set to it must still persist and echo, not be
    // swallowed as a no-op against a zero "unset" sentinel — which would leave
    // the in-core mirror holding a marker the DB never received.
    let mut s = TestServer::new();
    let a1 = register_with_caps(&mut s, 1, "alice", "draft/read-marker");
    identify(&mut s, a1, "alice");
    let _ = s.db_requests(); // drop the IDENTIFY's VerifyPassword
    s.line(a1, "MARKREAD #room timestamp=1970-01-01T00:00:00.000Z");
    assert!(
        s.drain(a1).is_empty(),
        "epoch zero must wait for persistence too"
    );
    let request = confirm_read_marker(&mut s);
    assert_eq!(request.target, "#room");
    assert_eq!(request.marker_ms.as_millis(), 0);
    assert_eq!(
        s.drain(a1),
        vec![":irc.test.example MARKREAD #room timestamp=1970-01-01T00:00:00.000Z"]
    );
}

#[test]
fn markread_requires_cap_and_works_anonymously() {
    let mut s = TestServer::new();
    // No cap → unknown command.
    let plain = s.register(1, "bob");
    s.line(plain, "MARKREAD #x");
    assert!(has_numeric(&s.drain(plain), "421"));
    // Cap but not logged in → works per-connection (session-local); an unset
    // marker queries as '*'.
    let capped = register_with_caps(&mut s, 2, "carol", "draft/read-marker");
    s.line(capped, "MARKREAD #x");
    assert!(
        s.drain(capped)[0].contains("MARKREAD #x *"),
        "anonymous query returns *"
    );
    // Set then get, preserving millisecond precision.
    s.line(capped, "MARKREAD #x timestamp=2026-07-18T12:00:00.500Z");
    s.drain(capped);
    s.line(capped, "MARKREAD #x");
    assert!(
        s.drain(capped)[0].contains("timestamp=2026-07-18T12:00:00.500Z"),
        "millisecond precision must round-trip"
    );
    // Malformed timestamp → FAIL.
    s.line(capped, "MARKREAD #x timestamp=not-a-time");
    assert!(s.drain(capped)[0].contains("FAIL MARKREAD"));
}

#[test]
fn markread_query_rejects_and_bounds_invalid_targets() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "draft/read-marker");
    // Query and set forms accept the same target language. This token fits in
    // the client command body, but reflecting it whole alongside the server
    // prefix and FAIL detail would exceed the server-line limit.
    let target = "x".repeat(450);
    s.line(alice, &format!("MARKREAD {target}"));
    let out = s.drain(alice);
    assert_eq!(out.len(), 1, "{out:#?}");
    assert!(out[0].contains("FAIL MARKREAD INVALID_PARAMS"), "{out:#?}");
    assert!(
        out[0].len() <= e6irc_proto::message::MAX_LINE_LEN - 2,
        "the error echo exceeded the IRC content limit: {} bytes",
        out[0].len()
    );
    assert!(
        !out[0].contains(&target),
        "the unbounded target was reflected whole"
    );
}

#[test]
fn markread_store_failure_is_loud_labeled_and_non_mutating() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "draft/read-marker labeled-response");
    identify(&mut s, alice, "alice");

    s.line(
        alice,
        "@label=marker1 MARKREAD #room timestamp=2026-07-18T12:00:00.000Z",
    );
    s.line(alice, "PING :after-marker");
    assert!(
        s.drain(alice).is_empty(),
        "later output must wait behind the durable verdict"
    );
    let request = reject_read_marker(&mut s);
    assert_eq!(request.label.as_deref(), Some("marker1"));
    let out = s.drain(alice);
    assert!(
        out.iter().any(|line| {
            line.starts_with("@label=marker1 ")
                && line.contains("FAIL MARKREAD TEMPORARILY_UNAVAILABLE #room")
        }),
        "the database failure must be labeled and explicit: {out:#?}"
    );
    let fail = out
        .iter()
        .position(|line| line.contains("FAIL MARKREAD"))
        .expect("FAIL");
    let pong = out
        .iter()
        .position(|line| line.contains("PONG") && line.contains("after-marker"))
        .expect("held PONG released");
    assert!(fail < pong, "the deferred verdict was overtaken: {out:#?}");

    s.line(alice, "MARKREAD #room");
    assert_eq!(
        s.drain(alice),
        vec![":irc.test.example MARKREAD #room *"],
        "a failed write must not enter the durable hot mirror"
    );
}

#[test]
fn markread_query_behind_pending_update_never_replies_with_a_stale_value() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "draft/read-marker");
    identify(&mut s, alice, "alice");
    s.line(alice, "MARKREAD #room timestamp=2020-01-01T00:00:00.000Z");
    confirm_read_marker(&mut s);
    s.drain(alice);

    s.line(alice, "MARKREAD #room timestamp=2026-07-18T12:00:00.000Z");
    s.line(alice, "MARKREAD #room");
    assert!(
        s.drain(alice).is_empty(),
        "both replies remain ordered behind the pending write"
    );
    confirm_read_marker(&mut s);
    let out = s.drain(alice);
    assert_eq!(
        out[0],
        ":irc.test.example MARKREAD #room timestamp=2026-07-18T12:00:00.000Z"
    );
    assert!(
        out[1].contains(
            "FAIL MARKREAD TEMPORARILY_UNAVAILABLE #room :Read marker update in progress"
        ),
        "the later query must not emit the old 2020 marker after the 2026 commit: {out:#?}"
    );
}

#[test]
fn markread_noop_behind_pending_update_uses_the_committed_value() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "draft/read-marker");
    identify(&mut s, alice, "alice");
    s.line(alice, "MARKREAD #room timestamp=2020-01-01T00:00:00.000Z");
    confirm_read_marker(&mut s);
    s.drain(alice);

    s.line(alice, "MARKREAD #room timestamp=2026-07-18T12:00:00.000Z");
    let forward = take_read_marker_request(&mut s);
    s.line(alice, "MARKREAD #room timestamp=2010-01-01T00:00:00.000Z");
    let older = take_read_marker_request(&mut s);
    assert_eq!(
        older.marker_ms,
        e6irc_proto::time::parse_server_time_millis("2010-01-01T00:00:00.000Z")
            .expect("test timestamp")
    );

    confirm_read_marker_as(&mut s, &forward, forward.marker_ms);
    confirm_read_marker_as(&mut s, &older, forward.marker_ms);
    assert_eq!(
        s.drain(alice),
        vec![
            ":irc.test.example MARKREAD #room timestamp=2026-07-18T12:00:00.000Z",
            ":irc.test.example MARKREAD #room timestamp=2026-07-18T12:00:00.000Z",
        ],
        "the second reply must use PostgreSQL's monotonic committed value"
    );
}

#[test]
fn markread_full_db_queue_fails_without_leaking_a_deferred_hold() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "draft/read-marker");
    identify(&mut s, alice, "alice");
    s.line(alice, "JOIN #flood");
    s.drain(alice);
    s.db_requests();
    for i in 0..80 {
        s.line(alice, &format!("PRIVMSG #flood :m{i}"));
        s.drain(alice);
    }

    s.line(alice, "MARKREAD #room timestamp=2026-07-18T12:00:00.000Z");
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|line| line.contains("FAIL MARKREAD TEMPORARILY_UNAVAILABLE #room")),
        "a saturated persistence queue must fail synchronously: {out:#?}"
    );
    s.line(alice, "PING :still-live");
    assert!(
        s.drain(alice)
            .iter()
            .any(|line| line.contains("PONG") && line.contains("still-live")),
        "a failed enqueue must not leave a deferred-output hold"
    );
}

#[test]
fn markread_pending_target_counts_toward_the_account_cap() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "draft/read-marker");
    identify(&mut s, alice, "alice");
    s.core.preload_read_markers(
        (0..255)
            .map(|i| {
                (
                    "alice".to_string(),
                    format!("#room{i}"),
                    Millis::from_millis(i),
                )
            })
            .collect(),
    );

    s.line(
        alice,
        "MARKREAD #reserved timestamp=2026-07-18T12:00:00.000Z",
    );
    assert!(s.drain(alice).is_empty(), "the first write is pending");
    s.line(
        alice,
        "MARKREAD #overflow timestamp=2026-07-18T12:00:00.000Z",
    );
    assert!(
        s.drain(alice).is_empty(),
        "the cap failure remains ordered behind the first write's verdict"
    );
    confirm_read_marker(&mut s);
    assert!(
        s.drain(alice)
            .iter()
            .any(|line| line.contains("FAIL MARKREAD INVALID_PARAMS #overflow")),
        "an in-flight distinct target must reserve the final cap slot"
    );
}

#[test]
fn markread_commit_updates_siblings_after_requester_disconnects() {
    let mut s = TestServer::new();
    let a1 = register_with_caps(&mut s, 1, "alice", "draft/read-marker");
    identify(&mut s, a1, "alice");
    let a2 = register_with_caps(&mut s, 2, "alice2", "draft/read-marker");
    identify(&mut s, a2, "alice");

    s.line(a1, "MARKREAD #room timestamp=2026-07-18T12:00:00.000Z");
    let request = take_read_marker_request(&mut s);
    s.core.handle(Input::Closed {
        conn: a1,
        reason: "test disconnect".into(),
    });
    s.drain(a2);
    s.core.handle(Input::DbReply {
        conn: a1,
        reply: e6ircd::core::DbReply::ReadMarkerStored {
            account: request.account,
            target: request.target,
            display: request.display,
            marker_ms: request.marker_ms,
            label: request.label,
        },
    });
    assert_eq!(
        s.drain(a2),
        vec![":irc.test.example MARKREAD #room timestamp=2026-07-18T12:00:00.000Z"],
        "the committed global state must survive its requester's disconnect"
    );
    s.line(a2, "MARKREAD #room");
    assert_eq!(
        s.drain(a2),
        vec![":irc.test.example MARKREAD #room timestamp=2026-07-18T12:00:00.000Z"]
    );
}

#[test]
fn join_replays_read_marker_before_end_of_names() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "draft/read-marker");
    s.line(alice, "JOIN #c");
    let out = s.drain(alice);
    let mr = out
        .iter()
        .position(|l| l.contains("MARKREAD #c"))
        .expect("MARKREAD on join");
    let end = out
        .iter()
        .position(|l| l.contains(" 366 "))
        .expect("RPL_ENDOFNAMES");
    assert!(mr < end, "MARKREAD must precede 366: {out:#?}");
    assert!(out[mr].contains("MARKREAD #c *"), "no marker → *");

    // Set a marker, part, rejoin → the marker is replayed on the rejoin.
    s.line(alice, "MARKREAD #c timestamp=2026-07-18T12:00:00.000Z");
    s.line(alice, "PART #c");
    s.drain(alice);
    s.line(alice, "JOIN #c");
    assert!(
        s.drain(alice)
            .iter()
            .any(|l| l.contains("MARKREAD #c timestamp=2026-07-18T12:00:00.000Z")),
        "rejoin must replay the stored marker"
    );
}

#[test]
fn whois_accepts_target_server_argument() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.register(2, "bob");
    // WHOIS <server> <nick>: the nick is the last param
    s.line(alice, "WHOIS irc.test.example bob");
    let out = s.drain(alice);
    let w311 = out.iter().find(|l| l.contains(" 311 ")).expect("311");
    assert!(w311.contains("bob"), "{w311}");
    assert!(has_numeric(&out, "318"));
}

#[test]
fn whowas_after_quit_and_nick_change() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    // unknown nick → 406 + 369
    s.line(alice, "WHOWAS ghost");
    let out = s.drain(alice);
    assert!(
        has_numeric(&out, "406") && has_numeric(&out, "369"),
        "{out:#?}"
    );

    // bob changes nick → old nick recorded
    s.line(bob, "NICK robert");
    s.drain(bob);
    s.line(alice, "WHOWAS bob");
    let out = s.drain(alice);
    let w314 = out.iter().find(|l| l.contains(" 314 ")).expect("314");
    assert!(
        w314.contains("bob") && w314.contains("host2.example"),
        "{w314}"
    );
    // The RPL_WHOISSERVER (312) carries a last-seen time, not a placeholder.
    let w312 = out.iter().find(|l| l.contains(" 312 ")).expect("312");
    assert!(
        w312.contains("last seen") && !w312.contains("(unknown)"),
        "WHOWAS 312 must show the last-seen time: {w312}"
    );
    assert!(has_numeric(&out, "369"));

    // robert quits → also recorded; WHOWAS shows most recent first
    s.line(bob, "NICK bob");
    s.drain(bob);
    s.line(bob, "QUIT :gone");
    s.drain(bob);
    s.line(alice, "WHOWAS bob 1");
    let out = s.drain(alice);
    assert_eq!(
        out.iter().filter(|l| l.contains(" 314 ")).count(),
        1,
        "count limit: {out:#?}"
    );
}

#[test]
fn time_and_info_and_invalid_key() {
    let mut s = TestServer::new();
    let c = s.register(1, "alice");
    s.line(c, "TIME");
    let out = s.drain(c);
    let t = out.iter().find(|l| l.contains(" 391 ")).expect("391");
    // clock() = 1_000_000 → 1970-01-12T13:46:40.000Z
    assert!(t.contains("1970-01-12T13:46:40.000Z"), "{t}");

    s.line(c, "INFO");
    let out = s.drain(c);
    assert!(out.iter().any(|l| l.contains(" 371 ")) && has_numeric(&out, "374"));

    // +k with a space is rejected (525), channel stays keyless
    s.line(c, "JOIN #k");
    s.drain(c);
    s.line(c, "MODE #k +k :bad key");
    let out = s.drain(c);
    assert!(has_numeric(&out, "525"), "{out:#?}");
    let bob = s.register(2, "bob");
    s.line(bob, "JOIN #k");
    assert!(has_numeric(&s.drain(bob), "366"), "no key was set");
}

#[test]
fn oper_and_invisible_umodes() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    // wrong oper password → 464
    s.line(alice, "OPER god wrong");
    assert!(has_numeric(&s.drain(alice), "464"));
    // right → 381 + MODE +o
    s.line(alice, "OPER god letmein");
    let out = s.drain(alice);
    assert!(has_numeric(&out, "381"), "{out:#?}");
    assert!(out.iter().any(|l| l.contains("MODE alice :+o")), "{out:#?}");
    // WHOIS shows 313; WHO flag has *
    let bob = s.register(2, "bob");
    s.line(bob, "WHOIS alice");
    assert!(has_numeric(&s.drain(bob), "313"));

    // invisible: +i hides from wildcard WHO for a non-channel-sharer
    s.line(alice, "MODE alice +i");
    assert!(s.drain(alice).iter().any(|l| l.contains("MODE alice :+i")));
    s.line(bob, "WHO ali*");
    let out = s.drain(bob);
    assert!(
        !out.iter().any(|l| l.contains(" 352 ")),
        "invisible hidden: {out:#?}"
    );
    // exact WHO still shows
    s.line(bob, "WHO alice");
    assert!(s.drain(bob).iter().any(|l| l.contains(" 352 ")));
    // sharing a channel reveals in wildcard WHO
    s.line(alice, "JOIN #shared");
    s.drain(alice);
    s.line(bob, "JOIN #shared");
    s.drain(bob);
    s.line(bob, "WHO ali*");
    assert!(
        s.drain(bob).iter().any(|l| l.contains(" 352 ")),
        "shared channel reveals"
    );
}

#[test]
fn labeled_response_framing() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "labeled-response batch echo-message");
    let bob = s.register(2, "bob");
    for c in [alice, bob] {
        s.line(c, "JOIN #lr");
        s.drain(c);
    }
    s.drain(alice);

    // single-line response gets the label tag
    s.line(alice, "@label=abc PRIVMSG #lr :hi");
    let out = s.drain(alice);
    assert_eq!(out.len(), 1, "{out:#?}");
    assert!(out[0].starts_with("@label=abc"), "{out:#?}");
    assert!(out[0].contains("PRIVMSG #lr :hi"), "{out:#?}");
    // the recipient got an untagged (unlabeled) copy
    assert!(
        s.drain(bob)[0].starts_with(":alice!"),
        "recipient unlabeled"
    );

    // a MODE change broadcasts to the channel incl. the setter, captured
    // as a single labeled line
    s.line(alice, "@label=def MODE #lr +m");
    let out = s.drain(alice);
    assert_eq!(out.len(), 1, "{out:#?}");
    assert!(
        out[0].starts_with("@label=def") && out[0].contains("MODE #lr +m"),
        "{out:#?}"
    );

    // a command with no direct response → ACK
    s.line(alice, "@label=xyz PONG :token");
    let out = s.drain(alice);
    assert_eq!(out.len(), 1, "{out:#?}");
    assert!(
        out[0].contains("@label=xyz") && out[0].contains("ACK"),
        "{out:#?}"
    );
}

#[test]
fn unknown_command_parses_and_replies_421() {
    let mut s = TestServer::new();
    let c = s.register(1, "alice");
    s.line(c, "NONEXISTENT_COMMAND arg");
    let out = s.drain(c);
    assert!(has_numeric(&out, "421"), "{out:#?}");
    assert!(out[0].contains("NONEXISTENT_COMMAND"), "{out:#?}");
}

#[test]
fn empty_privmsg_text_is_412() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "JOIN #e");
    s.drain(alice);
    s.line(alice, "PRIVMSG #e :");
    assert!(has_numeric(&s.drain(alice), "412"));
}

#[test]
fn statusmsg_targets_ops_only() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice"); // op (first joiner)
    let bob = s.register(2, "bob");
    let carol = s.register(3, "carol");
    for c in [alice, bob, carol] {
        s.line(c, "JOIN #st");
        s.drain(c);
    }
    s.drain(alice);
    s.drain(bob);
    // voice bob
    s.line(alice, "MODE #st +v bob");
    for c in [alice, bob, carol] {
        s.drain(c);
    }
    // @#st: only alice (op) receives
    s.line(carol, "PRIVMSG @#st :ops only");
    assert_eq!(
        s.drain(alice),
        vec![":carol!carol@host3.example PRIVMSG @#st :ops only"]
    );
    assert!(s.drain(bob).is_empty(), "voiced bob is not an op");
    // +#st: alice (op) and bob (voice) receive
    s.line(carol, "PRIVMSG +#st :ops and voice");
    assert_eq!(s.drain(alice).len(), 1);
    assert_eq!(s.drain(bob).len(), 1);
}

#[test]
fn invalid_channel_limit_is_696() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "JOIN #lim");
    s.drain(alice);
    for bad in ["0", "-1", "abc"] {
        s.line(alice, &format!("MODE #lim +l {bad}"));
        let out = s.drain(alice);
        assert!(has_numeric(&out, "696"), "limit {bad}: {out:#?}");
    }
    // a valid limit is accepted
    s.line(alice, "MODE #lim +l 5");
    let out = s.drain(alice);
    assert!(out.iter().any(|l| l.contains("MODE #lim +l 5")), "{out:#?}");
}

#[test]
fn no_ctcp_mode_blocks_ctcp_except_action() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    for c in [alice, bob] {
        s.line(c, "JOIN #cc");
        s.drain(c);
    }
    s.drain(alice);
    s.line(alice, "MODE #cc +C");
    s.drain(alice);
    s.drain(bob);
    // a CTCP VERSION is blocked with 404
    s.line(bob, "PRIVMSG #cc :\u{1}VERSION\u{1}");
    assert!(has_numeric(&s.drain(bob), "404"), "CTCP blocked");
    assert!(s.drain(alice).is_empty());
    // ACTION (/me) is exempt
    s.line(bob, "PRIVMSG #cc :\u{1}ACTION waves\u{1}");
    assert_eq!(s.drain(alice).len(), 1, "ACTION allowed");
    // plain text still fine
    s.line(bob, "PRIVMSG #cc :hi");
    assert_eq!(s.drain(alice).len(), 1);
}

/// +C must block a CTCP buried on the *second* line of a multiline batch. The
/// batch is flattened to one PRIVMSG per line for non-multiline recipients, so
/// a CTCP on line 2+ would otherwise re-emerge as its own message and slip past
/// the +C check, which used to inspect only the first byte of the joined blob.
#[test]
fn no_ctcp_mode_blocks_ctcp_buried_in_a_multiline_batch() {
    let mut s = TestServer::new_no_persistence();
    // alice joins first, so she is the op that can set +C.
    let alice = s.register(1, "alice");
    let bob = register_with_caps(&mut s, 2, "bob", "batch draft/multiline");
    s.line(alice, "JOIN #cc");
    s.drain(alice);
    s.line(bob, "JOIN #cc");
    for c in [alice, bob] {
        s.drain(c);
    }
    s.line(alice, "MODE #cc +C");
    s.drain(bob);
    s.drain(alice);
    // A batch whose first line is innocent but whose second is a CTCP VERSION.
    s.line(bob, "BATCH +7 draft/multiline #cc");
    s.line(bob, "@batch=7 PRIVMSG #cc :hi there");
    s.line(bob, "@batch=7 PRIVMSG #cc :\u{1}VERSION\u{1}");
    s.line(bob, "BATCH -7");
    // The whole batch is refused (404), and alice (no multiline cap) receives
    // nothing — not a flattened CTCP.
    let out = s.drain(bob);
    assert!(
        out.iter().any(|l| l.contains(" 404 ")),
        "buried CTCP not blocked by +C: {out:#?}"
    );
    assert!(
        s.drain(alice).is_empty(),
        "a CTCP on line 2 leaked past +C to a non-multiline recipient"
    );
}

/// The +C (no-CTCP) gate must reconstruct `draft/multiline-concat` the way a
/// capable recipient does: a CTCP split across a concat boundary has no single
/// `\n`-delimited line that trips the check, yet reassembles into a blocked
/// CTCP. `\x01ACTION` (an exempt ACTION on its own) + a concat continuation
/// `VERSION\x01` reconstructs to `\x01ACTIONVERSION\x01`, which must be blocked.
#[test]
fn no_ctcp_mode_blocks_ctcp_split_across_a_concat_boundary() {
    let mut s = TestServer::new_no_persistence();
    let alice = s.register(1, "alice");
    let bob = register_with_caps(&mut s, 2, "bob", "batch draft/multiline message-tags");
    s.line(alice, "JOIN #cc");
    s.drain(alice);
    s.line(bob, "JOIN #cc");
    for c in [alice, bob] {
        s.drain(c);
    }
    s.line(alice, "MODE #cc +C");
    s.drain(bob);
    s.drain(alice);
    // First line is a bare ACTION tag (exempt on its own); the concat
    // continuation extends it past ACTION into a blocked CTCP.
    s.line(bob, "BATCH +7 draft/multiline #cc");
    s.line(bob, "@batch=7 PRIVMSG #cc :\u{1}ACTION");
    s.line(
        bob,
        "@batch=7;draft/multiline-concat PRIVMSG #cc :VERSION\u{1}",
    );
    s.line(bob, "BATCH -7");
    let out = s.drain(bob);
    assert!(
        out.iter().any(|l| l.contains(" 404 ")),
        "concat-reconstructed CTCP not blocked by +C: {out:#?}"
    );
    assert!(
        s.drain(alice).is_empty(),
        "a concat-split CTCP leaked past +C"
    );
    // A genuine multi-line ACTION (no concat trickery) is still allowed.
    s.line(bob, "BATCH +8 draft/multiline #cc");
    s.line(bob, "@batch=8 PRIVMSG #cc :\u{1}ACTION waves\u{1}");
    s.line(bob, "BATCH -8");
    let out = s.drain(bob);
    assert!(
        !out.iter().any(|l| l.contains(" 404 ")),
        "a legitimate ACTION was wrongly blocked: {out:#?}"
    );
}

#[test]
fn kill_requires_oper() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    let carol = s.register(3, "carol");
    for c in [alice, bob] {
        s.line(c, "JOIN #k");
        s.drain(c);
    }
    s.drain(alice);
    // non-oper KILL → 481
    s.line(alice, "KILL bob :nope");
    assert!(has_numeric(&s.drain(alice), "481"));
    // oper KILL disconnects the victim and broadcasts QUIT
    s.line(alice, "OPER god letmein");
    s.drain(alice);
    s.line(alice, "KILL bob :bye");
    let bob_out = s.drain(bob);
    assert!(
        bob_out.iter().any(|l| l.starts_with("ERROR :")),
        "{bob_out:#?}"
    );
    assert!(
        s.drain(alice).iter().any(|l| l.contains("QUIT")),
        "peer sees QUIT"
    );
    // bob's nick is freed
    let _ = carol;
    let c4 = s.connect(4);
    s.line(c4, "NICK bob");
    s.line(c4, "USER b 0 * :B");
    assert!(has_numeric(&s.drain(c4), "001"));
    // killing an unknown nick → 401
    s.line(alice, "KILL ghost :x");
    assert!(has_numeric(&s.drain(alice), "401"));
}

/// A KILL comment near the input-line limit must not build an over-length
/// ERROR line: the `Closing Link` wrapper's overhead pushed it past 512 bytes,
/// which panics the debug wire check (an oper-triggerable core crash in any
/// debug/fuzz build) and is discarded whole by the victim's framing in
/// release — the killed client was told nothing. The reason must be fitted
/// like the QUIT path fits its own.
#[test]
fn kill_with_maximal_comment_fits_the_error_line() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    s.line(alice, "OPER god letmein");
    s.drain(alice);
    // A legal input line (well under 512) whose ERROR wrapping would overflow.
    let comment = "x".repeat(460);
    s.line(alice, &format!("KILL bob :{comment}"));
    let bob_out = s.drain(bob);
    let error = bob_out
        .iter()
        .find(|l| l.starts_with("ERROR :"))
        .expect("victim must still receive the close notice");
    assert!(
        error.len() + 2 <= 512,
        "ERROR line exceeds the wire limit ({} bytes)",
        error.len() + 2
    );
}

/// A QUIT that arrives while a deferred DB reply is outstanding must still
/// deliver its terminal ERROR: the close path dropped the session together
/// with the output held behind the deferral — the ERROR included — so the
/// quitting client saw nothing at all.
#[test]
fn quit_while_reply_deferred_still_delivers_the_error() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "batch draft/chathistory");
    s.line(alice, "JOIN #room");
    s.drain(alice);
    // Defer: the CHATHISTORY page goes to the (undrained) DB queue, so the
    // connection's later output is held behind the pending reply.
    s.line(alice, "CHATHISTORY LATEST #room * 5");
    assert!(
        s.drain(alice).is_empty(),
        "the page should be deferred, not answered"
    );
    s.line(alice, "QUIT :bye");
    let out = s.drain(alice);
    assert!(
        out.iter().any(|l| l.starts_with("ERROR :Closing Link")),
        "terminal ERROR dropped behind the deferred hold: {out:#?}"
    );
}

#[test]
fn wallops_to_plus_w_opers_only() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    let carol = s.register(3, "carol");
    // non-oper WALLOPS → 481
    s.line(alice, "WALLOPS :hi");
    assert!(has_numeric(&s.drain(alice), "481"));
    // bob sets +w, carol stays -w
    s.line(bob, "MODE bob +w");
    assert!(s.drain(bob).iter().any(|l| l.contains("MODE bob :+w")));
    // alice opers and wallops
    s.line(alice, "OPER god letmein");
    s.drain(alice);
    s.line(alice, "WALLOPS :hi everyone");
    assert_eq!(
        s.drain(bob),
        vec![":alice!alice@host1.example WALLOPS :hi everyone"]
    );
    assert!(s.drain(carol).is_empty(), "carol has no +w");
}

#[test]
fn bot_mode_tags_and_whois() {
    let mut s = TestServer::new();
    let botc = register_with_caps(&mut s, 1, "botnick", "message-tags");
    let user = register_with_caps(&mut s, 2, "user", "message-tags");
    // set +B
    s.line(botc, "MODE botnick +B");
    assert!(s.drain(botc).iter().any(|l| l.contains("MODE botnick :+B")));
    // messages from the bot carry the bot tag for message-tags clients
    s.line(botc, "PRIVMSG user :beep boop");
    let got = s.drain(user);
    assert!(
        got[0].contains("bot") && got[0].contains("PRIVMSG user :beep boop"),
        "{got:#?}"
    );
    // WHOIS shows 335
    s.line(user, "WHOIS botnick");
    assert!(has_numeric(&s.drain(user), "335"));
    // WHO shows the B flag
    s.line(user, "JOIN #b");
    s.drain(user);
    s.line(botc, "JOIN #b");
    s.drain(botc);
    s.drain(user);
    s.line(user, "WHO #b");
    let out = s.drain(user);
    let row = out
        .iter()
        .find(|l| l.contains(" 352 ") && l.contains("botnick"))
        .expect("352");
    assert!(row.contains('B'), "{row}");
}

#[test]
fn fresh_session_flood_bucket_starts_full_regardless_of_uptime() {
    // The monotonic clock's epoch is process start, so a session opened a few
    // seconds into uptime must STILL start with the full command burst — not
    // `min(uptime_seconds, burst)`. Regression for a fresh bucket under-filled
    // during the first `command_burst` seconds after a restart, which would
    // wrongly Excess-Flood-kill a client pipelining a legitimate burst — the
    // worst case being a post-restart reconnect storm. A fixed clock only 3s
    // into "uptime" reproduces it (the usual 1e9-ms test clock masks it, since
    // uptime then dwarfs any burst).
    fn early_mono() -> MonoMillis {
        MonoMillis::from_millis(3_000)
    }
    let (db_tx, _db_rx) = queue(Config {
        name: "d",
        capacity: 8,
        policy: Policy::Fifo,
    });
    let mut core = Core::new(
        CoreConfig {
            server_name: "irc.test.example".into(),
            network_name: "T".into(),
            description: "test server".into(),
            registration_before_connect: false,
            registration_require_email: false,
            sendq: 256,
            motd: vec![],
            nicklen: 16,
            sasl_enabled: false,
            opers: vec![],
            max_hot_channels: 8,
            clock: || Millis::from_millis(1_000_000_000),
            mono_clock: early_mono,
            command_burst: Some(10),
            registration_burst: None,
        },
        db_tx,
    );
    let conn = ConnId(1);
    let (tx, mut rx) = queue(Config {
        name: "s",
        capacity: 512,
        policy: Policy::Fifo,
    });
    core.handle(Input::Open {
        conn,
        tx,
        host: "h".into(),
        transport: e6ircd::core::ConnectionTransport::Tcp,
    });
    for line in ["NICK alice", "USER a 0 * :A"] {
        core.handle(Input::Line {
            conn,
            line: line.as_bytes().to_vec(),
        });
    }
    while rx.try_pop().is_some() {}

    // Send exactly `command_burst` floodable commands in the same tick. With a
    // full fresh bucket all ten are credited; with the old uptime-seeded bucket
    // (3 tokens) the fourth would be dropped with Excess Flood.
    for _ in 0..10 {
        core.handle(Input::Line {
            conn,
            line: b"AWAY :busy".to_vec(),
        });
    }
    let out: Vec<String> = std::iter::from_fn(|| {
        rx.try_pop().map(|e| {
            String::from_utf8(e.payload.0.to_vec())
                .unwrap()
                .trim_end()
                .to_string()
        })
    })
    .collect();
    assert!(
        !out.iter().any(|l| l.contains("Excess Flood")),
        "a fresh session must start with the full burst, not min(uptime, burst): {out:#?}"
    );
}

#[test]
fn account_creation_is_rate_limited_per_ip() {
    // With registration_burst=1, one client IP may create at most one account
    // before the bucket empties; the second REGISTER is refused without ever
    // reaching the DB worker. (The bucket refills over an hour, far longer than
    // this test's fixed clock advances, so the second attempt stays throttled.)
    let (db_tx, mut db_rx) = queue(Config {
        name: "d",
        capacity: 8,
        policy: Policy::Fifo,
    });
    let mut core = Core::new(
        CoreConfig {
            server_name: "irc.test.example".into(),
            network_name: "T".into(),
            description: "test server".into(),
            registration_before_connect: false,
            registration_require_email: false,
            sendq: 256,
            motd: vec![],
            nicklen: 16,
            sasl_enabled: true,
            opers: vec![],
            max_hot_channels: 8,
            clock: || Millis::from_millis(1_000_000_000),
            mono_clock: test_mono,
            command_burst: None,
            registration_burst: Some(1),
        },
        db_tx,
    );
    let conn = ConnId(1);
    let (tx, _rx) = queue(Config {
        name: "s",
        capacity: 512,
        policy: Policy::Fifo,
    });
    core.handle(Input::Open {
        conn,
        tx,
        host: "shared-ip".into(),
        transport: e6ircd::core::ConnectionTransport::Tcp,
    });
    for line in ["NICK alice", "USER a 0 * :A", "REGISTER * * pw"] {
        core.handle(Input::Line {
            conn,
            line: line.as_bytes().to_vec(),
        });
    }
    // Resolve the first REGISTER as "already exists": this clears the
    // in-flight `pending_register` (so the per-connection concurrent-register
    // guard won't be what refuses the next attempt) without logging the
    // session in — leaving it eligible to try again, now against an empty
    // bucket.
    core.handle(Input::DbReply {
        conn,
        reply: e6ircd::core::DbReply::AccountExists {
            origin: e6ircd::core::AccountOrigin::RegisterCommand,
        },
    });
    // A second account-creation attempt from the same IP must be throttled by
    // the rate limiter (not the concurrent-register guard): it never reaches
    // the worker.
    core.handle(Input::Line {
        conn,
        line: b"REGISTER * * pw".to_vec(),
    });
    let creates = std::iter::from_fn(|| db_rx.try_pop())
        .filter(|env| matches!(env.payload, e6ircd::core::DbRequest::CreateAccount { .. }))
        .count();
    assert_eq!(
        creates, 1,
        "registration_burst=1 must let exactly one account creation reach the DB worker"
    );
}

#[test]
fn hot_history_ring_is_lru_evicted() {
    // A server with room for only 2 hot channels: activity in a third
    // must evict the least-recently-active channel's ring.
    let (db_tx, db_rx) = queue(Config {
        name: "d",
        capacity: 8,
        policy: Policy::Fifo,
    });
    let mut core = Core::new(
        CoreConfig {
            server_name: "irc.test.example".into(),
            network_name: "T".into(),
            description: "test server".into(),
            registration_before_connect: false,
            registration_require_email: false,
            sendq: 256,
            motd: vec![],
            nicklen: 16,
            sasl_enabled: false,
            opers: vec![],
            max_hot_channels: 2,
            clock: || Millis::from_millis(1_000_000_000),
            mono_clock: test_mono,
            command_burst: None,
            registration_burst: None,
        },
        db_tx,
    );
    let _ = db_rx;
    // a capable observer to read CHATHISTORY
    let conn = ConnId(1);
    let (tx, mut rx) = queue(Config {
        name: "s",
        capacity: 512,
        policy: Policy::Fifo,
    });
    core.handle(Input::Open {
        conn,
        tx,
        host: "h".into(),
        transport: e6ircd::core::ConnectionTransport::Tcp,
    });
    for line in [
        "CAP LS 302",
        "CAP REQ :batch draft/chathistory",
        "NICK o",
        "USER o 0 * :O",
        "CAP END",
    ] {
        core.handle(Input::Line {
            conn,
            line: line.as_bytes().to_vec(),
        });
    }
    // join three channels, post to each in order a, b, c
    for ch in ["#a", "#b", "#c"] {
        core.handle(Input::Line {
            conn,
            line: format!("JOIN {ch}").into_bytes(),
        });
        core.handle(Input::Line {
            conn,
            line: format!("PRIVMSG {ch} :msg in {ch}").into_bytes(),
        });
    }
    // drain everything queued so far
    while rx.try_pop().is_some() {}

    // #a was least-recently active (a, then b, then c) → its ring is
    // evicted. Without a database, an evicted channel's LATEST returns
    // an empty batch (nothing in the ring, no PG to page from).
    core.handle(Input::Line {
        conn,
        line: b"CHATHISTORY LATEST #a * 10".to_vec(),
    });
    let out: Vec<String> = std::iter::from_fn(|| {
        rx.try_pop().map(|e| {
            String::from_utf8(e.payload.0.to_vec())
                .unwrap()
                .trim_end()
                .to_string()
        })
    })
    .collect();
    let batch: Vec<_> = out.iter().filter(|l| l.contains("batch=")).collect();
    assert!(
        batch.is_empty(),
        "#a ring should be evicted (empty batch): {out:#?}"
    );

    // #c is most-recently active → still hot, returns its message.
    core.handle(Input::Line {
        conn,
        line: b"CHATHISTORY LATEST #c * 10".to_vec(),
    });
    let out: Vec<String> = std::iter::from_fn(|| {
        rx.try_pop().map(|e| {
            String::from_utf8(e.payload.0.to_vec())
                .unwrap()
                .trim_end()
                .to_string()
        })
    })
    .collect();
    assert!(
        out.iter().any(|l| l.contains("msg in #c")),
        "#c still hot: {out:#?}"
    );
}

// ChanServ founder ownership: a registered channel's founder is opped on
// join even when not the first to arrive (DESIGN §7.6).

#[test]
fn preloaded_founder_is_opped_on_join() {
    let mut s = TestServer::new();
    // Boot-loaded ownership (name_folded, founder_folded).
    s.core
        .preload_founders(vec![("#chan".to_string(), "boss".to_string())]);

    // A non-founder arrives first and is opped as the first joiner.
    let alice = s.register(1, "alice");
    s.line(alice, "JOIN #chan");
    let names = s
        .drain(alice)
        .into_iter()
        .find(|l| l.contains(" 353 "))
        .expect("353");
    assert!(
        names.ends_with(":@alice"),
        "first joiner not opped: {names}"
    );

    s.drain(alice);
    // The founder identifies and joins second, yet is opped.
    let bob = s.register(2, "bob");
    identify(&mut s, bob, "boss");
    s.line(bob, "JOIN #chan");
    let names = s
        .drain(bob)
        .into_iter()
        .find(|l| l.contains(" 353 "))
        .expect("353");
    assert!(names.contains("@bob"), "founder not opped on join: {names}");
    // The pre-existing member must be *told* bob is now an op — otherwise her
    // client tracks him as an ordinary user while the server treats him as an
    // operator (a silent membership desync).
    let alice_saw = s.drain(alice);
    assert!(
        alice_saw.iter().any(|l| l.contains("MODE #chan +o bob")),
        "peer never told the auto-opped founder is an op: {alice_saw:#?}"
    );

    // A third, non-founder user is not opped.
    let carol = s.register(3, "carol");
    s.line(carol, "JOIN #chan");
    let names = s
        .drain(carol)
        .into_iter()
        .find(|l| l.contains(" 353 "))
        .expect("353");
    assert!(
        names.contains("carol") && !names.contains("@carol"),
        "non-founder wrongly opped: {names}"
    );
}

#[test]
fn registration_records_founder_for_later_rejoin() {
    let mut s = TestServer::new();

    // Boss registers and joins #room (opped as first), then registers it.
    let boss = s.register(1, "boss");
    identify(&mut s, boss, "boss");
    s.line(boss, "JOIN #room");
    s.drain(boss);
    s.line(boss, "PRIVMSG ChanServ :REGISTER #room");
    s.db_requests();
    // The DB confirms registration; the core records ownership in its hot
    // map so a later rejoin re-ops the founder.
    s.core.handle(Input::DbReply {
        conn: boss,
        reply: e6ircd::core::DbReply::ChannelRegistered {
            channel: "#room".to_string(),
            founder_account: "boss".to_string(),
            topic: None,
            label: None,
        },
    });
    s.drain(boss);

    // Boss leaves; the channel empties and is dropped.
    s.line(boss, "PART #room");
    s.drain(boss);

    // Someone else recreates it and is opped as the first joiner.
    let dave = s.register(2, "dave");
    s.line(dave, "JOIN #room");
    let names = s
        .drain(dave)
        .into_iter()
        .find(|l| l.contains(" 353 "))
        .expect("353");
    assert!(names.ends_with(":@dave"), "recreator not opped: {names}");

    // The founder rejoins and is re-opped despite not being first.
    s.line(boss, "JOIN #room");
    let names = s
        .drain(boss)
        .into_iter()
        .find(|l| l.contains(" 353 "))
        .expect("353");
    assert!(names.contains("@boss"), "founder not re-opped: {names}");
}

/// The founder recorded in the hot map is the account the DB row was written
/// with (echoed on the reply), not the session's account at reply time. When
/// the session's account differs from (or is absent at) reply time — e.g. an
/// IDENTIFY/LOGOUT raced the round-trip — the old handler read `session.account`
/// and recorded the wrong founder, or none, diverging the hot map from the DB
/// until restart. The echoed `founder_account` is authoritative.
#[test]
fn channel_registration_uses_the_echoed_founder_not_the_live_session() {
    let mut s = TestServer::new();
    // Boss holds the channel but this session is NOT identified — mirroring a
    // session whose account changed between the request and this reply. The old
    // code would record no founder (session.account is None); the new code
    // records the echoed founder regardless.
    let boss = s.register(1, "boss");
    s.line(boss, "JOIN #room");
    s.drain(boss);
    s.core.handle(Input::DbReply {
        conn: boss,
        reply: e6ircd::core::DbReply::ChannelRegistered {
            channel: "#room".to_string(),
            founder_account: "boss".to_string(),
            topic: None,
            label: None,
        },
    });
    s.drain(boss);
    // Empty and recreate; the founder must still be re-opped on rejoin — proof
    // the hot founder map was seeded from the echoed account, not the (absent)
    // session account.
    s.line(boss, "PART #room");
    s.drain(boss);
    let dave = s.register(2, "dave");
    s.line(dave, "JOIN #room");
    s.drain(dave);
    identify(&mut s, boss, "boss");
    s.line(boss, "JOIN #room");
    let names = s
        .drain(boss)
        .into_iter()
        .find(|l| l.contains(" 353 "))
        .expect("353");
    assert!(
        names.contains("@boss"),
        "founder from the echoed account not recorded: {names}"
    );
}

/// A NickServ REGISTER whose DB write fails must tell the user, not hang. The
/// failure reply carries the NickServ origin so the handler answers rather than
/// dropping a bare, unattributable Unavailable.
#[test]
fn nickserv_register_db_unavailable_notifies() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.drain(alice);
    s.line(alice, "PRIVMSG NickServ :REGISTER hunter2");
    s.db_requests();
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::AccountRegisterUnavailable {
            origin: e6ircd::core::AccountOrigin::NickServ,
        },
    });
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|l| l.contains("NickServ") && l.contains("temporarily unavailable")),
        "NickServ REGISTER DB failure was silently dropped: {out:#?}"
    );
}

/// A ChanServ REGISTER whose DB write fails must tell the user, not hang.
#[test]
fn chanserv_register_db_unavailable_notifies() {
    let mut s = TestServer::new();
    let boss = s.register(1, "boss");
    identify(&mut s, boss, "boss");
    s.line(boss, "JOIN #room");
    s.drain(boss);
    s.line(boss, "PRIVMSG ChanServ :REGISTER #room");
    s.db_requests();
    s.core.handle(Input::DbReply {
        conn: boss,
        reply: e6ircd::core::DbReply::ChannelRegisterUnavailable {
            channel: "#room".into(),
            label: None,
        },
    });
    let out = s.drain(boss);
    assert!(
        out.iter()
            .any(|l| l.contains("ChanServ") && l.contains("temporarily unavailable")),
        "ChanServ REGISTER DB failure was silently dropped: {out:#?}"
    );
}

/// A founder transfer whose DB write *errors* must not be reported as the
/// definitive "no such account" — that would tell the founder a falsehood they
/// might act on. It reads as a temporary-unavailability instead.
#[test]
fn founder_transfer_db_error_reports_unavailable_not_missing() {
    let mut s = TestServer::new();
    s.core
        .preload_founders(vec![("#room".to_string(), "boss".to_string())]);
    let boss = s.register(1, "boss");
    identify(&mut s, boss, "boss");
    s.line(boss, "PRIVMSG ChanServ :SET #room FOUNDER alice");
    s.db_requests();
    s.channel_service_persisted(
        e6ircd::core::ChannelServicePersistence::FounderUnavailable {
            channel: "#room".to_string(),
            display: "#room".to_string(),
            label: None,
        },
    );
    let out = s.drain(boss);
    assert!(
        out.iter().any(|l| l.contains("temporarily unavailable")),
        "a store fault was reported as a definitive negative: {out:#?}"
    );
    assert!(
        !out.iter().any(|l| l.contains("no such account")),
        "a DB error must not claim the account is missing: {out:#?}"
    );
}

/// A CHATHISTORY page that fails in the store answers with a FAIL, not an empty
/// batch — an empty batch is indistinguishable from a buffer with no history,
/// and a bouncer-style client would cache "nothing here" for a window that does
/// exist.
#[test]
fn chathistory_db_error_fails_rather_than_empty_batch() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "batch draft/chathistory");
    s.line(alice, "JOIN #h");
    s.drain(alice);
    s.core.handle(Input::HistoryPage {
        conn: alice,
        display: "#h".into(),
        batch_ref: "b1".into(),
        rows: Err(()),
        label: None,
    });
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|l| l.contains("FAIL CHATHISTORY MESSAGE_ERROR")),
        "a store fault must FAIL, not send an empty batch: {out:#?}"
    );
    assert!(
        !out.iter().any(|l| l.contains("BATCH +")),
        "no batch should open on a store fault: {out:#?}"
    );
}

/// The deferred-history reply boundary is independent from command parsing:
/// it must not trust a stale or malformed display value enough to emit a line
/// the recipient's IRC framing discards. This is the regression seed found by
/// the `core_multi` fuzz target.
#[test]
fn chathistory_reply_clips_an_untrusted_display_before_opening_its_batch() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "batch draft/chathistory");
    s.drain(alice);
    s.core.handle(Input::HistoryPage {
        conn: alice,
        display: format!("#{}", "x".repeat(600)),
        batch_ref: "b1".into(),
        rows: Ok(Vec::new()),
        label: None,
    });
    let out = s.drain(alice);
    let open = out
        .iter()
        .find(|line| line.contains("BATCH +b1 chathistory"))
        .expect("history batch open");
    assert!(
        open.len() <= 512,
        "history batch open exceeds the wire limit: {open:?}"
    );
}

// CHATHISTORY TARGETS: enumerate the buffers a client has (DESIGN §11.2).

#[test]
fn chathistory_targets_enumerates_buffers() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "batch draft/chathistory");
    s.line(alice, "JOIN #a");
    s.line(alice, "JOIN #b");
    s.drain(alice);

    // TARGETS with two timestamp bounds becomes a QueryTargets DB request
    // over the client's channels.
    s.line(
        alice,
        "CHATHISTORY TARGETS timestamp=1970-01-01T00:00:00.000Z \
         timestamp=1971-01-01T00:00:00.000Z 10",
    );
    let batch_ref = s
        .db_requests()
        .into_iter()
        .find_map(|r| match r {
            e6ircd::core::DbRequest::QueryTargets {
                channels,
                limit,
                batch_ref,
                ..
            } => {
                assert!(
                    channels.contains(&"#a".to_string()) && channels.contains(&"#b".to_string()),
                    "channels: {channels:?}"
                );
                assert_eq!(limit, 10);
                Some(batch_ref)
            }
            _ => None,
        })
        .expect("QueryTargets request");

    // The DB answers with the active buffers; the core frames the batch.
    s.core.handle(Input::TargetsPage {
        conn: alice,
        batch_ref: batch_ref.clone(),
        // Epoch milliseconds, as CHATHISTORY TARGETS carries them.
        targets: Ok(vec![
            ("#a".into(), Millis::from_millis(1_000_000_000)),
            ("#b".into(), Millis::from_millis(999_999_000)),
        ]),
        label: None,
    });
    let out = s.drain(alice);
    assert!(
        out.contains(&format!(
            ":irc.test.example BATCH +{batch_ref} draft/chathistory-targets"
        )),
        "no batch open: {out:#?}"
    );
    assert!(
        out.contains(&format!(
            "@batch={batch_ref} :irc.test.example CHATHISTORY TARGETS #a 1970-01-12T13:46:40.000Z"
        )),
        "no #a target line: {out:#?}"
    );
    assert!(
        out.iter().any(|l| l.contains("CHATHISTORY TARGETS #b")),
        "no #b target line: {out:#?}"
    );
    assert!(
        out.contains(&format!(":irc.test.example BATCH -{batch_ref}")),
        "no batch close: {out:#?}"
    );
}

#[test]
fn chathistory_latest_selector_bounds_the_window() {
    // `LATEST <target> <selector> <limit>` must return only messages newer
    // than the selector; only `*` is unbounded. Returning the whole ring for
    // a bounded request replays messages the client already has.
    let mut s = TestServer::new_no_persistence();
    let alice = s.register(1, "alice");
    let bob = register_with_caps(&mut s, 2, "bob", "batch draft/chathistory message-tags");
    for c in [alice, bob] {
        s.line(c, "JOIN #hl");
        s.drain(c);
    }
    s.drain(alice);
    for i in 1..=5 {
        s.line(alice, &format!("PRIVMSG #hl :m{i}"));
    }
    let live = s.drain(bob);
    let msgid = |body: &str| -> String {
        live.iter()
            .find(|l| l.ends_with(&format!(":{body}")))
            .and_then(|l| {
                l.trim_start_matches('@')
                    .split([';', ' '])
                    .find_map(|t| t.strip_prefix("msgid="))
            })
            .expect("msgid")
            .to_string()
    };

    s.line(
        bob,
        &format!("CHATHISTORY LATEST #hl msgid={} 10", msgid("m3")),
    );
    let out = s.drain(bob);
    let inner: Vec<_> = out[1..out.len() - 1].to_vec();
    assert_eq!(inner.len(), 2, "only messages after m3: {out:#?}");
    for (i, body) in ["m4", "m5"].iter().enumerate() {
        assert!(inner[i].ends_with(&format!(":{body}")), "{}", inner[i]);
    }

    // `*` stays unbounded.
    s.line(bob, "CHATHISTORY LATEST #hl * 10");
    let out = s.drain(bob);
    assert_eq!(out.len() - 2, 5, "unbounded LATEST: {out:#?}");
}

#[test]
fn chathistory_between_direction_picks_which_end_the_limit_keeps() {
    // BETWEEN walks from its first selector toward its second, so a reversed
    // (newest-first) request with a short limit keeps the newest messages in
    // the span, not the oldest. Both orders describe the same window.
    let mut s = TestServer::new_no_persistence();
    let alice = s.register(1, "alice");
    let bob = register_with_caps(&mut s, 2, "bob", "batch draft/chathistory message-tags");
    for c in [alice, bob] {
        s.line(c, "JOIN #hb");
        s.drain(c);
    }
    s.drain(alice);
    for i in 1..=6 {
        s.line(alice, &format!("PRIVMSG #hb :m{i}"));
    }
    let live = s.drain(bob);
    let msgid = |body: &str| -> String {
        live.iter()
            .find(|l| l.ends_with(&format!(":{body}")))
            .and_then(|l| {
                l.trim_start_matches('@')
                    .split([';', ' '])
                    .find_map(|t| t.strip_prefix("msgid="))
            })
            .expect("msgid")
            .to_string()
    };
    let (first, last) = (msgid("m1"), msgid("m6"));

    // Oldest-first: the limit keeps m2, m3.
    s.line(
        bob,
        &format!("CHATHISTORY BETWEEN #hb msgid={first} msgid={last} 2"),
    );
    let out = s.drain(bob);
    let inner: Vec<_> = out[1..out.len() - 1].to_vec();
    assert_eq!(inner.len(), 2, "{out:#?}");
    for (i, body) in ["m2", "m3"].iter().enumerate() {
        assert!(inner[i].ends_with(&format!(":{body}")), "{}", inner[i]);
    }

    // Reversed bounds: same window, but the limit keeps m4, m5 — and the
    // batch is still rendered oldest-first.
    s.line(
        bob,
        &format!("CHATHISTORY BETWEEN #hb msgid={last} msgid={first} 2"),
    );
    let out = s.drain(bob);
    let inner: Vec<_> = out[1..out.len() - 1].to_vec();
    assert_eq!(inner.len(), 2, "{out:#?}");
    for (i, body) in ["m4", "m5"].iter().enumerate() {
        assert!(inner[i].ends_with(&format!(":{body}")), "{}", inner[i]);
    }
}

#[test]
fn replayed_message_keeps_the_time_it_was_delivered_with() {
    // A message is stamped once: the `time=` tag a client sees live must be
    // byte-identical to the one CHATHISTORY replays for the same msgid.
    // Reading the clock separately for delivery and for history let the two
    // disagree whenever the millisecond ticked over between them.
    let mut s = TestServer::new_with_advancing_clock();
    let alice = s.register(1, "alice");
    let bob = register_with_caps(
        &mut s,
        2,
        "bob",
        "batch draft/chathistory message-tags server-time",
    );
    for c in [alice, bob] {
        s.line(c, "JOIN #ht");
        s.drain(c);
    }
    s.drain(alice);
    s.line(alice, "PRIVMSG #ht :hello");
    let live = s.drain(bob);
    let tags_of = |line: &str| -> (String, String) {
        let tags = line
            .trim_start_matches('@')
            .split(' ')
            .next()
            .expect("tags");
        let get = |k: &str| {
            tags.split(';')
                .find_map(|t| t.strip_prefix(k))
                .unwrap_or_else(|| panic!("missing {k} in {line}"))
                .to_string()
        };
        (get("msgid="), get("time="))
    };
    let live_line = live
        .iter()
        .find(|l| l.ends_with(":hello"))
        .expect("live message");
    let (live_msgid, live_time) = tags_of(live_line);

    s.line(bob, "CHATHISTORY LATEST #ht * 10");
    let out = s.drain(bob);
    let replayed = out
        .iter()
        .find(|l| l.ends_with(":hello"))
        .expect("replayed message");
    let (replayed_msgid, replayed_time) = tags_of(replayed);
    assert_eq!(live_msgid, replayed_msgid);
    assert_eq!(
        live_time, replayed_time,
        "live and replayed time must match: {live_line} vs {replayed}"
    );
}

#[test]
fn direct_message_history_is_shared_by_both_participants() {
    // A conversation is stored once under a key both sides derive, so each
    // participant's CHATHISTORY sees the whole thread — not just the half they
    // sent — and every message keeps the recipient it was addressed to.
    let mut s = TestServer::new_no_persistence();
    let caps = "batch draft/chathistory message-tags";
    let alice = register_with_caps(&mut s, 1, "alice", caps);
    let bob = register_with_caps(&mut s, 2, "bob", caps);
    s.line(alice, "PRIVMSG bob :hi bob");
    s.line(bob, "PRIVMSG alice :hi alice");
    s.drain(alice);
    s.drain(bob);

    for (who, peer, expected_targets) in [
        (alice, "bob", ["bob", "alice"]),
        (bob, "alice", ["bob", "alice"]),
    ] {
        s.line(who, &format!("CHATHISTORY LATEST {peer} * 10"));
        let out = s.drain(who);
        let inner: Vec<_> = out[1..out.len() - 1].to_vec();
        assert_eq!(inner.len(), 2, "both sides of the thread: {out:#?}");
        assert!(inner[0].ends_with(":hi bob"), "{}", inner[0]);
        assert!(inner[1].ends_with(":hi alice"), "{}", inner[1]);
        // Each row keeps its original recipient, not the conversation name.
        for (i, target) in expected_targets.iter().enumerate() {
            assert!(
                inner[i].contains(&format!(" PRIVMSG {target} :")),
                "row {i} addressed to {target}: {}",
                inner[i]
            );
        }
    }
}

#[test]
fn chathistory_targets_lists_conversations_and_orders_oldest_first() {
    // TARGETS enumerates channels *and* direct-message correspondents, oldest
    // activity first, and matches a buffer on its latest message falling in the
    // window — a buffer whose newest activity is outside it has been read past.
    let mut s = TestServer::new_no_persistence();
    let caps = "batch draft/chathistory message-tags server-time";
    let alice = register_with_caps(&mut s, 1, "alice", caps);
    let bob = register_with_caps(&mut s, 2, "bob", caps);
    s.line(alice, "JOIN #room");
    s.line(bob, "JOIN #room");
    s.drain(alice);
    s.drain(bob);
    s.line(alice, "PRIVMSG #room :in the channel");
    s.line(alice, "PRIVMSG bob :in a dm");
    s.drain(alice);
    s.drain(bob);

    s.line(
        alice,
        "CHATHISTORY TARGETS timestamp=1970-01-01T00:00:00.000Z          timestamp=2262-01-01T00:00:00.000Z 10",
    );
    let out = s.drain(alice);
    let listed: Vec<String> = out
        .iter()
        .filter(|l| l.contains("CHATHISTORY TARGETS "))
        .filter_map(|l| l.split_whitespace().nth(4).map(str::to_string))
        .collect();
    assert_eq!(
        listed,
        vec!["#room".to_string(), "bob".to_string()],
        "{out:#?}"
    );

    // A window that ends before the buffers' latest activity matches nothing.
    s.line(
        alice,
        "CHATHISTORY TARGETS timestamp=1970-01-01T00:00:00.000Z          timestamp=1970-01-02T00:00:00.000Z 10",
    );
    let out = s.drain(alice);
    assert!(
        !out.iter().any(|l| l.contains("CHATHISTORY TARGETS ")),
        "no buffer's latest message is in that window: {out:#?}"
    );
}

#[test]
fn chathistory_around_msgid() {
    let mut s = TestServer::new_no_persistence();
    let alice = s.register(1, "alice");
    let bob = register_with_caps(&mut s, 2, "bob", "batch draft/chathistory message-tags");
    for c in [alice, bob] {
        s.line(c, "JOIN #ha");
        s.drain(c);
    }
    s.drain(alice);
    for i in 1..=5 {
        s.line(alice, &format!("PRIVMSG #ha :m{i}"));
    }
    let live = s.drain(bob);
    let msgid = |body: &str| -> String {
        live.iter()
            .find(|l| l.ends_with(&format!(":{body}")))
            .and_then(|l| {
                l.trim_start_matches('@')
                    .split([';', ' '])
                    .find_map(|t| t.strip_prefix("msgid="))
            })
            .expect("msgid")
            .to_string()
    };

    // AROUND m3, limit 4 → 2 older (m1,m2) + m3 + 1 newer (m4).
    s.line(
        bob,
        &format!("CHATHISTORY AROUND #ha msgid={} 4", msgid("m3")),
    );
    let out = s.drain(bob);
    let inner: Vec<_> = out[1..out.len() - 1].to_vec();
    assert_eq!(inner.len(), 4, "{out:#?}");
    for (i, body) in ["m1", "m2", "m3", "m4"].iter().enumerate() {
        assert!(
            inner[i].ends_with(&format!(":{body}")),
            "{}: {}",
            i,
            inner[i]
        );
    }
}

#[test]
fn chathistory_between_msgids() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = register_with_caps(&mut s, 2, "bob", "batch draft/chathistory message-tags");
    for c in [alice, bob] {
        s.line(c, "JOIN #hb2");
        s.drain(c);
    }
    s.drain(alice);
    for i in 1..=5 {
        s.line(alice, &format!("PRIVMSG #hb2 :m{i}"));
    }
    let live = s.drain(bob);
    let msgid = |body: &str| -> String {
        live.iter()
            .find(|l| l.ends_with(&format!(":{body}")))
            .and_then(|l| {
                l.trim_start_matches('@')
                    .split([';', ' '])
                    .find_map(|t| t.strip_prefix("msgid="))
            })
            .expect("msgid")
            .to_string()
    };

    // BETWEEN m2 and m5 (exclusive) → m3, m4.
    s.line(
        bob,
        &format!(
            "CHATHISTORY BETWEEN #hb2 msgid={} msgid={} 10",
            msgid("m2"),
            msgid("m5")
        ),
    );
    let out = s.drain(bob);
    let inner: Vec<_> = out[1..out.len() - 1].to_vec();
    assert_eq!(inner.len(), 2, "{out:#?}");
    assert!(inner[0].ends_with(":m3"), "{inner:#?}");
    assert!(inner[1].ends_with(":m4"), "{inner:#?}");
}

// ChanServ topic retention: a registered channel keeps its topic across an
// empty→recreate cycle (DESIGN §7.6, §8).

#[test]
fn registered_channel_topic_restored_on_recreate() {
    let mut s = TestServer::new();
    s.core
        .preload_founders(vec![("#room".to_string(), "boss".to_string())]);
    s.core.preload_topics(vec![(
        "#room".to_string(),
        "the topic".to_string(),
        "boss!b@h".to_string(),
        1_000_000,
    )]);

    // alice recreates the channel; the retained topic is restored and
    // shown in her JOIN reply (RPL_TOPIC 332).
    let alice = s.register(1, "alice");
    s.line(alice, "JOIN #room");
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|l| l.contains(" 332 ") && l.ends_with(":the topic")),
        "restored topic not shown on join: {out:#?}"
    );
}

#[test]
fn registered_channel_topic_persisted_on_set() {
    let mut s = TestServer::new();
    s.core
        .preload_founders(vec![("#reg".to_string(), "boss".to_string())]);
    let boss = s.register(1, "boss");
    s.line(boss, "JOIN #reg"); // first joiner → op
    s.drain(boss);
    s.db_requests();

    s.line(boss, "TOPIC #reg :new topic");
    assert!(
        s.drain(boss).is_empty(),
        "registered TOPIC must not echo before persistence"
    );
    let requests = s.db_requests();
    let revision = match requests.as_slice() {
        [
            e6ircd::core::DbRequest::SetChannelTopic {
                channel,
                topic: Some((text, ..)),
                revision,
                ..
            },
        ] if channel == "#reg" && text == "new topic" => *revision,
        other => panic!("SetChannelTopic not queued once: {other:#?}"),
    };
    s.core.handle(Input::DbReply {
        conn: boss,
        reply: e6ircd::core::DbReply::ChannelTopicSet {
            channel: "#reg".into(),
            display: "#reg".into(),
            prefix: "boss!u@127.0.0.1".into(),
            topic: Some(("new topic".into(), "boss!u@127.0.0.1".into(), 1)),
            revision,
            retained: true,
            label: None,
        },
    });
    assert!(
        s.drain(boss)
            .iter()
            .any(|line| line.contains(" TOPIC #reg :new topic")),
        "registered TOPIC was not emitted after persistence"
    );

    // An unregistered channel does not persist its topic.
    s.line(boss, "JOIN #plain");
    s.drain(boss);
    s.db_requests();
    s.line(boss, "TOPIC #plain :whatever");
    s.drain(boss);
    let leaked = s
        .db_requests()
        .into_iter()
        .any(|r| matches!(r, e6ircd::core::DbRequest::SetChannelTopic { .. }));
    assert!(!leaked, "unregistered channel wrongly persisted its topic");
}

#[test]
fn registered_topic_failed_verdicts_are_loud_labeled_and_non_mutating() {
    let mut s = TestServer::new();
    s.core
        .preload_founders(vec![("#reg".to_string(), "boss".to_string())]);
    s.core.preload_topics(vec![(
        "#reg".to_string(),
        "old topic".to_string(),
        "old!setter@host".to_string(),
        1,
    )]);
    let boss = register_with_caps(&mut s, 1, "boss", "labeled-response");
    s.line(boss, "JOIN #reg");
    s.drain(boss);
    s.db_requests();

    s.line(boss, "@label=topic7 TOPIC #reg :new topic");
    assert!(
        s.drain(boss).is_empty(),
        "a durable TOPIC verdict must not be pre-ACKed"
    );
    let requests = s.db_requests();
    let revision = match requests.as_slice() {
        [
            e6ircd::core::DbRequest::SetChannelTopic {
                revision,
                label: Some(label),
                ..
            },
        ] if label == "topic7" => *revision,
        other => panic!("labeled TOPIC request lost its correlation: {other:#?}"),
    };
    s.core.handle(Input::DbReply {
        conn: boss,
        reply: e6ircd::core::DbReply::ChannelTopicFailed {
            channel: "#reg".into(),
            display: "#reg".into(),
            revision,
            label: Some("topic7".into()),
            failure: e6ircd::core::ChannelTopicFailure::PersistenceUnavailable,
        },
    });
    let out = s.drain(boss);
    assert!(
        out.iter().any(|line| {
            line.starts_with("@label=topic7 ")
                && line.contains("FAIL TOPIC TEMPORARILY_UNAVAILABLE")
        }),
        "store failure was not a correlated loud failure: {out:#?}"
    );

    s.line(boss, "TOPIC #reg");
    let out = s.drain(boss);
    assert!(
        out.iter()
            .any(|line| line.contains(" 332 ") && line.ends_with(":old topic")),
        "failed persistence changed the live topic: {out:#?}"
    );

    s.line(boss, "@label=topic8 TOPIC #reg :missing-row topic");
    let requests = s.db_requests();
    let revision = match requests.as_slice() {
        [e6ircd::core::DbRequest::SetChannelTopic { revision, .. }] => *revision,
        other => panic!("second TOPIC did not enter the persistence path: {other:#?}"),
    };
    s.core.handle(Input::DbReply {
        conn: boss,
        reply: e6ircd::core::DbReply::ChannelTopicFailed {
            channel: "#reg".into(),
            display: "#reg".into(),
            revision,
            label: Some("topic8".into()),
            failure: e6ircd::core::ChannelTopicFailure::MissingRegistration,
        },
    });
    let out = s.drain(boss);
    assert!(
        out.iter().any(|line| {
            line.starts_with("@label=topic8 ") && line.contains("FAIL TOPIC REGISTRATION_CHANGED")
        }),
        "a missing registration row was not distinguished from a store outage: {out:#?}"
    );
    s.line(boss, "TOPIC #reg");
    let out = s.drain(boss);
    assert!(
        out.iter()
            .any(|line| line.contains(" 332 ") && line.ends_with(":old topic")),
        "a missing registration row changed the live topic: {out:#?}"
    );
}

#[test]
fn committed_registered_topic_survives_the_live_channel_becoming_empty() {
    let mut s = TestServer::new();
    s.core
        .preload_founders(vec![("#reg".to_string(), "boss".to_string())]);
    let boss = s.register(1, "boss");
    identify(&mut s, boss, "boss");
    s.line(boss, "JOIN #reg");
    s.drain(boss);
    s.db_requests();

    s.line(boss, "TOPIC #reg :durable after empty");
    let requests = s.db_requests();
    let revision = match requests.as_slice() {
        [e6ircd::core::DbRequest::SetChannelTopic { revision, .. }] => *revision,
        other => panic!("registered TOPIC was not queued: {other:#?}"),
    };
    s.line(boss, "PART #reg");
    s.core.handle(Input::DbReply {
        conn: boss,
        reply: e6ircd::core::DbReply::ChannelTopicSet {
            channel: "#reg".into(),
            display: "#reg".into(),
            prefix: "boss!u@127.0.0.1".into(),
            topic: Some(("durable after empty".into(), "boss!u@127.0.0.1".into(), 1)),
            revision,
            retained: true,
            label: None,
        },
    });
    let out = s.drain(boss);
    assert!(
        out.iter()
            .any(|line| line.contains(" TOPIC #reg :durable after empty")),
        "a committed topic was not acknowledged after the live channel emptied: {out:#?}"
    );
    assert!(
        !out.iter().any(|line| line.contains(" 403 ")),
        "a committed topic was falsely reported as a missing channel: {out:#?}"
    );

    s.line(boss, "JOIN #reg");
    let out = s.drain(boss);
    assert!(
        out.iter()
            .any(|line| line.contains(" 332 ") && line.ends_with(":durable after empty")),
        "the committed topic was not restored when the registered channel was recreated: {out:#?}"
    );
}

#[test]
fn keeptopic_on_captures_a_topic_request_still_in_flight() {
    let mut s = TestServer::new();
    s.core
        .preload_founders(vec![("#reg".to_string(), "boss".to_string())]);
    s.core.preload_keeptopic_off(vec!["#reg".to_string()]);
    let boss = s.register(1, "boss");
    identify(&mut s, boss, "boss");
    s.line(boss, "JOIN #reg");
    s.drain(boss);
    s.db_requests();

    s.line(boss, "TOPIC #reg :pending topic");
    let topic_requests = s.db_requests();
    assert!(matches!(
        topic_requests.as_slice(),
        [e6ircd::core::DbRequest::SetChannelTopic { .. }]
    ));
    // The TOPIC verdict has not landed, so the committed live channel still
    // has no topic. KEEPTOPIC must nevertheless capture the pending request.
    s.line(boss, "PRIVMSG ChanServ :SET #reg KEEPTOPIC ON");
    let option_requests = s.db_requests();
    assert!(
        matches!(
            option_requests.as_slice(),
            [e6ircd::core::DbRequest::SetChannelKeeptopic {
                keeptopic: true,
                topic: Some((text, ..)),
                ..
            }] if text == "pending topic"
        ),
        "KEEPTOPIC captured stale committed state instead of the pending TOPIC: \
         {option_requests:#?}"
    );
}

#[test]
fn chanserv_set_keeptopic_off_stops_topic_retention() {
    let mut s = TestServer::new();
    s.core
        .preload_founders(vec![("#reg".to_string(), "boss".to_string())]);
    s.core.preload_topics(vec![(
        "#reg".to_string(),
        "old topic".to_string(),
        "boss!b@h".to_string(),
        1_000_000,
    )]);
    let boss = s.register(1, "boss");
    identify(&mut s, boss, "boss");
    s.line(boss, "JOIN #reg");
    s.drain(boss);
    s.db_requests();

    // Turn KEEPTOPIC off: no success is emitted before PostgreSQL confirms the
    // flag and retained-topic clear as one transition.
    s.line(boss, "PRIVMSG ChanServ :SET #reg KEEPTOPIC OFF");
    assert!(
        s.drain(boss).is_empty(),
        "KEEPTOPIC must wait for its durable verdict"
    );
    let reqs = s.db_requests();
    assert!(
        matches!(
            reqs.as_slice(),
            [e6ircd::core::DbRequest::SetChannelKeeptopic {
                channel,
                keeptopic: false,
                topic: None,
                ..
            }] if channel == "#reg"
        ),
        "KEEPTOPIC OFF must be one atomic request: {reqs:#?}"
    );
    s.channel_service_persisted(e6ircd::core::ChannelServicePersistence::KeeptopicSet {
        channel: "#reg".into(),
        display: "#reg".into(),
        keeptopic: false,
        topic: None,
        applied: true,
        label: None,
    });
    let out = s.drain(boss);
    assert!(
        out.iter()
            .any(|l| l.contains("KEEPTOPIC") && l.to_ascii_uppercase().contains("OFF")),
        "no KEEPTOPIC OFF confirmation: {out:#?}"
    );

    // TOPIC still crosses the DB boundary while KEEPTOPIC is off. PostgreSQL
    // returns `retained: false`, which orders this correctly against any
    // pipelined ON/OFF request while allowing the live topic to change.
    s.line(boss, "TOPIC #reg :while off");
    assert!(s.drain(boss).is_empty());
    let reqs = s.db_requests();
    assert!(
        reqs.iter().any(|r| matches!(r,
            e6ircd::core::DbRequest::SetChannelTopic { channel, topic: Some((text, ..)), .. }
            if channel == "#reg" && text == "while off")),
        "registered TOPIC did not enter the ordered persistence path"
    );
    s.core.handle(Input::DbReply {
        conn: boss,
        reply: e6ircd::core::DbReply::ChannelTopicSet {
            channel: "#reg".into(),
            display: "#reg".into(),
            prefix: "boss!u@127.0.0.1".into(),
            topic: Some(("while off".into(), "boss!u@127.0.0.1".into(), 1)),
            revision: 1,
            retained: false,
            label: None,
        },
    });
    assert!(
        s.drain(boss)
            .iter()
            .any(|line| line.contains(" TOPIC #reg :while off"))
    );

    // Turning it back on atomically captures the current live topic.
    s.line(boss, "PRIVMSG ChanServ :SET #reg KEEPTOPIC ON");
    assert!(s.drain(boss).is_empty());
    let reqs = s.db_requests();
    assert!(reqs.iter().any(|r| matches!(r,
        e6ircd::core::DbRequest::SetChannelKeeptopic {
            channel,
            keeptopic: true,
            topic: Some((text, ..)),
            ..
        } if channel == "#reg" && text == "while off"
    )));
    s.channel_service_persisted(e6ircd::core::ChannelServicePersistence::KeeptopicSet {
        channel: "#reg".into(),
        display: "#reg".into(),
        keeptopic: true,
        topic: Some(("while off".into(), "boss!u@127.0.0.1".into(), 1)),
        applied: true,
        label: None,
    });
    s.drain(boss);
    s.line(boss, "TOPIC #reg :back on");
    assert!(s.drain(boss).is_empty());
    assert!(
        s.db_requests().into_iter().any(|r| matches!(r,
            e6ircd::core::DbRequest::SetChannelTopic { channel, topic: Some((text, ..)), .. }
            if channel == "#reg" && text == "back on")),
        "topic not persisted after KEEPTOPIC ON"
    );
}

/// Turning KEEPTOPIC back ON re-captures the channel's *current* live topic
/// immediately — the TOPIC path persists only on change and OFF dropped the
/// retained copy, so without the recapture the live topic would be silently
/// lost on the next empty→recreate cycle.
#[test]
fn chanserv_set_keeptopic_on_recaptures_the_live_topic() {
    let mut s = TestServer::new();
    s.core
        .preload_founders(vec![("#reg".to_string(), "boss".to_string())]);
    let boss = s.register(1, "boss");
    identify(&mut s, boss, "boss");
    s.line(boss, "JOIN #reg");
    s.drain(boss);
    s.line(boss, "PRIVMSG ChanServ :SET #reg KEEPTOPIC OFF");
    s.db_requests();
    s.channel_service_persisted(e6ircd::core::ChannelServicePersistence::KeeptopicSet {
        channel: "#reg".into(),
        display: "#reg".into(),
        keeptopic: false,
        topic: None,
        applied: true,
        label: None,
    });
    s.drain(boss);
    // A topic set while KEEPTOPIC is off: live, but not retained.
    s.line(boss, "TOPIC #reg :the live topic");
    s.db_requests();
    s.core.handle(Input::DbReply {
        conn: boss,
        reply: e6ircd::core::DbReply::ChannelTopicSet {
            channel: "#reg".into(),
            display: "#reg".into(),
            prefix: "boss!u@127.0.0.1".into(),
            topic: Some(("the live topic".into(), "boss!u@127.0.0.1".into(), 1)),
            revision: 1,
            retained: false,
            label: None,
        },
    });
    s.drain(boss);
    // Turning KEEPTOPIC back on must persist the current live topic right away,
    // in the same option write, with no second fallible request.
    s.line(boss, "PRIVMSG ChanServ :SET #reg KEEPTOPIC ON");
    assert!(s.drain(boss).is_empty());
    assert!(
        s.db_requests().into_iter().any(|r| matches!(r,
            e6ircd::core::DbRequest::SetChannelKeeptopic {
                channel,
                keeptopic: true,
                topic: Some((text, ..)),
                ..
            }
            if channel == "#reg" && text == "the live topic")),
        "KEEPTOPIC ON did not re-capture the current live topic"
    );
}

#[test]
fn chanserv_set_mlock_enforces_modes() {
    let mut s = TestServer::new();
    s.core
        .preload_founders(vec![("#reg".to_string(), "boss".to_string())]);
    let boss = s.register(1, "boss");
    identify(&mut s, boss, "boss");
    s.line(boss, "JOIN #reg"); // op; channel created with default +nt
    s.drain(boss);
    s.db_requests();

    // A bad lock char is rejected loudly, not stored.
    s.line(boss, "PRIVMSG ChanServ :SET #reg MLOCK +k");
    assert!(
        s.drain(boss)
            .iter()
            .any(|l| l.contains("not a lockable mode")),
        "bad mlock char not rejected"
    );
    assert!(
        s.db_requests()
            .into_iter()
            .all(|r| !matches!(r, e6ircd::core::DbRequest::SetChannelMlock { .. })),
        "rejected mlock was persisted"
    );

    // Lock +m-t: m forced on, t forced off — applied to the live channel now.
    s.line(boss, "PRIVMSG ChanServ :SET #reg MLOCK +m-t");
    assert!(
        s.drain(boss).is_empty(),
        "MLOCK must not confirm before the durable verdict"
    );
    let reqs = s.db_requests();
    assert!(
        reqs.iter().any(|r| matches!(r,
            e6ircd::core::DbRequest::SetChannelMlock { channel, mlock: Some(spec), .. }
            if channel == "#reg" && spec == "+m-t")),
        "mlock not persisted"
    );
    s.channel_service_persisted(e6ircd::core::ChannelServicePersistence::MlockSet {
        channel: "#reg".into(),
        display: "#reg".into(),
        mlock: Some("+m-t".into()),
        applied: true,
        label: None,
    });
    let out = s.drain(boss);
    assert!(
        out.iter()
            .any(|l| l.contains("MLOCK") && l.contains("+m-t")),
        "no MLOCK confirmation: {out:#?}"
    );
    assert!(
        out.iter()
            .any(|l| l.starts_with(":ChanServ MODE #reg") && l.contains("+m") && l.contains("-t")),
        "lock not applied on set: {out:#?}"
    );

    // Changing a locked mode the wrong way is refused (no MODE echo) AND the
    // refusal is loud — ERR_MLOCKRESTRICTED (742), not a silent no-op (DESIGN §2).
    s.line(boss, "MODE #reg -m");
    let out = s.drain(boss);
    assert!(
        !out.iter().any(|l| l.contains(" MODE ")),
        "locked -m was allowed: {out:#?}"
    );
    assert!(
        out.iter().any(|l| l.contains(" 742 ") && l.contains("-m")),
        "locked -m must be refused loudly with ERR_MLOCKRESTRICTED: {out:#?}"
    );
    s.line(boss, "MODE #reg +t");
    let out = s.drain(boss);
    assert!(
        !out.iter().any(|l| l.contains(" MODE ")),
        "locked +t was allowed: {out:#?}"
    );
    assert!(
        out.iter().any(|l| l.contains(" 742 ") && l.contains("+t")),
        "locked +t must be refused loudly: {out:#?}"
    );

    // A mixed change applies only the unlocked part (+C), not the locked -m.
    s.line(boss, "MODE #reg -m+C");
    let out = s.drain(boss);
    assert!(
        out.iter()
            .any(|l| l.contains(" MODE #reg ") && l.contains("+C") && !l.contains("-m")),
        "mixed change wrong: {out:#?}"
    );

    // Recreate: the last member parts (channel empties) then rejoins → the
    // lock is re-applied so its modes survive the channel going empty.
    s.line(boss, "PART #reg");
    s.drain(boss);
    s.line(boss, "JOIN #reg");
    let out = s.drain(boss);
    assert!(
        out.iter()
            .any(|l| l.starts_with(":ChanServ MODE #reg") && l.contains("+m") && l.contains("-t")),
        "lock not re-applied on recreate: {out:#?}"
    );
}

#[test]
fn corrupt_or_noncanonical_persisted_mlock_aborts_preload() {
    for spec in ["+k", "+tn", ""] {
        let mut s = TestServer::new();
        assert!(
            s.core
                .preload_mlock(vec![("#reg".into(), spec.into())])
                .is_err(),
            "persisted MLOCK {spec:?} was silently accepted"
        );
    }
}

#[test]
fn chanserv_metadata_store_failures_are_loud_labeled_and_non_mutating() {
    let mut s = TestServer::new();
    s.core
        .preload_founders(vec![("#reg".to_string(), "boss".to_string())]);
    s.core.preload_topics(vec![(
        "#reg".to_string(),
        "retained".to_string(),
        "boss!u@host".to_string(),
        1,
    )]);
    s.core
        .preload_mlock(vec![("#reg".to_string(), "+m".to_string())])
        .expect("valid MLOCK");
    let boss = register_with_caps(&mut s, 1, "boss", "labeled-response");
    identify(&mut s, boss, "boss");
    s.line(boss, "JOIN #reg");
    s.drain(boss);
    s.db_requests();

    s.line(
        boss,
        "@label=keep9 PRIVMSG ChanServ :SET #reg KEEPTOPIC OFF",
    );
    assert!(s.drain(boss).is_empty());
    assert!(matches!(
        s.db_requests().as_slice(),
        [e6ircd::core::DbRequest::SetChannelKeeptopic {
            label: Some(label),
            ..
        }] if label == "keep9"
    ));
    s.channel_service_persisted(
        e6ircd::core::ChannelServicePersistence::KeeptopicUnavailable {
            channel: "#reg".into(),
            display: "#reg".into(),
            label: Some("keep9".into()),
        },
    );
    let out = s.drain(boss);
    assert!(
        out.iter().any(|line| {
            line.starts_with("@label=keep9 ")
                && line.contains("KEEPTOPIC")
                && line.contains("temporarily unavailable")
        }),
        "KEEPTOPIC failure was not loud and correlated: {out:#?}"
    );

    s.line(boss, "@label=lock9 PRIVMSG ChanServ :SET #reg MLOCK OFF");
    assert!(s.drain(boss).is_empty());
    assert!(matches!(
        s.db_requests().as_slice(),
        [e6ircd::core::DbRequest::SetChannelMlock {
            label: Some(label),
            mlock: None,
            ..
        }] if label == "lock9"
    ));
    s.channel_service_persisted(e6ircd::core::ChannelServicePersistence::MlockUnavailable {
        channel: "#reg".into(),
        display: "#reg".into(),
        label: Some("lock9".into()),
    });
    let out = s.drain(boss);
    assert!(
        out.iter().any(|line| {
            line.starts_with("@label=lock9 ")
                && line.contains("MLOCK")
                && line.contains("temporarily unavailable")
        }),
        "MLOCK failure was not loud and correlated: {out:#?}"
    );

    // Neither failed write changed the committed hot state.
    s.line(boss, "MODE #reg -m");
    assert!(
        s.drain(boss)
            .iter()
            .any(|line| line.contains(" 742 ") && line.contains("-m")),
        "failed MLOCK clear removed the live lock"
    );
    s.line(boss, "PART #reg");
    s.drain(boss);
    s.line(boss, "JOIN #reg");
    let out = s.drain(boss);
    assert!(
        out.iter()
            .any(|line| line.contains(" 332 ") && line.ends_with(":retained")),
        "failed KEEPTOPIC update removed the retained topic: {out:#?}"
    );
}

#[test]
fn multiline_batch_is_one_message_to_capable_and_flattened_to_others() {
    // A multiline message is one message: both forms carry the same msgid, the
    // batch keeps the sender's blank lines and concat tags, and a client
    // without the capability gets one message per non-blank line because it has
    // no way to represent a line break inside a PRIVMSG.
    let mut s = TestServer::new_no_persistence();
    let alice = register_with_caps(
        &mut s,
        1,
        "alice",
        "batch draft/multiline message-tags echo-message server-time",
    );
    let bob = register_with_caps(&mut s, 2, "bob", "batch draft/multiline message-tags");
    let carol = register_with_caps(&mut s, 3, "carol", "message-tags");
    for c in [alice, bob, carol] {
        s.line(c, "JOIN #m");
    }
    // Drain after every join, so no one is still holding another's JOIN.
    for c in [alice, bob, carol] {
        s.drain(c);
    }
    s.line(alice, "BATCH +99 draft/multiline #m");
    s.line(alice, "@batch=99 PRIVMSG #m :hello");
    s.line(alice, "@batch=99 PRIVMSG #m :");
    s.line(alice, "@batch=99;draft/multiline-concat PRIVMSG #m :world");
    s.line(alice, "BATCH -99");

    let capable = s.drain(bob);
    assert!(capable[0].contains("BATCH +"), "{capable:#?}");
    assert!(
        capable[capable.len() - 1].contains("BATCH -"),
        "{capable:#?}"
    );
    let inner: Vec<_> = capable[1..capable.len() - 1].to_vec();
    assert_eq!(
        inner.len(),
        3,
        "blank line is kept in the batch: {capable:#?}"
    );
    assert!(inner[2].contains("draft/multiline-concat"), "{}", inner[2]);
    // The msgid identifies the message, so it is on the batch, not the lines.
    let batch_msgid = capable[0]
        .trim_start_matches('@')
        .split(' ')
        .next()
        .expect("tag section")
        .split(';')
        .find_map(|t| t.strip_prefix("msgid="))
        .expect("msgid on the batch open")
        .to_string();
    for line in &inner {
        assert!(
            !line.contains("msgid="),
            "inner lines carry no msgid: {line}"
        );
    }

    // Without the capability: no batch, blank line dropped, msgid on the first.
    let flat = s.drain(carol);
    assert!(!flat.iter().any(|l| l.contains("BATCH")), "{flat:#?}");
    assert_eq!(flat.len(), 2, "blank line dropped: {flat:#?}");
    assert!(flat[0].ends_with(":hello"), "{}", flat[0]);
    assert!(flat[1].ends_with(":world"), "{}", flat[1]);
    assert!(
        flat[0].contains(&format!("msgid={batch_msgid}")),
        "the flattened form is the same message: {}",
        flat[0]
    );
    assert!(!flat[1].contains("msgid="), "{}", flat[1]);
    assert!(
        !flat.iter().any(|l| l.contains("draft/multiline-concat")),
        "concat is meaningless without the capability: {flat:#?}"
    );
}

#[test]
fn failed_multiline_batch_answers_the_label_that_opened_it() {
    // The batch is the response owed to the command that opened it, so if that
    // command was labeled the failure has to carry the label — otherwise a
    // client tracking labels waits forever for a response that never comes.
    let mut s = TestServer::new_no_persistence();
    let alice = register_with_caps(
        &mut s,
        1,
        "alice",
        "batch draft/multiline message-tags labeled-response",
    );
    s.line(alice, "JOIN #m");
    s.drain(alice);
    s.line(alice, "@label=abc BATCH +9 draft/multiline #m");
    // Nothing is owed yet: the batch is still being assembled.
    assert!(
        s.drain(alice).is_empty(),
        "an opened batch is not yet a response"
    );
    s.line(alice, "@batch=9;draft/multiline-concat PRIVMSG #m :");
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|l| l.starts_with("@label=abc ") && l.contains("FAIL BATCH MULTILINE_INVALID")),
        "the failure must answer the labeled BATCH: {out:#?}"
    );
}

#[test]
fn successful_labeled_multiline_without_echo_gets_a_labeled_ack() {
    // A client with labeled-response + multiline but NOT echo-message completes
    // a labeled multiline batch. The label normally rides the sender's echo
    // copy, which doesn't exist without echo-message, so the server must send a
    // labeled ACK — otherwise the client waits forever for its response.
    let mut s = TestServer::new_no_persistence();
    let alice = register_with_caps(
        &mut s,
        1,
        "alice",
        "batch draft/multiline message-tags labeled-response",
    );
    let bob = s.register(2, "bob");
    for c in [alice, bob] {
        s.line(c, "JOIN #m");
        s.drain(c);
    }
    s.drain(alice);
    s.line(alice, "@label=abc BATCH +9 draft/multiline #m");
    assert!(
        s.drain(alice).is_empty(),
        "opening the batch owes nothing yet"
    );
    s.line(alice, "@batch=9 PRIVMSG #m :hello");
    s.line(alice, "BATCH -9");
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|l| l.starts_with("@label=abc ") && l.contains("ACK")),
        "the completed labeled batch must be answered with a labeled ACK: {out:#?}"
    );
    // The message is still delivered to the other member.
    assert!(
        s.drain(bob).iter().any(|l| l.contains("PRIVMSG #m :hello")),
        "the message is still delivered to members"
    );
}

/// A client with echo-message that labels the BATCH *close* separately from the
/// open must not get two `label=` tags on its multiline echo. The echo carries
/// the open's label inline; before the fix the close command's capture swallowed
/// it and injected its own label too, corrupting the response and robbing the
/// close of its own ACK.
#[test]
fn labeled_batch_close_with_echo_does_not_double_label_the_echo() {
    let mut s = TestServer::new_no_persistence();
    let alice = register_with_caps(
        &mut s,
        1,
        "alice",
        "batch draft/multiline message-tags labeled-response echo-message",
    );
    s.line(alice, "JOIN #m");
    s.drain(alice);

    s.line(alice, "@label=1 BATCH +9 draft/multiline #m");
    assert!(
        s.drain(alice).is_empty(),
        "opening the batch owes nothing yet"
    );
    s.line(alice, "@batch=9 PRIVMSG #m :hi");
    s.line(alice, "@label=2 BATCH -9");
    let out = s.drain(alice);

    // The echoed batch-open (the labeled response to the OPEN) carries exactly
    // one label tag — the open's `label=1` — never `label=2;label=1`.
    let echo_open = out
        .iter()
        .find(|l| l.contains("BATCH +") && l.contains("draft/multiline"))
        .expect("echoed multiline batch open");
    assert_eq!(
        echo_open.matches("label=").count(),
        1,
        "the multiline echo must carry one label, not the close's too: {echo_open}"
    );
    assert!(
        echo_open.contains("label=1"),
        "it carries the OPEN's label: {echo_open}"
    );
    // The CLOSE command gets its own labeled ACK.
    assert!(
        out.iter()
            .any(|l| l.starts_with("@label=2 ") && l.contains("ACK")),
        "the labeled close gets its own ACK: {out:#?}"
    );
}

#[test]
fn batch_reference_with_a_multibyte_first_character_is_refused_not_fatal() {
    // The leading `+`/`-` is one *character*, not one byte. Splitting the
    // reference by byte landed inside a multi-byte character and panicked the
    // core worker — reachable by any registered client, and fatal to everyone
    // on the server, not just the sender.
    let mut s = TestServer::new_no_persistence();
    let alice = register_with_caps(&mut s, 1, "alice", "batch draft/multiline message-tags");
    s.drain(alice);
    // (A NUL never gets this far — the line framer rejects it as malformed.)
    for reference in ["\u{61c}CH1", "é+1", "\u{1f600}", "字"] {
        s.line(alice, &format!("BATCH {reference} draft/multiline #c"));
        let out = s.drain(alice);
        assert!(
            out.iter().any(|l| l.contains("FAIL BATCH")),
            "reference {reference:?} must be refused: {out:#?}"
        );
    }
    // The connection is still usable afterwards.
    s.line(alice, "PING :alive");
    assert!(
        s.drain(alice).iter().any(|l| l.contains("PONG")),
        "the worker must survive a malformed batch reference"
    );
}

#[test]
fn multiline_batch_may_not_mix_privmsg_and_notice() {
    // NOTICE exists to say "never reply to this automatically". A batch is one
    // message, so it cannot be half notice — and relaying a NOTICE line as a
    // PRIVMSG would hand recipients a message the sender never wrote.
    let mut s = TestServer::new_no_persistence();
    let caps = "batch draft/multiline message-tags";
    let alice = register_with_caps(&mut s, 1, "alice", caps);
    let bob = register_with_caps(&mut s, 2, "bob", caps);
    for c in [alice, bob] {
        s.line(c, "JOIN #m");
    }
    for c in [alice, bob] {
        s.drain(c);
    }
    s.line(alice, "BATCH +1 draft/multiline #m");
    s.line(alice, "@batch=1 PRIVMSG #m :as privmsg");
    s.line(alice, "@batch=1 NOTICE #m :as notice");
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|l| l.contains("FAIL BATCH MULTILINE_INVALID")),
        "{out:#?}"
    );
    s.line(alice, "BATCH -1");
    s.drain(alice);
    let relayed = s.drain(bob);
    assert!(
        relayed.is_empty(),
        "a rejected batch relays nothing at all: {relayed:#?}"
    );
}

#[test]
fn tagmsg_may_not_claim_membership_of_a_multiline_batch() {
    // A multiline batch carries PRIVMSG and NOTICE only. Delivering a
    // batch-tagged TAGMSG on its own would take it out of the message being
    // assembled and send it *before* that message.
    let mut s = TestServer::new_no_persistence();
    let caps = "batch draft/multiline message-tags";
    let alice = register_with_caps(&mut s, 1, "alice", caps);
    let bob = register_with_caps(&mut s, 2, "bob", caps);
    for c in [alice, bob] {
        s.line(c, "JOIN #m");
    }
    for c in [alice, bob] {
        s.drain(c);
    }
    s.line(alice, "BATCH +2 draft/multiline #m");
    s.line(alice, "@batch=2;+x=1 TAGMSG #m");
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|l| l.contains("FAIL BATCH MULTILINE_INVALID")),
        "{out:#?}"
    );
    assert!(
        !s.drain(bob).iter().any(|l| l.contains("TAGMSG")),
        "the TAGMSG must not escape the batch it claimed"
    );

    // An untagged TAGMSG is unaffected.
    s.line(alice, "@+x=1 TAGMSG #m");
    s.drain(alice);
    assert!(
        s.drain(bob).iter().any(|l| l.contains("TAGMSG #m")),
        "a plain TAGMSG still works"
    );
}

#[test]
fn multiline_batch_permissions_match_a_plain_message() {
    // Splitting text across a batch must not evade the checks a single message
    // faces: the batch is refused for the same reason, and nothing is relayed.
    let mut s = TestServer::new_no_persistence();
    let caps = "batch draft/multiline message-tags";
    let alice = register_with_caps(&mut s, 1, "alice", caps);
    let bob = register_with_caps(&mut s, 2, "bob", caps);
    s.line(bob, "JOIN #locked");
    s.line(bob, "MODE #locked +m");
    s.drain(bob);
    s.line(alice, "JOIN #locked");
    s.drain(alice);

    s.line(alice, "BATCH +7 draft/multiline #locked");
    s.line(alice, "@batch=7 PRIVMSG #locked :let me in");
    s.line(alice, "BATCH -7");
    let out = s.drain(alice);
    assert!(
        out.iter().any(|l| l.contains("404")),
        "a moderated channel refuses the batch too: {out:#?}"
    );
    assert!(
        !s.drain(bob).iter().any(|l| l.contains("let me in")),
        "nothing may be relayed from a refused batch"
    );
}

#[test]
fn multiline_batch_abandoned_on_error_delivers_nothing() {
    // A batch that went wrong delivers nothing at all rather than a truncated
    // version of what the sender meant.
    let mut s = TestServer::new_no_persistence();
    let caps = "batch draft/multiline message-tags";
    let alice = register_with_caps(&mut s, 1, "alice", caps);
    let bob = register_with_caps(&mut s, 2, "bob", caps);
    for c in [alice, bob] {
        s.line(c, "JOIN #m");
        s.drain(c);
    }
    s.line(alice, "BATCH +5 draft/multiline #m");
    s.line(alice, "@batch=5 PRIVMSG #m :first");
    // Concat on a blank line is invalid, and abandons the batch.
    s.line(alice, "@batch=5;draft/multiline-concat PRIVMSG #m :");
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|l| l.contains("FAIL BATCH MULTILINE_INVALID")),
        "{out:#?}"
    );
    // Closing the abandoned batch is itself an error, and still sends nothing.
    s.line(alice, "BATCH -5");
    s.drain(alice);
    assert!(
        !s.drain(bob).iter().any(|l| l.contains("first")),
        "an abandoned batch must deliver nothing"
    );
}

#[test]
fn register_command_refuses_a_name_other_than_the_callers_nick() {
    // `custom-account-name` is not advertised, so REGISTER may only claim the
    // nick the caller is currently holding — otherwise a client could register
    // a name it has never proven it can hold.
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "draft/account-registration");
    s.drain(alice);
    s.line(alice, "REGISTER bob * hunter2");
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|l| l.contains("FAIL REGISTER ACCOUNT_NAME_MUST_BE_NICK bob")),
        "{out:#?}"
    );
    assert!(
        s.db_requests().is_empty(),
        "a refused registration must never reach the database"
    );

    // `*` and the caller's own nick both name the caller's account.
    for arg in ["*", "alice"] {
        s.line(alice, &format!("REGISTER {arg} * hunter2"));
        s.drain(alice);
        assert_eq!(
            s.db_requests(),
            vec![e6ircd::core::DbRequest::CreateAccount {
                conn: alice,
                name: "alice".into(),
                contact_email: None,
                password: "hunter2".into(),
                origin: e6ircd::core::AccountOrigin::RegisterCommand,
            }],
            "REGISTER {arg} must register the caller's own nick"
        );
        // Resolve the in-flight registration (as "already exists": clears the
        // pending-register guard without logging the session in) so the next
        // iteration is a fresh attempt, not a refused duplicate.
        s.core.handle(Input::DbReply {
            conn: alice,
            reply: e6ircd::core::DbReply::AccountExists {
                origin: e6ircd::core::AccountOrigin::RegisterCommand,
            },
        });
        s.drain(alice);
    }
}

#[test]
fn register_before_connect_is_refused_unless_enabled() {
    // A connection that has not completed registration has not proven it can
    // hold the nick it is asking to register, so this is opt-in — and the
    // refusal is the spec's code, not a bare "you have not registered".
    let mut s = TestServer::new();
    let conn = s.connect(1);
    s.line(conn, "NICK earlybird");
    s.drain(conn);
    s.line(conn, "REGISTER * * hunter2");
    let out = s.drain(conn);
    assert!(
        out.iter()
            .any(|l| l.contains("FAIL REGISTER COMPLETE_CONNECTION_REQUIRED")),
        "{out:#?}"
    );
    assert!(s.db_requests().is_empty());
}

#[test]
fn register_reply_waits_behind_nothing_but_arrives_in_order() {
    // The answer needs a database round trip, so the connection's later output
    // is held behind it: a client that pipelines REGISTER and PING must not see
    // the PONG first and conclude the registration produced no reply.
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "draft/account-registration");
    s.drain(alice);
    s.line(alice, "REGISTER * * hunter2");
    s.line(alice, "PING :sync");
    let before = s.drain(alice);
    assert!(
        before.is_empty(),
        "output must wait for the pending registration reply: {before:#?}"
    );
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::AccountCreated {
            account: "alice".into(),
            origin: e6ircd::core::AccountOrigin::RegisterCommand,
        },
    });
    let out = s.drain(alice);
    let register = out
        .iter()
        .position(|l| l.contains("REGISTER SUCCESS alice"))
        .expect("registration reply");
    let pong = out
        .iter()
        .position(|l| l.contains("PONG"))
        .expect("pong released after it");
    assert!(
        register < pong,
        "reply order must match command order: {out:#?}"
    );
}

#[test]
fn output_held_behind_a_deferred_reply_is_bounded_like_the_sendq() {
    // A CHATHISTORY page that reaches PostgreSQL is answered asynchronously,
    // and the connection's later output waits behind it so replies stay in
    // command order. That held output has not entered the send queue yet, so
    // it must carry the same bound: without one, a connection waiting on the
    // database could accumulate lines without limit and escape the SendQ kill.
    const SENDQ: usize = 8;
    const FLOOD: usize = 200;
    let mut s = TestServer::with_sendq(SENDQ);
    // echo-message so the connection's own traffic is output *to it*, which is
    // what accumulates behind the hold.
    let alice = register_with_caps(
        &mut s,
        1,
        "alice",
        "batch draft/chathistory message-tags echo-message",
    );
    s.line(alice, "JOIN #room");
    s.drain(alice);
    // Defer a reply: nothing drains the fake DB queue, so the hold stays open.
    s.line(alice, "CHATHISTORY LATEST #room * 50");
    s.drain(alice);
    for i in 0..FLOOD {
        s.line(alice, &format!("PRIVMSG #room :flood {i}"));
    }
    // Now let the deferred reply land, which releases whatever was held.
    s.core.handle(Input::HistoryPage {
        conn: alice,
        display: "#room".into(),
        batch_ref: "b1".into(),
        rows: Ok(Vec::new()),
        label: None,
    });
    let released = s.drain(alice).len();
    assert!(
        released < FLOOD,
        "held output must be bounded, not buffer the whole flood: {released} lines"
    );
}

#[test]
fn history_logmessage_gated_on_database() {
    // A channel message enqueues a LogMessage to persist history only when
    // a database is present. Without one, every enqueue would fail (no db
    // worker drains the queue) and log per-message, flooding stderr and
    // starving the core worker — so it must be skipped entirely.
    fn logs_a_message(sasl_enabled: bool) -> bool {
        let (db_tx, mut db_rx) = queue(Config {
            name: "d",
            capacity: 64,
            policy: Policy::Fifo,
        });
        let mut core = Core::new(
            CoreConfig {
                server_name: "irc.test.example".into(),
                network_name: "T".into(),
                description: "test server".into(),
                registration_before_connect: false,
                registration_require_email: false,
                sendq: 256,
                motd: vec![],
                nicklen: 16,
                sasl_enabled,
                opers: vec![],
                max_hot_channels: 8,
                clock: || Millis::from_millis(1_000_000_000),
                mono_clock: test_mono,
                command_burst: None,
                registration_burst: None,
            },
            db_tx,
        );
        let conn = ConnId(1);
        let (tx, _rx) = queue(Config {
            name: "s",
            capacity: 512,
            policy: Policy::Fifo,
        });
        core.handle(Input::Open {
            conn,
            tx,
            host: "h".into(),
            transport: e6ircd::core::ConnectionTransport::Tcp,
        });
        for line in ["NICK a", "USER a 0 * :A", "JOIN #c", "PRIVMSG #c :hello"] {
            core.handle(Input::Line {
                conn,
                line: line.as_bytes().to_vec(),
            });
        }
        let mut saw = false;
        while let Some(env) = db_rx.try_pop() {
            if matches!(env.payload, e6ircd::core::DbRequest::LogMessage { .. }) {
                saw = true;
            }
        }
        saw
    }
    assert!(
        logs_a_message(true),
        "history not persisted when a database is present"
    );
    assert!(
        !logs_a_message(false),
        "history enqueued despite no database (stderr-flood risk)"
    );
}

// NickServ GHOST + ChanServ DROP (DESIGN §7.6).

#[test]
fn nickserv_ghost_disconnects_stale_session() {
    let mut s = TestServer::new();
    let ghost = s.register(1, "alice");
    identify(&mut s, ghost, "alice");

    // A second session, identified to the same account under a different
    // nick, ghosts the stale one.
    let user = s.register(2, "alice2");
    identify(&mut s, user, "alice");
    s.line(user, "PRIVMSG NickServ :GHOST alice");
    let out = s.drain(user);
    assert!(
        out.iter().any(|l| l.contains("has been ghosted")),
        "no ghost confirmation: {out:#?}"
    );
    // The stale session was sent a closing ERROR.
    let ghost_out = s.drain(ghost);
    assert!(
        ghost_out.iter().any(|l| l.starts_with("ERROR :")),
        "ghost not disconnected: {ghost_out:#?}"
    );

    // You cannot ghost a nick you do not own.
    let mallory = s.register(3, "mallory");
    identify(&mut s, mallory, "mallory");
    s.line(mallory, "PRIVMSG NickServ :GHOST alice2");
    assert!(
        s.drain(mallory).iter().any(|l| l.contains("do not own")),
        "ghost of un-owned nick should be refused"
    );
}

#[test]
fn chanserv_drop_unregisters_channel() {
    let mut s = TestServer::new();
    s.core
        .preload_founders(vec![("#room".to_string(), "boss".to_string())]);
    let boss = s.register(1, "boss");
    identify(&mut s, boss, "boss");
    s.db_requests();

    s.line(boss, "PRIVMSG ChanServ :DROP #room");
    assert!(
        s.drain(boss).is_empty(),
        "DROP must not confirm before PostgreSQL deletes the row"
    );
    let requester = s
        .db_requests()
        .into_iter()
        .find_map(|request| match request {
            e6ircd::core::DbRequest::DropChannel {
                owner,
                channel,
                requester,
            } if channel == "#room" => Some((owner, requester)),
            _ => None,
        });
    let Some((owner, requester)) = requester else {
        panic!("DropChannel not queued");
    };
    let (session, display, label) = match &requester {
        e6ircd::core::ChannelDropRequester::ChanServ {
            session,
            display,
            label,
        } => (*session, display.clone(), label.clone()),
        e6ircd::core::ChannelDropRequester::Admin { .. } => {
            panic!("ChanServ DROP lost its requester session")
        }
    };
    s.core.handle(Input::ChannelDropResult {
        owner,
        channel: "#room".into(),
        requester,
        result: e6ircd::core::ChannelDropResult::Dropped,
    });
    s.core.handle(Input::ChannelDropReply {
        session,
        display,
        label,
        result: e6ircd::core::ChannelDropResult::Dropped,
    });
    let out = s.drain(boss);
    assert!(
        out.iter().any(|l| l.contains("has been dropped")),
        "no committed drop confirmation: {out:#?}"
    );

    // Registration is gone from the hot map: a second DROP is refused.
    s.line(boss, "PRIVMSG ChanServ :DROP #room");
    assert!(
        s.drain(boss).iter().any(|l| l.contains("not the founder")),
        "channel still registered after drop"
    );
}

#[test]
fn chanserv_drop_clears_the_mode_lock() {
    // DROP deletes the whole `channels` DB row, which carries the mode lock, so
    // the hot channel_mlock must be cleared too — otherwise recreating the
    // channel reapplies a stale lock the DB no longer holds.
    let mut s = TestServer::new();
    s.core
        .preload_founders(vec![("#reg2".to_string(), "boss".to_string())]);
    s.core
        .preload_mlock(vec![("#reg2".to_string(), "+s".to_string())])
        .expect("valid MLOCK");
    let boss = s.register(1, "boss");
    identify(&mut s, boss, "boss");
    s.db_requests();

    // First join: the registered+mlocked channel forces +s.
    s.line(boss, "JOIN #reg2");
    assert!(
        s.drain(boss)
            .iter()
            .any(|l| l.contains("MODE #reg2") && l.contains("+s")),
        "the mode lock is applied on the registered channel"
    );

    // Drop it, empty it, then recreate it.
    s.line(boss, "PRIVMSG ChanServ :DROP #reg2");
    assert!(s.drain(boss).is_empty());
    let requester = s
        .db_requests()
        .into_iter()
        .find_map(|request| match request {
            e6ircd::core::DbRequest::DropChannel {
                owner, requester, ..
            } => Some((owner, requester)),
            _ => None,
        });
    let Some((owner, requester)) = requester else {
        panic!("DropChannel not queued");
    };
    s.core.handle(Input::ChannelDropResult {
        owner,
        channel: "#reg2".into(),
        requester,
        result: e6ircd::core::ChannelDropResult::Dropped,
    });
    s.drain(boss);
    s.line(boss, "PART #reg2");
    s.drain(boss);
    s.line(boss, "JOIN #reg2");
    assert!(
        !s.drain(boss)
            .iter()
            .any(|l| l.contains("MODE #reg2") && l.contains("+s")),
        "a stale mode lock must not be reapplied to a dropped-and-recreated channel"
    );
}

#[test]
fn chanserv_drop_store_failure_is_loud_labeled_and_non_mutating() {
    let mut s = TestServer::new();
    s.core
        .preload_founders(vec![("#room".to_string(), "boss".to_string())]);
    let boss = register_with_caps(&mut s, 1, "boss", "labeled-response");
    identify(&mut s, boss, "boss");
    s.db_requests();

    s.line(boss, "@label=drop7 PRIVMSG ChanServ :DROP #room");
    assert!(s.drain(boss).is_empty());
    let requester = s
        .db_requests()
        .into_iter()
        .find_map(|request| match request {
            e6ircd::core::DbRequest::DropChannel {
                owner, requester, ..
            } if matches!(
                &requester,
                e6ircd::core::ChannelDropRequester::ChanServ {
                    label: Some(label),
                    ..
                } if label == "drop7"
            ) =>
            {
                Some((owner, requester))
            }
            _ => None,
        });
    let Some((owner, requester)) = requester else {
        panic!("labeled DropChannel not queued");
    };
    let (session, display, label) = match &requester {
        e6ircd::core::ChannelDropRequester::ChanServ {
            session,
            display,
            label,
        } => (*session, display.clone(), label.clone()),
        e6ircd::core::ChannelDropRequester::Admin { .. } => {
            panic!("ChanServ DROP lost its requester session")
        }
    };
    s.core.handle(Input::ChannelDropResult {
        owner,
        channel: "#room".into(),
        requester,
        result: e6ircd::core::ChannelDropResult::Unavailable,
    });
    s.core.handle(Input::ChannelDropReply {
        session,
        display,
        label,
        result: e6ircd::core::ChannelDropResult::Unavailable,
    });
    let out = s.drain(boss);
    assert!(
        out.iter().any(|line| {
            line.starts_with("@label=drop7 ") && line.contains("temporarily unavailable")
        }),
        "DROP failure was not loud and correlated: {out:#?}"
    );

    // The founder entry survived the failed delete, so retrying reaches the DB
    // instead of being refused as an already-dropped channel.
    s.line(boss, "PRIVMSG ChanServ :DROP #room");
    assert!(matches!(
        s.db_requests().as_slice(),
        [e6ircd::core::DbRequest::DropChannel { .. }]
    ));
}

#[test]
fn admin_channel_drop_waits_for_the_database_verdict() {
    let mut s = TestServer::new();
    s.core
        .preload_founders(vec![("#room".to_string(), "boss".to_string())]);
    let (reply_tx, mut reply_rx) = tokio::sync::oneshot::channel();
    s.core.handle(Input::Admin {
        req: e6ircd::core::AdminRequest::DropChannel {
            channel: "#room".into(),
            actor: "root".into(),
        },
        reply: reply_tx,
    });
    assert!(
        matches!(
            reply_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ),
        "admin DROP replied before persistence"
    );
    let requests = s.db_requests();
    let (owner, request_id, actor) = match requests.as_slice() {
        [
            e6ircd::core::DbRequest::DropChannel {
                owner,
                channel,
                requester: e6ircd::core::ChannelDropRequester::Admin { request_id, actor },
            },
        ] if channel == "#room" => (owner.clone(), *request_id, actor.clone()),
        other => panic!("admin DROP did not use the shared DB request: {other:#?}"),
    };
    assert_eq!(actor, "root", "DROP request lost its atomic audit actor");
    s.core.handle(Input::ChannelDropResult {
        owner,
        channel: "#room".into(),
        requester: e6ircd::core::ChannelDropRequester::Admin { request_id, actor },
        result: e6ircd::core::ChannelDropResult::Dropped,
    });
    match reply_rx.try_recv() {
        Ok(e6ircd::core::AdminReply::Ok(message)) => {
            assert!(message.contains("Unregistered #room"), "{message}");
        }
        other => panic!("admin DROP did not receive its committed verdict: {other:?}"),
    }
    assert!(
        s.db_requests().is_empty(),
        "admin DROP audit must be part of the delete transaction, not a second write"
    );
}

#[test]
fn owner_channel_control_waits_for_storage_and_updates_the_hot_access_map() {
    let mut s = TestServer::new();
    s.core
        .preload_founders(vec![("#room".to_string(), "boss".to_string())]);

    let (reply_tx, mut reply_rx) = tokio::sync::oneshot::channel();
    s.core.handle(Input::Admin {
        req: e6ircd::core::AdminRequest::MutateOwnedChannel {
            channel: "#ROOM".into(),
            actor: "BoSs".into(),
            mutation: e6ircd::core::ChannelMutation::SetAccess {
                account: "alice".into(),
                flags: Some("vo".into()),
            },
        },
        reply: reply_tx,
    });
    assert!(matches!(
        reply_rx.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    let request = s.db_requests();
    let (request_id, owner, mutation) = match request.as_slice() {
        [
            e6ircd::core::DbRequest::MutateOwnedChannel {
                request_id,
                owner,
                channel,
                actor,
                mutation,
            },
        ] => {
            assert_eq!(channel, "#room");
            assert_eq!(actor, "BoSs");
            (*request_id, owner.clone(), mutation.clone())
        }
        other => panic!("channel control did not queue its typed write: {other:#?}"),
    };
    assert_eq!(
        mutation,
        e6ircd::core::PersistedChannelMutation::SetAccess {
            account: "alice".into(),
            flags: Some("ov".into()),
        },
        "access flags were not canonicalized at the core boundary"
    );
    s.core.handle(Input::ChannelControlResult {
        owner,
        request_id,
        result: e6ircd::core::ChannelControlResult::Applied,
    });
    assert!(matches!(
        reply_rx.try_recv(),
        Ok(e6ircd::core::AdminReply::Ok(_))
    ));

    let boss = s.register(1, "boss");
    identify(&mut s, boss, "boss");
    s.line(boss, "JOIN #room");
    s.drain(boss);
    s.db_requests();
    let alice = s.register(2, "alice");
    identify(&mut s, alice, "alice");
    s.db_requests();
    s.line(alice, "JOIN #room");
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|line| line.contains(" 353 ") && line.contains("@alice")),
        "committed web grant did not reach the hot map: {out:#?}"
    );

    let (deny_tx, mut deny_rx) = tokio::sync::oneshot::channel();
    s.core.handle(Input::Admin {
        req: e6ircd::core::AdminRequest::MutateOwnedChannel {
            channel: "#room".into(),
            actor: "mallory".into(),
            mutation: e6ircd::core::ChannelMutation::Drop,
        },
        reply: deny_tx,
    });
    assert!(matches!(
        deny_rx.try_recv(),
        Ok(e6ircd::core::AdminReply::ChannelErr {
            kind: e6ircd::core::ChannelControlError::NotFound,
            ..
        })
    ));
    assert!(
        s.db_requests().is_empty(),
        "a non-founder request reached persistence"
    );
}

#[test]
fn owner_channel_control_verdicts_are_request_bound_and_consumed_once() {
    let mut s = TestServer::new();
    s.core
        .preload_founders(vec![("#room".to_string(), "boss".to_string())]);
    let (reply_tx, mut reply_rx) = tokio::sync::oneshot::channel();
    s.core.handle(Input::Admin {
        req: e6ircd::core::AdminRequest::MutateOwnedChannel {
            channel: "#room".into(),
            actor: "boss".into(),
            mutation: e6ircd::core::ChannelMutation::SetAccess {
                account: "alice".into(),
                flags: Some("o".into()),
            },
        },
        reply: reply_tx,
    });
    let (request_id, owner) = match s.db_requests().as_slice() {
        [
            e6ircd::core::DbRequest::MutateOwnedChannel {
                request_id, owner, ..
            },
        ] => (*request_id, owner.clone()),
        other => panic!("channel control did not queue: {other:#?}"),
    };

    s.core.handle(Input::ChannelControlResult {
        owner: owner.clone(),
        request_id,
        result: e6ircd::core::ChannelControlResult::Applied,
    });
    assert!(matches!(
        reply_rx.try_recv(),
        Ok(e6ircd::core::AdminReply::Ok(_))
    ));

    // A duplicate cannot apply after the pending request was consumed; it has
    // no channel or mutation payload that could describe a different action.
    s.core.handle(Input::ChannelControlResult {
        owner,
        request_id,
        result: e6ircd::core::ChannelControlResult::Applied,
    });
    let (next_tx, mut next_rx) = tokio::sync::oneshot::channel();
    s.core.handle(Input::Admin {
        req: e6ircd::core::AdminRequest::MutateOwnedChannel {
            channel: "#room".into(),
            actor: "boss".into(),
            mutation: e6ircd::core::ChannelMutation::SetMlock {
                mlock: Some("+i".into()),
            },
        },
        reply: next_tx,
    });
    assert!(matches!(
        next_rx.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        s.db_requests().as_slice(),
        [e6ircd::core::DbRequest::MutateOwnedChannel { .. }]
    ));
}

#[test]
fn owner_channel_registration_requires_live_operator_and_waits_for_storage() {
    let mut s = TestServer::new();
    let boss = s.register(1, "boss");
    identify(&mut s, boss, "boss");
    s.line(boss, "JOIN #web");
    s.line(boss, "TOPIC #web :from the console");
    s.drain(boss);
    s.db_requests();

    let (reply_tx, mut reply_rx) = tokio::sync::oneshot::channel();
    s.core.handle(Input::Admin {
        req: e6ircd::core::AdminRequest::RegisterOwnedChannel {
            channel: "#WEB".into(),
            actor: "BoSs".into(),
        },
        reply: reply_tx,
    });
    assert!(matches!(
        reply_rx.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    let requests = s.db_requests();
    let (request_id, owner, topic) = match requests.as_slice() {
        [
            e6ircd::core::DbRequest::RegisterOwnedChannel {
                request_id,
                owner,
                channel,
                founder_account,
                topic,
            },
        ] => {
            assert_eq!(channel, "#web");
            assert_eq!(founder_account, "BoSs");
            (*request_id, owner.clone(), topic.clone())
        }
        other => panic!("owner registration did not queue its typed write: {other:#?}"),
    };
    assert_eq!(
        topic.as_ref().map(|topic| topic.0.as_str()),
        Some("from the console")
    );
    s.core.handle(Input::OwnedChannelRegistrationResult {
        owner,
        request_id,
        result: e6ircd::core::ChannelRegistrationResult::Registered,
    });
    assert!(matches!(
        reply_rx.try_recv(),
        Ok(e6ircd::core::AdminReply::Ok(_))
    ));

    let alice = s.register(2, "alice");
    identify(&mut s, alice, "alice");
    s.db_requests();
    s.line(alice, "JOIN #blocked");
    s.line(boss, "JOIN #blocked");
    s.drain(alice);
    s.drain(boss);
    let (denied_tx, mut denied_rx) = tokio::sync::oneshot::channel();
    s.core.handle(Input::Admin {
        req: e6ircd::core::AdminRequest::RegisterOwnedChannel {
            channel: "#blocked".into(),
            actor: "boss".into(),
        },
        reply: denied_tx,
    });
    assert!(matches!(
        denied_rx.try_recv(),
        Ok(e6ircd::core::AdminReply::ChannelErr {
            kind: e6ircd::core::ChannelControlError::Conflict,
            ..
        })
    ));
    assert!(
        s.db_requests().is_empty(),
        "a non-operator registration reached persistence"
    );
}

// ChanServ FLAGS / access (DESIGN §7.6): founder grants per-account flags
// that auto-op / auto-voice on join.

#[test]
fn chanserv_flags_auto_ops_on_join() {
    let mut s = TestServer::new();
    s.core
        .preload_founders(vec![("#chan".to_string(), "boss".to_string())]);
    let boss = s.register(1, "boss");
    identify(&mut s, boss, "boss");
    s.line(boss, "JOIN #chan");
    s.drain(boss);
    s.db_requests();

    // Founder grants +o access to "alice"; it queues a persist request but does
    // not touch the hot map or confirm until the DB acknowledges the write.
    s.line(boss, "PRIVMSG ChanServ :FLAGS #chan alice +o");
    assert!(
        !s.drain(boss).iter().any(|l| l.contains("are now +o")),
        "flags confirmed before DB acknowledged"
    );
    let persisted = s.db_requests().into_iter().any(|r| {
        matches!(r,
            e6ircd::core::DbRequest::SetChannelAccess { channel, account, flags: Some(f), .. }
            if channel == "#chan" && account == "alice" && f == "o")
    });
    assert!(persisted, "SetChannelAccess not queued");

    // The DB confirms the write applied; only now is the hot map updated and
    // the founder notified.
    s.channel_service_persisted(e6ircd::core::ChannelServicePersistence::AccessSet {
        channel: "#chan".to_string(),
        display: "#chan".to_string(),
        account: "alice".to_string(),
        flags: Some("o".to_string()),
        applied: true,
        label: None,
    });
    assert!(
        s.drain(boss).iter().any(|l| l.contains("are now +o")),
        "no flags confirmation"
    );

    // alice joins and is auto-opped, though neither first nor founder.
    let alice = s.register(2, "alice");
    identify(&mut s, alice, "alice");
    s.line(alice, "JOIN #chan");
    let names = s
        .drain(alice)
        .into_iter()
        .find(|l| l.contains(" 353 "))
        .expect("353");
    assert!(names.contains("@alice"), "alice not auto-opped: {names}");

    // FLAGS with no account lists the entries.
    s.line(boss, "PRIVMSG ChanServ :FLAGS #chan");
    assert!(
        s.drain(boss).iter().any(|l| l.contains("alice +o")),
        "access entry not listed"
    );

    // A non-founder may not modify access.
    s.line(alice, "PRIVMSG ChanServ :FLAGS #chan bob +o");
    assert!(
        s.drain(alice).iter().any(|l| l.contains("not the founder")),
        "non-founder was allowed to set flags"
    );
}

/// Granting flags to an account that isn't registered must not create a phantom
/// hot-map entry — the DB writes no row (`applied: false`), so a later
/// registration of that name must not inherit auto-op it was never granted.
#[test]
fn chanserv_flags_unregistered_account_leaves_no_phantom_access() {
    let mut s = TestServer::new();
    s.core
        .preload_founders(vec![("#chan".to_string(), "boss".to_string())]);
    let boss = s.register(1, "boss");
    identify(&mut s, boss, "boss");
    s.line(boss, "JOIN #chan");
    s.drain(boss);
    s.db_requests();

    // Founder grants +o to "ghost", who has no account.
    s.line(boss, "PRIVMSG ChanServ :FLAGS #chan ghost +o");
    let persisted = s.db_requests().into_iter().any(|r| {
        matches!(r,
            e6ircd::core::DbRequest::SetChannelAccess { channel, account, .. }
            if channel == "#chan" && account == "ghost")
    });
    assert!(persisted, "SetChannelAccess not queued");

    // The DB reports the write did not apply (no such account).
    s.channel_service_persisted(e6ircd::core::ChannelServicePersistence::AccessSet {
        channel: "#chan".to_string(),
        display: "#chan".to_string(),
        account: "ghost".to_string(),
        flags: Some("o".to_string()),
        applied: false,
        label: None,
    });
    assert!(
        s.drain(boss)
            .iter()
            .any(|l| l.contains("is not registered")),
        "founder not told the grant was rejected"
    );

    // The access list must be empty — no phantom entry for ghost.
    s.line(boss, "PRIVMSG ChanServ :FLAGS #chan");
    assert!(
        !s.drain(boss).iter().any(|l| l.contains("ghost")),
        "phantom access entry created for unregistered account"
    );

    // If "ghost" now registers and joins, it must NOT be auto-opped.
    let ghost = s.register(2, "ghost");
    identify(&mut s, ghost, "ghost");
    s.line(ghost, "JOIN #chan");
    let names = s
        .drain(ghost)
        .into_iter()
        .find(|l| l.contains(" 353 "))
        .expect("353");
    assert!(
        !names.contains("@ghost"),
        "phantom access auto-opped a freshly-registered account: {names}"
    );
}

/// A FLAGS revocation whose requester disconnects during the DB round-trip
/// must still be applied to the hot access map — the DB has already committed
/// the DELETE, and dropping the reply would leave the revoked account with
/// auto-op until restart.
#[test]
fn chanserv_flags_revocation_applies_after_requester_disconnect() {
    let mut s = TestServer::new();
    s.core
        .preload_founders(vec![("#chan".to_string(), "boss".to_string())]);
    let boss = s.register(1, "boss");
    identify(&mut s, boss, "boss");
    s.line(boss, "JOIN #chan");
    s.drain(boss);
    // A bystander keeps the channel alive across boss's disconnect —
    // otherwise alice's later join recreates an empty channel and her
    // creator-op would mask the assertion.
    let carol = s.register(3, "carol");
    s.line(carol, "JOIN #chan");
    s.drain(carol);
    s.drain(boss);
    s.db_requests();

    // Grant +o to alice, DB-confirmed, so the hot map holds an entry.
    s.line(boss, "PRIVMSG ChanServ :FLAGS #chan alice +o");
    s.db_requests();
    s.channel_service_persisted(e6ircd::core::ChannelServicePersistence::AccessSet {
        channel: "#chan".to_string(),
        display: "#chan".to_string(),
        account: "alice".to_string(),
        flags: Some("o".to_string()),
        applied: true,
        label: None,
    });
    s.drain(boss);

    // Boss revokes, then the connection drops before the DB reply arrives.
    s.line(boss, "PRIVMSG ChanServ :FLAGS #chan alice -o");
    s.db_requests();
    s.core.handle(Input::Closed {
        conn: boss,
        reason: "Connection reset".into(),
    });
    // The DB committed the DELETE and replies to the now-dead conn; removals
    // always report applied: true.
    s.channel_service_persisted(e6ircd::core::ChannelServicePersistence::AccessSet {
        channel: "#chan".to_string(),
        display: "#chan".to_string(),
        account: "alice".to_string(),
        flags: None,
        applied: true,
        label: None,
    });

    // alice joins: the revocation must have landed — no auto-op.
    let alice = s.register(2, "alice");
    identify(&mut s, alice, "alice");
    s.line(alice, "JOIN #chan");
    let names = s
        .drain(alice)
        .into_iter()
        .find(|l| l.contains(" 353 "))
        .expect("353");
    assert!(
        !names.contains("@alice"),
        "revocation lost because the requester disconnected: {names}"
    );
}

/// A DB fault during a FLAGS change must be reported as a service outage, not
/// as "account is not registered" — a definitive negative the operator might
/// act on (the same law the founder-transfer path already follows).
#[test]
fn chanserv_flags_db_fault_reports_unavailable_not_unregistered() {
    let mut s = TestServer::new();
    s.core
        .preload_founders(vec![("#chan".to_string(), "boss".to_string())]);
    let boss = s.register(1, "boss");
    identify(&mut s, boss, "boss");
    s.line(boss, "JOIN #chan");
    s.drain(boss);
    s.db_requests();

    s.line(boss, "PRIVMSG ChanServ :FLAGS #chan alice +o");
    s.db_requests();
    s.channel_service_persisted(e6ircd::core::ChannelServicePersistence::AccessUnavailable {
        channel: "#chan".to_string(),
        display: "#chan".to_string(),
        label: None,
    });
    let lines = s.drain(boss);
    assert!(
        lines.iter().any(|l| l.contains("temporarily unavailable")),
        "no outage notice: {lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.contains("is not registered")),
        "DB fault misreported as unregistered account: {lines:?}"
    );
}

#[test]
fn chanserv_op_grants_op_to_member() {
    let mut s = TestServer::new();
    s.core
        .preload_founders(vec![("#chan".to_string(), "boss".to_string())]);
    let boss = s.register(1, "boss");
    identify(&mut s, boss, "boss");
    s.line(boss, "JOIN #chan");
    s.drain(boss);

    let alice = s.register(2, "alice");
    s.line(alice, "JOIN #chan");
    s.drain(alice);
    s.drain(boss);

    // Founder ops alice via ChanServ.
    s.line(boss, "PRIVMSG ChanServ :OP #chan alice");
    assert!(
        s.drain(boss).iter().any(|l| l.contains("Opped")),
        "no op confirmation"
    );
    assert!(
        s.drain(alice)
            .iter()
            .any(|l| l.contains("MODE #chan +o alice")),
        "no +o broadcast to channel"
    );

    // Someone without op access cannot use OP.
    let mallory = s.register(3, "mallory");
    identify(&mut s, mallory, "mallory");
    s.line(mallory, "JOIN #chan");
    s.drain(mallory);
    s.line(mallory, "PRIVMSG ChanServ :OP #chan mallory");
    assert!(
        s.drain(mallory)
            .iter()
            .any(|l| l.contains("do not have op access")),
        "op without access was allowed"
    );
}

#[test]
fn chanserv_set_founder_transfers_ownership() {
    let mut s = TestServer::new();
    s.core
        .preload_founders(vec![("#room".to_string(), "boss".to_string())]);
    let boss = s.register(1, "boss");
    identify(&mut s, boss, "boss");
    s.db_requests();

    // Founder transfers to "alice"; the request is queued.
    s.line(boss, "PRIVMSG ChanServ :SET #room FOUNDER alice");
    let queued = s.db_requests().into_iter().any(|r| {
        matches!(r,
            e6ircd::core::DbRequest::SetChannelFounder { channel, new_founder, .. }
            if channel == "#room" && new_founder == "alice")
    });
    assert!(queued, "SetChannelFounder not queued");

    // The DB confirms; ownership moves in the hot map.
    s.channel_service_persisted(e6ircd::core::ChannelServicePersistence::FounderChanged {
        channel: "#room".to_string(),
        account: "alice".to_string(),
        display: "#room".to_string(),
        label: None,
    });
    assert!(
        s.drain(boss).iter().any(|l| l.contains("transferred to")),
        "no transfer confirmation"
    );

    // The old founder can no longer SET; the new founder is opped on join.
    s.line(boss, "PRIVMSG ChanServ :SET #room FOUNDER boss");
    assert!(
        s.drain(boss).iter().any(|l| l.contains("not the founder")),
        "old founder still had control"
    );
    let alice = s.register(2, "alice");
    identify(&mut s, alice, "alice");
    let carol = s.register(3, "carol");
    s.line(carol, "JOIN #room");
    s.drain(carol);
    s.line(alice, "JOIN #room");
    let names = s
        .drain(alice)
        .into_iter()
        .find(|l| l.contains(" 353 "))
        .expect("353");
    assert!(names.contains("@alice"), "new founder not opped: {names}");

    // A failed transfer (no such account) is reported, not silently dropped.
    s.line(alice, "PRIVMSG ChanServ :SET #room FOUNDER ghost");
    s.db_requests();
    s.channel_service_persisted(e6ircd::core::ChannelServicePersistence::FounderMissing {
        channel: "#room".to_string(),
        display: "#room".to_string(),
        label: None,
    });
    assert!(
        s.drain(alice).iter().any(|l| l.contains("no such account")),
        "failed transfer not reported"
    );
}

// Oper K-lines (DESIGN §7.6/§15): ban a user@host, disconnect matches,
// refuse matching registrations.

#[test]
fn oper_kline_bans_disconnects_and_refuses() {
    let mut s = TestServer::new();
    let op = s.register(1, "god");
    s.line(op, "OPER god letmein");
    s.drain(op);
    let victim = s.register(2, "baddie"); // user=baddie, host=host2.example
    s.drain(victim);

    // K-line every host for user "baddie".
    s.line(op, "KLINE baddie@* :spamming");
    commit_server_ban(&mut s);
    assert!(
        s.drain(op).iter().any(|l| l.contains("Added K-Line")),
        "no kline confirmation"
    );
    // The matching online session is disconnected.
    assert!(
        s.drain(victim).iter().any(|l| l.starts_with("ERROR :")),
        "matching session not disconnected"
    );

    // A fresh registration matching the ban is refused (465 + ERROR, no
    // welcome).
    let newcomer = s.connect(3);
    s.line(newcomer, "NICK baddie");
    s.line(newcomer, "USER baddie 0 * :B");
    let out = s.drain(newcomer);
    assert!(out.iter().any(|l| l.contains(" 465 ")), "not 465: {out:#?}");
    assert!(out.iter().any(|l| l.starts_with("ERROR :")), "not closed");
    assert!(
        !out.iter().any(|l| l.contains(" 001 ")),
        "banned user welcomed"
    );

    // UNKLINE lifts it; a matching registration then succeeds.
    s.line(op, "UNKLINE baddie@*");
    commit_server_ban(&mut s);
    assert!(
        s.drain(op).iter().any(|l| l.contains("Removed K-Line")),
        "no unkline confirmation"
    );
    let ok = s.connect(4);
    s.line(ok, "NICK baddie");
    s.line(ok, "USER baddie 0 * :B");
    assert!(
        s.drain(ok).iter().any(|l| l.contains(" 001 ")),
        "not welcomed after unkline"
    );

    // A non-oper cannot KLINE.
    let plain = s.register(5, "plain");
    s.line(plain, "KLINE x@y :no");
    assert!(
        s.drain(plain).iter().any(|l| l.contains(" 481 ")),
        "non-oper was allowed to KLINE"
    );
}

/// A server ban preserves the operator's original mask casing for STATS/the
/// confirmation (a `MaskKey`, like the channel `+b` lists), while still removing
/// case-insensitively — the display-fidelity the folded-`String` form lost.
#[test]
fn server_ban_preserves_display_case_and_removes_case_insensitively() {
    let mut s = TestServer::new();
    let op = s.register(1, "god");
    s.line(op, "OPER god letmein");
    s.drain(op);

    // A mixed-case KLINE mask.
    s.line(op, "KLINE Baddie@Host :spam");
    commit_server_ban(&mut s);
    let out = s.drain(op);
    assert!(
        out.iter()
            .any(|l| l.contains("Added K-Line for Baddie@Host")),
        "confirmation must echo the operator's casing: {out:#?}"
    );

    // STATS-style list (KLINE with no argument) shows the original casing, not
    // the folded form.
    s.line(op, "KLINE");
    let out = s.drain(op);
    assert!(
        out.iter().any(|l| l.contains("Baddie@Host")),
        "the ban list must show the original casing: {out:#?}"
    );
    assert!(
        !out.iter().any(|l| l.contains("baddie@host")),
        "the ban list must not show the folded casing: {out:#?}"
    );

    // A differently-cased UNKLINE still lifts it (folded comparison).
    s.line(op, "UNKLINE baddie@HOST");
    commit_server_ban(&mut s);
    let out = s.drain(op);
    assert!(
        out.iter().any(|l| l.contains("Removed K-Line")),
        "a differently-cased UNKLINE must remove the ban: {out:#?}"
    );
}

/// A ban that matches the setting oper's own session must still confirm and
/// audit before the self-disconnect: the confirmation NOTICE and `record_audit`
/// run ahead of the victims loop, so a self-matching ban doesn't close the
/// oper's session and then send its confirmation into a gone connection (a
/// silent no-op) or record an actor-less audit row — the same self-close
/// ordering `cmd_kill` guards. (The mask targets the oper's own host rather
/// than `*@*`, which is refused as a netban, while still self-matching.)
#[test]
fn self_matching_kline_confirms_before_disconnecting_the_setter() {
    let mut s = TestServer::new();
    let op = s.register(1, "god");
    s.line(op, "OPER god letmein");
    s.drain(op);
    // A mask specific enough to pass the netban guard but that still matches the
    // oper's own user@host (the test harness gives conn 1 the host host1.example).
    s.line(op, "KLINE *@host1.example :cleanup");
    commit_server_ban(&mut s);
    let out = s.drain(op);
    assert!(
        out.iter().any(|l| l.contains("Added K-Line")),
        "the setter must receive the confirmation before being disconnected: {out:#?}"
    );
    assert!(
        out.iter().any(|l| l.starts_with("ERROR :")),
        "the self-matching setter is still disconnected: {out:#?}"
    );
}

// D-lines ban by host/IP; X-lines ban by realname (gecos). Same machinery
// as K-lines, differing only in the session field the mask tests against.

#[test]
fn oper_dline_bans_by_host() {
    let mut s = TestServer::new();
    let op = s.register(1, "god");
    s.line(op, "OPER god letmein");
    s.drain(op);

    s.line(op, "DLINE host7.example :bad netblock");
    commit_server_ban(&mut s);
    assert!(
        s.drain(op).iter().any(|l| l.contains("Added D-Line")),
        "no dline confirmation"
    );

    // A registration from the banned host is refused (465 + D-Lined ERROR).
    let banned = s.connect(7); // host7.example
    s.line(banned, "NICK joe");
    s.line(banned, "USER joe 0 * :Joe");
    let out = s.drain(banned);
    assert!(out.iter().any(|l| l.contains(" 465 ")), "not 465: {out:#?}");
    assert!(
        out.iter().any(|l| l.contains("D-Lined")),
        "not D-Lined: {out:#?}"
    );

    // A different host is unaffected.
    let ok = s.connect(8); // host8.example
    s.line(ok, "NICK ann");
    s.line(ok, "USER ann 0 * :Ann");
    assert!(
        s.drain(ok).iter().any(|l| l.contains(" 001 ")),
        "clean host refused"
    );

    s.line(op, "UNDLINE host7.example");
    commit_server_ban(&mut s);
    assert!(
        s.drain(op).iter().any(|l| l.contains("Removed D-Line")),
        "no undline confirmation"
    );
}

#[test]
fn oper_xline_bans_by_realname() {
    let mut s = TestServer::new();
    let op = s.register(1, "god");
    s.line(op, "OPER god letmein");
    s.drain(op);

    s.line(op, "XLINE *spambot* :no bots");
    commit_server_ban(&mut s);
    assert!(
        s.drain(op).iter().any(|l| l.contains("Added X-Line")),
        "no xline confirmation"
    );

    // A registration whose realname matches the gecos glob is refused.
    let banned = s.connect(2);
    s.line(banned, "NICK sam");
    s.line(banned, "USER sam 0 * :evil spambot v2");
    let out = s.drain(banned);
    assert!(out.iter().any(|l| l.contains(" 465 ")), "not 465: {out:#?}");
    assert!(
        out.iter().any(|l| l.contains("X-Lined")),
        "not X-Lined: {out:#?}"
    );

    // A different realname on the same server is fine.
    let ok = s.connect(3);
    s.line(ok, "NICK amy");
    s.line(ok, "USER amy 0 * :just a person");
    assert!(
        s.drain(ok).iter().any(|l| l.contains(" 001 ")),
        "clean gecos refused"
    );
}

/// An XLINE whose gecos mask contains spaces must ban the whole (space-joined)
/// mask, not the first token — `XLINE *Evil Corp* :spam` used to silently ban
/// `*Evil` with reason `Corp*`, a different and broader ban than typed.
#[test]
fn oper_xline_mask_with_spaces_is_not_split() {
    let mut s = TestServer::new();
    let op = s.register(1, "god");
    s.line(op, "OPER god letmein");
    s.drain(op);
    s.line(op, "XLINE *Evil Corp* :spam bots");
    commit_server_ban(&mut s);
    assert!(
        s.drain(op).iter().any(|l| l.contains("Added X-Line")),
        "no xline confirmation"
    );
    // A realname matching the full multi-word glob is refused...
    let banned = s.connect(2);
    s.line(banned, "NICK sam");
    s.line(banned, "USER sam 0 * :Totally Evil Corp Ltd");
    assert!(
        s.drain(banned).iter().any(|l| l.contains(" 465 ")),
        "multi-word gecos ban did not take"
    );
    // ...while a realname matching only the mangled first token ("*Evil") is not.
    let ok = s.connect(3);
    s.line(ok, "NICK amy");
    s.line(ok, "USER amy 0 * :Not So Evil");
    assert!(
        s.drain(ok).iter().any(|l| l.contains(" 001 ")),
        "a realname matching only the split-off token was wrongly banned"
    );
    // And it removes by the same multi-word mask.
    s.line(op, "UNXLINE *Evil Corp*");
    commit_server_ban(&mut s);
    assert!(
        s.drain(op).iter().any(|l| l.contains("Removed X-Line")),
        "multi-word xline could not be removed by its own mask"
    );
}

/// An XLINE with a multi-word mask and *no* reason (no trailing `:`) must ban
/// the whole space-joined mask, not treat its last word as the reason. Keying
/// the split on `p.len() >= 2` alone banned `*Evil` with reason `Corp*` for
/// `XLINE *Evil Corp*` — the reason is only present when sent as a trailing.
#[test]
fn oper_xline_multiword_mask_without_reason_bans_whole_mask() {
    let mut s = TestServer::new();
    let op = s.register(1, "god");
    s.line(op, "OPER god letmein");
    s.drain(op);
    s.line(op, "XLINE *Evil Corp*");
    commit_server_ban(&mut s);
    assert!(
        s.drain(op).iter().any(|l| l.contains("Added X-Line")),
        "no xline confirmation"
    );
    // The full multi-word glob is banned...
    let banned = s.connect(2);
    s.line(banned, "NICK sam");
    s.line(banned, "USER sam 0 * :Totally Evil Corp Ltd");
    assert!(
        s.drain(banned).iter().any(|l| l.contains(" 465 ")),
        "multi-word no-reason gecos ban did not take"
    );
    // ...while a realname matching only the would-be split token ("*Evil") is not.
    let ok = s.connect(3);
    s.line(ok, "NICK amy");
    s.line(ok, "USER amy 0 * :Not So Evil");
    assert!(
        s.drain(ok).iter().any(|l| l.contains(" 001 ")),
        "a realname matching only the split-off token was wrongly banned"
    );
}

/// A ban mask that constrains nothing (`*@*`, `*`) is an accidental server-wide
/// ban; `BanMask::parse` refuses it so such a mask can never reach the ban list.
/// The refusal is loud (a NOTICE), never a silent narrowing.
#[test]
fn oper_ban_matching_everyone_is_refused() {
    let mut s = TestServer::new();
    let op = s.register(1, "god");
    s.line(op, "OPER god letmein");
    s.drain(op);
    // Each of these constrains nothing and must be refused, with no DB write.
    for cmd in ["KLINE *@* :bye", "DLINE * :bye", "XLINE * :bye"] {
        s.line(op, cmd);
        let out = s.drain(op);
        assert!(
            out.iter()
                .any(|l| l.contains("Refusing") && l.contains("matches every user")),
            "{cmd} should be refused as a netban: {out:#?}"
        );
        assert!(
            !out.iter().any(|l| l.contains("Added")),
            "{cmd} must not be added"
        );
        assert!(
            s.db_requests()
                .iter()
                .all(|r| !matches!(r, e6ircd::core::DbRequest::MutateServerBan { .. })),
            "{cmd} must not reach the database"
        );
    }
    // A specific mask on the same commands is still accepted.
    s.line(op, "KLINE bad@host.example :spam");
    commit_server_ban(&mut s);
    assert!(
        s.drain(op).iter().any(|l| l.contains("Added K-Line")),
        "a specific KLINE is still accepted"
    );
    // `nick@*` constrains the user field, so it is not a netban.
    s.line(op, "KLINE baddie@* :spam");
    commit_server_ban(&mut s);
    assert!(
        s.drain(op).iter().any(|l| l.contains("Added K-Line")),
        "user@* is specific enough to accept"
    );
}

#[test]
fn server_ban_store_failure_is_loud_labeled_and_non_mutating() {
    let mut s = TestServer::new();
    let op = register_with_caps(&mut s, 1, "god", "labeled-response");
    s.line(op, "OPER god letmein");
    s.drain(op);
    s.db_requests();
    let victim = s.register(2, "baddie");
    s.drain(victim);

    s.line(op, "@label=ban7 KLINE baddie@* :spam");
    assert!(
        s.drain(op).is_empty(),
        "KLINE must not confirm before its audited durable write"
    );
    let requests = s.db_requests();
    let (mutation, requester) = match requests.as_slice() {
        [
            e6ircd::core::DbRequest::MutateServerBan {
                mutation,
                requester:
                    requester @ e6ircd::core::ServerBanRequester::Oper {
                        session,
                        label: Some(label),
                    },
            },
        ] if session.connection_id() == op && label == "ban7" => {
            (mutation.clone(), requester.clone())
        }
        other => panic!("KLINE did not preserve its requester/label: {other:#?}"),
    };
    assert!(
        s.drain(victim).is_empty(),
        "the matching user was disconnected before persistence"
    );
    s.core.handle(Input::ServerBanResult {
        mutation,
        requester,
        result: e6ircd::core::ServerBanResult::Unavailable,
    });
    let out = s.drain(op);
    assert!(
        out.iter().any(|line| {
            line.starts_with("@label=ban7 ")
                && line.contains("Server-ban change failed")
                && line.contains("temporarily unavailable")
        }),
        "KLINE store failure was not loud and correlated: {out:#?}"
    );
    assert!(
        s.drain(victim).is_empty(),
        "failed KLINE changed the hot enforcement list"
    );
}

/// Server-ban removal folds like enforcement: a ban set with one casing is
/// removable with another. Before, `UNKLINE` compared case-sensitively and
/// reported "no such ban" while the ban kept enforcing.
#[test]
fn server_ban_removal_is_case_insensitive() {
    let mut s = TestServer::new();
    let op = s.register(1, "god");
    s.line(op, "OPER god letmein");
    s.drain(op);
    s.line(op, "KLINE Baddie@Evil.Example :out");
    commit_server_ban(&mut s);
    assert!(
        s.drain(op).iter().any(|l| l.contains("Added K-Line")),
        "no kline confirmation"
    );
    // A registration matching the ban (folded) is refused regardless of casing.
    let banned = s.connect(2);
    s.line(banned, "NICK v");
    s.line(banned, "USER baddie 0 * :v");
    // host defaults to the test host; the user part matches the folded mask.
    // Remove using a different casing than it was added with.
    s.line(op, "UNKLINE baddie@evil.example");
    commit_server_ban(&mut s);
    assert!(
        s.drain(op).iter().any(|l| l.contains("Removed K-Line")),
        "case-variant UNKLINE failed to remove the ban"
    );
    // A second removal now finds nothing (it really was removed).
    s.line(op, "UNKLINE BADDIE@EVIL.EXAMPLE");
    assert!(
        s.drain(op).iter().any(|l| l.contains("No K-Line found")),
        "ban was not actually removed"
    );
}

#[test]
fn oper_actions_are_audited() {
    let mut s = TestServer::new();
    let op = s.register(1, "god");
    s.line(op, "OPER god letmein");
    s.drain(op);
    let audits = |s: &mut TestServer| -> Vec<(String, String)> {
        s.db_requests()
            .into_iter()
            .filter_map(|r| match r {
                e6ircd::core::DbRequest::AuditLog { action, target, .. } => Some((action, target)),
                _ => None,
            })
            .collect()
    };
    assert!(
        audits(&mut s)
            .iter()
            .any(|(a, t)| a == "OPER" && t == "god"),
        "OPER not audited"
    );

    s.line(op, "KLINE baddie@* :spam");
    let mutation = commit_server_ban(&mut s);
    s.drain(op);
    assert!(
        matches!(
            mutation,
            e6ircd::core::ServerBanMutation::Add {
                mask_display,
                set_by,
                kind,
                ..
            } if mask_display == "baddie@*" && set_by == "god" && kind == "kline"
        ),
        "KLINE mutation did not carry its atomic audit fields"
    );

    s.line(op, "UNKLINE baddie@*");
    let mutation = commit_server_ban(&mut s);
    s.drain(op);
    assert!(
        matches!(
            mutation,
            e6ircd::core::ServerBanMutation::Remove {
                mask_display,
                actor,
                kind,
                ..
            } if mask_display == "baddie@*" && actor == "god" && kind == "kline"
        ),
        "UNKLINE mutation did not carry its atomic audit fields"
    );
}

/// A self-KILL removes the actor's own session; the audit row must still name
/// the actor — recording after the close resolved the actor to an empty string,
/// an unattributed row in a log whose whole purpose is attribution.
#[test]
fn self_kill_audit_row_names_the_actor() {
    let mut s = TestServer::new();
    let op = s.register(1, "god");
    s.line(op, "OPER god letmein");
    s.drain(op);
    s.db_requests();
    s.line(op, "KILL god :cleaning up");
    let actor = s
        .db_requests()
        .into_iter()
        .find_map(|r| match r {
            e6ircd::core::DbRequest::AuditLog { actor, action, .. } if action == "KILL" => {
                Some(actor)
            }
            _ => None,
        })
        .expect("KILL not audited");
    assert_eq!(actor, "god", "self-KILL audit row lost its actor");
}

/// A QUIT sent inside a labeled command tears the session down from within the
/// labeled-response capture: the terminal ERROR used to be captured, then
/// dropped when the wrapper tried to deliver it to the already-removed
/// session — a silent close on the exact path that promises a loud one.
#[test]
fn labeled_quit_still_delivers_the_error() {
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "labeled-response batch");
    s.line(alice, "@label=q QUIT :bye");
    let out = s.drain(alice);
    assert!(
        out.iter().any(|l| l.contains("ERROR")),
        "labeled QUIT must still deliver the closing ERROR: {out:#?}"
    );
}

// Oper SETHOST + chghost (DESIGN §7.6/§7.7): cloak a user's host and
// announce it to chghost-capable peers.

#[test]
fn oper_sethost_changes_host_and_chghosts() {
    let mut s = TestServer::new();
    let op = s.register(1, "god");
    s.line(op, "OPER god letmein");
    s.drain(op);
    let obs = register_with_caps(&mut s, 2, "obs", "chghost");
    let target = s.register(3, "user");
    for c in [obs, target] {
        s.line(c, "JOIN #room");
        s.drain(c);
    }
    s.drain(obs);
    s.drain(op);

    s.line(op, "SETHOST user cloak.example");
    assert!(
        s.drain(op)
            .iter()
            .any(|l| l.contains("Set host of user to cloak.example")),
        "no oper confirmation"
    );
    // The chghost-capable observer is told, with the OLD prefix.
    assert!(
        s.drain(obs)
            .iter()
            .any(|l| l.contains("@host3.example CHGHOST user cloak.example")),
        "no CHGHOST"
    );
    // The target has no chghost cap, so it learns its new host via
    // RPL_VISIBLEHOST (396) instead of a CHGHOST it couldn't parse.
    let target_out = s.drain(target);
    assert!(
        target_out
            .iter()
            .any(|l| l.split(' ').nth(1) == Some("396") && l.contains("cloak.example")),
        "target not sent RPL_VISIBLEHOST: {target_out:#?}"
    );
    // The host actually changed: the target's next message shows it.
    s.line(target, "PRIVMSG #room :hi");
    assert!(
        s.drain(obs)
            .iter()
            .any(|l| l.contains("@cloak.example PRIVMSG #room :hi")),
        "new host not applied"
    );

    // A non-oper cannot SETHOST.
    let plain = s.register(4, "plain");
    s.line(plain, "SETHOST user x.y");
    assert!(
        s.drain(plain).iter().any(|l| l.contains(" 481 ")),
        "non-oper allowed to SETHOST"
    );
}

/// A chghost-capable target already learns of the host change from CHGHOST, so
/// it must not also get a redundant RPL_VISIBLEHOST.
#[test]
fn oper_sethost_capable_target_gets_no_redundant_396() {
    let mut s = TestServer::new();
    let op = s.register(1, "god");
    s.line(op, "OPER god letmein");
    s.drain(op);
    let target = register_with_caps(&mut s, 2, "user", "chghost");
    s.drain(target);
    s.line(op, "SETHOST user cloak.example");
    s.drain(op);
    let out = s.drain(target);
    assert!(
        out.iter().any(|l| l.contains("CHGHOST user cloak.example")),
        "capable target should get CHGHOST: {out:#?}"
    );
    assert!(
        !out.iter().any(|l| l.split(' ').nth(1) == Some("396")),
        "capable target must not get a redundant RPL_VISIBLEHOST: {out:#?}"
    );
}

/// Privileged actions (KILL, server bans) raise an operator server-notice to
/// every other operator, so oper activity is visible without tailing the DB
/// audit log.
#[test]
fn oper_kill_and_ban_raise_snotices() {
    let mut s = TestServer::new();
    let op1 = s.register(1, "god");
    s.line(op1, "OPER god letmein");
    s.drain(op1);
    // A second operator (same credentials, second session) watches for snotices.
    let op2 = s.register(2, "god2");
    s.line(op2, "OPER god letmein");
    s.drain(op2);
    let victim = s.register(3, "victim");
    s.drain(victim);

    // KILL: op2 sees the notice; the killed victim does not (it is excluded).
    s.line(op1, "KILL victim :spamming");
    let seen = s.drain(op2);
    assert!(
        seen.iter()
            .any(|l| l.contains("Notice -- Received KILL message for victim")
                && l.contains("from god")),
        "op2 did not see the KILL snotice: {seen:#?}"
    );

    // Ban: op2 sees the K-Line notice.
    s.line(op1, "KLINE bad@host.example :spam");
    commit_server_ban(&mut s);
    let seen = s.drain(op2);
    assert!(
        seen.iter()
            .any(|l| l.contains("Notice --") && l.contains("added K-Line for bad@host.example")),
        "op2 did not see the ban snotice: {seen:#?}"
    );
}

#[test]
fn unregistered_nick_holder_is_not_resolvable_and_never_panics() {
    // Regression: a session that has sent only NICK (no USER) reserves the
    // nick but is not a registered user. Resolving it for WHOIS/USERHOST/
    // MONITOR/SETHOST must not build a prefix from its absent user/realname
    // (that panicked the shared core worker → whole-server DoS).
    let mut s = TestServer::new();
    let squatter = s.connect(1);
    s.line(squatter, "NICK ghosty"); // holds the nick, still unregistered
    let alice = s.register(2, "alice");
    s.drain(alice);

    // WHOIS: not a user → ERR_NOSUCHNICK, and crucially no panic.
    s.line(alice, "WHOIS ghosty");
    assert!(
        s.drain(alice).iter().any(|l| l.contains(" 401 ")),
        "WHOIS of an unregistered holder should be ERR_NOSUCHNICK"
    );
    // USERHOST: no panic, no entry for the unregistered holder.
    s.line(alice, "USERHOST ghosty");
    let out = s.drain(alice);
    assert!(
        !out.iter().any(|l| l.contains("ghosty=")),
        "unregistered holder must not appear in USERHOST: {out:#?}"
    );
    // MONITOR: the unregistered holder is reported offline (not online), no panic.
    s.line(alice, "MONITOR + ghosty");
    let out = s.drain(alice);
    assert!(
        out.iter().any(|l| l.contains(" 731 ")) && !out.iter().any(|l| l.contains(" 730 ")),
        "unregistered holder should be MONITOR-offline: {out:#?}"
    );

    // Sanity: once it registers, it becomes resolvable.
    s.line(squatter, "USER g 0 * :Ghosty");
    s.drain(squatter);
    s.line(alice, "WHOIS ghosty");
    assert!(
        s.drain(alice).iter().any(|l| l.contains(" 311 ")),
        "registered holder should WHOIS normally"
    );
}

#[test]
fn statusmsg_is_not_stored_in_history() {
    // A STATUSMSG (@#/+#) reaches only ops/voiced; it must not enter the
    // shared history ring or the messages table, or CHATHISTORY would leak it
    // to members excluded from the live delivery.
    let mut s = TestServer::new();
    let op = s.register(1, "op");
    s.line(op, "JOIN #room"); // first joiner → op
    s.drain(op);
    s.db_requests();

    s.line(op, "PRIVMSG @#room :ops only");
    s.drain(op);
    assert!(
        !s.db_requests()
            .into_iter()
            .any(|r| matches!(r, e6ircd::core::DbRequest::LogMessage { .. })),
        "STATUSMSG must not be written to history"
    );

    // A normal channel message IS persisted.
    s.line(op, "PRIVMSG #room :normal");
    s.drain(op);
    assert!(
        s.db_requests().into_iter().any(|r| matches!(r,
            e6ircd::core::DbRequest::LogMessage { body, .. } if body == "normal")),
        "a normal channel message must be persisted"
    );
}

// ---- sweep: DoS caps + fidelity regressions -----------------------------

#[test]
fn join_zero_parts_all_channels() {
    let mut s = TestServer::new();
    let a = s.register(1, "alice");
    s.line(a, "JOIN #a");
    s.line(a, "JOIN #b");
    s.drain(a);
    s.line(a, "JOIN 0");
    let out = s.drain(a);
    let parts: Vec<_> = out.iter().filter(|l| l.contains(" PART ")).collect();
    assert_eq!(parts.len(), 2, "JOIN 0 must PART every channel: {out:#?}");
    assert!(out.iter().any(|l| l.contains("PART #a")));
    assert!(out.iter().any(|l| l.contains("PART #b")));
}

#[test]
fn channel_ban_list_is_capped() {
    let mut s = TestServer::new();
    let a = s.register(1, "alice");
    s.line(a, "JOIN #c"); // first in → auto-op
    s.drain(a);
    for i in 0..100 {
        s.line(a, &format!("MODE #c +b nick{i}!*@*"));
        if i % 20 == 0 {
            s.drain(a);
        }
    }
    s.drain(a);
    s.line(a, "MODE #c +b overflow!*@*");
    let out = s.drain(a);
    assert!(
        has_numeric(&out, "478"),
        "the 101st ban must be ERR_BANLISTFULL: {out:#?}"
    );
}

#[test]
fn channels_per_session_is_capped() {
    let mut s = TestServer::new();
    let a = s.register(1, "alice");
    for i in 0..250 {
        s.line(a, &format!("JOIN #ch{i}"));
        if i % 10 == 0 {
            s.drain(a);
        }
    }
    s.drain(a);
    s.line(a, "JOIN #onemore");
    let out = s.drain(a);
    assert!(
        has_numeric(&out, "405"),
        "the 251st channel must be ERR_TOOMANYCHANNELS: {out:#?}"
    );
}

#[test]
fn multi_target_message_delivers_and_caps() {
    let mut s = TestServer::new();
    let sender = s.register(1, "sender");
    let b = s.register(2, "bob");
    let c = s.register(3, "carol");
    let d = s.register(4, "dave");
    let e = s.register(5, "erin");
    let f = s.register(6, "frank");
    s.line(sender, "PRIVMSG bob,carol,dave,erin,frank :hi");
    assert!(s.drain(b).iter().any(|l| l.contains("PRIVMSG bob :hi")));
    assert!(s.drain(c).iter().any(|l| l.contains("PRIVMSG carol :hi")));
    assert!(s.drain(d).iter().any(|l| l.contains("PRIVMSG dave :hi")));
    assert!(s.drain(e).iter().any(|l| l.contains("PRIVMSG erin :hi")));
    assert!(
        s.drain(f).is_empty(),
        "the 5th target is over TARGMAX and must not receive"
    );
    let out = s.drain(sender);
    assert!(
        has_numeric(&out, "407"),
        "over-cap must yield ERR_TOOMANYTARGETS: {out:#?}"
    );
}

#[test]
fn channel_key_hidden_from_non_members() {
    let mut s = TestServer::new();
    let op = s.register(1, "op");
    s.line(op, "JOIN #k");
    s.drain(op);
    s.line(op, "MODE #k +k sekrit");
    s.drain(op);
    // A member sees the real key.
    s.line(op, "MODE #k");
    let out = s.drain(op);
    let line = out
        .iter()
        .find(|l| l.split(' ').nth(1) == Some("324"))
        .expect("324");
    assert!(line.contains("sekrit"), "member should see key: {line}");
    // A non-member sees `*`, never the value.
    let bob = s.register(2, "bob");
    s.line(bob, "MODE #k");
    let out = s.drain(bob);
    let line = out
        .iter()
        .find(|l| l.split(' ').nth(1) == Some("324"))
        .expect("324");
    assert!(
        line.contains('*') && !line.contains("sekrit"),
        "non-member must not see key value: {line}"
    );
}

#[test]
fn whois_hides_secret_channel_from_non_member() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "JOIN #sec");
    s.line(alice, "MODE #sec +s");
    s.drain(alice);
    let bob = s.register(2, "bob");
    s.line(bob, "WHOIS alice");
    let out = s.drain(bob);
    assert!(
        !out.iter().any(|l| l.contains("#sec")),
        "WHOIS must not leak a +s channel to a non-member: {out:#?}"
    );
    // Alice shares it, so her own WHOIS still lists it.
    s.line(alice, "WHOIS alice");
    let out = s.drain(alice);
    assert!(
        out.iter().any(|l| l.contains("#sec")),
        "a member's WHOIS still shows the shared secret channel: {out:#?}"
    );
}

#[test]
fn names_and_who_hide_secret_channel_from_non_member() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "JOIN #sec");
    s.line(alice, "MODE #sec +s");
    s.drain(alice);
    let bob = s.register(2, "bob");
    s.line(bob, "NAMES #sec");
    let out = s.drain(bob);
    assert!(
        !out.iter().any(|l| l.contains("alice")),
        "NAMES must hide +s membership: {out:#?}"
    );
    assert!(has_numeric(&out, "366"), "NAMES still ends (366): {out:#?}");
    s.line(bob, "WHO #sec");
    let out = s.drain(bob);
    assert!(
        !out.iter().any(|l| l.split(' ').nth(1) == Some("352")),
        "WHO must hide +s members: {out:#?}"
    );
    assert!(has_numeric(&out, "315"), "WHO still ends (315): {out:#?}");
}

#[test]
fn exception_list_query_requires_op() {
    let mut s = TestServer::new();
    let op = s.register(1, "op");
    s.line(op, "JOIN #x");
    s.drain(op);
    let bob = s.register(2, "bob");
    s.line(bob, "JOIN #x"); // second in → not op
    s.drain(bob);
    s.line(bob, "MODE #x +e");
    let out = s.drain(bob);
    assert!(
        has_numeric(&out, "482"),
        "a non-op +e list query must be ERR_CHANOPRIVSNEEDED: {out:#?}"
    );
}

#[test]
fn markread_accepts_user_target_rejects_invalid() {
    let mut s = TestServer::new();
    let a = register_with_caps(&mut s, 1, "alice", "draft/read-marker");
    identify(&mut s, a, "alice");
    // A user (DM) target is a valid marker target (draft/read-marker allows
    // both channels and users).
    s.line(a, "MARKREAD bob timestamp=2026-07-18T12:00:00.000Z");
    assert!(
        s.drain(a).is_empty(),
        "the valid target waits for its durable verdict"
    );
    confirm_read_marker(&mut s);
    let out = s.drain(a);
    assert!(
        !out.iter().any(|l| l.contains("FAIL")),
        "a user target must be accepted: {out:#?}"
    );
    assert!(out.iter().any(|l| l.contains("MARKREAD bob timestamp=")));
    // A target that is neither a valid channel nor a valid nick fails loudly.
    s.line(a, "MARKREAD !!! timestamp=2026-07-18T12:00:00.000Z");
    assert!(
        s.drain(a).iter().any(|l| l.contains("FAIL MARKREAD")),
        "an invalid target must fail loudly"
    );
}

// ---- sweep 2: fidelity + bug regressions --------------------------------

#[test]
fn list_filters_to_named_channel() {
    let mut s = TestServer::new();
    let a = s.register(1, "alice");
    s.line(a, "JOIN #a");
    s.line(a, "JOIN #b");
    s.drain(a);
    s.line(a, "LIST #a");
    let out = s.drain(a);
    let listed: Vec<_> = out
        .iter()
        .filter(|l| l.split(' ').nth(1) == Some("322"))
        .collect();
    assert_eq!(listed.len(), 1, "LIST #a must list only #a: {out:#?}");
    assert!(listed[0].contains("#a"));
    assert!(
        !out.iter()
            .any(|l| l.split(' ').nth(1) == Some("322") && l.contains("#b")),
        "LIST #a must not include #b: {out:#?}"
    );
}

#[test]
fn userhost_marks_operator() {
    let mut s = TestServer::new();
    let god = s.register(1, "god");
    s.line(god, "OPER god letmein");
    s.drain(god);
    s.line(god, "USERHOST god");
    let out = s.drain(god);
    let line = out
        .iter()
        .find(|l| l.split(' ').nth(1) == Some("302"))
        .expect("302");
    assert!(
        line.contains("god*="),
        "USERHOST must mark an oper with *: {line}"
    );
}

#[test]
fn tagmsg_blocked_for_banned_member() {
    let mut s = TestServer::new();
    let op = register_with_caps(&mut s, 1, "op", "message-tags");
    s.line(op, "JOIN #c");
    s.drain(op);
    let bob = register_with_caps(&mut s, 2, "bob", "message-tags");
    s.line(bob, "JOIN #c");
    s.drain(bob);
    s.line(op, "MODE #c +b bob!*@*");
    s.drain(op);
    s.drain(bob);
    // Banned (still a member) — TAGMSG must be refused like PRIVMSG.
    s.line(bob, "@+typing=active TAGMSG #c");
    let out = s.drain(bob);
    assert!(
        has_numeric(&out, "404"),
        "a banned member's TAGMSG must be ERR_CANNOTSENDTOCHAN: {out:#?}"
    );
}

#[test]
fn multi_target_dedups_casefolded() {
    let mut s = TestServer::new();
    let sender = s.register(1, "sender");
    let bob = s.register(2, "bob");
    s.line(sender, "PRIVMSG bob,BOB :hi");
    let got: Vec<_> = s
        .drain(bob)
        .into_iter()
        .filter(|l| l.contains("PRIVMSG bob :hi"))
        .collect();
    assert_eq!(
        got.len(),
        1,
        "case-folded duplicate targets must deliver exactly once: {got:#?}"
    );
}

#[test]
fn myinfo_reflects_implemented_modes() {
    let mut s = TestServer::new();
    let c = s.connect(1);
    s.line(c, "NICK alice");
    s.line(c, "USER alice 0 * :Alice");
    let burst = s.drain(c);
    let myinfo = burst
        .iter()
        .find(|l| l.split(' ').nth(1) == Some("004"))
        .expect("004 MYINFO");
    assert!(
        myinfo.contains("iowB") && myinfo.contains('C'),
        "MYINFO must advertise the umodes/chanmodes actually implemented: {myinfo}"
    );
}

#[test]
fn lusers_reports_real_invisible_count() {
    let mut s = TestServer::new();
    let a = s.register(1, "alice");
    s.line(a, "MODE alice +i");
    s.drain(a);
    s.line(a, "LUSERS");
    let out = s.drain(a);
    let client = out
        .iter()
        .find(|l| l.split(' ').nth(1) == Some("251"))
        .expect("251 RPL_LUSERCLIENT");
    assert!(
        client.contains("1 invisible") && !client.contains("0 invisible"),
        "LUSERS must count invisible users: {client}"
    );
}

// ---- sweep 3: fidelity + injection regressions --------------------------

#[test]
fn chathistory_rejects_unknown_msgref() {
    let mut s = TestServer::new();
    let a = register_with_caps(&mut s, 1, "alice", "batch draft/chathistory");
    s.line(a, "JOIN #h");
    s.drain(a);
    s.line(a, "CHATHISTORY BEFORE #h garbage 10");
    let out = s.drain(a);
    assert!(
        out.iter()
            .any(|l| l.contains("FAIL CHATHISTORY INVALID_MSGREFTYPE")),
        "unknown msgref must FAIL, not return an empty batch: {out:#?}"
    );
}

#[test]
fn chathistory_rejects_bad_limit() {
    let mut s = TestServer::new();
    let a = register_with_caps(&mut s, 1, "alice", "batch draft/chathistory");
    s.line(a, "JOIN #h");
    s.drain(a);
    for bad in [
        "CHATHISTORY LATEST #h * notanumber",
        "CHATHISTORY LATEST #h * 0",
        "CHATHISTORY LATEST #h * 501",
        "CHATHISTORY LATEST #h *",
        "CHATHISTORY LATEST #h * 10 extra",
        "CHATHISTORY TARGETS timestamp=1970-01-01T00:00:00.000Z timestamp=2262-01-01T00:00:00.000Z",
        "CHATHISTORY TARGETS timestamp=1970-01-01T00:00:00.000Z timestamp=2262-01-01T00:00:00.000Z 501",
        "CHATHISTORY TARGETS timestamp=1970-01-01T00:00:00.000Z timestamp=2262-01-01T00:00:00.000Z 10 extra",
    ] {
        s.line(a, bad);
        let out = s.drain(a);
        assert!(
            out.iter()
                .any(|l| l.contains("FAIL CHATHISTORY INVALID_PARAMS")),
            "'{bad}' must FAIL INVALID_PARAMS, not silently default: {out:#?}"
        );
    }
}

#[test]
fn topic_is_truncated_to_topiclen() {
    let mut s = TestServer::new();
    let op = s.register(1, "op");
    s.line(op, "JOIN #t");
    s.drain(op);
    let long = "x".repeat(500);
    s.line(op, &format!("TOPIC #t :{long}"));
    let out = s.drain(op);
    let topic = out
        .iter()
        .find(|l| l.contains(" TOPIC #t :"))
        .expect("TOPIC broadcast");
    let trailing = topic.split(" :").nth(1).expect("trailing");
    assert!(
        trailing.len() <= 390,
        "topic must be truncated to TOPICLEN (390): got {}",
        trailing.len()
    );
}

#[test]
fn labeled_response_reescapes_label() {
    let mut s = TestServer::new();
    let a = register_with_caps(&mut s, 1, "alice", "labeled-response");
    // Wire label `a\s\nb`: the parser unescapes it to a space+newline; the
    // reply must re-escape it, never emit a raw newline into the stream.
    s.line(a, r"@label=a\s\nb USERHOST alice");
    let out = s.drain(a);
    let reply = out
        .iter()
        .find(|l| l.contains("label="))
        .expect("labeled reply");
    assert!(
        !reply.contains('\n') && reply.contains(r"label=a\s\nb"),
        "label must be re-escaped, not injected raw: {reply:?}"
    );
}

#[test]
fn isupport_advertises_whox_and_length_limits() {
    let mut s = TestServer::new();
    let c = s.connect(1);
    s.line(c, "NICK alice");
    s.line(c, "USER alice 0 * :Alice");
    let burst = s.drain(c);
    let isupport: String = burst
        .iter()
        .filter(|l| l.split(' ').nth(1) == Some("005"))
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    for token in [
        "WHOX",
        "TOPICLEN=390",
        "KICKLEN=390",
        "AWAYLEN=390",
        // KICK's advertised TARGMAX must equal the enforced limit (TARGMAX=4);
        // KICK became multi-user in an earlier sweep but the advertisement stayed
        // at the old `KICK:1`, telling a state-tracking client a limit the server
        // does not keep. It now matches PRIVMSG/NOTICE.
        "TARGMAX=PRIVMSG:4,NOTICE:4,KICK:4",
        // KNOCK is implemented (cmd_knock), so it must be advertised — a client
        // that gates its /knock UI on this token was otherwise misled.
        "KNOCK",
    ] {
        assert!(
            isupport.contains(token),
            "ISUPPORT must advertise {token}: {isupport}"
        );
    }
}

// ---- sweep 4: combined MAXLIST, labeled batch, MONITOR subset ------------

#[test]
fn maxlist_is_a_combined_cap() {
    let mut s = TestServer::new();
    let a = s.register(1, "op");
    s.line(a, "JOIN #c");
    s.drain(a);
    // 50 bans + 50 quiets = 100 combined (the advertised bqeI:100 total).
    for i in 0..50 {
        s.line(a, &format!("MODE #c +b b{i}!*@*"));
        if i % 20 == 0 {
            s.drain(a);
        }
    }
    for i in 0..50 {
        s.line(a, &format!("MODE #c +q q{i}!*@*"));
        if i % 20 == 0 {
            s.drain(a);
        }
    }
    s.drain(a);
    // A 101st entry on a THIRD list must be refused — proving the cap is a
    // combined total, not per-list.
    s.line(a, "MODE #c +e over!*@*");
    let out = s.drain(a);
    assert!(
        has_numeric(&out, "478"),
        "combined MAXLIST must reject past 100 total: {out:#?}"
    );
}

#[test]
fn labeled_chathistory_has_single_batch_tag() {
    let mut s = TestServer::new_no_persistence();
    let a = register_with_caps(
        &mut s,
        1,
        "alice",
        "labeled-response batch draft/chathistory message-tags server-time",
    );
    s.line(a, "JOIN #h");
    s.drain(a);
    s.line(a, "PRIVMSG #h :hello");
    s.drain(a);
    s.line(a, "@label=42 CHATHISTORY LATEST #h * 10");
    let out = s.drain(a);
    let content = out
        .iter()
        .find(|l| l.contains("PRIVMSG #h :hello"))
        .expect("history content line");
    assert_eq!(
        content.matches("batch=").count(),
        1,
        "content line must carry exactly one batch tag, not two: {content}"
    );
    assert!(
        out.iter()
            .any(|l| l.contains("label=42") && l.contains("BATCH +")),
        "the label must ride the batch's opening line: {out:#?}"
    );
}

#[test]
fn monitor_reports_subset_before_limit() {
    let mut s = TestServer::new();
    let a = s.register(1, "watcher");
    let nicks: Vec<String> = (0..101).map(|i| format!("n{i}")).collect();
    s.line(a, &format!("MONITOR + {}", nicks.join(",")));
    let out = s.drain(a);
    assert!(has_numeric(&out, "734"), "should hit MONLISTFULL: {out:#?}");
    assert!(
        has_numeric(&out, "731"),
        "the nicks accepted before the cap must still get RPL_MONOFFLINE: {out:#?}"
    );
}

#[test]
fn monitor_online_reply_splits_to_fit_the_wire_limit() {
    // A client can monitor up to the cap, and every monitored nick can be
    // online. Emitted as one RPL_MONONLINE the full-prefix list runs to
    // thousands of bytes; the receiving client's framing discards an over-long
    // line whole, so it would never learn any of them are online.
    let mut s = TestServer::new();
    let watcher = s.register(1, "watcher");
    // 100 online peers (the MONITOR cap), each with a real prefix.
    let nicks: Vec<String> = (0..100).map(|i| format!("peer{i:03}")).collect();
    for (i, nick) in nicks.iter().enumerate() {
        s.register(100 + i as u64, nick);
    }
    // Add in chunks (the MONITOR + line itself must fit the input limit), then
    // ask for the whole status at once so the reply spans one burst.
    for chunk in nicks.chunks(20) {
        s.line(watcher, &format!("MONITOR + {}", chunk.join(",")));
        s.drain(watcher);
    }
    s.line(watcher, "MONITOR S");
    let out = s.drain(watcher);

    let online: Vec<&String> = out.iter().filter(|l| l.contains(" 730 ")).collect();
    // It must have split — 100 prefixes cannot fit one 512-byte line.
    assert!(
        online.len() > 1,
        "expected multiple RPL_MONONLINE lines, got {}: {out:#?}",
        online.len()
    );
    // Every line is a legal wire line (the content plus its CRLF).
    for line in &online {
        assert!(
            line.len() + 2 <= 512,
            "RPL_MONONLINE line is {} bytes, over the limit: {line}",
            line.len()
        );
    }
    // Nothing was lost in the split: every monitored nick is reported online.
    let joined = online
        .iter()
        .map(|l| l.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    for nick in &nicks {
        assert!(
            joined.contains(&format!("{nick}!")),
            "{nick} missing from the split reply"
        );
    }
}

#[test]
fn moderated_channel_still_allows_a_regular_member_to_set_the_topic() {
    // +m governs messages, not topic changes: a non-op/voice member of a +m,
    // -t channel may still set the topic. This pins the deliberate difference
    // between the TOPIC gate and Channel::may_speak — a "cleanup" that routed
    // TOPIC through may_speak would make +m wrongly block it, and this fails.
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    s.line(alice, "JOIN #c");
    s.drain(alice);
    s.line(bob, "JOIN #c");
    s.drain(bob);
    // Open the topic (-t) and moderate the channel (+m).
    s.line(alice, "MODE #c -t+m");
    s.drain(alice);
    s.drain(bob);

    // bob (a plain member) cannot speak under +m …
    s.line(bob, "PRIVMSG #c :hello");
    assert!(
        has_numeric(&s.drain(bob), "404"),
        "a +m channel must block a regular member's PRIVMSG"
    );
    // … but may still set the topic.
    s.line(bob, "TOPIC #c :bob's topic");
    let out = s.drain(bob);
    assert!(
        !has_numeric(&out, "482") && !has_numeric(&out, "404"),
        "a regular member must be able to set the topic of a +m -t channel: {out:#?}"
    );
    assert!(
        out.iter().any(|l| l.contains("TOPIC #c :bob's topic")),
        "the topic change should be broadcast: {out:#?}"
    );
}

#[test]
fn mode_broadcast_splits_to_fit_the_wire_limit() {
    // Many bans set in one MODE command build a broadcast line longer than the
    // 512-byte wire limit. The bans are applied server-side, but a recipient's
    // framing discards the over-long announcement whole — so other members
    // never see the bans that are now in force. State and what members observe
    // diverge silently.
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    s.line(alice, "JOIN #c");
    s.drain(alice);
    s.line(bob, "JOIN #c");
    s.drain(alice);
    s.drain(bob);

    // Six distinct ~80-byte masks: the input fits 510, the echoed broadcast
    // (with the +bbbbbb prefix and the op's own hostmask) does not.
    let masks: Vec<String> = (0..6).map(|i| format!("{}{i}", "b".repeat(78))).collect();
    s.line(alice, &format!("MODE #c +bbbbbb {}", masks.join(" ")));
    let out = s.drain(bob);

    let mode_lines: Vec<&String> = out.iter().filter(|l| l.contains(" MODE #c ")).collect();
    assert!(
        !mode_lines.is_empty(),
        "bob must see the MODE change: {out:#?}"
    );
    for line in &mode_lines {
        assert!(
            line.len() + 2 <= 512,
            "MODE broadcast line is {} bytes, over the wire limit: {line}",
            line.len()
        );
    }
    // Every ban must appear across the (possibly split) announcement.
    let joined = mode_lines
        .iter()
        .map(|l| l.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    for mask in &masks {
        assert!(
            joined.contains(mask.as_str()),
            "ban {mask} missing from the MODE broadcast"
        );
    }
}

#[test]
fn relayed_message_is_trimmed_to_the_wire_limit() {
    // The server adds the source prefix the sender didn't, so a max-length
    // PRIVMSG overflows 512 on relay and a strict client discards or truncates
    // the tail. The text is trimmed to fit before delivery, and everyone —
    // recipient and echoing sender — sees the identical trimmed message.
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "echo-message");
    let bob = s.register(2, "bob");
    s.line(alice, "JOIN #c");
    s.drain(alice);
    s.line(bob, "JOIN #c");
    s.drain(alice);
    s.drain(bob);

    // A body that would push "PRIVMSG #c :<body>" to the 510 traditional limit.
    let body = "x".repeat(510 - "PRIVMSG #c :".len());
    s.line(alice, &format!("PRIVMSG #c :{body}"));

    let relayed = s
        .drain(bob)
        .into_iter()
        .find(|l| l.contains("PRIVMSG #c"))
        .expect("bob receives the message");
    assert!(
        relayed.len() + 2 <= 512,
        "relayed line is {} bytes, over the wire limit",
        relayed.len()
    );
    // The sender's echo must be byte-identical to what the recipient saw.
    let echoed = s
        .drain(alice)
        .into_iter()
        .find(|l| l.contains("PRIVMSG #c"))
        .expect("alice echoes her own message");
    assert_eq!(
        relayed, echoed,
        "echo and relay must carry the same message"
    );
}

#[test]
fn relay_trim_lands_on_a_character_boundary() {
    // The trim is a byte budget; a multi-byte character straddling it must not
    // be cut through (that would emit invalid UTF-8, and would panic if it were
    // a naive slice).
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    let bob = s.register(2, "bob");
    s.line(alice, "JOIN #c");
    s.drain(alice);
    s.line(bob, "JOIN #c");
    s.drain(alice);
    s.drain(bob);

    // '☃' is three bytes; a run of them makes the budget land inside one.
    let body = "\u{2603}".repeat(166);
    s.line(alice, &format!("PRIVMSG #c :{body}"));
    let relayed = s
        .drain(bob)
        .into_iter()
        .find(|l| l.contains("PRIVMSG #c"))
        .expect("bob receives the message");
    assert!(relayed.len() + 2 <= 512, "{} bytes", relayed.len());
    // The relayed body is a valid prefix of the original (no split character).
    let sent_body = relayed.rsplit_once(" :").expect("trailing").1;
    assert!(body.starts_with(sent_body), "trim cut through a character");
    assert!(!sent_body.is_empty());
}

#[test]
fn multiline_flattened_line_fits_but_batch_form_stays_full() {
    // A multiline line near the input limit relays fine inside the batch to a
    // capable client (which negotiated the larger frame), but a client without
    // draft/multiline gets it flattened to a standalone PRIVMSG that must hold
    // the 512-byte wire limit — so the flattened copy is trimmed while the
    // batch copy is left full.
    let mut s = TestServer::new_no_persistence();
    let alice = register_with_caps(&mut s, 1, "alice", "batch draft/multiline message-tags");
    let bob = register_with_caps(&mut s, 2, "bob", "batch draft/multiline message-tags");
    let carol = register_with_caps(&mut s, 3, "carol", "message-tags");
    for c in [alice, bob, carol] {
        s.line(c, "JOIN #m");
    }
    for c in [alice, bob, carol] {
        s.drain(c);
    }

    // "PRIVMSG #m :<text>" must fit the 510 traditional input limit.
    let text = "x".repeat(490);
    s.line(alice, "BATCH +7 draft/multiline #m");
    s.line(alice, &format!("@batch=7 PRIVMSG #m :{text}"));
    s.line(alice, "BATCH -7");

    // Capable recipient: the inner PRIVMSG keeps the full body (its non-tag part
    // legitimately exceeds 512 — that is what multiline is for).
    let capable = s.drain(bob);
    let inner = capable
        .iter()
        .find(|l| l.contains("PRIVMSG #m"))
        .expect("bob's inner line");
    let non_tag = inner.strip_prefix('@').map_or(inner.as_str(), |r| {
        r.split_once(' ').map(|(_, rest)| rest).unwrap_or(inner)
    });
    assert!(
        non_tag.contains(&text),
        "the batch form must keep the full body"
    );
    assert!(
        non_tag.len() > 512,
        "the batch form is left full (non-tag {} bytes)",
        non_tag.len()
    );

    // Non-capable recipient: flattened to a PRIVMSG whose traditional part (the
    // non-tag portion, which the 512 limit governs) fits the wire limit.
    let flat = s.drain(carol);
    let line = flat
        .iter()
        .find(|l| l.contains("PRIVMSG #m"))
        .expect("carol's flattened line");
    let non_tag = line.strip_prefix('@').map_or(line.as_str(), |r| {
        r.split_once(' ').map(|(_, rest)| rest).unwrap_or(line)
    });
    assert!(
        non_tag.len() + 2 <= 512,
        "flattened line's traditional part is {} bytes, over the wire limit: {line}",
        non_tag.len()
    );
    // Trimmed, not dropped: a prefix of the body still arrives.
    assert!(line.contains(":xxxx"), "some of the body survived: {line}");
}

#[test]
fn chathistory_replay_of_a_multiline_line_fits_the_wire_limit() {
    // A multiline line is stored per-line and replayed by CHATHISTORY as its own
    // PRIVMSG, to a requester that need not have draft/multiline. The stored
    // body is trimmed to fit that replay line, so the replay never emits an
    // over-long PRIVMSG the requester's framing would discard.
    let mut s = TestServer::new_no_persistence();
    let alice = register_with_caps(&mut s, 1, "alice", "batch draft/multiline message-tags");
    let bob = register_with_caps(
        &mut s,
        2,
        "bob",
        "batch draft/chathistory server-time message-tags",
    );
    for c in [alice, bob] {
        s.line(c, "JOIN #m");
        s.drain(c);
    }
    s.drain(alice);

    let text = "y".repeat(490);
    s.line(alice, "BATCH +5 draft/multiline #m");
    s.line(alice, &format!("@batch=5 PRIVMSG #m :{text}"));
    s.line(alice, "BATCH -5");
    s.drain(bob);

    s.line(bob, "CHATHISTORY LATEST #m * 10");
    let out = s.drain(bob);
    let replayed = out
        .iter()
        .find(|l| l.contains("PRIVMSG #m"))
        .expect("the multiline line is replayed");
    let non_tag = replayed.strip_prefix('@').map_or(replayed.as_str(), |r| {
        r.split_once(' ').map(|(_, rest)| rest).unwrap_or(replayed)
    });
    assert!(
        non_tag.len() + 2 <= 512,
        "replayed line's traditional part is {} bytes, over the wire limit",
        non_tag.len()
    );
    assert!(replayed.contains(":yyyy"), "the body survived the replay");
}

/// Drive every "user text relayed with a server-added prefix" path to its
/// maximum and assert the relayed line still fits the wire limit. These are
/// the same shape as the PRIVMSG relay overflow: the sender's input was legal,
/// the server's added prefix pushes the relay past 512, and the recipient's
/// framing discards it whole. The debug-build funnel invariant also fires on
/// any violation, so this test doubles as its regression harness.
#[test]
fn reason_bearing_relays_fit_the_wire_limit() {
    let mut s = TestServer::new();
    // Longest identity this server permits (test config nicklen = 16).
    let long_nick = "n".repeat(16);
    let alice = s.connect(1);
    s.line(alice, &format!("NICK {long_nick}"));
    s.line(alice, &format!("USER {} 0 * :real", "u".repeat(10)));
    let reg = s.drain(alice);
    assert!(
        reg.iter().any(|l| l.contains(" 001 ")),
        "alice failed to register: {reg:#?}"
    );
    let bob = s.register(2, "bob");
    let chan = format!("#{}", "c".repeat(49));
    s.line(alice, &format!("JOIN {chan}"));
    s.drain(alice);
    s.line(bob, &format!("JOIN {chan}"));
    s.drain(alice);
    s.drain(bob);

    let assert_fits = |out: Vec<String>, what: &str, needle: &str| {
        let line = out
            .into_iter()
            .find(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("{what}: no line containing {needle}"));
        assert!(
            line.len() + 2 <= 512,
            "{what}: relayed line is {} bytes, over the wire limit: {line}",
            line.len()
        );
    };

    // TOPIC at TOPICLEN.
    s.line(alice, &format!("TOPIC {chan} :{}", "t".repeat(390)));
    assert_fits(s.drain(bob), "TOPIC", " TOPIC ");
    s.drain(alice);

    // KICK with a KICKLEN reason.
    s.line(alice, &format!("KICK {chan} bob :{}", "k".repeat(390)));
    assert_fits(s.drain(bob), "KICK", " KICK ");
    s.drain(alice);
    s.line(bob, &format!("JOIN {chan}"));
    s.drain(alice);
    s.drain(bob);

    // PART with the longest reason the input limit allows.
    let part_reason = "p".repeat(510 - format!("PART {chan} :").len());
    s.line(alice, &format!("PART {chan} :{part_reason}"));
    assert_fits(s.drain(bob), "PART", " PART ");
    s.drain(alice);
    s.line(alice, &format!("JOIN {chan}"));
    s.drain(alice);
    s.drain(bob);

    // QUIT with the longest reason the input limit allows.
    let quit_reason = "q".repeat(510 - "QUIT :".len());
    s.line(alice, &format!("QUIT :{quit_reason}"));
    assert_fits(s.drain(bob), "QUIT", " QUIT ");
}

#[test]
fn echoed_tokens_never_overflow_the_reply_explaining_them() {
    // Several replies echo a client-supplied token for attribution: an unknown
    // command (421), a bad CAP subcommand (410), an over-cap MONITOR list (734).
    // The token is bounded only by the input frame, so echoing it whole could
    // push the very reply that explains the error past the wire limit, and the
    // client's framing would then discard it. Each is clipped. The debug-build
    // wire invariant would also panic on any miss, so this is its regression.
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");

    // 421 unknown command.
    s.line(alice, &format!("{} arg", "Z".repeat(300)));
    let out = s.drain(alice);
    let n421 = out.iter().find(|l| l.contains(" 421 ")).expect("421");
    assert!(n421.len() + 2 <= 512, "421 is {} bytes", n421.len());

    // 410 invalid CAP subcommand.
    s.line(alice, &format!("CAP {}", "Q".repeat(300)));
    let out = s.drain(alice);
    let n410 = out.iter().find(|l| l.contains(" 410 ")).expect("410");
    assert!(n410.len() + 2 <= 512, "410 is {} bytes", n410.len());
}

#[test]
fn invalid_username_is_rejected_without_rewriting_identity() {
    let mut s = TestServer::new();
    let alice = s.connect(1);
    s.line(alice, "NICK alice");
    s.line(alice, "USER a@evil.com!x 0 * :real");
    assert!(
        s.drain(alice).iter().any(|l| l.contains(" 468 ")),
        "invalid username must fail loudly"
    );
    s.line(alice, "USER alice 0 * :real");
    assert!(s.drain(alice).iter().any(|l| l.contains(" 001 ")));
    let bob = s.register(2, "bob");
    for c in [alice, bob] {
        s.line(c, "JOIN #c");
    }
    s.drain(alice);
    s.drain(bob);

    s.line(alice, "PRIVMSG #c :hi");
    let relayed = s
        .drain(bob)
        .into_iter()
        .find(|l| l.contains("PRIVMSG #c"))
        .expect("bob receives the message");
    let prefix = relayed
        .strip_prefix(':')
        .and_then(|l| l.split(' ').next())
        .expect("source prefix");
    assert_eq!(prefix.matches('@').count(), 1, "one @ in prefix: {prefix}");
    assert_eq!(prefix.matches('!').count(), 1, "one ! in prefix: {prefix}");
    let user = prefix.split('!').nth(1).and_then(|r| r.split('@').next());
    assert_eq!(user, Some("alice"), "username: {prefix}");
}

#[test]
fn account_tag_value_is_escaped() {
    // A nick (hence an account name) may contain `\`, a legal nick character.
    // In an `account=` tag it must be escaped, or a client decodes `a\b` as
    // `ab` and attributes the message to a different account.
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "account-tag");
    let bob = s.register(2, "bob");
    for c in [alice, bob] {
        s.line(c, "JOIN #acct");
        s.drain(c);
    }
    s.drain(alice);
    // bob identifies to an account whose name contains a backslash.
    s.line(bob, "PRIVMSG NickServ :IDENTIFY pw");
    s.db_requests();
    s.core.handle(Input::DbReply {
        conn: bob,
        reply: e6ircd::core::DbReply::PasswordVerified {
            account: "a\\b".into(),
            origin: e6ircd::core::CredentialOrigin::NickServIdentify,
        },
    });
    s.drain(bob);
    s.drain(alice);

    s.line(bob, "PRIVMSG #acct :hi");
    let relayed = s
        .drain(alice)
        .into_iter()
        .find(|l| l.contains("PRIVMSG #acct"))
        .expect("alice receives the tagged message");
    // The tag carries the escaped form; re-parsing it recovers the real name.
    assert!(
        relayed.starts_with("@account=a\\\\b "),
        "account tag not escaped: {relayed}"
    );
    let parsed = e6irc_proto::message::Message::parse(&relayed).expect("valid line");
    let account = parsed
        .tags
        .iter()
        .find(|t| t.key == "account")
        .and_then(|t| t.value.as_deref());
    assert_eq!(account, Some("a\\b"), "round-tripped account name");
}

#[test]
fn malformed_client_tag_keys_are_not_relayed() {
    // A client-only tag key can, per the parser, hold any non-delimiter byte —
    // a control char, an emoji. The message-tags spec restricts it to
    // `+[vendor/]name`, and relaying a malformed key would push it to everyone
    // in the channel. Well-formed keys pass; malformed ones are dropped.
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "message-tags");
    let bob = register_with_caps(&mut s, 2, "bob", "message-tags");
    for c in [alice, bob] {
        s.line(c, "JOIN #t");
        s.drain(c);
    }
    s.drain(alice);

    // A valid vendor-style tag survives; an invalid one (control char) is gone.
    s.line(
        alice,
        "@+example.com/reply=abc;+bad\x02key=x PRIVMSG #t :hi",
    );
    let relayed = s
        .drain(bob)
        .into_iter()
        .find(|l| l.contains("PRIVMSG #t"))
        .expect("bob receives it");
    assert!(
        relayed.contains("+example.com/reply=abc"),
        "valid client tag dropped: {relayed}"
    );
    assert!(
        !relayed.contains("bad"),
        "malformed client tag key relayed: {relayed}"
    );
}

#[test]
fn empty_labeled_multiline_batch_still_answers_the_label() {
    // A labeled `BATCH +` opened and then closed with no content delivers
    // nothing — but the labeled command still owes a response. The framer was
    // told not to ACK the opening BATCH (the batch is its deferred response),
    // so the close must resolve the label with an ACK or a label-tracking
    // client waits forever.
    let mut s = TestServer::new_no_persistence();
    let alice = register_with_caps(
        &mut s,
        1,
        "alice",
        "batch draft/multiline message-tags labeled-response",
    );
    s.line(alice, "JOIN #m");
    s.drain(alice);
    s.line(alice, "@label=abc BATCH +9 draft/multiline #m");
    assert!(s.drain(alice).is_empty());
    s.line(alice, "BATCH -9");
    let out = s.drain(alice);
    assert!(
        out.iter()
            .any(|l| l.starts_with("@label=abc ") && l.contains("ACK")),
        "an empty labeled batch must still answer the label: {out:#?}"
    );
}

#[test]
fn refused_labeled_multiline_batch_still_answers_the_label() {
    // A labeled multiline batch whose delivery is refused at close time (the
    // channel went +m after the batch opened) sends the refusal numeric — but
    // the *opening* BATCH's label is still owed a response: no echo copy will
    // ever carry it, so the close must resolve it explicitly.
    let mut s = TestServer::new_no_persistence();
    let bob = s.register(1, "bob");
    s.line(bob, "JOIN #m");
    s.drain(bob);
    let alice = register_with_caps(
        &mut s,
        2,
        "alice",
        "batch draft/multiline message-tags labeled-response",
    );
    s.line(alice, "JOIN #m");
    s.drain(alice);
    s.line(bob, "MODE #m +m");
    s.drain(bob);
    s.drain(alice);
    s.line(alice, "@label=abc BATCH +9 draft/multiline #m");
    assert!(s.drain(alice).is_empty());
    s.line(alice, "@batch=9 PRIVMSG #m :hello");
    s.line(alice, "BATCH -9");
    let out = s.drain(alice);
    assert!(
        out.iter().any(|l| l.contains("Cannot send to channel")),
        "the refusal must be loud: {out:#?}"
    );
    assert!(
        out.iter()
            .any(|l| l.starts_with("@label=abc ") && l.contains("ACK")),
        "a refused labeled batch must still answer the label: {out:#?}"
    );
}

#[test]
fn echo_message_covers_messages_to_services() {
    // echo-message covers every message the client sends — including one to a
    // services pseudo-client. The echo is how an echo-message client renders
    // its own outgoing line; without it "/msg NickServ …" silently vanishes
    // from the sender's buffer. The echo precedes the service's reply.
    let mut s = TestServer::new();
    let alice = register_with_caps(&mut s, 1, "alice", "echo-message message-tags server-time");
    s.line(alice, "PRIVMSG NickServ :HELP");
    let out = s.drain(alice);
    let echo_pos = out
        .iter()
        .position(|l| l.contains(":alice!alice@host1.example PRIVMSG NickServ :HELP"))
        .expect("the sender's own message must be echoed");
    assert!(
        out[echo_pos].contains("msgid=") && out[echo_pos].contains("time="),
        "the echo carries the usual tags: {out:#?}"
    );
    let reply_pos = out
        .iter()
        .position(|l| l.contains("NOTICE alice"))
        .expect("the service replies");
    assert!(
        echo_pos < reply_pos,
        "echo precedes the service's reply: {out:#?}"
    );
    // Without echo-message, nothing is echoed (spec: MUST NOT).
    let bob = s.register(2, "bob");
    s.line(bob, "PRIVMSG NickServ :HELP");
    assert!(
        !s.drain(bob).iter().any(|l| l.contains("PRIVMSG NickServ")),
        "no echo without echo-message"
    );
}

#[test]
fn live_connection_pages_are_bounded_filterable_and_stable() {
    use e6ircd::core::{
        AdminReply, ConnectionTransport, LiveConnectionPageSize, LiveConnectionQuery,
    };

    let mut server = TestServer::new();
    let register = |server: &mut TestServer, id, nick, transport| {
        let connection = server.connect_with_transport(id, transport);
        server.line(connection, &format!("NICK {nick}"));
        server.line(connection, &format!("USER {nick} 0 * :Real {nick}"));
        server.drain(connection);
        connection
    };
    let alice = register(&mut server, 10, "Alice", ConnectionTransport::Tcp);
    identify(&mut server, alice, "AliceAccount");
    let bob = register(&mut server, 20, "Bob", ConnectionTransport::WebSocket);
    identify(&mut server, bob, "BobAccount");
    let carol = register(&mut server, 30, "Carol", ConnectionTransport::Local);
    server.line(carol, "OPER god letmein");
    server.drain(carol);

    let query = |before_id, page_size| LiveConnectionQuery {
        before_id,
        exact_nick: None,
        exact_account: None,
        transport: None,
        oper: None,
        page_size: LiveConnectionPageSize::new(page_size).expect("valid test page size"),
    };
    let AdminReply::Connections(first) = core_admin(
        &mut server,
        e6ircd::core::AdminRequest::ListConnections {
            query: query(None, 2),
        },
    ) else {
        panic!("expected live-connection page");
    };
    assert_eq!(
        first
            .entries
            .iter()
            .map(|entry| entry.id)
            .collect::<Vec<_>>(),
        [30, 20]
    );
    assert_eq!(first.next_before_id, Some(20));
    assert_eq!(first.entries[0].transport, ConnectionTransport::Local);
    assert_eq!(first.entries[0].idle_seconds, 0);

    // A new connection accepted after page one is newer than its cursor and
    // therefore cannot duplicate into page two.
    register(&mut server, 40, "Delta", ConnectionTransport::Tls);
    let AdminReply::Connections(second) = core_admin(
        &mut server,
        e6ircd::core::AdminRequest::ListConnections {
            query: query(first.next_before_id, 2),
        },
    ) else {
        panic!("expected second live-connection page");
    };
    assert_eq!(
        second
            .entries
            .iter()
            .map(|entry| entry.id)
            .collect::<Vec<_>>(),
        [10]
    );
    assert_eq!(second.next_before_id, None);

    for filtered in [
        LiveConnectionQuery {
            exact_nick: Some("bOB".into()),
            ..query(None, 10)
        },
        LiveConnectionQuery {
            exact_account: Some("aliceaccount".into()),
            ..query(None, 10)
        },
        LiveConnectionQuery {
            transport: Some(ConnectionTransport::Tls),
            ..query(None, 10)
        },
        LiveConnectionQuery {
            oper: Some(true),
            ..query(None, 10)
        },
    ] {
        let AdminReply::Connections(page) = core_admin(
            &mut server,
            e6ircd::core::AdminRequest::ListConnections { query: filtered },
        ) else {
            panic!("expected filtered live-connection page");
        };
        assert_eq!(page.entries.len(), 1);
    }
}

#[test]
fn immutable_connection_disconnect_cannot_follow_a_reused_nick() {
    use e6ircd::core::{AdminReply, ConnectionTransport};

    let mut server = TestServer::new();
    let old = server.register(10, "reused");
    server.core.handle(Input::Closed {
        conn: old,
        reason: "gone".into(),
    });
    let replacement = server.connect_with_transport(20, ConnectionTransport::Tls);
    server.line(replacement, "NICK reused");
    server.line(replacement, "USER reused 0 * :Replacement");
    server.drain(replacement);

    let stale = core_admin(
        &mut server,
        e6ircd::core::AdminRequest::DisconnectConnection {
            connection_id: old.0,
            reason: "stale form".into(),
            actor: "admin".into(),
        },
    );
    assert!(matches!(stale, AdminReply::ConnectionMissing));

    // The replacement still owns the nick and answers normally.
    server.line(replacement, "PING :alive");
    assert!(
        server
            .drain(replacement)
            .iter()
            .any(|line| line.contains(" PONG "))
    );

    let exact = core_admin(
        &mut server,
        e6ircd::core::AdminRequest::DisconnectConnection {
            connection_id: replacement.0,
            reason: "exact resource".into(),
            actor: "admin".into(),
        },
    );
    assert!(matches!(exact, AdminReply::Ok(_)));
}

#[test]
fn account_suspension_disconnects_every_session_and_gates_late_auth_verdicts() {
    use e6ircd::core::{AdminReply, LiveConnectionPageSize, LiveConnectionQuery};

    let mut server = TestServer::new();
    let alice_one = server.register(10, "AliceOne");
    identify(&mut server, alice_one, "Alice");
    let alice_two = server.register(20, "AliceTwo");
    identify(&mut server, alice_two, "aLICE");
    let bob = server.register(30, "Bob");
    identify(&mut server, bob, "Bob");

    let suspended = core_admin(
        &mut server,
        e6ircd::core::AdminRequest::SetAccountSuspended {
            account: "ALICE".into(),
            suspended: true,
            reason: "Account suspended".into(),
            actor: "admin".into(),
        },
    );
    assert!(matches!(suspended, AdminReply::Ok(_)));
    for connection in [alice_one, alice_two] {
        assert!(
            server
                .drain(connection)
                .iter()
                .any(|line| line.contains("ERROR") && line.contains("Account suspended")),
            "every casing of the suspended account is disconnected"
        );
    }
    server.line(bob, "PING :still-here");
    assert!(
        server.drain(bob).iter().any(|line| line.contains(" PONG ")),
        "another account is untouched"
    );

    // Model the race that matters: PostgreSQL has already verified the
    // password, but its reply reaches the ordered core after suspension.
    let late = server.register(40, "LateAlice");
    server.line(late, "PRIVMSG NickServ :IDENTIFY Alice pw");
    assert_eq!(
        server
            .db_requests()
            .into_iter()
            .filter(|request| matches!(request, e6ircd::core::DbRequest::VerifyPassword { .. }))
            .count(),
        1
    );
    server.core.handle(Input::DbReply {
        conn: late,
        reply: e6ircd::core::DbReply::PasswordVerified {
            account: "Alice".into(),
            origin: e6ircd::core::CredentialOrigin::NickServIdentify,
        },
    });
    assert!(
        server
            .drain(late)
            .iter()
            .any(|line| line.contains("Invalid password")),
        "a late success is converted to a denial"
    );

    let query = LiveConnectionQuery {
        before_id: None,
        exact_nick: None,
        exact_account: Some("alice".into()),
        transport: None,
        oper: None,
        page_size: LiveConnectionPageSize::new(10).expect("page size"),
    };
    let AdminReply::Connections(page) = core_admin(
        &mut server,
        e6ircd::core::AdminRequest::ListConnections {
            query: query.clone(),
        },
    ) else {
        panic!("expected connection page");
    };
    assert!(page.entries.is_empty(), "no Alice session survived");

    let reactivated = core_admin(
        &mut server,
        e6ircd::core::AdminRequest::SetAccountSuspended {
            account: "alice".into(),
            suspended: false,
            reason: "Account reactivated".into(),
            actor: "admin".into(),
        },
    );
    assert!(matches!(reactivated, AdminReply::Ok(_)));
    identify(&mut server, late, "Alice");
    let AdminReply::Connections(page) = core_admin(
        &mut server,
        e6ircd::core::AdminRequest::ListConnections { query },
    ) else {
        panic!("expected connection page");
    };
    assert_eq!(page.entries.len(), 1, "reactivation removes the live gate");
}

#[test]
fn suspended_accounts_are_gated_from_the_first_core_event_after_restart() {
    let mut server = TestServer::new();
    server.core.preload_suspended_accounts(vec!["alice".into()]);
    let alice = server.register(10, "Alice");
    server.line(alice, "PRIVMSG NickServ :IDENTIFY Alice pw");
    server.db_requests();
    server.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::PasswordVerified {
            account: "Alice".into(),
            origin: e6ircd::core::CredentialOrigin::NickServIdentify,
        },
    });
    assert!(
        server
            .drain(alice)
            .iter()
            .any(|line| line.contains("Invalid password"))
    );
}
