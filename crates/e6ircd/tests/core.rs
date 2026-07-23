//! Core worker tests: drive `Core::handle` directly with events and
//! assert on per-connection output queues. No sockets, no runtime —
//! fully deterministic.

use e6irc_queue::{Config, Policy, Receiver, queue};
use e6ircd::core::{ConnId, Core, CoreConfig, Input, Output};

struct TestServer {
    core: Core,
    conns: Vec<(ConnId, Receiver<Output>)>,
    db_rx: Receiver<e6ircd::core::DbRequest>,
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
        fn advancing() -> u64 {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NOW_MS: AtomicU64 = AtomicU64::new(1_000_000_000);
            NOW_MS.fetch_add(1, Ordering::Relaxed)
        }
        Self::with_config(false, advancing, 256)
    }

    /// A database-backed server with a deliberately small per-connection
    /// output bound, for exercising SendQ-style limits.
    fn with_sendq(sendq: usize) -> Self {
        Self::with_config(true, || 1_000_000_000, sendq)
    }

    fn with_persistence(sasl_enabled: bool) -> Self {
        Self::with_config(sasl_enabled, || 1_000_000_000, 256)
    }

    fn with_config(sasl_enabled: bool, clock: fn() -> u64, sendq: usize) -> Self {
        let (db_tx, db_rx) = queue(Config {
            name: "test-db",
            capacity: 64,
            policy: Policy::Fifo,
        });
        Self {
            core: Core::new(
                CoreConfig {
                    server_name: "irc.test.example".into(),
                    network_name: "TestNet".into(),
                    description: "test server".into(),
                    registration_before_connect: false,
                    registration_require_email: false,
                    sendq,
                    motd: vec!["Welcome to the test net".into()],
                    nicklen: 16,
                    sasl_enabled,
                    max_hot_channels: 8192,
                    opers: vec![("god".into(), "letmein".into())],
                    clock,
                    command_burst: None,
                },
                db_tx,
            ),
            conns: Vec::new(),
            db_rx,
        }
    }

    /// Drain requests the core sent to the (fake) DB worker.
    fn db_requests(&mut self) -> Vec<e6ircd::core::DbRequest> {
        let mut out = Vec::new();
        while let Some(env) = self.db_rx.try_pop() {
            out.push(env.payload);
        }
        out
    }

    fn connect(&mut self, id: u64) -> ConnId {
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
        },
    });
    s.drain(conn);
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
    assert!(
        has_numeric(&out, "442"),
        "non-member must get ERR_NOTONCHANNEL: {out:#?}"
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
    } = &req[0]
    else {
        panic!("expected VerifyPassword, got {:?}", req[0]);
    };
    assert_eq!(*conn, c);
    assert_eq!(account, "alice");
    assert_eq!(password, "hunter2");

    // inject the verification result
    s.core.handle(Input::DbReply {
        conn: c,
        reply: e6ircd::core::DbReply::PasswordVerified {
            account: "alice".into(),
        },
    });
    let out = s.drain(c);
    assert!(has_numeric(&out, "900"), "{out:#?}");
    assert!(has_numeric(&out, "903"), "{out:#?}");

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
        reply: e6ircd::core::DbReply::PasswordRejected,
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
            reply: e6ircd::core::DbReply::PasswordRejected,
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
fn unregistered_connection_is_reaped_after_registration_timeout() {
    let mut s = TestServer::new();
    let c = s.connect(1);
    s.line(c, "NICK half"); // never sends USER — registration never completes
    s.drain(c);
    // A tick past the registration deadline (the test clock is a constant
    // 1_000_000_000 ms, so `now` is supplied via the tick).
    s.core.handle(Input::Tick {
        now: 1_000_000_000 + 60_000,
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
        now: 1_000_000_000 + 121_000,
    });
    assert!(
        s.drain(alice).iter().any(|l| l.starts_with("PING ")),
        "idle client must be pinged"
    );
    // No PONG; past the pong deadline (60s) → reaped.
    s.core.handle(Input::Tick {
        now: 1_000_000_000 + 121_000 + 61_000,
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
        now: 1_000_000_000 + 121_000,
    });
    assert!(s.drain(alice).iter().any(|l| l.starts_with("PING ")));
    s.line(alice, "PONG :irc.test.example"); // client answers the ping
    s.core.handle(Input::Tick {
        now: 1_000_000_000 + 300_000,
    });
    assert!(
        !s.drain(alice).iter().any(|l| l.contains("Ping timeout")),
        "a client that PONGs must not be reaped"
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
        now: 1_000_000_000 + 121_000,
    }); // liveness PING
    assert!(s.drain(alice).iter().any(|l| l.starts_with("PING ")));
    // The client sends a normal command instead of a literal PONG — still alive.
    s.line(alice, "PRIVMSG #a :still here");
    s.drain(alice);
    s.core.handle(Input::Tick {
        now: 1_000_000_000 + 300_000,
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
        now: 1_000_000_000 + 121_000,
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
        now: 1_000_000_000 + 141_000,
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
    s.drain(c);
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
        }]
    );
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::PasswordVerified {
            account: "alice".into(),
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
        reply: e6ircd::core::DbReply::PasswordRejected,
    });
    let out = s.drain(alice);
    assert!(out[0].contains("Invalid password"), "{out:#?}");
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
        },
    });
    s.drain(alice);
    s.line(alice, "PRIVMSG ChanServ :REGISTER #mine");
    let req = s.db_requests();
    assert_eq!(
        req,
        vec![e6ircd::core::DbRequest::RegisterChannel {
            conn: alice,
            channel: "#mine".into(),
            founder_account: "alice".into(),
        }]
    );
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::ChannelRegistered {
            channel: "#mine".into(),
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
fn plain_who_still_works_alongside_whox() {
    let mut s = TestServer::new();
    let alice = s.register(1, "alice");
    s.line(alice, "JOIN #wx");
    s.drain(alice);
    s.line(alice, "WHO #wx");
    let out = s.drain(alice);
    assert!(has_numeric(&out, "352") && has_numeric(&out, "315"));
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

    // set a marker → echoed to the setter and the account's other client
    s.line(a1, "MARKREAD #room timestamp=2026-07-18T12:00:00.000Z");
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
            clock: || 1_000_000_000,
            command_burst: None,
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
        targets: vec![("#a".into(), 1_000_000_000), ("#b".into(), 999_999_000)],
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
    s.drain(boss);
    let persisted = s.db_requests().into_iter().any(|r| {
        matches!(r,
            e6ircd::core::DbRequest::SetChannelTopic { channel, topic: Some((text, ..)) }
            if channel == "#reg" && text == "new topic")
    });
    assert!(persisted, "SetChannelTopic not queued");

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

    // Turn KEEPTOPIC off: it persists the flag and clears the retained topic.
    s.line(boss, "PRIVMSG ChanServ :SET #reg KEEPTOPIC OFF");
    assert!(
        s.drain(boss)
            .iter()
            .any(|l| l.contains("KEEPTOPIC") && l.to_ascii_uppercase().contains("OFF")),
        "no KEEPTOPIC OFF confirmation"
    );
    let reqs = s.db_requests();
    assert!(
        reqs.iter().any(|r| matches!(r,
            e6ircd::core::DbRequest::SetChannelKeeptopic { channel, keeptopic: false } if channel == "#reg")),
        "KEEPTOPIC flag not persisted"
    );
    assert!(
        reqs.iter().any(|r| matches!(r,
            e6ircd::core::DbRequest::SetChannelTopic { channel, topic: None } if channel == "#reg")),
        "retained topic not cleared on KEEPTOPIC OFF"
    );

    // With KEEPTOPIC off, a new topic is NOT persisted for retention.
    s.line(boss, "TOPIC #reg :while off");
    s.drain(boss);
    assert!(
        !s.db_requests()
            .into_iter()
            .any(|r| matches!(r, e6ircd::core::DbRequest::SetChannelTopic { .. })),
        "topic wrongly persisted while KEEPTOPIC is off"
    );

    // Turning it back on resumes persistence.
    s.line(boss, "PRIVMSG ChanServ :SET #reg KEEPTOPIC ON");
    s.drain(boss);
    s.db_requests();
    s.line(boss, "TOPIC #reg :back on");
    s.drain(boss);
    assert!(
        s.db_requests().into_iter().any(|r| matches!(r,
            e6ircd::core::DbRequest::SetChannelTopic { channel, topic: Some((text, ..)) }
            if channel == "#reg" && text == "back on")),
        "topic not persisted after KEEPTOPIC ON"
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
    assert!(
        s.db_requests().into_iter().any(|r| matches!(r,
            e6ircd::core::DbRequest::SetChannelMlock { channel, mlock: Some(spec) }
            if channel == "#reg" && spec == "+m-t")),
        "mlock not persisted"
    );

    // Changing a locked mode the wrong way is refused (no MODE echo).
    s.line(boss, "MODE #reg -m");
    assert!(
        !s.drain(boss).iter().any(|l| l.contains(" MODE ")),
        "locked -m was allowed"
    );
    s.line(boss, "MODE #reg +t");
    assert!(
        !s.drain(boss).iter().any(|l| l.contains(" MODE ")),
        "locked +t was allowed"
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
                password: "hunter2".into(),
                origin: e6ircd::core::AccountOrigin::RegisterCommand,
            }],
            "REGISTER {arg} must register the caller's own nick"
        );
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
        rows: Vec::new(),
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
                clock: || 1_000_000_000,
                command_burst: None,
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
    let out = s.drain(boss);
    assert!(
        out.iter().any(|l| l.contains("has been dropped")),
        "no drop confirmation: {out:#?}"
    );
    let dropped = s.db_requests().into_iter().any(
        |r| matches!(r, e6ircd::core::DbRequest::DropChannel { channel } if channel == "#room"),
    );
    assert!(dropped, "DropChannel not queued");

    // Registration is gone from the hot map: a second DROP is refused.
    s.line(boss, "PRIVMSG ChanServ :DROP #room");
    assert!(
        s.drain(boss).iter().any(|l| l.contains("not the founder")),
        "channel still registered after drop"
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

    // Founder grants +o access to "alice"; it persists.
    s.line(boss, "PRIVMSG ChanServ :FLAGS #chan alice +o");
    assert!(
        s.drain(boss).iter().any(|l| l.contains("are now +o")),
        "no flags confirmation"
    );
    let persisted = s.db_requests().into_iter().any(|r| {
        matches!(r,
            e6ircd::core::DbRequest::SetChannelAccess { channel, account, flags: Some(f) }
            if channel == "#chan" && account == "alice" && f == "o")
    });
    assert!(persisted, "SetChannelAccess not queued");

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
    s.core.handle(Input::DbReply {
        conn: boss,
        reply: e6ircd::core::DbReply::FounderChanged {
            channel: "#room".to_string(),
            account: "alice".to_string(),
        },
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
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::FounderChangeFailed {
            channel: "#room".to_string(),
        },
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

// D-lines ban by host/IP; X-lines ban by realname (gecos). Same machinery
// as K-lines, differing only in the session field the mask tests against.

#[test]
fn oper_dline_bans_by_host() {
    let mut s = TestServer::new();
    let op = s.register(1, "god");
    s.line(op, "OPER god letmein");
    s.drain(op);

    s.line(op, "DLINE host7.example :bad netblock");
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
    s.drain(op);
    assert!(
        audits(&mut s)
            .iter()
            .any(|(a, t)| a == "KLINE" && t == "baddie@*"),
        "KLINE not audited"
    );

    s.line(op, "UNKLINE baddie@*");
    s.drain(op);
    assert!(
        audits(&mut s)
            .iter()
            .any(|(a, t)| a == "UNKLINE" && t == "baddie@*"),
        "UNKLINE not audited"
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
        "KICK:1",
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
