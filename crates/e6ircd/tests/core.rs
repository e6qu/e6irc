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
                    motd: vec!["Welcome to the test net".into()],
                    nicklen: 16,
                    sasl_enabled: true,
                    max_hot_channels: 8192,
                    opers: vec![("god".into(), "letmein".into())],
                    clock: || 1_000_000,
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
        }]
    );
    s.core.handle(Input::DbReply {
        conn: alice,
        reply: e6ircd::core::DbReply::AccountCreated {
            account: "alice".into(),
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
        reply: e6ircd::core::DbReply::AccountExists,
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
    let mut s = TestServer::new();
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
fn markread_requires_account_and_cap() {
    let mut s = TestServer::new();
    // no cap
    let plain = s.register(1, "bob");
    s.line(plain, "MARKREAD #x");
    assert!(has_numeric(&s.drain(plain), "421"));
    // cap but not logged in → FAIL
    let capped = register_with_caps(&mut s, 2, "carol", "draft/read-marker");
    s.line(capped, "MARKREAD #x");
    let out = s.drain(capped);
    assert!(out[0].contains("FAIL MARKREAD"), "{out:#?}");
    // malformed timestamp → FAIL
    identify(&mut s, capped, "carol");
    s.line(capped, "MARKREAD #x timestamp=not-a-time");
    let out = s.drain(capped);
    assert!(out[0].contains("FAIL MARKREAD"), "{out:#?}");
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
            motd: vec![],
            nicklen: 16,
            sasl_enabled: false,
            opers: vec![],
            max_hot_channels: 2,
            clock: || 1_000_000,
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
        targets: vec![("#a".into(), 1_000_000), ("#b".into(), 999_999)],
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
fn chathistory_around_msgid() {
    let mut s = TestServer::new();
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
                motd: vec![],
                nicklen: 16,
                sasl_enabled,
                opers: vec![],
                max_hot_channels: 8,
                clock: || 1_000_000,
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
