use super::*;
use crate::core::HistoryRow;
use crate::identity::{CredentialId, IssuedCredential};

const WRITER: ClockOrigin = ClockOrigin(1_700_000_000_000);

fn mono(ms: u64) -> MonoMillis {
    MonoMillis::from_millis(ms)
}

fn row(msgid: &str) -> HistoryRow {
    HistoryRow {
        msgid: msgid.into(),
        ts: Millis::from_millis(1_700_000_000_123),
        sender_prefix: "~guest!u@h".into(),
        sender_account: None,
        kind: HistoryKind::Privmsg,
        body: "hello there".into(),
        sender_is_bot: false,
        multiline: None,
        client_tags: "+draft/reply=abc".into(),
    }
}

/// A record with every field set to something other than its empty value.
fn full_record() -> SessionRecord {
    SessionRecord {
        directory_key: 42,
        host: "203.0.113.9".into(),
        transport: ConnectionTransport::Tls,
        tls: Some(TlsFacts {
            version: 0x0304,
            cipher_suite: 0x1301,
            server_name: Some("irc.example.net".into()),
            client_certificate: Some([7; 32]),
        }),
        registration: RecordedRegistration::Registered {
            nick: "alice".into(),
            user: "~alice".into(),
            realname: "Alice Liddell".into(),
        },
        cap_negotiating: true,
        cap_302: true,
        caps: 0b1011_0110,
        login: Some(RecordedLogin {
            account: "alice".into(),
            credential: CredentialId::Issued(IssuedCredential::AppPassword(9)),
            expires_at: Some(mono(90_000)),
        }),
        sasl: RecordedSasl::PlainPending,
        sasl_verify: Some(Some("lbl".into())),
        credential_attempts: 2,
        pending_identify: Some(None),
        pending_register: None,
        nick_held: Some("alice".into()),
        nick_deadlines: vec![("bob".into(), mono(70_000))],
        drop_confirmation: Some(("alice".into(), "token".into())),
        away: Some("gone fishing".into()),
        oper: Some("admin".into()),
        invisible: true,
        wallops: true,
        bot: true,
        registered_only: true,
        last_knock: Some(mono(10_000)),
        nick_changes: (3, Some(mono(20_000))),
        monitoring: vec![("carol".into(), "Carol".into())],
        channel_list: Some(RecordedSweep {
            question: RecordedQuestion::List {
                parameter: Some(">5".into()),
                parsed_at_secs: 1_700_000_000,
            },
            batch: Some("b1".into()),
            sent_through: Some("#middle".into()),
        }),
        channel_names: Some(RecordedSweep {
            question: RecordedQuestion::Names {
                multi_prefix: true,
                userhost_in_names: false,
            },
            batch: None,
            sent_through: None,
        }),
        paced_who: vec![RecordedPacedReply {
            batch: Some(("lbl".into(), "ref".into(), true)),
            lines: vec![Bytes::from_static(
                b":srv 352 alice #c u h srv bob H :0 Bob\r\n",
            )],
        }],
        anon_read_markers: vec![("~guest".into(), Millis::from_millis(1_700_000_000_000))],
        idle_since: mono(55_000),
        signon: Millis::from_millis(1_699_999_999_000),
        opened_at: mono(1_000),
        awaiting_pong: true,
        last_ping_sent: mono(60_000),
        conversations: vec![RecordedRing {
            key: "~guest\0alice".into(),
            complete: true,
            shed_through: Some((Millis::from_millis(5), "m0".into())),
            entries: vec![row("m1"), row("m2")],
        }],
    }
}

fn full_channel() -> ChannelState {
    let entry = |mask: &str| RecordedListEntry {
        mask: mask.into(),
        set_by: "alice".into(),
        set_at_secs: 1_700_000_000,
    };
    ChannelState {
        name: "#Rust".into(),
        created_at: Millis::from_millis(1_600_000_000_000),
        topic: Some(("safety first".into(), "alice!a@h".into(), 1_700_000_001)),
        flags: "nt".into(),
        key: Some("sekrit".into()),
        limit: Some(50),
        bans: vec![entry("*!*@bad")],
        quiets: vec![entry("*!*@loud")],
        ban_exceptions: vec![entry("*!*@good")],
        invite_exceptions: vec![entry("*!*@friend")],
        invited: vec![7, 8],
        last_knock: Some(mono(33_000)),
    }
}

#[test]
fn a_session_record_round_trips_in_the_newest_format() {
    let record = full_record();
    let body = record.encode(RecordFormat::NEWEST, WRITER).expect("encode");
    assert_eq!(SessionRecord::decode(body, WRITER), Ok(record));
}

/// Format 1 has no TLS facts: a record written in it reads back without them,
/// and with everything else.
#[test]
fn the_previous_format_carries_everything_but_the_tls_facts() {
    let record = full_record();
    let body = record
        .encode(RecordFormat::PREVIOUS, WRITER)
        .expect("encode");
    let read = SessionRecord::decode(body, WRITER).expect("decode");
    assert_eq!(read.tls, None);
    assert_eq!(
        read,
        SessionRecord {
            tls: None,
            ..record
        }
    );
}

/// A release reads its format and the one before; any other is refused whole,
/// by number, and never guessed at.
#[test]
fn a_format_outside_the_window_is_refused_by_number() {
    let body = full_record()
        .encode(RecordFormat::NEWEST, WRITER)
        .expect("encode");
    for number in [0u16, 3, 99, u16::MAX] {
        let mut forged = body.to_vec();
        forged[..2].copy_from_slice(&number.to_be_bytes());
        let forged = Bytes::from(forged);
        assert_eq!(
            SessionRecord::decode(forged.clone(), WRITER),
            Err(RecordError::Format(number)),
            "format {number}"
        );
        assert_eq!(
            ChannelState::decode(forged.clone(), WRITER),
            Err(RecordError::Format(number))
        );
        assert_eq!(
            CutState::decode(forged, WRITER),
            Err(RecordError::Format(number))
        );
    }
    for number in [RecordFormat::PREVIOUS, RecordFormat::NEWEST] {
        assert_eq!(RecordFormat::read(number.number()), Some(number));
    }
    assert!(RecordFormat::PREVIOUS < RecordFormat::NEWEST);
}

/// Every truncation of a body, and a body with bytes after its end, is
/// malformed: nothing reads a partial record as a whole one.
#[test]
fn a_truncated_or_overlong_body_is_malformed() {
    let body = full_record()
        .encode(RecordFormat::NEWEST, WRITER)
        .expect("encode");
    for end in 0..body.len() {
        let read = SessionRecord::decode(body.slice(..end), WRITER);
        assert!(
            matches!(read, Err(RecordError::Malformed(_))),
            "a body cut at {end} of {} read as {read:?}",
            body.len()
        );
    }
    let mut longer = body.to_vec();
    longer.push(0);
    assert!(matches!(
        SessionRecord::decode(Bytes::from(longer), WRITER),
        Err(RecordError::Malformed(_))
    ));
}

/// A monotonic reading is moved onto the reader's clock by the difference of
/// the two origins; wall-clock readings are kept as they are.
#[test]
fn monotonic_readings_move_onto_the_readers_clock() {
    let record = full_record();
    let body = record.encode(RecordFormat::NEWEST, WRITER).expect("encode");
    // The reader's monotonic clock started 40 s after the writer's.
    let reader = ClockOrigin(WRITER.0 + 40_000);
    let read = SessionRecord::decode(body, reader).expect("decode");
    assert_eq!(read.idle_since, mono(55_000 - 40_000));
    assert_eq!(read.last_ping_sent, mono(60_000 - 40_000));
    assert_eq!(read.nick_deadlines, vec![("bob".into(), mono(30_000))]);
    // Before the reader's clock began: its start, not a wrapped value.
    assert_eq!(read.opened_at, mono(0));
    assert_eq!(read.signon, record.signon);
    assert_eq!(read.conversations, record.conversations);
    // A reader whose clock started earlier sees the readings later.
    let earlier = ClockOrigin(WRITER.0 - 5_000);
    let body = record.encode(RecordFormat::NEWEST, WRITER).expect("encode");
    let read = SessionRecord::decode(body, earlier).expect("decode");
    assert_eq!(read.opened_at, mono(6_000));
}

/// The origin is fixed for a process, so an unchanged session writes the same
/// bytes, and is not sent again.
#[test]
fn an_unchanged_record_writes_the_same_bytes() {
    let record = full_record();
    let first = record.encode(RecordFormat::NEWEST, WRITER).expect("encode");
    let second = record.encode(RecordFormat::NEWEST, WRITER).expect("encode");
    assert_eq!(first, second);
    let mut changed = record;
    changed.away = None;
    assert_ne!(
        first,
        changed
            .encode(RecordFormat::NEWEST, WRITER)
            .expect("encode")
    );
}

#[test]
fn the_origin_is_the_wall_clock_less_the_monotonic_one() {
    assert_eq!(
        ClockOrigin::of(Millis::from_millis(10_000), mono(4_000)),
        ClockOrigin(6_000)
    );
    assert_eq!(
        ClockOrigin::of(Millis::from_millis(4_000), mono(10_000)),
        ClockOrigin(-6_000)
    );
}

#[test]
fn a_channel_state_round_trips_in_both_formats() {
    let state = full_channel();
    for format in [RecordFormat::PREVIOUS, RecordFormat::NEWEST] {
        let body = state.encode(format, WRITER).expect("encode");
        assert_eq!(ChannelState::decode(body, WRITER), Ok(state.clone()));
    }
    let empty = ChannelState {
        name: "#e".into(),
        created_at: Millis::from_millis(0),
        topic: None,
        flags: String::new(),
        key: None,
        limit: None,
        bans: Vec::new(),
        quiets: Vec::new(),
        ban_exceptions: Vec::new(),
        invite_exceptions: Vec::new(),
        invited: Vec::new(),
        last_knock: None,
    };
    let body = empty.encode(RecordFormat::NEWEST, WRITER).expect("encode");
    assert_eq!(ChannelState::decode(body, WRITER), Ok(empty));
}

#[test]
fn a_member_entry_round_trips() {
    for (op, voice) in [(false, false), (true, false), (false, true), (true, true)] {
        let entry = MemberEntry { op, voice };
        let body = entry.encode(RecordFormat::NEWEST, WRITER).expect("encode");
        assert_eq!(MemberEntry::decode(body, WRITER), Ok(entry));
    }
}

#[test]
fn the_cut_state_round_trips_and_refuses_impossible_buckets() {
    let state = CutState {
        whowas: vec![RecordedWhowas {
            key: "alice".into(),
            nick: "Alice".into(),
            user: "~a".into(),
            host: "h".into(),
            realname: "A".into(),
            signoff: Millis::from_millis(1_700_000_000_000),
        }],
        most_users: 1234,
        registration_buckets: vec![("203.0.113.0/24".into(), 2.5, mono(80_000))],
        edges: vec!["edge-a".into(), "edge-b".into()],
    };
    let body = state.encode(RecordFormat::NEWEST, WRITER).expect("encode");
    assert_eq!(CutState::decode(body, WRITER), Ok(state.clone()));
    for tokens in [f64::NAN, f64::INFINITY, -1.0] {
        let forged = CutState {
            registration_buckets: vec![("k".into(), tokens, mono(0))],
            ..state.clone()
        };
        let body = forged.encode(RecordFormat::NEWEST, WRITER).expect("encode");
        assert!(
            matches!(
                CutState::decode(body, WRITER),
                Err(RecordError::Malformed(_))
            ),
            "{tokens} tokens"
        );
    }
}

/// A small generator, so the round trip is checked over many shapes without
/// a property-testing dependency: a fixed seed, so a failure reproduces.
struct Shapes(u64);

impl Shapes {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn flip(&mut self) -> bool {
        self.next() & 1 == 1
    }

    fn text(&mut self) -> String {
        let len = (self.next() % 24) as usize;
        (0..len)
            .map(|_| char::from_u32(0x20 + (self.next() % 0x2000) as u32).unwrap_or('x'))
            .collect()
    }

    fn maybe<T>(&mut self, make: impl FnOnce(&mut Self) -> T) -> Option<T> {
        if self.flip() { Some(make(self)) } else { None }
    }

    fn many<T>(&mut self, mut make: impl FnMut(&mut Self) -> T) -> Vec<T> {
        let count = self.next() % 4;
        (0..count).map(|_| make(self)).collect()
    }
}

fn shaped_record(shapes: &mut Shapes) -> SessionRecord {
    let mut record = full_record();
    record.directory_key = shapes.next();
    record.host = shapes.text();
    record.tls = shapes.maybe(|s| TlsFacts {
        version: s.next() as u16,
        cipher_suite: s.next() as u16,
        server_name: s.maybe(Shapes::text),
        client_certificate: s.maybe(|s| [s.next() as u8; 32]),
    });
    record.registration = if shapes.flip() {
        RecordedRegistration::Registering {
            nick: shapes.maybe(Shapes::text),
            user: shapes.maybe(Shapes::text),
            realname: shapes.maybe(Shapes::text),
            refused_nick: shapes.maybe(Shapes::text),
        }
    } else {
        RecordedRegistration::Registered {
            nick: shapes.text(),
            user: shapes.text(),
            realname: shapes.text(),
        }
    };
    record.caps = shapes.next() as u32;
    record.login = shapes.maybe(|s| RecordedLogin {
        account: s.text(),
        credential: match s.next() % 3 {
            0 => CredentialId::AccountPassword,
            1 => CredentialId::Issued(IssuedCredential::AppPassword(s.next().cast_signed())),
            _ => CredentialId::Issued(IssuedCredential::ApiToken(s.next().cast_signed())),
        },
        expires_at: s.maybe(|s| mono(s.next() >> 20)),
    });
    record.sasl = match shapes.next() % 4 {
        0 => RecordedSasl::Idle,
        1 => RecordedSasl::PlainPending,
        2 => RecordedSasl::BearerPending,
        _ => RecordedSasl::Verifying,
    };
    record.sasl_verify = shapes.maybe(|s| s.maybe(Shapes::text));
    record.away = shapes.maybe(Shapes::text);
    record.monitoring = shapes.many(|s| (s.text(), s.text()));
    record.nick_deadlines = shapes.many(|s| (s.text(), mono(s.next() >> 20)));
    record.channel_list = shapes.maybe(|s| RecordedSweep {
        question: RecordedQuestion::List {
            parameter: s.maybe(Shapes::text),
            parsed_at_secs: s.next(),
        },
        batch: s.maybe(Shapes::text),
        sent_through: s.maybe(Shapes::text),
    });
    record.paced_who = shapes.many(|s| RecordedPacedReply {
        batch: s.maybe(|s| (s.text(), s.text(), s.flip())),
        lines: s.many(|s| Bytes::from(s.text())),
    });
    record.idle_since = mono(shapes.next() >> 20);
    record.conversations = shapes.many(|s| RecordedRing {
        key: s.text(),
        complete: s.flip(),
        shed_through: s.maybe(|s| (Millis::from_millis(s.next() >> 20), s.text())),
        entries: s.many(|s| row(&s.text())),
    });
    record
}

#[test]
fn records_of_many_shapes_round_trip_in_both_formats() {
    let mut shapes = Shapes(0x9e37_79b9_7f4a_7c15);
    for _ in 0..500 {
        let record = shaped_record(&mut shapes);
        let body = record.encode(RecordFormat::NEWEST, WRITER).expect("encode");
        assert_eq!(SessionRecord::decode(body, WRITER), Ok(record.clone()));
        let body = record
            .encode(RecordFormat::PREVIOUS, WRITER)
            .expect("encode");
        assert_eq!(
            SessionRecord::decode(body, WRITER),
            Ok(SessionRecord {
                tls: None,
                ..record
            })
        );
    }
}

/// Whatever bytes arrive, reading them ends in a record or an error, never a
/// panic: a body is what an edge — a separate process — hands back. One that
/// reads writes back as the same bytes (the `held_bodies` fuzz target's
/// property, over the shapes a mutated record takes).
#[test]
fn arbitrary_bytes_never_panic_a_reader() {
    let mut shapes = Shapes(7);
    let body = full_record()
        .encode(RecordFormat::NEWEST, WRITER)
        .expect("encode");
    let mut read = 0;
    for _ in 0..2000 {
        let mut bytes = body.to_vec();
        for _ in 0..(shapes.next() % 8) {
            let at = (shapes.next() as usize) % bytes.len();
            bytes[at] = shapes.next() as u8;
        }
        let bytes = Bytes::from(bytes);
        if let Ok(record) = SessionRecord::decode(bytes.clone(), WRITER)
            && bytes[2..10] == body[2..10]
        {
            let format = RecordFormat::read(u16::from_be_bytes([bytes[0], bytes[1]]))
                .expect("a body that read has a format read");
            assert_eq!(
                record.encode(format, WRITER).expect("encode"),
                bytes,
                "{record:?} writes differently"
            );
            read += 1;
        }
        drop(ChannelState::decode(bytes.clone(), WRITER));
        drop(MemberEntry::decode(bytes.clone(), WRITER));
        drop(CutState::decode(bytes, WRITER));
    }
    assert!(read > 0, "no mutation read: the round trip went unchecked");
}
