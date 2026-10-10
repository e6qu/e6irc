use super::*;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::Bytes;

fn session(id: u64) -> SessionId {
    SessionId::new(id).expect("non-zero")
}

fn hello() -> Hello {
    Hello {
        versions: VersionRange::spoken(),
        role: Role::Serving,
        edge: EdgeName::new("edge-a").expect("name"),
        stream: Stream::Sessions { index: 3 },
        slot: Slot::new(7),
        highest_epoch: 41,
        listeners: vec![
            ListenerReport {
                kind: ListenerKind::Irc,
                addr: "0.0.0.0:6697".parse().expect("address"),
                certificate: Some("/etc/e6irc/tls/fullchain.pem".into()),
                proxy_protocol: false,
            },
            ListenerReport {
                kind: ListenerKind::Http,
                addr: "[::]:8080".parse().expect("address"),
                certificate: None,
                proxy_protocol: true,
            },
        ],
        cut: CutId::new(0x5eed),
    }
}

fn tls() -> TlsFacts {
    TlsFacts {
        version: 0x0304,
        cipher_suite: 0x1302,
        server_name: Some("irc.example".into()),
        client_certificate: Some([7; 32]),
    }
}

fn part(index: u32, last: bool, bytes: &'static [u8]) -> BodyPart {
    BodyPart {
        index,
        last,
        bytes: Bytes::from_static(bytes),
    }
}

fn welcome() -> Welcome {
    Welcome {
        version: LINK_VERSION,
        epoch: 42,
        slot: Slot::new(7).expect("slot"),
        streams: 4,
        terms: EdgeTerms {
            trusted_proxies: vec![
                (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
                (IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
            ],
            max_connections_per_ip: Some(3),
            sendq_bytes: 512 * 1024,
            command_flood: Some(CommandFloodTerms { burst: 10, rate: 2 }),
            line_credit: 256,
        },
        admission: Admission::Upload,
    }
}

fn every_edge_frame() -> Vec<EdgeFrame> {
    vec![
        EdgeFrame::Hello(hello()),
        EdgeFrame::Hello(Hello {
            role: Role::Observer,
            stream: Stream::Http,
            slot: None,
            listeners: Vec::new(),
            cut: None,
            ..hello()
        }),
        EdgeFrame::Hello(Hello {
            versions: VersionRange::new(1, 1).expect("range"),
            cut: None,
            ..hello()
        }),
        EdgeFrame::Open(
            session(1 << 48 | 5),
            Open {
                kind: SessionKind::Irc,
                address: "192.0.2.1".parse().expect("address"),
                transport: Transport::Tls,
                tls: Some(tls()),
            },
        ),
        EdgeFrame::Open(
            session(1 << 48 | 6),
            Open {
                kind: SessionKind::Irc,
                address: "192.0.2.1".parse().expect("address"),
                transport: Transport::Tls,
                tls: Some(TlsFacts {
                    server_name: None,
                    client_certificate: None,
                    ..tls()
                }),
            },
        ),
        EdgeFrame::Open(
            session(9),
            Open {
                kind: SessionKind::Ui,
                address: "2001:db8::1".parse().expect("address"),
                transport: Transport::SecureWebSocket,
                tls: None,
            },
        ),
        EdgeFrame::Line(session(9), Bytes::from_static(b"PRIVMSG #a :hi")),
        EdgeFrame::Line(session(9), Bytes::from(vec![b'x'; MAX_LINE_LEN])),
        EdgeFrame::OverlongLine(session(9), Some("abc".into())),
        EdgeFrame::OverlongLine(session(9), None),
        EdgeFrame::Message(session(9), UiMessage::Text("{\"x\":1}".into())),
        EdgeFrame::Message(session(9), UiMessage::Binary),
        EdgeFrame::Closed(session(9), ClosedReason::ByClient),
        EdgeFrame::Closed(session(9), ClosedReason::ReadFailed("reset".into())),
        EdgeFrame::Closed(session(9), ClosedReason::MessageTooBig),
        EdgeFrame::Closed(session(9), ClosedReason::WriteFailed(WriteFailure::Stalled)),
        EdgeFrame::Closed(session(9), ClosedReason::WriterPanicked),
        EdgeFrame::Closed(session(9), ClosedReason::Stopped("gone".into())),
        EdgeFrame::Drained(session(9), u64::MAX),
        EdgeFrame::Paused,
        EdgeFrame::Upload(
            session(9),
            Upload {
                kind: SessionKind::Irc,
                address: "192.0.2.7".parse().expect("address"),
                transport: Transport::Tls,
                tls: Some(tls()),
                since_input_ms: 1234,
                unwritten: 77,
                unconfirmed: 2,
                closed: Some(ClosedReason::ReadFailed("reset".into())),
            },
        ),
        EdgeFrame::HomeUpload(session(11)),
        EdgeFrame::Upload(
            session(10),
            Upload {
                kind: SessionKind::Ui,
                address: "2001:db8::7".parse().expect("address"),
                transport: Transport::WebSocket,
                tls: None,
                since_input_ms: 0,
                unwritten: 0,
                unconfirmed: 0,
                closed: None,
            },
        ),
        EdgeFrame::RecordUpload(
            session(9),
            RecordPart {
                revision: 12,
                part: part(0, false, b"first"),
            },
        ),
        EdgeFrame::RecordUpload(
            session(9),
            RecordPart {
                revision: 12,
                part: part(1, true, b""),
            },
        ),
        EdgeFrame::ReplicaUpload(Replica {
            channel: Bytes::from_static(b"#zero"),
            revision: 4,
            change: ReplicaChange::State(Bytes::from_static(b"state")),
        }),
        EdgeFrame::CutUpload(CutPart {
            cut: CutId::new(9).expect("cut"),
            part: part(0, true, b"whowas"),
        }),
        EdgeFrame::UploadDone,
    ]
}

fn every_core_frame() -> Vec<CoreFrame> {
    vec![
        CoreFrame::Welcome(welcome()),
        CoreFrame::Welcome(Welcome {
            terms: EdgeTerms {
                trusted_proxies: Vec::new(),
                max_connections_per_ip: None,
                command_flood: None,
                ..welcome().terms
            },
            ..welcome()
        }),
        CoreFrame::Refused("no".into()),
        CoreFrame::Output(session(3), Bytes::from_static(b"PING :x\r\n")),
        CoreFrame::Kill(
            session(3),
            Bytes::from_static(b"ERROR :Closing Link: h (SendQ exceeded)\r\n"),
        ),
        CoreFrame::End(session(3), None),
        CoreFrame::End(
            session(3),
            Some(CloseFrame {
                code: 1008,
                reason: "policy".into(),
            }),
        ),
        CoreFrame::FloodExempt(session(3), true),
        CoreFrame::Credit(Credit::Stream(17)),
        CoreFrame::Credit(Credit::Session(session(3), 8192)),
        CoreFrame::Welcome(Welcome {
            version: 1,
            admission: Admission::Serve,
            ..welcome()
        }),
        CoreFrame::Welcome(Welcome {
            admission: Admission::Hold,
            ..welcome()
        }),
        CoreFrame::Pause,
        CoreFrame::Resume,
        CoreFrame::Ack(
            session(3),
            Ack {
                through: 9,
                retained: vec![2, 3, 9],
            },
        ),
        CoreFrame::Ack(session(3), Ack::default()),
        CoreFrame::Record(
            session(3),
            RecordPart {
                revision: 1,
                part: part(0, true, b"record"),
            },
        ),
        CoreFrame::Replica(Replica {
            channel: Bytes::from_static(b"#zero"),
            revision: 5,
            change: ReplicaChange::Member(session(3), Bytes::from_static(b"o")),
        }),
        CoreFrame::Replica(Replica {
            channel: Bytes::from_static(b"#zero"),
            revision: 6,
            change: ReplicaChange::MemberGone(session(3)),
        }),
        CoreFrame::Replica(Replica {
            channel: Bytes::from_static(b"#zero"),
            revision: 7,
            change: ReplicaChange::Gone,
        }),
        CoreFrame::CutState(CutPart {
            cut: CutId::new(9).expect("cut"),
            part: part(3, false, b"buckets"),
        }),
        CoreFrame::Cut(Cut {
            cut: CutId::new(9).expect("cut"),
            epoch: 42,
        }),
        CoreFrame::Home(session(11)),
    ]
}

fn round_trip<F: Frame + PartialEq + std::fmt::Debug + Clone>(frames: Vec<F>) {
    let mut buffer = BytesMut::new();
    for frame in &frames {
        encode(frame, &mut buffer).expect("encodes");
    }
    // Fed one byte at a time, the same frames come out.
    let whole = buffer.clone();
    let mut fed = BytesMut::new();
    let mut decoded = Vec::new();
    for byte in whole.iter() {
        fed.extend_from_slice(&[*byte]);
        while let Some(frame) = decode::<F>(&mut fed).expect("decodes") {
            decoded.push(frame);
        }
    }
    assert_eq!(decoded, frames);
    assert!(fed.is_empty());
}

#[test]
fn every_frame_survives_the_round_trip_in_any_chunking() {
    round_trip(every_edge_frame());
    round_trip(every_core_frame());
}

#[test]
fn a_frame_read_the_wrong_way_round_does_not_decode() {
    for frame in every_edge_frame() {
        let mut bytes = encoded(&frame).expect("encodes");
        assert!(
            decode::<CoreFrame>(&mut bytes).is_err(),
            "{frame:?} decoded as a core frame"
        );
    }
    for frame in every_core_frame() {
        let mut bytes = encoded(&frame).expect("encodes");
        assert!(
            decode::<EdgeFrame>(&mut bytes).is_err(),
            "{frame:?} decoded as an edge frame"
        );
    }
}

#[test]
fn a_field_past_its_bound_is_refused_when_written_and_when_read() {
    let long = EdgeFrame::Line(session(1), Bytes::from(vec![b'x'; MAX_LINE_LEN + 1]));
    let mut out = BytesMut::from(&b"kept"[..]);
    assert!(matches!(
        encode(&long, &mut out),
        Err(EncodeError::OverBound { field: "line", .. })
    ));
    assert_eq!(&out[..], b"kept", "a refused frame writes nothing");

    // The same line written by hand, past the bound, is refused by the reader.
    let mut forged = BytesMut::new();
    let payload_len = 4 + MAX_LINE_LEN + 1;
    forged.put_u32(u32::try_from(1 + 8 + payload_len).expect("small"));
    forged.put_u8(0x03);
    forged.put_u64(1);
    forged.put_u32(u32::try_from(MAX_LINE_LEN + 1).expect("small"));
    forged.put_slice(&vec![b'x'; MAX_LINE_LEN + 1]);
    assert!(matches!(
        decode::<EdgeFrame>(&mut forged),
        Err(DecodeError::OverBound { field: "line", .. })
    ));
}

#[test]
fn a_length_word_past_the_frame_bound_is_refused_before_it_is_buffered() {
    let mut buffer = BytesMut::new();
    buffer.put_u32(u32::try_from(MAX_FRAME_LEN + 1).expect("small"));
    assert_eq!(
        decode::<EdgeFrame>(&mut buffer),
        Err(DecodeError::LongFrame {
            length: MAX_FRAME_LEN + 1
        })
    );
    let mut short = BytesMut::new();
    short.put_u32(3);
    assert_eq!(
        decode::<EdgeFrame>(&mut short),
        Err(DecodeError::ShortFrame { length: 3 })
    );
}

#[test]
fn session_frames_name_a_session_and_link_frames_none() {
    let mut open_without = encoded(&EdgeFrame::Drained(session(5), 1)).expect("encodes");
    open_without[5..13].copy_from_slice(&0u64.to_be_bytes());
    assert_eq!(
        decode::<EdgeFrame>(&mut open_without),
        Err(DecodeError::MissingSession)
    );
    let mut hello_with = encoded(&EdgeFrame::Hello(hello())).expect("encodes");
    hello_with[5..13].copy_from_slice(&9u64.to_be_bytes());
    assert!(matches!(
        decode::<EdgeFrame>(&mut hello_with),
        Err(DecodeError::UnexpectedSession { .. })
    ));
}

#[test]
fn trailing_bytes_after_the_last_field_are_refused() {
    let mut bytes = encoded(&CoreFrame::FloodExempt(session(2), false)).expect("encodes");
    bytes.put_u8(0);
    let length = u32::from_be_bytes(bytes[..4].try_into().expect("word")) + 1;
    bytes[..4].copy_from_slice(&length.to_be_bytes());
    assert_eq!(
        decode::<CoreFrame>(&mut bytes),
        Err(DecodeError::TrailingBytes { count: 1 })
    );
}

#[test]
fn a_core_accepts_its_own_version_and_the_one_before_and_names_both_otherwise() {
    assert_eq!(negotiate(VersionRange::spoken()), Ok(LINK_VERSION));
    let newer = VersionRange::new(LINK_VERSION + 1, LINK_VERSION + 3).expect("range");
    let refused = negotiate(newer).expect_err("a newer edge");
    let text = refused.to_string();
    assert!(text.contains(&format!(
        "this core speaks versions {OLDEST_SPOKEN} to {LINK_VERSION}"
    )));
    assert!(text.contains(&format!(
        "the edge speaks {} to {}",
        LINK_VERSION + 1,
        LINK_VERSION + 3
    )));
    assert!(text.contains("upgrade the core"), "{text}");
    let older = VersionRange::new(0, 0).expect("range");
    assert!(
        negotiate(older)
            .expect_err("an older edge")
            .to_string()
            .contains("upgrade the edge")
    );
    assert!(!edge_upgrade_needed(LINK_VERSION));
    assert!(edge_upgrade_needed(LINK_VERSION - 1));
}

/// A version 1 Hello or Welcome cannot say what version 2 adds, and a
/// version 1 reader of a version 1 Hello reads exactly the fields it knew.
#[test]
fn the_opening_frames_carry_version_two_fields_only_in_version_two() {
    let v1 = VersionRange::new(1, 1).expect("range");
    assert!(matches!(
        encoded(&EdgeFrame::Hello(Hello {
            versions: v1,
            ..hello()
        })),
        Err(EncodeError::OverBound { .. })
    ));
    assert!(matches!(
        encoded(&CoreFrame::Welcome(Welcome {
            version: 1,
            ..welcome()
        })),
        Err(EncodeError::OverBound { .. })
    ));
    let with_cut = encoded(&EdgeFrame::Hello(hello())).expect("encodes");
    let without = encoded(&EdgeFrame::Hello(Hello {
        versions: v1,
        cut: None,
        ..hello()
    }))
    .expect("encodes");
    // The cut's option tag and eight bytes, and nothing else, set them apart.
    assert_eq!(with_cut.len(), without.len() + 9);
}

/// Every frame names the version that introduced it: what version 1 had is
/// 1, and what version 2 adds — an `Open` with TLS facts among it — is 2.
#[test]
fn every_frame_names_the_version_that_introduced_it() {
    for frame in every_edge_frame() {
        let expected = match &frame {
            EdgeFrame::Open(_, open) if open.tls.is_some() => 2,
            EdgeFrame::Paused
            | EdgeFrame::Upload(..)
            | EdgeFrame::RecordUpload(..)
            | EdgeFrame::ReplicaUpload(_)
            | EdgeFrame::CutUpload(_)
            | EdgeFrame::UploadDone
            | EdgeFrame::HomeUpload(_) => 2,
            _ => 1,
        };
        assert_eq!(frame.since(), expected, "{frame:?}");
    }
    for frame in every_core_frame() {
        assert!(frame.since() <= LINK_VERSION, "{frame:?}");
    }
    assert_eq!(CoreFrame::Pause.since(), 2);
    assert_eq!(CoreFrame::Refused("no".into()).since(), 1);
}

/// An acknowledgement's retained lines ascend, are never 0 and never past
/// the lines acknowledged: anything else is refused when read.
#[test]
fn retained_lines_are_read_only_in_order_and_within_the_acknowledgement() {
    for retained in [vec![3, 2], vec![2, 2], vec![0], vec![10]] {
        let mut forged = BytesMut::new();
        let count = u32::try_from(retained.len()).expect("small");
        let length = 1 + 8 + 8 + 4 + 8 * retained.len();
        forged.put_u32(u32::try_from(length).expect("small"));
        forged.put_u8(0x4b);
        forged.put_u64(3);
        forged.put_u64(9);
        forged.put_u32(count);
        for line in &retained {
            forged.put_u64(*line);
        }
        assert_eq!(
            decode::<CoreFrame>(&mut forged),
            Err(DecodeError::Invalid {
                field: "retained line"
            }),
            "{retained:?}"
        );
    }
}

/// A body is cut into parts of the part bound, gathered back in order, and
/// passed on as it was given; a part out of order is refused.
#[test]
fn bodies_split_gather_and_refuse_parts_out_of_order() {
    let body = Bytes::from(vec![5u8; held::MAX_BODY_PART * 2 + 3]);
    let parts = BodyPart::split(&body).expect("within the part count");
    assert_eq!(parts.len(), 3);
    assert!(parts[2].last && !parts[0].last && !parts[1].last);
    let mut gathered = Body::default();
    for part in parts.clone() {
        assert!(!gathered.is_whole());
        gathered.gather(part).expect("in order");
    }
    assert!(gathered.is_whole());
    assert_eq!(gathered.joined(), Some(body.clone()));
    assert_eq!(gathered.parts(), parts);
    assert_eq!(gathered.len(), body.len());

    let empty = BodyPart::split(&Bytes::new()).expect("one part");
    assert_eq!(empty.len(), 1);
    assert!(empty[0].last && empty[0].bytes.is_empty());

    let mut out_of_order = Body::default();
    assert_eq!(
        out_of_order.gather(parts[1].clone()),
        Err(held::OutOfOrder {
            expected: 0,
            got: 1
        })
    );
    // A first part starts the body over: a new revision replaces the old.
    let mut restarted = Body::default();
    restarted.gather(parts[0].clone()).expect("first");
    restarted.gather(part(0, true, b"new")).expect("restart");
    assert_eq!(restarted.joined(), Some(Bytes::from_static(b"new")));

    let too_many = Bytes::from(vec![
        0u8;
        held::MAX_BODY_PART * held::MAX_BODY_PARTS as usize + 1
    ]);
    assert!(BodyPart::split(&too_many).is_none());
}

#[test]
fn edge_names_are_one_dns_label() {
    for good in ["a", "edge-1", "0", &"x".repeat(MAX_EDGE_NAME_LEN)] {
        assert!(EdgeName::new(good).is_ok(), "{good}");
    }
    for bad in [
        "",
        "-a",
        "a-",
        "Edge",
        "a.b",
        "a_b",
        &"x".repeat(MAX_EDGE_NAME_LEN + 1),
    ] {
        assert!(EdgeName::new(bad).is_err(), "{bad}");
    }
}

#[test]
fn slots_leave_the_identifier_s_top_two_bits_clear() {
    assert!(Slot::new(0).is_none());
    assert!(Slot::new(MAX_SLOT + 1).is_none());
    let last = Slot::new(MAX_SLOT).expect("slot");
    let highest_id = last.first_id() | ((1u64 << SLOT_SHIFT) - 1);
    assert_eq!(highest_id >> 62, 0);
    assert!(i64::try_from(highest_id).is_ok());
}

#[test]
fn listener_addresses_keep_their_family() {
    let report = ListenerReport {
        kind: ListenerKind::Attach,
        addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 6698),
        certificate: None,
        proxy_protocol: false,
    };
    round_trip(vec![EdgeFrame::Hello(Hello {
        listeners: vec![report],
        ..hello()
    })]);
}

/// Every frame, corrupted a few bytes at a time by a seeded generator, either
/// fails to decode or decodes to a frame that re-encodes to the very bytes it
/// was read from: the decoder admits nothing an encoder could not write, and
/// never panics. (The `link_frames` fuzz target explores the same property
/// without a seed.)
#[test]
fn corrupted_frames_fail_or_round_trip_exactly() {
    fn check<F: Frame + std::fmt::Debug>(bytes: &[u8]) {
        let mut buffer = BytesMut::from(bytes);
        let mut consumed = 0;
        while let Ok(Some(frame)) = decode::<F>(&mut buffer) {
            let used = bytes.len() - buffer.len() - consumed;
            let again = encoded(&frame).expect("a decoded frame re-encodes");
            assert_eq!(
                &again[..],
                &bytes[consumed..consumed + used],
                "{frame:?} re-encodes differently"
            );
            consumed += used;
        }
    }
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = |bound: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        usize::try_from(seed % bound as u64).expect("below the bound")
    };
    let mut originals: Vec<BytesMut> = every_edge_frame()
        .iter()
        .map(|frame| encoded(frame).expect("encodes"))
        .collect();
    originals.extend(
        every_core_frame()
            .iter()
            .map(|frame| encoded(frame).expect("encodes")),
    );
    for original in &originals {
        for _ in 0..2_000 {
            let mut bytes = original.to_vec();
            for _ in 0..=next(3) {
                let at = next(bytes.len());
                bytes[at] = u8::try_from(next(256)).expect("a byte");
            }
            check::<EdgeFrame>(&bytes);
            check::<CoreFrame>(&bytes);
        }
    }
}
