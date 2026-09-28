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
            ..hello()
        }),
        EdgeFrame::Open(
            session(1 << 48 | 5),
            Open {
                kind: SessionKind::Irc,
                address: "192.0.2.1".parse().expect("address"),
                transport: Transport::Tls,
            },
        ),
        EdgeFrame::Open(
            session(9),
            Open {
                kind: SessionKind::Ui,
                address: "2001:db8::1".parse().expect("address"),
                transport: Transport::SecureWebSocket,
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
