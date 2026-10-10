use super::*;

use crate::core_link::tls::{CORE_NAME, LinkCredentialFiles, LinkCredentials, edge_subject};

#[test]
fn an_edge_accepts_its_own_epoch_or_a_higher_one_and_refuses_a_lower() {
    let mut epoch = EdgeEpoch::default();
    assert_eq!(epoch.admit(0), Ok(()));
    assert_eq!(epoch.admit(5), Ok(()));
    assert_eq!(epoch.admit(5), Ok(()), "the same core links again");
    assert_eq!(
        epoch.admit(4),
        Err(StaleCore {
            presented: 4,
            highest: 5
        })
    );
    assert_eq!(epoch.highest(), 5, "a refusal changes nothing");
    assert_eq!(epoch.admit(9), Ok(()));
    assert_eq!(epoch.highest(), 9);
}

/// A deployment's link credentials, written to a scratch directory: an
/// authority, a core's certificate, and edge `edge`'s.
struct Credentials {
    dir: std::path::PathBuf,
}

impl Credentials {
    fn new(test: &str, edge: &EdgeName) -> Self {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
            KeyPair, KeyUsagePurpose,
        };
        let dir = std::env::temp_dir().join(format!("e6irc-link-{test}-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        let authority_key = KeyPair::generate().expect("key");
        let mut authority = CertificateParams::new(Vec::<String>::new()).expect("params");
        authority
            .distinguished_name
            .push(DnType::CommonName, "test authority");
        authority.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        authority.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let authority_certificate = authority.self_signed(&authority_key).expect("authority");
        let issuer = Issuer::new(authority, &authority_key);
        let leaf = |name: &str, purpose: ExtendedKeyUsagePurpose, file: &str| {
            let key = KeyPair::generate().expect("key");
            let mut params = CertificateParams::new(vec![name.to_owned()]).expect("params");
            params.extended_key_usages = vec![purpose];
            let certificate = params.signed_by(&key, &issuer).expect("leaf");
            std::fs::write(dir.join(format!("{file}.pem")), certificate.pem()).expect("write");
            std::fs::write(dir.join(format!("{file}-key.pem")), key.serialize_pem())
                .expect("write");
        };
        std::fs::write(dir.join("ca.pem"), authority_certificate.pem()).expect("write");
        leaf(CORE_NAME, ExtendedKeyUsagePurpose::ServerAuth, "core");
        leaf(
            &edge_subject(edge),
            ExtendedKeyUsagePurpose::ClientAuth,
            "edge",
        );
        Self { dir }
    }

    fn load(&self, role: &str) -> LinkCredentials {
        LinkCredentials::load(&LinkCredentialFiles {
            ca: self.dir.join("ca.pem"),
            cert: self.dir.join(format!("{role}.pem")),
            key: self.dir.join(format!("{role}-key.pem")),
        })
        .expect("credentials")
    }
}

impl Drop for Credentials {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.dir));
    }
}

struct Uncounted;

impl TransportTelemetry for Uncounted {
    fn record_error(&self, _kind: TransportError) {}
    fn record_connection_rejected(&self) {}
}

/// The epoch fence as an edge keeps it across links: a core presenting a
/// lower epoch than one the edge accepted — a core that lost the lease — is
/// refused however it answers, and the edge keeps dialing until a core at
/// least as new answers. Every `Hello` says the highest epoch accepted.
#[tokio::test]
async fn a_core_below_the_accepted_epoch_is_refused_and_dialing_goes_on() {
    crate::certificate::install_crypto_provider();
    let edge = EdgeName::new("edge-a").expect("name");
    let credentials = Credentials::new("epoch", &edge);
    let acceptor = credentials.load("core").core_acceptor().expect("acceptor");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    // The fake core answers each link with the next epoch of these, and says
    // what each `Hello` told it.
    let (hellos, mut heard) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        for epoch in [5u64, 3, 7] {
            let (tcp, _) = listener.accept().await.expect("accept");
            let mut tls = acceptor.accept(tcp).await.expect("TLS");
            let Ok(EdgeFrame::Hello(hello)) = FrameReader::new(&mut tls).first::<EdgeFrame>().await
            else {
                panic!("no Hello");
            };
            hellos.send(hello.highest_epoch).expect("the test listens");
            let welcome = Welcome {
                version: e6irc_link::LINK_VERSION,
                epoch,
                slot: Slot::new(3).expect("slot"),
                streams: 1,
                terms: e6irc_link::EdgeTerms {
                    trusted_proxies: Vec::new(),
                    max_connections_per_ip: None,
                    sendq_bytes: 64 * 1024,
                    command_flood: None,
                    line_credit: 16,
                },
                admission: e6irc_link::Admission::Serve,
            };
            write_frame(&mut tls, &CoreFrame::Welcome(welcome))
                .await
                .expect("Welcome");
            // The first link ends at once; the others stay until the test
            // ends.
            if epoch == 5 {
                drop(tls);
            } else {
                tokio::spawn(async move {
                    let _held = tls;
                    std::future::pending::<()>().await;
                });
            }
        }
    });
    let ids = Arc::new(ConnectionIdAllocator::new(NonZeroU64::MIN));
    let core = RemoteCore::new(Arc::new(Uncounted), ids.clone());
    let (linked, mut links) = mpsc::unbounded_channel();
    tokio::spawn(
        core.clone().maintain(
            Dialing {
                edge,
                core: vec![address.to_string()],
                connector: credentials
                    .load("edge")
                    .edge_connector()
                    .expect("connector"),
                listeners: Vec::new(),
            },
            linked,
        ),
    );
    let bound = std::time::Duration::from_secs(60);
    let first = tokio::time::timeout(bound, links.recv())
        .await
        .expect("a link")
        .expect("linked");
    assert_eq!(first.welcome().epoch, 5);
    let identifier = ids.allocate().expect("an identifier");
    assert_eq!(
        identifier.0 >> e6irc_link::SLOT_SHIFT,
        3,
        "numbered in slot 3"
    );
    let second = tokio::time::timeout(bound, links.recv())
        .await
        .expect("a link")
        .expect("linked");
    assert_eq!(second.welcome().epoch, 7, "epoch 3 was refused");
    let mut told = Vec::new();
    while let Ok(highest) = heard.try_recv() {
        told.push(highest);
    }
    assert_eq!(told, [0, 5, 5]);
}

fn line(text: &str) -> InputLine {
    InputLine::Line(Bytes::copy_from_slice(text.as_bytes()))
}

fn texts(state: &SessionState) -> Vec<(u64, String)> {
    state
        .unacked
        .iter()
        .map(|(number, line)| match line {
            InputLine::Line(bytes) => (*number, String::from_utf8_lossy(bytes).into_owned()),
            InputLine::Overlong(_) => (*number, "(overlong)".to_owned()),
        })
        .collect()
}

fn acknowledged_session() -> (SessionState, EdgeSession) {
    let (proxy, edge) = link::session("test", 4096);
    let mut state = SessionState::new(proxy);
    state.acknowledged = true;
    (state, edge)
}

/// The edge keeps each line until the core acknowledges it, and a line the
/// core retains for replay until it no longer does; a line taken back is
/// numbered again.
#[test]
fn input_lines_are_kept_until_acknowledged_and_retained_lines_until_released() {
    let (mut state, _edge) = acknowledged_session();
    for text in ["a", "b", "c", "d", "e"] {
        state.number(&line(text));
    }
    state.unnumber();
    state.number(&line("e"));
    state
        .acknowledge(&Ack {
            through: 3,
            retained: vec![2],
        })
        .expect("an acknowledgement");
    assert_eq!(
        texts(&state),
        [(2, "b".into()), (4, "d".into()), (5, "e".into())]
    );
    state
        .acknowledge(&Ack {
            through: 5,
            retained: Vec::new(),
        })
        .expect("an acknowledgement");
    assert!(state.unacked.is_empty());
    assert!(
        state
            .acknowledge(&Ack {
                through: 6,
                retained: Vec::new(),
            })
            .is_err(),
        "a line never sent cannot be acknowledged"
    );
}

/// A session that is not acknowledged — a bouncer attachment, a `/ws/ui`
/// socket, any session of a version 1 link — keeps no line.
#[test]
fn an_unacknowledged_session_keeps_no_line() {
    let (proxy, _edge) = link::session("test", 4096);
    let mut state = SessionState::new(proxy);
    state.number(&line("a"));
    assert!(state.unacked.is_empty());
    assert_eq!(state.next_line, 2);
}

/// At a handover the lines past the last acknowledgement are counted
/// unconfirmed and dropped; the retained ones are replayed first on the next
/// link, numbered from 1; the bytes sent and not yet written are what the
/// next core counts in flight.
#[test]
fn a_handover_counts_the_unconfirmed_and_replays_the_retained() {
    let (mut state, mut edge) = acknowledged_session();
    for text in ["a", "b", "c", "d"] {
        state.number(&line(text));
    }
    state
        .acknowledge(&Ack {
            through: 3,
            retained: vec![1, 3],
        })
        .expect("an acknowledgement");
    let proxy = state.proxy.as_mut().expect("the core end");
    proxy
        .output(Output(Bytes::from_static(b"12345678\r\n")))
        .expect("room");
    proxy
        .output(Output(Bytes::from_static(b"1234\r\n")))
        .expect("room");
    // The writer wrote the first line, and the core heard it.
    let taken = edge.try_take().expect("a line");
    edge.written(link::weight(&taken.payload));
    assert_eq!(state.drained.poll_written(), Written::More(10));

    let (unwritten, unconfirmed) = state.hand_over(8192).expect("a session held");
    assert_eq!((unwritten, unconfirmed), (6, 1));
    assert_eq!(state.proxy.as_ref().expect("the core end").capacity(), 8192);
    assert_eq!(texts(&state), [(1, "a".into()), (3, "c".into())]);

    // What is written after the handover is reported to the next core.
    let taken = edge.try_take().expect("a line");
    edge.written(link::weight(&taken.payload));
    assert_eq!(state.drained.poll_written(), Written::More(6));

    let (replay, closed) = state.resume(true);
    assert_eq!(replay.len(), 2);
    assert_eq!(closed, None);
    assert_eq!(texts(&state), [(1, "a".into()), (2, "c".into())]);
    assert_eq!(state.next_line, 3);
}

/// Output written while no core could hear is not reported to the next one:
/// it is part of what that core is told is in flight, or already written.
#[test]
fn what_was_written_before_a_handover_is_not_reported_after_it() {
    let (mut state, mut edge) = acknowledged_session();
    let proxy = state.proxy.as_mut().expect("the core end");
    proxy
        .output(Output(Bytes::from_static(b"12345678\r\n")))
        .expect("room");
    let taken = edge.try_take().expect("a line");
    edge.written(link::weight(&taken.payload));
    // Written, and never reported: the link it would have gone on was cut.
    let (unwritten, _) = state.hand_over(4096).expect("a session held");
    assert_eq!(unwritten, 0);
    assert_eq!(state.drained.poll_written(), Written::Nothing);
}

/// A client that left while no core could hear is said once: in the upload,
/// or at `Resume` when the upload was already sent.
#[test]
fn a_client_that_left_in_the_gap_is_said_once() {
    let (mut state, _edge) = acknowledged_session();
    state.closed = Some(ClosedReason::ByClient);
    state.hand_over(4096).expect("a session held");
    assert_eq!(state.resume(true).1, None, "the upload said it");

    let (mut state, _edge) = acknowledged_session();
    state.hand_over(4096).expect("a session held");
    state.closed = Some(ClosedReason::ByClient);
    assert_eq!(state.resume(true).1, Some(ClosedReason::ByClient));
    assert_eq!(state.resume(true).1, None);
}

/// A record's parts gather in order at one revision; a first part starts a
/// revision over, and only a whole body replaces the record held.
#[test]
fn record_parts_gather_into_the_newest_whole_record() {
    let part = |revision, index, last, bytes: &'static [u8]| RecordPart {
        revision,
        part: e6irc_link::BodyPart {
            index,
            last,
            bytes: Bytes::from_static(bytes),
        },
    };
    let (mut state, _edge) = acknowledged_session();
    state
        .gather_record(part(1, 0, true, b"one"))
        .expect("gathered");
    assert_eq!(
        state.record.as_ref().and_then(|(_, body)| body.joined()),
        Some(Bytes::from_static(b"one"))
    );
    state
        .gather_record(part(2, 0, false, b"tw"))
        .expect("gathered");
    assert_eq!(
        state.record.as_ref().map(|(revision, _)| *revision),
        Some(1),
        "a partial record replaces nothing"
    );
    assert!(state.gather_record(part(3, 1, true, b"o")).is_err());

    let (mut state, _edge) = acknowledged_session();
    state
        .gather_record(part(2, 0, false, b"tw"))
        .expect("gathered");
    state
        .gather_record(part(2, 1, true, b"o"))
        .expect("gathered");
    assert_eq!(
        state
            .record
            .as_ref()
            .map(|(revision, body)| (*revision, body.joined())),
        Some((2, Some(Bytes::from_static(b"two"))))
    );
    assert!(state.gather_record(part(4, 2, true, b"x")).is_err());
}

/// A channel's replica uploads as its state, then each member here, at the
/// state's revision.
#[test]
fn a_held_channel_uploads_its_state_then_its_members() {
    let channel = Bytes::from_static(b"#zero");
    let member = SessionId::new(7).expect("an identifier");
    let mut held = HeldChannel::default();
    held.members.insert(member, Bytes::from_static(b"op"));
    assert_eq!(
        held.replicas(&channel),
        [Replica {
            channel: channel.clone(),
            revision: 0,
            change: ReplicaChange::Member(member, Bytes::from_static(b"op")),
        }]
    );
    held.state = Some((4, Bytes::from_static(b"state")));
    let replicas = held.replicas(&channel);
    assert_eq!(
        replicas.first().map(|replica| &replica.change),
        Some(&ReplicaChange::State(Bytes::from_static(b"state")))
    );
    assert!(replicas.iter().all(|replica| replica.revision == 4));
}
