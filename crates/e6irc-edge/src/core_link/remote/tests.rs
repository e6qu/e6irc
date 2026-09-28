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
