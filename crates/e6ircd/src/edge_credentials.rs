//! `e6ircd edge-credentials` (DESIGN §19.2, decision D8): the
//! deployment-private certificate authority every core link's mutual TLS
//! trusts, the core's certificate, and one certificate per edge.
//!
//! `init` writes the authority and the core's certificate into a directory;
//! `issue` writes one edge's certificate beside them, signed by the authority.
//! A core's certificate is issued for `core.e6irc.invalid` with the
//! server-authentication purpose, an edge's for `<name>.edge.e6irc.invalid`
//! with the client-authentication purpose, so neither can stand in for the
//! other (`e6irc_edge::core_link::tls`). The certificates do not expire; an
//! authority is withdrawn by issuing a new one and every certificate again.
//! Nothing is ever overwritten: a file that exists is refused by name.

use std::io;
use std::path::{Path, PathBuf};

use e6irc_link::EdgeName;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};

/// The authority's certificate, which both ends trust.
pub const AUTHORITY_CERTIFICATE: &str = "ca.pem";
/// The authority's private key: only `issue` reads it; no process that
/// serves needs it.
pub const AUTHORITY_KEY: &str = "ca-key.pem";
pub const CORE_CERTIFICATE: &str = "core.pem";
pub const CORE_KEY: &str = "core-key.pem";

/// The file names of `edge`'s certificate and key.
pub fn edge_files(edge: &EdgeName) -> (String, String) {
    (format!("edge-{edge}.pem"), format!("edge-{edge}-key.pem"))
}

fn failed(what: &str, error: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("{what}: {error}"))
}

/// The authority's parameters. `issue` rebuilds them to sign with, so they
/// must name the same subject every time.
fn authority_params() -> Result<CertificateParams, rcgen::Error> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "e6irc core-link certificate authority");
    params.distinguished_name = name;
    // It signs link certificates, never another authority.
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    Ok(params)
}

/// A link certificate for `subject`, with `purpose`.
fn leaf_params(
    subject: &str,
    purpose: ExtendedKeyUsagePurpose,
) -> Result<CertificateParams, rcgen::Error> {
    let mut params = CertificateParams::new(vec![subject.to_owned()])?;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, subject);
    params.distinguished_name = name;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![purpose];
    Ok(params)
}

/// Write `contents` to a new file, refusing one that exists; a key is
/// readable by its owner alone.
fn write_new(path: &Path, contents: &str, secret: bool) -> io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = secret;
    let mut file = options
        .open(path)
        .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", path.display())))?;
    file.write_all(contents.as_bytes())
        .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", path.display())))
}

/// Refuse to write over anything: every path must be new.
fn all_new(paths: &[PathBuf]) -> io::Result<()> {
    for path in paths {
        if path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists; nothing was written", path.display()),
            ));
        }
    }
    Ok(())
}

/// Write a new authority and the core's certificate into `dir`: the files
/// written.
pub fn init(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let paths: Vec<PathBuf> = [
        AUTHORITY_CERTIFICATE,
        AUTHORITY_KEY,
        CORE_CERTIFICATE,
        CORE_KEY,
    ]
    .into_iter()
    .map(|file| dir.join(file))
    .collect();
    all_new(&paths)?;
    std::fs::create_dir_all(dir)
        .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", dir.display())))?;
    let authority_key = KeyPair::generate().map_err(|error| failed("authority key", error))?;
    let authority = authority_params()
        .and_then(|params| params.self_signed(&authority_key))
        .map_err(|error| failed("authority certificate", error))?;
    let issuer = Issuer::new(
        authority_params().map_err(|error| failed("authority", error))?,
        &authority_key,
    );
    let core_key = KeyPair::generate().map_err(|error| failed("core key", error))?;
    let core = leaf_params(
        e6irc_edge::core_link::tls::CORE_NAME,
        ExtendedKeyUsagePurpose::ServerAuth,
    )
    .and_then(|params| params.signed_by(&core_key, &issuer))
    .map_err(|error| failed("core certificate", error))?;
    write_new(&paths[0], &authority.pem(), false)?;
    write_new(&paths[1], &authority_key.serialize_pem(), true)?;
    write_new(&paths[2], &core.pem(), false)?;
    write_new(&paths[3], &core_key.serialize_pem(), true)?;
    Ok(paths)
}

/// Write `edge`'s certificate into `dir`, signed by the authority `init`
/// wrote there: the files written.
pub fn issue(dir: &Path, edge: &EdgeName) -> io::Result<Vec<PathBuf>> {
    let (certificate, key) = edge_files(edge);
    let paths = vec![dir.join(certificate), dir.join(key)];
    all_new(&paths)?;
    let authority_key_path = dir.join(AUTHORITY_KEY);
    let authority_key = std::fs::read_to_string(&authority_key_path)
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "{}: {error} (run `e6ircd edge-credentials init` first)",
                    authority_key_path.display()
                ),
            )
        })
        .and_then(|pem| {
            KeyPair::from_pem(&pem)
                .map_err(|error| failed(&authority_key_path.display().to_string(), error))
        })?;
    let issuer = Issuer::new(
        authority_params().map_err(|error| failed("authority", error))?,
        &authority_key,
    );
    let edge_key = KeyPair::generate().map_err(|error| failed("edge key", error))?;
    let issued = leaf_params(
        &e6irc_edge::core_link::tls::edge_subject(edge),
        ExtendedKeyUsagePurpose::ClientAuth,
    )
    .and_then(|params| params.signed_by(&edge_key, &issuer))
    .map_err(|error| failed("edge certificate", error))?;
    write_new(&paths[0], &issued.pem(), false)?;
    write_new(&paths[1], &edge_key.serialize_pem(), true)?;
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use e6irc_edge::core_link::tls::{LinkCredentialFiles, LinkCredentials};

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("e6irc-credentials-{name}-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&dir));
        dir
    }

    fn files(dir: &Path, certificate: &str, key: &str) -> LinkCredentialFiles {
        LinkCredentialFiles {
            ca: dir.join(AUTHORITY_CERTIFICATE),
            cert: dir.join(certificate),
            key: dir.join(key),
        }
    }

    /// Complete a link handshake between `core` and `edge` credentials; the
    /// edge's name as the core reads it from the certificate, if it does.
    async fn handshake(
        core: &LinkCredentials,
        edge: &LinkCredentials,
        claimed: &EdgeName,
    ) -> Result<bool, String> {
        e6irc_edge::certificate::install_crypto_provider();
        let (near, far) = tokio::io::duplex(64 * 1024);
        let acceptor = core.core_acceptor().map_err(|error| error.to_string())?;
        let connector = edge.edge_connector().map_err(|error| error.to_string())?;
        // The client's end is kept until the server's side is done.
        let client = tokio::spawn(async move {
            connector
                .connect(e6irc_edge::core_link::tls::core_server_name(), far)
                .await
                .map_err(|error| error.to_string())
        });
        let served = acceptor
            .accept(near)
            .await
            .map_err(|error| error.to_string());
        let connected = client.await.map_err(|error| error.to_string())?;
        let served = served?;
        drop(connected?);
        let certificates = served.get_ref().1.peer_certificates().unwrap_or_default();
        Ok(e6irc_edge::core_link::tls::names_edge(
            certificates,
            claimed,
        ))
    }

    #[tokio::test]
    async fn issued_credentials_link_and_name_their_edge() {
        let dir = scratch("link");
        init(&dir).expect("init");
        let name = EdgeName::new("edge-a").expect("name");
        issue(&dir, &name).expect("issue");
        let (certificate, key) = edge_files(&name);
        let core = LinkCredentials::load(&files(&dir, CORE_CERTIFICATE, CORE_KEY)).expect("core");
        let edge = LinkCredentials::load(&files(&dir, &certificate, &key)).expect("edge");
        assert_eq!(handshake(&core, &edge, &name).await, Ok(true));
        let other = EdgeName::new("edge-b").expect("name");
        assert_eq!(
            handshake(&core, &edge, &other).await,
            Ok(false),
            "the certificate names edge-a only"
        );
        // Nothing is written over.
        assert_eq!(
            init(&dir).expect_err("exists").kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            issue(&dir, &name).expect_err("exists").kind(),
            io::ErrorKind::AlreadyExists
        );
        std::fs::remove_dir_all(&dir).expect("clean up");
    }

    /// An edge certificate cannot serve as a core's, nor a core's as an
    /// edge's, and another deployment's authority is trusted by neither.
    #[tokio::test]
    async fn the_two_roles_and_two_deployments_do_not_mix() {
        let dir = scratch("roles");
        init(&dir).expect("init");
        let name = EdgeName::new("edge-a").expect("name");
        issue(&dir, &name).expect("issue");
        let (certificate, key) = edge_files(&name);
        let core = LinkCredentials::load(&files(&dir, CORE_CERTIFICATE, CORE_KEY)).expect("core");
        let edge = LinkCredentials::load(&files(&dir, &certificate, &key)).expect("edge");
        assert!(
            handshake(&edge, &core, &name).await.is_err(),
            "roles swapped: an edge presenting as a core is refused"
        );
        let foreign = scratch("foreign");
        init(&foreign).expect("init");
        issue(&foreign, &name).expect("issue");
        let stranger = LinkCredentials::load(&files(&foreign, &certificate, &key)).expect("edge");
        assert!(
            handshake(&core, &stranger, &name).await.is_err(),
            "another deployment's edge is refused"
        );
        std::fs::remove_dir_all(&dir).expect("clean up");
        std::fs::remove_dir_all(&foreign).expect("clean up");
    }
}
