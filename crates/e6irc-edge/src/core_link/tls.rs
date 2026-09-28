//! Mutual TLS on every core link (DESIGN §19.2, decision D8): TLS 1.3 only,
//! both ends presenting a certificate issued by the deployment's own
//! certificate authority (`e6ircd edge-credentials`), on loopback and across
//! hosts alike.
//!
//! The two kinds of certificate cannot stand in for each other. A core's is
//! issued for [`CORE_NAME`] with the server-authentication purpose, and an
//! edge checks both before it trusts a core; an edge's is issued for its own
//! [`edge_subject`] with the client-authentication purpose, and a core checks
//! both, and that the certificate names the edge the `Hello` says it is.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use e6irc_link::EdgeName;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde::Deserialize;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// The name every core certificate is issued for, and every edge checks: a
/// name under `.invalid`, which no resolver answers, so it names a role
/// rather than a host and a core can move between hosts with its certificate.
pub const CORE_NAME: &str = "core.e6irc.invalid";

/// The name an edge's certificate is issued for.
pub fn edge_subject(edge: &EdgeName) -> String {
    format!("{edge}.edge.e6irc.invalid")
}

/// Where one end of the link reads its credentials: the certificate
/// authority it trusts, and its own certificate and key.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinkCredentialFiles {
    pub ca: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// One end's credentials, read and checked.
pub struct LinkCredentials {
    roots: Arc<rustls::RootCertStore>,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

fn invalid(path: &Path, what: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("core-link credentials {}: {what}", path.display()),
    )
}

fn certificates(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    use rustls::pki_types::pem::PemObject;
    let chain = CertificateDer::pem_file_iter(path)
        .map_err(|error| invalid(path, error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| invalid(path, error))?;
    if chain.is_empty() {
        return Err(invalid(path, "holds no certificate"));
    }
    Ok(chain)
}

impl LinkCredentials {
    pub fn load(files: &LinkCredentialFiles) -> io::Result<Self> {
        use rustls::pki_types::pem::PemObject;
        let mut roots = rustls::RootCertStore::empty();
        for authority in certificates(&files.ca)? {
            roots
                .add(authority)
                .map_err(|error| invalid(&files.ca, error))?;
        }
        let chain = certificates(&files.cert)?;
        let key =
            PrivateKeyDer::from_pem_file(&files.key).map_err(|error| invalid(&files.key, error))?;
        Ok(Self {
            roots: Arc::new(roots),
            chain,
            key,
        })
    }

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    }

    /// How an edge dials a core: presenting its own certificate, trusting only
    /// a core certificate of this deployment's authority.
    pub fn edge_connector(&self) -> io::Result<TlsConnector> {
        let config = rustls::ClientConfig::builder_with_provider(Self::provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(io::Error::other)?
            .with_root_certificates(self.roots.clone())
            .with_client_auth_cert(self.chain.clone(), self.key.clone_key())
            .map_err(io::Error::other)?;
        Ok(TlsConnector::from(Arc::new(config)))
    }

    /// How a core accepts edges: presenting its own certificate, admitting
    /// only a client presenting an edge certificate of this deployment's
    /// authority.
    pub fn core_acceptor(&self) -> io::Result<TlsAcceptor> {
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            self.roots.clone(),
            Self::provider(),
        )
        .build()
        .map_err(io::Error::other)?;
        let config = rustls::ServerConfig::builder_with_provider(Self::provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(io::Error::other)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(self.chain.clone(), self.key.clone_key())
            .map_err(io::Error::other)?;
        Ok(TlsAcceptor::from(Arc::new(config)))
    }
}

/// The name an edge checks a core's certificate against.
pub fn core_server_name() -> ServerName<'static> {
    ServerName::try_from(CORE_NAME).expect("a DNS name")
}

/// Whether `chain`, which the handshake already verified as an edge
/// certificate of this deployment, is issued for `edge`.
pub fn names_edge(chain: &[CertificateDer<'_>], edge: &EdgeName) -> bool {
    let Some(leaf) = chain.first() else {
        return false;
    };
    let Ok(subject) = ServerName::try_from(edge_subject(edge)) else {
        return false;
    };
    webpki::EndEntityCert::try_from(leaf).is_ok_and(|certificate| {
        certificate
            .verify_is_valid_for_subject_name(&subject)
            .is_ok()
    })
}
