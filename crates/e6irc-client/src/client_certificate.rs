//! A TLS client certificate a connection presents to the server: what a network
//! without SASL PLAIN authenticates with (SASL EXTERNAL, or NickServ's CertFP,
//! which recognises the certificate's fingerprint by itself).
//!
//! Built only from PEM text that parses, whose private key is one the process's
//! crypto provider can sign with, and whose key belongs to the certificate it
//! comes with: a pair that does not match would make every TLS handshake fail
//! later, as a refusal nobody could read.

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// The most certificates a chain may carry: the end-entity certificate and a
/// few intermediates. A self-signed one, which is what NickServ's CertFP wants,
/// is one.
pub const MAX_CHAIN_CERTIFICATES: usize = 8;

/// The longest PEM text either half may be. An RSA-4096 key with its chain is
/// well under it; it bounds what a caller stores and parses per network.
pub const MAX_PEM_BYTES: usize = 32 * 1024;

/// A certificate chain with its private key, ready for a TLS handshake.
///
/// Its `Debug` shows the fingerprint and never the key.
pub struct ClientCertificate {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    algorithm: KeyAlgorithm,
}

/// Why PEM text is not a usable client certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientCertificateError {
    /// Longer than [`MAX_PEM_BYTES`].
    TooLong,
    /// No `CERTIFICATE` block, or one that is not valid PEM.
    NoCertificate,
    /// More than [`MAX_CHAIN_CERTIFICATES`] certificates.
    ChainTooLong,
    /// No private key block (PKCS #8, SEC 1 or PKCS #1), or one that does not
    /// parse.
    NoPrivateKey,
    /// A key the TLS stack cannot sign with.
    UnsupportedKey,
    /// The key does not belong to the first certificate.
    KeyMismatch,
}

impl std::fmt::Display for ClientCertificateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TooLong => "the PEM text is longer than 32 KiB",
            Self::NoCertificate => "no PEM CERTIFICATE block was found",
            Self::ChainTooLong => "the certificate chain has more than 8 certificates",
            Self::NoPrivateKey => "no PEM private key block (PKCS #8, SEC 1 or PKCS #1) was found",
            Self::UnsupportedKey => "the private key is of a kind TLS cannot sign with",
            Self::KeyMismatch => "the private key does not belong to the first certificate",
        })
    }
}

impl std::error::Error for ClientCertificateError {}

/// The signature algorithm of a client certificate's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Ed25519,
    Ecdsa,
    Rsa,
}

impl KeyAlgorithm {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::Ecdsa => "ecdsa",
            Self::Rsa => "rsa",
        }
    }
}

impl ClientCertificate {
    /// Read a certificate chain (end-entity first) and its private key from
    /// PEM text.
    pub fn from_pem(certificate: &str, key: &str) -> Result<Self, ClientCertificateError> {
        if certificate.len() > MAX_PEM_BYTES || key.len() > MAX_PEM_BYTES {
            return Err(ClientCertificateError::TooLong);
        }
        let mut chain = Vec::new();
        for parsed in CertificateDer::pem_slice_iter(certificate.as_bytes()) {
            let parsed = parsed.map_err(|_| ClientCertificateError::NoCertificate)?;
            if chain.len() == MAX_CHAIN_CERTIFICATES {
                return Err(ClientCertificateError::ChainTooLong);
            }
            chain.push(parsed);
        }
        if chain.is_empty() {
            return Err(ClientCertificateError::NoCertificate);
        }
        let key = PrivateKeyDer::from_pem_slice(key.as_bytes())
            .map_err(|_| ClientCertificateError::NoPrivateKey)?;
        let signing = rustls::crypto::aws_lc_rs::default_provider()
            .key_provider
            .load_private_key(key.clone_key())
            .map_err(|_| ClientCertificateError::UnsupportedKey)?;
        let algorithm = match signing.algorithm() {
            rustls::SignatureAlgorithm::ED25519 => KeyAlgorithm::Ed25519,
            rustls::SignatureAlgorithm::ECDSA => KeyAlgorithm::Ecdsa,
            rustls::SignatureAlgorithm::RSA => KeyAlgorithm::Rsa,
            _ => return Err(ClientCertificateError::UnsupportedKey),
        };
        rustls::sign::CertifiedKey::new(chain.clone(), signing)
            .keys_match()
            .map_err(|_| ClientCertificateError::KeyMismatch)?;
        Ok(Self {
            chain,
            key,
            algorithm,
        })
    }

    /// The end-entity certificate's SHA-256 fingerprint, lowercase hex: what
    /// a network's services register (`NickServ CERT ADD`) and match.
    pub fn fingerprint_sha256(&self) -> String {
        Fingerprints::of_der(&self.chain[0]).sha256
    }

    /// The end-entity certificate's SHA-512 fingerprint, lowercase hex.
    pub fn fingerprint_sha512(&self) -> String {
        Fingerprints::of_der(&self.chain[0]).sha512
    }

    pub const fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    pub(crate) fn chain(&self) -> Vec<CertificateDer<'static>> {
        self.chain.clone()
    }

    pub(crate) fn key(&self) -> PrivateKeyDer<'static> {
        self.key.clone_key()
    }
}

/// A certificate's fingerprints, lowercase hex: the digests of its DER
/// encoding, which is what services that recognise a client certificate
/// (NickServ CertFP) are told and compare. Networks differ in which digest
/// they use, so both are given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprints {
    pub sha256: String,
    pub sha512: String,
}

impl Fingerprints {
    /// The fingerprints of one DER-encoded certificate.
    pub fn of_der(certificate: &[u8]) -> Self {
        Self {
            sha256: hex(
                aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, certificate).as_ref(),
            ),
            sha512: hex(
                aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA512, certificate).as_ref(),
            ),
        }
    }

    /// The first certificate's fingerprints in PEM text, without its key:
    /// what a stored certificate shows. `None` when there is no certificate.
    pub fn of_pem(certificate: &str) -> Option<Self> {
        CertificateDer::pem_slice_iter(certificate.as_bytes())
            .next()?
            .ok()
            .map(|certificate| Self::of_der(&certificate))
    }
}

impl Clone for ClientCertificate {
    fn clone(&self) -> Self {
        Self {
            chain: self.chain.clone(),
            key: self.key.clone_key(),
            algorithm: self.algorithm,
        }
    }
}

impl std::fmt::Debug for ClientCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCertificate")
            .field("algorithm", &self.algorithm)
            .field("sha256", &self.fingerprint_sha256())
            .field("key", &"<redacted>")
            .finish()
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut text, byte| {
            write!(text, "{byte:02x}").expect("writing to a String cannot fail");
            text
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generated(algorithm: &'static rcgen::SignatureAlgorithm) -> (String, String) {
        let key = rcgen::KeyPair::generate_for(algorithm).expect("key");
        let certificate = rcgen::CertificateParams::new(vec!["e6irc".to_owned()])
            .expect("params")
            .self_signed(&key)
            .expect("certificate");
        (certificate.pem(), key.serialize_pem())
    }

    #[test]
    fn a_generated_pair_is_read_with_its_fingerprints() {
        for (algorithm, expected) in [
            (&rcgen::PKCS_ED25519, KeyAlgorithm::Ed25519),
            (&rcgen::PKCS_ECDSA_P256_SHA256, KeyAlgorithm::Ecdsa),
        ] {
            let (certificate, key) = generated(algorithm);
            let read = ClientCertificate::from_pem(&certificate, &key).expect("a matching pair");
            assert_eq!(read.algorithm(), expected);
            assert_eq!(read.fingerprint_sha256().len(), 64);
            assert_eq!(read.fingerprint_sha512().len(), 128);
            let der = CertificateDer::from_pem_slice(certificate.as_bytes()).expect("der");
            assert_eq!(
                read.fingerprint_sha256(),
                hex(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &der).as_ref())
            );
            assert!(!format!("{read:?}").contains("PRIVATE"));
            assert_eq!(
                Fingerprints::of_pem(&certificate),
                Some(Fingerprints {
                    sha256: read.fingerprint_sha256(),
                    sha512: read.fingerprint_sha512(),
                })
            );
        }
    }

    #[test]
    fn a_key_of_another_certificate_is_refused() {
        let (certificate, _) = generated(&rcgen::PKCS_ECDSA_P256_SHA256);
        let (_, other_key) = generated(&rcgen::PKCS_ECDSA_P256_SHA256);
        assert_eq!(
            ClientCertificate::from_pem(&certificate, &other_key).unwrap_err(),
            ClientCertificateError::KeyMismatch
        );
    }

    #[test]
    fn text_that_is_not_a_certificate_or_key_is_refused_by_name() {
        let (certificate, key) = generated(&rcgen::PKCS_ED25519);
        assert_eq!(
            ClientCertificate::from_pem("not pem", &key).unwrap_err(),
            ClientCertificateError::NoCertificate
        );
        assert_eq!(
            ClientCertificate::from_pem(&certificate, "not pem").unwrap_err(),
            ClientCertificateError::NoPrivateKey
        );
        assert_eq!(
            ClientCertificate::from_pem(&"x".repeat(MAX_PEM_BYTES + 1), &key).unwrap_err(),
            ClientCertificateError::TooLong
        );
        assert_eq!(
            ClientCertificate::from_pem(&certificate.repeat(MAX_CHAIN_CERTIFICATES + 1), &key)
                .unwrap_err(),
            ClientCertificateError::ChainTooLong
        );
    }
}
