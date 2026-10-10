//! An IRC network's TLS client certificate (DESIGN §10.3): generated here, or
//! uploaded by its owner, and presented to the upstream, which logs it in
//! with SASL EXTERNAL or recognises its fingerprint (NickServ CertFP).
//!
//! A generated certificate is self-signed: services match the fingerprint,
//! never a chain, so there is no authority to issue it. It is minted with
//! rcgen on aws-lc-rs, the process's one crypto provider, as the core link's
//! certificates are (`edge_credentials`).

/// The key algorithms a generated certificate may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratedKey {
    Ed25519,
    EcdsaP256,
}

impl GeneratedKey {
    fn algorithm(self) -> &'static rcgen::SignatureAlgorithm {
        match self {
            Self::Ed25519 => &rcgen::PKCS_ED25519,
            Self::EcdsaP256 => &rcgen::PKCS_ECDSA_P256_SHA256,
        }
    }
}

/// A certificate and its private key, both PEM: what is stored (the key
/// sealed) and what [`e6irc_client::ClientCertificate::from_pem`] reads.
pub struct CertificatePem {
    pub certificate: String,
    pub key: String,
}

impl std::fmt::Debug for CertificatePem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificatePem")
            .field("certificate", &self.certificate)
            .field("key", &"<redacted>")
            .finish()
    }
}

/// Generate a self-signed client certificate for `subject` (the network's
/// owner and name, which say whose certificate it is to whoever reads it).
pub fn generate(algorithm: GeneratedKey, subject: &str) -> Result<CertificatePem, String> {
    let key = rcgen::KeyPair::generate_for(algorithm.algorithm())
        .map_err(|error| format!("key generation failed: {error}"))?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .map_err(|error| format!("certificate parameters: {error}"))?;
    let mut name = rcgen::DistinguishedName::new();
    name.push(rcgen::DnType::CommonName, subject);
    params.distinguished_name = name;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let certificate = params
        .self_signed(&key)
        .map_err(|error| format!("certificate signing failed: {error}"))?;
    Ok(CertificatePem {
        certificate: certificate.pem(),
        key: key.serialize_pem(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_certificate_is_one_the_client_presents() {
        for (algorithm, expected) in [
            (GeneratedKey::Ed25519, e6irc_client::KeyAlgorithm::Ed25519),
            (GeneratedKey::EcdsaP256, e6irc_client::KeyAlgorithm::Ecdsa),
        ] {
            let pem = generate(algorithm, "alice/oftc").expect("generated");
            let certificate = e6irc_client::ClientCertificate::from_pem(&pem.certificate, &pem.key)
                .expect("a usable pair");
            assert_eq!(certificate.algorithm(), expected);
            assert!(!format!("{pem:?}").contains("PRIVATE KEY"));
            // Each generation is a new key, so a rotation changes the
            // fingerprint services know the account by.
            let again = generate(algorithm, "alice/oftc").expect("generated");
            let again = e6irc_client::ClientCertificate::from_pem(&again.certificate, &again.key)
                .expect("a usable pair");
            assert_ne!(certificate.fingerprint_sha512(), again.fingerprint_sha512());
        }
    }
}
