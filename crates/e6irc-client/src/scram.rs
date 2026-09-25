//! SASL SCRAM (RFC 5802; SHA-256 per RFC 7677, SHA-512 as Libera offers it),
//! client side, without channel binding (`n,,`).
//!
//! Pure message construction and verification: the IRC exchange that carries
//! these messages lives in the connection. A password never crosses the wire,
//! and the server proves it holds the account's verifier: a final message whose
//! signature does not match is refused, never treated as success.

use aws_lc_rs::{constant_time, digest, hmac, pbkdf2};
use std::num::NonZeroU32;

/// The SCRAM variants this client speaks, strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScramHash {
    Sha512,
    Sha256,
}

impl ScramHash {
    /// The SASL mechanism name.
    pub const fn mechanism(self) -> &'static str {
        match self {
            Self::Sha512 => "SCRAM-SHA-512",
            Self::Sha256 => "SCRAM-SHA-256",
        }
    }

    const fn hmac(self) -> hmac::Algorithm {
        match self {
            Self::Sha512 => hmac::HMAC_SHA512,
            Self::Sha256 => hmac::HMAC_SHA256,
        }
    }

    const fn digest(self) -> &'static digest::Algorithm {
        match self {
            Self::Sha512 => &digest::SHA512,
            Self::Sha256 => &digest::SHA256,
        }
    }

    const fn pbkdf2(self) -> pbkdf2::Algorithm {
        match self {
            Self::Sha512 => pbkdf2::PBKDF2_HMAC_SHA512,
            Self::Sha256 => pbkdf2::PBKDF2_HMAC_SHA256,
        }
    }

    const fn output_len(self) -> usize {
        match self {
            Self::Sha512 => 64,
            Self::Sha256 => 32,
        }
    }
}

/// The most PBKDF2 iterations a server may demand. The count is the server's
/// to choose and costs this client CPU for every attempt; Atheme's default is
/// far below this bound.
pub const MAX_ITERATIONS: u32 = 1_000_000;

/// The fewest a server may demand. RFC 7677 §3 makes 4096 a MUST (the
/// SCRAM-SHA-512 draft mirrors it), and the reason is this client's: the
/// iteration count is what makes a captured transcript expensive to attack, so
/// a server asking for fewer is weakening *our* credential. It is refused
/// rather than quietly obeyed -- a server that cannot meet the floor of the
/// mechanism it advertised is one to hear about, not to log in to.
pub const MIN_ITERATIONS: u32 = 4_096;

/// Why a SCRAM exchange could not continue. Every one is the server's (or the
/// credential's) fault and ends the attempt: none is retried as another
/// mechanism, which would be a silent downgrade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScramError {
    /// The account name or password contains characters SASLprep prohibits.
    Unpreparable(&'static str),
    /// The server's first message is not `r=…,s=…,i=…`.
    MalformedServerFirst(String),
    /// The server's nonce does not extend the one this client sent.
    NonceMismatch,
    /// The iteration count is outside [`MIN_ITERATIONS`]..=[`MAX_ITERATIONS`].
    Iterations(u32),
    /// The server's final message is not `v=…` or `e=…`.
    MalformedServerFinal(String),
    /// The server reported an error (`e=…`) in its final message.
    ServerError(String),
    /// The server's signature does not prove it knows the account's verifier.
    ServerSignatureMismatch,
}

impl std::fmt::Display for ScramError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unpreparable(what) => {
                write!(
                    f,
                    "the {what} contains characters SCRAM cannot carry (SASLprep)"
                )
            }
            Self::MalformedServerFirst(message) => {
                write!(
                    f,
                    "the server's first SCRAM message is malformed: {message}"
                )
            }
            Self::NonceMismatch => write!(f, "the server's SCRAM nonce does not extend ours"),
            Self::Iterations(count) => write!(
                f,
                "the server asked for {count} SCRAM iterations \
                 (accepted: {MIN_ITERATIONS} to {MAX_ITERATIONS})"
            ),
            Self::MalformedServerFinal(message) => {
                write!(
                    f,
                    "the server's final SCRAM message is malformed: {message}"
                )
            }
            Self::ServerError(error) => write!(f, "the server ended SCRAM with: {error}"),
            Self::ServerSignatureMismatch => write!(
                f,
                "the server's SCRAM signature is wrong: it did not prove it knows this account"
            ),
        }
    }
}

impl ScramError {
    /// Whether this is the server's verdict that the credentials are wrong:
    /// an RFC 5802 `server-error` of `invalid-proof` (the password), or
    /// `unknown-user`, `invalid-encoding` or `invalid-username-encoding` (the
    /// account name or the proof it carried). Retrying the same credentials
    /// can only get the same answer, and every attempt counts against the
    /// account upstream. Every other error — including `other-error`, the
    /// channel-binding errors and `no-resources` — says nothing about them.
    pub fn rejects_credentials(&self) -> bool {
        matches!(
            self,
            Self::ServerError(error)
                if matches!(
                    error.as_str(),
                    "invalid-proof" | "unknown-user" | "invalid-encoding" | "invalid-username-encoding"
                )
        )
    }
}

/// A SCRAM exchange in progress, from the client's first message until the
/// server's signature is verified.
pub struct ScramClient {
    hash: ScramHash,
    password: String,
    client_nonce: String,
    client_first_bare: String,
}

/// The state after the client's final message: what the server must sign.
pub struct ScramAwaitingSignature {
    hash: ScramHash,
    expected_server_signature: Vec<u8>,
}

impl ScramClient {
    /// Start an exchange for `account` with a fresh random nonce.
    pub fn new(hash: ScramHash, account: &str, password: &str) -> Result<Self, ScramError> {
        let mut nonce = [0u8; 24];
        aws_lc_rs::rand::fill(&mut nonce).expect("the system random source is available");
        Self::with_nonce(
            hash,
            account,
            password,
            &e6irc_proto::base64::encode(&nonce),
        )
    }

    /// [`ScramClient::new`] with a given nonce (tests use RFC 7677's).
    pub fn with_nonce(
        hash: ScramHash,
        account: &str,
        password: &str,
        client_nonce: &str,
    ) -> Result<Self, ScramError> {
        let account =
            stringprep::saslprep(account).map_err(|_| ScramError::Unpreparable("account name"))?;
        let password = stringprep::saslprep(password)
            .map_err(|_| ScramError::Unpreparable("password"))?
            .into_owned();
        let client_first_bare = format!("n={},r={client_nonce}", sasl_name(&account));
        Ok(Self {
            hash,
            password,
            client_nonce: client_nonce.to_owned(),
            client_first_bare,
        })
    }

    /// The client's first message: the gs2 header (no channel binding, no
    /// authorization identity) and the bare part.
    pub fn client_first(&self) -> String {
        format!("n,,{}", self.client_first_bare)
    }

    /// Answer the server's first message with the client's final message
    /// (carrying the proof), and keep what the server's signature must be.
    pub fn client_final(
        self,
        server_first: &str,
    ) -> Result<(String, ScramAwaitingSignature), ScramError> {
        // A server that refuses before any proof says so here: Libera answers
        // `e=other-error` for an account whose stored password cannot do SCRAM,
        // though it advertises the mechanism.
        if let Some(error) = server_first.strip_prefix("e=") {
            return Err(ScramError::ServerError(error.to_owned()));
        }
        let malformed = || ScramError::MalformedServerFirst(server_first.to_owned());
        let mut attributes = server_first.split(',');
        let nonce = attributes
            .next()
            .and_then(|part| part.strip_prefix("r="))
            .ok_or_else(malformed)?;
        let salt = attributes
            .next()
            .and_then(|part| part.strip_prefix("s="))
            .and_then(e6irc_proto::base64::decode)
            .ok_or_else(malformed)?;
        let iterations: u32 = attributes
            .next()
            .and_then(|part| part.strip_prefix("i="))
            .and_then(|count| count.parse().ok())
            .ok_or_else(malformed)?;
        if !nonce.starts_with(&self.client_nonce) || nonce.len() == self.client_nonce.len() {
            return Err(ScramError::NonceMismatch);
        }
        let iterations = NonZeroU32::new(iterations)
            .filter(|count| (MIN_ITERATIONS..=MAX_ITERATIONS).contains(&count.get()))
            .ok_or(ScramError::Iterations(iterations))?;

        let hash = self.hash;
        let mut salted_password = vec![0u8; hash.output_len()];
        pbkdf2::derive(
            hash.pbkdf2(),
            iterations,
            &salt,
            self.password.as_bytes(),
            &mut salted_password,
        );
        let salted_key = hmac::Key::new(hash.hmac(), &salted_password);
        let client_key = hmac::sign(&salted_key, b"Client Key");
        let stored_key = digest::digest(hash.digest(), client_key.as_ref());
        // `biws` is base64("n,,"): the gs2 header this client sent.
        let client_final_without_proof = format!("c=biws,r={nonce}");
        let auth_message = format!(
            "{},{server_first},{client_final_without_proof}",
            self.client_first_bare
        );
        let client_signature = hmac::sign(
            &hmac::Key::new(hash.hmac(), stored_key.as_ref()),
            auth_message.as_bytes(),
        );
        let proof: Vec<u8> = client_key
            .as_ref()
            .iter()
            .zip(client_signature.as_ref())
            .map(|(key, signature)| key ^ signature)
            .collect();
        let server_key = hmac::sign(&salted_key, b"Server Key");
        let expected_server_signature = hmac::sign(
            &hmac::Key::new(hash.hmac(), server_key.as_ref()),
            auth_message.as_bytes(),
        )
        .as_ref()
        .to_vec();
        Ok((
            format!(
                "{client_final_without_proof},p={}",
                e6irc_proto::base64::encode(&proof)
            ),
            ScramAwaitingSignature {
                hash,
                expected_server_signature,
            },
        ))
    }
}

impl ScramAwaitingSignature {
    /// Verify the server's final message. `Ok` only when the server proved it
    /// holds this account's verifier.
    pub fn verify(self, server_final: &str) -> Result<ScramHash, ScramError> {
        if let Some(error) = server_final.strip_prefix("e=") {
            return Err(ScramError::ServerError(error.to_owned()));
        }
        let signature = server_final
            .split(',')
            .next()
            .and_then(|part| part.strip_prefix("v="))
            .and_then(e6irc_proto::base64::decode)
            .ok_or_else(|| ScramError::MalformedServerFinal(server_final.to_owned()))?;
        constant_time::verify_slices_are_equal(&signature, &self.expected_server_signature)
            .map_err(|_| ScramError::ServerSignatureMismatch)?;
        Ok(self.hash)
    }
}

/// RFC 5802 `saslname`: `=` and `,` are escaped as `=3D` and `=2C`.
fn sasl_name(account: &str) -> String {
    account.replace('=', "=3D").replace(',', "=2C")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7677 §3's worked example, byte for byte.
    #[test]
    fn rfc_7677_example_proof_and_signature() {
        let client =
            ScramClient::with_nonce(ScramHash::Sha256, "user", "pencil", "rOprNGfwEbeRWgbNEkqO")
                .expect("prepared");
        assert_eq!(client.client_first(), "n,,n=user,r=rOprNGfwEbeRWgbNEkqO");
        let (client_final, awaiting) = client
            .client_final(
                "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
                 s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
            )
            .expect("client final");
        assert_eq!(
            client_final,
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
             p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        assert_eq!(
            awaiting
                .verify("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
                .expect("the server's signature verifies"),
            ScramHash::Sha256
        );
    }

    #[test]
    fn a_wrong_server_signature_is_refused() {
        let client =
            ScramClient::with_nonce(ScramHash::Sha256, "user", "pencil", "rOprNGfwEbeRWgbNEkqO")
                .expect("prepared");
        let (_, awaiting) = client
            .client_final(
                "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
                 s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
            )
            .expect("client final");
        assert_eq!(
            awaiting.verify("v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
            Err(ScramError::ServerSignatureMismatch)
        );
    }

    #[test]
    fn the_server_must_extend_the_client_nonce_and_bound_its_iterations() {
        let start = || {
            ScramClient::with_nonce(ScramHash::Sha512, "user", "pencil", "abc").expect("prepared")
        };
        assert_eq!(
            start().client_final("r=xyz123,s=c2FsdA==,i=4096").err(),
            Some(ScramError::NonceMismatch)
        );
        assert_eq!(
            start().client_final("r=abc,s=c2FsdA==,i=4096").err(),
            Some(ScramError::NonceMismatch),
            "a server nonce part is required"
        );
        assert_eq!(
            start().client_final("r=abcdef,s=c2FsdA==,i=0").err(),
            Some(ScramError::Iterations(0))
        );
        // Below RFC 7677's floor the derived key is cheap to attack from a
        // captured transcript, so the exchange stops rather than obeying.
        assert_eq!(
            start()
                .client_final(&format!("r=abcdef,s=c2FsdA==,i={}", MIN_ITERATIONS - 1))
                .err(),
            Some(ScramError::Iterations(MIN_ITERATIONS - 1))
        );
        assert!(
            start()
                .client_final(&format!("r=abcdef,s=c2FsdA==,i={MIN_ITERATIONS}"))
                .is_ok(),
            "the floor itself is acceptable"
        );
        assert_eq!(
            start()
                .client_final(&format!("r=abcdef,s=c2FsdA==,i={}", MAX_ITERATIONS + 1))
                .err(),
            Some(ScramError::Iterations(MAX_ITERATIONS + 1))
        );
        assert!(matches!(
            start().client_final("s=c2FsdA==,r=abcdef,i=4096"),
            Err(ScramError::MalformedServerFirst(_))
        ));
    }

    /// Libera answers the client's first message with `e=other-error` when the
    /// account cannot do SCRAM. That is the server refusing before any proof,
    /// not a malformed message.
    #[test]
    fn a_server_error_in_place_of_the_first_message_is_reported_as_one() {
        let client =
            ScramClient::with_nonce(ScramHash::Sha512, "user", "pencil", "abc").expect("prepared");
        assert_eq!(
            client.client_final("e=other-error").err(),
            Some(ScramError::ServerError("other-error".into()))
        );
    }

    #[test]
    fn a_server_error_is_reported_in_its_words() {
        let client =
            ScramClient::with_nonce(ScramHash::Sha512, "user", "pencil", "abc").expect("prepared");
        let (_, awaiting) = client
            .client_final("r=abcdef,s=c2FsdA==,i=4096")
            .expect("client final");
        assert_eq!(
            awaiting.verify("e=invalid-proof"),
            Err(ScramError::ServerError("invalid-proof".into()))
        );
    }

    #[test]
    fn only_credential_server_errors_reject_the_credentials() {
        for error in [
            "invalid-proof",
            "unknown-user",
            "invalid-encoding",
            "invalid-username-encoding",
        ] {
            assert!(ScramError::ServerError(error.into()).rejects_credentials());
        }
        for error in ["other-error", "no-resources", "channel-bindings-dont-match"] {
            assert!(!ScramError::ServerError(error.into()).rejects_credentials());
        }
        assert!(!ScramError::ServerSignatureMismatch.rejects_credentials());
    }

    #[test]
    fn account_names_are_escaped_and_prepared() {
        let client =
            ScramClient::with_nonce(ScramHash::Sha512, "a=b,c", "pencil", "n").expect("prepared");
        assert_eq!(client.client_first(), "n,,n=a=3Db=2Cc,r=n");
        assert_eq!(
            ScramClient::with_nonce(ScramHash::Sha512, "user", "pass\u{0007}word", "n").err(),
            Some(ScramError::Unpreparable("password"))
        );
    }
}
