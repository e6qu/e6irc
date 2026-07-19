//! Secrets at rest. Sensitive config values (upstream SASL passwords)
//! may be stored sealed — `enc:v1:<base64>` — and decrypted at startup
//! with a 256-bit key kept outside the config file (a key file or the
//! `E6IRC_SECRET_KEY` env var). A leaked config alone then reveals no
//! passwords. Sealing uses ChaCha20-Poly1305 (aws-lc-rs, already in the
//! tree via rustls) with a fresh random nonce per value.
//!
//! A plaintext value whose text begins with the `enc:v1:` marker cannot
//! be represented literally; store such a value sealed instead.

use aws_lc_rs::aead::{Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

const PREFIX: &str = "enc:v1:";
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;

/// A 256-bit key that seals and opens config secrets.
pub struct SecretKey([u8; KEY_LEN]);

#[derive(Debug, PartialEq, Eq)]
pub enum SecretError {
    /// The key material was not 32 base64-decoded bytes.
    BadKey,
    /// The blob did not carry the `enc:v1:` marker.
    NotSealed,
    /// The base64 body was malformed or too short to hold nonce+tag.
    Corrupt,
    /// Authentication failed: wrong key or tampered ciphertext.
    Decrypt,
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadKey => write!(f, "key must be 32 base64-encoded bytes"),
            Self::NotSealed => write!(f, "value is not a sealed secret (enc:v1:)"),
            Self::Corrupt => write!(f, "sealed secret is malformed"),
            Self::Decrypt => write!(f, "wrong key or tampered secret"),
        }
    }
}

impl std::error::Error for SecretError {}

/// True when `value` is a sealed blob (and so needs a key to open).
pub fn is_sealed(value: &str) -> bool {
    value.starts_with(PREFIX)
}

impl SecretKey {
    /// Parse a base64-encoded 32-byte key (surrounding whitespace ok).
    pub fn from_base64(s: &str) -> Result<Self, SecretError> {
        let bytes = e6irc_proto::base64::decode(s.trim()).ok_or(SecretError::BadKey)?;
        let arr: [u8; KEY_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| SecretError::BadKey)?;
        Ok(Self(arr))
    }

    /// Generate a fresh key from the system RNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        SystemRandom::new()
            .fill(&mut bytes)
            .expect("system RNG must produce key bytes");
        Self(bytes)
    }

    /// The key as base64, for writing to a key file.
    pub fn to_base64(&self) -> String {
        e6irc_proto::base64::encode(&self.0)
    }

    fn aead(&self) -> LessSafeKey {
        LessSafeKey::new(
            UnboundKey::new(&aws_lc_rs::aead::CHACHA20_POLY1305, &self.0)
                .expect("32-byte key is valid for CHACHA20_POLY1305"),
        )
    }

    /// Seal `plaintext` into an `enc:v1:` blob with a fresh random nonce.
    pub fn seal(&self, plaintext: &str) -> String {
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce)
            .expect("system RNG must produce a nonce");
        let mut in_out = plaintext.as_bytes().to_vec();
        self.aead()
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::empty(),
                &mut in_out,
            )
            .expect("sealing cannot fail with a valid key");
        let mut blob = Vec::with_capacity(NONCE_LEN + in_out.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&in_out);
        format!("{PREFIX}{}", e6irc_proto::base64::encode(&blob))
    }

    /// Open an `enc:v1:` blob back to plaintext. Fails loudly on a wrong
    /// key, a tampered blob, or a value that isn't sealed at all.
    pub fn open(&self, blob: &str) -> Result<String, SecretError> {
        let body = blob.strip_prefix(PREFIX).ok_or(SecretError::NotSealed)?;
        let raw = e6irc_proto::base64::decode(body).ok_or(SecretError::Corrupt)?;
        if raw.len() < NONCE_LEN + TAG_LEN {
            return Err(SecretError::Corrupt);
        }
        let (nonce, ct) = raw.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| SecretError::Corrupt)?;
        let mut in_out = ct.to_vec();
        let plain = self
            .aead()
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| SecretError::Decrypt)?;
        String::from_utf8(plain.to_vec()).map_err(|_| SecretError::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trips() {
        let key = SecretKey::generate();
        for pt in ["", "hunter2", "a longer secret with spaces", "unïcodé🔑"] {
            let sealed = key.seal(pt);
            assert!(is_sealed(&sealed), "{sealed}");
            assert_eq!(key.open(&sealed).unwrap(), pt);
        }
    }

    #[test]
    fn nonce_is_fresh_per_seal() {
        let key = SecretKey::generate();
        assert_ne!(key.seal("same"), key.seal("same"));
    }

    #[test]
    fn wrong_key_fails_loudly() {
        let sealed = SecretKey::generate().seal("secret");
        assert_eq!(
            SecretKey::generate().open(&sealed),
            Err(SecretError::Decrypt)
        );
    }

    #[test]
    fn tamper_fails_loudly() {
        let key = SecretKey::generate();
        let sealed = key.seal("secret");
        let body = sealed.strip_prefix(PREFIX).unwrap();
        let mut raw = e6irc_proto::base64::decode(body).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        let tampered = format!("{PREFIX}{}", e6irc_proto::base64::encode(&raw));
        assert_eq!(key.open(&tampered), Err(SecretError::Decrypt));
    }

    #[test]
    fn rejects_unsealed_and_corrupt() {
        let key = SecretKey::generate();
        assert_eq!(key.open("plaintext"), Err(SecretError::NotSealed));
        assert_eq!(key.open("enc:v1:!!!!"), Err(SecretError::Corrupt));
        assert_eq!(key.open("enc:v1:AAAA"), Err(SecretError::Corrupt));
    }

    #[test]
    fn key_base64_round_trips() {
        let key = SecretKey::generate();
        let restored = SecretKey::from_base64(&key.to_base64()).unwrap();
        // A blob sealed by one must open with the other.
        assert_eq!(restored.open(&key.seal("x")).unwrap(), "x");
    }

    #[test]
    fn rejects_bad_key_material() {
        assert_eq!(
            SecretKey::from_base64("short").err(),
            Some(SecretError::BadKey)
        );
        assert_eq!(
            SecretKey::from_base64(&e6irc_proto::base64::encode(&[0u8; 16])).err(),
            Some(SecretError::BadKey)
        );
    }
}
