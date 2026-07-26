//! Secrets at rest. Sensitive values (upstream SASL passwords, the OIDC client
//! secret, oper passwords) may be stored sealed and decrypted at startup with a
//! 256-bit key kept outside the config (a key file or the `E6IRC_SECRET_KEY` env
//! var). A leaked config alone then reveals no passwords. Sealing uses
//! ChaCha20-Poly1305 (aws-lc-rs, already in the tree via rustls) with a fresh
//! random nonce per value.
//!
//! **Context binding.** A sealed blob is bound to an authenticated-additional-data
//! *context* — a purpose/owner tag — so a blob sealed in one context (say, the
//! per-account BNC password of account A) cannot be opened in another (account B's
//! row, or a config field): the AEAD tag check fails. New blobs are `enc:v2:` and
//! carry that binding. Legacy `enc:v1:` blobs were sealed with no context and are
//! still opened (with empty AAD) so an existing deployment keeps working; a value
//! re-sealed on change upgrades to v2.
//!
//! A plaintext value whose text begins with an `enc:v1:`/`enc:v2:` marker cannot
//! be represented literally; store such a value sealed instead.

use aws_lc_rs::aead::{Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

/// Legacy marker: sealed with no context binding (empty AAD). Read-only now.
const V1_PREFIX: &str = "enc:v1:";
/// Current marker: sealed with a context bound as AEAD associated data.
const V2_PREFIX: &str = "enc:v2:";
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;

/// The context bound to a config-file secret (oper/OIDC/server-network values):
/// a fixed tag that a per-account BNC blob's context can never equal, so the two
/// classes of secret can't be substituted for one another.
pub const CONFIG_CONTEXT: &[u8] = b"config";

/// A 256-bit key that seals and opens config secrets.
pub struct SecretKey([u8; KEY_LEN]);

#[derive(Debug, PartialEq, Eq)]
pub enum SecretError {
    /// The key material was not 32 base64-decoded bytes.
    BadKey,
    /// The blob did not carry an `enc:v1:`/`enc:v2:` marker.
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
            Self::NotSealed => write!(f, "value is not a sealed secret (enc:v1:/enc:v2:)"),
            Self::Corrupt => write!(f, "sealed secret is malformed"),
            Self::Decrypt => write!(f, "wrong key or tampered secret"),
        }
    }
}

impl std::error::Error for SecretError {}

/// True when `value` is a sealed blob (and so needs a key to open), of either
/// generation.
pub fn is_sealed(value: &str) -> bool {
    value.starts_with(V1_PREFIX) || value.starts_with(V2_PREFIX)
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

    /// Seal `plaintext` into an `enc:v2:` blob (fresh random nonce), binding
    /// `context` as AEAD associated data — the blob can then only be opened with
    /// the same context, so it cannot be reused in a different purpose/owner.
    pub fn seal(&self, plaintext: &str, context: &[u8]) -> String {
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce)
            .expect("system RNG must produce a nonce");
        let mut in_out = plaintext.as_bytes().to_vec();
        self.aead()
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(context),
                &mut in_out,
            )
            .expect("sealing cannot fail with a valid key");
        let mut blob = Vec::with_capacity(NONCE_LEN + in_out.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&in_out);
        format!("{V2_PREFIX}{}", e6irc_proto::base64::encode(&blob))
    }

    /// Open a sealed blob back to plaintext. A `v2` blob must be opened with the
    /// same `context` it was sealed under (the AEAD tag check fails otherwise); a
    /// legacy `v1` blob carried no context and is opened with empty AAD (`context`
    /// ignored) so existing deployments keep working. Fails loudly on a wrong key,
    /// a tampered blob, a context mismatch, or a value that isn't sealed at all.
    pub fn open(&self, blob: &str, context: &[u8]) -> Result<String, SecretError> {
        let (body, aad) = if let Some(body) = blob.strip_prefix(V2_PREFIX) {
            (body, Aad::from(context))
        } else if let Some(body) = blob.strip_prefix(V1_PREFIX) {
            (body, Aad::from(&[][..]))
        } else {
            return Err(SecretError::NotSealed);
        };
        let raw = e6irc_proto::base64::decode(body).ok_or(SecretError::Corrupt)?;
        if raw.len() < NONCE_LEN + TAG_LEN {
            return Err(SecretError::Corrupt);
        }
        let (nonce, ct) = raw.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| SecretError::Corrupt)?;
        let mut in_out = ct.to_vec();
        let plain = self
            .aead()
            .open_in_place(nonce, aad, &mut in_out)
            .map_err(|_| SecretError::Decrypt)?;
        String::from_utf8(plain.to_vec()).map_err(|_| SecretError::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTX: &[u8] = b"test-context";

    #[test]
    fn seal_open_round_trips() {
        let key = SecretKey::generate();
        for pt in ["", "hunter2", "a longer secret with spaces", "unïcodé🔑"] {
            let sealed = key.seal(pt, CTX);
            assert!(is_sealed(&sealed), "{sealed}");
            assert!(sealed.starts_with(V2_PREFIX), "new seals are v2: {sealed}");
            assert_eq!(key.open(&sealed, CTX).unwrap(), pt);
        }
    }

    #[test]
    fn open_with_a_different_context_fails() {
        let key = SecretKey::generate();
        let sealed = key.seal("secret", b"context-a");
        // Right key, right blob, WRONG context: the AEAD tag check rejects it, so
        // a blob sealed for one owner/purpose cannot be opened for another.
        assert_eq!(key.open(&sealed, b"context-b"), Err(SecretError::Decrypt));
        assert_eq!(key.open(&sealed, b"context-a").unwrap(), "secret");
    }

    #[test]
    fn legacy_v1_blob_opens_with_empty_context() {
        // A blob produced by the pre-context sealer (no AAD) must still open,
        // regardless of the context passed — existing deployments keep working.
        let key = SecretKey::generate();
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new().fill(&mut nonce).unwrap();
        let mut in_out = b"legacy".to_vec();
        key.aead()
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::empty(),
                &mut in_out,
            )
            .unwrap();
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&in_out);
        let v1 = format!("{V1_PREFIX}{}", e6irc_proto::base64::encode(&blob));
        assert_eq!(key.open(&v1, b"whatever").unwrap(), "legacy");
        assert_eq!(key.open(&v1, CONFIG_CONTEXT).unwrap(), "legacy");
    }

    #[test]
    fn nonce_is_fresh_per_seal() {
        let key = SecretKey::generate();
        assert_ne!(key.seal("same", CTX), key.seal("same", CTX));
    }

    #[test]
    fn wrong_key_fails_loudly() {
        let sealed = SecretKey::generate().seal("secret", CTX);
        assert_eq!(
            SecretKey::generate().open(&sealed, CTX),
            Err(SecretError::Decrypt)
        );
    }

    #[test]
    fn tamper_fails_loudly() {
        let key = SecretKey::generate();
        let sealed = key.seal("secret", CTX);
        let body = sealed.strip_prefix(V2_PREFIX).unwrap();
        let mut raw = e6irc_proto::base64::decode(body).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        let tampered = format!("{V2_PREFIX}{}", e6irc_proto::base64::encode(&raw));
        assert_eq!(key.open(&tampered, CTX), Err(SecretError::Decrypt));
    }

    #[test]
    fn rejects_unsealed_and_corrupt() {
        let key = SecretKey::generate();
        assert_eq!(key.open("plaintext", CTX), Err(SecretError::NotSealed));
        assert_eq!(key.open("enc:v2:!!!!", CTX), Err(SecretError::Corrupt));
        assert_eq!(key.open("enc:v2:AAAA", CTX), Err(SecretError::Corrupt));
    }

    #[test]
    fn key_base64_round_trips() {
        let key = SecretKey::generate();
        let restored = SecretKey::from_base64(&key.to_base64()).unwrap();
        // A blob sealed by one must open with the other.
        assert_eq!(restored.open(&key.seal("x", CTX), CTX).unwrap(), "x");
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
