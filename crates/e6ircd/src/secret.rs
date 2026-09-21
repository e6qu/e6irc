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

/// A 256-bit key that seals and opens config secrets. Its bytes are wiped when
/// it is dropped, so a later memory disclosure (a core file, a swapped page)
/// does not carry a key the process has let go of.
pub struct SecretKey([u8; KEY_LEN]);

impl Drop for SecretKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

/// An ordered key set used during rotation. New values are always sealed with
/// `primary`; reads try it first and then the explicitly configured previous
/// keys. This makes the deployment transition crash-safe: either generation of
/// ciphertext remains readable while a database-wide re-seal is in flight.
pub struct SecretKeyring {
    primary: SecretKey,
    previous: Vec<SecretKey>,
}

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
    /// The same key appeared more than once in a keyring.
    DuplicateKey,
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadKey => write!(f, "key must be 32 base64-encoded bytes"),
            Self::NotSealed => write!(f, "value is not a sealed secret (enc:v1:/enc:v2:)"),
            Self::Corrupt => write!(f, "sealed secret is malformed"),
            Self::Decrypt => write!(f, "wrong key or tampered secret"),
            Self::DuplicateKey => write!(f, "a secret key is configured more than once"),
        }
    }
}

impl SecretKeyring {
    /// Construct a keyring with no rotation fallback.
    pub fn single(primary: SecretKey) -> Self {
        Self {
            primary,
            previous: Vec::new(),
        }
    }

    /// Construct an ordered rotation keyring, rejecting duplicate key
    /// material instead of silently making an operator's fallback list
    /// ambiguous.
    pub fn new(primary: SecretKey, previous: Vec<SecretKey>) -> Result<Self, SecretError> {
        // Compared in place: a list of copies would leave key bytes behind
        // that no `Drop` wipes.
        for (index, key) in previous.iter().enumerate() {
            if key.0 == primary.0 || previous[..index].iter().any(|earlier| earlier.0 == key.0) {
                return Err(SecretError::DuplicateKey);
            }
        }
        Ok(Self { primary, previous })
    }

    /// Number of explicitly configured keys, useful for redacted operator
    /// posture without exposing key material or fingerprints.
    pub fn key_count(&self) -> usize {
        1 + self.previous.len()
    }

    /// Seal with the primary key. Fallback keys are read-only.
    pub fn seal(&self, plaintext: &str, context: &[u8]) -> String {
        self.primary.seal(plaintext, context)
    }

    /// Open with the primary key, then each explicit previous key. Malformed
    /// or unsealed values fail immediately; only an authentication mismatch
    /// can mean that another configured key owns the blob.
    pub fn open(&self, blob: &str, context: &[u8]) -> Result<String, SecretError> {
        match self.primary.open(blob, context) {
            Ok(plaintext) => Ok(plaintext),
            Err(SecretError::Decrypt) => {
                for key in &self.previous {
                    match key.open(blob, context) {
                        Ok(plaintext) => return Ok(plaintext),
                        Err(SecretError::Decrypt) => {}
                        Err(error) => return Err(error),
                    }
                }
                Err(SecretError::Decrypt)
            }
            Err(error) => Err(error),
        }
    }
}

impl std::error::Error for SecretError {}

/// True when `value` is a sealed blob (and so needs a key to open), of either
/// generation.
pub fn is_sealed(value: &str) -> bool {
    value.starts_with(V1_PREFIX) || value.starts_with(V2_PREFIX)
}

/// Mark this process non-dumpable (`prctl(PR_SET_DUMPABLE, 0)`): the kernel
/// then writes no core file for it and refuses `ptrace` attachment and
/// `/proc/<pid>/mem` reads from other processes of the same user. Memory here
/// holds the master key, opened upstream credentials, and session tokens.
#[cfg(target_os = "linux")]
pub fn mark_process_non_dumpable() -> std::io::Result<()> {
    // SAFETY: PR_SET_DUMPABLE takes one integer argument and touches no
    // memory of ours; the unused arguments are passed as zero, as documented.
    let result = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// A fresh 256-bit bearer secret (a session, an API token, an invitation, a
/// browser state value) spelled in the URL-safe base64 alphabet: 44
/// characters, every symbol distinct, none needing escaping in a link, a query
/// or a cookie. The one generator, so no call site can spell it lossily.
pub fn random_url_safe_token() -> String {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("system RNG must produce token bytes");
    e6irc_proto::base64::encode_url_safe(&bytes)
}

impl SecretKey {
    /// Parse a base64-encoded 32-byte key (surrounding whitespace ok).
    pub fn from_base64(s: &str) -> Result<Self, SecretError> {
        use zeroize::Zeroize;
        let mut bytes = e6irc_proto::base64::decode(s.trim()).ok_or(SecretError::BadKey)?;
        let key = <[u8; KEY_LEN]>::try_from(bytes.as_slice())
            .map(Self)
            .map_err(|_| SecretError::BadKey);
        bytes.zeroize();
        key
    }

    /// Parse key text read from a file, wiping the text once it is parsed so
    /// the key's base64 spelling does not outlive it in freed memory.
    pub fn from_base64_text(mut text: String) -> Result<Self, SecretError> {
        use zeroize::Zeroize;
        let key = Self::from_base64(&text);
        text.zeroize();
        key
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

    /// The master key is wiped when its holder lets go of it, so a later
    /// memory disclosure (a core file, a swapped page) does not carry it.
    #[test]
    fn a_dropped_key_leaves_zeroes_behind() {
        let mut key = std::mem::ManuallyDrop::new(SecretKey::generate());
        assert!(key.0.iter().any(|byte| *byte != 0));
        // SAFETY: the value is dropped exactly once and never used as a key
        // again; only its plain bytes, which stay allocated inside the
        // `ManuallyDrop`, are read afterwards.
        unsafe { std::mem::ManuallyDrop::drop(&mut key) };
        assert_eq!(key.0, [0u8; KEY_LEN]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_process_can_be_marked_non_dumpable() {
        mark_process_non_dumpable().expect("PR_SET_DUMPABLE");
        // SAFETY: PR_GET_DUMPABLE reads one process attribute.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
    }

    #[test]
    fn random_url_safe_tokens_carry_256_bits_in_the_url_safe_alphabet() {
        let token = random_url_safe_token();
        assert_eq!(token.len(), 44, "{token}");
        assert!(
            token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'=')),
            "{token}"
        );
        assert_ne!(token, random_url_safe_token());
    }

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

    #[test]
    fn keyring_reads_previous_but_always_seals_with_primary() {
        let old = SecretKey::generate();
        let old_blob = old.seal("before", CTX);
        let primary = SecretKey::generate();
        let primary_copy = SecretKey::from_base64(&primary.to_base64()).unwrap();
        let ring = SecretKeyring::new(primary, vec![old]).unwrap();

        assert_eq!(ring.open(&old_blob, CTX).unwrap(), "before");
        let new_blob = ring.seal("after", CTX);
        assert_eq!(primary_copy.open(&new_blob, CTX).unwrap(), "after");
    }

    #[test]
    fn keyring_rejects_duplicate_material() {
        let key = SecretKey::generate();
        let duplicate = SecretKey::from_base64(&key.to_base64()).unwrap();
        assert!(matches!(
            SecretKeyring::new(key, vec![duplicate]),
            Err(SecretError::DuplicateKey)
        ));
    }
}
