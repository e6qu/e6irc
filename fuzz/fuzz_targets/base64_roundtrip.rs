#![no_main]

//! `base64::decode` parses the SASL `AUTHENTICATE` payload — untrusted bytes on
//! the authentication path, decoded before any credential check. Two properties:
//!
//! 1. **Decode never panics** on arbitrary text (malformed padding, non-alphabet
//!    bytes, wrong length): it returns `None`, never crashes the worker that
//!    every client's SASL exchange runs through.
//! 2. **Encode/decode round-trips.** For any bytes, `decode(encode(b)) == b` —
//!    the property SASL relies on to recover the exact credential the client
//!    sent, byte for byte.

use e6irc_proto::base64::{decode, encode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1. Decoding arbitrary text must not panic (result ignored).
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = decode(text);
    }

    // 2. Round-trip: encoding any bytes and decoding must return them exactly.
    let reencoded = encode(data);
    assert_eq!(
        decode(&reencoded).as_deref(),
        Some(data),
        "encode/decode is not a round-trip"
    );
});
