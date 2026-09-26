#![no_main]

//! The bouncer's line-processing turns bytes from a hostile *upstream* server
//! into what an attached client sees. Three functions run on every deployment
//! (not just the feature-gated bridges) and are the relay boundary:
//!
//! - `decode_server_line` turns one framed upstream line (arbitrary bytes)
//!   into text, fitted so a line that fitted as bytes still fits as text;
//! - `upstream_line` neutralizes CR/LF/NUL in a stored upstream line, so a
//!   hostile upstream cannot smuggle a second forged line into an attached
//!   client's stream, and rejects a line over an IRC wire budget, loudly;
//! - `filter_tags` strips message tags an attaching client did not negotiate.
//!
//! The invariants asserted here for arbitrary input: after the real pipeline
//! (decode, sanitize, then filter), the line a client would receive contains
//! no CR, LF, or NUL — the bytes that would let one upstream line become two on
//! the client's wire — and a line whose bytes fit the wire budgets is relayed,
//! never replaced by the rejection notice: decoding invalid bytes (each one
//! three bytes of U+FFFD) must not turn "fits as bytes" into "rejected as
//! text". Plus the obvious no-panic.

use e6irc_proto::message::{decode_server_line, server_frame_fits};
use e6ircd::bouncer::fuzz::{AttachCaps, filter_tags, upstream_line};
use libfuzzer_sys::fuzz_target;

fn injects(s: &str) -> bool {
    s.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0))
}

fuzz_target!(|data: &[u8]| {
    // First byte selects which tag families the attaching client negotiated.
    let sel = data.first().copied().unwrap_or(0);
    let caps = AttachCaps {
        sasl: false,
        server_time: sel & 1 != 0,
        message_tags: sel & 2 != 0,
        account_tag: sel & 4 != 0,
        echo_message: false,
        batch: false,
        chathistory: false,
        read_marker: false,
        cap_notify: false,
        cap_302: false,
    };
    let bytes = data.get(1..).unwrap_or(&[]);

    // The real pipeline: an upstream line is decoded as the relay reads it,
    // sanitized on the way into the buffer, and tag-filtered on the way out.
    let raw = decode_server_line(bytes).into_owned();
    let sanitized = upstream_line(raw.clone());
    assert!(
        !injects(&sanitized),
        "sanitize left an injectable byte: {sanitized:?}"
    );
    // A framed line never holds CR or LF (the framing split on them); within
    // that domain, a line that fits as bytes is relayed as itself, with only
    // its NULs neutralized.
    let framed = !bytes.iter().any(|b| matches!(b, b'\r' | b'\n'));
    if framed && server_frame_fits(bytes) {
        assert!(
            server_frame_fits(raw.as_bytes()),
            "decoding outgrew the budget the bytes fitted: {} bytes",
            raw.len()
        );
        assert_eq!(
            sanitized,
            raw.replace('\0', " "),
            "a line that fits as bytes was rejected as text"
        );
    }

    let delivered = filter_tags(&sanitized, caps);
    if let Some(delivered) = &delivered {
        assert!(
            !injects(delivered),
            "filtered line carries an injectable byte: {delivered:?}"
        );
    }
    // The security invariant is injection-prevention above: whatever tags a
    // client did or did not negotiate, the pipeline never hands it a line that
    // splits into two on its wire. (filter_tags is only ever fed parse-validated
    // or daemon-constructed lines in production, so its behaviour on the
    // malformed lines this fuzzer also reaches — e.g. a body that itself begins
    // with `@` — is out of the reachable domain and not asserted here.)
    drop(filter_tags(&sanitized, AttachCaps::default()));
});
