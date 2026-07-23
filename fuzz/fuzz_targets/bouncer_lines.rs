#![no_main]

//! The bouncer's line-processing turns bytes from a hostile *upstream* server
//! into what an attached client sees. Two functions run on every deployment
//! (not just the feature-gated bridges) and are the injection-prevention
//! boundary:
//!
//! - `sanitize_upstream_line` neutralizes CR/LF/NUL in a stored upstream line,
//!   so a hostile upstream cannot smuggle a second forged line into an attached
//!   client's stream.
//! - `filter_tags` strips message tags an attaching client did not negotiate.
//!
//! The security invariant asserted here for arbitrary input: after the real
//! pipeline (sanitize, then filter), the line a client would receive contains
//! no CR, LF, or NUL — the bytes that would let one upstream line become two on
//! the client's wire. Plus the obvious no-panic.

use e6ircd::bouncer::fuzz::{AttachCaps, filter_tags, sanitize_upstream_line};
use libfuzzer_sys::fuzz_target;

fn injects(s: &str) -> bool {
    s.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0))
}

fuzz_target!(|data: &[u8]| {
    // First byte selects which tag families the attaching client negotiated.
    let sel = data.first().copied().unwrap_or(0);
    let caps = AttachCaps {
        server_time: sel & 1 != 0,
        message_tags: sel & 2 != 0,
        account_tag: sel & 4 != 0,
    };
    let raw = String::from_utf8_lossy(data.get(1..).unwrap_or(&[])).into_owned();

    // The real pipeline: a stored upstream line is sanitized on the way in and
    // tag-filtered on the way out to a client.
    let sanitized = sanitize_upstream_line(raw.clone());
    assert!(!injects(&sanitized), "sanitize left an injectable byte: {sanitized:?}");

    let delivered = filter_tags(&sanitized, caps);
    assert!(
        !injects(&delivered),
        "filtered line carries an injectable byte: {delivered:?}"
    );
    // The security invariant is injection-prevention above: whatever tags a
    // client did or did not negotiate, the pipeline never hands it a line that
    // splits into two on its wire. (filter_tags is only ever fed parse-validated
    // or daemon-constructed lines in production, so its behaviour on the
    // malformed lines this fuzzer also reaches — e.g. a body that itself begins
    // with `@` — is out of the reachable domain and not asserted here.)
    let _ = filter_tags(&sanitized, AttachCaps::default());
});
