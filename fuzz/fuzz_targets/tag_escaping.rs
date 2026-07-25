#![no_main]

use e6irc_proto::message::{escape_tag_value, unescape_tag_value};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    // unescape ∘ escape is the identity for any *valid* tag value. A NUL cannot
    // appear in a tag value on the wire (it has no escape sequence and would
    // truncate the line), so `escape_tag_value` deliberately drops it — that
    // output is wire-safe but not round-trippable, so exclude NUL from the
    // identity check.
    if !s.contains('\0') {
        assert_eq!(unescape_tag_value(&escape_tag_value(s)), s);
    }
    // The escaper's output is always wire-safe: no bare NUL survives, whatever
    // the input.
    assert!(!escape_tag_value(s).contains('\0'));
    // Unescaping arbitrary input must terminate without panicking (the reverse
    // direction is not injective: invalid escapes collapse).
    let _ = unescape_tag_value(s);
});
