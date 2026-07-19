#![no_main]

use e6irc_proto::message::{escape_tag_value, unescape_tag_value};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    // escape ∘ unescape must be the identity for any value...
    assert_eq!(unescape_tag_value(&escape_tag_value(s)), s);
    // ...and unescaping arbitrary input must terminate without panicking
    // (the reverse direction is not injective: invalid escapes collapse).
    let _ = unescape_tag_value(s);
});
