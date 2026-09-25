#![no_main]

use e6irc_proto::isupport::IsupportToken;
use libfuzzer_sys::fuzz_target;

// The daemon only ever parses 005 tokens (an upstream's, for the bouncer and
// the clients), so parsing is the surface: it must never panic, and what it
// accepts must hold the token's invariants.
fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(token) = IsupportToken::parse(raw) else {
        return;
    };
    assert!(
        !token.name.is_empty()
            && token
                .name
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()),
        "accepted an invalid name: {:?}",
        token.name
    );
    assert!(
        !(token.negated && token.value.is_some()),
        "a negated token carries no value"
    );
    let prefix = if token.negated { "-" } else { "" };
    assert!(
        raw.starts_with(&format!("{prefix}{}", token.name)),
        "the name is the raw token's own"
    );
    if let Some(value) = &token.value {
        // Unescaping only ever shortens: `\xHH` becomes one byte.
        assert!(value.len() < raw.len(), "value longer than its token");
    }
});
