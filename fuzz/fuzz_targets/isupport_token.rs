#![no_main]

use e6irc_proto::isupport::IsupportToken;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(token) = IsupportToken::parse(s) else {
        return;
    };
    let wire = token.serialize();
    let reparsed = IsupportToken::parse(&wire).expect("serialized token must re-parse");
    assert_eq!(reparsed, token, "parse/serialize round-trip diverged");
});
