#![no_main]

use e6irc_proto::message::Message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(line) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(parsed) = Message::parse(line) else {
        return;
    };
    // Anything parseable must serialize, and the result must re-parse to
    // an equivalent message (serialization is canonical, so byte
    // equality is only guaranteed from the second generation on).
    let wire = parsed.to_line().expect("parsed message must serialize");
    let reparsed = Message::parse(&wire).expect("serialized message must re-parse");
    assert_eq!(
        reparsed.to_line().expect("re-serialization"),
        wire,
        "serialize is not a fixed point"
    );
});
