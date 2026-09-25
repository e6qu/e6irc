#![no_main]

use e6irc_proto::message::Message;
use libfuzzer_sys::fuzz_target;

// Every consumer reads a parsed `Message` field by field (the core's dispatch,
// the bouncer's line processing, the clients), trusting the structure `parse`
// promises. Whatever the input, `parse` must return rather than panic, and a
// message it accepts must hold the invariants those readers assume.
fuzz_target!(|data: &[u8]| {
    let Ok(line) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(msg) = Message::parse(line) else {
        return;
    };
    let wire_safe = |s: &str| !s.contains(['\r', '\n', '\0']);

    assert!(!msg.command.is_empty(), "empty command from {line:?}");
    assert!(
        msg.command
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')),
        "command {:?} from {line:?}",
        msg.command
    );
    for tag in &msg.tags {
        assert!(!tag.key.is_empty(), "empty tag key from {line:?}");
        assert!(
            !tag.key.contains([' ', ';', '=']) && wire_safe(tag.key),
            "tag key {:?} from {line:?}",
            tag.key
        );
    }
    if let Some(source) = &msg.source {
        assert!(!source.name.is_empty(), "empty source name from {line:?}");
        assert!(
            !source.name.contains(['!', '@']),
            "source name {:?} from {line:?}",
            source.name
        );
        for part in [Some(source.name), source.user, source.host]
            .into_iter()
            .flatten()
        {
            assert!(
                !part.contains(' ') && wire_safe(part),
                "source part {part:?} from {line:?}"
            );
        }
    }
    let last = msg.params.len().checked_sub(1);
    for (i, param) in msg.params.iter().enumerate() {
        assert!(wire_safe(param), "param {param:?} from {line:?}");
        // Only a `:`-marked final parameter may be empty, hold a space, or
        // begin with a colon; every other one is a single middle token.
        if !(msg.has_trailing && Some(i) == last) {
            assert!(
                !param.is_empty() && !param.contains(' ') && !param.starts_with(':'),
                "middle param {param:?} from {line:?}"
            );
        }
    }
});
