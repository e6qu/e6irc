#![no_main]

use std::borrow::Cow;

use e6irc_proto::message::{Message, Source, Tag};
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

// The construction side of the parse↔serialize contract. `parse_message`
// covers parse-first (`parse → to_line → parse`); this covers serialize-first.
// `Message`/`Tag`/`Source` have public fields, so any code can build a message
// directly (a bridge, a test, a future edit) without going through `parse` —
// and the invariant that `to_line` never emits a line that re-splits into a
// *different* message then rests entirely on `to_line`'s own checks, with no
// differential backstop. This target is that backstop: build an arbitrary
// `Message` from owned bytes and assert that whenever `to_line` ACCEPTS it, the
// wire form parses back and is a serialization fixed point. A message `to_line`
// rejects (a param with a space, an illegal command, …) is skipped — that path
// is the deliberate serialize-side guard, not a round-trip candidate.
fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    // Owned backing storage the borrowed `Message` references.
    let Ok(command) = String::arbitrary(&mut u) else {
        return;
    };
    let Ok(params) = Vec::<String>::arbitrary(&mut u) else {
        return;
    };
    let Ok(tag_pairs) = Vec::<(String, Option<String>)>::arbitrary(&mut u) else {
        return;
    };
    let Ok(source_parts) = Option::<(String, Option<String>, Option<String>)>::arbitrary(&mut u)
    else {
        return;
    };
    let Ok(has_trailing) = bool::arbitrary(&mut u) else {
        return;
    };

    let source = source_parts.as_ref().map(|(name, user, host)| Source {
        name: name.as_str(),
        user: user.as_deref(),
        host: host.as_deref(),
    });
    let tags = tag_pairs
        .iter()
        .map(|(key, value)| Tag {
            key: key.as_str(),
            value: value.as_deref().map(Cow::Borrowed),
        })
        .collect();
    let params_ref: Vec<&str> = params.iter().map(String::as_str).collect();

    let msg = Message {
        tags,
        source,
        command: command.as_str(),
        params: params_ref,
        has_trailing,
    };

    // Whatever `to_line` accepts, `parse` must accept and round-trip.
    if let Ok(wire) = msg.to_line() {
        let reparsed = Message::parse(&wire).expect("to_line output must re-parse");
        assert_eq!(
            reparsed.to_line().expect("re-serialization"),
            wire,
            "serialize is not a fixed point from the construction side"
        );
    }
});
