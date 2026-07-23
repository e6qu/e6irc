#![no_main]

//! `floor_char_boundary` / `truncate_on_char_boundary` underlie every
//! length-cap in the daemon — topic, kick reason, away, composer line, bridged
//! message — and several of those sit directly on remote input. Slicing a
//! `str` at the index this returns must never panic and must never lose or
//! corrupt bytes, for *any* string and *any* budget.
//!
//! The input is split into a budget and a body so the fuzzer explores the
//! interesting region — a cut landing inside a multi-byte character — rather
//! than only huge budgets that never cut at all.

use e6irc_proto::message::{floor_char_boundary, truncate_on_char_boundary};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    // First byte picks a budget in a range that straddles the string length, so
    // cuts land before, inside, and past the end.
    let budget = data.first().copied().unwrap_or(0) as usize % (s.len() + 2);

    let floor = floor_char_boundary(s, budget);
    assert!(floor <= budget || floor == s.len(), "floor exceeded its budget");
    assert!(floor <= s.len(), "floor past the end");
    assert!(s.is_char_boundary(floor), "floor not on a boundary");

    // The slice the primitive exists to make safe. A panic here is the bug.
    let head = truncate_on_char_boundary(s, budget);
    assert_eq!(head, &s[..floor], "truncate disagreed with floor");
    assert!(s.starts_with(head), "truncation is not a prefix");
    // Nothing beyond the budget survives (except when the budget itself was
    // past the end, where the whole string is legitimately kept).
    assert!(head.len() <= budget || head.len() == s.len());
});
