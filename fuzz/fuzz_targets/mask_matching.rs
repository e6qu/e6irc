#![no_main]

//! `mask::matches` is the hostmask glob used for every ban, quiet, and
//! exception — untrusted input, since any channel operator sets the masks it is
//! run against. Its shipped implementation is an *iterative* matcher that
//! backtracks over a single remembered `*` (the O(n·m) algorithm); its
//! correctness for multiple stars is subtle enough to be worth proving rather
//! than trusting.
//!
//! This is a **differential** fuzz: for arbitrary `(mask, subject)` it compares
//! the shipped matcher against a trivially-correct recursive reference with the
//! same `*` / `?` semantics. Any disagreement — a ban that matches under one
//! and not the other — is a finding. The naive reference is exponential in the
//! worst case, so inputs are capped short; that is plenty to exercise every
//! backtracking path while keeping each execution fast.

use e6irc_proto::casemap::CaseMapping;
use e6irc_proto::mask;
use libfuzzer_sys::fuzz_target;

/// The specification: `*` matches any run (including empty), `?` matches exactly
/// one byte, everything else is a literal. No escaping (matching `mask::glob`).
///
/// The textbook glob dynamic program: `dp[i][j]` is "does `pattern[i..]` match
/// `text[j..]`". O(n·m) and unambiguously correct — a naive recursive spec is
/// exponential on an all-`*` pattern, which the fuzzer (correctly) flags as a
/// slow unit; that slowness is the reference's, not the code under test's.
fn reference(pattern: &[u8], text: &[u8]) -> bool {
    let (n, m) = (pattern.len(), text.len());
    let mut dp = vec![vec![false; m + 1]; n + 1];
    dp[n][m] = true;
    for i in (0..n).rev() {
        for j in (0..=m).rev() {
            dp[i][j] = if pattern[i] == b'*' {
                // Match zero bytes (advance the pattern) or one (advance text).
                dp[i + 1][j] || (j < m && dp[i][j + 1])
            } else {
                j < m && (pattern[i] == b'?' || pattern[i] == text[j]) && dp[i + 1][j + 1]
            };
        }
    }
    dp[0][0]
}

fuzz_target!(|data: &[u8]| {
    // Cap lengths so the exponential reference stays fast; split the input into
    // a mask and a subject on the first NUL (or halve it if there is none).
    let data = &data[..data.len().min(120)];
    let (raw_mask, raw_subject) = match data.iter().position(|&b| b == 0) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => data.split_at(data.len() / 2),
    };
    let mask = &raw_mask[..raw_mask.len().min(48)];
    let subject = &raw_subject[..raw_subject.len().min(48)];
    let (Ok(mask), Ok(subject)) = (std::str::from_utf8(mask), std::str::from_utf8(subject)) else {
        return;
    };

    for cm in [
        CaseMapping::Rfc1459,
        CaseMapping::Rfc1459Strict,
        CaseMapping::Ascii,
    ] {
        let shipped = mask::matches(cm, mask, subject);
        // The public matcher folds both sides before globbing; the reference
        // globs the same folded bytes, isolating the glob from the fold.
        let folded_mask = cm.casefold(mask);
        let folded_subject = cm.casefold(subject);
        let spec = reference(folded_mask.as_bytes(), folded_subject.as_bytes());
        assert_eq!(
            shipped, spec,
            "glob disagrees with spec ({cm:?}): mask={mask:?} subject={subject:?} \
             shipped={shipped} spec={spec}"
        );
    }
});
