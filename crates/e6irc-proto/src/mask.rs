//! IRC hostmask matching: `*` (any run) and `?` (any one) wildcards,
//! compared under the server casemapping. Used for bans, quiets,
//! exceptions, and invite exceptions.

use crate::casemap::CaseMapping;

/// Does `mask` (e.g. `*!*@*.example.com`) match `subject`
/// (e.g. `nick!user@host.example.com`)?
pub fn matches(casemap: CaseMapping, mask: &str, subject: &str) -> bool {
    let mask: Vec<u8> = mask.bytes().map(|b| casemap.lower(b)).collect();
    let subject: Vec<u8> = subject.bytes().map(|b| casemap.lower(b)).collect();
    glob(&mask, &subject)
}

/// Are two hostmasks the *same* mask under the server casemapping? List modes
/// (`+b/+q/+e/+I`) match subjects case-insensitively via [`matches`], so their
/// add-dedup and removal must compare masks the same way: otherwise `-b FOO!*@*`
/// fails to remove a ban stored as `foo!*@*` (leaving it enforced) while the
/// server still broadcasts the removal, and `+b FOO!*@*` after `+b foo!*@*`
/// double-stores one logical ban. Length-preserving per-byte fold, so equal
/// masks always share a length.
pub fn eq(casemap: CaseMapping, a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .all(|(x, y)| casemap.lower(x) == casemap.lower(y))
}

/// Iterative wildcard match with backtracking over the last `*`.
fn glob(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        // The `*` wildcard must be recognized *before* the literal-equality
        // check: a literal `*` byte in the subject is 0x2A, so testing
        // `pattern[p] == text[t]` first would match a pattern `*` against a
        // subject `*` one-to-one — treating the wildcard as a literal and
        // failing masks like `*?` against a subject containing `*`.
        if p < pattern.len() && pattern[p] == b'*' {
            star = Some((p, t));
            p += 1;
        } else if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if let Some((sp, st)) = star {
            p = sp + 1;
            t = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::casemap::CaseMapping::Rfc1459;

    fn hit(mask: &str, subject: &str) -> bool {
        matches(Rfc1459, mask, subject)
    }

    #[test]
    fn exact_and_case_insensitive() {
        assert!(hit("nick!user@host", "nick!user@host"));
        assert!(hit("NICK!user@HOST", "nick!USER@host"));
        // rfc1459: {} matches []
        assert!(hit("n{x}!u@h", "n[x]!u@h"));
        assert!(!hit("nick!user@host", "nick!user@other"));
    }

    #[test]
    fn star_wildcards() {
        assert!(hit("*!*@*", "anyone!anything@anywhere"));
        assert!(hit("*!*@*.example.com", "alice!u@node.example.com"));
        assert!(!hit("*!*@*.example.com", "alice!u@example.org"));
        assert!(hit("al*e!*@*", "alice!u@h"));
        assert!(hit("*", "nick!user@host"));
    }

    #[test]
    fn question_mark() {
        assert!(hit("n?ck!*@*", "nick!u@h"));
        assert!(hit("n?ck!*@*", "nack!u@h"));
        assert!(!hit("n?ck!*@*", "nck!u@h"));
    }

    #[test]
    fn backtracking_cases() {
        assert!(hit("*abc*abc", "xabcyabcabc"));
        assert!(!hit("*abc", "ab"));
        assert!(hit("a*b*c", "aXXbYYc"));
        assert!(!hit("a*b*c", "aXXcYYb"));
    }

    #[test]
    fn star_is_a_wildcard_even_against_a_literal_star_in_the_subject() {
        // A literal `*` byte in the subject is 0x2A; the pattern's `*` must
        // still be a wildcard against it, not a one-to-one literal match.
        // (Found by the differential glob fuzz target: `*?` vs `*`.)
        assert!(hit("*?", "*"));
        assert!(hit("*", "*"));
        assert!(hit("*", "***"));
        assert!(hit("a*", "a*b*c"));
        assert!(hit("*!*@*", "n!u*x@h"));
        // And it still rejects when it genuinely should not match.
        assert!(!hit("x*", "*abc"));
    }

    #[test]
    fn eq_folds_like_the_matcher() {
        // Same mask under rfc1459 folding, differing only in case → equal, so a
        // `-b` removes what a differently-cased `+b` stored.
        assert!(eq(Rfc1459, "FOO!*@*", "foo!*@*"));
        assert!(eq(Rfc1459, "n{x}!u@h", "n[x]!u@h")); // rfc1459: {}~ ↔ []^
        // Genuinely different masks are not equal.
        assert!(!eq(Rfc1459, "foo!*@*", "bar!*@*"));
        assert!(!eq(Rfc1459, "foo!*@*", "foo!*@*.net")); // length differs
        // A wildcard is a literal here (equality, not matching): `*` != a name.
        assert!(!eq(Rfc1459, "*!*@*", "foo!*@*"));
    }

    #[test]
    fn empty_edges() {
        assert!(hit("*", ""));
        assert!(!hit("?", ""));
        assert!(hit("", ""));
        assert!(!hit("", "x"));
    }
}
