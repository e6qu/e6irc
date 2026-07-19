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

/// Iterative wildcard match with backtracking over the last `*`.
fn glob(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == text[t] || pattern[p] == b'?') {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some((p, t));
            p += 1;
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
    fn empty_edges() {
        assert!(hit("*", ""));
        assert!(!hit("?", ""));
        assert!(hit("", ""));
        assert!(!hit("", "x"));
    }
}
