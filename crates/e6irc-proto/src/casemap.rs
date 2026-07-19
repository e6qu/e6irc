//! Nick/channel case mapping.
//!
//! Libera.Chat (Solanum) advertises `CASEMAPPING=rfc1459`: ASCII case
//! folding where `[]\~` are additionally the uppercase forms of `{}|^`
//! (RFC 1459 §2.2; https://modern.ircdocs.horse/#casemapping-parameter).
//! `rfc1459-strict` omits the `~`/`^` pair; `ascii` maps letters only.

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum CaseMapping {
    #[default]
    Rfc1459,
    Rfc1459Strict,
    Ascii,
}

impl CaseMapping {
    /// Lowercase a single byte under this mapping. Non-ASCII bytes are
    /// returned unchanged.
    pub const fn lower(self, b: u8) -> u8 {
        match b {
            b'A'..=b'Z' => b + 32,
            b'[' | b']' | b'\\' => match self {
                Self::Rfc1459 | Self::Rfc1459Strict => b + 32,
                Self::Ascii => b,
            },
            b'~' => match self {
                Self::Rfc1459 => b'^',
                Self::Rfc1459Strict | Self::Ascii => b,
            },
            _ => b,
        }
    }

    /// Casefold a string for comparison/keying. Only ASCII is affected;
    /// multi-byte UTF-8 sequences pass through untouched.
    pub fn casefold(self, s: &str) -> String {
        let folded: Vec<u8> = s.bytes().map(|b| self.lower(b)).collect();
        // lower() maps ASCII to ASCII and leaves bytes >= 0x80 untouched,
        // so folding cannot break UTF-8 validity.
        String::from_utf8(folded).expect("ASCII-only mapping preserves UTF-8")
    }

    /// Case-insensitive equality under this mapping, without allocating.
    pub fn eq(self, a: &str, b: &str) -> bool {
        a.len() == b.len()
            && a.bytes()
                .zip(b.bytes())
                .all(|(x, y)| self.lower(x) == self.lower(y))
    }

    /// The value advertised in `RPL_ISUPPORT CASEMAPPING=`.
    pub const fn isupport_token(self) -> &'static str {
        match self {
            Self::Rfc1459 => "rfc1459",
            Self::Rfc1459Strict => "rfc1459-strict",
            Self::Ascii => "ascii",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CaseMapping::{Ascii, Rfc1459, Rfc1459Strict};

    #[test]
    fn rfc1459_folds_ascii_letters_and_special_pairs() {
        assert_eq!(Rfc1459.casefold("FOO[]\\~bar"), "foo{}|^bar");
        assert_eq!(Rfc1459.casefold("nick"), "nick");
        assert_eq!(Rfc1459.casefold("#Chan[1]"), "#chan{1}");
    }

    #[test]
    fn rfc1459_strict_excludes_tilde_caret_pair() {
        assert_eq!(Rfc1459Strict.casefold("A[]\\~^"), "a{}|~^");
        assert!(Rfc1459Strict.eq("[x]", "{x}"));
        assert!(!Rfc1459Strict.eq("~x", "^x"));
    }

    #[test]
    fn ascii_maps_letters_only() {
        assert_eq!(Ascii.casefold("A[z]"), "a[z]");
        assert!(Ascii.eq("NiCk", "nick"));
        assert!(!Ascii.eq("[a]", "{a}"));
    }

    #[test]
    fn rfc1459_equality() {
        assert!(Rfc1459.eq("Nick", "nick"));
        assert!(Rfc1459.eq("[a]\\~", "{a}|^"));
        assert!(Rfc1459.eq("#CHAN", "#chan"));
        assert!(!Rfc1459.eq("nick", "nick2"));
        assert!(!Rfc1459.eq("nick", ""));
    }

    #[test]
    fn non_ascii_passes_through_unchanged() {
        assert_eq!(Rfc1459.casefold("Ólaf"), "Ólaf");
        assert!(Rfc1459.eq("Ólaf", "Ólaf"));
        assert!(!Rfc1459.eq("Ólaf", "ólaf"));
    }

    #[test]
    fn lower_single_bytes() {
        assert_eq!(Rfc1459.lower(b'A'), b'a');
        assert_eq!(Rfc1459.lower(b'['), b'{');
        assert_eq!(Rfc1459.lower(b']'), b'}');
        assert_eq!(Rfc1459.lower(b'\\'), b'|');
        assert_eq!(Rfc1459.lower(b'~'), b'^');
        assert_eq!(Rfc1459.lower(b'0'), b'0');
        assert_eq!(Rfc1459.lower(0xC3), 0xC3);
        assert_eq!(Rfc1459Strict.lower(b'~'), b'~');
        assert_eq!(Ascii.lower(b'['), b'[');
        assert_eq!(Ascii.lower(b'Z'), b'z');
    }

    #[test]
    fn casefold_is_idempotent() {
        for m in [Rfc1459, Rfc1459Strict, Ascii] {
            for s in ["MixedCASE[]\\~^{}|", "Ólaf~", "#chan", ""] {
                let once = m.casefold(s);
                assert_eq!(m.casefold(&once), once);
            }
        }
    }

    #[test]
    fn isupport_tokens() {
        assert_eq!(Rfc1459.isupport_token(), "rfc1459");
        assert_eq!(Rfc1459Strict.isupport_token(), "rfc1459-strict");
        assert_eq!(Ascii.isupport_token(), "ascii");
    }
}
