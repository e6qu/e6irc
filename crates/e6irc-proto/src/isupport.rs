//! `RPL_ISUPPORT` (005) token model, shared by the server (advertising)
//! and the client/BNC side (interpreting what an upstream advertises).
//!
//! Format per the ISUPPORT spec as consolidated in Modern IRC
//! (https://modern.ircdocs.horse/#rplisupport-005): each middle param is
//! `NAME`, `NAME=value`, or `-NAME` (negation on later 005s); values may
//! encode arbitrary octets as `\xHH` hex escapes.

use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsupportToken<'a> {
    /// True for `-NAME`: the server retracts a previously advertised token.
    pub negated: bool,
    pub name: &'a str,
    pub value: Option<Cow<'a, str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsupportError {
    /// Empty name, or name with characters outside `A-Z0-9`.
    BadName,
    /// A negated token must not carry a value.
    NegatedWithValue,
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

impl<'a> IsupportToken<'a> {
    /// Parse one 005 middle parameter.
    pub fn parse(raw: &'a str) -> Result<Self, IsupportError> {
        let (negated, rest) = match raw.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, raw),
        };
        let (name, value) = match rest.split_once('=') {
            Some((n, v)) => (n, Some(unescape_value(v))),
            None => (rest, None),
        };
        if !valid_name(name) {
            return Err(IsupportError::BadName);
        }
        if negated && value.is_some() {
            return Err(IsupportError::NegatedWithValue);
        }
        Ok(Self {
            negated,
            name,
            value,
        })
    }

    /// Wire form of this token (value re-escaped as needed).
    pub fn serialize(&self) -> String {
        let mut out = String::new();
        if self.negated {
            out.push('-');
        }
        out.push_str(self.name);
        if let Some(value) = &self.value {
            out.push('=');
            out.push_str(&escape_value(value));
        }
        out
    }
}

/// Decode `\xHH` escapes for ASCII octets. Invalid or truncated escapes,
/// and escapes of non-ASCII octets, are literal text; multi-byte UTF-8
/// stays as-is (it needs no escaping — see [`escape_value`]).
pub fn unescape_value(raw: &str) -> Cow<'_, str> {
    if !raw.contains('\\') {
        return Cow::Borrowed(raw);
    }
    let mut out = String::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let decoded = if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1] == b'x'
            && bytes[i + 2].is_ascii_hexdigit()
            && bytes[i + 3].is_ascii_hexdigit()
        {
            // Both digits are ASCII, so `i + 2` and `i + 4` are char
            // boundaries and the slice cannot split a multi-byte char.
            u8::from_str_radix(&raw[i + 2..i + 4], 16)
                .ok()
                .filter(u8::is_ascii)
        } else {
            None
        };
        match decoded {
            Some(b) => {
                out.push(b as char);
                i += 4;
            }
            None => {
                let c = raw[i..].chars().next().expect("i is a char boundary");
                out.push(c);
                i += c.len_utf8();
            }
        }
    }
    Cow::Owned(out)
}

/// Encode a value: ASCII outside the printable non-space range, plus `\`
/// and `=`, becomes `\xHH`; non-ASCII UTF-8 passes through unescaped so
/// escape/unescape stay exact inverses.
pub fn escape_value(value: &str) -> Cow<'_, str> {
    fn needs_escape(b: u8) -> bool {
        b <= 0x20 || b == 0x7F || b == b'\\' || b == b'='
    }
    if !value.bytes().any(needs_escape) {
        return Cow::Borrowed(value);
    }
    let mut out = String::with_capacity(value.len() + 6);
    for c in value.chars() {
        if c.is_ascii() && needs_escape(c as u8) {
            out.push_str(&format!("\\x{:02X}", c as u8));
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flag_and_valued_tokens() {
        let t = IsupportToken::parse("EXCEPTS").unwrap();
        assert_eq!(
            t,
            IsupportToken {
                negated: false,
                name: "EXCEPTS",
                value: None
            }
        );

        let t = IsupportToken::parse("CASEMAPPING=rfc1459").unwrap();
        assert_eq!(t.name, "CASEMAPPING");
        assert_eq!(t.value.as_deref(), Some("rfc1459"));

        let t = IsupportToken::parse("CHANMODES=eIbq,k,flj,CFLMPQScgimnprstuz").unwrap();
        assert_eq!(t.value.as_deref(), Some("eIbq,k,flj,CFLMPQScgimnprstuz"));

        // empty value is allowed and distinct from no value
        let t = IsupportToken::parse("TARGMAX=").unwrap();
        assert_eq!(t.value.as_deref(), Some(""));
    }

    #[test]
    fn parses_negation() {
        let t = IsupportToken::parse("-MONITOR").unwrap();
        assert_eq!(
            t,
            IsupportToken {
                negated: true,
                name: "MONITOR",
                value: None
            }
        );
        assert_eq!(
            IsupportToken::parse("-MONITOR=5").unwrap_err(),
            IsupportError::NegatedWithValue
        );
    }

    #[test]
    fn rejects_bad_names() {
        for bad in ["", "-", "lower", "SP ACE", "UND_ER"] {
            assert_eq!(
                IsupportToken::parse(bad).unwrap_err(),
                IsupportError::BadName,
                "{bad:?}"
            );
        }
        // digits are fine
        assert!(IsupportToken::parse("ELIST5").is_ok());
    }

    #[test]
    fn value_escaping_roundtrip() {
        assert_eq!(unescape_value(r"a\x20b"), "a b");
        assert_eq!(unescape_value(r"\x5Cx"), r"\x");
        // invalid/truncated escapes stay literal
        assert_eq!(unescape_value(r"a\xZZb"), r"a\xZZb");
        assert_eq!(unescape_value(r"tail\x2"), r"tail\x2");
        assert!(matches!(unescape_value("plain"), Cow::Borrowed("plain")));

        assert_eq!(escape_value("a b=c\\d"), r"a\x20b\x3Dc\x5Cd");
        assert!(matches!(escape_value("plain"), Cow::Borrowed("plain")));
        for value in ["a b=c\\d", "Ünïcode Nét", "mix é = \\ x"] {
            assert_eq!(unescape_value(&escape_value(value)), value, "{value:?}");
        }
        // escapes of non-ASCII octets stay literal (UTF-8 is never escaped)
        assert_eq!(unescape_value(r"\xC3\xA9"), r"\xC3\xA9");
        // `\x` followed by multi-byte UTF-8 must not slice mid-char (a
        // fuzzer found this panic): the escape is invalid, so it is literal.
        assert_eq!(unescape_value("\\x€"), "\\x€");
        assert_eq!(unescape_value("a\\x\u{1f600}b"), "a\\x\u{1f600}b");
        assert_eq!(unescape_value("\\xé0"), "\\xé0");
    }

    #[test]
    fn parse_unescapes_values() {
        let t = IsupportToken::parse(r"NETWORK=Some\x20Net").unwrap();
        assert_eq!(t.value.as_deref(), Some("Some Net"));
    }

    #[test]
    fn serialize_forms() {
        let flag = IsupportToken {
            negated: false,
            name: "EXCEPTS",
            value: None,
        };
        assert_eq!(flag.serialize(), "EXCEPTS");
        let neg = IsupportToken {
            negated: true,
            name: "MONITOR",
            value: None,
        };
        assert_eq!(neg.serialize(), "-MONITOR");
        let valued = IsupportToken {
            negated: false,
            name: "NETWORK",
            value: Some("Some Net".into()),
        };
        assert_eq!(valued.serialize(), r"NETWORK=Some\x20Net");
    }
}
