//! One home for turning untrusted text into fields safe for the IRC wire.
//!
//! Every string a client or an upstream sends eventually lands somewhere on the
//! wire, and where it lands sets the rule it must obey:
//!
//! - **Source prefix** (`nick!user@host`): no `!`, `@`, space, or CR/LF/NUL, or
//!   a receiving client misparses the components (host spoofing).
//! - **Middle parameter** (a nick, channel, account in `WHOISACCOUNT` etc.): no
//!   space (it would split into two params) and no CR/LF/NUL.
//! - **Tag key/value**: keys are restricted to `+[vendor/]name`; values must be
//!   escaped (that escaping lives in `e6irc_proto::message::escape_tag_value`).
//! - **Trailing parameter** (realname, away, topic, kick/part/quit reasons): any
//!   byte *except* CR/LF/NUL is legal, so these need only length bounding.
//!
//! Client input has already had CR/LF/NUL rejected by the parser, so for it only
//! the position-specific rules remain. **Upstream** bytes (bridge relays) have
//! not, so [`upstream_line`] neutralizes those first. Length bounding and
//! wire-limit fitting are a separate concern and live with delivery
//! (`truncate_chars`, `fit_trailing`, `fit_relayed_text`) over
//! `e6irc_proto::message::truncate_on_char_boundary`.

/// Validate a username for the `nick!user@host` source prefix.
pub(crate) fn username(raw: &str, max_len: usize) -> Option<String> {
    (!raw.is_empty()
        && raw.len() <= max_len
        && raw
            .chars()
            .all(|c| !matches!(c, '!' | '@' | ' ') && !c.is_control()))
    .then(|| raw.to_string())
}

/// A provider-supplied name reduced to a nick-like account name: ASCII
/// alphanumerics and the RFC1459 "special" nick characters survive, everything
/// else (spaces, control, line/tag separators) is dropped and bounded to 32.
/// Returns `None` when no usable name remains. Used for OIDC provisioning.
pub(crate) fn account_name(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '-' | '_' | '.' | '[' | ']' | '{' | '}' | '\\' | '|' | '^' | '`'
                )
        })
        .take(32)
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

/// An arbitrary upstream display name reduced to a safe nick token for the
/// source-prefix position: any character that is not nick-legal becomes `_`, so
/// a hostile bridge upstream cannot smuggle a space, `!`, `@`, or `:` into the
/// prefix and forge a different source or command. Bounded to 30 characters.
#[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
pub(crate) fn nick_token(raw: &str) -> String {
    let legal = |c: char| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '[' | ']' | '\\' | '`' | '_' | '^' | '{' | '|' | '}' | '-'
            )
    };
    let mut out: String = raw
        .chars()
        .map(|c| if legal(c) { c } else { '_' })
        .take(30)
        .collect();
    if out.is_empty() {
        out.push('_');
    }
    out
}

/// Make one upstream line safe to buffer or broadcast.
pub(crate) fn upstream_line(line: String) -> String {
    let line = if line.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
        line.chars()
            .map(|c| {
                if matches!(c, '\r' | '\n' | '\0') {
                    ' '
                } else {
                    c
                }
            })
            .collect()
    } else {
        line
    };
    e6irc_proto::message::truncate_on_char_boundary(&line, e6irc_proto::message::MAX_LINE_LEN - 2)
        .to_string()
}

/// Longest client-only tag key relayed. The whole tag section is bounded, but
/// an oversized key is still propagated verbatim to every recipient — a vendor
/// host plus a name never needs more than this.
pub(crate) const MAX_TAG_KEY_LEN: usize = 100;

/// Whether a client-only tag key is well-formed enough to relay to other
/// clients. The parser accepts any non-delimiter byte in a key (control chars,
/// non-ASCII), but the message-tags spec restricts a client-only key to `+`,
/// then an optional dotted-hostname `vendor/`, then a `[A-Za-z0-9-]` name — so
/// relaying a raw key would propagate a malformed, oversized, or hostile one to
/// everyone in the channel. A key that does not fit the spec (structure, charset,
/// or length) is dropped rather than relayed.
pub(crate) fn valid_client_tag_key(key: &str) -> bool {
    let Some(rest) = key.strip_prefix('+') else {
        return false;
    };
    if rest.is_empty() || rest.len() > MAX_TAG_KEY_LEN {
        return false;
    }
    // `[vendor/]name` with at most one `/`: `split_once` keeps any further `/` in
    // the name segment, which the name charset then rejects.
    let (vendor, name) = match rest.split_once('/') {
        Some((v, n)) => (Some(v), n),
        None => (None, rest),
    };
    let name_ok = !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    // The vendor is a hostname: alphanumerics, `-`, and `.` — but not empty
    // (a leading `/` is malformed).
    let vendor_ok = vendor.is_none_or(|v| {
        !v.is_empty()
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
    });
    name_ok && vendor_ok
}

/// Whether `nick` is a legal nickname: it starts with a letter or one of the
/// RFC1459 "special" characters and continues with those plus digits and `-`,
/// within `nicklen`. A NickServ-registered account name inherits exactly this
/// charset (a registered nick *is* the account), and a nick-derived source
/// prefix stays within it. An **OIDC-provisioned** account name ([`account_name`])
/// is deliberately broader — it also admits `.` and a leading digit, for
/// email-local-part names like `john.doe` — because it is never used in the nick
/// position; it appears only in tag/param positions (`account=`, WHOISACCOUNT,
/// extended-join) where those extra characters are not delimiters.
pub(crate) fn valid_nick(nick: &str, nicklen: usize) -> bool {
    let mut bytes = nick.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    let special = |b: u8| {
        matches!(
            b,
            b'[' | b']' | b'\\' | b'`' | b'_' | b'^' | b'{' | b'|' | b'}'
        )
    };
    if !(first.is_ascii_alphabetic() || special(first)) {
        return false;
    }
    nick.len() <= nicklen && bytes.all(|b| b.is_ascii_alphanumeric() || special(b) || b == b'-')
}

/// Maximum channel-name length in bytes. Enforced by [`valid_channel_name`] and
/// advertised as ISUPPORT `CHANNELLEN`; the advertisement reads this const so the
/// two can never drift (the class the ISUPPORT builder is written to prevent).
pub(crate) const CHANNELLEN: usize = 50;

/// Whether `name` is a legal channel name: `#`-prefixed, non-empty, ≤ CHANNELLEN
/// bytes, and free of the bytes that would split it or the line (space, comma,
/// BEL, `:`, and CR/LF/NUL). A middle parameter, so no space is the load-bearing
/// rule — but CR/LF/NUL matter too: client names are pre-screened by
/// `Message::parse`, yet a *bridge* channel name comes from a remote API and
/// never passes through the parser, so a `#foo\nEVIL` would otherwise flatten
/// (via `upstream_line`) to the multi-param forge `#foo EVIL` the space-check
/// exists to prevent.
pub(crate) fn valid_channel_name(name: &str) -> bool {
    name.starts_with('#')
        && name.len() > 1
        && name.len() <= CHANNELLEN
        && !name
            .bytes()
            .any(|b| matches!(b, b' ' | b',' | 0x07 | b':' | b'\r' | b'\n' | 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_rejects_prefix_breaking_chars() {
        assert_eq!(username("a@evil.com!x", 10), None);
        assert_eq!(username("@@@", 10), None);
        assert_eq!(username("ok_name", 10), Some("ok_name".to_string()));
    }

    #[test]
    fn valid_client_tag_key_matches_the_spec_charset() {
        assert!(valid_client_tag_key("+example.com/reply"));
        assert!(valid_client_tag_key("+typing"));
        assert!(!valid_client_tag_key("+bad\u{2}key"));
        assert!(!valid_client_tag_key("+")); // empty
        assert!(!valid_client_tag_key("noplus"));
    }

    /// An adversarial alphabet: one nick-legal letter, the prefix separators,
    /// whitespace, the three injection bytes, a backslash, a bracket, a digit, a
    /// control char, and a multi-byte character. Every function's *output*
    /// contract is checked against every string of length 0..=3 over it — small
    /// enough to be exhaustive, wide enough to hit each per-character branch and
    /// its boundaries.
    const ALPHABET: &[char] = &[
        'a', '@', '!', ' ', '\r', '\n', '\0', '\\', '[', '1', '\u{2}', '\u{e9}',
    ];

    fn each_input(mut check: impl FnMut(&str)) {
        let n = ALPHABET.len();
        for len in 0..=3usize {
            let total = n.pow(len as u32);
            for mut code in 0..total {
                let mut s = String::new();
                for _ in 0..len {
                    s.push(ALPHABET[code % n]);
                    code /= n;
                }
                check(&s);
            }
        }
    }

    #[test]
    fn username_is_prefix_safe_or_rejected() {
        each_input(|raw| {
            let Some(out) = username(raw, 8) else {
                return;
            };
            assert!(out.len() <= 8, "username over budget: {out:?}");
            for c in out.chars() {
                assert!(
                    !matches!(c, '!' | '@' | ' ') && !c.is_control(),
                    "username kept an unsafe char {c:?} from {raw:?}"
                );
            }
        });
    }

    #[test]
    fn account_name_is_nick_charset_or_rejected() {
        each_input(|raw| {
            let Some(out) = account_name(raw) else {
                return;
            };
            assert!(out.chars().count() <= 32, "account_name too long: {out:?}");
            for c in out.chars() {
                assert!(
                    c.is_ascii_alphanumeric()
                        || matches!(
                            c,
                            '-' | '_' | '.' | '[' | ']' | '{' | '}' | '\\' | '|' | '^' | '`'
                        ),
                    "account_name kept a non-nick char {c:?} from {raw:?}"
                );
            }
        });
    }

    #[test]
    fn account_name_rejects_an_empty_sanitized_value() {
        assert_eq!(account_name(" @!\r\n"), None);
        assert_eq!(account_name("valid_name"), Some("valid_name".to_string()));
    }

    #[test]
    fn upstream_line_output_has_no_injection_bytes() {
        each_input(|raw| {
            let out = upstream_line(raw.to_string());
            assert!(
                !out.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)),
                "upstream_line left an injection byte in {out:?} from {raw:?}"
            );
        });
    }

    #[test]
    fn valid_client_tag_key_accepts_only_spec_keys() {
        each_input(|raw| {
            if valid_client_tag_key(raw) {
                let rest = raw.strip_prefix('+').expect("accepted key starts with +");
                assert!(!rest.is_empty());
                assert!(
                    rest.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'/')),
                    "accepted a malformed tag key {raw:?}"
                );
            }
        });
    }

    #[test]
    #[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
    fn nick_token_output_is_prefix_safe() {
        each_input(|raw| {
            let out = nick_token(raw);
            assert!(!out.is_empty(), "nick_token empty for {raw:?}");
            assert!(out.chars().count() <= 30, "nick_token too long: {out:?}");
            for c in out.chars() {
                assert!(
                    c.is_ascii_alphanumeric()
                        || matches!(
                            c,
                            '[' | ']' | '\\' | '`' | '_' | '^' | '{' | '|' | '}' | '-'
                        ),
                    "nick_token kept a non-nick char {c:?} from {raw:?}"
                );
                assert!(
                    !matches!(c, '!' | '@' | ':' | ' ' | '\r' | '\n' | '\0'),
                    "nick_token kept a prefix-breaking char {c:?} from {raw:?}"
                );
            }
        });
    }

    #[test]
    fn upstream_line_neutralizes_injection_bytes() {
        assert_eq!(upstream_line("a\rb\nc\0d".into()), "a b c d");
        let clean = "x y z".to_string();
        assert_eq!(upstream_line(clean.clone()), clean);
    }

    #[test]
    fn upstream_line_fits_one_irc_frame_on_a_character_boundary() {
        let safe = upstream_line("𝄞".repeat(200));
        assert!(safe.len() <= e6irc_proto::message::MAX_LINE_LEN - 2);
        assert!(std::str::from_utf8(safe.as_bytes()).is_ok());
    }

    #[test]
    fn valid_client_tag_key_enforces_spec_and_length() {
        // Legit client-only keys.
        assert!(valid_client_tag_key("+typing"));
        assert!(valid_client_tag_key("+draft/react"));
        assert!(valid_client_tag_key("+example.com/reaction"));
        // Not client-only (no `+`), empty, malformed structure.
        assert!(!valid_client_tag_key("typing")); // no +
        assert!(!valid_client_tag_key("+")); // empty
        assert!(!valid_client_tag_key("+/name")); // empty vendor (leading /)
        assert!(!valid_client_tag_key("+vendor/")); // empty name (trailing /)
        assert!(!valid_client_tag_key("+a/b/c")); // multiple /
        assert!(!valid_client_tag_key("+foo.bar")); // `.` only allowed in vendor
        // Length cap — a key at the cap is fine; one over it is dropped, not
        // relayed to everyone.
        assert!(valid_client_tag_key(&format!(
            "+{}",
            "a".repeat(MAX_TAG_KEY_LEN)
        )));
        assert!(!valid_client_tag_key(&format!(
            "+{}",
            "a".repeat(MAX_TAG_KEY_LEN + 1)
        )));
    }

    #[test]
    fn valid_channel_name_rejects_line_and_param_breakers() {
        assert!(valid_channel_name("#room"));
        // Space/comma/BEL/colon (the original set).
        for bad in ["#a b", "#a,b", "#a\x07b", "#a:b"] {
            assert!(!valid_channel_name(bad), "{bad:?} must be rejected");
        }
        // CR/LF/NUL — a bridge name that never passes Message::parse. `#foo\nEVIL`
        // would flatten to the `#foo EVIL` param forge without this.
        for bad in ["#foo\nEVIL", "#foo\rEVIL", "#foo\0EVIL"] {
            assert!(
                !valid_channel_name(bad),
                "{bad:?} must be rejected (CR/LF/NUL)"
            );
        }
        assert!(!valid_channel_name("#")); // just the sigil
        assert!(!valid_channel_name("room")); // no #
    }
}
