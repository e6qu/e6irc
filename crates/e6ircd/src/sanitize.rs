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
//! not, so [`upstream_line`] neutralizes those first. Generated-field length
//! bounding and wire-limit fitting are a separate concern and live with delivery
//! (`truncate_chars`, `fit_trailing`, `fit_relayed_text`) over
//! `e6irc_proto::message::truncate_on_char_boundary`.

/// Validate a username for the `nick!user@host` source prefix, cut to at most
/// `max_len` bytes on a char boundary.
///
/// Length and content are different kinds of fault. An over-long username is
/// truncated, never refused: Modern IRC says a server *MUST* truncate it, and
/// clients (and `USER $USER …` scripts) send whatever the local login is —
/// refusing would block registration outright. A prefix-breaking character
/// anywhere in the input (`!`, `@`, space, a control) is still refused, even
/// past the cut: the client asked for a name the server cannot represent.
pub(crate) fn username(raw: &str, max_len: usize) -> Option<String> {
    let valid = raw
        .chars()
        .all(|c| !matches!(c, '!' | '@' | ' ') && !c.is_control());
    let kept = e6irc_proto::message::truncate_on_char_boundary(raw, max_len);
    (valid && !kept.is_empty()).then(|| kept.to_string())
}

/// A host or ban mask spelled so it stands as one middle parameter, in
/// Solanum's spellings: a leading `:` (an IPv6 address such as `::1`) gets a
/// `0` in front — `0::1`, the same address — so it cannot open the trailing
/// parameter early, and a space (an X-line mask may hold several) is written
/// `\s`, which is how X-line masks spell a space anyway. The operator's
/// listing (STATS K/D/X) and a session's shown host both go through it, so
/// neither can be rendered as the numeric funnel's `*` placeholder or split
/// into two parameters.
pub(crate) fn mask_middle(mask: &str) -> std::borrow::Cow<'_, str> {
    if !mask.starts_with(':') && !mask.contains(' ') {
        return std::borrow::Cow::Borrowed(mask);
    }
    let zero = if mask.starts_with(':') { "0" } else { "" };
    std::borrow::Cow::Owned(format!("{zero}{}", mask.replace(' ', "\\s")))
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

/// The text of a CTCP `ACTION` (`/me`), or `None` when `text` is not one.
///
/// The tag ends at the first space or the closing `\x01`, so a prefix test
/// (`starts_with("\x01ACTION")`) would wrongly accept `\x01ACTIONX\x01` or
/// `\x01ACTIONVERSION\x01` — crafted CTCP that would then slip through a `+C`
/// (no-CTCP) channel, or reach a bridge as a `/me`. The closing `\x01` is
/// optional, as it is for every CTCP. One predicate, read by the core's `+C`
/// check and by the bridges' outbound translation, so the two cannot disagree
/// about what an ACTION is.
pub(crate) fn ctcp_action(text: &str) -> Option<&str> {
    let rest = text.strip_prefix("\u{1}ACTION")?;
    let rest = match rest.strip_prefix(' ') {
        Some(body) => body,
        None if rest.is_empty() || rest.starts_with('\u{1}') => rest,
        None => return None,
    };
    Some(rest.strip_suffix('\u{1}').unwrap_or(rest))
}

/// What an echo shows in place of a [`sensitive_service_command`].
pub(crate) const SENSITIVE_SERVICE_COMMAND_REDACTED: &str = "[sensitive services command redacted]";

/// Account services an IRC client authenticates to by message: NickServ (and
/// its `NS` alias) as Atheme, Anope and this server run it, QuakeNet's `Q`,
/// Undernet's `X`, and GameSurge's `AuthServ`.
const ACCOUNT_SERVICES: &[&str] = &["NickServ", "NS", "Q", "X", "AuthServ"];

/// Commands to those services that can carry a password, an email address, a
/// reset or recovery token, or a verification code.
const SENSITIVE_SERVICE_COMMANDS: &[&str] = &[
    "REGISTER",
    "IDENTIFY",
    "ID",
    "LOGIN",
    "AUTH",
    "GHOST",
    "RECOVER",
    "REGAIN",
    "RELEASE",
    "SENDPASS",
    "SETPASS",
    "RESETPASS",
    "VERIFY",
    "CONFIRM",
    "DROP",
    "GROUP",
];

/// `SET` settings to those services that carry a secret or a contact address.
const SENSITIVE_SERVICE_SETTINGS: &[&str] = &["PASSWORD", "PASS", "EMAIL", "PUBKEY"];

/// Whether a message to `target` saying `text` is an account-services command
/// that can carry a secret. The one list every echo consults — the bouncer's
/// synthesized and upstream-reflected echoes (which reach the persistent
/// backlog) and the core's echo of a line to its own services — so a command
/// cannot be redacted on one path and replayed verbatim on another. The whole
/// argument string is redacted because service dialects disagree about which
/// position is secret.
pub(crate) fn sensitive_service_command(target: &str, text: &str) -> bool {
    let service = target.split_once('@').map_or(target, |(name, _)| name);
    if !ACCOUNT_SERVICES
        .iter()
        .any(|known| service.eq_ignore_ascii_case(known))
    {
        return false;
    }
    let is_one_of = |word: &str, list: &[&str]| list.iter().any(|w| word.eq_ignore_ascii_case(w));
    let mut words = text.split_whitespace();
    let command = words.next().unwrap_or_default();
    is_one_of(command, SENSITIVE_SERVICE_COMMANDS)
        || (command.eq_ignore_ascii_case("SET")
            && words
                .next()
                .is_some_and(|setting| is_one_of(setting, SENSITIVE_SERVICE_SETTINGS)))
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
    if e6irc_proto::message::server_frame_fits(line.as_bytes()) {
        line
    } else {
        ":e6irc NOTICE * :upstream input rejected: server line exceeds an IRC wire budget"
            .to_string()
    }
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

/// Serialize the unique valid client-only tags from one parsed message.
/// Duplicate keys resolve exactly like [`e6irc_proto::message::Message::tag`]:
/// the last value wins while the first occurrence fixes stable output order.
/// Server-provenance tags such as `time` and `msgid` never cross this boundary.
pub(crate) fn client_tag_string(msg: &e6irc_proto::message::Message<'_>) -> String {
    let mut order: Vec<&str> = Vec::new();
    let mut values: std::collections::HashMap<&str, Option<&str>> =
        std::collections::HashMap::new();
    for tag in msg.tags.iter().filter(|tag| valid_client_tag_key(tag.key)) {
        if !values.contains_key(tag.key) {
            order.push(tag.key);
        }
        values.insert(tag.key, tag.value.as_deref());
    }
    order
        .iter()
        .map(|&key| match values[key] {
            Some(value) => format!("{key}={}", e6irc_proto::message::escape_tag_value(value)),
            None => key.to_string(),
        })
        .collect::<Vec<_>>()
        .join(";")
}

/// Client-only tags that describe a moment rather than a message — a typing
/// indicator — and so never enter history: replayed, they would announce
/// someone typing long after they stopped, and stored as TAGMSGs they would
/// crowd real messages out of the bounded hot ring.
const EPHEMERAL_CLIENT_TAGS: &[&str] = &["+typing", "+draft/typing"];

/// The part of a relayed client tag string ([`client_tag_string`]) that
/// history keeps with the message: every tag but the ephemeral ones. Empty when
/// nothing is left, which for a TAGMSG means there is nothing to store.
pub(crate) fn history_client_tags(relayed: &str) -> String {
    relayed
        .split(';')
        .filter(|tag| {
            let key = tag.split_once('=').map_or(*tag, |(key, _)| key);
            !key.is_empty() && !EPHEMERAL_CLIENT_TAGS.contains(&key)
        })
        .collect::<Vec<_>>()
        .join(";")
}

/// Whether `line` is a TAGMSG that history keeps nothing of (only ephemeral
/// client-only tags, or none): it is told live and never enters a backlog or
/// the stored history — the rule the core's history applies, applied to the
/// bouncer's raw lines.
pub(crate) fn is_ephemeral_tagmsg(line: &str) -> bool {
    e6irc_proto::message::Message::parse(line).is_ok_and(|message| {
        message.command.eq_ignore_ascii_case("TAGMSG")
            && history_client_tags(&client_tag_string(&message)).is_empty()
    })
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

/// A client-facing BNC network selector. The same value appears in config,
/// REST paths, HTML, and the raw attach `nick/network` address, so every ingress
/// admits one bounded, path-safe token language.
pub(crate) fn valid_network_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name != "."
        && name != ".."
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
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
    fn username_over_the_cap_is_truncated_not_refused() {
        assert_eq!(
            username("averyverylongname", 10),
            Some("averyveryl".to_string())
        );
        // Cut on a char boundary: `é` is two bytes and would straddle byte 10.
        assert_eq!(
            username("abcdefghi\u{e9}xyz", 10),
            Some("abcdefghi".to_string())
        );
        // A prefix-breaking char is refused even when it lies past the cut.
        assert_eq!(username("abcdefghijklm@x", 10), None);
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
            let Some(out) = username(raw, 2) else {
                return;
            };
            // A 2-byte budget under 3-char inputs exercises the truncation too.
            assert!(out.len() <= 2, "username over budget: {out:?}");
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
    fn ctcp_action_reads_exactly_the_action_tag() {
        assert_eq!(ctcp_action("\u{1}ACTION waves\u{1}"), Some("waves"));
        assert_eq!(ctcp_action("\u{1}ACTION waves"), Some("waves"));
        assert_eq!(ctcp_action("\u{1}ACTION\u{1}"), Some(""));
        assert_eq!(ctcp_action("\u{1}ACTION"), Some(""));
        assert_eq!(ctcp_action("\u{1}ACTIONX\u{1}"), None);
        assert_eq!(ctcp_action("\u{1}ACTIONVERSION\u{1}"), None);
        assert_eq!(ctcp_action("\u{1}VERSION\u{1}"), None);
        assert_eq!(ctcp_action("ACTION waves"), None);
    }

    #[test]
    fn upstream_line_neutralizes_injection_bytes() {
        assert_eq!(upstream_line("a\rb\nc\0d".into()), "a b c d");
        let clean = "x y z".to_string();
        assert_eq!(upstream_line(clean.clone()), clean);
    }

    #[test]
    fn upstream_line_preserves_server_tags_and_rejects_an_overlong_body_loudly() {
        let tagged = format!("@example={} :srv NOTICE nick :ok", "𝄞".repeat(200));
        assert!(tagged.len() > e6irc_proto::message::MAX_LINE_LEN - 2);
        assert_eq!(upstream_line(tagged.clone()), tagged);

        let rejected = upstream_line("𝄞".repeat(200));
        assert!(rejected.contains("upstream input rejected"));
        assert!(e6irc_proto::message::server_frame_fits(rejected.as_bytes()));
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
