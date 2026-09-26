//! IRC message parsing and serialization.
//!
//! Grammar per the Modern IRC client protocol
//! (https://modern.ircdocs.horse/#client-to-server-protocol-structure)
//! with IRCv3 message tags
//! (https://ircv3.net/specs/extensions/message-tags).
//!
//! Parsing is zero-copy: a `Message` borrows from the input line. Tag
//! values are the only place that may allocate, and only when the raw
//! value actually contains escape sequences.

use std::borrow::Cow;

/// Maximum length of the traditional message part (command + params),
/// including the trailing CRLF.
pub const MAX_LINE_LEN: usize = 512;
/// Maximum bytes of the tags part a server may send to a client,
/// including the leading `@` and trailing space.
pub const MAX_SERVER_TAGS_LEN: usize = 8191;
/// Maximum bytes of the tags part a client may send to a server.
pub const MAX_CLIENT_TAGS_LEN: usize = 4096;

/// Maximum bytes of one line a server accepts from a client, *excluding* the
/// CRLF: the client tag budget plus the traditional message part minus its
/// 2-byte CRLF. This is the single source of truth for the cap the framing
/// [`crate::framing::LineBuffer`] enforces on inbound client lines.
pub const MAX_CLIENT_FRAME_LEN: usize = MAX_CLIENT_TAGS_LEN + MAX_LINE_LEN - 2;
/// The same cap for a line a client accepts from a server, which may carry the
/// larger server tag budget (server-time, msgid, account, batch, …).
pub const MAX_SERVER_FRAME_LEN: usize = MAX_SERVER_TAGS_LEN + MAX_LINE_LEN - 2;

fn frame_fits(line: &[u8], tags_budget: usize) -> bool {
    let body_budget = MAX_LINE_LEN - 2;
    if !line.starts_with(b"@") {
        return line.len() <= body_budget;
    }
    let Some(space) = line.iter().position(|byte| *byte == b' ') else {
        // Syntactically malformed tag-only input is left for the parser to
        // classify, but it still cannot consume more than the tag allowance.
        return line.len() <= tags_budget;
    };
    let tags_len = space + 1;
    tags_len <= tags_budget && line.len() - tags_len <= body_budget
}

/// Whether one CRLF-stripped client→server line fits both independent IRC
/// budgets. Checking only their sum lets an untagged message borrow the whole
/// tag allowance and exceed the traditional 512-byte line limit.
pub fn client_frame_fits(line: &[u8]) -> bool {
    frame_fits(line, MAX_CLIENT_TAGS_LEN)
}

/// Whether one CRLF-stripped server→client line fits both independent IRC
/// budgets, including the larger server message-tag allowance.
pub fn server_frame_fits(line: &[u8]) -> bool {
    frame_fits(line, MAX_SERVER_TAGS_LEN)
}

/// Whether a value is a usable IRCv3 message identifier. Message IDs are
/// required values and are later reused as command parameters, so a leading
/// `:` or wire whitespace would change their meaning outside the tag section.
pub fn valid_message_id(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with(':')
        && !value
            .bytes()
            .any(|byte| matches!(byte, b' ' | b'\r' | b'\n'))
}

/// The largest byte index `≤ index` that lies on a UTF-8 character boundary
/// (both ends of the string count). Clamps to `s.len()` when `index` is past
/// the end.
///
/// This is the one primitive under every "cut a string to fit a byte budget"
/// site in the codebase: length-capping a topic, a kick reason, a composer
/// line, a bridged message. Slicing a `str` at a byte index that falls inside a
/// multi-byte character panics, and that panic — reachable from remote input
/// wherever the budget meets non-ASCII text — has recurred here often enough to
/// be worth one shared, tested function instead of a hand-rolled boundary walk
/// at each site. Mirrors the signature of the unstable `str::floor_char_boundary`
/// so it can be replaced by the standard method if that stabilizes.
pub fn floor_char_boundary(s: &str, index: usize) -> usize {
    if index >= s.len() {
        return s.len();
    }
    let mut i = index;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// `s` truncated to at most `max_bytes`, never through a character.
pub fn truncate_on_char_boundary(s: &str, max_bytes: usize) -> &str {
    &s[..floor_char_boundary(s, max_bytes)]
}

/// Decode one CRLF-stripped server→client line for relay, never turning a
/// line that fits the wire budgets *as bytes* into one that does not fit *as
/// text*.
///
/// IRC bodies are arbitrary bytes, and a relay cannot know which legacy
/// encoding a sender used (Latin-1, CP1252, Shift-JIS, KOI8-R are all routine),
/// so every invalid byte becomes U+FFFD: guessing one code page would render
/// the others as plausible-looking wrong text, where U+FFFD marks the loss
/// honestly. U+FFFD is three bytes, so a line of high bytes can triple in
/// size. Checking the budget on the bytes and then decoding used to hand
/// downstream code a 600-byte text line from a 230-byte frame, which the
/// bouncer then replaced whole with a rejection notice — a member of any
/// channel could blank every line they sent that way. So when decoding
/// overflows a budget the text is fitted here, on character boundaries:
///
/// - the tag section drops every tag that carries U+FFFD (the tags that grew;
///   what remains is byte-for-byte a subset of what fitted, so it fits too),
///   and is dropped whole if no tag is left;
/// - the traditional part is cut to [`MAX_LINE_LEN`] − 2 bytes, like any
///   over-long trailing.
///
/// A line whose *bytes* already exceed a budget is returned decoded but
/// unfitted: that line is the caller's to reject, loudly, as too long.
pub fn decode_server_line(line: &[u8]) -> Cow<'_, str> {
    let text = String::from_utf8_lossy(line);
    if !server_frame_fits(line) || server_frame_fits(text.as_bytes()) {
        return text;
    }
    let body_budget = MAX_LINE_LEN - 2;
    let Some(rest) = text.strip_prefix('@') else {
        return Cow::Owned(truncate_on_char_boundary(&text, body_budget).to_owned());
    };
    let Some((tags, body)) = rest.split_once(' ') else {
        // A tag-only (malformed) line: only the tag allowance bounds it.
        return Cow::Owned(truncate_on_char_boundary(&text, MAX_SERVER_TAGS_LEN).to_owned());
    };
    let mut fitted = String::with_capacity(line.len());
    let tags_len = tags.len() + 2; // the `@` and the separating space
    if tags_len <= MAX_SERVER_TAGS_LEN {
        fitted.push('@');
        fitted.push_str(tags);
        fitted.push(' ');
    } else {
        let kept: Vec<&str> = tags
            .split(';')
            .filter(|tag| !tag.contains(char::REPLACEMENT_CHARACTER))
            .collect();
        if !kept.is_empty() {
            fitted.push('@');
            fitted.push_str(&kept.join(";"));
            fitted.push(' ');
        }
    }
    fitted.push_str(truncate_on_char_boundary(body, body_budget));
    Cow::Owned(fitted)
}

/// A parameter that can stand in a *middle* position of an outbound line:
/// non-empty, not `:`-leading, and free of space, CR, LF and NUL.
///
/// Replies that attribute an error echo the offending client token (an
/// unknown command, a bad CAP subcommand, a rejected channel) as a middle
/// parameter. A parsed parameter can break every one of those rules — the last
/// one may arrive in trailing form (`NICK :a b`, `JOIN ::x`) — and an echo that
/// breaks one splits or shifts the reply's parameters (`432 * a b :…`), while
/// one of unbounded length pushes the reply past the wire limit, where the
/// recipient's framing discards the very line explaining the error. The only
/// constructor, [`MiddleParam::echo`], renders an unframeable token as the
/// conventional `*` placeholder and clips the rest to
/// [`MiddleParam::ECHO_MAX`] bytes, so a line builder that takes a
/// `MiddleParam` cannot be handed raw client text. The core and the bouncer's
/// attach listener share it, so their echo rules cannot drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MiddleParam<'a>(&'a str);

impl<'a> MiddleParam<'a> {
    /// The longest echo: identifies any token, and leaves every reply shape
    /// room for its other, server-bounded parameters.
    pub const ECHO_MAX: usize = 64;

    /// `token`, or `*` when it cannot stand as a middle parameter, clipped to
    /// [`Self::ECHO_MAX`] bytes on a character boundary.
    pub fn echo(token: &'a str) -> Self {
        let unframeable = token.is_empty()
            || token.starts_with(':')
            || token
                .bytes()
                .any(|byte| matches!(byte, b' ' | b'\r' | b'\n' | 0));
        if unframeable {
            return Self("*");
        }
        Self(truncate_on_char_boundary(token, Self::ECHO_MAX))
    }

    pub fn as_str(self) -> &'a str {
        self.0
    }
}

impl std::fmt::Display for MiddleParam<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<'a> {
    pub tags: Vec<Tag<'a>>,
    pub source: Option<Source<'a>>,
    /// Verbatim command as received, e.g. `PRIVMSG`, `privmsg`, or `001`.
    pub command: &'a str,
    pub params: Vec<&'a str>,
    /// Whether the last parameter carried the `:` trailing marker on the
    /// wire, even where it was not strictly required. Commands whose last
    /// argument is optional free text (`KLINE`/`DLINE`/`XLINE` reasons) key
    /// on it.
    pub has_trailing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag<'a> {
    /// Verbatim key, including any `+` client-only prefix and vendor part.
    pub key: &'a str,
    /// Unescaped value. `None` for a valueless tag (`@a`); per spec a
    /// missing value and an empty value (`@a=`) are semantically equal.
    pub value: Option<Cow<'a, str>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source<'a> {
    /// Nick, or server name for server sources.
    pub name: &'a str,
    pub user: Option<&'a str>,
    pub host: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Empty input or only whitespace.
    Empty,
    /// CR, LF, or NUL inside the line (caller must split lines first).
    IllegalByte,
    /// `@` or `:` section present but the line ends before a command.
    Truncated,
    /// Malformed tags section (empty section, empty key).
    BadTag,
    /// Empty source after `:`.
    BadSource,
    /// Command is not letters-only or a 3-digit numeric.
    BadCommand,
}

fn valid_command(command: &str) -> bool {
    let bytes = command.as_bytes();
    match bytes {
        [] => false,
        _ if bytes.iter().all(u8::is_ascii_alphabetic) => true,
        [_, _, _] if bytes.iter().all(u8::is_ascii_digit) => true,
        // Lenient: a word-ish token containing at least one letter
        // parses; the dispatcher answers ERR_UNKNOWNCOMMAND for
        // anything it doesn't implement. All-digit tokens must be a
        // 3-digit numeric (handled above); other digit runs are invalid.
        _ => {
            bytes.iter().any(u8::is_ascii_alphabetic)
                && bytes
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        }
    }
}

fn contains_illegal_byte(s: &str) -> bool {
    s.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0))
}

impl<'a> Message<'a> {
    /// Parse one line, without its CRLF terminator.
    pub fn parse(line: &'a str) -> Result<Self, ParseError> {
        if contains_illegal_byte(line) {
            return Err(ParseError::IllegalByte);
        }
        let mut rest = line;

        let mut tags = Vec::new();
        if let Some(after_at) = rest.strip_prefix('@') {
            let (raw_tags, after) = after_at.split_once(' ').ok_or(ParseError::Truncated)?;
            tags = parse_tag_section(raw_tags)?;
            rest = after;
        }

        rest = rest.trim_start_matches(' ');
        let mut source = None;
        if let Some(after_colon) = rest.strip_prefix(':') {
            let (raw_source, after) = after_colon.split_once(' ').ok_or(ParseError::Truncated)?;
            if raw_source.is_empty() {
                return Err(ParseError::BadSource);
            }
            let (main, host) = match raw_source.split_once('@') {
                Some((m, h)) => (m, Some(h)),
                None => (raw_source, None),
            };
            let (name, user) = match main.split_once('!') {
                Some((n, u)) => (n, Some(u)),
                None => (main, None),
            };
            if name.is_empty() {
                return Err(ParseError::BadSource);
            }
            source = Some(Source { name, user, host });
            rest = after.trim_start_matches(' ');
        }

        if rest.is_empty() {
            // Distinguish "nothing at all" from "tags/source then nothing".
            return if tags.is_empty() && source.is_none() {
                Err(ParseError::Empty)
            } else {
                Err(ParseError::Truncated)
            };
        }

        let (command, mut rest) = match rest.split_once(' ') {
            Some((c, r)) => (c, r),
            None => (rest, ""),
        };
        if !valid_command(command) {
            return Err(ParseError::BadCommand);
        }

        let mut params = Vec::new();
        let mut has_trailing = false;
        loop {
            rest = rest.trim_start_matches(' ');
            if rest.is_empty() {
                break;
            }
            if let Some(trailing) = rest.strip_prefix(':') {
                params.push(trailing);
                has_trailing = true;
                break;
            }
            match rest.split_once(' ') {
                Some((param, r)) => {
                    params.push(param);
                    rest = r;
                }
                None => {
                    params.push(rest);
                    break;
                }
            }
        }

        Ok(Self {
            tags,
            source,
            command,
            params,
            has_trailing,
        })
    }

    /// The last tag with this key (per spec, last occurrence wins).
    pub fn tag(&self, key: &str) -> Option<&Tag<'a>> {
        self.tags.iter().rev().find(|t| t.key == key)
    }
}

/// The tags of a tag section (the text between the leading `@` and the first
/// space), in wire order.
fn parse_tag_section(raw_tags: &str) -> Result<Vec<Tag<'_>>, ParseError> {
    raw_tags
        .split(';')
        .map(|item| {
            let (key, value) = match item.split_once('=') {
                Some((k, v)) => (k, Some(unescape_tag_value(v))),
                None => (item, None),
            };
            if key.is_empty() {
                Err(ParseError::BadTag)
            } else {
                Ok(Tag { key, value })
            }
        })
        .collect()
}

/// The unescaped value of tag `key` on a line that is refused before it can be
/// parsed whole — not UTF-8, over the length limits, or malformed after its
/// tag section — read from the tag section alone, exactly as
/// [`Message::tag`] would read it (the last occurrence wins). A server answers
/// such a line under its `label`, which the client is waiting on. `None` when
/// the line has no well-formed tag section, or the tag no value.
pub fn tag_section_value(line: &[u8], key: &str) -> Option<String> {
    let rest = line.strip_prefix(b"@")?;
    let end = rest.iter().position(|&b| b == b' ')?;
    let section = std::str::from_utf8(&rest[..end]).ok()?;
    if contains_illegal_byte(section) {
        return None;
    }
    let tags = parse_tag_section(section).ok()?;
    tags.into_iter()
        .rev()
        .find(|tag| tag.key == key)?
        .value
        .map(Cow::into_owned)
}

/// Unescape a raw tag value per the message-tags spec: `\:` `\s` `\\`
/// `\r` `\n`; an invalid escape drops the backslash; a lone trailing
/// backslash is dropped.
pub fn unescape_tag_value(raw: &str) -> Cow<'_, str> {
    if !raw.contains('\\') {
        return Cow::Borrowed(raw);
    }
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some(':') => out.push(';'),
            Some('s') => out.push(' '),
            Some('\\') => out.push('\\'),
            Some('r') => out.push('\r'),
            Some('n') => out.push('\n'),
            Some(other) => out.push(other),
            None => {}
        }
    }
    Cow::Owned(out)
}

/// Escape a tag value for the wire. The output is wire-safe **by
/// construction**: `;`/space/`\`/CR/LF get their `\`-escapes, and a NUL — which
/// has no tag escape and cannot legally appear in a message at all — is dropped
/// rather than passed through. This is the single choke point for tag-value wire
/// safety: every tagged line this system writes goes through it, so none can
/// put a raw NUL on the wire and truncate the line. Today no caller can supply a NUL (relayed values
/// come from `parse`, which forbids it; account names are server-validated), so
/// the NUL branch is defense in depth.
pub fn escape_tag_value(value: &str) -> Cow<'_, str> {
    if !value
        .bytes()
        .any(|b| matches!(b, b';' | b' ' | b'\\' | b'\r' | b'\n' | 0))
    {
        return Cow::Borrowed(value);
    }
    let mut out = String::with_capacity(value.len() + 4);
    for c in value.chars() {
        match c {
            ';' => out.push_str("\\:"),
            ' ' => out.push_str("\\s"),
            '\\' => out.push_str("\\\\"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            // No tag escape exists for NUL and it cannot ride a wire line; drop
            // it so the escaper's output is always wire-safe.
            '\0' => {}
            _ => out.push(c),
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_char_boundary_clamps_and_never_splits() {
        // '☃' is three bytes: indexes 1 and 2 fall inside it.
        let s = "a☃b";
        assert_eq!(floor_char_boundary(s, 0), 0);
        assert_eq!(floor_char_boundary(s, 1), 1); // between 'a' and '☃'
        assert_eq!(floor_char_boundary(s, 2), 1); // inside '☃' -> back to 1
        assert_eq!(floor_char_boundary(s, 3), 1); // inside '☃' -> back to 1
        assert_eq!(floor_char_boundary(s, 4), 4); // between '☃' and 'b'
        // Past the end clamps to len rather than panicking.
        assert_eq!(floor_char_boundary(s, 99), s.len());
        assert_eq!(floor_char_boundary("", 5), 0);
    }

    #[test]
    fn truncate_on_char_boundary_is_a_valid_slice_for_every_cut() {
        // A budget landing inside every position of a multi-byte string still
        // yields a valid prefix — the property every call site depends on.
        let s = "αβγδε"; // five 2-byte characters
        for max in 0..=s.len() + 2 {
            let out = truncate_on_char_boundary(s, max);
            assert!(s.starts_with(out));
            assert!(out.len() <= max.min(s.len()));
        }
    }

    fn msg(line: &str) -> Message<'_> {
        Message::parse(line).expect(line)
    }

    #[test]
    fn frame_budgets_are_independent_and_directional() {
        assert!(server_frame_fits(&vec![b'x'; MAX_LINE_LEN - 2]));
        assert!(!server_frame_fits(&vec![b'x'; MAX_LINE_LEN - 1]));

        let server_tags = format!("@{} PING", "a".repeat(MAX_SERVER_TAGS_LEN - 2));
        assert!(server_frame_fits(server_tags.as_bytes()));
        assert!(!client_frame_fits(server_tags.as_bytes()));

        let client_tags = format!("@{} PING", "a".repeat(MAX_CLIENT_TAGS_LEN - 2));
        assert!(client_frame_fits(client_tags.as_bytes()));
        let oversized_body = format!("@a {}", "x".repeat(MAX_LINE_LEN - 1));
        assert!(!server_frame_fits(oversized_body.as_bytes()));
        assert!(!client_frame_fits(oversized_body.as_bytes()));
    }

    #[test]
    fn parses_command_and_params() {
        let m = msg("PRIVMSG #chan :hello world");
        assert!(m.tags.is_empty());
        assert!(m.source.is_none());
        assert_eq!(m.command, "PRIVMSG");
        assert_eq!(m.params, vec!["#chan", "hello world"]);
    }

    #[test]
    fn parses_without_trailing() {
        let m = msg("JOIN #a,#b somekey");
        assert_eq!(m.params, vec!["#a,#b", "somekey"]);
    }

    #[test]
    fn parses_command_only() {
        let m = msg("QUIT");
        assert_eq!(m.command, "QUIT");
        assert!(m.params.is_empty());
    }

    #[test]
    fn parses_user_source() {
        let m = msg(":nick!user@example.host PRIVMSG #c :hi");
        let s = m.source.unwrap();
        assert_eq!(s.name, "nick");
        assert_eq!(s.user, Some("user"));
        assert_eq!(s.host, Some("example.host"));
    }

    #[test]
    fn parses_server_source_and_numeric() {
        let m = msg(":irc.example.com 001 nick :Welcome to IRC");
        let s = m.source.unwrap();
        assert_eq!(s.name, "irc.example.com");
        assert_eq!(s.user, None);
        assert_eq!(s.host, None);
        assert_eq!(m.command, "001");
        assert_eq!(m.params, vec!["nick", "Welcome to IRC"]);
    }

    #[test]
    fn parses_tags() {
        let m = msg("@time=2021-01-01T00:00:00.000Z;msgid=abc :n!u@h PRIVMSG #c :hi");
        assert_eq!(m.tags.len(), 2);
        assert_eq!(
            m.tag("time").unwrap().value.as_deref(),
            Some("2021-01-01T00:00:00.000Z")
        );
        assert_eq!(m.tag("msgid").unwrap().value.as_deref(), Some("abc"));
        assert_eq!(m.command, "PRIVMSG");
    }

    #[test]
    fn parses_valueless_and_empty_tags() {
        let m = msg("@a;b=;+c=v CAP LS");
        assert_eq!(m.tag("a").unwrap().value, None);
        assert_eq!(m.tag("b").unwrap().value.as_deref(), Some(""));
        assert_eq!(m.tag("+c").unwrap().value.as_deref(), Some("v"));
    }

    #[test]
    fn duplicate_tag_key_last_wins() {
        let m = msg("@k=1;k=2 PING");
        assert_eq!(m.tag("k").unwrap().value.as_deref(), Some("2"));
    }

    #[test]
    fn tag_value_unescaping() {
        let m = msg(r"@k=a\:b\s\\c PING");
        assert_eq!(m.tag("k").unwrap().value.as_deref(), Some(r"a;b \c"));
    }

    #[test]
    fn unescape_rules() {
        assert_eq!(unescape_tag_value(r"a\:b"), "a;b");
        assert_eq!(unescape_tag_value(r"\s\r\n\\"), " \r\n\\");
        // invalid escape drops the backslash
        assert_eq!(unescape_tag_value(r"\x"), "x");
        // lone trailing backslash dropped
        assert_eq!(unescape_tag_value("a\\"), "a");
        // borrowed when nothing to do
        assert!(matches!(
            unescape_tag_value("plain"),
            Cow::Borrowed("plain")
        ));
    }

    #[test]
    fn escape_roundtrip() {
        let value = "a;b c\\d\r\n";
        let escaped = escape_tag_value(value);
        assert_eq!(escaped, r"a\:b\sc\\d\r\n");
        assert_eq!(unescape_tag_value(&escaped), value);
        assert!(matches!(escape_tag_value("plain"), Cow::Borrowed("plain")));
    }

    #[test]
    fn escape_drops_nul_so_output_is_wire_safe() {
        // NUL has no tag escape and cannot ride a wire line; the escaper — the
        // single tag-value wire-safety choke point — drops it rather than
        // emitting a raw NUL that would truncate the line. A NUL-only value must
        // take the neutralizing slow path, not the borrow fast path.
        assert_eq!(escape_tag_value("a\0b"), "ab");
        assert_eq!(escape_tag_value("\0"), "");
        assert!(!escape_tag_value("x\0;y").contains('\0'));
    }

    #[test]
    fn tolerates_multiple_spaces() {
        let m = msg("PRIVMSG   #c    :hi  there");
        assert_eq!(m.params, vec!["#c", "hi  there"]);
    }

    #[test]
    fn empty_trailing_is_empty_param() {
        let m = msg("TOPIC #c :");
        assert_eq!(m.params, vec!["#c", ""]);
    }

    #[test]
    fn colon_inside_middle_param_is_literal() {
        let m = msg("MODE #c +b nick!*@host:port");
        assert_eq!(m.params, vec!["#c", "+b", "nick!*@host:port"]);
    }

    #[test]
    fn parse_errors() {
        assert_eq!(Message::parse("").unwrap_err(), ParseError::Empty);
        assert_eq!(Message::parse("   ").unwrap_err(), ParseError::Empty);
        assert_eq!(
            Message::parse("PING\r\n").unwrap_err(),
            ParseError::IllegalByte
        );
        assert_eq!(
            Message::parse("PI\0NG").unwrap_err(),
            ParseError::IllegalByte
        );
        assert_eq!(
            Message::parse("@only-tags").unwrap_err(),
            ParseError::Truncated
        );
        assert_eq!(
            Message::parse(":only-source").unwrap_err(),
            ParseError::Truncated
        );
        assert_eq!(Message::parse("@ PING").unwrap_err(), ParseError::BadTag);
        assert_eq!(Message::parse("@=v PING").unwrap_err(), ParseError::BadTag);
        assert_eq!(
            Message::parse("@a;;b PING").unwrap_err(),
            ParseError::BadTag
        );
        assert_eq!(Message::parse(": PING").unwrap_err(), ParseError::BadSource);
        assert_eq!(
            Message::parse("PRIV+MSG x").unwrap_err(),
            ParseError::BadCommand
        );
        assert_eq!(Message::parse("12 x").unwrap_err(), ParseError::BadCommand);
        assert_eq!(
            Message::parse("1234 x").unwrap_err(),
            ParseError::BadCommand
        );
        // "12a" now parses leniently (has a letter) → dispatch would 421.
        assert_eq!(Message::parse("12a x").unwrap().command, "12a");
    }

    #[test]
    fn message_ids_are_nonempty_wire_parameters() {
        for valid in ["opaque", "Mixed-._/value"] {
            assert!(valid_message_id(valid), "{valid}");
        }
        for invalid in ["", ":trailing", "has space", "has\rreturn", "has\nline"] {
            assert!(!valid_message_id(invalid), "{invalid:?}");
        }
    }

    /// A line that fits as bytes still fits once its invalid bytes are
    /// decoded: each one becomes three-byte U+FFFD, and the relay used to
    /// reject the tripled line whole.
    #[test]
    fn decoding_never_turns_a_fitting_frame_into_an_overlong_line() {
        let mut raw = b":alice!u@h PRIVMSG #c :".to_vec();
        raw.extend(std::iter::repeat_n(0xE9, 200));
        assert!(server_frame_fits(&raw));
        let text = decode_server_line(&raw);
        assert!(server_frame_fits(text.as_bytes()), "{} bytes", text.len());
        assert!(text.starts_with(":alice!u@h PRIVMSG #c :\u{FFFD}"));
        assert!(Message::parse(&text).is_ok());

        // An over-grown tag section loses the tags that grew, keeps the rest.
        let mut tagged = b"@time=2026-01-01T00:00:00.000Z;+x=".to_vec();
        tagged.extend(std::iter::repeat_n(0xE9, 5000));
        tagged.extend_from_slice(b" :a PRIVMSG #c :hi");
        assert!(server_frame_fits(&tagged));
        let text = decode_server_line(&tagged);
        assert!(server_frame_fits(text.as_bytes()));
        assert_eq!(text, "@time=2026-01-01T00:00:00.000Z :a PRIVMSG #c :hi");

        // Valid text is untouched, and a frame already over budget is left
        // for the caller to reject.
        assert!(matches!(
            decode_server_line(b":a PRIVMSG #c :hi"),
            Cow::Borrowed(":a PRIVMSG #c :hi")
        ));
        let overlong = vec![b'x'; MAX_LINE_LEN];
        assert_eq!(decode_server_line(&overlong).len(), MAX_LINE_LEN);
    }

    #[test]
    fn a_middle_echo_is_always_one_bounded_parameter() {
        for token in ["", ":x", "a b", ":", "a\rb", "a\nb", "a\0b"] {
            assert_eq!(MiddleParam::echo(token).as_str(), "*", "{token:?}");
        }
        assert_eq!(MiddleParam::echo("nick").as_str(), "nick");
        assert_eq!(
            MiddleParam::echo(&"é".repeat(40)).as_str().len(),
            MiddleParam::ECHO_MAX
        );
        assert_eq!(MiddleParam::echo(&"x".repeat(100)).to_string().len(), 64);
    }
}
