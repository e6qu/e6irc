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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<'a> {
    pub tags: Vec<Tag<'a>>,
    pub source: Option<Source<'a>>,
    /// Verbatim command as received, e.g. `PRIVMSG`, `privmsg`, or `001`.
    pub command: &'a str,
    pub params: Vec<&'a str>,
    /// Whether the last parameter carries the `:` trailing marker even
    /// when not strictly required. `parse` preserves what was on the
    /// wire so parse → serialize is byte-exact; when constructing,
    /// set it to match conventional formatting (e.g. PRIVMSG text).
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializeError {
    BadCommand,
    /// Tag key empty or containing space/`;`/`=`.
    BadTagKey,
    /// Source containing spaces or empty name.
    BadSource,
    /// A non-final parameter that is empty, starts with `:`, or contains
    /// a space; or any parameter containing CR/LF/NUL.
    BadParam,
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
    /// Convenience constructor for a tagless, sourceless message.
    pub fn new(command: &'a str, params: Vec<&'a str>) -> Self {
        Self {
            tags: Vec::new(),
            source: None,
            command,
            params,
            has_trailing: false,
        }
    }

    /// Parse one line, without its CRLF terminator.
    pub fn parse(line: &'a str) -> Result<Self, ParseError> {
        if contains_illegal_byte(line) {
            return Err(ParseError::IllegalByte);
        }
        let mut rest = line;

        let mut tags = Vec::new();
        if let Some(after_at) = rest.strip_prefix('@') {
            let (raw_tags, after) = after_at.split_once(' ').ok_or(ParseError::Truncated)?;
            for item in raw_tags.split(';') {
                let (key, value) = match item.split_once('=') {
                    Some((k, v)) => (k, Some(unescape_tag_value(v))),
                    None => (item, None),
                };
                if key.is_empty() {
                    return Err(ParseError::BadTag);
                }
                tags.push(Tag { key, value });
            }
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

    /// Serialize to a wire line, without CRLF. Validates invariants the
    /// type itself cannot express.
    pub fn to_line(&self) -> Result<String, SerializeError> {
        if !valid_command(self.command) {
            return Err(SerializeError::BadCommand);
        }
        let mut out = String::new();

        if !self.tags.is_empty() {
            out.push('@');
            for (i, tag) in self.tags.iter().enumerate() {
                if tag.key.is_empty()
                    || tag
                        .key
                        .bytes()
                        .any(|b| matches!(b, b' ' | b';' | b'=' | b'\r' | b'\n' | 0))
                {
                    return Err(SerializeError::BadTagKey);
                }
                if i > 0 {
                    out.push(';');
                }
                out.push_str(tag.key);
                if let Some(value) = &tag.value {
                    out.push('=');
                    out.push_str(&escape_tag_value(value));
                }
            }
            out.push(' ');
        }

        if let Some(source) = &self.source {
            let parts = [Some(source.name), source.user, source.host];
            if source.name.is_empty()
                || parts
                    .into_iter()
                    .flatten()
                    .any(|p| p.contains(' ') || contains_illegal_byte(p))
            {
                return Err(SerializeError::BadSource);
            }
            out.push(':');
            out.push_str(source.name);
            if let Some(user) = source.user {
                out.push('!');
                out.push_str(user);
            }
            if let Some(host) = source.host {
                out.push('@');
                out.push_str(host);
            }
            out.push(' ');
        }

        out.push_str(self.command);

        for (i, param) in self.params.iter().enumerate() {
            if contains_illegal_byte(param) {
                return Err(SerializeError::BadParam);
            }
            let last = i == self.params.len() - 1;
            let needs_trailing = param.is_empty() || param.starts_with(':') || param.contains(' ');
            if needs_trailing && !last {
                return Err(SerializeError::BadParam);
            }
            out.push(' ');
            if last && (needs_trailing || self.has_trailing) {
                out.push(':');
            }
            out.push_str(param);
        }

        Ok(out)
    }
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

/// Escape a tag value for the wire.
pub fn escape_tag_value(value: &str) -> Cow<'_, str> {
    if !value
        .bytes()
        .any(|b| matches!(b, b';' | b' ' | b'\\' | b'\r' | b'\n'))
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
            _ => out.push(c),
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(line: &str) -> Message<'_> {
        Message::parse(line).expect(line)
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
    fn serialize_canonical_forms() {
        let m = Message::new("PRIVMSG", vec!["#chan", "hello world"]);
        assert_eq!(m.to_line().unwrap(), "PRIVMSG #chan :hello world");

        // trailing marker required for empty / leading-colon last params
        let m = Message::new("TOPIC", vec!["#c", ""]);
        assert_eq!(m.to_line().unwrap(), "TOPIC #c :");
        let m = Message::new("PRIVMSG", vec!["#c", ":)"]);
        assert_eq!(m.to_line().unwrap(), "PRIVMSG #c ::)");

        // no marker needed for a plain last param
        let m = Message::new("JOIN", vec!["#a"]);
        assert_eq!(m.to_line().unwrap(), "JOIN #a");
    }

    #[test]
    fn serialize_with_source_and_tags() {
        let m = Message {
            tags: vec![
                Tag {
                    key: "time",
                    value: Some("2021-01-01T00:00:00.000Z".into()),
                },
                Tag {
                    key: "k",
                    value: Some("a;b c".into()),
                },
                Tag {
                    key: "flag",
                    value: None,
                },
            ],
            source: Some(Source {
                name: "nick",
                user: Some("u"),
                host: Some("h.example"),
            }),
            command: "PRIVMSG",
            params: vec!["#c", "hi"],
            has_trailing: true,
        };
        assert_eq!(
            m.to_line().unwrap(),
            r"@time=2021-01-01T00:00:00.000Z;k=a\:b\sc;flag :nick!u@h.example PRIVMSG #c :hi"
        );
    }

    #[test]
    fn serialize_errors() {
        assert_eq!(
            Message::new("PRIV MSG", vec![]).to_line().unwrap_err(),
            SerializeError::BadCommand
        );
        // non-final param with a space
        assert_eq!(
            Message::new("X", vec!["a b", "c"]).to_line().unwrap_err(),
            SerializeError::BadParam
        );
        // non-final empty param
        assert_eq!(
            Message::new("X", vec!["", "c"]).to_line().unwrap_err(),
            SerializeError::BadParam
        );
        // CR/LF/NUL never serializable
        assert_eq!(
            Message::new("X", vec!["a\nb"]).to_line().unwrap_err(),
            SerializeError::BadParam
        );
        // bad tag key
        let m = Message {
            tags: vec![Tag {
                key: "a b",
                value: None,
            }],
            ..Message::new("PING", vec![])
        };
        assert_eq!(m.to_line().unwrap_err(), SerializeError::BadTagKey);
        // source with space
        let m = Message {
            source: Some(Source {
                name: "a b",
                user: None,
                host: None,
            }),
            ..Message::new("PING", vec![])
        };
        assert_eq!(m.to_line().unwrap_err(), SerializeError::BadSource);
    }

    #[test]
    fn parse_serialize_roundtrip() {
        for line in [
            "PRIVMSG #chan :hello world",
            "@time=2021-01-01T00:00:00.000Z;msgid=abc :n!u@h PRIVMSG #c :hi",
            ":irc.example.com 001 nick :Welcome to IRC",
            "TOPIC #c :",
            "QUIT",
            "@flag CAP LS 302",
            r"@k=a\:b\sc PING",
        ] {
            let parsed = Message::parse(line).unwrap();
            assert_eq!(parsed.to_line().unwrap(), line, "roundtrip of {line:?}");
        }
    }
}
