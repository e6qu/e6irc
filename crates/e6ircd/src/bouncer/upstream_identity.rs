//! The identity an `irc` driver presents to an upstream, as parsed values.
//!
//! Each of these is interpolated into a registration or `JOIN` line, so a
//! string that merely passed a length check could still change the *shape* of
//! that line: `NICK al ice` carries two parameters, `JOIN 0` leaves every
//! channel, `JOIN #a,#b` joins two. Holding them as
//! types built only by [`std::str::FromStr`] means the configuration file, a
//! stored row, and the API cannot differ in what they admit, and the driver
//! cannot be handed a value that was never checked (DESIGN §2).
//!
//! The grammar is deliberately *structural*, not a network's nickname policy.
//! Upstreams disagree about length and alphabet (Libera allows 16 bytes of
//! ASCII; Ergo allows Unicode), and a nickname one of them dislikes comes back
//! as a loud 432. What is rejected here is what no IRC server could read as a
//! single nickname or channel at all.

use std::fmt;
use std::str::FromStr;

/// Why a configured upstream identity value cannot be put on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamIdentityError {
    field: &'static str,
    reason: &'static str,
}

impl UpstreamIdentityError {
    /// The request/configuration field at fault (`nick`, `username`,
    /// `realname`, `autojoin`), for a form to point at.
    pub const fn field(&self) -> &'static str {
        self.field
    }

    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for UpstreamIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.field, self.reason)
    }
}

impl std::error::Error for UpstreamIdentityError {}

/// A character that would end an IRC parameter, end the line, or be dropped or
/// rewritten by a server: whitespace and every control character.
fn breaks_a_parameter(character: char) -> bool {
    character.is_whitespace() || character.is_control()
}

/// The nickname offered to an upstream in `NICK`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamNick(String);

impl UpstreamNick {
    pub const MAX_BYTES: usize = 64;

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for UpstreamNick {
    type Err = UpstreamIdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let error = |reason| UpstreamIdentityError {
            field: "nick",
            reason,
        };
        let Some(first) = value.chars().next() else {
            return Err(error("is required"));
        };
        if value.len() > Self::MAX_BYTES {
            return Err(error("is limited to 64 bytes"));
        }
        // A leading `:` starts a trailing parameter; the rest are channel,
        // status-message, and server-mask prefixes, which make a nickname
        // indistinguishable from another kind of target.
        if matches!(first, ':' | '#' | '&' | '+' | '!' | '~' | '%' | '@' | '$') {
            return Err(error("must not begin with a channel or prefix character"));
        }
        // `,` separates targets, `*` and `?` are mask wildcards, and `!` and
        // `@` delimit `nick!user@host` -- the prefix the driver itself builds
        // around this value for every synthesized echo.
        if value
            .chars()
            .any(|c| breaks_a_parameter(c) || matches!(c, ',' | '*' | '?' | '!' | '@'))
        {
            return Err(error(
                "must be one word without spaces, control characters, or any of , * ? ! @",
            ));
        }
        Ok(Self(value.to_string()))
    }
}

impl fmt::Display for UpstreamNick {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The user name (ident) sent as the first `USER` parameter.
///
/// It used to be the first ten bytes of the nickname. A nickname may begin
/// with `_`, `[` or `|`; a user name may not, so Solanum and its relatives
/// closed the link on perfectly legal nicknames (`Invalid username [~_bot]`)
/// and the owner had no field to correct. It is now something the owner states.
///
/// Unlike the nickname's, this grammar is the strictest common one rather than
/// merely structural, because servers do not answer a bad user name with a
/// numeric a client can act on: they close the link. Solanum's `valid_username`
/// requires an alphanumeric first character; `.` is left out because whether
/// (and how many) dots are accepted is per-server configuration
/// (`dots_in_ident`); ten bytes is the classic `USERLEN`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamUsername(String);

impl UpstreamUsername {
    pub const MAX_BYTES: usize = 10;

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for UpstreamUsername {
    type Err = UpstreamIdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let error = |reason| UpstreamIdentityError {
            field: "username",
            reason,
        };
        let Some(first) = value.bytes().next() else {
            return Err(error("is required"));
        };
        if value.len() > Self::MAX_BYTES {
            return Err(error("is limited to 10 bytes"));
        }
        if !first.is_ascii_alphanumeric() {
            return Err(error("must begin with an ASCII letter or digit"));
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(error("may contain only ASCII letters, digits, '_' and '-'"));
        }
        Ok(Self(value.to_string()))
    }
}

impl fmt::Display for UpstreamUsername {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The free-text real name sent as the trailing `USER` parameter. Spaces are
/// its whole point; only what would end the line is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamRealname(String);

impl UpstreamRealname {
    pub const MAX_BYTES: usize = 128;

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for UpstreamRealname {
    type Err = UpstreamIdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let error = |reason| UpstreamIdentityError {
            field: "realname",
            reason,
        };
        if value.is_empty() {
            return Err(error("is required"));
        }
        if value.len() > Self::MAX_BYTES {
            return Err(error("is limited to 128 bytes"));
        }
        if value.chars().any(char::is_control) {
            return Err(error("must not contain control characters"));
        }
        Ok(Self(value.to_string()))
    }
}

/// One channel the driver joins after registering. Exactly one channel: not a
/// comma list, not a name followed by a key, and never `0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamChannel(String);

impl UpstreamChannel {
    pub const MAX_BYTES: usize = 64;

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for UpstreamChannel {
    type Err = UpstreamIdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let error = |reason| UpstreamIdentityError {
            field: "autojoin",
            reason,
        };
        if value.len() > Self::MAX_BYTES {
            return Err(error("names are limited to 64 bytes"));
        }
        channel_shape(value).map_err(error)?;
        Ok(Self(value.to_string()))
    }
}

/// Whether `value` can be exactly one channel in a `JOIN` line, as a reason
/// when it cannot. Length is each caller's own bound.
fn channel_shape(value: &str) -> Result<(), &'static str> {
    // RFC 2811 channel prefixes. Requiring one is what excludes `0`, which
    // an IRC server reads as "leave every channel".
    if !value.starts_with(['#', '&', '+', '!']) {
        return Err("names must begin with #, &, + or !");
    }
    one_channel_word(value)
}

/// The shape every channel name in a `JOIN` line has, whatever its prefix:
/// something after the prefix, and nothing that ends the parameter or the
/// list.
fn one_channel_word(value: &str) -> Result<(), &'static str> {
    if value.chars().count() < 2 {
        return Err("names need at least one character after the prefix");
    }
    if value.chars().any(|c| breaks_a_parameter(c) || c == ',') {
        return Err("names must be one word each, without spaces, commas, or control characters");
    }
    Ok(())
}

impl fmt::Display for UpstreamChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A channel an upstream confirmed the driver's membership in. The driver puts
/// it back into a `JOIN` line after a reconnect, so it has the same one-channel
/// shape as a configured [`UpstreamChannel`]; its length bound is the
/// protocol's rather than this project's configuration limit, because the name
/// was chosen on a network whose `CHANNELLEN` may be anything up to RFC 1459's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedChannel(String);

impl ConfirmedChannel {
    /// RFC 1459 section 1.3: a channel name is at most 200 characters.
    pub(crate) const MAX_BYTES: usize = 200;

    /// `None` when the network whose naming rules `names` holds could not
    /// have meant `value` as one channel: it must start with one of the
    /// network's own channel types (its `CHANTYPES`, which is what excludes
    /// `0`).
    pub(crate) fn parse(value: &str, names: &e6irc_client::NetworkNames) -> Option<Self> {
        (value.len() <= Self::MAX_BYTES
            && names.is_channel(value)
            && one_channel_word(value).is_ok())
        .then(|| Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The key of a keyed channel (`+k`): as the owner configured it for an
/// autojoin channel, or as a client joined it with or the channel was since
/// set to, so the driver can join it and rejoin it after a reconnect. A secret
/// of the channel's members: a configured one is stored sealed (DESIGN §10),
/// a learned one is kept in memory only, beside the reconnect intent, and
/// neither is ever shown — its `Debug` is redacted, so no log or panic message
/// can carry it.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ChannelKey(String);

impl ChannelKey {
    /// The longest key kept: longer than any server's `KEYLEN`.
    pub(crate) const MAX_BYTES: usize = 100;

    /// `None` for what cannot be one key parameter of a `JOIN` line.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        (!value.is_empty()
            && value.len() <= Self::MAX_BYTES
            && !value.starts_with(':')
            && !value.chars().any(|c| breaks_a_parameter(c) || c == ','))
        .then(|| Self(value.to_string()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ChannelKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChannelKey(<redacted>)")
    }
}

/// One configured autojoin entry in plaintext, before it is parsed: a channel
/// (or a bridge's room or channel id) and, for an IRC channel, the key it is
/// joined with. This is the form a request states and a stored row opens to;
/// only [`AutojoinChannel`] reaches a driver. Its `Debug` never shows the key.
#[derive(Clone, PartialEq, Eq)]
pub struct AutojoinEntry {
    pub channel: String,
    pub key: Option<String>,
}

impl AutojoinEntry {
    /// Most entries a network may be configured to join.
    pub const MAX_CONFIGURED: usize = 64;

    /// A channel joined without a key.
    pub fn unkeyed(channel: impl Into<String>) -> Self {
        Self {
            channel: channel.into(),
            key: None,
        }
    }

    /// An entry as a request writes it: `#channel`, or `#channel key` for a
    /// keyed one — the two parameters of `JOIN`, in the order `JOIN` takes
    /// them. Whether the key is one parameter is [`AutojoinChannel`]'s to say.
    pub fn from_submitted(value: &str) -> Self {
        match value.split_once(' ') {
            Some((channel, key)) => Self {
                channel: channel.to_string(),
                key: Some(key.to_string()),
            },
            None => Self::unkeyed(value),
        }
    }
}

impl fmt::Debug for AutojoinEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AutojoinEntry")
            .field("channel", &self.channel)
            .field("key", &self.key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// A configured channel the IRC driver joins after registering, with the key
/// it is joined with when it is keyed. Built only from an [`AutojoinEntry`]
/// (or its request form, by [`FromStr`]), so the key is one `JOIN` parameter
/// and the channel one channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutojoinChannel {
    channel: UpstreamChannel,
    key: Option<ChannelKey>,
}

impl AutojoinChannel {
    pub fn channel(&self) -> &UpstreamChannel {
        &self.channel
    }

    pub(crate) fn key(&self) -> Option<&ChannelKey> {
        self.key.as_ref()
    }

    /// Parse one plaintext entry.
    pub fn from_entry(entry: &AutojoinEntry) -> Result<Self, UpstreamIdentityError> {
        let key = entry
            .key
            .as_deref()
            .map(|key| {
                ChannelKey::parse(key).ok_or(UpstreamIdentityError {
                    field: "autojoin",
                    reason: "keys must be one word each, of at most 100 bytes, without commas, \
                             control characters, or a leading ':'",
                })
            })
            .transpose()?;
        Ok(Self {
            channel: entry.channel.parse()?,
            key,
        })
    }

    /// Parse a whole configured list, bounding its length as well as each
    /// entry.
    pub fn parse_list(entries: &[AutojoinEntry]) -> Result<Vec<Self>, UpstreamIdentityError> {
        if entries.len() > AutojoinEntry::MAX_CONFIGURED {
            return Err(UpstreamIdentityError {
                field: "autojoin",
                reason: "is limited to 64 channels",
            });
        }
        entries.iter().map(Self::from_entry).collect()
    }
}

impl FromStr for AutojoinChannel {
    type Err = UpstreamIdentityError;

    /// `#channel` or `#channel key`, as [`AutojoinEntry::from_submitted`]
    /// reads a request.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_entry(&AutojoinEntry::from_submitted(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_channel_key_is_one_parameter_and_never_shown() {
        let key = ChannelKey::parse("hunter2").expect("a key");
        assert_eq!(key.as_str(), "hunter2");
        assert!(!format!("{key:?}").contains("hunter2"));
        for bad in ["", "two words", "a,b", ":colon", "bell\u{7}"] {
            assert_eq!(ChannelKey::parse(bad), None, "{bad:?}");
        }
    }

    /// The very nicknames whose derived user names got networks refused are
    /// what this grammar turns away, along with everything per-server.
    #[test]
    fn a_username_is_one_every_server_accepts() {
        for good in [
            "alice",
            "e6irc",
            "a",
            "0day",
            "bot-2",
            "first_last",
            "abcdefghij",
        ] {
            assert_eq!(good.parse::<UpstreamUsername>().expect(good).as_str(), good);
        }
        for (bad, reason) in [
            ("", "is required"),
            ("_bot", "must begin with an ASCII letter or digit"),
            ("|me|", "must begin with an ASCII letter or digit"),
            ("-dash", "must begin with an ASCII letter or digit"),
            ("~ident", "must begin with an ASCII letter or digit"),
            (
                "first.last",
                "may contain only ASCII letters, digits, '_' and '-'",
            ),
            ("me|", "may contain only ASCII letters, digits, '_' and '-'"),
            (
                "al ice",
                "may contain only ASCII letters, digits, '_' and '-'",
            ),
            ("zoë", "may contain only ASCII letters, digits, '_' and '-'"),
            (
                "a\r\nJOIN",
                "may contain only ASCII letters, digits, '_' and '-'",
            ),
            ("abcdefghijk", "is limited to 10 bytes"),
        ] {
            let error = bad.parse::<UpstreamUsername>().expect_err(bad);
            assert_eq!(error.field(), "username");
            assert_eq!(error.reason(), reason, "{bad:?}");
        }
    }

    /// The native clients decide whether a nickname may double as the user
    /// name with `e6irc_client::is_portable_username`. Two grammars that must
    /// agree are tested to agree.
    #[test]
    fn the_clients_username_predicate_is_this_grammar() {
        for word in [
            "alice",
            "a",
            "0day",
            "bot-2",
            "first_last",
            "abcdefghij",
            "abcdefghijk",
            "",
            "_bot",
            "-dash",
            "~ident",
            "first.last",
            "me|",
            "al ice",
            "zoë",
            "a\r\nJOIN",
            ":a",
            "A9_-",
        ] {
            assert_eq!(
                e6irc_client::is_portable_username(word),
                word.parse::<UpstreamUsername>().is_ok(),
                "{word:?}"
            );
        }
    }

    #[test]
    fn a_nickname_is_exactly_one_wire_parameter() {
        for good in ["alice", "e6bnc", "_bot", "[away]", "guest-42", "Zoë", "a"] {
            assert_eq!(
                good.parse::<UpstreamNick>().expect(good).as_str(),
                good,
                "{good}"
            );
        }
        for bad in [
            "",
            "al ice",
            "alice\r\nJOIN #x",
            "tab\there",
            "nul\0",
            ":alice",
            "#alice",
            "&alice",
            "@alice",
            "+alice",
            "$server",
            "a,b",
            "a!b",
            "a@b",
            "al*ce",
            "al?ce",
            "bell\u{7}",
            "nbsp\u{a0}x",
        ] {
            let error = bad.parse::<UpstreamNick>().expect_err(bad);
            assert_eq!(error.field(), "nick", "{bad:?}");
        }
        assert!("n".repeat(64).parse::<UpstreamNick>().is_ok());
        assert!("n".repeat(65).parse::<UpstreamNick>().is_err());
    }

    #[test]
    fn a_real_name_keeps_its_spaces_but_cannot_end_the_line() {
        assert_eq!(
            "Alice von Example :-)"
                .parse::<UpstreamRealname>()
                .expect("spaces and colons are text here")
                .as_str(),
            "Alice von Example :-)"
        );
        for bad in ["", "two\r\nlines", "nul\0", "escape\u{1b}[2J"] {
            assert_eq!(
                bad.parse::<UpstreamRealname>().expect_err(bad).field(),
                "realname"
            );
        }
        assert!("r".repeat(128).parse::<UpstreamRealname>().is_ok());
        assert!("r".repeat(129).parse::<UpstreamRealname>().is_err());
    }

    #[test]
    fn a_configured_channel_is_one_channel_and_never_join_zero() {
        for good in [
            "#e6irc",
            "&local",
            "+modeless",
            "!12345safe",
            "#日本語",
            "#a:b",
        ] {
            assert_eq!(good.parse::<UpstreamChannel>().expect(good).as_str(), good);
        }
        for bad in [
            "0",
            "",
            "#",
            "e6irc",
            "#a,#b",
            "#a key",
            "#a\r\nQUIT",
            "#bell\u{7}",
            "#nul\0",
        ] {
            assert_eq!(
                bad.parse::<UpstreamChannel>().expect_err(bad).field(),
                "autojoin",
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_confirmed_channel_has_the_configured_shape_and_the_protocol_length() {
        let names = e6irc_client::NetworkNames::default();
        let long = format!("#{}", "c".repeat(199));
        assert_eq!(
            ConfirmedChannel::parse(&long, &names)
                .expect("RFC 1459 length")
                .as_str(),
            long
        );
        assert!(long.parse::<UpstreamChannel>().is_err());
        for bad in ["0", "", "#", "nick", "#a,#b", "#a key", "#bell\u{7}"] {
            assert_eq!(ConfirmedChannel::parse(bad, &names), None, "{bad:?}");
        }
        assert_eq!(
            ConfirmedChannel::parse(&format!("#{}", "c".repeat(200)), &names),
            None
        );
    }

    /// Which names are channels is the network's to say: IRCnet's `!` channels
    /// are channels there, and `&` is not one on a network whose CHANTYPES is
    /// `#` alone.
    #[test]
    fn a_confirmed_channel_starts_with_one_of_the_networks_channel_types() {
        let mut names = e6irc_client::NetworkNames::default();
        assert_eq!(ConfirmedChannel::parse("!ABCDEchan", &names), None);
        names.adopt_tokens(["CHANTYPES=#!"]);
        assert!(ConfirmedChannel::parse("!ABCDEchan", &names).is_some());
        assert_eq!(ConfirmedChannel::parse("&local", &names), None);
    }

    #[test]
    fn a_configured_list_is_bounded_and_fails_on_its_first_bad_name() {
        let many: Vec<AutojoinEntry> = (0..64)
            .map(|n| AutojoinEntry::unkeyed(format!("#c{n}")))
            .collect();
        assert_eq!(AutojoinChannel::parse_list(&many).expect("64").len(), 64);
        let too_many: Vec<AutojoinEntry> = (0..65)
            .map(|n| AutojoinEntry::unkeyed(format!("#c{n}")))
            .collect();
        assert_eq!(
            AutojoinChannel::parse_list(&too_many)
                .expect_err("65")
                .reason(),
            "is limited to 64 channels"
        );
        assert!(
            AutojoinChannel::parse_list(&[
                AutojoinEntry::unkeyed("#ok"),
                AutojoinEntry::unkeyed("0")
            ])
            .is_err()
        );
    }

    /// An autojoin entry is the two `JOIN` parameters in `JOIN`'s order: one
    /// channel, then optionally one key. The key is a secret and never shown.
    #[test]
    fn an_autojoin_entry_is_a_channel_and_optionally_one_key() {
        let keyed: AutojoinChannel = "#staff hunter2".parse().expect("a keyed channel");
        assert_eq!(keyed.channel().as_str(), "#staff");
        assert_eq!(keyed.key().map(ChannelKey::as_str), Some("hunter2"));
        assert!(!format!("{keyed:?}").contains("hunter2"));
        let entry = AutojoinEntry::from_submitted("#staff hunter2");
        assert!(!format!("{entry:?}").contains("hunter2"));
        let open: AutojoinChannel = "#open".parse().expect("an open channel");
        assert_eq!(open.key(), None);
        for (bad, reason) in [
            ("#a two words", "keys must be one word each"),
            ("#a k,ey", "keys must be one word each"),
            ("#a :key", "keys must be one word each"),
            ("#a ", "keys must be one word each"),
            ("0 key", "names must begin with #, &, + or !"),
            ("#a,#b key", "names must be one word each"),
        ] {
            let error = bad.parse::<AutojoinChannel>().expect_err(bad);
            assert_eq!(error.field(), "autojoin", "{bad:?}");
            assert!(error.reason().starts_with(reason), "{bad:?}: {error}");
        }
        assert!(
            format!("#a {}", "k".repeat(100))
                .parse::<AutojoinChannel>()
                .is_ok()
        );
        assert!(
            format!("#a {}", "k".repeat(101))
                .parse::<AutojoinChannel>()
                .is_err()
        );
    }
}
