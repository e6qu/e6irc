//! The middle parameters of a core numeric, typed by where their text came
//! from.

use std::borrow::Cow;

use e6irc_proto::message::MiddleParam;

/// One middle parameter of a numeric the core sends
/// ([`ServerState::numeric`](super::state::ServerState::numeric)).
///
/// A middle is exactly one wire parameter. Whatever it is built from, the
/// numeric funnel renders it as one: a value that is empty, `:`-leading, or
/// carries a space, CR, LF or NUL becomes the conventional `*` placeholder,
/// because any of those would collapse, shift or split the reply's parameters
/// (`NICK :a b` answered `432 * a b :…`). What the constructor records is
/// where the text came from, which sets how much of it is kept:
///
/// - [`Middle::echo`]: text a client or an upstream supplied, echoed for
///   attribution (an unknown command, a refused nick, a WHOX token). It takes
///   the shared [`MiddleParam::echo`] rule, the one the bouncer's attach
///   numerics use, clipped to [`MiddleParam::ECHO_MAX`] bytes.
/// - [`Middle::own`]: a value the server holds, validated where it entered —
///   a nick, a channel's display name, a stored mask, a mode string. Its
///   length is bounded by that ingress, and the funnel holds it to
///   [`Middle::OWN_MAX`] bytes.
/// - an integer, through `From`: a count, a timestamp, a limit.
///
/// There is no constructor for several parameters in one value: a reply with a
/// variable number of them (a mode string and its arguments) passes one
/// `Middle` each, so no joined segment can carry an unvalidated token.
#[derive(Debug, Clone)]
pub(crate) struct Middle<'a>(Source<'a>);

#[derive(Debug, Clone)]
enum Source<'a> {
    Echo(MiddleParam<'a>),
    Own(Cow<'a, str>),
}

impl<'a> Middle<'a> {
    /// The longest server-owned middle kept whole: every one is short by
    /// construction (a nick, a 50-byte channel name, a 63-byte host, a
    /// BANMASKLEN-bounded mask), so this only bounds a value whose ingress
    /// failed to.
    pub(crate) const OWN_MAX: usize = 100;

    /// Text a client or an upstream supplied, echoed back.
    pub(crate) fn echo(token: &'a str) -> Self {
        Self(Source::Echo(MiddleParam::echo(token)))
    }

    /// A value the server owns, validated where it entered.
    pub(crate) fn own(value: impl Into<Cow<'a, str>>) -> Self {
        Self(Source::Own(value.into()))
    }

    /// The parameter as the funnel writes it, before the line's own budget.
    pub(super) fn wire(&self) -> &str {
        match &self.0 {
            Source::Echo(echo) => echo.as_str(),
            Source::Own(value) => {
                let stands_alone = MiddleParam::stands_alone(value);
                debug_assert!(
                    stands_alone,
                    "a server-owned numeric middle cannot stand as one parameter: {value:?}"
                );
                if !stands_alone {
                    return "*";
                }
                e6irc_proto::message::truncate_on_char_boundary(value, Self::OWN_MAX)
            }
        }
    }
}

macro_rules! integer_middles {
    ($($integer:ty),*) => {$(
        impl From<$integer> for Middle<'static> {
            fn from(number: $integer) -> Self {
                Self(Source::Own(Cow::Owned(number.to_string())))
            }
        }
    )*};
}

integer_middles!(u16, u32, u64, usize, i64);

#[cfg(test)]
mod tests {
    use super::Middle;

    #[test]
    fn an_echo_is_one_parameter_clipped_to_the_echo_bound() {
        for token in ["", ":x", "a b", " ", "trailing ", "a\rb", "a\nb", "a\0b"] {
            assert_eq!(Middle::echo(token).wire(), "*", "{token:?}");
        }
        assert_eq!(Middle::echo("nick").wire(), "nick");
        assert_eq!(Middle::echo(&"x".repeat(100)).wire().len(), 64);
    }

    #[test]
    fn an_own_value_is_kept_to_its_bound() {
        for token in ["alice", "#chan", "+o", "0", "255.255.255.255", "H@", "*"] {
            assert_eq!(Middle::own(token).wire(), token);
        }
        assert_eq!(Middle::own("x".repeat(150)).wire().len(), Middle::OWN_MAX);
        assert_eq!(Middle::from(42_u64).wire(), "42");
    }

    /// A server-owned value that cannot stand as one parameter is a server
    /// bug: loud in a debug build, the `*` placeholder in a release one.
    #[test]
    #[cfg_attr(
        debug_assertions,
        should_panic(expected = "cannot stand as one parameter")
    )]
    fn an_own_value_that_cannot_stand_alone_is_a_placeholder() {
        assert_eq!(Middle::own("+ntk sekrit").wire(), "*");
    }
}
