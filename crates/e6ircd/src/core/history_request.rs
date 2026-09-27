//! The parameters of `CHATHISTORY` and `MARKREAD`, parsed once for both
//! surfaces that answer them — the core and the bouncer's attach listener.
//!
//! Each surface used to parse its own, and they drifted: one refused
//! `BETWEEN #c timestamp=bad foo=1 10` as a bad reference type and the other as
//! a bad parameter, and one accepted a `MARKREAD` with a stray third parameter
//! the other refused. What a request means, and which `FAIL` a malformed one
//! gets, is decided here; each surface decides only what is its own — whether
//! the target exists, and where the answer comes from.

use e6irc_proto::time::Millis;

use super::HistoryFail;

/// Most messages one CHATHISTORY request may return, and most buffers one
/// TARGETS request may list. The single source for the validation below and
/// the `CHATHISTORY=` ISUPPORT token, so what is advertised can never drift
/// from what is enforced.
pub(crate) const CHATHISTORY_MAX: usize = 500;

/// A refused request: the code its `FAIL` carries, and the description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Refusal {
    pub(crate) code: HistoryFail,
    pub(crate) detail: &'static str,
}

impl Refusal {
    const fn new(code: HistoryFail, detail: &'static str) -> Self {
        Self { code, detail }
    }
}

/// A CHATHISTORY subcommand that pages one target, parsed once from the wire
/// token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChathistorySub {
    Latest,
    Before,
    After,
    Around,
    Between,
}

impl ChathistorySub {
    /// Parse a subcommand token (case-insensitive). `None` is an unknown
    /// subcommand (→ UNKNOWN_COMMAND) — or TARGETS, which pages no target and
    /// is parsed by [`parse_targets`].
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "LATEST" => Some(Self::Latest),
            "BEFORE" => Some(Self::Before),
            "AFTER" => Some(Self::After),
            "AROUND" => Some(Self::Around),
            "BETWEEN" => Some(Self::Between),
            _ => None,
        }
    }

    /// The canonical spelling, as a failure names the subcommand it refuses.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Latest => "LATEST",
            Self::Before => "BEFORE",
            Self::After => "AFTER",
            Self::Around => "AROUND",
            Self::Between => "BETWEEN",
        }
    }

    /// BETWEEN takes two selectors then the limit; the others take one.
    pub(crate) fn takes_two_selectors(self) -> bool {
        matches!(self, Self::Between)
    }

    /// Every parameter the subcommand takes, itself included:
    /// `<sub> <target> <selector> [<selector>] <limit>`.
    pub(crate) fn parameter_count(self) -> usize {
        if self.takes_two_selectors() { 5 } else { 4 }
    }

    /// The refusal of a request with more parameters than this subcommand takes.
    pub(crate) fn too_many_parameters(self) -> Refusal {
        Refusal::new(
            HistoryFail::InvalidParams,
            if self.takes_two_selectors() {
                "Expected exactly <target> <selector> <selector> <limit>"
            } else {
                "Expected exactly <target> <selector> <limit>"
            },
        )
    }
}

/// A CHATHISTORY message-reference selector, parsed *once* from the wire token
/// ("parse, don't validate", DESIGN §2): a `timestamp=` carries its
/// [`Millis`] already, so no later site re-parses it or defaults a malformed
/// one to epoch 0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Selector {
    /// The open bound `*` — a real selector only for LATEST.
    Star,
    /// `msgid=<id>`: an exact message reference.
    Msgid(String),
    /// `timestamp=<t>`: a server-time bound, already parsed to milliseconds.
    Timestamp(Millis),
}

/// Why a wire token is not a usable [`Selector`].
enum SelectorError {
    /// Not one of `*` / `msgid=` / `timestamp=` (→ INVALID_MSGREFTYPE).
    UnknownRefType,
    /// A `timestamp=` whose value is not a valid server-time, or a `msgid=`
    /// without a value or whose value cannot be reused as an IRC command
    /// parameter (→ INVALID_PARAMS).
    Malformed,
}

impl Selector {
    /// The message id this selector names, if it names one.
    pub(crate) fn msgid(&self) -> Option<&str> {
        match self {
            Selector::Msgid(msgid) => Some(msgid),
            Selector::Timestamp(_) | Selector::Star => None,
        }
    }

    /// Whether this is the open bound `*`.
    pub(crate) fn is_star(&self) -> bool {
        matches!(self, Selector::Star)
    }

    fn parse(sel: &str) -> Result<Self, SelectorError> {
        if sel == "*" {
            Ok(Selector::Star)
        } else if let Some(id) = sel.strip_prefix("msgid=") {
            e6irc_proto::message::valid_message_id(id)
                .then(|| Selector::Msgid(id.to_string()))
                .ok_or(SelectorError::Malformed)
        } else if let Some(ts) = sel.strip_prefix("timestamp=") {
            e6irc_proto::time::parse_server_time_millis(ts)
                .map(Selector::Timestamp)
                .ok_or(SelectorError::Malformed)
        } else {
            Err(SelectorError::UnknownRefType)
        }
    }
}

/// The selectors of a request paging with `sub`: `first`, and `second` for
/// BETWEEN (`*` for the others, which take one). The failures, in one
/// precedence for both selectors together: an unknown reference type in
/// either (INVALID_MSGREFTYPE), then `*` where only LATEST allows it, then a
/// malformed value of a known type (both INVALID_PARAMS).
pub(crate) fn parse_selectors(
    sub: ChathistorySub,
    first: &str,
    second: &str,
) -> Result<(Selector, Selector), Refusal> {
    let first = Selector::parse(first);
    let second = if sub.takes_two_selectors() {
        Selector::parse(second)
    } else {
        Ok(Selector::Star)
    };
    if matches!(first, Err(SelectorError::UnknownRefType))
        || matches!(second, Err(SelectorError::UnknownRefType))
    {
        return Err(Refusal::new(
            HistoryFail::InvalidMsgRefType,
            "Unknown message reference type",
        ));
    }
    // `*` is the open bound, meaningful *only* for LATEST. For BEFORE/AFTER/
    // AROUND — and for either bound of BETWEEN — accepting it yields the wrong
    // window: an empty batch for the one-selector forms, or a full unbounded
    // scan for BETWEEN.
    let star_misused = match sub {
        ChathistorySub::Latest => false,
        ChathistorySub::Between => {
            matches!(first, Ok(Selector::Star)) || matches!(second, Ok(Selector::Star))
        }
        _ => matches!(first, Ok(Selector::Star)),
    };
    if star_misused {
        return Err(Refusal::new(
            HistoryFail::InvalidParams,
            "* is only a valid selector for LATEST",
        ));
    }
    match (first, second) {
        (Ok(first), Ok(second)) => Ok((first, second)),
        _ => Err(Refusal::new(
            HistoryFail::InvalidParams,
            "Malformed message reference selector",
        )),
    }
}

/// A page limit: a positive integer no greater than [`CHATHISTORY_MAX`] —
/// never silently defaulted.
pub(crate) fn parse_limit(raw: &str) -> Result<usize, Refusal> {
    raw.parse::<usize>()
        .ok()
        .filter(|n| (1..=CHATHISTORY_MAX).contains(n))
        .ok_or(Refusal::new(
            HistoryFail::InvalidParams,
            "limit must be between 1 and 500",
        ))
}

/// A parsed `CHATHISTORY TARGETS <timestamp> <timestamp> <limit>`: the window
/// its bounds make, whichever order they were given in, both exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TargetsWindow {
    pub(crate) after: Millis,
    pub(crate) before: Millis,
    pub(crate) limit: usize,
}

/// Parse `CHATHISTORY TARGETS …`; `p` starts at the subcommand.
pub(crate) fn parse_targets(p: &[&str]) -> Result<TargetsWindow, Refusal> {
    if p.len() != 4 {
        let code = if p.len() < 4 {
            HistoryFail::NeedMoreParams
        } else {
            HistoryFail::InvalidParams
        };
        return Err(Refusal::new(
            code,
            "Expected exactly two timestamp= bounds and a limit",
        ));
    }
    let bound = |raw: &str| {
        raw.strip_prefix("timestamp=")
            .and_then(e6irc_proto::time::parse_server_time_millis)
    };
    let (Some(a), Some(b)) = (bound(p[1]), bound(p[2])) else {
        return Err(Refusal::new(
            HistoryFail::InvalidParams,
            "Expected two timestamp= bounds",
        ));
    };
    Ok(TargetsWindow {
        after: a.min(b),
        before: a.max(b),
        limit: parse_limit(p[3])?,
    })
}

/// A parsed `MARKREAD`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MarkreadRequest<'a> {
    /// `MARKREAD <target>`: what is the marker?
    Query { target: &'a str },
    /// `MARKREAD <target> timestamp=<time>`: move it forward to `marker`.
    Set { target: &'a str, marker: Millis },
}

/// Parse `MARKREAD <target> [timestamp=<time>]`; `p` starts at the target.
/// `valid_target` is the surface's own rule for what may be named (the core's
/// nick and channel grammar, or an external network's structural one), checked
/// after the parameter count and before the position. A refusal carries the
/// target it names in its `FAIL`, `*` when none was given.
pub(crate) fn parse_markread<'a>(
    p: &[&'a str],
    valid_target: impl FnOnce(&str) -> bool,
) -> Result<MarkreadRequest<'a>, (&'a str, Refusal)> {
    let Some(&target) = p.first() else {
        return Err((
            "*",
            Refusal::new(HistoryFail::NeedMoreParams, "Not enough parameters"),
        ));
    };
    let refuse = |detail| Err((target, Refusal::new(HistoryFail::InvalidParams, detail)));
    if p.len() > 2 {
        return refuse("Expected <target> [timestamp=<time>]");
    }
    if !valid_target(target) {
        return refuse("Invalid target");
    }
    let Some(&position) = p.get(1) else {
        return Ok(MarkreadRequest::Query { target });
    };
    let Some(time) = position.strip_prefix("timestamp=") else {
        return refuse("Expected timestamp=");
    };
    // Millisecond precision: a marker must round-trip its `.mmm` fraction.
    match e6irc_proto::time::parse_server_time_millis(time) {
        Some(marker) => Ok(MarkreadRequest::Set { target, marker }),
        None => refuse("Malformed timestamp"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(sub: ChathistorySub, first: &str, second: &str) -> Option<Refusal> {
        parse_selectors(sub, first, second).err()
    }

    /// An unknown reference type in either selector outranks a malformed
    /// value in the other, whichever comes first.
    #[test]
    fn an_unknown_reference_type_outranks_a_malformed_value() {
        for (first, second) in [("timestamp=bad", "foo=1"), ("foo=1", "timestamp=bad")] {
            assert_eq!(
                refused(ChathistorySub::Between, first, second).map(|r| r.code),
                Some(HistoryFail::InvalidMsgRefType),
                "{first} {second}"
            );
        }
        assert_eq!(
            refused(ChathistorySub::Between, "timestamp=bad", "msgid=x").map(|r| r.code),
            Some(HistoryFail::InvalidParams)
        );
        assert_eq!(
            refused(ChathistorySub::Before, "*", "*").map(|r| r.detail),
            Some("* is only a valid selector for LATEST")
        );
        // A one-selector subcommand never reads a second.
        assert!(refused(ChathistorySub::Latest, "*", "foo=1").is_none());
    }

    #[test]
    fn markread_takes_a_target_and_at_most_a_timestamp() {
        let ok = |_: &str| true;
        assert_eq!(
            parse_markread(&[], ok),
            Err((
                "*",
                Refusal::new(HistoryFail::NeedMoreParams, "Not enough parameters")
            ))
        );
        assert_eq!(
            parse_markread(&["#c", "timestamp=2026-01-01T00:00:00.000Z", "junk"], ok)
                .map_err(|(target, refusal)| (target, refusal.code)),
            Err(("#c", HistoryFail::InvalidParams))
        );
        assert_eq!(
            parse_markread(&["#c"], ok),
            Ok(MarkreadRequest::Query { target: "#c" })
        );
        assert_eq!(
            parse_markread(&["#c", "timestamp=2026-01-01T00:00:00.1Z"], ok),
            Ok(MarkreadRequest::Set {
                target: "#c",
                marker: e6irc_proto::time::parse_server_time_millis("2026-01-01T00:00:00.100Z")
                    .expect("a time"),
            })
        );
        for bad in ["2026-01-01T00:00:00.000Z", "timestamp=not-a-time"] {
            assert!(parse_markread(&["#c", bad], ok).is_err(), "{bad}");
        }
        assert_eq!(
            parse_markread(&["bad target", "timestamp=junk"], |_| false)
                .map_err(|(_, refusal)| refusal.detail),
            Err("Invalid target")
        );
    }

    #[test]
    fn targets_orders_its_bounds_and_bounds_its_limit() {
        let window = parse_targets(&[
            "TARGETS",
            "timestamp=2026-01-02T00:00:00.000Z",
            "timestamp=2026-01-01T00:00:00.000Z",
            "5",
        ])
        .expect("a window");
        assert!(window.after < window.before);
        assert_eq!(window.limit, 5);
        for limit in ["0", "501", "-1", "x"] {
            assert!(parse_limit(limit).is_err(), "{limit}");
        }
        assert_eq!(parse_limit("500"), Ok(500));
    }
}
