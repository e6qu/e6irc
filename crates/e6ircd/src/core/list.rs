//! LIST's parameter and the state of a LIST reply still being sent.
//!
//! The parameter grammar is Solanum's `m_list` (as deployed on Libera), which
//! advertises it as `ELIST=CMNTU`: up to [`MAX_LIST_CONDITIONS`]
//! comma-separated conditions, all of which a channel must meet —
//!
//! - `<n` / `>n` (U): fewer / more than `n` members (`<0` sets no bound);
//! - `C<n` / `C>n` (C): created less / more than `n` minutes ago;
//! - `T<n` / `T>n` (T): topic set less / more than `n` minutes ago — a channel
//!   with no topic meets neither;
//! - a glob starting with `#`, `*` or `?` (M): the channel name matches it,
//!   casemapped; a plain `#name` is the exact channel;
//! - `!glob` (N): the channel name does not match it.
//!
//! Anything else is refused whole ("Invalid parameters for /LIST"). Where
//! Solanum keeps only the last mask of several, a channel here may match any
//! of them, so `LIST #a,#b` lists both as RFC 1459 describes; every other
//! condition narrows.
//!
//! The reply is paced (`SAFELIST`): rows go out only while the client's send
//! queue is under half full, and the rest follow as it drains, so a LIST of
//! every channel on a large network cannot overflow the queue and cost the
//! client its connection. Nor is the list copied to be paced out: the LIST
//! keeps a cursor per channel shard ([`ChannelListCursor`]) and reads the next
//! page after it as there is room, as Solanum's SAFELIST keeps its place in
//! the channel hash rather than a copy of it.

use e6irc_proto::casemap::CaseMapping;
use e6irc_proto::mask::FoldedMask;

use std::collections::VecDeque;
use std::sync::Arc;

use super::state::{ChanKey, ChannelListRequestId, ChannelListRow};

/// The `ELIST` letters [`ListFilter::parse`] implements.
pub(crate) const ELIST: &str = "CMNTU";

/// Most comma-separated conditions one LIST parameter may carry: Solanum's
/// bound. Solanum ignores the conditions past it; here they refuse the LIST.
pub(crate) const MAX_LIST_CONDITIONS: usize = 7;

/// A LIST parameter the grammar above does not describe.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct InvalidListParameters;

/// An inclusive range of whole Unix seconds; an unset end is unbounded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Window {
    since: Option<u64>,
    until: Option<u64>,
}

impl Window {
    fn is_bounded(self) -> bool {
        self.since.is_some() || self.until.is_some()
    }

    fn contains(self, secs: u64) -> bool {
        self.since.is_none_or(|since| secs >= since) && self.until.is_none_or(|until| secs <= until)
    }
}

/// Which channels a LIST asks for, decided once where the command is parsed —
/// its time bounds already absolute — and carried unchanged to every shard
/// that holds channels.
#[derive(Debug, Clone, Default)]
pub(crate) struct ListFilter {
    /// A channel is listed only if it matches one of these (none: any name).
    masks: Vec<FoldedMask>,
    /// A channel matching any of these is not listed.
    excluded: Vec<FoldedMask>,
    min_members: u64,
    max_members: Option<u64>,
    created: Window,
    topic_set: Window,
}

/// What [`ListFilter::admits`] needs to know of one channel.
pub(crate) struct ListCandidate<'a> {
    pub key: &'a ChanKey,
    pub members: usize,
    pub created_secs: u64,
    pub topic_set_secs: Option<u64>,
}

/// A decimal count with no sign: `None` unless `text` is one or more ASCII
/// digits. Too large a count saturates, which no bound here can tell apart.
fn count(text: &str) -> Option<u64> {
    (!text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())).then(|| {
        text.bytes().fold(0u64, |total, digit| {
            total
                .saturating_mul(10)
                .saturating_add(u64::from(digit - b'0'))
        })
    })
}

/// `C<n` / `C>n` / `T<n` / `T>n`, after the letter: a bound `n` minutes back
/// from `now_secs`.
fn minutes_ago(
    window: &mut Window,
    text: &str,
    now_secs: u64,
) -> Result<(), InvalidListParameters> {
    let (within, minutes) = match text.split_at_checked(1) {
        Some(("<", minutes)) => (true, minutes),
        Some((">", minutes)) => (false, minutes),
        _ => return Err(InvalidListParameters),
    };
    let minutes = count(minutes).ok_or(InvalidListParameters)?;
    let bound = now_secs.saturating_sub(minutes.saturating_mul(60));
    if within {
        window.since = Some(bound);
    } else {
        window.until = Some(bound);
    }
    Ok(())
}

impl ListFilter {
    /// Parse LIST's first parameter (absent or empty: every channel). The
    /// relative time conditions are resolved against `now_secs`.
    pub(crate) fn parse(
        parameter: Option<&str>,
        now_secs: u64,
        casemap: CaseMapping,
    ) -> Result<Self, InvalidListParameters> {
        let mut filter = Self::default();
        let Some(parameter) = parameter.filter(|parameter| !parameter.is_empty()) else {
            return Ok(filter);
        };
        // One trailing comma closes the list; any other empty condition is
        // malformed.
        let conditions = parameter.strip_suffix(',').unwrap_or(parameter);
        let conditions: Vec<&str> = conditions.split(',').collect();
        if conditions.len() > MAX_LIST_CONDITIONS {
            return Err(InvalidListParameters);
        }
        for condition in conditions {
            let Some(first) = condition.chars().next() else {
                return Err(InvalidListParameters);
            };
            let rest = &condition[first.len_utf8()..];
            match first {
                '<' => {
                    let members = count(rest).ok_or(InvalidListParameters)?;
                    filter.max_members = members.checked_sub(1);
                }
                '>' => {
                    filter.min_members = match rest.strip_prefix('-') {
                        Some(negative) => count(negative).map(|_| 0),
                        None => count(rest).map(|members| members.saturating_add(1)),
                    }
                    .ok_or(InvalidListParameters)?;
                }
                'C' | 'c' => minutes_ago(&mut filter.created, rest, now_secs)?,
                'T' | 't' => minutes_ago(&mut filter.topic_set, rest, now_secs)?,
                '!' => filter.excluded.push(FoldedMask::new(casemap, rest)),
                '#' | '*' | '?' => filter.masks.push(FoldedMask::new(casemap, condition)),
                _ => return Err(InvalidListParameters),
            }
        }
        Ok(filter)
    }

    /// Whether `channel` meets every condition.
    pub(crate) fn admits(&self, channel: &ListCandidate<'_>) -> bool {
        let name = channel.key.as_str().as_bytes();
        let members = u64::try_from(channel.members).unwrap_or(u64::MAX);
        members >= self.min_members
            && self.max_members.is_none_or(|max| members <= max)
            && self.created.contains(channel.created_secs)
            && (!self.topic_set.is_bounded()
                || channel
                    .topic_set_secs
                    .is_some_and(|secs| self.topic_set.contains(secs)))
            && (self.masks.is_empty() || self.masks.iter().any(|mask| mask.matches_folded(name)))
            && !self.excluded.iter().any(|mask| mask.matches_folded(name))
    }
}

/// Most channels one page request examines on its shard, whatever it finds:
/// a LIST whose conditions admit few channels must not cost its owner shard a
/// scan of every channel in one event. The page then comes back short, with
/// its resume point, and the next one continues from there.
pub(crate) const LIST_PAGE_SCAN: usize = 1024;

/// A connection's LIST that has not finished answering: a cursor, not a copy
/// of the channel list. A connection has at most one: a LIST sent while one is
/// in progress aborts it instead (Solanum), which costs nothing — the cursor
/// is dropped, and a page still on its way finds no LIST of its `id` to join.
///
/// The reply is open from the start (its `RPL_LISTSTART` sent, inside `batch`
/// for a labeled LIST). Each channel shard is read in pages of the rows after
/// the last key it reported, in casemapped key order, and the rows of every
/// shard are merged in that order as they are sent. What the session holds is
/// at most one page per shard, each no larger than the room its send queue had
/// when the page was asked for — never the network's channel list.
pub(crate) struct ChannelListCursor {
    pub(crate) id: ChannelListRequestId,
    pub(crate) filter: Arc<ListFilter>,
    pub(crate) batch: Option<String>,
    shards: Vec<ShardCursor>,
}

/// One channel shard's part of a LIST in progress.
struct ShardCursor {
    /// Rows of its last page not yet sent, in key order.
    rows: VecDeque<ChannelListRow>,
    page: ShardPage,
}

enum ShardPage {
    /// No page is on its way; the next starts after `after` (at the first
    /// channel when `None`).
    Idle { after: Option<ChanKey> },
    /// A page was asked for and has not arrived.
    Requested,
    /// The shard has reported its last channel.
    Exhausted,
}

/// What a LIST sends next.
pub(crate) enum NextRow {
    Row(ChannelListRow),
    /// A shard's next row is not in yet, and it may sort first.
    Waiting,
    /// Every shard's channels have been listed.
    Finished,
}

impl ChannelListCursor {
    pub(crate) fn new(
        id: ChannelListRequestId,
        filter: ListFilter,
        batch: Option<String>,
        shards: usize,
    ) -> Self {
        Self {
            id,
            filter: Arc::new(filter),
            batch,
            shards: (0..shards)
                .map(|_| ShardCursor {
                    rows: VecDeque::new(),
                    page: ShardPage::Idle { after: None },
                })
                .collect(),
        }
    }

    /// The row that sorts first among every shard's, once no shard still to
    /// report can have one before it.
    pub(crate) fn next_row(&mut self) -> NextRow {
        let mut first: Option<(usize, &ChanKey)> = None;
        for (index, shard) in self.shards.iter().enumerate() {
            match shard.rows.front() {
                Some(row) => {
                    if first.is_none_or(|(_, best)| row.key.as_str() < best.as_str()) {
                        first = Some((index, &row.key));
                    }
                }
                None if matches!(shard.page, ShardPage::Exhausted) => {}
                None => return NextRow::Waiting,
            }
        }
        match first.map(|(index, _)| index) {
            Some(index) => NextRow::Row(
                self.shards[index]
                    .rows
                    .pop_front()
                    .expect("the chosen shard has a row"),
            ),
            None => NextRow::Finished,
        }
    }

    /// The shards whose next page is needed now — every row of theirs is
    /// sent and none is on its way — each with the key it starts after. They
    /// are marked as asked.
    pub(crate) fn pages_wanted(&mut self) -> Vec<(usize, Option<ChanKey>)> {
        let mut wanted = Vec::new();
        for (index, shard) in self.shards.iter_mut().enumerate() {
            if shard.rows.is_empty()
                && let ShardPage::Idle { after } = &mut shard.page
            {
                wanted.push((index, after.take()));
                shard.page = ShardPage::Requested;
            }
        }
        wanted
    }

    /// Take shard `index`'s page: its rows in key order, and the key the next
    /// page starts after — `None` when the shard has no channel past them.
    pub(crate) fn accept(
        &mut self,
        index: usize,
        rows: Vec<ChannelListRow>,
        next: Option<ChanKey>,
    ) {
        let shard = &mut self.shards[index];
        assert!(
            matches!(shard.page, ShardPage::Requested) && shard.rows.is_empty(),
            "a LIST page arrived that was not asked for"
        );
        shard.rows.extend(rows);
        shard.page = match next {
            Some(after) => ShardPage::Idle { after: Some(after) },
            None => ShardPage::Exhausted,
        };
    }

    /// Rows the cursor holds, waiting to be sent.
    #[cfg(test)]
    pub(crate) fn held_rows(&self) -> usize {
        self.shards.iter().map(|shard| shard.rows.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e6irc_proto::casemap::CaseMapping::Rfc1459;

    const NOW: u64 = 10_000_000;

    fn filter(parameter: &str) -> ListFilter {
        ListFilter::parse(Some(parameter), NOW, Rfc1459).expect("valid LIST parameter")
    }

    fn key(name: &str) -> ChanKey {
        ChanKey::for_test(&Rfc1459.casefold(name))
    }

    fn admits(
        filter: &ListFilter,
        name: &str,
        members: usize,
        created: u64,
        topic: Option<u64>,
    ) -> bool {
        filter.admits(&ListCandidate {
            key: &key(name),
            members,
            created_secs: created,
            topic_set_secs: topic,
        })
    }

    fn plain(filter: &ListFilter, name: &str) -> bool {
        admits(filter, name, 1, NOW, None)
    }

    #[test]
    fn no_parameter_lists_everything() {
        for parameter in [None, Some("")] {
            let all = ListFilter::parse(parameter, NOW, Rfc1459).expect("valid");
            assert!(admits(&all, "#a", 0, 0, None));
        }
    }

    #[test]
    fn masks_are_casemapped_globs_and_any_of_several_matches() {
        let masks = filter("*an1");
        assert!(plain(&masks, "#chan1"));
        assert!(plain(&masks, "#CHAN1"));
        assert!(!plain(&masks, "#chan2"));
        assert!(plain(&filter("#c*n2"), "#chan2"));
        // rfc1459 folds [ to {.
        assert!(plain(&filter("#a[b"), "#A{B"));
        let several = filter("#a,#b");
        assert!(plain(&several, "#a") && plain(&several, "#b") && !plain(&several, "#c"));
        assert!(plain(&filter("?c"), "#c"));
    }

    #[test]
    fn a_negated_mask_excludes_what_it_matches() {
        let negated = filter("!*an1");
        assert!(!plain(&negated, "#chan1"));
        assert!(plain(&negated, "#chan2"));
        let both = filter("#ch*,!*2");
        assert!(plain(&both, "#chan1") && !plain(&both, "#chan2") && !plain(&both, "#other"));
    }

    #[test]
    fn user_counts_are_strict_bounds() {
        assert!(!admits(&filter(">1"), "#a", 1, NOW, None));
        assert!(admits(&filter(">1"), "#a", 2, NOW, None));
        assert!(admits(&filter("<2"), "#a", 1, NOW, None));
        assert!(!admits(&filter("<2"), "#a", 2, NOW, None));
        assert!(!admits(&filter("<1"), "#a", 1, NOW, None));
        // `<0` sets no upper bound, `>-n` no lower one.
        assert!(admits(&filter("<0"), "#a", 5000, NOW, None));
        assert!(admits(&filter(">5,>-1"), "#a", 0, NOW, None));
        let between = filter(">1,<4");
        assert!(!admits(&between, "#a", 1, NOW, None));
        assert!(admits(&between, "#a", 3, NOW, None));
        assert!(!admits(&between, "#a", 4, NOW, None));
    }

    #[test]
    fn creation_time_is_minutes_ago() {
        let old = NOW - 3 * 60;
        let new = NOW - 60;
        let within_two = filter("C<2");
        assert!(!admits(&within_two, "#a", 1, old, None));
        assert!(admits(&within_two, "#a", 1, new, None));
        let before_two = filter("c>2");
        assert!(admits(&before_two, "#a", 1, old, None));
        assert!(!admits(&before_two, "#a", 1, new, None));
        assert!(!admits(&filter("C<0"), "#a", 1, new, None));
        assert!(admits(&filter("C<0"), "#a", 1, NOW, None));
        assert!(admits(&filter("C>0"), "#a", 1, new, None));
    }

    #[test]
    fn topic_time_is_minutes_ago_and_needs_a_topic() {
        let old = Some(NOW - 3 * 60);
        let new = Some(NOW - 60);
        assert!(admits(&filter("T<2"), "#a", 1, NOW, new));
        assert!(!admits(&filter("T<2"), "#a", 1, NOW, old));
        assert!(admits(&filter("t>2"), "#a", 1, NOW, old));
        assert!(!admits(&filter("T>2"), "#a", 1, NOW, new));
        assert!(!admits(&filter("T<10"), "#a", 1, NOW, None));
        assert!(!admits(&filter("T>0"), "#a", 1, NOW, None));
    }

    #[test]
    fn every_condition_must_hold() {
        let combined = filter("#a*,>1,C<10,T>1");
        let topic = Some(NOW - 5 * 60);
        assert!(admits(&combined, "#abc", 2, NOW, topic));
        assert!(!admits(&combined, "#b", 2, NOW, topic));
        assert!(!admits(&combined, "#abc", 1, NOW, topic));
        assert!(!admits(&combined, "#abc", 2, NOW - 3600, topic));
        assert!(!admits(&combined, "#abc", 2, NOW, None));
    }

    #[test]
    fn malformed_parameters_are_refused_whole() {
        for parameter in [
            "foo",
            "<",
            "<x",
            "<5x",
            ">",
            ">x",
            ">-",
            "C",
            "C5",
            "C<",
            "C<x",
            "T=1",
            ",>1",
            ">1,,<5",
            ">1,,",
            "#a,#b,#c,#d,#e,#f,#g,#h",
        ] {
            assert_eq!(
                ListFilter::parse(Some(parameter), NOW, Rfc1459).err(),
                Some(InvalidListParameters),
                "{parameter:?}"
            );
        }
        // One trailing comma is allowed, and seven conditions are.
        assert!(ListFilter::parse(Some(">1,"), NOW, Rfc1459).is_ok());
        assert!(ListFilter::parse(Some("#a,#b,#c,#d,#e,#f,#g"), NOW, Rfc1459).is_ok());
    }

    #[test]
    fn huge_counts_saturate() {
        assert!(admits(
            &filter("C<99999999999999999999999"),
            "#a",
            1,
            0,
            None
        ));
        assert!(!admits(
            &filter(">99999999999999999999999"),
            "#a",
            1_000_000,
            NOW,
            None
        ));
    }
}
