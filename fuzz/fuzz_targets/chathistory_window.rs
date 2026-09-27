#![no_main]

//! The hot history ring and the CHATHISTORY window arithmetic over it, against
//! the database they fall back to.
//!
//! Messages reach a ring out of time order — a conversation's entry from the
//! peer's shard, a wall clock stepped back — and the ring sheds its oldest
//! under an entry cap and a byte budget. The ring is kept sorted by
//! `(ts, arrival)`, which is the database's `(ts, id)` order for the rows one
//! shard both keeps and persists, so a page the ring answers must be the page
//! the database would.
//!
//! This is a **differential** fuzz. Arbitrary arrivals (timestamps in any
//! order, TAGMSGs, client tags of any size) are pushed into a ring with an
//! arbitrary byte budget. The ring must hold, in `(ts, arrival)` order, the
//! newest part of everything it was given with nothing missing inside it, its
//! newest line always among it, and its newest timestamp per scope equal to a
//! recount. Then arbitrary CHATHISTORY windows are resolved against it; every
//! one the ring claims to cover must equal the same window cut from a model of
//! the database, which holds every arrival.

use e6ircd::core::fuzz::{Arrival, footprint, ring_after, window};
use libfuzzer_sys::fuzz_target;

/// A model of the `messages` table for one target: every arrival, as
/// `(ts, arrival index)`, in `(ts, id)` order.
struct Database(Vec<(u64, usize)>);

impl Database {
    /// Rows strictly before a selector's position (an upper-exclusive bound).
    fn before(&self, selector: &Selector) -> Option<usize> {
        Some(match *selector {
            Selector::Msgid(index) => self.0.iter().position(|&(_, i)| i == index)?,
            Selector::Timestamp(t) => self.0.iter().filter(|&&(ts, _)| ts < t).count(),
        })
    }

    /// The first row strictly after a selector's position (a lower-exclusive
    /// bound).
    fn after(&self, selector: &Selector) -> Option<usize> {
        Some(match *selector {
            Selector::Msgid(index) => self.0.iter().position(|&(_, i)| i == index)? + 1,
            Selector::Timestamp(t) => self.0.iter().filter(|&&(ts, _)| ts <= t).count(),
        })
    }

    /// A selector's place in the `(ts, id)` order: a row's own (ids start at
    /// one), a timestamp's before every row stamped with it.
    fn place(&self, selector: &Selector) -> Option<(u64, usize)> {
        match *selector {
            Selector::Msgid(index) => self
                .0
                .iter()
                .find(|&&(_, i)| i == index)
                .map(|&(ts, i)| (ts, i + 1)),
            Selector::Timestamp(t) => Some((t, 0)),
        }
    }

    fn ids(&self, from: usize, to: usize) -> Vec<String> {
        let to = to.min(self.0.len());
        let from = from.min(to);
        self.0[from..to]
            .iter()
            .map(|&(_, i)| format!("m{i}"))
            .collect()
    }

    fn newest(&self, from: usize, to: usize, limit: usize) -> Vec<String> {
        self.ids(to.saturating_sub(limit).max(from), to)
    }

    fn oldest(&self, from: usize, to: usize, limit: usize) -> Vec<String> {
        self.ids(from, from.saturating_add(limit).min(to))
    }

    /// The page a request cuts from the whole record.
    fn page(
        &self,
        sub: Sub,
        first: &Selector,
        second: &Selector,
        limit: usize,
    ) -> Option<Vec<String>> {
        let n = self.0.len();
        Some(match sub {
            Sub::LatestStar => self.newest(0, n, limit),
            Sub::Latest => self.newest(self.after(first)?, n, limit),
            Sub::Before => self.newest(0, self.before(first)?, limit),
            Sub::After => self.oldest(self.after(first)?, n, limit),
            Sub::Around => {
                let pivot = self.before(first)?;
                let older = limit / 2;
                self.ids(pivot.saturating_sub(older), pivot + (limit - older))
            }
            Sub::Between => {
                let newest_first = self.place(first)? > self.place(second)?;
                let (older, newer) = if newest_first {
                    (second, first)
                } else {
                    (first, second)
                };
                let (from, to) = (self.after(older)?, self.before(newer)?);
                if newest_first {
                    self.newest(from, to, limit)
                } else {
                    self.oldest(from, to, limit)
                }
            }
        })
    }
}

#[derive(Debug, Clone, Copy)]
enum Sub {
    LatestStar,
    Latest,
    Before,
    After,
    Around,
    Between,
}

#[derive(Debug, Clone, Copy)]
enum Selector {
    /// The message that arrived `n`th.
    Msgid(usize),
    Timestamp(u64),
}

impl Selector {
    fn wire(self) -> String {
        match self {
            Selector::Msgid(index) => format!("msgid=m{index}"),
            Selector::Timestamp(ms) => format!(
                "timestamp={}",
                e6irc_proto::time::server_time(e6irc_proto::time::Millis::from_millis(ms))
            ),
        }
    }
}

/// Bytes read off the front of the input, zero once it runs out.
struct Input<'a>(&'a [u8]);

impl Input<'_> {
    fn byte(&mut self) -> u8 {
        match self.0.split_first() {
            Some((&first, rest)) => {
                self.0 = rest;
                first
            }
            None => 0,
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let count = usize::from(input.byte() % 64);
    // Timestamps from a narrow range, so they collide and interleave.
    let arrivals: Vec<Arrival> = (0..count)
        .map(|_| {
            let shape = input.byte();
            Arrival {
                ts: 1_000 + u64::from(input.byte() % 32),
                tagmsg: shape & 1 != 0,
                tag_bytes: u16::from(shape >> 1) * 8,
            }
        })
        .collect();
    // A budget of a few ordinary entries, so shedding is common.
    let unit = footprint(Arrival {
        ts: 0,
        tagmsg: false,
        tag_bytes: 0,
    });
    let budget = unit * (1 + usize::from(input.byte() % 16));
    let ring = ring_after(&arrivals, budget);

    let mut database: Vec<(u64, usize)> = arrivals
        .iter()
        .enumerate()
        .map(|(index, arrival)| (arrival.ts, index))
        .collect();
    database.sort();
    let database = Database(database);

    // The ring is the newest part of the record, whole, in its order.
    let held = ring.entries.len();
    let suffix: Vec<(String, u64)> = database.0[database.0.len() - held..]
        .iter()
        .map(|&(ts, index)| (format!("m{index}"), ts))
        .collect();
    assert_eq!(
        ring.entries, suffix,
        "the ring is not the newest part of the record"
    );
    assert_eq!(ring.complete, held == database.0.len());
    if let Some(&(_, newest)) = database.0.last() {
        assert!(held > 0, "the ring lost its newest line (m{newest})");
    }
    let recount = |text_only: bool| {
        ring.entries
            .iter()
            .filter(|(id, _)| {
                let index: usize = id[1..].parse().expect("an arrival index");
                !(text_only && arrivals[index].tagmsg)
            })
            .map(|&(_, ts)| ts)
            .max()
    };
    assert_eq!(ring.latest_text, recount(true));
    assert_eq!(ring.latest_all, recount(false));

    // Windows the ring covers are the database's windows.
    for _ in 0..8 {
        let shape = input.byte();
        let sub = match shape % 6 {
            0 => Sub::LatestStar,
            1 => Sub::Latest,
            2 => Sub::Before,
            3 => Sub::After,
            4 => Sub::Around,
            _ => Sub::Between,
        };
        let mut selector = || {
            let pick = input.byte();
            if pick & 1 == 0 && count > 0 {
                Selector::Msgid(usize::from(pick >> 1) % count)
            } else {
                Selector::Timestamp(998 + u64::from(pick >> 1) % 36)
            }
        };
        let (first, second) = (selector(), selector());
        let limit = 1 + usize::from(shape >> 3) % 8;
        let (name, first_wire, second_wire) = match sub {
            Sub::LatestStar => ("LATEST", "*".to_string(), "*".to_string()),
            Sub::Latest => ("LATEST", first.wire(), "*".to_string()),
            Sub::Before => ("BEFORE", first.wire(), "*".to_string()),
            Sub::After => ("AFTER", first.wire(), "*".to_string()),
            Sub::Around => ("AROUND", first.wire(), "*".to_string()),
            Sub::Between => ("BETWEEN", first.wire(), second.wire()),
        };
        let Some((page, covered)) = window(&ring, name, &first_wire, &second_wire, limit) else {
            panic!("a well-formed request was refused: {name} {first_wire} {second_wire}");
        };
        if !covered {
            continue;
        }
        let expected = database.page(sub, &first, &second, limit);
        match expected {
            Some(expected) => assert_eq!(
                page, expected,
                "{name} {first_wire} {second_wire} {limit}: ring {:?}",
                ring.entries
            ),
            // A msgid the database does not hold: nothing the ring could hold.
            None => assert!(page.is_empty(), "{name} {first_wire}: {page:?}"),
        }
    }
});
