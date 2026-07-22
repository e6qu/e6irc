#![no_main]

//! Drive the core worker with several connections interleaved, plus the events
//! that arrive from outside a client's socket.
//!
//! `core_dispatch` drives one connection, which cannot reach the invariants
//! that only exist *between* connections: nick collisions, kicks and invites,
//! a conversation needing two participants, a multiline batch relayed to
//! someone else. Nor can it reach the events a client never sends — the
//! liveness `Tick` (which closes connections part-way through another's
//! command stream) and the deferred database replies whose whole job is to be
//! ordered against a connection's other output.
//!
//! Each input line is one action, chosen by its first byte:
//!   `0`..`2`  that connection sends the rest of the line
//!   `T`       a liveness tick (the reaper may close connections)
//!   `X`       a connection closes
//!   `O`       a connection sent an over-long line
//!   `H`/`G`   a deferred history / targets page arrives for a connection
//! anything else is a line from connection 0, so a corpus of plain IRC still
//! works and the fuzzer can discover the prefixes by mutation.
//!
//! Any panic is the finding: one worker serves every client, so a panic
//! reached through any connection takes down all of them.

use e6irc_queue::{Config, Policy, Receiver, queue};
use e6ircd::core::{ConnId, Core, CoreConfig, HistoryRow, Input, Output};
use libfuzzer_sys::fuzz_target;

/// Advances on every read, so events get distinct timestamps and the
/// one-stamp-per-message paths are exercised rather than collapsed.
fn advancing_clock() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NOW_MS: AtomicU64 = AtomicU64::new(1_700_000_000_000);
    NOW_MS.fetch_add(1, Ordering::Relaxed)
}

const CONNS: u64 = 3;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (db_tx, _db_rx) = queue(Config {
        name: "fuzz-db",
        capacity: 1024,
        policy: Policy::Fifo,
    });
    let mut core = Core::new(
        CoreConfig {
            server_name: "irc.fuzz.example".into(),
            network_name: "Fuzz".into(),
            description: "fuzz server".into(),
            sendq: 256,
            motd: vec!["motd".into()],
            nicklen: 16,
            sasl_enabled: false,
            opers: vec![("o".into(), "p".into())],
            max_hot_channels: 2,
            clock: advancing_clock,
            command_burst: None,
            registration_before_connect: false,
            registration_require_email: false,
        },
        db_tx,
    );

    let mut rxs: Vec<Receiver<Output>> = Vec::new();
    for id in 0..CONNS {
        let (tx, rx) = queue(Config {
            name: "fuzz-sendq",
            capacity: 256,
            policy: Policy::Fifo,
        });
        rxs.push(rx);
        core.handle(Input::Open {
            conn: ConnId(id),
            tx,
            host: format!("h{id}.example"),
        });
    }

    let mut tick = 1_700_000_000_000u64;
    for raw in text.split('\n').take(256) {
        // Split off the leading *character*: `&raw[1..]` would land inside a
        // multi-byte one and panic in the harness, which looks exactly like a
        // finding until you read the backtrace. (The daemon had this same bug
        // in its BATCH parser; it is an easy one to write.)
        let mut chars = raw.chars();
        let (action, rest) = match chars.next() {
            Some(c) => (u32::from(c).try_into().unwrap_or(0u8), chars.as_str()),
            None => (b'0', ""),
        };
        // The connection an action applies to, when it needs one.
        let pick = |s: &str| ConnId(u64::from(s.bytes().next().unwrap_or(b'0') % CONNS as u8));
        match action {
            b'0'..=b'2' => core.handle(Input::Line {
                conn: ConnId(u64::from(action - b'0')),
                line: rest.as_bytes().to_vec(),
            }),
            b'T' => {
                // Advance far enough that timeouts can actually fire.
                tick += 20_000;
                core.handle(Input::Tick { now: tick });
            }
            b'X' => core.handle(Input::Closed {
                conn: pick(rest),
                reason: "fuzz close".into(),
            }),
            b'O' => core.handle(Input::OverlongLine { conn: pick(rest) }),
            b'H' => core.handle(Input::HistoryPage {
                conn: pick(rest),
                display: rest.get(1..).unwrap_or("#c").to_string(),
                batch_ref: "b".into(),
                rows: vec![HistoryRow {
                    msgid: "m".into(),
                    ts: tick,
                    sender_prefix: "n!u@h".into(),
                    kind: "privmsg".into(),
                    body: rest.to_string(),
                }],
                label: None,
            }),
            b'G' => core.handle(Input::TargetsPage {
                conn: pick(rest),
                batch_ref: "b".into(),
                targets: vec![(rest.get(1..).unwrap_or("#c").to_string(), tick)],
                label: None,
            }),
            _ => core.handle(Input::Line {
                conn: ConnId(0),
                line: raw.as_bytes().to_vec(),
            }),
        }
        // Drain so a full send queue cannot mask later commands.
        for rx in &mut rxs {
            while rx.try_pop().is_some() {}
        }
    }
});
