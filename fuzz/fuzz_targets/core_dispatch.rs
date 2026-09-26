#![no_main]

//! Drive the core worker with an arbitrary command stream from one client.
//!
//! The parser targets cover well-formed-in, well-formed-out. This one covers
//! the part with *state*: registration, capability negotiation, channels, and
//! the multiline BATCH machine, where a line's effect depends on every line
//! before it. The core is full of `expect("checked")` invariants that hold
//! across the sequences a normal client produces; a fuzzer's job is to find a
//! sequence that does not.
//!
//! Any panic is the finding — including the debug build's wire check, which
//! aborts on any line the worker builds past the IRC wire limit. There is no
//! oracle beyond "the worker survives whatever a client sends", which is
//! exactly the contract a server owes a hostile peer.
//!
//! The first byte selects the configuration, so the account surface
//! (REGISTER, SASL, services) is reached too: with `sasl_enabled` the worker
//! queues database requests nothing answers, and a full queue is itself a path
//! (every account command refuses loudly when it cannot enqueue).

use e6irc_queue::{Config, Policy, queue};
use e6ircd::core::{ConnId, ConnectionTransport, Core, CoreConfig, Input};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    let (db_tx, _db_rx) = queue(Config {
        name: "fuzz-db",
        capacity: 256,
        policy: Policy::Fifo,
    });
    let mut core = Core::new(
        CoreConfig {
            server_name: "irc.fuzz.example".into(),
            network_name: "Fuzz".into(),
            description: "fuzz server".into(),
            sendq: 512,
            motd: vec!["motd".into()],
            nicklen: 16,
            // No database answers here (`db_rx` is never drained), which
            // the account surface must survive like a stalled one.
            sasl_enabled: selector & 1 != 0,
            opers: vec![("o".into(), "p".into())],
            max_hot_channels: 4,
            clock: || e6irc_proto::time::Millis::from_millis(1_000_000_000),
            mono_clock: || e6irc_proto::time::MonoMillis::from_millis(1_000_000_000),
            command_flood: None,
            registration_burst: None,
            registration_before_connect: selector & 2 != 0,
            registration_require_email: false,
            sasl_requirement: Default::default(),
            reserved_account_names: e6ircd::identity::ReservedAccountNames::default(),
        },
        db_tx,
    );
    let conn = ConnId(1);
    let (tx, mut rx) = queue(Config {
        name: "fuzz-sendq",
        capacity: 512,
        policy: Policy::Fifo,
    });
    core.handle(Input::Open {
        conn,
        tx,
        host: "fuzz.host".into(),
        transport: ConnectionTransport::Tcp,
    });
    // Each input line is one command. Bounded so a huge input is many short
    // runs rather than one enormous one.
    for line in text.split('\n').take(256) {
        core.handle(Input::Line {
            conn,
            line: line.as_bytes().to_vec(),
        });
        // Drain so the send queue cannot fill and mask later commands.
        while rx.try_pop().is_some() {}
    }
    core.handle(Input::Closed {
        conn,
        reason: "fuzz done".into(),
    });
});
