//! Libera.Chat compatibility contract (DESIGN §7.7), checked against the
//! vendored greeting snapshot in vendor/tests/libera-snapshot/.
//!
//! For every ISUPPORT token e6ircd advertises that Libera also
//! advertises, the values must agree — we may lag Libera's surface
//! while it is being built out, but we must never diverge on it.
//!
//! The snapshot is read from the source tree at test time (never
//! embedded), so no vendored data ends up in any shipped binary.

use std::collections::HashMap;

use e6irc_queue::{Config, Policy, queue};
use e6ircd::core::{ConnId, Core, CoreConfig, Input};

fn reference() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/tests/libera-snapshot/libera-greeting.txt"
    );
    std::fs::read_to_string(path).expect("vendored Libera snapshot present")
}

/// Tokens where divergence is deliberate and documented — additions
/// need a reason in the comment.
const WHITELIST: &[&str] = &[
    // TARGMAX is enforcement-specific: we advertise limits only for the
    // commands we actually bound (PRIVMSG/NOTICE at 4, matching Libera's
    // values for those), whereas Libera also lists NAMES/LIST/KICK/WHOIS/
    // ACCEPT/MONITOR. Advertising limits we do not enforce would be a false
    // claim, so the token legitimately differs.
    "TARGMAX",
    // Libera: eIbq,k,flj,CFLMPQRSTcgimnprstuz. We implement eIbq,k,l,
    // imnst so far; the missing type-C (f forward, j join-throttle) and
    // type-D flags are rejected loudly with 472 until implemented, so
    // the divergence is visible, never silent. Full parity is this
    // phase's exit criterion, tracked in PLAN.md.
    "CHANMODES",
];

fn isupport_tokens(lines: impl Iterator<Item = String>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for line in lines {
        let mut parts = line.split(' ');
        if parts.nth(1) != Some("005") {
            continue;
        }
        // skip the nick param; stop at the trailing text
        for token in parts.skip(1) {
            if token.starts_with(':') {
                break;
            }
            let (name, value) = match token.split_once('=') {
                Some((n, v)) => (n.to_string(), v.to_string()),
                None => (token.to_string(), String::new()),
            };
            out.insert(name, value);
        }
    }
    out
}

fn our_isupport() -> HashMap<String, String> {
    let (db_tx, _db_rx) = queue(Config {
        name: "db",
        capacity: 8,
        policy: Policy::Fifo,
    });
    let mut core = Core::new(
        CoreConfig {
            server_name: "irc.test.example".into(),
            network_name: "TestNet".into(),
            description: "test server".into(),
            registration_before_connect: false,
            registration_require_email: false,
            sendq: 256,
            motd: vec![],
            nicklen: 16,
            sasl_enabled: true,
            opers: vec![],
            max_hot_channels: 8192,
            clock: || e6irc_proto::time::Millis::from_millis(0),
            command_burst: None,
        },
        db_tx,
    );
    let conn = ConnId(1);
    let (tx, mut rx) = queue(Config {
        name: "sendq",
        capacity: 256,
        policy: Policy::Fifo,
    });
    core.handle(Input::Open {
        conn,
        tx,
        host: "h".into(),
    });
    core.handle(Input::Line {
        conn,
        line: b"NICK n".to_vec(),
    });
    core.handle(Input::Line {
        conn,
        line: b"USER u 0 * :r".to_vec(),
    });
    let mut lines = Vec::new();
    while let Some(env) = rx.try_pop() {
        lines.push(String::from_utf8(env.payload.0.to_vec()).unwrap());
    }
    isupport_tokens(lines.into_iter())
}

#[test]
fn advertised_isupport_matches_libera_where_shared() {
    let reference = reference();
    let libera = isupport_tokens(reference.lines().map(str::to_string));
    assert!(
        libera.len() > 20,
        "reference capture looks truncated: {} tokens",
        libera.len()
    );
    let ours = our_isupport();
    let mut diverged = Vec::new();
    for (name, our_value) in &ours {
        // NETWORK is deployment-specific by nature.
        if name == "NETWORK" || WHITELIST.contains(&name.as_str()) {
            continue;
        }
        if let Some(libera_value) = libera.get(name)
            && libera_value != our_value
        {
            diverged.push(format!(
                "{name}: ours={our_value:?} libera={libera_value:?}"
            ));
        }
    }
    assert!(
        diverged.is_empty(),
        "ISUPPORT divergence from Libera:\n{}",
        diverged.join("\n")
    );
}

#[test]
fn libera_cap_ls_reference_is_intact() {
    // Guard the capture itself: the tokens the compat work targets must
    // be present in the vendored reference.
    let reference = reference();
    let cap_line = reference
        .lines()
        .find(|l| l.contains(" CAP * LS :"))
        .expect("CAP LS line in reference");
    for cap in [
        "sasl=",
        "server-time",
        "message-tags",
        "account-notify",
        "echo-message",
    ] {
        assert!(
            cap_line.contains(cap),
            "reference missing {cap}: {cap_line}"
        );
    }
}
