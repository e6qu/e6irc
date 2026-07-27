//! draft/read-marker: per-target read positions.

use super::*;

// ---- read-marker (draft/read-marker) ------------------------------------

pub(super) fn markread_fail(
    state: &mut ServerState,
    conn: ConnId,
    target: &str,
    code: &str,
    detail: &str,
) {
    let server = state.config.server_name.clone();
    let target = clip_echo(target);
    state.send(
        conn,
        &format!(":{server} FAIL MARKREAD {code} {target} :{detail}"),
    );
}

/// Send `conn` the current read marker for `key` (displayed as `display`),
/// resolving from the account map when logged in or the session-local map
/// otherwise, and `*` when none is set. Shared by the MARKREAD query form and
/// the on-JOIN replay.
pub(super) fn send_current_markread(
    state: &mut ServerState,
    conn: ConnId,
    key: &ChanKey,
    display: &str,
) {
    let account = state.sessions[&conn].account.clone();
    let ms = match &account {
        Some(a) => state
            .read_markers
            .get(&(state.account_key(a), key.clone()))
            .copied(),
        None => state.sessions[&conn].anon_read_markers.get(key).copied(),
    };
    let marker = ms
        .map(|ms| format!("timestamp={}", e6irc_proto::time::server_time(ms)))
        .unwrap_or_else(|| "*".to_string());
    let server = state.config.server_name.clone();
    let display = clip_echo(display);
    state.send(conn, &format!(":{server} MARKREAD {display} {marker}"));
}

pub(super) fn cmd_markread(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    if !state.sessions[&conn].caps.read_marker {
        state.numeric(
            conn,
            ERR_UNKNOWNCOMMAND,
            &["MARKREAD"],
            Some("Unknown command"),
        );
        return;
    }
    let Some(&target) = p.first() else {
        // MARKREAD is an IRCv3 command: errors are `FAIL`, not legacy numerics.
        markread_fail(
            state,
            conn,
            "*",
            "NEED_MORE_PARAMS",
            "Not enough parameters",
        );
        return;
    };
    // Both forms echo the target. Validate before the query/set split so the
    // query form cannot reflect a client-sized invalid token into an overlong
    // server line, and cannot query names the set form would reject.
    if !crate::sanitize::valid_channel_name(target)
        && !crate::sanitize::valid_nick(target, state.config.nicklen)
    {
        markread_fail(state, conn, target, "INVALID_PARAMS", "Invalid target");
        return;
    }
    // A logged-in client's markers are account-keyed (shared across the
    // account's connections and persisted); a client that isn't logged in gets
    // per-connection markers (the connection *is* the client), kept in the
    // session and lost on disconnect. Either way MARKREAD works — the spec ties
    // markers to the client, not strictly to an account.
    let account = state.sessions[&conn].account.clone();
    let key = state.chan_key(target);
    let server = state.config.server_name.clone();
    let marker_pending = account.as_ref().is_some_and(|account| {
        state
            .pending_read_markers
            .contains_key(&(state.account_key(account), key.clone()))
    });
    let output_held = state.sessions[&conn].deferred_replies > 0;

    // Query form: MARKREAD <target>
    let Some(&arg) = p.get(1) else {
        // A query whose output is held while this target has an update pending
        // cannot precompute the old value: it could be released after the new
        // value and appear to move the marker backwards.
        if marker_pending && output_held {
            markread_fail(
                state,
                conn,
                target,
                "TEMPORARILY_UNAVAILABLE",
                "Read marker update in progress",
            );
            return;
        }
        send_current_markread(state, conn, &key, target);
        return;
    };

    // Set form: MARKREAD <target> timestamp=<iso>
    let Some(ts) = arg.strip_prefix("timestamp=") else {
        markread_fail(state, conn, target, "INVALID_PARAMS", "Expected timestamp=");
        return;
    };
    // Millisecond precision: a marker must round-trip its `.mmm` fraction, so
    // parse to millis (not seconds) and store that.
    let Some(new_ms) = e6irc_proto::time::parse_server_time_millis(ts) else {
        markread_fail(state, conn, target, "INVALID_PARAMS", "Malformed timestamp");
        return;
    };
    let Some(account) = account else {
        // Not logged in: session-local marker, capped, monotonic, replied only
        // to this connection (there are no sibling connections to sync).
        let markers = &mut state
            .sessions
            .get_mut(&conn)
            .expect("checked")
            .anon_read_markers;
        if !markers.contains_key(&key) && markers.len() >= MAX_READ_MARKERS_PER_ACCOUNT {
            markread_fail(
                state,
                conn,
                target,
                "INVALID_PARAMS",
                "Too many read markers",
            );
            return;
        }
        let slot = markers
            .entry(key)
            .or_insert(e6irc_proto::time::Millis::from_millis(0));
        *slot = (*slot).max(new_ms);
        let current = *slot;
        state.send(
            conn,
            &format!(
                ":{server} MARKREAD {target} timestamp={}",
                e6irc_proto::time::server_time(current)
            ),
        );
        return;
    };

    // Logged in: account-keyed marker — persisted and synced to the account's
    // other connections. An account may retain only so many markers (they
    // outlive membership, so a membership gate would not bound the map). The
    // in-core map is keyed by the folded `AccountKey`, so a marker set as "Alice"
    // and later queried as "alice" resolves to one entry, not two.
    let account_key = state.account_key(&account);
    let marker_key = (account_key.clone(), key.clone());
    let is_new = !state.read_markers.contains_key(&marker_key)
        && !state.pending_read_markers.contains_key(&marker_key);
    let confirmed_count = state
        .read_markers
        .keys()
        .filter(|(a, _)| a == &account_key)
        .count();
    let pending_only_count = state
        .pending_read_markers
        .keys()
        .filter(|pending @ (a, _)| a == &account_key && !state.read_markers.contains_key(*pending))
        .count();
    if is_new && confirmed_count + pending_only_count >= MAX_READ_MARKERS_PER_ACCOUNT {
        markread_fail(
            state,
            conn,
            target,
            "INVALID_PARAMS",
            "Too many read markers",
        );
        return;
    }
    // A request at or behind a value that was already confirmed durable needs
    // no write. Everything else waits for PostgreSQL: mutating the hot mirror
    // and broadcasting first would make a queue/store failure look successful
    // until the next restart exposed the lost marker.
    let existing = state.read_markers.get(&marker_key).copied();
    if !marker_pending
        && let Some(current) = existing
        && new_ms <= current
    {
        state.send(
            conn,
            &format!(
                ":{server} MARKREAD {target} timestamp={}",
                e6irc_proto::time::server_time(current)
            ),
        );
        return;
    }

    let label = state.capture.as_ref().and_then(|cap| cap.label.clone());
    let persist = crate::core::DbRequest::SetReadMarker {
        conn,
        account: account.clone(),
        target: key.as_str().to_string(),
        display: target.to_string(),
        marker_ms: new_ms,
        label,
    };
    if state.db_tx.try_push(persist).is_err() {
        markread_fail(
            state,
            conn,
            target,
            "TEMPORARILY_UNAVAILABLE",
            "Read marker could not be persisted",
        );
        return;
    }

    *state.pending_read_markers.entry(marker_key).or_default() += 1;
    state.defer_reply(conn);
    if let Some(cap) = state.capture.as_mut()
        && cap.label.is_some()
    {
        cap.deferred = true;
    }
}

fn release_pending_marker(state: &mut ServerState, account: &str, target: &str) {
    let key = (state.account_key(account), state.chan_key(target));
    match state.pending_read_markers.entry(key) {
        std::collections::hash_map::Entry::Occupied(mut entry) if *entry.get() > 1 => {
            *entry.get_mut() -= 1;
        }
        std::collections::hash_map::Entry::Occupied(entry) => {
            entry.remove();
        }
        std::collections::hash_map::Entry::Vacant(_) => {
            eprintln!(
                "core: invariant violation: read-marker DB reply without a pending reservation"
            );
        }
    }
}

pub(super) fn read_marker_stored(
    state: &mut ServerState,
    conn: ConnId,
    account: String,
    target: String,
    display: String,
    marker_ms: e6irc_proto::time::Millis,
    label: Option<String>,
) {
    release_pending_marker(state, &account, &target);
    let marker_key = (state.account_key(&account), state.chan_key(&target));
    let moved_forward = state
        .read_markers
        .insert(marker_key, marker_ms)
        .is_none_or(|previous| marker_ms > previous);
    let server = state.config.server_name.clone();
    let line = format!(
        ":{server} MARKREAD {} timestamp={}",
        clip_echo(&display),
        e6irc_proto::time::server_time(marker_ms)
    );

    // A durable forward move syncs to the account's other registered clients
    // that negotiated the capability. The requester is emitted separately so
    // its deferred ordering and label are preserved, including if it changed
    // accounts while the write was in flight.
    if moved_forward {
        for peer in state.account_connections(&account) {
            if peer != conn
                && state
                    .sessions
                    .get(&peer)
                    .is_some_and(|session| session.is_registered() && session.caps.read_marker)
            {
                state.send(peer, &line);
            }
        }
    }
    if state.sessions.contains_key(&conn) {
        state.emit_deferred_labeled(conn, label, move |state| {
            state.send(conn, &line);
        });
    }
}

pub(super) fn read_marker_unavailable(
    state: &mut ServerState,
    conn: ConnId,
    account: String,
    target: String,
    display: String,
    label: Option<String>,
) {
    release_pending_marker(state, &account, &target);
    if state.sessions.contains_key(&conn) {
        state.emit_deferred_labeled(conn, label, move |state| {
            markread_fail(
                state,
                conn,
                &display,
                "TEMPORARILY_UNAVAILABLE",
                "Read marker could not be persisted",
            );
        });
    }
}
