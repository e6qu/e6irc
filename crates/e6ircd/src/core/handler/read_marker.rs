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
        Some(a) => state.read_markers.get(&(a.clone(), key.clone())).copied(),
        None => state.sessions[&conn].anon_read_markers.get(key).copied(),
    };
    let marker = ms
        .map(|ms| format!("timestamp={}", e6irc_proto::time::server_time(ms)))
        .unwrap_or_else(|| "*".to_string());
    let server = state.config.server_name.clone();
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
    // A logged-in client's markers are account-keyed (shared across the
    // account's connections and persisted); a client that isn't logged in gets
    // per-connection markers (the connection *is* the client), kept in the
    // session and lost on disconnect. Either way MARKREAD works — the spec ties
    // markers to the client, not strictly to an account.
    let account = state.sessions[&conn].account.clone();
    let key = state.chan_key(target);
    let server = state.config.server_name.clone();

    // Query form: MARKREAD <target>
    let Some(&arg) = p.get(1) else {
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
    // The set form is the only path that grows a marker map, so bound the
    // target: a real channel or a valid nick (draft/read-marker allows both
    // channel and direct-message targets).
    if !crate::sanitize::valid_channel_name(target)
        && !crate::sanitize::valid_nick(target, state.config.nicklen)
    {
        markread_fail(state, conn, target, "INVALID_PARAMS", "Invalid target");
        return;
    }

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
    // outlive membership, so a membership gate would not bound the map).
    let is_new = !state
        .read_markers
        .contains_key(&(account.clone(), key.clone()));
    if is_new
        && state
            .read_markers
            .keys()
            .filter(|(a, _)| a == &account)
            .count()
            >= MAX_READ_MARKERS_PER_ACCOUNT
    {
        markread_fail(
            state,
            conn,
            target,
            "INVALID_PARAMS",
            "Too many read markers",
        );
        return;
    }
    // Decide "moved forward" from whether a marker *exists*, not by comparing
    // against a zero sentinel: `Millis(0)` is a legitimate marker value (the Unix
    // epoch, which the timestamp parser accepts), so a `.or_insert(0)` sentinel
    // would make a first-ever set to epoch-0 look like a no-op (`0 > 0` is false)
    // — it would update the in-core mirror but skip the DB write, silently
    // diverging the two. A first set always persists, whatever its value.
    let existing = state
        .read_markers
        .get(&(account.clone(), key.clone()))
        .copied();
    let moved_forward = existing.is_none_or(|cur| new_ms > cur);
    if moved_forward {
        state
            .read_markers
            .insert((account.clone(), key.clone()), new_ms);
        let persist = crate::core::DbRequest::SetReadMarker {
            account: account.clone(),
            target: key.as_str().to_string(),
            marker_ms: new_ms,
        };
        if state.db_tx.try_push(persist).is_err() {
            eprintln!(
                "history: db queue full or closed; read marker for {} not persisted",
                key.as_str()
            );
        }
    }
    let current = existing.map_or(new_ms, |cur| cur.max(new_ms));
    let line = format!(
        ":{server} MARKREAD {target} timestamp={}",
        e6irc_proto::time::server_time(current)
    );
    // A forward move syncs to all the account's clients; a no-op just
    // confirms the current marker to the requester.
    if moved_forward {
        for peer in state.account_connections(&account) {
            state.send(peer, &line);
        }
    } else {
        state.send(conn, &line);
    }
}
