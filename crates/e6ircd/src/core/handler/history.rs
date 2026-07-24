//! CHATHISTORY: the hot ring and its PostgreSQL fallback.

use super::*;

// ---- CHATHISTORY (draft/chathistory, hot ring) --------------------------

/// A CHATHISTORY selector is a supported message reference: the open bound
/// `*`, a `msgid=`, or a `timestamp=`. Anything else is INVALID_MSGREFTYPE.
pub(super) fn is_valid_msgref(sel: &str) -> bool {
    sel == "*" || sel.starts_with("msgid=") || sel.starts_with("timestamp=")
}

/// Emit a draft/chathistory `FAIL`. `context` carries the spec's positional
/// params for the code — the subcommand, and for target errors the target —
/// which a client needs to attribute the failure to the request it made.
pub(super) fn chathistory_fail(
    state: &mut ServerState,
    conn: ConnId,
    code: &str,
    context: &[&str],
    detail: &str,
) {
    let server = state.config.server_name.clone();
    let mut line = format!(":{server} FAIL CHATHISTORY {code}");
    for param in context {
        line.push(' ');
        // Context params echo the client's own subcommand/target for
        // attribution; clipped so the FAIL explaining an error is never itself
        // discarded for length.
        line.push_str(crate::core::handler::clip_echo(param));
    }
    line.push_str(" :");
    line.push_str(detail);
    state.send(conn, &line);
}

/// Serve history from the channel's hot ring, falling back to PostgreSQL
/// for windows the ring no longer fully covers. The ring answers directly
/// while it holds the channel's entire history; once it has overflowed or
/// been evicted, a request that reaches older than the ring is resolved
/// against the `messages` table by composite `(ts, id)` position.
pub(super) fn cmd_chathistory(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let caps = state.sessions[&conn].caps;
    if !caps.batch || !caps.chathistory {
        chathistory_fail(
            state,
            conn,
            "NEED_CAPS",
            &[],
            "batch and draft/chathistory required",
        );
        return;
    }
    // TARGETS enumerates buffers, not a single channel — handle it before
    // the channel-target parsing below.
    if p.first().is_some_and(|s| s.eq_ignore_ascii_case("TARGETS")) {
        chathistory_targets(state, conn, p);
        return;
    }
    let (Some(&sub), Some(&target)) = (p.first(), p.get(1)) else {
        let sub = p.first().copied().unwrap_or("*");
        chathistory_fail(
            state,
            conn,
            "NEED_MORE_PARAMS",
            &[sub],
            "Missing parameters",
        );
        return;
    };
    // A channel target requires membership. Any other target names the other
    // participant in a direct-message conversation, which the requester is a
    // participant of by construction — the key is derived from their own nick,
    // so a client can only ever ask for a conversation it is part of.
    let hist_key = if target.starts_with('#') {
        let key = state.chan_key(target);
        let is_member = state
            .channels
            .get(&key)
            .is_some_and(|c| c.members.contains_key(&conn));
        if !is_member {
            chathistory_fail(
                state,
                conn,
                "INVALID_TARGET",
                &[sub, target],
                "You are not on that channel",
            );
            return;
        }
        crate::core::state::HistoryKey::from(&key)
    } else {
        if state.sessions[&conn].nick.is_none() {
            chathistory_fail(
                state,
                conn,
                "INVALID_TARGET",
                &[sub, target],
                "You are not registered",
            );
            return;
        }
        state
            .dm_conversation(&state.conn_identity(conn), &state.nick_identity(target))
            .0
    };
    // BETWEEN takes two selectors then the limit; the others take one
    // selector then the limit.
    let is_between = sub.eq_ignore_ascii_case("BETWEEN");
    let selector = p.get(2).copied().unwrap_or("*");
    let selector2 = p.get(3).copied().unwrap_or("*");
    // An unrecognized message-reference type is INVALID_MSGREFTYPE, not a
    // silently-empty batch (we advertise MSGREFTYPES=msgid,timestamp).
    let refs: &[&str] = if is_between {
        &[selector, selector2]
    } else {
        &[selector]
    };
    if refs.iter().any(|s| !is_valid_msgref(s)) {
        chathistory_fail(
            state,
            conn,
            "INVALID_MSGREFTYPE",
            &[sub, target],
            "Unknown message reference type",
        );
        return;
    }
    // `*` is the open bound, meaningful *only* for LATEST. For BEFORE/AFTER/
    // AROUND — and for either bound of BETWEEN — it is not a real selector, and
    // accepting it silently yields the wrong window: an empty batch for the
    // one-selector forms, or a full unbounded scan for BETWEEN (both selectors
    // resolve to "no position", degenerating to `0 .. u64::MAX`). Reject it as
    // INVALID_PARAMS rather than answer a malformed request with wrong data.
    if !sub.eq_ignore_ascii_case("LATEST") && refs.contains(&"*") {
        chathistory_fail(
            state,
            conn,
            "INVALID_PARAMS",
            &[sub, target],
            "* is only a valid selector for LATEST",
        );
        return;
    }
    // A `timestamp=` selector whose value is not a valid server-time is
    // malformed. Reject it up front instead of letting `selector_ts` silently
    // default the bound (to 0, or `u64::MAX as i64 == -1`), which would answer a
    // garbage request with the latest N messages or a silently-empty window.
    if refs.iter().any(|s| {
        s.strip_prefix("timestamp=")
            .is_some_and(|v| e6irc_proto::time::parse_server_time_millis(v).is_none())
    }) {
        chathistory_fail(
            state,
            conn,
            "INVALID_PARAMS",
            &[sub, target],
            "Malformed timestamp= selector",
        );
        return;
    }
    // The limit must be a positive integer — never silently default it.
    let limit: usize = match p
        .get(if is_between { 4 } else { 3 })
        .map(|l| l.parse::<usize>())
    {
        Some(Ok(n)) if n > 0 => n.min(500),
        _ => {
            chathistory_fail(
                state,
                conn,
                "INVALID_PARAMS",
                &[sub, target],
                "limit must be a positive integer",
            );
            return;
        }
    };
    let (history, complete) = state.history_ring(&hist_key);

    // Pure resolution of the requested window against the in-memory ring;
    // `None` is an unknown subcommand. Extracted so the arithmetic — which has
    // carried off-by-one and paging-direction bugs — is unit- and
    // differentially-fuzz-testable in isolation from the I/O around it.
    let Some((entries, covered)) =
        resolve_ring_window(&history, complete, sub, selector, selector2, limit)
    else {
        chathistory_fail(
            state,
            conn,
            "INVALID_PARAMS",
            &[sub, target],
            &format!("Unknown subcommand {sub}"),
        );
        return;
    };

    // The batch names the target the client asked for, echoed as given; the
    // replayed messages carry their own canonical addressing (history_page).
    // A live channel supplies its own (≤ CHANNELLEN) display name; the fallback
    // echoes the raw target, which for a DM correspondent or a never-joined
    // name is bounded only by the input frame — clip it so the batch open and
    // every replayed line stay inside the wire limit.
    let display = state
        .chan_key_if_channel(target)
        .and_then(|k| state.channels.get(&k).map(|c| c.name.clone()))
        .unwrap_or_else(|| crate::core::handler::clip_echo(target).to_string());
    let batch_ref = state.next_msgid();

    // Ring miss with a database available: page from PostgreSQL instead,
    // preserving one code path for rendering (history_page).
    if !covered && state.config.sasl_enabled {
        // A msgid selector pages on the composite (ts, id) via a msgid pivot,
        // which stays exact even if two messages share a millisecond; a
        // timestamp selector uses the millisecond ts bound.
        let msgid_of = |sel: &str| sel.strip_prefix("msgid=").map(str::to_string);
        let query = match sub.to_ascii_uppercase().as_str() {
            // `LATEST <target> * <limit>` is unbounded; any other selector
            // bounds it to messages strictly newer than the selector.
            "LATEST" if selector == "*" => crate::core::HistoryQuery::Latest { limit },
            "LATEST" => match msgid_of(selector) {
                Some(msgid) => crate::core::HistoryQuery::LatestAfterMsgid { msgid, limit },
                None => crate::core::HistoryQuery::LatestAfter {
                    after_ts: selector_ts(&history, selector)
                        .unwrap_or(e6irc_proto::time::Millis::from_millis(0)),
                    limit,
                },
            },
            "BEFORE" => match msgid_of(selector) {
                Some(msgid) => crate::core::HistoryQuery::BeforeMsgid { msgid, limit },
                None => crate::core::HistoryQuery::Before {
                    before_ts: selector_ts(&history, selector)
                        .unwrap_or(e6irc_proto::time::Millis::from_millis(u64::MAX)),
                    limit,
                },
            },
            "AROUND" => match msgid_of(selector) {
                Some(msgid) => crate::core::HistoryQuery::AroundMsgid { msgid, limit },
                None => crate::core::HistoryQuery::Around {
                    around_ts: selector_ts(&history, selector)
                        .unwrap_or(e6irc_proto::time::Millis::from_millis(0)),
                    limit,
                },
            },
            // Both selectors travel to the DB as-is; it resolves each pivot's
            // `(ts, id)` position and derives the span and paging direction
            // there. This is the fix for the ring-only mis-resolution: a `msgid=`
            // pivot that has scrolled out of the ring used to lose its bound
            // (mixed with a timestamp) or collapse the direction to oldest-first
            // (two msgids), returning the wrong or an empty (inverted) window.
            "BETWEEN" => crate::core::HistoryQuery::BetweenSelectors {
                first: selector_bound(selector),
                second: selector_bound(selector2),
                limit,
            },
            _ => match msgid_of(selector) {
                Some(msgid) => crate::core::HistoryQuery::AfterMsgid { msgid, limit },
                None => crate::core::HistoryQuery::After {
                    after_ts: selector_ts(&history, selector)
                        .unwrap_or(e6irc_proto::time::Millis::from_millis(0)),
                    limit,
                },
            },
        };
        // Carry the labeled-response label (if any) onto the deferred batch.
        let label = state.capture.as_ref().and_then(|c| c.label.clone());
        let request = crate::core::DbRequest::QueryHistory {
            conn,
            target: hist_key.as_str().to_string(),
            display: display.clone(),
            batch_ref,
            query,
            label,
        };
        if state.db_tx.try_push(request).is_err() {
            // Enqueue failed: fall through to a synchronous FAIL, which the
            // labeled-response framer still handles normally.
            chathistory_fail(
                state,
                conn,
                "MESSAGE_ERROR",
                &[sub, target],
                "History temporarily unavailable",
            );
        } else {
            // Queued: hold this connection's later output behind the batch so
            // the reply order matches the command order.
            state.defer_reply(conn);
            if let Some(cap) = state.capture.as_mut() {
                // The labeled batch is emitted when the DB replies, so tell the
                // framer not to ACK this command as an empty response.
                if cap.label.is_some() {
                    cap.deferred = true;
                }
            }
        }
        return;
    }

    let rows: Vec<crate::core::HistoryRow> = entries
        .into_iter()
        .map(|e| crate::core::HistoryRow {
            msgid: e.msgid,
            ts: e.ts,
            sender_prefix: e.sender_prefix,
            kind: e.kind,
            body: e.body,
        })
        .collect();
    // Ring path runs under labeled-response capture; frame_labeled applies the
    // label, so history_page must not (pass None). The ring read cannot fail,
    // so the page is always `Ok`.
    history_page(state, conn, &display, &batch_ref, Ok(rows), None);
}

/// The correspondent in a conversation key, from `me`'s point of view, or
/// `None` when the key names a channel or a conversation `me` is not part of.
/// A conversation with oneself yields oneself.
pub(super) fn dm_correspondent(key: &crate::core::state::HistoryKey, me: &str) -> Option<String> {
    let raw = key.as_str();
    if raw.starts_with('#') {
        return None;
    }
    let (lo, hi) = raw.split_once('!')?;
    if lo == me {
        Some(hi.to_string())
    } else if hi == me {
        Some(lo.to_string())
    } else {
        None
    }
}

/// CHATHISTORY TARGETS: enumerate the requester's buffers with activity
/// strictly inside a `timestamp=<a> timestamp=<b> <limit>` window — the bounds
/// are exclusive, as they are for BETWEEN (DESIGN §11.2). A
/// bouncer/multi-buffer client uses this to find which buffers have backlog
/// on reconnect. Targets are the channels the requester is on *and* the
/// correspondents they have exchanged direct messages with; the authoritative
/// source is PostgreSQL, with the hot rings answering when no database is
/// configured. Ordered oldest-activity-first, so a limit keeps the oldest.
pub(super) fn chathistory_targets(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let parse = |i: usize| {
        p.get(i)
            .and_then(|s| s.strip_prefix("timestamp="))
            .and_then(e6irc_proto::time::parse_server_time_millis)
    };
    let (Some(a), Some(b)) = (parse(1), parse(2)) else {
        chathistory_fail(
            state,
            conn,
            "INVALID_PARAMS",
            &["TARGETS"],
            "Expected two timestamp= bounds",
        );
        return;
    };
    let (min_ts, max_ts) = if a <= b { (a, b) } else { (b, a) };
    let limit = p
        .get(3)
        .and_then(|l| l.parse::<usize>().ok())
        .unwrap_or(100)
        .clamp(1, 500);

    // Visible targets are the channels the requester is on, plus every
    // conversation they take part in. (No early return on "no channels": a
    // client with only direct messages still has buffers to report.)
    let keys: Vec<crate::core::state::ChanKey> =
        state.sessions[&conn].channels.iter().cloned().collect();
    let me = state.conn_identity(conn);
    let batch_ref = state.next_msgid();

    if state.config.sasl_enabled {
        let channels = keys.iter().map(|k| k.as_str().to_string()).collect();
        // Carry the labeled-response label (if any) onto the deferred batch.
        let label = state.capture.as_ref().and_then(|c| c.label.clone());
        let request = crate::core::DbRequest::QueryTargets {
            conn,
            channels,
            me,
            min_ts,
            max_ts,
            limit,
            batch_ref,
            label,
        };
        if state.db_tx.try_push(request).is_err() {
            // Enqueue failed: fall through to a synchronous FAIL the framer
            // still handles normally.
            chathistory_fail(
                state,
                conn,
                "MESSAGE_ERROR",
                &["TARGETS"],
                "History temporarily unavailable",
            );
        } else {
            state.defer_reply(conn);
            if let Some(cap) = state.capture.as_mut() {
                // The labeled batch is emitted when the DB replies, so don't
                // ACK this command as an empty response.
                if cap.label.is_some() {
                    cap.deferred = true;
                }
            }
        }
        return;
    }

    // No database: enumerate from the hot rings.
    // A buffer qualifies on its *latest* message falling inside the window,
    // not on merely containing one: newer activity means the client has
    // already moved past it.
    let latest_in_window = |state: &ServerState,
                            key: &crate::core::state::HistoryKey|
     -> Option<e6irc_proto::time::Millis> {
        let latest = state.history.get(key)?.entries.iter().map(|e| e.ts).max()?;
        (latest > min_ts && latest < max_ts).then_some(latest)
    };
    let mut targets: Vec<(String, e6irc_proto::time::Millis)> = Vec::new();
    for key in &keys {
        if let Some(latest) = latest_in_window(state, &key.into())
            && let Some(chan) = state.channels.get(key)
        {
            targets.push((chan.name.clone(), latest));
        }
    }
    // Conversations: every hot key that is not a channel and lists the
    // requester as a participant. The correspondent is the other participant
    // (or the requester, for a conversation with oneself).
    let conversations: Vec<(crate::core::state::HistoryKey, String)> = state
        .history
        .keys()
        .filter_map(|k| dm_correspondent(k, &me).map(|peer| (k.clone(), peer)))
        .collect();
    for (key, peer) in conversations {
        if let Some(latest) = latest_in_window(state, &key) {
            // Push the raw correspondent *identity*; `targets_page` is the single
            // site that resolves an identity to a display nick, so this path and
            // the DB path (which also yields identities) convert identically.
            targets.push((peer, latest));
        }
    }
    // Oldest activity first; a limit therefore keeps the oldest buffers.
    targets.sort_by_key(|t| t.1);
    targets.truncate(limit);
    // No-DB path runs under labeled-response capture; frame_labeled applies it.
    // The ring enumeration cannot fail, so the page is always `Ok`.
    targets_page(state, conn, &batch_ref, Ok(targets), None);
}

/// Emit a `draft/chathistory-targets` batch: one `CHATHISTORY TARGETS
/// <target> <time>` line per buffer, ordered by last activity oldest-first (so
/// a `limit` keeps the oldest buffers — the ones a reconnecting client is most
/// at risk of having missed).
pub(crate) fn targets_page(
    state: &mut ServerState,
    conn: ConnId,
    batch_ref: &str,
    targets: Result<Vec<(String, e6irc_proto::time::Millis)>, ()>,
    label: Option<&str>,
) {
    // A store fault answers with a FAIL, not an empty batch — see history_page
    // for the reasoning (an empty page is indistinguishable from "no buffers").
    let targets = match targets {
        Ok(targets) => targets,
        Err(()) => {
            let line = match label {
                Some(label) => format!(
                    "@label={label} :{} FAIL CHATHISTORY MESSAGE_ERROR TARGETS :History temporarily unavailable",
                    state.config.server_name,
                ),
                None => format!(
                    ":{} FAIL CHATHISTORY MESSAGE_ERROR TARGETS :History temporarily unavailable",
                    state.config.server_name,
                ),
            };
            state.send(conn, &line);
            return;
        }
    };
    let server = state.config.server_name.clone();
    // `label` is set only on the async DB path (produced outside the
    // synchronous labeled-response capture), so it labels its own BATCH open;
    // the in-memory path runs under capture with `None` and is framed by
    // frame_labeled instead — mirroring history_page.
    let open = match label {
        Some(label) => {
            format!("@label={label} :{server} BATCH +{batch_ref} draft/chathistory-targets")
        }
        None => format!(":{server} BATCH +{batch_ref} draft/chathistory-targets"),
    };
    state.send(conn, &open);
    for (target, ts) in targets {
        // A channel target: prefer its live display name. Anything else is a DM
        // correspondent stored as an *identity* (`~nick` or a folded account) —
        // resolve it to the display nick here, the one conversion site for both
        // the in-memory and DB paths, so a client never receives a `~`-prefixed
        // non-target. (identity_nick passes a channel name through unchanged, so
        // an evicted channel still emits its own name.)
        let key = state.chan_key(&target);
        let display = match state.channels.get(&key) {
            Some(c) => c.name.clone(),
            None => state.identity_nick(&target),
        };
        let time = e6irc_proto::time::server_time(ts);
        // A legitimate target is a channel (≤ CHANNELLEN) or a correspondent
        // nick (≤ nicklen), always short — but the value flows from a stored
        // conversation key derived from identities, so clip it to keep this
        // line inside the wire limit regardless of how it was produced.
        let display = crate::core::handler::clip_echo(&display);
        state.send(
            conn,
            &format!("@batch={batch_ref} :{server} CHATHISTORY TARGETS {display} {time}"),
        );
    }
    state.send(conn, &format!(":{server} BATCH -{batch_ref}"));
}

/// A ring-missing reference needs PostgreSQL when the ring is full
/// (older rows may exist) and the selector is a timestamp we can bound
/// on directly. A msgid absent from the ring is treated as ring-empty
/// (returns nothing) rather than triggering an unbounded DB scan.
/// Resolve a CHATHISTORY request against the in-memory ring, purely.
///
/// Returns the matching entries (oldest-first, as stored) and whether the ring
/// *covers* the request — `false` means the window reaches older than the ring
/// holds and PostgreSQL must serve it. `None` is an unknown subcommand. `sub` is
/// matched case-insensitively; `selector`/`selector2` are `msgid=`/`timestamp=`
/// references (or `*`), `limit` the requested count.
///
/// This is the arithmetic the whole subsystem turns on and the part that has
/// carried bugs (paging direction, off-by-one at the bounds, same-second
/// ordering) — kept pure so a unit test and the `chathistory_window` differential
/// fuzz can pin it against a specification without a database or a live ring.
pub(super) fn resolve_ring_window(
    history: &[crate::core::state::HistoryEntry],
    complete: bool,
    sub: &str,
    selector: &str,
    selector2: &str,
    limit: usize,
) -> Option<(Vec<crate::core::state::HistoryEntry>, bool)> {
    let n = history.len();
    // Start index of a *lower-exclusive* bound (AFTER / bounded-LATEST / the older
    // end of BETWEEN): the first entry strictly newer than the pivot. A `msgid`
    // pivot is the message *after* it; a `timestamp=T` pivot is the first entry
    // with `ts > T` — strict, exactly as the DB (`ts > $2`), so the ring can't
    // drop the first message after a `T` that falls between two entries. `None`
    // means a msgid pivot absent from the ring (route to the DB).
    let lower_start = |sel: &str| -> Option<usize> {
        if let Some(msgid) = sel.strip_prefix("msgid=") {
            history.iter().position(|e| e.msgid == msgid).map(|p| p + 1)
        } else if let Some(ts) = sel.strip_prefix("timestamp=") {
            e6irc_proto::time::parse_server_time_millis(ts)
                .map(|t| history.iter().position(|e| e.ts > t).unwrap_or(n))
        } else {
            None
        }
    };
    // End index (exclusive) of an *upper-exclusive* bound (BEFORE / the newer end
    // of BETWEEN): the count of entries strictly older than the pivot. A `msgid`
    // pivot excludes itself (entries before it); a `timestamp=T` pivot is the
    // entries with `ts < T`. `None` means a msgid pivot absent from the ring.
    let upper_end = |sel: &str| -> Option<usize> {
        if let Some(msgid) = sel.strip_prefix("msgid=") {
            history.iter().position(|e| e.msgid == msgid)
        } else if let Some(ts) = sel.strip_prefix("timestamp=") {
            e6irc_proto::time::parse_server_time_millis(ts)
                .map(|t| history.iter().position(|e| e.ts >= t).unwrap_or(n))
        } else {
            None
        }
    };
    // AROUND's pivot: the index where the "newer half" begins. A `msgid` pivot is
    // included in the newer half (DB uses `(ts,id) >= pivot`); a `timestamp=T`
    // pivot begins at the first entry with `ts >= T` — same split the DB makes.
    let around_pivot = upper_end;
    // Keep at most `limit` of `history[start..end)`: the newest (right) or oldest.
    let keep_newest = |start: usize, end: usize| -> Vec<crate::core::state::HistoryEntry> {
        let end = end.min(n);
        let start = end.saturating_sub(limit).max(start.min(end));
        history[start..end].to_vec()
    };
    let keep_oldest = |start: usize, end: usize| -> Vec<crate::core::state::HistoryEntry> {
        let end = end.min(n);
        let start = start.min(end);
        history[start..(start + limit).min(end)].to_vec()
    };
    let miss = |sel: &str| (Vec::new(), !needs_db_for_missing_ref(!complete, sel));

    let resolved: (Vec<crate::core::state::HistoryEntry>, bool) =
        match sub.to_ascii_uppercase().as_str() {
            // `*` is unbounded; any other selector restricts LATEST to
            // messages strictly newer than it (draft/chathistory).
            "LATEST" if selector == "*" => (keep_newest(0, n), complete || n >= limit),
            "LATEST" => match lower_start(selector) {
                // Newest `limit` of the entries after the pivot. The newest are
                // always in the ring, so this is covered unless the whole
                // after-set is smaller than `limit` *and* the pivot is older than
                // the ring's oldest (start == 0), where evicted entries might
                // belong to it.
                Some(start) => (keep_newest(start, n), complete || start > 0 || n >= limit),
                None => miss(selector),
            },
            "BEFORE" => match upper_end(selector) {
                Some(end) => {
                    let start = end.saturating_sub(limit);
                    (keep_newest(0, end), complete || start > 0)
                }
                None => miss(selector),
            },
            "AFTER" => match lower_start(selector) {
                // Oldest `limit` after the pivot. The result's oldest is the
                // globally-first entry after the pivot only when the pivot sits
                // at/after the ring's oldest (start > 0) — otherwise evicted
                // entries may also be after it, so the DB must serve it.
                Some(start) => (keep_oldest(start, n), complete || start > 0),
                None => miss(selector),
            },
            "AROUND" => match around_pivot(selector) {
                Some(pivot) => {
                    let before = limit / 2;
                    let start = pivot.saturating_sub(before);
                    let end = (pivot + (limit - before)).min(n);
                    (
                        history[start..end.max(start)].to_vec(),
                        complete || start > 0,
                    )
                }
                None => miss(selector),
            },
            "BETWEEN" => {
                // Both endpoints must resolve in the ring; otherwise the DB does.
                match (upper_end(selector), upper_end(selector2)) {
                    (Some(u1), Some(u2)) => {
                        // Order the pivots by how many entries precede each: the
                        // smaller `upper_end` is the older bound. The window walks
                        // *from* the first selector *toward* the second, so the
                        // `limit` cuts from the first's end — newest-first when the
                        // first selector is the newer bound.
                        let newest_first = u1 > u2;
                        let older_sel = if u1 <= u2 { selector } else { selector2 };
                        // Lower bound: strictly after the older pivot. Upper bound:
                        // strictly before the newer pivot (= the larger upper_end).
                        match lower_start(older_sel) {
                            Some(start) => {
                                let end = u1.max(u2);
                                let covered = complete || start > 0;
                                let rows = if newest_first {
                                    keep_newest(start, end)
                                } else {
                                    keep_oldest(start, end)
                                };
                                (rows, covered)
                            }
                            None => (Vec::new(), complete),
                        }
                    }
                    // An endpoint missing from the ring: only the DB can resolve it.
                    _ => (Vec::new(), complete),
                }
            }
            _ => return None,
        };
    Some(resolved)
}

pub(super) fn needs_db_for_missing_ref(ring_full: bool, selector: &str) -> bool {
    // A `msgid=` pivot resolves in SQL against the composite `(ts, id)` position
    // (BeforeMsgid/AfterMsgid/AroundMsgid), so a msgid absent from an *incomplete*
    // ring must go to the database — not be treated as "no such/older history",
    // which silently dead-ended backward pagination one page past the ring edge.
    // A `timestamp=` bound likewise pages from the DB. Only `*` (open bound) can
    // never need it.
    ring_full && (selector.starts_with("timestamp=") || selector.starts_with("msgid="))
}

/// Turn a validated BETWEEN selector into a [`SelectorBound`] for the DB to
/// resolve. By this point the selector has passed `is_valid_msgref`, the
/// non-`*` check, and (for `timestamp=`) the parse check, so both prefixes hold.
fn selector_bound(selector: &str) -> crate::core::SelectorBound {
    if let Some(msgid) = selector.strip_prefix("msgid=") {
        crate::core::SelectorBound::Msgid(msgid.to_string())
    } else {
        let ts = selector
            .strip_prefix("timestamp=")
            .and_then(e6irc_proto::time::parse_server_time_millis)
            .unwrap_or_else(|| e6irc_proto::time::Millis::from_millis(0));
        crate::core::SelectorBound::Timestamp(ts)
    }
}

/// Resolve a msgid=/timestamp= selector to a timestamp for DB paging.
pub(super) fn selector_ts(
    history: &[crate::core::state::HistoryEntry],
    selector: &str,
) -> Option<e6irc_proto::time::Millis> {
    if let Some(msgid) = selector.strip_prefix("msgid=") {
        history.iter().find(|e| e.msgid == msgid).map(|e| e.ts)
    } else if let Some(ts) = selector.strip_prefix("timestamp=") {
        e6irc_proto::time::parse_server_time_millis(ts)
    } else {
        None
    }
}

/// Render a resolved history window as a batch. The single choke point
/// for CHATHISTORY output, used by both the ring and DB paths.
///
/// `label` is set only on the async DB path: that reply is produced outside the
/// synchronous labeled-response capture, so it must tag its own opening BATCH
/// line with the label. The ring path runs under capture (`label` is `None`)
/// and is framed by [`frame_labeled`] instead.
pub(crate) fn history_page(
    state: &mut ServerState,
    conn: ConnId,
    display: &str,
    batch_ref: &str,
    rows: Result<Vec<crate::core::HistoryRow>, ()>,
    label: Option<&str>,
) {
    // A store fault answers with a FAIL, not an empty batch — otherwise a
    // transient DB error is indistinguishable from a buffer with no history,
    // and the client would cache "nothing here" for a window that does exist.
    // (The label, if any, still rides the FAIL so the labeled-response framer
    // resolves the command.) The synchronous try_push-failure path emits the
    // same MESSAGE_ERROR.
    let rows = match rows {
        Ok(rows) => rows,
        Err(()) => {
            let line = match label {
                Some(label) => format!(
                    "@label={label} :{} FAIL CHATHISTORY MESSAGE_ERROR {} :History temporarily unavailable",
                    state.config.server_name,
                    crate::core::handler::clip_echo(display),
                ),
                None => format!(
                    ":{} FAIL CHATHISTORY MESSAGE_ERROR {} :History temporarily unavailable",
                    state.config.server_name,
                    crate::core::handler::clip_echo(display),
                ),
            };
            state.send(conn, &line);
            return;
        }
    };
    let server = state.config.server_name.clone();
    let open = match label {
        Some(label) => format!("@label={label} :{server} BATCH +{batch_ref} chathistory {display}"),
        None => format!(":{server} BATCH +{batch_ref} chathistory {display}"),
    };
    state.send(conn, &open);
    // A channel message was addressed to the channel, so every replayed row
    // carries the same target. A direct message was addressed to a *person*,
    // and a conversation holds both directions — so each row is re-addressed
    // the way it was originally sent: rows the requester sent name the
    // correspondent, rows the correspondent sent name the requester. Replaying
    // a whole thread under one target would rewrite who each message was to.
    //
    // Both sides are named in their canonical casing rather than however the
    // client spelled the target, so a replayed message is byte-identical to the
    // one delivered live.
    let dm = (!display.starts_with('#'))
        .then(|| state.sessions.get(&conn).and_then(|s| s.nick.clone()))
        .flatten()
        .map(|me| {
            let my_key = state.casemap.casefold(&me);
            let peer = state.display_nick(&state.casemap.casefold(display));
            (me, my_key, peer)
        });
    for row in rows {
        let time = e6irc_proto::time::server_time(row.ts);
        let target = match &dm {
            Some((me, my_key, peer)) => {
                let sender = row.sender_prefix.split('!').next().unwrap_or_default();
                if &state.casemap.casefold(sender) == my_key {
                    peer.as_str()
                } else {
                    me.as_str()
                }
            }
            None => display,
        };
        // Canonical uppercase verb on the wire regardless of source: the ring
        // holds "PRIVMSG"/"NOTICE" but the DB stores lowercase, and this is the
        // one render site for both — normalize here so the same message never
        // replays with a different verb case depending on where it came from.
        let verb = row.kind.wire();
        // Fit the body against *this* line's traditional head, not the one it
        // was stored under: a DM row is re-addressed on replay (to the requester
        // or the correspondent), so its target — and thus the space left for the
        // body — can differ from delivery. Tags don't count toward the 512
        // limit, so the head measured here is only the non-tag part.
        let target = crate::core::handler::clip_echo(target);
        let head = format!(":{} {verb} {target} :", row.sender_prefix);
        let body = crate::core::handler::fit_trailing(&head, &row.body);
        let line = format!(
            "@batch={batch_ref};msgid={};time={time} {head}{body}",
            row.msgid,
        );
        state.send(conn, &line);
    }
    state.send(conn, &format!(":{server} BATCH -{batch_ref}"));
}

#[cfg(test)]
mod window_tests {
    use super::resolve_ring_window;
    use crate::core::MessageKind;
    use crate::core::state::HistoryEntry;
    use e6irc_proto::time::Millis;

    fn entry(i: usize) -> HistoryEntry {
        HistoryEntry {
            msgid: format!("m{i}"),
            // Entries 10ms apart so a `timestamp=` between two lands cleanly.
            ts: Millis::from_millis(1000 + i as u64 * 10),
            sender_prefix: "n!u@h".into(),
            kind: MessageKind::Privmsg,
            body: format!("b{i}"),
        }
    }

    /// Independent specification of the window arithmetic, formulated with
    /// direct index ranges rather than the shipped `skip`/`take` chains, so a
    /// disagreement points at a real bug in one of them.
    fn reference(
        history: &[HistoryEntry],
        complete: bool,
        sub: &str,
        selector: &str,
        selector2: &str,
        limit: usize,
    ) -> Option<(Vec<String>, bool)> {
        let n = history.len();
        // Independent boundary resolution, formulated directly from the message
        // times (not the shipped `.position()` chains), and matching the DB's
        // strict semantics: lower bounds are `ts > T` / after-the-msgid, upper
        // bounds are `ts < T` / before-the-msgid.
        //
        // First entry strictly newer than the pivot (a lower-exclusive bound).
        let after_start = |sel: &str| -> Option<usize> {
            if let Some(m) = sel.strip_prefix("msgid=") {
                history.iter().position(|e| e.msgid == m).map(|p| p + 1)
            } else if let Some(ts) = sel.strip_prefix("timestamp=") {
                let t = e6irc_proto::time::parse_server_time_millis(ts)?;
                Some(history.iter().filter(|e| e.ts <= t).count())
            } else {
                None
            }
        };
        // Count of entries strictly older than the pivot (an upper-exclusive
        // bound); also AROUND's newer-half start (msgid included, `ts >= T`).
        let older_count = |sel: &str| -> Option<usize> {
            if let Some(m) = sel.strip_prefix("msgid=") {
                history.iter().position(|e| e.msgid == m)
            } else if let Some(ts) = sel.strip_prefix("timestamp=") {
                let t = e6irc_proto::time::parse_server_time_millis(ts)?;
                Some(history.iter().filter(|e| e.ts < t).count())
            } else {
                None
            }
        };
        let ids = |lo: usize, hi: usize| -> Vec<String> {
            let (lo, hi) = (lo.min(n), hi.min(n));
            if lo >= hi {
                return Vec::new();
            }
            history[lo..hi].iter().map(|e| e.msgid.clone()).collect()
        };
        // Keep at most `limit` of [start, end): the newest (right) or oldest.
        let keep_newest = |start: usize, end: usize| (end.saturating_sub(limit).max(start), end);
        let keep_oldest = |start: usize, end: usize| (start, (start + limit).min(end));
        // Missing non-BETWEEN reference: PG for a timestamp *or msgid* past an
        // incomplete ring (a msgid pivots in SQL, so a missing one is not "no
        // history" — see needs_db_for_missing_ref).
        let miss = |sel: &str| {
            (
                Vec::new(),
                !((!complete) && (sel.starts_with("timestamp=") || sel.starts_with("msgid="))),
            )
        };

        let out = match sub.to_ascii_uppercase().as_str() {
            "LATEST" if selector == "*" => {
                let (s, e) = keep_newest(0, n);
                (ids(s, e), complete || n >= limit)
            }
            "LATEST" => match after_start(selector) {
                Some(start) => {
                    let (s, e) = keep_newest(start, n);
                    (ids(s, e), complete || start > 0 || n >= limit)
                }
                None => miss(selector),
            },
            "BEFORE" => match older_count(selector) {
                Some(end) => {
                    let (s, e) = keep_newest(0, end);
                    (ids(s, e), complete || end.saturating_sub(limit) > 0)
                }
                None => miss(selector),
            },
            "AFTER" => match after_start(selector) {
                Some(start) => {
                    let (s, e) = keep_oldest(start, n);
                    (ids(s, e), complete || start > 0)
                }
                None => miss(selector),
            },
            "AROUND" => match older_count(selector) {
                Some(pivot) => {
                    let before = limit / 2;
                    let s = pivot.saturating_sub(before);
                    let e = (pivot + (limit - before)).min(n);
                    (ids(s, e.max(s)), complete || s > 0)
                }
                None => miss(selector),
            },
            "BETWEEN" => match (older_count(selector), older_count(selector2)) {
                (Some(u1), Some(u2)) => {
                    let newest_first = u1 > u2;
                    let older_sel = if u1 <= u2 { selector } else { selector2 };
                    match after_start(older_sel) {
                        Some(start) => {
                            let end = u1.max(u2);
                            let (s, e) = if newest_first {
                                keep_newest(start, end)
                            } else {
                                keep_oldest(start, end)
                            };
                            (ids(s, e), complete || start > 0)
                        }
                        None => (Vec::new(), complete),
                    }
                }
                _ => (Vec::new(), complete),
            },
            _ => return None,
        };
        Some(out)
    }

    #[test]
    fn ring_window_matches_the_spec_exhaustively() {
        let st = |i: usize, delta: i64| {
            let ms = (1000 + i as u64 * 10) as i64 + delta;
            format!(
                "timestamp={}",
                e6irc_proto::time::server_time(Millis::from_millis(ms as u64))
            )
        };
        for n in 0..=5usize {
            let history: Vec<HistoryEntry> = (0..n).map(entry).collect();
            // Selectors that resolve to each index, plus misses of each kind.
            let mut sels: Vec<String> = vec!["*".into(), "msgid=miss".into(), st(n, 100)];
            for i in 0..n {
                sels.push(format!("msgid=m{i}"));
                sels.push(st(i, 0)); // exactly on entry i
                sels.push(st(i, -5)); // between i-1 and i → resolves to i
            }
            for complete in [true, false] {
                for sub in ["LATEST", "BEFORE", "AFTER", "AROUND"] {
                    for sel in &sels {
                        for limit in 1..=8usize {
                            let got = resolve_ring_window(&history, complete, sub, sel, "*", limit)
                                .map(|(v, c)| {
                                    (v.iter().map(|e| e.msgid.clone()).collect::<Vec<_>>(), c)
                                });
                            let want = reference(&history, complete, sub, sel, "*", limit);
                            assert_eq!(
                                got, want,
                                "{sub} sel={sel} limit={limit} n={n} complete={complete}"
                            );
                        }
                    }
                }
                // BETWEEN takes two selectors.
                for a in &sels {
                    for b in &sels {
                        for limit in 1..=8usize {
                            let got =
                                resolve_ring_window(&history, complete, "BETWEEN", a, b, limit)
                                    .map(|(v, c)| {
                                        (v.iter().map(|e| e.msgid.clone()).collect::<Vec<_>>(), c)
                                    });
                            let want = reference(&history, complete, "BETWEEN", a, b, limit);
                            assert_eq!(
                                got, want,
                                "BETWEEN a={a} b={b} limit={limit} n={n} complete={complete}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn after_a_between_messages_timestamp_uses_strict_greater_than() {
        // Entries at ts 1000, 1010, 1020. `AFTER timestamp=1005` (between m0 and
        // m1) must return everything with ts > 1005 → [m1, m2], not [m2]. The
        // ring uses strict `ts > T`, matching the DB — the previous `ts >= T` +
        // `skip(pos+1)` dropped the first message after a between-messages T.
        let history: Vec<HistoryEntry> = (0..3).map(entry).collect();
        let t = |ms: u64| {
            format!(
                "timestamp={}",
                e6irc_proto::time::server_time(Millis::from_millis(ms))
            )
        };
        let ids = |rows: Vec<HistoryEntry>| -> Vec<String> {
            rows.into_iter().map(|e| e.msgid).collect()
        };
        let (rows, covered) =
            resolve_ring_window(&history, true, "AFTER", &t(1005), "*", 10).unwrap();
        assert_eq!(ids(rows), ["m1", "m2"]);
        assert!(covered);
        // Exactly on a message excludes it (strict): AFTER 1010 → [m2].
        let (rows, _) = resolve_ring_window(&history, true, "AFTER", &t(1010), "*", 10).unwrap();
        assert_eq!(ids(rows), ["m2"]);
        // Bounded LATEST is strict too: LATEST timestamp=1005 → newest of ts>1005.
        let (rows, _) = resolve_ring_window(&history, true, "LATEST", &t(1005), "*", 10).unwrap();
        assert_eq!(ids(rows), ["m1", "m2"]);
    }

    #[test]
    fn after_a_timestamp_older_than_the_ring_defers_to_the_database() {
        // The ring holds [1000, 1010, 1020] but is incomplete (older evicted).
        // AFTER a timestamp before the ring's oldest can't be answered from the
        // ring alone — evicted messages may also be after it — so it defers.
        let history: Vec<HistoryEntry> = (0..3).map(entry).collect();
        let old = format!(
            "timestamp={}",
            e6irc_proto::time::server_time(Millis::from_millis(500))
        );
        let (_, covered) = resolve_ring_window(&history, false, "AFTER", &old, "*", 10).unwrap();
        assert!(
            !covered,
            "AFTER older than an incomplete ring must defer to the DB"
        );
        // A complete ring genuinely has everything, so it stays covered.
        let (_, covered_complete) =
            resolve_ring_window(&history, true, "AFTER", &old, "*", 10).unwrap();
        assert!(covered_complete);
    }

    #[test]
    fn missing_msgid_on_an_incomplete_ring_defers_to_the_database() {
        // A msgid pivot absent from an *incomplete* ring must report `covered =
        // false` so the DB (which pivots on the msgid in SQL) is consulted —
        // otherwise backward pagination silently dead-ends one page past the ring
        // edge. A complete ring genuinely has no such message, so it stays
        // covered (empty).
        let history: Vec<HistoryEntry> = (0..3).map(entry).collect();
        for sub in ["BEFORE", "AFTER", "AROUND", "LATEST"] {
            let (rows, covered) =
                resolve_ring_window(&history, false, sub, "msgid=gone", "*", 10).unwrap();
            assert!(rows.is_empty());
            assert!(
                !covered,
                "{sub} with a missing msgid on an incomplete ring must defer to the DB"
            );
            let (_, covered_complete) =
                resolve_ring_window(&history, true, sub, "msgid=gone", "*", 10).unwrap();
            assert!(
                covered_complete,
                "{sub} on a complete ring with no such msgid is genuinely empty"
            );
        }
    }
}
