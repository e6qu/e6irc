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
            // The two selectors may be given newest-first. That does not change
            // the window, only which end `limit` cuts from, so the bounds are
            // normalized to (older, newer) — passing them through reversed
            // would make the SQL range empty — and the direction travels
            // alongside as `newest_first`.
            "BETWEEN" => {
                let a = selector_ts(&history, selector);
                let b = selector_ts(&history, selector2);
                let newest_first = matches!((a, b), (Some(a), Some(b)) if a > b);
                match (msgid_of(selector), msgid_of(selector2)) {
                    (Some(first), Some(second)) => {
                        let (after_msgid, before_msgid) = if newest_first {
                            (second, first)
                        } else {
                            (first, second)
                        };
                        crate::core::HistoryQuery::BetweenMsgid {
                            after_msgid,
                            before_msgid,
                            limit,
                            newest_first,
                        }
                    }
                    _ => {
                        let a = a.unwrap_or(e6irc_proto::time::Millis::from_millis(0));
                        let b = b.unwrap_or(e6irc_proto::time::Millis::from_millis(u64::MAX));
                        let (after_ts, before_ts) = if a <= b { (a, b) } else { (b, a) };
                        crate::core::HistoryQuery::Between {
                            after_ts,
                            before_ts,
                            limit,
                            newest_first,
                        }
                    }
                }
            }
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
    // label, so history_page must not (pass None).
    history_page(state, conn, &display, &batch_ref, rows, None);
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
            targets.push((state.identity_nick(&peer), latest));
        }
    }
    // Oldest activity first; a limit therefore keeps the oldest buffers.
    targets.sort_by_key(|t| t.1);
    targets.truncate(limit);
    // No-DB path runs under labeled-response capture; frame_labeled applies it.
    targets_page(state, conn, &batch_ref, targets, None);
}

/// Emit a `draft/chathistory-targets` batch: one `CHATHISTORY TARGETS
/// <target> <time>` line per buffer, newest-first.
pub(crate) fn targets_page(
    state: &mut ServerState,
    conn: ConnId,
    batch_ref: &str,
    targets: Vec<(String, e6irc_proto::time::Millis)>,
    label: Option<&str>,
) {
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
        // Prefer the channel's display name while it is still in memory.
        let key = state.chan_key(&target);
        let display = state
            .channels
            .get(&key)
            .map(|c| c.name.clone())
            .unwrap_or(target);
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
    let position = |sel: &str| -> Option<usize> {
        if let Some(msgid) = sel.strip_prefix("msgid=") {
            history.iter().position(|e| e.msgid == msgid)
        } else if let Some(ts) = sel.strip_prefix("timestamp=") {
            // first entry at/after the timestamp
            let ts = e6irc_proto::time::parse_server_time_millis(ts)?;
            history.iter().position(|e| e.ts >= ts)
        } else {
            None
        }
    };

    let resolved: (Vec<crate::core::state::HistoryEntry>, bool) =
        match sub.to_ascii_uppercase().as_str() {
            // `*` is unbounded; any other selector restricts LATEST to
            // messages strictly newer than it (draft/chathistory).
            "LATEST" if selector == "*" => {
                let skip = history.len().saturating_sub(limit);
                let covered = complete || history.len() >= limit;
                (history.iter().skip(skip).cloned().collect(), covered)
            }
            "LATEST" => match position(selector) {
                Some(pos) => {
                    let start = pos + 1;
                    // Keep the newest `limit` of the bounded range, not the
                    // oldest — LATEST is most-recent-first.
                    let skip = start + history.len().saturating_sub(start).saturating_sub(limit);
                    // The bound itself is in the ring, so everything newer is
                    // too: no database round trip is needed.
                    (history.iter().skip(skip).cloned().collect(), true)
                }
                None => (Vec::new(), !needs_db_for_missing_ref(!complete, selector)),
            },
            "BEFORE" => match position(selector) {
                Some(pos) => {
                    let start = pos.saturating_sub(limit);
                    let covered = complete || start > 0;
                    (
                        history.iter().take(pos).skip(start).cloned().collect(),
                        covered,
                    )
                }
                // reference past a full ring: only PG can resolve it
                None => (Vec::new(), !needs_db_for_missing_ref(!complete, selector)),
            },
            "AFTER" => match position(selector) {
                Some(pos) => (
                    history.iter().skip(pos + 1).take(limit).cloned().collect(),
                    true,
                ),
                None => (Vec::new(), !needs_db_for_missing_ref(!complete, selector)),
            },
            "AROUND" => match position(selector) {
                Some(pos) => {
                    let before = limit / 2;
                    let start = pos.saturating_sub(before);
                    let end = (pos + (limit - before)).min(history.len());
                    // Only the older half can reach past the ring's start.
                    let covered = complete || start > 0;
                    (
                        history.iter().take(end).skip(start).cloned().collect(),
                        covered,
                    )
                }
                None => (Vec::new(), !needs_db_for_missing_ref(!complete, selector)),
            },
            "BETWEEN" => match (position(selector), position(selector2)) {
                // Both endpoints in the ring: the span between them is
                // contiguous and fully in memory.
                (Some(a), Some(b)) => {
                    // The argument order picks the paging direction: the
                    // window is walked *from* the first selector *toward* the
                    // second, so when the first is the newer bound a limit
                    // smaller than the span keeps the newest entries, not the
                    // oldest.
                    let newest_first = a > b;
                    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
                    let start = lo + 1;
                    let span = hi.saturating_sub(start);
                    let skip = if newest_first {
                        start + span.saturating_sub(limit)
                    } else {
                        start
                    };
                    (
                        history
                            .iter()
                            .take(hi)
                            .skip(skip)
                            .take(limit)
                            .cloned()
                            .collect(),
                        true,
                    )
                }
                // An endpoint missing from the ring: only PG can resolve it.
                _ => (Vec::new(), complete),
            },
            _ => return None,
        };
    Some(resolved)
}

pub(super) fn needs_db_for_missing_ref(ring_full: bool, selector: &str) -> bool {
    ring_full && selector.starts_with("timestamp=")
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
    rows: Vec<crate::core::HistoryRow>,
    label: Option<&str>,
) {
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
        // Same selector→index resolution the code uses (shared on purpose: this
        // test isolates the *window* math, not the lookup).
        let pos = |sel: &str| -> Option<usize> {
            if let Some(m) = sel.strip_prefix("msgid=") {
                history.iter().position(|e| e.msgid == m)
            } else if let Some(ts) = sel.strip_prefix("timestamp=") {
                let ts = e6irc_proto::time::parse_server_time_millis(ts)?;
                history.iter().position(|e| e.ts >= ts)
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
        // Missing non-BETWEEN reference: PG only for a timestamp past a full ring.
        let miss = |sel: &str| (Vec::new(), !((!complete) && sel.starts_with("timestamp=")));

        let out = match sub.to_ascii_uppercase().as_str() {
            "LATEST" if selector == "*" => {
                let (s, e) = keep_newest(0, n);
                (ids(s, e), complete || n >= limit)
            }
            "LATEST" => match pos(selector) {
                Some(p) => {
                    let (s, e) = keep_newest(p + 1, n);
                    (ids(s, e), true)
                }
                None => miss(selector),
            },
            "BEFORE" => match pos(selector) {
                Some(p) => {
                    let (s, e) = keep_newest(0, p);
                    (ids(s, e), complete || s > 0)
                }
                None => miss(selector),
            },
            "AFTER" => match pos(selector) {
                Some(p) => {
                    let (s, e) = keep_oldest(p + 1, n);
                    (ids(s, e), true)
                }
                None => miss(selector),
            },
            "AROUND" => match pos(selector) {
                Some(p) => {
                    let before = limit / 2;
                    let s = p.saturating_sub(before);
                    let e = (p + (limit - before)).min(n);
                    (ids(s, e), complete || s > 0)
                }
                None => miss(selector),
            },
            "BETWEEN" => match (pos(selector), pos(selector2)) {
                (Some(a), Some(b)) => {
                    let (lo, hi) = (a.min(b), a.max(b));
                    let (s, e) = if a > b {
                        keep_newest(lo + 1, hi)
                    } else {
                        keep_oldest(lo + 1, hi)
                    };
                    (ids(s, e), true)
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
}
