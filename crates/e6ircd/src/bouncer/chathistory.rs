//! BNC-side `draft/chathistory` and `draft/read-marker` handling for the
//! attach listener: page backlog out of the PG-backed history store and
//! maintain per-target read positions, without involving the upstream.
//!
//! Both commands are served only when the client negotiated the cap and the
//! network has a database backing it (the attach interception guards the
//! former; a missing store fails loudly here, never silently).

use tokio::io::{AsyncWrite, AsyncWriteExt};

use e6irc_proto::casemap::CaseMapping;

use super::{AttachCaps, NetworkHandle, NetworkHistory};

/// The largest page a client may ask for in one CHATHISTORY reply. Bounded so
/// a hostile client cannot demand the whole 5000-line backlog in one write.
const CHATHISTORY_LIMIT_MAX: i64 = 500;

/// Serve a `CHATHISTORY` command from an attached client. `params` are the
/// words after the command verb, case-preserved.
pub(crate) async fn handle_chathistory(
    handle: &NetworkHandle,
    write: &mut (impl AsyncWrite + Unpin),
    caps: AttachCaps,
    params: &[&str],
) -> std::io::Result<()> {
    let Some(sub) = params.first() else {
        return fail(write, "INVALID_PARAMS", "missing subcommand").await;
    };
    match sub.to_ascii_uppercase().as_str() {
        "LATEST" => paged(handle, write, caps, Paging::Latest, params).await,
        "BEFORE" => paged(handle, write, caps, Paging::Before, params).await,
        "AFTER" => paged(handle, write, caps, Paging::After, params).await,
        "TARGETS" => targets(handle, write, params).await,
        "AROUND" | "BETWEEN" => {
            fail(
                write,
                "UNSUPPORTED_SUBCOMMAND",
                "that subcommand is not supported",
            )
            .await
        }
        _ => fail(write, "INVALID_PARAMS", "unknown subcommand").await,
    }
}

/// Serve a `MARKREAD` command from an attached client. `account` is the
/// authenticated account the markers are keyed on (a shared network still
/// keeps per-account read positions).
pub(crate) async fn handle_markread(
    handle: &NetworkHandle,
    write: &mut (impl AsyncWrite + Unpin),
    account: &str,
    params: &[&str],
) -> std::io::Result<()> {
    let Some(&target) = params.first() else {
        return fail_command(write, "MARKREAD", "INVALID_PARAMS", "missing target").await;
    };
    let history = match handle.history() {
        Some(h) => h,
        None => {
            return fail_command(
                write,
                "MARKREAD",
                "UNAVAILABLE",
                "read markers are not configured",
            )
            .await;
        }
    };
    let (network, pool) = (&history.network, &history.pool);
    match (target, params.get(1)) {
        // `MARKREAD *` queries every marker for this account/network.
        ("*", None) => match crate::db::list_bnc_read_markers(pool, account, network).await {
            Ok(rows) => {
                for (t, ts) in rows {
                    write_marker(write, &t, &ts).await?;
                }
            }
            Err(e) => {
                eprintln!("bnc: read marker query failed for {account}/{network}: {e}");
                return fail_command(
                    write,
                    "MARKREAD",
                    "TEMPORARY_FAILURE",
                    "read markers unavailable",
                )
                .await;
            }
        },
        // The spec forbids setting a position on the `*` query form.
        ("*", Some(_)) => {
            return fail_command(
                write,
                "MARKREAD",
                "INVALID_PARAMS",
                "target * does not take a timestamp",
            )
            .await;
        }
        // `MARKREAD <target>` queries one marker.
        (target, None) => {
            match crate::db::get_bnc_read_marker(pool, account, network, target).await {
                Ok(Some(ts)) => write_marker(write, target, &ts).await?,
                Ok(None) => {}
                Err(e) => {
                    eprintln!("bnc: read marker query failed for {account}/{network}: {e}");
                    return fail_command(
                        write,
                        "MARKREAD",
                        "TEMPORARY_FAILURE",
                        "read markers unavailable",
                    )
                    .await;
                }
            }
        }
        // `MARKREAD <target> <timestamp>` sets the position and acknowledges.
        (target, Some(raw)) => {
            let timestamp = match normalize_timestamp(raw) {
                Some(ts) => ts,
                None => {
                    return fail_command(
                        write,
                        "MARKREAD",
                        "INVALID_PARAMS",
                        "malformed timestamp",
                    )
                    .await;
                }
            };
            if let Err(e) =
                crate::db::set_bnc_read_marker(pool, account, network, target, &timestamp).await
            {
                eprintln!("bnc: read marker write failed for {account}/{network}: {e}");
                return fail_command(
                    write,
                    "MARKREAD",
                    "TEMPORARY_FAILURE",
                    "read markers unavailable",
                )
                .await;
            }
            write_marker(write, target, &timestamp).await?;
        }
    }
    write.flush().await?;
    Ok(())
}

/// The persisted history store for a network, or a loud `FAIL` and `None` when
/// the network has none configured (paging a store-less network must not look
/// like an empty backlog — DESIGN §2: no silent fallbacks).
async fn require_history(
    handle: &NetworkHandle,
    write: &mut (impl AsyncWrite + Unpin),
) -> std::io::Result<Option<NetworkHistory>> {
    match handle.history() {
        Some(h) => Ok(Some(h)),
        None => {
            fail(write, "UNAVAILABLE", "history store not configured").await?;
            Ok(None)
        }
    }
}

/// Which paging direction a CHATHISTORY subcommand asks for.
enum Paging {
    Latest,
    Before,
    After,
}

/// `CHATHISTORY (LATEST|BEFORE|AFTER) <target> <selector> <limit>`.
async fn paged(
    handle: &NetworkHandle,
    write: &mut (impl AsyncWrite + Unpin),
    caps: AttachCaps,
    paging: Paging,
    params: &[&str],
) -> std::io::Result<()> {
    let (Some(target), Some(selector), Some(limit_raw)) =
        (params.get(1), params.get(2), params.get(3))
    else {
        return fail(
            write,
            "INVALID_PARAMS",
            "expected <target> <selector> <limit>",
        )
        .await;
    };
    let Some(limit) = parse_limit(limit_raw) else {
        return fail(write, "INVALID_PARAMS", "limit must be a positive integer").await;
    };
    let limit = limit.min(CHATHISTORY_LIMIT_MAX);
    let Some(history) = require_history(handle, write).await? else {
        return Ok(());
    };

    let boundary = match resolve_selector(&history, target, selector, &paging).await {
        Ok(b) => b,
        Err(reason) => return fail(write, "INVALID_PARAMS", reason).await,
    };

    let folded = CaseMapping::Rfc1459.casefold(target);
    let result = match (paging, boundary) {
        (Paging::Latest, Boundary::Unbounded) => {
            crate::db::bnc_history_latest(
                &history.pool,
                &history.owner,
                &history.network,
                &folded,
                None,
                limit,
            )
            .await
        }
        (Paging::Latest, Boundary::Id(at)) => {
            crate::db::bnc_history_latest(
                &history.pool,
                &history.owner,
                &history.network,
                &folded,
                Some(at),
                limit,
            )
            .await
        }
        (Paging::Before, Boundary::Id(before)) => {
            crate::db::bnc_history_before(
                &history.pool,
                &history.owner,
                &history.network,
                &folded,
                before,
                limit,
            )
            .await
        }
        (Paging::After, Boundary::Id(after)) => {
            crate::db::bnc_history_after(
                &history.pool,
                &history.owner,
                &history.network,
                &folded,
                after,
                limit,
            )
            .await
        }
        (Paging::After, Boundary::Unbounded) => {
            // A timestamp older than the backlog: everything is after it, so
            // page from the very start of the target's stored history.
            crate::db::bnc_history_after(
                &history.pool,
                &history.owner,
                &history.network,
                &folded,
                0,
                limit,
            )
            .await
        }
        // BEFORE with `*` was rejected during resolution; an Empty boundary
        // (unknown msgid, timestamp before the backlog) is an empty page.
        // Before+Unbounded is unreachable by construction (the selector
        // resolver rejects `*` for BEFORE) but kept exhaustive.
        (Paging::Before, Boundary::Unbounded) | (_, Boundary::Empty) => Ok(Vec::new()),
    };
    let rows = match result {
        Ok(rows) => rows,
        Err(e) => return db_error(write, e).await,
    };

    reply_lines(write, caps, target, &rows).await
}

/// A resolved CHATHISTORY selector: either an inclusive row-id boundary
/// (id ≤ this for LATEST, id < this for BEFORE, id > this for AFTER), an
/// unbounded page (the `*` selector), or nothing to page at all.
enum Boundary {
    Unbounded,
    Id(i64),
    Empty,
}

/// Map a CHATHISTORY `<selector>` to its boundary id.
async fn resolve_selector(
    history: &NetworkHistory,
    target: &str,
    selector: &str,
    paging: &Paging,
) -> Result<Boundary, &'static str> {
    let folded = CaseMapping::Rfc1459.casefold(target);
    if selector == "*" {
        return match paging {
            // `*` means "the newest" — valid only for LATEST; BEFORE/AFTER
            // need a concrete reference to page from.
            Paging::Latest => Ok(Boundary::Unbounded),
            Paging::Before | Paging::After => Err("BEFORE/AFTER need a msgid or timestamp"),
        };
    }
    // A bare ISO-8601 value is accepted as a timestamp too (clients differ on
    // whether they send the `timestamp=` prefix).
    let timestamp = selector
        .strip_prefix("timestamp=")
        .or_else(|| e6irc_proto::time::parse_server_time_millis(selector).map(|_| selector));
    let row = if let Some(msgid) = selector.strip_prefix("msgid=") {
        match crate::db::bnc_history_msgid_row(
            &history.pool,
            &history.owner,
            &history.network,
            msgid,
        )
        .await
        {
            Ok(row) => row,
            Err(_) => return Err("history store unavailable"),
        }
    } else if let Some(ts) = timestamp {
        match crate::db::bnc_history_timestamp_row(
            &history.pool,
            &history.owner,
            &history.network,
            &folded,
            ts,
        )
        .await
        {
            Ok(row) => row,
            Err(_) => return Err("history store unavailable"),
        }
    } else {
        return Err("selector must be *, msgid=..., or timestamp=...");
    };
    Ok(match row {
        Some(id) => Boundary::Id(id),
        // An unknown msgid is an empty page. So is a timestamp with nothing at
        // or before it — except AFTER such a timestamp, where "everything is
        // after it" means page from the very start of the target's history.
        None if matches!(paging, Paging::After) && timestamp.is_some() => Boundary::Unbounded,
        None => Boundary::Empty,
    })
}

/// `CHATHISTORY TARGETS <timestamp> <target-count>`: list the conversation
/// targets that still have backlog, newest-active first.
async fn targets(
    handle: &NetworkHandle,
    write: &mut (impl AsyncWrite + Unpin),
    params: &[&str],
) -> std::io::Result<()> {
    let Some(history) = require_history(handle, write).await? else {
        return Ok(());
    };
    let ts = params.get(1).copied().unwrap_or("*");
    let count_raw = params.get(2).copied().unwrap_or("50");
    let count = match parse_limit(count_raw) {
        Some(n) => n.min(CHATHISTORY_LIMIT_MAX),
        None => {
            return fail(
                write,
                "INVALID_PARAMS",
                "target count must be a positive integer",
            )
            .await;
        }
    };
    let cutoff = if ts == "*" {
        None
    } else if e6irc_proto::time::parse_server_time_millis(ts).is_some() {
        Some(ts)
    } else {
        return fail(
            write,
            "INVALID_PARAMS",
            "timestamp must be * or an ISO-8601 instant",
        )
        .await;
    };
    let rows = match crate::db::bnc_history_targets(
        &history.pool,
        &history.owner,
        &history.network,
        cutoff,
        count,
    )
    .await
    {
        Ok(rows) => rows,
        Err(e) => return db_error(write, e).await,
    };

    // TARGETS is itself batched; the inner lines carry the per-target newest
    // timestamp so a client can resume each conversation from its end. A
    // client that negotiated draft/chathistory has batch too (the spec
    // requires it), so the reply is always wrapped.
    let inner: Vec<String> = rows
        .iter()
        .map(|(t, newest)| format!(":*bnc* CHATHISTORY TARGETS {t} {newest}\r\n"))
        .collect();
    write_batch(write, true, None, &inner).await
}

/// `reply_lines` and `targets` differ only in the batch target and in how each
/// line is produced, so the wrapper is shared: `BATCH +tag chathistory
/// [target]`, the lines, then `BATCH -tag`. `target` is `None` for TARGETS
/// (whose inner lines carry their own target).
async fn write_batch(
    write: &mut (impl AsyncWrite + Unpin),
    batch: bool,
    target: Option<&str>,
    inner: &[String],
) -> std::io::Result<()> {
    if batch {
        let tag = next_batch_tag();
        let head = match target {
            Some(t) => format!(":*bnc* BATCH +{tag} chathistory {t}\r\n"),
            None => format!(":*bnc* BATCH +{tag} chathistory\r\n"),
        };
        write.write_all(head.as_bytes()).await?;
        for line in inner {
            write.write_all(line.as_bytes()).await?;
        }
        write
            .write_all(format!(":*bnc* BATCH -{tag}\r\n").as_bytes())
            .await?;
    } else {
        for line in inner {
            write.write_all(line.as_bytes()).await?;
        }
    }
    write.flush().await?;
    Ok(())
}

/// Emit one CHATHISTORY page: a `BATCH chathistory <target>` wrapper when the
/// client negotiated `batch`, then the lines themselves (tags filtered to the
/// caps the client negotiated, exactly like a live line).
async fn reply_lines(
    write: &mut (impl AsyncWrite + Unpin),
    caps: AttachCaps,
    target: &str,
    rows: &[crate::db::BncHistoryLine],
) -> std::io::Result<()> {
    let inner: Vec<String> = rows
        .iter()
        .map(|row| {
            let line = super::filter_tags(&row.line, caps);
            format!("{line}\r\n")
        })
        .collect();
    write_batch(write, caps.batch, Some(target), &inner).await
}

/// `MARKREAD <target> <timestamp>` reply line.
async fn write_marker(
    write: &mut (impl AsyncWrite + Unpin),
    target: &str,
    timestamp: &str,
) -> std::io::Result<()> {
    write
        .write_all(format!(":*bnc* MARKREAD {target} {timestamp}\r\n").as_bytes())
        .await
}

/// A `FAIL <command> <code> :<message>` error reply, shared by CHATHISTORY
/// and MARKREAD.
async fn fail_command(
    write: &mut (impl AsyncWrite + Unpin),
    command: &str,
    code: &str,
    message: &str,
) -> std::io::Result<()> {
    write
        .write_all(format!(":*bnc* FAIL {command} {code} :{message}\r\n").as_bytes())
        .await?;
    write.flush().await?;
    Ok(())
}

/// A `FAIL CHATHISTORY <code> :<message>` error reply.
async fn fail(
    write: &mut (impl AsyncWrite + Unpin),
    code: &str,
    message: &str,
) -> std::io::Result<()> {
    fail_command(write, "CHATHISTORY", code, message).await
}

/// Surface a history-store query failure as a loud FAIL, never a silent empty
/// page (DESIGN §2: no silent fallbacks).
async fn db_error(
    write: &mut (impl AsyncWrite + Unpin),
    e: crate::db::DbError,
) -> std::io::Result<()> {
    eprintln!("bnc: chathistory query failed: {e}");
    fail(write, "TEMPORARY_FAILURE", "history store unavailable").await
}

/// Parse a positive page limit.
fn parse_limit(raw: &str) -> Option<i64> {
    let n = raw.parse::<i64>().ok()?;
    (n > 0).then_some(n)
}

/// Normalize a MARKREAD timestamp: either a bare ISO-8601 instant or the
/// `timestamp=`-prefixed form, validated before it is stored.
fn normalize_timestamp(raw: &str) -> Option<String> {
    let ts = raw.strip_prefix("timestamp=").unwrap_or(raw);
    e6irc_proto::time::parse_server_time_millis(ts)
        .is_some()
        .then(|| ts.to_string())
}

/// A process-wide counter minting distinct BATCH tags (the tag just has to be
/// unique while its batch is open; a monotonically increasing suffix is enough).
fn next_batch_tag() -> String {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    format!(
        "e6b{}",
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}
