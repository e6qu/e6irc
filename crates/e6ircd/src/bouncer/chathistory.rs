//! BNC-side `draft/chathistory` and `draft/read-marker` handling for the
//! attach listener: page backlog out of the PG-backed history store and
//! maintain per-target read positions, without involving the upstream.
//!
//! Both commands are served only when the client negotiated the cap and the
//! network has a database backing it (the attach interception guards the
//! former; a missing store fails loudly here, never silently).

use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::{AttachCaps, NetworkHandle, NetworkHistory};

/// The largest page a client may ask for in one CHATHISTORY reply. Bounded so
/// a hostile client cannot demand the whole 5000-line backlog in one write.
pub(super) const CHATHISTORY_LIMIT_MAX: i64 = 500;

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
        "AROUND" => paged(handle, write, caps, Paging::Around, params).await,
        "BETWEEN" => paged(handle, write, caps, Paging::Between, params).await,
        "TARGETS" => targets(handle, write, caps, params).await,
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
    origin: u64,
    params: &[&str],
) -> std::io::Result<()> {
    if params.len() > 2 {
        return fail_command(
            write,
            "MARKREAD",
            "INVALID_PARAMS",
            "expected <target> [timestamp]",
        )
        .await;
    }
    let Some(&target) = params.first() else {
        return fail_command(write, "MARKREAD", "INVALID_PARAMS", "missing target").await;
    };
    if !valid_target(target) {
        return fail_command(write, "MARKREAD", "INVALID_PARAMS", "invalid target").await;
    }
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
    match params.get(1) {
        // `MARKREAD <target>` queries one marker.
        None => match crate::db::get_bnc_read_marker(pool, account, network, target).await {
            Ok(Some(ts)) => write_marker(write, target, &ts).await?,
            Ok(None) => write_marker(write, target, "*").await?,
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
        // `MARKREAD <target> <timestamp>` sets the position and acknowledges.
        Some(raw) => {
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
            let stored =
                match crate::db::set_bnc_read_marker(pool, account, network, target, &timestamp)
                    .await
                {
                    Ok(crate::db::BncReadMarkerWrite::Stored(stored)) => stored,
                    Ok(crate::db::BncReadMarkerWrite::LimitReached) => {
                        return fail_command(
                            write,
                            "MARKREAD",
                            "INVALID_PARAMS",
                            "too many read marker targets",
                        )
                        .await;
                    }
                    Err(e) => {
                        eprintln!("bnc: read marker write failed for {account}/{network}: {e}");
                        return fail_command(
                            write,
                            "MARKREAD",
                            "TEMPORARY_FAILURE",
                            "read markers unavailable",
                        )
                        .await;
                    }
                };
            write_marker(write, target, &stored).await?;
            handle.publish_read_marker(account, target, &stored, origin);
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
    Around,
    Between,
}

/// `CHATHISTORY (LATEST|BEFORE|AFTER) <target> <selector> <limit>`.
async fn paged(
    handle: &NetworkHandle,
    write: &mut (impl AsyncWrite + Unpin),
    caps: AttachCaps,
    paging: Paging,
    params: &[&str],
) -> std::io::Result<()> {
    let between = matches!(paging, Paging::Between);
    let expected = if between { 5 } else { 4 };
    if params.len() != expected {
        return fail(
            write,
            "INVALID_PARAMS",
            if between {
                "expected exactly <target> <selector> <selector> <limit>"
            } else {
                "expected exactly <target> <selector> <limit>"
            },
        )
        .await;
    }
    let target = params[1];
    if !valid_target(target) {
        return fail(write, "INVALID_PARAMS", "invalid target").await;
    }
    let selector = match HistorySelector::parse(params[2]) {
        Ok(selector) => selector,
        Err(reason) => return fail(write, "INVALID_PARAMS", reason).await,
    };
    let selector2 = if between {
        match HistorySelector::parse(params[3]) {
            Ok(selector) => selector,
            Err(reason) => return fail(write, "INVALID_PARAMS", reason).await,
        }
    } else {
        HistorySelector::Star
    };
    if !matches!(paging, Paging::Latest)
        && (matches!(selector, HistorySelector::Star)
            || matches!(selector2, HistorySelector::Star) && between)
    {
        return fail(
            write,
            "INVALID_PARAMS",
            "* is only a valid selector for LATEST",
        )
        .await;
    }
    let limit_raw = params[if between { 4 } else { 3 }];
    let Some(limit) = parse_limit(limit_raw) else {
        return fail(write, "INVALID_PARAMS", "limit must be between 1 and 500").await;
    };
    let Some(history) = require_history(handle, write).await? else {
        return Ok(());
    };
    let rows =
        match crate::db::bnc_history_lines(&history.pool, &history.owner, &history.network, target)
            .await
        {
            Ok(rows) => rows,
            Err(e) => return db_error(write, e).await,
        };
    let selected = resolve_window(&rows, paging, &selector, &selector2, limit as usize);
    reply_lines(write, caps, target, &selected).await
}

#[derive(Debug, PartialEq, Eq)]
enum HistorySelector {
    Star,
    Msgid(String),
    Timestamp(String),
}

impl HistorySelector {
    fn parse(raw: &str) -> Result<Self, &'static str> {
        if raw == "*" {
            return Ok(Self::Star);
        }
        if let Some(msgid) = raw.strip_prefix("msgid=") {
            return e6irc_proto::message::valid_message_id(msgid)
                .then(|| Self::Msgid(msgid.to_string()))
                .ok_or("invalid msgid selector");
        }
        if let Some(timestamp) = raw.strip_prefix("timestamp=") {
            return e6irc_proto::time::parse_server_time_millis(timestamp)
                .map(e6irc_proto::time::server_time)
                .map(Self::Timestamp)
                .ok_or("invalid timestamp selector");
        }
        Err("selector must be *, msgid=..., or timestamp=...")
    }
}

fn resolve_window<'a>(
    rows: &'a [crate::db::BncHistoryLine],
    paging: Paging,
    selector: &HistorySelector,
    selector2: &HistorySelector,
    limit: usize,
) -> Vec<&'a crate::db::BncHistoryLine> {
    let n = rows.len();
    let lower_start = |selector: &HistorySelector| match selector {
        HistorySelector::Msgid(msgid) => rows
            .iter()
            .position(|row| row.msgid.as_deref() == Some(msgid))
            .map(|position| position + 1),
        HistorySelector::Timestamp(timestamp) => {
            Some(rows.partition_point(|row| row.sent_at.as_str() <= timestamp.as_str()))
        }
        HistorySelector::Star => None,
    };
    let upper_end = |selector: &HistorySelector| match selector {
        HistorySelector::Msgid(msgid) => rows
            .iter()
            .position(|row| row.msgid.as_deref() == Some(msgid)),
        HistorySelector::Timestamp(timestamp) => {
            Some(rows.partition_point(|row| row.sent_at.as_str() < timestamp.as_str()))
        }
        HistorySelector::Star => None,
    };
    let newest = |start: usize, end: usize| {
        let end = end.min(n);
        let start = end.saturating_sub(limit).max(start.min(end));
        rows[start..end].iter().collect()
    };
    let oldest = |start: usize, end: usize| {
        let end = end.min(n);
        let start = start.min(end);
        rows[start..(start + limit).min(end)].iter().collect()
    };
    match paging {
        Paging::Latest if matches!(selector, HistorySelector::Star) => newest(0, n),
        Paging::Latest => lower_start(selector).map_or_else(Vec::new, |start| newest(start, n)),
        Paging::Before => upper_end(selector).map_or_else(Vec::new, |end| newest(0, end)),
        Paging::After => lower_start(selector).map_or_else(Vec::new, |start| oldest(start, n)),
        Paging::Around => upper_end(selector).map_or_else(Vec::new, |pivot| {
            let before = limit / 2;
            let start = pivot.saturating_sub(before);
            let end = (pivot + (limit - before)).min(n);
            rows[start..end].iter().collect()
        }),
        Paging::Between => match (upper_end(selector), upper_end(selector2)) {
            (Some(first), Some(second)) => {
                let newest_first = first > second;
                let older = if first <= second { selector } else { selector2 };
                match lower_start(older) {
                    Some(start) if newest_first => newest(start, first.max(second)),
                    Some(start) => oldest(start, first.max(second)),
                    None => Vec::new(),
                }
            }
            _ => Vec::new(),
        },
    }
}

/// `CHATHISTORY TARGETS <timestamp> <timestamp> <target-count>`: list the
/// conversation targets whose newest activity is strictly between the bounds.
async fn targets(
    handle: &NetworkHandle,
    write: &mut (impl AsyncWrite + Unpin),
    caps: AttachCaps,
    params: &[&str],
) -> std::io::Result<()> {
    if params.len() != 4 {
        return fail(
            write,
            "INVALID_PARAMS",
            "expected exactly <timestamp> <timestamp> <target-count>",
        )
        .await;
    }
    let Some(history) = require_history(handle, write).await? else {
        return Ok(());
    };
    let parse_timestamp = |raw: &str| {
        raw.strip_prefix("timestamp=")
            .and_then(e6irc_proto::time::parse_server_time_millis)
            .map(e6irc_proto::time::server_time)
    };
    let (Some(first), Some(second)) = (parse_timestamp(params[1]), parse_timestamp(params[2]))
    else {
        return fail(write, "INVALID_PARAMS", "expected two timestamp= bounds").await;
    };
    let (minimum, maximum) = if first <= second {
        (first, second)
    } else {
        (second, first)
    };
    let count_raw = params[3];
    let count = match parse_limit(count_raw) {
        Some(n) => n,
        None => {
            return fail(
                write,
                "INVALID_PARAMS",
                "target count must be between 1 and 500",
            )
            .await;
        }
    };
    let rows = match crate::db::bnc_history_targets(
        &history.pool,
        &history.owner,
        &history.network,
        &minimum,
        &maximum,
        count,
    )
    .await
    {
        Ok(rows) => rows,
        Err(e) => return db_error(write, e).await,
    };

    // The inner lines carry the per-target newest timestamp so a client can
    // resume each conversation from its end. Clients that negotiated `batch`
    // receive the specified wrapper; limited clients receive the lines directly.
    let inner: Vec<String> = rows
        .iter()
        .map(|(t, newest)| format!(":*bnc* CHATHISTORY TARGETS {t} {newest}\r\n"))
        .collect();
    write_batch(write, caps.batch, HistoryBatch::Targets, &inner).await
}

enum HistoryBatch<'a> {
    Messages(&'a str),
    Targets,
}

/// `reply_lines` and `targets` differ only in the batch kind and in how each
/// line is produced, so the wrapper is shared.
async fn write_batch(
    write: &mut (impl AsyncWrite + Unpin),
    batch: bool,
    kind: HistoryBatch<'_>,
    inner: &[String],
) -> std::io::Result<()> {
    if batch {
        let tag = next_batch_tag();
        let head = match kind {
            HistoryBatch::Messages(target) => {
                format!(":*bnc* BATCH +{tag} chathistory {target}\r\n")
            }
            HistoryBatch::Targets => {
                format!(":*bnc* BATCH +{tag} draft/chathistory-targets\r\n")
            }
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
    rows: &[&crate::db::BncHistoryLine],
) -> std::io::Result<()> {
    let inner: Vec<String> = rows
        .iter()
        .filter_map(|row| {
            let line = history_replay_line(row, caps)?;
            format!("{line}\r\n").into()
        })
        .collect();
    write_batch(write, caps.batch, HistoryBatch::Messages(target), &inner).await
}

/// Filter a stored line to the client's negotiated tags and ensure a
/// server-time-capable CHATHISTORY client receives the canonical timestamp the
/// database used to order it. The upstream `time` tag is replaced, not
/// duplicated; duplicate tag keys are forbidden and would make clients choose
/// inconsistent values.
fn history_replay_line(row: &crate::db::BncHistoryLine, caps: AttachCaps) -> Option<String> {
    let filtered = super::filter_tags(&row.line, caps)?;
    if !caps.server_time {
        return Some(filtered);
    }
    let without_time = remove_tag(&filtered, "time");
    match without_time.strip_prefix('@') {
        Some(rest) => format!("@time={};{rest}", row.sent_at),
        None => format!("@time={} {without_time}", row.sent_at),
    }
    .into()
}

fn remove_tag(line: &str, key_to_remove: &str) -> String {
    let Some(rest) = line.strip_prefix('@') else {
        return line.to_string();
    };
    let Some((tags, body)) = rest.split_once(' ') else {
        return String::new();
    };
    let kept: Vec<&str> = tags
        .split(';')
        .filter(|tag| tag.split('=').next() != Some(key_to_remove))
        .collect();
    if kept.is_empty() {
        body.to_string()
    } else {
        format!("@{} {body}", kept.join(";"))
    }
}

/// `MARKREAD <target> <timestamp>` reply line.
async fn write_marker(
    write: &mut (impl AsyncWrite + Unpin),
    target: &str,
    timestamp: &str,
) -> std::io::Result<()> {
    let marker = if timestamp == "*" {
        "*".to_string()
    } else {
        format!("timestamp={timestamp}")
    };
    write
        .write_all(format!(":*bnc* MARKREAD {target} {marker}\r\n").as_bytes())
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
    (n > 0 && n <= CHATHISTORY_LIMIT_MAX).then_some(n)
}

fn valid_target(target: &str) -> bool {
    if target.starts_with(['#', '&']) {
        return target.len() > 1
            && target.len() <= 64
            && !target.bytes().any(|byte| {
                byte.is_ascii_whitespace() || matches!(byte, b'\0' | b',' | b':' | 0x07)
            });
    }
    crate::sanitize::valid_nick(target, 30)
}

/// Normalize a required `timestamp=` MARKREAD position before storage.
fn normalize_timestamp(raw: &str) -> Option<String> {
    let ts = raw.strip_prefix("timestamp=")?;
    e6irc_proto::time::parse_server_time_millis(ts).map(e6irc_proto::time::server_time)
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn limits_and_targets_are_closed_bounded_values() {
        assert_eq!(parse_limit("1"), Some(1));
        assert_eq!(parse_limit("500"), Some(500));
        for invalid in ["0", "501", "-1", "not-a-number"] {
            assert_eq!(parse_limit(invalid), None, "{invalid}");
        }
        assert!(valid_target("#room"));
        assert!(valid_target("&local"));
        assert!(valid_target("SomeNick"));
        assert!(!valid_target(""));
        assert!(!valid_target(&"x".repeat(65)));
        assert!(!valid_target("bad,target"));
        assert!(!valid_target("!!!"));
        assert!(!valid_target("*"));
        assert!(matches!(
            HistorySelector::parse("msgid=opaque"),
            Ok(HistorySelector::Msgid(_))
        ));
        for invalid in [
            "msgid=",
            "msgid=:invalid",
            "2026-01-01T00:00:00.000Z",
            "timestamp=invalid",
        ] {
            assert!(HistorySelector::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[tokio::test]
    async fn chathistory_does_not_require_the_optional_batch_capability() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let (handle, _ends) = NetworkHandle::channels(4);
        handle_chathistory(
            &handle,
            &mut server,
            AttachCaps {
                chathistory: true,
                ..AttachCaps::default()
            },
            &["LATEST", "#room", "*", "10"],
        )
        .await
        .expect("write history response");
        server.shutdown().await.expect("close server half");
        let mut reply = String::new();
        client.read_to_string(&mut reply).await.expect("read reply");
        assert!(reply.contains("FAIL CHATHISTORY UNAVAILABLE"), "{reply}");
        assert!(!reply.contains("NEED_CAPS"), "{reply}");
    }

    #[test]
    fn every_history_window_has_the_specified_boundary_and_direction() {
        fn row(id: i64) -> crate::db::BncHistoryLine {
            crate::db::BncHistoryLine {
                id,
                line: format!(":n PRIVMSG #room :{id}"),
                msgid: Some(format!("m{id}")),
                sent_at: format!("2026-01-01T00:00:0{id}.000Z"),
            }
        }
        let rows: Vec<_> = (1..=6).map(row).collect();
        let ids = |selected: Vec<&crate::db::BncHistoryLine>| {
            selected.into_iter().map(|row| row.id).collect::<Vec<_>>()
        };
        let star = HistorySelector::Star;
        let msgid = |id| HistorySelector::Msgid(format!("m{id}"));
        assert_eq!(
            ids(resolve_window(&rows, Paging::Latest, &star, &star, 2)),
            vec![5, 6]
        );
        assert_eq!(
            ids(resolve_window(&rows, Paging::Latest, &msgid(2), &star, 2)),
            vec![5, 6],
            "bounded LATEST keeps the newest messages after its pivot"
        );
        assert_eq!(
            ids(resolve_window(&rows, Paging::Before, &msgid(5), &star, 2)),
            vec![3, 4]
        );
        assert_eq!(
            ids(resolve_window(&rows, Paging::After, &msgid(2), &star, 2)),
            vec![3, 4]
        );
        assert_eq!(
            ids(resolve_window(&rows, Paging::Around, &msgid(4), &star, 4)),
            vec![2, 3, 4, 5]
        );
        assert_eq!(
            ids(resolve_window(
                &rows,
                Paging::Between,
                &msgid(2),
                &msgid(6),
                2
            )),
            vec![3, 4]
        );
        assert_eq!(
            ids(resolve_window(
                &rows,
                Paging::Between,
                &msgid(6),
                &msgid(2),
                2
            )),
            vec![4, 5],
            "a reverse BETWEEN window limits from its first, newer endpoint"
        );
        assert!(resolve_window(&rows, Paging::Before, &msgid(99), &star, 2).is_empty());
    }

    #[tokio::test]
    async fn targets_use_the_dedicated_batch_type() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        write_batch(
            &mut server,
            true,
            HistoryBatch::Targets,
            &[":*bnc* CHATHISTORY TARGETS #room 2026-01-01T00:00:00.000Z\r\n".into()],
        )
        .await
        .expect("write target batch");
        server.shutdown().await.expect("close server half");
        let mut reply = String::new();
        client.read_to_string(&mut reply).await.expect("read batch");
        assert!(reply.contains(" draft/chathistory-targets\r\n"));
    }

    #[test]
    fn replay_uses_the_same_canonical_time_as_history_ordering() {
        let row = crate::db::BncHistoryLine {
            id: 1,
            line: "@time=invalid;msgid=m1 :n PRIVMSG #room :message".into(),
            msgid: Some("m1".into()),
            sent_at: "2026-01-01T00:00:00.123Z".into(),
        };
        let line = history_replay_line(
            &row,
            AttachCaps {
                server_time: true,
                message_tags: true,
                ..AttachCaps::default()
            },
        )
        .expect("PRIVMSG is visible with these caps");
        assert_eq!(
            line,
            "@time=2026-01-01T00:00:00.123Z;msgid=m1 :n PRIVMSG #room :message"
        );
        assert_eq!(
            line.matches("time=").count(),
            1,
            "history must never emit duplicate time tags"
        );
    }

    #[tokio::test]
    async fn malformed_history_commands_fail_before_storage() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let (handle, _ends) = NetworkHandle::channels(4);
        for params in [
            vec!["LATEST", "#room", "*", "501"],
            vec!["LATEST", "#room", "*", "10", "extra"],
            vec!["TARGETS", "*"],
        ] {
            handle_chathistory(
                &handle,
                &mut server,
                AttachCaps {
                    batch: true,
                    chathistory: true,
                    ..AttachCaps::default()
                },
                &params,
            )
            .await
            .expect("history rejection");
        }
        handle_markread(
            &handle,
            &mut server,
            "alice",
            0,
            &["#room", "timestamp=2026-01-01T00:00:00.000Z", "extra"],
        )
        .await
        .expect("MARKREAD rejection");
        server.shutdown().await.expect("close server half");
        let mut replies = String::new();
        client
            .read_to_string(&mut replies)
            .await
            .expect("read replies");
        assert_eq!(
            replies.matches("FAIL CHATHISTORY INVALID_PARAMS").count(),
            3
        );
        assert!(replies.contains("FAIL MARKREAD INVALID_PARAMS"));
        assert!(
            !replies.contains("UNAVAILABLE"),
            "validation must precede storage"
        );
    }

    #[test]
    fn markread_requires_a_real_target_and_timestamp_selector() {
        assert!(!valid_target("*"));
        assert_eq!(normalize_timestamp("2026-01-01T00:00:00.000Z"), None);
        assert_eq!(normalize_timestamp("timestamp=not-a-time"), None);
        assert_eq!(
            normalize_timestamp("timestamp=2026-01-01T00:00:00.1Z"),
            Some("2026-01-01T00:00:00.100Z".into())
        );
    }
}
