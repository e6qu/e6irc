//! BNC-side `draft/chathistory` and `draft/read-marker` handling for the
//! attach listener: page backlog out of the PG-backed history store and
//! maintain per-target read positions, without involving the upstream.
//!
//! Both commands are served only when the client negotiated the cap and the
//! network has a database backing it (the attach interception guards the
//! former; a missing store fails loudly here, never silently).

use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::{AttachCaps, NetworkHandle, NetworkHistory};
use crate::core::HistoryFail;
use crate::core::history_request::{
    ChathistorySub, MarkreadRequest, Refusal, Selector, parse_limit, parse_markread,
    parse_selectors, parse_targets,
};
use crate::db::{BncHistoryPaging as Paging, BncHistorySelector as HistorySelector};

/// The largest page a client may ask for in one CHATHISTORY reply — the
/// core's own bound, so a hostile client cannot demand the whole 5000-line
/// backlog in one write.
pub(super) const CHATHISTORY_LIMIT_MAX: usize = crate::core::history_request::CHATHISTORY_MAX;

/// Serve a `CHATHISTORY` command from an attached client. `params` are the
/// words after the command verb, case-preserved.
pub(crate) async fn handle_chathistory(
    handle: &NetworkHandle,
    write: &mut (impl AsyncWrite + Unpin),
    caps: AttachCaps,
    params: &[&str],
) -> std::io::Result<()> {
    // The same codes, in the same order of precedence, as the core's
    // CHATHISTORY: the subcommand is judged first, then the parameter count.
    let Some(sub) = params.first() else {
        return fail(
            write,
            HistoryFail::NeedMoreParams,
            &["*"],
            "Missing parameters",
        )
        .await;
    };
    if sub.eq_ignore_ascii_case("TARGETS") {
        return targets(handle, write, caps, params).await;
    }
    let Some(sub) = ChathistorySub::parse(sub) else {
        let detail = "Unknown subcommand";
        return fail(write, HistoryFail::UnknownCommand, &[sub], detail).await;
    };
    paged(handle, write, caps, sub, params).await
}

/// `CHATHISTORY` refused because the client did not negotiate the cap.
pub(crate) async fn refuse_without_cap(
    write: &mut (impl AsyncWrite + Unpin),
) -> std::io::Result<()> {
    fail(
        write,
        HistoryFail::NeedCaps,
        &[],
        "draft/chathistory required",
    )
    .await
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
    // Parsed by the parser the core's MARKREAD shares, so both refuse a
    // malformed request with the same FAIL; the target (or `*` when none was
    // given) always rides it.
    let (target, marker) = match parse_markread(params, valid_target) {
        Ok(MarkreadRequest::Query { target }) => (target, None),
        Ok(MarkreadRequest::Set { target, marker }) => (target, Some(marker)),
        Err((target, refusal)) => {
            return fail_markread(write, refusal.code, target, refusal.detail).await;
        }
    };
    let Some(history) = handle.history() else {
        return fail_markread(
            write,
            HistoryFail::TemporarilyUnavailable,
            target,
            "read markers are not configured",
        )
        .await;
    };
    let (network, pool) = (&history.network, &history.pool);
    let casemapping = handle.names().casemapping();
    match marker {
        // `MARKREAD <target>` queries one marker.
        None => send_read_marker(write, &history, casemapping, account, target).await?,
        // `MARKREAD <target> <timestamp>` sets the position and acknowledges.
        Some(marker) => {
            let timestamp = e6irc_proto::time::server_time(marker);
            let stored = match crate::db::set_bnc_read_marker(
                pool,
                account,
                network,
                target,
                casemapping,
                &timestamp,
            )
            .await
            {
                Ok(crate::db::BncReadMarkerWrite::Stored(stored)) => stored,
                Ok(crate::db::BncReadMarkerWrite::LimitReached) => {
                    return fail_markread(
                        write,
                        HistoryFail::InvalidParams,
                        target,
                        "too many read marker targets",
                    )
                    .await;
                }
                Err(e) => {
                    eprintln!("bnc: read marker write failed for {account}/{network}: {e}");
                    return fail_markread(
                        write,
                        HistoryFail::TemporarilyUnavailable,
                        target,
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

/// Send `target`'s current read marker (`*` when none is set), or the
/// `TEMPORARILY_UNAVAILABLE` FAIL when the store cannot answer. The MARKREAD
/// query form and the replay after a JOIN both answer through here. A marker
/// is keyed by its target folded the network's way (`casemapping`), as the
/// backlog it marks is.
pub(crate) async fn send_read_marker(
    write: &mut (impl AsyncWrite + Unpin),
    history: &NetworkHistory,
    casemapping: e6irc_proto::casemap::CaseMapping,
    account: &str,
    target: &str,
) -> std::io::Result<()> {
    match crate::db::get_bnc_read_marker(
        &history.pool,
        account,
        &history.network,
        target,
        casemapping,
    )
    .await
    {
        Ok(Some(ts)) => write_marker(write, target, &ts).await,
        Ok(None) => write_marker(write, target, "*").await,
        Err(e) => {
            eprintln!(
                "bnc: read marker query failed for {account}/{}/{target}: {e}",
                history.network
            );
            fail_markread(
                write,
                HistoryFail::TemporarilyUnavailable,
                target,
                "read markers unavailable",
            )
            .await
        }
    }
}

/// The persisted history store for a network, or a loud `FAIL` and `None` when
/// the network has none configured (paging a store-less network must not look
/// like an empty backlog — DESIGN §2: no silent fallbacks). `context` is the
/// request the FAIL answers.
async fn require_history(
    handle: &NetworkHandle,
    write: &mut (impl AsyncWrite + Unpin),
    context: &[&str],
) -> std::io::Result<Option<NetworkHistory>> {
    match handle.history() {
        Some(h) => Ok(Some(h)),
        None => {
            fail(
                write,
                HistoryFail::MessageError,
                context,
                "history store not configured",
            )
            .await?;
            Ok(None)
        }
    }
}

/// `CHATHISTORY <LATEST|BEFORE|AFTER|AROUND> <target> <selector> <limit>` and
/// `CHATHISTORY BETWEEN <target> <selector> <selector> <limit>`.
async fn paged(
    handle: &NetworkHandle,
    write: &mut (impl AsyncWrite + Unpin),
    caps: AttachCaps,
    sub: ChathistorySub,
    params: &[&str],
) -> std::io::Result<()> {
    let expected = sub.parameter_count();
    let name = sub.name();
    if params.len() < expected {
        return fail(
            write,
            HistoryFail::NeedMoreParams,
            &[name],
            "Missing parameters",
        )
        .await;
    }
    let target = params[1];
    let context = [name, target];
    let refuse = |refusal: Refusal| (refusal.code, refusal.detail);
    if params.len() > expected {
        let (code, detail) = refuse(sub.too_many_parameters());
        return fail(write, code, &context, detail).await;
    }
    if !valid_target(target) {
        return fail(
            write,
            HistoryFail::InvalidTarget,
            &context,
            "invalid target",
        )
        .await;
    }
    let second = if sub.takes_two_selectors() {
        params[3]
    } else {
        "*"
    };
    let (selector, selector2) = match parse_selectors(sub, params[2], second) {
        Ok((first, second)) => (stored_selector(first), stored_selector(second)),
        Err(refusal) => {
            let (code, detail) = refuse(refusal);
            return fail(write, code, &context, detail).await;
        }
    };
    let limit = match parse_limit(params[expected - 1]) {
        Ok(limit) => i64::try_from(limit).expect("a page limit fits a database integer"),
        Err(refusal) => {
            let (code, detail) = refuse(refusal);
            return fail(write, code, &context, detail).await;
        }
    };
    let paging = match sub {
        ChathistorySub::Latest => Paging::Latest,
        ChathistorySub::Before => Paging::Before,
        ChathistorySub::After => Paging::After,
        ChathistorySub::Around => Paging::Around,
        ChathistorySub::Between => Paging::Between,
    };
    let Some(history) = require_history(handle, write, &context).await? else {
        return Ok(());
    };
    match crate::db::bnc_history_window(
        &history.pool,
        &history.owner,
        &history.network,
        target,
        handle.names().casemapping(),
        paging,
        crate::db::BncHistoryScope::for_message_tags(caps.message_tags),
        &selector,
        &selector2,
        limit,
    )
    .await
    {
        Ok(Ok(rows)) => reply_lines(write, caps, target, &rows).await,
        // A `msgid=` selector that names no message in the buffer being paged
        // is not an empty page: a client resuming from the last message it saw
        // would read an empty page as "nothing new" when the truth is "that
        // position is gone". (A timestamp always names a position, so one that
        // matches nothing is a genuinely empty page.)
        Ok(Err(crate::db::UnknownBncMsgid)) => {
            fail(write, HistoryFail::MessageError, &context, "unknown msgid").await
        }
        Err(e) => db_error(write, &context, e).await,
    }
}

/// A parsed selector as the store compares it: a message id, or a timestamp in
/// the stored representation.
fn stored_selector(selector: Selector) -> HistorySelector {
    match selector {
        Selector::Star => HistorySelector::Star,
        Selector::Msgid(msgid) => HistorySelector::Msgid(msgid),
        Selector::Timestamp(ms) => HistorySelector::Timestamp(e6irc_proto::time::server_time(ms)),
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
    const CONTEXT: &[&str] = &["TARGETS"];
    let window = match parse_targets(params) {
        Ok(window) => window,
        Err(refusal) => return fail(write, refusal.code, CONTEXT, refusal.detail).await,
    };
    let minimum = e6irc_proto::time::server_time(window.after);
    let maximum = e6irc_proto::time::server_time(window.before);
    let count = i64::try_from(window.limit).expect("a page limit fits a database integer");
    let Some(history) = require_history(handle, write, CONTEXT).await? else {
        return Ok(());
    };
    let rows = match crate::db::bnc_history_targets(
        &history.pool,
        &history.owner,
        &history.network,
        crate::db::BncHistoryScope::for_message_tags(caps.message_tags),
        &minimum,
        &maximum,
        count,
    )
    .await
    {
        Ok(rows) => rows,
        Err(e) => return db_error(write, CONTEXT, e).await,
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
            write.write_all(in_batch(&tag, line).as_bytes()).await?;
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

/// `line` as a member of batch `tag`: the `batch=` tag leads its tag section,
/// merged into the tags the line already carries. A line inside a `BATCH`
/// without it is, to the client, not part of the batch at all.
fn in_batch(tag: &str, line: &str) -> String {
    match line.strip_prefix('@') {
        Some(tagged) => format!("@batch={tag};{tagged}"),
        None => format!("@batch={tag} {line}"),
    }
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
            // The query already excluded what this client cannot receive, so a
            // row with nothing left to send means the two disagree -- which
            // would shorten the page silently, the very fault the scope fixes.
            // Say so on the wire instead of quietly sending fewer lines.
            let Some(line) = history_replay_line(row, caps) else {
                eprintln!(
                    "bnc: stored backlog line {} is undeliverable inside its own history scope",
                    row.id,
                );
                return ":*bnc* NOTICE * :backlog line omitted: not deliverable to this client\r\n"
                    .to_string();
            };
            format!("{line}\r\n")
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
    let without_time = super::without_tag(&filtered, "time");
    match without_time.strip_prefix('@') {
        Some(rest) => format!("@time={};{rest}", row.sent_at),
        None => format!("@time={} {without_time}", row.sent_at),
    }
    .into()
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

/// A `FAIL <command> <code> <context..> :<message>` error reply, rendered by
/// the core's own [`HistoryFail`] so the two surfaces speak one code set.
async fn fail_command(
    write: &mut (impl AsyncWrite + Unpin),
    command: &str,
    code: HistoryFail,
    context: &[&str],
    message: &str,
) -> std::io::Result<()> {
    let line = code.line("*bnc*", command, context, message);
    write.write_all(format!("{line}\r\n").as_bytes()).await?;
    write.flush().await?;
    Ok(())
}

/// A `FAIL CHATHISTORY` error reply.
async fn fail(
    write: &mut (impl AsyncWrite + Unpin),
    code: HistoryFail,
    context: &[&str],
    message: &str,
) -> std::io::Result<()> {
    fail_command(write, "CHATHISTORY", code, context, message).await
}

/// A `FAIL MARKREAD <code> <target>` error reply.
async fn fail_markread(
    write: &mut (impl AsyncWrite + Unpin),
    code: HistoryFail,
    target: &str,
    message: &str,
) -> std::io::Result<()> {
    fail_command(write, "MARKREAD", code, &[target], message).await
}

/// Surface a history-store query failure as a loud FAIL, never a silent empty
/// page (DESIGN §2: no silent fallbacks): the spec's `MESSAGE_ERROR`, naming
/// the request it answers.
async fn db_error(
    write: &mut (impl AsyncWrite + Unpin),
    context: &[&str],
    e: crate::db::DbError,
) -> std::io::Result<()> {
    eprintln!("bnc: chathistory query failed: {e}");
    fail(
        write,
        HistoryFail::MessageError,
        context,
        "history store unavailable",
    )
    .await
}

/// Whether `target` can name one conversation of an external network. Its
/// channel types, nick grammar and lengths are the network's (Ergo's Unicode
/// nicks, IRCnet's `!` channels, a `NICKLEN` of 32), and the conversations
/// the bouncer files are named as the network named them, so the check is
/// structural: one parameter, one name, no longer than any channel name
/// (RFC 1459's 200 bytes, which bounds every nick a network accepts too).
fn valid_target(target: &str) -> bool {
    !target.is_empty()
        && target != "*"
        && target.len() <= super::ConfirmedChannel::MAX_BYTES
        && !target.starts_with(':')
        && !target
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == ',')
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
    fn targets_are_closed_bounded_values() {
        // Whatever the network names: Unicode and long nicks, `!` channels.
        for valid in [
            "#room",
            "&local",
            "SomeNick",
            "zoë",
            "!ABCDEchan",
            "a-thirty-two-byte-nick-on-ergo-x",
            &"x".repeat(200),
        ] {
            assert!(valid_target(valid), "{valid}");
        }
        for invalid in ["", "*", ":colon", "bad,target", "two words", "bell\u{7}"] {
            assert!(!valid_target(invalid), "{invalid:?}");
        }
        assert!(!valid_target(&"x".repeat(201)));
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
        assert_eq!(
            reply,
            ":*bnc* FAIL CHATHISTORY MESSAGE_ERROR LATEST #room :history store not configured\r\n"
        );
    }

    /// The bouncer answers with the core's codes and context parameters, and
    /// validation precedes storage (none is configured here, and only the
    /// well-formed MARKREAD query reaches the store check).
    #[tokio::test]
    async fn chathistory_and_markread_failures_use_the_core_code_set() {
        let (mut client, mut server) = tokio::io::duplex(8192);
        let (handle, _ends) = NetworkHandle::channels(4);
        let caps = AttachCaps {
            chathistory: true,
            ..AttachCaps::default()
        };
        for params in [
            vec!["FROB", "#room"],
            vec![],
            vec!["latest", "#room", "*"],
            vec![
                "BEFORE",
                "bad,target",
                "timestamp=2026-01-01T00:00:00.000Z",
                "5",
            ],
            vec!["BEFORE", "#room", "nonsense=1", "5"],
            vec!["TARGETS", "timestamp=2026-01-01T00:00:00.000Z"],
            vec!["LATEST", "#room", "*", "501"],
            vec!["LATEST", "#room", "*", "10", "extra"],
            vec!["BETWEEN", "#room", "timestamp=bad", "foo=1", "10"],
        ] {
            handle_chathistory(&handle, &mut server, caps, &params)
                .await
                .expect("history rejection");
        }
        for params in [
            vec![],
            vec!["#room", "timestamp=2026-01-01T00:00:00.000Z", "extra"],
            vec!["#room", "2026-01-01T00:00:00.000Z"],
            vec!["#room", "timestamp=not-a-time"],
            vec!["*"],
            vec!["#room"],
        ] {
            handle_markread(&handle, &mut server, "alice", 0, &params)
                .await
                .expect("markread rejection");
        }
        server.shutdown().await.expect("close server half");
        let mut replies = String::new();
        client
            .read_to_string(&mut replies)
            .await
            .expect("read replies");
        let lines: Vec<&str> = replies.split("\r\n").filter(|l| !l.is_empty()).collect();
        assert_eq!(
            lines,
            [
                ":*bnc* FAIL CHATHISTORY UNKNOWN_COMMAND FROB :Unknown subcommand",
                ":*bnc* FAIL CHATHISTORY NEED_MORE_PARAMS * :Missing parameters",
                ":*bnc* FAIL CHATHISTORY NEED_MORE_PARAMS LATEST :Missing parameters",
                ":*bnc* FAIL CHATHISTORY INVALID_TARGET BEFORE bad,target :invalid target",
                ":*bnc* FAIL CHATHISTORY INVALID_MSGREFTYPE BEFORE #room :Unknown message reference type",
                ":*bnc* FAIL CHATHISTORY NEED_MORE_PARAMS TARGETS :Expected exactly two timestamp= bounds and a limit",
                ":*bnc* FAIL CHATHISTORY INVALID_PARAMS LATEST #room :limit must be between 1 and 500",
                ":*bnc* FAIL CHATHISTORY INVALID_PARAMS LATEST #room :Expected exactly <target> <selector> <limit>",
                ":*bnc* FAIL CHATHISTORY INVALID_MSGREFTYPE BETWEEN #room :Unknown message reference type",
                ":*bnc* FAIL MARKREAD NEED_MORE_PARAMS * :Not enough parameters",
                ":*bnc* FAIL MARKREAD INVALID_PARAMS #room :Expected <target> [timestamp=<time>]",
                ":*bnc* FAIL MARKREAD INVALID_PARAMS #room :Expected timestamp=",
                ":*bnc* FAIL MARKREAD INVALID_PARAMS #room :Malformed timestamp",
                ":*bnc* FAIL MARKREAD INVALID_PARAMS * :Invalid target",
                ":*bnc* FAIL MARKREAD TEMPORARILY_UNAVAILABLE #room :read markers are not configured",
            ]
        );
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

    /// Every line inside a batch names it: merged into a tag section the line
    /// already has, or opening one.
    #[tokio::test]
    async fn each_line_inside_a_batch_carries_its_reference() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        write_batch(
            &mut server,
            true,
            HistoryBatch::Messages("#room"),
            &[
                "@time=2026-01-01T00:00:00.000Z :a!a@h PRIVMSG #room :tagged\r\n".into(),
                ":b!b@h PRIVMSG #room :untagged\r\n".into(),
            ],
        )
        .await
        .expect("write batch");
        server.shutdown().await.expect("close server half");
        let mut reply = String::new();
        client.read_to_string(&mut reply).await.expect("read batch");
        let lines: Vec<&str> = reply.split("\r\n").filter(|l| !l.is_empty()).collect();
        let reference = lines[0]
            .strip_prefix(":*bnc* BATCH +")
            .and_then(|rest| rest.split_once(' '))
            .map(|(reference, _)| reference)
            .unwrap_or_else(|| panic!("batch open: {reply}"));
        assert_eq!(
            lines[1..],
            [
                format!(
                    "@batch={reference};time=2026-01-01T00:00:00.000Z :a!a@h PRIVMSG #room :tagged"
                ),
                format!("@batch={reference} :b!b@h PRIVMSG #room :untagged"),
                format!(":*bnc* BATCH -{reference}"),
            ]
        );
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
}
