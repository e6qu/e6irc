//! Message history for the web client and API consumers.

use super::*;

const DEFAULT_HISTORY_PAGE_SIZE: usize = 50;
const MAX_HISTORY_PAGE_SIZE: usize = 500;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HistoryParams {
    pub(super) target: String,
    #[serde(default)]
    pub(super) before: Option<String>,
    #[serde(default)]
    pub(super) after: Option<String>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
}

#[derive(Clone, Copy)]
struct HistoryPageSize(usize);

impl HistoryPageSize {
    fn parse(value: Option<usize>) -> Result<Self, &'static str> {
        let value = value.unwrap_or(DEFAULT_HISTORY_PAGE_SIZE);
        if !(1..=MAX_HISTORY_PAGE_SIZE).contains(&value) {
            return Err("limit must be between 1 and 500");
        }
        Ok(Self(value))
    }

    fn get(self) -> usize {
        self.0
    }
}

/// Why a history request is refused, and the query parameter at fault.
///
/// This API positions a page by time only. A message id is not a position it
/// accepts — `before=<msgid>` is an invalid timestamp, refused here — so it has
/// no way to be asked for the page beside a message the store no longer holds,
/// and an empty page always means "nothing in that window".
#[derive(Debug, PartialEq, Eq)]
struct HistoryQueryRefusal {
    message: &'static str,
    field: &'static str,
}

fn parse_history_query(
    params: &HistoryParams,
) -> Result<crate::core::HistoryQuery, HistoryQueryRefusal> {
    let refuse = |field, message| HistoryQueryRefusal { message, field };
    if params.target.is_empty() {
        return Err(refuse("target", "target must not be empty"));
    }
    let limit = HistoryPageSize::parse(params.limit)
        .map_err(|message| refuse("limit", message))?
        .get();
    match (&params.before, &params.after) {
        (Some(_), Some(_)) => Err(refuse("after", "before and after are mutually exclusive")),
        (Some(ts), None) => e6irc_proto::time::parse_server_time_millis(ts)
            .map(|before_ts| crate::core::HistoryQuery::Before { before_ts, limit })
            .ok_or(refuse("before", "before must be an RFC 3339 timestamp")),
        (None, Some(ts)) => e6irc_proto::time::parse_server_time_millis(ts)
            .map(|after_ts| crate::core::HistoryQuery::After { after_ts, limit })
            .ok_or(refuse("after", "after must be an RFC 3339 timestamp")),
        (None, None) => Ok(crate::core::HistoryQuery::Latest { limit }),
    }
}

#[derive(serde::Serialize)]
struct HistoryMessage {
    msgid: String,
    time: String,
    from: String,
    kind: String,
    body: String,
}

#[derive(serde::Serialize)]
struct HistoryResponse {
    target: String,
    messages: Vec<HistoryMessage>,
}
pub(super) async fn history(
    State(state): State<Arc<AppState>>,
    Authenticated(account, _): Authenticated,
    QueryParams(params): QueryParams<HistoryParams>,
) -> Response {
    let pool = pool_of(&state);
    let query = match parse_history_query(&params) {
        Ok(query) => query,
        Err(refusal) => {
            return problem_at_field(
                StatusCode::BAD_REQUEST,
                refusal.message,
                None,
                Some(refusal.field),
            );
        }
    };
    let target_folded = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(&params.target);
    let account_folded = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(&account);
    let target_folded = if target_folded.starts_with('#') {
        match crate::db::account_may_read_channel(pool, &target_folded, &account_folded).await {
            Ok(true) => target_folded,
            Ok(false) => {
                return problem(
                    StatusCode::FORBIDDEN,
                    "Not authorized to read this target's history",
                    None,
                );
            }
            Err(e) => {
                eprintln!("http: history authorization query failed: {e}");
                return problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Database unavailable",
                    None,
                );
            }
        }
    } else {
        crate::core::dm_conversation_key(&account_folded, &target_folded).0
    };
    // REST reads a channel only for its founder and access list (above), who
    // keep the whole record; a conversation's key is derived from the caller.
    let floor = crate::core::HistoryFloor::Whole;
    let rows = match crate::db::query_history(pool, &target_folded, floor, query).await {
        Ok(rows) => rows,
        Err(e) => {
            eprintln!("http: history query failed: {e}");
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            );
        }
    };
    let messages = rows
        .into_iter()
        .map(|row| HistoryMessage {
            msgid: row.msgid,
            time: e6irc_proto::time::server_time(row.ts),
            from: row.sender_prefix,
            kind: row.kind.wire().into(),
            body: row.body,
        })
        .collect();
    json_no_store(HistoryResponse {
        target: params.target,
        messages,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(limit: Option<usize>, before: Option<&str>, after: Option<&str>) -> HistoryParams {
        HistoryParams {
            target: "#channel".into(),
            before: before.map(str::to_owned),
            after: after.map(str::to_owned),
            limit,
        }
    }

    #[test]
    fn history_page_window_is_closed() {
        assert!(matches!(
            parse_history_query(&params(None, None, None)),
            Ok(crate::core::HistoryQuery::Latest { limit: 50 })
        ));
        assert!(parse_history_query(&params(Some(0), None, None)).is_err());
        assert!(parse_history_query(&params(Some(501), None, None)).is_err());
        assert!(
            parse_history_query(&HistoryParams {
                target: String::new(),
                before: None,
                after: None,
                limit: None,
            })
            .is_err()
        );
        assert!(
            parse_history_query(&params(
                Some(1),
                Some("2026-01-01T00:00:00.000Z"),
                Some("2026-01-02T00:00:00.000Z"),
            ))
            .is_err()
        );
    }

    #[test]
    fn a_refused_window_names_the_parameter_at_fault() {
        let field = |params| parse_history_query(&params).expect_err("refused").field;
        assert_eq!(field(params(Some(0), None, None)), "limit");
        // A message id is not a position this API accepts.
        assert_eq!(field(params(None, Some("01JABCDEFmsgid"), None)), "before");
        assert_eq!(field(params(None, None, Some("01JABCDEFmsgid"))), "after");
        assert_eq!(
            field(HistoryParams {
                target: String::new(),
                before: None,
                after: None,
                limit: None,
            }),
            "target"
        );
    }
}
