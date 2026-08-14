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

fn parse_history_query(params: &HistoryParams) -> Result<crate::core::HistoryQuery, &'static str> {
    if params.target.is_empty() {
        return Err("target must not be empty");
    }
    let limit = HistoryPageSize::parse(params.limit)?.get();
    match (&params.before, &params.after) {
        (Some(_), Some(_)) => Err("before and after are mutually exclusive"),
        (Some(ts), None) => e6irc_proto::time::parse_server_time_millis(ts)
            .map(|before_ts| crate::core::HistoryQuery::Before { before_ts, limit })
            .ok_or("invalid before timestamp"),
        (None, Some(ts)) => e6irc_proto::time::parse_server_time_millis(ts)
            .map(|after_ts| crate::core::HistoryQuery::After { after_ts, limit })
            .ok_or("invalid after timestamp"),
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
    Authenticated(account): Authenticated,
    Query(params): Query<HistoryParams>,
) -> Response {
    let pool = pool_of(&state);
    let query = match parse_history_query(&params) {
        Ok(query) => query,
        Err(message) => return problem(StatusCode::BAD_REQUEST, message, None),
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
    let rows = match crate::db::query_history(pool, &target_folded, query).await {
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
    axum::Json(HistoryResponse {
        target: params.target,
        messages,
    })
    .into_response()
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
}
