//! Message history for the web client and API consumers.

use super::*;

// ---- history ------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct HistoryParams {
    pub(super) target: String,
    #[serde(default)]
    pub(super) before: Option<String>,
    #[serde(default)]
    pub(super) after: Option<String>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
}

/// Paged history for the authenticated account. Casefolds the target
/// the same way the IRC path does, so web and IRC see one history.
pub(super) async fn history(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Query(params): Query<HistoryParams>,
) -> Response {
    let account = match authenticate(&state, &headers).await {
        Ok(account) => account,
        Err(response) => return response,
    };
    let pool = pool_of(&state);
    // Authorize the target: without a view of live membership this endpoint
    // must fail closed, so restrict it to channels the account has a
    // registered relationship with (founder or access). Otherwise any account
    // could read any channel's history, including secret (+s) ones.
    let target_folded = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(&params.target);
    let account_folded = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(&account);
    // A channel needs an explicit authorization check. Anything else names a
    // direct-message correspondent, and the conversation key is built *from the
    // authenticated account* — so a caller can only ever address a conversation
    // it is part of, and no check is needed because none can be bypassed. A
    // caller passing a raw conversation key gets a key derived from it in turn,
    // which matches nothing.
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
    let limit = params.limit.unwrap_or(50).min(500);
    let query = match (&params.before, &params.after) {
        (Some(ts), _) => match e6irc_proto::time::parse_server_time_millis(ts) {
            Some(before_ts) => crate::core::HistoryQuery::Before { before_ts, limit },
            None => return problem(StatusCode::BAD_REQUEST, "Invalid 'before' timestamp", None),
        },
        (None, Some(ts)) => match e6irc_proto::time::parse_server_time_millis(ts) {
            Some(after_ts) => crate::core::HistoryQuery::After { after_ts, limit },
            None => return problem(StatusCode::BAD_REQUEST, "Invalid 'after' timestamp", None),
        },
        (None, None) => crate::core::HistoryQuery::Latest { limit },
    };
    let rows = crate::db::query_history(pool, &target_folded, query).await;
    let messages: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "msgid": r.msgid,
                // `HistoryRow::ts` is already milliseconds; scaling it again
                // put every REST timestamp a thousand-fold into the future.
                "time": e6irc_proto::time::server_time(r.ts),
                "from": r.sender_prefix,
                "kind": r.kind.wire(),
                "body": r.body,
            })
        })
        .collect();
    (
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::json!({ "target": params.target, "messages": messages }).to_string(),
    )
        .into_response()
}
