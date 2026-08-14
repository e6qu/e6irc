use super::*;

#[derive(serde::Serialize)]
struct BrowserSessionResponse {
    id: i64,
    created_at: String,
    expires_at: String,
    method: &'static str,
    provider: Option<String>,
    user_agent: Option<String>,
    current: bool,
}

#[derive(serde::Serialize)]
struct BrowserSessionListResponse {
    sessions: Vec<BrowserSessionResponse>,
}

/// List the caller's unexpired browser sessions. Stable resource identifiers
/// permit revocation; token hashes never leave PostgreSQL.
pub(super) async fn list_browser_sessions(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Authenticated(account): Authenticated,
) -> Response {
    let current = session_token(&headers, state.secure_cookies);
    match crate::db::list_web_sessions(pool_of(&state), &account, current.as_deref()).await {
        Ok(rows) => {
            let sessions = rows
                .into_iter()
                .map(|row| BrowserSessionResponse {
                    id: row.id,
                    created_at: row.created_at,
                    expires_at: row.expires_at,
                    method: if row.provider.is_some() {
                        "oidc"
                    } else {
                        "local"
                    },
                    provider: row.provider,
                    user_agent: row.user_agent,
                    current: row.current,
                })
                .collect::<Vec<_>>();
            json_no_store(BrowserSessionListResponse { sessions })
        }
        Err(error) => {
            eprintln!("http: browser session list failed: {error}");
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            )
        }
    }
}

/// Revoke one browser session owned by the caller. Revoking the request's
/// current cookie also clears that cookie, so the browser cannot retain a
/// visibly logged-in but invalid credential.
pub(super) async fn revoke_browser_session(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Authenticated(account): Authenticated,
    Path(id): Path<i64>,
) -> Response {
    let current = session_token(&headers, state.secure_cookies);
    match crate::db::delete_web_session_by_id(pool_of(&state), &account, id, current.as_deref())
        .await
    {
        Ok(Some(was_current)) => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            if was_current {
                response.headers_mut().insert(
                    header::SET_COOKIE,
                    clear_session_cookie(state.secure_cookies)
                        .parse()
                        .expect("session clear cookie is valid"),
                );
            }
            no_store(response.headers_mut());
            response
        }
        Ok(None) => problem(StatusCode::NOT_FOUND, "No such browser session", None),
        Err(error) => {
            eprintln!("http: browser session revoke failed: {error}");
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            )
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BrowserSessionBulkDeleteQuery {
    except: Option<String>,
}

/// Revoke every browser session other than the cookie session that authorized
/// this request. The selector is explicit so an accidental collection DELETE
/// cannot broaden into a destructive account-wide operation.
pub(super) async fn revoke_other_browser_sessions(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Query(query): Query<BrowserSessionBulkDeleteQuery>,
    Authenticated(account): Authenticated,
) -> Response {
    if query.except.as_deref() != Some("current") {
        return problem(
            StatusCode::BAD_REQUEST,
            "Invalid browser session selector",
            Some("DELETE /api/v1/me/sessions requires except=current."),
        );
    }
    let Some(current) = session_token(&headers, state.secure_cookies) else {
        return problem(
            StatusCode::UNAUTHORIZED,
            "Browser session required",
            Some("A bearer token cannot identify the browser session to preserve."),
        );
    };
    match crate::db::delete_other_web_sessions(pool_of(&state), &account, &current).await {
        Ok(revoked) => json_no_store(serde_json::json!({ "revoked": revoked })),
        Err(error) => {
            eprintln!("http: other browser sessions revoke failed: {error}");
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            )
        }
    }
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LiveConnectionQueryParams {
    pub(super) limit: Option<usize>,
    pub(super) before_id: Option<i64>,
    pub(super) nick: Option<String>,
    pub(super) account: Option<String>,
    pub(super) transport: Option<String>,
    pub(super) oper: Option<String>,
}

/// Owner connection queries deliberately cannot carry an account filter:
/// ownership comes only from the authenticated request.
#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OwnLiveConnectionQueryParams {
    pub(super) limit: Option<usize>,
    pub(super) before_id: Option<i64>,
    pub(super) nick: Option<String>,
    pub(super) transport: Option<String>,
    pub(super) oper: Option<String>,
}

impl From<OwnLiveConnectionQueryParams> for LiveConnectionQueryParams {
    fn from(params: OwnLiveConnectionQueryParams) -> Self {
        Self {
            limit: params.limit,
            before_id: params.before_id,
            nick: params.nick,
            account: None,
            transport: params.transport,
            oper: params.oper,
        }
    }
}

pub(super) struct ValidatedLiveConnectionQuery {
    pub(super) page_size: crate::core::LiveConnectionPageSize,
    pub(super) before_id: Option<u64>,
    pub(super) nick: Option<String>,
    pub(super) account: Option<String>,
    pub(super) transport: Option<crate::core::ConnectionTransport>,
    pub(super) oper: Option<bool>,
}

impl ValidatedLiveConnectionQuery {
    pub(super) fn core_query(
        &self,
        forced_account: Option<&str>,
    ) -> crate::core::LiveConnectionQuery {
        crate::core::LiveConnectionQuery {
            before_id: self.before_id,
            exact_nick: self.nick.clone(),
            exact_account: forced_account
                .map(str::to_owned)
                .or_else(|| self.account.clone()),
            transport: self.transport,
            oper: self.oper,
            page_size: self.page_size,
        }
    }
}

#[allow(clippy::result_large_err)] // Err is the standard full problem Response
pub(super) fn validate_live_connection_query(
    params: LiveConnectionQueryParams,
    default_limit: usize,
) -> Result<ValidatedLiveConnectionQuery, Response> {
    let page_size = super::device::bounded_admin_page_size(
        params.limit,
        default_limit,
        crate::core::LiveConnectionPageSize::new,
        "Invalid live-connection limit",
        "The live-connection limit must be between 1 and 1,000.",
    )?;
    let before_id = super::device::positive_admin_cursor(
        params.before_id,
        "Invalid live-connection cursor",
        "The before_id cursor must be a positive live-connection id.",
    )?
    .map(|id| id as u64);
    let nick = super::device::printable_exact_filter(
        params.nick,
        64,
        "Invalid live-connection filter",
        "The exact nick must contain 1–64 printable bytes.",
    )?;
    let account = super::device::printable_exact_filter(
        params.account,
        MAX_ACCOUNT_LEN,
        "Invalid live-connection filter",
        "The exact account must contain 1–64 printable bytes.",
    )?;
    let transport = match params.transport.as_deref().map(str::trim) {
        None | Some("") => None,
        Some("tcp") => Some(crate::core::ConnectionTransport::Tcp),
        Some("tls") => Some(crate::core::ConnectionTransport::Tls),
        Some("websocket") => Some(crate::core::ConnectionTransport::WebSocket),
        Some("local") => Some(crate::core::ConnectionTransport::Local),
        Some(_) => {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                "Invalid live-connection filter",
                Some("The transport filter must be tcp, tls, websocket, or local."),
            ));
        }
    };
    let oper = match params.oper.as_deref().map(str::trim) {
        None | Some("") => None,
        Some("true") => Some(true),
        Some("false") => Some(false),
        Some(_) => {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                "Invalid live-connection filter",
                Some("The oper filter must be true or false."),
            ));
        }
    };
    Ok(ValidatedLiveConnectionQuery {
        page_size,
        before_id,
        nick,
        account,
        transport,
        oper,
    })
}

#[derive(serde::Serialize)]
struct LiveConnectionResponse {
    id: String,
    nick: String,
    user: String,
    host: String,
    account: Option<String>,
    oper: bool,
    transport: &'static str,
    connected_at: String,
    idle_seconds: u64,
    channels: Vec<String>,
}

#[derive(serde::Serialize)]
struct LiveConnectionPageResponse {
    connections: Vec<LiveConnectionResponse>,
    next_before_id: Option<String>,
}

fn live_connection_response(entry: crate::core::LiveConnectionInfo) -> LiveConnectionResponse {
    LiveConnectionResponse {
        id: entry.id.to_string(),
        nick: entry.nick,
        user: entry.user,
        host: entry.host,
        account: entry.account,
        oper: entry.oper,
        transport: entry.transport.as_str(),
        connected_at: e6irc_proto::time::server_time(entry.connected_at),
        idle_seconds: entry.idle_seconds,
        channels: entry.channels,
    }
}

async fn connection_page(
    state: &AppState,
    query: crate::core::LiveConnectionQuery,
) -> Result<crate::core::LiveConnectionPage, Response> {
    match core_reply(state, crate::core::AdminRequest::ListConnections { query }).await {
        Ok(crate::core::AdminReply::Connections(page)) => Ok(page),
        Ok(_) => {
            eprintln!("http: core returned a mutation reply for a live-connection query");
            Err(problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Live connection directory unavailable",
                None,
            ))
        }
        Err(error) => {
            eprintln!("http: live-connection query failed: {error}");
            Err(problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Live connection directory unavailable",
                None,
            ))
        }
    }
}

fn live_connection_page_response(page: crate::core::LiveConnectionPage) -> Response {
    json_no_store(LiveConnectionPageResponse {
        connections: page
            .entries
            .into_iter()
            .map(live_connection_response)
            .collect(),
        next_before_id: page.next_before_id.map(|id| id.to_string()),
    })
}

pub(super) async fn admin_connections(
    State(state): State<Arc<AppState>>,
    _admin: AdminAccount,
    Query(params): Query<LiveConnectionQueryParams>,
) -> Response {
    let query = match validate_live_connection_query(params, 100) {
        Ok(query) => query,
        Err(response) => return response,
    };
    match connection_page(&state, query.core_query(None)).await {
        Ok(page) => live_connection_page_response(page),
        Err(response) => response,
    }
}

pub(super) async fn me_connections(
    State(state): State<Arc<AppState>>,
    Authenticated(account): Authenticated,
    Query(params): Query<OwnLiveConnectionQueryParams>,
) -> Response {
    let query = match validate_live_connection_query(params.into(), 100) {
        Ok(query) => query,
        Err(response) => return response,
    };
    match connection_page(&state, query.core_query(Some(&account))).await {
        Ok(page) => live_connection_page_response(page),
        Err(response) => response,
    }
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DisconnectConnectionQuery {
    reason: Option<String>,
}

#[allow(clippy::result_large_err)] // Err is the standard full problem Response
pub(super) fn validate_disconnect_reason(reason: String) -> Result<String, Response> {
    let reason = reason.trim();
    if reason.len() > 300 || reason.chars().any(char::is_control) {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "Invalid disconnect reason",
            Some("The disconnect reason must contain at most 300 printable bytes."),
        ));
    }
    Ok(reason.to_owned())
}

async fn disconnect_response(state: &AppState, request: crate::core::AdminRequest) -> Response {
    match core_reply(state, request).await {
        Ok(crate::core::AdminReply::Ok(_)) => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            no_store(response.headers_mut());
            response
        }
        Ok(crate::core::AdminReply::ConnectionMissing) => {
            problem(StatusCode::NOT_FOUND, "No such live connection", None)
        }
        Ok(crate::core::AdminReply::Err(message)) => problem(
            StatusCode::BAD_REQUEST,
            "Disconnect rejected",
            Some(&message),
        ),
        Ok(_) => {
            eprintln!("http: core returned an unexpected live-connection disconnect reply");
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Live connection control unavailable",
                None,
            )
        }
        Err(error) => {
            eprintln!("http: live-connection disconnect failed: {error}");
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Live connection control unavailable",
                None,
            )
        }
    }
}

async fn validated_disconnect(
    state: &AppState,
    connection_id: u64,
    params: DisconnectConnectionQuery,
    make_request: impl FnOnce(u64, String) -> crate::core::AdminRequest,
) -> Response {
    if connection_id == 0 {
        return problem(
            StatusCode::BAD_REQUEST,
            "Invalid live-connection id",
            Some("The live-connection id must be positive."),
        );
    }
    let reason = match validate_disconnect_reason(params.reason.unwrap_or_default()) {
        Ok(reason) => reason,
        Err(response) => return response,
    };
    disconnect_response(state, make_request(connection_id, reason)).await
}

pub(super) async fn admin_disconnect_connection(
    State(state): State<Arc<AppState>>,
    AdminAccount(actor): AdminAccount,
    Path(connection_id): Path<u64>,
    Query(params): Query<DisconnectConnectionQuery>,
) -> Response {
    validated_disconnect(&state, connection_id, params, |connection_id, reason| {
        crate::core::AdminRequest::DisconnectConnection {
            connection_id,
            reason,
            actor,
        }
    })
    .await
}

pub(super) async fn me_disconnect_connection(
    State(state): State<Arc<AppState>>,
    Authenticated(account): Authenticated,
    Path(connection_id): Path<u64>,
    Query(params): Query<DisconnectConnectionQuery>,
) -> Response {
    validated_disconnect(&state, connection_id, params, |connection_id, reason| {
        crate::core::AdminRequest::DisconnectOwnConnection {
            connection_id,
            reason,
            account,
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_bad_query(params: LiveConnectionQueryParams) {
        match validate_live_connection_query(params, 100) {
            Ok(_) => panic!("invalid live-connection query was accepted"),
            Err(response) => assert_eq!(response.status(), StatusCode::BAD_REQUEST),
        }
    }

    #[test]
    fn live_connection_query_parses_once_into_closed_bounded_types() {
        let validated = validate_live_connection_query(
            LiveConnectionQueryParams {
                limit: Some(37),
                before_id: Some(91),
                nick: Some(" Alice ".into()),
                account: Some(" Account ".into()),
                transport: Some("websocket".into()),
                oper: Some("false".into()),
            },
            100,
        )
        .expect("valid query");
        assert_eq!(validated.page_size.value(), 37);
        assert_eq!(validated.before_id, Some(91));
        assert_eq!(validated.nick.as_deref(), Some("Alice"));
        assert_eq!(validated.account.as_deref(), Some("Account"));
        assert_eq!(
            validated.transport,
            Some(crate::core::ConnectionTransport::WebSocket)
        );
        assert_eq!(validated.oper, Some(false));
    }

    #[test]
    fn live_connection_query_rejects_every_unbounded_or_open_ended_value() {
        for limit in [0, crate::core::LiveConnectionPageSize::MAX + 1] {
            assert_bad_query(LiveConnectionQueryParams {
                limit: Some(limit),
                ..Default::default()
            });
        }
        for before_id in [0, -1] {
            assert_bad_query(LiveConnectionQueryParams {
                before_id: Some(before_id),
                ..Default::default()
            });
        }
        for transport in ["udp", "TCP"] {
            assert_bad_query(LiveConnectionQueryParams {
                transport: Some(transport.into()),
                ..Default::default()
            });
        }
        for oper in ["1", "yes"] {
            assert_bad_query(LiveConnectionQueryParams {
                oper: Some(oper.into()),
                ..Default::default()
            });
        }
        for nick in ["line\nbreak".to_string(), "x".repeat(65)] {
            assert_bad_query(LiveConnectionQueryParams {
                nick: Some(nick),
                ..Default::default()
            });
        }
        for account in [
            "line\u{7f}break".to_string(),
            "x".repeat(MAX_ACCOUNT_LEN + 1),
        ] {
            assert_bad_query(LiveConnectionQueryParams {
                account: Some(account),
                ..Default::default()
            });
        }
    }

    #[test]
    fn disconnect_reason_is_trimmed_and_bounded() {
        assert_eq!(
            validate_disconnect_reason(" maintenance ".into()).expect("valid reason"),
            "maintenance"
        );
        for reason in ["line\nbreak".to_string(), "x".repeat(301)] {
            let response = validate_disconnect_reason(reason).expect_err("invalid reason");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn url_queries_reject_unknown_fields() {
        let uri = "/?extra=1".parse().expect("query URI");
        assert!(Query::<BrowserSessionBulkDeleteQuery>::try_from_uri(&uri).is_err());
        assert!(Query::<LiveConnectionQueryParams>::try_from_uri(&uri).is_err());
        assert!(Query::<OwnLiveConnectionQueryParams>::try_from_uri(&uri).is_err());
        assert!(Query::<DisconnectConnectionQuery>::try_from_uri(&uri).is_err());
    }
}
