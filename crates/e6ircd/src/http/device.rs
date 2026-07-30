//! Device authorization grant (RFC 8628).

use super::*;

// ---- device authorization grant (RFC 8628) ------------------------------

/// Start a device grant. No auth: the client is not yet a principal, but each
/// call inserts a live `device_grants` row that pruning cannot touch for 10
/// minutes — `RateLimited` caps the per-IP rate so an anonymous flood can't
/// accumulate rows unboundedly.
pub(super) async fn device_start(State(state): State<Arc<AppState>>, _rl: RateLimited) -> Response {
    let Some(pool) = &state.pool else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "No database configured",
            None,
        );
    };
    match crate::db::create_device_grant(pool).await {
        Ok((device_code, user_code)) => {
            let verification_uri = format!(
                "{}/device",
                state
                    .public_url
                    .as_deref()
                    .unwrap_or("")
                    .trim_end_matches('/')
            );
            (
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::json!({
                    "device_code": device_code,
                    "user_code": user_code,
                    "verification_uri": verification_uri,
                    "interval": 5,
                    "expires_in": 600,
                })
                .to_string(),
            )
                .into_response()
        }
        Err(e) => {
            eprintln!("http: device start failed: {e}");
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            )
        }
    }
}

#[derive(Deserialize)]
pub(super) struct DeviceTokenReq {
    pub(super) device_code: String,
}

/// Poll for the token. RFC 8628 error codes on the not-yet-ready cases.
pub(super) async fn device_token(
    State(state): State<Arc<AppState>>,
    // Unauthenticated and each poll opens a DB transaction in `poll_device_grant`
    // *before* validating the code, so an anonymous flood of bogus codes would
    // saturate the connection pool. Rate-limit per client IP like every sibling.
    _rl: RateLimited,
    JsonBody(req): JsonBody<DeviceTokenReq>,
) -> Response {
    let Some(pool) = &state.pool else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "No database configured",
            None,
        );
    };
    let oauth_err = |code: &str| {
        (
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::json!({ "error": code }).to_string(),
        )
            .into_response()
    };
    // The grant is consumed and the token minted in one transaction inside
    // `poll_device_grant`, so a mint failure can't destroy an approved grant.
    match crate::db::poll_device_grant(pool, &req.device_code, "device").await {
        Ok(crate::db::DeviceStatus::Approved(token)) => (
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::json!({ "access_token": token, "token_type": "bearer" }).to_string(),
        )
            .into_response(),
        Ok(crate::db::DeviceStatus::Pending) => oauth_err("authorization_pending"),
        Ok(crate::db::DeviceStatus::Expired) => oauth_err("expired_token"),
        Ok(crate::db::DeviceStatus::Unknown) => oauth_err("invalid_grant"),
        Err(e) => {
            eprintln!("http: device poll failed: {e}");
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            )
        }
    }
}

#[derive(Deserialize)]
pub(super) struct DeviceApproveReq {
    pub(super) user_code: String,
}

/// Normalise a user-typed code (users may type it lowercase or with a
/// separator) and approve its pending grant as `account`. Shared by the JSON
/// API and the `/device` verification page.
pub(super) async fn approve_user_code(
    state: &AppState,
    account: &str,
    raw_code: &str,
) -> Result<bool, crate::db::DbError> {
    let pool = pool_of(state);
    let code: String = raw_code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    crate::db::approve_device_grant(pool, &code, account).await
}

/// Approve a device grant as the signed-in user (cookie-authenticated).
pub(super) async fn device_approve(
    State(state): State<Arc<AppState>>,
    SessionMutation(account): SessionMutation,
    JsonBody(req): JsonBody<DeviceApproveReq>,
) -> Response {
    match approve_user_code(&state, &account, &req.user_code).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => problem(StatusCode::NOT_FOUND, "No such pending code", None),
        Err(e) => {
            eprintln!("http: device approve failed: {e}");
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            )
        }
    }
}

#[allow(clippy::result_large_err)] // Err is the standard full problem Response
pub(super) fn bounded_admin_page_size<T>(
    requested: Option<usize>,
    default_limit: usize,
    make: impl FnOnce(usize) -> Option<T>,
    invalid_title: &'static str,
    detail: &'static str,
) -> Result<T, Response> {
    make(requested.unwrap_or(default_limit))
        .ok_or_else(|| problem(StatusCode::BAD_REQUEST, invalid_title, Some(detail)))
}

#[allow(clippy::result_large_err)] // Err is the standard full problem Response
pub(super) fn positive_admin_cursor(
    before_id: Option<i64>,
    invalid_title: &'static str,
    detail: &'static str,
) -> Result<Option<i64>, Response> {
    if before_id.is_some_and(|id| id <= 0) {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            invalid_title,
            Some(detail),
        ));
    }
    Ok(before_id)
}

#[allow(clippy::result_large_err)] // Err is the standard full problem Response
pub(super) fn printable_exact_filter(
    value: Option<String>,
    maximum_bytes: usize,
    invalid_title: &'static str,
    detail: &'static str,
) -> Result<Option<String>, Response> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > maximum_bytes || value.chars().any(char::is_control) {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            invalid_title,
            Some(detail),
        ));
    }
    Ok(Some(value.to_owned()))
}

#[derive(Default, serde::Deserialize)]
pub(super) struct AccountDirectoryQuery {
    pub(super) limit: Option<usize>,
    pub(super) before_id: Option<i64>,
    pub(super) name: Option<String>,
}

pub(super) struct ValidatedAccountDirectoryQuery {
    pub(super) page_size: crate::db::AccountDirectoryPageSize,
    pub(super) before_id: Option<i64>,
    pub(super) name: Option<String>,
}

impl ValidatedAccountDirectoryQuery {
    pub(super) fn database_filter(&self) -> crate::db::AccountDirectoryFilter<'_> {
        crate::db::AccountDirectoryFilter {
            before_id: self.before_id,
            exact_name: self.name.as_deref(),
            page_size: self.page_size,
        }
    }
}

#[allow(clippy::result_large_err)] // Err is the standard full problem Response
pub(super) fn validate_account_directory_query(
    params: AccountDirectoryQuery,
    default_limit: usize,
) -> Result<ValidatedAccountDirectoryQuery, Response> {
    let page_size = bounded_admin_page_size(
        params.limit,
        default_limit,
        crate::db::AccountDirectoryPageSize::new,
        "Invalid account-directory limit",
        "The account-directory limit must be between 1 and 1,000.",
    )?;
    let before_id = positive_admin_cursor(
        params.before_id,
        "Invalid account-directory cursor",
        "The before_id cursor must be a positive account id.",
    )?;
    let name = printable_exact_filter(
        params.name,
        MAX_ACCOUNT_LEN,
        "Invalid account filter",
        "The exact account name must contain 1–64 printable bytes.",
    )?;
    Ok(ValidatedAccountDirectoryQuery {
        page_size,
        before_id,
        name,
    })
}

/// Page administrator-safe account posture (admin only).
pub(super) async fn admin_accounts(
    State(state): State<Arc<AppState>>,
    _admin: AdminAccount,
    axum::extract::Query(params): axum::extract::Query<AccountDirectoryQuery>,
) -> Response {
    let pool = pool_of(&state);
    let query = match validate_account_directory_query(params, 100) {
        Ok(query) => query,
        Err(response) => return response,
    };
    match crate::db::query_account_directory(pool, query.database_filter()).await {
        Ok(page) => admin_json(serde_json::json!({
            "accounts": page.entries
                .into_iter()
                .map(|entry| {
                    let folded =
                        e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(&entry.name);
                    let configured =
                        state.configured_admin_accounts.contains(&folded);
                    serde_json::json!({
                    "id": entry.id,
                    "name": entry.name,
                    "created_at": entry.created_at,
                    "authentication": {
                        "local_password": entry.has_local_password,
                        "app_passwords": entry.app_passwords,
                        "api_tokens": entry.api_tokens,
                        "oidc_identities": entry.oidc_identities,
                        "browser_sessions": entry.browser_sessions,
                    },
                    "resources": {
                        "networks": entry.networks,
                        "founded_channels": entry.founded_channels,
                    },
                    "administrator": entry.administrator || configured,
                    "administrator_sources": {
                        "durable": entry.administrator,
                        "configuration": configured,
                    },
                    "suspended": entry.suspended,
                })})
                .collect::<Vec<_>>(),
            "next_before_id": page.next_before_id,
        })),
        Err(e) => admin_db_error("account directory", e),
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AccountStateBody {
    suspended: Option<bool>,
    administrator: Option<bool>,
}

pub(super) async fn admin_account_state(
    State(state): State<Arc<AppState>>,
    AdminAccount(actor): AdminAccount,
    axum::extract::Path(account_id): axum::extract::Path<i64>,
    body: Result<axum::Json<AccountStateBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let body = match parse_json(body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let mutation = match (body.suspended, body.administrator) {
        (Some(suspended), None) => {
            super::mutate_account_suspension(&state, &actor, account_id, suspended)
                .await
                .map(|message| ("suspended", suspended, message))
        }
        (None, Some(administrator)) => {
            super::mutate_account_administrator(&state, &actor, account_id, administrator)
                .await
                .map(|message| ("administrator", administrator, message))
        }
        _ => {
            return problem(
                StatusCode::BAD_REQUEST,
                "Invalid account state change",
                Some("Set exactly one of suspended or administrator."),
            );
        }
    };
    match mutation {
        Ok((field, value, message)) => admin_json(serde_json::json!({
            "account_id": account_id,
            (field): value,
            "message": message,
        })),
        Err((status, detail)) => problem(status, "Account state change failed", Some(&detail)),
    }
}

pub(super) fn admin_json(body: serde_json::Value) -> Response {
    let mut response = (
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response();
    no_store(response.headers_mut());
    response
}

pub(super) fn admin_db_error(what: &str, e: impl std::fmt::Display) -> Response {
    eprintln!("http: admin {what} failed: {e}");
    problem(
        StatusCode::SERVICE_UNAVAILABLE,
        "Database unavailable",
        None,
    )
}

/// Aggregate server counts (admin only).
pub(super) async fn admin_stats(
    State(state): State<Arc<AppState>>,
    _admin: AdminAccount,
) -> Response {
    let pool = pool_of(&state);
    match crate::db::server_stats(pool).await {
        Ok((accounts, channels, server_bans)) => admin_json(serde_json::json!({
            "server": state.server_name,
            "network": state.network_name,
            "accounts": accounts,
            "registered_channels": channels,
            "server_bans": server_bans,
        })),
        Err(e) => admin_db_error("server stats", e),
    }
}

#[derive(Default, serde::Deserialize)]
pub(super) struct RegisteredChannelDirectoryQuery {
    pub(super) limit: Option<usize>,
    pub(super) before_id: Option<i64>,
    pub(super) name: Option<String>,
    pub(super) founder: Option<String>,
}

pub(super) struct ValidatedRegisteredChannelDirectoryQuery {
    pub(super) page_size: crate::db::RegisteredChannelDirectoryPageSize,
    pub(super) before_id: Option<i64>,
    pub(super) name: Option<String>,
    pub(super) founder: Option<String>,
}

impl ValidatedRegisteredChannelDirectoryQuery {
    pub(super) fn database_filter(&self) -> crate::db::RegisteredChannelDirectoryFilter<'_> {
        crate::db::RegisteredChannelDirectoryFilter {
            before_id: self.before_id,
            exact_name: self.name.as_deref(),
            exact_founder: self.founder.as_deref(),
            page_size: self.page_size,
        }
    }
}

#[allow(clippy::result_large_err)] // Err is the standard full problem Response
pub(super) fn validate_registered_channel_directory_query(
    params: RegisteredChannelDirectoryQuery,
    default_limit: usize,
) -> Result<ValidatedRegisteredChannelDirectoryQuery, Response> {
    let page_size = bounded_admin_page_size(
        params.limit,
        default_limit,
        crate::db::RegisteredChannelDirectoryPageSize::new,
        "Invalid registered-channel limit",
        "The registered-channel limit must be between 1 and 1,000.",
    )?;
    let before_id = positive_admin_cursor(
        params.before_id,
        "Invalid registered-channel cursor",
        "The before_id cursor must be a positive registered-channel id.",
    )?;
    let name = printable_exact_filter(
        params.name,
        crate::sanitize::CHANNELLEN,
        "Invalid registered-channel filter",
        "The exact channel name must contain 1–50 printable bytes.",
    )?;
    let founder = printable_exact_filter(
        params.founder,
        MAX_ACCOUNT_LEN,
        "Invalid registered-channel filter",
        "The exact founder name must contain 1–64 printable bytes.",
    )?;
    Ok(ValidatedRegisteredChannelDirectoryQuery {
        page_size,
        before_id,
        name,
        founder,
    })
}

/// Filter and page registered-channel policy with its founder (admin only).
pub(super) async fn admin_channels(
    State(state): State<Arc<AppState>>,
    _admin: AdminAccount,
    axum::extract::Query(params): axum::extract::Query<RegisteredChannelDirectoryQuery>,
) -> Response {
    let pool = pool_of(&state);
    let query = match validate_registered_channel_directory_query(params, 100) {
        Ok(query) => query,
        Err(response) => return response,
    };
    match crate::db::query_registered_channel_directory(pool, query.database_filter()).await {
        Ok(page) => admin_json(serde_json::json!({
            "channels": page.entries
                .into_iter()
                .map(|entry| serde_json::json!({
                    "id": entry.id,
                    "name": entry.name,
                    "founder": entry.founder,
                    "created_at": entry.created_at,
                    "policy": {
                        "keeptopic": entry.keeptopic,
                        "topic_retained": entry.topic_retained,
                        "mlock": entry.mlock,
                        "access_entries": entry.access_entries,
                    },
                }))
                .collect::<Vec<_>>(),
            "next_before_id": page.next_before_id,
        })),
        Err(e) => admin_db_error("registered-channel directory", e),
    }
}

#[derive(Default, serde::Deserialize)]
pub(super) struct ServerBanDirectoryQuery {
    pub(super) limit: Option<usize>,
    pub(super) before_id: Option<i64>,
    pub(super) kind: Option<String>,
    pub(super) mask: Option<String>,
}

pub(super) struct ValidatedServerBanDirectoryQuery {
    pub(super) page_size: crate::db::ServerBanDirectoryPageSize,
    pub(super) before_id: Option<i64>,
    pub(super) kind: Option<String>,
    pub(super) mask: Option<String>,
}

impl ValidatedServerBanDirectoryQuery {
    pub(super) fn database_filter(&self) -> crate::db::ServerBanDirectoryFilter<'_> {
        crate::db::ServerBanDirectoryFilter {
            before_id: self.before_id,
            exact_kind: self.kind.as_deref(),
            exact_mask: self.mask.as_deref(),
            page_size: self.page_size,
        }
    }
}

#[allow(clippy::result_large_err)] // Err is the standard full problem Response
pub(super) fn validate_server_ban_directory_query(
    params: ServerBanDirectoryQuery,
    default_limit: usize,
) -> Result<ValidatedServerBanDirectoryQuery, Response> {
    let page_size = bounded_admin_page_size(
        params.limit,
        default_limit,
        crate::db::ServerBanDirectoryPageSize::new,
        "Invalid server-ban limit",
        "The server-ban limit must be between 1 and 1,000.",
    )?;
    let before_id = positive_admin_cursor(
        params.before_id,
        "Invalid server-ban cursor",
        "The before_id cursor must be a positive server-ban id.",
    )?;
    let kind = match params.kind.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(kind @ ("kline" | "dline" | "xline")) => Some(kind.to_owned()),
        Some(_) => {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                "Invalid server-ban filter",
                Some("The kind filter must be kline, dline, or xline."),
            ));
        }
    };
    let mask = printable_exact_filter(
        params.mask,
        e6irc_proto::message::MAX_LINE_LEN,
        "Invalid server-ban filter",
        "The exact mask must contain 1–512 printable bytes.",
    )?;
    Ok(ValidatedServerBanDirectoryQuery {
        page_size,
        before_id,
        kind,
        mask,
    })
}

/// Filter and page persisted K/D/X-line policy (admin only).
pub(super) async fn admin_server_bans(
    State(state): State<Arc<AppState>>,
    _admin: AdminAccount,
    axum::extract::Query(params): axum::extract::Query<ServerBanDirectoryQuery>,
) -> Response {
    let pool = pool_of(&state);
    let query = match validate_server_ban_directory_query(params, 100) {
        Ok(query) => query,
        Err(response) => return response,
    };
    match crate::db::query_server_ban_directory(pool, query.database_filter()).await {
        Ok(page) => admin_json(serde_json::json!({
            "bans": page.entries
                .into_iter()
                .map(|entry| {
                    serde_json::json!({
                        "id": entry.id,
                        "mask": entry.mask,
                        "reason": entry.reason,
                        "set_by": entry.set_by,
                        "kind": entry.kind,
                        "created_at": entry.created_at,
                    })
                })
                .collect::<Vec<_>>(),
            "next_before_id": page.next_before_id,
        })),
        Err(e) => admin_db_error("server-ban directory", e),
    }
}

#[derive(Default, serde::Deserialize)]
pub(super) struct AuditQuery {
    pub(super) limit: Option<usize>,
    pub(super) before_id: Option<i64>,
    pub(super) actor: Option<String>,
    pub(super) action: Option<String>,
    pub(super) target: Option<String>,
}

pub(super) struct ValidatedAuditQuery {
    pub(super) page_size: crate::db::AuditLogPageSize,
    pub(super) before_id: Option<i64>,
    pub(super) actor: Option<String>,
    pub(super) action: Option<String>,
    pub(super) target: Option<String>,
}

impl ValidatedAuditQuery {
    pub(super) fn database_filter(&self) -> crate::db::AuditLogFilter<'_> {
        crate::db::AuditLogFilter {
            before_id: self.before_id,
            actor: self.actor.as_deref(),
            action: self.action.as_deref(),
            target: self.target.as_deref(),
            page_size: self.page_size,
        }
    }
}

#[allow(clippy::result_large_err)] // Err is the standard full problem Response
fn audit_filter(
    value: Option<String>,
    name: &str,
    maximum: usize,
) -> Result<Option<String>, Response> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.chars().count() > maximum || value.chars().any(char::is_control) {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "Invalid audit filter",
            Some(&format!(
                "The exact {name} filter must contain 1–{maximum} printable characters."
            )),
        ));
    }
    Ok(Some(value.to_owned()))
}

#[allow(clippy::result_large_err)] // Err is the standard full problem Response
pub(super) fn validate_audit_query(
    params: AuditQuery,
    default_limit: usize,
) -> Result<ValidatedAuditQuery, Response> {
    let page_size = bounded_admin_page_size(
        params.limit,
        default_limit,
        crate::db::AuditLogPageSize::new,
        "Invalid audit limit",
        "The audit limit must be between 1 and 1,000.",
    )?;
    let before_id = positive_admin_cursor(
        params.before_id,
        "Invalid audit cursor",
        "The before_id cursor must be a positive audit entry id.",
    )?;
    Ok(ValidatedAuditQuery {
        page_size,
        before_id,
        actor: audit_filter(params.actor, "actor", 128)?,
        action: audit_filter(params.action, "action", 64)?,
        target: audit_filter(params.target, "target", 512)?,
    })
}

/// Query the oper audit log, newest-first (admin only).
pub(super) async fn admin_audit(
    State(state): State<Arc<AppState>>,
    _admin: AdminAccount,
    axum::extract::Query(params): axum::extract::Query<AuditQuery>,
) -> Response {
    let pool = pool_of(&state);
    let query = match validate_audit_query(params, 100) {
        Ok(query) => query,
        Err(response) => return response,
    };
    match crate::db::query_audit_log(pool, query.database_filter()).await {
        Ok(page) => admin_json(serde_json::json!({
            "audit": page.entries
                .into_iter()
                .map(|entry| {
                    serde_json::json!({
                        "id": entry.id, "actor": entry.actor, "action": entry.action,
                        "target": entry.target, "detail": entry.detail,
                        "at": entry.created_at,
                    })
                })
                .collect::<Vec<_>>(),
            "next_before_id": page.next_before_id,
        })),
        Err(e) => admin_db_error("audit log", e),
    }
}

#[cfg(test)]
mod admin_query_tests {
    use super::*;

    #[test]
    fn account_directory_query_validation_preserves_exact_bounded_values() {
        let query = validate_account_directory_query(
            AccountDirectoryQuery {
                limit: Some(25),
                before_id: Some(42),
                name: Some(" Alice ".into()),
            },
            100,
        )
        .expect("valid query");
        assert_eq!(query.page_size.value(), 25);
        assert_eq!(query.before_id, Some(42));
        assert_eq!(query.name.as_deref(), Some("Alice"));
    }

    #[test]
    fn account_directory_query_validation_rejects_invalid_values() {
        for params in [
            AccountDirectoryQuery {
                limit: Some(0),
                ..AccountDirectoryQuery::default()
            },
            AccountDirectoryQuery {
                limit: Some(1_001),
                ..AccountDirectoryQuery::default()
            },
            AccountDirectoryQuery {
                before_id: Some(0),
                ..AccountDirectoryQuery::default()
            },
            AccountDirectoryQuery {
                name: Some("bad\naccount".into()),
                ..AccountDirectoryQuery::default()
            },
            AccountDirectoryQuery {
                name: Some("x".repeat(MAX_ACCOUNT_LEN + 1)),
                ..AccountDirectoryQuery::default()
            },
        ] {
            assert!(validate_account_directory_query(params, 100).is_err());
        }
    }

    #[test]
    fn registered_channel_query_validation_preserves_exact_bounded_values() {
        let query = validate_registered_channel_directory_query(
            RegisteredChannelDirectoryQuery {
                limit: Some(25),
                before_id: Some(42),
                name: Some(" #Ops ".into()),
                founder: Some(" Alice ".into()),
            },
            100,
        )
        .expect("valid query");
        assert_eq!(query.page_size.value(), 25);
        assert_eq!(query.before_id, Some(42));
        assert_eq!(query.name.as_deref(), Some("#Ops"));
        assert_eq!(query.founder.as_deref(), Some("Alice"));
    }

    #[test]
    fn registered_channel_query_validation_rejects_invalid_values() {
        for params in [
            RegisteredChannelDirectoryQuery {
                limit: Some(0),
                ..RegisteredChannelDirectoryQuery::default()
            },
            RegisteredChannelDirectoryQuery {
                before_id: Some(0),
                ..RegisteredChannelDirectoryQuery::default()
            },
            RegisteredChannelDirectoryQuery {
                name: Some("x".repeat(crate::sanitize::CHANNELLEN + 1)),
                ..RegisteredChannelDirectoryQuery::default()
            },
            RegisteredChannelDirectoryQuery {
                founder: Some("bad\nfounder".into()),
                ..RegisteredChannelDirectoryQuery::default()
            },
        ] {
            assert!(validate_registered_channel_directory_query(params, 100).is_err());
        }
    }

    #[test]
    fn server_ban_query_validation_preserves_exact_bounded_values() {
        let query = validate_server_ban_directory_query(
            ServerBanDirectoryQuery {
                limit: Some(25),
                before_id: Some(42),
                kind: Some("kline".into()),
                mask: Some(" Baddie@Host ".into()),
            },
            100,
        )
        .expect("valid query");
        assert_eq!(query.page_size.value(), 25);
        assert_eq!(query.before_id, Some(42));
        assert_eq!(query.kind.as_deref(), Some("kline"));
        assert_eq!(query.mask.as_deref(), Some("Baddie@Host"));
    }

    #[test]
    fn server_ban_query_validation_rejects_invalid_values() {
        for params in [
            ServerBanDirectoryQuery {
                limit: Some(1_001),
                ..ServerBanDirectoryQuery::default()
            },
            ServerBanDirectoryQuery {
                before_id: Some(-1),
                ..ServerBanDirectoryQuery::default()
            },
            ServerBanDirectoryQuery {
                kind: Some("gline".into()),
                ..ServerBanDirectoryQuery::default()
            },
            ServerBanDirectoryQuery {
                mask: Some("bad\rmask".into()),
                ..ServerBanDirectoryQuery::default()
            },
        ] {
            assert!(validate_server_ban_directory_query(params, 100).is_err());
        }
    }

    #[test]
    fn audit_query_validation_preserves_exact_bounded_values() {
        let query = validate_audit_query(
            AuditQuery {
                limit: Some(25),
                before_id: Some(42),
                actor: Some(" alice ".into()),
                action: Some("KLINE".into()),
                target: Some("user@host".into()),
            },
            100,
        )
        .expect("valid query");
        assert_eq!(query.page_size.value(), 25);
        assert_eq!(query.before_id, Some(42));
        assert_eq!(query.actor.as_deref(), Some("alice"));
        assert_eq!(query.action.as_deref(), Some("KLINE"));
        assert_eq!(query.target.as_deref(), Some("user@host"));
    }

    #[test]
    fn audit_query_validation_rejects_invalid_sizes_cursors_and_text() {
        for params in [
            AuditQuery {
                limit: Some(0),
                ..AuditQuery::default()
            },
            AuditQuery {
                limit: Some(1_001),
                ..AuditQuery::default()
            },
            AuditQuery {
                before_id: Some(0),
                ..AuditQuery::default()
            },
            AuditQuery {
                actor: Some("bad\nactor".into()),
                ..AuditQuery::default()
            },
            AuditQuery {
                action: Some("x".repeat(65)),
                ..AuditQuery::default()
            },
            AuditQuery {
                target: Some("x".repeat(513)),
                ..AuditQuery::default()
            },
        ] {
            assert!(validate_audit_query(params, 100).is_err());
        }
    }
}

pub(super) async fn me(
    State(state): State<Arc<AppState>>,
    Authenticated(account): Authenticated,
    headers: axum::http::HeaderMap,
) -> Response {
    // A *valid* session cookie yields the rich OIDC identity (email/role/
    // provider/logout URL). A stale or absent cookie falls through to Bearer —
    // the precedence every other route uses — so a valid PAT still works
    // alongside a stale cookie (previously that combination returned 401). A DB
    // fault is the one case that does not fall through: it is reported, not
    // masked as "no session".
    if let (Some(token), Some(pool)) = (session_token(&headers, state.secure_cookies), &state.pool)
    {
        match crate::db::session_identity(pool, &token).await {
            Ok(Some(identity)) => {
                let mut response = (
                    [(header::CONTENT_TYPE, "application/json")],
                    serde_json::json!({
                        "account": identity.account,
                        "email": identity.email,
                        "role": identity.role,
                        "provider": identity.provider,
                        "release_revision": state.application_release_revision,
                        "csrf_token": state.csrf_token(&token),
                        "logout_url": format!(
                            "/api/v1/auth/logout?csrf={}",
                            state.csrf_token(&token)
                        ),
                    })
                    .to_string(),
                )
                    .into_response();
                // This body carries the session-bound CSRF token; keep it out of
                // any shared/proxy cache.
                no_store(response.headers_mut());
                return response;
            }
            Ok(None) => {} // stale cookie: fall through to Bearer
            Err(error) => {
                eprintln!("http: identity lookup failed: {error}");
                return problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Database unavailable",
                    None,
                );
            }
        }
    }
    (
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::json!({ "account": account }).to_string(),
    )
        .into_response()
}

#[derive(Deserialize)]
pub(super) struct TokenRequest {
    pub(super) label: String,
    #[serde(default = "default_token_scopes")]
    pub(super) scopes: Vec<crate::identity::ApiTokenScope>,
    #[serde(default = "default_token_lifetime_days")]
    pub(super) expires_in_days: u16,
}

fn default_token_scopes() -> Vec<crate::identity::ApiTokenScope> {
    vec![
        crate::identity::ApiTokenScope::Read,
        crate::identity::ApiTokenScope::Write,
        crate::identity::ApiTokenScope::Irc,
    ]
}

const fn default_token_lifetime_days() -> u16 {
    crate::identity::ApiTokenLifetimeDays::DEFAULT.value()
}

/// Mint a PAT for the authenticated account (shown once).
pub(super) async fn create_api_token(
    State(state): State<Arc<AppState>>,
    SessionMutation(account): SessionMutation,
    body: Result<axum::Json<TokenRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let req = match super::parse_json(body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    if let Some(resp) = validate_label(&req.label) {
        return resp;
    }
    let Some(scopes) = crate::identity::ApiTokenScopes::new(req.scopes.iter().copied()) else {
        return problem(
            StatusCode::BAD_REQUEST,
            "Invalid token scopes",
            Some("Choose at least one closed token scope."),
        );
    };
    let Some(lifetime) = crate::identity::ApiTokenLifetimeDays::new(req.expires_in_days) else {
        return problem(
            StatusCode::BAD_REQUEST,
            "Invalid token lifetime",
            Some("expires_in_days must be between 1 and 365."),
        );
    };
    let pool = pool_of(&state);
    // The per-account PAT cap is enforced atomically inside `issue_api_token`
    // (count + insert in one FOR UPDATE transaction), so there is no racy
    // list-then-insert here: two concurrent creates can't both slip past cap-1.
    match crate::db::issue_scoped_api_token(pool, &account, &req.label, scopes, lifetime).await {
        Ok(token) => (
            StatusCode::CREATED,
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::json!({
                "token": token,
                "label": req.label,
                "scopes": scopes.iter().collect::<Vec<_>>(),
                "expires_in_days": lifetime.value(),
                "note": "Store this now; it is not retrievable later.",
            })
            .to_string(),
        )
            .into_response(),
        Err(crate::db::DbError::TooManyCredentials) => problem(
            StatusCode::CONFLICT,
            "Too many tokens",
            Some("Revoke an existing personal access token first."),
        ),
        Err(e) => {
            eprintln!("http: token issuance failed: {e}");
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            )
        }
    }
}

pub(super) async fn logout(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(pool) = &state.pool else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "No database configured",
            None,
        );
    };
    if let Some(token) = session_token(&headers, state.secure_cookies)
        && let Err(e) = crate::db::delete_web_session(pool, &token).await
    {
        eprintln!("http: logout failed: {e}");
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Database unavailable",
            None,
        );
    }
    (
        StatusCode::NO_CONTENT,
        [(
            header::SET_COOKIE,
            clear_session_cookie(state.secure_cookies),
        )],
    )
        .into_response()
}

/// RP-initiated (front-channel) logout: clear the local session, then
/// navigate the browser to the identity provider's end-session endpoint so
/// the provider's SSO session is ended too — not just the local one. This
/// is a GET so the logout link is a top-level browser navigation (the
/// provider requires that, not a cross-origin fetch). A local-account session
/// returns directly to this application. An OIDC session whose provider is
/// not configured for coordinated logout fails loudly instead of leaving the
/// upstream SSO session active.
#[derive(Deserialize)]
pub(super) struct LogoutQuery {
    #[serde(default)]
    pub(super) csrf: Option<String>,
}

pub(super) async fn logout_sso(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Query(query): Query<LogoutQuery>,
) -> Response {
    let clear = clear_session_cookie(state.secure_cookies);
    let Some(pool) = &state.pool else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "No database configured",
            None,
        );
    };
    let Some(token) = session_token(&headers, state.secure_cookies) else {
        return (
            StatusCode::SEE_OTHER,
            [
                (header::LOCATION, "/auth/signed-out".to_string()),
                (header::SET_COOKIE, clear),
            ],
        )
            .into_response();
    };
    // Bind this destructive GET to the session's CSRF token, so a cross-site
    // top-level navigation can't force-logout the victim. RP-initiated OIDC
    // logout must stay a GET navigation, so the token rides the query string.
    if !query
        .csrf
        .as_deref()
        .is_some_and(|c| state.csrf_valid(&token, c))
    {
        return problem(StatusCode::FORBIDDEN, "Invalid or missing CSRF token", None);
    }
    let (id_token, provider) = match crate::db::session_logout_hint(pool, &token).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("http: logout hint lookup failed: {e}");
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Session storage failed",
                None,
            );
        }
    };
    let provider_config = provider
        .as_deref()
        .and_then(|name| state.oidc_providers.iter().find(|p| p.name == name));
    // Coordinated logout is all-or-nothing *by design*: if the upstream provider
    // session cannot be ended too, this fails loudly (503) and preserves BOTH
    // the local and upstream sessions rather than tearing down the local one
    // while silently leaving the user signed in at the identity provider. The
    // loud failure lets the user act on it; `oidc_logout_without_end_session_...`
    // pins this contract (a failed logout keeps /me at 200).
    let location = match (id_token, provider, provider_config) {
        (Some(hint), Some(_), Some(provider)) => {
            let Some(endpoint) = provider.end_session_endpoint.as_deref() else {
                return problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "OIDC provider does not support coordinated logout",
                    None,
                );
            };
            let Some(public) = state.public_url.as_deref() else {
                return problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Public application URL is not configured",
                    None,
                );
            };
            let mut url = match openidconnect::url::Url::parse(endpoint) {
                Ok(url) => url,
                Err(e) => {
                    eprintln!("http: invalid end_session_endpoint {endpoint:?}: {e}");
                    return problem(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "OIDC logout endpoint is invalid",
                        None,
                    );
                }
            };
            url.query_pairs_mut()
                .append_pair("id_token_hint", &hint)
                .append_pair("client_id", &provider.client_id)
                .append_pair(
                    "post_logout_redirect_uri",
                    &if provider.name == "shauth" {
                        format!(
                            "{}/auth/shauth/logout/complete",
                            public.trim_end_matches('/')
                        )
                    } else {
                        format!("{}/auth/signed-out", public.trim_end_matches('/'))
                    },
                );
            url.to_string()
        }
        (Some(_), _, _) | (None, Some(_), _) => {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "OIDC session metadata is incomplete",
                None,
            );
        }
        (None, None, None) => "/auth/signed-out".to_string(),
        (None, None, Some(_)) => {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "OIDC session metadata is inconsistent",
                None,
            );
        }
    };
    if let Err(e) = crate::db::delete_web_session(pool, &token).await {
        eprintln!("http: logout failed: {e}");
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Database unavailable",
            None,
        );
    }
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, location), (header::SET_COOKIE, clear)],
    )
        .into_response()
}

/// The only Shauth post-logout redirect registered for e6irc. Query input is
/// deliberately ignored; Shauth owns the one-time correlation that selects
/// the trusted application-local signed-out destination.
pub(super) async fn shauth_logout_complete(State(state): State<Arc<AppState>>) -> Response {
    let Some(provider) = state
        .oidc_providers
        .iter()
        .find(|provider| provider.name == "shauth")
    else {
        return problem(StatusCode::NOT_FOUND, "Shauth is not configured", None);
    };
    let Ok(mut issuer) = openidconnect::url::Url::parse(&provider.issuer_url) else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Shauth issuer is invalid",
            None,
        );
    };
    issuer.set_path("/oauth/logout/complete");
    issuer.set_query(None);
    issuer.set_fragment(None);
    let mut response = (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, issuer.to_string())],
    )
        .into_response();
    no_store(response.headers_mut());
    response
}

pub(super) async fn server_info(State(state): State<Arc<AppState>>) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::json!({
            "server_name": state.server_name,
            "network_name": state.network_name,
            "version": env!("CARGO_PKG_VERSION"),
        })
        .to_string(),
    )
        .into_response()
}
