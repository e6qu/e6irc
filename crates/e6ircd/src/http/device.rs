//! Device authorization grant (RFC 8628).

use super::*;

// ---- device authorization grant (RFC 8628) ------------------------------

/// Start a device grant. No auth: the client is not yet a principal.
pub(super) async fn device_start(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
) -> Response {
    // Rate-limit per client IP: this is unauthenticated and each call inserts a
    // live `device_grants` row that pruning cannot touch for 10 minutes, so an
    // anonymous flood would otherwise accumulate rows unboundedly. Gate it like
    // every other unauthenticated work-inducing endpoint (oidc_start, etc.).
    if !auth_rate_ok(
        &state,
        client_ip(peer.ip(), &headers, &state.trusted_proxies),
    ) {
        return problem(StatusCode::TOO_MANY_REQUESTS, "Too many requests", None);
    }
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

/// Approve a device grant as the signed-in user (cookie-authenticated).
pub(super) async fn device_approve(
    State(state): State<Arc<AppState>>,
    Authenticated(account): Authenticated,
    JsonBody(req): JsonBody<DeviceApproveReq>,
) -> Response {
    let pool = pool_of(&state);
    // Normalise: users may type the code lowercase or with a separator.
    let code: String = req
        .user_code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    match crate::db::approve_device_grant(pool, &code, &account).await {
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

/// Authenticate, then require the account be an admin (per config).
/// Returns the account name, or a 401/403 response.
pub(super) async fn require_admin(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<String, Response> {
    let account = authenticate(state, headers).await?;
    let folded = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(&account);
    if state.admin_accounts.contains(&folded) {
        Ok(account)
    } else {
        Err(problem(StatusCode::FORBIDDEN, "Admin only", None))
    }
}

/// List every account (admin only).
pub(super) async fn admin_accounts(
    State(state): State<Arc<AppState>>,
    _admin: AdminAccount,
) -> Response {
    let pool = pool_of(&state);
    match crate::db::list_accounts(pool).await {
        Ok(names) => (
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::json!({ "accounts": names }).to_string(),
        )
            .into_response(),
        Err(e) => {
            eprintln!("http: admin account list failed: {e}");
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            )
        }
    }
}

pub(super) fn admin_json(body: serde_json::Value) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
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

/// List every registered channel with its founder (admin only).
pub(super) async fn admin_channels(
    State(state): State<Arc<AppState>>,
    _admin: AdminAccount,
) -> Response {
    let pool = pool_of(&state);
    match crate::db::list_registered_channels(pool).await {
        Ok(rows) => admin_json(serde_json::json!({
            "channels": rows
                .into_iter()
                .map(|(name, founder)| serde_json::json!({ "name": name, "founder": founder }))
                .collect::<Vec<_>>(),
        })),
        Err(e) => admin_db_error("channel list", e),
    }
}

/// List every server ban / K-line (admin only).
pub(super) async fn admin_server_bans(
    State(state): State<Arc<AppState>>,
    _admin: AdminAccount,
) -> Response {
    let pool = pool_of(&state);
    match crate::db::list_server_bans(pool).await {
        Ok(rows) => admin_json(serde_json::json!({
            "bans": rows
                .into_iter()
                .map(|(mask, reason, set_by, kind)| {
                    serde_json::json!({
                        "mask": mask, "reason": reason, "set_by": set_by, "kind": kind,
                    })
                })
                .collect::<Vec<_>>(),
        })),
        Err(e) => admin_db_error("server-ban list", e),
    }
}

#[derive(serde::Deserialize)]
pub(super) struct AuditQuery {
    pub(super) limit: Option<usize>,
}

/// Query the oper audit log, newest-first (admin only).
pub(super) async fn admin_audit(
    State(state): State<Arc<AppState>>,
    _admin: AdminAccount,
    axum::extract::Query(params): axum::extract::Query<AuditQuery>,
) -> Response {
    let pool = pool_of(&state);
    let limit = params.limit.unwrap_or(100).clamp(1, 1000) as i64;
    match crate::db::list_audit_log(pool, limit).await {
        Ok(rows) => admin_json(serde_json::json!({
            "audit": rows
                .into_iter()
                .map(|(actor, action, target, detail, at)| {
                    serde_json::json!({
                        "actor": actor, "action": action, "target": target,
                        "detail": detail, "at": at,
                    })
                })
                .collect::<Vec<_>>(),
        })),
        Err(e) => admin_db_error("audit log", e),
    }
}

pub(super) async fn me(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Some(token) = session_token(&headers, state.secure_cookies) {
        let Some(pool) = &state.pool else {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "No database configured",
                None,
            );
        };
        return match crate::db::session_identity(pool, &token).await {
            Ok(Some(identity)) => (
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::json!({
                    "account": identity.account,
                    "email": identity.email,
                    "role": identity.role,
                    "provider": identity.provider,
                    "release_revision": state.application_release_revision,
                    "logout_url": format!("/api/v1/auth/logout?csrf={}", state.csrf_token(&token)),
                })
                .to_string(),
            )
                .into_response(),
            Ok(None) => problem(StatusCode::UNAUTHORIZED, "Not logged in", None),
            Err(error) => {
                eprintln!("http: identity lookup failed: {error}");
                problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Database unavailable",
                    None,
                )
            }
        };
    }
    match authenticate(&state, &headers).await {
        Ok(account) => (
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::json!({ "account": account }).to_string(),
        )
            .into_response(),
        Err(response) => response,
    }
}

#[derive(Deserialize)]
pub(super) struct TokenRequest {
    pub(super) label: String,
}

/// Mint a PAT for the authenticated account (shown once).
pub(super) async fn create_api_token(
    State(state): State<Arc<AppState>>,
    Authenticated(account): Authenticated,
    body: Result<axum::Json<TokenRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let axum::Json(req) = match body {
        Ok(b) => b,
        Err(e) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "Invalid request body",
                Some(&e.to_string()),
            );
        }
    };
    let pool = pool_of(&state);
    match crate::db::issue_api_token(pool, &account, &req.label).await {
        Ok(token) => (
            StatusCode::CREATED,
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::json!({
                "token": token,
                "label": req.label,
                "note": "Store this now; it is not retrievable later.",
            })
            .to_string(),
        )
            .into_response(),
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
