//! Device authorization grant (RFC 8628).

use super::*;

macro_rules! json_or_response {
    ($body:expr) => {
        match parse_json($body) {
            Ok(body) => body,
            Err(response) => return response,
        }
    };
}

// ---- device authorization grant (RFC 8628) ------------------------------

/// Start a device grant. No auth: the client is not yet a principal, but each
/// call inserts a live `device_grants` row that pruning cannot touch for 10
/// minutes — `RateLimited` caps the per-IP rate so an anonymous flood can't
/// accumulate rows unboundedly.
pub(super) async fn device_start(State(state): State<Arc<AppState>>, _rl: RateLimited) -> Response {
    let Some(verification_uri) = device_verification_uri(state.public_url.as_deref()) else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Device authorization unavailable",
            Some("http.public_url must be configured to advertise an absolute verification URI"),
        );
    };
    let pool = require_pool!(state);
    match crate::db::create_device_grant(pool).await {
        Ok((device_code, user_code)) => (
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
            .into_response(),
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

fn device_verification_uri(public_url: Option<&str>) -> Option<String> {
    public_url.map(|url| format!("{}/device", url.trim_end_matches('/')))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
    let pool = require_pool!(state);
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
#[serde(deny_unknown_fields)]
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

#[cfg(test)]
mod tests {
    use super::device_verification_uri;

    #[test]
    fn device_verification_uri_requires_a_public_origin() {
        assert_eq!(device_verification_uri(None), None);
        assert_eq!(
            device_verification_uri(Some("https://chat.example/e6irc/")),
            Some("https://chat.example/e6irc/device".into())
        );
    }
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
    AdminAccount(actor): AdminAccount,
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
                    "current": folded == e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(&actor),
                })})
                .collect::<Vec<_>>(),
            "next_before_id": page.next_before_id,
        })),
        Err(e) => admin_db_error("account directory", e),
    }
}

#[derive(serde::Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub(super) enum AccountStateBody {
    Suspension { suspended: bool },
    Administrator { administrator: bool },
}

pub(super) async fn admin_account_state(
    State(state): State<Arc<AppState>>,
    AdminAccount(actor): AdminAccount,
    axum::extract::Path(account_id): axum::extract::Path<i64>,
    body: Result<axum::Json<AccountStateBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let body = json_or_response!(body);
    let mutation = match body {
        AccountStateBody::Suspension { suspended } => {
            super::mutate_account_suspension(&state, &actor, account_id, suspended)
                .await
                .map(|message| ("suspended", suspended, message))
        }
        AccountStateBody::Administrator { administrator } => {
            super::mutate_account_administrator(&state, &actor, account_id, administrator)
                .await
                .map(|message| ("administrator", administrator, message))
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

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdminCreateAccountBody {
    account: String,
    password: String,
    contact_email: Option<String>,
    #[serde(default)]
    administrator: bool,
}

pub(super) async fn admin_create_account(
    State(state): State<Arc<AppState>>,
    AdminAccount(actor): AdminAccount,
    body: Result<axum::Json<AdminCreateAccountBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let body = json_or_response!(body);
    let account_id = match super::create_account_lifecycle(
        &state,
        &actor,
        &body.account,
        &body.password,
        body.contact_email.as_deref(),
        body.administrator,
    )
    .await
    {
        Ok(account_id) => account_id,
        Err((status, detail)) => {
            return problem(status, "Account creation failed", Some(&detail));
        }
    };
    let mut response = admin_json(serde_json::json!({
        "id": account_id,
        "account": body.account,
        "administrator": body.administrator,
    }));
    *response.status_mut() = StatusCode::CREATED;
    response
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdminCreateAccountInvitationBody {
    account: String,
    contact_email: Option<String>,
    expires_in_days: u16,
    #[serde(default)]
    administrator: bool,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct AccountInvitationDirectoryQuery {
    limit: Option<usize>,
    before_id: Option<i64>,
}

#[allow(clippy::result_large_err)] // Err is the standard full problem Response
fn validate_account_invitation_directory_query(
    params: AccountInvitationDirectoryQuery,
    default_limit: usize,
) -> Result<(crate::db::AccountInvitationPageSize, Option<i64>), Response> {
    let page_size = bounded_admin_page_size(
        params.limit,
        default_limit,
        crate::db::AccountInvitationPageSize::new,
        "Invalid invitation-directory limit",
        "The invitation-directory limit must be between 1 and 1,000.",
    )?;
    let before_id = positive_admin_cursor(
        params.before_id,
        "Invalid invitation-directory cursor",
        "The before_id cursor must be a positive invitation id.",
    )?;
    Ok((page_size, before_id))
}

pub(super) async fn admin_account_invitations(
    State(state): State<Arc<AppState>>,
    _admin: AdminAccount,
    axum::extract::Query(params): axum::extract::Query<AccountInvitationDirectoryQuery>,
) -> Response {
    let (page_size, before_id) = match validate_account_invitation_directory_query(params, 100) {
        Ok(query) => query,
        Err(response) => return response,
    };
    match crate::db::list_account_invitations(pool_of(&state), before_id, page_size).await {
        Ok(page) => admin_json(serde_json::json!({
            "invitations": page.entries.into_iter().map(|invitation| {
                serde_json::json!({
                    "id": invitation.id,
                    "account": invitation.account_name,
                    "contact_email": invitation.contact_email,
                    "administrator": invitation.administrator,
                    "created_by": invitation.created_by,
                    "created_at": invitation.created_at,
                    "expires_at": invitation.expires_at,
                })
            }).collect::<Vec<_>>(),
            "next_before_id": page.next_before_id,
        })),
        Err(error) => admin_db_error("account invitation directory", error),
    }
}

pub(super) async fn admin_create_account_invitation(
    State(state): State<Arc<AppState>>,
    AdminAccount(actor): AdminAccount,
    body: Result<
        axum::Json<AdminCreateAccountInvitationBody>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    let body = json_or_response!(body);
    if !crate::sanitize::valid_nick(&body.account, MAX_ACCOUNT_LEN) {
        return problem(
            StatusCode::BAD_REQUEST,
            "Invalid account",
            Some("The account must be a valid IRC nickname of at most 64 bytes."),
        );
    }
    let contact_email = match super::parse_optional_contact_email(body.contact_email.as_deref()) {
        Ok(ce) => ce,
        Err(msg) => return problem(StatusCode::BAD_REQUEST, "Invalid contact email", Some(&msg)),
    };
    let Some(lifetime) = crate::identity::AccountInvitationLifetimeDays::new(body.expires_in_days)
    else {
        return problem(
            StatusCode::BAD_REQUEST,
            "Invalid invitation lifetime",
            Some("Invitation lifetime must be between 1 and 30 days."),
        );
    };
    match crate::db::issue_account_invitation(
        pool_of(&state),
        &body.account,
        contact_email.as_ref(),
        body.administrator,
        lifetime,
        &actor,
    )
    .await
    {
        Ok(token) => {
            let invitation_url = super::account_invitation_url(&state, &token);
            let mut response = admin_json(serde_json::json!({
                "account": body.account,
                "administrator": body.administrator,
                "expires_in_days": body.expires_in_days,
                "invitation_url": invitation_url,
                "note": "This bearer link is shown once and cannot be retrieved later.",
            }));
            *response.status_mut() = StatusCode::CREATED;
            response
        }
        Err(crate::db::DbError::DuplicateAccount(_)) => problem(
            StatusCode::CONFLICT,
            "Account name unavailable",
            Some("The name exists, is retired, or already has a pending invitation."),
        ),
        Err(crate::db::DbError::TooManyInvitations) => problem(
            StatusCode::CONFLICT,
            "Too many pending invitations",
            Some("Revoke or wait for an existing invitation to expire."),
        ),
        Err(error) => admin_db_error("account invitation issuance", error),
    }
}

pub(super) async fn admin_revoke_account_invitation(
    State(state): State<Arc<AppState>>,
    AdminAccount(actor): AdminAccount,
    axum::extract::Path(invitation_id): axum::extract::Path<i64>,
) -> Response {
    match crate::db::revoke_account_invitation(pool_of(&state), invitation_id, &actor).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => problem(StatusCode::NOT_FOUND, "Invitation unavailable", None),
        Err(error) => admin_db_error("account invitation revocation", error),
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AccountDeletionBody {
    confirmation: String,
}

pub(super) async fn admin_delete_account(
    State(state): State<Arc<AppState>>,
    AdminAccount(actor): AdminAccount,
    axum::extract::Path(account_id): axum::extract::Path<i64>,
    body: Result<axum::Json<AccountDeletionBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let body = json_or_response!(body);
    let target = match crate::db::account_name_by_id(pool_of(&state), account_id).await {
        Ok(Some(target)) => target,
        Ok(None) => return problem(StatusCode::NOT_FOUND, "No such account", None),
        Err(error) => return admin_db_error("account deletion target", error),
    };
    if body.confirmation != target {
        return problem(
            StatusCode::BAD_REQUEST,
            "Account confirmation does not match",
            Some("Supply the exact display-cased account name."),
        );
    }
    match super::delete_account_lifecycle(&state, &actor, account_id, false).await {
        Ok(message) => admin_json(serde_json::json!({ "message": message })),
        Err((status, detail)) => problem(status, "Account deletion failed", Some(&detail)),
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
/// Every account's BNC networks with their live driver state (admin only):
/// the fleet-wide view an operator needs to spot a misbehaving upstream
/// without suspending the whole account. Runtime data comes from the same
/// registry snapshots the owner-scoped endpoints serve.
pub(super) async fn admin_networks(
    State(state): State<Arc<AppState>>,
    _admin: AdminAccount,
) -> Response {
    let pool = pool_of(&state);
    match crate::db::list_bnc_network_inventory(pool).await {
        Ok(rows) => {
            let mut networks: Vec<serde_json::Value> = rows
                .into_iter()
                .map(|row| {
                    let runtime = state
                        .bnc_registry
                        .as_ref()
                        .and_then(|r| r.get_owned(&row.owner, &row.network.name))
                        .map(|h| h.runtime_snapshot());
                    let mut value = super::networks::network_json(row.network, runtime.as_ref());
                    value["owner"] = serde_json::json!(row.owner);
                    value
                })
                .collect();
            if let Some(registry) = &state.bnc_registry {
                networks.extend(
                    registry
                        .list()
                        .into_iter()
                        .filter(|status| status.owner.is_none())
                        .map(|status| {
                            serde_json::json!({
                                "owner": "shared",
                                "name": status.name,
                                "kind": status.kind,
                                "enabled": true,
                                "connected": status.connected,
                                "runtime": super::networks::runtime_json(&status.runtime),
                                "shared": true,
                            })
                        }),
                );
            }
            networks.sort_by(|left, right| {
                (left["owner"].as_str(), left["name"].as_str())
                    .cmp(&(right["owner"].as_str(), right["name"].as_str()))
            });
            admin_json(serde_json::json!({ "networks": networks }))
        }
        Err(e) => admin_db_error("network inventory", e),
    }
}

pub(super) async fn admin_stats(
    State(state): State<Arc<AppState>>,
    _admin: AdminAccount,
) -> Response {
    let pool = pool_of(&state);
    let (networks, connected) = crate::http::bnc_counts(&state);
    let live = state.telemetry.snapshot(networks, connected);
    match crate::db::server_stats(pool).await {
        Ok((accounts, channels, server_bans)) => admin_json(serde_json::json!({
            "server": state.server_name,
            "network": state.network_name,
            "accounts": accounts,
            "registered_channels": channels,
            "server_bans": server_bans,
            "version": env!("CARGO_PKG_VERSION"),
            "live": {
                "connections": live.active_connections,
                "connected_upstreams": live.bnc_connected,
                "upstreams": live.bnc_networks,
                "traffic": live.irc_bytes_in_total.saturating_add(live.irc_bytes_out_total).saturating_add(live.bnc_bytes_in_total).saturating_add(live.bnc_bytes_out_total),
                "errors": live.errors.values().sum::<u64>(),
            },
        })),
        Err(e) => admin_db_error("server stats", e),
    }
}

/// Return the revisioned managed configuration without credential material.
/// A client can use `revision` as the compare-and-swap precondition for later
/// writes, but no OIDC, oper, or upstream secret ever crosses this boundary.
pub(super) async fn admin_configuration(
    State(state): State<Arc<AppState>>,
    _admin: AdminAccount,
) -> Response {
    let Some(config) = &state.managed_config else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Configuration unavailable",
            None,
        );
    };
    let snapshot = config.read().await.clone();
    let mut settings = snapshot.settings;
    for provider in &mut settings.oidc_providers {
        provider.client_secret.clear();
    }
    for oper in &mut settings.opers {
        oper.password.clear();
    }
    for network in &mut settings.networks {
        network.sasl_password = None;
        if network.kind.account_is_secret() {
            network.sasl_account = None;
        }
    }
    let bound_bnc_addr = match &state.bnc_listener {
        Some(listener) => listener.status().await.map(|(_, bound)| bound),
        None => None,
    };
    let network_drivers = [
        Some("irc"),
        Some("local"),
        cfg!(feature = "matrix").then_some("matrix"),
        cfg!(feature = "discord").then_some("discord"),
        cfg!(feature = "slack").then_some("slack"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    admin_json(serde_json::json!({
        "revision": snapshot.revision,
        "updated_by": snapshot.updated_by,
        "updated_at": snapshot.updated_at,
        "settings": settings,
        "runtime": {
            "bound_bnc_addr": bound_bnc_addr,
            "http_bind": state.http_bind,
            "has_master_key": state.secret_key.is_some(),
            "master_key_count": state.secret_key.as_ref().map_or(0, |keys| keys.key_count()),
            "release_revision": state.application_release_revision,
            "network_drivers": network_drivers,
        },
    }))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdminOperBody {
    revision: i64,
    name: String,
    password: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdminConfigRevision {
    revision: i64,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdminOidcBody {
    revision: i64,
    name: String,
    issuer_url: String,
    client_id: String,
    client_secret: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    allowed_email_domains: Vec<String>,
    end_session_endpoint: Option<String>,
    token_endpoint_auth_method: crate::config::TokenEndpointAuthMethod,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdminNetworkBody {
    revision: i64,
    name: String,
    owner: Option<String>,
    kind: crate::config::NetworkKind,
    #[serde(default)]
    addr: String,
    tls: bool,
    #[serde(default)]
    nick: String,
    realname: Option<String>,
    #[serde(default)]
    autojoin: Vec<String>,
    buffer_cap: usize,
    sasl_account: Option<String>,
    sasl_password: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdminNetworkDeleteBody {
    revision: i64,
    owner: ManagedNetworkOwner,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum ManagedNetworkOwner {
    Owner(String),
    Shared(()),
}

impl ManagedNetworkOwner {
    fn into_option(self) -> Option<String> {
        match self {
            Self::Owner(owner) => Some(owner),
            Self::Shared(()) => None,
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdminConfigurationPatch {
    revision: i64,
    settings: AdminScalarSettings,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminScalarSettings {
    server_name: String,
    network_name: String,
    description: String,
    motd: Vec<String>,
    nicklen: usize,
    sendq: usize,
    core_queue: usize,
    core_workers: usize,
    max_hot_channels: usize,
    listeners: Vec<crate::config::ListenerConfig>,
    registration: crate::config::RegistrationConfig,
    limits: crate::config::LimitsConfig,
    observability: crate::config::ObservabilityConfig,
    storage: crate::config::StorageConfig,
    bnc_addr: Option<std::net::SocketAddr>,
    public_url: Option<String>,
    secure_cookies: bool,
    admin_accounts: Vec<String>,
}

impl AdminScalarSettings {
    fn apply_to(self, current: &crate::config::ManagedConfig) -> crate::config::ManagedConfig {
        crate::config::ManagedConfig {
            server_name: self.server_name,
            network_name: self.network_name,
            description: self.description,
            motd: self.motd,
            nicklen: self.nicklen,
            sendq: self.sendq,
            core_queue: self.core_queue,
            core_workers: self.core_workers,
            max_hot_channels: self.max_hot_channels,
            listeners: self.listeners,
            registration: self.registration,
            limits: self.limits,
            observability: self.observability,
            storage: self.storage,
            bnc_addr: self.bnc_addr,
            public_url: self.public_url,
            secure_cookies: self.secure_cookies,
            admin_accounts: self.admin_accounts,
            oidc_providers: current.oidc_providers.clone(),
            opers: current.opers.clone(),
            networks: current.networks.clone(),
            credentials_from_bootstrap: current.credentials_from_bootstrap,
        }
    }
}

pub(super) async fn admin_patch_configuration(
    State(state): State<Arc<AppState>>,
    AdminAccount(actor): AdminAccount,
    body: Result<axum::Json<AdminConfigurationPatch>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let body = match parse_json(body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let Some(config) = &state.managed_config else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Configuration unavailable",
            None,
        );
    };
    let mut current = config.write().await;
    if current.revision != body.revision {
        return problem(
            StatusCode::CONFLICT,
            "Configuration revision conflict",
            Some("Reload the configuration and retry with its current revision."),
        );
    }
    let settings = body.settings.apply_to(&current.settings);
    if let Err(error) = settings.validate() {
        return problem(
            StatusCode::BAD_REQUEST,
            "Invalid configuration",
            Some(&error.to_string()),
        );
    }
    let previous_bnc = current.settings.bnc_addr;
    let bnc_changed = previous_bnc != settings.bnc_addr;
    if bnc_changed {
        let Some(listener) = &state.bnc_listener else {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "BNC listener unavailable",
                None,
            );
        };
        let applied = match settings.bnc_addr {
            Some(address) => listener
                .enable(address)
                .await
                .map(|_| ())
                .map_err(|error| format!("Could not bind {address}: {error}")),
            None => {
                listener.stop().await;
                Ok(())
            }
        };
        if let Err(error) = applied {
            return problem(
                StatusCode::BAD_REQUEST,
                "Invalid BNC listener",
                Some(&error),
            );
        }
    }
    let mut restart_comparison = current.settings.clone();
    restart_comparison.bnc_addr = settings.bnc_addr;
    restart_comparison.observability = settings.observability.clone();
    let restart_required = restart_comparison != settings;
    let detail = format!(
        "revision {}; BNC listener {}; restart {}",
        current.revision + 1,
        if bnc_changed { "changed" } else { "unchanged" },
        if restart_required {
            "required"
        } else {
            "not required"
        }
    );
    match crate::db::save_managed_config(
        pool_of(&state),
        current.revision,
        &settings,
        &actor,
        &detail,
    )
    .await
    {
        Ok(snapshot) => {
            *current = snapshot.clone();
            admin_json(
                serde_json::json!({ "revision": snapshot.revision, "restart_required": restart_required }),
            )
        }
        Err(error) => {
            if bnc_changed && let Some(listener) = &state.bnc_listener {
                match previous_bnc {
                    Some(address) => {
                        let _ = listener.enable(address).await;
                    }
                    None => listener.stop().await,
                }
            }
            admin_db_error("managed configuration", error)
        }
    }
}

pub(super) async fn admin_create_network(
    State(state): State<Arc<AppState>>,
    AdminAccount(actor): AdminAccount,
    body: Result<axum::Json<AdminNetworkBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let body = match parse_json(body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if body.kind.is_bridge() && !kind_feature_available(body.kind) {
        return problem(
            StatusCode::BAD_REQUEST,
            "Unsupported network kind",
            Some(&format!(
                "This server was not built with the {} feature.",
                body.kind.as_db_str()
            )),
        );
    }
    let sasl_account = optional_config_string(body.sasl_account);
    let sasl_password = optional_config_string(body.sasl_password);
    let secret_needed =
        sasl_password.is_some() || (body.kind.account_is_secret() && sasl_account.is_some());
    let key = state.secret_key.clone();
    if secret_needed && key.is_none() {
        return master_key_required("Upstream credentials");
    }
    let name = body.name.trim().to_string();
    let owner = optional_config_string(body.owner);
    let addr = body.addr.trim().to_string();
    let nick = body.nick.trim().to_string();
    let realname = optional_config_string(body.realname);
    let autojoin = body
        .autojoin
        .into_iter()
        .map(|channel| channel.trim().to_string())
        .filter(|channel| !channel.is_empty())
        .collect();
    mutate_managed_configuration(&state, &actor, body.revision, move |settings| {
        reject_bootstrap_credential_change(settings, "network")?;
        let sealed_account = if body.kind.account_is_secret() {
            seal_configuration_secret(sasl_account, key.as_ref())?
        } else {
            sasl_account
        };
        let sealed_password = seal_configuration_secret(sasl_password, key.as_ref())?;
        settings.networks.push(crate::config::NetworkEntry {
            name: name.clone(),
            kind: body.kind,
            owner,
            addr,
            tls: body.tls,
            nick,
            realname,
            autojoin,
            buffer_cap: body.buffer_cap,
            sasl_account: sealed_account,
            sasl_password: sealed_password,
        });
        Ok(format!("added server network {name}"))
    })
    .await
}

pub(super) async fn admin_delete_network(
    State(state): State<Arc<AppState>>,
    AdminAccount(actor): AdminAccount,
    axum::extract::Path(name): axum::extract::Path<String>,
    body: Result<axum::Json<AdminNetworkDeleteBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let body = match parse_json(body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let owner = optional_config_string(body.owner.into_option());
    mutate_managed_configuration(&state, &actor, body.revision, move |settings| {
        reject_bootstrap_credential_change(settings, "network")?;
        let before = settings.networks.len();
        settings
            .networks
            .retain(|network| network.name != name || network.owner.as_deref() != owner.as_deref());
        (settings.networks.len() != before)
            .then(|| format!("removed server network {name}"))
            .ok_or_else(|| format!("No matching server network named '{name}'."))
    })
    .await
}

fn optional_config_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| (!value.trim().is_empty()).then(|| value.trim().to_string()))
}

fn seal_configuration_secret(
    value: Option<String>,
    key: Option<&Arc<crate::secret::SecretKeyring>>,
) -> Result<Option<String>, String> {
    value
        .map(|value| {
            key.ok_or_else(|| "A master key is required to store upstream credentials.".into())
                .map(|key| key.seal(&value, crate::secret::CONFIG_CONTEXT))
        })
        .transpose()
}

pub(super) async fn admin_create_oidc_provider(
    State(state): State<Arc<AppState>>,
    AdminAccount(actor): AdminAccount,
    body: Result<axum::Json<AdminOidcBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let body = match parse_json(body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let Some(key) = configuration_secret_key(&state) else {
        return master_key_required("OIDC client secrets");
    };
    let domains = match body
        .allowed_email_domains
        .into_iter()
        .map(|domain| crate::identity::EmailDomain::parse(&domain))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(domains) => domains,
        Err(error) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "Invalid OIDC provider",
                Some(&error.to_string()),
            );
        }
    };
    let name = body.name.trim().to_string();
    let issuer_url = body.issuer_url.trim().to_string();
    let client_id = body.client_id.trim().to_string();
    if name.is_empty()
        || issuer_url.is_empty()
        || client_id.is_empty()
        || body.client_secret.is_empty()
    {
        return problem(
            StatusCode::BAD_REQUEST,
            "Invalid OIDC provider",
            Some("Name, issuer URL, client ID, and client secret are required."),
        );
    }
    let scopes = body
        .scopes
        .into_iter()
        .map(|scope| scope.trim().to_string())
        .filter(|scope| !scope.is_empty())
        .collect();
    let end_session_endpoint = body
        .end_session_endpoint
        .and_then(|value| (!value.trim().is_empty()).then(|| value.trim().to_string()));
    mutate_managed_configuration(&state, &actor, body.revision, move |settings| {
        add_managed_oidc_provider(
            settings,
            crate::config::OidcProviderConfig {
                name,
                issuer_url,
                client_id,
                client_secret: key.seal(&body.client_secret, crate::secret::CONFIG_CONTEXT),
                scopes,
                allowed_email_domains: domains,
                end_session_endpoint,
                token_endpoint_auth_method: body.token_endpoint_auth_method,
            },
        )
    })
    .await
}

pub(super) async fn admin_delete_oidc_provider(
    State(state): State<Arc<AppState>>,
    AdminAccount(actor): AdminAccount,
    axum::extract::Path(name): axum::extract::Path<String>,
    body: Result<axum::Json<AdminConfigRevision>, axum::extract::rejection::JsonRejection>,
) -> Response {
    delete_managed_configuration_item_api(
        state,
        actor,
        name,
        body,
        oidc_provider_configuration_item(),
    )
    .await
}

pub(super) async fn admin_create_oper(
    State(state): State<Arc<AppState>>,
    AdminAccount(actor): AdminAccount,
    body: Result<axum::Json<AdminOperBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let body = match parse_json(body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let Some(key) = configuration_secret_key(&state) else {
        return master_key_required("Operator passwords");
    };
    let name = body.name.trim();
    if name.is_empty() || body.password.is_empty() {
        return problem(
            StatusCode::BAD_REQUEST,
            "Invalid operator",
            Some("Operator name and password are required."),
        );
    }
    mutate_managed_configuration(&state, &actor, body.revision, |settings| {
        add_managed_oper(
            settings,
            crate::config::OperConfig {
                name: name.to_string(),
                password: key.seal(&body.password, crate::secret::CONFIG_CONTEXT),
            },
        )
    })
    .await
}

pub(super) async fn admin_delete_oper(
    State(state): State<Arc<AppState>>,
    AdminAccount(actor): AdminAccount,
    axum::extract::Path(name): axum::extract::Path<String>,
    body: Result<axum::Json<AdminConfigRevision>, axum::extract::rejection::JsonRejection>,
) -> Response {
    delete_managed_configuration_item_api(state, actor, name, body, oper_configuration_item()).await
}

fn configuration_secret_key(state: &AppState) -> Option<&Arc<crate::secret::SecretKeyring>> {
    state.secret_key.as_ref()
}

fn master_key_required(credential_label: &str) -> Response {
    problem(
        StatusCode::CONFLICT,
        "Master key required",
        Some(&format!(
            "{credential_label} cannot be stored without a master key."
        )),
    )
}

async fn delete_managed_configuration_item_api<T>(
    state: Arc<AppState>,
    actor: String,
    name: String,
    body: Result<axum::Json<AdminConfigRevision>, axum::extract::rejection::JsonRejection>,
    item: ManagedConfigurationItem<T>,
) -> Response {
    let body = match parse_json(body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    mutate_managed_configuration(&state, &actor, body.revision, |settings| {
        delete_managed_configuration_item(settings, &name, item)
    })
    .await
}

async fn mutate_managed_configuration(
    state: &AppState,
    actor: &str,
    revision: i64,
    change: impl FnOnce(&mut crate::config::ManagedConfig) -> Result<String, String>,
) -> Response {
    let Some(config) = &state.managed_config else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Configuration unavailable",
            None,
        );
    };
    let mut current = config.write().await;
    if current.revision != revision {
        return problem(
            StatusCode::CONFLICT,
            "Configuration revision conflict",
            Some("Reload the configuration and retry with its current revision."),
        );
    }
    let mut settings = current.settings.clone();
    let detail = match change(&mut settings) {
        Ok(detail) => detail,
        Err(error) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "Invalid configuration change",
                Some(&error),
            );
        }
    };
    if let Err(error) = settings.validate() {
        return problem(
            StatusCode::BAD_REQUEST,
            "Invalid configuration change",
            Some(&error.to_string()),
        );
    }
    match crate::db::save_managed_config(
        pool_of(state),
        revision,
        &settings,
        actor,
        &format!("{detail}; restart required"),
    )
    .await
    {
        Ok(snapshot) => {
            *current = snapshot.clone();
            admin_json(serde_json::json!({ "revision": snapshot.revision, "message": detail }))
        }
        Err(crate::db::DbError::StaleServerSettings) => problem(
            StatusCode::CONFLICT,
            "Configuration revision conflict",
            Some("Reload the configuration and retry with its current revision."),
        ),
        Err(error) => admin_db_error("operator configuration", error),
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

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdminServerBanBody {
    kind: String,
    mask: String,
    #[serde(default)]
    reason: String,
}

pub(super) async fn admin_create_server_ban(
    State(state): State<Arc<AppState>>,
    AdminAccount(actor): AdminAccount,
    body: Result<axum::Json<AdminServerBanBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let body = match parse_json(body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    server_ban_response(
        &state,
        crate::core::AdminRequest::AddServerBan {
            mask: body.mask,
            kind: body.kind,
            reason: body.reason,
            actor,
        },
        StatusCode::CREATED,
    )
    .await
}

pub(super) async fn admin_delete_server_ban(
    State(state): State<Arc<AppState>>,
    AdminAccount(actor): AdminAccount,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Response {
    if id <= 0 {
        return problem(StatusCode::BAD_REQUEST, "Invalid server-ban id", None);
    }
    let ban = match crate::db::server_ban_directory_entry(pool_of(&state), id).await {
        Ok(Some(ban)) => ban,
        Ok(None) => return problem(StatusCode::NOT_FOUND, "No such server ban", None),
        Err(error) => return admin_db_error("server-ban lookup", error),
    };
    server_ban_response(
        &state,
        crate::core::AdminRequest::RemoveServerBan {
            expected_id: Some(id),
            mask: ban.mask,
            kind: ban.kind,
            actor,
        },
        StatusCode::NO_CONTENT,
    )
    .await
}

async fn server_ban_response(
    state: &AppState,
    request: crate::core::AdminRequest,
    success: StatusCode,
) -> Response {
    match super::core_reply(state, request).await {
        Ok(crate::core::AdminReply::Ok(_message)) if success == StatusCode::NO_CONTENT => {
            let mut response = success.into_response();
            no_store(response.headers_mut());
            response
        }
        Ok(crate::core::AdminReply::Ok(message)) => {
            let mut response = (
                success,
                axum::Json(serde_json::json!({ "message": message })),
            )
                .into_response();
            no_store(response.headers_mut());
            response
        }
        Ok(crate::core::AdminReply::BanErr { kind, message }) => {
            let (status, title) = match kind {
                crate::core::BanControlError::Invalid => {
                    (StatusCode::BAD_REQUEST, "Invalid server ban")
                }
                crate::core::BanControlError::NotFound => {
                    (StatusCode::NOT_FOUND, "No such server ban")
                }
                crate::core::BanControlError::Conflict => {
                    (StatusCode::CONFLICT, "Server-ban change conflict")
                }
                crate::core::BanControlError::Unavailable => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Server-ban control unavailable",
                ),
            };
            problem(status, title, Some(&message))
        }
        Ok(_) | Err(_) => problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Server-ban control unavailable",
            None,
        ),
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
    fn account_state_request_has_exactly_one_change() {
        assert!(matches!(
            serde_json::from_str::<AccountStateBody>(r#"{"suspended":true}"#),
            Ok(AccountStateBody::Suspension { suspended: true })
        ));
        assert!(matches!(
            serde_json::from_str::<AccountStateBody>(r#"{"administrator":false}"#),
            Ok(AccountStateBody::Administrator {
                administrator: false
            })
        ));
        for body in [
            r#"{}"#,
            r#"{"suspended":true,"administrator":false}"#,
            r#"{"suspended":true,"extra":false}"#,
        ] {
            assert!(
                serde_json::from_str::<AccountStateBody>(body).is_err(),
                "{body}"
            );
        }
    }

    #[test]
    fn managed_network_delete_names_an_owner_or_shared_scope() {
        assert!(matches!(
            serde_json::from_str::<AdminNetworkDeleteBody>(r#"{"revision":1,"owner":"alice"}"#),
            Ok(AdminNetworkDeleteBody {
                owner: ManagedNetworkOwner::Owner(_),
                ..
            })
        ));
        assert!(matches!(
            serde_json::from_str::<AdminNetworkDeleteBody>(r#"{"revision":1,"owner":null}"#),
            Ok(AdminNetworkDeleteBody {
                owner: ManagedNetworkOwner::Shared(()),
                ..
            })
        ));
        assert!(serde_json::from_str::<AdminNetworkDeleteBody>(r#"{"revision":1}"#).is_err());
    }

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
#[serde(deny_unknown_fields)]
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

#[cfg(test)]
mod token_request_tests {
    use super::*;

    #[test]
    fn token_request_rejects_unknown_fields() {
        assert!(
            serde_json::from_str::<TokenRequest>(r#"{"label":"desktop","extra":true}"#).is_err()
        );
    }

    #[test]
    fn device_requests_reject_unknown_fields() {
        assert!(
            serde_json::from_str::<DeviceTokenReq>(r#"{"device_code":"code","extra":true}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<DeviceApproveReq>(r#"{"user_code":"ABCD-EFGH","extra":true}"#)
                .is_err()
        );
    }
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
    let pool = require_pool!(state);
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
    let pool = require_pool!(state);
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
    // Require CSRF for this destructive GET; OIDC logout uses query parameters.
    if !query
        .csrf
        .as_deref()
        .is_some_and(|c| state.csrf_valid(&token, c))
    {
        return problem(StatusCode::FORBIDDEN, "Invalid or missing CSRF token", None);
    }
    let crate::db::SessionLogoutHint { id_token, provider } =
        match crate::db::session_logout_hint(pool, &token).await {
            Ok(hint) => hint,
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
    // Keep both sessions when coordinated logout cannot end the upstream session.
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
