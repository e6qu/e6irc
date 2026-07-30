//! App passwords and personal access tokens.

use super::*;

#[derive(Deserialize)]
pub(super) struct ProfileRequest {
    pub(super) contact_email: Option<String>,
}

pub(super) async fn me_profile(
    State(state): State<Arc<AppState>>,
    Authenticated(account): Authenticated,
) -> Response {
    match crate::db::account_contact_email(pool_of(&state), &account).await {
        Ok(contact_email) => {
            let mut response = (
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::json!({
                    "account": account,
                    "contact_email": contact_email,
                })
                .to_string(),
            )
                .into_response();
            no_store(response.headers_mut());
            response
        }
        Err(error) => database_unavailable("profile read", error),
    }
}

pub(super) async fn update_me_profile(
    State(state): State<Arc<AppState>>,
    Authenticated(account): Authenticated,
    JsonBody(request): JsonBody<ProfileRequest>,
) -> Response {
    let contact_email = match request.contact_email.as_deref() {
        Some(email) => match crate::identity::ContactEmail::parse(email) {
            Ok(email) => Some(email),
            Err(error) => {
                return problem(
                    StatusCode::BAD_REQUEST,
                    "Invalid contact email",
                    Some(&error.to_string()),
                );
            }
        },
        None => None,
    };
    match crate::db::set_account_contact_email(pool_of(&state), &account, contact_email.as_ref())
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => database_unavailable("profile update", error),
    }
}

fn database_unavailable(operation: &str, error: impl std::fmt::Display) -> Response {
    eprintln!("http: {operation} failed: {error}");
    problem(
        StatusCode::SERVICE_UNAVAILABLE,
        "Database unavailable",
        None,
    )
}

fn owner_scoped_delete_response(
    result: Result<bool, crate::db::DbError>,
    not_found_title: &'static str,
    operation: &'static str,
) -> Response {
    match result {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => problem(StatusCode::NOT_FOUND, not_found_title, None),
        Err(error) => database_unavailable(operation, error),
    }
}

#[derive(Deserialize)]
pub(super) struct AppPasswordRequest {
    pub(super) account: String,
    pub(super) password: String,
    pub(super) label: String,
}

/// Exchange an account's password for a fresh app password (shown once;
/// only its hash is stored). This is the password-based path; the OIDC
/// web session flow is the primary way accounts authenticate.
pub(super) async fn create_app_password(
    State(state): State<Arc<AppState>>,
    // Verifies a password, so it's an online brute-force target: bounded by both
    // the per-IP `RateLimited` bucket (this argument) and argon2's cost.
    _rl: RateLimited,
    body: Result<axum::Json<AppPasswordRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Some(pool) = &state.pool else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "No database configured",
            Some("This server runs without persistence; accounts are unavailable."),
        );
    };
    let req = match super::parse_json(body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    if let Some(detail) = credential_input_error(&req.account, &req.password) {
        return problem(
            StatusCode::BAD_REQUEST,
            "Invalid account or password",
            Some(detail),
        );
    }
    if let Some(resp) = validate_label(&req.label) {
        return resp;
    }
    match crate::db::issue_app_password(pool, &req.account, &req.password, &req.label).await {
        Ok(secret) => (
            StatusCode::CREATED,
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::json!({
                "app_password": secret,
                "label": req.label,
                "note": "Store this now; it is not retrievable later.",
            })
            .to_string(),
        )
            .into_response(),
        Err(crate::db::DbError::BadCredentials) => problem(
            StatusCode::UNAUTHORIZED,
            "Invalid account or password",
            None,
        ),
        Err(crate::db::DbError::TooManyCredentials) => problem(
            StatusCode::CONFLICT,
            "Too many app passwords",
            Some("Revoke an existing app password first."),
        ),
        Err(error) => database_unavailable("app password issuance", error),
    }
}

#[derive(Deserialize)]
pub(super) struct ChangePasswordRequest {
    #[serde(default)]
    pub(super) current_password: Option<String>,
    pub(super) new_password: String,
}

/// Rotate the authenticated account's primary password. An app password
/// cannot authorize this operation.
pub(super) async fn change_password(
    State(state): State<Arc<AppState>>,
    _rl: RateLimited,
    Authenticated(account): Authenticated,
    body: Result<axum::Json<ChangePasswordRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let req = match super::parse_json(body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if let Some(detail) = req
        .current_password
        .as_deref()
        .and_then(password_input_error)
        .or_else(|| password_input_error(&req.new_password))
    {
        return problem(StatusCode::BAD_REQUEST, "Invalid password", Some(detail));
    }
    let result = match req.current_password {
        Some(current) => {
            crate::db::change_local_password(pool_of(&state), &account, &current, &req.new_password)
                .await
        }
        None => crate::db::set_local_password(pool_of(&state), &account, &req.new_password).await,
    };
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(crate::db::DbError::BadCredentials) => problem(
            StatusCode::UNAUTHORIZED,
            "Current password is incorrect",
            None,
        ),
        Err(crate::db::DbError::LocalPasswordExists) => problem(
            StatusCode::CONFLICT,
            "Current password is required",
            Some("This account already has a primary password."),
        ),
        Err(error) => database_unavailable("password rotation", error),
    }
}

// ---- credential management ----------------------------------------------

/// List the authenticated account's app passwords by id and label.
pub(super) async fn list_credentials(
    State(state): State<Arc<AppState>>,
    Authenticated(account): Authenticated,
) -> Response {
    let pool = pool_of(&state);
    match crate::db::list_credentials(pool, &account).await {
        Ok(rows) => {
            let creds: Vec<serde_json::Value> = rows
                .into_iter()
                .map(|(id, kind, label, created_at, last_used_at)| {
                    serde_json::json!({
                        "id": id,
                        "kind": kind,
                        "label": label,
                        "created_at": created_at,
                        "last_used_at": last_used_at,
                    })
                })
                .collect();
            (
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::json!({ "credentials": creds }).to_string(),
            )
                .into_response()
        }
        Err(error) => database_unavailable("credential list", error),
    }
}

/// List the OIDC identities linked to the caller's account. New ones are
/// added via `GET /api/v1/auth/oidc/{provider}/link`.
pub(super) async fn me_identities(
    State(state): State<Arc<AppState>>,
    Authenticated(account): Authenticated,
) -> Response {
    let pool = pool_of(&state);
    match crate::db::list_oidc_identities(pool, &account).await {
        Ok(rows) => {
            let identities: Vec<serde_json::Value> = rows
                .into_iter()
                .map(|(id, issuer, subject, created_at)| {
                    serde_json::json!({
                        "id": id,
                        "issuer": issuer,
                        "subject": subject,
                        "created_at": created_at,
                    })
                })
                .collect();
            (
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::json!({ "identities": identities }).to_string(),
            )
                .into_response()
        }
        Err(error) => database_unavailable("identity list", error),
    }
}

/// Unlink one of the caller's OIDC identities. The database refuses the last
/// login method and revokes every web session asserted by the removed identity
/// in the same transaction.
pub(super) async fn me_identity_unlink(
    State(state): State<Arc<AppState>>,
    Authenticated(account): Authenticated,
    Path(id): Path<i64>,
) -> Response {
    let pool = pool_of(&state);
    match crate::db::unlink_oidc_identity(pool, &account, id).await {
        Ok(crate::db::UnlinkIdentityOutcome::Unlinked) => StatusCode::NO_CONTENT.into_response(),
        Ok(crate::db::UnlinkIdentityOutcome::LastLoginMethod) => problem(
            StatusCode::CONFLICT,
            "Last login method",
            Some("Add a local password or link another identity before removing this one."),
        ),
        Ok(crate::db::UnlinkIdentityOutcome::NotFound) => {
            problem(StatusCode::NOT_FOUND, "No such identity", None)
        }
        Err(error) => database_unavailable("identity unlink", error),
    }
}

/// List the caller's IRCv3 read markers (`draft/read-marker`): the last
/// point they have read in each target, mirrored from MARKREAD.
pub(super) async fn me_read_markers(
    State(state): State<Arc<AppState>>,
    Authenticated(account): Authenticated,
) -> Response {
    let pool = pool_of(&state);
    match crate::db::list_read_markers(pool, &account).await {
        Ok(rows) => {
            let markers: Vec<serde_json::Value> = rows
                .into_iter()
                .map(|(target, timestamp)| {
                    serde_json::json!({ "target": target, "timestamp": timestamp })
                })
                .collect();
            (
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::json!({ "markers": markers }).to_string(),
            )
                .into_response()
        }
        Err(error) => database_unavailable("read-marker list", error),
    }
}

/// List the authenticated account's personal access tokens (never the token
/// itself — only its hash is stored).
pub(super) async fn me_tokens_list(
    State(state): State<Arc<AppState>>,
    Authenticated(account): Authenticated,
) -> Response {
    let pool = pool_of(&state);
    match crate::db::list_api_tokens(pool, &account).await {
        Ok(rows) => {
            let tokens: Vec<serde_json::Value> = rows
                .into_iter()
                .map(|token| {
                    serde_json::json!({
                        "id": token.id,
                        "label": token.label,
                        "created_at": token.created_at,
                        "expires_at": token.expires_at,
                        "scopes": token.scopes.iter().collect::<Vec<_>>(),
                    })
                })
                .collect();
            (
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::json!({ "tokens": tokens }).to_string(),
            )
                .into_response()
        }
        Err(error) => database_unavailable("token list", error),
    }
}

/// Revoke one of the authenticated account's PATs by id.
pub(super) async fn me_tokens_revoke(
    State(state): State<Arc<AppState>>,
    Authenticated(account): Authenticated,
    Path(id): Path<i64>,
) -> Response {
    let pool = pool_of(&state);
    owner_scoped_delete_response(
        crate::db::delete_api_token(pool, &account, id).await,
        "No such token",
        "token revoke",
    )
}

/// Revoke one of the authenticated account's app passwords by id.
pub(super) async fn revoke_credential(
    State(state): State<Arc<AppState>>,
    Authenticated(account): Authenticated,
    Path(id): Path<i64>,
) -> Response {
    let pool = pool_of(&state);
    owner_scoped_delete_response(
        crate::db::revoke_credential(pool, &account, id).await,
        "No such credential",
        "credential revoke",
    )
}
