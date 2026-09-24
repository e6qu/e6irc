//! App passwords and personal access tokens.

use super::*;

#[derive(serde::Serialize)]
struct CredentialResponse {
    id: i64,
    kind: String,
    label: Option<String>,
    created_at: String,
    last_used_at: Option<String>,
}

#[derive(serde::Serialize)]
struct CredentialListResponse {
    credentials: Vec<CredentialResponse>,
}

#[derive(serde::Serialize)]
struct OidcIdentityResponse {
    id: i64,
    issuer: String,
    subject: String,
    created_at: String,
}

#[derive(serde::Serialize)]
struct OidcIdentityListResponse<'a> {
    identities: Vec<OidcIdentityResponse>,
    link_providers: Vec<&'a str>,
}

#[derive(serde::Serialize)]
struct ReadMarkerResponse {
    target: String,
    timestamp: String,
}

#[derive(serde::Serialize)]
struct ReadMarkerListResponse {
    markers: Vec<ReadMarkerResponse>,
}

#[derive(serde::Serialize)]
struct ApiTokenResponse {
    id: i64,
    label: String,
    created_at: String,
    expires_at: String,
    scopes: Vec<crate::identity::ApiTokenScope>,
}

#[derive(serde::Serialize)]
struct ApiTokenListResponse {
    tokens: Vec<ApiTokenResponse>,
}

#[derive(serde::Serialize)]
struct ProfileResponse {
    account: String,
    contact_email: Option<String>,
}

#[derive(serde::Serialize)]
struct SecurityActivityResponse {
    activity: Vec<SecurityActivityEntry>,
    next_before_id: Option<i64>,
}

#[derive(serde::Serialize)]
struct SecurityActivityEntry {
    id: i64,
    actor: String,
    action: String,
    target: String,
    detail: String,
    at: String,
}

#[derive(serde::Serialize)]
struct AppPasswordResponse {
    app_password: String,
    label: String,
    note: &'static str,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum ContactEmailUpdate {
    Set(String),
    Remove(()),
}

impl ContactEmailUpdate {
    fn as_deref(&self) -> Option<&str> {
        match self {
            Self::Set(value) => Some(value),
            Self::Remove(()) => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProfileRequest {
    pub(super) contact_email: ContactEmailUpdate,
}

pub(super) async fn me_profile(
    State(state): State<Arc<AppState>>,
    Authenticated(account, _): Authenticated,
) -> Response {
    match crate::db::account_contact_email(pool_of(&state), &account).await {
        Ok(contact_email) => json_no_store(ProfileResponse {
            account,
            contact_email,
        }),
        Err(error) => database_unavailable("profile read", error),
    }
}

/// Replace the private contact email. It is the account's recovery contact, so
/// redirecting it is reserved to the browser session like every other change
/// that could hand the account to someone else.
pub(super) async fn update_me_profile(
    State(state): State<Arc<AppState>>,
    SessionMutation(account, _): SessionMutation,
    JsonBody(request): JsonBody<ProfileRequest>,
) -> Response {
    let contact_email = match super::parse_optional_contact_email(request.contact_email.as_deref())
    {
        Ok(ce) => ce,
        Err(msg) => {
            return problem(StatusCode::BAD_REQUEST, "Invalid contact email", Some(&msg));
        }
    };
    match crate::db::set_account_contact_email(pool_of(&state), &account, contact_email.as_ref())
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => database_unavailable("profile update", error),
    }
}

/// Account exports produced at once, process-wide. Each holds one pooled
/// database connection in a `REPEATABLE READ` transaction for as long as its
/// client takes to read the document.
const MAX_CONCURRENT_ACCOUNT_EXPORTS: usize = 2;

/// Seconds a refused export is told to wait before retrying.
const EXPORT_BUSY_RETRY_AFTER_SECONDS: u64 = 10;

/// Admission for account exports ([`MAX_CONCURRENT_ACCOUNT_EXPORTS`]).
pub(crate) struct AccountExportSlots(Arc<tokio::sync::Semaphore>);

impl AccountExportSlots {
    pub(crate) fn new() -> Self {
        Self(Arc::new(tokio::sync::Semaphore::new(
            MAX_CONCURRENT_ACCOUNT_EXPORTS,
        )))
    }

    /// A slot held for as long as one export runs, or `None` when every slot
    /// is taken.
    fn admit(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.0.clone().try_acquire_owned().ok()
    }
}

pub(super) async fn export_me(
    State(state): State<Arc<AppState>>,
    Authenticated(account, _): Authenticated,
) -> Response {
    let Some(slot) = state.account_exports.admit() else {
        return retry_later(
            "Account exports are busy",
            "The server is producing as many account exports as it allows at once.",
            EXPORT_BUSY_RETRY_AFTER_SECONDS,
        );
    };
    let export = match crate::db::begin_account_export(pool_of(&state), &account).await {
        Ok(Some(export)) => export,
        Ok(None) => return problem(StatusCode::NOT_FOUND, "No such account", None),
        Err(error) => return database_unavailable("account export", error),
    };
    // The document is produced a page at a time while the client reads it; a
    // failure part-way ends the body with an error, so the client sees a
    // broken download rather than a document that looks complete.
    let (chunks, body) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        let _slot = slot;
        pump_export(export, chunks, crate::peer_write::PEER_WRITE_DEADLINE).await;
    });
    let mut response = (
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"e6irc-account-export.json\"",
            ),
        ],
        axum::body::Body::new(ChannelBody(body)),
    )
        .into_response();
    no_store(response.headers_mut());
    response
}

/// Where an export's pages come from: the database transaction, or a test's
/// stand-in.
trait ExportPages: Send {
    fn next_page(
        &mut self,
    ) -> impl std::future::Future<Output = Result<Option<String>, crate::db::DbError>> + Send;
}

impl ExportPages for crate::db::AccountExport {
    fn next_page(
        &mut self,
    ) -> impl std::future::Future<Output = Result<Option<String>, crate::db::DbError>> + Send {
        self.next_chunk()
    }
}

/// Hand an export's pages to its response body until the document ends, the
/// client goes, or the client stops reading for `deadline`. The export — and
/// the database transaction it holds — is released when this returns.
async fn pump_export(
    mut export: impl ExportPages,
    chunks: tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::io::Error>>,
    deadline: std::time::Duration,
) {
    loop {
        let next = match export.next_page().await {
            Ok(Some(chunk)) => Ok(bytes::Bytes::from(chunk)),
            Ok(None) => return,
            Err(error) => {
                eprintln!("http: account export failed part-way: {error}");
                Err(std::io::Error::other("account export failed part-way"))
            }
        };
        let failed = next.is_err();
        match crate::peer_write::within_send_deadline(deadline, chunks.send(next)).await {
            Ok(()) if !failed => {}
            // Ended with its error, or the client went away.
            Ok(()) | Err(crate::peer_write::SendFailure::Transport) => return,
            Err(crate::peer_write::SendFailure::Stalled) => {
                eprintln!(
                    "http: account export abandoned: the client read nothing for {}s",
                    deadline.as_secs()
                );
                return;
            }
        }
    }
}

/// A response body read from a channel of chunks: each `Err` ends the body
/// with that error.
struct ChannelBody(tokio::sync::mpsc::Receiver<Result<bytes::Bytes, std::io::Error>>);

impl http_body::Body for ChannelBody {
    type Data = bytes::Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        self.0
            .poll_recv(context)
            .map(|chunk| chunk.map(|chunk| chunk.map(http_body::Frame::data)))
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SecurityActivityQuery {
    limit: Option<usize>,
    before_id: Option<i64>,
}

pub(super) async fn me_security_activity(
    State(state): State<Arc<AppState>>,
    Authenticated(account, _): Authenticated,
    QueryParams(query): QueryParams<SecurityActivityQuery>,
) -> Response {
    let page_size = match query.limit.map_or_else(
        || crate::db::AuditLogPageSize::new(100),
        crate::db::AuditLogPageSize::new,
    ) {
        Some(page_size) => page_size,
        None => {
            return problem(
                StatusCode::BAD_REQUEST,
                "Invalid security activity limit",
                Some("The security activity limit must be between 1 and 1,000."),
            );
        }
    };
    if query.before_id.is_some_and(|id| id <= 0) {
        return problem(
            StatusCode::BAD_REQUEST,
            "Invalid security activity cursor",
            Some("The before_id cursor must be a positive activity entry id."),
        );
    }
    match crate::db::query_account_security_activity(
        pool_of(&state),
        &account,
        query.before_id,
        page_size,
    )
    .await
    {
        Ok(page) => json_no_store(SecurityActivityResponse {
            activity: page
                .entries
                .into_iter()
                .map(|entry| SecurityActivityEntry {
                    id: entry.id,
                    actor: entry.actor,
                    action: entry.action,
                    target: entry.target,
                    detail: entry.detail,
                    at: entry.created_at,
                })
                .collect(),
            next_before_id: page.next_before_id,
        }),
        Err(error) => database_unavailable("security activity", error),
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

enum OwnerItem {
    Token,
    Credential,
}

async fn delete_owner_item(
    state: &AppState,
    account: &str,
    id: i64,
    item: OwnerItem,
    not_found_title: &'static str,
    operation: &'static str,
) -> Response {
    let pool = pool_of(state);
    let result = match item {
        OwnerItem::Token => crate::db::delete_api_token(pool, account, id).await,
        OwnerItem::Credential => crate::db::revoke_credential(pool, account, id).await,
    };
    owner_scoped_delete_response(result, not_found_title, operation)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AppPasswordRequest {
    pub(super) account: String,
    pub(super) password: String,
    pub(super) label: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An export whose pages never end, and which says when it is dropped —
    /// which is when its database transaction would be released.
    struct EndlessPages(Option<tokio::sync::oneshot::Sender<()>>);

    impl ExportPages for EndlessPages {
        async fn next_page(&mut self) -> Result<Option<String>, crate::db::DbError> {
            Ok(Some("x".repeat(1024)))
        }
    }

    impl Drop for EndlessPages {
        fn drop(&mut self) {
            if let Some(released) = self.0.take() {
                released.send(()).expect("the test awaits the release");
            }
        }
    }

    /// A client that stops reading its download releases the export — and
    /// with it the pooled connection and its transaction — at the deadline.
    /// The export task used to park on a full channel for as long as the
    /// client held the connection open, and enough such clients starved the
    /// pool.
    #[tokio::test(start_paused = true)]
    async fn an_export_whose_client_stops_reading_is_released_at_the_deadline() {
        let (released_tx, released) = tokio::sync::oneshot::channel();
        let (chunks, _unread_body) = tokio::sync::mpsc::channel(4);
        let pump = tokio::spawn(pump_export(
            EndlessPages(Some(released_tx)),
            chunks,
            std::time::Duration::from_secs(30),
        ));
        tokio::time::timeout(std::time::Duration::from_secs(60), released)
            .await
            .expect("the export is released once the client has read nothing for the deadline")
            .expect("released signal");
        pump.await.expect("pump task");
    }

    #[test]
    fn account_exports_past_the_bound_are_refused_until_one_ends() {
        let slots = AccountExportSlots::new();
        let held: Vec<_> = (0..MAX_CONCURRENT_ACCOUNT_EXPORTS)
            .map(|_| slots.admit().expect("a free slot"))
            .collect();
        assert!(slots.admit().is_none(), "every slot is taken");
        drop(held);
        assert!(slots.admit().is_some(), "an ended export frees its slot");
    }

    #[test]
    fn app_password_request_rejects_unknown_fields() {
        assert!(
            serde_json::from_str::<AppPasswordRequest>(
                r#"{"account":"alice","password":"secret","label":"desktop","extra":true}"#
            )
            .is_err()
        );
    }

    #[test]
    fn profile_and_password_requests_reject_unknown_fields() {
        assert!(
            serde_json::from_str::<ProfileRequest>(
                r#"{"contact_email":"alice@example.test","extra":true}"#
            )
            .is_err()
        );
        assert!(serde_json::from_str::<ProfileRequest>(r#"{}"#).is_err());
        let removal = serde_json::from_str::<ProfileRequest>(r#"{"contact_email":null}"#)
            .expect("explicit null profile removal");
        assert!(matches!(
            removal.contact_email,
            ContactEmailUpdate::Remove(())
        ));
        assert!(
            serde_json::from_str::<ChangePasswordRequest>(
                r#"{"current_password":"old","new_password":"new","extra":true}"#
            )
            .is_err()
        );
    }

    #[test]
    fn security_activity_query_rejects_unknown_fields() {
        let uri = "/?extra=1".parse().expect("query URI");
        assert!(axum::extract::Query::<SecurityActivityQuery>::try_from_uri(&uri).is_err());
    }
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
        Err(r) => return r.into(),
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
    app_password_issue_response(
        crate::db::issue_app_password(pool, &req.account, &req.password, &req.label).await,
        req.label,
    )
}

fn app_password_issue_response(
    result: Result<String, crate::db::DbError>,
    label: String,
) -> Response {
    match result {
        Ok(secret) => created_no_store(AppPasswordResponse {
            app_password: secret,
            label,
            note: "Store this now; it is not retrievable later.",
        }),
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
#[serde(deny_unknown_fields)]
pub(super) struct SessionAppPasswordRequest {
    pub(super) label: String,
}

/// Mint an app password for the browser-session account. This separate
/// session-only resource preserves the public password-exchange endpoint's
/// no-bearer-escalation contract while letting the console use its canonical
/// API rather than a rendered mutation handler.
pub(super) async fn create_session_app_password(
    State(state): State<Arc<AppState>>,
    SessionMutation(account, _): SessionMutation,
    JsonBody(request): JsonBody<SessionAppPasswordRequest>,
) -> Response {
    if let Some(response) = validate_label(&request.label) {
        return response;
    }
    app_password_issue_response(
        crate::db::issue_app_password_for_account(pool_of(&state), &account, &request.label).await,
        request.label,
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChangePasswordRequest {
    #[serde(default)]
    pub(super) current_password: Option<String>,
    pub(super) new_password: String,
}

/// What a password change did beyond the password itself, stated to the person
/// who made it. Other browser sessions end because the old password may be in
/// someone else's hands; app passwords and personal access tokens are
/// separately managed credentials and are deliberately left alone, so the
/// person is told to revoke those themselves if they suspect them.
pub(super) const PASSWORD_CHANGE_DETAIL: &str = "Other browser sessions were signed out; app \
     passwords and access tokens are unchanged — revoke them below if you suspect them.";

#[derive(serde::Serialize)]
struct PasswordChangeResponse {
    detail: &'static str,
}

/// Rotate the authenticated account's primary password. Neither an app
/// password nor a bearer can authorize this operation: an OpenID Connect-only
/// account has no current password to demand, so a token admitted here could
/// install one and sign in as the owner. Every browser session but the one
/// making the change ends with it (see [`crate::db::change_local_password`]).
pub(super) async fn change_password(
    State(state): State<Arc<AppState>>,
    _rl: RateLimited,
    SessionMutation(account, session): SessionMutation,
    body: Result<axum::Json<ChangePasswordRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let req = match super::parse_json(body) {
        Ok(body) => body,
        Err(response) => return response.into(),
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
            crate::db::change_local_password(
                pool_of(&state),
                &account,
                &current,
                &req.new_password,
                &session,
            )
            .await
        }
        None => {
            crate::db::set_local_password(pool_of(&state), &account, &req.new_password, &session)
                .await
        }
    };
    match result {
        Ok(()) => json_no_store(PasswordChangeResponse {
            detail: PASSWORD_CHANGE_DETAIL,
        }),
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
    Authenticated(account, _): Authenticated,
) -> Response {
    let pool = pool_of(&state);
    match crate::db::list_credentials(pool, &account).await {
        Ok(rows) => {
            let credentials = rows
                .into_iter()
                .map(|row| CredentialResponse {
                    id: row.id,
                    kind: row.kind,
                    label: row.label,
                    created_at: row.created_at,
                    last_used_at: row.last_used_at,
                })
                .collect();
            json_no_store(CredentialListResponse { credentials })
        }
        Err(error) => database_unavailable("credential list", error),
    }
}

/// List the OIDC identities linked to the caller's account. New ones are
/// added via `GET /api/v1/auth/oidc/{provider}/link`.
pub(super) async fn me_identities(
    State(state): State<Arc<AppState>>,
    Authenticated(account, _): Authenticated,
) -> Response {
    let pool = pool_of(&state);
    match crate::db::list_oidc_identities(pool, &account).await {
        Ok(rows) => {
            let identities = rows
                .into_iter()
                .map(|row| OidcIdentityResponse {
                    id: row.id,
                    issuer: row.issuer,
                    subject: row.subject,
                    created_at: row.created_at,
                })
                .collect();
            let link_providers: Vec<&str> = state
                .oidc_providers
                .iter()
                .map(|provider| provider.name.as_str())
                .collect();
            json_no_store(OidcIdentityListResponse {
                identities,
                link_providers,
            })
        }
        Err(error) => database_unavailable("identity list", error),
    }
}

/// Unlink one of the caller's OIDC identities. The database refuses the last
/// login method and revokes every web session asserted by the removed identity
/// in the same transaction.
pub(super) async fn me_identity_unlink(
    State(state): State<Arc<AppState>>,
    SessionMutation(account, session): SessionMutation,
    PathParams(id): PathParams<i64>,
) -> Response {
    let pool = pool_of(&state);
    match crate::db::unlink_oidc_identity(pool, &account, id).await {
        Ok(crate::db::UnlinkIdentityOutcome::Unlinked) => {
            match crate::db::session_account(pool, &session).await {
                Ok(Some(_)) => StatusCode::NO_CONTENT.into_response(),
                Ok(None) => {
                    let mut response = StatusCode::NO_CONTENT.into_response();
                    response.headers_mut().insert(
                        header::SET_COOKIE,
                        clear_session_cookie(state.secure_cookies)
                            .parse()
                            .expect("session clear cookie is valid"),
                    );
                    response
                }
                Err(error) => database_unavailable("identity-unlink session refresh", error),
            }
        }
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
    Authenticated(account, _): Authenticated,
) -> Response {
    let pool = pool_of(&state);
    match crate::db::list_read_markers(pool, &account).await {
        Ok(rows) => {
            let markers = rows
                .into_iter()
                .map(|(target, timestamp)| ReadMarkerResponse { target, timestamp })
                .collect();
            json_no_store(ReadMarkerListResponse { markers })
        }
        Err(error) => database_unavailable("read-marker list", error),
    }
}

/// List the authenticated account's personal access tokens (never the token
/// itself — only its hash is stored).
pub(super) async fn me_tokens_list(
    State(state): State<Arc<AppState>>,
    Authenticated(account, _): Authenticated,
) -> Response {
    let pool = pool_of(&state);
    match crate::db::list_api_tokens(pool, &account).await {
        Ok(rows) => {
            let tokens = rows
                .into_iter()
                .map(|token| ApiTokenResponse {
                    id: token.id,
                    label: token.label,
                    created_at: token.created_at,
                    expires_at: token.expires_at,
                    scopes: token.scopes.iter().collect(),
                })
                .collect();
            json_no_store(ApiTokenListResponse { tokens })
        }
        Err(error) => database_unavailable("token list", error),
    }
}

/// Revoke one of the authenticated account's PATs by id.
pub(super) async fn me_tokens_revoke(
    State(state): State<Arc<AppState>>,
    Authenticated(account, _): Authenticated,
    PathParams(id): PathParams<i64>,
) -> Response {
    delete_owner_item(
        &state,
        &account,
        id,
        OwnerItem::Token,
        "No such token",
        "token revoke",
    )
    .await
}

/// Revoke one of the authenticated account's app passwords by id.
pub(super) async fn revoke_credential(
    State(state): State<Arc<AppState>>,
    Authenticated(account, _): Authenticated,
    PathParams(id): PathParams<i64>,
) -> Response {
    delete_owner_item(
        &state,
        &account,
        id,
        OwnerItem::Credential,
        "No such credential",
        "credential revoke",
    )
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DeleteOwnAccountRequest {
    pub(super) confirmation: String,
}

pub(super) async fn delete_own_account(
    State(state): State<Arc<AppState>>,
    SessionMutation(account, _): SessionMutation,
    JsonBody(request): JsonBody<DeleteOwnAccountRequest>,
) -> Response {
    if request.confirmation != account {
        return problem(
            StatusCode::BAD_REQUEST,
            "Account confirmation does not match",
            Some("Supply the exact display-cased account name."),
        );
    }
    let account_id = match crate::db::account_id_by_name(pool_of(&state), &account).await {
        Ok(Some(account_id)) => account_id,
        Ok(None) => return problem(StatusCode::NOT_FOUND, "No such account", None),
        Err(error) => return database_unavailable("account deletion target", error),
    };
    match super::delete_account_lifecycle(&state, &account, account_id, true).await {
        Ok(_) => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            response.headers_mut().insert(
                header::SET_COOKIE,
                clear_session_cookie(state.secure_cookies)
                    .parse()
                    .expect("session clear cookie is valid"),
            );
            response
        }
        Err((status, detail)) => problem(status, "Account deletion failed", Some(&detail)),
    }
}
