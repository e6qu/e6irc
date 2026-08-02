//! HTTP layer: REST API (and later the web client backend), served
//! in-process by the same binary (DESIGN §12).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{Form, Path, Query, State};
use axum::http::{Request, StatusCode, header};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::config::OidcProviderConfig;

mod channels;
mod credentials;
mod device;
mod history;
pub(crate) mod networks;
mod oidc;
mod openapi;
mod sessions;
mod ws;

use channels::*;
use credentials::*;
use device::*;
use history::*;
use networks::*;
use oidc::*;
use openapi::*;
use sessions::*;
use ws::*;

/// The database pool for an unauthenticated endpoint, or a 503 problem
/// response when the server runs without one. (Authenticated endpoints use
/// [`pool_of`], which relies on `authenticate`'s fail-closed pool check.)
macro_rules! require_pool {
    ($state:expr) => {
        match &$state.pool {
            Some(pool) => pool,
            None => {
                return problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "No database configured",
                    None,
                )
            }
        }
    };
}
pub(crate) use require_pool;

/// The UI-managed configuration handle for a console configuration handler,
/// or a 503 problem when the server runs without PostgreSQL-backed
/// configuration.
macro_rules! require_managed_config {
    ($state:expr) => {
        match &$state.managed_config {
            Some(config) => config,
            None => {
                return problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Configuration unavailable",
                    Some("PostgreSQL is required for UI-managed configuration."),
                )
            }
        }
    };
}

/// The BNC registry for a console network/bridge handler, or a 404 problem
/// when the server runs without the bouncer enabled.
macro_rules! require_registry {
    ($state:expr) => {
        match &$state.bnc_registry {
            Some(registry) => registry,
            None => return problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None),
        }
    };
}

/// A URL-encoded form body whose extraction failures use the API's problem
/// response contract instead of Axum's default text rejection.
pub(crate) struct FormBody<T>(pub(crate) T);

impl<T, S> axum::extract::FromRequest<S> for FormBody<T>
where
    axum::Form<T>:
        axum::extract::FromRequest<S, Rejection = axum::extract::rejection::FormRejection>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Form::<T>::from_request(req, state).await {
            Ok(axum::Form(value)) => Ok(Self(value)),
            Err(error) => Err(problem(
                StatusCode::BAD_REQUEST,
                "Invalid form",
                Some(&error.to_string()),
            )),
        }
    }
}

/// One in-flight OIDC authorization (state → verifier/nonce), expiring
/// after ten minutes.
pub struct PendingAuth {
    provider: String,
    pkce_verifier: String,
    nonce: openidconnect::Nonce,
    started: Instant,
    /// When set, the callback links the resulting identity to this account
    /// instead of logging in / auto-provisioning.
    link_account: Option<String>,
    /// A silent (`prompt=none`) SSO probe: on `login_required` the callback
    /// bounces to `/?sso=none` instead of returning an error.
    silent: bool,
}

pub struct AppState {
    pub server_name: String,
    pub network_name: String,
    /// Absent when the server runs without persistence; endpoints that
    /// need it answer 503, never fake success.
    pub pool: Option<PgPool>,
    pub public_url: Option<String>,
    /// Bootstrap HTTP bind; shown with provenance in the configuration console.
    pub http_bind: Option<std::net::SocketAddr>,
    pub secure_cookies: bool,
    pub oidc_providers: Vec<OidcProviderConfig>,
    pub application_release_revision: Option<String>,
    pub pending_auth: Mutex<HashMap<String, PendingAuth>>,
    /// Inbound queue to the IRC core, for the ws-irc bridge.
    pub core_tx: e6irc_queue::Sender<crate::core::Input>,
    /// Shared connection-id allocator (with every other ingress transport).
    pub next_conn: std::sync::Arc<crate::core::ConnectionIdAllocator>,
    /// Per-connection SendQ capacity.
    pub sendq: usize,
    /// The always-on network registry shared by web chat, management, and the
    /// optional raw attach listener. Present whenever PostgreSQL is available.
    pub bnc_registry: Option<std::sync::Arc<crate::bouncer::Registry>>,
    /// Runtime controller for the client attach listener. Present whenever a
    /// database-backed registry exists, even while the listener is disabled.
    pub bnc_listener: Option<std::sync::Arc<crate::net::BncListenerController>>,
    /// Latest persisted operational settings revision. Absent with no database.
    pub managed_config:
        Option<std::sync::Arc<tokio::sync::RwLock<crate::db::ManagedConfigSnapshot>>>,
    /// Fixed-cardinality counters, gauges, and latency histograms.
    pub(crate) telemetry: std::sync::Arc<crate::observability::Telemetry>,
    /// Master key for sealing upstream secrets at rest; `None` when no
    /// key is configured (then networks with an upstream password are
    /// refused rather than stored in the clear).
    pub secret_key: Option<std::sync::Arc<crate::secret::SecretKeyring>>,
    /// Accounts permitted to use the `/api/v1/admin` endpoints (rfc1459
    /// casefolded at startup). Empty = admin disabled.
    pub admin_accounts: std::sync::RwLock<std::collections::HashSet<String>>,
    /// Restart-scoped administrator grants from managed/bootstrap
    /// configuration. Kept separate from the effective registry so revoking a
    /// durable grant cannot accidentally revoke authority that configuration
    /// still grants (or pretend that it did).
    pub configured_admin_accounts: std::collections::HashSet<String>,
    /// Per-startup key for deriving CSRF tokens for cookie-authenticated
    /// form posts from the server-rendered pages.
    pub csrf_key: [u8; 32],
    /// Trusted reverse-proxy CIDRs; when the socket peer matches one, the
    /// client IP is taken from `X-Forwarded-For` (see [`client_ip`]).
    pub trusted_proxies: Vec<ipnet::IpNet>,
    /// Token-bucket size for the auth endpoints per client IP; `None` disables
    /// auth rate limiting. The bucket refills to full over 60 seconds.
    pub auth_rate_burst: Option<usize>,
    /// Per-client-IP auth token buckets: `(tokens, last_refill)`.
    pub auth_buckets: Mutex<HashMap<std::net::IpAddr, (f64, std::time::Instant)>>,
    /// Per-account ordinary/administrator API token buckets. The boolean key
    /// distinguishes the smaller administrator budget.
    pub api_rate_burst: usize,
    pub administrator_api_rate_burst: usize,
    pub api_buckets: Mutex<HashMap<(String, bool), (f64, std::time::Instant)>>,
    /// The per-IP connection cap, shared with the TCP listeners so IRC sessions
    /// opened over `/ws/irc` count against the same budget as raw-socket ones.
    pub(crate) conn_limiter: crate::net::ConnLimiter,
    /// Random per-process prefix plus a monotonic suffix generate opaque,
    /// bounded correlation identifiers without accepting an untrusted request
    /// header into logs or responses.
    pub(crate) request_id_prefix: u64,
    pub(crate) request_id_counter: AtomicU64,
    /// HSTS is safe only when the configured public origin is HTTPS.
    pub(crate) hsts_enabled: bool,
    /// Digest of the deployment-supplied one-time bootstrap secret. Plaintext
    /// is dropped with startup configuration before requests are accepted.
    pub(crate) bootstrap_token_digest: Option<[u8; 32]>,
    /// Fast presentation state; PostgreSQL remains the transactional authority
    /// that exactly zero accounts exist.
    pub(crate) bootstrap_available: AtomicBool,
}

pub(crate) fn bootstrap_token_digest(token: &str) -> [u8; 32] {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, token.as_bytes());
    digest
        .as_ref()
        .try_into()
        .expect("SHA-256 output is always 32 bytes")
}

impl AppState {
    pub fn no_pending_auth() -> Mutex<HashMap<String, PendingAuth>> {
        Mutex::new(HashMap::new())
    }

    /// A CSRF token bound to a web session: `HMAC(csrf_key, session)`.
    pub fn csrf_token(&self, session: &str) -> String {
        let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &self.csrf_key);
        let tag = aws_lc_rs::hmac::sign(&key, session.as_bytes());
        tag.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Constant-time check of a CSRF token against the session.
    fn csrf_valid(&self, session: &str, token: &str) -> bool {
        let expected = self.csrf_token(session);
        expected.len() == token.len()
            && aws_lc_rs::constant_time::verify_slices_are_equal(
                expected.as_bytes(),
                token.as_bytes(),
            )
            .is_ok()
    }

    fn next_request_id(&self) -> String {
        let suffix = self.request_id_counter.fetch_add(1, Ordering::Relaxed);
        format!("{:016x}{suffix:016x}", self.request_id_prefix)
    }
}

/// RFC 9457 problem+json error body.
/// Longest label accepted for an app password or personal access token. These
/// are stored in an unbounded `TEXT` column and shown back in the account UI, so
/// bound them like every other client-supplied field (the network fields cap at
/// 64/128/255) rather than accepting a multi-megabyte JSON body into storage.
pub(super) const MAX_LABEL_LEN: usize = 64;
pub(super) const MAX_ACCOUNT_LEN: usize = 64;
pub(super) const MAX_PASSWORD_LEN: usize = 512;

pub(super) fn label_validation_error(label: &str) -> Option<String> {
    if label.chars().count() > MAX_LABEL_LEN {
        return Some(format!("Labels are at most {MAX_LABEL_LEN} characters."));
    }
    if label.chars().any(|c| c.is_control()) {
        return Some("Labels must not contain control characters.".into());
    }
    None
}

/// Validate a client-supplied credential label: bounded and free of control
/// characters (which would corrupt the account UI / logs). Returns a ready 400
/// response when invalid, or `None` when the label is acceptable.
pub(super) fn validate_label(label: &str) -> Option<Response> {
    label_validation_error(label)
        .map(|detail| problem(StatusCode::BAD_REQUEST, "Invalid label", Some(&detail)))
}

pub(super) fn credential_input_error(account: &str, password: &str) -> Option<&'static str> {
    if account.is_empty() || account.len() > MAX_ACCOUNT_LEN {
        return Some("Account names must contain 1–64 bytes.");
    }
    if password.is_empty() || password.len() > MAX_PASSWORD_LEN {
        return Some("Passwords must contain 1–512 bytes.");
    }
    None
}

pub(super) fn password_input_error(password: &str) -> Option<&'static str> {
    if password.is_empty() || password.len() > MAX_PASSWORD_LEN {
        Some("Passwords must contain 1–512 bytes.")
    } else {
        None
    }
}

/// Resolve a bounded integer query parameter without silently changing the
/// caller's requested window. HTTP collection endpoints share this boundary so
/// a new `?limit=` cannot accidentally reintroduce clamp-and-pretend behavior.
#[allow(clippy::result_large_err)] // Err is the standard full problem Response
pub(super) fn bounded_query_limit(
    requested: Option<usize>,
    default: usize,
    maximum: usize,
    collection: &str,
) -> Result<i64, Response> {
    let limit = requested.unwrap_or(default);
    if !(1..=maximum).contains(&limit) {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            &format!("Invalid {collection} limit"),
            Some(&format!(
                "The {collection} limit must be between 1 and {maximum}."
            )),
        ));
    }
    i64::try_from(limit).map_err(|_| {
        problem(
            StatusCode::BAD_REQUEST,
            &format!("Invalid {collection} limit"),
            Some(&format!(
                "The {collection} limit must be between 1 and {maximum}."
            )),
        )
    })
}

/// Unwrap a JSON request body, turning a rejection into a 400 problem response.
/// Shared by the JSON POST handlers so the parse boilerplate isn't copied.
#[allow(clippy::result_large_err)] // Err is a full problem Response, as throughout this module
pub(super) fn parse_json<T>(
    body: Result<axum::Json<T>, axum::extract::rejection::JsonRejection>,
) -> Result<T, Response> {
    match body {
        Ok(axum::Json(b)) => Ok(b),
        Err(e) => Err(problem(
            StatusCode::BAD_REQUEST,
            "Invalid request body",
            Some(&e.to_string()),
        )),
    }
}

fn problem(status: StatusCode, title: &str, detail: Option<&str>) -> Response {
    let mut body = serde_json::json!({
        "status": status.as_u16(),
        "title": title,
    });
    if let Some(d) = detail {
        body["detail"] = serde_json::Value::String(d.to_string());
    }
    (
        status,
        [(header::CONTENT_TYPE, "application/problem+json")],
        body.to_string(),
    )
        .into_response()
}

/// Map an account-authority lifecycle failure to its HTTP status: the
/// self-targeting and last-administrator refusals are client conflicts the
/// caller can fix; anything else is a store fault — logged, never detailed
/// to the client. One rule for the suspend and authority-change endpoints.
fn authority_error_status(context: &str, error: crate::db::DbError) -> (StatusCode, String) {
    match error {
        crate::db::DbError::CannotSuspendSelf
        | crate::db::DbError::CannotDemoteSelf
        | crate::db::DbError::LastAdministrator => (StatusCode::CONFLICT, error.to_string()),
        _ => {
            eprintln!("{context} failed: {error}");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable".into(),
            )
        }
    }
}

/// A JSON response with `no-store` cache control — the shared shape for
/// private, per-account API payloads that must never be cached.
fn json_no_store(value: impl serde::Serialize) -> Response {
    let mut response = axum::Json(value).into_response();
    no_store(response.headers_mut());
    response
}

/// Redirect to `/login` while clearing the browser session cookie — the
/// shared tail of the "this session is gone now" flows (account deletion,
/// revoking one's own current browser session).
fn redirect_signed_out(state: &AppState) -> Response {
    let mut response = Redirect::to("/login").into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        clear_session_cookie(state.secure_cookies)
            .parse()
            .expect("session clear cookie is valid"),
    );
    response
}

/// Parse an optional contact-email field, or return a `BAD_REQUEST` problem
/// response for an invalid one. Shared by the profile and invitation handlers.
pub(super) fn parse_optional_contact_email(
    raw: Option<&str>,
) -> Result<Option<crate::identity::ContactEmail>, String> {
    match raw {
        Some(email) => crate::identity::ContactEmail::parse(email)
            .map(Some)
            .map_err(|e| e.to_string()),
        None => Ok(None),
    }
}

/// Run one HTTP control-plane mutation on the core and await its typed outcome.
/// The core owns live-state ordering and the database verdict; HTTP handlers do
/// not write durable/live state along a second path.
async fn core_action(state: &AppState, req: crate::core::AdminRequest) -> Result<String, String> {
    match core_reply(state, req).await? {
        crate::core::AdminReply::Ok(message) => Ok(message),
        crate::core::AdminReply::Err(message)
        | crate::core::AdminReply::ChannelErr { message, .. }
        | crate::core::AdminReply::BanErr { message, .. } => Err(message),
        crate::core::AdminReply::Connections(_) => {
            Err("unexpected live-connection reply for a mutation".into())
        }
        crate::core::AdminReply::ConnectionMissing => Err("no such live connection".into()),
    }
}

async fn core_reply(
    state: &AppState,
    req: crate::core::AdminRequest,
) -> Result<crate::core::AdminReply, String> {
    const CORE_REPLY_TIMEOUT: Duration = Duration::from_secs(5);

    let (tx, rx) = tokio::sync::oneshot::channel();
    if state
        .core_tx
        .push(crate::core::Input::Admin { req, reply: tx })
        .await
        .is_err()
    {
        return Err("core worker unavailable".into());
    }
    match tokio::time::timeout(CORE_REPLY_TIMEOUT, rx).await {
        Ok(Ok(reply)) => Ok(reply),
        Ok(Err(_closed)) => Err("core worker dropped the request".into()),
        Err(_elapsed) => Err("core worker did not answer within 5 seconds".into()),
    }
}

fn account_mutation_pool(
    state: &AppState,
    account_id: i64,
) -> Result<&sqlx::PgPool, (StatusCode, String)> {
    if account_id <= 0 {
        return Err((StatusCode::BAD_REQUEST, "Invalid account id".into()));
    }
    state.pool.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "No database configured".into(),
    ))
}

pub(super) async fn mutate_account_suspension(
    state: &AppState,
    actor: &str,
    account_id: i64,
    suspended: bool,
) -> Result<String, (StatusCode, String)> {
    let pool = account_mutation_pool(state, account_id)?;
    let registry = state.bnc_registry.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Network registry unavailable".into(),
    ))?;
    // Account state and network CRUD share one mutation lane. Without this
    // guard, an already-authorized network create could commit between the
    // owner-wide stop and credential revocation, leaving a suspended
    // account's new driver running.
    let _network_mutation = registry.mutation_guard().await;
    let target_name = crate::db::account_name_by_id(pool, account_id)
        .await
        .map_err(|error| {
            eprintln!("account lifecycle target lookup failed: {error}");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable".into(),
            )
        })?
        .ok_or((StatusCode::NOT_FOUND, "No such account".into()))?;

    let prepared_networks = if suspended {
        Vec::new()
    } else {
        let rows = crate::db::list_bnc_networks(pool, &target_name)
            .await
            .map_err(|error| {
                eprintln!("account reactivation network lookup failed: {error}");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Could not load owned networks".into(),
                )
            })?;
        let mut prepared = Vec::new();
        for row in rows.into_iter().filter(|row| row.enabled) {
            let driver =
                crate::bouncer::driver_from_row(&row, state.secret_key.as_deref(), &target_name)
                    .map_err(|error| {
                        (
                            StatusCode::CONFLICT,
                            format!(
                                "Cannot reactivate while network {} is invalid: {error}",
                                row.name
                            ),
                        )
                    })?;
            prepared.push((row.name, driver));
        }
        prepared
    };

    let configured_administrators: Vec<String> =
        state.configured_admin_accounts.iter().cloned().collect();
    let change = crate::db::set_account_suspended(
        pool,
        account_id,
        suspended,
        actor,
        &configured_administrators,
    )
    .await
    .map_err(|error| authority_error_status("account lifecycle mutation", error))?
    .ok_or((StatusCode::NOT_FOUND, "No such account".into()))?;

    if suspended {
        let stopped_networks = registry.remove_owner(&change.folded);
        core_action(
            state,
            crate::core::AdminRequest::SetAccountSuspended {
                account: change.folded.clone(),
                suspended: true,
                reason: "Account suspended".into(),
                actor: actor.to_string(),
            },
        )
        .await
        .map_err(|error| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "Account was suspended and {stopped_networks} network(s) stopped, but live IRC disconnect failed: {error}"
                ),
            )
        })?;
        Ok(format!(
            "Suspended {} and stopped {stopped_networks} owned network(s).",
            change.name
        ))
    } else {
        core_action(
            state,
            crate::core::AdminRequest::SetAccountSuspended {
                account: change.folded.clone(),
                suspended: false,
                reason: "Account reactivated".into(),
                actor: actor.to_string(),
            },
        )
        .await
        .map_err(|error| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Account was reactivated, but the live IRC core remained gated: {error}"),
            )
        })?;
        let started_networks = prepared_networks.len();
        for (name, driver) in prepared_networks {
            registry.add(Some(&change.folded), &name, driver);
        }
        Ok(format!(
            "Reactivated {} and started {started_networks} owned network(s).",
            change.name
        ))
    }
}

pub(super) async fn mutate_account_administrator(
    state: &AppState,
    actor: &str,
    account_id: i64,
    administrator: bool,
) -> Result<String, (StatusCode, String)> {
    let pool = account_mutation_pool(state, account_id)?;
    let configured_administrators: Vec<String> =
        state.configured_admin_accounts.iter().cloned().collect();
    let change = crate::db::set_account_administrator(
        pool,
        account_id,
        administrator,
        actor,
        &configured_administrators,
    )
    .await
    .map_err(|error| authority_error_status("account authority mutation", error))?
    .ok_or((StatusCode::NOT_FOUND, "No such account".into()))?;
    let configured = state.configured_admin_accounts.contains(&change.folded);
    let mut effective = state
        .admin_accounts
        .write()
        .expect("administrator registry lock");
    if administrator || configured {
        effective.insert(change.folded.clone());
    } else {
        effective.remove(&change.folded);
    }
    Ok(if administrator {
        format!(
            "Granted durable administrator authority to {}.",
            change.name
        )
    } else if configured {
        format!(
            "Removed durable administrator authority from {}; configuration still grants administrator access.",
            change.name
        )
    } else {
        format!(
            "Removed durable administrator authority from {}.",
            change.name
        )
    })
}

pub(super) async fn create_account_lifecycle(
    state: &AppState,
    actor: &str,
    account: &str,
    password: &str,
    contact_email: Option<&str>,
    administrator: bool,
) -> Result<i64, (StatusCode, String)> {
    if !crate::sanitize::valid_nick(account, MAX_ACCOUNT_LEN) {
        return Err((
            StatusCode::BAD_REQUEST,
            "The account must be a valid IRC nickname of at most 64 bytes.".into(),
        ));
    }
    if let Some(detail) = password_input_error(password) {
        return Err((StatusCode::BAD_REQUEST, detail.into()));
    }
    let contact_email = contact_email
        .map(crate::identity::ContactEmail::parse)
        .transpose()
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    let pool = state.pool.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "No database configured".into(),
    ))?;
    let account_id = crate::db::create_account_by_administrator(
        pool,
        account,
        password,
        contact_email.as_ref(),
        administrator,
        actor,
    )
    .await
    .map_err(|error| match error {
        crate::db::DbError::DuplicateAccount(_) => {
            (StatusCode::CONFLICT, "Account already exists.".into())
        }
        _ => {
            eprintln!("administrator account creation failed: {error}");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable".into(),
            )
        }
    })?;
    if administrator {
        state
            .admin_accounts
            .write()
            .expect("administrator registry lock")
            .insert(e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(account));
    }
    Ok(account_id)
}

fn account_invitation_url(state: &AppState, token: &str) -> String {
    let path = format!("/invite/{token}");
    state
        .public_url
        .as_deref()
        .map(|base| format!("{}{path}", base.trim_end_matches('/')))
        .unwrap_or(path)
}

pub(super) async fn delete_account_lifecycle(
    state: &AppState,
    actor: &str,
    account_id: i64,
    allow_self: bool,
) -> Result<String, (StatusCode, String)> {
    let pool = account_mutation_pool(state, account_id)?;
    let registry = state.bnc_registry.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Network registry unavailable".into(),
    ))?;
    let _network_mutation = registry.mutation_guard().await;
    let configured_administrators: Vec<String> =
        state.configured_admin_accounts.iter().cloned().collect();
    let target = crate::db::account_deletion_target(pool, account_id, &configured_administrators)
        .await
        .map_err(account_deletion_error)?
        .ok_or((StatusCode::NOT_FOUND, "No such account".into()))?;
    let actor_folded = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(actor);
    if !allow_self && target.folded == actor_folded {
        return Err((
            StatusCode::CONFLICT,
            "Use the self-service account deletion control for your own account.".into(),
        ));
    }

    core_action(
        state,
        crate::core::AdminRequest::SetAccountSuspended {
            account: target.folded.clone(),
            suspended: true,
            reason: "Account permanently deleted".into(),
            actor: actor.to_string(),
        },
    )
    .await
    .map_err(|error| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Could not establish the live authentication gate: {error}"),
        )
    })?;

    let deleted = match crate::db::delete_account_permanently(
        pool,
        account_id,
        actor,
        &configured_administrators,
    )
    .await
    {
        Ok(Some(deleted)) => deleted,
        Ok(None) => {
            undo_account_deletion_gate(state, &target.folded, actor).await?;
            return Err((StatusCode::NOT_FOUND, "No such account".into()));
        }
        Err(error) => {
            undo_account_deletion_gate(state, &target.folded, actor).await?;
            return Err(account_deletion_error(error));
        }
    };
    let stopped_networks = registry.remove_owner(&deleted.folded);
    state
        .admin_accounts
        .write()
        .expect("administrator registry lock")
        .remove(&deleted.folded);
    Ok(format!(
        "Permanently deleted {} and stopped {stopped_networks} owned network(s). The account name is retired.",
        deleted.name
    ))
}

fn account_deletion_error(error: crate::db::DbError) -> (StatusCode, String) {
    match error {
        crate::db::DbError::AccountOwnsChannels(_) | crate::db::DbError::LastAdministrator => {
            (StatusCode::CONFLICT, error.to_string())
        }
        _ => {
            eprintln!("account deletion failed: {error}");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable".into(),
            )
        }
    }
}

async fn undo_account_deletion_gate(
    state: &AppState,
    account: &str,
    actor: &str,
) -> Result<(), (StatusCode, String)> {
    core_action(
        state,
        crate::core::AdminRequest::SetAccountSuspended {
            account: account.to_string(),
            suspended: false,
            reason: "Account deletion did not commit".into(),
            actor: actor.to_string(),
        },
    )
    .await
    .map(|_| ())
    .map_err(|error| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "Deletion did not commit and the live authentication gate could not be removed: {error}"
            ),
        )
    })
}

#[cfg(test)]
mod query_limit_tests {
    use super::*;

    #[test]
    fn bounded_limits_default_accept_and_reject_without_clamping() {
        assert_eq!(bounded_query_limit(None, 100, 1000, "audit").unwrap(), 100);
        assert_eq!(bounded_query_limit(Some(1), 100, 1000, "audit").unwrap(), 1);
        assert_eq!(
            bounded_query_limit(Some(1000), 100, 1000, "audit").unwrap(),
            1000
        );
        for value in [0, 1001] {
            let response = bounded_query_limit(Some(value), 100, 1000, "audit").unwrap_err();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }
}

fn bnc_counts(state: &AppState) -> (u64, u64) {
    state
        .bnc_registry
        .as_ref()
        .map(|registry| {
            let statuses = registry.list();
            (
                statuses.len() as u64,
                statuses.iter().filter(|network| network.connected).count() as u64,
            )
        })
        .unwrap_or_default()
}

async fn observe_http(
    State(state): State<Arc<AppState>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let started = Instant::now();
    let request_id = state.next_request_id();
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        "x-request-id",
        request_id.parse().expect("generated request identifier"),
    );
    if state.hsts_enabled {
        response.headers_mut().insert(
            header::STRICT_TRANSPORT_SECURITY,
            "max-age=31536000; includeSubDomains"
                .parse()
                .expect("static HSTS header"),
        );
    }
    state
        .telemetry
        .record_http_request(started.elapsed(), response.status().is_server_error());
    response
}

#[derive(Serialize)]
struct Readiness {
    ready: bool,
    core: &'static str,
    database: &'static str,
}

const READINESS_DATABASE_TIMEOUT: Duration = Duration::from_secs(2);

async fn database_is_ready(pool: &sqlx::PgPool) -> bool {
    matches!(
        tokio::time::timeout(
            READINESS_DATABASE_TIMEOUT,
            sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(pool),
        )
        .await,
        Ok(Ok(1))
    )
}

async fn readiness(State(state): State<Arc<AppState>>) -> Response {
    let core_ready = state.telemetry.core_is_fresh(Duration::from_secs(45));
    let database_ready = match &state.pool {
        Some(pool) => {
            let started = Instant::now();
            let ready = database_is_ready(pool).await;
            state.telemetry.record_database_request(started.elapsed());
            if !ready {
                state
                    .telemetry
                    .record_error(crate::observability::ErrorKind::Database);
            }
            ready
        }
        None => true,
    };
    let ready = core_ready && database_ready;
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        axum::Json(Readiness {
            ready,
            core: if core_ready { "ready" } else { "stale" },
            database: if state.pool.is_none() {
                "not_configured"
            } else if database_ready {
                "ready"
            } else {
                "unavailable"
            },
        }),
    )
        .into_response()
}

#[derive(Deserialize)]
struct ObservabilityQuery {
    #[serde(default = "default_observability_minutes")]
    minutes: u64,
}

const MAX_OBSERVABILITY_MINUTES: u64 = 7 * 24 * 60;

#[derive(Debug, Clone, Copy)]
struct InvalidObservabilityRange;

fn default_observability_minutes() -> u64 {
    60
}

fn validate_observability_minutes(minutes: u64) -> Result<u64, InvalidObservabilityRange> {
    if (1..=MAX_OBSERVABILITY_MINUTES).contains(&minutes) {
        Ok(minutes)
    } else {
        Err(InvalidObservabilityRange)
    }
}

#[derive(Serialize)]
struct ObservabilityResponse {
    current: crate::observability::Snapshot,
    history: Vec<crate::observability::Snapshot>,
}

async fn admin_observability(
    State(state): State<Arc<AppState>>,
    _admin: AdminAccount,
    Query(query): Query<ObservabilityQuery>,
) -> Response {
    let minutes = match validate_observability_minutes(query.minutes) {
        Ok(minutes) => minutes,
        Err(InvalidObservabilityRange) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "Invalid monitoring range",
                Some("The history range must be between 1 and 10,080 minutes."),
            );
        }
    };
    let (networks, connected) = bnc_counts(&state);
    let current = state.telemetry.snapshot(networks, connected);
    let Some(pool) = &state.pool else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Monitoring history unavailable",
            Some("PostgreSQL is required for historical monitoring."),
        );
    };
    let since_ms = current
        .sampled_at_ms
        .saturating_sub(minutes.saturating_mul(60_000));
    let started = Instant::now();
    match crate::db::list_observability_samples(pool, since_ms, current.sampled_at_ms, 1_000).await
    {
        Ok(history) => {
            state.telemetry.record_database_request(started.elapsed());
            json_no_store(ObservabilityResponse { current, history })
        }
        Err(error) => {
            state.telemetry.record_database_request(started.elapsed());
            state
                .telemetry
                .record_error(crate::observability::ErrorKind::Database);
            eprintln!("monitoring history query failed: {error}");
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Monitoring history unavailable",
                None,
            )
        }
    }
}

async fn admin_metrics(State(state): State<Arc<AppState>>, _admin: AdminAccount) -> Response {
    let (networks, connected) = bnc_counts(&state);
    let mut response = (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.telemetry.prometheus(networks, connected),
    )
        .into_response();
    no_store(response.headers_mut());
    response
}

async fn health() -> &'static str {
    "ok"
}

// Define every OpenAPI-documented HTTP operation once. This expands to both
// the axum routes and the method/path inventory validated by `openapi.rs`, so a
// handler cannot be added to the public REST surface without becoming an
// explicit specification obligation in the same edit.
macro_rules! documented_routes {
    ($( $path:literal => { $( $method:ident : $handler:expr ),+ $(,)? } ),+ $(,)?) => {
        pub(super) const DOCUMENTED_ROUTE_OPERATIONS: &[(&str, &str)] = &[
            $( $(($path, stringify!($method))),+ ),+
        ];

        fn add_documented_routes(router: Router<Arc<AppState>>) -> Router<Arc<AppState>> {
            router$(
                .route(
                    $path,
                    axum::routing::MethodRouter::new()$(.$method($handler))+
                )
            )+
        }
    };
}

documented_routes! {
    "/healthz" => { get: health },
    "/readyz" => { get: readiness },
    "/api/v1/server" => { get: server_info },
    "/api/v1/openapi.json" => { get: openapi },
    "/api/v1/auth/app-passwords" => { post: create_app_password },
    "/api/v1/auth/oidc/{provider}/start" => { get: oidc_start },
    "/api/v1/auth/oidc/{provider}/sso" => { get: oidc_sso_start },
    "/api/v1/auth/oidc/{provider}/link" => { get: oidc_link_start },
    "/api/v1/auth/oidc/{provider}/callback" => { get: oidc_callback },
    "/api/v1/auth/oidc/backchannel-logout" => { post: oidc_backchannel_logout },
    "/api/v1/auth/oidc/frontchannel-logout" => { get: oidc_frontchannel_logout },
    "/api/v1/auth/logout" => { get: logout_sso, post: logout },
    "/api/v1/auth/device/start" => { post: device_start },
    "/api/v1/auth/device/token" => { post: device_token },
    "/api/v1/auth/device/approve" => { post: device_approve },
    "/api/v1/me" => { get: me },
    "/api/v1/me/profile" => { get: me_profile, patch: update_me_profile },
    "/api/v1/me/account" => { delete: delete_own_account },
    "/api/v1/me/export" => { get: export_me },
    "/api/v1/me/security-activity" => { get: me_security_activity },
    "/api/v1/me/identities" => { get: me_identities },
    "/api/v1/me/identities/{id}" => { delete: me_identity_unlink },
    "/api/v1/me/sessions" => {
        get: list_browser_sessions,
        delete: revoke_other_browser_sessions,
    },
    "/api/v1/me/sessions/{id}" => { delete: revoke_browser_session },
    "/api/v1/me/connections" => { get: me_connections },
    "/api/v1/me/connections/{id}" => { delete: me_disconnect_connection },
    "/api/v1/me/tokens" => { get: me_tokens_list, post: create_api_token },
    "/api/v1/me/tokens/{id}" => { delete: me_tokens_revoke },
    "/api/v1/me/read-markers" => { get: me_read_markers },
    "/api/v1/me/password" => { put: change_password },
    "/api/v1/me/channels" => { get: list_owned_channels, post: register_owned_channel },
    "/api/v1/me/channels/{name}" => {
        get: get_owned_channel,
        patch: patch_owned_channel,
        delete: delete_owned_channel,
    },
    "/api/v1/me/channels/{name}/access/{account}" => {
        put: put_channel_access,
        delete: delete_channel_access,
    },
    "/api/v1/me/credentials" => { get: list_credentials },
    "/api/v1/me/credentials/{id}" => { delete: revoke_credential },
    "/api/v1/me/networks" => { get: list_networks, post: create_network },
    "/api/v1/me/networks/preflight" => { post: preflight_network },
    "/api/v1/me/networks/{name}" => {
        get: get_network,
        put: update_network,
        patch: patch_network,
        delete: delete_network,
    },
    "/api/v1/me/networks/{name}/buffer" => { get: network_buffer },
    "/api/v1/history" => { get: history },
    "/api/v1/admin/accounts" => { get: admin_accounts, post: admin_create_account },
    "/api/v1/admin/accounts/{id}" => {
        patch: admin_account_state,
        delete: admin_delete_account,
    },
    "/api/v1/admin/invitations" => {
        get: admin_account_invitations,
        post: admin_create_account_invitation,
    },
    "/api/v1/admin/invitations/{id}" => { delete: admin_revoke_account_invitation },
    "/api/v1/admin/connections" => { get: admin_connections },
    "/api/v1/admin/connections/{id}" => { delete: admin_disconnect_connection },
    "/api/v1/admin/channels" => { get: admin_channels },
    "/api/v1/admin/channels/{name}" => { delete: delete_admin_channel },
    "/api/v1/admin/networks" => { get: admin_networks },
    "/api/v1/admin/networks/{owner}/{name}" => { patch: patch_admin_network },
    "/api/v1/admin/bans" => { get: admin_server_bans, post: admin_create_server_ban },
    "/api/v1/admin/bans/{id}" => { delete: admin_delete_server_ban },
    "/api/v1/admin/audit" => { get: admin_audit },
    "/api/v1/admin/stats" => { get: admin_stats },
    "/api/v1/admin/configuration" => { get: admin_configuration },
    "/api/v1/admin/configuration/opers" => { post: admin_create_oper },
    "/api/v1/admin/configuration/opers/{name}" => { delete: admin_delete_oper },
    "/api/v1/admin/configuration/oidc-providers" => { post: admin_create_oidc_provider },
    "/api/v1/admin/configuration/oidc-providers/{name}" => { delete: admin_delete_oidc_provider },
    "/api/v1/admin/observability" => { get: admin_observability },
    "/api/v1/admin/metrics" => { get: admin_metrics },
}

pub fn router(state: Arc<AppState>) -> Router {
    let router = Router::new()
        .route("/login", get(pages::login).post(pages::local_login))
        .route(
            "/bootstrap",
            get(pages::bootstrap).post(pages::bootstrap_submit),
        )
        .route(
            "/invite/{token}",
            get(pages::account_invitation).post(pages::accept_account_invitation),
        )
        .route("/auth/signed-out", get(pages::signed_out))
        .route("/auth/validation", get(pages::validation))
        .route("/auth/shauth/logout/complete", get(shauth_logout_complete))
        .route("/auth.css", get(pages::auth_styles))
        .route("/console.js", get(pages::console_script))
        .route("/account", get(pages::account_redirect))
        .route("/console", get(pages::console))
        .route("/console/accounts", get(pages::console_accounts))
        .route(
            "/console/accounts/create",
            post(pages::console_create_account),
        )
        .route(
            "/console/accounts/invitations",
            post(pages::console_create_invitation),
        )
        .route(
            "/console/accounts/invitations/{id}/delete",
            post(pages::console_revoke_invitation),
        )
        .route(
            "/console/accounts/{id}/delete",
            post(pages::console_delete_account),
        )
        .route(
            "/console/accounts/{id}/suspension",
            post(pages::console_account_suspension),
        )
        .route(
            "/console/accounts/{id}/administrator",
            post(pages::console_account_administrator),
        )
        .route(
            "/console/admin/channels",
            get(pages::console_admin_channels),
        )
        .route(
            "/console/admin/networks",
            get(pages::console_admin_networks),
        )
        .route(
            "/console/admin/networks/{owner}/{name}/toggle",
            post(pages::console_admin_network_toggle),
        )
        .route("/console/audit", get(pages::console_audit))
        .route("/console/account", get(pages::console_account))
        .route(
            "/console/account/profile",
            post(pages::console_update_profile),
        )
        .route(
            "/console/account/delete",
            post(pages::console_delete_own_account),
        )
        .route("/console/channels", get(pages::console_channels))
        .route(
            "/console/channels/topic",
            post(pages::console_channel_topic),
        )
        .route(
            "/console/channels/register",
            post(pages::console_channel_register),
        )
        .route(
            "/console/channels/keeptopic",
            post(pages::console_channel_keeptopic),
        )
        .route(
            "/console/channels/mlock",
            post(pages::console_channel_mlock),
        )
        .route(
            "/console/channels/access",
            post(pages::console_channel_access),
        )
        .route(
            "/console/channels/access/delete",
            post(pages::console_channel_access_delete),
        )
        .route(
            "/console/channels/founder",
            post(pages::console_channel_founder),
        )
        .route("/console/channels/drop", post(pages::console_channel_drop))
        .route(
            "/console/account/app-passwords",
            post(pages::console_create_app_password),
        )
        .route(
            "/console/account/password",
            post(pages::console_change_password),
        )
        .route(
            "/console/account/app-passwords/{id}/delete",
            post(pages::console_revoke_app_password),
        )
        .route(
            "/console/account/tokens",
            post(pages::console_create_api_token),
        )
        .route(
            "/console/account/tokens/{id}/delete",
            post(pages::console_revoke_api_token),
        )
        .route(
            "/console/account/identities/{id}/delete",
            post(pages::console_unlink_identity),
        )
        .route("/console/monitoring", get(pages::console_monitoring))
        .route(
            "/console/monitoring/panel",
            get(pages::console_monitoring_panel),
        )
        .route(
            "/console/configuration",
            get(pages::console_configuration).post(pages::console_update_configuration),
        )
        .route(
            "/console/configuration/opers",
            post(pages::console_add_oper),
        )
        .route(
            "/console/configuration/opers/delete",
            post(pages::console_delete_oper),
        )
        .route("/console/configuration/oidc", post(pages::console_add_oidc))
        .route(
            "/console/configuration/oidc/delete",
            post(pages::console_delete_oidc),
        )
        .route(
            "/console/configuration/shared-networks",
            post(pages::console_add_shared_network),
        )
        .route(
            "/console/configuration/shared-networks/delete",
            post(pages::console_delete_shared_network),
        )
        .route(
            "/console/networks",
            get(pages::console_networks).post(pages::console_add_network),
        )
        .route("/console/networks/rows", get(pages::console_network_rows))
        .route(
            "/console/networks/{name}/delete",
            post(pages::console_delete_network),
        )
        .route(
            "/console/networks/preflight",
            post(pages::console_preflight_network),
        )
        .route(
            "/console/networks/{name}/toggle",
            post(pages::console_toggle_network),
        )
        .route(
            "/console/networks/{name}/edit",
            get(pages::console_edit_network).post(pages::console_update_network),
        )
        .route(
            "/console/networks/{name}/operations",
            get(pages::console_network_operations),
        )
        .route(
            "/console/networks/{name}",
            get(pages::console_network_detail),
        )
        .route(
            "/console/integrations",
            get(pages::console_integrations).post(pages::console_add_bridge),
        )
        .route(
            "/console/integrations/{name}/edit",
            get(pages::console_edit_bridge).post(pages::console_update_bridge),
        )
        .route(
            "/console/integrations/delete",
            post(pages::console_delete_bridge),
        )
        .route(
            "/console/integrations/toggle",
            post(pages::console_toggle_bridge),
        )
        .route(
            "/console/bans",
            get(pages::console_server_bans).post(pages::console_add_ban),
        )
        .route("/console/bans/delete", post(pages::console_remove_ban))
        .route(
            "/console/admin/channels/drop",
            post(pages::console_drop_channel),
        )
        .route("/console/sessions", get(pages::console_sessions))
        .route(
            "/console/sessions/{id}/disconnect",
            post(pages::console_disconnect_session),
        )
        .route("/console/my-sessions", get(pages::console_my_sessions))
        .route(
            "/console/my-sessions/{id}/disconnect",
            post(pages::console_disconnect_own_session),
        )
        .route(
            "/console/my-sessions/browser/{id}/delete",
            post(pages::console_revoke_browser_session),
        )
        .route(
            "/console/my-sessions/browser/others/delete",
            post(pages::console_revoke_other_browser_sessions),
        )
        .route(
            "/device",
            get(pages::device_page).post(pages::approve_device_form),
        );
    let router = add_documented_routes(router)
        .route("/ws/irc", get(ws_irc))
        .route("/ws/ui", get(ws_ui));
    // With the `embed-web` feature the built web client (web/dist) is
    // baked into the binary and served at `/` and `/assets/*`; otherwise
    // the assets live on S3/CDN and only the API + WebSocket paths are
    // served here. (DESIGN §13.3)
    #[cfg(feature = "embed-web")]
    let router = router
        .route("/", get(web::index))
        .route("/assets/{*path}", get(web::asset));
    router
        .fallback(async || problem(StatusCode::NOT_FOUND, "Not Found", None))
        // Defense-in-depth: every response (including the JSON/problem+json API
        // paths, which don't go through security_headers) carries nosniff, so a
        // response body can never be sniffed into an executable type.
        .layer(axum::middleware::map_response(
            |mut resp: Response| async move {
                resp.headers_mut()
                    .entry(header::X_CONTENT_TYPE_OPTIONS)
                    .or_insert(header::HeaderValue::from_static("nosniff"));
                resp
            },
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            observe_http,
        ))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(1024 * 1024))
        .layer(tower::limit::ConcurrencyLimitLayer::new(1024))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            std::time::Duration::from_secs(30),
        ))
        .with_state(state)
}

/// A minimal router that serves IRC-over-WebSocket at the root path (`/`). Used
/// by a dedicated `websocket = true` listener — a bare WS-IRC port with no HTTP
/// UI — so a client connecting to `ws://host:port/` reaches the same core as the
/// raw TCP listeners. Shares the AppState (core_tx, per-IP limiter, sendq) with
/// any HTTP server. Kept separate from `router` so the full HTTP surface
/// (login, console, API) is never exposed on a port meant only for WS-IRC.
pub fn ws_irc_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(ws_irc))
        .fallback(async || problem(StatusCode::NOT_FOUND, "Not Found", None))
        .with_state(state)
}

/// Embedded web client (the Vite build in web/dist) served under the
/// `embed-web` feature. In debug builds rust-embed reads from disk; in
/// release it embeds the files, so a release build needs `pnpm build`
/// in web/ beforehand.
#[cfg(feature = "embed-web")]
mod web {
    use super::*;

    #[derive(rust_embed::Embed)]
    #[folder = "../../web/dist"]
    struct Dist;

    fn serve(path: &str) -> Response {
        match Dist::get(path) {
            Some(file) => {
                let mime = mime_for(path);
                // Hashed asset filenames are safe to cache immutably; the
                // entry HTML must revalidate so new builds are picked up.
                let cache = if path.starts_with("assets/") {
                    "public, max-age=31536000, immutable"
                } else {
                    "no-cache"
                };
                let mut response = (
                    [(header::CONTENT_TYPE, mime), (header::CACHE_CONTROL, cache)],
                    file.data.into_owned(),
                )
                    .into_response();
                security_headers(response.headers_mut());
                response
            }
            None => problem(StatusCode::NOT_FOUND, "Not Found", None),
        }
    }

    fn mime_for(path: &str) -> &'static str {
        match path.rsplit('.').next() {
            Some("html") => "text/html; charset=utf-8",
            Some("js") => "text/javascript; charset=utf-8",
            Some("css") => "text/css; charset=utf-8",
            Some("json") => "application/json",
            Some("svg") => "image/svg+xml",
            Some("woff2") => "font/woff2",
            Some("png") => "image/png",
            _ => "application/octet-stream",
        }
    }

    /// The application entry point is an authentication boundary, not a
    /// public static file. An existing local session renders the client. An
    /// anonymous browser is sent to `/login`, which renders the provider
    /// sign-in links a validator (and a human) can discover and click —
    /// auto-redirecting to the single provider's `/start` skips that page
    /// and is undetectable by SSO validators (#191).
    pub async fn index(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
    ) -> Response {
        match authenticate(&state, &headers).await {
            Ok(_) => serve("index.html"),
            Err(response) if response.status() != StatusCode::UNAUTHORIZED => response,
            Err(_) => Redirect::to("/login").into_response(),
        }
    }

    pub async fn asset(axum::extract::Path(path): axum::extract::Path<String>) -> Response {
        serve(&format!("assets/{path}"))
    }
}

/// Reject a credential mutation while the config still holds bootstrap-sealed
/// credentials. A master key and restart are required before changing them.
fn reject_bootstrap_credential_change(
    settings: &crate::config::ManagedConfig,
    credential_kind: &str,
) -> Result<(), String> {
    (!settings.credentials_from_bootstrap)
        .then_some(())
        .ok_or_else(|| {
            format!(
                "Configure a master key and restart before changing bootstrap {credential_kind} credentials."
            )
        })
}

/// Remove one named managed-configuration item, reporting a missing name.
fn remove_named<T>(
    items: &mut Vec<T>,
    name: &str,
    item_kind: &str,
    item_name: impl Fn(&T) -> &str,
) -> Result<(), String> {
    let before = items.len();
    items.retain(|item| item_name(item) != name);
    (items.len() != before)
        .then_some(())
        .ok_or_else(|| format!("No {item_kind} named '{name}'."))
}

fn add_managed_oper(
    settings: &mut crate::config::ManagedConfig,
    oper: crate::config::OperConfig,
) -> Result<String, String> {
    reject_bootstrap_credential_change(settings, "operator")?;
    let name = oper.name.clone();
    settings.opers.push(oper);
    Ok(format!("added IRC operator {name}"))
}

fn add_managed_oidc_provider(
    settings: &mut crate::config::ManagedConfig,
    provider: crate::config::OidcProviderConfig,
) -> Result<String, String> {
    reject_bootstrap_credential_change(settings, "identity-provider")?;
    let name = provider.name.clone();
    settings.oidc_providers.push(provider);
    Ok(format!("added OpenID Connect provider {name}"))
}

struct ManagedConfigurationItem<T> {
    credential_kind: &'static str,
    item_kind: &'static str,
    items: fn(&mut crate::config::ManagedConfig) -> &mut Vec<T>,
    item_name: fn(&T) -> &str,
}

fn delete_managed_configuration_item<T>(
    settings: &mut crate::config::ManagedConfig,
    name: &str,
    item: ManagedConfigurationItem<T>,
) -> Result<String, String> {
    reject_bootstrap_credential_change(settings, item.credential_kind)?;
    remove_named((item.items)(settings), name, item.item_kind, item.item_name)?;
    Ok(format!("removed {} {name}", item.item_kind))
}

/// Server-rendered HTML pages (askama). Complements the Vite chat client with
/// authentication, self-service, and operational management surfaces.
mod pages {
    use super::*;
    use askama::Template;

    #[derive(Template)]
    #[template(path = "login.html")]
    struct Login {
        providers: Vec<String>,
        local_enabled: bool,
        bootstrap_available: bool,
        login_state: String,
        account: String,
        error: Option<String>,
    }

    #[derive(Template)]
    #[template(path = "signed_out.html")]
    struct SignedOut {
        /// The single configured provider to offer directly, when there is
        /// exactly one. The provider's configured name is part of its starter
        /// path, so this cannot be a fixed string: an operator who names the
        /// provider anything other than `shauth` would otherwise be offered a
        /// link to a starter that does not exist.
        sole_provider: Option<String>,
    }

    /// Shared context inherited by every console template.
    #[derive(Clone)]
    struct ConsoleShell {
        account: String,
        csrf: String,
        is_admin: bool,
        active: &'static str,
    }

    fn console_shell(
        state: &AppState,
        account: String,
        csrf: String,
        active: &'static str,
    ) -> ConsoleShell {
        ConsoleShell {
            is_admin: is_admin_account(state, &account),
            account,
            csrf,
            active,
        }
    }

    #[derive(Template)]
    #[template(path = "validation.html")]
    struct Validation {
        username: String,
        email: String,
        role: String,
        release: String,
        logout_url: String,
    }

    fn login_response(
        state: &AppState,
        account: String,
        error: Option<String>,
        status: StatusCode,
    ) -> Response {
        let local_enabled = state.pool.is_some();
        let login_state = local_enabled
            .then(super::random_browser_token)
            .unwrap_or_default();
        let providers = state
            .oidc_providers
            .iter()
            .map(|provider| provider.name.clone())
            .collect();
        let mut response = render_auth(Login {
            providers,
            local_enabled,
            bootstrap_available: state.bootstrap_available.load(Ordering::Acquire),
            login_state: login_state.clone(),
            account,
            error,
        });
        *response.status_mut() = status;
        if local_enabled {
            let secure = if state.secure_cookies { "; Secure" } else { "" };
            response.headers_mut().insert(
                header::SET_COOKIE,
                format!(
                    "{}={login_state}; HttpOnly; SameSite=Strict; Path=/; Max-Age=600{secure}",
                    super::login_state_cookie_name(state.secure_cookies)
                )
                .parse()
                .expect("generated cookie is a valid header"),
            );
        }
        response
    }

    /// Login landing: local credentials plus one button per configured OIDC
    /// provider. A fresh browser-bound state accompanies every local form.
    pub async fn login(State(state): State<Arc<AppState>>) -> Response {
        login_response(&state, String::new(), None, StatusCode::OK)
    }

    #[derive(Template)]
    #[template(path = "bootstrap.html")]
    struct Bootstrap {
        bootstrap_state: String,
        account: String,
        error: Option<String>,
    }

    fn bootstrap_state_cookie_name(secure: bool) -> &'static str {
        if secure {
            "__Host-e6irc_bootstrap_state"
        } else {
            "e6irc_bootstrap_state"
        }
    }

    fn browser_state_matches(
        headers: &axum::http::HeaderMap,
        cookie_name: &str,
        supplied: &str,
    ) -> bool {
        super::cookie_value(headers, cookie_name).is_some_and(|cookie| {
            cookie.len() == supplied.len()
                && aws_lc_rs::constant_time::verify_slices_are_equal(
                    cookie.as_bytes(),
                    supplied.as_bytes(),
                )
                .is_ok()
        })
    }

    fn authenticated_redirect(
        token: &str,
        location: &'static str,
        state_cookie_name: &str,
        secure_cookies: bool,
    ) -> Response {
        let secure = if secure_cookies { "; Secure" } else { "" };
        (
            StatusCode::SEE_OTHER,
            axum::response::AppendHeaders([
                (header::LOCATION, location.to_string()),
                (
                    header::SET_COOKIE,
                    super::session_cookie(token, secure_cookies),
                ),
                (
                    header::SET_COOKIE,
                    format!(
                        "{state_cookie_name}=; HttpOnly; SameSite=Strict; \
                         Path=/; Max-Age=0{secure}"
                    ),
                ),
            ]),
        )
            .into_response()
    }

    fn bootstrap_response(
        state: &AppState,
        account: String,
        error: Option<String>,
        status: StatusCode,
    ) -> Response {
        if state.bootstrap_token_digest.is_none()
            || !state.bootstrap_available.load(Ordering::Acquire)
        {
            return Redirect::to("/login").into_response();
        }
        let bootstrap_state = super::random_browser_token();
        let mut response = render_auth(Bootstrap {
            bootstrap_state: bootstrap_state.clone(),
            account,
            error,
        });
        *response.status_mut() = status;
        let secure = if state.secure_cookies { "; Secure" } else { "" };
        response.headers_mut().insert(
            header::SET_COOKIE,
            format!(
                "{}={bootstrap_state}; HttpOnly; SameSite=Strict; Path=/; Max-Age=600{secure}",
                bootstrap_state_cookie_name(state.secure_cookies)
            )
            .parse()
            .expect("generated cookie is a valid header"),
        );
        response
    }

    pub async fn bootstrap(State(state): State<Arc<AppState>>) -> Response {
        bootstrap_response(&state, String::new(), None, StatusCode::OK)
    }

    #[derive(Deserialize)]
    pub struct BootstrapForm {
        bootstrap_state: String,
        token: String,
        account: String,
        password: String,
        password_confirmation: String,
    }

    pub async fn bootstrap_submit(
        State(state): State<Arc<AppState>>,
        _rate_limited: RateLimited,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<BootstrapForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let Some(expected_token) = state.bootstrap_token_digest else {
            return problem(StatusCode::NOT_FOUND, "Bootstrap unavailable", None);
        };
        let pool = require_pool!(state);
        if !state.bootstrap_available.load(Ordering::Acquire) {
            return problem(StatusCode::CONFLICT, "Bootstrap already complete", None);
        }
        let form = match parse_form(form) {
            Ok(form) => form,
            Err(response) => return response,
        };
        let bound = browser_state_matches(
            &headers,
            bootstrap_state_cookie_name(state.secure_cookies),
            &form.bootstrap_state,
        );
        if !bound {
            return bootstrap_response(
                &state,
                form.account,
                Some("This bootstrap form expired. Please try again.".into()),
                StatusCode::FORBIDDEN,
            );
        }
        let supplied_token = super::bootstrap_token_digest(&form.token);
        if aws_lc_rs::constant_time::verify_slices_are_equal(&expected_token, &supplied_token)
            .is_err()
        {
            return bootstrap_response(
                &state,
                form.account,
                Some("Invalid bootstrap token.".into()),
                StatusCode::UNAUTHORIZED,
            );
        }
        if !crate::sanitize::valid_nick(&form.account, MAX_ACCOUNT_LEN) {
            return bootstrap_response(
                &state,
                form.account,
                Some("The administrator account must be a valid IRC nickname.".into()),
                StatusCode::BAD_REQUEST,
            );
        }
        if let Some(detail) = password_input_error(&form.password) {
            return bootstrap_response(
                &state,
                form.account,
                Some(detail.into()),
                StatusCode::BAD_REQUEST,
            );
        }
        if form.password != form.password_confirmation {
            return bootstrap_response(
                &state,
                form.account,
                Some("Password confirmation does not match.".into()),
                StatusCode::BAD_REQUEST,
            );
        }
        match crate::db::bootstrap_first_admin(pool, &form.account, &form.password).await {
            Ok(_account_id) => {}
            Err(crate::db::DbError::AlreadyInitialized) => {
                state.bootstrap_available.store(false, Ordering::Release);
                return problem(StatusCode::CONFLICT, "Bootstrap already complete", None);
            }
            Err(error) => {
                eprintln!("browser bootstrap failed: {error}");
                return problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Bootstrap storage failed",
                    None,
                );
            }
        }
        state
            .admin_accounts
            .write()
            .expect("administrator registry lock")
            .insert(e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(&form.account));
        state.bootstrap_available.store(false, Ordering::Release);
        let user_agent = super::session_user_agent(&headers);
        let token =
            match crate::db::create_web_session(pool, &form.account, user_agent.as_ref()).await {
                Ok(token) => token,
                Err(error) => {
                    eprintln!("bootstrap session creation failed: {error}");
                    return problem(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Administrator created; session storage failed",
                        Some("Sign in with the administrator account to continue."),
                    );
                }
            };
        authenticated_redirect(
            &token,
            "/console",
            bootstrap_state_cookie_name(state.secure_cookies),
            state.secure_cookies,
        )
    }

    #[derive(Template)]
    #[template(path = "invite.html")]
    struct AccountInvitation {
        token: String,
        invitation_state: String,
        account: String,
        administrator: bool,
        expires_at: String,
        error: Option<String>,
    }

    fn invitation_state_cookie_name(secure: bool) -> &'static str {
        if secure {
            "__Host-e6irc_invitation_state"
        } else {
            "e6irc_invitation_state"
        }
    }

    fn valid_invitation_token(token: &str) -> bool {
        token.len() == 48
            && token.starts_with("e6i_")
            && token[4..]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'='))
    }

    fn invitation_response(
        state: &AppState,
        token: String,
        preview: crate::db::AccountInvitationPreview,
        error: Option<String>,
        status: StatusCode,
    ) -> Response {
        let invitation_state = super::random_browser_token();
        let mut response = render_auth(AccountInvitation {
            token,
            invitation_state: invitation_state.clone(),
            account: preview.account_name,
            administrator: preview.administrator,
            expires_at: preview.expires_at,
            error,
        });
        *response.status_mut() = status;
        let secure = if state.secure_cookies { "; Secure" } else { "" };
        response.headers_mut().insert(
            header::SET_COOKIE,
            format!(
                "{}={invitation_state}; HttpOnly; SameSite=Strict; Path=/; Max-Age=600{secure}",
                invitation_state_cookie_name(state.secure_cookies)
            )
            .parse()
            .expect("generated cookie is a valid header"),
        );
        response
    }

    pub async fn account_invitation(
        State(state): State<Arc<AppState>>,
        Path(token): Path<String>,
    ) -> Response {
        if !valid_invitation_token(&token) {
            return problem(StatusCode::NOT_FOUND, "Invitation unavailable", None);
        }
        let pool = require_pool!(state);
        match crate::db::account_invitation_preview(pool, &token).await {
            Ok(Some(preview)) => invitation_response(&state, token, preview, None, StatusCode::OK),
            Ok(None) => problem(StatusCode::NOT_FOUND, "Invitation unavailable", None),
            Err(error) => {
                eprintln!("account invitation lookup failed: {error}");
                problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Invitation storage unavailable",
                    None,
                )
            }
        }
    }

    #[derive(Deserialize)]
    pub struct AccountInvitationAcceptanceForm {
        invitation_state: String,
        password: String,
        password_confirmation: String,
    }

    pub async fn accept_account_invitation(
        State(state): State<Arc<AppState>>,
        _rate_limited: RateLimited,
        headers: axum::http::HeaderMap,
        Path(token): Path<String>,
        form: Result<
            axum::Form<AccountInvitationAcceptanceForm>,
            axum::extract::rejection::FormRejection,
        >,
    ) -> Response {
        if !valid_invitation_token(&token) {
            return problem(StatusCode::NOT_FOUND, "Invitation unavailable", None);
        }
        let pool = require_pool!(state);
        let preview = match crate::db::account_invitation_preview(pool, &token).await {
            Ok(Some(preview)) => preview,
            Ok(None) => return problem(StatusCode::NOT_FOUND, "Invitation unavailable", None),
            Err(error) => {
                eprintln!("account invitation lookup failed: {error}");
                return problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Invitation storage unavailable",
                    None,
                );
            }
        };
        let form = match parse_form(form) {
            Ok(form) => form,
            Err(response) => return response,
        };
        if !browser_state_matches(
            &headers,
            invitation_state_cookie_name(state.secure_cookies),
            &form.invitation_state,
        ) {
            return invitation_response(
                &state,
                token,
                preview,
                Some("This invitation form expired. Please try again.".into()),
                StatusCode::FORBIDDEN,
            );
        }
        if let Some(detail) = password_input_error(&form.password) {
            return invitation_response(
                &state,
                token,
                preview,
                Some(detail.into()),
                StatusCode::BAD_REQUEST,
            );
        }
        if form.password != form.password_confirmation {
            return invitation_response(
                &state,
                token,
                preview,
                Some("Password confirmation does not match.".into()),
                StatusCode::BAD_REQUEST,
            );
        }
        let account = match crate::db::accept_account_invitation(pool, &token, &form.password).await
        {
            Ok(account) => account,
            Err(crate::db::DbError::InvitationUnavailable) => {
                return problem(StatusCode::NOT_FOUND, "Invitation unavailable", None);
            }
            Err(error) => {
                eprintln!("account invitation acceptance failed: {error}");
                return problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Invitation storage unavailable",
                    None,
                );
            }
        };
        if preview.administrator {
            state
                .admin_accounts
                .write()
                .expect("administrator registry lock")
                .insert(e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(&account));
        }
        let user_agent = super::session_user_agent(&headers);
        let session = match crate::db::create_web_session(pool, &account, user_agent.as_ref()).await
        {
            Ok(session) => session,
            Err(error) => {
                eprintln!("invited account session creation failed: {error}");
                return problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Account created; session storage failed",
                    Some("Sign in with the new account to continue."),
                );
            }
        };
        authenticated_redirect(
            &session,
            "/console",
            invitation_state_cookie_name(state.secure_cookies),
            state.secure_cookies,
        )
    }

    #[derive(Deserialize)]
    pub struct LocalLoginForm {
        login_state: String,
        account: String,
        password: String,
    }

    pub async fn local_login(
        State(state): State<Arc<AppState>>,
        _rate_limited: RateLimited,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<LocalLoginForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let Some(pool) = &state.pool else {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "No database configured",
                Some("Local account login is unavailable on this server."),
            );
        };
        let form = match parse_form(form) {
            Ok(form) => form,
            Err(response) => return response,
        };
        let bound = browser_state_matches(
            &headers,
            super::login_state_cookie_name(state.secure_cookies),
            &form.login_state,
        );
        if !bound {
            return login_response(
                &state,
                form.account,
                Some("This sign-in form expired. Please try again.".into()),
                StatusCode::FORBIDDEN,
            );
        }
        if let Some(detail) = credential_input_error(&form.account, &form.password) {
            return login_response(
                &state,
                form.account,
                Some(detail.into()),
                StatusCode::BAD_REQUEST,
            );
        }
        let account =
            match crate::db::verify_local_password(pool, &form.account, &form.password).await {
                Ok(Some(account)) => account,
                Ok(None) => {
                    // A failed web login is a security event; one bounded line
                    // per denial, without the password.
                    eprintln!("web: login failed for account {}", form.account);
                    return login_response(
                        &state,
                        form.account,
                        Some("Invalid account or password.".into()),
                        StatusCode::UNAUTHORIZED,
                    );
                }
                Err(error) => {
                    eprintln!("local login: credential verification failed: {error}");
                    return problem(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Authentication storage unavailable",
                        None,
                    );
                }
            };
        let user_agent = super::session_user_agent(&headers);
        let token = match crate::db::create_web_session(pool, &account, user_agent.as_ref()).await {
            Ok(token) => token,
            Err(error) => {
                eprintln!("local login: session creation failed: {error}");
                return problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Session storage failed",
                    None,
                );
            }
        };
        authenticated_redirect(
            &token,
            "/",
            super::login_state_cookie_name(state.secure_cookies),
            state.secure_cookies,
        )
    }

    /// Public, reload-safe landing after coordinated logout. It deliberately
    /// never probes the local or provider session, so a completed logout does
    /// not immediately send the browser back through silent single sign-on.
    pub async fn signed_out(State(state): State<Arc<AppState>>) -> Response {
        let mut providers = state.oidc_providers.iter();
        let sole_provider = match (providers.next(), providers.next()) {
            (Some(provider), None) => Some(provider.name.clone()),
            _ => None,
        };
        render_auth(SignedOut { sole_provider })
    }

    /// Deployment-neutral authenticated identity contract consumed by
    /// Shauth's browser validator. It accepts only a complete durable OIDC
    /// session and otherwise returns to the application-local signed-out page.
    pub async fn validation(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
    ) -> Response {
        let pool = require_pool!(state);
        let Some(token) = session_token(&headers, state.secure_cookies) else {
            return validation_signed_out();
        };
        let identity = match crate::db::session_identity(pool, &token).await {
            Ok(Some(identity)) => identity,
            Ok(None) => return validation_signed_out(),
            Err(error) => {
                eprintln!("validation: session lookup failed: {error}");
                return problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Session storage failed",
                    None,
                );
            }
        };
        if identity.provider.as_deref() != Some("shauth") {
            return validation_signed_out();
        }
        let (Some(email), Some(role), Some(release)) = (
            identity.email,
            identity.role,
            state.application_release_revision.clone(),
        ) else {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Authenticated identity contract is incomplete",
                None,
            );
        };
        render_auth(Validation {
            username: identity.account,
            email,
            role,
            release,
            logout_url: format!("/api/v1/auth/logout?csrf={}", state.csrf_token(&token)),
        })
    }

    fn validation_signed_out() -> Response {
        let mut response = Redirect::to("/auth/signed-out").into_response();
        no_store(response.headers_mut());
        response
    }

    pub async fn auth_styles() -> Response {
        (
            [
                (header::CONTENT_TYPE, "text/css; charset=utf-8"),
                (header::CACHE_CONTROL, "public, max-age=3600"),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            ],
            include_str!("../../assets/auth.css"),
        )
            .into_response()
    }

    pub async fn console_script() -> Response {
        (
            [
                (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
                (header::CACHE_CONTROL, "public, max-age=3600"),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            ],
            include_str!("../../assets/console.js"),
        )
            .into_response()
    }

    /// The console add-network form (urlencoded). `tls` is an
    /// HTML checkbox (`"on"` when checked, absent otherwise). The SASL pair and
    /// realname are optional text inputs that submit as empty strings when left
    /// blank, so `into_create` maps blank → `None`.
    #[derive(Deserialize)]
    pub struct NetworkFormFields {
        csrf: String,
        #[serde(default)]
        preset: String,
        name: String,
        addr: String,
        nick: String,
        #[serde(default)]
        tls: Option<String>,
        #[serde(default)]
        autojoin: String,
        #[serde(default)]
        realname: String,
        #[serde(default)]
        sasl_account: String,
        #[serde(default)]
        sasl_password: String,
    }

    impl NetworkFormFields {
        /// Resolve a selected catalog entry into the submitted fields. Doing
        /// this server-side makes presets work without JavaScript; mutating the
        /// fields also ensures a later validation error re-renders the values
        /// that will actually be submitted, not stale values from the previous
        /// selection.
        fn apply_preset(&mut self) -> Result<(), NetworkMutationError> {
            if !self.preset.is_empty() && self.preset != "custom" {
                let Some(preset) = irc_network_preset(&self.preset) else {
                    return Err(NetworkMutationError::new(
                        StatusCode::BAD_REQUEST,
                        "Unknown IRC network preset",
                        Some("select one of the listed networks or Custom"),
                    ));
                };
                self.name = preset.name.to_string();
                self.addr = preset.addr.to_string();
                self.tls = preset.tls.then(|| "on".to_string());
            }
            Ok(())
        }

        /// Build the `CreateNetwork` for an IRC upstream from already-resolved
        /// form fields, treating a blank optional text input as absent.
        fn into_resolved_create(self) -> CreateNetwork {
            let opt = |s: String| {
                let s = s.trim().to_string();
                (!s.is_empty()).then_some(s)
            };
            CreateNetwork {
                kind: crate::config::NetworkKind::Irc,
                name: self.name.trim().to_string(),
                addr: self.addr.trim().to_string(),
                tls: self.tls.as_deref() == Some("on"),
                nick: self.nick.trim().to_string(),
                realname: opt(self.realname),
                autojoin: self
                    .autojoin
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect(),
                sasl_account: opt(self.sasl_account),
                sasl_password: opt(self.sasl_password),
            }
        }
    }

    #[derive(Clone)]
    /// A form failure plus the field it belongs to, when it has one. Field
    /// errors render inline at the offending input; fieldless failures render
    /// as the page banner.
    struct FormFieldError {
        message: String,
        field: Option<&'static str>,
    }

    impl FormFieldError {
        fn banner(message: impl Into<String>) -> Self {
            Self {
                message: message.into(),
                field: None,
            }
        }

        fn from_mutation(error: &crate::http::networks::NetworkMutationError) -> Self {
            Self {
                message: error.message(),
                field: error.field(),
            }
        }
    }

    struct NetworkFormView {
        preset: String,
        name: String,
        addr: String,
        nick: String,
        realname: String,
        autojoin: String,
        sasl_account: String,
        tls: bool,
    }

    impl NetworkFormView {
        fn libera(account: &str) -> Self {
            let preset =
                irc_network_preset("libera").expect("Libera preset is part of the catalog");
            Self {
                preset: preset.id.into(),
                name: preset.name.into(),
                addr: preset.addr.into(),
                nick: account.into(),
                realname: String::new(),
                autojoin: String::new(),
                sasl_account: String::new(),
                tls: preset.tls,
            }
        }

        fn submitted(fields: &NetworkFormFields) -> Self {
            Self {
                preset: fields.preset.clone(),
                name: fields.name.clone(),
                addr: fields.addr.clone(),
                nick: fields.nick.clone(),
                realname: fields.realname.clone(),
                autojoin: fields.autojoin.clone(),
                sasl_account: fields.sasl_account.clone(),
                tls: fields.tls.as_deref() == Some("on"),
            }
        }
    }

    struct CredentialView {
        id: i64,
        kind: String,
        label: String,
        created: String,
        last_used: String,
        revocable: bool,
    }

    struct ApiTokenView {
        id: i64,
        label: String,
        created: String,
        expires: String,
        scopes: String,
    }

    struct IdentityView {
        id: i64,
        issuer: String,
        subject: String,
        created: String,
    }

    struct ReadMarkerView {
        target: String,
        timestamp: String,
    }

    #[derive(Template)]
    #[template(path = "console_account.html")]
    struct ConsoleAccount {
        shell: ConsoleShell,
        credentials: Vec<CredentialView>,
        has_local_password: bool,
        tokens: Vec<ApiTokenView>,
        identities: Vec<IdentityView>,
        read_markers: Vec<ReadMarkerView>,
        security_activity: Vec<AuditRow>,
        contact_email: String,
        link_providers: Vec<String>,
        outcome: Option<String>,
        success: bool,
        secret: Option<String>,
        secret_kind: &'static str,
    }

    async fn account_build(
        state: &AppState,
        account: String,
        csrf: String,
        outcome: Option<String>,
        success: bool,
        secret: Option<String>,
        secret_kind: &'static str,
    ) -> Result<ConsoleAccount, Response> {
        let pool = pool_of(state);
        let credentials: Vec<CredentialView> = crate::db::list_credentials(pool, &account)
            .await
            .map_err(|e| super::device::admin_db_error("credential list", e))?
            .into_iter()
            .map(|(id, kind, label, created, last_used)| CredentialView {
                id,
                revocable: kind == "app_password",
                kind,
                label: label.unwrap_or_default(),
                created,
                last_used: last_used.unwrap_or_else(|| "Never".into()),
            })
            .collect();
        let has_local_password = credentials
            .iter()
            .any(|credential| credential.kind == "local_password");
        let tokens = crate::db::list_api_tokens(pool, &account)
            .await
            .map_err(|e| super::device::admin_db_error("token list", e))?
            .into_iter()
            .map(|token| ApiTokenView {
                id: token.id,
                label: token.label,
                created: token.created_at,
                expires: token.expires_at,
                scopes: token
                    .scopes
                    .iter()
                    .map(crate::identity::ApiTokenScope::as_str)
                    .collect::<Vec<_>>()
                    .join(", "),
            })
            .collect();
        let identities = crate::db::list_oidc_identities(pool, &account)
            .await
            .map_err(|e| super::device::admin_db_error("identity list", e))?
            .into_iter()
            .map(|(id, issuer, subject, created)| IdentityView {
                id,
                issuer,
                subject,
                created,
            })
            .collect();
        let read_markers = crate::db::list_read_markers(pool, &account)
            .await
            .map_err(|e| super::device::admin_db_error("read-marker list", e))?
            .into_iter()
            .map(|(target, timestamp)| ReadMarkerView { target, timestamp })
            .collect();
        let contact_email = crate::db::account_contact_email(pool, &account)
            .await
            .map_err(|e| super::device::admin_db_error("profile read", e))?
            .unwrap_or_default();
        let security_activity = crate::db::query_account_security_activity(
            pool,
            &account,
            None,
            crate::db::AuditLogPageSize::new(50).expect("static activity page size is valid"),
        )
        .await
        .map_err(|e| super::device::admin_db_error("security activity", e))?
        .entries
        .into_iter()
        .map(AuditRow::from)
        .collect();
        let link_providers = state
            .oidc_providers
            .iter()
            .map(|provider| provider.name.clone())
            .collect();
        Ok(ConsoleAccount {
            shell: console_shell(state, account, csrf, "account"),
            credentials,
            has_local_password,
            tokens,
            identities,
            read_markers,
            security_activity,
            contact_email,
            link_providers,
            outcome,
            success,
            secret,
            secret_kind,
        })
    }

    /// Authenticate a cookie session for a server-rendered page and derive its
    /// CSRF token, returning `(account, csrf)`. On no/invalid session returns the
    /// `/login` redirect; with `admin_only`, a non-admin gets 403. This is the
    /// shared preamble of every console/account page handler.
    async fn page_actor(
        state: &AppState,
        headers: &axum::http::HeaderMap,
        admin_only: bool,
    ) -> Result<(String, String), Response> {
        let account = authenticate(state, headers)
            .await
            .map_err(|_| Redirect::to("/login").into_response())?;
        if admin_only && !is_admin_account(state, &account) {
            return Err(problem(StatusCode::FORBIDDEN, "Admin only", None));
        }
        let csrf = session_token(headers, state.secure_cookies)
            .map(|s| state.csrf_token(&s))
            .unwrap_or_default();
        Ok((account, csrf))
    }

    /// An administrator-authenticated server-rendered page actor. Declaring
    /// this extractor in a handler signature makes the login redirect, admin
    /// gate, and session-bound CSRF derivation preconditions of calling it.
    pub(super) struct AdminPageActor {
        account: String,
        csrf: String,
    }

    impl axum::extract::FromRequestParts<Arc<AppState>> for AdminPageActor {
        type Rejection = Response;

        async fn from_request_parts(
            parts: &mut axum::http::request::Parts,
            state: &Arc<AppState>,
        ) -> Result<Self, Self::Rejection> {
            let (account, csrf) = page_actor(state, &parts.headers, true).await?;
            Ok(Self { account, csrf })
        }
    }

    /// Preserve the old account-page URL while keeping one canonical
    /// self-service console.
    pub async fn account_redirect(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
    ) -> Response {
        if let Err(response) = page_actor(&state, &headers, false).await {
            return response;
        }
        Redirect::to("/console/account").into_response()
    }

    pub async fn console_account(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
    ) -> Response {
        let (account, csrf) = match page_actor(&state, &headers, false).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
        match account_build(&state, account, csrf, None, true, None, "").await {
            Ok(view) => render_private(view),
            Err(response) => response,
        }
    }

    pub async fn console_update_profile(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<AccountContactForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let (account, form) = match account_form_actor(&state, &headers, form).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        let contact_email = if form.contact_email.trim().is_empty() {
            None
        } else {
            match crate::identity::ContactEmail::parse(form.contact_email.trim()) {
                Ok(email) => Some(email),
                Err(error) => {
                    return account_result(
                        &state,
                        account,
                        &headers,
                        AccountResult::message(StatusCode::BAD_REQUEST, error.to_string()),
                    )
                    .await;
                }
            }
        };
        let result =
            crate::db::set_account_contact_email(pool_of(&state), &account, contact_email.as_ref())
                .await;
        let view = match result {
            Ok(()) => AccountResult::message(
                StatusCode::OK,
                if contact_email.is_some() {
                    "Contact email updated."
                } else {
                    "Contact email removed."
                },
            ),
            Err(error) => {
                eprintln!("http: contact email update failed: {error}");
                AccountResult::message(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Contact email was not changed.",
                )
            }
        };
        account_result(&state, account, &headers, view).await
    }

    pub async fn console_delete_own_account(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        form: Result<
            axum::Form<AccountPermanentDeleteForm>,
            axum::extract::rejection::FormRejection,
        >,
    ) -> Response {
        let (account, form) = match account_form_actor(&state, &headers, form).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        if form.confirmation != account {
            return account_result(
                &state,
                account,
                &headers,
                AccountResult::message(
                    StatusCode::BAD_REQUEST,
                    "Account confirmation does not match. Supply the exact display-cased account name.",
                ),
            )
            .await;
        }
        let account_id = match crate::db::account_id_by_name(pool_of(&state), &account).await {
            Ok(Some(account_id)) => account_id,
            Ok(None) => return Redirect::to("/login").into_response(),
            Err(error) => return super::device::admin_db_error("account deletion target", error),
        };
        match delete_account_lifecycle(&state, &account, account_id, true).await {
            Ok(_) => redirect_signed_out(&state),
            Err((status, detail)) => {
                account_result(
                    &state,
                    account,
                    &headers,
                    AccountResult::message(status, detail),
                )
                .await
            }
        }
    }

    #[derive(Deserialize)]
    pub struct AccountLabelForm {
        csrf: String,
        label: String,
    }

    #[derive(Deserialize)]
    pub struct AccountContactForm {
        csrf: String,
        #[serde(default)]
        contact_email: String,
    }

    #[derive(Deserialize)]
    pub struct AccountTokenForm {
        csrf: String,
        label: String,
        expires_in_days: u16,
        #[serde(default)]
        scope_read: Option<String>,
        #[serde(default)]
        scope_write: Option<String>,
        #[serde(default)]
        scope_administrator: Option<String>,
        #[serde(default)]
        scope_irc: Option<String>,
    }

    #[derive(Deserialize)]
    pub struct AccountDeleteForm {
        csrf: String,
    }

    #[derive(Deserialize)]
    pub struct AccountPermanentDeleteForm {
        csrf: String,
        confirmation: String,
    }

    #[derive(Deserialize)]
    pub struct AccountPasswordForm {
        csrf: String,
        #[serde(default)]
        current_password: String,
        new_password: String,
        confirm_password: String,
    }

    trait AccountForm {
        fn csrf(&self) -> &str;
    }

    /// Every form type carrying a `csrf` field implements [`AccountForm`] the
    /// same way — one macro so the mapping can't drift (or grow a copy that
    /// points at the wrong field).
    macro_rules! account_form {
        ($($t:ty),* $(,)?) => {
            $(impl AccountForm for $t {
                fn csrf(&self) -> &str {
                    &self.csrf
                }
            })*
        };
    }
    account_form!(
        AccountLabelForm,
        AccountTokenForm,
        AccountContactForm,
        AccountDeleteForm,
        AccountPermanentDeleteForm,
        AccountPasswordForm,
        ToggleFields,
        NetworkFormFields,
        NetworkEditForm,
        BridgeToggleFields,
        BridgeDeleteFields,
        BridgeFormFields,
        BridgeEditFormFields,
        BanForm,
        BanDeleteForm,
        DropChannelForm,
    );

    async fn account_form_actor<T: AccountForm>(
        state: &AppState,
        headers: &axum::http::HeaderMap,
        form: Result<axum::Form<T>, axum::extract::rejection::FormRejection>,
    ) -> Result<(String, T), Response> {
        let fields = parse_form(form)?;
        let account = require_form_actor(state, headers, fields.csrf()).await?;
        Ok((account, fields))
    }

    /// Parse a console form and authenticate its actor as an administrator —
    /// the admin-gated sibling of [`account_form_actor`].
    async fn admin_form_actor<T: AccountForm>(
        state: &AppState,
        headers: &axum::http::HeaderMap,
        form: Result<axum::Form<T>, axum::extract::rejection::FormRejection>,
    ) -> Result<(String, T), Response> {
        let fields = parse_form(form)?;
        let account = require_admin_form_actor(state, headers, fields.csrf()).await?;
        Ok((account, fields))
    }

    async fn account_label_actor(
        state: &AppState,
        headers: &axum::http::HeaderMap,
        form: Result<axum::Form<AccountLabelForm>, axum::extract::rejection::FormRejection>,
    ) -> Result<(String, String), Response> {
        let (account, form) = account_form_actor(state, headers, form).await?;
        if let Some(error) = label_validation_error(&form.label) {
            return Err(account_result(
                state,
                account,
                headers,
                AccountResult::message(StatusCode::BAD_REQUEST, error),
            )
            .await);
        }
        Ok((account, form.label))
    }

    struct AccountResult {
        status: StatusCode,
        message: String,
        secret: Option<String>,
        secret_kind: &'static str,
    }

    impl AccountResult {
        fn message(status: StatusCode, message: impl Into<String>) -> Self {
            Self {
                status,
                message: message.into(),
                secret: None,
                secret_kind: "",
            }
        }

        fn issued(
            status: StatusCode,
            message: impl Into<String>,
            secret: String,
            secret_kind: &'static str,
        ) -> Self {
            Self {
                status,
                message: message.into(),
                secret: Some(secret),
                secret_kind,
            }
        }
    }

    async fn account_result(
        state: &AppState,
        account: String,
        headers: &axum::http::HeaderMap,
        result: AccountResult,
    ) -> Response {
        let csrf = session_token(headers, state.secure_cookies)
            .map(|session| state.csrf_token(&session))
            .unwrap_or_default();
        match account_build(
            state,
            account,
            csrf,
            Some(result.message),
            result.status.is_success(),
            result.secret,
            result.secret_kind,
        )
        .await
        {
            Ok(view) => {
                let mut response = render_private(view);
                *response.status_mut() = result.status;
                response
            }
            Err(response) => response,
        }
    }

    struct AccountDeleteMessages {
        success: &'static str,
        missing: &'static str,
        operation: &'static str,
    }

    /// The shared body of the "revoke one owned credential by id" console
    /// handlers: authenticate the form actor, run the delete, and render the
    /// outcome with the per-endpoint messages. `delete` is a boxed future so
    /// the two async db fns fit one signature.
    #[allow(clippy::type_complexity)] // HRTB boxed future — the only shape that fits two async db fns
    async fn console_revoke_owned(
        state: &AppState,
        headers: &axum::http::HeaderMap,
        form: Result<axum::Form<AccountDeleteForm>, axum::extract::rejection::FormRejection>,
        id: i64,
        delete: for<'a> fn(
            &'a sqlx::PgPool,
            &'a str,
            i64,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<bool, crate::db::DbError>> + Send + 'a>,
        >,
        messages: AccountDeleteMessages,
    ) -> Response {
        let (account, _) = match account_form_actor(state, headers, form).await {
            Ok(account) => account,
            Err(response) => return response,
        };
        let result = delete(pool_of(state), &account, id).await;
        account_delete_result(state, account, headers, result, messages).await
    }

    struct AccountIssueMessages {
        success: &'static str,
        secret_kind: &'static str,
        cap_reached: &'static str,
        operation: &'static str,
    }

    async fn account_issue_result(
        state: &AppState,
        account: String,
        headers: &axum::http::HeaderMap,
        result: Result<String, crate::db::DbError>,
        messages: AccountIssueMessages,
    ) -> Response {
        match result {
            Ok(secret) => {
                account_result(
                    state,
                    account,
                    headers,
                    AccountResult::issued(
                        StatusCode::CREATED,
                        messages.success,
                        secret,
                        messages.secret_kind,
                    ),
                )
                .await
            }
            Err(crate::db::DbError::TooManyCredentials) => {
                account_result(
                    state,
                    account,
                    headers,
                    AccountResult::message(StatusCode::CONFLICT, messages.cap_reached),
                )
                .await
            }
            Err(error) => super::device::admin_db_error(messages.operation, error),
        }
    }

    async fn account_delete_result(
        state: &AppState,
        account: String,
        headers: &axum::http::HeaderMap,
        result: Result<bool, crate::db::DbError>,
        messages: AccountDeleteMessages,
    ) -> Response {
        match result {
            Ok(true) => {
                account_result(
                    state,
                    account,
                    headers,
                    AccountResult::message(StatusCode::OK, messages.success),
                )
                .await
            }
            Ok(false) => {
                account_result(
                    state,
                    account,
                    headers,
                    AccountResult::message(StatusCode::NOT_FOUND, messages.missing),
                )
                .await
            }
            Err(error) => super::device::admin_db_error(messages.operation, error),
        }
    }

    pub async fn console_create_app_password(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<AccountLabelForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let (account, label) = match account_label_actor(&state, &headers, form).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        let result =
            crate::db::issue_app_password_for_account(pool_of(&state), &account, &label).await;
        account_issue_result(
            &state,
            account,
            &headers,
            result,
            AccountIssueMessages {
                success: "App password created. Copy it now; it cannot be shown again.",
                secret_kind: "App password",
                cap_reached: "Too many app passwords. Revoke one before creating another.",
                operation: "app-password creation",
            },
        )
        .await
    }

    pub async fn console_change_password(
        State(state): State<Arc<AppState>>,
        _rate_limited: RateLimited,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<AccountPasswordForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let (account, form) = match account_form_actor(&state, &headers, form).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        if let Some(detail) = (!form.current_password.is_empty())
            .then(|| password_input_error(&form.current_password))
            .flatten()
            .or_else(|| password_input_error(&form.new_password))
        {
            return account_result(
                &state,
                account,
                &headers,
                AccountResult::message(StatusCode::BAD_REQUEST, detail),
            )
            .await;
        }
        if form.new_password != form.confirm_password {
            return account_result(
                &state,
                account,
                &headers,
                AccountResult::message(
                    StatusCode::BAD_REQUEST,
                    "The new password and confirmation do not match.",
                ),
            )
            .await;
        }
        let adding_first_password = form.current_password.is_empty();
        let result = if adding_first_password {
            crate::db::set_local_password(pool_of(&state), &account, &form.new_password).await
        } else {
            crate::db::change_local_password(
                pool_of(&state),
                &account,
                &form.current_password,
                &form.new_password,
            )
            .await
        };
        match result {
            Ok(()) => {
                account_result(
                    &state,
                    account,
                    &headers,
                    AccountResult::message(
                        StatusCode::OK,
                        if adding_first_password {
                            "Local password added."
                        } else {
                            "Primary password changed."
                        },
                    ),
                )
                .await
            }
            Err(crate::db::DbError::BadCredentials) => {
                account_result(
                    &state,
                    account,
                    &headers,
                    AccountResult::message(
                        StatusCode::UNAUTHORIZED,
                        "The current password is incorrect.",
                    ),
                )
                .await
            }
            Err(crate::db::DbError::LocalPasswordExists) => account_result(
                &state,
                account,
                &headers,
                AccountResult::message(
                    StatusCode::CONFLICT,
                    "This account already has a primary password. Enter it to rotate the password.",
                ),
            )
            .await,
            Err(error) => super::device::admin_db_error("password rotation", error),
        }
    }

    pub async fn console_revoke_app_password(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        Path(id): Path<i64>,
        form: Result<axum::Form<AccountDeleteForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        console_revoke_owned(
            &state,
            &headers,
            form,
            id,
            |pool, account, id| Box::pin(crate::db::revoke_credential(pool, account, id)),
            AccountDeleteMessages {
                success: "App password revoked.",
                missing: "No revocable app password with that identifier.",
                operation: "app-password revocation",
            },
        )
        .await
    }

    pub async fn console_create_api_token(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<AccountTokenForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let (account, form) = match account_form_actor(&state, &headers, form).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        if let Some(error) = label_validation_error(&form.label) {
            return account_result(
                &state,
                account,
                &headers,
                AccountResult::message(StatusCode::BAD_REQUEST, error),
            )
            .await;
        }
        let scopes = [
            form.scope_read
                .is_some()
                .then_some(crate::identity::ApiTokenScope::Read),
            form.scope_write
                .is_some()
                .then_some(crate::identity::ApiTokenScope::Write),
            form.scope_administrator
                .is_some()
                .then_some(crate::identity::ApiTokenScope::Administrator),
            form.scope_irc
                .is_some()
                .then_some(crate::identity::ApiTokenScope::Irc),
        ]
        .into_iter()
        .flatten();
        let Some(scopes) = crate::identity::ApiTokenScopes::new(scopes) else {
            return account_result(
                &state,
                account,
                &headers,
                AccountResult::message(StatusCode::BAD_REQUEST, "Choose at least one token scope."),
            )
            .await;
        };
        let Some(lifetime) = crate::identity::ApiTokenLifetimeDays::new(form.expires_in_days)
        else {
            return account_result(
                &state,
                account,
                &headers,
                AccountResult::message(
                    StatusCode::BAD_REQUEST,
                    "Token lifetime must be between 1 and 365 days.",
                ),
            )
            .await;
        };
        let result = crate::db::issue_scoped_api_token(
            pool_of(&state),
            &account,
            &form.label,
            scopes,
            lifetime,
        )
        .await;
        account_issue_result(
            &state,
            account,
            &headers,
            result,
            AccountIssueMessages {
                success: "Personal access token created. Copy it now; it cannot be shown again.",
                secret_kind: "Personal access token",
                cap_reached: "Too many personal access tokens. Revoke one before creating another.",
                operation: "token creation",
            },
        )
        .await
    }

    pub async fn console_revoke_api_token(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        Path(id): Path<i64>,
        form: Result<axum::Form<AccountDeleteForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        console_revoke_owned(
            &state,
            &headers,
            form,
            id,
            |pool, account, id| Box::pin(crate::db::delete_api_token(pool, account, id)),
            AccountDeleteMessages {
                success: "Personal access token revoked.",
                missing: "No personal access token with that identifier.",
                operation: "token revocation",
            },
        )
        .await
    }

    pub async fn console_unlink_identity(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        Path(id): Path<i64>,
        form: Result<axum::Form<AccountDeleteForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let (account, _) = match account_form_actor(&state, &headers, form).await {
            Ok(account) => account,
            Err(response) => return response,
        };
        match crate::db::unlink_oidc_identity(pool_of(&state), &account, id).await {
            Ok(crate::db::UnlinkIdentityOutcome::Unlinked) => {
                let session_still_valid = match session_token(&headers, state.secure_cookies) {
                    Some(token) => {
                        crate::db::session_account(pool_of(&state), &token)
                            .await
                            .map_err(|error| {
                                super::device::admin_db_error("session refresh", error)
                            })
                    }
                    None => Ok(None),
                };
                match session_still_valid {
                    Ok(Some(_)) => {
                        account_result(
                            &state,
                            account,
                            &headers,
                            AccountResult::message(
                                StatusCode::OK,
                                "Login identity unlinked.",
                            ),
                        )
                        .await
                    }
                    Ok(None) => {
                        let mut response = Redirect::to("/login").into_response();
                        response.headers_mut().insert(
                            header::SET_COOKIE,
                            clear_session_cookie(state.secure_cookies)
                                .parse()
                                .expect("session clear cookie is valid"),
                        );
                        response
                    }
                    Err(response) => response,
                }
            }
            Ok(crate::db::UnlinkIdentityOutcome::LastLoginMethod) => account_result(
                &state,
                account,
                &headers,
                AccountResult::message(
                    StatusCode::CONFLICT,
                    "This is your last login method. Add a local password or link another provider before removing it.",
                ),
            )
            .await,
            Ok(crate::db::UnlinkIdentityOutcome::NotFound) => {
                account_result(
                    &state,
                    account,
                    &headers,
                    AccountResult::message(
                        StatusCode::NOT_FOUND,
                        "No linked identity with that identifier.",
                    ),
                )
                .await
            }
            Err(error) => super::device::admin_db_error("identity unlink", error),
        }
    }

    struct ChannelAccessView {
        account: String,
        flags: String,
        auto_op: bool,
        auto_voice: bool,
    }

    struct OwnedChannelView {
        name: String,
        founder: String,
        keeptopic: bool,
        topic: String,
        topic_setter: String,
        mlock: String,
        access: Vec<ChannelAccessView>,
    }

    #[derive(Template)]
    #[template(path = "console_channels.html")]
    struct ConsoleChannels {
        shell: ConsoleShell,
        channels: Vec<OwnedChannelView>,
        error: Option<String>,
    }

    async fn console_channels_build(
        state: &AppState,
        account: String,
        csrf: String,
        error: Option<String>,
    ) -> Result<ConsoleChannels, Response> {
        let channels = crate::db::list_owned_channels(pool_of(state), &account)
            .await
            .map_err(|error| super::device::admin_db_error("owned channel list", error))?
            .into_iter()
            .map(|channel| OwnedChannelView {
                name: channel.name,
                founder: channel.founder,
                keeptopic: channel.keeptopic,
                topic: channel.topic.unwrap_or_default(),
                topic_setter: channel
                    .topic_setter
                    .unwrap_or_else(|| "No retained topic".into()),
                mlock: channel.mlock.unwrap_or_default(),
                access: channel
                    .access
                    .into_iter()
                    .map(|entry| ChannelAccessView {
                        auto_op: entry.flags.contains('o'),
                        auto_voice: entry.flags.contains('v'),
                        account: entry.account,
                        flags: entry.flags,
                    })
                    .collect(),
            })
            .collect();
        Ok(ConsoleChannels {
            shell: console_shell(state, account, csrf, "channels"),
            channels,
            error,
        })
    }

    pub async fn console_channels(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
    ) -> Response {
        let (account, csrf) = match page_actor(&state, &headers, false).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        match console_channels_build(&state, account, csrf, None).await {
            Ok(view) => render_private(view),
            Err(response) => response,
        }
    }

    #[derive(Deserialize)]
    pub struct ChannelTopicForm {
        csrf: String,
        channel: String,
        #[serde(default)]
        topic: String,
    }

    #[derive(Deserialize)]
    pub struct ChannelRegisterForm {
        csrf: String,
        channel: String,
    }

    #[derive(Deserialize)]
    pub struct ChannelKeeptopicForm {
        csrf: String,
        channel: String,
        enabled: String,
    }

    #[derive(Deserialize)]
    pub struct ChannelMlockForm {
        csrf: String,
        channel: String,
        #[serde(default)]
        mlock: String,
    }

    #[derive(Deserialize)]
    pub struct ChannelAccessForm {
        csrf: String,
        channel: String,
        account: String,
        #[serde(default)]
        auto_op: Option<String>,
        #[serde(default)]
        auto_voice: Option<String>,
    }

    #[derive(Deserialize)]
    pub struct ChannelAccessDeleteForm {
        csrf: String,
        channel: String,
        account: String,
    }

    #[derive(Deserialize)]
    pub struct ChannelFounderForm {
        csrf: String,
        channel: String,
        account: String,
    }

    #[derive(Deserialize)]
    pub struct OwnedChannelDropForm {
        csrf: String,
        channel: String,
    }

    async fn run_owned_channel_form(
        state: &AppState,
        headers: &axum::http::HeaderMap,
        csrf: &str,
        channel: String,
        mutation: crate::core::ChannelMutation,
    ) -> Response {
        let account = match require_form_actor(state, headers, csrf).await {
            Ok(account) => account,
            Err(response) => return response,
        };
        let request = crate::core::AdminRequest::MutateOwnedChannel {
            channel,
            actor: account.clone(),
            mutation,
        };
        match core_action(state, request).await {
            Ok(_) => Redirect::to("/console/channels").into_response(),
            Err(message) => {
                let csrf = session_token(headers, state.secure_cookies)
                    .map(|session| state.csrf_token(&session))
                    .unwrap_or_default();
                match console_channels_build(state, account, csrf, Some(message)).await {
                    Ok(view) => render_private(view),
                    Err(response) => response,
                }
            }
        }
    }

    pub async fn console_channel_topic(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        FormBody(form): FormBody<ChannelTopicForm>,
    ) -> Response {
        let topic = (!form.topic.trim().is_empty()).then_some(form.topic);
        run_owned_channel_form(
            &state,
            &headers,
            &form.csrf,
            form.channel,
            crate::core::ChannelMutation::SetTopic { topic },
        )
        .await
    }

    pub async fn console_channel_register(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        FormBody(form): FormBody<ChannelRegisterForm>,
    ) -> Response {
        let account = match require_form_actor(&state, &headers, &form.csrf).await {
            Ok(account) => account,
            Err(response) => return response,
        };
        let request = crate::core::AdminRequest::RegisterOwnedChannel {
            channel: form.channel,
            actor: account.clone(),
        };
        match core_action(&state, request).await {
            Ok(_) => Redirect::to("/console/channels").into_response(),
            Err(message) => {
                match console_channels_build(&state, account, form.csrf, Some(message)).await {
                    Ok(view) => render_private(view),
                    Err(response) => response,
                }
            }
        }
    }

    pub async fn console_channel_keeptopic(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        FormBody(form): FormBody<ChannelKeeptopicForm>,
    ) -> Response {
        let enabled = match form.enabled.as_str() {
            "on" => true,
            "off" => false,
            _ => {
                return problem(StatusCode::BAD_REQUEST, "Invalid KEEPTOPIC value", None);
            }
        };
        run_owned_channel_form(
            &state,
            &headers,
            &form.csrf,
            form.channel,
            crate::core::ChannelMutation::SetKeeptopic { enabled },
        )
        .await
    }

    pub async fn console_channel_mlock(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        FormBody(form): FormBody<ChannelMlockForm>,
    ) -> Response {
        let mlock = (!form.mlock.trim().is_empty()).then_some(form.mlock);
        run_owned_channel_form(
            &state,
            &headers,
            &form.csrf,
            form.channel,
            crate::core::ChannelMutation::SetMlock { mlock },
        )
        .await
    }

    pub async fn console_channel_access(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        FormBody(form): FormBody<ChannelAccessForm>,
    ) -> Response {
        let mut flags = String::new();
        if form.auto_op.is_some() {
            flags.push('o');
        }
        if form.auto_voice.is_some() {
            flags.push('v');
        }
        run_owned_channel_form(
            &state,
            &headers,
            &form.csrf,
            form.channel,
            crate::core::ChannelMutation::SetAccess {
                account: form.account,
                flags: Some(flags),
            },
        )
        .await
    }

    pub async fn console_channel_access_delete(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        FormBody(form): FormBody<ChannelAccessDeleteForm>,
    ) -> Response {
        run_owned_channel_form(
            &state,
            &headers,
            &form.csrf,
            form.channel,
            crate::core::ChannelMutation::SetAccess {
                account: form.account,
                flags: None,
            },
        )
        .await
    }

    pub async fn console_channel_founder(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        FormBody(form): FormBody<ChannelFounderForm>,
    ) -> Response {
        run_owned_channel_form(
            &state,
            &headers,
            &form.csrf,
            form.channel,
            crate::core::ChannelMutation::TransferFounder {
                account: form.account,
            },
        )
        .await
    }

    pub async fn console_channel_drop(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        FormBody(form): FormBody<OwnedChannelDropForm>,
    ) -> Response {
        run_owned_channel_form(
            &state,
            &headers,
            &form.csrf,
            form.channel,
            crate::core::ChannelMutation::Drop,
        )
        .await
    }

    struct AuditRow {
        id: i64,
        at: String,
        actor: String,
        action: String,
        target: String,
        detail: String,
    }

    impl From<crate::db::AuditLogRow> for AuditRow {
        fn from(entry: crate::db::AuditLogRow) -> Self {
            Self {
                id: entry.id,
                at: entry.created_at,
                actor: entry.actor,
                action: entry.action,
                target: entry.target,
                detail: entry.detail,
            }
        }
    }

    #[derive(Template)]
    #[template(path = "console.html")]
    struct Console {
        // Shared console-shell fields (see `console_base.html`).
        shell: ConsoleShell,
        server_name: String,
        network_name: String,
        version: String,
        stat_accounts: i64,
        stat_channels: i64,
        stat_server_bans: i64,
        live_connections: u64,
        live_upstreams: String,
        live_traffic: String,
        live_errors: u64,
        accounts: Vec<crate::db::AccountDirectoryRow>,
        channels: Vec<crate::db::RegisteredChannelDirectoryRow>,
        bans: Vec<crate::db::ServerBanDirectoryRow>,
        audit: Vec<AuditRow>,
    }

    #[derive(Template)]
    #[template(path = "console_accounts.html")]
    struct ConsoleAccounts {
        shell: ConsoleShell,
        entries: Vec<crate::db::AccountDirectoryRow>,
        invitations: Vec<crate::db::AccountInvitationRow>,
        invitation_before_id: Option<i64>,
        invitation_next_before_id: Option<i64>,
        name: String,
        limit: usize,
        has_filter: bool,
        has_cursor: bool,
        next_before_id: Option<i64>,
        outcome: Option<String>,
        success: bool,
        invitation_url: Option<String>,
    }

    #[derive(Template)]
    #[template(path = "console_admin_channels.html")]
    struct ConsoleAdminChannels {
        shell: ConsoleShell,
        entries: Vec<crate::db::RegisteredChannelDirectoryRow>,
        name: String,
        founder: String,
        limit: usize,
        has_filters: bool,
        has_cursor: bool,
        next_before_id: Option<i64>,
        error: Option<String>,
    }

    /// One row of the admin fleet view: a network of any account with its
    /// live driver state.
    struct ConsoleAdminNetworkView {
        owner: String,
        name: String,
        kind: String,
        addr: String,
        tls: bool,
        enabled: bool,
        connected: bool,
        state: String,
        attached_clients: u64,
        errors: u64,
        last_error: Option<String>,
    }

    #[derive(Template)]
    #[template(path = "console_admin_networks.html")]
    struct ConsoleAdminNetworks {
        shell: ConsoleShell,
        networks: Vec<ConsoleAdminNetworkView>,
    }

    #[derive(Template)]
    #[template(path = "console_bans.html")]
    struct ConsoleServerBans {
        shell: ConsoleShell,
        entries: Vec<crate::db::ServerBanDirectoryRow>,
        kind: String,
        mask: String,
        limit: usize,
        has_filters: bool,
        has_cursor: bool,
        next_before_id: Option<i64>,
        error: Option<String>,
    }

    #[derive(Template)]
    #[template(path = "console_audit.html")]
    struct ConsoleAudit {
        shell: ConsoleShell,
        entries: Vec<AuditRow>,
        actor: String,
        action: String,
        target: String,
        limit: usize,
        has_filters: bool,
        has_cursor: bool,
        next_before_id: Option<i64>,
    }

    /// Assemble the bounded admin overview. Callers have already admin-gated
    /// the request.
    async fn console_build(
        state: &AppState,
        account: String,
        csrf: String,
    ) -> Result<Console, Response> {
        let pool = pool_of(state);
        let (stat_accounts, stat_channels, stat_server_bans) = crate::db::server_stats(pool)
            .await
            .map_err(|e| super::device::admin_db_error("server stats", e))?;
        let accounts = crate::db::query_account_directory(
            pool,
            crate::db::AccountDirectoryFilter {
                before_id: None,
                exact_name: None,
                page_size: crate::db::AccountDirectoryPageSize::new(10)
                    .expect("ten is a valid account preview size"),
            },
        )
        .await
        .map_err(|e| super::device::admin_db_error("account directory", e))?
        .entries;
        let channels = crate::db::query_registered_channel_directory(
            pool,
            crate::db::RegisteredChannelDirectoryFilter {
                before_id: None,
                exact_name: None,
                exact_founder: None,
                page_size: crate::db::RegisteredChannelDirectoryPageSize::new(10)
                    .expect("ten is a valid registered-channel preview size"),
            },
        )
        .await
        .map_err(|e| super::device::admin_db_error("registered-channel directory", e))?
        .entries;
        let bans = crate::db::query_server_ban_directory(
            pool,
            crate::db::ServerBanDirectoryFilter {
                before_id: None,
                exact_kind: None,
                exact_mask: None,
                page_size: crate::db::ServerBanDirectoryPageSize::new(10)
                    .expect("ten is a valid server-ban preview size"),
            },
        )
        .await
        .map_err(|e| super::device::admin_db_error("server-ban directory", e))?
        .entries;
        let audit = crate::db::list_audit_log(
            pool,
            crate::db::AuditLogPageSize::new(10).expect("ten is a valid audit preview size"),
        )
        .await
        .map_err(|e| super::device::admin_db_error("audit log", e))?
        .into_iter()
        .map(AuditRow::from)
        .collect();
        let (networks, connected) = bnc_counts(state);
        let live = state.telemetry.snapshot(networks, connected);
        Ok(Console {
            shell: console_shell(state, account, csrf, "overview"),
            server_name: state.server_name.clone(),
            network_name: state.network_name.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            stat_accounts,
            stat_channels,
            stat_server_bans,
            live_connections: live.active_connections,
            live_upstreams: format!("{} / {}", live.bnc_connected, live.bnc_networks),
            live_traffic: format_bytes(
                live.irc_bytes_in_total
                    .saturating_add(live.irc_bytes_out_total)
                    .saturating_add(live.bnc_bytes_in_total)
                    .saturating_add(live.bnc_bytes_out_total),
            ),
            live_errors: live.errors.values().sum(),
            accounts,
            channels,
            bans,
            audit,
        })
    }

    struct TrafficBar {
        inbound_height: u64,
        outbound_height: u64,
        title: String,
    }

    struct ConnectionBar {
        irc_height: u64,
        bnc_height: u64,
        title: String,
    }

    struct UpstreamBar {
        height: u64,
        status_class: &'static str,
        title: String,
    }

    struct ErrorBar {
        height: u64,
        title: String,
    }

    struct LatencyBar {
        core_height: u64,
        database_height: u64,
        http_height: u64,
        title: String,
    }

    struct QueueBar {
        core_height: u64,
        database_height: u64,
        title: String,
    }

    struct QueueView {
        label: &'static str,
        depth: u64,
        capacity: u64,
        pressure: u64,
        mode: String,
        mode_switches: u64,
    }

    struct MonitoringWindowLink {
        label: &'static str,
        minutes: u64,
        active: bool,
    }

    #[derive(Clone, Copy)]
    enum MonitoringWindow {
        Hour,
        SixHours,
        Day,
        Week,
    }

    #[derive(Debug, Clone, Copy)]
    struct InvalidMonitoringWindow;

    impl MonitoringWindow {
        const ALL: [Self; 4] = [Self::Hour, Self::SixHours, Self::Day, Self::Week];

        fn from_query(minutes: Option<u64>) -> Result<Self, InvalidMonitoringWindow> {
            match minutes.unwrap_or(60) {
                60 => Ok(Self::Hour),
                360 => Ok(Self::SixHours),
                1_440 => Ok(Self::Day),
                super::MAX_OBSERVABILITY_MINUTES => Ok(Self::Week),
                _ => Err(InvalidMonitoringWindow),
            }
        }

        const fn minutes(self) -> u64 {
            match self {
                Self::Hour => 60,
                Self::SixHours => 360,
                Self::Day => 1_440,
                Self::Week => super::MAX_OBSERVABILITY_MINUTES,
            }
        }

        const fn label(self) -> &'static str {
            match self {
                Self::Hour => "1 hour",
                Self::SixHours => "6 hours",
                Self::Day => "24 hours",
                Self::Week => "7 days",
            }
        }
    }

    #[derive(Deserialize, Default)]
    pub struct ConsoleMonitoringQuery {
        minutes: Option<u64>,
    }

    fn invalid_monitoring_window_response() -> Response {
        problem(
            StatusCode::BAD_REQUEST,
            "Invalid monitoring window",
            Some("Choose one of 60, 360, 1,440, or 10,080 minutes."),
        )
    }

    struct ErrorView {
        kind: String,
        count: u64,
        last_seen: String,
    }

    struct MonitoringView {
        core_ready: bool,
        database_ready: bool,
        active_connections: u64,
        registered_connections: u64,
        channels: u64,
        opened_total: u64,
        rejected_total: u64,
        traffic_in: String,
        traffic_out: String,
        upstream_in: String,
        upstream_out: String,
        inbound_rate: String,
        outbound_rate: String,
        upstream_inbound_rate: String,
        upstream_outbound_rate: String,
        http_requests: u64,
        database_requests: u64,
        bnc_connected: u64,
        bnc_networks: u64,
        upstreams_ready: bool,
        upstreams_degraded: bool,
        bnc_clients: u64,
        error_total: u64,
        sendq_kills: u64,
        core_p50: String,
        core_p95: String,
        core_p99: String,
        database_p50: String,
        database_p95: String,
        database_p99: String,
        http_p50: String,
        http_p95: String,
        http_p99: String,
        traffic_bars: Vec<TrafficBar>,
        upstream_traffic_bars: Vec<TrafficBar>,
        connection_bars: Vec<ConnectionBar>,
        upstream_bars: Vec<UpstreamBar>,
        error_bars: Vec<ErrorBar>,
        latency_bars: Vec<LatencyBar>,
        queue_bars: Vec<QueueBar>,
        queues: Vec<QueueView>,
        errors: Vec<ErrorView>,
        sampled_age: String,
        history_samples: usize,
        window_label: &'static str,
        window_minutes: u64,
        window_links: Vec<MonitoringWindowLink>,
    }

    #[derive(Template)]
    #[template(path = "console_monitoring.html")]
    struct ConsoleMonitoring {
        shell: ConsoleShell,
        view: MonitoringView,
    }

    #[derive(Template)]
    #[template(path = "_monitoring_panel.html")]
    struct ConsoleMonitoringPanel {
        view: MonitoringView,
    }

    fn format_bytes(bytes: u64) -> String {
        const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
        let mut value = bytes as f64;
        let mut unit = 0;
        while value >= 1024.0 && unit < UNITS.len() - 1 {
            value /= 1024.0;
            unit += 1;
        }
        if unit == 0 {
            format!("{bytes} {}", UNITS[unit])
        } else {
            format!("{value:.1} {}", UNITS[unit])
        }
    }

    fn format_latency(micros: u64) -> String {
        if micros == u64::MAX {
            return "> 5 s".into();
        }
        if micros >= 1_000_000 {
            format!("{:.2} s", micros as f64 / 1_000_000.0)
        } else if micros >= 1_000 {
            format!("{:.1} ms", micros as f64 / 1_000.0)
        } else {
            format!("{micros} µs")
        }
    }

    fn format_age(now_ms: u64, then_ms: u64) -> String {
        if then_ms == 0 {
            return "never".into();
        }
        let seconds = now_ms.saturating_sub(then_ms) / 1_000;
        match seconds {
            0..=59 => format!("{seconds}s ago"),
            60..=3_599 => format!("{}m ago", seconds / 60),
            3_600..=86_399 => format!("{}h ago", seconds / 3_600),
            _ => format!("{}d ago", seconds / 86_400),
        }
    }

    fn chart_height(value: u64, peak: u64) -> u64 {
        if value == 0 {
            0
        } else {
            (value.saturating_mul(100) / peak.max(1)).max(1)
        }
    }

    fn queue_pressure(queue: Option<&crate::observability::QueueSnapshot>) -> u64 {
        queue
            .filter(|queue| queue.capacity > 0)
            .map(|queue| queue.depth.saturating_mul(100) / queue.capacity)
            .unwrap_or(0)
    }

    fn snapshot_error_total(snapshot: &crate::observability::Snapshot) -> u64 {
        snapshot.errors.values().copied().sum()
    }

    fn traffic_history_bars(
        history: &[crate::observability::Snapshot],
        now_ms: u64,
        inbound: impl Fn(&crate::observability::Snapshot) -> u64,
        outbound: impl Fn(&crate::observability::Snapshot) -> u64,
        inbound_label: &str,
        outbound_label: &str,
    ) -> Vec<TrafficBar> {
        let deltas: Vec<(u64, u64, u64)> = history
            .windows(2)
            .map(|pair| {
                (
                    inbound(&pair[1]).saturating_sub(inbound(&pair[0])),
                    outbound(&pair[1]).saturating_sub(outbound(&pair[0])),
                    pair[1].sampled_at_ms,
                )
            })
            .collect();
        let peak = deltas
            .iter()
            .map(|(inbound, outbound, _)| inbound.max(outbound))
            .copied()
            .max()
            .unwrap_or(1)
            .max(1);
        deltas
            .into_iter()
            .map(|(inbound, outbound, sampled_at)| TrafficBar {
                inbound_height: chart_height(inbound, peak),
                outbound_height: chart_height(outbound, peak),
                title: format!(
                    "{} {inbound_label} · {} {outbound_label} · {}",
                    format_bytes(inbound),
                    format_bytes(outbound),
                    format_age(now_ms, sampled_at)
                ),
            })
            .collect()
    }

    async fn monitoring_view(state: &AppState, window: MonitoringWindow) -> MonitoringView {
        let (networks, connected) = bnc_counts(state);
        let current = state.telemetry.snapshot(networks, connected);
        let pool = pool_of(state);
        let since_ms = current
            .sampled_at_ms
            .saturating_sub(window.minutes().saturating_mul(60_000));
        let started = Instant::now();
        let (mut history, database_ready) =
            match crate::db::list_observability_samples(pool, since_ms, current.sampled_at_ms, 60)
                .await
            {
                Ok(history) => (history, true),
                Err(error) => {
                    state
                        .telemetry
                        .record_error(crate::observability::ErrorKind::Database);
                    eprintln!("monitoring console history query failed: {error}");
                    (Vec::new(), false)
                }
            };
        state.telemetry.record_database_request(started.elapsed());
        if history
            .last()
            .is_some_and(|snapshot| snapshot.sampled_at_ms == current.sampled_at_ms)
        {
            history.pop();
        }
        history.push(current.clone());

        let elapsed_seconds = history
            .first()
            .map(|first| current.sampled_at_ms.saturating_sub(first.sampled_at_ms) / 1_000)
            .unwrap_or(0)
            .max(1);
        let first = history.first().unwrap_or(&current);
        let inbound_rate = current
            .irc_bytes_in_total
            .saturating_sub(first.irc_bytes_in_total)
            / elapsed_seconds;
        let outbound_rate = current
            .irc_bytes_out_total
            .saturating_sub(first.irc_bytes_out_total)
            / elapsed_seconds;
        let upstream_inbound_rate = current
            .bnc_bytes_in_total
            .saturating_sub(first.bnc_bytes_in_total)
            / elapsed_seconds;
        let upstream_outbound_rate = current
            .bnc_bytes_out_total
            .saturating_sub(first.bnc_bytes_out_total)
            / elapsed_seconds;

        let traffic_bars = traffic_history_bars(
            &history,
            current.sampled_at_ms,
            |snapshot| snapshot.irc_bytes_in_total,
            |snapshot| snapshot.irc_bytes_out_total,
            "inbound",
            "outbound",
        );
        let upstream_traffic_bars = traffic_history_bars(
            &history,
            current.sampled_at_ms,
            |snapshot| snapshot.bnc_bytes_in_total,
            |snapshot| snapshot.bnc_bytes_out_total,
            "received",
            "sent",
        );

        let connection_history: Vec<_> = history
            .iter()
            .filter(|snapshot| snapshot.schema_version == current.schema_version)
            .collect();
        let connection_peak = connection_history
            .iter()
            .map(|snapshot| {
                snapshot
                    .active_connections
                    .max(snapshot.bnc_client_connections)
            })
            .max()
            .unwrap_or(1)
            .max(1);
        let connection_bars = connection_history
            .iter()
            .map(|snapshot| ConnectionBar {
                irc_height: chart_height(snapshot.active_connections, connection_peak),
                bnc_height: chart_height(snapshot.bnc_client_connections, connection_peak),
                title: format!(
                    "{} IRC · {} BNC · {}",
                    snapshot.active_connections,
                    snapshot.bnc_client_connections,
                    format_age(current.sampled_at_ms, snapshot.sampled_at_ms)
                ),
            })
            .collect();

        let upstream_bars = history
            .iter()
            .map(|snapshot| UpstreamBar {
                height: match std::num::NonZeroU64::new(snapshot.bnc_networks) {
                    Some(networks) => snapshot.bnc_connected.saturating_mul(100) / networks.get(),
                    None => 0,
                },
                status_class: if snapshot.bnc_networks == 0 {
                    "bar-off"
                } else if snapshot.bnc_connected == snapshot.bnc_networks {
                    "bar-ok"
                } else if snapshot.bnc_connected > 0 {
                    "bar-warn"
                } else {
                    "bar-off"
                },
                title: format!(
                    "{} of {} connected · {}",
                    snapshot.bnc_connected,
                    snapshot.bnc_networks,
                    format_age(current.sampled_at_ms, snapshot.sampled_at_ms)
                ),
            })
            .collect();

        let error_deltas: Vec<(u64, u64)> = history
            .windows(2)
            .map(|pair| {
                (
                    snapshot_error_total(&pair[1]).saturating_sub(snapshot_error_total(&pair[0])),
                    pair[1].sampled_at_ms,
                )
            })
            .collect();
        let error_peak = error_deltas
            .iter()
            .map(|(count, _)| *count)
            .max()
            .unwrap_or(1)
            .max(1);
        let error_bars = error_deltas
            .into_iter()
            .map(|(count, sampled_at)| ErrorBar {
                height: chart_height(count, error_peak),
                title: format!(
                    "{count} new errors · {}",
                    format_age(current.sampled_at_ms, sampled_at)
                ),
            })
            .collect();

        let latency_peak = history
            .iter()
            .map(|snapshot| {
                snapshot
                    .core_latency
                    .p95_us
                    .max(snapshot.database_latency.p95_us)
                    .max(snapshot.http_latency.p95_us)
            })
            .max()
            .unwrap_or(1)
            .max(1);
        let latency_bars = history
            .iter()
            .map(|snapshot| LatencyBar {
                core_height: chart_height(snapshot.core_latency.p95_us, latency_peak),
                database_height: chart_height(snapshot.database_latency.p95_us, latency_peak),
                http_height: chart_height(snapshot.http_latency.p95_us, latency_peak),
                title: format!(
                    "Core {} · PostgreSQL {} · HTTP {} · {}",
                    format_latency(snapshot.core_latency.p95_us),
                    format_latency(snapshot.database_latency.p95_us),
                    format_latency(snapshot.http_latency.p95_us),
                    format_age(current.sampled_at_ms, snapshot.sampled_at_ms)
                ),
            })
            .collect();
        let queue_bars = history
            .iter()
            .map(|snapshot| {
                let core = queue_pressure(snapshot.queues.get("core"));
                let database = queue_pressure(snapshot.queues.get("db"));
                QueueBar {
                    core_height: core,
                    database_height: database,
                    title: format!(
                        "Core {core}% · PostgreSQL {database}% · {}",
                        format_age(current.sampled_at_ms, snapshot.sampled_at_ms)
                    ),
                }
            })
            .collect();
        let queues = [("core", "IRC core"), ("db", "Database worker")]
            .into_iter()
            .filter_map(|(name, label)| {
                current.queues.get(name).map(|queue| QueueView {
                    label,
                    depth: queue.depth,
                    capacity: queue.capacity,
                    pressure: queue_pressure(Some(queue)),
                    mode: queue.mode.label().to_uppercase(),
                    mode_switches: queue.mode_switches,
                })
            })
            .collect();
        let errors = current
            .errors
            .iter()
            .filter(|(_, count)| **count > 0)
            .map(|(kind, count)| ErrorView {
                kind: kind.replace('_', " "),
                count: *count,
                last_seen: format_age(
                    current.sampled_at_ms,
                    current.error_last_seen_ms.get(kind).copied().unwrap_or(0),
                ),
            })
            .collect();
        let error_total = current.errors.values().sum();
        MonitoringView {
            core_ready: state.telemetry.core_is_fresh(Duration::from_secs(45)),
            database_ready,
            active_connections: current.active_connections,
            registered_connections: current.registered_connections,
            channels: current.channels,
            opened_total: current.connections_opened_total,
            rejected_total: current.connections_rejected_total,
            traffic_in: format_bytes(current.irc_bytes_in_total),
            traffic_out: format_bytes(current.irc_bytes_out_total),
            upstream_in: format_bytes(current.bnc_bytes_in_total),
            upstream_out: format_bytes(current.bnc_bytes_out_total),
            inbound_rate: format!("{}/s", format_bytes(inbound_rate)),
            outbound_rate: format!("{}/s", format_bytes(outbound_rate)),
            upstream_inbound_rate: format!("{}/s", format_bytes(upstream_inbound_rate)),
            upstream_outbound_rate: format!("{}/s", format_bytes(upstream_outbound_rate)),
            http_requests: current.http_requests_total,
            database_requests: current.database_requests_total,
            bnc_connected: current.bnc_connected,
            bnc_networks: current.bnc_networks,
            upstreams_ready: current.bnc_networks > 0
                && current.bnc_connected == current.bnc_networks,
            upstreams_degraded: current.bnc_connected > 0
                && current.bnc_connected < current.bnc_networks,
            bnc_clients: current.bnc_client_connections,
            error_total,
            sendq_kills: current.sendq_kills_total,
            core_p50: format_latency(current.core_latency.p50_us),
            core_p95: format_latency(current.core_latency.p95_us),
            core_p99: format_latency(current.core_latency.p99_us),
            database_p50: format_latency(current.database_latency.p50_us),
            database_p95: format_latency(current.database_latency.p95_us),
            database_p99: format_latency(current.database_latency.p99_us),
            http_p50: format_latency(current.http_latency.p50_us),
            http_p95: format_latency(current.http_latency.p95_us),
            http_p99: format_latency(current.http_latency.p99_us),
            traffic_bars,
            upstream_traffic_bars,
            connection_bars,
            upstream_bars,
            error_bars,
            latency_bars,
            queue_bars,
            queues,
            errors,
            sampled_age: format_age(current.sampled_at_ms, current.sampled_at_ms),
            history_samples: history.len().saturating_sub(1),
            window_label: window.label(),
            window_minutes: window.minutes(),
            window_links: MonitoringWindow::ALL
                .into_iter()
                .map(|candidate| MonitoringWindowLink {
                    label: candidate.label(),
                    minutes: candidate.minutes(),
                    active: candidate.minutes() == window.minutes(),
                })
                .collect(),
        }
    }

    pub async fn console_monitoring(
        State(state): State<Arc<AppState>>,
        AdminPageActor { account, csrf }: AdminPageActor,
        Query(query): Query<ConsoleMonitoringQuery>,
    ) -> Response {
        let window = match MonitoringWindow::from_query(query.minutes) {
            Ok(window) => window,
            Err(InvalidMonitoringWindow) => return invalid_monitoring_window_response(),
        };
        let view = monitoring_view(&state, window).await;
        render_private(ConsoleMonitoring {
            shell: console_shell(&state, account, csrf, "monitoring"),
            view,
        })
    }

    struct AccountDirectorySubmission {
        outcome: String,
        success: bool,
        invitation_url: Option<String>,
    }

    async fn console_accounts_response(
        state: &AppState,
        account: String,
        csrf: String,
        params: super::device::AccountDirectoryQuery,
        invitation_before_id: Option<i64>,
        submission: Option<AccountDirectorySubmission>,
    ) -> Response {
        let query = match super::device::validate_account_directory_query(params, 50) {
            Ok(query) => query,
            Err(response) => return response,
        };
        let mut page =
            match crate::db::query_account_directory(pool_of(state), query.database_filter()).await
            {
                Ok(page) => page,
                Err(error) => {
                    return super::device::admin_db_error("account directory", error);
                }
            };
        if invitation_before_id.is_some_and(|id| id <= 0) {
            return problem(
                StatusCode::BAD_REQUEST,
                "Invalid invitation-directory cursor",
                Some("The invitation_before_id cursor must be a positive invitation id."),
            );
        }
        let invitation_page_size =
            crate::db::AccountInvitationPageSize::new(50).expect("fixed page size is valid");
        let invitation_page = match crate::db::list_account_invitations(
            pool_of(state),
            invitation_before_id,
            invitation_page_size,
        )
        .await
        {
            Ok(invitations) => invitations,
            Err(error) => {
                return super::device::admin_db_error("account invitation directory", error);
            }
        };
        let actor_folded = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(&account);
        for entry in &mut page.entries {
            let folded = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(&entry.name);
            entry.current = folded == actor_folded;
            entry.configured_administrator = state.configured_admin_accounts.contains(&folded);
            entry.effective_administrator = entry.administrator || entry.configured_administrator;
        }
        let name = query.name.unwrap_or_default();
        let has_cursor = query.before_id.is_some();
        let (outcome, success, invitation_url) =
            submission.map_or((None, true, None), |submission| {
                (
                    Some(submission.outcome),
                    submission.success,
                    submission.invitation_url,
                )
            });
        render_private(ConsoleAccounts {
            shell: console_shell(state, account, csrf, "accounts"),
            entries: page.entries,
            invitations: invitation_page.entries,
            invitation_before_id,
            invitation_next_before_id: invitation_page.next_before_id,
            has_filter: !name.is_empty(),
            has_cursor,
            name,
            limit: query.page_size.value(),
            next_before_id: page.next_before_id,
            outcome,
            success,
            invitation_url,
        })
    }

    pub async fn console_accounts(
        State(state): State<Arc<AppState>>,
        AdminPageActor { account, csrf }: AdminPageActor,
        Query(params): Query<ConsoleAccountsQuery>,
    ) -> Response {
        let invitation_before_id = params.invitation_before_id;
        console_accounts_response(
            &state,
            account,
            csrf,
            super::device::AccountDirectoryQuery {
                limit: params.limit,
                before_id: params.before_id,
                name: params.name,
            },
            invitation_before_id,
            None,
        )
        .await
    }

    #[derive(Default, Deserialize)]
    pub struct ConsoleAccountsQuery {
        limit: Option<usize>,
        before_id: Option<i64>,
        name: Option<String>,
        invitation_before_id: Option<i64>,
    }

    #[derive(Deserialize)]
    pub struct AccountSuspensionForm {
        csrf: String,
        suspended: bool,
    }

    pub async fn console_account_suspension(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        Path(account_id): Path<i64>,
        form: Result<axum::Form<AccountSuspensionForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let (form, actor) = match parse_admin_form(&state, &headers, form).await {
            Ok(parsed) => parsed,
            Err(response) => return response,
        };
        match mutate_account_suspension(&state, &actor, account_id, form.suspended).await {
            Ok(_message) => Redirect::to("/console/accounts").into_response(),
            Err((status, detail)) => problem(status, "Account state change failed", Some(&detail)),
        }
    }

    #[derive(Deserialize)]
    pub struct AccountAdministratorForm {
        csrf: String,
        administrator: bool,
    }

    pub async fn console_account_administrator(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        Path(account_id): Path<i64>,
        form: Result<axum::Form<AccountAdministratorForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let (form, actor) = match parse_admin_form(&state, &headers, form).await {
            Ok(parsed) => parsed,
            Err(response) => return response,
        };
        match mutate_account_administrator(&state, &actor, account_id, form.administrator).await {
            Ok(_message) => Redirect::to("/console/accounts").into_response(),
            Err((status, detail)) => problem(
                status,
                "Administrator authority change failed",
                Some(&detail),
            ),
        }
    }

    #[derive(Deserialize)]
    pub struct AccountCreateForm {
        csrf: String,
        account: String,
        password: String,
        #[serde(default)]
        contact_email: String,
        #[serde(default)]
        administrator: Option<String>,
    }

    #[derive(Deserialize)]
    pub struct AccountInvitationForm {
        csrf: String,
        account: String,
        #[serde(default)]
        contact_email: String,
        expires_in_days: u16,
        #[serde(default)]
        administrator: Option<String>,
    }

    #[derive(Deserialize)]
    pub struct AccountInvitationRevokeForm {
        csrf: String,
    }

    pub async fn console_create_account(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<AccountCreateForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let (form, actor) = match parse_admin_form(&state, &headers, form).await {
            Ok(parsed) => parsed,
            Err(response) => return response,
        };
        let contact_email =
            (!form.contact_email.trim().is_empty()).then_some(form.contact_email.trim());
        match create_account_lifecycle(
            &state,
            &actor,
            &form.account,
            &form.password,
            contact_email,
            form.administrator.as_deref() == Some("on"),
        )
        .await
        {
            Ok(_) => Redirect::to("/console/accounts").into_response(),
            Err((status, detail)) => problem(status, "Account creation failed", Some(&detail)),
        }
    }

    pub async fn console_create_invitation(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<AccountInvitationForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let (form, actor) = match parse_admin_form(&state, &headers, form).await {
            Ok(parsed) => parsed,
            Err(response) => return response,
        };
        let result = if !crate::sanitize::valid_nick(&form.account, MAX_ACCOUNT_LEN) {
            Err((
                StatusCode::BAD_REQUEST,
                "The account must be a valid IRC nickname of at most 64 bytes.".to_string(),
            ))
        } else {
            let contact_email = if form.contact_email.trim().is_empty() {
                Ok(None)
            } else {
                crate::identity::ContactEmail::parse(form.contact_email.trim())
                    .map(Some)
                    .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))
            };
            let lifetime =
                crate::identity::AccountInvitationLifetimeDays::new(form.expires_in_days).ok_or((
                    StatusCode::BAD_REQUEST,
                    "Invitation lifetime must be between 1 and 30 days.".to_string(),
                ));
            match (contact_email, lifetime) {
                (Ok(contact_email), Ok(lifetime)) => crate::db::issue_account_invitation(
                    pool_of(&state),
                    &form.account,
                    contact_email.as_ref(),
                    form.administrator.as_deref() == Some("on"),
                    lifetime,
                    &actor,
                )
                .await
                .map_err(|error| match error {
                    crate::db::DbError::DuplicateAccount(_) => (
                        StatusCode::CONFLICT,
                        "The account name already exists, is retired, or has a pending invitation."
                            .to_string(),
                    ),
                    crate::db::DbError::TooManyInvitations => {
                        (StatusCode::CONFLICT, error.to_string())
                    }
                    _ => {
                        eprintln!("account invitation issuance failed: {error}");
                        (
                            StatusCode::SERVICE_UNAVAILABLE,
                            "Invitation storage unavailable.".to_string(),
                        )
                    }
                }),
                (Err(error), _) | (_, Err(error)) => Err(error),
            }
        };
        let (status, outcome, invitation_url) = match result {
            Ok(token) => {
                let url = account_invitation_url(&state, &token);
                (
                    StatusCode::OK,
                    "Invitation issued. Copy the single-use link before leaving this page."
                        .to_string(),
                    Some(url),
                )
            }
            Err((status, detail)) => (status, detail, None),
        };
        let csrf = session_token(&headers, state.secure_cookies)
            .map(|session| state.csrf_token(&session))
            .unwrap_or_default();
        let mut response = console_accounts_response(
            &state,
            actor,
            csrf,
            super::device::AccountDirectoryQuery::default(),
            None,
            Some(AccountDirectorySubmission {
                outcome,
                success: status.is_success(),
                invitation_url,
            }),
        )
        .await;
        *response.status_mut() = status;
        response
    }

    pub async fn console_revoke_invitation(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        Path(invitation_id): Path<i64>,
        form: Result<
            axum::Form<AccountInvitationRevokeForm>,
            axum::extract::rejection::FormRejection,
        >,
    ) -> Response {
        let (_form, actor) = match parse_admin_form(&state, &headers, form).await {
            Ok(parsed) => parsed,
            Err(response) => return response,
        };
        match crate::db::revoke_account_invitation(pool_of(&state), invitation_id, &actor).await {
            Ok(true) => Redirect::to("/console/accounts").into_response(),
            Ok(false) => problem(StatusCode::NOT_FOUND, "Invitation unavailable", None),
            Err(error) => super::device::admin_db_error("account invitation revocation", error),
        }
    }

    pub async fn console_delete_account(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        Path(account_id): Path<i64>,
        form: Result<
            axum::Form<AccountPermanentDeleteForm>,
            axum::extract::rejection::FormRejection,
        >,
    ) -> Response {
        let (form, actor) = match parse_admin_form(&state, &headers, form).await {
            Ok(parsed) => parsed,
            Err(response) => return response,
        };
        let target = match crate::db::account_name_by_id(pool_of(&state), account_id).await {
            Ok(Some(target)) => target,
            Ok(None) => return problem(StatusCode::NOT_FOUND, "No such account", None),
            Err(error) => {
                return super::device::admin_db_error("account deletion target", error);
            }
        };
        if form.confirmation != target {
            return problem(
                StatusCode::BAD_REQUEST,
                "Account confirmation does not match",
                Some("Supply the exact display-cased account name."),
            );
        }
        match delete_account_lifecycle(&state, &actor, account_id, false).await {
            Ok(_) => Redirect::to("/console/accounts").into_response(),
            Err((status, detail)) => problem(status, "Account deletion failed", Some(&detail)),
        }
    }

    async fn console_admin_channels_build(
        state: &AppState,
        account: String,
        csrf: String,
        query: super::device::ValidatedRegisteredChannelDirectoryQuery,
        error: Option<String>,
    ) -> Result<ConsoleAdminChannels, Response> {
        let page =
            crate::db::query_registered_channel_directory(pool_of(state), query.database_filter())
                .await
                .map_err(|error| {
                    super::device::admin_db_error("registered-channel directory", error)
                })?;
        let name = query.name.unwrap_or_default();
        let founder = query.founder.unwrap_or_default();
        Ok(ConsoleAdminChannels {
            shell: console_shell(state, account, csrf, "admin-channels"),
            entries: page.entries,
            has_filters: !name.is_empty() || !founder.is_empty(),
            has_cursor: query.before_id.is_some(),
            name,
            founder,
            limit: query.page_size.value(),
            next_before_id: page.next_before_id,
            error,
        })
    }

    pub async fn console_admin_channels(
        State(state): State<Arc<AppState>>,
        AdminPageActor { account, csrf }: AdminPageActor,
        Query(params): Query<super::device::RegisteredChannelDirectoryQuery>,
    ) -> Response {
        let query = match super::device::validate_registered_channel_directory_query(params, 50) {
            Ok(query) => query,
            Err(response) => return response,
        };
        match console_admin_channels_build(&state, account, csrf, query, None).await {
            Ok(view) => render_private(view),
            Err(response) => response,
        }
    }

    /// The fleet-wide BNC view: every account's networks with live driver
    /// state, so an operator can spot (and stop) a single misbehaving
    /// upstream without suspending the whole account.
    pub async fn console_admin_networks(
        State(state): State<Arc<AppState>>,
        AdminPageActor { account, csrf }: AdminPageActor,
    ) -> Response {
        let rows = match crate::db::list_bnc_network_inventory(pool_of(&state)).await {
            Ok(rows) => rows,
            Err(error) => return super::device::admin_db_error("network inventory", error),
        };
        let networks = rows
            .into_iter()
            .map(|row| {
                let runtime = state
                    .bnc_registry
                    .as_ref()
                    .and_then(|r| r.get_owned(&row.owner, &row.network.name))
                    .map(|h| h.runtime_snapshot());
                let connected = runtime.as_ref().is_some_and(|runtime| {
                    runtime.lifecycle == crate::bouncer::NetworkLifecycle::Connected
                });
                let state_label = if row.network.enabled {
                    runtime
                        .as_ref()
                        .map(|runtime| runtime.lifecycle.as_str().replace('_', " "))
                        .unwrap_or_else(|| "not running".into())
                } else {
                    "disabled".into()
                };
                ConsoleAdminNetworkView {
                    owner: row.owner,
                    name: row.network.name,
                    kind: row.network.kind.as_db_str().to_string(),
                    addr: row.network.addr,
                    tls: row.network.tls,
                    enabled: row.network.enabled,
                    connected,
                    state: state_label,
                    attached_clients: runtime
                        .as_ref()
                        .map_or(0, |runtime| runtime.attached_clients),
                    errors: runtime.as_ref().map_or(0, |runtime| runtime.errors),
                    last_error: runtime
                        .as_ref()
                        .and_then(|runtime| runtime.last_error)
                        .map(|failure| failure.summary().to_string()),
                }
            })
            .collect();
        render_private(ConsoleAdminNetworks {
            shell: console_shell(&state, account, csrf, "admin-networks"),
            networks,
        })
    }

    /// Enable or disable one network of any account (admin lever for a
    /// misbehaving upstream). Privileged and audited as such.
    pub async fn console_admin_network_toggle(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        Path((owner, name)): Path<(String, String)>,
        form: Result<axum::Form<ToggleFields>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let registry = require_registry!(state);
        let (admin, f) = match admin_form_actor(&state, &headers, form).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        let Some(enabled) = toggle_target(&f.enabled) else {
            return invalid_toggle_response();
        };
        // The admin is the actor here (the owner is only the target), and the
        // core audits every toggle — an administrator touching another
        // account's network is unmistakably attributed.
        if let Err(error) =
            set_network_enabled_core(&state, registry, &admin, &owner, &name, enabled).await
        {
            return error.into_response();
        }
        Redirect::to("/console/admin/networks").into_response()
    }

    async fn console_server_bans_build(
        state: &AppState,
        account: String,
        csrf: String,
        query: super::device::ValidatedServerBanDirectoryQuery,
        error: Option<String>,
    ) -> Result<ConsoleServerBans, Response> {
        let page = crate::db::query_server_ban_directory(pool_of(state), query.database_filter())
            .await
            .map_err(|error| super::device::admin_db_error("server-ban directory", error))?;
        let kind = query.kind.unwrap_or_default();
        let mask = query.mask.unwrap_or_default();
        Ok(ConsoleServerBans {
            shell: console_shell(state, account, csrf, "bans"),
            entries: page.entries,
            has_filters: !kind.is_empty() || !mask.is_empty(),
            has_cursor: query.before_id.is_some(),
            kind,
            mask,
            limit: query.page_size.value(),
            next_before_id: page.next_before_id,
            error,
        })
    }

    pub async fn console_server_bans(
        State(state): State<Arc<AppState>>,
        AdminPageActor { account, csrf }: AdminPageActor,
        Query(params): Query<super::device::ServerBanDirectoryQuery>,
    ) -> Response {
        let query = match super::device::validate_server_ban_directory_query(params, 50) {
            Ok(query) => query,
            Err(response) => return response,
        };
        match console_server_bans_build(&state, account, csrf, query, None).await {
            Ok(view) => render_private(view),
            Err(response) => response,
        }
    }

    pub async fn console_audit(
        State(state): State<Arc<AppState>>,
        AdminPageActor { account, csrf }: AdminPageActor,
        Query(params): Query<super::device::AuditQuery>,
    ) -> Response {
        let query = match super::device::validate_audit_query(params, 50) {
            Ok(query) => query,
            Err(response) => return response,
        };
        let page = match crate::db::query_audit_log(pool_of(&state), query.database_filter()).await
        {
            Ok(page) => page,
            Err(error) => return super::device::admin_db_error("audit log", error),
        };
        let entries = page
            .entries
            .into_iter()
            .map(|entry| AuditRow {
                id: entry.id,
                at: entry.created_at,
                actor: entry.actor,
                action: entry.action,
                target: entry.target,
                detail: entry.detail,
            })
            .collect();
        let actor = query.actor.unwrap_or_default();
        let action = query.action.unwrap_or_default();
        let target = query.target.unwrap_or_default();
        let has_cursor = query.before_id.is_some();
        render_private(ConsoleAudit {
            shell: console_shell(&state, account, csrf, "audit"),
            entries,
            has_filters: !actor.is_empty() || !action.is_empty() || !target.is_empty(),
            has_cursor,
            actor,
            action,
            target,
            limit: query.page_size.value(),
            next_before_id: page.next_before_id,
        })
    }

    pub async fn console_monitoring_panel(
        State(state): State<Arc<AppState>>,
        _admin: AdminPageActor,
        Query(query): Query<ConsoleMonitoringQuery>,
    ) -> Response {
        let window = match MonitoringWindow::from_query(query.minutes) {
            Ok(window) => window,
            Err(InvalidMonitoringWindow) => return invalid_monitoring_window_response(),
        };
        render_private(ConsoleMonitoringPanel {
            view: monitoring_view(&state, window).await,
        })
    }

    /// One BNC network in the console networks view, with its live upstream
    /// connection state resolved from the registry (not just its stored config).
    struct ConsoleNetView {
        name: String,
        kind: &'static str,
        addr: String,
        tls: bool,
        enabled: bool,
        connected: bool,
        state: String,
        attached_clients: u64,
        errors: u64,
    }

    #[derive(Template)]
    #[template(path = "console_configuration.html")]
    struct ConsoleConfiguration {
        shell: ConsoleShell,
        revision: i64,
        settings: crate::config::ManagedConfig,
        updated_by: String,
        updated_at: String,
        motd: String,
        bnc_addr: String,
        bound_bnc_addr: Option<std::net::SocketAddr>,
        max_connections_per_ip: String,
        command_burst: String,
        auth_rate_burst: String,
        api_rate_burst: String,
        administrator_api_rate_burst: String,
        registration_burst: String,
        trusted_proxies: String,
        listeners: String,
        public_url: String,
        admin_accounts: String,
        opers: Vec<String>,
        oidc_providers: Vec<OidcProviderView>,
        shared_networks: Vec<SharedNetworkView>,
        matrix_built: bool,
        discord_built: bool,
        slack_built: bool,
        http_bind: String,
        has_master_key: bool,
        master_key_count: usize,
        release_revision: String,
        outcome: Option<String>,
        success: bool,
    }

    struct OidcProviderView {
        name: String,
        issuer_url: String,
        client_id: String,
        scopes: String,
        allowed_email_domains: String,
        token_method: &'static str,
    }

    struct SharedNetworkView {
        name: String,
        owner_display: String,
        owner_value: String,
        kind: &'static str,
        addr: String,
    }

    #[derive(Deserialize)]
    pub struct ManagedConfigForm {
        csrf: String,
        revision: i64,
        server_name: String,
        network_name: String,
        description: String,
        #[serde(default)]
        motd: String,
        nicklen: usize,
        sendq: usize,
        core_queue: usize,
        max_hot_channels: usize,
        #[serde(default)]
        bnc_enabled: Option<String>,
        #[serde(default)]
        bnc_addr: String,
        #[serde(default)]
        max_connections_per_ip: String,
        #[serde(default)]
        command_burst: String,
        #[serde(default)]
        auth_rate_burst: String,
        #[serde(default)]
        api_rate_burst: String,
        #[serde(default)]
        administrator_api_rate_burst: String,
        #[serde(default)]
        registration_burst: String,
        #[serde(default)]
        trusted_proxies: String,
        #[serde(default)]
        listeners: String,
        #[serde(default)]
        public_url: String,
        #[serde(default)]
        secure_cookies: Option<String>,
        #[serde(default)]
        admin_accounts: String,
        #[serde(default)]
        registration_before_connect: Option<String>,
        #[serde(default)]
        registration_require_email: Option<String>,
        #[serde(default)]
        observability_enabled: Option<String>,
        observability_sample_interval_seconds: u64,
        observability_retention_hours: u64,
        storage_history_retention_days: u64,
        storage_audit_retention_days: u64,
    }

    fn optional_number(value: &str, field: &str) -> Result<Option<usize>, String> {
        let value = value.trim();
        if value.is_empty() {
            return Ok(None);
        }
        value
            .parse::<usize>()
            .map(Some)
            .map_err(|_| format!("{field} must be a positive whole number or blank"))
    }

    fn optional_number_display(value: Option<usize>) -> String {
        value.map(|number| number.to_string()).unwrap_or_default()
    }

    fn parse_listeners(value: &str) -> Result<Vec<crate::config::ListenerConfig>, String> {
        value
            .lines()
            .enumerate()
            .filter(|(_, line)| !line.trim().is_empty())
            .map(|(index, line)| {
                let fields: Vec<_> = line.split('|').map(str::trim).collect();
                let address = fields
                    .first()
                    .ok_or_else(|| format!("Listener line {} has no address", index + 1))?
                    .parse()
                    .map_err(|_| format!("Listener line {} has an invalid address", index + 1))?;
                let mode = fields.get(1).copied().unwrap_or("plain");
                let (websocket, tls) =
                    match mode {
                        "plain" => (false, None),
                        "websocket" => (true, None),
                        "tls" => {
                            let cert = fields.get(2).filter(|field| !field.is_empty()).ok_or_else(
                                || {
                                    format!(
                                        "TLS listener line {} needs a certificate path",
                                        index + 1
                                    )
                                },
                            )?;
                            let key = fields.get(3).filter(|field| !field.is_empty()).ok_or_else(
                                || {
                                    format!(
                                        "TLS listener line {} needs a private-key path",
                                        index + 1
                                    )
                                },
                            )?;
                            (
                                false,
                                Some(crate::config::TlsConfig {
                                    cert_path: std::path::PathBuf::from(cert),
                                    key_path: std::path::PathBuf::from(key),
                                }),
                            )
                        }
                        _ => {
                            return Err(format!(
                                "Listener line {} mode must be plain, tls, or websocket",
                                index + 1
                            ));
                        }
                    };
                Ok(crate::config::ListenerConfig {
                    addr: address,
                    tls,
                    websocket,
                })
            })
            .collect()
    }

    fn display_listeners(listeners: &[crate::config::ListenerConfig]) -> String {
        listeners
            .iter()
            .map(|listener| match &listener.tls {
                Some(tls) => format!(
                    "{} | tls | {} | {}",
                    listener.addr,
                    tls.cert_path.display(),
                    tls.key_path.display()
                ),
                None if listener.websocket => format!("{} | websocket", listener.addr),
                None => format!("{} | plain", listener.addr),
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn managed_settings_from_form(
        form: &ManagedConfigForm,
    ) -> Result<crate::config::ManagedConfig, String> {
        let bnc_addr = if form.bnc_enabled.is_some() {
            Some(
                form.bnc_addr
                    .trim()
                    .parse()
                    .map_err(|_| "BNC listen address must be host:port".to_string())?,
            )
        } else {
            None
        };
        let settings = crate::config::ManagedConfig {
            server_name: form.server_name.trim().to_string(),
            network_name: form.network_name.trim().to_string(),
            description: form.description.trim().to_string(),
            motd: form.motd.lines().map(str::to_string).collect(),
            nicklen: form.nicklen,
            sendq: form.sendq,
            core_queue: form.core_queue,
            max_hot_channels: form.max_hot_channels,
            listeners: parse_listeners(&form.listeners)?,
            registration: crate::config::RegistrationConfig {
                before_connect: form.registration_before_connect.is_some(),
                require_email: form.registration_require_email.is_some(),
            },
            limits: crate::config::LimitsConfig {
                max_connections_per_ip: optional_number(
                    &form.max_connections_per_ip,
                    "Connections per IP",
                )?,
                command_burst: optional_number(&form.command_burst, "Command burst")?,
                trusted_proxies: form
                    .trusted_proxies
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .map(str::to_string)
                    .collect(),
                auth_rate_burst: optional_number(&form.auth_rate_burst, "Authentication burst")?,
                api_rate_burst: optional_number(&form.api_rate_burst, "Authenticated API burst")?,
                administrator_api_rate_burst: optional_number(
                    &form.administrator_api_rate_burst,
                    "Administrator API burst",
                )?,
                registration_burst: optional_number(
                    &form.registration_burst,
                    "Registration burst",
                )?,
            },
            observability: crate::config::ObservabilityConfig {
                enabled: form.observability_enabled.is_some(),
                sample_interval_seconds: form.observability_sample_interval_seconds,
                retention_hours: form.observability_retention_hours,
            },
            storage: crate::config::StorageConfig {
                history_retention_days: form.storage_history_retention_days,
                audit_retention_days: form.storage_audit_retention_days,
            },
            bnc_addr,
            public_url: (!form.public_url.trim().is_empty())
                .then(|| form.public_url.trim().to_string()),
            secure_cookies: form.secure_cookies.is_some(),
            admin_accounts: form
                .admin_accounts
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_string)
                .collect(),
            oidc_providers: Vec::new(),
            opers: Vec::new(),
            networks: Vec::new(),
            credentials_from_bootstrap: false,
        };
        // The scalar form never edits credential-bearing collections; preserve
        // them by the caller before validation.
        Ok(settings)
    }

    async fn render_configuration(
        state: &AppState,
        account: String,
        csrf: String,
        snapshot: crate::db::ManagedConfigSnapshot,
        outcome: Option<String>,
        success: bool,
    ) -> Response {
        let bound_bnc_addr = match &state.bnc_listener {
            Some(listener) => listener.status().await.map(|(_, bound)| bound),
            None => None,
        };
        let settings = snapshot.settings;
        let opers = settings
            .opers
            .iter()
            .map(|oper| oper.name.clone())
            .collect();
        let oidc_providers = settings
            .oidc_providers
            .iter()
            .map(|provider| OidcProviderView {
                name: provider.name.clone(),
                issuer_url: provider.issuer_url.clone(),
                client_id: provider.client_id.clone(),
                scopes: provider.scopes.join(" "),
                allowed_email_domains: provider
                    .allowed_email_domains
                    .iter()
                    .map(crate::identity::EmailDomain::as_str)
                    .collect::<Vec<_>>()
                    .join(", "),
                token_method: match provider.token_endpoint_auth_method {
                    crate::config::TokenEndpointAuthMethod::ClientSecretBasic => {
                        "client_secret_basic"
                    }
                    crate::config::TokenEndpointAuthMethod::ClientSecretPost => {
                        "client_secret_post"
                    }
                },
            })
            .collect();
        let shared_networks = settings
            .networks
            .iter()
            .map(|network| SharedNetworkView {
                name: network.name.clone(),
                owner_display: network
                    .owner
                    .clone()
                    .unwrap_or_else(|| "all accounts".into()),
                owner_value: network.owner.clone().unwrap_or_default(),
                kind: network.kind.as_db_str(),
                addr: network.addr.clone(),
            })
            .collect();
        render_private(ConsoleConfiguration {
            shell: console_shell(state, account, csrf, "configuration"),
            revision: snapshot.revision,
            updated_by: snapshot.updated_by,
            updated_at: snapshot.updated_at,
            motd: settings.motd.join("\n"),
            bnc_addr: settings
                .bnc_addr
                .map(|address| address.to_string())
                .unwrap_or_default(),
            bound_bnc_addr,
            max_connections_per_ip: optional_number_display(settings.limits.max_connections_per_ip),
            command_burst: optional_number_display(settings.limits.command_burst),
            auth_rate_burst: optional_number_display(settings.limits.auth_rate_burst),
            api_rate_burst: optional_number_display(settings.limits.api_rate_burst),
            administrator_api_rate_burst: optional_number_display(
                settings.limits.administrator_api_rate_burst,
            ),
            registration_burst: optional_number_display(settings.limits.registration_burst),
            trusted_proxies: settings.limits.trusted_proxies.join("\n"),
            listeners: display_listeners(&settings.listeners),
            public_url: settings.public_url.clone().unwrap_or_default(),
            admin_accounts: settings.admin_accounts.join("\n"),
            opers,
            oidc_providers,
            shared_networks,
            matrix_built: cfg!(feature = "matrix"),
            discord_built: cfg!(feature = "discord"),
            slack_built: cfg!(feature = "slack"),
            http_bind: state
                .http_bind
                .map(|address| address.to_string())
                .unwrap_or_else(|| "dedicated WebSocket listener only".into()),
            has_master_key: state.secret_key.is_some(),
            master_key_count: state.secret_key.as_ref().map_or(0, |keys| keys.key_count()),
            release_revision: state
                .application_release_revision
                .clone()
                .unwrap_or_else(|| "not set".into()),
            settings,
            outcome,
            success,
        })
    }

    async fn render_configuration_error(
        state: &AppState,
        account: String,
        csrf: String,
        snapshot: crate::db::ManagedConfigSnapshot,
        error: impl Into<String>,
    ) -> Response {
        render_configuration(state, account, csrf, snapshot, Some(error.into()), false).await
    }

    pub async fn console_configuration(
        State(state): State<Arc<AppState>>,
        AdminPageActor { account, csrf }: AdminPageActor,
    ) -> Response {
        let config = require_managed_config!(state);
        let snapshot = config.read().await.clone();
        render_configuration(&state, account, csrf, snapshot, None, true).await
    }

    async fn restore_bnc_listener(
        state: &AppState,
        previous: Option<std::net::SocketAddr>,
    ) -> Result<(), String> {
        let listener = state
            .bnc_listener
            .as_ref()
            .ok_or_else(|| "BNC listener controller is unavailable".to_string())?;
        match previous {
            Some(address) => {
                listener.enable(address).await.map(|_| ()).map_err(|error| {
                    format!("could not restore the previous BNC listener: {error}")
                })
            }
            None => {
                listener.stop().await;
                Ok(())
            }
        }
    }

    pub async fn console_update_configuration(
        State(state): State<Arc<AppState>>,
        AdminConfigPayload {
            form,
            account,
            csrf,
        }: AdminConfigPayload<ManagedConfigForm>,
    ) -> Response {
        let config = require_managed_config!(state);
        let mut current = config.write().await;
        if current.revision != form.revision {
            return render_configuration_error(
                &state,
                account,
                csrf,
                current.clone(),
                "Configuration changed in another session. Review the current values and submit again.",
            )
            .await;
        }
        let mut settings = match managed_settings_from_form(&form) {
            Ok(settings) => settings,
            Err(error) => {
                return render_configuration_error(&state, account, csrf, current.clone(), error)
                    .await;
            }
        };
        settings.oidc_providers = current.settings.oidc_providers.clone();
        settings.opers = current.settings.opers.clone();
        settings.networks = current.settings.networks.clone();
        settings.credentials_from_bootstrap = current.settings.credentials_from_bootstrap;
        if let Err(error) = settings.validate() {
            return render_configuration_error(
                &state,
                account,
                csrf,
                current.clone(),
                error.to_string(),
            )
            .await;
        }
        let previous_bnc = current.settings.bnc_addr;
        let bnc_changed = previous_bnc != settings.bnc_addr;
        if bnc_changed {
            let Some(listener) = &state.bnc_listener else {
                return render_configuration_error(
                    &state,
                    account,
                    csrf,
                    current.clone(),
                    "A database-backed BNC listener controller is unavailable.",
                )
                .await;
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
                return render_configuration_error(&state, account, csrf, current.clone(), error)
                    .await;
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
        let pool = pool_of(&state);
        match crate::db::save_managed_config(pool, current.revision, &settings, &account, &detail)
            .await
        {
            Ok(snapshot) => {
                *current = snapshot.clone();
                let message = if restart_required {
                    "Configuration saved. The BNC listener is live; restart the server to apply the other changed settings."
                } else {
                    "Configuration saved and applied."
                };
                drop(current);
                render_configuration(&state, account, csrf, snapshot, Some(message.into()), true)
                    .await
            }
            Err(error) => {
                let rollback = if bnc_changed {
                    restore_bnc_listener(&state, previous_bnc).await.err()
                } else {
                    None
                };
                let message = match rollback {
                    Some(rollback) => format!(
                        "Configuration was not saved: {error}. Runtime rollback also failed: {rollback}"
                    ),
                    None => format!("Configuration was not saved: {error}"),
                };
                render_configuration_error(&state, account, csrf, current.clone(), message).await
            }
        }
    }

    #[derive(Deserialize)]
    pub struct OperForm {
        csrf: String,
        name: String,
        password: String,
    }

    #[derive(Deserialize)]
    pub struct DeleteConfigItem {
        csrf: String,
        name: String,
    }

    #[derive(Deserialize)]
    pub struct OidcForm {
        csrf: String,
        name: String,
        issuer_url: String,
        client_id: String,
        client_secret: String,
        #[serde(default)]
        scopes: String,
        #[serde(default)]
        allowed_email_domains: String,
        #[serde(default)]
        end_session_endpoint: String,
        token_endpoint_auth_method: String,
    }

    #[derive(Deserialize)]
    pub struct SharedNetworkForm {
        csrf: String,
        name: String,
        #[serde(default)]
        owner: String,
        kind: String,
        #[serde(default)]
        addr: String,
        #[serde(default)]
        tls: Option<String>,
        nick: String,
        #[serde(default)]
        realname: String,
        #[serde(default)]
        autojoin: String,
        #[serde(default)]
        buffer_cap: usize,
        #[serde(default)]
        sasl_account: String,
        #[serde(default)]
        sasl_password: String,
    }

    #[derive(Deserialize)]
    pub struct DeleteSharedNetwork {
        csrf: String,
        name: String,
        owner: String,
    }

    trait AdminConfigForm {
        fn csrf(&self) -> &str;
    }

    macro_rules! impl_admin_config_form {
        ($($form:ty),+ $(,)?) => {
            $(
                impl AdminConfigForm for $form {
                    fn csrf(&self) -> &str {
                        &self.csrf
                    }
                }
            )+
        };
    }

    impl_admin_config_form!(
        ManagedConfigForm,
        OperForm,
        DeleteConfigItem,
        OidcForm,
        SharedNetworkForm,
        DeleteSharedNetwork,
    );

    pub(super) struct AdminConfigPayload<T> {
        form: T,
        account: String,
        csrf: String,
    }

    impl<T> axum::extract::FromRequest<Arc<AppState>> for AdminConfigPayload<T>
    where
        T: AdminConfigForm + Send + 'static,
        axum::Form<T>: axum::extract::FromRequest<
                Arc<AppState>,
                Rejection = axum::extract::rejection::FormRejection,
            >,
    {
        type Rejection = Response;

        async fn from_request(
            request: axum::extract::Request,
            state: &Arc<AppState>,
        ) -> Result<Self, Self::Rejection> {
            let headers = request.headers().clone();
            let form = match axum::Form::<T>::from_request(request, state).await {
                Ok(axum::Form(form)) => form,
                Err(error) => {
                    return Err(problem(
                        StatusCode::BAD_REQUEST,
                        "Invalid form",
                        Some(&error.to_string()),
                    ));
                }
            };
            let csrf = form.csrf().to_string();
            let account = require_admin_form_actor(state, &headers, &csrf).await?;
            Ok(Self {
                form,
                account,
                csrf,
            })
        }
    }

    async fn mutate_managed_config(
        state: &AppState,
        account: String,
        csrf: String,
        change: impl FnOnce(&mut crate::config::ManagedConfig) -> Result<String, String>,
    ) -> Response {
        let config = require_managed_config!(state);
        let mut current = config.write().await;
        let mut settings = current.settings.clone();
        let detail = match change(&mut settings) {
            Ok(detail) => detail,
            Err(error) => {
                return render_configuration_error(state, account, csrf, current.clone(), error)
                    .await;
            }
        };
        if let Err(error) = settings.validate() {
            return render_configuration_error(
                state,
                account,
                csrf,
                current.clone(),
                error.to_string(),
            )
            .await;
        }
        let outcome =
            format!("Configuration saved: {detail}. Restart the server to apply this change.");
        match crate::db::save_managed_config(
            pool_of(state),
            current.revision,
            &settings,
            &account,
            &format!("{detail}; restart required"),
        )
        .await
        {
            Ok(snapshot) => {
                *current = snapshot.clone();
                drop(current);
                render_configuration(state, account, csrf, snapshot, Some(outcome), true).await
            }
            Err(error) => {
                render_configuration_error(
                    state,
                    account,
                    csrf,
                    current.clone(),
                    format!("Configuration was not saved: {error}"),
                )
                .await
            }
        }
    }

    pub async fn console_add_oper(
        State(state): State<Arc<AppState>>,
        AdminConfigPayload {
            form,
            account,
            csrf,
        }: AdminConfigPayload<OperForm>,
    ) -> Response {
        let Some(key) = state.secret_key.clone() else {
            return mutate_managed_config(&state, account, csrf, |_| {
                Err("A master key is required to store operator passwords.".into())
            })
            .await;
        };
        mutate_managed_config(&state, account, csrf, move |settings| {
            let name = form.name.trim();
            if name.is_empty() || form.password.is_empty() {
                return Err("Operator name and password are required.".into());
            }
            add_managed_oper(
                settings,
                crate::config::OperConfig {
                    name: name.to_string(),
                    password: key.seal(&form.password, crate::secret::CONFIG_CONTEXT),
                },
            )
        })
        .await
    }

    pub async fn console_delete_oper(
        State(state): State<Arc<AppState>>,
        AdminConfigPayload {
            form,
            account,
            csrf,
        }: AdminConfigPayload<DeleteConfigItem>,
    ) -> Response {
        mutate_managed_config(&state, account, csrf, move |settings| {
            delete_managed_configuration_item(
                settings,
                &form.name,
                ManagedConfigurationItem {
                    credential_kind: "operator",
                    item_kind: "IRC operator",
                    items: |settings| &mut settings.opers,
                    item_name: |oper| &oper.name,
                },
            )
        })
        .await
    }

    pub async fn console_add_oidc(
        State(state): State<Arc<AppState>>,
        AdminConfigPayload {
            form,
            account,
            csrf,
        }: AdminConfigPayload<OidcForm>,
    ) -> Response {
        let Some(key) = state.secret_key.clone() else {
            return mutate_managed_config(&state, account, csrf, |_| {
                Err("A master key is required to store OpenID Connect client secrets.".into())
            })
            .await;
        };
        mutate_managed_config(&state, account, csrf, move |settings| {
            let method = match form.token_endpoint_auth_method.as_str() {
                "client_secret_basic" => crate::config::TokenEndpointAuthMethod::ClientSecretBasic,
                "client_secret_post" => crate::config::TokenEndpointAuthMethod::ClientSecretPost,
                _ => return Err("Unknown token endpoint authentication method.".into()),
            };
            let allowed_email_domains = form
                .allowed_email_domains
                .split([',', ' ', '\n'])
                .map(str::trim)
                .filter(|domain| !domain.is_empty())
                .map(crate::identity::EmailDomain::parse)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?;
            add_managed_oidc_provider(
                settings,
                crate::config::OidcProviderConfig {
                    name: form.name.trim().to_string(),
                    issuer_url: form.issuer_url.trim().to_string(),
                    client_id: form.client_id.trim().to_string(),
                    client_secret: key.seal(&form.client_secret, crate::secret::CONFIG_CONTEXT),
                    scopes: form
                        .scopes
                        .split([',', ' '])
                        .map(str::trim)
                        .filter(|scope| !scope.is_empty())
                        .map(str::to_string)
                        .collect(),
                    allowed_email_domains,
                    end_session_endpoint: (!form.end_session_endpoint.trim().is_empty())
                        .then(|| form.end_session_endpoint.trim().to_string()),
                    token_endpoint_auth_method: method,
                },
            )
        })
        .await
    }

    pub async fn console_delete_oidc(
        State(state): State<Arc<AppState>>,
        AdminConfigPayload {
            form,
            account,
            csrf,
        }: AdminConfigPayload<DeleteConfigItem>,
    ) -> Response {
        mutate_managed_config(&state, account, csrf, move |settings| {
            delete_managed_configuration_item(
                settings,
                &form.name,
                ManagedConfigurationItem {
                    credential_kind: "identity-provider",
                    item_kind: "identity provider",
                    items: |settings| &mut settings.oidc_providers,
                    item_name: |provider| &provider.name,
                },
            )
        })
        .await
    }

    pub async fn console_add_shared_network(
        State(state): State<Arc<AppState>>,
        AdminConfigPayload {
            form,
            account,
            csrf,
        }: AdminConfigPayload<SharedNetworkForm>,
    ) -> Response {
        let kind = match crate::config::NetworkKind::from_db_str(&form.kind) {
            Some(kind) => kind,
            None => {
                return mutate_managed_config(&state, account, csrf, |_| {
                    Err("Unknown network driver kind.".into())
                })
                .await;
            }
        };
        if kind.is_bridge() && !kind_feature_available(kind) {
            let feature = kind.as_db_str();
            return mutate_managed_config(&state, account, csrf, |_| {
                Err(format!(
                    "This server was not built with the {feature} feature."
                ))
            })
            .await;
        }
        let secret_needed = !form.sasl_password.is_empty()
            || (kind.account_is_secret() && !form.sasl_account.is_empty());
        let key = state.secret_key.clone();
        if secret_needed && key.is_none() {
            return mutate_managed_config(&state, account, csrf, |_| {
                Err("A master key is required to store upstream credentials.".into())
            })
            .await;
        }
        mutate_managed_config(&state, account, csrf, move |settings| {
            if settings.credentials_from_bootstrap {
                return Err(
                    "Configure a master key and restart before changing bootstrap network credentials."
                        .into(),
                );
            }
            let optional = |value: String| {
                let value = value.trim().to_string();
                (!value.is_empty()).then_some(value)
            };
            let mut sasl_account = optional(form.sasl_account);
            let mut sasl_password = optional(form.sasl_password);
            if kind.account_is_secret()
                && let Some(value) = &sasl_account
            {
                sasl_account = Some(
                    key.as_ref()
                        .expect("secret-needed check")
                        .seal(value, crate::secret::CONFIG_CONTEXT),
                );
            }
            if let Some(value) = &sasl_password {
                sasl_password = Some(
                    key.as_ref()
                        .expect("secret-needed check")
                        .seal(value, crate::secret::CONFIG_CONTEXT),
                );
            }
            let name = form.name.trim().to_string();
            settings.networks.push(crate::config::NetworkEntry {
                name: name.clone(),
                kind,
                owner: optional(form.owner),
                addr: form.addr.trim().to_string(),
                tls: form.tls.is_some(),
                nick: form.nick.trim().to_string(),
                realname: optional(form.realname),
                autojoin: form
                    .autojoin
                    .split(',')
                    .map(str::trim)
                    .filter(|channel| !channel.is_empty())
                    .map(str::to_string)
                    .collect(),
                buffer_cap: if form.buffer_cap == 0 {
                    1000
                } else {
                    form.buffer_cap
                },
                sasl_account,
                sasl_password,
            });
            Ok(format!("added server network {name}"))
        })
        .await
    }

    pub async fn console_delete_shared_network(
        State(state): State<Arc<AppState>>,
        AdminConfigPayload {
            form,
            account,
            csrf,
        }: AdminConfigPayload<DeleteSharedNetwork>,
    ) -> Response {
        mutate_managed_config(&state, account, csrf, move |settings| {
            if settings.credentials_from_bootstrap {
                return Err(
                    "Configure a master key and restart before changing bootstrap networks.".into(),
                );
            }
            let owner = (!form.owner.is_empty()).then_some(form.owner.as_str());
            let before = settings.networks.len();
            settings.networks.retain(|network| {
                !(network.name == form.name && network.owner.as_deref() == owner)
            });
            if settings.networks.len() == before {
                return Err(format!("No matching server network named '{}'.", form.name));
            }
            Ok(format!("removed server network {}", form.name))
        })
        .await
    }

    struct SessionRow {
        id: u64,
        nick: String,
        user: String,
        host: String,
        account: Option<String>,
        oper: bool,
        transport: &'static str,
        connected_at: String,
        idle_seconds: u64,
        /// Channels the session is in, pre-joined for display.
        channels: String,
    }

    struct BrowserSessionRow {
        id: i64,
        method: String,
        user_agent: String,
        created: String,
        expires: String,
        current: bool,
    }

    #[derive(Template)]
    #[template(path = "console_sessions.html")]
    struct ConsoleSessions {
        shell: ConsoleShell,
        title: &'static str,
        hint: &'static str,
        disconnect_action: &'static str,
        sessions: Vec<SessionRow>,
        nick_filter: String,
        account_filter: String,
        transport_filter: String,
        oper_filter: String,
        limit: usize,
        has_filters: bool,
        has_cursor: bool,
        next_before_id: Option<u64>,
        show_browser_sessions: bool,
        show_account_filter: bool,
        browser_sessions: Vec<BrowserSessionRow>,
        error: Option<String>,
    }

    struct NetworkPreflightView {
        confirmed_nick: String,
        resolved_addresses: usize,
        dns_ms: u64,
        connect_ms: u64,
        registration_ms: u64,
    }

    #[derive(Template)]
    #[template(path = "console_networks.html")]
    struct ConsoleNetworks {
        shell: ConsoleShell,
        networks: Vec<ConsoleNetView>,
        attach_addr: Option<std::net::SocketAddr>,
        presets: &'static [IrcNetworkPreset],
        form: NetworkFormView,
        error: Option<FormFieldError>,
        success: Option<NetworkPreflightView>,
        can_store_secrets: bool,
    }

    /// The networks table as a standalone fragment: the list page's live
    /// refresh swaps it in whole (the same discipline as the monitoring
    /// panel), so reconnecting upstreams update without a full page reload.
    #[derive(Template)]
    #[template(path = "console_network_rows.html")]
    struct ConsoleNetworkRows {
        networks: Vec<ConsoleNetView>,
        csrf: String,
    }

    #[derive(Template)]
    #[template(path = "console_network_edit.html")]
    struct ConsoleNetworkEdit {
        shell: ConsoleShell,
        name: String,
        addr: String,
        tls: bool,
        nick: String,
        realname: String,
        autojoin: String,
        sasl_account: String,
        can_store_secrets: bool,
        error: Option<String>,
    }

    #[derive(Template)]
    #[template(path = "console_bridge_edit.html")]
    struct ConsoleBridgeEdit {
        shell: ConsoleShell,
        name: String,
        platform: &'static str,
        needs_nick: bool,
        needs_account: bool,
        account_label: &'static str,
        password_label: &'static str,
        addr: String,
        addr_required: bool,
        nick: String,
        autojoin: String,
        has_sasl_account: bool,
        has_sasl_password: bool,
        can_store_secrets: bool,
        error: Option<String>,
    }

    struct NetworkOperationsView {
        state: String,
        connected: bool,
        state_changed: String,
        next_retry: String,
        recent_failures: Vec<String>,
        connected_since: String,
        last_input: String,
        last_output: String,
        last_error: String,
        last_error_reason: String,
        connect_latency: String,
        connection_attempts: u64,
        errors: u64,
        attached_clients: u64,
        traffic_in: String,
        traffic_out: String,
        lines_in: u64,
        lines_out: u64,
        memory_buffer: String,
        stored_lines: i64,
        stored_oldest: String,
        stored_newest: String,
        recent_lines: Vec<String>,
    }

    #[derive(Template)]
    #[template(path = "console_network_detail.html")]
    struct ConsoleNetworkDetail {
        shell: ConsoleShell,
        name: String,
        kind: &'static str,
        addr: String,
        tls: bool,
        nick: String,
        realname: String,
        autojoin: String,
        enabled: bool,
        editable: bool,
        bridge_editable: bool,
        has_sasl_account: bool,
        has_sasl_password: bool,
        view: NetworkOperationsView,
    }

    #[derive(Template)]
    #[template(path = "_network_operations.html")]
    struct ConsoleNetworkOperations {
        view: NetworkOperationsView,
    }

    /// The console edit-network form (urlencoded). `tls` is an HTML checkbox.
    #[derive(Deserialize)]
    pub struct NetworkEditForm {
        csrf: String,
        addr: String,
        nick: String,
        #[serde(default)]
        tls: Option<String>,
        #[serde(default)]
        realname: String,
        #[serde(default)]
        autojoin: String,
        #[serde(default)]
        sasl_account: String,
        #[serde(default)]
        sasl_password: String,
        #[serde(default)]
        clear_sasl: Option<String>,
    }

    /// Admin console: server-wide read views (accounts, registered channels,
    /// server bans, audit log) rendered server-side. Cookie-authenticated and
    /// admin-gated the same way the `/api/v1/admin/*` JSON endpoints are — an
    /// unauthenticated visitor goes to `/login`, a signed-in non-admin gets 403 —
    /// so the console can never surface server-wide data to a non-admin.
    pub async fn console(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
    ) -> Response {
        let (account, csrf) = match page_actor(&state, &headers, true).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        match console_build(&state, account, csrf).await {
            Ok(view) => render_private(view),
            Err(resp) => resp,
        }
    }

    /// Whether `account` may reach the admin console sections.
    fn is_admin_account(state: &AppState, account: &str) -> bool {
        state
            .admin_accounts
            .read()
            .expect("administrator registry lock")
            .contains(&e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(account))
    }

    /// Build the caller's BNC networks with live upstream state from the
    /// registry (a network with no live handle — disabled, or not yet dialed —
    /// reads as not connected). One place keeps the list view consistent after
    /// every form redirect.
    async fn console_network_views(
        state: &AppState,
        account: &str,
    ) -> Result<Vec<ConsoleNetView>, Response> {
        let pool = pool_of(state);
        let rows = crate::db::list_bnc_networks(pool, account)
            .await
            .map_err(|e| {
                eprintln!("console: network list: {e}");
                problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Database unavailable",
                    None,
                )
            })?;
        Ok(rows
            .into_iter()
            .map(|n| {
                let runtime = state
                    .bnc_registry
                    .as_ref()
                    .and_then(|r| r.get_owned(account, &n.name))
                    .map(|h| h.runtime_snapshot());
                let connected = runtime.as_ref().is_some_and(|runtime| {
                    runtime.lifecycle == crate::bouncer::NetworkLifecycle::Connected
                });
                let state_label = if n.enabled {
                    runtime
                        .as_ref()
                        .map(|runtime| runtime.lifecycle.as_str().replace('_', " "))
                        .unwrap_or_else(|| "not running".into())
                } else {
                    "disabled".into()
                };
                ConsoleNetView {
                    name: n.name,
                    kind: n.kind.as_db_str(),
                    addr: n.addr,
                    tls: n.tls,
                    enabled: n.enabled,
                    connected,
                    state: state_label,
                    attached_clients: runtime
                        .as_ref()
                        .map_or(0, |runtime| runtime.attached_clients),
                    errors: runtime.as_ref().map_or(0, |runtime| runtime.errors),
                }
            })
            .collect())
    }

    fn runtime_time(value: Option<e6irc_proto::time::Millis>) -> String {
        value
            .map(e6irc_proto::time::server_time)
            .unwrap_or_else(|| "never".into())
    }

    fn now_millis() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_millis()
            .min(u64::MAX as u128) as u64
    }

    fn runtime_age(value: Option<e6irc_proto::time::Millis>) -> String {
        value
            .map(|at| format_age(now_millis(), at.as_millis()))
            .unwrap_or_else(|| "never".into())
    }

    async fn network_operations_view(
        state: &AppState,
        account: &str,
        name: &str,
        enabled: bool,
    ) -> Result<NetworkOperationsView, Response> {
        let runtime = state
            .bnc_registry
            .as_ref()
            .and_then(|registry| registry.get_owned(account, name))
            .map(|handle| handle.runtime_snapshot());
        let summary = crate::db::bnc_buffer_summary(pool_of(state), account, name)
            .await
            .map_err(|error| {
                eprintln!("console: network buffer summary: {error}");
                problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Database unavailable",
                    None,
                )
            })?;
        let recent_lines = crate::db::recent_bnc_lines(pool_of(state), account, name, 100)
            .await
            .map_err(|error| {
                eprintln!("console: network buffer read: {error}");
                problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Database unavailable",
                    None,
                )
            })?;
        let state_label = if !enabled {
            "disabled".into()
        } else {
            runtime
                .as_ref()
                .map(|runtime| runtime.lifecycle.as_str().replace('_', " "))
                .unwrap_or_else(|| "not running".into())
        };
        let connected = runtime.as_ref().is_some_and(|runtime| {
            runtime.lifecycle == crate::bouncer::NetworkLifecycle::Connected
        });
        Ok(NetworkOperationsView {
            state: state_label,
            connected,
            state_changed: runtime
                .as_ref()
                .map(|runtime| e6irc_proto::time::server_time(runtime.state_changed_at))
                .unwrap_or_else(|| "not available".into()),
            next_retry: runtime
                .as_ref()
                .and_then(|runtime| runtime.next_retry_at)
                .map(|at| {
                    format!(
                        "{} (in {})",
                        e6irc_proto::time::server_time(at),
                        format_latency(
                            at.as_millis()
                                .saturating_sub(now_millis())
                                .saturating_mul(1_000)
                        ),
                    )
                })
                .unwrap_or_else(|| "not scheduled".into()),
            recent_failures: runtime
                .as_ref()
                .map(|runtime| {
                    runtime
                        .recent_failures
                        .iter()
                        .map(|record| {
                            format!(
                                "{} — {}",
                                e6irc_proto::time::server_time(record.at),
                                record.summary(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default(),
            connected_since: runtime_age(runtime.as_ref().and_then(|runtime| runtime.connected_at)),
            last_input: runtime_age(runtime.as_ref().and_then(|runtime| runtime.last_input_at)),
            last_output: runtime_age(runtime.as_ref().and_then(|runtime| runtime.last_output_at)),
            last_error: runtime_age(runtime.as_ref().and_then(|runtime| runtime.last_error_at)),
            last_error_reason: runtime
                .as_ref()
                .and_then(|runtime| runtime.last_error)
                .map(|failure| failure.summary().to_string())
                .unwrap_or_else(|| "No classified runtime failure.".into()),
            connect_latency: runtime
                .as_ref()
                .and_then(|runtime| runtime.connect_latency_ms)
                .map(|millis| format_latency(millis.saturating_mul(1_000)))
                .unwrap_or_else(|| "not measured".into()),
            connection_attempts: runtime
                .as_ref()
                .map_or(0, |runtime| runtime.connection_attempts),
            errors: runtime.as_ref().map_or(0, |runtime| runtime.errors),
            attached_clients: runtime
                .as_ref()
                .map_or(0, |runtime| runtime.attached_clients),
            traffic_in: format_bytes(runtime.as_ref().map_or(0, |runtime| runtime.bytes_in)),
            traffic_out: format_bytes(runtime.as_ref().map_or(0, |runtime| runtime.bytes_out)),
            lines_in: runtime.as_ref().map_or(0, |runtime| runtime.lines_in),
            lines_out: runtime.as_ref().map_or(0, |runtime| runtime.lines_out),
            memory_buffer: runtime
                .as_ref()
                .map(|runtime| format!("{} / {}", runtime.buffer_lines, runtime.buffer_capacity))
                .unwrap_or_else(|| "0 / 0".into()),
            stored_lines: summary.lines,
            stored_oldest: runtime_time(summary.oldest_at),
            stored_newest: runtime_time(summary.newest_at),
            recent_lines,
        })
    }

    /// Resolve one authenticated caller's stored network and its page token.
    /// Keeping authentication, ownership lookup, and not-found/error mapping in
    /// one edge prevents the detail page and its refresh fragment from drifting
    /// into different access-control behavior.
    async fn console_owned_network(
        state: &AppState,
        headers: &axum::http::HeaderMap,
        name: &str,
    ) -> Result<(String, String, crate::db::BncNetworkRow), Response> {
        let (account, csrf) = page_actor(state, headers, false).await?;
        let network = crate::db::get_bnc_network(pool_of(state), &account, name)
            .await
            .map_err(|error| super::device::admin_db_error("network fetch", error))?
            .ok_or_else(|| problem(StatusCode::NOT_FOUND, "No such network", None))?;
        Ok((account, csrf, network))
    }

    pub async fn console_network_detail(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        Path(name): Path<String>,
    ) -> Response {
        let (account, csrf, network) = match console_owned_network(&state, &headers, &name).await {
            Ok(result) => result,
            Err(response) => return response,
        };
        let view =
            match network_operations_view(&state, &account, &network.name, network.enabled).await {
                Ok(view) => view,
                Err(response) => return response,
            };
        let is_admin = is_admin_account(&state, &account);
        render_private(ConsoleNetworkDetail {
            shell: console_shell(&state, account.clone(), csrf, "networks"),
            name: network.name,
            kind: network.kind.as_db_str(),
            addr: network.addr,
            tls: network.tls,
            nick: network.nick,
            realname: network.realname.unwrap_or_default(),
            autojoin: network.autojoin.join(", "),
            enabled: network.enabled,
            editable: network.kind == crate::config::NetworkKind::Irc,
            bridge_editable: network.kind.is_bridge() && is_admin,
            has_sasl_account: network.sasl_account.is_some(),
            has_sasl_password: network.sasl_password_sealed.is_some(),
            view,
        })
    }

    pub async fn console_network_operations(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        Path(name): Path<String>,
    ) -> Response {
        let (account, _, network) = match console_owned_network(&state, &headers, &name).await {
            Ok(result) => result,
            Err(response) => return response,
        };
        match network_operations_view(&state, &account, &network.name, network.enabled).await {
            Ok(view) => render_private(ConsoleNetworkOperations { view }),
            Err(response) => response,
        }
    }

    /// Render the network list and create form. Failed submissions use this same
    /// path so their exact error and all non-secret fields remain in context.
    async fn console_networks_page(
        state: &AppState,
        account: String,
        csrf: String,
        form: NetworkFormView,
        error: Option<FormFieldError>,
        success: Option<NetworkPreflightView>,
    ) -> Response {
        let networks = match console_network_views(state, &account).await {
            Ok(n) => n,
            Err(r) => return r,
        };
        let attach_addr = match &state.bnc_listener {
            Some(listener) => listener.status().await.map(|(_, bound)| bound),
            None => None,
        };
        render_private(ConsoleNetworks {
            shell: console_shell(state, account, csrf, "networks"),
            networks,
            attach_addr,
            presets: IRC_NETWORK_PRESETS,
            form,
            error,
            success,
            can_store_secrets: state.secret_key.is_some(),
        })
    }

    /// Re-render the networks console with the just-submitted form and the
    /// mutation error mapped onto its fields — the shared failure tail of the
    /// add/preflight network handlers.
    async fn console_networks_mutation_error(
        state: &AppState,
        account: String,
        csrf: String,
        form_view: NetworkFormView,
        error: &crate::http::networks::NetworkMutationError,
    ) -> Response {
        console_networks_page(
            state,
            account,
            csrf,
            form_view,
            Some(FormFieldError::from_mutation(error)),
            None,
        )
        .await
    }

    /// Console → BNC networks: the caller's own always-on upstreams with live
    /// connection status, plus add/remove. Any authenticated user manages their
    /// own networks (not admin-gated); an anonymous visitor goes to `/login`.
    pub async fn console_networks(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
    ) -> Response {
        let (account, csrf) = match page_actor(&state, &headers, false).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        let form = NetworkFormView::libera(&account);
        console_networks_page(&state, account, csrf, form, None, None).await
    }

    /// The live-refresh fragment backing `/console/networks`' table.
    pub async fn console_network_rows(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
    ) -> Response {
        let (account, csrf) = match page_actor(&state, &headers, false).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        let networks = match console_network_views(&state, &account).await {
            Ok(n) => n,
            Err(r) => return r,
        };
        render_private(ConsoleNetworkRows { networks, csrf })
    }

    /// Add a network from the console and return to the canonical list.
    pub async fn console_add_network(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<NetworkFormFields>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let (account, fields) = match account_form_actor(&state, &headers, form).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        let csrf = session_token(&headers, state.secure_cookies)
            .map(|session| state.csrf_token(&session))
            .unwrap_or_default();
        let mut fields = fields;
        let preset_result = fields.apply_preset();
        let form_view = NetworkFormView::submitted(&fields);
        let Some(registry) = &state.bnc_registry else {
            return console_networks_page(
                &state,
                account,
                csrf,
                form_view,
                Some(FormFieldError::banner(
                    "The network registry is not available on this server.",
                )),
                None,
            )
            .await;
        };
        let req = match preset_result {
            Ok(()) => fields.into_resolved_create(),
            Err(error) => {
                return console_networks_mutation_error(&state, account, csrf, form_view, &error)
                    .await;
            }
        };
        if let Err(error) = create_network_core(&state, registry, &account, &req).await {
            return console_networks_mutation_error(&state, account, csrf, form_view, &error).await;
        }
        Redirect::to("/console/networks").into_response()
    }

    /// Exercise the exact production IRC dial and registration path while
    /// retaining the form for a subsequent create. The preflight has no
    /// durable side effect and never starts a reconnect loop.
    pub async fn console_preflight_network(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<NetworkFormFields>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let (account, mut fields) = match account_form_actor(&state, &headers, form).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        let csrf = session_token(&headers, state.secure_cookies)
            .map(|session| state.csrf_token(&session))
            .unwrap_or_default();
        if let Err(error) = fields.apply_preset() {
            let form_view = NetworkFormView::submitted(&fields);
            return console_networks_mutation_error(&state, account, csrf, form_view, &error).await;
        }
        let form_view = NetworkFormView::submitted(&fields);
        let create = fields.into_resolved_create();
        let request = PreflightNetwork {
            addr: create.addr,
            tls: create.tls,
            nick: create.nick,
            realname: create.realname,
            sasl_account: create.sasl_account,
            sasl_password: create.sasl_password,
        };
        match preflight_network_core(request).await {
            Ok(result) => {
                let view = NetworkPreflightView {
                    confirmed_nick: result.confirmed_nick,
                    resolved_addresses: result.resolved_addresses,
                    dns_ms: result.dns_ms,
                    connect_ms: result.connect_ms,
                    registration_ms: result.registration_ms,
                };
                console_networks_page(&state, account, csrf, form_view, None, Some(view)).await
            }
            Err(error) => {
                console_networks_page(
                    &state,
                    account,
                    csrf,
                    form_view,
                    Some(FormFieldError::banner(error.message())),
                    None,
                )
                .await
            }
        }
    }

    /// Delete an owner-scoped network and stop its live driver.
    async fn delete_network_by_name(
        state: &AppState,
        account: &str,
        name: &str,
    ) -> Result<(), Response> {
        let Some(registry) = &state.bnc_registry else {
            return Err(problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None));
        };
        delete_network_core(state, registry, account, name, EditableNetworkKind::Any)
            .await
            .map_err(NetworkMutationError::into_response)
    }

    /// Delete a network from the console and return to the canonical list.
    pub async fn console_delete_network(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        Path(name): Path<String>,
        form: Result<axum::Form<AccountDeleteForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let (account, _) = match account_form_actor(&state, &headers, form).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        if let Err(response) = delete_network_by_name(&state, &account, &name).await {
            return response;
        }
        Redirect::to("/console/networks").into_response()
    }

    /// The console toggle button posts the *target* enabled state so the flip is
    /// not derived from a possibly-stale row (no read-then-write race).
    #[derive(Deserialize)]
    pub struct ToggleFields {
        csrf: String,
        enabled: String,
    }

    fn toggle_target(value: &str) -> Option<bool> {
        match value {
            "true" | "on" | "1" => Some(true),
            "false" | "off" | "0" => Some(false),
            _ => None,
        }
    }

    fn invalid_toggle_response() -> Response {
        problem(
            StatusCode::BAD_REQUEST,
            "Invalid enabled state",
            Some("enabled must be true or false"),
        )
    }

    /// Enable/disable a network from the console. Reuses the same core the REST
    /// `PATCH` uses.
    pub async fn console_toggle_network(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        Path(name): Path<String>,
        form: Result<axum::Form<ToggleFields>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let registry = require_registry!(state);
        let (account, f) = match account_form_actor(&state, &headers, form).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        let Some(enabled) = toggle_target(&f.enabled) else {
            return invalid_toggle_response();
        };
        if let Err(error) =
            set_network_enabled_core(&state, registry, &account, &account, &name, enabled).await
        {
            return error.into_response();
        }
        Redirect::to("/console/networks").into_response()
    }

    /// Render the edit-network form (shared by the GET and the failed-POST
    /// re-render, which differ only in field values and the error banner).
    #[allow(clippy::too_many_arguments)]
    fn console_network_edit_page(
        state: &AppState,
        account: String,
        csrf: String,
        name: String,
        addr: String,
        tls: bool,
        nick: String,
        realname: String,
        autojoin: String,
        sasl_account: String,
        can_store_secrets: bool,
        error: Option<String>,
    ) -> Response {
        render_private(ConsoleNetworkEdit {
            shell: console_shell(state, account, csrf, "networks"),
            name,
            addr,
            tls,
            nick,
            realname,
            autojoin,
            sasl_account,
            can_store_secrets,
            error,
        })
    }

    /// Console → edit-network form (GET): pre-filled with the network's current
    /// connection/identity fields. Any authenticated user may edit their own
    /// network (not admin-gated), matching `/console/networks`.
    pub async fn console_edit_network(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        Path(name): Path<String>,
    ) -> Response {
        let (account, csrf) = match page_actor(&state, &headers, false).await {
            Ok(x) => x,
            Err(r) => return r,
        };
        let pool = pool_of(&state);
        let row = match crate::db::get_bnc_network(pool, &account, &name).await {
            Ok(Some(row)) => row,
            Ok(None) => return problem(StatusCode::NOT_FOUND, "No such network", None),
            Err(e) => return super::device::admin_db_error("network fetch", e),
        };
        // This form edits IRC upstream fields; a bridge is configured on the
        // Integrations page. Send a bridge there rather than render an
        // IRC-shaped form over it.
        if row.kind != crate::config::NetworkKind::Irc {
            return Redirect::to("/console/networks").into_response();
        }
        console_network_edit_page(
            &state,
            account,
            csrf,
            row.name,
            row.addr,
            row.tls,
            row.nick,
            row.realname.unwrap_or_default(),
            row.autojoin.join(", "),
            row.sasl_account.unwrap_or_default(),
            state.secret_key.is_some(),
            None,
        )
    }

    /// Console → apply an edited network (POST): validate, persist the new
    /// connection/identity fields, and rebuild the live driver. On success
    /// redirect to the network list; on failure re-render the form with a banner
    /// (keeping the submitted values).
    pub async fn console_update_network(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        Path(name): Path<String>,
        form: Result<axum::Form<NetworkEditForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        // Plain form: parse first, then authenticate + verify the body CSRF.
        let (account, f) = match account_form_actor(&state, &headers, form).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        let registry = require_registry!(state);
        let tls = f.tls.as_deref() == Some("on");
        let realname = (!f.realname.trim().is_empty()).then(|| f.realname.trim().to_string());
        let autojoin: Vec<String> = f
            .autojoin
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        let sasl_account = f.sasl_account.trim();
        let sasl_password = (!f.sasl_password.is_empty()).then_some(f.sasl_password.as_str());
        let credentials = if f.clear_sasl.as_deref() == Some("on") {
            // The checkbox is the explicit operation. Values may still arrive
            // from a no-JavaScript browser whose pre-filled account field was
            // not disabled; removal wins rather than making that UI path fail.
            NetworkCredentialUpdate::Remove
        } else if sasl_account.is_empty() && sasl_password.is_none() {
            NetworkCredentialUpdate::Remove
        } else {
            NetworkCredentialUpdate::Set {
                account: Some(sasl_account),
                password: sasl_password,
            }
        };
        let result = update_network_core(
            &state,
            registry,
            &account,
            &name,
            EditableNetworkKind::Irc,
            &f.addr,
            tls,
            &f.nick,
            realname.as_deref(),
            &autojoin,
            credentials,
        )
        .await;
        let error = match result {
            Ok(()) => return Redirect::to("/console/networks").into_response(),
            Err(error) => error.message(),
        };
        // Re-render the form with a banner, keeping what the user typed.
        let csrf = session_token(&headers, state.secure_cookies)
            .map(|s| state.csrf_token(&s))
            .unwrap_or_default();
        console_network_edit_page(
            &state,
            account,
            csrf,
            name,
            f.addr,
            tls,
            f.nick,
            f.realname,
            f.autojoin,
            f.sasl_account,
            state.secret_key.is_some(),
            Some(error),
        )
    }

    struct BridgeNet {
        name: String,
        owner: String,
        connected: bool,
        enabled: bool,
        state: String,
        /// Whether the viewing admin owns this bridge (so it can be removed from
        /// here). A config-file / shared bridge is managed via config, not here.
        manageable: bool,
    }
    struct BridgePlatformMeta {
        name: &'static str,
        kind: crate::config::NetworkKind,
        feature: &'static str,
        configure: &'static str,
        addr_required: bool,
        needs_nick: bool,
        needs_account: bool,
        account_label: &'static str,
        password_label: &'static str,
    }

    const BRIDGE_PLATFORMS: &[BridgePlatformMeta] = &[
        BridgePlatformMeta {
            name: "Matrix",
            kind: crate::config::NetworkKind::Matrix,
            feature: "matrix",
            configure: "A homeserver bridged as a network: messages relay both ways.",
            addr_required: true,
            needs_nick: true,
            needs_account: false,
            account_label: "",
            password_label: "Login password",
        },
        BridgePlatformMeta {
            name: "Discord",
            kind: crate::config::NetworkKind::Discord,
            feature: "discord",
            configure: "A Discord bot session; autojoin lists the channel IDs to bridge.",
            addr_required: false,
            needs_nick: false,
            needs_account: false,
            account_label: "",
            password_label: "Bot token",
        },
        BridgePlatformMeta {
            name: "Slack",
            kind: crate::config::NetworkKind::Slack,
            feature: "slack",
            configure: "A Slack workspace; autojoin lists the channels to bridge.",
            addr_required: false,
            needs_nick: false,
            needs_account: true,
            account_label: "Bot token (xoxb-)",
            password_label: "App token (xapp-)",
        },
    ];

    fn bridge_platform_meta(
        kind: crate::config::NetworkKind,
    ) -> Option<&'static BridgePlatformMeta> {
        BRIDGE_PLATFORMS.iter().find(|meta| meta.kind == kind)
    }

    struct BridgePlatform {
        meta: &'static BridgePlatformMeta,
        built: bool,
        networks: Vec<BridgeNet>,
    }

    #[derive(Template)]
    #[template(path = "console_integrations.html")]
    struct ConsoleIntegrations {
        shell: ConsoleShell,
        bouncer_enabled: bool,
        platforms: Vec<BridgePlatform>,
        /// Error banner shown after a failed add/remove; `None` on the plain GET.
        error: Option<String>,
    }

    /// Console → Integrations (admin): the chat-platform bridges. For each
    /// platform it shows whether this binary was built with the feature and the
    /// bridge networks currently running (with live status), plus add/remove for
    /// the admin's own bridges. `error` renders a banner after a failed action.
    async fn console_integrations_build(
        state: &AppState,
        account: String,
        csrf: String,
        error: Option<String>,
    ) -> Result<ConsoleIntegrations, Response> {
        let all = state
            .bnc_registry
            .as_ref()
            .map(|r| r.list())
            .unwrap_or_default();
        let stored = crate::db::list_bnc_network_inventory(pool_of(state))
            .await
            .map_err(|error| super::device::admin_db_error("network inventory", error))?;
        let admin_folded = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(&account);
        let bridge_nets = |kind: &str| -> Vec<BridgeNet> {
            let mut networks: Vec<BridgeNet> = stored
                .iter()
                .filter(|row| row.network.kind.as_db_str() == kind)
                .map(|row| {
                    let owner_folded =
                        e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(&row.owner);
                    let runtime = all.iter().find(|status| {
                        status.owner.as_deref() == Some(owner_folded.as_str())
                            && status.name.eq_ignore_ascii_case(&row.network.name)
                    });
                    let connected = runtime.is_some_and(|status| status.connected);
                    BridgeNet {
                        name: row.network.name.clone(),
                        owner: row.owner.clone(),
                        connected,
                        enabled: row.network.enabled,
                        state: if row.network.enabled {
                            runtime
                                .map(|status| status.runtime.lifecycle.as_str().replace('_', " "))
                                .unwrap_or_else(|| "not running".into())
                        } else {
                            "disabled".into()
                        },
                        manageable: owner_folded == admin_folded,
                    }
                })
                .collect();
            networks.extend(
                all.iter()
                    .filter(|status| status.kind == kind && status.owner.is_none())
                    .map(|status| BridgeNet {
                        name: status.name.clone(),
                        owner: "shared".into(),
                        connected: status.connected,
                        enabled: true,
                        state: status.runtime.lifecycle.as_str().replace('_', " "),
                        manageable: false,
                    }),
            );
            networks
        };
        let platforms = BRIDGE_PLATFORMS
            .iter()
            .map(|meta| BridgePlatform {
                meta,
                built: kind_feature_available(meta.kind),
                networks: bridge_nets(meta.feature),
            })
            .collect();
        Ok(ConsoleIntegrations {
            shell: console_shell(state, account, csrf, "integrations"),
            bouncer_enabled: state.bnc_registry.is_some(),
            platforms,
            error,
        })
    }

    /// Console → Integrations (admin) GET.
    pub async fn console_integrations(
        State(state): State<Arc<AppState>>,
        AdminPageActor { account, csrf }: AdminPageActor,
    ) -> Response {
        match console_integrations_build(&state, account, csrf, None).await {
            Ok(view) => render_private(view),
            Err(response) => response,
        }
    }

    /// Re-render the integrations page with an error banner after a failed
    /// add/remove (an admin has already been resolved by the caller).
    async fn console_integrations_error(
        state: &AppState,
        headers: &axum::http::HeaderMap,
        account: String,
        message: String,
    ) -> Response {
        let csrf = session_token(headers, state.secure_cookies)
            .map(|s| state.csrf_token(&s))
            .unwrap_or_default();
        match console_integrations_build(state, account, csrf, Some(message)).await {
            Ok(view) => render_private(view),
            Err(response) => response,
        }
    }

    /// The bridge connection/identity fields shared by the add and edit
    /// forms (all optional on the wire; meaning is per kind).
    #[derive(Deserialize)]
    struct BridgeConnectionFields {
        #[serde(default)]
        addr: String,
        #[serde(default)]
        nick: String,
        #[serde(default)]
        sasl_account: String,
        #[serde(default)]
        sasl_password: String,
        #[serde(default)]
        autojoin: String,
    }

    /// The console add-bridge form (urlencoded with a hidden CSRF field). Field
    /// meaning is per kind.
    #[derive(Deserialize)]
    pub struct BridgeFormFields {
        csrf: String,
        kind: String,
        name: String,
        #[serde(flatten)]
        connection: BridgeConnectionFields,
    }

    #[derive(Deserialize)]
    pub struct BridgeEditFormFields {
        csrf: String,
        #[serde(flatten)]
        connection: BridgeConnectionFields,
    }

    #[derive(Deserialize)]
    pub struct BridgeDeleteFields {
        csrf: String,
        name: String,
    }

    #[derive(Deserialize)]
    pub struct BridgeToggleFields {
        csrf: String,
        name: String,
        enabled: String,
    }

    /// Unwrap an axum form, turning a rejection into a 400 problem response.
    /// Shared by the console's plain-form handlers so the parse boilerplate
    /// isn't copied into each.
    #[allow(clippy::result_large_err)] // Err is a full problem Response, as throughout
    fn parse_form<T>(
        form: Result<axum::Form<T>, axum::extract::rejection::FormRejection>,
    ) -> Result<T, Response> {
        match form {
            Ok(axum::Form(f)) => Ok(f),
            Err(e) => Err(problem(
                StatusCode::BAD_REQUEST,
                "Invalid form",
                Some(&e.to_string()),
            )),
        }
    }

    /// Authenticate a plain-form (body-CSRF) actor: the caller is signed in and
    /// the form carried a valid CSRF token. Not admin-gated — for self-service
    /// actions on the caller's own resources. Returns the account or a response.
    async fn require_form_actor(
        state: &AppState,
        headers: &axum::http::HeaderMap,
        csrf: &str,
    ) -> Result<String, Response> {
        let account = authenticate(state, headers)
            .await
            .map_err(|_| Redirect::to("/login").into_response())?;
        let Some(session) = session_token(headers, state.secure_cookies) else {
            return Err(problem(StatusCode::UNAUTHORIZED, "Session required", None));
        };
        if !state.csrf_valid(&session, csrf) {
            return Err(problem(StatusCode::FORBIDDEN, "Bad CSRF token", None));
        }
        Ok(account)
    }

    async fn require_admin_form_actor(
        state: &AppState,
        headers: &axum::http::HeaderMap,
        csrf: &str,
    ) -> Result<String, Response> {
        let account = require_form_actor(state, headers, csrf).await?;
        if !is_admin_account(state, &account) {
            return Err(problem(StatusCode::FORBIDDEN, "Admin only", None));
        }
        Ok(account)
    }

    trait CsrfForm {
        fn csrf(&self) -> &str;
    }

    macro_rules! csrf_forms {
        ($($form:ty),+ $(,)?) => {
            $(
                impl CsrfForm for $form {
                    fn csrf(&self) -> &str {
                        &self.csrf
                    }
                }
            )+
        };
    }

    csrf_forms!(
        AccountSuspensionForm,
        AccountAdministratorForm,
        AccountCreateForm,
        AccountInvitationForm,
        AccountInvitationRevokeForm,
        AccountPermanentDeleteForm,
    );

    /// Parse and authorize an administrator-owned browser form as one gate so
    /// mutations cannot drift between subtly different CSRF/admin prologues.
    #[allow(clippy::result_large_err)] // Err is the standard full problem Response
    async fn parse_admin_form<T: CsrfForm>(
        state: &AppState,
        headers: &axum::http::HeaderMap,
        form: Result<axum::Form<T>, axum::extract::rejection::FormRejection>,
    ) -> Result<(T, String), Response> {
        let form = parse_form(form)?;
        let actor = require_admin_form_actor(state, headers, form.csrf()).await?;
        Ok((form, actor))
    }

    /// Ask the core for one already-validated bounded connection page.
    async fn list_live_connections(
        state: &AppState,
        query: crate::core::LiveConnectionQuery,
    ) -> Result<crate::core::LiveConnectionPage, String> {
        match core_reply(state, crate::core::AdminRequest::ListConnections { query }).await {
            Ok(crate::core::AdminReply::Connections(page)) => Ok(page),
            Ok(_) => Err("unexpected reply".into()),
            Err(error) => Err(error),
        }
    }

    enum AdminPolicyPage {
        RegisteredChannels,
        ServerBans,
    }

    /// Re-render the policy page that owns a failed mutation. Successful
    /// actions use Post/Redirect/Get; failures stay visible beside the exact
    /// controls that produced them.
    async fn admin_policy_error_page(
        state: &AppState,
        headers: &axum::http::HeaderMap,
        account: String,
        message: String,
        page: AdminPolicyPage,
    ) -> Response {
        let csrf = session_token(headers, state.secure_cookies)
            .map(|s| state.csrf_token(&s))
            .unwrap_or_default();
        match page {
            AdminPolicyPage::RegisteredChannels => {
                let query = match super::device::validate_registered_channel_directory_query(
                    super::device::RegisteredChannelDirectoryQuery::default(),
                    50,
                ) {
                    Ok(query) => query,
                    Err(response) => return response,
                };
                match console_admin_channels_build(state, account, csrf, query, Some(message)).await
                {
                    Ok(view) => render_private(view),
                    Err(response) => response,
                }
            }
            AdminPolicyPage::ServerBans => {
                let query = match super::device::validate_server_ban_directory_query(
                    super::device::ServerBanDirectoryQuery::default(),
                    50,
                ) {
                    Ok(query) => query,
                    Err(response) => return response,
                };
                match console_server_bans_build(state, account, csrf, query, Some(message)).await {
                    Ok(view) => render_private(view),
                    Err(response) => response,
                }
            }
        }
    }

    #[derive(Deserialize)]
    pub struct BanForm {
        csrf: String,
        kind: String,
        mask: String,
        #[serde(default)]
        reason: String,
    }

    #[derive(Deserialize)]
    pub struct BanDeleteForm {
        csrf: String,
        kind: String,
        mask: String,
    }

    #[derive(Deserialize)]
    pub struct DropChannelForm {
        csrf: String,
        channel: String,
    }

    /// Gate an admin form action (admin + CSRF) and run it on the core. Returns
    /// the redirect `Response` on success, or the gate `Response` (login/403) on
    /// a gate failure; on an *action* failure returns `Err((account, message))`
    /// so the caller re-renders its own page with the message. This is the shared
    /// tail of every console mutation — only the form type, the request it builds,
    /// and the page it re-renders on error differ.
    async fn run_admin_form(
        state: &AppState,
        headers: &axum::http::HeaderMap,
        csrf: &str,
        redirect: &'static str,
        make_req: impl FnOnce(String) -> crate::core::AdminRequest,
    ) -> Result<Response, (String, String)> {
        let account = match require_admin_form_actor(state, headers, csrf).await {
            Ok(a) => a,
            Err(gate) => return Ok(gate),
        };
        let req = make_req(account.clone());
        match core_action(state, req).await {
            Ok(_) => Ok(Redirect::to(redirect).into_response()),
            Err(msg) => Err((account, msg)),
        }
    }

    /// Run an admin console form action and render its policy-error page on an
    /// action failure — the shared tail of the ban, channel, and session
    /// handlers, which differ only in redirect, request, and error page.
    async fn admin_form_page(
        state: &AppState,
        headers: &axum::http::HeaderMap,
        csrf: &str,
        redirect: &'static str,
        make_req: impl FnOnce(String) -> crate::core::AdminRequest,
        error_page: AdminPolicyPage,
    ) -> Response {
        match run_admin_form(state, headers, csrf, redirect, make_req).await {
            Ok(resp) => resp,
            Err((account, msg)) => {
                admin_policy_error_page(state, headers, account, msg, error_page).await
            }
        }
    }

    /// The full console mutation flow for a csrf-carrying admin form: parse,
    /// build the request from the form and actor, run it, and render the
    /// policy-error page on failure. The admin mutation handlers differ only
    /// in the request the form becomes.
    async fn admin_policy_form<F: AccountForm>(
        state: &AppState,
        headers: &axum::http::HeaderMap,
        form: Result<axum::Form<F>, axum::extract::rejection::FormRejection>,
        redirect: &'static str,
        error_page: AdminPolicyPage,
        make: impl FnOnce(F, String) -> crate::core::AdminRequest,
    ) -> Response {
        let f = match parse_form(form) {
            Ok(f) => f,
            Err(r) => return r,
        };
        let csrf = f.csrf().to_string();
        let make = |actor| make(f, actor);
        admin_form_page(state, headers, &csrf, redirect, make, error_page).await
    }

    /// Console → add a K/D/X-line (admin). Runs through the core so it enforces
    /// and disconnects matching sessions exactly like oper KLINE.
    pub async fn console_add_ban(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<BanForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        admin_policy_form(
            &state,
            &headers,
            form,
            "/console/bans",
            AdminPolicyPage::ServerBans,
            |f, actor| crate::core::AdminRequest::AddServerBan {
                mask: f.mask,
                kind: f.kind,
                reason: f.reason,
                actor,
            },
        )
        .await
    }

    /// Console → remove a K/D/X-line (admin).
    pub async fn console_remove_ban(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<BanDeleteForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        admin_policy_form(
            &state,
            &headers,
            form,
            "/console/bans",
            AdminPolicyPage::ServerBans,
            |f, actor| crate::core::AdminRequest::RemoveServerBan {
                expected_id: None,
                mask: f.mask,
                kind: f.kind,
                actor,
            },
        )
        .await
    }

    /// Console → unregister a channel (admin), like ChanServ DROP.
    pub async fn console_drop_channel(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<DropChannelForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        admin_policy_form(
            &state,
            &headers,
            form,
            "/console/admin/channels",
            AdminPolicyPage::RegisteredChannels,
            |f, actor| crate::core::AdminRequest::DropChannel {
                channel: f.channel,
                actor,
            },
        )
        .await
    }

    #[derive(Deserialize)]
    pub struct DisconnectForm {
        csrf: String,
        #[serde(default)]
        reason: String,
    }

    #[allow(clippy::result_large_err)] // Err is the standard full problem Response
    fn parse_disconnect_form(
        connection_id: u64,
        form: Result<axum::Form<DisconnectForm>, axum::extract::rejection::FormRejection>,
    ) -> Result<(String, String), Response> {
        if connection_id == 0 {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                "Invalid live-connection id",
                None,
            ));
        }
        let form = parse_form(form)?;
        let reason = validate_disconnect_reason(form.reason)?;
        Ok((form.csrf, reason))
    }

    /// Render one bounded live-connection page. `own` forces the account filter
    /// for self-service and also includes the caller's capped durable browser
    /// logins.
    async fn render_sessions_page(
        state: &AppState,
        headers: &axum::http::HeaderMap,
        account: String,
        own: bool,
        query: ValidatedLiveConnectionQuery,
        error: Option<String>,
    ) -> Response {
        let csrf = session_token(headers, state.secure_cookies)
            .map(|s| state.csrf_token(&s))
            .unwrap_or_default();
        let page =
            list_live_connections(state, query.core_query(own.then_some(account.as_str()))).await;
        let (sessions, next_before_id, mut error) = match page {
            Ok(page) => (
                page.entries
                    .into_iter()
                    .map(|connection| SessionRow {
                        id: connection.id,
                        nick: connection.nick,
                        user: connection.user,
                        host: connection.host,
                        account: connection.account,
                        oper: connection.oper,
                        transport: connection.transport.as_str(),
                        connected_at: e6irc_proto::time::server_time(connection.connected_at),
                        idle_seconds: connection.idle_seconds,
                        channels: connection.channels.join(", "),
                    })
                    .collect(),
                page.next_before_id,
                error,
            ),
            // Surface a snapshot failure as the banner rather than a blank page.
            Err(message) => (Vec::new(), None, Some(error.unwrap_or(message))),
        };
        let browser_sessions = if own {
            let current = session_token(headers, state.secure_cookies);
            match crate::db::list_web_sessions(pool_of(state), &account, current.as_deref()).await {
                Ok(rows) => rows
                    .into_iter()
                    .map(|row| BrowserSessionRow {
                        id: row.id,
                        method: row.provider.map_or_else(
                            || "Local password".into(),
                            |provider| format!("OpenID Connect · {provider}"),
                        ),
                        user_agent: row.user_agent.unwrap_or_else(|| "Unknown browser".into()),
                        created: row.created_at,
                        expires: row.expires_at,
                        current: row.current,
                    })
                    .collect(),
                Err(database_error) => {
                    eprintln!("console: browser session list failed: {database_error}");
                    if error.is_none() {
                        error = Some("Browser session storage is unavailable.".into());
                    }
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };
        let (active, title, hint, disconnect_action) = if own {
            (
                "my-sessions",
                "Your sessions",
                "Durable browser logins and live IRC connections authenticated to your account. Disconnecting a live connection targets its immutable connection ID.",
                "/console/my-sessions",
            )
        } else {
            (
                "sessions",
                "Live connections",
                "Bounded, newest-first registered IRC connections across TCP, TLS, WebSocket, and the local in-process network.",
                "/console/sessions",
            )
        };
        let nick_filter = query.nick.unwrap_or_default();
        let account_filter = query.account.unwrap_or_default();
        let transport_filter = query
            .transport
            .map(crate::core::ConnectionTransport::as_str)
            .unwrap_or_default()
            .to_owned();
        let oper_filter = query.oper.map(|oper| oper.to_string()).unwrap_or_default();
        render_private(ConsoleSessions {
            shell: console_shell(state, account, csrf, active),
            title,
            hint,
            disconnect_action,
            sessions,
            has_filters: !nick_filter.is_empty()
                || !account_filter.is_empty()
                || !transport_filter.is_empty()
                || !oper_filter.is_empty(),
            has_cursor: query.before_id.is_some(),
            nick_filter,
            account_filter,
            transport_filter,
            oper_filter,
            limit: query.page_size.value(),
            next_before_id,
            show_browser_sessions: own,
            show_account_filter: !own,
            browser_sessions,
            error,
        })
    }

    #[allow(clippy::result_large_err)] // Err is the standard full problem Response
    fn default_live_connection_query() -> Result<ValidatedLiveConnectionQuery, Response> {
        validate_live_connection_query(LiveConnectionQueryParams::default(), 50)
    }

    async fn sessions_error_page(
        state: &AppState,
        headers: &axum::http::HeaderMap,
        account: String,
        own: bool,
        message: String,
    ) -> Response {
        let query = match default_live_connection_query() {
            Ok(query) => query,
            Err(response) => return response,
        };
        render_sessions_page(state, headers, account, own, query, Some(message)).await
    }

    /// Console → bounded live connection directory (admin-gated).
    pub async fn console_sessions(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        AdminPageActor { account, .. }: AdminPageActor,
        Query(params): Query<LiveConnectionQueryParams>,
    ) -> Response {
        let query = match validate_live_connection_query(params, 50) {
            Ok(query) => query,
            Err(response) => return response,
        };
        render_sessions_page(&state, &headers, account, false, query, None).await
    }

    /// Console → disconnect an exact live connection (admin), like oper KILL
    /// after its nick has resolved to one immutable connection.
    pub async fn console_disconnect_session(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        Path(connection_id): Path<u64>,
        form: Result<axum::Form<DisconnectForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let (csrf, reason) = match parse_disconnect_form(connection_id, form) {
            Ok(parsed) => parsed,
            Err(response) => return response,
        };
        let make = |actor| crate::core::AdminRequest::DisconnectConnection {
            connection_id,
            reason,
            actor,
        };
        match run_admin_form(&state, &headers, &csrf, "/console/sessions", make).await {
            Ok(response) => response,
            Err((account, message)) => {
                sessions_error_page(&state, &headers, account, false, message).await
            }
        }
    }

    /// Console → the caller's capped browser sessions and bounded live
    /// connections.
    pub async fn console_my_sessions(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        Query(params): Query<OwnLiveConnectionQueryParams>,
    ) -> Response {
        let (account, _) = match page_actor(&state, &headers, false).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        let query = match validate_live_connection_query(params.into(), 50) {
            Ok(query) => query,
            Err(response) => return response,
        };
        render_sessions_page(&state, &headers, account, true, query, None).await
    }

    /// Console → disconnect one exact live connection only if it remains owned
    /// by the caller.
    pub async fn console_disconnect_own_session(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        Path(connection_id): Path<u64>,
        form: Result<axum::Form<DisconnectForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let (csrf, reason) = match parse_disconnect_form(connection_id, form) {
            Ok(parsed) => parsed,
            Err(response) => return response,
        };
        let account = match require_form_actor(&state, &headers, &csrf).await {
            Ok(account) => account,
            Err(response) => return response,
        };
        let request = crate::core::AdminRequest::DisconnectOwnConnection {
            connection_id,
            reason,
            account: account.clone(),
        };
        match core_action(&state, request).await {
            Ok(_) => Redirect::to("/console/my-sessions").into_response(),
            Err(message) => sessions_error_page(&state, &headers, account, true, message).await,
        }
    }

    async fn browser_session_error(
        state: &AppState,
        headers: &axum::http::HeaderMap,
        account: String,
        message: &'static str,
    ) -> Response {
        sessions_error_page(state, headers, account, true, message.to_owned()).await
    }

    /// Console → revoke one durable browser session owned by the caller.
    pub async fn console_revoke_browser_session(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        Path(id): Path<i64>,
        form: Result<axum::Form<AccountDeleteForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let (account, _) = match account_form_actor(&state, &headers, form).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        let current = session_token(&headers, state.secure_cookies);
        match crate::db::delete_web_session_by_id(pool_of(&state), &account, id, current.as_deref())
            .await
        {
            Ok(Some(false)) => Redirect::to("/console/my-sessions").into_response(),
            Ok(Some(true)) => redirect_signed_out(&state),
            Ok(None) => {
                browser_session_error(&state, &headers, account, "No such browser session.").await
            }
            Err(error) => {
                eprintln!("console: browser session revoke failed: {error}");
                browser_session_error(
                    &state,
                    &headers,
                    account,
                    "Browser session storage is unavailable.",
                )
                .await
            }
        }
    }

    /// Console → revoke every other browser login while preserving the session
    /// whose CSRF token authorized the form.
    pub async fn console_revoke_other_browser_sessions(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<AccountDeleteForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let (account, _) = match account_form_actor(&state, &headers, form).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        let current = session_token(&headers, state.secure_cookies)
            .expect("form actor requires a cookie session");
        match crate::db::delete_other_web_sessions(pool_of(&state), &account, &current).await {
            Ok(_) => Redirect::to("/console/my-sessions").into_response(),
            Err(error) => {
                eprintln!("console: other browser session revoke failed: {error}");
                browser_session_error(
                    &state,
                    &headers,
                    account,
                    "Browser session storage is unavailable.",
                )
                .await
            }
        }
    }

    async fn owned_bridge(
        state: &AppState,
        account: &str,
        name: &str,
    ) -> Result<crate::db::BncNetworkRow, Response> {
        match crate::db::get_bnc_network(pool_of(state), account, name).await {
            Ok(Some(row)) if row.kind.is_bridge() => Ok(row),
            Ok(Some(_)) => Err(problem(
                StatusCode::BAD_REQUEST,
                "Not a bridge",
                Some("IRC networks are managed on the BNC networks page"),
            )),
            Ok(None) => Err(problem(StatusCode::NOT_FOUND, "No such bridge", None)),
            Err(error) => Err(super::device::admin_db_error("bridge fetch", error)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn console_bridge_edit_page(
        state: &AppState,
        account: String,
        csrf: String,
        row: crate::db::BncNetworkRow,
        addr: String,
        nick: String,
        autojoin: String,
        error: Option<String>,
    ) -> Response {
        let Some(meta) = bridge_platform_meta(row.kind) else {
            return problem(StatusCode::BAD_REQUEST, "Not a bridge", None);
        };
        render_private(ConsoleBridgeEdit {
            shell: console_shell(state, account, csrf, "integrations"),
            name: row.name,
            platform: meta.name,
            needs_nick: meta.needs_nick,
            needs_account: meta.needs_account,
            account_label: meta.account_label,
            password_label: meta.password_label,
            addr,
            addr_required: meta.addr_required,
            nick,
            autojoin,
            has_sasl_account: row.sasl_account.is_some(),
            has_sasl_password: row.sasl_password_sealed.is_some(),
            can_store_secrets: state.secret_key.is_some(),
            error,
        })
    }

    /// Console → Integrations: edit one account-owned bridge. Stored secrets
    /// are represented only by presence indicators and are never rendered.
    pub async fn console_edit_bridge(
        State(state): State<Arc<AppState>>,
        AdminPageActor { account, csrf }: AdminPageActor,
        Path(name): Path<String>,
    ) -> Response {
        let row = match owned_bridge(&state, &account, &name).await {
            Ok(row) => row,
            Err(response) => return response,
        };
        console_bridge_edit_page(
            &state,
            account,
            csrf,
            row.clone(),
            row.addr,
            row.nick,
            row.autojoin.join(", "),
            None,
        )
    }

    /// Validate and atomically replace one account-owned bridge's mutable
    /// endpoint, identity, channel list, and any explicitly supplied tokens.
    /// Blank token inputs preserve the encrypted stored value.
    pub async fn console_update_bridge(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        Path(name): Path<String>,
        form: Result<axum::Form<BridgeEditFormFields>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let (account, form) = match admin_form_actor(&state, &headers, form).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        let registry = require_registry!(state);
        let form = form.connection;
        let autojoin: Vec<String> = form
            .autojoin
            .split(',')
            .map(str::trim)
            .filter(|channel| !channel.is_empty())
            .map(str::to_string)
            .collect();
        let account_secret = (!form.sasl_account.is_empty()).then_some(form.sasl_account.as_str());
        let password_secret =
            (!form.sasl_password.is_empty()).then_some(form.sasl_password.as_str());
        let credentials = if account_secret.is_none() && password_secret.is_none() {
            NetworkCredentialUpdate::Keep
        } else {
            NetworkCredentialUpdate::Set {
                account: account_secret,
                password: password_secret,
            }
        };
        let result = update_network_core(
            &state,
            registry,
            &account,
            &name,
            EditableNetworkKind::Bridge,
            &form.addr,
            true,
            &form.nick,
            None,
            &autojoin,
            credentials,
        )
        .await;
        let error = match result {
            Ok(()) => return Redirect::to("/console/integrations").into_response(),
            Err(error) => error.message(),
        };
        let row = match owned_bridge(&state, &account, &name).await {
            Ok(row) => row,
            Err(response) => return response,
        };
        let csrf = session_token(&headers, state.secure_cookies)
            .map(|session| state.csrf_token(&session))
            .unwrap_or_default();
        console_bridge_edit_page(
            &state,
            account,
            csrf,
            row,
            form.addr,
            form.nick,
            form.autojoin,
            Some(error),
        )
    }

    /// Console → Integrations: add a bridge (admin). Maps the platform form onto
    /// `CreateNetwork` and reuses `create_network_core` (schema, per-kind secret
    /// sealing, feature-gated driver construction) — so a console-created bridge
    /// and a config-file one run through the exact same path. Owned by the
    /// creating admin's account.
    pub async fn console_add_bridge(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<BridgeFormFields>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let (account, f) = match admin_form_actor(&state, &headers, form).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        let Some(registry) = &state.bnc_registry else {
            let msg = "The bouncer is not enabled on this server.".to_string();
            return console_integrations_error(&state, &headers, account, msg).await;
        };
        let Some(kind) = crate::config::NetworkKind::from_db_str(&f.kind).filter(|k| k.is_bridge())
        else {
            let msg = format!("'{}' is not a bridge platform.", f.kind);
            return console_integrations_error(&state, &headers, account, msg).await;
        };
        // Pre-check the build feature so the banner names it specifically.
        if !kind_feature_available(kind) {
            let msg = format!(
                "This server was not built with the {} feature — rebuild with --features {}.",
                f.kind, f.kind
            );
            return console_integrations_error(&state, &headers, account, msg).await;
        }
        let opt = |s: String| if s.is_empty() { None } else { Some(s) };
        let conn = f.connection;
        let req = CreateNetwork {
            kind,
            name: f.name,
            addr: conn.addr,
            tls: true,
            nick: conn.nick,
            realname: None,
            autojoin: conn
                .autojoin
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
            sasl_account: opt(conn.sasl_account),
            sasl_password: opt(conn.sasl_password),
        };
        if let Err(error) = create_network_core(&state, registry, &account, &req).await {
            return console_integrations_error(&state, &headers, account, error.message()).await;
        }
        Redirect::to("/console/integrations").into_response()
    }

    /// Console → Integrations: remove one of the admin's own bridges.
    pub async fn console_delete_bridge(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<BridgeDeleteFields>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let (account, f) = match admin_form_actor(&state, &headers, form).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        let registry = require_registry!(state);
        if let Err(error) = delete_network_core(
            &state,
            registry,
            &account,
            &f.name,
            EditableNetworkKind::Bridge,
        )
        .await
        {
            return console_integrations_error(&state, &headers, account, error.message()).await;
        }
        Redirect::to("/console/integrations").into_response()
    }

    /// Pause or resume one of the administrator's account-owned bridges while
    /// retaining its encrypted configuration and detached backlog.
    pub async fn console_toggle_bridge(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<BridgeToggleFields>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let (account, form) = match admin_form_actor(&state, &headers, form).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        let registry = require_registry!(state);
        let Some(enabled) = toggle_target(&form.enabled) else {
            return invalid_toggle_response();
        };
        if let Err(error) =
            set_network_enabled_core(&state, registry, &account, &account, &form.name, enabled)
                .await
        {
            return console_integrations_error(&state, &headers, account, error.message()).await;
        }
        Redirect::to("/console/integrations").into_response()
    }

    #[derive(Template)]
    #[template(path = "device.html")]
    struct Device {
        csrf: String,
        /// Set after a POST: the outcome message shown above the form.
        outcome: Option<String>,
        /// Styles the outcome as success vs failure.
        approved: bool,
    }

    /// The RFC 8628 verification page `device_start` advertises as
    /// `verification_uri`: the signed-in user types the code shown on the
    /// device. Cookie-authenticated; unauthenticated visitors go to `/login`
    /// (and can come back after signing in).
    pub async fn device_page(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
    ) -> Response {
        let Ok(_account) = authenticate(&state, &headers).await else {
            return Redirect::to("/login").into_response();
        };
        let csrf = session_token(&headers, state.secure_cookies)
            .map(|s| state.csrf_token(&s))
            .unwrap_or_default();
        render_auth(Device {
            csrf,
            outcome: None,
            approved: false,
        })
    }

    /// The `/device` form (urlencoded): code + CSRF token as form fields.
    #[derive(Deserialize)]
    pub struct DeviceFormFields {
        user_code: String,
        csrf: String,
    }

    /// Approve a device code from the verification page's form; re-renders
    /// the page with the outcome.
    pub async fn approve_device_form(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<DeviceFormFields>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let Ok(account) = authenticate(&state, &headers).await else {
            return Redirect::to("/login").into_response();
        };
        let Some(session) = session_token(&headers, state.secure_cookies) else {
            return problem(StatusCode::UNAUTHORIZED, "Session required", None);
        };
        let axum::Form(fields) = match form {
            Ok(f) => f,
            Err(r) => return problem(StatusCode::BAD_REQUEST, "Bad form", Some(&r.to_string())),
        };
        if !state.csrf_valid(&session, &fields.csrf) {
            return problem(StatusCode::FORBIDDEN, "Bad CSRF token", None);
        }
        let (outcome, approved) =
            match super::device::approve_user_code(&state, &account, &fields.user_code).await {
                Ok(true) => ("Device approved — you can return to it now.", true),
                Ok(false) => (
                    "No pending device with that code — check it and try again.",
                    false,
                ),
                Err(e) => {
                    eprintln!("http: device approve failed: {e}");
                    (
                        "Approval storage is temporarily unavailable — try again.",
                        false,
                    )
                }
            };
        render_auth(Device {
            csrf: state.csrf_token(&session),
            outcome: Some(outcome.to_string()),
            approved,
        })
    }

    fn render<T: Template>(t: T) -> Response {
        match t.render() {
            Ok(html) => {
                let mut response = Html(html).into_response();
                security_headers(response.headers_mut());
                response
            }
            Err(e) => {
                eprintln!("template render error: {e}");
                problem(StatusCode::INTERNAL_SERVER_ERROR, "Template error", None)
            }
        }
    }

    /// Like [`render`], plus private-page caching and script policy. The console
    /// has one same-origin runtime (`/console.js`) and no inline JavaScript, so
    /// every personalized page can carry a useful CSP in every build. Inline
    /// styles remain necessary for the server-rendered traffic bars.
    fn render_private<T: Template>(template: T) -> Response {
        render_with_security_headers(
            template,
            "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        )
    }

    /// Render a template with private-page caching and the shared security
    /// headers (no-store, frame-deny, no-referrer). `csp` is the only thing
    /// that varies between page families.
    fn render_with_security_headers<T: Template>(template: T, csp: &'static str) -> Response {
        let mut response = render(template);
        if response.status().is_success() {
            let headers = response.headers_mut();
            no_store(headers);
            headers.insert(
                header::CONTENT_SECURITY_POLICY,
                csp.parse().expect("static header"),
            );
            headers.insert(
                header::X_FRAME_OPTIONS,
                "DENY".parse().expect("static header"),
            );
            headers.insert(
                header::REFERRER_POLICY,
                "no-referrer".parse().expect("static header"),
            );
        }
        response
    }

    fn render_auth<T: Template>(template: T) -> Response {
        let mut response = render_with_security_headers(
            template,
            "default-src 'none'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        );
        if response.status().is_success() {
            response.headers_mut().insert(
                header::X_CONTENT_TYPE_OPTIONS,
                "nosniff".parse().expect("static header"),
            );
        }
        response
    }

    #[cfg(test)]
    mod bootstrap_helper_tests {
        use super::*;

        #[test]
        fn browser_state_cookie_is_exact_constant_time_input() {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                header::COOKIE,
                "other=x; state=exact-value".parse().unwrap(),
            );
            assert!(browser_state_matches(&headers, "state", "exact-value"));
            assert!(!browser_state_matches(&headers, "state", "exact-valuE"));
            assert!(!browser_state_matches(&headers, "state", "short"));
            assert!(!browser_state_matches(&headers, "missing", "exact-value"));
            assert_eq!(bootstrap_state_cookie_name(false), "e6irc_bootstrap_state");
            assert_eq!(
                bootstrap_state_cookie_name(true),
                "__Host-e6irc_bootstrap_state"
            );
        }

        #[test]
        fn authenticated_redirect_sets_session_and_expires_browser_state() {
            for secure in [false, true] {
                let response =
                    authenticated_redirect("session-token", "/console", "state-cookie", secure);
                assert_eq!(response.status(), StatusCode::SEE_OTHER);
                assert_eq!(
                    response.headers().get(header::LOCATION).unwrap(),
                    "/console"
                );
                let cookies: Vec<_> = response
                    .headers()
                    .get_all(header::SET_COOKIE)
                    .iter()
                    .map(|value| value.to_str().unwrap())
                    .collect();
                assert_eq!(cookies.len(), 2);
                assert!(cookies[0].contains("session-token"));
                assert!(cookies[0].contains("HttpOnly"));
                assert!(cookies[1].starts_with("state-cookie=;"));
                assert!(cookies[1].contains("Max-Age=0"));
                assert_eq!(cookies[0].contains("; Secure"), secure);
                assert_eq!(cookies[1].contains("; Secure"), secure);
            }
        }

        #[test]
        fn bootstrap_digest_is_stable_and_token_specific() {
            let digest = super::super::bootstrap_token_digest("one-time-secret");
            assert_eq!(
                digest,
                super::super::bootstrap_token_digest("one-time-secret")
            );
            assert_ne!(digest, super::super::bootstrap_token_digest("other-secret"));
            assert_eq!(digest.len(), 32);
        }
    }

    #[cfg(test)]
    mod network_form_tests {
        use super::*;

        fn fields(preset: &str) -> NetworkFormFields {
            NetworkFormFields {
                csrf: "token".into(),
                preset: preset.into(),
                name: "stale name".into(),
                addr: "stale.example:6667".into(),
                nick: "alice".into(),
                tls: None,
                autojoin: "#rust, #e6irc".into(),
                realname: String::new(),
                sasl_account: String::new(),
                sasl_password: String::new(),
            }
        }

        #[test]
        fn preset_owns_safe_id_endpoint_and_tls_defaults() {
            let mut submitted = fields("libera");
            submitted.apply_preset().expect("known preset");
            let request = submitted.into_resolved_create();
            assert_eq!(request.name, "libera");
            assert_eq!(request.addr, "irc.libera.chat:6697");
            assert!(request.tls);
            assert_eq!(request.autojoin, ["#rust", "#e6irc"]);
        }

        #[test]
        fn resolved_preset_values_are_the_values_rerendered_after_an_error() {
            let mut submitted = fields("oftc");
            submitted.apply_preset().expect("known preset");
            let view = NetworkFormView::submitted(&submitted);
            assert_eq!(view.preset, "oftc");
            assert_eq!(view.name, "oftc");
            assert_eq!(view.addr, "irc.oftc.net:6697");
            assert!(view.tls);
        }

        #[test]
        fn unknown_preset_is_not_silently_treated_as_custom() {
            let error = fields("invented")
                .apply_preset()
                .expect_err("unknown preset must fail");
            assert!(error.message().contains("Unknown IRC network preset"));
        }
    }
}

#[cfg(test)]
mod composer_tests {
    use super::composer_to_irc;

    #[test]
    fn composer_json_form_becomes_privmsg() {
        let frame = r##"{"target":"#rust","message":"hi there","HEADERS":{}}"##;
        assert_eq!(composer_to_irc(frame), "PRIVMSG #rust :hi there");
    }

    #[test]
    fn raw_prefix_sends_literally() {
        let frame = r##"{"target":"#rust","message":"/raw WHOIS bob"}"##;
        assert_eq!(composer_to_irc(frame), "WHOIS bob");
    }

    #[test]
    fn message_without_target_is_sent_as_is() {
        let frame = r#"{"message":"JOIN #x"}"#;
        assert_eq!(composer_to_irc(frame), "JOIN #x");
    }

    #[test]
    fn non_json_frame_is_relayed_unchanged() {
        assert_eq!(composer_to_irc("PRIVMSG #c :raw"), "PRIVMSG #c :raw");
    }

    #[test]
    fn slash_commands_map_to_irc() {
        use super::slash_to_irc;
        assert_eq!(slash_to_irc("hello", "#c"), "PRIVMSG #c :hello");
        assert_eq!(
            slash_to_irc("/me waves", "#c"),
            "PRIVMSG #c :\u{1}ACTION waves\u{1}"
        );
        assert_eq!(slash_to_irc("/join #other", "#c"), "JOIN #other");
        assert_eq!(slash_to_irc("/part", "#c"), "PART ");
        assert_eq!(slash_to_irc("/nick bob", "#c"), "NICK bob");
        assert_eq!(
            slash_to_irc("/topic new topic", "#c"),
            "TOPIC #c :new topic"
        );
        assert_eq!(slash_to_irc("/msg bob hi bob", "#c"), "PRIVMSG bob :hi bob");
        assert_eq!(slash_to_irc("/raw WHOIS bob", "#c"), "WHOIS bob");
        // unknown slash-command passes through (server answers 421)
        assert_eq!(slash_to_irc("/frobnicate x", "#c"), "FROBNICATE x");
    }
}

#[cfg(test)]
mod cookie_tests {
    use super::{
        clear_session_cookie, login_state_cookie_name, oidc_state_cookie_name, session_cookie,
        session_cookie_name,
    };

    #[test]
    fn secure_cookies_use_host_prefix() {
        // The `__Host-` prefix is what pins the cookie to the exact host with
        // Secure+Path=/ and no Domain — dropping it would reopen fixation.
        assert_eq!(session_cookie_name(true), "__Host-e6irc_session");
        assert_eq!(oidc_state_cookie_name(true), "__Host-e6irc_oidc_state");
        assert_eq!(login_state_cookie_name(true), "__Host-e6irc_login_state");
        // Plain-HTTP dev (no TLS) can't use `__Host-` (it requires Secure).
        assert_eq!(session_cookie_name(false), "e6irc_session");
        assert_eq!(oidc_state_cookie_name(false), "e6irc_oidc_state");
        assert_eq!(login_state_cookie_name(false), "e6irc_login_state");
    }

    #[test]
    fn clear_matches_setter_name_and_flags() {
        // A `__Host-` cookie is only cleared by a Set-Cookie that repeats the
        // name, Secure, and Path=/ — otherwise the browser keeps the session.
        let secure = clear_session_cookie(true);
        assert!(secure.starts_with("__Host-e6irc_session="), "{secure}");
        assert!(secure.contains("; Secure"), "{secure}");
        assert!(secure.contains("; Path=/"), "{secure}");
        assert!(secure.contains("; Max-Age=0"), "{secure}");
        // The `__Host-` prefix forbids a Domain attribute.
        assert!(!secure.contains("Domain"), "{secure}");
        // Insecure variant drops Secure but keeps the same name it set.
        let insecure = clear_session_cookie(false);
        assert!(insecure.starts_with("e6irc_session="), "{insecure}");
        assert!(!insecure.contains("Secure"), "{insecure}");

        let setter = session_cookie("opaque", true);
        assert!(
            setter.starts_with("__Host-e6irc_session=opaque"),
            "{setter}"
        );
        assert!(setter.contains("; Secure"), "{setter}");
        assert!(setter.contains("; HttpOnly"), "{setter}");
        assert!(setter.contains("; SameSite=Lax"), "{setter}");
    }
}

#[cfg(test)]
mod credential_input_tests {
    use super::{credential_input_error, password_input_error};

    #[test]
    fn credential_fields_are_bounded_before_argon2() {
        assert_eq!(credential_input_error("alice", "secret"), None);
        assert!(credential_input_error("", "secret").is_some());
        assert!(credential_input_error(&"a".repeat(65), "secret").is_some());
        assert!(password_input_error("").is_some());
        assert!(password_input_error(&"p".repeat(513)).is_some());
        assert_eq!(password_input_error(&"p".repeat(512)), None);
    }
}

#[cfg(test)]
mod client_ip_tests {
    use super::client_ip;

    fn xff(value: &str) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-forwarded-for", value.parse().unwrap());
        h
    }
    fn ip(s: &str) -> std::net::IpAddr {
        s.parse().unwrap()
    }
    fn net(s: &str) -> ipnet::IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn untrusted_peer_ignores_forwarded_header() {
        // A direct (untrusted) client can spoof X-Forwarded-For; we must use
        // the real socket peer, never the header, or rate limits are bypassed.
        let trusted = [net("10.0.0.0/8")];
        let got = client_ip(ip("203.0.113.7"), &xff("1.2.3.4"), &trusted);
        assert_eq!(got, ip("203.0.113.7"));
    }

    #[test]
    fn trusted_proxy_uses_rightmost_untrusted_forwarded_entry() {
        // Behind a trusted proxy, the client is the rightmost XFF entry that
        // isn't itself a trusted hop — a client-appended left entry can't
        // impersonate someone else.
        let trusted = [net("10.0.0.0/8")];
        let got = client_ip(
            ip("10.0.0.1"),
            &xff("9.9.9.9, 203.0.113.7, 10.0.0.2"),
            &trusted,
        );
        assert_eq!(got, ip("203.0.113.7"));
    }

    #[test]
    fn trusted_proxy_without_header_falls_back_to_peer() {
        let trusted = [net("10.0.0.0/8")];
        let got = client_ip(ip("10.0.0.1"), &axum::http::HeaderMap::new(), &trusted);
        assert_eq!(got, ip("10.0.0.1"));
    }

    #[test]
    fn all_forwarded_entries_trusted_falls_back_to_peer() {
        let trusted = [net("10.0.0.0/8")];
        let got = client_ip(ip("10.0.0.1"), &xff("10.0.0.9, 10.0.0.8"), &trusted);
        assert_eq!(got, ip("10.0.0.1"));
    }

    #[test]
    fn multiple_forwarded_headers_are_joined_in_order() {
        // A proxy that appends a *separate* X-Forwarded-For header rather than
        // merging: the client-supplied first header must not win over the
        // proxy's appended one. The real client (the appended header's rightmost
        // untrusted entry) is returned, not the spoofed 6.6.6.6 in the first.
        let trusted = [net("10.0.0.0/8")];
        let mut h = axum::http::HeaderMap::new();
        h.append("x-forwarded-for", "6.6.6.6".parse().unwrap());
        h.append("x-forwarded-for", "203.0.113.7, 10.0.0.2".parse().unwrap());
        assert_eq!(client_ip(ip("10.0.0.1"), &h, &trusted), ip("203.0.113.7"));
    }

    #[test]
    fn port_annotated_and_bracketed_forwarded_entries_are_parsed() {
        // Some proxies emit `ip:port` / `[ip6]:port`. A bare IpAddr parse would
        // reject these and skip past the real client to a spoofable entry or the
        // proxy IP; the resolver must recover the address.
        let trusted = [net("10.0.0.0/8")];
        // Rightmost non-trusted entry is a port-annotated IPv4 client.
        assert_eq!(
            client_ip(
                ip("10.0.0.1"),
                &xff("1.2.3.4, 203.0.113.7:52833, 10.0.0.2"),
                &trusted
            ),
            ip("203.0.113.7"),
        );
        // Bracketed IPv6 with a port.
        assert_eq!(
            client_ip(
                ip("10.0.0.1"),
                &xff("[2001:db8::5]:443, 10.0.0.2"),
                &trusted
            ),
            ip("2001:db8::5"),
        );
        // Bracketed IPv6 with no port.
        assert_eq!(
            client_ip(ip("10.0.0.1"), &xff("[2001:db8::9]"), &trusted),
            ip("2001:db8::9"),
        );
        // A port-annotated *trusted* hop is still recognized as trusted (parsed,
        // then matched), so it's skipped rather than mis-returned as the client.
        assert_eq!(
            client_ip(ip("10.0.0.1"), &xff("203.0.113.7, 10.0.0.2:9000"), &trusted),
            ip("203.0.113.7"),
        );
    }
}

#[cfg(test)]
mod logout_tests {
    use super::*;
    use openidconnect::core::{CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey};
    use openidconnect::{JsonWebKeyId, PrivateSigningKey};

    const TEST_RSA_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvKIZ7REtlhJ+LVEBmTVqJ2wlJ1e+l0KGylITuLiHF185w4Bm
ulmkCtBoH6W7NqbXt3sgM6lKV1B50Za8JSz+m6cgMhO3fUmlxrhbVKh4s3N3oDz6
ERlRH6gDIfpLg4Tzow5gMNt2hFmFpWvntlEcqFX91BR6ZAV7zXV42V3pNtQhkBCA
7yKIOJFVd69gGwfQGXRTdUl8F8wX6JRrIrEfMpSz0bovUVlPCy6zqzU8v2mnEF5j
7PK/56b/CSci5ZQJD4e2XkAAR1DQJ/LX6kiKf4jT2l84VNsFp+0bxTt87IcGp/7m
Xq/MIFBqe1ww1Sso4lYWNS4TpBpH6aEv8kj6VQIDAQABAoIBABNy/kvWddYPpZFc
FRdcLcwPRzxpfGYBrr6tHEnzQsCK6byJ4G2t4O9ZgibjMmyl4r+REyaoeZkLm+fb
jB4kJ8NaRcRMCqMBJTXaW9ZcgYd1LBwqNVlufBIQw3PtJ/yRSIKjMJFRC4UFavV9
rPg8IEGODjwf+WeXNibeyh1VZL6pjtCW+SA5eo8HViYyu3qCwYycEXkb/BxGVhNe
lZgHkyMQItzZdVppWJCEtnOUmapsyzXta9cSlw/TduPDlSdaBYXrFS/Lrf5EKlXB
wechrH4KsZ/31wKw0fBtwt6XhQ6WBEH1pXUmgAaea5icacAAAQ1E0FCbuF4h2Vfd
7hq5HFkCgYEA4YsgmuBNjx/Waws2qfdjyUB6LDmyMobdV+Se+ZHr8ppY428VNHdG
tLOFzA3hblx94wJoS8RWnugqGkwy1kj+eKbPApm19vtefTR8L5pnenphCt/FJKHt
ZIFaPh26+8fNeraks951l03hbNsh9e5+wRRPc/dTSMNXuvtkiUsfEE0CgYEA1hsD
ZsGNMr0b0cTCEc2EycDUkWZAV4bICXoDN16Vt3UwXbKi7SlIfG/qLqD4y+nXXnT3
XORkBAm014HrsWX5ulmtUr0g09okjlbN96hKeTqOm9eMxUQQQtq4SP+Kvy0weW1h
/F7e+0Km006Qw+W55m9w6HvaPnsbDSUfTOzr1ikCgYEAqCIF6U6ioroyJlQSqPux
2HoHWWadT4s3/+h/Fj7QbGbhMpJBdX4hKF3XtPj3/0RV19+YjjrL8+PQVxBMqW96
u8hl82NQwdA7bQyuMvJgh24pX2jW1usbQ9wlwL57AGy+4ea7uxZwBJ3bGUH1/BaR
SS/x1todrNVqVgpHtQ1aF9UCgYBSaJlZjrwTQHiZt/resVUf9qmawVmYltcd1qmw
QSatM10HY3+UeyRcSRNBGVJJ4lq0D586UOoyJ65EmMwoPtDtKiEtTIB7KmaRptWm
Mk9f8+r6DvAu6XC82sS9zCYSSYlz42copTd8TH47rOzJif2QtWonAazSCb4yxAwV
JsfraQKBgFoNm/o5GId1sqDOqGofHzsv4ESXfxFN/fPfFeaetTDWDdxy6VZOJJGY
MwLJVyUtP7cOpP2iOixMg3DXCB8r2cs+ueh39qeHuPqaKh35teG07+RniASGsgNH
ELXcSQ+IOhrSANLPrHcXve6GfmpJx1m8A7Whc0RfbsjoBAmNuALv
-----END RSA PRIVATE KEY-----"#;

    fn base64url(data: &[u8]) -> String {
        e6irc_proto::base64::encode(data)
            .replace('+', "-")
            .replace('/', "_")
            .trim_end_matches('=')
            .to_string()
    }

    fn logout_token_with_type(
        payload: serde_json::Value,
        token_type: Option<&str>,
    ) -> (String, openidconnect::core::CoreJsonWebKey) {
        let key = CoreRsaPrivateSigningKey::from_pem(
            TEST_RSA_KEY,
            Some(JsonWebKeyId::new("logout-key".into())),
        )
        .expect("test RSA key");
        let algorithm = CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256;
        let mut header = serde_json::json!({"alg": "RS256", "kid": "logout-key"});
        if let Some(token_type) = token_type {
            header["typ"] = serde_json::Value::String(token_type.into());
        }
        let header = base64url(&serde_json::to_vec(&header).expect("header"));
        let payload = base64url(&serde_json::to_vec(&payload).expect("payload"));
        let input = format!("{header}.{payload}");
        let signature = key.sign(&algorithm, input.as_bytes()).expect("sign");
        (
            format!("{input}.{}", base64url(&signature)),
            key.as_verification_key(),
        )
    }

    fn logout_token(payload: serde_json::Value) -> (String, openidconnect::core::CoreJsonWebKey) {
        logout_token_with_type(payload, Some("logout+jwt"))
    }

    fn logout_test_provider() -> OidcProviderConfig {
        OidcProviderConfig {
            name: "shauth".into(),
            issuer_url: "https://auth.example".into(),
            client_id: "e6irc".into(),
            client_secret: "secret".into(),
            scopes: vec![],
            allowed_email_domains: vec![],
            end_session_endpoint: None,
            token_endpoint_auth_method: Default::default(),
        }
    }

    #[test]
    fn verifies_signed_backchannel_logout_contract() {
        let now = 1_800_000_000;
        let (raw, key) = logout_token(serde_json::json!({
            "iss": "https://auth.example",
            "aud": ["e6irc", "another-audience"],
            "sub": "subject-1",
            "sid": "session-1",
            "iat": now,
            "exp": now + 600,
            "jti": "logout-1",
            "events": { BACKCHANNEL_LOGOUT_EVENT: {} }
        }));
        let provider = logout_test_provider();
        let algorithm = CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256;
        let claims = verify_logout_token_with_metadata(
            &raw,
            &provider,
            std::slice::from_ref(&algorithm),
            std::slice::from_ref(&key),
            now,
        )
        .expect("valid logout token");
        assert_eq!(claims.sid.as_deref(), Some("session-1"));

        let payload = serde_json::json!({
            "iss": "https://auth.example",
            "aud": "e6irc",
            "sid": "session-1",
            "iat": now,
            "exp": now + 600,
            "jti": "logout-provider-type",
            "events": { BACKCHANNEL_LOGOUT_EVENT: {} }
        });
        for token_type in [None, Some("JWT")] {
            let (provider_token, provider_key) =
                logout_token_with_type(payload.clone(), token_type);
            verify_logout_token_with_metadata(
                &provider_token,
                &provider,
                std::slice::from_ref(&algorithm),
                std::slice::from_ref(&provider_key),
                now,
            )
            .expect("standard provider logout token type");
        }
        let (wrong_type, wrong_type_key) = logout_token_with_type(payload, Some("at+jwt"));
        assert!(
            verify_logout_token_with_metadata(
                &wrong_type,
                &provider,
                std::slice::from_ref(&algorithm),
                std::slice::from_ref(&wrong_type_key),
                now,
            )
            .is_err(),
            "a token explicitly typed for another protocol must be rejected"
        );

        let mut tampered = raw.into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        assert!(
            verify_logout_token_with_metadata(
                std::str::from_utf8(&tampered).expect("ASCII JWT"),
                &provider,
                std::slice::from_ref(&algorithm),
                std::slice::from_ref(&key),
                now,
            )
            .is_err()
        );
    }

    #[test]
    fn backchannel_logout_normalizes_and_validates_claims() {
        let now = 1_800_000_000;
        let provider = logout_test_provider();
        let algorithm = CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256;
        let verify = |payload: serde_json::Value| {
            let (raw, key) = logout_token(payload);
            verify_logout_token_with_metadata(
                &raw,
                &provider,
                std::slice::from_ref(&algorithm),
                std::slice::from_ref(&key),
                now,
            )
        };
        let base = |extra: serde_json::Value| {
            let mut v = serde_json::json!({
                "iss": "https://auth.example", "aud": "e6irc",
                "sid": "session-1", "iat": now, "jti": "j-1",
                "events": { BACKCHANNEL_LOGOUT_EVENT: {} }
            });
            v.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            v
        };

        // A1: an empty-string sub is dropped to None so revocation is not
        // over-constrained (Some("") would silently match no session).
        let claims = verify(base(serde_json::json!({"sub": ""}))).expect("empty sub ok with a sid");
        assert_eq!(claims.sub, None, "empty sub must normalize to None");
        assert_eq!(claims.sid.as_deref(), Some("session-1"));
        // A real value is passed through verbatim (must match what login stored).
        let claims = verify(base(serde_json::json!({"sub": "subject-1"}))).expect("ok");
        assert_eq!(claims.sub.as_deref(), Some("subject-1"));

        // A2: the backchannel-logout event MAY carry data — a non-empty object
        // is accepted, not just an exactly-empty one.
        assert!(
            verify(base(
                serde_json::json!({"events": { BACKCHANNEL_LOGOUT_EVENT: { "reason": "admin" } }})
            ))
            .is_ok(),
            "non-empty event object must be accepted"
        );

        // A7: a present azp must name this client.
        assert!(
            verify(base(serde_json::json!({"azp": "someone-else"}))).is_err(),
            "mismatched azp must be rejected"
        );
        assert!(
            verify(base(serde_json::json!({"azp": "e6irc"}))).is_ok(),
            "matching azp must be accepted"
        );

        // Blank sid AND blank sub → no identifier → rejected.
        let mut no_id = base(serde_json::json!({"sub": "  "}));
        no_id
            .as_object_mut()
            .unwrap()
            .insert("sid".into(), serde_json::json!("  "));
        assert!(verify(no_id).is_err(), "blank sid and sub must be rejected");
    }
}
