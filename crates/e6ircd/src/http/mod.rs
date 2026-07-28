//! HTTP layer: REST API (and later the web client backend), served
//! in-process by the same binary (DESIGN §12).

use std::collections::HashMap;
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

mod credentials;
mod device;
mod history;
pub(crate) mod networks;
mod oidc;
mod openapi;
mod ws;

use credentials::*;
use device::*;
use history::*;
use networks::*;
use oidc::*;
use openapi::*;
use ws::*;

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
    /// Shared connection-id allocator (with the TCP listeners).
    pub next_conn: std::sync::Arc<std::sync::atomic::AtomicU64>,
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
    pub secret_key: Option<std::sync::Arc<crate::secret::SecretKey>>,
    /// Accounts permitted to use the `/api/v1/admin` endpoints (rfc1459
    /// casefolded at startup). Empty = admin disabled.
    pub admin_accounts: std::collections::HashSet<String>,
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
    /// The per-IP connection cap, shared with the TCP listeners so IRC sessions
    /// opened over `/ws/irc` count against the same budget as raw-socket ones.
    pub(crate) conn_limiter: crate::net::ConnLimiter,
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
}

/// RFC 9457 problem+json error body.
/// Longest label accepted for an app password or personal access token. These
/// are stored in an unbounded `TEXT` column and shown back in the account UI, so
/// bound them like every other client-supplied field (the network fields cap at
/// 64/128/255) rather than accepting a multi-megabyte JSON body into storage.
pub(super) const MAX_LABEL_LEN: usize = 64;

/// Validate a client-supplied credential label: bounded and free of control
/// characters (which would corrupt the account UI / logs). Returns a ready 400
/// response when invalid, or `None` when the label is acceptable.
pub(super) fn validate_label(label: &str) -> Option<Response> {
    if label.chars().count() > MAX_LABEL_LEN {
        return Some(problem(
            StatusCode::BAD_REQUEST,
            "Label too long",
            Some(&format!("Labels are at most {MAX_LABEL_LEN} characters.")),
        ));
    }
    if label.chars().any(|c| c.is_control()) {
        return Some(problem(
            StatusCode::BAD_REQUEST,
            "Invalid label",
            Some("Labels must not contain control characters."),
        ));
    }
    None
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
    let response = next.run(request).await;
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

async fn readiness(State(state): State<Arc<AppState>>) -> Response {
    let core_ready = state.telemetry.core_is_fresh(Duration::from_secs(45));
    let database_ready = match &state.pool {
        Some(pool) => {
            let started = Instant::now();
            let ready = sqlx::query_scalar::<_, i32>("SELECT 1")
                .fetch_one(pool)
                .await
                .is_ok();
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

fn default_observability_minutes() -> u64 {
    60
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
    let minutes = query.minutes.clamp(1, 10_080);
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
            axum::Json(ObservabilityResponse { current, history }).into_response()
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
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.telemetry.prometheus(networks, connected),
    )
        .into_response()
}

pub fn router(state: Arc<AppState>) -> Router {
    let router = Router::new()
        .route("/healthz", get(async || "ok"))
        .route("/readyz", get(readiness))
        .route("/login", get(pages::login))
        .route("/auth/signed-out", get(pages::signed_out))
        .route("/auth/validation", get(pages::validation))
        .route("/auth/shauth/logout/complete", get(shauth_logout_complete))
        .route("/auth.css", get(pages::auth_styles))
        .route("/account", get(pages::account))
        .route("/console", get(pages::console))
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
        .route(
            "/console/networks/{name}",
            axum::routing::delete(pages::console_delete_network),
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
            "/console/integrations",
            get(pages::console_integrations).post(pages::console_add_bridge),
        )
        .route(
            "/console/integrations/delete",
            post(pages::console_delete_bridge),
        )
        .route("/console/bans", post(pages::console_add_ban))
        .route("/console/bans/delete", post(pages::console_remove_ban))
        .route("/console/channels/drop", post(pages::console_drop_channel))
        .route("/console/sessions", get(pages::console_sessions))
        .route("/console/sessions/kill", post(pages::console_kill_session))
        .route("/console/my-sessions", get(pages::console_my_sessions))
        .route(
            "/console/my-sessions/kill",
            post(pages::console_kill_own_session),
        )
        .route(
            "/device",
            get(pages::device_page).post(pages::approve_device_form),
        )
        .route("/account/networks", post(pages::add_network_form))
        .route(
            "/account/networks/{name}",
            axum::routing::delete(pages::delete_network_form),
        )
        .route("/api/v1/server", get(server_info))
        .route("/api/v1/openapi.json", get(openapi))
        .route("/api/v1/auth/app-passwords", post(create_app_password))
        .route("/api/v1/auth/oidc/{provider}/start", get(oidc_start))
        .route("/api/v1/auth/oidc/{provider}/sso", get(oidc_sso_start))
        .route("/api/v1/auth/oidc/{provider}/link", get(oidc_link_start))
        .route("/api/v1/auth/oidc/{provider}/callback", get(oidc_callback))
        .route(
            "/api/v1/auth/oidc/backchannel-logout",
            post(oidc_backchannel_logout),
        )
        .route(
            "/api/v1/auth/oidc/frontchannel-logout",
            get(oidc_frontchannel_logout),
        )
        .route("/api/v1/me/identities", get(me_identities))
        .route("/api/v1/auth/logout", post(logout).get(logout_sso))
        .route("/api/v1/auth/device/start", post(device_start))
        .route("/api/v1/auth/device/token", post(device_token))
        .route("/api/v1/auth/device/approve", post(device_approve))
        .route("/api/v1/me", get(me))
        .route(
            "/api/v1/me/tokens",
            get(me_tokens_list).post(create_api_token),
        )
        .route(
            "/api/v1/me/tokens/{id}",
            axum::routing::delete(me_tokens_revoke),
        )
        .route("/api/v1/me/read-markers", get(me_read_markers))
        .route("/api/v1/me/credentials", get(list_credentials))
        .route(
            "/api/v1/me/credentials/{id}",
            axum::routing::delete(revoke_credential),
        )
        .route(
            "/api/v1/me/networks",
            get(list_networks).post(create_network),
        )
        .route(
            "/api/v1/me/networks/{name}",
            axum::routing::delete(delete_network).patch(patch_network),
        )
        .route("/api/v1/me/networks/{name}/buffer", get(network_buffer))
        .route("/api/v1/history", get(history))
        .route("/api/v1/admin/accounts", get(admin_accounts))
        .route("/api/v1/admin/channels", get(admin_channels))
        .route("/api/v1/admin/bans", get(admin_server_bans))
        .route("/api/v1/admin/audit", get(admin_audit))
        .route("/api/v1/admin/stats", get(admin_stats))
        .route("/api/v1/admin/observability", get(admin_observability))
        .route("/api/v1/admin/metrics", get(admin_metrics))
        .route("/ws/irc", get(ws_irc))
        .route("/ws/ui", get(ws_ui));
    // With the `embed-web` feature the built web client (web/dist) is
    // baked into the binary and served at `/` and `/assets/*`; otherwise
    // the assets live on S3/CDN and only the API + WebSocket paths are
    // served here. (DESIGN §13.3)
    #[cfg(feature = "embed-web")]
    let router = router
        .route("/", get(web::index))
        .route("/htmx.min.js", get(web::htmx))
        .route("/ws.min.js", get(web::htmx_ws))
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

    #[derive(Default, Deserialize)]
    pub struct EntryQuery {
        sso: Option<String>,
    }

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
    /// public static file. An existing local session renders the client. A
    /// browser is sent through the provider's ordinary OpenID Connect
    /// authorization request. An existing provider session completes without
    /// prompting; otherwise the provider owns the credential prompt.
    pub async fn index(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        Query(query): Query<EntryQuery>,
    ) -> Response {
        match authenticate(&state, &headers).await {
            Ok(_) => serve("index.html"),
            Err(response) if response.status() != StatusCode::UNAUTHORIZED => response,
            Err(_) if query.sso.as_deref() == Some("none") => {
                Redirect::to("/login").into_response()
            }
            Err(_) if state.oidc_providers.len() == 1 => Redirect::temporary(&format!(
                "/api/v1/auth/oidc/{}/start",
                state.oidc_providers[0].name
            ))
            .into_response(),
            Err(_) => Redirect::to("/login").into_response(),
        }
    }

    pub async fn asset(axum::extract::Path(path): axum::extract::Path<String>) -> Response {
        serve(&format!("assets/{path}"))
    }

    /// Standalone htmx (copied into web/dist by the build) for the
    /// server-rendered askama pages, which aren't part of the Vite bundle.
    pub async fn htmx() -> Response {
        serve("htmx.min.js")
    }

    pub async fn htmx_ws() -> Response {
        serve("ws.min.js")
    }
}

/// Server-rendered HTML pages (askama). Complements the Vite/htmx chat
/// client with a login landing and a read-only user section.
mod pages {
    use super::*;
    use askama::Template;

    #[derive(Template)]
    #[template(path = "login.html")]
    struct Login {
        providers: Vec<String>,
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

    #[derive(Template)]
    #[template(path = "validation.html")]
    struct Validation {
        username: String,
        email: String,
        role: String,
        release: String,
        logout_url: String,
    }

    /// Login landing: one button per configured OIDC provider.
    pub async fn login(State(state): State<Arc<AppState>>) -> Response {
        let providers = state
            .oidc_providers
            .iter()
            .map(|p| p.name.clone())
            .collect();
        render_auth(Login { providers })
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
        let Some(pool) = &state.pool else {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "No database configured",
                None,
            );
        };
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

    struct NetworkView {
        name: String,
        addr: String,
        tls: bool,
        nick: String,
    }

    /// The account page's add-network form (urlencoded). `tls` is an
    /// HTML checkbox (`"on"` when checked, absent otherwise). The SASL pair and
    /// realname are optional text inputs that submit as empty strings when left
    /// blank, so `into_create` maps blank → `None`.
    #[derive(Deserialize)]
    pub struct NetworkFormFields {
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
        /// Build the `CreateNetwork` for an IRC upstream from the submitted form,
        /// treating a blank optional text input as absent. Shared by the account
        /// page and the console so the two forms map identically.
        fn into_create(self) -> CreateNetwork {
            let opt = |s: String| {
                let s = s.trim().to_string();
                (!s.is_empty()).then_some(s)
            };
            CreateNetwork {
                kind: crate::config::NetworkKind::Irc,
                name: self.name,
                addr: self.addr,
                tls: self.tls.as_deref() == Some("on"),
                nick: self.nick,
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

    struct CredView {
        kind: String,
        label: String,
        created: String,
    }

    #[derive(Template)]
    #[template(path = "account.html")]
    struct Account {
        account: String,
        csrf: String,
        /// Whether this account may reach the admin `/console` — controls the
        /// header link, so a non-admin is never shown a door that 403s.
        is_admin: bool,
        networks: Vec<NetworkView>,
        credentials: Vec<CredView>,
    }

    #[derive(Template)]
    #[template(path = "network_rows.html")]
    struct NetworkRows {
        csrf: String,
        networks: Vec<NetworkView>,
    }

    async fn network_views(pool: &PgPool, account: &str) -> Result<Vec<NetworkView>, Response> {
        crate::db::list_bnc_networks(pool, account)
            .await
            .map(|rows| {
                rows.into_iter()
                    .map(|n| NetworkView {
                        name: n.name,
                        addr: n.addr,
                        tls: n.tls,
                        nick: n.nick,
                    })
                    .collect()
            })
            .map_err(|e| {
                eprintln!("account: networks: {e}");
                problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Database unavailable",
                    None,
                )
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

    /// User section: the signed-in account's networks and credentials,
    /// with htmx forms to add/remove networks. Cookie-authenticated;
    /// unauthenticated visitors go to `/login`.
    pub async fn account(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
    ) -> Response {
        let Ok(account) = authenticate(&state, &headers).await else {
            return Redirect::to("/login").into_response();
        };
        let csrf = session_token(&headers, state.secure_cookies)
            .map(|s| state.csrf_token(&s))
            .unwrap_or_default();
        let pool = pool_of(&state);

        let networks = match network_views(pool, &account).await {
            Ok(n) => n,
            Err(r) => return r,
        };
        let credentials = match crate::db::list_credentials(pool, &account).await {
            Ok(rows) => rows
                .into_iter()
                .map(|(_, kind, label, created, _)| CredView {
                    kind,
                    label: label.unwrap_or_default(),
                    created,
                })
                .collect(),
            Err(e) => {
                eprintln!("account page: credentials: {e}");
                return problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Database unavailable",
                    None,
                );
            }
        };
        let is_admin = is_admin_account(&state, &account);
        render_private(Account {
            account,
            csrf,
            is_admin,
            networks,
            credentials,
        })
    }

    struct ChannelRow {
        name: String,
        founder: String,
    }
    struct BanRow {
        kind: String,
        mask: String,
        reason: String,
        set_by: String,
    }
    struct AuditRow {
        at: String,
        actor: String,
        action: String,
        target: String,
        detail: String,
    }

    #[derive(Template)]
    #[template(path = "console.html")]
    struct Console {
        // Shared console-shell fields (see `console_base.html`).
        account: String,
        csrf: String,
        is_admin: bool,
        active: &'static str,
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
        accounts: Vec<String>,
        channels: Vec<ChannelRow>,
        bans: Vec<BanRow>,
        audit: Vec<AuditRow>,
        /// An error banner shown at the top when a management action failed
        /// (e.g. an invalid ban mask). `None` on the plain GET.
        error: Option<String>,
    }

    /// Assemble the admin console view (all server-wide read data). `error` is a
    /// banner to show when re-rendering after a failed management action. Callers
    /// have already admin-gated the request.
    async fn console_build(
        state: &AppState,
        account: String,
        csrf: String,
        error: Option<String>,
    ) -> Result<Console, Response> {
        let pool = pool_of(state);
        let (stat_accounts, stat_channels, stat_server_bans) = crate::db::server_stats(pool)
            .await
            .map_err(|e| super::device::admin_db_error("server stats", e))?;
        let accounts = crate::db::list_accounts(pool)
            .await
            .map_err(|e| super::device::admin_db_error("account list", e))?;
        let channels = crate::db::list_registered_channels(pool)
            .await
            .map_err(|e| super::device::admin_db_error("channel list", e))?
            .into_iter()
            .map(|(name, founder)| ChannelRow { name, founder })
            .collect();
        let bans = crate::db::list_server_bans(pool)
            .await
            .map_err(|e| super::device::admin_db_error("server-ban list", e))?
            .into_iter()
            .map(|(mask, reason, set_by, kind)| BanRow {
                kind,
                mask,
                reason,
                set_by,
            })
            .collect();
        let audit = crate::db::list_audit_log(pool, 100)
            .await
            .map_err(|e| super::device::admin_db_error("audit log", e))?
            .into_iter()
            .map(|(actor, action, target, detail, at)| AuditRow {
                at,
                actor,
                action,
                target,
                detail,
            })
            .collect();
        let (networks, connected) = bnc_counts(state);
        let live = state.telemetry.snapshot(networks, connected);
        Ok(Console {
            account,
            csrf,
            is_admin: true,
            active: "overview",
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
            error,
        })
    }

    struct TrafficBar {
        inbound_height: u64,
        outbound_height: u64,
        age: String,
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
        http_requests: u64,
        database_requests: u64,
        bnc_connected: u64,
        bnc_networks: u64,
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
        bars: Vec<TrafficBar>,
        errors: Vec<ErrorView>,
        sampled_age: String,
        history_samples: usize,
    }

    #[derive(Template)]
    #[template(path = "console_monitoring.html")]
    struct ConsoleMonitoring {
        account: String,
        csrf: String,
        is_admin: bool,
        active: &'static str,
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

    async fn monitoring_view(state: &AppState) -> MonitoringView {
        let (networks, connected) = bnc_counts(state);
        let current = state.telemetry.snapshot(networks, connected);
        let pool = pool_of(state);
        let since_ms = current.sampled_at_ms.saturating_sub(60 * 60 * 1_000);
        let started = Instant::now();
        let (mut history, database_ready) =
            match crate::db::list_observability_samples(pool, since_ms, current.sampled_at_ms, 240)
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

        let deltas: Vec<(u64, u64, u64)> = history
            .windows(2)
            .map(|pair| {
                (
                    pair[1]
                        .irc_bytes_in_total
                        .saturating_sub(pair[0].irc_bytes_in_total),
                    pair[1]
                        .irc_bytes_out_total
                        .saturating_sub(pair[0].irc_bytes_out_total),
                    pair[1].sampled_at_ms,
                )
            })
            .rev()
            .take(48)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        let peak = deltas
            .iter()
            .map(|(inbound, outbound, _)| inbound.max(outbound))
            .copied()
            .max()
            .unwrap_or(1)
            .max(1);
        let bars = deltas
            .into_iter()
            .map(|(inbound, outbound, sampled_at)| TrafficBar {
                inbound_height: (inbound.saturating_mul(100) / peak).max(u64::from(inbound > 0)),
                outbound_height: (outbound.saturating_mul(100) / peak).max(u64::from(outbound > 0)),
                age: format_age(current.sampled_at_ms, sampled_at),
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
            http_requests: current.http_requests_total,
            database_requests: current.database_requests_total,
            bnc_connected: current.bnc_connected,
            bnc_networks: current.bnc_networks,
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
            bars,
            errors,
            sampled_age: format_age(current.sampled_at_ms, current.sampled_at_ms),
            history_samples: history.len().saturating_sub(1),
        }
    }

    pub async fn console_monitoring(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
    ) -> Response {
        let (account, csrf) = match page_actor(&state, &headers, true).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
        let view = monitoring_view(&state).await;
        render_private(ConsoleMonitoring {
            account,
            csrf,
            is_admin: true,
            active: "monitoring",
            view,
        })
    }

    pub async fn console_monitoring_panel(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
    ) -> Response {
        if let Err(response) = page_actor(&state, &headers, true).await {
            return response;
        }
        render_private(ConsoleMonitoringPanel {
            view: monitoring_view(&state).await,
        })
    }

    /// One BNC network in the console networks view, with its live upstream
    /// connection state resolved from the registry (not just its stored config).
    struct ConsoleNetView {
        name: String,
        addr: String,
        tls: bool,
        nick: String,
        autojoin: String,
        enabled: bool,
        connected: bool,
        /// Only IRC upstreams are editable via the IRC edit form; a bridge is
        /// configured on the Integrations page, so it shows no Edit link.
        editable: bool,
    }

    #[derive(Template)]
    #[template(path = "console_configuration.html")]
    struct ConsoleConfiguration {
        account: String,
        csrf: String,
        is_admin: bool,
        active: &'static str,
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
        release_revision: String,
        outcome: Option<String>,
        success: bool,
    }

    struct OidcProviderView {
        name: String,
        issuer_url: String,
        client_id: String,
        scopes: String,
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
            account,
            csrf,
            is_admin: true,
            active: "configuration",
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
        headers: axum::http::HeaderMap,
    ) -> Response {
        let (account, csrf) = match page_actor(&state, &headers, true).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
        let Some(config) = &state.managed_config else {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Configuration unavailable",
                Some("PostgreSQL is required for UI-managed configuration."),
            );
        };
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
        let Some(config) = &state.managed_config else {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Configuration unavailable",
                Some("PostgreSQL is required for UI-managed configuration."),
            );
        };
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
        let Some(config) = &state.managed_config else {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Configuration unavailable",
                Some("PostgreSQL is required for UI-managed configuration."),
            );
        };
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
                render_configuration(
                    state,
                    account,
                    csrf,
                    snapshot,
                    Some(
                        "Configuration saved. Restart the server to apply this access change."
                            .into(),
                    ),
                    true,
                )
                .await
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
            settings.opers.push(crate::config::OperConfig {
                name: name.to_string(),
                password: key.seal(&form.password, crate::secret::CONFIG_CONTEXT),
            });
            Ok(format!("added IRC operator {name}"))
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
            if settings.credentials_from_bootstrap {
                return Err(
                    "Configure a master key and restart before changing bootstrap operator credentials."
                        .into(),
                );
            }
            let before = settings.opers.len();
            settings.opers.retain(|oper| oper.name != form.name);
            if settings.opers.len() == before {
                return Err(format!("No IRC operator named '{}'.", form.name));
            }
            Ok(format!("removed IRC operator {}", form.name))
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
            let name = form.name.trim().to_string();
            settings
                .oidc_providers
                .push(crate::config::OidcProviderConfig {
                    name: name.clone(),
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
                    end_session_endpoint: (!form.end_session_endpoint.trim().is_empty())
                        .then(|| form.end_session_endpoint.trim().to_string()),
                    token_endpoint_auth_method: method,
                });
            Ok(format!("added OpenID Connect provider {name}"))
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
            if settings.credentials_from_bootstrap {
                return Err(
                    "Configure a master key and restart before changing bootstrap identity-provider credentials."
                        .into(),
                );
            }
            let before = settings.oidc_providers.len();
            settings
                .oidc_providers
                .retain(|provider| provider.name != form.name);
            if settings.oidc_providers.len() == before {
                return Err(format!("No identity provider named '{}'.", form.name));
            }
            Ok(format!("removed OpenID Connect provider {}", form.name))
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
        nick: String,
        user: String,
        host: String,
        account: Option<String>,
        oper: bool,
        /// Channels the session is in, pre-joined for display.
        channels: String,
    }

    #[derive(Template)]
    #[template(path = "console_sessions.html")]
    struct ConsoleSessions {
        account: String,
        csrf: String,
        is_admin: bool,
        active: &'static str,
        title: &'static str,
        hint: &'static str,
        kill_action: &'static str,
        sessions: Vec<SessionRow>,
        error: Option<String>,
    }

    #[derive(Template)]
    #[template(path = "console_networks.html")]
    struct ConsoleNetworks {
        account: String,
        csrf: String,
        is_admin: bool,
        active: &'static str,
        networks: Vec<ConsoleNetView>,
        attach_addr: Option<std::net::SocketAddr>,
    }

    #[derive(Template)]
    #[template(path = "console_network_rows.html")]
    struct ConsoleNetworkRows {
        csrf: String,
        networks: Vec<ConsoleNetView>,
    }

    #[derive(Template)]
    #[template(path = "console_network_edit.html")]
    struct ConsoleNetworkEdit {
        account: String,
        csrf: String,
        is_admin: bool,
        active: &'static str,
        name: String,
        addr: String,
        tls: bool,
        nick: String,
        realname: String,
        autojoin: String,
        error: Option<String>,
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
        let Ok(account) = authenticate(&state, &headers).await else {
            return Redirect::to("/login").into_response();
        };
        if !is_admin_account(&state, &account) {
            return problem(StatusCode::FORBIDDEN, "Admin only", None);
        }
        let csrf = session_token(&headers, state.secure_cookies)
            .map(|s| state.csrf_token(&s))
            .unwrap_or_default();
        match console_build(&state, account, csrf, None).await {
            Ok(view) => render_private(view),
            Err(resp) => resp,
        }
    }

    /// Whether `account` may reach the admin console sections.
    fn is_admin_account(state: &AppState, account: &str) -> bool {
        state
            .admin_accounts
            .contains(&e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(account))
    }

    /// Build the caller's BNC networks with live upstream state from the
    /// registry (a network with no live handle — disabled, or not yet dialed —
    /// reads as not connected). One place so the full page and the htmx
    /// add/delete fragment render identical rows.
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
                let connected = state
                    .bnc_registry
                    .as_ref()
                    .and_then(|r| r.get_owned(account, &n.name))
                    .map(|h| h.is_connected())
                    .unwrap_or(false);
                let editable = n.kind == crate::config::NetworkKind::Irc;
                ConsoleNetView {
                    name: n.name,
                    addr: n.addr,
                    tls: n.tls,
                    nick: n.nick,
                    autojoin: n.autojoin.join(", "),
                    enabled: n.enabled,
                    connected,
                    editable,
                }
            })
            .collect())
    }

    /// Console → BNC networks: the caller's own always-on upstreams with live
    /// connection status, plus add/remove. Any authenticated user manages their
    /// own networks (not admin-gated); an anonymous visitor goes to `/login`.
    pub async fn console_networks(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
    ) -> Response {
        let Ok(account) = authenticate(&state, &headers).await else {
            return Redirect::to("/login").into_response();
        };
        // The view lists networks straight from the database (like the account
        // page), so it works even where the bouncer is disabled — status simply
        // reads not-connected. Add/remove do require the live registry.
        let csrf = session_token(&headers, state.secure_cookies)
            .map(|s| state.csrf_token(&s))
            .unwrap_or_default();
        let is_admin = is_admin_account(&state, &account);
        let networks = match console_network_views(&state, &account).await {
            Ok(n) => n,
            Err(r) => return r,
        };
        let attach_addr = match &state.bnc_listener {
            Some(listener) => listener.status().await.map(|(_, bound)| bound),
            None => None,
        };
        render_private(ConsoleNetworks {
            account,
            csrf,
            is_admin,
            active: "networks",
            networks,
            attach_addr,
        })
    }

    async fn console_networks_fragment(state: &AppState, account: &str, csrf: String) -> Response {
        match console_network_views(state, account).await {
            Ok(networks) => render_private(ConsoleNetworkRows { csrf, networks }),
            Err(r) => r,
        }
    }

    /// Shared body of the two add-network form handlers (console + account):
    /// require the bouncer, parse the (identical) form, build the CreateNetwork,
    /// and run `create_network_core`. The callers differ only in which table
    /// fragment they render on success.
    async fn add_network_from_form(
        state: &AppState,
        account: &str,
        form: Result<axum::Form<NetworkFormFields>, axum::extract::rejection::FormRejection>,
    ) -> Result<(), Response> {
        let Some(registry) = &state.bnc_registry else {
            return Err(problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None));
        };
        let axum::Form(f) = form.map_err(|e| {
            problem(
                StatusCode::BAD_REQUEST,
                "Invalid form",
                Some(&e.to_string()),
            )
        })?;
        let req = f.into_create();
        create_network_core(state, registry, account, &req).await
    }

    /// Add a network from the console (htmx); returns the refreshed rows fragment.
    /// Reuses the same `create_network_core` the REST API and account page use.
    pub async fn console_add_network(
        State(state): State<Arc<AppState>>,
        CsrfVerified(account): CsrfVerified,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<NetworkFormFields>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        if let Err(r) = add_network_from_form(&state, &account, form).await {
            return r;
        }
        let csrf = session_token(&headers, state.secure_cookies)
            .map(|s| state.csrf_token(&s))
            .unwrap_or_default();
        console_networks_fragment(&state, &account, csrf).await
    }

    /// Shared body of the two delete-network handlers (console + account):
    /// require the bouncer, delete the row (owner-scoped), and stop its live
    /// driver. The callers differ only in which fragment they render.
    async fn delete_network_by_name(
        state: &AppState,
        account: &str,
        name: &str,
    ) -> Result<(), Response> {
        let Some(registry) = &state.bnc_registry else {
            return Err(problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None));
        };
        match crate::db::delete_bnc_network(pool_of(state), account, name).await {
            Ok(true) => {
                registry.remove(Some(account), name);
                Ok(())
            }
            Ok(false) => Err(problem(StatusCode::NOT_FOUND, "No such network", None)),
            Err(e) => {
                eprintln!("network delete: {e}");
                Err(problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Database unavailable",
                    None,
                ))
            }
        }
    }

    /// Delete a network from the console (htmx); returns the refreshed fragment.
    pub async fn console_delete_network(
        State(state): State<Arc<AppState>>,
        CsrfVerified(account): CsrfVerified,
        headers: axum::http::HeaderMap,
        Path(name): Path<String>,
    ) -> Response {
        if let Err(r) = delete_network_by_name(&state, &account, &name).await {
            return r;
        }
        let csrf = session_token(&headers, state.secure_cookies)
            .map(|s| state.csrf_token(&s))
            .unwrap_or_default();
        console_networks_fragment(&state, &account, csrf).await
    }

    /// The console toggle button posts the *target* enabled state so the flip is
    /// not derived from a possibly-stale row (no read-then-write race).
    #[derive(Deserialize)]
    pub struct ToggleFields {
        enabled: String,
    }

    /// Enable/disable a network from the console (htmx); returns the refreshed
    /// rows fragment. Reuses the same core the REST `PATCH` uses.
    pub async fn console_toggle_network(
        State(state): State<Arc<AppState>>,
        CsrfVerified(account): CsrfVerified,
        headers: axum::http::HeaderMap,
        Path(name): Path<String>,
        form: Result<axum::Form<ToggleFields>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let Some(registry) = &state.bnc_registry else {
            return problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None);
        };
        let axum::Form(f) = match form {
            Ok(f) => f,
            Err(e) => {
                return problem(
                    StatusCode::BAD_REQUEST,
                    "Invalid form",
                    Some(&e.to_string()),
                );
            }
        };
        let enabled = matches!(f.enabled.as_str(), "true" | "on" | "1");
        if let Err(r) = set_network_enabled_core(&state, registry, &account, &name, enabled).await {
            return r;
        }
        let csrf = session_token(&headers, state.secure_cookies)
            .map(|s| state.csrf_token(&s))
            .unwrap_or_default();
        console_networks_fragment(&state, &account, csrf).await
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
        error: Option<String>,
    ) -> Response {
        let is_admin = is_admin_account(state, &account); // shell nav only
        render_private(ConsoleNetworkEdit {
            account,
            csrf,
            is_admin,
            active: "networks",
            name,
            addr,
            tls,
            nick,
            realname,
            autojoin,
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
        let axum::Form(f) = match form {
            Ok(f) => f,
            Err(e) => {
                return problem(
                    StatusCode::BAD_REQUEST,
                    "Invalid form",
                    Some(&e.to_string()),
                );
            }
        };
        let account = match require_form_actor(&state, &headers, &f.csrf).await {
            Ok(a) => a,
            Err(r) => return r,
        };
        let Some(registry) = &state.bnc_registry else {
            return problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None);
        };
        let tls = f.tls.as_deref() == Some("on");
        let realname = (!f.realname.trim().is_empty()).then(|| f.realname.trim().to_string());
        let autojoin: Vec<String> = f
            .autojoin
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        let result = update_network_core(
            &state,
            registry,
            &account,
            &name,
            &f.addr,
            tls,
            &f.nick,
            realname.as_deref(),
            &autojoin,
        )
        .await;
        if result.is_ok() {
            return Redirect::to("/console/networks").into_response();
        }
        // Re-render the form with a banner, keeping what the user typed.
        let csrf = session_token(&headers, state.secure_cookies)
            .map(|s| state.csrf_token(&s))
            .unwrap_or_default();
        let err = "Could not save — check the address (host:port, not an internal \
                   IP), nick, and field lengths."
            .to_string();
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
            Some(err),
        )
    }

    struct BridgeNet {
        name: String,
        owner: String,
        connected: bool,
        /// Whether the viewing admin owns this bridge (so it can be removed from
        /// here). A config-file / shared bridge is managed via config, not here.
        deletable: bool,
    }
    struct BridgePlatform {
        name: &'static str,
        kind: &'static str,
        built: bool,
        configure: &'static str,
        /// Fields the add-bridge form should collect for this platform.
        needs_addr: bool,
        needs_nick: bool,
        needs_account: bool,
        account_label: &'static str,
        password_label: &'static str,
        networks: Vec<BridgeNet>,
    }

    #[derive(Template)]
    #[template(path = "console_integrations.html")]
    struct ConsoleIntegrations {
        account: String,
        csrf: String,
        is_admin: bool,
        active: &'static str,
        bouncer_enabled: bool,
        platforms: Vec<BridgePlatform>,
        /// Error banner shown after a failed add/remove; `None` on the plain GET.
        error: Option<String>,
    }

    /// Console → Integrations (admin): the chat-platform bridges. For each
    /// platform it shows whether this binary was built with the feature and the
    /// bridge networks currently running (with live status), plus add/remove for
    /// the admin's own bridges. `error` renders a banner after a failed action.
    fn console_integrations_build(
        state: &AppState,
        account: String,
        csrf: String,
        error: Option<String>,
    ) -> ConsoleIntegrations {
        let all = state
            .bnc_registry
            .as_ref()
            .map(|r| r.list())
            .unwrap_or_default();
        let admin_folded = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(&account);
        let bridge_nets = |kind: &str| -> Vec<BridgeNet> {
            all.iter()
                .filter(|n| n.kind == kind)
                .map(|n| BridgeNet {
                    name: n.name.clone(),
                    owner: n.owner.clone().unwrap_or_else(|| "shared".into()),
                    connected: n.connected,
                    // Only the admin's own bridges are removable here; a shared /
                    // config-file bridge (owner = None) is managed via config.
                    deletable: n.owner.as_deref() == Some(admin_folded.as_str()),
                })
                .collect()
        };
        let platforms = vec![
            BridgePlatform {
                name: "Matrix",
                kind: "matrix",
                built: cfg!(feature = "matrix"),
                configure: "A homeserver bridged as a network: messages relay both ways.",
                needs_addr: true,
                needs_nick: true,
                needs_account: false,
                account_label: "",
                password_label: "Login password",
                networks: bridge_nets("matrix"),
            },
            BridgePlatform {
                name: "Discord",
                kind: "discord",
                built: cfg!(feature = "discord"),
                configure: "A Discord bot session; autojoin lists the channel IDs to bridge.",
                needs_addr: false,
                needs_nick: false,
                needs_account: false,
                account_label: "",
                password_label: "Bot token",
                networks: bridge_nets("discord"),
            },
            BridgePlatform {
                name: "Slack",
                kind: "slack",
                built: cfg!(feature = "slack"),
                configure: "A Slack workspace; autojoin lists the channels to bridge.",
                needs_addr: false,
                needs_nick: false,
                needs_account: true,
                account_label: "Bot token (xoxb-)",
                password_label: "App token (xapp-)",
                networks: bridge_nets("slack"),
            },
        ];
        ConsoleIntegrations {
            account,
            csrf,
            is_admin: true,
            active: "integrations",
            bouncer_enabled: state.bnc_registry.is_some(),
            platforms,
            error,
        }
    }

    /// Console → Integrations (admin) GET.
    pub async fn console_integrations(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
    ) -> Response {
        let (account, csrf) = match page_actor(&state, &headers, true).await {
            Ok(x) => x,
            Err(r) => return r,
        };
        render_private(console_integrations_build(&state, account, csrf, None))
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
        render_private(console_integrations_build(
            state,
            account,
            csrf,
            Some(message),
        ))
    }

    /// The console add-bridge form (urlencoded; hidden CSRF field — a plain form
    /// can't set the `x-csrf-token` header htmx uses). Field meaning is per kind.
    #[derive(Deserialize)]
    pub struct BridgeFormFields {
        csrf: String,
        kind: String,
        name: String,
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

    #[derive(Deserialize)]
    pub struct BridgeDeleteFields {
        csrf: String,
        name: String,
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

    /// Run one admin console action on the core worker and await its outcome.
    /// The action mutates live state (hot ban list, registered-channel maps) and
    /// persists, exactly like the equivalent oper/services IRC command.
    async fn admin_action(
        state: &AppState,
        req: crate::core::AdminRequest,
    ) -> Result<String, String> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if state
            .core_tx
            .push(crate::core::Input::Admin { req, reply: tx })
            .await
            .is_err()
        {
            return Err("core worker unavailable".into());
        }
        match rx.await {
            Ok(crate::core::AdminReply::Ok(m)) => Ok(m),
            Ok(crate::core::AdminReply::Err(m)) => Err(m),
            Ok(crate::core::AdminReply::Sessions(_)) => {
                Err("unexpected sessions reply for a mutation".into())
            }
            Err(_) => Err("core worker dropped the request".into()),
        }
    }

    /// Snapshot live client sessions from the core worker. With `own`, restrict
    /// to sessions authenticated as that account (the caller's own clients).
    async fn admin_list_sessions(
        state: &AppState,
        own: Option<String>,
    ) -> Result<Vec<crate::core::SessionInfo>, String> {
        let req = match own {
            Some(account) => crate::core::AdminRequest::ListOwnSessions { account },
            None => crate::core::AdminRequest::ListSessions,
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        if state
            .core_tx
            .push(crate::core::Input::Admin { req, reply: tx })
            .await
            .is_err()
        {
            return Err("core worker unavailable".into());
        }
        match rx.await {
            Ok(crate::core::AdminReply::Sessions(s)) => Ok(s),
            Ok(_) => Err("unexpected reply".into()),
            Err(_) => Err("core worker dropped the request".into()),
        }
    }

    /// Re-render the admin console with an error banner after a failed action.
    async fn console_error_page(
        state: &AppState,
        headers: &axum::http::HeaderMap,
        account: String,
        message: String,
    ) -> Response {
        let csrf = session_token(headers, state.secure_cookies)
            .map(|s| state.csrf_token(&s))
            .unwrap_or_default();
        match console_build(state, account, csrf, Some(message)).await {
            Ok(view) => render_private(view),
            Err(resp) => resp,
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
        match admin_action(state, req).await {
            Ok(_) => Ok(Redirect::to(redirect).into_response()),
            Err(msg) => Err((account, msg)),
        }
    }

    /// Console → add a K/D/X-line (admin). Runs through the core so it enforces
    /// and disconnects matching sessions exactly like oper KLINE.
    pub async fn console_add_ban(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<BanForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let f = match parse_form(form) {
            Ok(f) => f,
            Err(r) => return r,
        };
        let make = |actor| crate::core::AdminRequest::AddServerBan {
            mask: f.mask,
            kind: f.kind,
            reason: f.reason,
            actor,
        };
        match run_admin_form(&state, &headers, &f.csrf, "/console", make).await {
            Ok(resp) => resp,
            Err((account, msg)) => console_error_page(&state, &headers, account, msg).await,
        }
    }

    /// Console → remove a K/D/X-line (admin).
    pub async fn console_remove_ban(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<BanDeleteForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let f = match parse_form(form) {
            Ok(f) => f,
            Err(r) => return r,
        };
        let make = |actor| crate::core::AdminRequest::RemoveServerBan {
            mask: f.mask,
            kind: f.kind,
            actor,
        };
        match run_admin_form(&state, &headers, &f.csrf, "/console", make).await {
            Ok(resp) => resp,
            Err((account, msg)) => console_error_page(&state, &headers, account, msg).await,
        }
    }

    /// Console → unregister a channel (admin), like ChanServ DROP.
    pub async fn console_drop_channel(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<DropChannelForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let f = match parse_form(form) {
            Ok(f) => f,
            Err(r) => return r,
        };
        let make = |actor| crate::core::AdminRequest::DropChannel {
            channel: f.channel,
            actor,
        };
        match run_admin_form(&state, &headers, &f.csrf, "/console", make).await {
            Ok(resp) => resp,
            Err((account, msg)) => console_error_page(&state, &headers, account, msg).await,
        }
    }

    #[derive(Deserialize)]
    pub struct KillForm {
        csrf: String,
        nick: String,
        #[serde(default)]
        reason: String,
    }

    /// Render the client-sessions view. `own = false` is the admin view of every
    /// session (`/console/sessions`); `own = true` is the caller's self-service
    /// view of their own connected clients (`/console/my-sessions`). `error`
    /// shows a banner after a failed disconnect.
    async fn render_sessions_page(
        state: &AppState,
        headers: &axum::http::HeaderMap,
        account: String,
        own: bool,
        error: Option<String>,
    ) -> Response {
        let csrf = session_token(headers, state.secure_cookies)
            .map(|s| state.csrf_token(&s))
            .unwrap_or_default();
        let is_admin = is_admin_account(state, &account);
        let filter = own.then(|| account.clone());
        let (sessions, error): (Vec<SessionRow>, Option<String>) =
            match admin_list_sessions(state, filter).await {
                Ok(list) => (
                    list.into_iter()
                        .map(|s| SessionRow {
                            nick: s.nick,
                            user: s.user,
                            host: s.host,
                            account: s.account,
                            oper: s.oper,
                            channels: s.channels.join(", "),
                        })
                        .collect(),
                    error,
                ),
                // Surface a snapshot failure as the banner rather than a blank page.
                Err(msg) => (Vec::new(), Some(error.unwrap_or(msg))),
            };
        let (active, title, hint, kill_action) = if own {
            (
                "my-sessions",
                "Your sessions",
                "Clients currently signed in to your account (raw IRC, WebSocket, BNC). Disconnecting one signs it out immediately.",
                "/console/my-sessions/kill",
            )
        } else {
            (
                "sessions",
                "Client sessions",
                "Live registered client connections (raw IRC, WebSocket, and BNC attach). Disconnecting one removes it immediately, like the oper KILL.",
                "/console/sessions/kill",
            )
        };
        render_private(ConsoleSessions {
            account,
            csrf,
            is_admin,
            active,
            title,
            hint,
            kill_action,
            sessions,
            error,
        })
    }

    /// Console → live client sessions (admin-gated, like `/console`).
    pub async fn console_sessions(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
    ) -> Response {
        let Ok(account) = authenticate(&state, &headers).await else {
            return Redirect::to("/login").into_response();
        };
        if !is_admin_account(&state, &account) {
            return problem(StatusCode::FORBIDDEN, "Admin only", None);
        }
        render_sessions_page(&state, &headers, account, false, None).await
    }

    /// Console → KILL a client session by nick (admin), like oper KILL.
    pub async fn console_kill_session(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<KillForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let f = match parse_form(form) {
            Ok(f) => f,
            Err(r) => return r,
        };
        let make = |actor| crate::core::AdminRequest::Kill {
            nick: f.nick,
            reason: f.reason,
            actor,
        };
        match run_admin_form(&state, &headers, &f.csrf, "/console/sessions", make).await {
            Ok(resp) => resp,
            Err((account, msg)) => {
                render_sessions_page(&state, &headers, account, false, Some(msg)).await
            }
        }
    }

    /// Console → your own sessions (any authenticated user; not admin-gated).
    pub async fn console_my_sessions(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
    ) -> Response {
        let Ok(account) = authenticate(&state, &headers).await else {
            return Redirect::to("/login").into_response();
        };
        render_sessions_page(&state, &headers, account, true, None).await
    }

    /// Console → disconnect one of *your own* sessions by nick. The core refuses
    /// to touch a session not authenticated as the caller, so this cannot kill
    /// anyone else even though it is not admin-gated.
    pub async fn console_kill_own_session(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<KillForm>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let f = match parse_form(form) {
            Ok(f) => f,
            Err(r) => return r,
        };
        let account = match require_form_actor(&state, &headers, &f.csrf).await {
            Ok(a) => a,
            Err(r) => return r,
        };
        let req = crate::core::AdminRequest::KillOwn {
            nick: f.nick,
            reason: f.reason,
            account: account.clone(),
        };
        match admin_action(&state, req).await {
            Ok(_) => Redirect::to("/console/my-sessions").into_response(),
            Err(msg) => render_sessions_page(&state, &headers, account, true, Some(msg)).await,
        }
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
        let f = match parse_form(form) {
            Ok(f) => f,
            Err(r) => return r,
        };
        let account = match require_admin_form_actor(&state, &headers, &f.csrf).await {
            Ok(a) => a,
            Err(r) => return r,
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
        // Pre-check the build feature so the banner names it specifically (rather
        // than the generic create-failure message) — create_network_core also
        // enforces it, but its problem+json detail is lost to the plain form.
        if !kind_feature_available(kind) {
            let msg = format!(
                "This server was not built with the {} feature — rebuild with --features {}.",
                f.kind, f.kind
            );
            return console_integrations_error(&state, &headers, account, msg).await;
        }
        let opt = |s: String| if s.is_empty() { None } else { Some(s) };
        let req = CreateNetwork {
            kind,
            name: f.name,
            addr: f.addr,
            tls: true,
            nick: f.nick,
            realname: None,
            autojoin: f
                .autojoin
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
            sasl_account: opt(f.sasl_account),
            sasl_password: opt(f.sasl_password),
        };
        // create_network_core answers a problem+json Response; for the console
        // (a plain form) re-render the page with a banner instead of navigating
        // the admin to a bare JSON body. The specific reason is on the REST path.
        if create_network_core(&state, registry, &account, &req)
            .await
            .is_err()
        {
            let msg = "Could not add the bridge — check the name and required \
                       fields (and the server's master key for sealed tokens)."
                .to_string();
            return console_integrations_error(&state, &headers, account, msg).await;
        }
        Redirect::to("/console/integrations").into_response()
    }

    /// Console → Integrations: remove one of the admin's own bridges.
    pub async fn console_delete_bridge(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<BridgeDeleteFields>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let f = match parse_form(form) {
            Ok(f) => f,
            Err(r) => return r,
        };
        let account = match require_admin_form_actor(&state, &headers, &f.csrf).await {
            Ok(a) => a,
            Err(r) => return r,
        };
        let Some(registry) = &state.bnc_registry else {
            return problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None);
        };
        let pool = pool_of(&state);
        match crate::db::delete_bnc_network(pool, &account, &f.name).await {
            Ok(true) => registry.remove(Some(&account), &f.name),
            Ok(false) => {
                let msg = format!("No such bridge '{}'.", f.name);
                return console_integrations_error(&state, &headers, account, msg).await;
            }
            Err(e) => {
                eprintln!("console: bridge delete: {e}");
                let msg = "Database unavailable — bridge not removed.".to_string();
                return console_integrations_error(&state, &headers, account, msg).await;
            }
        };
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

    /// The `/device` form (urlencoded): code + CSRF token as form fields
    /// (a plain HTML form cannot set the `x-csrf-token` header htmx uses).
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

    /// A cookie-authenticated account whose request also carries a valid
    /// `x-csrf-token` header — the CSRF precondition for an htmx form mutation,
    /// as an extractor. A state-changing form-POST handler is CSRF-protected
    /// because it *asks for this in its signature*, not because the author
    /// remembered to open the body with a check — the same way [`Authenticated`]
    /// closed the authentication class. A new `pages::*` form handler that omits
    /// it fails to compile for want of the account argument.
    ///
    /// Header-based by construction: a `FromRequestParts` extractor cannot read
    /// a form-body field, so the one plain HTML form that carries its token in
    /// the body (`approve_device_form`, which htmx can't drive) keeps its own
    /// explicit `csrf_valid` check.
    pub(crate) struct CsrfVerified(pub(crate) String);

    impl axum::extract::FromRequestParts<Arc<AppState>> for CsrfVerified {
        type Rejection = Response;

        async fn from_request_parts(
            parts: &mut axum::http::request::Parts,
            state: &Arc<AppState>,
        ) -> Result<Self, Self::Rejection> {
            let account = authenticate(state, &parts.headers).await?;
            let session = session_token(&parts.headers, state.secure_cookies)
                .ok_or_else(|| problem(StatusCode::UNAUTHORIZED, "Session required", None))?;
            let token = parts
                .headers
                .get("x-csrf-token")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if state.csrf_valid(&session, token) {
                Ok(CsrfVerified(account))
            } else {
                Err(problem(StatusCode::FORBIDDEN, "Bad CSRF token", None))
            }
        }
    }

    /// Add a network from the account page's htmx form; returns the
    /// refreshed network table fragment.
    pub async fn add_network_form(
        State(state): State<Arc<AppState>>,
        CsrfVerified(account): CsrfVerified,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<NetworkFormFields>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        if let Err(r) = add_network_from_form(&state, &account, form).await {
            return r;
        }
        networks_fragment(&state, &headers, &account).await
    }

    /// Delete a network from the account page; returns the refreshed
    /// network table fragment.
    pub async fn delete_network_form(
        State(state): State<Arc<AppState>>,
        CsrfVerified(account): CsrfVerified,
        headers: axum::http::HeaderMap,
        Path(name): Path<String>,
    ) -> Response {
        if let Err(r) = delete_network_by_name(&state, &account, &name).await {
            return r;
        }
        networks_fragment(&state, &headers, &account).await
    }

    async fn networks_fragment(
        state: &AppState,
        headers: &axum::http::HeaderMap,
        account: &str,
    ) -> Response {
        let csrf = session_token(headers, state.secure_cookies)
            .map(|s| state.csrf_token(&s))
            .unwrap_or_default();
        let pool = state.pool.as_ref().expect("checked");
        match network_views(pool, account).await {
            Ok(networks) => render_private(NetworkRows { csrf, networks }),
            Err(r) => r,
        }
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

    /// Like [`render`], plus `Cache-Control: no-store` — for an authenticated
    /// per-user page that carries a session-bound CSRF token and personal data
    /// (account, network list) yet still runs scripts (htmx). It deliberately
    /// keeps `render`'s script-permitting headers rather than `render_auth`'s
    /// `default-src 'none'` CSP, which would block htmx; the point here is only
    /// to keep the personalized response out of shared/bfcache, the same reason
    /// `/me` sets `no_store` explicitly. Without this the browser's Back/bfcache
    /// re-shows the previous user's account after logout on a shared machine.
    fn render_private<T: Template>(template: T) -> Response {
        let mut response = render(template);
        if response.status().is_success() {
            no_store(response.headers_mut());
        }
        response
    }

    fn render_auth<T: Template>(template: T) -> Response {
        let mut response = render(template);
        if response.status().is_success() {
            let headers = response.headers_mut();
            no_store(headers);
            headers.insert(
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
                    .parse()
                    .expect("static header"),
            );
            headers.insert(
                header::X_FRAME_OPTIONS,
                "DENY".parse().expect("static header"),
            );
            headers.insert(
                header::X_CONTENT_TYPE_OPTIONS,
                "nosniff".parse().expect("static header"),
            );
            headers.insert(
                header::REFERRER_POLICY,
                "no-referrer".parse().expect("static header"),
            );
        }
        response
    }
}

#[cfg(test)]
mod composer_tests {
    use super::composer_to_irc;

    #[test]
    fn htmx_form_becomes_privmsg() {
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
    use super::{clear_session_cookie, oidc_state_cookie_name, session_cookie_name};

    #[test]
    fn secure_cookies_use_host_prefix() {
        // The `__Host-` prefix is what pins the cookie to the exact host with
        // Secure+Path=/ and no Domain — dropping it would reopen fixation.
        assert_eq!(session_cookie_name(true), "__Host-e6irc_session");
        assert_eq!(oidc_state_cookie_name(true), "__Host-e6irc_oidc_state");
        // Plain-HTTP dev (no TLS) can't use `__Host-` (it requires Secure).
        assert_eq!(session_cookie_name(false), "e6irc_session");
        assert_eq!(oidc_state_cookie_name(false), "e6irc_oidc_state");
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

    fn logout_token(payload: serde_json::Value) -> (String, openidconnect::core::CoreJsonWebKey) {
        let key = CoreRsaPrivateSigningKey::from_pem(
            TEST_RSA_KEY,
            Some(JsonWebKeyId::new("logout-key".into())),
        )
        .expect("test RSA key");
        let algorithm = CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256;
        let header = base64url(br#"{"alg":"RS256","kid":"logout-key","typ":"logout+jwt"}"#);
        let payload = base64url(&serde_json::to_vec(&payload).expect("payload"));
        let input = format!("{header}.{payload}");
        let signature = key.sign(&algorithm, input.as_bytes()).expect("sign");
        (
            format!("{input}.{}", base64url(&signature)),
            key.as_verification_key(),
        )
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
        let provider = OidcProviderConfig {
            name: "shauth".into(),
            issuer_url: "https://auth.example".into(),
            client_id: "e6irc".into(),
            client_secret: "secret".into(),
            scopes: vec![],
            end_session_endpoint: None,
            token_endpoint_auth_method: Default::default(),
        };
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
        let provider = OidcProviderConfig {
            name: "shauth".into(),
            issuer_url: "https://auth.example".into(),
            client_id: "e6irc".into(),
            client_secret: "secret".into(),
            scopes: vec![],
            end_session_endpoint: None,
            token_endpoint_auth_method: Default::default(),
        };
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
