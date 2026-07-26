//! HTTP layer: REST API (and later the web client backend), served
//! in-process by the same binary (DESIGN §12).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{Form, Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::Deserialize;
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
    /// The BNC network registry (shared with the BNC listener); `None`
    /// when the bouncer is not enabled.
    pub bnc_registry: Option<std::sync::Arc<crate::bouncer::Registry>>,
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

pub fn router(state: AppState) -> Router {
    let router = Router::new()
        .route("/healthz", get(async || "ok"))
        .route("/login", get(pages::login))
        .route("/auth/signed-out", get(pages::signed_out))
        .route("/auth/validation", get(pages::validation))
        .route("/auth/shauth/logout/complete", get(shauth_logout_complete))
        .route("/auth.css", get(pages::auth_styles))
        .route("/account", get(pages::account))
        .route("/console", get(pages::console))
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
            "/console/integrations",
            get(pages::console_integrations).post(pages::console_add_bridge),
        )
        .route(
            "/console/integrations/delete",
            post(pages::console_delete_bridge),
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
        .with_state(Arc::new(state))
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
    /// browser with only an upstream SSO session is sent through a silent
    /// OpenID Connect authorization request, while a completed silent probe
    /// without an upstream session lands on the interactive login page.
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
                "/api/v1/auth/oidc/{}/sso",
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
        accounts: Vec<String>,
        channels: Vec<ChannelRow>,
        bans: Vec<BanRow>,
        audit: Vec<AuditRow>,
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
    }

    #[derive(Template)]
    #[template(path = "console_networks.html")]
    struct ConsoleNetworks {
        account: String,
        csrf: String,
        is_admin: bool,
        active: &'static str,
        networks: Vec<ConsoleNetView>,
    }

    #[derive(Template)]
    #[template(path = "console_network_rows.html")]
    struct ConsoleNetworkRows {
        csrf: String,
        networks: Vec<ConsoleNetView>,
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
        let pool = pool_of(&state);

        let (stat_accounts, stat_channels, stat_server_bans) =
            match crate::db::server_stats(pool).await {
                Ok(t) => t,
                Err(e) => return super::device::admin_db_error("server stats", e),
            };
        let accounts = match crate::db::list_accounts(pool).await {
            Ok(v) => v,
            Err(e) => return super::device::admin_db_error("account list", e),
        };
        let channels = match crate::db::list_registered_channels(pool).await {
            Ok(v) => v
                .into_iter()
                .map(|(name, founder)| ChannelRow { name, founder })
                .collect(),
            Err(e) => return super::device::admin_db_error("channel list", e),
        };
        let bans = match crate::db::list_server_bans(pool).await {
            Ok(v) => v
                .into_iter()
                .map(|(mask, reason, set_by, kind)| BanRow {
                    kind,
                    mask,
                    reason,
                    set_by,
                })
                .collect(),
            Err(e) => return super::device::admin_db_error("server-ban list", e),
        };
        let audit = match crate::db::list_audit_log(pool, 100).await {
            Ok(v) => v
                .into_iter()
                .map(|(actor, action, target, detail, at)| AuditRow {
                    at,
                    actor,
                    action,
                    target,
                    detail,
                })
                .collect(),
            Err(e) => return super::device::admin_db_error("audit log", e),
        };

        render_private(Console {
            account,
            csrf,
            is_admin: true, // gated above; the shell shows the Server nav section
            active: "overview",
            server_name: state.server_name.clone(),
            network_name: state.network_name.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            stat_accounts,
            stat_channels,
            stat_server_bans,
            accounts,
            channels,
            bans,
            audit,
        })
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
                ConsoleNetView {
                    name: n.name,
                    addr: n.addr,
                    tls: n.tls,
                    nick: n.nick,
                    autojoin: n.autojoin.join(", "),
                    enabled: n.enabled,
                    connected,
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
        render_private(ConsoleNetworks {
            account,
            csrf,
            is_admin,
            active: "networks",
            networks,
        })
    }

    async fn console_networks_fragment(state: &AppState, account: &str, csrf: String) -> Response {
        match console_network_views(state, account).await {
            Ok(networks) => render_private(ConsoleNetworkRows { csrf, networks }),
            Err(r) => r,
        }
    }

    /// Add a network from the console (htmx); returns the refreshed rows fragment.
    /// Reuses the same `create_network_core` the REST API and account page use.
    pub async fn console_add_network(
        State(state): State<Arc<AppState>>,
        CsrfVerified(account): CsrfVerified,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<NetworkFormFields>, axum::extract::rejection::FormRejection>,
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
        let req = f.into_create();
        if let Err(r) = create_network_core(&state, registry, &account, &req).await {
            return r;
        }
        let csrf = session_token(&headers, state.secure_cookies)
            .map(|s| state.csrf_token(&s))
            .unwrap_or_default();
        console_networks_fragment(&state, &account, csrf).await
    }

    /// Delete a network from the console (htmx); returns the refreshed fragment.
    pub async fn console_delete_network(
        State(state): State<Arc<AppState>>,
        CsrfVerified(account): CsrfVerified,
        headers: axum::http::HeaderMap,
        Path(name): Path<String>,
    ) -> Response {
        let Some(registry) = &state.bnc_registry else {
            return problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None);
        };
        let pool = pool_of(&state);
        match crate::db::delete_bnc_network(pool, &account, &name).await {
            Ok(true) => registry.remove(Some(&account), &name),
            Ok(false) => return problem(StatusCode::NOT_FOUND, "No such network", None),
            Err(e) => {
                eprintln!("console: network delete: {e}");
                return problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Database unavailable",
                    None,
                );
            }
        };
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
    }

    /// Console → Integrations (admin): the chat-platform bridges. For each
    /// platform it shows whether this binary was built with the feature and the
    /// bridge networks currently running (with live status). Bridges are
    /// configured as `[[network]]` entries today; runtime CRUD is future work,
    /// so this is a status + configuration-guidance view.
    pub async fn console_integrations(
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
        render_private(ConsoleIntegrations {
            account,
            csrf,
            is_admin: true,
            active: "integrations",
            bouncer_enabled: state.bnc_registry.is_some(),
            platforms,
        })
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

    async fn require_admin_form_actor(
        state: &AppState,
        headers: &axum::http::HeaderMap,
        csrf: &str,
    ) -> Result<String, Response> {
        let account = authenticate(state, headers)
            .await
            .map_err(|_| Redirect::to("/login").into_response())?;
        if !is_admin_account(state, &account) {
            return Err(problem(StatusCode::FORBIDDEN, "Admin only", None));
        }
        let Some(session) = session_token(headers, state.secure_cookies) else {
            return Err(problem(StatusCode::UNAUTHORIZED, "Session required", None));
        };
        if !state.csrf_valid(&session, csrf) {
            return Err(problem(StatusCode::FORBIDDEN, "Bad CSRF token", None));
        }
        Ok(account)
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
        let axum::Form(f) = match form {
            Ok(f) => f,
            Err(e) => return problem(StatusCode::BAD_REQUEST, "Bad form", Some(&e.to_string())),
        };
        let account = match require_admin_form_actor(&state, &headers, &f.csrf).await {
            Ok(a) => a,
            Err(r) => return r,
        };
        let Some(registry) = &state.bnc_registry else {
            return problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None);
        };
        let Some(kind) = crate::config::NetworkKind::from_db_str(&f.kind).filter(|k| k.is_bridge())
        else {
            return problem(StatusCode::BAD_REQUEST, "Not a bridge kind", None);
        };
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
        if let Err(r) = create_network_core(&state, registry, &account, &req).await {
            return r;
        }
        Redirect::to("/console/integrations").into_response()
    }

    /// Console → Integrations: remove one of the admin's own bridges.
    pub async fn console_delete_bridge(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<BridgeDeleteFields>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let axum::Form(f) = match form {
            Ok(f) => f,
            Err(e) => return problem(StatusCode::BAD_REQUEST, "Bad form", Some(&e.to_string())),
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
            Ok(false) => return problem(StatusCode::NOT_FOUND, "No such bridge", None),
            Err(e) => {
                eprintln!("console: bridge delete: {e}");
                return problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Database unavailable",
                    None,
                );
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
        let req = f.into_create();
        if let Err(r) = create_network_core(&state, registry, &account, &req).await {
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
        let Some(registry) = &state.bnc_registry else {
            return problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None);
        };
        let pool = pool_of(&state);
        match crate::db::delete_bnc_network(pool, &account, &name).await {
            Ok(true) => registry.remove(Some(&account), &name),
            Ok(false) => return problem(StatusCode::NOT_FOUND, "No such network", None),
            Err(e) => {
                eprintln!("account: network delete: {e}");
                return problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Database unavailable",
                    None,
                );
            }
        };
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
