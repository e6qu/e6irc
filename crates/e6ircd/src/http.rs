//! HTTP layer: REST API (and later the web client backend), served
//! in-process by the same binary (DESIGN §12).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use sqlx::PgPool;

use crate::config::OidcProviderConfig;

/// One in-flight OIDC authorization (state → verifier/nonce), expiring
/// after ten minutes.
pub struct PendingAuth {
    provider: String,
    pkce_verifier: String,
    nonce: openidconnect::Nonce,
    started: Instant,
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
        .route("/account", get(pages::account))
        .route("/account/networks", post(pages::add_network_form))
        .route(
            "/account/networks/{name}",
            axum::routing::delete(pages::delete_network_form),
        )
        .route("/api/v1/server", get(server_info))
        .route("/api/v1/openapi.json", get(openapi))
        .route("/api/v1/auth/app-passwords", post(create_app_password))
        .route("/api/v1/auth/oidc/{provider}/start", get(oidc_start))
        .route("/api/v1/auth/oidc/{provider}/callback", get(oidc_callback))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/device/start", post(device_start))
        .route("/api/v1/auth/device/token", post(device_token))
        .route("/api/v1/auth/device/approve", post(device_approve))
        .route("/api/v1/me", get(me))
        .route("/api/v1/me/tokens", post(create_api_token))
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
            axum::routing::delete(delete_network),
        )
        .route("/api/v1/history", get(history))
        .route("/api/v1/admin/accounts", get(admin_accounts))
        .route("/api/v1/admin/channels", get(admin_channels))
        .route("/api/v1/admin/klines", get(admin_klines))
        .route("/api/v1/admin/audit", get(admin_audit))
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
        .route("/assets/{*path}", get(web::asset));
    router
        .fallback(async || problem(StatusCode::NOT_FOUND, "Not Found", None))
        .with_state(Arc::new(state))
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
                (
                    [(header::CONTENT_TYPE, mime), (header::CACHE_CONTROL, cache)],
                    file.data.into_owned(),
                )
                    .into_response()
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

    pub async fn index() -> Response {
        serve("index.html")
    }

    pub async fn asset(axum::extract::Path(path): axum::extract::Path<String>) -> Response {
        serve(&format!("assets/{path}"))
    }

    /// Standalone htmx (copied into web/dist by the build) for the
    /// server-rendered askama pages, which aren't part of the Vite bundle.
    pub async fn htmx() -> Response {
        serve("htmx.min.js")
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

    /// Login landing: one button per configured OIDC provider.
    pub async fn login(State(state): State<Arc<AppState>>) -> Response {
        let providers = state
            .oidc_providers
            .iter()
            .map(|p| p.name.clone())
            .collect();
        render(Login { providers })
    }

    struct NetworkView {
        name: String,
        addr: String,
        tls: bool,
        nick: String,
    }

    /// The account page's add-network form (urlencoded). `tls` is an
    /// HTML checkbox (`"on"` when checked, absent otherwise).
    #[derive(Deserialize)]
    pub struct NetworkFormFields {
        name: String,
        addr: String,
        nick: String,
        #[serde(default)]
        tls: Option<String>,
        #[serde(default)]
        autojoin: String,
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
        let csrf = session_token(&headers)
            .map(|s| state.csrf_token(&s))
            .unwrap_or_default();
        let pool = state.pool.as_ref().expect("authenticate checked the pool");

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
        render(Account {
            account,
            csrf,
            networks,
            credentials,
        })
    }

    /// Cookie-authenticate and verify the CSRF token for a page mutation.
    /// Returns the account name, or an error response.
    async fn authed_csrf(
        state: &AppState,
        headers: &axum::http::HeaderMap,
    ) -> Result<String, Response> {
        let account = authenticate(state, headers).await?;
        let session = session_token(headers)
            .ok_or_else(|| problem(StatusCode::UNAUTHORIZED, "Session required", None))?;
        let token = headers
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if state.csrf_valid(&session, token) {
            Ok(account)
        } else {
            Err(problem(StatusCode::FORBIDDEN, "Bad CSRF token", None))
        }
    }

    /// Add a network from the account page's htmx form; returns the
    /// refreshed network table fragment.
    pub async fn add_network_form(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        form: Result<axum::Form<NetworkFormFields>, axum::extract::rejection::FormRejection>,
    ) -> Response {
        let account = match authed_csrf(&state, &headers).await {
            Ok(a) => a,
            Err(r) => return r,
        };
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
        let req = CreateNetwork {
            name: f.name,
            addr: f.addr,
            tls: f.tls.as_deref() == Some("on"),
            nick: f.nick,
            realname: None,
            autojoin: f
                .autojoin
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
            sasl_account: None,
            sasl_password: None,
        };
        if let Err(r) = create_network_core(&state, registry, &account, &req).await {
            return r;
        }
        networks_fragment(&state, &headers, &account).await
    }

    /// Delete a network from the account page; returns the refreshed
    /// network table fragment.
    pub async fn delete_network_form(
        State(state): State<Arc<AppState>>,
        headers: axum::http::HeaderMap,
        Path(name): Path<String>,
    ) -> Response {
        let account = match authed_csrf(&state, &headers).await {
            Ok(a) => a,
            Err(r) => return r,
        };
        let Some(registry) = &state.bnc_registry else {
            return problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None);
        };
        let pool = state.pool.as_ref().expect("authenticate checked the pool");
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
        let csrf = session_token(headers)
            .map(|s| state.csrf_token(&s))
            .unwrap_or_default();
        let pool = state.pool.as_ref().expect("checked");
        match network_views(pool, account).await {
            Ok(networks) => render(NetworkRows { csrf, networks }),
            Err(r) => r,
        }
    }

    fn render<T: Template>(t: T) -> Response {
        match t.render() {
            Ok(html) => Html(html).into_response(),
            Err(e) => {
                eprintln!("template render error: {e}");
                problem(StatusCode::INTERNAL_SERVER_ERROR, "Template error", None)
            }
        }
    }
}

// ---- OIDC login ---------------------------------------------------------

type OidcClient = openidconnect::core::CoreClient<
    openidconnect::EndpointSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointMaybeSet,
    openidconnect::EndpointMaybeSet,
>;

fn oidc_http_client() -> openidconnect::reqwest::Client {
    // No redirect following: token endpoints must answer directly.
    openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client")
}

async fn discover_client(
    state: &AppState,
    provider: &OidcProviderConfig,
) -> Result<OidcClient, String> {
    use openidconnect::{ClientId, ClientSecret, IssuerUrl, RedirectUrl};
    let issuer = IssuerUrl::new(provider.issuer_url.clone()).map_err(|e| e.to_string())?;
    let metadata =
        openidconnect::core::CoreProviderMetadata::discover_async(issuer, &oidc_http_client())
            .await
            .map_err(|e| format!("discovery failed: {e}"))?;
    let public_url = state
        .public_url
        .as_deref()
        .ok_or("public_url not configured")?;
    let redirect = RedirectUrl::new(format!(
        "{}/api/v1/auth/oidc/{}/callback",
        public_url.trim_end_matches('/'),
        provider.name
    ))
    .map_err(|e| e.to_string())?;
    Ok(openidconnect::core::CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(provider.client_id.clone()),
        Some(ClientSecret::new(provider.client_secret.clone())),
    )
    .set_redirect_uri(redirect))
}

async fn oidc_start(
    State(state): State<Arc<AppState>>,
    Path(provider_name): Path<String>,
) -> Response {
    use openidconnect::{CsrfToken, Nonce, PkceCodeChallenge, Scope};
    let Some(provider) = state
        .oidc_providers
        .iter()
        .find(|p| p.name == provider_name)
        .cloned()
    else {
        return problem(StatusCode::NOT_FOUND, "Unknown OIDC provider", None);
    };
    let client = match discover_client(&state, &provider).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("oidc: {e}");
            return problem(StatusCode::BAD_GATEWAY, "OIDC provider unreachable", None);
        }
    };
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf, nonce) = client
        .authorize_url(
            openidconnect::core::CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("profile".into()))
        .add_scope(Scope::new("email".into()))
        .set_pkce_challenge(pkce_challenge)
        .url();
    let mut pending = state.pending_auth.lock().expect("poisoned");
    pending.retain(|_, p| p.started.elapsed() < Duration::from_secs(600));
    pending.insert(
        csrf.secret().clone(),
        PendingAuth {
            provider: provider.name.clone(),
            pkce_verifier: pkce_verifier.secret().clone(),
            nonce,
            started: Instant::now(),
        },
    );
    Redirect::temporary(auth_url.as_str()).into_response()
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

async fn oidc_callback(
    State(state): State<Arc<AppState>>,
    Path(provider_name): Path<String>,
    Query(query): Query<CallbackQuery>,
) -> Response {
    use openidconnect::{AuthorizationCode, PkceCodeVerifier, TokenResponse};
    if let Some(err) = query.error {
        return problem(StatusCode::UNAUTHORIZED, "OIDC login refused", Some(&err));
    }
    let (Some(code), Some(csrf_state)) = (query.code, query.state) else {
        return problem(StatusCode::BAD_REQUEST, "Missing code or state", None);
    };
    let Some(pending) = state
        .pending_auth
        .lock()
        .expect("poisoned")
        .remove(&csrf_state)
    else {
        return problem(
            StatusCode::UNAUTHORIZED,
            "Unknown or expired login state",
            None,
        );
    };
    if pending.provider != provider_name || pending.started.elapsed() > Duration::from_secs(600) {
        return problem(StatusCode::UNAUTHORIZED, "Login state mismatch", None);
    }
    let Some(pool) = state.pool.clone() else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "No database configured",
            None,
        );
    };
    let provider = state
        .oidc_providers
        .iter()
        .find(|p| p.name == provider_name)
        .cloned()
        .expect("pending auth references a configured provider");
    let client = match discover_client(&state, &provider).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("oidc: {e}");
            return problem(StatusCode::BAD_GATEWAY, "OIDC provider unreachable", None);
        }
    };
    let token_response = match client
        .exchange_code(AuthorizationCode::new(code))
        .expect("token endpoint present after discovery")
        .set_pkce_verifier(PkceCodeVerifier::new(pending.pkce_verifier))
        .request_async(&oidc_http_client())
        .await
    {
        Ok(t) => t,
        Err(e) => {
            eprintln!("oidc: code exchange failed: {e}");
            return problem(StatusCode::UNAUTHORIZED, "Code exchange failed", None);
        }
    };
    let Some(id_token) = token_response.id_token() else {
        return problem(StatusCode::UNAUTHORIZED, "Provider sent no ID token", None);
    };
    let claims = match id_token.claims(&client.id_token_verifier(), &pending.nonce) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("oidc: id token rejected: {e}");
            return problem(StatusCode::UNAUTHORIZED, "ID token validation failed", None);
        }
    };
    let issuer = claims.issuer().as_str();
    let subject = claims.subject().as_str();
    let preferred = claims
        .preferred_username()
        .map(|u| u.as_str().to_string())
        .or_else(|| {
            claims
                .email()
                .and_then(|e| e.as_str().split('@').next().map(str::to_string))
        })
        .unwrap_or_else(|| "user".to_string());
    let account =
        match crate::db::find_or_create_oidc_account(&pool, issuer, subject, &preferred).await {
            Ok(a) => a,
            Err(e) => {
                eprintln!("oidc: account provisioning failed: {e}");
                return problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Account storage failed",
                    None,
                );
            }
        };
    let token = match crate::db::create_web_session(&pool, &account).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("oidc: session creation failed: {e}");
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Session storage failed",
                None,
            );
        }
    };
    let secure = if state.secure_cookies { "; Secure" } else { "" };
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, "/".to_string()),
            (
                header::SET_COOKIE,
                format!(
                    "e6irc_session={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=1209600{secure}"
                ),
            ),
        ],
    )
        .into_response()
}

/// The single authentication choke point for the REST API: session
/// cookie or `Authorization: Bearer` PAT, resolved to an account name.
async fn authenticate(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<String, Response> {
    let Some(pool) = &state.pool else {
        return Err(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "No database configured",
            None,
        ));
    };
    if let Some(bearer) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        return match crate::db::api_token_account(pool, bearer).await {
            Ok(Some(account)) => Ok(account),
            Ok(None) => Err(problem(StatusCode::UNAUTHORIZED, "Invalid token", None)),
            Err(e) => {
                eprintln!("http: token lookup failed: {e}");
                Err(problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Database unavailable",
                    None,
                ))
            }
        };
    }
    if let Some(token) = session_token(headers) {
        return match crate::db::session_account(pool, &token).await {
            Ok(Some(account)) => Ok(account),
            Ok(None) => Err(problem(StatusCode::UNAUTHORIZED, "Not logged in", None)),
            Err(e) => {
                eprintln!("http: session lookup failed: {e}");
                Err(problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Database unavailable",
                    None,
                ))
            }
        };
    }
    Err(problem(StatusCode::UNAUTHORIZED, "Not logged in", None))
}

fn session_token(headers: &axum::http::HeaderMap) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    cookies.split(';').find_map(|part| {
        part.trim()
            .strip_prefix("e6irc_session=")
            .map(str::to_string)
    })
}

// ---- device authorization grant (RFC 8628) ------------------------------

/// Start a device grant. No auth: the client is not yet a principal.
async fn device_start(State(state): State<Arc<AppState>>) -> Response {
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
struct DeviceTokenReq {
    device_code: String,
}

/// Poll for the token. RFC 8628 error codes on the not-yet-ready cases.
async fn device_token(
    State(state): State<Arc<AppState>>,
    body: Result<axum::Json<DeviceTokenReq>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Some(pool) = &state.pool else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "No database configured",
            None,
        );
    };
    let axum::Json(req) = match body {
        Ok(b) => b,
        Err(e) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "Invalid JSON",
                Some(&e.to_string()),
            );
        }
    };
    let oauth_err = |code: &str| {
        (
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::json!({ "error": code }).to_string(),
        )
            .into_response()
    };
    match crate::db::poll_device_grant(pool, &req.device_code).await {
        Ok(crate::db::DeviceStatus::Approved(account)) => {
            match crate::db::issue_api_token(pool, &account, "device").await {
                Ok(token) => (
                    [(header::CONTENT_TYPE, "application/json")],
                    serde_json::json!({ "access_token": token, "token_type": "bearer" })
                        .to_string(),
                )
                    .into_response(),
                Err(e) => {
                    eprintln!("http: device token mint failed: {e}");
                    problem(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Database unavailable",
                        None,
                    )
                }
            }
        }
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
struct DeviceApproveReq {
    user_code: String,
}

/// Approve a device grant as the signed-in user (cookie-authenticated).
async fn device_approve(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    body: Result<axum::Json<DeviceApproveReq>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let account = match authenticate(&state, &headers).await {
        Ok(a) => a,
        Err(response) => return response,
    };
    let axum::Json(req) = match body {
        Ok(b) => b,
        Err(e) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "Invalid JSON",
                Some(&e.to_string()),
            );
        }
    };
    let pool = state.pool.as_ref().expect("authenticate checked the pool");
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
async fn require_admin(
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
async fn admin_accounts(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Err(response) = require_admin(&state, &headers).await {
        return response;
    }
    let pool = state.pool.as_ref().expect("authenticate checked the pool");
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

fn admin_json(body: serde_json::Value) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

fn admin_db_error(what: &str, e: impl std::fmt::Display) -> Response {
    eprintln!("http: admin {what} failed: {e}");
    problem(
        StatusCode::SERVICE_UNAVAILABLE,
        "Database unavailable",
        None,
    )
}

/// List every registered channel with its founder (admin only).
async fn admin_channels(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Err(response) = require_admin(&state, &headers).await {
        return response;
    }
    let pool = state.pool.as_ref().expect("authenticate checked the pool");
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
async fn admin_klines(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Err(response) = require_admin(&state, &headers).await {
        return response;
    }
    let pool = state.pool.as_ref().expect("authenticate checked the pool");
    match crate::db::list_klines(pool).await {
        Ok(rows) => admin_json(serde_json::json!({
            "klines": rows
                .into_iter()
                .map(|(mask, reason, set_by)| {
                    serde_json::json!({ "mask": mask, "reason": reason, "set_by": set_by })
                })
                .collect::<Vec<_>>(),
        })),
        Err(e) => admin_db_error("kline list", e),
    }
}

#[derive(serde::Deserialize)]
struct AuditQuery {
    limit: Option<usize>,
}

/// Query the oper audit log, newest-first (admin only).
async fn admin_audit(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(params): axum::extract::Query<AuditQuery>,
) -> Response {
    if let Err(response) = require_admin(&state, &headers).await {
        return response;
    }
    let pool = state.pool.as_ref().expect("authenticate checked the pool");
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

async fn me(State(state): State<Arc<AppState>>, headers: axum::http::HeaderMap) -> Response {
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
struct TokenRequest {
    label: String,
}

/// Mint a PAT for the authenticated account (shown once).
async fn create_api_token(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    body: Result<axum::Json<TokenRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let account = match authenticate(&state, &headers).await {
        Ok(a) => a,
        Err(response) => return response,
    };
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
    let pool = state.pool.as_ref().expect("authenticate checked the pool");
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

async fn logout(State(state): State<Arc<AppState>>, headers: axum::http::HeaderMap) -> Response {
    let Some(pool) = &state.pool else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "No database configured",
            None,
        );
    };
    if let Some(token) = session_token(&headers)
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
            "e6irc_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0".to_string(),
        )],
    )
        .into_response()
}

async fn server_info(State(state): State<Arc<AppState>>) -> Response {
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

/// OpenAPI 3.1 description of the REST surface. Hand-authored and kept in
/// step with the routes above; consumers use it to generate clients.
async fn openapi() -> Response {
    let bearer = serde_json::json!([{ "bearer": [] }]);
    let ok_json = serde_json::json!({
        "200": { "description": "OK", "content": { "application/json": {} } }
    });
    let spec = serde_json::json!({
        "openapi": "3.1.0",
        "info": {
            "title": "e6irc REST API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Account, credential, and BNC-network management for e6ircd.",
        },
        "components": {
            "securitySchemes": {
                "bearer": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "A personal access token (see POST /api/v1/me/tokens).",
                }
            }
        },
        "paths": {
            "/healthz": {
                "get": { "summary": "Liveness probe", "responses": {
                    "200": { "description": "the literal string \"ok\"" } } }
            },
            "/api/v1/server": {
                "get": { "summary": "Server name, network name, version", "responses": ok_json }
            },
            "/api/v1/auth/app-passwords": {
                "post": {
                    "summary": "Exchange an account password for a new app password",
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": { "type": "object",
                            "required": ["account", "password", "label"],
                            "properties": {
                                "account": { "type": "string" },
                                "password": { "type": "string" },
                                "label": { "type": "string" } } } } } },
                    "responses": { "200": { "description": "the app password (shown once)" },
                        "401": { "description": "bad credentials" },
                        "503": { "description": "no database configured" } }
                }
            },
            "/api/v1/me": {
                "get": { "summary": "The authenticated account", "security": bearer,
                    "responses": ok_json }
            },
            "/api/v1/auth/device/start": {
                "post": { "summary": "Begin an RFC 8628 device authorization grant",
                    "responses": { "200": { "description": "device_code, user_code, verification_uri" } } }
            },
            "/api/v1/auth/device/token": {
                "post": { "summary": "Poll for the device grant's token",
                    "responses": { "200": { "description": "access_token once approved" },
                        "400": { "description": "authorization_pending / expired_token / invalid_grant" } } }
            },
            "/api/v1/auth/device/approve": {
                "post": { "summary": "Approve a device grant by user_code", "security": bearer,
                    "responses": { "204": { "description": "approved" },
                        "404": { "description": "no such pending code" } } }
            },
            "/api/v1/me/tokens": {
                "post": { "summary": "Mint a personal access token (shown once)",
                    "security": bearer, "responses": ok_json }
            },
            "/api/v1/me/credentials": {
                "get": { "summary": "List the account's credentials", "security": bearer,
                    "responses": ok_json }
            },
            "/api/v1/me/credentials/{id}": {
                "delete": { "summary": "Revoke a credential", "security": bearer,
                    "parameters": [{ "name": "id", "in": "path", "required": true,
                        "schema": { "type": "integer" } }],
                    "responses": { "204": { "description": "revoked" },
                        "404": { "description": "no such credential" } } }
            },
            "/api/v1/me/networks": {
                "get": { "summary": "List the account's BNC networks", "security": bearer,
                    "responses": ok_json },
                "post": { "summary": "Create a BNC network and start its driver",
                    "security": bearer,
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": { "type": "object",
                            "required": ["name", "addr", "nick"],
                            "properties": {
                                "name": { "type": "string" },
                                "addr": { "type": "string" },
                                "tls": { "type": "boolean" },
                                "nick": { "type": "string" },
                                "realname": { "type": "string" },
                                "autojoin": { "type": "array", "items": { "type": "string" } },
                                "sasl_account": { "type": "string" },
                                "sasl_password": { "type": "string" } } } } } },
                    "responses": { "201": { "description": "created" },
                        "409": { "description": "duplicate name, or upstream secret with no master key" } } }
            },
            "/api/v1/me/networks/{name}": {
                "delete": { "summary": "Delete a BNC network and stop its driver",
                    "security": bearer,
                    "parameters": [{ "name": "name", "in": "path", "required": true,
                        "schema": { "type": "string" } }],
                    "responses": { "204": { "description": "deleted" },
                        "404": { "description": "no such network" } } }
            },
            "/api/v1/history": {
                "get": { "summary": "Paged message history for the account", "security": bearer,
                    "responses": ok_json }
            },
            "/api/v1/admin/accounts": {
                "get": { "summary": "List all accounts (admin only)", "security": bearer,
                    "responses": { "200": { "description": "account names" },
                        "403": { "description": "not an admin account" } } }
            },
            "/api/v1/admin/channels": {
                "get": { "summary": "List registered channels + founders (admin only)",
                    "security": bearer,
                    "responses": { "200": { "description": "channels" },
                        "403": { "description": "not an admin account" } } }
            },
            "/api/v1/admin/klines": {
                "get": { "summary": "List server bans / K-lines (admin only)",
                    "security": bearer,
                    "responses": { "200": { "description": "klines" },
                        "403": { "description": "not an admin account" } } }
            },
            "/api/v1/admin/audit": {
                "get": { "summary": "Query the oper audit log, newest-first (admin only)",
                    "security": bearer,
                    "parameters": [ { "name": "limit", "in": "query",
                        "schema": { "type": "integer" } } ],
                    "responses": { "200": { "description": "audit entries" },
                        "403": { "description": "not an admin account" } } }
            }
        }
    });
    (
        [(header::CONTENT_TYPE, "application/json")],
        spec.to_string(),
    )
        .into_response()
}

#[derive(Deserialize)]
struct AppPasswordRequest {
    account: String,
    password: String,
    label: String,
}

/// Exchange an account's password for a fresh app password (shown once;
/// only its hash is stored). The web session flow will supersede this
/// as the primary path once OIDC lands.
async fn create_app_password(
    State(state): State<Arc<AppState>>,
    body: Result<axum::Json<AppPasswordRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Some(pool) = &state.pool else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "No database configured",
            Some("This server runs without persistence; accounts are unavailable."),
        );
    };
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
        Err(e) => {
            eprintln!("http: app password issuance failed: {e}");
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            )
        }
    }
}

// ---- history ------------------------------------------------------------

#[derive(Deserialize)]
struct HistoryParams {
    target: String,
    #[serde(default)]
    before: Option<String>,
    #[serde(default)]
    after: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

/// Paged history for the authenticated account. Casefolds the target
/// the same way the IRC path does, so web and IRC see one history.
async fn history(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Query(params): Query<HistoryParams>,
) -> Response {
    if let Err(response) = authenticate(&state, &headers).await {
        return response;
    }
    let pool = state.pool.as_ref().expect("authenticate checked the pool");
    let limit = params.limit.unwrap_or(50).min(500);
    let query = match (&params.before, &params.after) {
        (Some(ts), _) => match e6irc_proto::time::parse_server_time_seconds(ts) {
            Some(before_ts) => crate::core::HistoryQuery::Before { before_ts, limit },
            None => return problem(StatusCode::BAD_REQUEST, "Invalid 'before' timestamp", None),
        },
        (None, Some(ts)) => match e6irc_proto::time::parse_server_time_seconds(ts) {
            Some(after_ts) => crate::core::HistoryQuery::After { after_ts, limit },
            None => return problem(StatusCode::BAD_REQUEST, "Invalid 'after' timestamp", None),
        },
        (None, None) => crate::core::HistoryQuery::Latest { limit },
    };
    let target = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(&params.target);
    let rows = crate::db::query_history(pool, &target, query).await;
    let messages: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "msgid": r.msgid,
                "time": e6irc_proto::time::server_time(r.ts * 1000),
                "from": r.sender_prefix,
                "kind": r.kind,
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

// ---- ws-irc (IRCv3-over-WebSocket, DESIGN §13.4) -------------------------

use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};

async fn ws_irc(State(state): State<Arc<AppState>>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| ws_irc_conn(state, socket))
}

/// Bridge one WebSocket to the IRC core: each inbound text frame is one
/// IRC line; each core Output line is one outbound text frame. Mirrors
/// the TCP connection path (net::serve_conn) over the WS transport. A
/// single task owns the socket and selects between inbound frames and
/// the drained SendQ — no split, so no extra dependency.
async fn ws_irc_conn(state: Arc<AppState>, mut socket: WebSocket) {
    use crate::core::{ConnId, Input, Output};
    use e6irc_proto::framing::{LineBuffer, LineEvent};
    use std::sync::atomic::Ordering;

    let conn = ConnId(state.next_conn.fetch_add(1, Ordering::Relaxed));
    let (out_tx, mut out_rx) = e6irc_queue::queue::<Output>(e6irc_queue::Config {
        name: "ws-sendq",
        capacity: state.sendq,
        policy: e6irc_queue::Policy::Fifo,
    });
    if state
        .core_tx
        .push(Input::Open {
            conn,
            tx: out_tx,
            host: "websocket".into(),
        })
        .await
        .is_err()
    {
        return;
    }
    let core_tx = state.core_tx.clone();
    let mut framing = LineBuffer::new(4096 + 510);
    let mut events = Vec::new();

    loop {
        tokio::select! {
            // Outbound: a core Output line becomes one text frame.
            out = out_rx.pop() => {
                let Some(env) = out else { break };
                let bytes = env.payload.0;
                let text = String::from_utf8_lossy(&bytes).trim_end().to_string();
                if socket.send(WsMessage::text(text)).await.is_err() {
                    break;
                }
            }
            // Inbound: frame(s) -> lines -> core.
            frame = socket.recv() => {
                let data: Vec<u8> = match frame {
                    Some(Ok(WsMessage::Text(t))) => t.as_bytes().to_vec(),
                    Some(Ok(WsMessage::Binary(b))) => b.to_vec(),
                    Some(Ok(_)) => continue,
                    _ => break, // close or error
                };
                let mut with_nl = data;
                with_nl.push(b'\n');
                framing.feed(&with_nl, &mut events);
                for event in events.drain(..) {
                    let input = match event {
                        LineEvent::Line(line) => Input::Line { conn, line },
                        LineEvent::TooLong => Input::OverlongLine { conn },
                    };
                    if core_tx.push(input).await.is_err() {
                        break;
                    }
                }
            }
        }
    }
    let _ = core_tx
        .push(Input::Closed {
            conn,
            reason: "WebSocket closed".into(),
        })
        .await;
}

// ---- live web UI socket (DESIGN §13.2) ----------------------------------

#[derive(Deserialize)]
struct UiParams {
    /// Which of the caller's networks to attach this UI socket to.
    network: String,
}

/// The web client's live socket: cookie-authenticated, attaches to one
/// of the caller's networks, and pushes ready-to-swap HTML fragments
/// (the browser side runs htmx's WS extension). Composer text sent up
/// the socket is relayed to the upstream network. This is the same
/// multiplexer attach path an IRC client uses — the web client *is* an
/// attached client.
async fn ws_ui(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Query(params): Query<UiParams>,
    ws: WebSocketUpgrade,
) -> Response {
    let account = match authenticate(&state, &headers).await {
        Ok(a) => a,
        Err(response) => return response,
    };
    let Some(registry) = &state.bnc_registry else {
        return problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None);
    };
    let Some(handle) = registry.get(&account, &params.network) else {
        return problem(StatusCode::NOT_FOUND, "No such network", None);
    };
    ws.on_upgrade(move |socket| ws_ui_conn(handle, socket))
}

async fn ws_ui_conn(handle: std::sync::Arc<crate::bouncer::NetworkHandle>, mut socket: WebSocket) {
    use crate::bouncer::DriverEvent;
    use tokio::sync::broadcast::error::RecvError;

    // Playback: everything buffered while detached, as fragments.
    for line in handle.buffer_snapshot() {
        if socket
            .send(WsMessage::text(render_line_fragment(&line)))
            .await
            .is_err()
        {
            return;
        }
    }
    let mut events = handle.subscribe();
    loop {
        tokio::select! {
            ev = events.recv() => match ev {
                Ok(DriverEvent::Line(line)) => {
                    if socket
                        .send(WsMessage::text(render_line_fragment(&line)))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(DriverEvent::Connected) => {
                    let _ = socket.send(WsMessage::text(render_status_fragment("connected"))).await;
                }
                Ok(DriverEvent::Disconnected) => {
                    let _ = socket.send(WsMessage::text(render_status_fragment("disconnected"))).await;
                }
                Err(RecvError::Lagged(_)) => {}      // slow client: skip the gap
                Err(RecvError::Closed) => break,      // driver gone
            },
            frame = socket.recv() => match frame {
                Some(Ok(WsMessage::Text(t))) => {
                    if !handle.send(&composer_to_irc(&t)) {
                        break; // driver gone
                    }
                }
                Some(Ok(_)) => {}
                _ => break, // close or error
            },
        }
    }
}

/// Translate a composer frame into an IRC line. The htmx web composer
/// sends a JSON form (`{"target": "#c", "message": "hi", ...}`) which
/// becomes `PRIVMSG #c :hi`, with a small set of slash-commands. A
/// non-JSON frame (e.g. a raw line from a script or test) is relayed
/// unchanged.
fn composer_to_irc(frame: &str) -> String {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(frame) else {
        return frame.to_string();
    };
    let Some(message) = v.get("message").and_then(|m| m.as_str()) else {
        return frame.to_string();
    };
    let target = v.get("target").and_then(|t| t.as_str()).unwrap_or("");
    slash_to_irc(message, target)
}

/// Map a composer message (with the current `target`) to an IRC line.
/// Recognised slash-commands: `/raw`, `/me`, `/msg`, `/join`, `/part`,
/// `/nick`, `/topic`. Anything else is a PRIVMSG to `target`.
fn slash_to_irc(message: &str, target: &str) -> String {
    let (cmd, rest) = match message.strip_prefix('/') {
        Some(body) => match body.split_once(' ') {
            Some((c, r)) => (c.to_ascii_lowercase(), r),
            None => (body.to_ascii_lowercase(), ""),
        },
        None => {
            return if target.is_empty() {
                message.to_string()
            } else {
                format!("PRIVMSG {target} :{message}")
            };
        }
    };
    match cmd.as_str() {
        "raw" => rest.to_string(),
        "me" => format!("PRIVMSG {target} :\u{1}ACTION {rest}\u{1}"),
        "join" | "part" | "nick" => format!("{} {rest}", cmd.to_ascii_uppercase()),
        "topic" => format!("TOPIC {target} :{rest}"),
        // `/msg <target> <text>`
        "msg" => match rest.split_once(' ') {
            Some((to, text)) => format!("PRIVMSG {to} :{text}"),
            None => rest.to_string(),
        },
        // Unknown slash-command: pass it through raw (server answers 421).
        _ => format!("{} {rest}", cmd.to_ascii_uppercase()),
    }
}

/// Escape text for safe interpolation into an HTML fragment.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// One upstream line as an out-of-band append into the buffer element.
fn render_line_fragment(line: &str) -> String {
    format!(
        "<div hx-swap-oob=\"beforeend:#buffer\"><div class=\"line\">{}</div></div>",
        html_escape(line)
    )
}

/// A connection-status change as an OOB swap of the status element.
fn render_status_fragment(status: &str) -> String {
    format!(
        "<div id=\"status\" hx-swap-oob=\"true\" class=\"status status-{status}\">{}</div>",
        html_escape(status)
    )
}

// ---- credential management ----------------------------------------------

async fn list_credentials(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    let account = match authenticate(&state, &headers).await {
        Ok(a) => a,
        Err(response) => return response,
    };
    let pool = state.pool.as_ref().expect("authenticate checked the pool");
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
        Err(e) => {
            eprintln!("http: credential list failed: {e}");
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            )
        }
    }
}

async fn revoke_credential(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let account = match authenticate(&state, &headers).await {
        Ok(a) => a,
        Err(response) => return response,
    };
    let pool = state.pool.as_ref().expect("authenticate checked the pool");
    match crate::db::revoke_credential(pool, &account, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => problem(StatusCode::NOT_FOUND, "No such credential", None),
        Err(e) => {
            eprintln!("http: credential revoke failed: {e}");
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            )
        }
    }
}

// ---- per-account BNC networks -------------------------------------------

#[derive(Deserialize)]
struct CreateNetwork {
    name: String,
    addr: String,
    #[serde(default)]
    tls: bool,
    nick: String,
    #[serde(default)]
    realname: Option<String>,
    #[serde(default)]
    autojoin: Vec<String>,
    /// Upstream SASL account + password (plaintext over the API; stored
    /// sealed). Both or neither.
    #[serde(default)]
    sasl_account: Option<String>,
    #[serde(default)]
    sasl_password: Option<String>,
}

/// The account's own networks (metadata only — never the secret).
async fn list_networks(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    let account = match authenticate(&state, &headers).await {
        Ok(a) => a,
        Err(response) => return response,
    };
    if state.bnc_registry.is_none() {
        return problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None);
    }
    let pool = state.pool.as_ref().expect("authenticate checked the pool");
    match crate::db::list_bnc_networks(pool, &account).await {
        Ok(rows) => {
            let nets: Vec<serde_json::Value> = rows
                .into_iter()
                .map(|n| {
                    serde_json::json!({
                        "name": n.name,
                        "addr": n.addr,
                        "tls": n.tls,
                        "nick": n.nick,
                        "realname": n.realname,
                        "autojoin": n.autojoin,
                        "sasl_account": n.sasl_account,
                        "has_sasl_password": n.sasl_password_sealed.is_some(),
                    })
                })
                .collect();
            (
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::json!({ "networks": nets }).to_string(),
            )
                .into_response()
        }
        Err(e) => {
            eprintln!("http: network list failed: {e}");
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            )
        }
    }
}

/// Create a network the caller owns, persist it, and start its always-on
/// driver.
async fn create_network(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    body: Result<axum::Json<CreateNetwork>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let account = match authenticate(&state, &headers).await {
        Ok(a) => a,
        Err(response) => return response,
    };
    let Some(registry) = &state.bnc_registry else {
        return problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None);
    };
    let axum::Json(req) = match body {
        Ok(b) => b,
        Err(e) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "Invalid JSON",
                Some(&e.to_string()),
            );
        }
    };

    match create_network_core(&state, registry, &account, &req).await {
        Ok(()) => (
            StatusCode::CREATED,
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::json!({ "name": req.name, "attach": format!("{}/{}", account, req.name) })
                .to_string(),
        )
            .into_response(),
        Err(response) => response,
    }
}

/// The one create path: validate, seal the upstream secret, persist, and
/// start the driver. Used by both the JSON API and the account form.
async fn create_network_core(
    state: &AppState,
    registry: &crate::bouncer::Registry,
    account: &str,
    req: &CreateNetwork,
) -> Result<(), Response> {
    // The name is the client-facing /network selector: no separator or
    // whitespace, and non-empty.
    if req.name.is_empty() || req.name.contains('/') || req.name.chars().any(char::is_whitespace) {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "Invalid network name",
            Some("name must be non-empty and contain no '/' or whitespace"),
        ));
    }
    if req.addr.is_empty() || req.nick.is_empty() {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "addr and nick are required",
            None,
        ));
    }
    // Upstream SASL is both-or-neither.
    let upstream = match (&req.sasl_account, &req.sasl_password) {
        (Some(a), Some(p)) => Some((a.clone(), p.clone())),
        (None, None) => None,
        _ => {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                "Incomplete upstream SASL",
                Some("provide both sasl_account and sasl_password, or neither"),
            ));
        }
    };
    // Seal the upstream password for storage; requires a master key.
    let sealed = match &upstream {
        Some((_, password)) => {
            let Some(key) = &state.secret_key else {
                return Err(problem(
                    StatusCode::CONFLICT,
                    "No master key configured",
                    Some("the server cannot store upstream credentials without [secrets]"),
                ));
            };
            Some(key.seal(password))
        }
        None => None,
    };

    let row = crate::db::BncNetworkRow {
        name: req.name.clone(),
        addr: req.addr.clone(),
        tls: req.tls,
        nick: req.nick.clone(),
        realname: req.realname.clone(),
        autojoin: req.autojoin.clone(),
        sasl_account: upstream.as_ref().map(|(a, _)| a.clone()),
        sasl_password_sealed: sealed,
    };
    let pool = state.pool.as_ref().expect("caller checked the pool");
    match crate::db::create_bnc_network(pool, account, &row).await {
        Ok(_) => {}
        Err(crate::db::DbError::DuplicateNetwork(_)) => {
            return Err(problem(
                StatusCode::CONFLICT,
                "Network already exists",
                None,
            ));
        }
        Err(e) => {
            eprintln!("http: network create failed: {e}");
            return Err(problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            ));
        }
    }

    registry.add(
        Some(account.to_string()),
        req.name.clone(),
        Box::new(crate::bouncer::IrcDriver::new(
            crate::bouncer::NetworkConfig {
                addr: req.addr.clone(),
                tls: req.tls,
                nick: req.nick.clone(),
                realname: req.realname.clone().unwrap_or_else(|| req.nick.clone()),
                autojoin: req.autojoin.clone(),
                buffer_cap: 1000,
                sasl: upstream,
            },
        )),
    );
    Ok(())
}

/// Delete one of the caller's networks and stop its driver.
async fn delete_network(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(name): Path<String>,
) -> Response {
    let account = match authenticate(&state, &headers).await {
        Ok(a) => a,
        Err(response) => return response,
    };
    let Some(registry) = &state.bnc_registry else {
        return problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None);
    };
    let pool = state.pool.as_ref().expect("authenticate checked the pool");
    match crate::db::delete_bnc_network(pool, &account, &name).await {
        Ok(true) => {
            registry.remove(Some(&account), &name);
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => problem(StatusCode::NOT_FOUND, "No such network", None),
        Err(e) => {
            eprintln!("http: network delete failed: {e}");
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            )
        }
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
