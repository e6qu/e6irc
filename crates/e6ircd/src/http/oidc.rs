//! OIDC login, linking and back-channel logout.

use super::*;

// ---- OIDC login ---------------------------------------------------------

pub(super) type OidcClient = openidconnect::core::CoreClient<
    openidconnect::EndpointSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointMaybeSet,
    openidconnect::EndpointMaybeSet,
>;

pub(super) fn oidc_http_client() -> openidconnect::reqwest::Client {
    // No redirect following: token endpoints must answer directly. Timeouts
    // bound each outbound call so an unresponsive IdP (reached from
    // unauthenticated login/discovery/back-channel paths) can't pin a task.
    openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .expect("reqwest client")
}

pub(super) async fn discover_client(
    state: &AppState,
    provider: &OidcProviderConfig,
) -> Result<OidcClient, String> {
    use openidconnect::{ClientId, ClientSecret, RedirectUrl};
    let metadata = discover_metadata(provider).await?;
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
    let auth_type = match provider.token_endpoint_auth_method {
        crate::config::TokenEndpointAuthMethod::ClientSecretBasic => {
            openidconnect::AuthType::BasicAuth
        }
        crate::config::TokenEndpointAuthMethod::ClientSecretPost => {
            openidconnect::AuthType::RequestBody
        }
    };
    Ok(openidconnect::core::CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(provider.client_id.clone()),
        Some(ClientSecret::new(provider.client_secret.clone())),
    )
    .set_redirect_uri(redirect)
    .set_auth_type(auth_type))
}

/// TTL for a cached OIDC discovery document (and its JWKS). Bounds outbound
/// fetches so an unauthenticated flood of login/logout requests can't amplify
/// into one IdP round-trip each.
pub(super) const DISCOVERY_TTL: std::time::Duration = std::time::Duration::from_secs(900);

#[allow(clippy::type_complexity)]
pub(super) fn discovery_cache() -> &'static std::sync::Mutex<
    HashMap<
        String,
        (
            std::time::Instant,
            openidconnect::core::CoreProviderMetadata,
        ),
    >,
> {
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<
            HashMap<
                String,
                (
                    std::time::Instant,
                    openidconnect::core::CoreProviderMetadata,
                ),
            >,
        >,
    > = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

pub(super) async fn discover_metadata(
    provider: &OidcProviderConfig,
) -> Result<openidconnect::core::CoreProviderMetadata, String> {
    use openidconnect::IssuerUrl;
    let key = provider.issuer_url.clone();
    // Serve a fresh cached document (which already carries the JWKS) without
    // an outbound fetch.
    if let Some((at, meta)) = discovery_cache().lock().expect("poisoned").get(&key)
        && at.elapsed() < DISCOVERY_TTL
    {
        return Ok(meta.clone());
    }
    let issuer = IssuerUrl::new(key.clone()).map_err(|e| e.to_string())?;
    let meta =
        openidconnect::core::CoreProviderMetadata::discover_async(issuer, &oidc_http_client())
            .await
            .map_err(|e| format!("discovery failed: {e}"))?;
    discovery_cache()
        .lock()
        .expect("poisoned")
        .insert(key, (std::time::Instant::now(), meta.clone()));
    Ok(meta)
}

pub(super) async fn oidc_start(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    Path(provider_name): Path<String>,
) -> Response {
    // Rate-limit login starts per client IP: each forces an outbound discovery
    // fetch and grows pending_auth, so an unauthenticated flood is throttled.
    if !auth_rate_ok(
        &state,
        client_ip(peer.ip(), &headers, &state.trusted_proxies),
    ) {
        return problem(StatusCode::TOO_MANY_REQUESTS, "Too many requests", None);
    }
    oidc_authorize(&state, &provider_name, None, false).await
}

/// Silently check for an existing SSO session at the provider
/// (`prompt=none`). If the browser already has a session with the identity
/// provider (e.g. Shauth), the provider returns a code with no prompt and
/// the callback logs the user in; otherwise it returns `login_required` and
/// the callback bounces to `/?sso=none` so the app can offer interactive
/// login. This is how e6irc "recognizes" the cross-origin SSO cookie
/// without a second explicit login.
pub(super) async fn oidc_sso_start(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    Path(provider_name): Path<String>,
) -> Response {
    if !auth_rate_ok(
        &state,
        client_ip(peer.ip(), &headers, &state.trusted_proxies),
    ) {
        return problem(StatusCode::TOO_MANY_REQUESTS, "Too many requests", None);
    }
    oidc_authorize(&state, &provider_name, None, true).await
}

/// Begin an OIDC flow that *links* the resulting identity to the
/// authenticated caller's account rather than logging in. The account is
/// remembered in the pending-auth entry; the shared callback attaches the
/// identity when the provider returns.
pub(super) async fn oidc_link_start(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    Authenticated(account): Authenticated,
    Path(provider_name): Path<String>,
) -> Response {
    // Rate-limit per client IP like oidc_start/oidc_sso_start: each call forces
    // a discovery fetch and grows `pending_auth`. Authenticated, so not an
    // unauthenticated vector, but gated for parity with its siblings.
    if !auth_rate_ok(
        &state,
        client_ip(peer.ip(), &headers, &state.trusted_proxies),
    ) {
        return problem(StatusCode::TOO_MANY_REQUESTS, "Too many requests", None);
    }
    oidc_authorize(&state, &provider_name, Some(account), false).await
}

/// Shared authorization-request builder for login, link, and silent-SSO
/// flows. `silent` adds `prompt=none` so the provider returns without any
/// UI (used for the SSO-session probe).
/// Cap on in-flight OIDC login flows, bounding the `pending_auth` map against
/// an unauthenticated flood of login initiations.
pub(super) const MAX_PENDING_AUTH: usize = 4096;

pub(super) async fn oidc_authorize(
    state: &AppState,
    provider_name: &str,
    link_account: Option<String>,
    silent: bool,
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
    let client = match discover_client(state, &provider).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("oidc: {e}");
            return problem(StatusCode::BAD_GATEWAY, "OIDC provider unreachable", None);
        }
    };
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let mut request = client
        .authorize_url(
            openidconnect::core::CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(pkce_challenge);
    // `openid` is implied by the flow; add the provider's other scopes
    // (defaulting to profile + email).
    let scopes = if provider.scopes.is_empty() {
        vec!["profile".to_string(), "email".to_string()]
    } else {
        provider.scopes.clone()
    };
    for scope in scopes {
        request = request.add_scope(Scope::new(scope));
    }
    if silent {
        request = request.add_extra_param("prompt", "none");
    }
    let (auth_url, csrf, nonce) = request.url();
    let mut pending = state.pending_auth.lock().expect("poisoned");
    pending.retain(|_, p| p.started.elapsed() < Duration::from_secs(600));
    // Bound the map so an unauthenticated flood of /start (each entry lives up
    // to 10 minutes) cannot grow it without limit.
    if pending.len() >= MAX_PENDING_AUTH {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many pending logins; retry shortly",
            None,
        );
    }
    pending.insert(
        csrf.secret().clone(),
        PendingAuth {
            provider: provider.name.clone(),
            pkce_verifier: pkce_verifier.secret().clone(),
            nonce,
            started: Instant::now(),
            link_account,
            silent,
        },
    );
    drop(pending);
    // Bind the flow to this browser: an HttpOnly cookie equal to the OAuth
    // `state`. The callback requires it, so a login response captured by an
    // attacker cannot be replayed into a victim's browser to plant the
    // attacker's session (login CSRF / session fixation). SameSite=Lax still
    // rides the top-level redirect back from the provider.
    let secure = if state.secure_cookies { "; Secure" } else { "" };
    (
        StatusCode::TEMPORARY_REDIRECT,
        [
            (header::LOCATION, auth_url.to_string()),
            (
                header::SET_COOKIE,
                format!(
                    "{}={}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600{secure}",
                    oidc_state_cookie_name(state.secure_cookies),
                    csrf.secret()
                ),
            ),
        ],
    )
        .into_response()
}

#[derive(Deserialize)]
pub(super) struct CallbackQuery {
    pub(super) code: Option<String>,
    pub(super) state: Option<String>,
    pub(super) error: Option<String>,
}

pub(super) async fn oidc_callback(
    State(state): State<Arc<AppState>>,
    Path(provider_name): Path<String>,
    headers: axum::http::HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    use openidconnect::{AuthorizationCode, PkceCodeVerifier, TokenResponse};
    if let Some(err) = query.error {
        // Consuming the pending entry requires the browser to present the
        // binding cookie, constant-time-equal to the returned `state` — the
        // same guard the success path applies below, and for the same reason:
        // an attacker who learns a victim's in-flight `state` but lacks the
        // cookie must not be able to race the callback with `?error=…&state=…`
        // and burn the victim's still-pending login (a login-DoS). An unbound
        // error callback still gets the honest refusal response; it just does
        // not get to delete anyone's pending entry.
        let bound_state = query.state.as_ref().filter(|s| {
            cookie_value(&headers, oidc_state_cookie_name(state.secure_cookies)).is_some_and(|c| {
                aws_lc_rs::constant_time::verify_slices_are_equal(c.as_bytes(), s.as_bytes())
                    .is_ok()
            })
        });
        // A silent SSO probe (`prompt=none`) with no upstream session comes
        // back as `login_required`; that is expected — clear the pending
        // entry and bounce to interactive login rather than erroring.
        let was_silent = bound_state
            .and_then(|s| state.pending_auth.lock().expect("poisoned").remove(s))
            .is_some_and(|p| p.silent);
        if was_silent {
            // `consent_required` is not `login_required`: the browser *does*
            // have a provider session, it has simply never authorized this
            // client. OpenID Connect answers a silent probe that way on a
            // relying party's first visit, and the specified next step is one
            // ordinary authorization request. For a first-party application
            // the provider grants that without any interaction, so single
            // sign-on stays seamless; treating it as "not signed in" would
            // strand a signed-in user on the sign-in page forever, because the
            // consent that is missing can never be recorded by probing.
            if err == "consent_required" {
                return oidc_authorize(&state, &provider_name, None, false).await;
            }
            return Redirect::to("/?sso=none").into_response();
        }
        return problem(StatusCode::UNAUTHORIZED, "OIDC login refused", Some(&err));
    }
    let (Some(code), Some(csrf_state)) = (query.code, query.state) else {
        return problem(StatusCode::BAD_REQUEST, "Missing code or state", None);
    };
    // Require the browser to present the binding cookie set at authorize time,
    // constant-time-equal to the returned `state`. Without this, an attacker
    // who completed their own login could feed the resulting callback URL to a
    // victim and plant the attacker's session in the victim's browser.
    //
    // This check comes *before* the pending entry is consumed: an attacker who
    // learns a victim's in-flight `state` but lacks the browser cookie must be
    // turned away without burning the victim's login, or they could DoS every
    // in-flight sign-in by racing the callback.
    let bound =
        cookie_value(&headers, oidc_state_cookie_name(state.secure_cookies)).is_some_and(|c| {
            aws_lc_rs::constant_time::verify_slices_are_equal(c.as_bytes(), csrf_state.as_bytes())
                .is_ok()
        });
    if !bound {
        return problem(
            StatusCode::UNAUTHORIZED,
            "Login state not bound to this browser",
            None,
        );
    }
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
    let sid = jwt_string_claim(&id_token.to_string(), "sid")
        .ok()
        .flatten();
    // Link flow: attach this identity to the account that started it,
    // rather than logging in / provisioning a new account.
    if let Some(account) = &pending.link_account {
        return match crate::db::link_oidc_identity(&pool, account, issuer, subject).await {
            Ok(crate::db::LinkOutcome::Linked | crate::db::LinkOutcome::AlreadyYours) => {
                Redirect::to("/?linked=1").into_response()
            }
            Ok(crate::db::LinkOutcome::Conflict) => problem(
                StatusCode::CONFLICT,
                "Identity already linked to another account",
                None,
            ),
            Err(e) => {
                eprintln!("oidc: identity link failed: {e}");
                problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Account storage failed",
                    None,
                )
            }
        };
    }
    let preferred = claims
        .preferred_username()
        .map(|u| u.as_str().to_string())
        .or_else(|| {
            claims
                .email()
                .and_then(|e| e.as_str().split('@').next().map(str::to_string))
        })
        .unwrap_or_else(|| "user".to_string());
    // The provider-supplied name is echoed into IRC numerics/tags (WHOISACCOUNT,
    // extended-join, account= tag); strip anything that isn't a safe nick-like
    // character so a spaced/control-laden username can't split a line.
    let preferred = crate::sanitize::account_name(&preferred);
    let email = claims.email().map(|value| value.as_str().to_string());
    let role = jwt_string_claim(&id_token.to_string(), "role")
        .ok()
        .flatten();
    let verified_shauth_identity = email.is_some()
        && claims.email_verified() == Some(true)
        && matches!(role.as_deref(), Some("developer" | "admin"));
    if pending.provider == "shauth" && !verified_shauth_identity {
        return problem(
            StatusCode::UNAUTHORIZED,
            "Shauth identity claims are incomplete",
            None,
        );
    }
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
    // Record the id token + provider so logout can end the provider's SSO
    // session (RP-initiated logout), not just the local e6irc session.
    let id_token_raw = id_token.to_string();
    let token = match crate::db::create_oidc_web_session(
        &pool,
        &account,
        crate::db::OidcSessionIdentity {
            id_token: Some(&id_token_raw),
            provider: Some(&pending.provider),
            issuer: Some(issuer),
            subject: Some(subject),
            sid: sid.as_deref(),
            email: email.as_deref(),
            role: role.as_deref(),
        },
    )
    .await
    {
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
                    "{}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=1209600{secure}",
                    session_cookie_name(state.secure_cookies)
                ),
            ),
            // The state-binding cookie has done its job (the pending entry was
            // consumed above); expire it now rather than leaving it in the
            // browser until its Max-Age. Defense-in-depth — no stray auth state.
            (
                header::SET_COOKIE,
                format!(
                    "{}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0{secure}",
                    oidc_state_cookie_name(state.secure_cookies)
                ),
            ),
        ],
    )
        .into_response()
}

pub(super) const BACKCHANNEL_LOGOUT_EVENT: &str =
    "http://schemas.openid.net/event/backchannel-logout";

#[derive(Deserialize)]
pub(super) struct BackchannelLogoutForm {
    pub(super) logout_token: String,
}

#[derive(Deserialize)]
pub(super) struct FrontchannelLogoutQuery {
    pub(super) iss: String,
    pub(super) sid: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}

impl AudienceClaim {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.iter().any(|value| value == expected),
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct BackchannelLogoutClaims {
    pub(super) iss: String,
    pub(super) aud: AudienceClaim,
    #[serde(default)]
    pub(super) sub: Option<String>,
    #[serde(default)]
    pub(super) sid: Option<String>,
    pub(super) iat: i64,
    #[serde(default)]
    pub(super) exp: Option<i64>,
    pub(super) jti: String,
    pub(super) events: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub(super) azp: Option<String>,
    #[serde(default)]
    pub(super) nonce: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub(super) struct LogoutTokenHeader {
    pub(super) alg: openidconnect::core::CoreJwsSigningAlgorithm,
    #[serde(default)]
    pub(super) kid: Option<String>,
    #[serde(default)]
    pub(super) typ: Option<String>,
}

pub(super) fn base64url_decode(segment: &str) -> Result<Vec<u8>, String> {
    if segment.is_empty()
        || segment.contains('=')
        || !segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err("invalid base64url segment".into());
    }
    let mut standard = segment.replace('-', "+").replace('_', "/");
    standard.extend(std::iter::repeat_n('=', (4 - standard.len() % 4) % 4));
    e6irc_proto::base64::decode(&standard).ok_or_else(|| "invalid base64url segment".into())
}

pub(super) fn jwt_string_claim(raw: &str, name: &str) -> Result<Option<String>, String> {
    let segments: Vec<&str> = raw.split('.').collect();
    if segments.len() != 3 {
        return Err("JWT must have three segments".into());
    }
    let payload: serde_json::Value = serde_json::from_slice(&base64url_decode(segments[1])?)
        .map_err(|_| "JWT payload is not JSON")?;
    Ok(payload
        .get(name)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string))
}

pub(super) fn verify_logout_token_with_metadata(
    raw: &str,
    provider: &OidcProviderConfig,
    supported_algorithms: &[openidconnect::core::CoreJwsSigningAlgorithm],
    keys: &[openidconnect::core::CoreJsonWebKey],
    now: i64,
) -> Result<BackchannelLogoutClaims, String> {
    use openidconnect::JsonWebKey;

    let segments: Vec<&str> = raw.split('.').collect();
    if segments.len() != 3 {
        return Err("logout token must have three segments".into());
    }
    let header: LogoutTokenHeader = serde_json::from_slice(&base64url_decode(segments[0])?)
        .map_err(|_| "logout token header is invalid")?;
    if header.typ.as_deref().is_some_and(|typ| typ != "logout+jwt") {
        return Err("logout token type is invalid".into());
    }
    if !supported_algorithms.contains(&header.alg) {
        return Err("logout token signing algorithm is not supported by the provider".into());
    }
    let signature = base64url_decode(segments[2])?;
    let signing_input = format!("{}.{}", segments[0], segments[1]);
    let valid_keys = keys
        .iter()
        .filter(|key| {
            header
                .kid
                .as_deref()
                .is_none_or(|kid| key.key_id().is_some_and(|key_id| key_id.as_str() == kid))
        })
        .filter(|key| {
            key.verify_signature(&header.alg, signing_input.as_bytes(), &signature)
                .is_ok()
        })
        .count();
    if valid_keys != 1 {
        return Err("logout token signature is invalid or ambiguous".into());
    }
    let mut claims: BackchannelLogoutClaims =
        serde_json::from_slice(&base64url_decode(segments[1])?)
            .map_err(|_| "logout token claims are invalid")?;
    // A whitespace-only / empty sid or sub cannot identify a session. Login
    // stores these values verbatim, so a real value is compared as-is (do
    // NOT trim — that would stop it matching what was stored); only a blank
    // one is dropped to `None` so it never reaches revocation as `Some("")`,
    // which would over-constrain the query and silently revoke nothing.
    let has_subject = claims.sub.as_deref().is_some_and(|v| !v.trim().is_empty());
    let has_sid = claims.sid.as_deref().is_some_and(|v| !v.trim().is_empty());
    if claims.iss != provider.issuer_url
        || !claims.aud.contains(&provider.client_id)
        // If `azp` (authorized party) is present it must name this client —
        // this rejects a multi-audience token authorized to a different RP
        // that merely also lists our client_id.
        || claims.azp.as_deref().is_some_and(|azp| azp != provider.client_id)
        || claims.jti.trim().is_empty()
        || claims.nonce.is_some()
        || (!has_subject && !has_sid)
        || claims.iat < now - 600
        || claims.iat > now + 60
        || claims.exp.is_some_and(|exp| exp <= now)
        || claims.events.len() != 1
        // The backchannel-logout event's value is a JSON object that MAY
        // carry data — require it present and an object, not exactly empty.
        || !claims
            .events
            .get(BACKCHANNEL_LOGOUT_EVENT)
            .is_some_and(serde_json::Value::is_object)
    {
        return Err("logout token claims are invalid".into());
    }
    if !has_subject {
        claims.sub = None;
    }
    if !has_sid {
        claims.sid = None;
    }
    Ok(claims)
}

pub(super) async fn oidc_backchannel_logout(
    State(state): State<Arc<AppState>>,
    form: Result<Form<BackchannelLogoutForm>, axum::extract::rejection::FormRejection>,
) -> Response {
    let Some(pool) = &state.pool else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "No database configured",
            None,
        );
    };
    let Form(form) = match form {
        Ok(value) => value,
        Err(_) => return problem(StatusCode::BAD_REQUEST, "Invalid logout token", None),
    };
    let unverified_issuer = match jwt_string_claim(form.logout_token.trim(), "iss") {
        Ok(Some(value)) => value,
        _ => return problem(StatusCode::BAD_REQUEST, "Invalid logout token", None),
    };
    let Some(provider) = state
        .oidc_providers
        .iter()
        .find(|provider| provider.issuer_url == unverified_issuer)
    else {
        return problem(StatusCode::BAD_REQUEST, "Invalid logout token", None);
    };
    let metadata = match discover_metadata(provider).await {
        Ok(value) => value,
        Err(error) => {
            eprintln!("oidc: logout metadata discovery failed: {error}");
            return problem(StatusCode::BAD_GATEWAY, "OIDC provider unreachable", None);
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs() as i64;
    let claims = match verify_logout_token_with_metadata(
        form.logout_token.trim(),
        provider,
        metadata.id_token_signing_alg_values_supported(),
        metadata.jwks().keys(),
        now,
    ) {
        Ok(value) => value,
        Err(_) => return problem(StatusCode::BAD_REQUEST, "Invalid logout token", None),
    };
    let expires_at = claims.exp.unwrap_or(claims.iat + 600);
    match crate::db::consume_oidc_backchannel_logout(
        pool,
        &claims.iss,
        claims.sub.as_deref(),
        claims.sid.as_deref(),
        &claims.jti,
        expires_at,
    )
    .await
    {
        Ok(_) => StatusCode::OK.into_response(),
        Err(crate::db::DbError::ReplayedLogoutToken) => {
            problem(StatusCode::BAD_REQUEST, "Invalid logout token", None)
        }
        Err(error) => {
            eprintln!("oidc: back-channel session revocation failed: {error}");
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Session storage failed",
                None,
            )
        }
    }
}

pub(super) async fn oidc_frontchannel_logout(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    Query(query): Query<FrontchannelLogoutQuery>,
) -> Response {
    // Unlike the signed back-channel path, this endpoint has no token to verify —
    // it revokes a session by a guessable `sid`. Rate-limit per client IP so it
    // can't be used to brute-force sids and force-logout victims, matching the
    // other unauthenticated OIDC endpoints.
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
    if query.sid.trim().is_empty()
        || !state
            .oidc_providers
            .iter()
            .any(|provider| provider.issuer_url == query.iss)
    {
        return problem(
            StatusCode::BAD_REQUEST,
            "Invalid front-channel logout",
            None,
        );
    }
    if let Err(error) =
        crate::db::revoke_oidc_frontchannel_sessions(pool, &query.iss, &query.sid).await
    {
        eprintln!("oidc: front-channel session revocation failed: {error}");
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Session storage failed",
            None,
        );
    }
    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store".to_string()),
            (
                header::SET_COOKIE,
                clear_session_cookie(state.secure_cookies),
            ),
        ],
        "",
    )
        .into_response()
}

/// The single authentication choke point for the REST API: session
/// cookie or `Authorization: Bearer` PAT, resolved to an account name.
/// A JSON body, rejected as a problem document rather than axum's default.
///
/// Several routes spelled out the same ten-line match to turn a
/// `JsonRejection` into `400 Invalid JSON`. As an extractor the conversion
/// happens once and a handler simply asks for the body it needs.
pub(crate) struct JsonBody<T>(pub(crate) T);

impl<T, S> axum::extract::FromRequest<S> for JsonBody<T>
where
    axum::Json<T>:
        axum::extract::FromRequest<S, Rejection = axum::extract::rejection::JsonRejection>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(axum::Json(value)) => Ok(JsonBody(value)),
            Err(e) => Err(problem(
                StatusCode::BAD_REQUEST,
                "Invalid JSON",
                Some(&e.to_string()),
            )),
        }
    }
}

/// An authenticated account, extracted before the handler body runs.
///
/// Every authenticated route opened with the same eight lines: call
/// `authenticate`, return its rejection, then re-derive the pool it had already
/// proved was there. As an extractor that prologue does not exist to be
/// repeated — a route is authenticated because it asks for this in its
/// signature, which is also where a reader looks to find out.
pub(crate) struct Authenticated(pub(crate) String);

impl axum::extract::FromRequestParts<Arc<AppState>> for Authenticated {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        authenticate(state, &parts.headers).await.map(Authenticated)
    }
}

/// The authenticated account of an **admin**. Same idea as [`Authenticated`],
/// one rung up: a handler that asks for this in its signature cannot be reached
/// by a non-admin, and — the point — an admin route cannot *forget* the check,
/// because the check is the parameter, not a first line a new handler might
/// omit. (Admin gating was a convention every `admin_*` handler had to open
/// with; this makes the ungated admin handler fail to compile for want of an
/// argument, the same way [`Authenticated`] did for authentication.)
pub(crate) struct AdminAccount;

impl axum::extract::FromRequestParts<Arc<AppState>> for AdminAccount {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        // The gate is the point; the admin's name is discarded because no admin
        // read endpoint needs it. A future audited admin *action* that wants the
        // actor can carry it then.
        require_admin(state, &parts.headers)
            .await
            .map(|_account| AdminAccount)
    }
}

/// The pool, once a request has authenticated. `authenticate` fails closed when
/// no database is configured, so reaching a handler body proves one.
pub(super) fn pool_of(state: &AppState) -> &sqlx::PgPool {
    state.pool.as_ref().expect("authenticate checked the pool")
}

pub(super) async fn authenticate(
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
    if let Some(token) = session_token(headers, state.secure_cookies) {
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

/// Resolve the real client IP: if the socket peer is a trusted proxy, take the
/// rightmost non-trusted `X-Forwarded-For` entry (the client the proxy chain
/// received from); otherwise the peer is the client. XFF is only consulted for
/// trusted peers so a direct client cannot spoof its IP with the header.
pub(super) fn client_ip(
    peer: std::net::IpAddr,
    headers: &axum::http::HeaderMap,
    trusted: &[ipnet::IpNet],
) -> std::net::IpAddr {
    if !trusted.iter().any(|net| net.contains(&peer)) {
        return peer;
    }
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        for part in xff.rsplit(',') {
            if let Some(ip) = parse_forwarded_ip(part)
                && !trusted.iter().any(|net| net.contains(&ip))
            {
                return ip;
            }
        }
    }
    peer
}

/// Parse one `X-Forwarded-For` entry to an IP, tolerating the `ip:port` and
/// bracketed-IPv6 forms some proxies emit (`203.0.113.9:443`, `[2001:db8::1]`,
/// `[2001:db8::1]:443`). A bare `parse::<IpAddr>()` rejects all of those, which
/// would make `client_ip` silently skip the real rightmost client and fall back
/// to a spoofable left-hand entry or the proxy's own IP — collapsing per-IP
/// rate limits and bans onto one key. Returns `None` only for a truly malformed
/// entry.
fn parse_forwarded_ip(entry: &str) -> Option<std::net::IpAddr> {
    let s = entry.trim();
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return Some(ip); // bare IPv4 or unbracketed IPv6
    }
    if let Ok(sock) = s.parse::<std::net::SocketAddr>() {
        return Some(sock.ip()); // ip:port or [ip]:port
    }
    // `[ip]` with no port.
    s.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .and_then(|inner| inner.parse::<std::net::IpAddr>().ok())
}

/// Spend one token from `ip`'s auth bucket. Returns `false` (rate-limited) when
/// the bucket is empty; always `true` when `auth_rate_burst` is unset. The
/// bucket refills to full over 60s; fully-refilled entries are pruned so the
/// map can't grow without bound.
pub(super) fn auth_rate_ok(state: &AppState, ip: std::net::IpAddr) -> bool {
    let Some(burst) = state.auth_rate_burst else {
        return true;
    };
    let burst = burst as f64;
    let refill_per_sec = burst / 60.0;
    let now = std::time::Instant::now();
    let mut buckets = state.auth_buckets.lock().expect("poisoned");
    if buckets.len() > 4096 {
        buckets.retain(|_, (tokens, last)| {
            *tokens + now.duration_since(*last).as_secs_f64() * refill_per_sec < burst
        });
    }
    let entry = buckets.entry(ip).or_insert((burst, now));
    entry.0 = (entry.0 + now.duration_since(entry.1).as_secs_f64() * refill_per_sec).min(burst);
    entry.1 = now;
    if entry.0 >= 1.0 {
        entry.0 -= 1.0;
        true
    } else {
        false
    }
}

/// Whether two URLs share an origin (scheme + host + port).
pub(super) fn same_origin(a: &str, b: &str) -> bool {
    match (
        openidconnect::url::Url::parse(a),
        openidconnect::url::Url::parse(b),
    ) {
        (Ok(x), Ok(y)) => x.origin() == y.origin(),
        _ => false,
    }
}

/// Frame/MIME/referrer protections for every HTML/app response. Uses only
/// `frame-ancestors 'none'` (not a resource-restricting CSP), so it stops
/// clickjacking without breaking the htmx app's script/style/WebSocket loads.
/// The auth pages layer a stricter `default-src 'none'` CSP on top.
pub(super) fn security_headers(headers: &mut axum::http::HeaderMap) {
    headers.insert(
        header::X_FRAME_OPTIONS,
        "DENY".parse().expect("static header"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        "frame-ancestors 'none'".parse().expect("static header"),
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

pub(super) fn no_store(headers: &mut axum::http::HeaderMap) {
    headers.insert(
        header::CACHE_CONTROL,
        "no-store".parse().expect("static header"),
    );
    headers.insert(header::PRAGMA, "no-cache".parse().expect("static header"));
    headers.insert(
        header::REFERRER_POLICY,
        "no-referrer".parse().expect("static header"),
    );
}

pub(super) fn cookie_value(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    cookies.split(';').find_map(|part| {
        part.trim()
            .strip_prefix(name)?
            .strip_prefix('=')
            .map(str::to_string)
    })
}

/// Session/state cookie names. When cookies are Secure (production), the
/// `__Host-` prefix is used: the browser then enforces Secure + Path=/ + no
/// Domain, so a related-subdomain or on-path attacker over plain HTTP can't
/// plant a `Domain`-scoped cookie of the same name (fixation). The prefix
/// requires Secure, so dev-mode (`secure_cookies=false`) keeps the bare name.
/// The read side must pick the SAME name as the setter — reading both would
/// reopen the very fixation vector the prefix closes.
pub(super) fn session_cookie_name(secure: bool) -> &'static str {
    if secure {
        "__Host-e6irc_session"
    } else {
        "e6irc_session"
    }
}

pub(super) fn oidc_state_cookie_name(secure: bool) -> &'static str {
    if secure {
        "__Host-e6irc_oidc_state"
    } else {
        "e6irc_oidc_state"
    }
}

/// The `Set-Cookie` value that clears the session cookie. Must use the same
/// name (and Secure flag) as the setter, or the browser won't delete it.
pub(super) fn clear_session_cookie(secure: bool) -> String {
    let sec = if secure { "; Secure" } else { "" };
    format!(
        "{}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0{sec}",
        session_cookie_name(secure)
    )
}

pub(super) fn session_token(headers: &axum::http::HeaderMap, secure: bool) -> Option<String> {
    cookie_value(headers, session_cookie_name(secure))
}
