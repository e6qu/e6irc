//! OIDC login, linking and back-channel logout.

use super::*;

/// A web-session role the server actually models. The OIDC `role` claim is
/// free-form text from the provider; only these two values mean anything (they
/// gate the shauth developer portal) and only these two satisfy the
/// `web_sessions.oidc_role` CHECK constraint. Parsing the claim into this type
/// at the boundary makes an unrecognized role structurally `None` — the raw
/// string can never reach a DB write that the CHECK would reject.
#[derive(Clone, Copy)]
pub(super) enum Role {
    Developer,
    Admin,
}

impl Role {
    fn from_claim(s: &str) -> Option<Self> {
        match s {
            "developer" => Some(Self::Developer),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Developer => "developer",
            Self::Admin => "admin",
        }
    }
}

// ---- OIDC login ---------------------------------------------------------

/// A relying-party client whose authorization *and* token endpoints are known.
/// Discovery makes the token endpoint optional; a client built without one can
/// start a login it can never finish, so that state is refused at construction
/// rather than `expect()`ed at the code exchange.
pub(super) type OidcClient = openidconnect::core::CoreClient<
    openidconnect::EndpointSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointSet,
    openidconnect::EndpointMaybeSet,
>;

/// A relying-party client for one provider, built from its discovery
/// document, with the HTTP client its calls must go through.
pub(super) struct ProviderClient {
    pub(super) client: OidcClient,
    pub(super) http: super::oidc_provider::ProviderHttp,
}

/// The client for `provider` from a discovery answer.
fn client_from_discovery(
    state: &AppState,
    provider: &OidcProviderConfig,
    discovery: super::oidc_provider::ProviderDiscovery,
) -> Result<ProviderClient, String> {
    use openidconnect::{ClientId, ClientSecret, RedirectUrl};
    let super::oidc_provider::ProviderDiscovery { metadata, http } = discovery;
    let token_endpoint = metadata
        .token_endpoint()
        .cloned()
        .ok_or("discovery document has no token_endpoint")?;
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
    let client = openidconnect::core::CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(provider.client_id.clone()),
        Some(ClientSecret::new(provider.client_secret.clone())),
    )
    .set_token_uri(token_endpoint)
    .set_redirect_uri(redirect)
    .set_auth_type(auth_type);
    Ok(ProviderClient { client, http })
}

/// The shared failure shape of the start and callback handlers: the provider
/// is unreachable or its discovery document cannot support the
/// authorization-code flow.
fn provider_unavailable(error: &str) -> ResponseRejection {
    eprintln!("oidc: {error}");
    ResponseRejection::from(problem(
        StatusCode::BAD_GATEWAY,
        "OIDC provider unavailable",
        Some("The identity provider is unreachable or its discovery document is unusable."),
    ))
}

/// Discover the client, or answer `BAD_GATEWAY`.
async fn discover_client_or_bad_gateway(
    state: &AppState,
    provider: &OidcProviderConfig,
) -> ResponseResult<ProviderClient> {
    super::oidc_provider::discover(state.internal_upstreams, provider)
        .await
        .and_then(|discovery| client_from_discovery(state, provider, discovery))
        .map_err(|error| provider_unavailable(&error))
}

/// The client rebuilt from the provider's keys fetched again, after a token
/// failed signature verification against the cached ones (the provider
/// rotated its keys). Throttled and single-flight in
/// [`super::oidc_provider::refresh`].
async fn refreshed_client_or_bad_gateway(
    state: &AppState,
    provider: &OidcProviderConfig,
) -> ResponseResult<ProviderClient> {
    super::oidc_provider::refresh(state.internal_upstreams, provider)
        .await
        .and_then(|discovery| client_from_discovery(state, provider, discovery))
        .map_err(|error| provider_unavailable(&error))
}

pub(super) async fn oidc_start(
    State(state): State<Arc<AppState>>,
    // Each login start forces an outbound discovery fetch, so throttle the
    // unauthenticated flood per client IP.
    _rl: RateLimited,
    PathParams(provider_name): PathParams<String>,
) -> Response {
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
    _rl: RateLimited,
    PathParams(provider_name): PathParams<String>,
) -> Response {
    oidc_authorize(&state, &provider_name, None, true).await
}

/// Begin an OIDC flow that *links* the resulting identity to the
/// authenticated caller's account rather than logging in. The account is
/// sealed into the flow cookie; the shared callback attaches the identity when
/// the provider returns.
pub(super) async fn oidc_link_start(
    State(state): State<Arc<AppState>>,
    // Authenticated, so not an unauthenticated vector, but each call forces a
    // discovery fetch — gated for parity with its siblings.
    _rl: RateLimited,
    // Whoever finishes this flow at the provider becomes a login identity of
    // the account. A bearer admitted here could link its holder's own identity
    // and sign in as the owner, with nothing more than the `read` scope.
    BrowserSession(account, session): BrowserSession,
    PathParams(provider_name): PathParams<String>,
    // A cross-site top-level navigation carries the SameSite=Lax session
    // cookie, so without the session-bound value any page could start a link
    // flow in the owner's browser and, at a provider that auto-approves, attach
    // whichever provider identity that browser is signed in to.
    QueryParams(query): QueryParams<CsrfQuery>,
) -> Response {
    if !query.admits(&state, &session) {
        return csrf_refusal();
    }
    oidc_authorize(&state, &provider_name, Some(account), false).await
}

/// How long a browser may take between leaving for the provider and coming
/// back to the callback.
const OIDC_FLOW_TTL: Duration = Duration::from_secs(600);

/// The AEAD associated data every flow cookie is sealed under: a flow cookie
/// cannot be opened as any other sealed value, nor another value as a flow.
const OIDC_FLOW_CONTEXT: &[u8] = b"oidc-authorization-flow";

/// An authorization-code flow a browser is in the middle of, carried *by that
/// browser* in its HttpOnly state cookie, sealed with the process's flow key
/// ([`AppState::oidc_flow_key`]). The server keeps nothing per flow, so no
/// number of anonymous `/start` requests can exhaust anything a real login
/// needs.
///
/// Sealing makes every field authentic and secret: the browser cannot read
/// the PKCE verifier or nonce, nor rewrite the provider, the account a link
/// attaches to, or the expiry. Replay is bounded without server state: the
/// authorization code a callback exchanges is single-use at the provider and
/// bound to this flow's PKCE verifier, every callback that proves the binding
/// clears the cookie, and a cookie outlives neither [`OIDC_FLOW_TTL`] nor the
/// process (the key is regenerated at startup).
#[derive(Serialize, Deserialize)]
struct OidcFlow {
    provider: String,
    /// The OAuth `state` the provider echoes back; the callback admits only a
    /// response whose `state` equals it.
    state: String,
    pkce_verifier: String,
    nonce: String,
    /// Seconds since the Unix epoch after which the flow is refused.
    expires_at: u64,
    /// When set, the callback links the resulting identity to this account
    /// instead of logging in / auto-provisioning.
    link_account: Option<String>,
    /// A silent (`prompt=none`) SSO probe: on `login_required` the callback
    /// bounces to `/?sso=none` instead of returning an error.
    silent: bool,
}

/// Why a callback's flow cookie was not admitted.
#[derive(Debug, PartialEq, Eq)]
enum FlowRefusal {
    /// No cookie, a cookie this process did not seal, or one whose `state`
    /// differs from the callback's: the response is not this browser's.
    Unbound,
    Expired,
    WrongProvider,
    /// The flow has already been answered: a replayed copy of its cookie.
    Spent,
}

impl FlowRefusal {
    fn response(&self) -> Response {
        let title = match self {
            Self::Unbound => "Login state not bound to this browser",
            Self::Expired => "Unknown or expired login state",
            Self::WrongProvider => "Login state mismatch",
            Self::Spent => "Login state already used",
        };
        problem(StatusCode::UNAUTHORIZED, title, None)
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_secs()
}

impl OidcFlow {
    fn seal(&self, key: &crate::secret::SecretKey) -> String {
        key.seal(
            &serde_json::to_string(self).expect("a flow serializes"),
            OIDC_FLOW_CONTEXT,
        )
    }

    /// The flow this browser started, admitted only when it is authentic, its
    /// `state` equals the one the provider returned (constant-time), it is for
    /// this provider, and it has not expired.
    fn open(
        key: &crate::secret::SecretKey,
        cookie: Option<&str>,
        provider: &str,
        returned_state: &str,
        now: u64,
    ) -> Result<Self, FlowRefusal> {
        let flow: Self = cookie
            .and_then(|sealed| key.open(sealed, OIDC_FLOW_CONTEXT).ok())
            .and_then(|json| serde_json::from_str(&json).ok())
            .ok_or(FlowRefusal::Unbound)?;
        if aws_lc_rs::constant_time::verify_slices_are_equal(
            flow.state.as_bytes(),
            returned_state.as_bytes(),
        )
        .is_err()
        {
            return Err(FlowRefusal::Unbound);
        }
        if flow.provider != provider {
            return Err(FlowRefusal::WrongProvider);
        }
        if now >= flow.expires_at {
            return Err(FlowRefusal::Expired);
        }
        Ok(flow)
    }

    /// The browser's flow for this callback, read from its state cookie, and
    /// spent: a flow is answered once, so a kept copy of the cookie cannot
    /// make this server call the provider again.
    fn from_callback(
        state: &AppState,
        headers: &axum::http::HeaderMap,
        provider: &str,
        returned_state: &str,
    ) -> Result<Self, FlowRefusal> {
        let now = unix_now();
        let flow = Self::open(
            &state.oidc_flow_key,
            cookie_value(headers, oidc_state_cookie_name(state.secure_cookies)).as_deref(),
            provider,
            returned_state,
            now,
        )?;
        if !state
            .spent_oidc_flows
            .spend(&flow.state, flow.expires_at, now)
        {
            return Err(FlowRefusal::Spent);
        }
        Ok(flow)
    }
}

/// The `Set-Cookie` value that ends a flow: sent by every callback that proved
/// the browser's binding, so a flow cookie is spent once it has been answered.
fn clear_flow_cookie(secure_cookies: bool) -> String {
    let secure = if secure_cookies { "; Secure" } else { "" };
    format!(
        "{}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0{secure}",
        oidc_state_cookie_name(secure_cookies)
    )
}

/// `response` with the flow cookie cleared.
fn spending_flow(state: &AppState, mut response: Response) -> Response {
    response.headers_mut().append(
        header::SET_COOKIE,
        clear_flow_cookie(state.secure_cookies)
            .parse()
            .expect("cookie header value"),
    );
    response
}

/// Shared authorization-request builder for login, link, and silent-SSO
/// flows. `silent` adds `prompt=none` so the provider returns without any
/// UI (used for the SSO-session probe).
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
    let client = match discover_client_or_bad_gateway(state, &provider).await {
        Ok(provider_client) => provider_client.client,
        Err(resp) => return resp.into(),
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
    for scope in requested_scopes(&provider) {
        request = request.add_scope(Scope::new(scope));
    }
    if silent {
        request = request.add_extra_param("prompt", "none");
    }
    let (auth_url, csrf, nonce) = request.url();
    let flow = OidcFlow {
        provider: provider.name.clone(),
        state: csrf.secret().clone(),
        pkce_verifier: pkce_verifier.secret().clone(),
        nonce: nonce.secret().clone(),
        expires_at: unix_now() + OIDC_FLOW_TTL.as_secs(),
        link_account,
        silent,
    };
    // Bind the flow to this browser: the callback admits only a response whose
    // `state` matches the sealed flow in this cookie, so a login response
    // captured by an attacker cannot be replayed into a victim's browser to
    // plant the attacker's session (login CSRF / session fixation).
    // SameSite=Lax still rides the top-level redirect back from the provider.
    let secure = if state.secure_cookies { "; Secure" } else { "" };
    (
        StatusCode::TEMPORARY_REDIRECT,
        [
            (header::LOCATION, auth_url.to_string()),
            (
                header::SET_COOKIE,
                format!(
                    "{}={}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}{secure}",
                    oidc_state_cookie_name(state.secure_cookies),
                    flow.seal(&state.oidc_flow_key),
                    OIDC_FLOW_TTL.as_secs(),
                ),
            ),
        ],
    )
        .into_response()
}

fn requested_scopes(provider: &OidcProviderConfig) -> Vec<String> {
    if provider.scopes.is_empty() {
        vec!["profile".into(), "email".into()]
    } else {
        provider.scopes.clone()
    }
}

/// The provider's redirect back: the parameters this server acts on. Unlike
/// every other query, the set is open. The authorization response is the
/// provider's vocabulary, not this server's, and RFC 6749 §4.1.2 requires a
/// client to ignore parameters it does not recognize — Google appends
/// `authuser`, `prompt` and `hd`, Keycloak and Microsoft Entra
/// `session_state`. A granted `scope` is likewise not acted on: §3.3 lets a
/// provider grant a different set than was requested, and what is trusted is
/// the ID token, whose signature, issuer, audience and nonce are verified.
#[derive(Deserialize)]
pub(super) struct CallbackQuery {
    pub(super) code: Option<String>,
    pub(super) state: Option<String>,
    pub(super) error: Option<String>,
    #[serde(rename = "iss")]
    pub(super) issuer: Option<String>,
}

/// How the callback answers a provisioning refusal: the provider's claim named
/// an account that already exists (or whose name is retired), and the server
/// does not pick a different name for a person.
fn account_name_taken(claim_name: &str) -> Response {
    problem(
        StatusCode::CONFLICT,
        "Account name already taken",
        Some(&format!(
            "The identity provider's account claim is \"{claim_name}\", and an account of that \
             name already exists on this server (or the name is retired). Sign in to the \
             existing account and link this identity from its account page, or ask an \
             administrator."
        )),
    )
}

pub(super) async fn oidc_callback(
    State(state): State<Arc<AppState>>,
    // A callback can make this server call the provider's token endpoint with
    // its client secret; unthrottled, it made the server an amplifier against
    // the provider.
    _rl: RateLimited,
    PathParams(provider_name): PathParams<String>,
    headers: axum::http::HeaderMap,
    QueryParams(query): QueryParams<CallbackQuery>,
) -> Response {
    let Some(provider) = state
        .oidc_providers
        .iter()
        .find(|p| p.name == provider_name)
        .cloned()
    else {
        return problem(StatusCode::NOT_FOUND, "Unknown OIDC provider", None);
    };
    if query
        .issuer
        .as_deref()
        .is_some_and(|issuer| provider.issuer_url != issuer)
    {
        return problem(StatusCode::UNAUTHORIZED, "OIDC issuer mismatch", None);
    }
    if let Some(err) = query.error.as_deref() {
        // Only a callback that proves this browser's binding — the sealed flow
        // cookie whose `state` equals the returned one — spends the cookie or
        // learns the flow was silent. An attacker who learns a victim's
        // in-flight `state` cannot race the callback with `?error=…&state=…`
        // and burn the victim's still-pending login (a login-DoS); an unbound
        // error callback still gets the honest refusal response.
        let Some(flow) = query.state.as_deref().and_then(|returned| {
            OidcFlow::from_callback(&state, &headers, &provider_name, returned).ok()
        }) else {
            return problem(StatusCode::UNAUTHORIZED, "OIDC login refused", Some(err));
        };
        // A silent SSO probe (`prompt=none`) with no upstream session comes
        // back as `login_required`; that is expected — bounce to interactive
        // login rather than erroring.
        if flow.silent {
            // `consent_required` is not `login_required`: the browser *does*
            // have a provider session, it has simply never authorized this
            // client. OpenID Connect answers a silent probe that way on a
            // relying party's first visit, and the specified next step is one
            // ordinary authorization request. For a first-party application
            // the provider grants that without any interaction, so single
            // sign-on stays seamless; treating it as "not signed in" would
            // strand a signed-in user on the sign-in page forever, because the
            // consent that is missing can never be recorded by probing. The
            // new flow's cookie replaces this one.
            if err == "consent_required" {
                return oidc_authorize(&state, &provider_name, None, false).await;
            }
            return spending_flow(&state, Redirect::to("/?sso=none").into_response());
        }
        return spending_flow(
            &state,
            problem(StatusCode::UNAUTHORIZED, "OIDC login refused", Some(err)),
        );
    }
    let (Some(code), Some(returned_state)) = (query.code, query.state) else {
        return problem(StatusCode::BAD_REQUEST, "Missing code or state", None);
    };
    // Require this browser's sealed flow for the returned `state`. Without it,
    // an attacker who completed their own login could feed the resulting
    // callback URL to a victim and plant the attacker's session in the
    // victim's browser. A refused callback leaves the cookie alone, so an
    // attacker who learns a victim's in-flight `state` cannot burn the login.
    let flow = match OidcFlow::from_callback(&state, &headers, &provider_name, &returned_state) {
        Ok(flow) => flow,
        Err(refusal) => return refusal.response(),
    };
    spending_flow(
        &state,
        complete_flow(&state, &provider, flow, code, &headers).await,
    )
}

/// Finish an admitted flow: exchange the code, verify the ID token, and link
/// the identity or establish the session.
async fn complete_flow(
    state: &AppState,
    provider: &OidcProviderConfig,
    flow: OidcFlow,
    code: String,
    headers: &axum::http::HeaderMap,
) -> Response {
    use openidconnect::{AuthorizationCode, Nonce, PkceCodeVerifier, TokenResponse};
    let Some(pool) = state.pool.clone() else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "No database configured",
            None,
        );
    };
    let ProviderClient { client, http } =
        match discover_client_or_bad_gateway(state, provider).await {
            Ok(provider_client) => provider_client,
            Err(resp) => return resp.into(),
        };
    let token_response = match client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(PkceCodeVerifier::new(flow.pkce_verifier))
        .request_async(&http)
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
    let nonce = Nonce::new(flow.nonce);
    let verified = match id_token.claims(&client.id_token_verifier(), &nonce) {
        // Signed by a key the cached set does not hold: the provider may have
        // rotated its keys since they were fetched. Fetch them again (at most
        // once per interval, one fetch at a time) and verify once more.
        Err(openidconnect::ClaimsVerificationError::SignatureVerification(_)) => {
            match refreshed_client_or_bad_gateway(state, provider).await {
                Ok(refreshed) => id_token.claims(&refreshed.client.id_token_verifier(), &nonce),
                Err(resp) => return resp.into(),
            }
        }
        verified => verified,
    };
    let claims = match verified {
        Ok(c) => c,
        Err(e) => {
            eprintln!("oidc: id token rejected: {e}");
            return problem(StatusCode::UNAUTHORIZED, "ID token validation failed", None);
        }
    };
    let issuer = claims.issuer().as_str();
    let subject = claims.subject().as_str();
    let email = claims.email().map(|value| value.as_str().to_string());
    if !email_domain_admitted(
        provider,
        email.as_deref(),
        claims.email_verified() == Some(true),
    ) {
        return problem(
            StatusCode::FORBIDDEN,
            "Identity is outside the provider's allowed email domains",
            Some("A verified email claim in an allowed domain is required."),
        );
    }
    // The provider's own claims for this session. The token was verified
    // above, so failing to read it back is a fault worth hearing about rather
    // than a quiet `None`: without `sid`, a back-channel logout can only match
    // this session by subject, which revokes more than the provider asked.
    let token_claims = match jwt_string_claims(&id_token.to_string()) {
        Ok(claims) => Some(claims),
        Err(error) => {
            eprintln!(
                "oidc: {issuer}: a verified id_token's claims could not be read ({error}); \
                 this session has no sid and logs out by subject"
            );
            None
        }
    };
    let sid = token_claims.as_ref().and_then(|claims| claims.sid.clone());
    // Link flow: attach this identity to the account that started it,
    // rather than logging in / provisioning a new account.
    if let Some(account) = &flow.link_account {
        return match crate::db::link_oidc_identity(&pool, account, issuer, subject).await {
            Ok(crate::db::LinkOutcome::Linked | crate::db::LinkOutcome::AlreadyYours) => {
                (StatusCode::SEE_OTHER, [(header::LOCATION, "/?linked=1")]).into_response()
            }
            Ok(crate::db::LinkOutcome::Conflict) => problem(
                StatusCode::CONFLICT,
                "Identity already linked to another account",
                None,
            ),
            Err(crate::db::DbError::BadCredentials) => problem(
                StatusCode::FORBIDDEN,
                "Account unavailable",
                Some("This account cannot gain a login identity."),
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
    // A returning identity signs in to the account it is linked to, whatever
    // its claims now say; only a first sign-in derives a name.
    let linked = match crate::db::oidc_linked_account(&pool, issuer, subject).await {
        Ok(linked) => linked,
        Err(e) => {
            eprintln!("oidc: identity lookup failed: {e}");
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Account storage failed",
                None,
            );
        }
    };
    let preferred = match linked {
        Some(account) => account,
        None => match provisioned_account_name(
            provider,
            claims
                .preferred_username()
                .map(|value| value.as_str().to_string())
                .as_deref(),
            email.as_deref(),
            claims.email_verified() == Some(true),
        ) {
            Ok(name) => name,
            Err(refusal) => return refusal.response(),
        },
    };
    // Only stored roles reach the database.
    let role = token_claims
        .as_ref()
        .and_then(|claims| claims.role.as_deref())
        .and_then(Role::from_claim);
    let verified_shauth_identity =
        email.is_some() && claims.email_verified() == Some(true) && role.is_some();
    if flow.provider == "shauth" && !verified_shauth_identity {
        return problem(
            StatusCode::UNAUTHORIZED,
            "Shauth identity claims are incomplete",
            None,
        );
    }
    let account =
        match crate::db::find_or_create_oidc_account(&pool, issuer, subject, &preferred).await {
            Ok(a) => a,
            Err(crate::db::DbError::DuplicateAccount(name)) => return account_name_taken(&name),
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
    let user_agent = session_user_agent(headers);
    let token = match crate::db::create_web_session_with_identity(
        &pool,
        &account,
        crate::db::OidcSessionIdentity {
            id_token: Some(&id_token_raw),
            provider: Some(&flow.provider),
            issuer: Some(issuer),
            subject: Some(subject),
            sid: sid.as_deref(),
            email: email.as_deref(),
            role: role.map(Role::as_str),
        },
        user_agent.as_ref(),
    )
    .await
    {
        Ok(t) => t,
        Err(crate::db::DbError::BadCredentials) => {
            return problem(
                StatusCode::FORBIDDEN,
                "Account unavailable",
                Some("This account cannot start a new session."),
            );
        }
        Err(e) => {
            eprintln!("oidc: session creation failed: {e}");
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Session storage failed",
                None,
            );
        }
    };
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, "/".to_string()),
            (
                header::SET_COOKIE,
                session_cookie(&token, state.secure_cookies),
            ),
        ],
    )
        .into_response()
}

/// Why a first sign-in may not provision an account.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ProvisioningRefusal {
    /// The configured claim is absent or not an IRC-safe account name.
    UnusableClaim(&'static str),
    /// The email claim names accounts, but the provider has not verified the
    /// address: anyone could have typed it at a provider that lets people
    /// register.
    UnverifiedEmail,
    /// The email claim names accounts, but no domain policy says whose
    /// addresses they are: without one, `alice@anywhere` would become the
    /// account `alice`, whoever holds that mailbox.
    NoDomainPolicy,
}

impl ProvisioningRefusal {
    pub(super) fn response(&self) -> Response {
        match self {
            Self::UnusableClaim(detail) => problem(
                StatusCode::UNAUTHORIZED,
                "Provider sent no usable account claim",
                Some(detail),
            ),
            Self::UnverifiedEmail => problem(
                StatusCode::FORBIDDEN,
                "Account provisioning refused",
                Some(
                    "This provider names new accounts by email, and it has not verified this \
                     identity's address. Verify the address with the provider, or ask an \
                     administrator to create the account and link this identity to it.",
                ),
            ),
            Self::NoDomainPolicy => problem(
                StatusCode::FORBIDDEN,
                "Account provisioning refused",
                Some(
                    "This provider names new accounts by the local part of an email address, \
                     which is only a name when the provider's allowed email domains say whose \
                     addresses they are, and it has none. Ask an administrator to configure \
                     the provider's allowed email domains, or to create the account and link \
                     this identity to it.",
                ),
            ),
        }
    }
}

/// The account a first sign-in provisions, named by the provider's
/// configured claim. An email names an account only when the provider
/// verified it and a domain policy admits it (the policy itself is enforced
/// for every sign-in by [`email_domain_admitted`]); the local part of an
/// address anyone could claim never becomes a name. There is no fallback to
/// another claim: the administrator chose this one.
pub(super) fn provisioned_account_name(
    provider: &OidcProviderConfig,
    preferred_username: Option<&str>,
    email: Option<&str>,
    email_verified: bool,
) -> Result<String, ProvisioningRefusal> {
    match provider.account_claim {
        crate::config::OidcAccountClaim::PreferredUsername => preferred_username
            .and_then(crate::sanitize::account_name)
            .ok_or(ProvisioningRefusal::UnusableClaim(
                "The configured preferred_username claim must contain an IRC-safe account name.",
            )),
        crate::config::OidcAccountClaim::Email => {
            let unusable = ProvisioningRefusal::UnusableClaim(
                "The configured email claim must be a valid email with an IRC-safe local part.",
            );
            let email = email
                .and_then(|value| crate::identity::ContactEmail::parse(value).ok())
                .ok_or(unusable)?;
            if !email_verified {
                return Err(ProvisioningRefusal::UnverifiedEmail);
            }
            if provider.allowed_email_domains.is_empty() {
                return Err(ProvisioningRefusal::NoDomainPolicy);
            }
            crate::sanitize::account_name(email.local_part()).ok_or(
                ProvisioningRefusal::UnusableClaim(
                    "The configured email claim must be a valid email with an IRC-safe local part.",
                ),
            )
        }
    }
}

fn email_domain_admitted(
    provider: &OidcProviderConfig,
    email: Option<&str>,
    email_verified: bool,
) -> bool {
    provider.allowed_email_domains.is_empty()
        || (email_verified
            && email
                .and_then(|email| crate::identity::ContactEmail::parse(email).ok())
                .is_some_and(|email| {
                    provider
                        .allowed_email_domains
                        .iter()
                        .any(|domain| domain.admits(&email))
                }))
}

pub(super) const BACKCHANNEL_LOGOUT_EVENT: &str =
    "http://schemas.openid.net/event/backchannel-logout";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BackchannelLogoutForm {
    pub(super) logout_token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
    pub(super) exp: i64,
    pub(super) jti: String,
    pub(super) events: HashMap<String, serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    pub(super) azp: Option<String>,
    #[serde(default)]
    pub(super) nonce: ClaimPresence,
}

#[derive(Debug, Default)]
pub(super) enum ClaimPresence {
    #[default]
    Missing,
    Present,
}

impl<'de> Deserialize<'de> for ClaimPresence {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        serde::de::IgnoredAny::deserialize(deserializer)?;
        Ok(Self::Present)
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct LogoutTokenHeader {
    pub(super) alg: openidconnect::core::CoreJwsSigningAlgorithm,
    #[serde(default)]
    pub(super) kid: Option<String>,
    #[serde(default)]
    pub(super) typ: Option<String>,
}

#[derive(Deserialize)]
struct JwtStringClaims {
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    sid: Option<String>,
    #[serde(default)]
    role: Option<String>,
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

fn jwt_string_claims(raw: &str) -> Result<JwtStringClaims, String> {
    let mut segments = raw.split('.');
    let Some(_) = segments.next() else {
        return Err("JWT must have three segments".into());
    };
    let Some(payload) = segments.next() else {
        return Err("JWT must have three segments".into());
    };
    let Some(_) = segments.next() else {
        return Err("JWT must have three segments".into());
    };
    if segments.next().is_some() {
        return Err("JWT must have three segments".into());
    }
    serde_json::from_slice(&base64url_decode(payload)?)
        .map_err(|_| "JWT payload is not JSON".into())
}

/// Why a logout token was refused.
#[derive(Debug)]
pub(super) enum LogoutTokenRejection {
    /// Exactly one key of the set must verify the signature, and none (or
    /// more than one) did. A key the set does not hold yet — the provider
    /// rotated its keys — looks like this, so the caller fetches the keys
    /// again and verifies once more.
    Signature,
    /// Anything else about the token is wrong; new keys would not change it.
    Invalid(String),
}

impl From<String> for LogoutTokenRejection {
    fn from(reason: String) -> Self {
        Self::Invalid(reason)
    }
}

impl From<&str> for LogoutTokenRejection {
    fn from(reason: &str) -> Self {
        Self::Invalid(reason.to_string())
    }
}

pub(super) fn verify_logout_token_with_metadata(
    raw: &str,
    provider: &OidcProviderConfig,
    supported_algorithms: &[openidconnect::core::CoreJwsSigningAlgorithm],
    keys: &[openidconnect::core::CoreJsonWebKey],
    now: i64,
) -> Result<BackchannelLogoutClaims, LogoutTokenRejection> {
    use openidconnect::JsonWebKey;

    let segments: Vec<&str> = raw.split('.').collect();
    if segments.len() != 3 {
        return Err("logout token must have three segments".into());
    }
    let header: LogoutTokenHeader = serde_json::from_slice(&base64url_decode(segments[0])?)
        .map_err(|_| "logout token header is invalid")?;
    if !matches!(
        header.typ.as_deref(),
        None | Some("JWT") | Some("logout+jwt")
    ) {
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
        return Err(LogoutTokenRejection::Signature);
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
        || matches!(claims.nonce, ClaimPresence::Present)
        || (!has_subject && !has_sid)
        || claims.iat < now - 600
        || claims.iat > now + 60
        || claims.exp <= now
        || claims.exp <= claims.iat
        || claims.events.len() != 1
        || !claims.events.contains_key(BACKCHANNEL_LOGOUT_EVENT)
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

/// Why a back-channel logout token was not verified.
#[derive(Debug)]
pub(super) enum LogoutVerification {
    /// The provider's discovery document or keys could not be fetched.
    Unreachable(String),
    Rejected(LogoutTokenRejection),
}

/// Verify a back-channel logout token against the provider's keys.
///
/// A provider treats a `400` as final, so a token signed by a key this server
/// has not fetched yet — the provider rotated its keys — would never end the
/// session it names. A signature no cached key verifies therefore fetches the
/// keys again (throttled, one fetch at a time) and verifies once more before
/// the token is refused.
pub(super) async fn verify_logout_token(
    policy: crate::egress::InternalUpstreams,
    provider: &OidcProviderConfig,
    raw: &str,
    now: i64,
) -> Result<BackchannelLogoutClaims, LogoutVerification> {
    let verify = |discovery: &super::oidc_provider::ProviderDiscovery| {
        verify_logout_token_with_metadata(
            raw,
            provider,
            discovery.metadata.id_token_signing_alg_values_supported(),
            discovery.metadata.jwks().keys(),
            now,
        )
    };
    let discovery = super::oidc_provider::discover(policy, provider)
        .await
        .map_err(LogoutVerification::Unreachable)?;
    match verify(&discovery) {
        Err(LogoutTokenRejection::Signature) => {
            let refreshed = super::oidc_provider::refresh(policy, provider)
                .await
                .map_err(LogoutVerification::Unreachable)?;
            verify(&refreshed).map_err(LogoutVerification::Rejected)
        }
        verified => verified.map_err(LogoutVerification::Rejected),
    }
}

// Deliberately NOT `RateLimited` (unlike its front-channel sibling): this
// endpoint is called server-to-server by the IdP, from a single source IP, and a
// mass-logout event legitimately bursts many tokens at once — a per-IP limit
// would DROP real logout notifications (leaving sessions alive that should end),
// a worse outcome than the marginal DoS it would prevent. The work an unsigned
// request induces is already bounded: signature verification is fast, discovery
// is cached (900s, a failure 30s), a key refresh for an unknown signing key runs
// at most once per 30s, and a DB row is written only for a validly-signed token
// an attacker cannot forge. See the front-channel handler for the contrasting
// case.
pub(super) async fn oidc_backchannel_logout(
    State(state): State<Arc<AppState>>,
    form: Result<Form<BackchannelLogoutForm>, axum::extract::rejection::FormRejection>,
) -> Response {
    let pool = require_pool!(state);
    let Form(form) = match form {
        Ok(value) => value,
        Err(_) => return problem(StatusCode::BAD_REQUEST, "Invalid logout token", None),
    };
    let unverified_issuer = match jwt_string_claims(form.logout_token.trim()) {
        Ok(JwtStringClaims {
            iss: Some(value), ..
        }) => value,
        _ => return problem(StatusCode::BAD_REQUEST, "Invalid logout token", None),
    };
    let Some(provider) = state
        .oidc_providers
        .iter()
        .find(|provider| provider.issuer_url == unverified_issuer)
    else {
        return problem(StatusCode::BAD_REQUEST, "Invalid logout token", None);
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs() as i64;
    let claims = match verify_logout_token(
        state.internal_upstreams,
        provider,
        form.logout_token.trim(),
        now,
    )
    .await
    {
        Ok(value) => value,
        Err(LogoutVerification::Unreachable(error)) => {
            eprintln!("oidc: logout metadata discovery failed: {error}");
            return problem(StatusCode::BAD_GATEWAY, "OIDC provider unreachable", None);
        }
        Err(LogoutVerification::Rejected(rejection)) => {
            let reason = match &rejection {
                LogoutTokenRejection::Signature => "no key of the provider's set verifies it",
                LogoutTokenRejection::Invalid(reason) => reason,
            };
            eprintln!("oidc: back-channel logout token refused: {reason}");
            return problem(StatusCode::BAD_REQUEST, "Invalid logout token", None);
        }
    };
    match crate::db::consume_oidc_backchannel_logout(
        pool,
        &claims.iss,
        claims.sub.as_deref(),
        claims.sid.as_deref(),
        &claims.jti,
        claims.exp,
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
    headers: axum::http::HeaderMap,
    // Unlike the signed back-channel path, this endpoint has no token to verify —
    // it revokes a session by a guessable `sid`. Rate-limit per client IP so it
    // can't be used to brute-force sids and force-logout victims.
    _rl: RateLimited,
    QueryParams(query): QueryParams<FrontchannelLogoutQuery>,
) -> Response {
    let pool = require_pool!(state);
    // The provider loads this in an iframe (OpenID Connect Front-Channel
    // Logout 1.0 §2), so its origin, and only its origin, may frame the answer.
    // The baseline for `/api/` denies all framing, which blocked every logout.
    let Some(frame_policy) = (!query.sid.trim().is_empty())
        .then(|| {
            state
                .oidc_providers
                .iter()
                .find(|provider| provider.issuer_url == query.iss)
        })
        .flatten()
        .and_then(|provider| frontchannel_frame_policy(&provider.issuer_url))
    else {
        return problem(
            StatusCode::BAD_REQUEST,
            "Invalid front-channel logout",
            None,
        );
    };
    let presented = session_token(&headers, state.secure_cookies);
    let revocation = match crate::db::revoke_oidc_frontchannel_sessions(
        pool,
        &query.iss,
        &query.sid,
        presented.as_deref(),
    )
    .await
    {
        Ok(revocation) => revocation,
        Err(error) => {
            eprintln!("oidc: front-channel session revocation failed: {error}");
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Session storage failed",
                None,
            );
        }
    };
    let mut response = (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store".to_string()),
            (header::CONTENT_SECURITY_POLICY, frame_policy),
        ],
        "",
    )
        .into_response();
    // The cookie is cleared only when it named a session this logout revoked;
    // a visitor whose own session the issuer/sid does not name keeps it.
    if revocation.presented_session_revoked {
        response.headers_mut().insert(
            header::SET_COOKIE,
            clear_session_cookie(state.secure_cookies)
                .parse()
                .expect("generated cookie is a valid header"),
        );
    }
    response
}

/// The front-channel logout answer's policy: nothing may load, and only the
/// issuer's origin may frame it. `None` for an issuer with no tuple origin,
/// which no provider can frame from.
fn frontchannel_frame_policy(issuer_url: &str) -> Option<String> {
    let origin = url::Url::parse(issuer_url).ok()?.origin();
    origin.is_tuple().then(|| {
        format!(
            "default-src 'none'; frame-ancestors {}",
            origin.ascii_serialization()
        )
    })
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
            Err(e) => Err(body_rejection(e.status(), "Invalid JSON", &e.to_string())),
        }
    }
}

/// Declares `$wrapper` as axum's `$inner` extractor whose rejection is answered
/// by `$refuse` — a problem document — instead of axum's plain-text (or empty)
/// default. Every "axum would answer this in its own shape" wrapper is this one
/// impl, so the shapes cannot drift apart.
macro_rules! problem_extractor {
    (
        $wrapper:ty => $inner:ty,
        [$($generics:tt)*],
        |$value:pat_param| $unwrap:expr,
        $refuse:expr $(,)?
    ) => {
        impl<$($generics)* S: Send + Sync> axum::extract::FromRequestParts<S> for $wrapper {
            type Rejection = Response;

            async fn from_request_parts(
                parts: &mut axum::http::request::Parts,
                state: &S,
            ) -> Result<Self, Self::Rejection> {
                <$inner as axum::extract::FromRequestParts<S>>::from_request_parts(parts, state)
                    .await
                    .map(|$value| $unwrap)
                    .map_err(|rejection| $refuse(&rejection))
            }
        }
    };
}
pub(crate) use problem_extractor;

/// A query string, rejected as a problem document rather than axum's plain-text
/// default. Every query struct is `deny_unknown_fields`, so a stray parameter
/// is a `400` on every route; this is the one place that `400` takes its shape.
pub(crate) struct QueryParams<T>(pub(crate) T);

problem_extractor!(
    QueryParams<T> => Query<T>,
    [T: serde::de::DeserializeOwned,],
    |Query(value)| QueryParams(value),
    |rejection: &axum::extract::rejection::QueryRejection| problem(
        StatusCode::BAD_REQUEST,
        "Invalid query",
        Some(&rejection.body_text()),
    ),
);

/// Path parameters, rejected as a problem document rather than axum's
/// plain-text default. A `/tokens/abc` where an integer ID belongs, or a
/// segment whose percent-encoding is not UTF-8, is a `400` in the same shape as
/// every other refusal, so a client reads one error format for the whole API.
/// Handlers ask for this, never `axum::extract::Path` directly.
pub(crate) struct PathParams<T>(pub(crate) T);

problem_extractor!(
    PathParams<T> => axum::extract::Path<T>,
    [T: serde::de::DeserializeOwned + Send,],
    |axum::extract::Path(value)| PathParams(value),
    path_rejection_problem,
);

/// The problem document for a path the extractor refused. A route matched
/// but the extractor found no parameters is a server bug, not the client's
/// input, so it is a `500`; everything else is the client's `400`.
fn path_rejection_problem(rejection: &axum::extract::rejection::PathRejection) -> Response {
    match rejection {
        axum::extract::rejection::PathRejection::MissingPathParams(_) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Route parameters unavailable",
            Some(&rejection.body_text()),
        ),
        _ => problem(
            StatusCode::BAD_REQUEST,
            "Invalid path parameter",
            Some(&rejection.body_text()),
        ),
    }
}

/// The answer to a request whose path exists but whose method does not, in the
/// same problem shape as every other refusal. Axum still adds the `Allow`
/// header naming the methods the path does serve.
pub(super) async fn method_not_allowed() -> Response {
    problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed", None)
}

/// An authenticated account and the credential that proved it, extracted
/// before the handler body runs.
///
/// Every authenticated route opened with the same eight lines: call
/// `authenticate`, return its rejection, then re-derive the pool it had already
/// proved was there. As an extractor that prologue does not exist to be
/// repeated — a route is authenticated because it asks for this in its
/// signature, which is also where a reader looks to find out.
///
/// The credential travels with the account because it is the only verified
/// answer to "which browser session is this?" and "may this caller write?". A
/// handler that re-read the `Cookie` header for that answer trusted a value
/// nobody had checked against the account: a bearer beside a junk cookie made
/// "every session except the current one" mean every session.
pub(crate) struct Authenticated(pub(crate) String, pub(crate) RequestCredential);

impl axum::extract::FromRequestParts<Arc<AppState>> for Authenticated {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let principal = authenticate_principal(state, &parts.headers).await?;
        admit_api_request(state, &principal, parts)?;
        Ok(Authenticated(principal.account, principal.credential))
    }
}

/// An account authenticated by its browser session and nothing else, with the
/// verified session token.
///
/// Some operations are about the browser session itself (which one to keep,
/// which one is current) or hand authority to whoever completes them (linking a
/// login identity). A bearer cannot name a browser session and must not be able
/// to acquire one, so those routes ask for this instead of [`Authenticated`] and
/// a token is refused before the handler exists to be reached.
pub(crate) struct BrowserSession(pub(crate) String, pub(crate) String);

impl axum::extract::FromRequestParts<Arc<AppState>> for BrowserSession {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let (principal, session) = authenticate_browser_session(state, &parts.headers).await?;
        admit_api_request(state, &principal, parts)?;
        Ok(BrowserSession(principal.account, session))
    }
}

/// A cookie-authenticated, session-bound browser mutation.
///
/// Token issuance, device approval, the primary password, the recovery
/// contact, and login identities can each mint or redirect authority over the
/// account. Allowing an existing bearer to call any of them would let a narrow
/// token expand its own scopes or become the account outright. Requiring the
/// browser session — whose unsafe methods must carry the constant-time checked
/// CSRF header — makes that escalation unrepresentable at the handler boundary.
pub(crate) struct SessionMutation(pub(crate) String, pub(crate) String);

impl axum::extract::FromRequestParts<Arc<AppState>> for SessionMutation {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let BrowserSession(account, session) =
            BrowserSession::from_request_parts(parts, state).await?;
        Ok(SessionMutation(account, session))
    }
}

/// The authenticated account of an **admin**. Same idea as [`Authenticated`],
/// one rung up: a handler that asks for this in its signature cannot be reached
/// by a non-admin, and — the point — an admin route cannot *forget* the check,
/// because the check is the parameter, not a first line a new handler might
/// omit. (Admin gating was a convention every `admin_*` handler had to open
/// with; this makes the ungated admin handler fail to compile for want of an
/// argument, the same way [`Authenticated`] did for authentication.)
pub(crate) struct AdminAccount(pub(crate) String);

impl axum::extract::FromRequestParts<Arc<AppState>> for AdminAccount {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        // Keep the resolved account in the typed gate: read handlers may ignore
        // it, while audited mutations can attribute the actor without
        // authenticating a second time along a divergent path.
        let principal = authenticate_principal(state, &parts.headers).await?;
        authorize_api_request(state, &principal.credential, parts, true)
            .map_err(|denial| api_authorization_response(denial, parts.uri.path()))?;
        if is_effective_admin(state, &principal) {
            spend_api_budget(state, &principal.account, true).map_err(rate_limit_response)?;
            Ok(AdminAccount(principal.account))
        } else {
            Err(problem(StatusCode::FORBIDDEN, "Admin only", None))
        }
    }
}

/// A request that has spent one token from the per-IP auth-rate budget. Every
/// unauthenticated, work-inducing route asks for this in its signature instead
/// of opening with the `client_ip` + `spend_auth_budget` prologue (and pulling in
/// `ConnectInfo` + `HeaderMap`) by hand — so the throttle is declared in one
/// visible place, a `_: RateLimited` argument, and a route that induces work
/// without it is a conspicuous omission rather than a forgotten first line the
/// way `device_token` once was. Rejects `429` when the budget is exhausted.
pub(crate) struct RateLimited;

impl axum::extract::FromRequestParts<Arc<AppState>> for RateLimited {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        // The server installs `ConnectInfo` (net.rs serves with
        // `into_make_service_with_connect_info`); if it is somehow absent, fall
        // back to the unspecified address so the limit still applies (fail
        // closed) rather than skipping the gate.
        let peer =
            <axum::extract::ConnectInfo<std::net::SocketAddr> as axum::extract::FromRequestParts<
                Arc<AppState>,
            >>::from_request_parts(parts, state)
            .await
            .map(|ci| ci.0.ip())
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let ip = client_ip(peer, &parts.headers, &state.trusted_proxies);
        spend_auth_budget(state, ip)
            .map(|()| RateLimited)
            .map_err(|retry_after| {
                retry_later(
                    "Too many requests",
                    "This address's authentication budget is spent. Retry after the interval in the Retry-After header.",
                    retry_after,
                )
            })
    }
}

/// The pool, once a request has authenticated. Authentication fails closed
/// when no database is configured, so reaching a handler body proves one.
pub(super) fn pool_of(state: &AppState) -> &sqlx::PgPool {
    state.pool.as_ref().expect("authenticate checked the pool")
}

/// The account a request authenticated as, the credential that proved it, and
/// the account's durable posture as the database held it for this request.
#[derive(Debug, Clone)]
pub(super) struct RequestPrincipal {
    pub(super) account: String,
    pub(super) credential: RequestCredential,
    /// Read from the account row on every request, so authority granted or
    /// revoked outside this process — `e6ircd recover-administrator`, another
    /// replica — is honoured by the next request without a restart.
    pub(super) flags: crate::db::AccountFlags,
}

/// Whether `principal` may administer: durable authority on its account row, or
/// a grant in the running configuration. This is the one place that answers
/// the question, for the JSON administrator routes and the console pages alike.
pub(super) fn is_effective_admin(state: &AppState, principal: &RequestPrincipal) -> bool {
    principal.flags.is_admin()
        || state
            .configured_admin_accounts
            .contains(&e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(&principal.account))
}

/// Authenticate a request by its browser session and nothing else, yielding the
/// principal and the verified session token. A bearer is refused: it cannot
/// name a browser session and must not be able to act as one.
pub(super) async fn authenticate_browser_session(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> ResponseResult<(RequestPrincipal, String)> {
    let principal = authenticate_principal(state, headers).await?;
    let RequestCredential::Session(session) = &principal.credential else {
        return Err(problem(
            StatusCode::UNAUTHORIZED,
            "Browser session required",
            Some("A bearer token cannot act for a browser session."),
        )
        .into());
    };
    let session = session.clone();
    Ok((principal, session))
}

#[derive(Debug, Clone)]
pub(crate) enum RequestCredential {
    /// Browser sessions carry interactive authority but unsafe REST methods
    /// must prove possession of the session-bound CSRF value.
    Session(String),
    /// Tokens carry only the explicit grant checked for the requested method.
    ApiToken {
        scopes: crate::identity::ApiTokenScopes,
        /// The stored token, so a socket it opens can end when it does.
        credential: crate::db::RevocableCredential,
    },
}

impl RequestCredential {
    /// The verified browser session token, when a cookie authenticated the
    /// request.
    pub(crate) fn browser_session(&self) -> Option<&str> {
        match self {
            Self::Session(session) => Some(session),
            Self::ApiToken { .. } => None,
        }
    }

    /// The stored credential behind this request, which a long-lived socket
    /// watches so it ends when the credential does.
    pub(crate) fn revocable(&self) -> crate::db::RevocableCredential {
        match self {
            Self::Session(session) => crate::db::RevocableCredential::browser_session(session),
            Self::ApiToken { credential, .. } => credential.clone(),
        }
    }

    /// Whether the credential may originate a mutation that no HTTP method
    /// announces — a composer frame sent up a socket whose upgrade was a `GET`.
    pub(crate) fn grants_write(&self) -> bool {
        match self {
            Self::Session(_) => true,
            Self::ApiToken { scopes, .. } => scopes.contains(crate::identity::ApiTokenScope::Write),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApiAuthorizationDenial {
    Csrf,
    Scope(crate::identity::ApiTokenScope),
    AdministratorScope,
}

async fn authenticate_principal(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> ResponseResult<RequestPrincipal> {
    let Some(pool) = &state.pool else {
        return Err(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "No database configured",
            None,
        )
        .into());
    };
    if let Some(bearer) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        return match crate::db::api_token_principal(pool, bearer).await {
            Ok(Some(principal)) => {
                require_active_account(pool, principal.account)
                    .await
                    .map(|(account, flags)| RequestPrincipal {
                        account,
                        credential: RequestCredential::ApiToken {
                            scopes: principal.scopes,
                            credential: crate::db::RevocableCredential::api_token(bearer),
                        },
                        flags,
                    })
            }
            Ok(None) => Err(problem(StatusCode::UNAUTHORIZED, "Invalid token", None).into()),
            Err(e) => {
                eprintln!("http: token lookup failed: {e}");
                Err(problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Database unavailable",
                    None,
                )
                .into())
            }
        };
    }
    if let Some(token) = session_token(headers, state.secure_cookies) {
        return match crate::db::session_account(pool, &token).await {
            Ok(Some(account)) => {
                require_active_account(pool, account)
                    .await
                    .map(|(account, flags)| RequestPrincipal {
                        account,
                        credential: RequestCredential::Session(token),
                        flags,
                    })
            }
            Ok(None) => Err(problem(StatusCode::UNAUTHORIZED, "Not logged in", None).into()),
            Err(e) => {
                eprintln!("http: session lookup failed: {e}");
                Err(problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Database unavailable",
                    None,
                )
                .into())
            }
        };
    }
    Err(problem(StatusCode::UNAUTHORIZED, "Not logged in", None).into())
}

/// The shared admission rule for an ordinary authenticated route: the
/// credential authorizes this method, then the request spends the account's
/// budget.
pub(super) fn admit_api_request(
    state: &AppState,
    principal: &RequestPrincipal,
    parts: &axum::http::request::Parts,
) -> ResponseResult<()> {
    authorize_api_request(state, &principal.credential, parts, false)
        .map_err(|denial| api_authorization_response(denial, parts.uri.path()))?;
    spend_api_budget(state, &principal.account, false)
        .map_err(|retry_after| rate_limit_response(retry_after).into())
}

fn authorize_api_request(
    state: &AppState,
    credential: &RequestCredential,
    parts: &axum::http::request::Parts,
    administrator_route: bool,
) -> Result<(), ApiAuthorizationDenial> {
    let RequestCredential::ApiToken { scopes, .. } = credential else {
        if parts.method != axum::http::Method::GET && parts.method != axum::http::Method::HEAD {
            let RequestCredential::Session(session) = credential else {
                unreachable!("closed request credential set")
            };
            if !csrf_header_valid(state, session, &parts.headers) {
                return Err(ApiAuthorizationDenial::Csrf);
            }
        }
        return Ok(());
    };
    let operation =
        if parts.method == axum::http::Method::GET || parts.method == axum::http::Method::HEAD {
            crate::identity::ApiTokenScope::Read
        } else {
            crate::identity::ApiTokenScope::Write
        };
    if !scopes.contains(operation) {
        return Err(ApiAuthorizationDenial::Scope(operation));
    }
    if administrator_route && !scopes.contains(crate::identity::ApiTokenScope::Administrator) {
        return Err(ApiAuthorizationDenial::AdministratorScope);
    }
    Ok(())
}

/// Whether the request carries the `X-E6IRC-CSRF` value bound to `session`. A
/// cross-site page can make a browser send the cookie, but cannot read the
/// value or set the header.
pub(super) fn csrf_header_valid(
    state: &AppState,
    session: &str,
    headers: &axum::http::HeaderMap,
) -> bool {
    let csrf = headers
        .get("x-e6irc-csrf")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    state.csrf_valid(session, csrf)
}

pub(super) fn csrf_refusal() -> Response {
    problem(StatusCode::FORBIDDEN, "Invalid or missing CSRF token", None)
}

fn api_authorization_response(denial: ApiAuthorizationDenial, path: &str) -> Response {
    match denial {
        ApiAuthorizationDenial::Csrf => csrf_refusal(),
        ApiAuthorizationDenial::Scope(scope) => problem(
            StatusCode::FORBIDDEN,
            "Token scope denied",
            Some(&format!(
                "The token does not grant the {} scope required for {path}.",
                scope.as_str()
            )),
        ),
        ApiAuthorizationDenial::AdministratorScope => problem(
            StatusCode::FORBIDDEN,
            "Token scope denied",
            Some("The token does not grant the administrator scope."),
        ),
    }
}

const MAX_API_RATE_BUCKETS: usize = 65_536;
pub(super) const API_RATE_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
const API_RATE_BUCKET_STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(600);

pub(super) fn spend_api_budget(
    state: &AppState,
    account: &str,
    administrator: bool,
) -> Result<(), u64> {
    let burst = if administrator {
        state.administrator_api_rate_burst
    } else {
        state.api_rate_burst
    };
    let key = (
        e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(account),
        administrator,
    );
    let now = std::time::Instant::now();
    let mut buckets = state.api_buckets.lock().expect("API rate limiter lock");
    if !buckets.contains_key(&key) && buckets.len() >= MAX_API_RATE_BUCKETS {
        buckets.retain(|_, (_, last)| now.duration_since(*last) < API_RATE_BUCKET_STALE_AFTER);
        if buckets.len() >= MAX_API_RATE_BUCKETS {
            return Err(1);
        }
    }
    spend_api_bucket(&mut buckets, key, burst, now)
}

/// Spend one token from `key`'s bucket, which holds `burst` tokens and refills
/// to full over [`API_RATE_WINDOW`]. A refusal is the whole seconds until the
/// next token exists.
pub(super) fn spend_api_bucket<K: std::hash::Hash + Eq>(
    buckets: &mut std::collections::HashMap<K, (f64, std::time::Instant)>,
    key: K,
    burst: usize,
    now: std::time::Instant,
) -> Result<(), u64> {
    let (tokens, last) = buckets.entry(key).or_insert((burst as f64, now));
    let elapsed = now.duration_since(*last).as_secs_f64();
    let refill_per_second = burst as f64 / API_RATE_WINDOW.as_secs_f64();
    *tokens = (*tokens + elapsed * refill_per_second).min(burst as f64);
    *last = now;
    if *tokens >= 1.0 {
        *tokens -= 1.0;
        Ok(())
    } else {
        let retry_after = ((1.0 - *tokens) / refill_per_second).ceil().max(1.0) as u64;
        Err(retry_after)
    }
}

pub(super) fn rate_limit_response(retry_after: u64) -> Response {
    retry_later(
        "Account request limit exceeded",
        "Retry after the interval in the Retry-After header.",
        retry_after,
    )
}

/// A wait in whole `Retry-After` seconds, rounded up so a client that obeys it
/// never retries early, and never zero.
pub(super) fn retry_after_seconds(wait: std::time::Duration) -> u64 {
    wait.as_secs()
        .saturating_add(u64::from(wait.subsec_nanos() > 0))
        .max(1)
}

/// A `429` problem carrying the seconds after which the same request can
/// succeed.
pub(super) fn retry_later(title: &str, detail: &str, retry_after: u64) -> Response {
    too_many_requests(
        problem(RETRY_LATER_STATUS, title, Some(detail)),
        retry_after,
    )
}

const RETRY_LATER_STATUS: StatusCode = StatusCode::TOO_MANY_REQUESTS;

/// Turn `response` into a `429` that says when to retry: the one place a
/// `429` is made, so none leaves without `Retry-After`. [`retry_later`] is the
/// problem-document form; a page (the sign-in form) passes its own document.
pub(super) fn too_many_requests(mut response: Response, retry_after: u64) -> Response {
    *response.status_mut() = RETRY_LATER_STATUS;
    response.headers_mut().insert(
        header::RETRY_AFTER,
        retry_after
            .to_string()
            .parse()
            .expect("numeric Retry-After is a valid header"),
    );
    response
}

/// A password check refused because the account name has spent its attempts
/// for the window ([`crate::db::DbError::LoginThrottled`]): the same `429` and
/// `Retry-After` from every endpoint that checks a password.
pub(super) fn login_throttled(retry_after: crate::db::LoginRetryAfter) -> Response {
    retry_later(
        "Too many login attempts",
        &retry_after.explanation(),
        retry_after.seconds(),
    )
}

/// The account and its durable posture, refused when suspended or gone.
async fn require_active_account(
    pool: &sqlx::PgPool,
    account: String,
) -> ResponseResult<(String, crate::db::AccountFlags)> {
    match crate::db::account_flags(pool, &account).await {
        Ok(Some(flags)) if flags.is_suspended() => {
            Err(problem(StatusCode::FORBIDDEN, "Account suspended", None).into())
        }
        Ok(Some(flags)) => Ok((account, flags)),
        Ok(None) => Err(problem(StatusCode::UNAUTHORIZED, "Not logged in", None).into()),
        Err(error) => {
            eprintln!("http: account posture lookup failed: {error}");
            Err(problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            )
            .into())
        }
    }
}

/// Resolve the real client IP: if the socket peer is a trusted proxy, take the
/// rightmost non-trusted `X-Forwarded-For` entry (the client the proxy chain
/// received from); otherwise the peer is the client. XFF is only consulted for
/// trusted peers so a direct client cannot spoof its IP with the header.
pub(super) fn client_ip(
    peer: std::net::IpAddr,
    headers: &axum::http::HeaderMap,
    trusted: &[ipnet::IpNet],
) -> crate::net::ClientIp {
    // Every address is judged in its canonical spelling: a dual-stack listener
    // presents an IPv4 proxy mapped, and a proxy may forward a mapped client.
    let peer = crate::net::ClientIp::new(peer);
    let is_trusted =
        |address: crate::net::ClientIp| trusted.iter().any(|net| net.contains(&address.ip()));
    if !is_trusted(peer) {
        return peer;
    }
    // Concatenate *every* X-Forwarded-For header in header order before scanning
    // right-to-left for the first non-trusted entry (the real client the trusted
    // proxy chain saw). Reading only the first header (`get`) would miss the
    // trusted proxy's appended entry when a proxy emits a *separate* header
    // rather than merging, letting a client-supplied earlier header win — a
    // spoofed key that collapses per-IP rate limits/bans. Whole-string rsplit
    // over the joined value handles both the merged and multi-header forms.
    let joined = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(",");
    for part in joined.rsplit(',') {
        if let Some(ip) = parse_forwarded_ip(part)
            && !is_trusted(ip)
        {
            return ip;
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
fn parse_forwarded_ip(entry: &str) -> Option<crate::net::ClientIp> {
    let s = entry.trim();
    let address = if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        Some(ip) // bare IPv4 or unbracketed IPv6
    } else if let Ok(sock) = s.parse::<std::net::SocketAddr>() {
        Some(sock.ip()) // ip:port or [ip]:port
    } else {
        // `[ip]` with no port.
        s.strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .and_then(|inner| inner.parse::<std::net::IpAddr>().ok())
    };
    address.map(crate::net::ClientIp::new)
}

/// Hard ceiling on the auth-rate bucket map. The age-based retain below only
/// removes *fully-refilled* (idle ≥60s) entries, so a flood from many distinct
/// IPs (trivial with an IPv6 /64) keeps every entry below full and retains them
/// all — the map would otherwise grow to ~request-rate × 60s. This cap bounds it.
const MAX_AUTH_BUCKETS: usize = 4096;

/// Spend one token from `client`'s auth bucket, keyed by its
/// [`PeerLimitKey`](crate::net::PeerLimitKey) (an IPv6 client's whole `/64`).
/// A refusal is the whole seconds until the bucket holds a token again, for
/// the `Retry-After` header; always `Ok` when `auth_rate_burst` is unset. The
/// bucket refills to full over [`API_RATE_WINDOW`]; fully-refilled entries are
/// pruned, and the map is hard-capped at `MAX_AUTH_BUCKETS` so it can't grow
/// without bound even under a distinct-IP flood.
pub(super) fn spend_auth_budget(state: &AppState, client: crate::net::ClientIp) -> Result<(), u64> {
    let Some(burst) = state.auth_rate_burst else {
        return Ok(());
    };
    let ip = client.limit_key();
    let refill_per_sec = burst as f64 / API_RATE_WINDOW.as_secs_f64();
    let now = std::time::Instant::now();
    let mut buckets = state.auth_buckets.lock().expect("poisoned");
    if buckets.len() > MAX_AUTH_BUCKETS {
        buckets.retain(|_, (tokens, last)| {
            *tokens + now.duration_since(*last).as_secs_f64() * refill_per_sec < burst as f64
        });
        // A distinct-IP flood leaves nothing for the retain to prune (every
        // entry is below full). Evict the least-recently-seen entry to make room
        // for a new IP — its bucket simply resets to a fresh burst next time,
        // which is harmless — so memory stays bounded regardless of source spread.
        if buckets.len() >= MAX_AUTH_BUCKETS
            && !buckets.contains_key(&ip)
            && let Some(oldest) = buckets
                .iter()
                .min_by_key(|(_, (_, last))| *last)
                .map(|(k, _)| *k)
        {
            buckets.remove(&oldest);
        }
    }
    spend_api_bucket(&mut buckets, ip, burst, now)
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

/// Frame/MIME/referrer protections for every HTML/app response. The embedded
/// application uses only same-origin scripts, styles, fonts, and HTTP/WebSocket
/// connections; auth and console pages layer their narrower policies on top.
pub(super) fn security_headers(headers: &mut axum::http::HeaderMap) {
    headers.insert(
        header::X_FRAME_OPTIONS,
        "DENY".parse().expect("static header"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
            .parse()
            .expect("static header"),
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

pub(super) fn login_state_cookie_name(secure: bool) -> &'static str {
    if secure {
        "__Host-e6irc_login_state"
    } else {
        "e6irc_login_state"
    }
}

pub(super) fn random_browser_token() -> String {
    crate::secret::random_url_safe_token()
}

pub(super) fn session_cookie(token: &str, secure: bool) -> String {
    let sec = if secure { "; Secure" } else { "" };
    format!(
        "{}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=1209600{sec}",
        session_cookie_name(secure)
    )
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

pub(super) fn session_user_agent(
    headers: &axum::http::HeaderMap,
) -> Option<crate::db::SessionUserAgent> {
    headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .and_then(crate::db::SessionUserAgent::from_header)
}

#[cfg(test)]
mod domain_policy_tests {
    use super::*;

    #[test]
    fn frontchannel_logout_may_be_framed_by_its_issuer_only() {
        assert_eq!(
            frontchannel_frame_policy("https://id.example:8443/realms/main").as_deref(),
            Some("default-src 'none'; frame-ancestors https://id.example:8443")
        );
        assert_eq!(frontchannel_frame_policy("not a url"), None);
        assert_eq!(frontchannel_frame_policy("data:text/plain,x"), None);
    }

    #[test]
    fn jwt_string_claims_parse_only_string_claims() {
        let payload = e6irc_proto::base64::encode(
            br#"{"iss":"https://identity.example","sid":"session-1","role":"admin"}"#,
        )
        .replace(['+', '/'], "-")
        .trim_end_matches('=')
        .to_string();
        let claims = jwt_string_claims(&format!("header.{payload}.signature")).expect("claims");
        assert_eq!(claims.iss.as_deref(), Some("https://identity.example"));
        assert_eq!(claims.sid.as_deref(), Some("session-1"));
        assert_eq!(claims.role.as_deref(), Some("admin"));

        let non_string = e6irc_proto::base64::encode(br#"{"iss":1}"#)
            .replace(['+', '/'], "-")
            .trim_end_matches('=')
            .to_string();
        assert!(jwt_string_claims(&format!("header.{non_string}.signature")).is_err());
    }

    fn provider(domains: &[&str]) -> OidcProviderConfig {
        OidcProviderConfig {
            name: "corp".into(),
            issuer_url: "https://identity.example".into(),
            client_id: "e6irc".into(),
            client_secret: "secret".into(),
            account_claim: crate::config::OidcAccountClaim::PreferredUsername,
            scopes: vec![],
            allowed_email_domains: domains
                .iter()
                .map(|domain| crate::identity::EmailDomain::parse(domain).expect("test domain"))
                .collect(),
            end_session_endpoint: None,
            token_endpoint_auth_method: crate::config::TokenEndpointAuthMethod::ClientSecretBasic,
        }
    }

    #[test]
    fn allowed_domain_policy_is_exact_verified_and_fail_closed() {
        let unrestricted = provider(&[]);
        assert!(email_domain_admitted(&unrestricted, None, false));

        let restricted = provider(&["example.com"]);
        assert!(email_domain_admitted(
            &restricted,
            Some("Alice@Example.COM"),
            true
        ));
        assert!(!email_domain_admitted(
            &restricted,
            Some("alice@example.com"),
            false
        ));
        assert!(!email_domain_admitted(
            &restricted,
            Some("alice@sub.example.com"),
            true
        ));
        assert!(!email_domain_admitted(&restricted, None, true));
        assert!(!email_domain_admitted(
            &restricted,
            Some("not-an-email"),
            true
        ));
    }

    #[test]
    fn frontchannel_logout_query_rejects_unknown_fields() {
        let uri = "/?extra=1".parse().expect("query URI");
        assert!(axum::extract::Query::<FrontchannelLogoutQuery>::try_from_uri(&uri).is_err());
    }

    /// RFC 6749 §4.1.2: the client ignores response parameters it does not
    /// recognize. These are what Google, Keycloak and Entra actually append,
    /// including a granted `scope` spelled differently from the request.
    #[test]
    fn callback_query_ignores_provider_extension_parameters() {
        let uri = "/?state=s&code=c&scope=email%20openid%20https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email&authuser=0&hd=example.com&prompt=consent&session_state=abc"
            .parse()
            .expect("query URI");
        let query = axum::extract::Query::<CallbackQuery>::try_from_uri(&uri)
            .expect("provider extension parameters are ignored");
        assert_eq!(query.state.as_deref(), Some("s"));
        assert_eq!(query.code.as_deref(), Some("c"));
    }

    fn flow(expires_at: u64) -> OidcFlow {
        OidcFlow {
            provider: "corp".into(),
            state: "returned-state".into(),
            pkce_verifier: "verifier".into(),
            nonce: "nonce".into(),
            expires_at,
            link_account: Some("alice".into()),
            silent: true,
        }
    }

    #[test]
    fn a_sealed_flow_opens_only_for_its_state_provider_and_lifetime() {
        let key = crate::secret::SecretKey::generate();
        let sealed = flow(1_000).seal(&key);
        assert!(!sealed.contains("verifier") && !sealed.contains("alice"));

        let opened = OidcFlow::open(&key, Some(&sealed), "corp", "returned-state", 999)
            .expect("the browser's own flow");
        assert_eq!(opened.pkce_verifier, "verifier");
        assert_eq!(opened.nonce, "nonce");
        assert_eq!(opened.link_account.as_deref(), Some("alice"));
        assert!(opened.silent);

        let open = |cookie: Option<&str>, provider: &str, state: &str, now: u64| {
            OidcFlow::open(&key, cookie, provider, state, now).err()
        };
        assert_eq!(
            open(Some(&sealed), "corp", "another-state", 999),
            Some(FlowRefusal::Unbound)
        );
        assert_eq!(
            open(None, "corp", "returned-state", 999),
            Some(FlowRefusal::Unbound)
        );
        assert_eq!(
            open(Some("returned-state"), "corp", "returned-state", 999),
            Some(FlowRefusal::Unbound),
            "the pre-sealing plain-state cookie is not a flow"
        );
        assert_eq!(
            open(Some(&sealed), "other", "returned-state", 999),
            Some(FlowRefusal::WrongProvider)
        );
        assert_eq!(
            open(Some(&sealed), "corp", "returned-state", 1_000),
            Some(FlowRefusal::Expired)
        );
    }

    #[test]
    fn a_flow_cannot_be_forged_or_carried_across_keys_or_contexts() {
        let key = crate::secret::SecretKey::generate();
        let sealed = flow(1_000).seal(&key);
        let other = crate::secret::SecretKey::generate();
        assert_eq!(
            OidcFlow::open(&other, Some(&sealed), "corp", "returned-state", 0).err(),
            Some(FlowRefusal::Unbound),
            "a flow from before a restart (or another process) is refused"
        );
        let mut tampered = sealed.clone().into_bytes();
        let last = tampered.len() - 3;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).expect("ascii");
        assert_eq!(
            OidcFlow::open(&key, Some(&tampered), "corp", "returned-state", 0).err(),
            Some(FlowRefusal::Unbound)
        );
        let json = serde_json::to_string(&flow(1_000)).expect("json");
        let foreign_context = key.seal(&json, crate::secret::CONFIG_CONTEXT);
        assert_eq!(
            OidcFlow::open(&key, Some(&foreign_context), "corp", "returned-state", 0).err(),
            Some(FlowRefusal::Unbound),
            "a value sealed for another purpose is not a flow"
        );
    }

    #[test]
    fn callback_query_accepts_the_standard_issuer_parameter() {
        let uri = "/?iss=https%3A%2F%2Fidentity.example"
            .parse()
            .expect("query URI");
        let query = axum::extract::Query::<CallbackQuery>::try_from_uri(&uri)
            .expect("standard issuer parameter");
        assert_eq!(query.issuer.as_deref(), Some("https://identity.example"));
    }

    #[test]
    fn account_rate_buckets_are_bounded_by_time_and_rate_class() {
        let start = std::time::Instant::now();
        let mut buckets = std::collections::HashMap::new();
        let ordinary = ("alice".to_string(), false);
        assert!(spend_api_bucket(&mut buckets, ordinary.clone(), 2, start).is_ok());
        assert!(spend_api_bucket(&mut buckets, ordinary.clone(), 2, start).is_ok());
        assert_eq!(
            spend_api_bucket(&mut buckets, ordinary.clone(), 2, start),
            Err(30)
        );
        assert!(
            spend_api_bucket(
                &mut buckets,
                ordinary,
                2,
                start + std::time::Duration::from_secs(30)
            )
            .is_ok()
        );
        assert!(
            spend_api_bucket(&mut buckets, ("alice".to_string(), true), 1, start).is_ok(),
            "administrator and ordinary budgets are intentionally independent"
        );
    }
}
