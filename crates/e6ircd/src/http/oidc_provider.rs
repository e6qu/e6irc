//! Talking to an identity provider: where its HTTP calls may go, its cached
//! discovery document and keys, and the authorization flows already answered.

use super::*;

use openidconnect::reqwest;

/// How long a discovery document (and the keys that came with it) is served
/// from the cache. Bounds outbound fetches so an unauthenticated flood of
/// login/logout requests cannot amplify into one provider round trip each.
const DISCOVERY_TTL: std::time::Duration = std::time::Duration::from_secs(900);

/// How long a failed discovery is answered from the cache. Without it an
/// unreachable provider made every unauthenticated start, callback, and
/// back-channel POST dial it again.
const DISCOVERY_FAILURE_TTL: std::time::Duration = std::time::Duration::from_secs(30);

/// The least time between two forced refreshes of one provider's keys. A token
/// signed by a key the cache does not hold forces one (the provider rotated
/// its keys); a flood of tokens naming unknown keys forces at most one per
/// interval.
const KEY_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Where one provider's HTTP calls may go: the server's egress rule
/// (`crate::egress`), judged again for every request.
///
/// An identity provider is configured by an administrator, not typed by an
/// account holder, and self-hosted providers routinely live inside the
/// server's own network. So the configured issuer's own position decides:
/// when the issuer is inside (loopback, private) the provider's endpoints may
/// be too; when it is outside, the endpoints its discovery document
/// advertises — the token endpoint, the key set, anything the provider or
/// whoever controls its document names — must be outside as well. Addresses
/// that are never a network (the cloud metadata endpoint among them) are
/// refused either way.
/// Its endpoints' schemes are judged per request too ([`EndpointSchemes`]).
#[derive(Clone)]
pub(super) struct ProviderHttp {
    client: reqwest::Client,
    policy: crate::egress::InternalUpstreams,
    schemes: EndpointSchemes,
}

/// Which URL schemes a server lets its identity providers' endpoints use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum EndpointSchemes {
    /// `https` only: the server's cookies are `Secure` (`secure_cookies`), so
    /// it is served over HTTPS, and a plaintext discovery document, key set or
    /// token exchange would let an on-path attacker forge ID tokens or read
    /// authorization codes and the client secret.
    HttpsOnly,
    /// `http` too: a development server talking to a local provider.
    HttpOrHttps,
}

impl EndpointSchemes {
    pub(crate) const fn for_secure_cookies(secure_cookies: bool) -> Self {
        if secure_cookies {
            Self::HttpsOnly
        } else {
            Self::HttpOrHttps
        }
    }

    /// Why `url` may not be the provider's `what`, if it may not.
    fn refusal(self, what: &str, url: &url::Url) -> Option<String> {
        (self == Self::HttpsOnly && url.scheme() != "https")
            .then(|| format!("the provider's {what} must be https, not {}", url.scheme()))
    }
}

/// Where a server lets its identity providers' calls go: its egress rule and
/// the schemes their endpoints may use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ProviderRules {
    pub(crate) egress: crate::egress::InternalUpstreams,
    pub(crate) schemes: EndpointSchemes,
}

impl ProviderHttp {
    fn new(policy: crate::egress::InternalUpstreams, schemes: EndpointSchemes) -> Self {
        // No redirect following: a provider endpoint must answer directly,
        // and a 3xx cannot re-target an address the rule refuses. Timeouts
        // bound each call so an unresponsive provider (reached from
        // unauthenticated paths) cannot pin a task.
        let client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(15))
            .dns_resolver(Arc::new(crate::egress::VettingResolver::new(policy)))
            .build()
            .expect("reqwest client");
        Self {
            client,
            policy,
            schemes,
        }
    }
}

impl<'c> openidconnect::AsyncHttpClient<'c> for ProviderHttp {
    type Error = openidconnect::HttpClientError<reqwest::Error>;
    type Future = std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<openidconnect::HttpResponse, Self::Error>>
                + Send
                + Sync
                + 'c,
        >,
    >;

    fn call(&'c self, request: openidconnect::HttpRequest) -> Self::Future {
        // A URL whose host is an address literal never reaches the resolver:
        // the connector dials it directly. So the literal is judged here,
        // before the client sees it. The scheme is judged with it: the key set
        // and the token endpoint are fetched through here.
        let refusal = url::Url::parse(&request.uri().to_string())
            .map_err(|_| "provider URL does not parse".to_string())
            .and_then(|url| {
                if let Some(refusal) = self.schemes.refusal("endpoint", &url) {
                    return Err(refusal);
                }
                self.policy
                    .refusal_for_url(&url)
                    .map_or(Ok(()), |refusal| Err(refusal.reason().to_string()))
            });
        Box::pin(async move {
            refusal.map_err(openidconnect::HttpClientError::Other)?;
            self.client.call(request).await
        })
    }
}

/// The egress policy for `issuer`'s calls under the server's `policy`: see
/// [`ProviderHttp`].
async fn provider_policy(
    issuer: &str,
    policy: crate::egress::InternalUpstreams,
) -> Result<crate::egress::InternalUpstreams, String> {
    use crate::egress::{InternalUpstreams, UpstreamRefusal};
    if policy == InternalUpstreams::Allow {
        return Ok(policy);
    }
    let url = url::Url::parse(issuer).map_err(|_| "issuer_url does not parse".to_string())?;
    let addresses: Vec<std::net::IpAddr> = match url.host() {
        Some(url::Host::Ipv4(ip)) => vec![ip.into()],
        Some(url::Host::Ipv6(ip)) => vec![ip.into()],
        Some(url::Host::Domain(domain)) => {
            tokio::net::lookup_host((domain, url.port_or_known_default().unwrap_or(443)))
                .await
                .map_err(|error| format!("issuer {domain} does not resolve: {error}"))?
                .map(|address| address.ip())
                .collect()
        }
        None => return Err("issuer_url has no host".into()),
    };
    let refusals: Vec<Option<UpstreamRefusal>> = addresses
        .iter()
        .map(|&ip| InternalUpstreams::Refuse.refusal(ip))
        .collect();
    if refusals.contains(&Some(UpstreamRefusal::Internal)) {
        // The administrator put the provider inside; its endpoints may be.
        Ok(InternalUpstreams::Allow)
    } else if refusals.contains(&None) {
        Ok(InternalUpstreams::Refuse)
    } else {
        Err(UpstreamRefusal::NeverAnUpstream.reason().into())
    }
}

/// A provider's discovery document, its keys, and the client its calls go
/// through.
#[derive(Clone)]
pub(super) struct ProviderDiscovery {
    pub(super) metadata: openidconnect::core::CoreProviderMetadata,
    pub(super) http: ProviderHttp,
}

enum CachedDiscovery {
    Found {
        fetched: std::time::Instant,
        discovery: Box<ProviderDiscovery>,
    },
    Failed {
        at: std::time::Instant,
        error: String,
    },
}

/// Cache key: the issuer, and the server's rules for providers (tests run
/// servers with different rules in one process).
type DiscoveryKey = (String, ProviderRules);

fn discovery_cache() -> &'static std::sync::Mutex<HashMap<DiscoveryKey, CachedDiscovery>> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<HashMap<DiscoveryKey, CachedDiscovery>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(Default::default)
}

/// Refreshes are made one at a time, so a burst of tokens signed by a new key
/// makes one fetch, and every waiter then reads its result.
fn refresh_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(Default::default)
}

/// The cached answer for `key` when it is younger than `fresh_for` (or, for a
/// failure, [`DISCOVERY_FAILURE_TTL`]).
fn cached(
    key: &DiscoveryKey,
    fresh_for: std::time::Duration,
) -> Option<Result<ProviderDiscovery, String>> {
    match discovery_cache()
        .lock()
        .expect("discovery cache")
        .get(key)?
    {
        CachedDiscovery::Found { fetched, discovery } if fetched.elapsed() < fresh_for => {
            Some(Ok(ProviderDiscovery::clone(discovery)))
        }
        CachedDiscovery::Failed { at, error } if at.elapsed() < DISCOVERY_FAILURE_TTL => {
            Some(Err(error.clone()))
        }
        _ => None,
    }
}

async fn fetch(issuer: &str, rules: ProviderRules) -> Result<ProviderDiscovery, String> {
    let http = ProviderHttp::new(provider_policy(issuer, rules.egress).await?, rules.schemes);
    let issuer = openidconnect::IssuerUrl::new(issuer.to_string()).map_err(|e| e.to_string())?;
    let metadata = openidconnect::core::CoreProviderMetadata::discover_async(issuer, &http)
        .await
        .map_err(|error| format!("discovery failed: {}", discovery_error(&error)))?;
    advertised_endpoint_refusal(&metadata, rules.schemes).map_or(Ok(()), Err)?;
    Ok(ProviderDiscovery { metadata, http })
}

/// Why the endpoints a discovery document advertises may not be used under
/// `schemes`, if they may not. The browser is sent to the authorization
/// endpoint, so it is judged here, where it is learned; the others are also
/// judged on every call ([`ProviderHttp`]), but a document that names one
/// in plaintext is refused whole rather than failing a login halfway.
fn advertised_endpoint_refusal(
    metadata: &openidconnect::core::CoreProviderMetadata,
    schemes: EndpointSchemes,
) -> Option<String> {
    [
        (
            "authorization_endpoint",
            Some(metadata.authorization_endpoint().url()),
        ),
        (
            "token_endpoint",
            metadata.token_endpoint().map(|url| url.url()),
        ),
        ("jwks_uri", Some(metadata.jwks_uri().url())),
        (
            "userinfo_endpoint",
            metadata.userinfo_endpoint().map(|url| url.url()),
        ),
    ]
    .into_iter()
    .find_map(|(what, url)| url.and_then(|url| schemes.refusal(what, url)))
}

async fn fetch_and_cache(key: DiscoveryKey) -> Result<ProviderDiscovery, String> {
    let result = fetch(&key.0, key.1).await;
    let entry = match &result {
        Ok(discovery) => CachedDiscovery::Found {
            fetched: std::time::Instant::now(),
            discovery: Box::new(discovery.clone()),
        },
        Err(error) => CachedDiscovery::Failed {
            at: std::time::Instant::now(),
            error: error.clone(),
        },
    };
    discovery_cache()
        .lock()
        .expect("discovery cache")
        .insert(key, entry);
    result
}

fn discovery_error(error: &(dyn std::error::Error + 'static)) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

/// The provider's discovery document and keys, from the cache when fresh.
pub(super) async fn discover(
    rules: ProviderRules,
    provider: &OidcProviderConfig,
) -> Result<ProviderDiscovery, String> {
    let key = (provider.issuer_url.clone(), rules);
    if let Some(answer) = cached(&key, DISCOVERY_TTL) {
        return answer;
    }
    fetch_and_cache(key).await
}

/// The provider's document and keys fetched again, because a token was signed
/// by a key the cache does not hold — the provider rotated its keys. One
/// refresh runs at a time, and a provider refreshed less than
/// [`KEY_REFRESH_INTERVAL`] ago is answered from the cache, so tokens naming
/// unknown keys cannot drive a fetch each.
pub(super) async fn refresh(
    rules: ProviderRules,
    provider: &OidcProviderConfig,
) -> Result<ProviderDiscovery, String> {
    let key = (provider.issuer_url.clone(), rules);
    let _single = refresh_lock().lock().await;
    if let Some(answer) = cached(&key, KEY_REFRESH_INTERVAL) {
        return answer;
    }
    fetch_and_cache(key).await
}

/// Authorization flows whose callback has been answered, by their `state`.
///
/// A flow cookie is cleared by the callback that spends it, but a client that
/// keeps a copy could present it again until it expires, and each
/// presentation would make this server call the provider's token endpoint
/// with its client secret. Remembering the spent `state` until the flow would
/// have expired makes a flow answerable once. The set is bounded: past
/// [`MAX_SPENT_FLOWS`] the flow closest to its own expiry is forgotten first,
/// so no volume of logins can exhaust it or refuse a real one.
#[derive(Default)]
pub(crate) struct SpentFlows {
    spent: std::sync::Mutex<HashMap<String, u64>>,
}

const MAX_SPENT_FLOWS: usize = 65_536;

impl SpentFlows {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record `state` as spent until `expires_at` (Unix seconds). `false` when
    /// it already was: the flow has been answered.
    pub(super) fn spend(&self, state: &str, expires_at: u64, now: u64) -> bool {
        let mut spent = self.spent.lock().expect("spent flows");
        spent.retain(|_, expiry| *expiry > now);
        if spent.contains_key(state) {
            return false;
        }
        if spent.len() >= MAX_SPENT_FLOWS
            && let Some(soonest) = spent
                .iter()
                .min_by_key(|(_, expiry)| **expiry)
                .map(|(state, _)| state.clone())
        {
            spent.remove(&soonest);
        }
        spent.insert(state.to_string(), expires_at);
        true
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::egress::InternalUpstreams;

    /// Make `issuer`'s cached document old enough for a key refresh to fetch.
    pub(in crate::http) fn age_for_refresh(issuer: &str, policy: ProviderRules) {
        if let Some(CachedDiscovery::Found { fetched, .. }) = discovery_cache()
            .lock()
            .expect("cache")
            .get_mut(&(issuer.to_string(), policy))
        {
            *fetched = std::time::Instant::now()
                .checked_sub(KEY_REFRESH_INTERVAL)
                .expect("the monotonic clock has run for the interval");
        }
    }

    #[tokio::test]
    async fn a_provider_inside_may_use_inside_endpoints_and_one_outside_may_not() {
        assert_eq!(
            provider_policy("http://127.0.0.1:5556/dex", InternalUpstreams::Refuse).await,
            Ok(InternalUpstreams::Allow)
        );
        assert_eq!(
            provider_policy("https://93.184.215.14", InternalUpstreams::Refuse).await,
            Ok(InternalUpstreams::Refuse)
        );
        assert!(
            provider_policy("http://169.254.169.254", InternalUpstreams::Refuse)
                .await
                .is_err()
        );
        assert_eq!(
            provider_policy("http://169.254.169.254", InternalUpstreams::Allow).await,
            Ok(InternalUpstreams::Allow),
            "the operator's allowance is the server's; the metadata address is still refused per request"
        );
    }

    #[tokio::test]
    async fn a_request_to_a_refused_address_is_never_sent() {
        use openidconnect::AsyncHttpClient;
        let outside = ProviderHttp::new(InternalUpstreams::Refuse, EndpointSchemes::HttpOrHttps);
        let inside = ProviderHttp::new(InternalUpstreams::Allow, EndpointSchemes::HttpOrHttps);
        for (http, url) in [
            (&outside, "http://169.254.169.254/latest/meta-data/"),
            (&inside, "http://169.254.169.254/latest/meta-data/"),
            (&outside, "http://127.0.0.1:9/token"),
            (&outside, "http://2130706433/token"),
        ] {
            let request = openidconnect::http::Request::builder()
                .uri(url)
                .body(Vec::new())
                .expect("request");
            let error = http.call(request).await.expect_err(url);
            assert!(
                matches!(&error, openidconnect::HttpClientError::Other(reason) if reason.contains("must not")),
                "{url}: {error}"
            );
        }
    }

    /// Under `secure_cookies`, no provider endpoint is reached over plaintext:
    /// the request is refused before it is sent, whatever the address.
    #[tokio::test]
    async fn a_plaintext_endpoint_is_never_called_when_https_is_required() {
        use openidconnect::AsyncHttpClient;
        let https_only = ProviderHttp::new(InternalUpstreams::Allow, EndpointSchemes::HttpsOnly);
        let request = openidconnect::http::Request::builder()
            .uri("http://127.0.0.1:9/keys")
            .body(Vec::new())
            .expect("request");
        let error = https_only.call(request).await.expect_err("plaintext");
        assert!(
            matches!(&error, openidconnect::HttpClientError::Other(reason)
                if reason.contains("must be https")),
            "{error}"
        );
    }

    /// A discovery document fetched over https that advertises a plaintext
    /// endpoint is refused under `secure_cookies`, naming the endpoint, and
    /// used as it is by a development server.
    #[test]
    fn a_document_advertising_a_plaintext_endpoint_is_refused_when_https_is_required() {
        let document = |authorization: &str, token: &str, keys: &str, userinfo: &str| {
            serde_json::from_value::<openidconnect::core::CoreProviderMetadata>(serde_json::json!({
                "issuer": "https://id.example",
                "authorization_endpoint": authorization,
                "token_endpoint": token,
                "jwks_uri": keys,
                "userinfo_endpoint": userinfo,
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
            }))
            .expect("discovery document")
        };
        let https = "https://id.example/x";
        let plain = "http://id.example/x";
        assert_eq!(
            advertised_endpoint_refusal(
                &document(https, https, https, https),
                EndpointSchemes::HttpsOnly
            ),
            None
        );
        for (metadata, named) in [
            (
                document(plain, https, https, https),
                "authorization_endpoint",
            ),
            (document(https, plain, https, https), "token_endpoint"),
            (document(https, https, plain, https), "jwks_uri"),
            (document(https, https, https, plain), "userinfo_endpoint"),
        ] {
            let refusal = advertised_endpoint_refusal(&metadata, EndpointSchemes::HttpsOnly)
                .expect("a plaintext endpoint is refused");
            assert!(
                refusal.contains(named) && refusal.contains("https"),
                "{refusal}"
            );
            assert_eq!(
                advertised_endpoint_refusal(&metadata, EndpointSchemes::HttpOrHttps),
                None,
                "a development server may use {named} over http"
            );
        }
    }

    /// A provider stand-in whose key set can change, counting each fetch.
    pub(in crate::http) async fn provider(
        keys: Arc<std::sync::Mutex<serde_json::Value>>,
        fetches: Arc<std::sync::atomic::AtomicUsize>,
        healthy: bool,
    ) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let issuer = format!("http://{}", listener.local_addr().expect("address"));
        let document = serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/auth"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/keys"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        });
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || {
                    let (document, fetches) = (document.clone(), fetches.clone());
                    async move {
                        fetches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if healthy {
                            axum::Json(document).into_response()
                        } else {
                            StatusCode::INTERNAL_SERVER_ERROR.into_response()
                        }
                    }
                }),
            )
            .route(
                "/keys",
                get(move || {
                    let keys = keys.lock().expect("keys").clone();
                    async move { axum::Json(keys) }
                }),
            );
        tokio::spawn(async move { axum::serve(listener, app).await });
        issuer
    }

    fn key_set(kid: &str) -> serde_json::Value {
        serde_json::json!({ "keys": [{
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
            "n": "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
            "e": "AQAB",
        }]})
    }

    pub(in crate::http) fn provider_config(issuer: &str) -> OidcProviderConfig {
        OidcProviderConfig {
            name: "corp".into(),
            issuer_url: issuer.into(),
            client_id: "e6irc".into(),
            client_secret: "secret".into(),
            account_claim: crate::config::OidcAccountClaim::PreferredUsername,
            scopes: vec![],
            allowed_email_domains: vec![],
            end_session_endpoint: None,
            token_endpoint_auth_method: crate::config::TokenEndpointAuthMethod::ClientSecretBasic,
        }
    }

    fn key_ids(discovery: &ProviderDiscovery) -> Vec<String> {
        use openidconnect::JsonWebKey;
        discovery
            .metadata
            .jwks()
            .keys()
            .iter()
            .filter_map(|key| key.key_id().map(|id| id.as_str().to_string()))
            .collect()
    }

    #[tokio::test]
    async fn a_key_refresh_is_throttled_and_a_failed_discovery_is_remembered_briefly() {
        let policy = ProviderRules {
            egress: InternalUpstreams::Refuse,
            schemes: EndpointSchemes::HttpOrHttps,
        };
        let keys = Arc::new(std::sync::Mutex::new(key_set("old")));
        let fetches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = |fetches: &std::sync::atomic::AtomicUsize| {
            fetches.load(std::sync::atomic::Ordering::SeqCst)
        };
        let issuer = provider(keys.clone(), fetches.clone(), true).await;
        let config = provider_config(&issuer);
        assert_eq!(
            key_ids(&discover(policy, &config).await.expect("discovery")),
            ["old"]
        );
        // The provider rotates its keys. A refresh right after a fetch is
        // answered from the cache: tokens naming unknown keys cannot drive a
        // fetch each.
        *keys.lock().expect("keys") = key_set("new");
        assert_eq!(
            key_ids(&refresh(policy, &config).await.expect("throttled")),
            ["old"]
        );
        assert_eq!(count(&fetches), 1);
        // Once the interval has passed, a refresh fetches the rotated keys,
        // and the next refresh is throttled again.
        age_for_refresh(&issuer, policy);
        assert_eq!(
            key_ids(&refresh(policy, &config).await.expect("refresh")),
            ["new"]
        );
        assert_eq!(count(&fetches), 2);
        assert_eq!(
            key_ids(&refresh(policy, &config).await.expect("throttled")),
            ["new"]
        );
        assert_eq!(count(&fetches), 2);
        assert_eq!(
            key_ids(&discover(policy, &config).await.expect("cached")),
            ["new"]
        );

        let broken_fetches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let broken = provider_config(&provider(keys, broken_fetches.clone(), false).await);
        assert!(discover(policy, &broken).await.is_err());
        assert!(discover(policy, &broken).await.is_err());
        assert!(refresh(policy, &broken).await.is_err());
        assert_eq!(
            count(&broken_fetches),
            1,
            "a failure is remembered, not fetched again per request"
        );
    }

    #[test]
    fn a_flow_is_answered_once_and_the_record_stays_bounded() {
        let spent = SpentFlows::new();
        assert!(spent.spend("state-1", 1_000, 100));
        assert!(!spent.spend("state-1", 1_000, 200), "a replay is refused");
        assert!(
            spent.spend("state-1", 2_000, 1_000),
            "an expired record is forgotten"
        );
        for index in 0..MAX_SPENT_FLOWS + 10 {
            assert!(spent.spend(&format!("flow-{index}"), 5_000 + index as u64, 1_001));
        }
        assert!(spent.spent.lock().expect("spent").len() <= MAX_SPENT_FLOWS);
    }
}
