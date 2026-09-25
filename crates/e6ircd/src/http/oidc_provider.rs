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
#[derive(Clone)]
pub(super) struct ProviderHttp {
    client: reqwest::Client,
    policy: crate::egress::InternalUpstreams,
}

impl ProviderHttp {
    fn new(policy: crate::egress::InternalUpstreams) -> Self {
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
        Self { client, policy }
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
        // before the client sees it.
        let refusal = url::Url::parse(&request.uri().to_string())
            .map_err(|_| "provider URL does not parse".to_string())
            .and_then(|url| {
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

/// Cache key: the issuer, and the server's egress policy (tests run servers
/// with different policies in one process).
type DiscoveryKey = (String, crate::egress::InternalUpstreams);

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

async fn fetch(
    issuer: &str,
    policy: crate::egress::InternalUpstreams,
) -> Result<ProviderDiscovery, String> {
    let http = ProviderHttp::new(provider_policy(issuer, policy).await?);
    let issuer = openidconnect::IssuerUrl::new(issuer.to_string()).map_err(|e| e.to_string())?;
    let metadata = openidconnect::core::CoreProviderMetadata::discover_async(issuer, &http)
        .await
        .map_err(|error| format!("discovery failed: {}", discovery_error(&error)))?;
    Ok(ProviderDiscovery { metadata, http })
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
    policy: crate::egress::InternalUpstreams,
    provider: &OidcProviderConfig,
) -> Result<ProviderDiscovery, String> {
    let key = (provider.issuer_url.clone(), policy);
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
    policy: crate::egress::InternalUpstreams,
    provider: &OidcProviderConfig,
) -> Result<ProviderDiscovery, String> {
    let key = (provider.issuer_url.clone(), policy);
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
    pub(in crate::http) fn age_for_refresh(issuer: &str, policy: InternalUpstreams) {
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
        let outside = ProviderHttp::new(InternalUpstreams::Refuse);
        let inside = ProviderHttp::new(InternalUpstreams::Allow);
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
        let policy = InternalUpstreams::Refuse;
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
