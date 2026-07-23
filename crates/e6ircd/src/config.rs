//! Server configuration. TOML on disk; unknown keys are a startup
//! error — configuration mistakes must never be silently ignored.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

fn default_nicklen() -> usize {
    16
}
fn default_sendq() -> usize {
    1024
}
fn default_core_queue() -> usize {
    65536
}
fn default_description() -> String {
    "e6irc server".into()
}

/// `draft/account-registration` policy, advertised as the capability's value
/// so a client knows the rules before it tries.
#[derive(Debug, Clone, Default, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistrationConfig {
    /// Allow REGISTER before the connection completes registration
    /// (`before-connect`). Off by default: a half-open connection creating
    /// accounts is a spam vector unless the operator opts in.
    #[serde(default)]
    pub before_connect: bool,
    /// Require an email address (`email-required`). e6ircd cannot send
    /// verification mail, so this only enforces that one was supplied.
    #[serde(default)]
    pub require_email: bool,
}

fn default_max_hot_channels() -> usize {
    8192
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server_name: String,
    pub network_name: String,
    /// Human-readable description of *this server* (RPL_LINKS `<server info>`).
    /// Distinct from `network_name`, which names the network this server
    /// belongs to — the two are different things and RPL_LINKS wants this one.
    #[serde(default = "default_description")]
    pub description: String,
    #[serde(default)]
    pub motd: Vec<String>,
    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,
    /// Maximum nick length (ISUPPORT NICKLEN).
    #[serde(default = "default_nicklen")]
    pub nicklen: usize,
    /// Per-connection outbound queue capacity (events); overflow kills
    /// the client ("SendQ exceeded").
    #[serde(default = "default_sendq")]
    pub sendq: usize,
    /// Core worker inbound queue capacity; when full, connection
    /// readers stop reading their sockets (backpressure).
    #[serde(default = "default_core_queue")]
    pub core_queue: usize,
    /// Cap on channels holding an in-memory history ring (LRU eviction
    /// beyond this; evicted channels serve CHATHISTORY from Postgres).
    #[serde(default = "default_max_hot_channels")]
    pub max_hot_channels: usize,
    /// `draft/account-registration` policy. Only meaningful with a database,
    /// since there are no accounts without one.
    #[serde(default)]
    pub registration: RegistrationConfig,
    /// PostgreSQL connection; enables accounts and SASL when present.
    #[serde(default)]
    pub database: Option<DatabaseConfig>,
    /// HTTP listener (REST API + web backend); off when absent.
    #[serde(default)]
    pub http: Option<HttpConfig>,
    /// OIDC providers for web login (requires http + database).
    #[serde(default, rename = "oidc")]
    pub oidc_providers: Vec<OidcProviderConfig>,
    /// Immutable deployed source revision exposed to post-deployment
    /// acceptance checks. Required when Shauth is configured.
    #[serde(default)]
    pub application_release_revision: Option<String>,
    /// IRC operators. Passwords are plaintext in the config file, which
    /// must therefore be protected (0600); this matches ircd.conf
    /// convention.
    #[serde(default, rename = "oper")]
    pub opers: Vec<OperConfig>,
    /// BNC upstream networks (server-level; per-user comes with account
    /// integration).
    #[serde(default, rename = "network")]
    pub networks: Vec<NetworkEntry>,
    /// The bouncer listener, where clients attach as nick/network.
    #[serde(default)]
    pub bnc: Option<BncConfig>,
    /// Source of the key that decrypts sealed (`enc:v1:`) secrets. When
    /// absent, the `E6IRC_SECRET_KEY` env var is consulted instead.
    #[serde(default)]
    pub secrets: Option<SecretsConfig>,
    /// Abuse limits. All off by default.
    #[serde(default)]
    pub limits: LimitsConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Maximum simultaneous connections from one IP; `None` = unlimited.
    /// Excess connections are refused at accept (before registration).
    #[serde(default)]
    pub max_connections_per_ip: Option<usize>,
    /// Per-session command-flood bucket size; `None` disables the
    /// throttle. Registered non-oper sessions spend one token per command
    /// (PING/PONG exempt) and refill one per second.
    #[serde(default)]
    pub command_burst: Option<usize>,
    /// CIDRs of trusted reverse proxies (e.g. the load balancer). When a
    /// request's socket peer matches one of these, its client IP is taken
    /// from `X-Forwarded-For`; otherwise the socket peer IP is used. Parsing
    /// is validated at startup — an invalid CIDR is a hard error.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Token-bucket size for the auth endpoints (credential issue + OIDC login
    /// start), per client IP; the bucket refills to full over 60 seconds.
    /// `None` disables auth rate limiting.
    #[serde(default)]
    pub auth_rate_burst: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretsConfig {
    /// Path to a file holding the base64-encoded 32-byte master key.
    pub key_file: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkEntry {
    /// Selector used by clients (the /network suffix on the nick).
    pub name: String,
    /// Driver kind: an outbound `irc` upstream (default), or the
    /// in-process `local` network (this e6ircd itself).
    #[serde(default)]
    pub kind: NetworkKind,
    /// e6irc account that owns this network. When set, only that account
    /// may attach to it; when absent the network is shared (any
    /// authenticated account may attach). Per-user self-service creation
    /// (DB-backed) reuses this ownership.
    #[serde(default)]
    pub owner: Option<String>,
    /// Upstream address (host:port). Ignored for `local`.
    #[serde(default)]
    pub addr: String,
    #[serde(default)]
    pub tls: bool,
    pub nick: String,
    #[serde(default)]
    pub realname: Option<String>,
    #[serde(default)]
    pub autojoin: Vec<String>,
    #[serde(default = "default_bnc_buffer")]
    pub buffer_cap: usize,
    /// Upstream SASL account (with sasl_password enables SASL PLAIN).
    #[serde(default)]
    pub sasl_account: Option<String>,
    #[serde(default)]
    pub sasl_password: Option<String>,
}

fn default_bnc_buffer() -> usize {
    1000
}

/// Which driver backs a BNC network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkKind {
    /// A persistent outbound IRC client to an external network.
    #[default]
    Irc,
    /// This e6ircd itself, joined in-process — an always-on local
    /// presence with backlog, no external connection.
    Local,
    /// A Matrix homeserver bridged as a network (requires the `matrix`
    /// build feature). `addr` = homeserver URL, `nick` = login user,
    /// `sasl_password` = password, `autojoin` = room aliases.
    Matrix,
    /// A Discord bot session bridged as a network (requires the `discord`
    /// build feature). `sasl_password` = bot token, `autojoin` = channel
    /// ids to bridge, `addr` = optional API base (defaults to Discord).
    Discord,
    /// A Slack workspace bridged as a network (requires the `slack` build
    /// feature). `sasl_account` = bot token (xoxb-), `sasl_password` =
    /// app-level token (xapp-), `autojoin` = channel ids, `addr` =
    /// optional Web-API base (defaults to Slack).
    Slack,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BncConfig {
    pub addr: SocketAddr,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperConfig {
    pub name: String,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpConfig {
    pub addr: SocketAddr,
    /// Externally reachable base URL (scheme://host[:port]), used to
    /// build OIDC redirect URIs. Required when [[oidc]] is configured.
    #[serde(default)]
    pub public_url: Option<String>,
    /// Mark session cookies Secure (default true; disable only for
    /// plain-HTTP development).
    #[serde(default = "default_true")]
    pub secure_cookies: bool,
    /// Accounts allowed to use the `/api/v1/admin` endpoints. Empty
    /// (default) means no one — admin is opt-in and explicit.
    #[serde(default)]
    pub admin_accounts: Vec<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcProviderConfig {
    /// URL path segment and display name, e.g. "corp".
    pub name: String,
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    /// OAuth scopes to request in addition to `openid`. Defaults to
    /// `profile` + `email`; providers like Shauth also accept
    /// `offline_access`.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// RP-initiated logout (OIDC end-session) endpoint. When set, e6irc's
    /// logout redirects the browser here with `id_token_hint` and
    /// `post_logout_redirect_uri` so the identity provider's SSO session is
    /// ended too — not just the local e6irc session. Shauth/Hydra expose
    /// this at `<issuer>/oauth2/sessions/logout`.
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
    /// How this client authenticates to the token endpoint. The method is a
    /// property of the *client registration*, not of the provider, so
    /// discovery cannot supply it: a provider that advertises several methods
    /// still rejects every one the client was not registered for. Shauth
    /// registers managed applications with `client_secret_post`.
    #[serde(default)]
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
}

/// Client authentication methods e6irc supports at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuthMethod {
    /// HTTP Basic credentials, the OAuth 2.0 default.
    #[default]
    ClientSecretBasic,
    /// Credentials in the request body, which Shauth's registrations require.
    ClientSecretPost,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    pub url: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_name: "irc.localhost".into(),
            network_name: "e6irc".into(),
            description: default_description(),
            registration: RegistrationConfig::default(),
            motd: Vec::new(),
            listeners: Vec::new(),
            nicklen: default_nicklen(),
            sendq: default_sendq(),
            core_queue: default_core_queue(),
            max_hot_channels: default_max_hot_channels(),
            database: None,
            http: None,
            oidc_providers: Vec::new(),
            application_release_revision: None,
            opers: Vec::new(),
            networks: Vec::new(),
            bnc: None,
            secrets: None,
            limits: LimitsConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    pub addr: SocketAddr,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
    Invalid(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "cannot read config: {e}"),
            Self::Parse(e) => write!(f, "invalid config: {e}"),
            Self::Invalid(msg) => write!(f, "invalid config: {msg}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Open one config secret: decrypt if sealed (requiring a key), else
/// pass the plaintext through. Fails loudly on the mismatches.
fn open_secret(value: &str, key: Option<&crate::secret::SecretKey>) -> Result<String, ConfigError> {
    if !crate::secret::is_sealed(value) {
        return Ok(value.to_string());
    }
    let key = key.ok_or_else(|| {
        ConfigError::Invalid(
            "an encrypted secret (enc:v1:) is present but no key is configured — \
             set [secrets].key_file or E6IRC_SECRET_KEY"
                .into(),
        )
    })?;
    key.open(value)
        .map_err(|e| ConfigError::Invalid(format!("cannot decrypt secret: {e}")))
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
        let mut config: Self = toml::from_str(&text).map_err(ConfigError::Parse)?;
        config.validate()?;
        config.resolve_secrets()?;
        Ok(config)
    }

    /// Resolve the master key from `[secrets].key_file`, else from the
    /// `E6IRC_SECRET_KEY` env var, else none. The order is fixed and the
    /// file — when configured — is authoritative.
    pub fn secret_key(&self) -> Result<Option<crate::secret::SecretKey>, ConfigError> {
        use crate::secret::SecretKey;
        if let Some(s) = &self.secrets {
            let raw = std::fs::read_to_string(&s.key_file).map_err(|e| {
                ConfigError::Invalid(format!(
                    "cannot read secrets key_file {}: {e}",
                    s.key_file.display()
                ))
            })?;
            return SecretKey::from_base64(&raw)
                .map(Some)
                .map_err(|e| ConfigError::Invalid(format!("secrets key_file: {e}")));
        }
        match std::env::var("E6IRC_SECRET_KEY") {
            Ok(v) => SecretKey::from_base64(&v)
                .map(Some)
                .map_err(|e| ConfigError::Invalid(format!("E6IRC_SECRET_KEY: {e}"))),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(ConfigError::Invalid(
                "E6IRC_SECRET_KEY is not valid UTF-8".into(),
            )),
        }
    }

    /// Decrypt every sealed (`enc:v1:`) secret field in place. Plaintext
    /// values pass through unchanged; a sealed value with no key, or one
    /// that fails to decrypt, is a hard startup error.
    fn resolve_secrets(&mut self) -> Result<(), ConfigError> {
        let key = self.secret_key()?;
        for net in &mut self.networks {
            if let Some(pw) = net.sasl_password.take() {
                net.sasl_password = Some(open_secret(&pw, key.as_ref())?);
            }
        }
        for oper in &mut self.opers {
            oper.password = open_secret(&oper.password, key.as_ref())?;
        }
        for provider in &mut self.oidc_providers {
            provider.client_secret = open_secret(&provider.client_secret, key.as_ref())?;
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.listeners.is_empty() {
            return Err(ConfigError::Invalid(
                "at least one [[listeners]] required".into(),
            ));
        }
        if self.server_name.is_empty() || self.server_name.contains(' ') {
            return Err(ConfigError::Invalid(
                "server_name must be a hostname".into(),
            ));
        }
        // network_name becomes the ISUPPORT `NETWORK=` token, a space-delimited
        // 005 middle param — a space (or control char) would split it into two
        // malformed tokens. Reject at load rather than emit a broken numeric.
        if self.network_name.is_empty()
            || self
                .network_name
                .contains(|c: char| c == ' ' || c.is_control())
        {
            return Err(ConfigError::Invalid(
                "network_name must be a single token (no spaces or control characters)".into(),
            ));
        }
        if self.nicklen == 0 || self.sendq == 0 || self.core_queue == 0 {
            return Err(ConfigError::Invalid("limits must be nonzero".into()));
        }
        if self.max_hot_channels == 0 {
            return Err(ConfigError::Invalid(
                "max_hot_channels must be nonzero (0 retains no channel history)".into(),
            ));
        }
        if self.limits.command_burst == Some(0) {
            return Err(ConfigError::Invalid(
                "limits.command_burst must be nonzero when set (0 flood-kills every command)"
                    .into(),
            ));
        }
        if self.limits.auth_rate_burst == Some(0) {
            return Err(ConfigError::Invalid(
                "limits.auth_rate_burst must be nonzero when set".into(),
            ));
        }
        for cidr in &self.limits.trusted_proxies {
            if cidr.parse::<ipnet::IpNet>().is_err() {
                return Err(ConfigError::Invalid(format!(
                    "limits.trusted_proxies: invalid CIDR '{cidr}'"
                )));
            }
        }
        if !self.oidc_providers.is_empty() {
            if self.database.is_none() {
                return Err(ConfigError::Invalid(
                    "[[oidc]] requires [database] for account storage".into(),
                ));
            }
            match &self.http {
                Some(h)
                    if h.public_url.as_deref().is_some_and(|value| {
                        openidconnect::url::Url::parse(value).is_ok_and(|url| {
                            matches!(url.scheme(), "http" | "https") && url.has_host()
                        })
                    }) => {}
                _ => {
                    return Err(ConfigError::Invalid(
                        "[[oidc]] requires [http] with an absolute HTTP(S) public_url for redirect URIs".into(),
                    ));
                }
            }
            let mut provider_names = std::collections::HashSet::new();
            for provider in &self.oidc_providers {
                if provider.name.is_empty()
                    || !provider
                        .name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                {
                    return Err(ConfigError::Invalid(
                        "[[oidc]].name must contain only ASCII letters, digits, '-' or '_'".into(),
                    ));
                }
                if !provider_names.insert(provider.name.as_str()) {
                    return Err(ConfigError::Invalid(format!(
                        "duplicate OIDC provider name '{}'",
                        provider.name
                    )));
                }
                if provider.client_id.is_empty() || provider.client_secret.is_empty() {
                    return Err(ConfigError::Invalid(format!(
                        "OIDC provider '{}' requires client_id and client_secret",
                        provider.name
                    )));
                }
                for (field, value) in [
                    ("issuer_url", Some(provider.issuer_url.as_str())),
                    (
                        "end_session_endpoint",
                        provider.end_session_endpoint.as_deref(),
                    ),
                ] {
                    let Some(value) = value else { continue };
                    let valid = openidconnect::url::Url::parse(value).is_ok_and(|url| {
                        matches!(url.scheme(), "http" | "https") && url.has_host()
                    });
                    if !valid {
                        return Err(ConfigError::Invalid(format!(
                            "OIDC provider '{}' has an invalid {field}",
                            provider.name
                        )));
                    }
                }
            }
            if let Some(shauth) = self
                .oidc_providers
                .iter()
                .find(|provider| provider.name == "shauth")
            {
                let revision = self.application_release_revision.as_deref().unwrap_or("");
                let immutable_revision = (12..=64).contains(&revision.len())
                    && revision
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                    || revision.strip_prefix("sha256:").is_some_and(|digest| {
                        digest.len() == 64
                            && digest
                                .bytes()
                                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                    });
                if !immutable_revision {
                    return Err(ConfigError::Invalid(
                        "Shauth requires application_release_revision to be an immutable lowercase hexadecimal revision or sha256 digest".into(),
                    ));
                }
                let Some(end_session) = shauth.end_session_endpoint.as_deref() else {
                    return Err(ConfigError::Invalid(
                        "Shauth requires end_session_endpoint for global logout".into(),
                    ));
                };
                let issuer = openidconnect::url::Url::parse(&shauth.issuer_url)
                    .expect("OIDC issuer was validated above");
                let logout = openidconnect::url::Url::parse(end_session)
                    .expect("OIDC logout endpoint was validated above");
                if issuer.origin() != logout.origin() {
                    return Err(ConfigError::Invalid(
                        "Shauth end_session_endpoint must use the configured issuer origin".into(),
                    ));
                }
            }
        }
        if self.bnc.is_some() {
            // Config [[network]]s are optional now — accounts add their
            // own networks at runtime — but authentication needs accounts.
            if self.database.is_none() {
                return Err(ConfigError::Invalid(
                    "[bnc] requires [database] to authenticate attaching clients".into(),
                ));
            }
        }
        // Network selection by (owner, name) must be unambiguous: no two
        // entries may share an (owner, name), and a name cannot be both
        // shared and owned (an authenticated client resolves one network).
        let mut seen: std::collections::HashSet<(Option<&str>, &str)> =
            std::collections::HashSet::new();
        let mut shared: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut owned: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for n in &self.networks {
            if !seen.insert((n.owner.as_deref(), n.name.as_str())) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate network '{}' for the same owner",
                    n.name
                )));
            }
            match &n.owner {
                Some(_) => owned.insert(n.name.as_str()),
                None => shared.insert(n.name.as_str()),
            };
        }
        if let Some(name) = owned.intersection(&shared).next() {
            return Err(ConfigError::Invalid(format!(
                "network '{name}' is both shared and owned — names must be unambiguous"
            )));
        }
        for n in &self.networks {
            match n.kind {
                NetworkKind::Irc if n.addr.is_empty() => {
                    return Err(ConfigError::Invalid(format!(
                        "network '{}' (kind=irc) requires addr",
                        n.name
                    )));
                }
                NetworkKind::Matrix if n.addr.is_empty() => {
                    return Err(ConfigError::Invalid(format!(
                        "network '{}' (kind=matrix) requires addr (homeserver URL)",
                        n.name
                    )));
                }
                NetworkKind::Matrix if n.sasl_password.is_none() => {
                    return Err(ConfigError::Invalid(format!(
                        "network '{}' (kind=matrix) requires sasl_password (login password)",
                        n.name
                    )));
                }
                NetworkKind::Discord if n.sasl_password.is_none() => {
                    return Err(ConfigError::Invalid(format!(
                        "network '{}' (kind=discord) requires sasl_password (bot token)",
                        n.name
                    )));
                }
                NetworkKind::Slack if n.sasl_account.is_none() || n.sasl_password.is_none() => {
                    return Err(ConfigError::Invalid(format!(
                        "network '{}' (kind=slack) requires sasl_account (bot token) and \
                         sasl_password (app-level token)",
                        n.name
                    )));
                }
                _ => {}
            }
        }
        // OPER blocks: an empty name or password is a dangerous silent default
        // (an empty password would let `OPER <name> ""` succeed), and a duplicate
        // name is ambiguous (first-match wins with no warning). Reject loudly,
        // like every other subsystem's config.
        let mut oper_names: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for oper in &self.opers {
            if oper.name.is_empty() || oper.password.is_empty() {
                return Err(ConfigError::Invalid(
                    "[[oper]] requires a non-empty name and password".into(),
                ));
            }
            if !oper_names.insert(oper.name.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate [[oper]] name '{}'",
                    oper.name
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let c: Config = toml::from_str(
            r#"
            server_name = "irc.x.example"
            network_name = "XNet"
            [[listeners]]
            addr = "0.0.0.0:6667"
            [[listeners]]
            addr = "0.0.0.0:6697"
            [listeners.tls]
            cert_path = "/etc/tls/cert.pem"
            key_path = "/etc/tls/key.pem"
            "#,
        )
        .expect("parse");
        c.validate().expect("valid");
        assert_eq!(c.nicklen, 16);
        assert!(c.listeners[1].tls.is_some());
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = toml::from_str::<Config>(
            r#"
            server_name = "irc.x.example"
            network_name = "XNet"
            listners = []
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("listners"), "{err}");
    }

    #[test]
    fn no_listeners_is_invalid() {
        let c: Config = toml::from_str(
            r#"
            server_name = "irc.x.example"
            network_name = "XNet"
            "#,
        )
        .expect("parse");
        assert!(c.validate().is_err());
    }

    #[test]
    fn oper_with_empty_password_or_duplicate_name_is_rejected() {
        let base = r#"
            server_name = "irc.x.example"
            network_name = "XNet"
            [[listeners]]
            addr = "0.0.0.0:6667"
        "#;
        // Empty password is a dangerous silent default.
        let c: Config = toml::from_str(&format!(
            "{base}\n[[oper]]\nname = \"admin\"\npassword = \"\"\n"
        ))
        .expect("parse");
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("non-empty name and password"), "{err}");
        // Duplicate oper name is ambiguous.
        let c: Config = toml::from_str(&format!(
            "{base}\n[[oper]]\nname = \"admin\"\npassword = \"a\"\n\
             [[oper]]\nname = \"admin\"\npassword = \"b\"\n"
        ))
        .expect("parse");
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("duplicate [[oper]] name"), "{err}");
        // A well-formed, unique oper is accepted.
        let c: Config = toml::from_str(&format!(
            "{base}\n[[oper]]\nname = \"admin\"\npassword = \"s3cret\"\n"
        ))
        .expect("parse");
        c.validate().expect("valid oper accepted");
    }

    #[test]
    fn network_name_with_space_is_rejected() {
        // A space would split the ISUPPORT `NETWORK=` token into two.
        let c: Config = toml::from_str(
            r#"
            server_name = "irc.x.example"
            network_name = "Cool Net"
            [[listeners]]
            addr = "127.0.0.1:0"
            "#,
        )
        .expect("parse");
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("network_name"), "{err}");
    }

    #[test]
    fn plaintext_secret_passes_through() {
        assert_eq!(open_secret("hunter2", None).unwrap(), "hunter2");
        let key = crate::secret::SecretKey::generate();
        assert_eq!(open_secret("hunter2", Some(&key)).unwrap(), "hunter2");
    }

    #[test]
    fn sealed_secret_decrypts_with_key() {
        let key = crate::secret::SecretKey::generate();
        let sealed = key.seal("s3cr3t");
        assert_eq!(open_secret(&sealed, Some(&key)).unwrap(), "s3cr3t");
    }

    #[test]
    fn sealed_secret_without_key_is_rejected() {
        let sealed = crate::secret::SecretKey::generate().seal("s3cr3t");
        let err = open_secret(&sealed, None).unwrap_err().to_string();
        assert!(err.contains("no key is configured"), "{err}");
    }

    #[test]
    fn sealed_secret_with_wrong_key_is_rejected() {
        let sealed = crate::secret::SecretKey::generate().seal("s3cr3t");
        let other = crate::secret::SecretKey::generate();
        assert!(open_secret(&sealed, Some(&other)).is_err());
    }

    #[test]
    fn resolve_decrypts_network_sasl_password_via_key_file() {
        let key = crate::secret::SecretKey::generate();
        let sealed = key.seal("upstreampass");
        let dir = std::env::temp_dir();
        let path = dir.join(format!("e6irc-key-{}.b64", std::process::id()));
        std::fs::write(&path, key.to_base64()).unwrap();

        let mut cfg = Config {
            networks: vec![NetworkEntry {
                kind: Default::default(),
                name: "libera".into(),
                owner: None,
                addr: "irc.libera.chat:6697".into(),
                tls: true,
                nick: "e6bnc".into(),
                realname: None,
                autojoin: Vec::new(),
                buffer_cap: 1000,
                sasl_account: Some("e6bnc".into()),
                sasl_password: Some(sealed),
            }],
            secrets: Some(SecretsConfig {
                key_file: path.clone(),
            }),
            ..Config::default()
        };
        cfg.resolve_secrets().expect("resolve");
        std::fs::remove_file(&path).ok();
        assert_eq!(
            cfg.networks[0].sasl_password.as_deref(),
            Some("upstreampass")
        );
    }

    fn net(name: &str, owner: Option<&str>) -> NetworkEntry {
        NetworkEntry {
            kind: Default::default(),
            name: name.into(),
            owner: owner.map(str::to_string),
            addr: "irc.example:6667".into(),
            tls: false,
            nick: "n".into(),
            realname: None,
            autojoin: Vec::new(),
            buffer_cap: 1000,
            sasl_account: None,
            sasl_password: None,
        }
    }

    #[test]
    fn same_network_name_across_distinct_owners_is_ok() {
        let cfg = Config {
            listeners: vec![ListenerConfig {
                addr: "127.0.0.1:0".parse().unwrap(),
                tls: None,
            }],
            networks: vec![net("libera", Some("alice")), net("libera", Some("bob"))],
            ..Config::default()
        };
        cfg.validate().expect("distinct owners may reuse a name");
    }

    #[test]
    fn duplicate_owner_and_name_is_rejected() {
        let cfg = Config {
            listeners: vec![ListenerConfig {
                addr: "127.0.0.1:0".parse().unwrap(),
                tls: None,
            }],
            networks: vec![net("libera", Some("alice")), net("libera", Some("alice"))],
            ..Config::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn name_both_shared_and_owned_is_rejected() {
        let cfg = Config {
            listeners: vec![ListenerConfig {
                addr: "127.0.0.1:0".parse().unwrap(),
                tls: None,
            }],
            networks: vec![net("libera", None), net("libera", Some("alice"))],
            ..Config::default()
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("both shared and owned"), "{err}");
    }

    #[test]
    fn zero_command_burst_is_rejected() {
        let cfg = Config {
            listeners: vec![ListenerConfig {
                addr: "127.0.0.1:0".parse().unwrap(),
                tls: None,
            }],
            limits: LimitsConfig {
                command_burst: Some(0),
                ..LimitsConfig::default()
            },
            ..Config::default()
        };
        assert!(
            cfg.validate().is_err(),
            "command_burst=0 flood-kills every command and must be rejected"
        );
    }

    #[test]
    fn zero_max_hot_channels_is_rejected() {
        let cfg = Config {
            listeners: vec![ListenerConfig {
                addr: "127.0.0.1:0".parse().unwrap(),
                tls: None,
            }],
            max_hot_channels: 0,
            ..Config::default()
        };
        assert!(
            cfg.validate().is_err(),
            "max_hot_channels=0 retains no history and must be rejected"
        );
    }

    fn oidc_config(name: &str, issuer: &str, end_session: Option<&str>) -> Config {
        Config {
            listeners: vec![ListenerConfig {
                addr: "127.0.0.1:0".parse().unwrap(),
                tls: None,
            }],
            http: Some(HttpConfig {
                addr: "127.0.0.1:0".parse().unwrap(),
                public_url: Some("https://chat.example".into()),
                secure_cookies: true,
                admin_accounts: vec![],
            }),
            database: Some(DatabaseConfig {
                url: "postgres://db.example/e6irc".into(),
            }),
            oidc_providers: vec![OidcProviderConfig {
                name: name.into(),
                issuer_url: issuer.into(),
                client_id: "e6irc".into(),
                client_secret: "secret".into(),
                scopes: vec![],
                end_session_endpoint: end_session.map(str::to_string),
                token_endpoint_auth_method: Default::default(),
            }],
            application_release_revision: Some("0123456789ab".into()),
            ..Config::default()
        }
    }

    #[test]
    fn oidc_coordinates_are_validated_at_startup() {
        oidc_config(
            "shauth",
            "https://auth.example",
            Some("https://auth.example/oauth2/sessions/logout"),
        )
        .validate()
        .expect("valid coordinates");

        for (name, issuer, end_session) in [
            (
                "bad/name",
                "https://auth.example",
                Some("https://auth.example/logout"),
            ),
            ("shauth", "not a URL", Some("https://auth.example/logout")),
            (
                "shauth",
                "https://auth.example",
                Some("javascript:alert(1)"),
            ),
        ] {
            assert!(
                oidc_config(name, issuer, end_session).validate().is_err(),
                "accepted invalid OIDC coordinates: {name} {issuer} {end_session:?}"
            );
        }

        for revision in [None, Some("main"), Some("ABCDEF012345"), Some("sha256:bad")] {
            let mut config = oidc_config(
                "shauth",
                "https://auth.example",
                Some("https://auth.example/logout"),
            );
            config.application_release_revision = revision.map(str::to_string);
            assert!(
                config.validate().is_err(),
                "accepted mutable Shauth release revision {revision:?}"
            );
        }

        let mut foreign_logout = oidc_config(
            "shauth",
            "https://auth.example",
            Some("https://attacker.example/logout"),
        );
        foreign_logout.application_release_revision = Some("0123456789ab".into());
        assert!(
            foreign_logout.validate().is_err(),
            "accepted a Shauth logout endpoint on another origin"
        );
    }

    #[test]
    fn resolve_decrypts_oper_and_oidc_secrets() {
        let key = crate::secret::SecretKey::generate();
        let path = std::env::temp_dir().join(format!("e6irc-key2-{}.b64", std::process::id()));
        std::fs::write(&path, key.to_base64()).unwrap();

        let mut cfg = Config {
            opers: vec![OperConfig {
                name: "root".into(),
                password: key.seal("operpass"),
            }],
            oidc_providers: vec![OidcProviderConfig {
                name: "corp".into(),
                issuer_url: "https://issuer.example".into(),
                client_id: "cid".into(),
                client_secret: key.seal("oidcsecret"),
                scopes: vec![],
                end_session_endpoint: None,
                token_endpoint_auth_method: Default::default(),
            }],
            secrets: Some(SecretsConfig {
                key_file: path.clone(),
            }),
            ..Config::default()
        };
        cfg.resolve_secrets().expect("resolve");
        std::fs::remove_file(&path).ok();
        assert_eq!(cfg.opers[0].password, "operpass");
        assert_eq!(cfg.oidc_providers[0].client_secret, "oidcsecret");
    }
}
