//! Server configuration. TOML on disk; unknown keys are a startup
//! error — configuration mistakes must never be silently ignored.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

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
fn default_observability_enabled() -> bool {
    true
}
fn default_observability_sample_interval() -> u64 {
    15
}
fn default_observability_retention() -> u64 {
    168
}
fn default_history_retention_days() -> u64 {
    30
}
fn default_audit_retention_days() -> u64 {
    365
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfig {
    #[serde(default = "default_observability_enabled")]
    pub enabled: bool,
    #[serde(default = "default_observability_sample_interval")]
    pub sample_interval_seconds: u64,
    #[serde(default = "default_observability_retention")]
    pub retention_hours: u64,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            enabled: default_observability_enabled(),
            sample_interval_seconds: default_observability_sample_interval(),
            retention_hours: default_observability_retention(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// Durable IRC message-history lifetime.
    #[serde(default = "default_history_retention_days")]
    pub history_retention_days: u64,
    /// Privileged audit-event lifetime.
    #[serde(default = "default_audit_retention_days")]
    pub audit_retention_days: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            history_retention_days: default_history_retention_days(),
            audit_retention_days: default_audit_retention_days(),
        }
    }
}

/// `draft/account-registration` policy, advertised as the capability's value
/// so a client knows the rules before it tries.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
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
    /// One-time browser bootstrap for the first administrator. It is usable
    /// only while the account table is empty; normal login takes over after
    /// the first successful transaction.
    #[serde(default)]
    pub bootstrap: Option<BootstrapConfig>,
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
    /// Source of the key that decrypts sealed (`enc:v1:`/`enc:v2:`) secrets. When
    /// absent, the `E6IRC_SECRET_KEY` env var is consulted instead.
    #[serde(default)]
    pub secrets: Option<SecretsConfig>,
    /// Abuse limits. All off by default.
    #[serde(default)]
    pub limits: LimitsConfig,
    /// In-process operational metrics and bounded historical samples.
    #[serde(default)]
    pub observability: ObservabilityConfig,
    /// Database retention and expired-resource cleanup policy.
    #[serde(default)]
    pub storage: StorageConfig,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
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
    /// Authenticated REST requests per account per minute. `None` uses the
    /// built-in production default.
    #[serde(default)]
    pub api_rate_burst: Option<usize>,
    /// Administrator REST requests per administrator per minute. `None` uses
    /// the smaller built-in production default.
    #[serde(default)]
    pub administrator_api_rate_burst: Option<usize>,
    /// Token-bucket size for account creation (REGISTER / NickServ REGISTER),
    /// per client IP; the bucket refills to full over one hour. Bounds bulk
    /// account minting from one address. `None` disables the throttle.
    #[serde(default)]
    pub registration_burst: Option<usize>,
}

/// Operational settings owned by the database-backed control plane.
///
/// Values needed to reach the control plane itself deliberately do not appear
/// here: the database URL, master-key source, HTTP bind address, and immutable
/// release revision remain bootstrap configuration. Every field in this type is
/// rendered and editable by the admin console, stored as one revision, and
/// applied on the next process start; the BNC listener is additionally applied
/// live by its runtime controller.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedConfig {
    pub server_name: String,
    pub network_name: String,
    pub description: String,
    pub motd: Vec<String>,
    pub nicklen: usize,
    pub sendq: usize,
    pub core_queue: usize,
    pub max_hot_channels: usize,
    pub listeners: Vec<ListenerConfig>,
    pub registration: RegistrationConfig,
    pub limits: LimitsConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    pub bnc_addr: Option<SocketAddr>,
    pub public_url: Option<String>,
    pub secure_cookies: bool,
    pub admin_accounts: Vec<String>,
    pub oidc_providers: Vec<OidcProviderConfig>,
    pub opers: Vec<OperConfig>,
    pub networks: Vec<NetworkEntry>,
    /// Legacy deployments may have plaintext credential-bearing values only in
    /// bootstrap config and no master key yet. Their public metadata is shown in
    /// the console, but this flag prevents redacted placeholders from replacing
    /// the working bootstrap credentials. Supplying a key on a later start
    /// atomically imports sealed values and clears the flag.
    pub credentials_from_bootstrap: bool,
}

impl ManagedConfig {
    pub fn from_config(
        config: &Config,
        key: Option<&crate::secret::SecretKeyring>,
    ) -> Result<Self, ConfigError> {
        let network_has_secret = config.networks.iter().any(|network| {
            network.sasl_password.is_some()
                || (network.kind.account_is_secret() && network.sasl_account.is_some())
        });
        let credentials_from_bootstrap = key.is_none()
            && (!config.oidc_providers.is_empty()
                || !config.opers.is_empty()
                || network_has_secret);
        let seal = |value: &str| -> String {
            key.map_or_else(String::new, |key| {
                key.seal(value, crate::secret::CONFIG_CONTEXT)
            })
        };
        let mut oidc_providers = config.oidc_providers.clone();
        for provider in &mut oidc_providers {
            provider.client_secret = seal(&provider.client_secret);
        }
        let mut opers = config.opers.clone();
        for oper in &mut opers {
            oper.password = seal(&oper.password);
        }
        let mut networks = config.networks.clone();
        for network in &mut networks {
            if let Some(password) = &network.sasl_password {
                network.sasl_password = Some(seal(password));
            }
            if network.kind.account_is_secret()
                && let Some(account) = &network.sasl_account
            {
                network.sasl_account = Some(seal(account));
            }
        }
        Ok(Self {
            server_name: config.server_name.clone(),
            network_name: config.network_name.clone(),
            description: config.description.clone(),
            motd: config.motd.clone(),
            nicklen: config.nicklen,
            sendq: config.sendq,
            core_queue: config.core_queue,
            max_hot_channels: config.max_hot_channels,
            listeners: config.listeners.clone(),
            registration: config.registration.clone(),
            limits: config.limits.clone(),
            observability: config.observability.clone(),
            storage: config.storage.clone(),
            bnc_addr: config.bnc.as_ref().map(|bnc| bnc.addr),
            public_url: config
                .http
                .as_ref()
                .and_then(|http| http.public_url.clone()),
            secure_cookies: config.http.as_ref().is_none_or(|http| http.secure_cookies),
            admin_accounts: config
                .http
                .as_ref()
                .map(|http| http.admin_accounts.clone())
                .unwrap_or_default(),
            oidc_providers,
            opers,
            networks,
            credentials_from_bootstrap,
        })
    }

    pub fn apply_to(&self, config: &mut Config) {
        config.server_name.clone_from(&self.server_name);
        config.network_name.clone_from(&self.network_name);
        config.description.clone_from(&self.description);
        config.motd.clone_from(&self.motd);
        config.nicklen = self.nicklen;
        config.sendq = self.sendq;
        config.core_queue = self.core_queue;
        config.max_hot_channels = self.max_hot_channels;
        config.listeners.clone_from(&self.listeners);
        config.registration = self.registration.clone();
        config.limits = self.limits.clone();
        config.observability = self.observability.clone();
        config.storage = self.storage.clone();
        config.bnc = self.bnc_addr.map(|addr| BncConfig { addr });
        if let Some(http) = &mut config.http {
            http.public_url.clone_from(&self.public_url);
            http.secure_cookies = self.secure_cookies;
            http.admin_accounts.clone_from(&self.admin_accounts);
        }
        if !self.credentials_from_bootstrap {
            config.oidc_providers.clone_from(&self.oidc_providers);
            config.opers.clone_from(&self.opers);
            config.networks.clone_from(&self.networks);
        }
    }

    /// Validate through the startup parser's one configuration choke point.
    /// Bootstrap prerequisites are supplied with inert, valid values solely so
    /// this operational subset can be checked without reimplementing its
    /// invariants in an HTTP handler.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut config = Config {
            database: Some(DatabaseConfig {
                url: "postgresql://control-plane-validation".into(),
            }),
            http: Some(HttpConfig {
                addr: "127.0.0.1:0".parse().expect("literal socket address"),
                public_url: None,
                secure_cookies: false,
                admin_accounts: Vec::new(),
            }),
            application_release_revision: Some("0123456789ab".into()),
            ..Config::default()
        };
        self.apply_to(&mut config);
        config.validate()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretsConfig {
    /// Path to a file holding the base64-encoded 32-byte primary key. New
    /// ciphertext is always sealed with this key.
    pub key_file: PathBuf,
    /// Read-only fallback keys retained during a rotation. Remove them after
    /// every stored secret has been re-sealed with the primary key.
    #[serde(default)]
    pub previous_key_files: Vec<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
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
    /// IRC `host:port` or a bridge's HTTP(S) provider base. Empty selects the
    /// provider default only for bridge kinds that define one. Ignored for
    /// `local`.
    #[serde(default)]
    pub addr: String,
    /// IRC transport security. Bridge entries require `true` as the canonical
    /// marker that the transport is HTTP(S), whose URL scheme controls security.
    #[serde(default)]
    pub tls: bool,
    pub nick: String,
    #[serde(default)]
    pub realname: Option<String>,
    #[serde(default)]
    pub autojoin: Vec<String>,
    #[serde(default = "default_bnc_buffer")]
    pub buffer_cap: usize,
    /// IRC SASL account, or Slack bot token. Matrix and Discord reject it.
    #[serde(default)]
    pub sasl_account: Option<String>,
    /// IRC SASL password, Matrix login password, Discord bot token, or Slack
    /// app token.
    #[serde(default)]
    pub sasl_password: Option<String>,
}

fn default_bnc_buffer() -> usize {
    1000
}

/// Which driver backs a BNC network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
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

impl NetworkKind {
    /// Stable lowercase token for the DB `kind` column and the wire (matches the
    /// serde `rename_all = "lowercase"` used when parsing config).
    pub fn as_db_str(self) -> &'static str {
        match self {
            NetworkKind::Irc => "irc",
            NetworkKind::Local => "local",
            NetworkKind::Matrix => "matrix",
            NetworkKind::Discord => "discord",
            NetworkKind::Slack => "slack",
        }
    }

    /// Parse a DB/wire kind token; `None` for anything unrecognized (callers
    /// surface the bad value rather than silently defaulting).
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "irc" => Some(NetworkKind::Irc),
            "local" => Some(NetworkKind::Local),
            "matrix" => Some(NetworkKind::Matrix),
            "discord" => Some(NetworkKind::Discord),
            "slack" => Some(NetworkKind::Slack),
            _ => None,
        }
    }

    /// Whether this is a chat-platform bridge (Matrix/Discord/Slack) rather than
    /// an IRC upstream or the in-process local network.
    pub fn is_bridge(self) -> bool {
        matches!(
            self,
            NetworkKind::Matrix | NetworkKind::Discord | NetworkKind::Slack
        )
    }

    /// Whether this kind carries its secret in `sasl_account` (Slack's bot
    /// token), which the DB path must therefore seal — unlike an IRC account
    /// name, which is public.
    pub fn account_is_secret(self) -> bool {
        matches!(self, NetworkKind::Slack)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BncConfig {
    pub addr: SocketAddr,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapConfig {
    /// High-entropy one-time secret entered in the first-run browser form.
    /// The environment entrypoint writes it only to its mode-0600 bootstrap
    /// file, and the HTTP state retains only its SHA-256 digest.
    pub token: String,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
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
    /// When non-empty, only verified email claims in one of these exact
    /// canonical domains may sign in or link through this provider.
    #[serde(default)]
    pub allowed_email_domains: Vec<crate::identity::EmailDomain>,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
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
            bootstrap: None,
            oidc_providers: Vec::new(),
            application_release_revision: None,
            opers: Vec::new(),
            networks: Vec::new(),
            bnc: None,
            secrets: None,
            limits: LimitsConfig::default(),
            observability: ObservabilityConfig::default(),
            storage: StorageConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    pub addr: SocketAddr,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// Serve IRC-over-WebSocket at the root path on this listener instead of a
    /// raw TCP IRC stream (a bare WS-IRC port with no HTTP UI). A client
    /// connects to `ws://addr/` and reaches the same core as a raw listener.
    #[serde(default)]
    pub websocket: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
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
fn open_secret(
    value: &str,
    key: Option<&crate::secret::SecretKeyring>,
) -> Result<String, ConfigError> {
    if !crate::secret::is_sealed(value) {
        return Ok(value.to_string());
    }
    let key = key.ok_or_else(|| {
        ConfigError::Invalid(
            "an encrypted secret (enc:v1:/enc:v2:) is present but no key is configured — \
             set [secrets].key_file or E6IRC_SECRET_KEY"
                .into(),
        )
    })?;
    // Config-file secrets share one context tag, distinct from any per-account
    // BNC secret's, so the two classes can't be substituted.
    key.open(value, crate::secret::CONFIG_CONTEXT)
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

    /// Resolve the primary and rotation fallback keys. `[secrets]` is
    /// authoritative when present; otherwise `E6IRC_SECRET_KEY` supplies the
    /// primary and comma-separated `E6IRC_PREVIOUS_SECRET_KEYS` supplies
    /// read-only fallbacks.
    pub fn secret_keyring(&self) -> Result<Option<crate::secret::SecretKeyring>, ConfigError> {
        use crate::secret::{SecretKey, SecretKeyring};
        if let Some(s) = &self.secrets {
            let raw = std::fs::read_to_string(&s.key_file).map_err(|e| {
                ConfigError::Invalid(format!(
                    "cannot read secrets key_file {}: {e}",
                    s.key_file.display()
                ))
            })?;
            let primary = SecretKey::from_base64(&raw)
                .map_err(|e| ConfigError::Invalid(format!("secrets key_file: {e}")))?;
            let mut previous = Vec::with_capacity(s.previous_key_files.len());
            for path in &s.previous_key_files {
                let raw = std::fs::read_to_string(path).map_err(|e| {
                    ConfigError::Invalid(format!(
                        "cannot read secrets previous_key_file {}: {e}",
                        path.display()
                    ))
                })?;
                previous.push(SecretKey::from_base64(&raw).map_err(|e| {
                    ConfigError::Invalid(format!(
                        "secrets previous_key_file {}: {e}",
                        path.display()
                    ))
                })?);
            }
            return SecretKeyring::new(primary, previous)
                .map(Some)
                .map_err(|e| ConfigError::Invalid(format!("secrets keyring: {e}")));
        }
        let primary = match std::env::var("E6IRC_SECRET_KEY") {
            Ok(value) => Some(
                SecretKey::from_base64(&value)
                    .map_err(|e| ConfigError::Invalid(format!("E6IRC_SECRET_KEY: {e}")))?,
            ),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::Invalid(
                    "E6IRC_SECRET_KEY is not valid UTF-8".into(),
                ));
            }
        };
        let previous = match std::env::var("E6IRC_PREVIOUS_SECRET_KEYS") {
            Ok(value) => {
                if value.split(',').any(|part| part.trim().is_empty()) {
                    return Err(ConfigError::Invalid(
                        "E6IRC_PREVIOUS_SECRET_KEYS contains an empty key".into(),
                    ));
                }
                value
                    .split(',')
                    .map(|part| {
                        SecretKey::from_base64(part).map_err(|e| {
                            ConfigError::Invalid(format!("E6IRC_PREVIOUS_SECRET_KEYS: {e}"))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?
            }
            Err(std::env::VarError::NotPresent) => Vec::new(),
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::Invalid(
                    "E6IRC_PREVIOUS_SECRET_KEYS is not valid UTF-8".into(),
                ));
            }
        };
        match primary {
            Some(primary) => SecretKeyring::new(primary, previous)
                .map(Some)
                .map_err(|e| ConfigError::Invalid(format!("secret keyring: {e}"))),
            None if previous.is_empty() => Ok(None),
            None => Err(ConfigError::Invalid(
                "E6IRC_PREVIOUS_SECRET_KEYS is set but E6IRC_SECRET_KEY is unset".into(),
            )),
        }
    }

    /// Decrypt every sealed (`enc:v1:`/`enc:v2:`) secret field in place. Plaintext
    /// values pass through unchanged; a sealed value with no key, or one
    /// that fails to decrypt, is a hard startup error.
    fn resolve_secrets(&mut self) -> Result<(), ConfigError> {
        let key = self.secret_keyring()?;
        self.resolve_secrets_with_key(key.as_ref())
    }

    pub(crate) fn resolve_secrets_with_key(
        &mut self,
        key: Option<&crate::secret::SecretKeyring>,
    ) -> Result<(), ConfigError> {
        for net in &mut self.networks {
            if let Some(pw) = net.sasl_password.take() {
                net.sasl_password = Some(open_secret(&pw, key)?);
            }
            // `sasl_account` carries the Slack driver's `xoxb-` bot token (a
            // documented secret), so it must be unsealed too — otherwise a
            // sealed value is handed to Slack verbatim as the token and auth
            // fails with no hint the seal was ignored. A plaintext IRC account
            // name passes through `open_secret` unchanged.
            if let Some(account) = net.sasl_account.take() {
                net.sasl_account = Some(open_secret(&account, key)?);
            }
        }
        for oper in &mut self.opers {
            oper.password = open_secret(&oper.password, key)?;
        }
        for provider in &mut self.oidc_providers {
            provider.client_secret = open_secret(&provider.client_secret, key)?;
        }
        if let Some(bootstrap) = &mut self.bootstrap {
            bootstrap.token = open_secret(&bootstrap.token, key)?;
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.listeners.is_empty() {
            return Err(ConfigError::Invalid(
                "at least one [[listeners]] required".into(),
            ));
        }
        // A websocket listener is served by plain axum (like the [http]
        // listener) with TLS terminated by a front proxy; it cannot itself
        // present a certificate. Reject the combination rather than silently
        // ignore the tls section.
        if self
            .listeners
            .iter()
            .any(|l| l.websocket && l.tls.is_some())
        {
            return Err(ConfigError::Invalid(
                "a [[listeners]] with websocket = true cannot also set tls (terminate TLS at a proxy)".into(),
            ));
        }
        if let Some(bootstrap) = &self.bootstrap {
            if self.database.is_none() || self.http.is_none() {
                return Err(ConfigError::Invalid(
                    "[bootstrap] requires both [database] and [http]".into(),
                ));
            }
            if !(32..=512).contains(&bootstrap.token.len())
                || bootstrap.token.chars().any(char::is_control)
            {
                return Err(ConfigError::Invalid(
                    "bootstrap.token must contain 32–512 bytes and no control characters".into(),
                ));
            }
        }
        // server_name is the source prefix (`:<server_name> …`) of every
        // server-originated line, so a space, control byte, or prefix-significant
        // char (`!`/`@`) would forge a malformed or spoofable source. Restrict it
        // to a hostname charset — the contract the field already advertises — so
        // an injected prefix is unrepresentable rather than caught per render
        // site. (`WireLine` only neutralizes CR/LF/NUL, so other control bytes
        // would otherwise ride onto the wire.) The `network_name` guard below
        // rejects control chars for the same reason; server_name is the more
        // sensitive field and must be at least as strict.
        if self.server_name.is_empty()
            || !self
                .server_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            return Err(ConfigError::Invalid(
                "server_name must be a hostname (ASCII letters, digits, '.', '-')".into(),
            ));
        }
        // server_name is in the fixed head of every numeric; an unbounded value
        // inflates every line's overhead and is the largest lever for pushing a
        // reply past the 512-byte wire limit. A hostname fits well within 64.
        if self.server_name.len() > 64 {
            return Err(ConfigError::Invalid(
                "server_name must be at most 64 bytes".into(),
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
        // NETWORK= is a 005 middle; `numeric` would silently clip an over-long
        // value rather than advertise it faithfully. Bound it at load instead.
        if self.network_name.len() > 64 {
            return Err(ConfigError::Invalid(
                "network_name must be at most 64 bytes".into(),
            ));
        }
        if self.nicklen == 0 || self.sendq == 0 || self.core_queue == 0 {
            return Err(ConfigError::Invalid("limits must be nonzero".into()));
        }
        // The advertised NICKLEN rides every relayed line's source prefix, so an
        // unbounded nick can blow past the 512-byte wire limit (the same reason
        // server_name/network_name are capped at 64) and inflates per-nick
        // memory. Bound it like the other identifiers.
        if self.nicklen > 64 {
            return Err(ConfigError::Invalid(
                "nicklen must be at most 64 (it rides every relayed line's prefix)".into(),
            ));
        }
        if self.max_hot_channels == 0 {
            return Err(ConfigError::Invalid(
                "max_hot_channels must be nonzero (0 retains no channel history)".into(),
            ));
        }
        if !(5..=300).contains(&self.observability.sample_interval_seconds) {
            return Err(ConfigError::Invalid(
                "observability.sample_interval_seconds must be between 5 and 300".into(),
            ));
        }
        if !(1..=2160).contains(&self.observability.retention_hours) {
            return Err(ConfigError::Invalid(
                "observability.retention_hours must be between 1 and 2160".into(),
            ));
        }
        if !(1..=3650).contains(&self.storage.history_retention_days) {
            return Err(ConfigError::Invalid(
                "storage.history_retention_days must be between 1 and 3650".into(),
            ));
        }
        if !(1..=3650).contains(&self.storage.audit_retention_days) {
            return Err(ConfigError::Invalid(
                "storage.audit_retention_days must be between 1 and 3650".into(),
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
        if self.limits.api_rate_burst == Some(0) {
            return Err(ConfigError::Invalid(
                "limits.api_rate_burst must be nonzero when set".into(),
            ));
        }
        if self.limits.administrator_api_rate_burst == Some(0) {
            return Err(ConfigError::Invalid(
                "limits.administrator_api_rate_burst must be nonzero when set".into(),
            ));
        }
        if self.limits.registration_burst == Some(0) {
            return Err(ConfigError::Invalid(
                "limits.registration_burst must be nonzero when set (0 refuses every account \
                 creation)"
                    .into(),
            ));
        }
        // `try_acquire` refuses a connection once `count >= max`, so a max of 0
        // refuses *every* connection (a fresh IP already has count 0) — the
        // server boots, reports "listening", and silently rejects all traffic.
        // Reject the footgun like its command_burst/auth_rate_burst siblings.
        if self.limits.max_connections_per_ip == Some(0) {
            return Err(ConfigError::Invalid(
                "limits.max_connections_per_ip must be nonzero when set (0 refuses every \
                 connection)"
                    .into(),
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
            let mut provider_issuers = std::collections::HashSet::new();
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
                // Two providers sharing an issuer would collide on the
                // `(issuer, subject)` account key — a subject at one would resolve
                // to the other's account. Reject at load rather than cross-wire
                // accounts at runtime.
                if !provider_issuers.insert(provider.issuer_url.as_str()) {
                    return Err(ConfigError::Invalid(format!(
                        "duplicate OIDC issuer_url '{}' — providers must have distinct issuers",
                        provider.issuer_url
                    )));
                }
                if provider.client_id.is_empty() || provider.client_secret.is_empty() {
                    return Err(ConfigError::Invalid(format!(
                        "OIDC provider '{}' requires client_id and client_secret",
                        provider.name
                    )));
                }
                let mut allowed_domains = std::collections::HashSet::new();
                for domain in &provider.allowed_email_domains {
                    if !allowed_domains.insert(domain.as_str()) {
                        return Err(ConfigError::Invalid(format!(
                            "OIDC provider '{}' repeats allowed email domain '{}'",
                            provider.name,
                            domain.as_str()
                        )));
                    }
                }
                // In production (secure cookies) the issuer must be HTTPS:
                // discovery and JWKS are fetched from it, so plaintext lets an
                // on-path attacker inject signing keys and forge ID tokens. A dev
                // setup (secure_cookies = false) may still use http for a local
                // provider.
                let require_https = self.http.as_ref().is_some_and(|h| h.secure_cookies);
                for (field, value) in [
                    ("issuer_url", Some(provider.issuer_url.as_str())),
                    (
                        "end_session_endpoint",
                        provider.end_session_endpoint.as_deref(),
                    ),
                ] {
                    let Some(value) = value else { continue };
                    let parsed = openidconnect::url::Url::parse(value).ok();
                    let valid = parsed.as_ref().is_some_and(|url| {
                        matches!(url.scheme(), "http" | "https") && url.has_host()
                    });
                    if !valid {
                        return Err(ConfigError::Invalid(format!(
                            "OIDC provider '{}' has an invalid {field}",
                            provider.name
                        )));
                    }
                    if field == "issuer_url"
                        && require_https
                        && parsed.is_some_and(|url| url.scheme() != "https")
                    {
                        return Err(ConfigError::Invalid(format!(
                            "OIDC provider '{}' issuer_url must be https when secure_cookies is set \
                             (plaintext discovery/JWKS is forgeable by an on-path attacker)",
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
        // `[registration]` policy only means anything with an account store; set
        // without a `[database]` it silently does nothing (there are no accounts
        // to create), so reject it loudly like [[oidc]]/[bnc] do — a no-silent
        // no-op.
        if self.registration != RegistrationConfig::default() && self.database.is_none() {
            return Err(ConfigError::Invalid(
                "[registration] requires [database] (there are no accounts without one)".into(),
            ));
        }
        // `admin_accounts` grants the admin REST surface to named accounts —
        // which are resolved against the account store. Without `[database]`
        // every admin request fails per-request and no one can ever be admin, so
        // the grant is silently inert. Reject it loudly, like the guards above.
        if self
            .http
            .as_ref()
            .is_some_and(|h| !h.admin_accounts.is_empty())
            && self.database.is_none()
        {
            return Err(ConfigError::Invalid(
                "http.admin_accounts requires [database] (admin names resolve against the account store)".into(),
            ));
        }
        // `secure_cookies` declares a TLS deployment: the session cookie is
        // `Secure`/`__Host-` and won't ride a plaintext origin, and `public_url`
        // builds the OIDC `redirect_uri`/`post_logout_redirect_uri`. A
        // `secure_cookies = true` with an `http://` public_url is contradictory
        // — it advertises the auth round-trip over plaintext while the cookie it
        // needs can't be sent — and boots silently today. Reject it, symmetric
        // to the OIDC `issuer_url` https-under-secure-cookies guard above.
        if let Some(h) = &self.http
            && h.secure_cookies
            && h.public_url.as_deref().is_some_and(|value| {
                openidconnect::url::Url::parse(value).is_ok_and(|url| url.scheme() != "https")
            })
        {
            return Err(ConfigError::Invalid(
                "http.public_url must be https when secure_cookies is set (a Secure/__Host- \
                 cookie cannot ride a plaintext origin, and the OIDC redirect_uri would be \
                 advertised over http)"
                    .into(),
            ));
        }
        // A configured `public_url` seeds the OIDC redirect_uri *and* the device
        // flow's user-facing verification URL (`http/device.rs`), so an
        // unparseable or non-http(s) value would silently propagate a broken base
        // URL — and the https guard above only fires on a value that *parses*, so
        // outright garbage would slip through when `[[oidc]]` is absent. Validate
        // it as an http/https URL with a host whenever it is set (DESIGN §2).
        if let Some(h) = &self.http
            && let Some(value) = h.public_url.as_deref()
            && !openidconnect::url::Url::parse(value)
                .is_ok_and(|url| matches!(url.scheme(), "http" | "https") && url.has_host())
        {
            return Err(ConfigError::Invalid(
                "http.public_url must be an http(s) URL with a host".into(),
            ));
        }
        // Configured networks need an authenticated management/attach surface.
        // The registry is available with a database even when the raw BNC
        // listener is disabled, because the web client and console use it too.
        // Requiring the listener here made "enable BNC from the console"
        // structurally impossible and caused the active-looking network form to
        // fail with "Bouncer not enabled".
        if !self.networks.is_empty() && self.database.is_none() {
            return Err(ConfigError::Invalid(
                "[[network]] entries require [database] for authenticated access".into(),
            ));
        }
        // Network selection by (owner, name) must be unambiguous: no two
        // entries may share an (owner, name), and a name cannot be both
        // shared and owned (an authenticated client resolves one network).
        let case_mapping = e6irc_proto::casemap::CaseMapping::Rfc1459;
        let mut seen: std::collections::HashSet<(Option<String>, String)> =
            std::collections::HashSet::new();
        let mut shared: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut owned: std::collections::HashSet<String> = std::collections::HashSet::new();
        for n in &self.networks {
            let owner = n.owner.as_deref().map(|value| case_mapping.casefold(value));
            let name = case_mapping.casefold(&n.name);
            if !seen.insert((owner.clone(), name.clone())) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate network '{}' for the same owner",
                    n.name
                )));
            }
            match owner {
                Some(_) => owned.insert(name),
                None => shared.insert(name),
            };
        }
        if let Some(name) = owned.intersection(&shared).next() {
            return Err(ConfigError::Invalid(format!(
                "network '{name}' is both shared and owned — names must be unambiguous"
            )));
        }
        for n in &self.networks {
            // A zero backlog cap is silently coerced to 1 by `Buffer::push`
            // (`self.cap.max(1)`) — a silent fallback (DESIGN §2) an operator
            // would not expect. Reject it loudly like the sibling zero-value
            // guards (`max_hot_channels`, `command_burst`).
            if n.buffer_cap == 0 {
                return Err(ConfigError::Invalid(format!(
                    "network '{}' buffer_cap must be nonzero",
                    n.name
                )));
            }
            if let Some(account) = n.sasl_account.as_deref() {
                crate::bouncer::validate_network_credential(account, 255).map_err(|error| {
                    ConfigError::Invalid(format!(
                        "network '{}' has invalid sasl_account: {error}",
                        n.name
                    ))
                })?;
            }
            if let Some(password) = n.sasl_password.as_deref() {
                crate::bouncer::validate_network_credential(password, 512).map_err(|error| {
                    ConfigError::Invalid(format!(
                        "network '{}' has invalid sasl_password: {error}",
                        n.name
                    ))
                })?;
            }
            if n.kind == NetworkKind::Irc && n.sasl_account.is_some() != n.sasl_password.is_some() {
                return Err(ConfigError::Invalid(format!(
                    "network '{}' (kind=irc) requires both sasl_account and sasl_password, or neither",
                    n.name
                )));
            }
            if n.kind.is_bridge() {
                if !n.tls {
                    return Err(ConfigError::Invalid(format!(
                        "network '{}' (kind={}) requires tls=true as its HTTP transport marker",
                        n.name,
                        n.kind.as_db_str()
                    )));
                }
                if n.realname.is_some() {
                    return Err(ConfigError::Invalid(format!(
                        "network '{}' (kind={}) does not accept realname",
                        n.name,
                        n.kind.as_db_str()
                    )));
                }
                if matches!(n.kind, NetworkKind::Discord | NetworkKind::Slack) && !n.nick.is_empty()
                {
                    return Err(ConfigError::Invalid(format!(
                        "network '{}' (kind={}) does not accept nick",
                        n.name,
                        n.kind.as_db_str()
                    )));
                }
                if matches!(n.kind, NetworkKind::Matrix | NetworkKind::Discord)
                    && n.sasl_account.is_some()
                {
                    return Err(ConfigError::Invalid(format!(
                        "network '{}' (kind={}) does not accept sasl_account",
                        n.name,
                        n.kind.as_db_str()
                    )));
                }
                crate::bouncer::validate_bridge_base(n.kind, &n.addr).map_err(|error| {
                    ConfigError::Invalid(format!("network '{}': {error}", n.name))
                })?;
            }
            match n.kind {
                NetworkKind::Irc if n.addr.is_empty() => {
                    return Err(ConfigError::Invalid(format!(
                        "network '{}' (kind=irc) requires addr",
                        n.name
                    )));
                }
                NetworkKind::Irc if !crate::bouncer::validate_irc_upstream_addr(&n.addr) => {
                    return Err(ConfigError::Invalid(format!(
                        "network '{}' (kind=irc) addr must be host:port with a nonzero numeric port",
                        n.name
                    )));
                }
                NetworkKind::Matrix if n.nick.is_empty() => {
                    return Err(ConfigError::Invalid(format!(
                        "network '{}' (kind=matrix) requires nick (provider user)",
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

    fn listening_config() -> Config {
        Config {
            listeners: vec![listener()],
            ..Config::default()
        }
    }

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
    fn overlong_server_or_network_name_is_rejected() {
        let long = "x".repeat(65);
        let c: Config = toml::from_str(&format!(
            "server_name = \"{long}\"\nnetwork_name = \"XNet\"\n[[listeners]]\naddr = \"0.0.0.0:6667\"\n"
        ))
        .expect("parse");
        assert!(
            c.validate()
                .unwrap_err()
                .to_string()
                .contains("server_name"),
            "an over-long server_name must be rejected at load"
        );
        let c: Config = toml::from_str(&format!(
            "server_name = \"irc.x.example\"\nnetwork_name = \"{long}\"\n[[listeners]]\naddr = \"0.0.0.0:6667\"\n"
        ))
        .expect("parse");
        assert!(
            c.validate()
                .unwrap_err()
                .to_string()
                .contains("network_name"),
            "an over-long network_name must be rejected at load"
        );
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
    fn server_name_with_control_or_prefix_char_is_rejected() {
        // server_name is the source prefix of every server-originated line;
        // a control byte (TOML `\t` tab, `\u0007` BEL), space, or prefix-significant char
        // (`@`/`!`) must not load. (Values are TOML-escaped in the literal.)
        for bad in [
            r"irc\t.example",
            r"irc\u0007.example",
            "irc x",
            "irc@evil",
            "ir!c",
        ] {
            let c: Config = toml::from_str(&format!(
                "server_name = \"{bad}\"\nnetwork_name = \"XNet\"\n[[listeners]]\naddr = \"127.0.0.1:0\"\n"
            ))
            .expect("parse");
            let err = c.validate().unwrap_err().to_string();
            assert!(
                err.contains("server_name"),
                "server_name {bad:?} must be rejected: got {err}"
            );
        }
        // A normal hostname (with dots and a hyphen) still loads.
        let c: Config = toml::from_str(
            "server_name = \"irc.fail-closed.example\"\nnetwork_name = \"XNet\"\n[[listeners]]\naddr = \"127.0.0.1:0\"\n",
        )
        .expect("parse");
        c.validate().expect("a hostname server_name is accepted");
    }

    #[test]
    fn network_buffer_cap_zero_is_rejected() {
        // A zero backlog cap is otherwise silently coerced to 1 by Buffer::push.
        let c: Config = toml::from_str(
            r#"
            server_name = "irc.x.example"
            network_name = "XNet"
            [[listeners]]
            addr = "127.0.0.1:0"
            [database]
            url = "postgres://localhost/x"
            [bnc]
            addr = "127.0.0.1:0"
            [[network]]
            name = "libera"
            addr = "irc.libera.chat:6697"
            tls = true
            nick = "n"
            buffer_cap = 0
            "#,
        )
        .expect("parse");
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("buffer_cap"), "{err}");
    }

    #[test]
    fn unparseable_public_url_is_rejected_even_without_oidc() {
        // The https-under-secure-cookies guard only fires on a value that parses;
        // outright garbage must still be rejected (it seeds the device flow URL).
        let with_public_url = |value: &str| -> Config {
            toml::from_str(&format!(
                "server_name = \"irc.x.example\"\nnetwork_name = \"XNet\"\n\
                 [[listeners]]\naddr = \"127.0.0.1:0\"\n\
                 [database]\nurl = \"postgres://localhost/x\"\n\
                 [http]\naddr = \"127.0.0.1:0\"\npublic_url = \"{value}\"\n"
            ))
            .expect("parse")
        };
        let err = with_public_url("not a url")
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("public_url"), "{err}");
        // A well-formed http(s) URL is accepted.
        with_public_url("https://irc.example")
            .validate()
            .expect("a valid public_url is accepted");
    }

    #[test]
    fn plaintext_secret_passes_through() {
        assert_eq!(open_secret("hunter2", None).unwrap(), "hunter2");
        let key = crate::secret::SecretKeyring::single(crate::secret::SecretKey::generate());
        assert_eq!(open_secret("hunter2", Some(&key)).unwrap(), "hunter2");
    }

    #[test]
    fn sealed_secret_decrypts_with_key() {
        let key = crate::secret::SecretKey::generate();
        let sealed = key.seal("s3cr3t", crate::secret::CONFIG_CONTEXT);
        let ring = crate::secret::SecretKeyring::single(key);
        assert_eq!(open_secret(&sealed, Some(&ring)).unwrap(), "s3cr3t");
    }

    #[test]
    fn sealed_secret_without_key_is_rejected() {
        let sealed =
            crate::secret::SecretKey::generate().seal("s3cr3t", crate::secret::CONFIG_CONTEXT);
        let err = open_secret(&sealed, None).unwrap_err().to_string();
        assert!(err.contains("no key is configured"), "{err}");
    }

    #[test]
    fn sealed_secret_with_wrong_key_is_rejected() {
        let sealed =
            crate::secret::SecretKey::generate().seal("s3cr3t", crate::secret::CONFIG_CONTEXT);
        let other = crate::secret::SecretKeyring::single(crate::secret::SecretKey::generate());
        assert!(open_secret(&sealed, Some(&other)).is_err());
    }

    #[test]
    fn resolve_decrypts_network_sasl_password_via_key_file() {
        let key = crate::secret::SecretKey::generate();
        let sealed = key.seal("upstreampass", crate::secret::CONFIG_CONTEXT);
        // The Slack driver's bot token lives in sasl_account; a sealed value
        // there must also be unsealed (it used to be handed to Slack verbatim).
        let sealed_account = key.seal("xoxb-secret-token", crate::secret::CONFIG_CONTEXT);
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
                sasl_account: Some(sealed_account),
                sasl_password: Some(sealed),
            }],
            secrets: secrets_at(&path),
            ..Config::default()
        };
        cfg.resolve_secrets().expect("resolve");
        std::fs::remove_file(&path).ok();
        assert_eq!(
            cfg.networks[0].sasl_password.as_deref(),
            Some("upstreampass")
        );
        assert_eq!(
            cfg.networks[0].sasl_account.as_deref(),
            Some("xoxb-secret-token"),
            "a sealed sasl_account (Slack bot token) must be unsealed too"
        );
    }

    #[test]
    fn keyring_opens_previous_ciphertext_and_seals_with_primary() {
        let old = crate::secret::SecretKey::generate();
        let old_blob = old.seal("before-rotation", crate::secret::CONFIG_CONTEXT);
        let new = crate::secret::SecretKey::generate();
        let new_copy = crate::secret::SecretKey::from_base64(&new.to_base64()).unwrap();
        let directory = std::env::temp_dir();
        let primary_path = directory.join(format!("e6irc-primary-key-{}.b64", std::process::id()));
        let previous_path =
            directory.join(format!("e6irc-previous-key-{}.b64", std::process::id()));
        std::fs::write(&primary_path, new.to_base64()).unwrap();
        std::fs::write(&previous_path, old.to_base64()).unwrap();

        let config = Config {
            secrets: Some(SecretsConfig {
                key_file: primary_path.clone(),
                previous_key_files: vec![previous_path.clone()],
            }),
            ..Config::default()
        };
        let keys = config
            .secret_keyring()
            .expect("read keyring")
            .expect("configured");
        std::fs::remove_file(primary_path).ok();
        std::fs::remove_file(previous_path).ok();

        assert_eq!(
            keys.open(&old_blob, crate::secret::CONFIG_CONTEXT).unwrap(),
            "before-rotation"
        );
        assert_eq!(
            new_copy
                .open(
                    &keys.seal("after-rotation", crate::secret::CONFIG_CONTEXT),
                    crate::secret::CONFIG_CONTEXT,
                )
                .unwrap(),
            "after-rotation"
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

    /// Configured `[[network]]`s are only reachable through the BNC registry,
    /// which needs `[bnc]` (and `[bnc]` needs `[database]`). Tests about
    /// network selection must satisfy those so they exercise the selection
    /// rules, not the "networks require [bnc]" guard.
    fn bnc() -> Option<BncConfig> {
        Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
        })
    }

    fn db() -> Option<DatabaseConfig> {
        Some(DatabaseConfig {
            url: "postgres://localhost/x".into(),
        })
    }

    /// The plain-TCP test listener shared by every config-construction test —
    /// one loopback address, no TLS, no websocket. Extracted because every
    /// `Config { .. }` in this module repeated it verbatim.
    fn listener() -> ListenerConfig {
        ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }
    }

    /// A `[secrets]` block keyed on `path` with no rotation history — shared
    /// by the resolve-secrets tests.
    fn secrets_at(path: &std::path::Path) -> Option<SecretsConfig> {
        Some(SecretsConfig {
            key_file: path.to_path_buf(),
            previous_key_files: Vec::new(),
        })
    }

    /// A test config with the standard listener and `[bnc]`/`[database]`
    /// scaffolding around the given networks — shared by the validation tests.
    fn config_with(networks: Vec<NetworkEntry>) -> Config {
        Config {
            listeners: vec![listener()],
            networks,
            bnc: bnc(),
            database: db(),
            ..Config::default()
        }
    }

    #[test]
    fn irc_network_address_requires_host_and_nonzero_numeric_port() {
        for addr in [
            "irc.example",
            "irc.example:not-a-port",
            "irc.example:0",
            "2001:db8::1:6697",
        ] {
            let mut network = net("custom", None);
            network.addr = addr.into();
            let cfg = Config {
                listeners: vec![listener()],
                networks: vec![network],
                bnc: bnc(),
                database: db(),
                ..Config::default()
            };
            let error = cfg.validate().unwrap_err().to_string();
            assert!(error.contains("host:port"), "{addr:?}: {error}");
        }

        let mut network = net("ipv6", None);
        network.addr = "[2001:db8::1]:6697".into();
        let cfg = config_with(vec![network]);
        cfg.validate().expect("bracketed IPv6 address is valid");
    }

    #[test]
    fn bridge_config_uses_the_same_canonical_shapes_as_the_driver_factory() {
        let bridge_config = |network| config_with(vec![network]);
        let mut matrix = net("matrix", None);
        matrix.kind = NetworkKind::Matrix;
        matrix.addr = "https://matrix.example".into();
        matrix.tls = true;
        matrix.nick = "@alice:matrix.example".into();
        matrix.sasl_password = Some("secret".into());
        bridge_config(matrix.clone())
            .validate()
            .expect("canonical Matrix config");

        matrix.addr = "matrix.example".into();
        assert!(
            bridge_config(matrix)
                .validate()
                .unwrap_err()
                .to_string()
                .contains("HTTP(S)")
        );

        let mut slack = net("slack", None);
        slack.kind = NetworkKind::Slack;
        slack.addr.clear();
        slack.tls = true;
        slack.nick.clear();
        slack.sasl_account = Some("xoxb-token".into());
        slack.sasl_password = Some("xapp-token".into());
        bridge_config(slack.clone())
            .validate()
            .expect("canonical Slack config with provider endpoint");

        slack.nick = "ignored-user".into();
        assert!(
            bridge_config(slack)
                .validate()
                .unwrap_err()
                .to_string()
                .contains("does not accept nick")
        );
    }

    #[test]
    fn configured_network_credentials_are_complete_nonempty_and_bounded() {
        let config = |network| config_with(vec![network]);
        let mut irc = net("irc-sasl", None);
        irc.sasl_account = Some("alice".into());
        assert!(
            config(irc)
                .validate()
                .unwrap_err()
                .to_string()
                .contains("both sasl_account and sasl_password")
        );

        let mut slack = net("slack-empty", None);
        slack.kind = NetworkKind::Slack;
        slack.addr.clear();
        slack.tls = true;
        slack.nick.clear();
        slack.sasl_account = Some(String::new());
        slack.sasl_password = Some("xapp-token".into());
        assert!(
            config(slack)
                .validate()
                .unwrap_err()
                .to_string()
                .contains("non-empty")
        );
    }

    #[test]
    fn same_network_name_across_distinct_owners_is_ok() {
        let cfg = Config {
            listeners: vec![listener()],
            networks: vec![net("libera", Some("alice")), net("libera", Some("bob"))],
            bnc: bnc(),
            database: db(),
            ..Config::default()
        };
        cfg.validate().expect("distinct owners may reuse a name");
    }

    #[test]
    fn websocket_listener_with_tls_is_rejected() {
        // A websocket listener is served by plain axum with TLS terminated at a
        // proxy; combining it with a tls section is refused at load, never
        // silently ignored.
        let cfg = Config {
            listeners: vec![ListenerConfig {
                addr: "127.0.0.1:0".parse().unwrap(),
                tls: Some(TlsConfig {
                    cert_path: "/unused/cert.pem".into(),
                    key_path: "/unused/key.pem".into(),
                }),
                websocket: true,
            }],
            ..Config::default()
        };
        assert!(cfg.validate().is_err(), "websocket + tls must be rejected");
    }

    #[test]
    fn duplicate_owner_and_name_is_rejected() {
        let cfg = Config {
            listeners: vec![listener()],
            networks: vec![net("Libera", Some("Alice")), net("libera", Some("alice"))],
            bnc: bnc(),
            database: db(),
            ..Config::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn name_both_shared_and_owned_is_rejected() {
        let cfg = Config {
            listeners: vec![listener()],
            networks: vec![net("Libera", None), net("libera", Some("alice"))],
            bnc: bnc(),
            database: db(),
            ..Config::default()
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("both shared and owned"), "{err}");
    }

    #[test]
    fn networks_without_database_are_rejected() {
        let cfg = Config {
            listeners: vec![listener()],
            networks: vec![net("libera", None)],
            ..Config::default()
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("require [database]"), "{err}");
    }

    #[test]
    fn database_networks_do_not_require_raw_attach_listener() {
        let cfg = Config {
            listeners: vec![listener()],
            networks: vec![net("libera", None)],
            database: db(),
            ..Config::default()
        };
        cfg.validate().unwrap();
    }

    #[test]
    fn zero_command_burst_is_rejected() {
        let cfg = Config {
            listeners: vec![listener()],
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
    fn zero_registration_burst_is_rejected() {
        let cfg = Config {
            listeners: vec![listener()],
            limits: LimitsConfig {
                registration_burst: Some(0),
                ..LimitsConfig::default()
            },
            ..Config::default()
        };
        assert!(
            cfg.validate().is_err(),
            "registration_burst=0 refuses every account creation and must be rejected"
        );
    }

    #[test]
    fn browser_bootstrap_requires_full_stack_and_a_strong_bounded_token() {
        let bootstrap = Some(BootstrapConfig {
            token: "0123456789abcdef0123456789abcdef".into(),
        });
        let mut config = Config {
            listeners: vec![listener()],
            bootstrap: bootstrap.clone(),
            ..Config::default()
        };
        assert!(config.validate().is_err(), "database and HTTP are required");

        config.database = db();
        config.http = Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![],
        });
        config.validate().expect("complete browser bootstrap");

        config.bootstrap = Some(BootstrapConfig {
            token: "too-short".into(),
        });
        assert!(config.validate().is_err());
        config.bootstrap = Some(BootstrapConfig {
            token: format!("{}x", "a".repeat(512)),
        });
        assert!(config.validate().is_err());
        config.bootstrap = Some(BootstrapConfig {
            token: format!("{}\n", "a".repeat(31)),
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_max_connections_per_ip_is_rejected() {
        // `count >= 0` is always true, so a max of 0 refuses every connection —
        // the server would boot and silently reject all traffic.
        let cfg = Config {
            listeners: vec![listener()],
            limits: LimitsConfig {
                max_connections_per_ip: Some(0),
                ..LimitsConfig::default()
            },
            ..Config::default()
        };
        assert!(
            cfg.validate().is_err(),
            "max_connections_per_ip=0 refuses every connection and must be rejected"
        );
    }

    #[test]
    fn oversized_nicklen_is_rejected() {
        let cfg = Config {
            listeners: vec![listener()],
            nicklen: 500,
            ..Config::default()
        };
        assert!(
            cfg.validate().is_err(),
            "an unbounded nicklen can push a relayed line past the wire limit"
        );
    }

    #[test]
    fn registration_without_database_is_rejected() {
        let cfg = Config {
            listeners: vec![listener()],
            registration: RegistrationConfig {
                before_connect: true,
                ..RegistrationConfig::default()
            },
            database: None,
            ..Config::default()
        };
        assert!(
            cfg.validate().is_err(),
            "[registration] without [database] is a silent no-op and must be rejected"
        );
    }

    #[test]
    fn zero_max_hot_channels_is_rejected() {
        let cfg = Config {
            listeners: vec![listener()],
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
            listeners: vec![listener()],
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
                allowed_email_domains: vec![],
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
    fn oidc_issuer_must_be_https_under_secure_cookies() {
        // Production (secure cookies) must reject a plaintext issuer — discovery
        // and JWKS are forgeable over http by an on-path attacker.
        // oidc_config sets secure_cookies = true.
        let config = oidc_config("dex", "http://auth.example", None);
        assert!(
            config.validate().unwrap_err().to_string().contains("https"),
            "http issuer must be rejected under secure_cookies"
        );
        // A dev setup (secure_cookies = false) may still use http locally.
        let mut dev = oidc_config("dex", "http://127.0.0.1:5556/dex", None);
        dev.http.as_mut().unwrap().secure_cookies = false;
        dev.validate().expect("http issuer allowed in dev");
    }

    #[test]
    fn oidc_duplicate_issuer_is_rejected() {
        // Two providers sharing an issuer would collide on the (issuer, subject)
        // account key.
        let mut config = oidc_config("dex", "https://auth.example", None);
        config.oidc_providers.push(OidcProviderConfig {
            name: "dex2".into(),
            issuer_url: "https://auth.example".into(), // same issuer
            client_id: "e6irc2".into(),
            client_secret: "secret2".into(),
            scopes: vec![],
            allowed_email_domains: vec![],
            end_session_endpoint: None,
            token_endpoint_auth_method: Default::default(),
        });
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("duplicate OIDC issuer"),
            "duplicate issuer must be rejected"
        );
    }

    #[test]
    fn oidc_allowed_email_domains_are_canonical_and_unique() {
        let mut config = oidc_config("corp", "https://auth.example", None);
        config.oidc_providers[0].allowed_email_domains = vec![
            crate::identity::EmailDomain::parse("Example.COM").expect("domain"),
            crate::identity::EmailDomain::parse("example.com").expect("domain"),
        ];
        let error = config.validate().expect_err("duplicate domain");
        assert!(error.to_string().contains("repeats allowed email domain"));

        let parsed: Config = toml::from_str(
            r#"
server_name = "irc.example"
network_name = "Example"
application_release_revision = "0123456789ab"

[[listeners]]
addr = "127.0.0.1:6667"

[database]
url = "postgres://db.example/e6irc"

[http]
addr = "127.0.0.1:8080"
public_url = "https://chat.example"

[[oidc]]
name = "corp"
issuer_url = "https://auth.example"
client_id = "e6irc"
client_secret = "secret"
allowed_email_domains = ["Example.COM", "subsidiary.example"]
"#,
        )
        .expect("parse");
        assert_eq!(
            parsed.oidc_providers[0].allowed_email_domains[0].as_str(),
            "example.com"
        );
        parsed.validate().expect("valid domain policy");
    }

    #[test]
    fn observability_bounds_are_validated() {
        let mut config = listening_config();
        config.observability.sample_interval_seconds = 4;
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("sample_interval_seconds")
        );
        config.observability.sample_interval_seconds = 15;
        config.observability.retention_hours = 2161;
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("retention_hours")
        );
    }

    #[test]
    fn persisted_settings_without_observability_use_safe_defaults() {
        let settings = ManagedConfig::from_config(&Config::default(), None).unwrap();
        let mut value = serde_json::to_value(settings).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("observability")
            .expect("serialized field");
        let decoded: ManagedConfig = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.observability, ObservabilityConfig::default());
    }

    #[test]
    fn storage_retention_is_bounded_and_old_settings_receive_defaults() {
        let mut config = listening_config();
        config.storage.history_retention_days = 0;
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("history_retention_days")
        );
        config.storage.history_retention_days = 30;
        config.storage.audit_retention_days = 3651;
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("audit_retention_days")
        );

        let settings = ManagedConfig::from_config(&Config::default(), None).unwrap();
        let mut value = serde_json::to_value(settings).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("storage")
            .expect("serialized field");
        let decoded: ManagedConfig = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.storage, StorageConfig::default());
    }

    #[test]
    fn resolve_decrypts_oper_and_oidc_secrets() {
        let key = crate::secret::SecretKey::generate();
        let path = std::env::temp_dir().join(format!("e6irc-key2-{}.b64", std::process::id()));
        std::fs::write(&path, key.to_base64()).unwrap();

        let mut cfg = Config {
            opers: vec![OperConfig {
                name: "root".into(),
                password: key.seal("operpass", crate::secret::CONFIG_CONTEXT),
            }],
            oidc_providers: vec![OidcProviderConfig {
                name: "corp".into(),
                issuer_url: "https://issuer.example".into(),
                client_id: "cid".into(),
                client_secret: key.seal("oidcsecret", crate::secret::CONFIG_CONTEXT),
                scopes: vec![],
                allowed_email_domains: vec![],
                end_session_endpoint: None,
                token_endpoint_auth_method: Default::default(),
            }],
            secrets: secrets_at(&path),
            ..Config::default()
        };
        cfg.resolve_secrets().expect("resolve");
        std::fs::remove_file(&path).ok();
        assert_eq!(cfg.opers[0].password, "operpass");
        assert_eq!(cfg.oidc_providers[0].client_secret, "oidcsecret");
    }
}
