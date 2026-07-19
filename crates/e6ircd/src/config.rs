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
fn default_max_hot_channels() -> usize {
    8192
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server_name: String,
    pub network_name: String,
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
    /// PostgreSQL connection; enables accounts and SASL when present.
    #[serde(default)]
    pub database: Option<DatabaseConfig>,
    /// HTTP listener (REST API + web backend); off when absent.
    #[serde(default)]
    pub http: Option<HttpConfig>,
    /// OIDC providers for web login (requires http + database).
    #[serde(default, rename = "oidc")]
    pub oidc_providers: Vec<OidcProviderConfig>,
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
            motd: Vec::new(),
            listeners: Vec::new(),
            nicklen: default_nicklen(),
            sendq: default_sendq(),
            core_queue: default_core_queue(),
            max_hot_channels: default_max_hot_channels(),
            database: None,
            http: None,
            oidc_providers: Vec::new(),
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
        if self.nicklen == 0 || self.sendq == 0 || self.core_queue == 0 {
            return Err(ConfigError::Invalid("limits must be nonzero".into()));
        }
        if !self.oidc_providers.is_empty() {
            if self.database.is_none() {
                return Err(ConfigError::Invalid(
                    "[[oidc]] requires [database] for account storage".into(),
                ));
            }
            match &self.http {
                Some(h) if h.public_url.is_some() => {}
                _ => {
                    return Err(ConfigError::Invalid(
                        "[[oidc]] requires [http] with public_url for redirect URIs".into(),
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
