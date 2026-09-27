//! Server configuration. TOML on disk; unknown keys are a startup
//! error — configuration mistakes must never be silently ignored.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

fn default_nicklen() -> usize {
    16
}

/// Shortest `nicklen` a server may advertise: NickServ nick protection renames
/// a user who does not identify to `Guest` and five digits, which must be a
/// valid nick.
pub const MIN_NICKLEN: usize = 10;
/// Most core shards. Each is a task with its own `core_queue`-slot inbound
/// queue, and every broadcast (a tick, a channel event with members elsewhere)
/// is one message per shard, so shards past the machine's cores only add cost.
pub const MAX_CORE_WORKERS: usize = 64;
/// Most inbound events one core shard may have queued (16× the default).
pub const MAX_CORE_QUEUE: usize = 1 << 20;
/// The default SendQ: the 1,024 lines the send queue held when it counted
/// lines, at a full 512-byte line each (RFC 1459's limit on a line without
/// tags). Ordinary traffic queues as much as it did; what changed is that a
/// few maximum-size tagged lines can no longer pin sixteen times that.
pub const DEFAULT_SENDQ_BYTES: usize = 1024 * e6irc_proto::message::MAX_LINE_LEN;
/// Most bytes queued for one connection before it is killed for SendQ (64×
/// the default). This is per connection: it bounds what one slow reader can
/// pin.
pub const MAX_SENDQ_BYTES: usize = 64 * DEFAULT_SENDQ_BYTES;
/// Fewest bytes a SendQ may hold: two of the longest lines the server sends
/// (8,191 bytes of tags and a 512-byte line), so the half a paced LIST or WHO
/// may take still holds one.
pub const MIN_SENDQ_BYTES: usize = 2 * (e6irc_proto::message::MAX_SERVER_FRAME_LEN + 2);
/// Most channels that may hold an in-memory history ring at once.
pub const MAX_HOT_CHANNELS: usize = 1 << 20;
/// The default byte budget of one hot history ring: its 500 entries at a
/// kilobyte each, which an ordinary line (512 bytes of text, its msgid, its
/// sender and the entry's own fields) stays under. Only entries carrying
/// kilobytes of client tags, or long multiline messages, shorten a ring.
pub const DEFAULT_HISTORY_RING_BYTES: usize = 500 * 1024;
/// Most bytes one hot history ring may hold (128× the default).
pub const MAX_HISTORY_RING_BYTES: usize = 128 * DEFAULT_HISTORY_RING_BYTES;
/// The default byte budget of every hot history ring together: 512 MiB, a
/// thousand full rings of ordinary lines — far more than the few hundred
/// channels busy at once on a network this server is sized for — where a
/// count of rings alone let 8,192 rings of twelve-kilobyte entries pin
/// fifty gigabytes.
pub const DEFAULT_HOT_HISTORY_BYTES: usize = 512 << 20;
/// Most bytes every hot history ring together may hold (128× the default).
pub const MAX_HOT_HISTORY_BYTES: usize = 128 * DEFAULT_HOT_HISTORY_BYTES;
/// Most lines one network keeps in memory for replay (`buffer_cap`), and the
/// lines its stored backlog keeps (`crate::db::BNC_BUFFER_CAP` is this bound).
/// A start restores a network's whole `buffer_cap` from that backlog, so the
/// replay the setting promises survives a restart: a `buffer_cap` above what
/// storage keeps used to be honoured only until then.
pub const MAX_NETWORK_BUFFER_CAP: usize = 5_000;
/// Longest `server_name`, in bytes. It is the source of every numeric, so it
/// is in the fixed head of every reply; a hostname fits well within it.
pub const MAX_SERVER_NAME_LEN: usize = 64;
/// Longest `nicklen` a server may advertise. A nickname rides every relayed
/// line's source prefix and is the target of every numeric.
pub const MAX_NICKLEN: usize = 64;
/// Longest `network_name`, in bytes: the ISUPPORT `NETWORK=` token.
pub const MAX_NETWORK_NAME_LEN: usize = 64;
/// Bytes of a numeric reply before its first parameter at the longest
/// `server_name` and nickname: `:<server> <code> <nick>`. Every numeric is
/// fitted to the wire by `numeric_line`, which clips what does not fit; a
/// configured text that has to arrive whole is bounded against this instead.
const MAX_NUMERIC_HEAD_LEN: usize = 1 + MAX_SERVER_NAME_LEN + 1 + 3 + 1 + MAX_NICKLEN;
/// What a line may carry before its CRLF.
const WIRE_LINE_BUDGET: usize = e6irc_proto::message::MAX_LINE_LEN - 2;
/// Longest `motd` line, in bytes: what fits a `RPL_MOTD` (`<head> :- <line>`)
/// at the longest server name and nickname, so no client is sent a clipped
/// one.
pub const MAX_MOTD_LINE_LEN: usize = WIRE_LINE_BUDGET - MAX_NUMERIC_HEAD_LEN - " :- ".len();
/// Most bytes the whole MOTD may take as a new client is sent it at
/// registration — its `RPL_MOTD` lines between `RPL_MOTDSTART` and
/// `RPL_ENDOFMOTD`, at the longest server name and nickname ([`motd_reply_bytes`]).
/// The client is sent it before it has read a byte, beside the rest of the
/// registration burst (welcome, ISUPPORT, LUSERS, user modes), so all of it
/// must fit the smallest SendQ a connection can have or a long MOTD kills
/// every slow reader for SendQ: the MOTD has half of [`MIN_SENDQ_BYTES`], and
/// the rest of the burst, a score of mostly short numerics, the other half.
/// Bounded in bytes rather than lines, since bytes are what the SendQ holds: a
/// MOTD of short lines may have many more of them than one of long lines.
pub const MAX_MOTD_BYTES: usize = MIN_SENDQ_BYTES / 2;
/// `RPL_MOTDSTART`'s text after the server name (`- <server> Message of the day - `).
pub(crate) const MOTD_START_SUFFIX: &str = " Message of the day - ";
/// `RPL_ENDOFMOTD`'s text.
pub(crate) const MOTD_END_TEXT: &str = "End of /MOTD command.";
/// What a numeric reply spends besides its trailing text, at the longest
/// server name and nickname: `<head> :` and the CRLF.
const NUMERIC_REPLY_OVERHEAD: usize = MAX_NUMERIC_HEAD_LEN + " :".len() + 2;
/// What one `motd` line's `RPL_MOTD` spends besides the line itself, at the
/// longest server name and nickname: its reply's overhead and the `- ` before
/// the line.
pub const MOTD_LINE_REPLY_OVERHEAD: usize = NUMERIC_REPLY_OVERHEAD + "- ".len();
/// `RPL_MOTDSTART` and `RPL_ENDOFMOTD` together, at the longest server name
/// and nickname.
const MOTD_FRAME_BYTES: usize = 2 * NUMERIC_REPLY_OVERHEAD
    + "- ".len()
    + MAX_SERVER_NAME_LEN
    + MOTD_START_SUFFIX.len()
    + MOTD_END_TEXT.len();
/// What the `motd` lines may take together, each counting its length and
/// [`MOTD_LINE_REPLY_OVERHEAD`]: [`MAX_MOTD_BYTES`] less the frame around them.
pub const MAX_MOTD_LINES_BYTES: usize = MAX_MOTD_BYTES - MOTD_FRAME_BYTES;

/// The bytes `motd` takes as a new client is sent it, at the longest server
/// name and nickname: every line's `RPL_MOTD`, `RPL_MOTDSTART` and
/// `RPL_ENDOFMOTD`. An empty MOTD is one `ERR_NOMOTD` instead, well within
/// any bound.
pub fn motd_reply_bytes(motd: &[String]) -> usize {
    MOTD_FRAME_BYTES
        + motd
            .iter()
            .map(|line| line.len() + MOTD_LINE_REPLY_OVERHEAD)
            .sum::<usize>()
}
/// Longest `description`, in bytes: what fits a `RPL_LINKS` (`<head> <server>
/// <server> :0 <description>`) at the longest server name and nickname.
pub const MAX_DESCRIPTION_LEN: usize =
    WIRE_LINE_BUDGET - MAX_NUMERIC_HEAD_LEN - 2 * (1 + MAX_SERVER_NAME_LEN) - " :0 ".len();
/// Longest account name, in bytes: an IRC nickname the account store admits.
/// `http.admin_accounts` entries and administrator-created accounts are held
/// to it at their respective ingresses.
pub const MAX_ACCOUNT_NAME_LEN: usize = 64;

fn default_sendq_bytes() -> usize {
    DEFAULT_SENDQ_BYTES
}
fn default_core_queue() -> usize {
    65536
}
fn default_core_workers() -> usize {
    1
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

fn default_max_history_ring_bytes() -> usize {
    DEFAULT_HISTORY_RING_BYTES
}

fn default_max_hot_history_bytes() -> usize {
    DEFAULT_HOT_HISTORY_BYTES
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The IRC server name. A database-backed document may leave it out when
    /// the console stores it ([`Self::left_to_stored_settings`]).
    #[serde(default)]
    pub server_name: String,
    /// The IRC network name; like `server_name`, it may be left to the stored
    /// settings.
    #[serde(default)]
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
    /// Per-connection outbound queue capacity, in bytes (Solanum's class
    /// `sendq`), output held behind a deferred reply included; overflow kills
    /// the client ("SendQ exceeded").
    #[serde(default = "default_sendq_bytes")]
    pub sendq_bytes: usize,
    /// Core worker inbound queue capacity; when full, connection
    /// readers stop reading their sockets (backpressure).
    #[serde(default = "default_core_queue")]
    pub core_queue: usize,
    /// Number of independent core shards. One preserves the single-worker
    /// deployment; larger values enable hash-sharded runtime ownership.
    #[serde(default = "default_core_workers")]
    pub core_workers: usize,
    /// Cap on channels holding an in-memory history ring (LRU eviction
    /// beyond this; evicted channels serve CHATHISTORY from Postgres).
    #[serde(default = "default_max_hot_channels")]
    pub max_hot_channels: usize,
    /// Byte budget of one channel's or conversation's history ring: its
    /// oldest entries go first once it is exceeded.
    #[serde(default = "default_max_history_ring_bytes")]
    pub max_history_ring_bytes: usize,
    /// Byte budget of every history ring together: the least recently active
    /// rings are evicted once it is exceeded, as beyond `max_hot_channels`.
    #[serde(default = "default_max_hot_history_bytes")]
    pub max_hot_history_bytes: usize,
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
    #[serde(
        default,
        rename = "network",
        deserialize_with = "deserialize_static_networks"
    )]
    pub networks: Vec<NetworkEntry>,
    /// The bouncer listener, where clients attach as nick/network.
    #[serde(default)]
    pub bnc: Option<BncConfig>,
    /// Whether a network may have an upstream inside this host's own network
    /// (loopback, RFC 1918, carrier-grade NAT, unique-local). Refused by
    /// default: an account holder could otherwise make this server connect to
    /// internal infrastructure and learn what answers. `allow` is for test
    /// harnesses whose upstreams listen on loopback.
    #[serde(default)]
    pub internal_upstreams: crate::egress::InternalUpstreams,
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
    /// Which keys the document this configuration was read from states, so a
    /// console-owned setting it states can be held to the stored value
    /// ([`ManagedConfig::bootstrap_drift`]) while one it leaves unstated is
    /// not. Not a key of the document itself.
    #[serde(skip)]
    pub stated: StatedSettings,
    /// The console-owned settings every server needs that the document
    /// leaves out ([`LEFT_TO_STORED_SETTINGS`]): each takes the stored
    /// revision's value at start. Allowed only beside a `[database]`, and a
    /// first start with no stored settings to take them from is refused naming
    /// them (`net::start`). Removing a console-owned setting from the
    /// bootstrap is how an operator hands it to the console, so these may be
    /// removed like any other; so may `http.public_url`
    /// ([`LEFT_TO_STORED_PUBLIC_URL`]).
    #[serde(skip)]
    pub left_to_stored_settings: Vec<&'static str>,
}

/// The settings a server cannot run without that the console owns, and so
/// that a database-backed document may leave to the stored revision.
pub const LEFT_TO_STORED_SETTINGS: [&str; 3] = ["server_name", "network_name", "listeners"];

/// The public URL, which a database-backed document with an `[http]` listener
/// leaves to the stored revision by not stating it, as it does the names in
/// [`LEFT_TO_STORED_SETTINGS`]. A server can run without one — the features
/// that build an absolute link (OpenID Connect, device login, invitations)
/// then refuse, each saying so, and a WebSocket upgrade is held to its `Host`
/// — but a first start does not take that from an omission: the console's
/// first revision is imported from the document, and a public URL an operator
/// forgot would be stored as none. Without a database there is no stored
/// revision, and leaving it out is running without one, as before.
pub const LEFT_TO_STORED_PUBLIC_URL: &str = "http.public_url";

/// The keys of [`LEFT_TO_STORED_SETTINGS`] `document` does not state, and
/// [`LEFT_TO_STORED_PUBLIC_URL`] when a database-backed document's `[http]`
/// does not state it.
fn left_out_of(document: &toml::Table) -> Vec<&'static str> {
    let public_url_left = document.contains_key("database")
        && document
            .get("http")
            .and_then(toml::Value::as_table)
            .is_some_and(|http| !http.contains_key("public_url"));
    LEFT_TO_STORED_SETTINGS
        .into_iter()
        .filter(|key| !document.contains_key(*key))
        .chain(public_url_left.then_some(LEFT_TO_STORED_PUBLIC_URL))
        .collect()
}

/// The keys a configuration document states, as opposed to leaving them to a
/// default. On a database-backed start every console-owned setting the
/// document states must agree with the stored revision, and one it does not
/// state is the console's alone ([`ManagedConfig::bootstrap_drift`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum StatedSettings {
    /// A configuration built in code rather than read from a document. Every
    /// setting counts as stated: nothing says which were meant, and treating
    /// all of them as meant is the reading under which none can be silently
    /// overridden.
    #[default]
    Everything,
    /// A document (a file, or the environment's): the dotted paths of every
    /// value that is not a table (`http.admin_accounts`, `limits.command_burst`,
    /// `oidc`), less the ones the environment filled with its own defaults.
    Keys(std::collections::BTreeSet<String>),
}

impl StatedSettings {
    /// The keys `document` states, less `defaulted` (the environment's own
    /// defaults, which no operator stated).
    fn of_document(document: &toml::Table, defaulted: &[&str]) -> Self {
        fn leaves(prefix: &str, table: &toml::Table, out: &mut std::collections::BTreeSet<String>) {
            for (key, value) in table {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                match value {
                    toml::Value::Table(table) => leaves(&path, table, out),
                    _ => {
                        out.insert(path);
                    }
                }
            }
        }
        let mut keys = std::collections::BTreeSet::new();
        leaves("", document, &mut keys);
        for key in defaulted {
            keys.remove(*key);
        }
        Self::Keys(keys)
    }

    /// Whether the document states anything at `path` (a bootstrap key path
    /// such as `http.admin_accounts` or `oidc[0].client_secret`): the key
    /// itself, a key enclosing it (`oidc` states `oidc[0].client_secret`), or
    /// a key inside it (`bnc.tls.cert_path` states part of `bnc.tls`).
    fn covers(&self, path: &str) -> bool {
        fn encloses(outer: &str, inner: &str) -> bool {
            inner
                .strip_prefix(outer)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(['.', '[']))
        }
        match self {
            Self::Everything => true,
            Self::Keys(keys) => keys
                .iter()
                .any(|key| encloses(key, path) || encloses(path, key)),
        }
    }
}

const DEFAULT_API_RATE_BURST: usize = 240;
const DEFAULT_ADMINISTRATOR_API_RATE_BURST: usize = 60;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Maximum simultaneous connections from one IP; `None` = unlimited.
    /// Excess connections are refused at accept (before registration).
    #[serde(default)]
    pub max_connections_per_ip: Option<usize>,
    /// Per-connection command-flood bucket size (Solanum's
    /// `client_flood_burst_max` shape). Every line a non-oper connection sends,
    /// PING/PONG and pre-registration lines included, spends one token; when
    /// the bucket is empty the server stops reading that connection until a
    /// token is regained (DESIGN §7.2). Always on: it is the bound on every
    /// output-amplifying command class and on what one connection can queue
    /// for the core. Must be at least `command_rate`.
    #[serde(default = "default_command_burst")]
    pub command_burst: usize,
    /// Tokens the command-flood bucket regains per second, up to
    /// `command_burst` (Solanum's `client_flood_message_num`).
    #[serde(default = "default_command_rate")]
    pub command_rate: usize,
    /// CIDRs of trusted reverse proxies (e.g. the load balancer). When a
    /// request's socket peer matches one of these, its client IP is taken
    /// from `X-Forwarded-For`; otherwise the socket peer IP is used. Parsed
    /// when the configuration is read: an invalid CIDR is a hard error, and an
    /// IPv4-mapped one is read as its IPv4 range
    /// ([`crate::net::canonical_network`]).
    #[serde(default, deserialize_with = "deserialize_canonical_networks")]
    pub trusted_proxies: Vec<ipnet::IpNet>,
    /// Token-bucket size for the unauthenticated, work-inducing endpoints
    /// (password login, OIDC starts and callbacks, device authorization,
    /// invitation and bootstrap acceptance), per client address (an IPv6
    /// client's whole `/64`); the bucket refills to full over 60 seconds. On
    /// by default ([`DEFAULT_AUTH_RATE_BURST`]); `"off"` disables it, for a
    /// deployment whose reverse proxy throttles these routes itself.
    #[serde(default)]
    pub auth_rate_burst: AuthRateBurst,
    /// Authenticated REST requests per account per minute.
    #[serde(default = "default_api_rate_burst")]
    pub api_rate_burst: usize,
    /// Administrator REST requests per administrator per minute.
    #[serde(default = "default_administrator_api_rate_burst")]
    pub administrator_api_rate_burst: usize,
    /// Token-bucket size for account creation (REGISTER / NickServ REGISTER),
    /// per client IP; the bucket refills to full over one hour. Bounds bulk
    /// account minting from one address. `None` disables the throttle.
    #[serde(default)]
    pub registration_burst: Option<usize>,
    /// Refuse to register any IRC client that has not logged in to an account
    /// by the end of registration (Solanum's `need_sasl` auth block, for
    /// everyone). See [`SaslRequirement`].
    #[serde(default)]
    pub require_sasl: bool,
    /// The same refusal, only for clients connecting from these address
    /// ranges (a cloud provider's, say). Redundant, and refused, when
    /// `require_sasl` already covers everyone. Read like `trusted_proxies`.
    #[serde(default, deserialize_with = "deserialize_canonical_networks")]
    pub require_sasl_from: Vec<ipnet::IpNet>,
}

/// The default `limits.auth_rate_burst`: twenty requests a minute from one
/// address. A person signing in spends two or three (the login page's POST,
/// an OIDC start and its callback); a device polling its authorization every
/// five seconds spends twelve a minute. The per-account attempt window bounds
/// guessing at one account; this bounds what one address drives across all of
/// them — names sprayed, argon2 checks, OIDC round trips, device grants.
pub const DEFAULT_AUTH_RATE_BURST: usize = 20;

/// `limits.auth_rate_burst`: how many authentication requests one client
/// address may make at once, refilling over a minute, or `"off"`.
///
/// A number in a document or the stored settings, or the string `"off"`: a
/// throttle that is on by default needs a spelling for off that no one writes
/// by accident, and `0` (which reads as "none allowed") or a missing key
/// (which means the default) are not it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRateBurst {
    /// No throttle on the authentication endpoints.
    Off,
    /// A bucket of this many requests per client address.
    PerMinute(usize),
}

impl Default for AuthRateBurst {
    fn default() -> Self {
        Self::PerMinute(DEFAULT_AUTH_RATE_BURST)
    }
}

impl AuthRateBurst {
    /// The bucket size, or `None` when the throttle is off.
    pub fn burst(self) -> Option<usize> {
        match self {
            Self::Off => None,
            Self::PerMinute(burst) => Some(burst),
        }
    }
}

impl Serialize for AuthRateBurst {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Off => serializer.serialize_str("off"),
            Self::PerMinute(burst) => serializer.serialize_u64(*burst as u64),
        }
    }
}

impl<'de> Deserialize<'de> for AuthRateBurst {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = AuthRateBurst;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a request count, or \"off\"")
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<AuthRateBurst, E> {
                usize::try_from(value)
                    .map(AuthRateBurst::PerMinute)
                    .map_err(|_| E::custom("auth_rate_burst is too large"))
            }

            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<AuthRateBurst, E> {
                u64::try_from(value)
                    .map_err(|_| E::custom("auth_rate_burst must not be negative"))
                    .and_then(|value| self.visit_u64(value))
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<AuthRateBurst, E> {
                match value {
                    "off" => Ok(AuthRateBurst::Off),
                    other => Err(E::invalid_value(serde::de::Unexpected::Str(other), &self)),
                }
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

impl LimitsConfig {
    /// Who these limits require to log in with SASL before registering.
    pub fn sasl_requirement(&self) -> SaslRequirement {
        SaslRequirement {
            everyone: self.require_sasl,
            ranges: self.require_sasl_from.clone(),
        }
    }
}

/// Which IRC clients must have logged in to an account by the end of
/// registration (`limits.require_sasl`, `limits.require_sasl_from`). A client
/// it covers that is still anonymous when its NICK/USER/CAP END complete is
/// refused as Libera refuses its SASL-only ranges: a NOTICE saying so, 465,
/// and `ERROR :Closing Link: … (SASL access only)`.
///
/// Logged in means an account on the connection: SASL, or a
/// `draft/account-registration` REGISTER before connect (which logs the new
/// account in, and which the operator enables separately). The bouncer's
/// in-process sessions are exempt: their owner authenticated to the bouncer,
/// and they have no address for a range to match.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SaslRequirement {
    everyone: bool,
    ranges: Vec<ipnet::IpNet>,
}

impl SaslRequirement {
    /// Whether a client connecting from `address` (`None` for a session with
    /// no address) must log in before registering.
    pub fn covers(&self, address: Option<std::net::IpAddr>) -> bool {
        self.everyone
            || address.is_some_and(|address| {
                let address = address.to_canonical();
                self.ranges.iter().any(|range| range.contains(&address))
            })
    }
}

/// Solanum's defaults: a 40-command burst refilling at 20 per second.
pub const DEFAULT_COMMAND_BURST: usize = 40;
pub const DEFAULT_COMMAND_RATE: usize = 20;
/// Upper bound on both flood knobs; the console offers the same range.
pub const MAX_COMMAND_FLOOD_TOKENS: usize = 10_000;

const fn default_command_burst() -> usize {
    DEFAULT_COMMAND_BURST
}

const fn default_command_rate() -> usize {
    DEFAULT_COMMAND_RATE
}

const fn default_api_rate_burst() -> usize {
    DEFAULT_API_RATE_BURST
}

const fn default_administrator_api_rate_burst() -> usize {
    DEFAULT_ADMINISTRATOR_API_RATE_BURST
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections_per_ip: None,
            command_burst: DEFAULT_COMMAND_BURST,
            command_rate: DEFAULT_COMMAND_RATE,
            trusted_proxies: Vec::new(),
            auth_rate_burst: AuthRateBurst::default(),
            api_rate_burst: DEFAULT_API_RATE_BURST,
            administrator_api_rate_burst: DEFAULT_ADMINISTRATOR_API_RATE_BURST,
            registration_burst: None,
            require_sasl: false,
            require_sasl_from: Vec::new(),
        }
    }
}

/// Operational settings owned by the database-backed control plane.
///
/// Values needed to reach the control plane itself deliberately do not appear
/// here: the database URL, master-key source, HTTP bind address, and immutable
/// release revision remain bootstrap configuration. Every field in this type is
/// rendered and editable by the admin console, stored as one revision, and
/// applied on the next process start; the BNC listener is additionally applied
/// live by its runtime controller. The first database-backed start imports them
/// from the configuration; after that a configuration may still state one only
/// with the stored value, or start is refused ([`Self::bootstrap_drift`]).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedConfig {
    pub server_name: String,
    pub network_name: String,
    pub description: String,
    pub motd: Vec<String>,
    pub nicklen: usize,
    pub sendq_bytes: usize,
    pub core_queue: usize,
    #[serde(default = "default_core_workers")]
    pub core_workers: usize,
    pub max_hot_channels: usize,
    #[serde(default = "default_max_history_ring_bytes")]
    pub max_history_ring_bytes: usize,
    #[serde(default = "default_max_hot_history_bytes")]
    pub max_hot_history_bytes: usize,
    pub listeners: Vec<ListenerConfig>,
    pub registration: RegistrationConfig,
    pub limits: LimitsConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    pub bnc_addr: Option<SocketAddr>,
    /// The attach listener's certificate (`[bnc].tls`); required unless
    /// `bnc_addr` is a loopback address.
    #[serde(default)]
    pub bnc_tls: Option<TlsConfig>,
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
    /// The names (never values) of the settings that differ between this
    /// revision and `next`, as dotted paths into the nested tables
    /// (`limits.command_burst`); a list such as `motd` or `listeners` is one
    /// name. Derived from the serialized form so a new field cannot be left
    /// out of the audit detail.
    pub fn changed_fields(&self, next: &Self) -> Vec<String> {
        changed_paths(self, next, Lists::Whole)
    }

    /// Whether reaching `next` from this configuration needs a restart.
    ///
    /// The one definition of which settings apply live, so the answer an
    /// administrator is given cannot drift from what the process does: the BNC
    /// attach listener is rebound in place, and the observability sampler and
    /// storage maintenance each re-read their settings every cycle. Everything
    /// else is read once, at start. (Storage used to be missing here, so a
    /// retention-only change was reported as needing a restart it did not.)
    pub fn requires_restart_to_reach(&self, next: &Self) -> bool {
        let mut reached_live = self.clone();
        reached_live.bnc_addr = next.bnc_addr;
        reached_live.bnc_tls = next.bnc_tls.clone();
        reached_live.observability = next.observability.clone();
        reached_live.storage = next.storage.clone();
        reached_live != *next
    }

    pub fn from_config(
        config: &Config,
        key: Option<&crate::secret::SecretKeyring>,
    ) -> Result<Self, ConfigError> {
        let network_has_secret = config.networks.iter().any(|network| {
            network.sasl_password.is_some()
                || network.server_password.is_some()
                || (network.kind.account_is_secret() && network.sasl_account.is_some())
        });
        let credentials_from_bootstrap = key.is_none()
            && (!config.oidc_providers.is_empty()
                || !config.opers.is_empty()
                || network_has_secret);
        Ok(Self::with_secrets(
            config,
            credentials_from_bootstrap,
            |value: &str| {
                key.map_or_else(String::new, |key| {
                    key.seal(value, crate::secret::CONFIG_CONTEXT)
                })
            },
        ))
    }

    /// The settings `config` holds, every secret passed through `seal`.
    fn with_secrets(
        config: &Config,
        credentials_from_bootstrap: bool,
        seal: impl Fn(&str) -> String,
    ) -> Self {
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
            if let Some(password) = &network.server_password {
                network.server_password = Some(seal(password));
            }
            if network.kind.account_is_secret()
                && let Some(account) = &network.sasl_account
            {
                network.sasl_account = Some(seal(account));
            }
        }
        Self {
            server_name: config.server_name.clone(),
            network_name: config.network_name.clone(),
            description: config.description.clone(),
            motd: config.motd.clone(),
            nicklen: config.nicklen,
            sendq_bytes: config.sendq_bytes,
            core_queue: config.core_queue,
            core_workers: config.core_workers,
            max_hot_channels: config.max_hot_channels,
            max_history_ring_bytes: config.max_history_ring_bytes,
            max_hot_history_bytes: config.max_hot_history_bytes,
            listeners: config.listeners.clone(),
            registration: config.registration.clone(),
            limits: config.limits.clone(),
            observability: config.observability.clone(),
            storage: config.storage.clone(),
            bnc_addr: config.bnc.as_ref().map(|bnc| bnc.addr),
            bnc_tls: config.bnc.as_ref().and_then(|bnc| bnc.tls.clone()),
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
        }
    }

    /// The console-owned settings `config` states with a value other than the
    /// one this stored revision gives them, by bootstrap key path
    /// (`http.admin_accounts`, `oidc[0].client_secret`) and never by value.
    ///
    /// The comparison is between what the configuration states and what start
    /// would actually run with once this revision is applied to it
    /// ([`Self::apply_to`]), with the stored secrets opened by `key`. A setting
    /// the configuration does not state ([`Config::stated`]) is the console's
    /// alone and never differs. Secrets are compared in constant time, and
    /// only whether one differs survives the comparison.
    pub fn bootstrap_drift(
        &self,
        config: &Config,
        key: Option<&crate::secret::SecretKeyring>,
    ) -> Result<Vec<String>, ConfigError> {
        let mut effective = config.clone();
        self.apply_to(&mut effective);
        effective.resolve_secrets_with_key(key)?;
        let mut stated = Self::with_secrets(config, false, str::to_owned);
        let mut stored = Self::with_secrets(&effective, false, str::to_owned);
        reduce_secrets_to_equality(&mut stated, &mut stored);
        Ok(changed_paths(&stated, &stored, Lists::OfTablesByIndex)
            .iter()
            .filter_map(|path| bootstrap_path(path))
            .filter(|path| config.stated.covers(path))
            .collect())
    }

    /// The attach listener these settings describe, when enabled.
    pub fn bnc(&self) -> Option<BncConfig> {
        self.bnc_addr.map(|addr| BncConfig {
            addr,
            tls: self.bnc_tls.clone(),
        })
    }

    pub fn apply_to(&self, config: &mut Config) {
        // Each of them is set from this revision below.
        config.left_to_stored_settings.clear();
        config.server_name.clone_from(&self.server_name);
        config.network_name.clone_from(&self.network_name);
        config.description.clone_from(&self.description);
        config.motd.clone_from(&self.motd);
        config.nicklen = self.nicklen;
        config.sendq_bytes = self.sendq_bytes;
        config.core_queue = self.core_queue;
        config.core_workers = self.core_workers;
        config.max_hot_channels = self.max_hot_channels;
        config.max_history_ring_bytes = self.max_history_ring_bytes;
        config.max_hot_history_bytes = self.max_hot_history_bytes;
        config.listeners.clone_from(&self.listeners);
        config.registration = self.registration.clone();
        config.limits = self.limits.clone();
        config.observability = self.observability.clone();
        config.storage = self.storage.clone();
        config.bnc = self.bnc();
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

    /// Validate through the startup parser's one configuration choke point,
    /// and read every certificate the settings name as start reads them. The
    /// bootstrap values these settings are judged against are the running
    /// process's own ([`BootstrapContext`]): its HTTP listener, its release
    /// revision (which a `shauth` provider requires), its upstream policy. Only
    /// the database URL is an inert stand-in: the console cannot change it,
    /// and nothing here connects. A revision this accepts is one the next
    /// start accepts too; judged against a made-up release revision, a
    /// `shauth` provider saved and the next start refused it, and a listener's
    /// certificate paths were first read by that start.
    pub fn validate(&self, bootstrap: BootstrapContext) -> Result<(), ConfigError> {
        let mut config = Config {
            database: Some(DatabaseConfig {
                url: "postgresql://control-plane-validation"
                    .parse()
                    .expect("a literal database URL"),
                startup_wait_seconds: DEFAULT_STARTUP_WAIT_SECONDS,
                max_connections: None,
            }),
            http: Some(HttpConfig {
                addr: bootstrap
                    .http_listener
                    .unwrap_or_else(|| "127.0.0.1:0".parse().expect("literal socket address")),
                public_url: None,
                secure_cookies: false,
                admin_accounts: Vec::new(),
                hsts_include_subdomains: bootstrap.hsts_include_subdomains,
            }),
            internal_upstreams: bootstrap.internal_upstreams,
            application_release_revision: bootstrap.application_release_revision,
            ..Config::default()
        };
        self.apply_to(&mut config);
        config.validate()?;
        crate::certificate::load_configured(&config).map_err(|error| {
            ConfigError::Invalid(format!(
                "a configured TLS certificate cannot be used: {error}"
            ))
        })
    }
}

/// Why a database-backed start refuses: the configuration states console-owned
/// settings with values other than the stored revision's
/// ([`ManagedConfig::bootstrap_drift`]). Names each setting and never a value.
#[derive(Debug)]
pub struct ManagedSettingsConflict {
    /// Bootstrap key paths, as [`ManagedConfig::bootstrap_drift`] names them.
    pub settings: Vec<String>,
    /// The stored revision they were compared with, and who saved it when.
    pub revision: i64,
    pub updated_by: String,
    pub updated_at: String,
}

impl std::fmt::Display for ManagedSettingsConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "the configuration states {} setting(s) that the console owns with a value other \
             than the stored one (revision {}, saved by {} at {}):",
            self.settings.len(),
            self.revision,
            self.updated_by,
            self.updated_at
        )?;
        for setting in &self.settings {
            writeln!(
                f,
                "  {setting}: the stated value differs from the stored value"
            )?;
        }
        write!(
            f,
            "No value is shown: any of them may be a secret. After the first database-backed \
             start these settings belong to the console (/console/configuration), and a stated \
             value that differs is refused rather than ignored. For each one, either remove it \
             from the configuration file or environment so the stored value applies, or set it \
             to the stored value, or change it in the console and then restart with it stated \
             the same way."
        )?;
        if self
            .settings
            .iter()
            .any(|setting| setting == "http.admin_accounts")
        {
            write!(
                f,
                " An operator locked out of the console regains administrator access with \
                 `e6ircd recover-administrator`, which does not need the server started."
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for ManagedSettingsConflict {}

/// How [`changed_paths`] names a list that differs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Lists {
    /// As one name (`motd`, `listeners`): the audit detail's granularity.
    Whole,
    /// A list of tables of the same length on both sides by element and key
    /// (`oidc_providers[0].client_secret`), so a refusal can say which value
    /// differs; any other list as one name.
    OfTablesByIndex,
}

/// The dotted paths (never the values) at which two revisions differ. Derived
/// from the serialized form so a new field cannot be left out.
fn changed_paths(before: &ManagedConfig, after: &ManagedConfig, lists: Lists) -> Vec<String> {
    use serde_json::Value;
    fn collect(prefix: &str, before: &Value, after: &Value, lists: Lists, out: &mut Vec<String>) {
        match (before, after) {
            (Value::Object(before), Value::Object(after)) => {
                let keys: std::collections::BTreeSet<&String> =
                    before.keys().chain(after.keys()).collect();
                for key in keys {
                    let path = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    match (before.get(key), after.get(key)) {
                        (Some(b), Some(a)) => collect(&path, b, a, lists, out),
                        _ => out.push(path),
                    }
                }
            }
            (Value::Array(before), Value::Array(after))
                if lists == Lists::OfTablesByIndex
                    && before.len() == after.len()
                    && before.iter().chain(after).all(Value::is_object) =>
            {
                for (index, (b, a)) in before.iter().zip(after).enumerate() {
                    collect(&format!("{prefix}[{index}]"), b, a, lists, out);
                }
            }
            _ if before != after => out.push(prefix.to_string()),
            _ => {}
        }
    }
    let mut changed = Vec::new();
    let (before, after) = (
        serde_json::to_value(before).expect("managed configuration serializes"),
        serde_json::to_value(after).expect("managed configuration serializes"),
    );
    collect("", &before, &after, lists, &mut changed);
    changed
}

/// Where a [`ManagedConfig`] path is stated in a configuration document: the
/// same key, except for the settings a document keeps under `[http]` or
/// `[bnc]` or under a table-array name. `None` for what no document states.
fn bootstrap_path(managed: &str) -> Option<String> {
    let (field, rest) = managed.split_at(managed.find(['.', '[']).unwrap_or(managed.len()));
    let key = match field {
        "public_url" => "http.public_url",
        "secure_cookies" => "http.secure_cookies",
        "admin_accounts" => "http.admin_accounts",
        "bnc_addr" => "bnc.addr",
        "bnc_tls" => "bnc.tls",
        "oidc_providers" => "oidc",
        "opers" => "oper",
        "networks" => "network",
        // Derived from whether a master key is present; never stated.
        "credentials_from_bootstrap" => return None,
        same => same,
    };
    Some(format!("{key}{rest}"))
}

/// Replace every secret of two revisions with a marker recording only whether
/// it equals the secret in the same position of the other, judged in constant
/// time. The comparison that follows then sees that a secret differs and
/// nothing else about it. A secret with no counterpart is in a list whose
/// length differs, which that comparison reports whole without reading it.
fn reduce_secrets_to_equality(left: &mut ManagedConfig, right: &mut ManagedConfig) {
    fn reduce(left: &mut String, right: &mut String) {
        let equal =
            aws_lc_rs::constant_time::verify_slices_are_equal(left.as_bytes(), right.as_bytes())
                .is_ok();
        left.clear();
        right.clear();
        if !equal {
            right.push_str("differs");
        }
    }
    fn reduce_optional(left: &mut Option<String>, right: &mut Option<String>) {
        // One side absent differs by shape; no content is compared.
        if let (Some(left), Some(right)) = (left, right) {
            reduce(left, right);
        }
    }
    for (l, r) in left
        .oidc_providers
        .iter_mut()
        .zip(&mut right.oidc_providers)
    {
        reduce(&mut l.client_secret, &mut r.client_secret);
    }
    for (l, r) in left.opers.iter_mut().zip(&mut right.opers) {
        reduce(&mut l.password, &mut r.password);
    }
    for (l, r) in left.networks.iter_mut().zip(&mut right.networks) {
        reduce_optional(&mut l.sasl_password, &mut r.sasl_password);
        reduce_optional(&mut l.server_password, &mut r.server_password);
        if l.kind.account_is_secret() || r.kind.account_is_secret() {
            reduce_optional(&mut l.sasl_account, &mut r.sasl_account);
        }
    }
}

/// The bootstrap values a managed-settings revision is judged against. They
/// come from the file or environment the process started with — the console
/// cannot change them — yet a managed value is valid only together with them.
#[derive(Debug, Clone)]
pub struct BootstrapContext {
    /// The address the running HTTP listener was configured with, so a
    /// listener or bouncer address edited in the console is checked against
    /// it. `None`: there is no HTTP listener for anything to collide with.
    pub http_listener: Option<std::net::SocketAddr>,
    /// `[http].hsts_include_subdomains`, which needs an `https://` public
    /// origin — and the public origin is a managed setting.
    pub hsts_include_subdomains: bool,
    /// The policy that decides whether a network may name an upstream inside
    /// this host's own network.
    pub internal_upstreams: crate::egress::InternalUpstreams,
    /// `application_release_revision`, which the `shauth` provider requires to
    /// be an immutable revision — and the providers are managed settings.
    pub application_release_revision: Option<String>,
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

/// The master-key material the process environment states, read once so the
/// keyring can be resolved against a stated environment rather than the live
/// one (which tests cannot set without racing each other).
pub struct EnvironmentSecretKeys {
    /// `E6IRC_SECRET_KEY`: the base64 primary key.
    pub primary: Option<String>,
    /// `E6IRC_PREVIOUS_SECRET_KEYS`: comma-separated base64 fallback keys.
    pub previous: Option<String>,
}

impl EnvironmentSecretKeys {
    const PRIMARY_VARIABLE: &'static str = "E6IRC_SECRET_KEY";
    const PREVIOUS_VARIABLE: &'static str = "E6IRC_PREVIOUS_SECRET_KEYS";

    /// Read by the environment's one rule (`environment_config::optional`): a
    /// variable set but empty is unset, so `E6IRC_SECRET_KEY=` beside a
    /// `[secrets].key_file` is no conflict and is no key either.
    pub fn from_process() -> Result<Self, ConfigError> {
        let read = |variable: &'static str| {
            crate::environment_config::optional(
                &crate::environment_config::process_environment,
                variable,
            )
            .map_err(|error| ConfigError::Invalid(error.to_string()))
        };
        Ok(Self {
            primary: read(Self::PRIMARY_VARIABLE)?,
            previous: read(Self::PREVIOUS_VARIABLE)?,
        })
    }

    /// The name of a set variable, for a refusal that names its source.
    fn first_set_variable(&self) -> Option<&'static str> {
        if self.primary.is_some() {
            Some(Self::PRIMARY_VARIABLE)
        } else if self.previous.is_some() {
            Some(Self::PREVIOUS_VARIABLE)
        } else {
            None
        }
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkEntry {
    /// Selector used by clients (the /network suffix on the nick).
    pub name: String,
    /// Driver kind: an outbound `irc` upstream or the in-process `local`
    /// network (this e6ircd itself).
    pub kind: NetworkKind,
    /// e6irc account that owns this network. When set, only that account
    /// may attach to it; when absent the network is shared (any
    /// authenticated account may attach). Per-user self-service creation
    /// (DB-backed) reuses this ownership.
    #[serde(default)]
    pub owner: Option<String>,
    /// IRC `host:port` or a bridge's HTTP(S) provider base. An explicit empty
    /// value selects a bridge provider default. Ignored for `local`.
    pub addr: String,
    /// IRC transport security. Bridge entries require `true` as the canonical
    /// marker that the transport is HTTP(S), whose URL scheme controls security.
    pub tls: bool,
    pub nick: String,
    /// The `USER` name (ident) an `irc` or `local` network registers with.
    /// Stated, never derived from the nick: a legal nickname (`_bot`) is not a
    /// legal user name. Bridges have none.
    #[serde(default)]
    pub username: Option<String>,
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
    /// The IRC server password sent as `PASS` before registration. `irc`
    /// only; sealed at rest like `sasl_password`.
    #[serde(default)]
    pub server_password: Option<String>,
}

fn default_bnc_buffer() -> usize {
    1000
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum NetworkEntryWire {
    Irc {
        #[serde(flatten)]
        common: NetworkEntryCommon,
        nick: String,
        username: String,
        realname: String,
        sasl_account: Option<String>,
        sasl_password: Option<String>,
        server_password: Option<String>,
    },
    Local {
        #[serde(flatten)]
        common: NetworkEntryCommon,
        nick: String,
        username: String,
        realname: String,
    },
    Matrix {
        #[serde(flatten)]
        common: NetworkEntryCommon,
        nick: String,
        sasl_password: String,
    },
    Discord {
        #[serde(flatten)]
        common: NetworkEntryCommon,
        sasl_password: String,
    },
    Slack {
        #[serde(flatten)]
        common: NetworkEntryCommon,
        sasl_account: String,
        sasl_password: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetworkEntryCommon {
    #[serde(default)]
    revision: Option<i64>,
    name: String,
    owner: Option<String>,
    addr: String,
    tls: bool,
    autojoin: Vec<String>,
    buffer_cap: usize,
}

impl From<NetworkEntryWire> for NetworkEntry {
    fn from(value: NetworkEntryWire) -> Self {
        match value {
            NetworkEntryWire::Irc {
                common,
                nick,
                username,
                realname,
                sasl_account,
                sasl_password,
                server_password,
            } => NetworkEntry {
                username: Some(username),
                server_password,
                ..common.into_entry(
                    NetworkKind::Irc,
                    nick,
                    Some(realname),
                    sasl_account,
                    sasl_password,
                )
            },
            NetworkEntryWire::Local {
                common,
                nick,
                username,
                realname,
            } => NetworkEntry {
                username: Some(username),
                ..common.into_entry(NetworkKind::Local, nick, Some(realname), None, None)
            },
            NetworkEntryWire::Matrix {
                common,
                nick,
                sasl_password,
            } => common.into_entry(NetworkKind::Matrix, nick, None, None, Some(sasl_password)),
            NetworkEntryWire::Discord {
                common,
                sasl_password,
            } => common.into_entry(
                NetworkKind::Discord,
                String::new(),
                None,
                None,
                Some(sasl_password),
            ),
            NetworkEntryWire::Slack {
                common,
                sasl_account,
                sasl_password,
            } => common.into_entry(
                NetworkKind::Slack,
                String::new(),
                None,
                Some(sasl_account),
                Some(sasl_password),
            ),
        }
    }
}

impl NetworkEntryCommon {
    fn into_entry(
        self,
        kind: NetworkKind,
        nick: String,
        realname: Option<String>,
        sasl_account: Option<String>,
        sasl_password: Option<String>,
    ) -> NetworkEntry {
        NetworkEntry {
            name: self.name,
            owner: self.owner,
            kind,
            addr: self.addr,
            tls: self.tls,
            nick,
            username: None,
            realname,
            autojoin: self.autojoin,
            buffer_cap: self.buffer_cap,
            sasl_account,
            sasl_password,
            server_password: None,
        }
    }
}

impl NetworkEntryWire {
    pub(crate) fn into_network_entry(self) -> NetworkEntry {
        self.into()
    }

    pub(crate) fn revision(&self) -> Option<i64> {
        match self {
            Self::Irc { common, .. }
            | Self::Local { common, .. }
            | Self::Matrix { common, .. }
            | Self::Discord { common, .. }
            | Self::Slack { common, .. } => common.revision,
        }
    }
}

impl NetworkEntry {
    pub(crate) fn normalized_connection_intent(mut self) -> Self {
        self.name = self.name.trim().to_string();
        self.owner = self.owner.map(|owner| owner.trim().to_string());
        self.addr = self.addr.trim().to_string();
        self.nick = self.nick.trim().to_string();
        self.username = self.username.map(|username| username.trim().to_string());
        self.realname = self.realname.map(|realname| realname.trim().to_string());
        self.autojoin = self
            .autojoin
            .into_iter()
            .map(|channel| channel.trim().to_string())
            .collect();
        // An IRC account name is public text and may be tidied; a secret — a
        // SASL password, a Slack bot token carried in `sasl_account`, a server
        // password — is kept verbatim: trimming would store another one.
        if !self.kind.account_is_secret() {
            self.sasl_account = self.sasl_account.map(|account| account.trim().to_string());
        }
        self
    }

    /// Validate fields shared by every configuration ingress.
    pub(crate) fn validate_connection_intent(&self) -> Result<(), String> {
        if self.buffer_cap > MAX_NETWORK_BUFFER_CAP {
            return Err(format!(
                "buffer_cap must be at most {MAX_NETWORK_BUFFER_CAP}"
            ));
        }
        if !crate::sanitize::valid_network_name(&self.name) {
            return Err(
                "network name must be a 1-64 byte path-safe token (letters, digits, '-', '_' or '.')"
                    .into(),
            );
        }
        if self
            .owner
            .as_deref()
            .is_some_and(|owner| owner.trim().is_empty())
        {
            return Err("network owner must be non-blank when set".into());
        }
        if self.buffer_cap == 0 {
            return Err("buffer_cap must be nonzero".into());
        }
        if self
            .autojoin
            .iter()
            .any(|channel| channel.trim().is_empty())
        {
            return Err("autojoin entries must be non-blank".into());
        }
        if self.server_password.is_some() && self.kind != NetworkKind::Irc {
            return Err(format!(
                "kind={} does not accept server_password; it applies only to kind=irc",
                self.kind.as_db_str()
            ));
        }
        self.validate_credential_contents()?;
        match self.kind {
            NetworkKind::Irc => {
                if self.sasl_account.is_some() != self.sasl_password.is_some() {
                    return Err(
                        "kind=irc requires both sasl_account and sasl_password, or neither".into(),
                    );
                }
                self.upstream_identity()?;
                if !crate::bouncer::validate_irc_upstream_addr(&self.addr) {
                    return Err(
                        "kind=irc requires addr as host:port with a nonzero numeric port".into(),
                    );
                }
            }
            NetworkKind::Local => {
                self.upstream_identity()?;
            }
            NetworkKind::Matrix | NetworkKind::Discord | NetworkKind::Slack => {
                if !self.tls {
                    return Err(format!(
                        "kind={} requires tls=true as its HTTP transport marker",
                        self.kind.as_db_str()
                    ));
                }
                if self.realname.is_some() {
                    return Err(format!(
                        "kind={} does not accept realname",
                        self.kind.as_db_str()
                    ));
                }
                if self.username.is_some() {
                    return Err(format!(
                        "kind={} does not accept username",
                        self.kind.as_db_str()
                    ));
                }
                if matches!(self.kind, NetworkKind::Discord | NetworkKind::Slack)
                    && !self.nick.is_empty()
                {
                    return Err(format!(
                        "kind={} does not accept nick",
                        self.kind.as_db_str()
                    ));
                }
                if matches!(self.kind, NetworkKind::Matrix | NetworkKind::Discord)
                    && self.sasl_account.is_some()
                {
                    return Err(format!(
                        "kind={} does not accept sasl_account",
                        self.kind.as_db_str()
                    ));
                }
                crate::bouncer::validate_bridge_base(self.kind, &self.addr)?;
                if self.kind == NetworkKind::Matrix && self.nick.trim().is_empty() {
                    return Err("kind=matrix requires a non-blank nick".into());
                }
                if matches!(self.kind, NetworkKind::Matrix | NetworkKind::Discord)
                    && self.sasl_password.is_none()
                {
                    return Err(format!(
                        "kind={} requires sasl_password",
                        self.kind.as_db_str()
                    ));
                }
                if self.kind == NetworkKind::Slack
                    && (self.sasl_account.is_none() || self.sasl_password.is_none())
                {
                    return Err("kind=slack requires sasl_account and sasl_password".into());
                }
            }
        }
        Ok(())
    }
}

impl NetworkEntry {
    /// What the credential fields contain, each named by its field and never
    /// quoted. A sealed value is skipped here — its ciphertext says nothing
    /// about the secret — and judged once it is opened, when
    /// [`Config::validate_secrets`] runs this again with nothing left sealed.
    fn validate_credential_contents(&self) -> Result<(), String> {
        fn opened(value: &Option<String>) -> Option<&str> {
            value
                .as_deref()
                .filter(|value| !crate::secret::is_sealed(value))
        }
        if let Some(account) = opened(&self.sasl_account) {
            crate::bouncer::validate_network_credential(account, 255)
                .map_err(|error| format!("invalid sasl_account: {error}"))?;
        }
        if let Some(password) = opened(&self.sasl_password) {
            crate::bouncer::validate_network_credential(password, 512)
                .map_err(|error| format!("invalid sasl_password: {error}"))?;
        }
        if let Some(password) = opened(&self.server_password) {
            e6irc_client::ServerPassword::parse(password.to_string())
                .map_err(|error| format!("invalid server_password: {error}"))?;
        }
        Ok(())
    }

    /// The identity the `irc` or `local` driver built from this entry presents,
    /// parsed by the one parser that builds the driver
    /// ([`crate::bouncer::UpstreamIdentity::parse`]): validating an entry and
    /// starting it cannot disagree about its nick, user name, real name or
    /// channels. A configured network's autojoin names channels only, so an
    /// entry is one channel and `#ops key` is refused as a channel name.
    pub(crate) fn upstream_identity(&self) -> Result<crate::bouncer::UpstreamIdentity, String> {
        let kind = self.kind.as_db_str();
        let username = self.username.as_deref().ok_or_else(|| {
            format!(
                "kind={kind} requires username (the IRC user name sent in USER; it is never \
                 derived from the nick)"
            )
        })?;
        let realname = self
            .realname
            .as_deref()
            .ok_or_else(|| format!("kind={kind} requires realname"))?;
        crate::bouncer::UpstreamIdentity::parse(
            &self.nick,
            username,
            realname,
            &self.autojoin_entries(),
        )
        .map_err(|error| format!("kind={kind} has invalid {error}"))
    }

    /// The autojoin list as the driver takes it. A server-level network's
    /// autojoin is public configuration (the administrator API returns it), so
    /// it names channels only: an entry with a key in it is refused by the
    /// channel grammar rather than read as a key nobody could keep secret.
    pub(crate) fn autojoin_entries(&self) -> Vec<crate::bouncer::AutojoinEntry> {
        self.autojoin
            .iter()
            .map(|channel| crate::bouncer::AutojoinEntry::unkeyed(channel.as_str()))
            .collect()
    }
}

/// Address ranges as a client's canonical address is matched against them: an
/// IPv4-mapped range is its IPv4 equivalent, and one shorter than `/96` (which
/// spans non-IPv4 addresses too) is refused rather than kept unmatchable.
fn deserialize_canonical_networks<'de, D>(deserializer: D) -> Result<Vec<ipnet::IpNet>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Vec::<ipnet::IpNet>::deserialize(deserializer)?
        .into_iter()
        .map(|net| {
            crate::net::canonical_network(net).ok_or_else(|| {
                serde::de::Error::custom(format!(
                    "{net} is an IPv4-mapped range shorter than /96, which also spans \
                     addresses that are not IPv4; write the IPv4 range instead"
                ))
            })
        })
        .collect()
}

fn deserialize_static_networks<'de, D>(deserializer: D) -> Result<Vec<NetworkEntry>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Vec::<NetworkEntryWire>::deserialize(deserializer).and_then(|entries| {
        entries
            .into_iter()
            .map(|entry| {
                if entry.revision().is_some() {
                    return Err(serde::de::Error::custom(
                        "static network configuration does not accept revision",
                    ));
                }
                let network = NetworkEntry::from(entry);
                network
                    .validate_connection_intent()
                    .map_err(serde::de::Error::custom)?;
                Ok(network)
            })
            .collect()
    })
}

/// Which driver backs a BNC network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkKind {
    /// A persistent outbound IRC client to an external network.
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BncConfig {
    pub addr: SocketAddr,
    /// The certificate the attach listener serves. Attaching clients send
    /// their account password (SASL PLAIN), so a listener on any address but
    /// loopback must set this ([`Config::validate`] refuses it otherwise).
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperConfig {
    pub name: String,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpConfig {
    pub addr: SocketAddr,
    /// Externally reachable base URL for browser and device links.
    /// Required for OIDC, device login, and account invitations.
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
    /// Add `includeSubDomains` to the HSTS header an `https://` public origin
    /// is served with. Off by default: it commits every subdomain of the host
    /// to HTTPS for a year, which only the operator knows to be true. The
    /// header never asks for preloading, which no configuration can revoke.
    #[serde(default)]
    pub hsts_include_subdomains: bool,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapConfig {
    /// High-entropy one-time secret entered in the first-run browser form.
    /// Stated from the environment it is never written to a file, and the HTTP
    /// state retains only its SHA-256 digest.
    pub token: String,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OidcProviderConfig {
    /// URL path segment and display name, e.g. "corp".
    pub name: String,
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    /// Claim used as the local account name.
    pub account_claim: OidcAccountClaim,
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
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OidcAccountClaim {
    PreferredUsername,
    Email,
}

/// Client authentication methods e6irc supports at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuthMethod {
    /// HTTP Basic credentials, the OAuth 2.0 default.
    ClientSecretBasic,
    /// Credentials in the request body, which Shauth's registrations require.
    ClientSecretPost,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    pub url: crate::db::DatabaseUrl,
    /// How long startup keeps retrying the first connection (doubling backoff,
    /// capped at 30 s, one line per attempt) before the process exits
    /// non-zero. `0` makes one attempt. A database that comes up after this
    /// process (a container ordering, a restart) is the case it exists for;
    /// its ceiling is [`crate::db::StartupDatabaseWait::MAX_SECONDS`].
    #[serde(default = "default_startup_wait_seconds")]
    pub startup_wait_seconds: u64,
    /// The most connections the server's shared pool opens, between
    /// [`crate::db::DatabasePoolSize::MIN`] and
    /// [`crate::db::DatabasePoolSize::MAX`] (refused outside them when the
    /// file is read). Absent, the pool is sized to this host by
    /// [`crate::db::DatabasePoolSize::for_this_host`]: one for the serial
    /// database worker, one per concurrent Argon2 computation, and two per
    /// runtime worker thread.
    #[serde(default)]
    pub max_connections: Option<crate::db::DatabasePoolSize>,
}

impl DatabaseConfig {
    /// The pool size the server opens: the configured one, else the default.
    pub fn pool_size(&self) -> crate::db::DatabasePoolSize {
        self.max_connections
            .unwrap_or_else(crate::db::DatabasePoolSize::for_this_host)
    }
}

/// What a secret-bearing configuration value shows in `Debug` output.
///
/// After `resolve_secrets` these structures hold opened plaintext, so their
/// `Debug` is written by hand to show only whether a secret is set. Each impl
/// destructures its struct exhaustively: a field added later fails to compile
/// until it is placed, redacted or not, rather than appearing by default.
const REDACTED: &str = "<redacted>";

fn redacted_option(value: &Option<String>) -> Option<&'static str> {
    value.as_ref().map(|_| REDACTED)
}

impl std::fmt::Debug for NetworkEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            name,
            kind,
            owner,
            addr,
            tls,
            nick,
            username,
            realname,
            autojoin,
            buffer_cap,
            sasl_account,
            sasl_password,
            server_password,
        } = self;
        f.debug_struct("NetworkEntry")
            .field("name", name)
            .field("kind", kind)
            .field("owner", owner)
            .field("addr", addr)
            .field("tls", tls)
            .field("nick", nick)
            .field("username", username)
            .field("realname", realname)
            .field("autojoin", autojoin)
            .field("buffer_cap", buffer_cap)
            // A Slack bot token for a Slack entry.
            .field("sasl_account", &redacted_option(sasl_account))
            .field("sasl_password", &redacted_option(sasl_password))
            .field("server_password", &redacted_option(server_password))
            .finish()
    }
}

impl std::fmt::Debug for OperConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { name, password: _ } = self;
        f.debug_struct("OperConfig")
            .field("name", name)
            .field("password", &REDACTED)
            .finish()
    }
}

impl std::fmt::Debug for BootstrapConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { token: _ } = self;
        f.debug_struct("BootstrapConfig")
            .field("token", &REDACTED)
            .finish()
    }
}

impl std::fmt::Debug for OidcProviderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            name,
            issuer_url,
            client_id,
            client_secret: _,
            account_claim,
            scopes,
            allowed_email_domains,
            end_session_endpoint,
            token_endpoint_auth_method,
        } = self;
        f.debug_struct("OidcProviderConfig")
            .field("name", name)
            .field("issuer_url", issuer_url)
            .field("client_id", client_id)
            .field("client_secret", &REDACTED)
            .field("account_claim", account_claim)
            .field("scopes", scopes)
            .field("allowed_email_domains", allowed_email_domains)
            .field("end_session_endpoint", end_session_endpoint)
            .field("token_endpoint_auth_method", token_endpoint_auth_method)
            .finish()
    }
}

impl std::fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            url,
            startup_wait_seconds,
            max_connections,
        } = self;
        // The URL shows everything but its password (`DatabaseUrl`'s `Debug`).
        f.debug_struct("DatabaseConfig")
            .field("url", url)
            .field("startup_wait_seconds", startup_wait_seconds)
            .field("max_connections", max_connections)
            .finish()
    }
}

pub const DEFAULT_STARTUP_WAIT_SECONDS: u64 = 300;

const fn default_startup_wait_seconds() -> u64 {
    DEFAULT_STARTUP_WAIT_SECONDS
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
            sendq_bytes: default_sendq_bytes(),
            core_queue: default_core_queue(),
            core_workers: default_core_workers(),
            max_hot_channels: default_max_hot_channels(),
            max_history_ring_bytes: default_max_history_ring_bytes(),
            max_hot_history_bytes: default_max_hot_history_bytes(),
            database: None,
            http: None,
            bootstrap: None,
            oidc_providers: Vec::new(),
            application_release_revision: None,
            opers: Vec::new(),
            networks: Vec::new(),
            bnc: None,
            internal_upstreams: crate::egress::InternalUpstreams::Refuse,
            secrets: None,
            limits: LimitsConfig::default(),
            observability: ObservabilityConfig::default(),
            storage: StorageConfig::default(),
            stated: StatedSettings::Everything,
            left_to_stored_settings: Vec::new(),
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
        // Deserialized from the text rather than from its table, so a value of
        // the wrong shape keeps the position the refusal reports it by.
        let mut config: Self = toml::from_str(&text).map_err(ConfigError::Parse)?;
        let document: toml::Table = toml::from_str(&text).map_err(ConfigError::Parse)?;
        config.stated = StatedSettings::of_document(&document, &[]);
        config.left_to_stored_settings = left_out_of(&document);
        Self::checked(config)
    }

    /// A configuration stated as a document: a file's, or one built in memory
    /// (the container environment; see `environment_config`), which gets
    /// exactly the validation a file does. `defaulted` names the keys the
    /// builder filled with its own defaults rather than an operator's
    /// statement, so they are not held to the stored console settings.
    pub fn from_table(table: toml::Table, defaulted: &[&str]) -> Result<Self, ConfigError> {
        let stated = StatedSettings::of_document(&table, defaulted);
        let left_to_stored_settings = left_out_of(&table);
        let mut config: Self = table.try_into().map_err(ConfigError::Parse)?;
        config.stated = stated;
        config.left_to_stored_settings = left_to_stored_settings;
        Self::checked(config)
    }

    /// Structure and non-secret content are checked first; then sealed secrets
    /// are opened; then the rules about what a secret *contains* run on the
    /// opened text (`validate_secrets`). Run before opening, those rules would
    /// judge the ciphertext — an `enc:v2:` bootstrap token is always long
    /// enough, and a sealed client secret that opens to nothing is never empty.
    fn checked(mut config: Self) -> Result<Self, ConfigError> {
        config.validate()?;
        config.resolve_secrets()?;
        config.validate_secrets()?;
        Ok(config)
    }

    /// Resolve the primary and rotation fallback keys from `[secrets]` or the
    /// process environment (`E6IRC_SECRET_KEY`, and comma-separated
    /// `E6IRC_PREVIOUS_SECRET_KEYS` for read-only fallbacks). The two sources
    /// are alternatives: a configuration that states both is refused rather
    /// than one being silently ignored.
    pub fn secret_keyring(&self) -> Result<Option<crate::secret::SecretKeyring>, ConfigError> {
        self.secret_keyring_from(EnvironmentSecretKeys::from_process()?)
    }

    /// Why every client would share one HTTP authentication budget, when this
    /// configuration makes that certain: the throttle is on (the default since
    /// 0088), no `limits.trusted_proxies` is set, and the HTTP listener binds
    /// only a loopback address — so every request arrives from this host, which
    /// in a deployment is a reverse proxy, and twenty sign-ins a minute is the
    /// budget of all of them together. A listener bound wider may or may not
    /// sit behind a proxy, which nothing here can see; the upgrade notes say
    /// what to set then.
    pub(crate) fn shared_authentication_budget(&self) -> Option<String> {
        let http = self.http.as_ref()?;
        let burst = self.limits.auth_rate_burst.burst()?;
        if !self.limits.trusted_proxies.is_empty() || !http.addr.ip().to_canonical().is_loopback() {
            return None;
        }
        Some(format!(
            "the HTTP authentication throttle (limits.auth_rate_burst, {burst} a minute per \
             address) is on and the HTTP listener binds only {}, so every request comes from \
             this host: behind a reverse proxy every user shares one budget. Set \
             limits.trusted_proxies to the proxy's address so each client is counted by the \
             address it forwards, or set limits.auth_rate_burst = \"off\" if the proxy throttles \
             these routes itself",
            http.addr.ip()
        ))
    }

    fn secret_keyring_from(
        &self,
        environment: EnvironmentSecretKeys,
    ) -> Result<Option<crate::secret::SecretKeyring>, ConfigError> {
        use crate::secret::{SecretKey, SecretKeyring};
        if let Some(s) = &self.secrets {
            if let Some(variable) = environment.first_set_variable() {
                return Err(ConfigError::Invalid(format!(
                    "[secrets].key_file ({}) and the {variable} environment variable both \
                     name a master key; state it once — remove one of them",
                    s.key_file.display()
                )));
            }
            let raw = std::fs::read_to_string(&s.key_file).map_err(|e| {
                ConfigError::Invalid(format!(
                    "cannot read secrets key_file {}: {e}",
                    s.key_file.display()
                ))
            })?;
            let primary = SecretKey::from_base64_text(raw)
                .map_err(|e| ConfigError::Invalid(format!("secrets key_file: {e}")))?;
            let mut previous = Vec::with_capacity(s.previous_key_files.len());
            for path in &s.previous_key_files {
                let raw = std::fs::read_to_string(path).map_err(|e| {
                    ConfigError::Invalid(format!(
                        "cannot read secrets previous_key_file {}: {e}",
                        path.display()
                    ))
                })?;
                previous.push(SecretKey::from_base64_text(raw).map_err(|e| {
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
        let primary = environment
            .primary
            .as_deref()
            .map(|value| {
                SecretKey::from_base64(value)
                    .map_err(|e| ConfigError::Invalid(format!("E6IRC_SECRET_KEY: {e}")))
            })
            .transpose()?;
        let previous = match environment.previous.as_deref() {
            Some(value) => {
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
            None => Vec::new(),
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

    /// Rules about what a secret-bearing field contains, judged on the opened
    /// text — so they run after `resolve_secrets`, never on an `enc:v2:` blob.
    /// Everything about a configuration that is not a secret's content is
    /// `validate`'s.
    pub fn validate_secrets(&self) -> Result<(), ConfigError> {
        if let Some(bootstrap) = &self.bootstrap
            && (!(32..=512).contains(&bootstrap.token.len())
                || bootstrap.token.chars().any(char::is_control))
        {
            return Err(ConfigError::Invalid(
                "bootstrap.token must contain 32–512 bytes and no control characters".into(),
            ));
        }
        for provider in &self.oidc_providers {
            if provider.client_secret.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "OIDC provider '{}' requires a non-empty client_secret",
                    provider.name
                )));
            }
        }
        for network in &self.networks {
            network.validate_credential_contents().map_err(|error| {
                ConfigError::Invalid(format!("network '{}': {error}", network.name))
            })?;
        }
        // An empty oper password would let `OPER <name> ""` succeed.
        for oper in &self.opers {
            if oper.password.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "[[oper]] '{}' requires a non-empty password",
                    oper.name
                )));
            }
        }
        Ok(())
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
            if let Some(password) = net.server_password.take() {
                net.server_password = Some(open_secret(&password, key)?);
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

    /// Refuse two listening sockets that cannot both bind.
    ///
    /// Left to the system, the second bind fails at start as a bare "address
    /// already in use" that names neither section. Two sockets collide when
    /// they ask for the same nonzero port on the same address, or on a wildcard
    /// address of the same family (`0.0.0.0` covers every IPv4 address), or when
    /// one is `[::]` and the other any IPv4 address: the daemon binds `[::]`
    /// dual-stack on every platform (`net::bind_listener`), so it covers every
    /// IPv4 address too. Port 0 asks for any free port and never collides.
    fn refuse_colliding_listeners(&self) -> Result<(), ConfigError> {
        let mut sockets: Vec<(String, std::net::SocketAddr)> = self
            .listeners
            .iter()
            .enumerate()
            .map(|(index, listener)| (format!("[[listeners]] #{}", index + 1), listener.addr))
            .collect();
        sockets.extend(
            self.http
                .iter()
                .map(|http| ("[http]".to_string(), http.addr)),
        );
        sockets.extend(self.bnc.iter().map(|bnc| ("[bnc]".to_string(), bnc.addr)));
        let dual_stack_over = |wide: std::net::SocketAddr, other: std::net::SocketAddr| {
            wide.is_ipv6() && wide.ip().is_unspecified() && other.is_ipv4()
        };
        let collide = |left: std::net::SocketAddr, right: std::net::SocketAddr| {
            left.port() != 0
                && left.port() == right.port()
                && ((left.is_ipv4() == right.is_ipv4()
                    && (left.ip() == right.ip()
                        || left.ip().is_unspecified()
                        || right.ip().is_unspecified()))
                    || dual_stack_over(left, right)
                    || dual_stack_over(right, left))
        };
        for (index, (first, first_addr)) in sockets.iter().enumerate() {
            for (second, second_addr) in &sockets[index + 1..] {
                if collide(*first_addr, *second_addr) {
                    return Err(ConfigError::Invalid(format!(
                        "{first} ({first_addr}) and {second} ({second_addr}) cannot both listen: they ask for the same address and port"
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.left_to_stored_settings.is_empty() && self.database.is_none() {
            return Err(ConfigError::Invalid(format!(
                "{} required: only a configuration with [database] may leave {} to the \
                 settings the console stores",
                self.left_to_stored_settings.join(", "),
                if self.left_to_stored_settings.len() == 1 {
                    "it"
                } else {
                    "them"
                }
            )));
        }
        if self.listeners.is_empty() && !self.left_to_stored_settings.contains(&"listeners") {
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
        if self.bootstrap.is_some() && (self.database.is_none() || self.http.is_none()) {
            return Err(ConfigError::Invalid(
                "[bootstrap] requires both [database] and [http]".into(),
            ));
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
        let left_to_stored = |key: &str| self.left_to_stored_settings.contains(&key);
        if !left_to_stored("server_name")
            && (self.server_name.is_empty()
                || !self
                    .server_name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'))
        {
            return Err(ConfigError::Invalid(
                "server_name must be a hostname (ASCII letters, digits, '.', '-')".into(),
            ));
        }
        // server_name is in the fixed head of every numeric; an unbounded value
        // inflates every line's overhead and is the largest lever for pushing a
        // reply past the 512-byte wire limit. A hostname fits well within 64.
        if self.server_name.len() > MAX_SERVER_NAME_LEN {
            return Err(ConfigError::Invalid(format!(
                "server_name must be at most {MAX_SERVER_NAME_LEN} bytes"
            )));
        }
        // network_name becomes the ISUPPORT `NETWORK=` token, a space-delimited
        // 005 middle param — a space (or control char) would split it into two
        // malformed tokens. Reject at load rather than emit a broken numeric.
        if !left_to_stored("network_name")
            && (self.network_name.is_empty()
                || self
                    .network_name
                    .contains(|c: char| c == ' ' || c.is_control()))
        {
            return Err(ConfigError::Invalid(
                "network_name must be a single token (no spaces or control characters)".into(),
            ));
        }
        // NETWORK= is a 005 middle; `numeric` would silently clip an over-long
        // value rather than advertise it faithfully. Bound it at load instead.
        if self.network_name.len() > MAX_NETWORK_NAME_LEN {
            return Err(ConfigError::Invalid(format!(
                "network_name must be at most {MAX_NETWORK_NAME_LEN} bytes"
            )));
        }
        // The description is RPL_LINKS' `<server info>` and each motd line an
        // RPL_MOTD's text: `numeric_line` would clip an over-long one on the
        // wire without a word, so each is bounded here, against the longest
        // server name and nickname, like the names above.
        if self.description.len() > MAX_DESCRIPTION_LEN {
            return Err(ConfigError::Invalid(format!(
                "description must be at most {MAX_DESCRIPTION_LEN} bytes (it is {}): longer \
                 would be cut short in the RPL_LINKS reply that carries it",
                self.description.len()
            )));
        }
        let motd_bytes = motd_reply_bytes(&self.motd);
        if motd_bytes > MAX_MOTD_BYTES {
            return Err(ConfigError::Invalid(format!(
                "motd must take at most {MAX_MOTD_BYTES} bytes as sent at registration (it takes \
                 {motd_bytes}: its lines together at most {MAX_MOTD_LINES_BYTES} bytes, each \
                 counting {MOTD_LINE_REPLY_OVERHEAD} more for its reply): a new client is sent the \
                 whole MOTD before it reads anything, and a longer one need not fit the smallest \
                 SendQ ({MIN_SENDQ_BYTES} bytes) beside the rest of that burst"
            )));
        }
        if let Some((index, line)) = self
            .motd
            .iter()
            .enumerate()
            .find(|(_, line)| line.len() > MAX_MOTD_LINE_LEN)
        {
            return Err(ConfigError::Invalid(format!(
                "motd line {} must be at most {MAX_MOTD_LINE_LEN} bytes (it is {}): longer would \
                 be cut short in the RPL_MOTD reply that carries it",
                index + 1,
                line.len()
            )));
        }
        if self.nicklen == 0
            || self.core_queue == 0
            || self.core_workers == 0
            || self.max_history_ring_bytes == 0
        {
            return Err(ConfigError::Invalid("limits must be nonzero".into()));
        }
        for (knob, value, most) in [
            ("core_workers", self.core_workers, MAX_CORE_WORKERS),
            ("core_queue", self.core_queue, MAX_CORE_QUEUE),
            ("sendq_bytes", self.sendq_bytes, MAX_SENDQ_BYTES),
            ("max_hot_channels", self.max_hot_channels, MAX_HOT_CHANNELS),
            (
                "max_history_ring_bytes",
                self.max_history_ring_bytes,
                MAX_HISTORY_RING_BYTES,
            ),
            (
                "max_hot_history_bytes",
                self.max_hot_history_bytes,
                MAX_HOT_HISTORY_BYTES,
            ),
        ] {
            if value > most {
                return Err(ConfigError::Invalid(format!(
                    "{knob} must be at most {most} (it is {value})"
                )));
            }
        }
        if self.sendq_bytes < MIN_SENDQ_BYTES {
            return Err(ConfigError::Invalid(format!(
                "sendq_bytes must be at least {MIN_SENDQ_BYTES}, two of the longest lines the \
                 server sends (it is {})",
                self.sendq_bytes
            )));
        }
        if self.max_hot_history_bytes < self.max_history_ring_bytes {
            return Err(ConfigError::Invalid(format!(
                "max_hot_history_bytes ({}) must be at least max_history_ring_bytes ({}): the \
                 budget of every ring together holds at least one full ring",
                self.max_hot_history_bytes, self.max_history_ring_bytes
            )));
        }
        self.refuse_colliding_listeners()?;
        // The advertised NICKLEN rides every relayed line's source prefix, so an
        // unbounded nick can blow past the 512-byte wire limit (the same reason
        // server_name/network_name are capped at 64) and inflates per-nick
        // memory. Bound it like the other identifiers.
        if self.nicklen > MAX_NICKLEN {
            return Err(ConfigError::Invalid(format!(
                "nicklen must be at most {MAX_NICKLEN} (it rides every relayed line's prefix)"
            )));
        }
        if self.nicklen < MIN_NICKLEN {
            return Err(ConfigError::Invalid(format!(
                "nicklen must be at least {MIN_NICKLEN} (nick protection renames to a Guest \
                 nick of that length)"
            )));
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
        if let Err(error) =
            crate::core::CommandFlood::new(self.limits.command_burst, self.limits.command_rate)
        {
            return Err(ConfigError::Invalid(error.to_string()));
        }
        if let Some(database) = &self.database
            && let Err(error) =
                crate::db::StartupDatabaseWait::from_seconds(database.startup_wait_seconds)
        {
            return Err(ConfigError::Invalid(error));
        }
        if self.limits.auth_rate_burst == AuthRateBurst::PerMinute(0) {
            return Err(ConfigError::Invalid(
                "limits.auth_rate_burst must be nonzero (0 refuses every login); \"off\" turns \
                 the throttle off"
                    .into(),
            ));
        }
        if self.limits.api_rate_burst == 0 {
            return Err(ConfigError::Invalid(
                "limits.api_rate_burst must be nonzero".into(),
            ));
        }
        if self.limits.administrator_api_rate_burst == 0 {
            return Err(ConfigError::Invalid(
                "limits.administrator_api_rate_burst must be nonzero".into(),
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
        if self.limits.require_sasl && !self.limits.require_sasl_from.is_empty() {
            return Err(ConfigError::Invalid(
                "limits.require_sasl_from lists address ranges, but limits.require_sasl already \
                 requires SASL of every client: clear one of them"
                    .into(),
            ));
        }
        if (self.limits.require_sasl || !self.limits.require_sasl_from.is_empty())
            && self.database.is_none()
        {
            return Err(ConfigError::Invalid(
                "limits.require_sasl and limits.require_sasl_from require [database]: without \
                 accounts no client can log in with SASL, so every client they cover would be \
                 refused"
                    .into(),
            ));
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
                if provider.client_id.is_empty() {
                    return Err(ConfigError::Invalid(format!(
                        "OIDC provider '{}' requires client_id",
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
                // In production (secure cookies) every provider endpoint must
                // be HTTPS: discovery and JWKS are fetched from the issuer, so
                // plaintext lets an on-path attacker inject signing keys and
                // forge ID tokens, and the browser is sent to the end-session
                // endpoint with the ID token. A dev setup (secure_cookies =
                // false) may still use http for a local provider. The endpoints
                // a discovery document advertises are held to the same rule
                // when it is fetched (`http::oidc_provider::EndpointSchemes`).
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
                    if require_https && parsed.is_some_and(|url| url.scheme() != "https") {
                        return Err(ConfigError::Invalid(format!(
                            "OIDC provider '{}' {field} must be https when secure_cookies is set \
                             (plaintext provider traffic is forgeable by an on-path attacker)",
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
        if let Some(bnc) = &self.bnc {
            // Config [[network]]s are optional now — accounts add their
            // own networks at runtime — but authentication needs accounts.
            if self.database.is_none() {
                return Err(ConfigError::Invalid(
                    "[bnc] requires [database] to authenticate attaching clients".into(),
                ));
            }
            // An attaching client sends its account password. Off loopback
            // that is readable by everything on the path unless the listener
            // is TLS.
            if bnc.tls.is_none() && !bnc.addr.ip().to_canonical().is_loopback() {
                return Err(ConfigError::Invalid(format!(
                    "[bnc].addr {} (the console's bnc_addr) is not a loopback address, so \
                     [bnc].tls (the console's bnc_tls) is required: attaching clients send \
                     their account password, which must not cross the network in cleartext",
                    bnc.addr
                )));
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
        // Every entry is compared, casefolded, against account names on every
        // request. An entry that is not an account name — `" bob"` from an
        // unsplit `"alice, bob"`, an empty string — can never match anyone and
        // would grant nothing while looking like a grant.
        if let Some(h) = &self.http
            && let Some(entry) = h
                .admin_accounts
                .iter()
                .find(|entry| !crate::sanitize::valid_nick(entry, MAX_ACCOUNT_NAME_LEN))
        {
            return Err(ConfigError::Invalid(format!(
                "http.admin_accounts entry {entry:?} is not a valid account name (an IRC \
                 nickname of at most {MAX_ACCOUNT_NAME_LEN} bytes, no spaces)"
            )));
        }
        // `secure_cookies` and the scheme of `public_url` describe the same
        // deployment and must agree. `secure_cookies = true` with an `http://`
        // origin advertises the auth round-trip over plaintext while the
        // `Secure`/`__Host-` cookie it needs can't be sent; `secure_cookies =
        // false` with an `https://` origin serves a TLS site whose session
        // cookie a browser will also send over plaintext. Both are refused,
        // symmetric to the OIDC `issuer_url` https-under-secure-cookies guard.
        if let Some(h) = &self.http
            && let Some(scheme) = h
                .public_url
                .as_deref()
                .and_then(|value| openidconnect::url::Url::parse(value).ok())
                .map(|url| url.scheme().to_owned())
        {
            if h.secure_cookies && scheme != "https" {
                return Err(ConfigError::Invalid(
                    "http.public_url must be https when secure_cookies is set (a Secure/__Host- \
                     cookie cannot ride a plaintext origin, and the OIDC redirect_uri would be \
                     advertised over http)"
                        .into(),
                ));
            }
            if !h.secure_cookies && scheme == "https" {
                return Err(ConfigError::Invalid(
                    "http.secure_cookies must be true when http.public_url is https (a session \
                     cookie without Secure is also sent over plaintext; set secure_cookies = \
                     false only with an http:// public_url for local development)"
                        .into(),
                ));
            }
        }
        // HSTS is sent only for an `https://` public origin; asking to widen a
        // header that is never sent would be a setting that does nothing.
        if let Some(h) = &self.http
            && h.hsts_include_subdomains
            && !left_to_stored(LEFT_TO_STORED_PUBLIC_URL)
            && !h
                .public_url
                .as_deref()
                .is_some_and(|value| value.starts_with("https://"))
        {
            return Err(ConfigError::Invalid(
                "http.hsts_include_subdomains requires an https:// http.public_url (HSTS is \
                 sent only for an HTTPS public origin)"
                    .into(),
            ));
        }
        // A configured `public_url` seeds every browser-facing absolute URL.
        // Credentials leak into those links; queries and fragments corrupt an
        // appended path. Keep a valid scheme, host, and optional deployment path.
        if let Some(h) = &self.http
            && let Some(value) = h.public_url.as_deref()
            && !openidconnect::url::Url::parse(value).is_ok_and(|url| {
                matches!(url.scheme(), "http" | "https")
                    && url.has_host()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
            })
        {
            return Err(ConfigError::Invalid(
                "http.public_url must be an http(s) URL with a host, without credentials, query, or fragment".into(),
            ));
        }
        // Configured networks need an authenticated management/attach surface.
        // The registry is available with a database even when the raw BNC
        // listener is disabled, because the web client and console use it too.
        // Requiring the listener here made "enable BNC from the console"
        // structurally impossible and made the active-looking network form fail.
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
            n.validate_connection_intent()
                .map_err(|error| ConfigError::Invalid(format!("network '{}': {error}", n.name)))?;
            if n.kind == NetworkKind::Irc
                && let Some(credential) = self.internal_upstreams.cleartext_credential(
                    &n.addr,
                    n.tls,
                    n.sasl_password.is_some(),
                    n.server_password.is_some(),
                )
            {
                return Err(ConfigError::Invalid(format!(
                    "network '{}': {}",
                    n.name,
                    credential.reason()
                )));
            }
        }
        // OPER blocks: an empty name is a dangerous silent default, and a
        // duplicate name is ambiguous (first-match wins with no warning). Reject
        // loudly, like every other subsystem's config. (The password's content
        // is `validate_secrets`'s: it may be sealed here.)
        let mut oper_names: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for oper in &self.opers {
            if oper.name.is_empty() {
                return Err(ConfigError::Invalid(
                    "[[oper]] requires a non-empty name".into(),
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
    fn debug_output_never_carries_a_secret() {
        let database: DatabaseConfig =
            toml::from_str(r#"url = "postgres://e6irc:db-hunter2@db.example.test/e6irc""#)
                .expect("database");
        let bootstrap: BootstrapConfig =
            toml::from_str(r#"token = "bootstrap-hunter2""#).expect("bootstrap");
        let oper: OperConfig =
            toml::from_str("name = \"root\"\npassword = \"oper-hunter2\"").expect("oper");
        for rendered in [
            format!("{database:?}"),
            format!("{bootstrap:?}"),
            format!("{oper:?}"),
        ] {
            assert!(!rendered.contains("hunter2"), "{rendered}");
        }
        let oidc = OidcProviderConfig {
            name: "corp".into(),
            issuer_url: "https://id.example.test".into(),
            client_id: "e6irc".into(),
            client_secret: "oidc-hunter2".into(),
            account_claim: OidcAccountClaim::PreferredUsername,
            scopes: Vec::new(),
            allowed_email_domains: Vec::new(),
            end_session_endpoint: None,
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretPost,
        };
        let rendered = format!("{oidc:?}");
        assert!(
            !rendered.contains("hunter2") && rendered.contains("corp"),
            "{rendered}"
        );
        let network: NetworkEntry = toml::from_str(
            r#"
            name = "libera"
            kind = "irc"
            addr = "irc.libera.chat:6697"
            tls = true
            nick = "alice"
            sasl_account = "alice"
            sasl_password = "sasl-hunter2"
            server_password = "pass-hunter2"
            "#,
        )
        .expect("network");
        let rendered = format!("{network:?}");
        assert!(
            !rendered.contains("hunter2") && rendered.contains("libera"),
            "{rendered}"
        );
    }

    fn listening_config() -> Config {
        Config {
            listeners: vec![listener()],
            ..Config::default()
        }
    }

    fn listener_on(addr: &str) -> ListenerConfig {
        ListenerConfig {
            addr: addr.parse().expect("socket address"),
            ..listener()
        }
    }

    fn refusal(config: &Config) -> String {
        match config.validate() {
            Err(ConfigError::Invalid(message)) => message,
            other => panic!("expected an invalid configuration, got {other:?}"),
        }
    }

    /// Two listeners on one address cannot both bind. The second bind fails at
    /// start with a bare "address in use" that names neither section; the
    /// configuration can say which two collide before anything is bound.
    #[test]
    fn listeners_that_cannot_both_bind_are_refused_by_name() {
        let mut config = listening_config();
        config.listeners = vec![listener_on("127.0.0.1:6667"), listener_on("127.0.0.1:6667")];
        let message = refusal(&config);
        assert!(
            message.contains("[[listeners]] #1") && message.contains("[[listeners]] #2"),
            "{message}"
        );

        // A wildcard address covers every address of its family.
        config.listeners = vec![listener_on("0.0.0.0:6667"), listener_on("127.0.0.1:6667")];
        assert!(refusal(&config).contains("127.0.0.1:6667"));
        // `[::]` is bound dual-stack, so it covers every IPv4 address as well.
        config.listeners = vec![listener_on("127.0.0.1:6667"), listener_on("[::]:6667")];
        assert!(refusal(&config).contains("[::]:6667"));

        config.listeners = vec![listener_on("127.0.0.1:6667")];
        config.database = Some(DatabaseConfig {
            url: "postgres://localhost/e6irc".parse().expect("database URL"),
            startup_wait_seconds: DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        });
        config.http = Some(HttpConfig {
            addr: "127.0.0.1:6667".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        });
        assert!(refusal(&config).contains("[http]"));
        config.http.as_mut().unwrap().addr = "127.0.0.1:8080".parse().unwrap();
        config.bnc = Some(BncConfig {
            addr: "127.0.0.1:8080".parse().unwrap(),
            tls: None,
        });
        let message = refusal(&config);
        assert!(
            message.contains("[http]") && message.contains("[bnc]"),
            "{message}"
        );

        // Port 0 asks the system for any free port, so it never collides; nor
        // do different ports, or the same port on two distinct addresses.
        config.bnc = Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        });
        config.http.as_mut().unwrap().addr = "127.0.0.1:0".parse().unwrap();
        config.listeners = vec![
            listener_on("127.0.0.1:0"),
            listener_on("127.0.0.1:0"),
            listener_on("127.0.0.1:6667"),
            listener_on("127.0.0.2:6667"),
            listener_on("[::1]:6667"),
        ];
        assert!(config.validate().is_ok(), "{:?}", config.validate());
    }

    /// Each of these sizes something the process allocates or spawns per unit.
    /// A value that parses but cannot be served is refused at load, not found
    /// as an out-of-memory kill under load.
    #[test]
    fn numeric_knobs_have_upper_bounds() {
        for (knob, set) in [
            (
                "core_workers",
                (|config, value| config.core_workers = value) as fn(&mut Config, usize),
            ),
            ("core_queue", |config, value| config.core_queue = value),
            ("sendq_bytes", |config, value| config.sendq_bytes = value),
            ("max_hot_channels", |config, value| {
                config.max_hot_channels = value
            }),
            ("max_history_ring_bytes", |config, value| {
                config.max_history_ring_bytes = value
            }),
            ("max_hot_history_bytes", |config, value| {
                config.max_hot_history_bytes = value
            }),
        ] {
            let mut config = listening_config();
            set(&mut config, usize::MAX);
            let message = refusal(&config);
            assert!(message.contains(knob), "{knob}: {message}");
        }
        let mut config = listening_config();
        config.core_workers = MAX_CORE_WORKERS;
        config.core_queue = MAX_CORE_QUEUE;
        config.sendq_bytes = MAX_SENDQ_BYTES;
        config.max_hot_channels = MAX_HOT_CHANNELS;
        config.max_history_ring_bytes = MAX_HISTORY_RING_BYTES;
        config.max_hot_history_bytes = MAX_HOT_HISTORY_BYTES;
        assert!(config.validate().is_ok(), "{:?}", config.validate());
    }

    /// The authentication throttle is on unless a document says `"off"`; a
    /// number sets it, zero is refused, and nothing else is read as off.
    #[test]
    fn the_auth_throttle_is_on_by_default_and_off_only_by_name() {
        let parse = |limits: &str| {
            toml::from_str::<Config>(&format!(
                "server_name = \"irc.x.example\"\nnetwork_name = \"X\"\n[limits]\n{limits}"
            ))
        };
        let default = parse("").expect("parse");
        assert_eq!(
            default.limits.auth_rate_burst,
            AuthRateBurst::PerMinute(DEFAULT_AUTH_RATE_BURST)
        );
        assert_eq!(default.limits.auth_rate_burst.burst(), Some(20));
        let off = parse("auth_rate_burst = \"off\"").expect("parse");
        assert_eq!(off.limits.auth_rate_burst.burst(), None);
        let set = parse("auth_rate_burst = 5").expect("parse");
        assert_eq!(set.limits.auth_rate_burst, AuthRateBurst::PerMinute(5));
        assert!(parse("auth_rate_burst = \"none\"").is_err());
        assert!(parse("auth_rate_burst = -1").is_err());
        let mut zero = listening_config();
        zero.limits.auth_rate_burst = AuthRateBurst::PerMinute(0);
        assert!(refusal(&zero).contains("auth_rate_burst"));
        // The stored form round-trips both spellings.
        for burst in [AuthRateBurst::Off, AuthRateBurst::PerMinute(7)] {
            let json = serde_json::to_value(burst).expect("serialize");
            assert_eq!(
                serde_json::from_value::<AuthRateBurst>(json).expect("read"),
                burst
            );
        }
        assert_eq!(serde_json::to_value(AuthRateBurst::Off).unwrap(), "off");
    }

    /// The SendQ counts bytes now: the old line-count key is refused by name
    /// rather than read as a byte count, and a SendQ too small for two of the
    /// longest lines is refused.
    #[test]
    fn the_sendq_is_configured_in_bytes() {
        let err = toml::from_str::<Config>(
            "server_name = \"irc.x.example\"\nnetwork_name = \"X\"\nsendq = 1024",
        )
        .expect_err("the line count is gone");
        assert!(err.to_string().contains("sendq"), "{err}");
        assert_eq!(Config::default().sendq_bytes, 1024 * 512);
        let mut config = listening_config();
        config.sendq_bytes = MIN_SENDQ_BYTES - 1;
        assert!(refusal(&config).contains("sendq_bytes"));
        config.sendq_bytes = MIN_SENDQ_BYTES;
        assert!(config.validate().is_ok(), "{:?}", config.validate());
    }

    /// The budget of every history ring together holds at least one full
    /// ring, and a ring's budget is not zero.
    #[test]
    fn hot_history_budgets_are_consistent() {
        let mut config = listening_config();
        config.max_hot_history_bytes = config.max_history_ring_bytes - 1;
        assert!(refusal(&config).contains("max_hot_history_bytes"));
        let mut config = listening_config();
        config.max_history_ring_bytes = 0;
        assert!(config.validate().is_err());
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
        // Empty password is a dangerous silent default. It is a rule about the
        // secret's content, so it is judged after sealed values are opened.
        let c: Config = toml::from_str(&format!(
            "{base}\n[[oper]]\nname = \"admin\"\npassword = \"\"\n"
        ))
        .expect("parse");
        c.validate().expect("structure is fine");
        let err = c.validate_secrets().unwrap_err().to_string();
        assert!(err.contains("non-empty password"), "{err}");
        // An empty name is structural and refused before any secret is opened.
        let c: Config = toml::from_str(&format!(
            "{base}\n[[oper]]\nname = \"\"\npassword = \"x\"\n"
        ))
        .expect("parse");
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("non-empty name"), "{err}");
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
        let error = toml::from_str::<Config>(
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
            kind = "irc"
            addr = "irc.libera.chat:6697"
            tls = true
            nick = "n"
            username = "ident"
            realname = "n"
            autojoin = []
            buffer_cap = 0
            "#,
        )
        .expect_err("zero buffer cap must fail at configuration ingress")
        .to_string();
        assert!(error.contains("buffer_cap"), "{error}");
    }

    /// The start-up warning names the one shape in which every client surely
    /// shares the authentication budget — throttle on, no trusted proxy, HTTP
    /// bound to loopback only — and is silent otherwise.
    #[test]
    fn a_loopback_http_listener_without_trusted_proxies_is_warned_about() {
        let mut config = listening_config();
        assert_eq!(config.shared_authentication_budget(), None, "no HTTP");
        config.http = Some(HttpConfig {
            addr: "127.0.0.1:8080".parse().unwrap(),
            public_url: None,
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: false,
        });
        let warning = config
            .shared_authentication_budget()
            .expect("behind a proxy every user shares one budget");
        assert!(warning.contains("limits.trusted_proxies"), "{warning}");
        assert!(warning.contains("\"off\""), "{warning}");
        if let Some(http) = &mut config.http {
            http.addr = "[::ffff:127.0.0.1]:8080".parse().unwrap();
        }
        assert!(
            config.shared_authentication_budget().is_some(),
            "mapped loopback"
        );

        let mut trusted = config.clone();
        trusted.limits.trusted_proxies = vec!["127.0.0.1/32".parse().unwrap()];
        assert_eq!(trusted.shared_authentication_budget(), None);
        let mut off = config.clone();
        off.limits.auth_rate_burst = AuthRateBurst::Off;
        assert_eq!(off.shared_authentication_budget(), None);
        let mut wide = config;
        if let Some(http) = &mut wide.http {
            http.addr = "0.0.0.0:8080".parse().unwrap();
        }
        assert_eq!(
            wide.shared_authentication_budget(),
            None,
            "a listener bound wider may or may not be behind a proxy"
        );
    }

    /// A database-backed document may leave the server's names and listeners
    /// to the stored settings; one without a database has nothing to take them
    /// from, and is refused naming each it leaves out.
    #[test]
    fn only_a_database_backed_document_may_leave_the_names_to_the_console() {
        let mut with_database: Config =
            toml::from_str("[database]\nurl = \"postgres://localhost/x\"\n").expect("parses");
        let document: toml::Table =
            toml::from_str("[database]\nurl = \"postgres://localhost/x\"\n").expect("table");
        with_database.left_to_stored_settings = left_out_of(&document);
        assert_eq!(
            with_database.left_to_stored_settings,
            LEFT_TO_STORED_SETTINGS
        );
        with_database
            .validate()
            .expect("left to the stored settings");

        let refusal = Config::from_table(
            toml::from_str("[[listeners]]\naddr = \"127.0.0.1:0\"\n").expect("table"),
            &[],
        )
        .expect_err("no database to take them from")
        .to_string();
        assert!(
            refusal.contains(
                "server_name, network_name required: only a configuration with \
                 [database] may leave them"
            ),
            "{refusal}"
        );
        // A document that states them is held to their rules as before.
        let refusal = Config::from_table(
            toml::from_str(
                "server_name = \"\"\nnetwork_name = \"n\"\n\
                 [database]\nurl = \"postgres://localhost/x\"\n",
            )
            .expect("table"),
            &[],
        )
        .expect_err("an empty server name is stated, not left out")
        .to_string();
        assert!(
            refusal.contains("server_name must be a hostname"),
            "{refusal}"
        );
    }

    /// A database-backed document whose `[http]` omits `public_url` leaves it
    /// to the stored settings, as the environment's unset `E6IRC_PUBLIC_URL`
    /// does; without a database, omitting it is running without one.
    #[test]
    fn a_database_backed_http_listener_may_leave_its_public_url_to_the_console() {
        let names = "server_name = \"irc.x.example\"\nnetwork_name = \"XNet\"\n\
                     [[listeners]]\naddr = \"127.0.0.1:0\"\n";
        let http = "[http]\naddr = \"127.0.0.1:0\"\n";
        let database = "[database]\nurl = \"postgres://localhost/x\"\n";
        let load = |document: String| {
            Config::from_table(toml::from_str(&document).expect("table"), &[]).expect("valid")
        };
        assert_eq!(
            load(format!("{names}{http}{database}")).left_to_stored_settings,
            [LEFT_TO_STORED_PUBLIC_URL]
        );
        let stated = load(format!(
            "{names}{http}public_url = \"https://x.example\"\n{database}"
        ));
        assert!(stated.left_to_stored_settings.is_empty());
        assert!(
            load(format!("{names}{http}"))
                .left_to_stored_settings
                .is_empty()
        );
        assert!(
            load(format!("{names}{database}"))
                .left_to_stored_settings
                .is_empty()
        );
    }

    /// `buffer_cap` is bounded by what the stored backlog keeps, so the replay
    /// it configures survives a restart; the bound is one constant both use.
    #[test]
    fn network_buffer_cap_is_bounded_by_what_storage_keeps() {
        let document = |cap: usize| {
            format!(
                "server_name = \"irc.x.example\"\nnetwork_name = \"XNet\"\n\
                 [[listeners]]\naddr = \"127.0.0.1:0\"\n\
                 [database]\nurl = \"postgres://localhost/x\"\n\
                 [[network]]\nname = \"libera\"\nkind = \"irc\"\n\
                 addr = \"irc.libera.chat:6697\"\ntls = true\nnick = \"n\"\n\
                 username = \"ident\"\nrealname = \"n\"\nautojoin = []\nbuffer_cap = {cap}\n"
            )
        };
        let config: Config = toml::from_str(&document(MAX_NETWORK_BUFFER_CAP)).expect("parses");
        config.validate().expect("at the bound");
        let refusal = toml::from_str::<Config>(&document(MAX_NETWORK_BUFFER_CAP + 1))
            .map_err(|error| error.to_string())
            .and_then(|config| config.validate().map_err(|error| error.to_string()))
            .expect_err("above the bound");
        assert!(
            refusal.contains("buffer_cap must be at most 5000"),
            "{refusal}"
        );
    }

    #[test]
    fn network_connection_intent_is_required() {
        let config = r#"
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
        "#;
        assert!(toml::from_str::<Config>(config).is_err());
        for entry in [
            "name = 'libera'\nkind = 'irc'\ntls = true\nnick = 'n'",
            "name = 'libera'\nkind = 'irc'\naddr = 'irc.libera.chat:6697'\nnick = 'n'",
        ] {
            assert!(toml::from_str::<NetworkEntry>(entry).is_err(), "{entry}");
        }
    }

    fn config_with_static_network(network: &str) -> String {
        format!(
            "server_name = 'irc.example.test'\nnetwork_name = 'Example'\n[[listeners]]\naddr = '127.0.0.1:0'\n[database]\nurl = 'postgres://localhost/example'\n[[network]]\n{network}"
        )
    }

    #[test]
    fn static_network_entries_are_driver_specific() {
        for entry in [
            "kind = 'irc'\nname = 'irc'\naddr = 'irc.example:6697'\ntls = true\nnick = 'alice'\nusername = 'alice'\nrealname = 'Alice'\nautojoin = []\nbuffer_cap = 1000\nsasl_account = 'alice'\nsasl_password = 'password'",
            "kind = 'local'\nname = 'local'\naddr = ''\ntls = false\nnick = 'alice'\nusername = 'alice'\nrealname = 'Alice'\nautojoin = []\nbuffer_cap = 1000",
            "kind = 'matrix'\nname = 'matrix'\naddr = 'https://matrix.example.test'\ntls = true\nnick = '@alice:example.test'\nautojoin = []\nbuffer_cap = 1000\nsasl_password = 'password'",
            "kind = 'discord'\nname = 'discord'\naddr = ''\ntls = true\nautojoin = []\nbuffer_cap = 1000\nsasl_password = 'token'",
            "kind = 'slack'\nname = 'slack'\naddr = ''\ntls = true\nautojoin = []\nbuffer_cap = 1000\nsasl_account = 'xoxb-token'\nsasl_password = 'xapp-token'",
        ] {
            assert!(toml::from_str::<NetworkEntryWire>(entry).is_ok(), "{entry}");
            assert!(
                toml::from_str::<Config>(&config_with_static_network(entry)).is_ok(),
                "{entry}"
            );
        }
        let incompatible = "kind = 'discord'\nname = 'discord'\naddr = ''\ntls = true\nnick = 'alice'\nautojoin = []\nbuffer_cap = 1000\nsasl_password = 'token'";
        assert!(
            toml::from_str::<NetworkEntryWire>(incompatible).is_err(),
            "{incompatible}"
        );
    }

    /// A server password is the `PASS` of an IRC connection: accepted for
    /// `kind=irc`, refused by name for every kind that sends no such line,
    /// and a sealed one is opened and then held to the same one-line rule.
    #[test]
    fn a_static_server_password_is_irc_only_and_opened_before_use() {
        let irc = "kind = 'irc'\nname = 'irc'\naddr = 'irc.example:6697'\ntls = true\nnick = 'alice'\nusername = 'alice'\nrealname = 'Alice'\nautojoin = []\nbuffer_cap = 1000";
        let config = toml::from_str::<Config>(&config_with_static_network(&format!(
            "{irc}\nserver_password = 'open sesame'"
        )))
        .expect("an irc network takes a server password");
        assert_eq!(
            config.networks[0].server_password.as_deref(),
            Some("open sesame")
        );
        for network in [
            "kind = 'local'\nname = 'local'\naddr = ''\ntls = false\nnick = 'alice'\nusername = 'alice'\nrealname = 'Alice'\nautojoin = []\nbuffer_cap = 1000\nserver_password = 'pass'",
            "kind = 'matrix'\nname = 'matrix'\naddr = 'https://matrix.example.test'\ntls = true\nnick = '@alice:example.test'\nautojoin = []\nbuffer_cap = 1000\nsasl_password = 'password'\nserver_password = 'pass'",
            "kind = 'discord'\nname = 'discord'\naddr = ''\ntls = true\nautojoin = []\nbuffer_cap = 1000\nsasl_password = 'token'\nserver_password = 'pass'",
            "kind = 'slack'\nname = 'slack'\naddr = ''\ntls = true\nautojoin = []\nbuffer_cap = 1000\nsasl_account = 'xoxb-token'\nsasl_password = 'xapp-token'\nserver_password = 'pass'",
        ] {
            let error = toml::from_str::<Config>(&config_with_static_network(network))
                .expect_err("only kind=irc sends PASS")
                .to_string();
            assert!(error.contains("server_password"), "{network}: {error}");
        }
        // Checked on the plaintext, and a managed entry that bypasses the wire
        // form is refused by the same rule.
        let over_long = format!(
            "{irc}\nserver_password = '{}'",
            "x".repeat(e6irc_client::ServerPassword::MAX_LEN + 1)
        );
        assert!(toml::from_str::<Config>(&config_with_static_network(&over_long)).is_err());
        let mut local = net("local", None);
        local.kind = NetworkKind::Local;
        local.server_password = Some("pass".into());
        assert!(
            local
                .validate_connection_intent()
                .expect_err("local sends no PASS")
                .contains("server_password")
        );

        // A sealed value is opened, then held to the same rule.
        let keyring = crate::secret::SecretKeyring::single(crate::secret::SecretKey::generate());
        let mut sealed = net("sealed", None);
        sealed.server_password = Some(keyring.seal(
            &"x".repeat(e6irc_client::ServerPassword::MAX_LEN),
            crate::secret::CONFIG_CONTEXT,
        ));
        sealed
            .validate_connection_intent()
            .expect("a sealed value's length is its ciphertext's, not the password's");
        let mut config = Config {
            networks: vec![sealed],
            ..Config::default()
        };
        config
            .resolve_secrets_with_key(Some(&keyring))
            .expect("opens");
        assert_eq!(
            config.networks[0].server_password.as_deref().map(str::len),
            Some(e6irc_client::ServerPassword::MAX_LEN)
        );
        config.validate_secrets().expect("fits one PASS line");
        config.networks[0].server_password =
            Some("x".repeat(e6irc_client::ServerPassword::MAX_LEN + 1));
        assert!(config.validate_secrets().is_err());
    }

    /// A SASL password (and a Slack bot token in `sasl_account`) is a secret:
    /// judged on its opened text, never on the ciphertext, and never trimmed.
    #[test]
    fn sasl_secrets_are_judged_opened_and_kept_verbatim() {
        let keyring = crate::secret::SecretKeyring::single(crate::secret::SecretKey::generate());
        let mut sealed = net("sealed", None);
        sealed.tls = true;
        sealed.sasl_account = Some("alice".into());
        sealed.sasl_password = Some(keyring.seal(&"x".repeat(512), crate::secret::CONFIG_CONTEXT));
        sealed
            .validate_connection_intent()
            .expect("a sealed value's length is its ciphertext's, not the password's");
        let mut config = Config {
            networks: vec![sealed],
            ..Config::default()
        };
        config
            .resolve_secrets_with_key(Some(&keyring))
            .expect("opens");
        config.validate_secrets().expect("512 bytes fit");
        config.networks[0].sasl_password = Some("x".repeat(513));
        let error = config
            .validate_secrets()
            .expect_err("the bound holds on the opened text")
            .to_string();
        assert!(error.contains("sasl_password"), "{error}");

        let mut padded = net("padded", None);
        padded.sasl_account = Some(" alice ".into());
        padded.sasl_password = Some("  spaced secret  ".into());
        let normalized = padded.normalized_connection_intent();
        assert_eq!(normalized.sasl_account.as_deref(), Some("alice"));
        assert_eq!(
            normalized.sasl_password.as_deref(),
            Some("  spaced secret  "),
            "a password is kept verbatim: trimming would store another one"
        );
        let mut slack = net("slack", None);
        slack.kind = NetworkKind::Slack;
        slack.sasl_account = Some(" xoxb-token ".into());
        assert_eq!(
            slack.normalized_connection_intent().sasl_account.as_deref(),
            Some(" xoxb-token "),
            "a Slack bot token in sasl_account is a secret, kept verbatim"
        );
    }

    /// A configured network's SASL or server password never crosses a
    /// plaintext connection to another machine; only the test harness's
    /// loopback upstream, under `internal_upstreams = "allow"`, may take one.
    #[test]
    fn a_static_network_refuses_credentials_without_tls() {
        let mut config = listening_config();
        config.database = Some(DatabaseConfig {
            url: "postgres://localhost/e6irc".parse().expect("database URL"),
            startup_wait_seconds: DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        });
        let mut plain = net("plain", None);
        plain.sasl_account = Some("alice".into());
        plain.sasl_password = Some("secret".into());
        config.networks = vec![plain.clone()];
        let message = refusal(&config);
        assert!(
            message.contains("sasl_password requires tls=true"),
            "{message}"
        );
        plain.sasl_account = None;
        plain.sasl_password = None;
        plain.server_password = Some("open sesame".into());
        config.networks = vec![plain.clone()];
        assert!(refusal(&config).contains("server_password requires tls=true"));
        plain.addr = "127.0.0.1:6667".into();
        config.networks = vec![plain.clone()];
        assert!(
            refusal(&config).contains("server_password"),
            "loopback is still refused under the default policy"
        );
        config.internal_upstreams = crate::egress::InternalUpstreams::Allow;
        config.validate().expect("the harness's loopback upstream");
        plain.tls = true;
        plain.addr = "irc.example:6697".into();
        config.networks = vec![plain];
        config.validate().expect("over TLS");
    }

    #[test]
    fn static_network_ingress_rejects_invalid_driver_fields() {
        for network in [
            "kind = 'irc'\nrevision = 1\nname = 'irc'\naddr = 'irc.example:6697'\ntls = true\nnick = 'alice'\nusername = 'alice'\nrealname = 'Alice'\nautojoin = []\nbuffer_cap = 1000\nsasl_account = 'alice'\nsasl_password = 'password'",
            "kind = 'local'\nname = 'local'\naddr = ''\ntls = false\nnick = 'alice'\nusername = 'alice'\nrealname = 'Alice'\nautojoin = ['   ']\nbuffer_cap = 1000",
            "kind = 'matrix'\nname = 'matrix'\naddr = '   '\ntls = true\nnick = '@alice:example.test'\nautojoin = []\nbuffer_cap = 1000\nsasl_password = 'password'",
            "kind = 'matrix'\nname = 'matrix'\naddr = 'https://matrix.example.test'\ntls = true\nnick = '   '\nautojoin = []\nbuffer_cap = 1000\nsasl_password = 'password'",
            "kind = 'discord'\nname = 'discord'\naddr = ''\ntls = true\nautojoin = []\nbuffer_cap = 1000\nsasl_password = '   '",
            "kind = 'slack'\nname = 'slack'\naddr = ''\ntls = true\nautojoin = []\nbuffer_cap = 1000\nsasl_account = 'xoxb-token'\nsasl_password = '   '",
        ] {
            assert!(
                toml::from_str::<Config>(&config_with_static_network(network)).is_err(),
                "{network}"
            );
        }
    }

    #[test]
    fn irc_network_requires_realname() {
        let config = toml::from_str::<Config>(
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
            kind = "irc"
            addr = "irc.libera.chat:6697"
            tls = true
            nick = "n"
            username = "ident"
            realname = " "
            "#,
        );
        assert!(
            config.is_err(),
            "IRC identity must fail at the parse boundary"
        );
    }

    /// New configuration never receives an implicit user name: a network whose
    /// file omits it does not start, and says which field is missing.
    #[test]
    fn irc_and_local_networks_state_their_username() {
        let config = |kind: &str, username: &str| {
            toml::from_str::<Config>(&format!(
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
                name = "net"
                kind = "{kind}"
                addr = "irc.libera.chat:6697"
                tls = true
                nick = "_bot"
                {username}
                realname = "Bot"
                autojoin = []
                buffer_cap = 1000
                "#
            ))
        };
        for kind in ["irc", "local"] {
            assert!(config(kind, r#"username = "bot""#).is_ok(), "{kind}");
            let missing = config(kind, "").expect_err("no derived default");
            assert!(missing.to_string().contains("username"), "{missing}");
            let derived = config(kind, r#"username = "_bot""#).expect_err("not a user name");
            assert!(
                derived
                    .to_string()
                    .contains("must begin with an ASCII letter or digit"),
                "{derived}"
            );
        }
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
        for value in ["https://irc.example", "https://irc.example/e6irc"] {
            with_public_url(value)
                .validate()
                .expect("a valid public_url is accepted");
        }
        for value in [
            "https://user:secret@irc.example",
            "https://irc.example?stale=true",
            "https://irc.example#stale",
        ] {
            let error = with_public_url(value)
                .validate()
                .expect_err("unsafe public URL");
            assert!(error.to_string().contains("public_url"), "{error}");
        }
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
                kind: NetworkKind::Irc,
                name: "libera".into(),
                owner: None,
                addr: "irc.libera.chat:6697".into(),
                tls: true,
                nick: "e6bnc".into(),
                username: Some("e6bnc".into()),
                realname: Some("e6bnc".into()),
                autojoin: Vec::new(),
                buffer_cap: 1000,
                sasl_account: Some(sealed_account),
                sasl_password: Some(sealed),
                server_password: None,
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
            kind: NetworkKind::Irc,
            name: name.into(),
            owner: owner.map(str::to_string),
            addr: "irc.example:6667".into(),
            tls: false,
            nick: "n".into(),
            username: Some("n".into()),
            realname: Some("n".into()),
            autojoin: Vec::new(),
            buffer_cap: 1000,
            sasl_account: None,
            sasl_password: None,
            server_password: None,
        }
    }

    /// Configured `[[network]]`s are only reachable through the BNC registry,
    /// which needs `[bnc]` (and `[bnc]` needs `[database]`). Tests about
    /// network selection must satisfy those so they exercise the selection
    /// rules, not the "networks require [bnc]" guard.
    fn bnc() -> Option<BncConfig> {
        Some(BncConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        })
    }

    fn db() -> Option<DatabaseConfig> {
        Some(DatabaseConfig {
            url: "postgres://localhost/x".parse().expect("database URL"),
            startup_wait_seconds: DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
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
        matrix.realname = None;
        matrix.username = None;
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
        slack.realname = None;
        slack.username = None;
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
        slack.realname = None;
        slack.username = None;
        slack.sasl_account = Some(String::new());
        slack.sasl_password = Some("xapp-token".into());
        assert!(
            config(slack)
                .validate()
                .unwrap_err()
                .to_string()
                .contains("non-blank")
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
    fn zero_core_workers_is_rejected() {
        let cfg = Config {
            core_workers: 0,
            ..Config::default()
        };
        assert!(cfg.validate().is_err(), "zero workers must be rejected");
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
    fn command_flood_defaults_to_solanum_shape_and_is_always_on() {
        let limits = LimitsConfig::default();
        assert_eq!(limits.command_burst, 40);
        assert_eq!(limits.command_rate, 20);
        // Omitting both keys yields the same defaults: the throttle has no
        // "absent means off" spelling.
        let parsed: LimitsConfig = toml::from_str("").expect("empty limits table");
        assert_eq!(parsed, limits);
    }

    #[test]
    fn managed_config_changed_fields_names_paths_never_values() {
        let before = ManagedConfig::from_config(&Config::default(), None).expect("managed");
        let mut after = before.clone();
        assert!(before.changed_fields(&after).is_empty());
        after.server_name = "irc.renamed.example".into();
        after.limits.command_burst += 1;
        after.motd.push("a very secret motd line".into());
        let changed = before.changed_fields(&after);
        assert_eq!(changed, ["limits.command_burst", "motd", "server_name"]);
        assert!(
            changed.iter().all(|name| !name.contains("secret")),
            "values must never appear: {changed:?}"
        );
    }

    #[test]
    fn database_startup_wait_is_bounded() {
        let with = |startup_wait_seconds: u64| Config {
            listeners: vec![listener()],
            database: Some(DatabaseConfig {
                url: "postgres://localhost/e6irc".parse().expect("database URL"),
                startup_wait_seconds,
                max_connections: None,
            }),
            ..Config::default()
        };
        with(0).validate().expect("0 is one attempt");
        with(3_600).validate().expect("an hour is the ceiling");
        let error = with(3_601).validate().unwrap_err().to_string();
        assert!(error.contains("database.startup_wait_seconds"), "{error}");
        let parsed: DatabaseConfig =
            toml::from_str("url = \"postgres://localhost/e6irc\"").expect("url alone");
        assert_eq!(parsed.startup_wait_seconds, DEFAULT_STARTUP_WAIT_SECONDS);
    }

    #[test]
    fn command_flood_rate_zero_and_burst_below_rate_are_rejected() {
        let with = |command_burst: usize, command_rate: usize| Config {
            listeners: vec![listener()],
            limits: LimitsConfig {
                command_burst,
                command_rate,
                ..LimitsConfig::default()
            },
            ..Config::default()
        };
        let error = with(40, 0).validate().unwrap_err().to_string();
        assert!(
            error.contains("limits.command_rate"),
            "command_rate=0 never refills and must be rejected: {error}"
        );
        let error = with(0, 20).validate().unwrap_err().to_string();
        assert!(
            error.contains("limits.command_burst"),
            "command_burst=0 never admits a line and must be rejected: {error}"
        );
        let error = with(10, 20).validate().unwrap_err().to_string();
        assert!(
            error.contains("at least limits.command_rate"),
            "a burst below the rate is a bucket that can never hold one second: {error}"
        );
        let error = with(MAX_COMMAND_FLOOD_TOKENS + 1, 20)
            .validate()
            .unwrap_err()
            .to_string();
        assert!(error.contains("at most"), "{error}");
        with(20, 20)
            .validate()
            .expect("burst equal to rate is the floor");
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

    /// A document with `limits` as its `[limits]` table, and a database
    /// unless `database` is false.
    fn with_limits(limits: &str, database: bool) -> Result<Config, ConfigError> {
        let database = if database {
            "[database]\nurl = \"postgres://localhost/e6irc\"\n"
        } else {
            ""
        };
        Config::from_table(
            toml::from_str(&format!(
                "server_name = \"irc.example\"\nnetwork_name = \"example\"\n\
                 [[listeners]]\naddr = \"127.0.0.1:6667\"\n{database}[limits]\n{limits}\n"
            ))
            .expect("document"),
            &[],
        )
    }

    #[test]
    fn the_sasl_requirement_is_parsed_and_covers_what_it_names() {
        let everyone = with_limits("require_sasl = true", true).expect("valid");
        assert!(everyone.limits.sasl_requirement().covers(None));
        assert!(
            everyone
                .limits
                .sasl_requirement()
                .covers(Some("198.51.100.1".parse().unwrap()))
        );

        let ranges = with_limits(
            r#"require_sasl_from = ["192.0.2.0/24", "2001:db8::/32"]"#,
            true,
        )
        .expect("valid")
        .limits
        .sasl_requirement();
        for (address, covered) in [
            ("192.0.2.1", true),
            ("::ffff:192.0.2.1", true),
            ("2001:db8::1", true),
            ("192.0.3.1", false),
            ("2001:db9::1", false),
        ] {
            assert_eq!(
                ranges.covers(Some(address.parse().unwrap())),
                covered,
                "{address}"
            );
        }
        assert!(!ranges.covers(None), "no address, no range to be in");
        assert!(!Config::default().limits.sasl_requirement().covers(None));
    }

    #[test]
    fn a_sasl_requirement_that_cannot_work_or_contradicts_itself_is_refused() {
        let error = with_limits(r#"require_sasl_from = ["192.0.2.0/33"]"#, true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("require_sasl_from"), "{error}");
        let error = with_limits(r#"require_sasl_from = ["cloud"]"#, true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("require_sasl_from"), "{error}");

        for limits in [
            "require_sasl = true",
            r#"require_sasl_from = ["192.0.2.0/24"]"#,
        ] {
            let error = with_limits(limits, false).unwrap_err().to_string();
            assert!(error.contains("require [database]"), "{limits}: {error}");
        }

        let error = with_limits(
            "require_sasl = true\nrequire_sasl_from = [\"192.0.2.0/24\"]",
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("clear one of them"), "{error}");
    }

    #[test]
    fn an_invalid_trusted_proxy_is_refused_when_the_configuration_is_read() {
        let error = with_limits(r#"trusted_proxies = ["10.0.0.0/40"]"#, false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("trusted_proxies"), "{error}");
        let parsed = with_limits(r#"trusted_proxies = ["10.0.0.0/8"]"#, false).expect("valid");
        assert_eq!(
            parsed.limits.trusted_proxies,
            ["10.0.0.0/8".parse::<ipnet::IpNet>().unwrap()]
        );
    }

    /// Clients are matched by their canonical address (IPv4, never
    /// IPv4-mapped), so a mapped range is read as the IPv4 range it names —
    /// kept as written it could never contain a client — and a mapped range
    /// shorter than /96 is refused.
    #[test]
    fn an_ipv4_mapped_range_is_read_as_its_ipv4_range() {
        let parsed = with_limits(
            r#"trusted_proxies = ["::ffff:10.0.0.0/104"]
require_sasl_from = ["::ffff:192.0.2.0/120", "2001:db8::/32"]"#,
            true,
        )
        .expect("valid");
        assert_eq!(
            parsed.limits.trusted_proxies,
            ["10.0.0.0/8".parse::<ipnet::IpNet>().unwrap()]
        );
        assert!(
            parsed
                .limits
                .sasl_requirement()
                .covers(Some("192.0.2.7".parse().unwrap()))
        );
        for field in ["trusted_proxies", "require_sasl_from"] {
            let error = with_limits(&format!(r#"{field} = ["::ffff:0.0.0.0/64"]"#), true)
                .unwrap_err()
                .to_string();
            assert!(error.contains("IPv4-mapped"), "{field}: {error}");
        }
    }

    /// The SASL requirement is console-owned like every other limit: the
    /// console's form stores it, and a configuration that states another value
    /// is held to the stored one.
    #[test]
    fn the_sasl_requirement_is_a_console_owned_setting() {
        let key = crate::secret::SecretKeyring::single(crate::secret::SecretKey::generate());
        let (_, stored) = stated_and_imported(DRIFT_DOCUMENT, &key);
        let (stated, _) = stated_and_imported(
            &format!("{DRIFT_DOCUMENT}\n[limits]\nrequire_sasl_from = [\"192.0.2.0/24\"]\n"),
            &key,
        );
        assert_eq!(
            stored.bootstrap_drift(&stated, Some(&key)).unwrap(),
            ["limits.require_sasl_from"]
        );
        let mut console = stored.clone();
        console.limits.require_sasl = true;
        let json = serde_json::to_value(&console).expect("serializes");
        assert_eq!(json["limits"]["require_sasl"], true);
        let round_trip: ManagedConfig = serde_json::from_value(json).expect("deserializes");
        assert_eq!(round_trip, console);
        round_trip
            .validate(BootstrapContext {
                http_listener: None,
                hsts_include_subdomains: false,
                internal_upstreams: crate::egress::InternalUpstreams::Refuse,
                application_release_revision: None,
            })
            .expect("the console may save it");
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
            hsts_include_subdomains: false,
        });
        config.validate().expect("complete browser bootstrap");
        config.validate_secrets().expect("a strong bounded token");

        for token in [
            "too-short".to_string(),
            format!("{}x", "a".repeat(512)),
            format!("{}\n", "a".repeat(31)),
        ] {
            config.bootstrap = Some(BootstrapConfig { token });
            config.validate().expect("token content is not structure");
            assert!(config.validate_secrets().is_err());
        }
    }

    /// A sealed bootstrap token is long enough as ciphertext whatever it opens
    /// to, and a sealed client secret is never empty as ciphertext. The rules
    /// about a secret's content must judge the opened text.
    #[test]
    fn secret_content_rules_judge_the_opened_secret_not_the_ciphertext() {
        let key = crate::secret::SecretKey::generate();
        let keyring = crate::secret::SecretKeyring::single(
            crate::secret::SecretKey::from_base64(&key.to_base64()).expect("key round trip"),
        );
        let mut config = Config {
            listeners: vec![listener()],
            database: db(),
            http: Some(HttpConfig {
                addr: "127.0.0.1:0".parse().unwrap(),
                public_url: None,
                secure_cookies: false,
                admin_accounts: vec![],
                hsts_include_subdomains: false,
            }),
            bootstrap: Some(BootstrapConfig {
                token: key.seal("short", crate::secret::CONFIG_CONTEXT),
            }),
            ..Config::default()
        };
        assert!(
            config.bootstrap.as_ref().unwrap().token.len() >= 32,
            "the ciphertext is long enough to pass a length rule by itself"
        );
        config.validate().expect("structure");
        config
            .resolve_secrets_with_key(Some(&keyring))
            .expect("opens");
        let error = config.validate_secrets().unwrap_err().to_string();
        assert!(error.contains("bootstrap.token"), "{error}");

        let mut config = oidc_config("corp", "https://auth.example", None);
        config.oidc_providers[0].client_secret = key.seal("", crate::secret::CONFIG_CONTEXT);
        config.validate().expect("structure");
        config
            .resolve_secrets_with_key(Some(&keyring))
            .expect("opens");
        let error = config.validate_secrets().unwrap_err().to_string();
        assert!(error.contains("client_secret"), "{error}");
    }

    /// `[secrets].key_file` and `E6IRC_SECRET_KEY` are alternatives. Stated
    /// together, one used to win silently; now the pair is refused by name.
    #[test]
    fn a_key_file_and_an_environment_key_together_are_refused_by_name() {
        let key = crate::secret::SecretKey::generate();
        let path =
            std::env::temp_dir().join(format!("e6irc-both-key-sources-{}.b64", std::process::id()));
        std::fs::write(&path, key.to_base64()).unwrap();
        let config = Config {
            secrets: secrets_at(&path),
            ..Config::default()
        };
        let refusal =
            |environment: EnvironmentSecretKeys| match config.secret_keyring_from(environment) {
                Err(error) => error.to_string(),
                Ok(_) => panic!("a key file beside an environment key must be refused"),
            };
        let error = refusal(EnvironmentSecretKeys {
            primary: Some(key.to_base64()),
            previous: None,
        });
        assert!(error.contains("E6IRC_SECRET_KEY"), "{error}");
        assert!(error.contains("key_file"), "{error}");
        assert!(
            error.contains(&path.display().to_string()),
            "names the file: {error}"
        );
        let error = refusal(EnvironmentSecretKeys {
            primary: None,
            previous: Some(key.to_base64()),
        });
        assert!(error.contains("E6IRC_PREVIOUS_SECRET_KEYS"), "{error}");
        // Each source alone still resolves.
        config
            .secret_keyring_from(EnvironmentSecretKeys {
                primary: None,
                previous: None,
            })
            .expect("file alone")
            .expect("configured");
        std::fs::remove_file(&path).ok();
        Config::default()
            .secret_keyring_from(EnvironmentSecretKeys {
                primary: Some(key.to_base64()),
                previous: None,
            })
            .expect("environment alone")
            .expect("configured");
    }

    /// An `http.admin_accounts` entry is compared against account names on
    /// every request; one that is not an account name grants nothing while
    /// looking like a grant.
    #[test]
    fn admin_accounts_entries_must_be_account_names() {
        let mut config = Config {
            listeners: vec![listener()],
            database: db(),
            http: Some(HttpConfig {
                addr: "127.0.0.1:0".parse().unwrap(),
                public_url: None,
                secure_cookies: false,
                admin_accounts: vec!["alice".into(), "Bob_1".into()],
                hsts_include_subdomains: false,
            }),
            ..Config::default()
        };
        config.validate().expect("account names");
        for entry in ["alice, bob", " bob", "", "1alice", "a".repeat(65).as_str()] {
            config.http.as_mut().unwrap().admin_accounts = vec![entry.to_string()];
            let error = config.validate().unwrap_err().to_string();
            assert!(
                error.contains("http.admin_accounts") && error.contains(&format!("{entry:?}")),
                "{entry:?}: {error}"
            );
        }
    }

    /// `secure_cookies` and the `public_url` scheme describe one deployment;
    /// both disagreements are refused, not just the one that breaks login.
    #[test]
    fn secure_cookies_and_public_url_scheme_must_agree() {
        let mut config = oidc_config("corp", "https://auth.example", None);
        config.validate().expect("https with secure cookies");
        config.http.as_mut().unwrap().secure_cookies = false;
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("secure_cookies must be true"), "{error}");
        config.http.as_mut().unwrap().public_url = Some("http://chat.example".into());
        config.oidc_providers[0].issuer_url = "http://auth.example".into();
        config
            .validate()
            .expect("http with plain cookies is local development");
        config.oidc_providers[0].issuer_url = "https://auth.example".into();
        config.http.as_mut().unwrap().secure_cookies = true;
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("public_url must be https"), "{error}");
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
    fn a_nicklen_too_short_for_a_guest_nick_is_rejected() {
        let short = Config {
            listeners: vec![listener()],
            nicklen: MIN_NICKLEN - 1,
            ..Config::default()
        };
        assert!(short.validate().is_err());
        let shortest = Config {
            listeners: vec![listener()],
            nicklen: MIN_NICKLEN,
            ..Config::default()
        };
        assert!(shortest.validate().is_ok());
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
                hsts_include_subdomains: false,
            }),
            database: Some(DatabaseConfig {
                url: "postgres://db.example/e6irc".parse().expect("database URL"),
                startup_wait_seconds: DEFAULT_STARTUP_WAIT_SECONDS,
                max_connections: None,
            }),
            oidc_providers: vec![OidcProviderConfig {
                name: name.into(),
                issuer_url: issuer.into(),
                client_id: "e6irc".into(),
                client_secret: "secret".into(),
                account_claim: OidcAccountClaim::PreferredUsername,
                scopes: vec![],
                allowed_email_domains: vec![],
                end_session_endpoint: end_session.map(str::to_string),
                token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
            }],
            application_release_revision: Some("0123456789ab".into()),
            ..Config::default()
        }
    }

    /// A description or motd line longer than its reply's room is refused at
    /// load and at a console save, which share this validation; it used to be
    /// accepted and clipped on the wire.
    #[test]
    fn texts_longer_than_their_reply_are_refused() {
        let mut config = listening_config();
        config.description = "d".repeat(MAX_DESCRIPTION_LEN);
        config.motd = vec!["fine".into(), "m".repeat(MAX_MOTD_LINE_LEN)];
        config.validate().expect("at the bounds");
        config.description.push('d');
        let refusal = config.validate().expect_err("description").to_string();
        assert!(
            refusal.contains("description must be at most 242 bytes"),
            "{refusal}"
        );
        config.description.pop();
        config.motd[1].push('m');
        let refusal = config.validate().expect_err("motd").to_string();
        assert!(
            refusal.contains("motd line 2 must be at most 372 bytes"),
            "{refusal}"
        );
        let managed = ManagedConfig::from_config(&config, None).expect("managed");
        let refusal = managed
            .validate(BootstrapContext {
                http_listener: None,
                hsts_include_subdomains: false,
                internal_upstreams: crate::egress::InternalUpstreams::Refuse,
                application_release_revision: None,
            })
            .expect_err("the console save is refused too")
            .to_string();
        assert!(refusal.contains("motd line 2"), "{refusal}");
    }

    /// A MOTD of more lines than the smallest SendQ holds at registration is
    /// refused at load and at a console save; it used to be accepted however
    /// long, and a slow reader's registration burst overran its SendQ.
    #[test]
    fn a_motd_longer_than_the_smallest_sendq_holds_is_refused() {
        assert_eq!(
            (
                MAX_MOTD_BYTES,
                MAX_MOTD_LINES_BYTES,
                MOTD_LINE_REPLY_OVERHEAD
            ),
            (8_703, 8_318, 140)
        );
        let mut config = listening_config();
        // Bytes, not lines: many short lines fit where few long ones would.
        let short = 8_318 / (1 + MOTD_LINE_REPLY_OVERHEAD);
        config.motd = vec!["m".into(); short];
        config.validate().expect("many short lines");
        assert!(short > 14, "{short}");
        // Long lines to the byte, then one byte more.
        let long = MAX_MOTD_LINE_LEN + MOTD_LINE_REPLY_OVERHEAD;
        let mut motd = vec!["m".repeat(MAX_MOTD_LINE_LEN); 15];
        motd.push("m".repeat(MAX_MOTD_LINES_BYTES - 15 * long - 2 * MOTD_LINE_REPLY_OVERHEAD));
        motd.push(String::new());
        assert_eq!(motd_reply_bytes(&motd), MAX_MOTD_BYTES);
        config.motd = motd;
        config.validate().expect("at the bound");
        config.motd.last_mut().expect("a line").push('m');
        let refusal = config.validate().expect_err("one byte more").to_string();
        assert!(
            refusal.contains(
                "motd must take at most 8703 bytes as sent at registration (it takes 8704"
            ),
            "{refusal}"
        );
        let managed = ManagedConfig::from_config(&config, None).expect("managed");
        let refusal = managed
            .validate(BootstrapContext {
                http_listener: None,
                hsts_include_subdomains: false,
                internal_upstreams: crate::egress::InternalUpstreams::Refuse,
                application_release_revision: None,
            })
            .expect_err("the console save is refused too")
            .to_string();
        assert!(refusal.contains("motd must take at most"), "{refusal}");
    }

    /// The console's form states the same bounds the validation holds a save
    /// to, so it does not offer a value the save refuses.
    #[test]
    fn the_console_form_states_the_configured_bounds() {
        let form = include_str!("../templates/console_configuration.html");
        for control in [
            format!("name=\"server_name\" maxlength=\"{MAX_SERVER_NAME_LEN}\""),
            format!("name=\"network_name\" maxlength=\"{MAX_NETWORK_NAME_LEN}\""),
            format!("name=\"description\" maxlength=\"{MAX_DESCRIPTION_LEN}\""),
            format!("each at most {MAX_MOTD_LINE_LEN} bytes"),
            format!(
                "together at most {MAX_MOTD_LINES_BYTES} bytes, each line counting \
                 {MOTD_LINE_REPLY_OVERHEAD} more"
            ),
            format!("name=\"buffer_cap\" min=\"1\" max=\"{MAX_NETWORK_BUFFER_CAP}\""),
        ] {
            assert!(form.contains(&control), "the form lacks {control}");
        }
    }

    /// A console save is judged against the running process's own release
    /// revision, as the next start is. It used to be judged against a made-up
    /// valid one, so a `shauth` provider saved on a deployment without an
    /// immutable revision and the next start refused the stored settings.
    #[test]
    fn a_console_save_is_judged_against_the_process_release_revision() {
        let stated = oidc_config(
            "shauth",
            "https://auth.example",
            Some("https://auth.example/oauth2/sessions/logout"),
        );
        let key = crate::secret::SecretKeyring::single(crate::secret::SecretKey::generate());
        let managed = ManagedConfig::from_config(&stated, Some(&key)).expect("managed");
        let context = |revision: Option<&str>| BootstrapContext {
            http_listener: None,
            hsts_include_subdomains: false,
            internal_upstreams: crate::egress::InternalUpstreams::Refuse,
            application_release_revision: revision.map(str::to_string),
        };
        for revision in [None, Some("main")] {
            let refusal = managed
                .validate(context(revision))
                .expect_err("start would refuse it")
                .to_string();
            assert!(
                refusal.contains("application_release_revision"),
                "{refusal}"
            );
        }
        managed
            .validate(context(Some("0123456789ab")))
            .expect("start accepts it");
    }

    /// A listener certificate edited in the console is read at the save, as
    /// start reads it: a path that does not load is refused then, not when the
    /// next start fails.
    #[test]
    fn a_console_save_reads_the_listener_certificates() {
        let directory =
            std::env::temp_dir().join(format!("e6irc-console-certificate-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("scratch directory");
        let files = TlsConfig {
            cert_path: directory.join("cert.pem"),
            key_path: directory.join("key.pem"),
        };
        let context = BootstrapContext {
            http_listener: None,
            hsts_include_subdomains: false,
            internal_upstreams: crate::egress::InternalUpstreams::Refuse,
            application_release_revision: None,
        };
        let mut managed = ManagedConfig::from_config(&listening_config(), None).expect("managed");
        managed.listeners.push(ListenerConfig {
            addr: "127.0.0.1:6697".parse().unwrap(),
            tls: Some(files.clone()),
            websocket: false,
        });
        let refusal = managed
            .validate(context.clone())
            .expect_err("missing certificate files")
            .to_string();
        assert!(refusal.contains("TLS certificate"), "{refusal}");
        assert!(refusal.contains("cert.pem"), "{refusal}");
        crate::certificate::write_self_signed(&files);
        managed
            .validate(context.clone())
            .expect("a certificate that loads");
        let other = TlsConfig {
            cert_path: directory.join("other-cert.pem"),
            key_path: directory.join("other-key.pem"),
        };
        crate::certificate::write_self_signed(&other);
        managed.listeners[1].tls = Some(TlsConfig {
            cert_path: files.cert_path.clone(),
            key_path: other.key_path.clone(),
        });
        assert!(
            managed.validate(context).is_err(),
            "a key that does not match its certificate is refused"
        );
        std::fs::remove_dir_all(directory).expect("remove the scratch directory");
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
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("issuer_url must be https"), "{error}");
        // The browser is sent to the end-session endpoint with the ID token.
        let config = oidc_config(
            "dex",
            "https://auth.example",
            Some("http://auth.example/logout"),
        );
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("end_session_endpoint must be https"),
            "{error}"
        );
        // A dev setup (secure_cookies = false, http public_url) may still use
        // http locally.
        let mut dev = oidc_config(
            "dex",
            "http://127.0.0.1:5556/dex",
            Some("http://127.0.0.1:5556/dex/logout"),
        );
        dev.http.as_mut().unwrap().secure_cookies = false;
        dev.http.as_mut().unwrap().public_url = Some("http://127.0.0.1:8080".into());
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
            account_claim: OidcAccountClaim::PreferredUsername,
            scopes: vec![],
            allowed_email_domains: vec![],
            end_session_endpoint: None,
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
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
account_claim = "preferred_username"
token_endpoint_auth_method = "client_secret_basic"
allowed_email_domains = ["Example.COM", "subsidiary.example"]
"#,
        )
        .expect("parse");
        assert_eq!(
            parsed.oidc_providers[0].allowed_email_domains[0].as_str(),
            "example.com"
        );
        parsed.validate().expect("valid domain policy");

        let missing_claim = toml::from_str::<Config>(
            r#"
[[oidc]]
name = "corp"
issuer_url = "https://auth.example"
client_id = "e6irc"
client_secret = "secret"
token_endpoint_auth_method = "client_secret_basic"
"#,
        )
        .expect_err("OIDC account claim is required");
        assert!(missing_claim.to_string().contains("account_claim"));

        let missing_token_auth = toml::from_str::<Config>(
            r#"
[[oidc]]
name = "corp"
issuer_url = "https://auth.example"
client_id = "e6irc"
client_secret = "secret"
account_claim = "preferred_username"
"#,
        )
        .expect_err("OIDC token authentication is required");
        assert!(
            missing_token_auth
                .to_string()
                .contains("token_endpoint_auth_method")
        );
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
                account_claim: OidcAccountClaim::PreferredUsername,
                scopes: vec![],
                allowed_email_domains: vec![],
                end_session_endpoint: None,
                token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
            }],
            secrets: secrets_at(&path),
            ..Config::default()
        };
        cfg.resolve_secrets().expect("resolve");
        std::fs::remove_file(&path).ok();
        assert_eq!(cfg.opers[0].password, "operpass");
        assert_eq!(cfg.oidc_providers[0].client_secret, "oidcsecret");
    }
    /// Attaching clients send their account password. A listener off loopback
    /// without TLS would carry it in cleartext; it is refused by the file and by
    /// the console save alike, naming the setting to change.
    #[test]
    fn a_cleartext_attach_listener_is_refused_off_loopback() {
        let mut config = listening_config();
        config.database = Some(DatabaseConfig {
            url: "postgres://localhost/e6irc".parse().expect("database URL"),
            startup_wait_seconds: DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        });
        for addr in [
            "0.0.0.0:6697",
            "192.0.2.10:6697",
            "[::]:6697",
            "[::ffff:192.0.2.10]:6697",
        ] {
            config.bnc = Some(BncConfig {
                addr: addr.parse().unwrap(),
                tls: None,
            });
            let message = refusal(&config);
            assert!(
                message.contains("[bnc].tls") && message.contains("bnc_tls"),
                "{addr}: {message}"
            );
        }
        for addr in ["127.0.0.1:6697", "[::1]:6697", "[::ffff:127.0.0.1]:6697"] {
            config.bnc = Some(BncConfig {
                addr: addr.parse().unwrap(),
                tls: None,
            });
            config
                .validate()
                .expect("loopback plaintext stays on this machine");
        }
        config.bnc = Some(BncConfig {
            addr: "0.0.0.0:6697".parse().unwrap(),
            tls: Some(TlsConfig {
                cert_path: "/etc/e6irc/cert.pem".into(),
                key_path: "/etc/e6irc/key.pem".into(),
            }),
        });
        config.validate().expect("a TLS listener may bind anywhere");

        let mut managed = ManagedConfig::from_config(&listening_config(), None).expect("managed");
        managed.bnc_addr = Some("0.0.0.0:6697".parse().unwrap());
        let bootstrap = BootstrapContext {
            http_listener: None,
            hsts_include_subdomains: false,
            internal_upstreams: crate::egress::InternalUpstreams::Refuse,
            application_release_revision: None,
        };
        let error = managed
            .validate(bootstrap.clone())
            .expect_err("the console save is refused too")
            .to_string();
        assert!(error.contains("bnc_tls"), "{error}");
        let directory =
            std::env::temp_dir().join(format!("e6irc-console-bnc-tls-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("scratch directory");
        let files = TlsConfig {
            cert_path: directory.join("cert.pem"),
            key_path: directory.join("key.pem"),
        };
        crate::certificate::write_self_signed(&files);
        managed.bnc_tls = Some(files);
        managed.validate(bootstrap).expect("with a certificate");
        std::fs::remove_dir_all(directory).expect("remove the scratch directory");
    }

    /// Widening a header that is never sent would be a setting that does
    /// nothing: HSTS goes out only for an `https://` public origin.
    #[test]
    fn hsts_subdomains_needs_an_https_public_origin() {
        let mut config = listening_config();
        config.database = Some(DatabaseConfig {
            url: "postgres://localhost/e6irc".parse().expect("database URL"),
            startup_wait_seconds: DEFAULT_STARTUP_WAIT_SECONDS,
            max_connections: None,
        });
        config.http = Some(HttpConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            public_url: Some("http://irc.example".into()),
            secure_cookies: false,
            admin_accounts: vec![],
            hsts_include_subdomains: true,
        });
        assert!(refusal(&config).contains("hsts_include_subdomains"));
        let http = config.http.as_mut().unwrap();
        http.public_url = Some("https://irc.example".into());
        http.secure_cookies = true;
        config
            .validate()
            .expect("an HTTPS origin may widen its HSTS");
    }

    #[test]
    fn only_settings_the_process_re_reads_avoid_a_restart() {
        let current = ManagedConfig::from_config(&Config::default(), None).unwrap();
        assert!(!current.requires_restart_to_reach(&current));

        // Applied live: storage maintenance and the sampler re-read these every
        // cycle, and the BNC attach listener is rebound in place.
        let mut retention = current.clone();
        retention.storage.history_retention_days += 1;
        assert!(!current.requires_restart_to_reach(&retention));
        let mut listener = current.clone();
        listener.bnc_addr = Some("127.0.0.1:6699".parse().unwrap());
        assert!(!current.requires_restart_to_reach(&listener));

        // Read once, at start.
        let mut renamed = retention.clone();
        renamed.server_name = "irc.other.example".into();
        assert!(current.requires_restart_to_reach(&renamed));
        let mut resized = current.clone();
        resized.sendq_bytes += 1;
        assert!(current.requires_restart_to_reach(&resized));
    }

    /// Every console-owned setting is named by the key a document states it
    /// under. A setting whose name mapped nowhere could never be found stated,
    /// so a changed value of it would be ignored again, silently.
    #[test]
    fn every_console_owned_setting_maps_to_the_key_a_document_states_it_under() {
        let everything: toml::Table = toml::from_str(
            r#"
            server_name = "irc.example"
            network_name = "example"
            description = "d"
            motd = ["m"]
            nicklen = 16
            sendq_bytes = 524288
            core_queue = 1024
            core_workers = 1
            max_hot_channels = 8
            max_history_ring_bytes = 512000
            max_hot_history_bytes = 536870912
            [[listeners]]
            addr = "127.0.0.1:6667"
            [registration]
            before_connect = true
            [limits]
            command_burst = 40
            [observability]
            enabled = true
            [storage]
            history_retention_days = 30
            [bnc]
            addr = "127.0.0.1:6698"
            tls = { cert_path = "c", key_path = "k" }
            [http]
            addr = "127.0.0.1:8080"
            public_url = "https://irc.example"
            secure_cookies = true
            admin_accounts = ["alice"]
            [[oidc]]
            name = "idp"
            [[oper]]
            name = "root"
            [[network]]
            name = "libera"
            "#,
        )
        .expect("document");
        let stated = StatedSettings::of_document(&everything, &[]);
        let settings = ManagedConfig::from_config(&Config::default(), None).expect("managed");
        let serialized = serde_json::to_value(&settings).expect("serializes");
        for field in serialized.as_object().expect("an object").keys() {
            match bootstrap_path(field) {
                Some(path) => assert!(stated.covers(&path), "{field} maps to {path}, unstated"),
                None => assert_eq!(field, "credentials_from_bootstrap"),
            }
        }
        let nothing = StatedSettings::of_document(&toml::Table::new(), &[]);
        assert!(!nothing.covers("http.admin_accounts"));
        // A key encloses what is inside it; a key inside a path states part of it.
        assert!(stated.covers("oidc[0].client_secret"));
        assert!(stated.covers("bnc.tls"));
        assert!(!stated.covers("http.addrx"));
    }

    /// The configuration a document states, and the revision it imports on a
    /// first start.
    fn stated_and_imported(
        document: &str,
        key: &crate::secret::SecretKeyring,
    ) -> (Config, ManagedConfig) {
        let config =
            Config::from_table(toml::from_str(document).expect("document"), &[]).expect("valid");
        let imported = ManagedConfig::from_config(&config, Some(key)).expect("imported");
        (config, imported)
    }

    const DRIFT_DOCUMENT: &str = r#"
        server_name = "irc.example"
        network_name = "example"
        [[listeners]]
        addr = "127.0.0.1:6667"
        [database]
        url = "postgres://localhost/e6irc"
        [http]
        addr = "127.0.0.1:8080"
        public_url = "https://irc.example"
        admin_accounts = ["alice", "bob"]
        [[oidc]]
        name = "idp"
        issuer_url = "https://idp.example"
        client_id = "e6irc"
        client_secret = "first-client-secret"
        account_claim = "preferred_username"
        token_endpoint_auth_method = "client_secret_post"
    "#;

    #[test]
    fn a_stated_setting_that_differs_from_the_stored_one_is_named_and_never_shown() {
        let key = crate::secret::SecretKeyring::single(crate::secret::SecretKey::generate());
        let (config, stored) = stated_and_imported(DRIFT_DOCUMENT, &key);
        assert_eq!(
            stored.bootstrap_drift(&config, Some(&key)).unwrap(),
            Vec::<String>::new(),
            "the revision a document imported agrees with it"
        );

        let (fewer_admins, _) =
            stated_and_imported(&DRIFT_DOCUMENT.replace(r#", "bob""#, ""), &key);
        assert_eq!(
            stored.bootstrap_drift(&fewer_admins, Some(&key)).unwrap(),
            ["http.admin_accounts"]
        );

        let (rotated, _) = stated_and_imported(
            &DRIFT_DOCUMENT.replace("first-client-secret", "second-client-secret"),
            &key,
        );
        let drift = stored.bootstrap_drift(&rotated, Some(&key)).unwrap();
        assert_eq!(drift, ["oidc[0].client_secret"]);
        let refusal = ManagedSettingsConflict {
            settings: drift,
            revision: 1,
            updated_by: "bootstrap".into(),
            updated_at: "now".into(),
        }
        .to_string();
        assert!(refusal.contains("oidc[0].client_secret"), "{refusal}");
        assert!(
            !refusal.contains("first-client") && !refusal.contains("second-client"),
            "{refusal}"
        );

        // Unstated, the list is the console's alone.
        let (unstated, _) = stated_and_imported(
            &DRIFT_DOCUMENT.replace(r#"admin_accounts = ["alice", "bob"]"#, ""),
            &key,
        );
        let mut console_edited = stored.clone();
        console_edited.admin_accounts = vec!["carol".into()];
        assert!(
            console_edited
                .bootstrap_drift(&unstated, Some(&key))
                .unwrap()
                .is_empty()
        );
        // A configuration built in code states everything it holds.
        let mut built = config.clone();
        built.stated = StatedSettings::Everything;
        assert_eq!(
            console_edited.bootstrap_drift(&built, Some(&key)).unwrap(),
            ["http.admin_accounts"]
        );
    }

    /// The environment's own defaults are not an operator's statement: an unset
    /// `E6IRC_NETWORK_NAME` or `E6IRC_IRC_ADDR` leaves the setting to the
    /// console, and a set one is held to it.
    #[test]
    fn an_environment_default_is_not_held_to_the_stored_value() {
        let minimal = [
            ("E6IRC_SERVER_NAME", "irc.example"),
            ("E6IRC_PUBLIC_URL", "https://irc.example"),
            ("E6IRC_DATABASE_URL", "postgres://localhost/e6irc"),
            ("APPLICATION_RELEASE_REVISION", "0123456789abcdef"),
        ];
        let from = |pairs: &[(&'static str, &'static str)]| {
            let document = crate::environment_config::configuration_table(&|variable: &str| {
                Ok(pairs
                    .iter()
                    .find(|(name, _)| *name == variable)
                    .map(|(_, value)| (*value).to_owned()))
            })
            .expect("environment");
            Config::from_table(document.table, &document.defaulted).expect("valid")
        };
        let config = from(&minimal);
        let mut stored = ManagedConfig::from_config(&config, None).expect("managed");
        stored.network_name = "Console".into();
        stored.listeners[0].addr = "127.0.0.1:7000".parse().unwrap();
        assert!(stored.bootstrap_drift(&config, None).unwrap().is_empty());

        let mut stating = minimal.to_vec();
        stating.extend([
            ("E6IRC_NETWORK_NAME", "e6qu"),
            ("E6IRC_IRC_ADDR", "127.0.0.1:6667"),
        ]);
        assert_eq!(
            stored.bootstrap_drift(&from(&stating), None).unwrap(),
            ["listeners[0].addr", "network_name"]
        );
    }
}
