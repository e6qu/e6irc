//! BNC (bouncer) subsystem: persistent connections to external IRC
//! networks on behalf of a user (DESIGN §10.3). Each network is an
//! always-on [`IrcNetwork`] driver running on its own task; the
//! buffering and attach logic above the drivers is shared.
//!
//! The [`Registry`] holds the running drivers keyed by (owner, name) and
//! is mutable at runtime, so accounts add and remove their own networks
//! (persisted in the `bnc_networks` table, upstream secrets sealed).
//! [`bnc_serve`] authenticates an attaching client with SASL PLAIN and
//! hands its socket to [`attach`], which replays the detached buffer and
//! relays live traffic both ways.

#![deny(clippy::let_underscore_must_use)]

#[cfg(any(feature = "discord", feature = "slack"))]
use std::collections::HashMap;
#[cfg(any(feature = "discord", feature = "slack"))]
use std::future::Future;

use e6irc_proto::message::MiddleParam;

mod account_lease;
mod attach_link;
pub use account_lease::{
    AccountLease, AccountRevocations, AccountRevoked, Revocation, RevocationTicket,
};
pub(crate) use attach_link::ATTACH_INBOUND_BYTES;
pub use attach_link::{AttachLink, AttachPort, ClientLines};
#[cfg(all(test, feature = "discord", feature = "slack"))]
mod bridge_oracle;
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
mod bridged_senders;
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
pub(crate) use bridged_senders::{BridgedSenders, ProviderAccount};
mod channel_views;
mod chathistory;
#[cfg(feature = "discord")]
mod discord;
mod irc_driver;
mod local_driver;
#[cfg(feature = "matrix")]
mod matrix;
mod nick_regain;
mod replies;
mod serve;
#[cfg(feature = "slack")]
mod slack;
mod upstream_identity;

#[cfg(feature = "discord")]
pub use discord::{DiscordConfig, DiscordDriver};
pub(crate) use irc_driver::KEEPALIVE_IDLE;
pub(crate) use irc_driver::validate_irc_upstream_addr;
pub use irc_driver::{
    FirstDial, IrcNetwork, IrcPreflight, IrcPreflightFailure, NetworkConfig, preflight_irc,
};
pub use local_driver::{CoreHandles, LocalDriver};
#[cfg(feature = "matrix")]
pub use matrix::{MatrixConfig, MatrixDevice, MatrixDriver};
pub use nick_regain::NickRegainTiming;
pub use serve::{ConfiguredNetwork, DriverStops, NetworkStatus, Registry};
pub(crate) use serve::{
    ConfiguredNetworkHeld, MutationLane, RegistryRefusal, UnwrittenLines, bnc_resume, bnc_serve,
};
#[cfg(feature = "slack")]
pub use slack::{SlackConfig, SlackDriver};
pub use upstream_identity::{
    AutojoinChannel, AutojoinEntry, ConfirmedChannel, UpstreamChannel, UpstreamIdentity,
    UpstreamIdentityError, UpstreamNick, UpstreamRealname, UpstreamSaslAccount, UpstreamUsername,
};

/// The ISUPPORT a network is described with when it has reported nothing of
/// its own — a bridge, which has no registration burst, or an upstream whose
/// burst has not arrived yet. A bridge delivers a STATUSMSG to the channel
/// itself (it has no ranks to narrow the audience to), so it accepts the
/// sigils.
pub(crate) const BRIDGE_ISUPPORT: &[&str] = &[
    "CASEMAPPING=rfc1459",
    "CHANTYPES=#&",
    "CHANNELLEN=64",
    "NICKLEN=30",
    "PREFIX=(qaohv)~&@%+",
    "STATUSMSG=@+",
];

/// How a bridge names things: [`BRIDGE_ISUPPORT`], read the way a client
/// reads it. Bridge routing and a bridge's backlog filing both classify
/// targets through this, so a message cannot be delivered to one conversation
/// and stored under another.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
pub(crate) fn bridge_names() -> e6irc_client::NetworkNames {
    let mut names = e6irc_client::NetworkNames::default();
    names.adopt_tokens(BRIDGE_ISUPPORT.iter().copied());
    names
}

/// ISUPPORT tokens the bouncer answers for itself rather than the network:
/// it serves CHATHISTORY from its own store, so the network's limits and
/// reference types say nothing about what an attached client can page; and
/// it decides which client-only tags reach the network (`CLIENTTAGDENY`),
/// since it strips them all for a network that cannot carry them.
pub(crate) const BOUNCER_OWNED_ISUPPORT: &[&str] = &["CHATHISTORY", "MSGREFTYPES", "CLIENTTAGDENY"];

/// The name of an ISUPPORT token (`CHANTYPES` of `CHANTYPES=#`, `-CHANTYPES`).
fn isupport_key(token: &str) -> &str {
    let token = token.strip_prefix('-').unwrap_or(token);
    token.split('=').next().unwrap_or(token)
}

/// The secret-context a BNC upstream password is sealed under: its *owning*
/// e6irc account, casefolded, with a `bnc:` purpose tag. Binding the blob to the
/// owner means a sealed password cannot be opened for a different account's row
/// (the AEAD tag check fails), and the `bnc:` tag keeps it distinct from a config
/// secret's [`crate::secret::CONFIG_CONTEXT`]. Seal and open must derive it the
/// same way, so both go through this one function.
pub fn bnc_secret_context(owner: &str) -> Vec<u8> {
    let folded = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(owner);
    format!("bnc:{folded}").into_bytes()
}

/// Default backlog buffer capacity for a runtime-created (DB-backed) network.
const DB_NETWORK_BUFFER_CAP: usize = 1000;
const _: () = assert!(
    DB_NETWORK_BUFFER_CAP <= crate::config::MAX_NETWORK_BUFFER_CAP,
    "a stored network's buffer must fit what storage keeps, or a restart restores less"
);

/// The one credential-field shape accepted by config, HTTP, stored-row driver
/// construction, and runtime edits.
pub(crate) fn validate_network_credential(value: &str, maximum: usize) -> Result<(), String> {
    if value.trim().is_empty()
        || value.len() > maximum
        || value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0))
    {
        Err(format!(
            "credentials must be non-blank, at most {maximum} bytes, and contain no CR, LF or NUL"
        ))
    } else {
        Ok(())
    }
}

/// Resolve provider channel ids into the two maps every chat bridge needs,
/// enforcing IRC target safety and RFC1459-casefold uniqueness once. Provider
/// drivers supply only their lookup request and failure classification, so
/// Discord and Slack cannot drift on the mapping invariants.
#[cfg(any(feature = "discord", feature = "slack"))]
async fn resolve_bridge_channels<F, Fut, L, E>(
    provider: &str,
    ids: &[String],
    mut fetch_name: F,
    classify_lookup_error: E,
) -> Result<(HashMap<String, String>, HashMap<String, String>), SessionOutcome>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<String, L>>,
    E: Fn(&str, L) -> SessionOutcome,
{
    let mut id_to_channel = HashMap::new();
    let mut channel_to_id = HashMap::new();
    for id in ids {
        let name = match fetch_name(id.clone()).await {
            Ok(name) => name,
            Err(error) => return Err(classify_lookup_error(id, error)),
        };
        let channel = format!("#{name}");
        if crate::sanitize::ChannelName::parse(&channel).is_err() {
            eprintln!(
                "{provider}: channel {id} has an unsafe name {name:?}; refusing to bridge it"
            );
            return Err(SessionOutcome::ConfigurationRejected(
                ConfigurationRefusal::new(
                    NetworkFailure::ChannelMappingFailed,
                    &format!("channel {id} has a name that is not a safe IRC channel name"),
                ),
            ));
        }
        let folded = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(&channel);
        if channel_to_id.contains_key(&folded) {
            eprintln!(
                "{provider}: channel {id} name {name:?} collides with an already-bridged \
                 channel {channel:?}; refusing to bridge it"
            );
            return Err(SessionOutcome::ConfigurationRejected(
                ConfigurationRefusal::new(
                    NetworkFailure::ChannelMappingFailed,
                    &format!("channel {id} maps to {channel}, which another channel already uses"),
                ),
            ));
        }
        id_to_channel.insert(id.clone(), channel);
        channel_to_id.insert(folded, id.clone());
    }
    Ok((id_to_channel, channel_to_id))
}

/// Validate the HTTP endpoint column used by a bridge driver. Matrix requires
/// one; Discord and Slack use their provider default when it is empty. Keeping
/// this at the driver-factory boundary means config, database boot, and runtime
/// mutations cannot disagree about which URL shapes are constructible.
pub(crate) fn validate_bridge_base(
    kind: crate::config::NetworkKind,
    value: &str,
) -> Result<(), String> {
    use crate::config::NetworkKind;
    let required = match kind {
        NetworkKind::Matrix => true,
        NetworkKind::Discord | NetworkKind::Slack => false,
        NetworkKind::Irc | NetworkKind::Local => {
            return Err(format!("kind={} is not an HTTP bridge", kind.as_db_str()));
        }
    };
    if value.is_empty() {
        return if required {
            Err(format!(
                "kind={} requires a homeserver URL",
                kind.as_db_str()
            ))
        } else {
            Ok(())
        };
    }
    let parsed = url::Url::parse(value).map_err(|_| {
        format!(
            "kind={} requires a valid HTTP(S) base URL",
            kind.as_db_str()
        )
    })?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(format!(
            "kind={} base URL must be absolute HTTP(S), without credentials, query, or fragment",
            kind.as_db_str()
        ));
    }
    // The Matrix password and access token, and the Discord and Slack bot
    // tokens, cross this base on every request; the gateway sockets already
    // refuse cleartext. Only the loopback test oracle may speak `http://`,
    // and only under `internal_upstreams = "allow"` does anything dial it.
    if parsed.scheme() == "http" && !parsed.host().is_some_and(is_loopback_host) {
        return Err(format!(
            "kind={} base URL must be https://: the network's credentials cross it, and only \
             a loopback http:// test oracle may speak cleartext",
            kind.as_db_str()
        ));
    }
    Ok(())
}

/// Everything a driver is built from, as named fields: the factory's callers
/// (static configuration, stored rows, the API) each hold these under their own
/// names, and a positional list of nine strings and options is one
/// transposition away from a real name registered as a user name.
pub struct DriverSpec {
    pub kind: crate::config::NetworkKind,
    /// The owning account, or `None` for a server-level network. With `name` it
    /// is the network's identity towards an upstream that tracks devices.
    pub owner: Option<String>,
    pub name: String,
    pub addr: String,
    pub tls: bool,
    pub nick: String,
    /// The IRC `USER` name. Required for `kind=irc`, refused for a bridge.
    pub username: Option<String>,
    /// Required for `kind=irc`; empty for a bridge.
    pub realname: String,
    /// The channels (a bridge's rooms or channel ids) to join, plaintext. Only
    /// an IRC channel has a key; a bridge's entry carrying one is refused.
    pub autojoin: Vec<AutojoinEntry>,
    pub buffer_cap: usize,
    pub sasl_account: Option<String>,
    pub sasl_password: Option<String>,
    /// The IRC connection password (`PASS`), plaintext. Accepted for
    /// `kind=irc` only; refused for a bridge.
    pub server_password: Option<String>,
    /// The server's policy on upstreams inside its own network.
    pub internal_upstreams: crate::egress::InternalUpstreams,
    /// Whether the driver dials at once or holds its first dial back as one of
    /// a boot's many (see [`FirstDial`]). Bridges dial their own APIs and
    /// ignore it.
    pub first_dial: FirstDial,
}

/// Build the driver for a network of `kind` from its *plaintext* fields — the
/// one feature-gated factory that maps the generic network fields onto each
/// backend's config. A bridge kind whose build feature is absent is a loud
/// error (never a silent fall-through to IRC), and `local` is not creatable as a
/// bouncer network. Used by config-network startup, DB-network boot, runtime
/// create, and re-enable, so no site can construct a driver by kind differently.
pub fn build_driver(spec: DriverSpec) -> Result<Box<dyn NetworkDriver>, String> {
    use crate::config::NetworkKind;
    let DriverSpec {
        kind,
        owner,
        name,
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
        internal_upstreams,
        first_dial,
    } = spec;
    let required_field = |value: String, field: &str, maximum: usize| {
        validate_network_credential(&value, maximum)
            .map(|()| value)
            .map_err(|error| format!("kind={} has invalid {field}: {error}", kind.as_db_str()))
    };
    let required_secret = |value: Option<String>, field: &str, maximum: usize| {
        required_field(
            value.ok_or_else(|| format!("kind={} requires {field}", kind.as_db_str()))?,
            field,
            maximum,
        )
    };
    if kind.is_bridge() && username.is_some() {
        return Err(format!(
            "kind={} does not accept a username; it applies only to IRC networks",
            kind.as_db_str()
        ));
    }
    if kind.is_bridge() && server_password.is_some() {
        return Err(format!(
            "kind={} does not accept a server password; it applies only to IRC networks",
            kind.as_db_str()
        ));
    }
    if kind.is_bridge() && autojoin.iter().any(|entry| entry.key.is_some()) {
        return Err(format!(
            "kind={} does not accept channel keys; they apply only to IRC networks",
            kind.as_db_str()
        ));
    }
    // What a bridge joins is a provider's room or channel id, which has no key.
    #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
    let bridged =
        || -> Vec<String> { autojoin.iter().map(|entry| entry.channel.clone()).collect() };
    match kind {
        // The Irc arm uses every parameter but the network's identity, so they
        // are never "unused" even in a build with no bridge features — the
        // bridge arms below just don't run.
        NetworkKind::Irc => {
            if !validate_irc_upstream_addr(&addr) {
                return Err(
                    "kind=irc requires addr as host:port with a nonzero numeric port".into(),
                );
            }
            // Every driver is built here — static configuration, stored rows,
            // the API — so a network whose credentials would cross cleartext
            // never gets a driver (a row stored before the rule existed says
            // so at boot instead of failing on every dial).
            if let Some(credential) = internal_upstreams.cleartext_credential(
                &addr,
                tls,
                sasl_password.is_some(),
                server_password.is_some(),
            ) {
                return Err(credential.reason().to_string());
            }
            let sasl = match (sasl_account, sasl_password) {
                (Some(account), Some(password)) => Some((
                    required_field(account, "SASL account", 255)?,
                    required_field(password, "SASL password", 512)?,
                )),
                (None, None) => None,
                _ => {
                    return Err(
                        "kind=irc requires both a SASL account and password, or neither".into(),
                    );
                }
            };
            let identity_error =
                |error: UpstreamIdentityError| format!("kind=irc has invalid {error}");
            let username = username.ok_or("kind=irc requires a username")?;
            let server_password = server_password
                .map(e6irc_client::ServerPassword::parse)
                .transpose()
                .map_err(|error| format!("kind=irc has an invalid server password: {error}"))?;
            let UpstreamIdentity {
                nick,
                username,
                realname,
                autojoin,
            } = UpstreamIdentity::parse(&nick, &username, &realname, &autojoin)
                .map_err(identity_error)?;
            Ok(Box::new(IrcDriver::new(NetworkConfig {
                addr,
                tls,
                nick,
                username,
                realname,
                autojoin,
                buffer_cap,
                sasl,
                server_password,
                keepalive_idle: KEEPALIVE_IDLE,
                rejection_retry_floor: REJECTION_RETRY_FLOOR,
                internal_upstreams,
                first_dial,
                nick_regain: NickRegainTiming::default(),
            })))
        }
        NetworkKind::Local => {
            Err("kind=local is an in-process network, not creatable as a bouncer network".into())
        }
        NetworkKind::Matrix => {
            validate_bridge_base(kind, &addr)?;
            if !tls {
                return Err("kind=matrix requires tls=true as its HTTP transport marker".into());
            }
            if nick.is_empty() {
                return Err("kind=matrix requires a user".into());
            }
            if sasl_account.is_some() {
                return Err("kind=matrix does not accept a SASL account field".into());
            }
            let password = required_secret(sasl_password, "a login password", 512)?;
            #[cfg(feature = "matrix")]
            {
                Ok(Box::new(MatrixDriver::new(MatrixConfig {
                    device: matrix::MatrixDevice::for_network(owner.as_deref(), &name),
                    homeserver: addr,
                    user: nick,
                    password,
                    rooms: bridged(),
                    buffer_cap,
                    internal_upstreams,
                })))
            }
            #[cfg(not(feature = "matrix"))]
            {
                drop((password, owner, name));
                Err("kind=matrix but this binary was built without the `matrix` feature".into())
            }
        }
        NetworkKind::Discord => {
            validate_bridge_base(kind, &addr)?;
            if !tls {
                return Err("kind=discord requires tls=true as its HTTP transport marker".into());
            }
            if !nick.is_empty() {
                return Err("kind=discord does not accept a nick field".into());
            }
            if sasl_account.is_some() {
                return Err("kind=discord does not accept a SASL account field".into());
            }
            let token = required_secret(sasl_password, "a bot token", 512)?;
            #[cfg(feature = "discord")]
            {
                let channels = bridged()
                    .iter()
                    .map(|channel| discord::DiscordChannelId::parse(channel))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| format!("kind=discord has an invalid channel: {error}"))?;
                Ok(Box::new(DiscordDriver::new(DiscordConfig {
                    token,
                    api_base: addr,
                    channels,
                    buffer_cap,
                    internal_upstreams,
                })))
            }
            #[cfg(not(feature = "discord"))]
            {
                drop(token);
                Err("kind=discord but this binary was built without the `discord` feature".into())
            }
        }
        NetworkKind::Slack => {
            validate_bridge_base(kind, &addr)?;
            if !tls {
                return Err("kind=slack requires tls=true as its HTTP transport marker".into());
            }
            if !nick.is_empty() {
                return Err("kind=slack does not accept a nick field".into());
            }
            let bot_token = required_secret(sasl_account, "a bot token", 255)?;
            let app_token = required_secret(sasl_password, "an app token", 512)?;
            #[cfg(feature = "slack")]
            {
                Ok(Box::new(SlackDriver::new(SlackConfig {
                    bot_token,
                    app_token,
                    api_base: addr,
                    channels: bridged(),
                    buffer_cap,
                    internal_upstreams,
                })))
            }
            #[cfg(not(feature = "slack"))]
            {
                drop((bot_token, app_token));
                Err("kind=slack but this binary was built without the `slack` feature".into())
            }
        }
    }
}

/// Build the driver for a persisted network row, unsealing its stored secrets
/// per kind: the password (`sasl_password_sealed`), the IRC server password
/// (`server_password_sealed`) and each autojoin channel's key are always
/// sealed, and for a
/// kind whose *account* field carries a secret (Slack's bot token) that is
/// sealed too — an IRC `sasl_account` is a public name and stays plaintext.
pub fn driver_from_row(
    row: &crate::db::BncNetworkRow,
    key: Option<&crate::secret::SecretKeyring>,
    owner: &str,
    internal_upstreams: crate::egress::InternalUpstreams,
    first_dial: FirstDial,
) -> Result<Box<dyn NetworkDriver>, String> {
    if row.kind.is_bridge() && row.realname.is_some() {
        return Err(format!(
            "kind={} does not accept a real name field",
            row.kind.as_db_str()
        ));
    }
    let context = bnc_secret_context(owner);
    let unseal = |blob: &str| -> Result<String, String> {
        let key = key.ok_or("stored upstream secret present but no master key is configured")?;
        key.open(blob, &context).map_err(|e| e.to_string())
    };
    let password = match &row.sasl_password_sealed {
        Some(sealed) => Some(unseal(sealed)?),
        None => None,
    };
    let account = match &row.sasl_account {
        Some(account) if row.kind.account_is_secret() => Some(unseal(account)?),
        other => other.clone(),
    };
    let server_password = match &row.server_password_sealed {
        Some(sealed) => Some(unseal(sealed)?),
        None => None,
    };
    let autojoin = row
        .autojoin
        .iter()
        .map(|entry| {
            Ok(AutojoinEntry {
                channel: entry.channel.clone(),
                key: entry.key_sealed.as_deref().map(unseal).transpose()?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let realname = match row.kind {
        crate::config::NetworkKind::Irc => row.realname.clone().ok_or_else(|| {
            "kind=irc stored network has no realname; update the network configuration".to_string()
        })?,
        crate::config::NetworkKind::Local => {
            return Err("kind=local is not a stored bouncer network".into());
        }
        crate::config::NetworkKind::Matrix
        | crate::config::NetworkKind::Discord
        | crate::config::NetworkKind::Slack => String::new(),
    };
    build_driver(DriverSpec {
        kind: row.kind,
        owner: Some(owner.to_string()),
        name: row.name.clone(),
        addr: row.addr.clone(),
        tls: row.tls,
        nick: row.nick.clone(),
        username: row.username.clone(),
        realname,
        autojoin,
        buffer_cap: DB_NETWORK_BUFFER_CAP,
        sasl_account: account,
        sasl_password: password,
        server_password,
        internal_upstreams,
        first_dial,
    })
}

use tokio::sync::mpsc;

/// Jittered exponential reconnect backoff shared by every always-on driver, so
/// their reconnect timing stays identical in one place. Starts at 200ms,
/// doubles per drop, caps at 30s, and resets once a session lasted long enough
/// (≥10s) to have clearly connected — otherwise a flapping-but-reachable
/// upstream would ratchet toward the cap forever. Jitter is a fixed fraction
/// of the delay, drawn per driver from its seed (no RNG), so concurrent
/// drivers that drop together spread out, and spread out *more* as the delay
/// grows — a fixed sub-100 ms spread on a four-minute refusal step put every
/// driver of one restart back on the throttled server within the same second.
pub(crate) struct Backoff {
    current: std::time::Duration,
    /// This driver's share of the jitter window, in thousandths of the base
    /// delay: 0 to [`Self::JITTER_PERMILLE_SPAN`]. Fixed for the driver's
    /// lifetime, so its whole schedule is shifted rather than shuffled.
    jitter_permille: u64,
}

impl Backoff {
    /// Jitter is 0–25% of the base delay.
    const JITTER_PERMILLE_SPAN: u64 = 250;

    /// The widest spread of first dials after a process start.
    pub(crate) const FIRST_DIAL_STAGGER: std::time::Duration = std::time::Duration::from_secs(5);

    pub(crate) fn new(seed: u64) -> Self {
        Self {
            current: std::time::Duration::from_millis(200),
            jitter_permille: Self::spread(seed) % (Self::JITTER_PERMILLE_SPAN + 1),
        }
    }

    /// Fibonacci-hash the stable per-driver seed so sequential driver ids land
    /// far apart in whatever window a caller reduces this into.
    const fn spread(seed: u64) -> u64 {
        seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32
    }

    /// The jitter this driver adds to `base`.
    pub(crate) fn jitter(&self, base: std::time::Duration) -> std::time::Duration {
        base.mul_f64(self.jitter_permille as f64 / 1000.0)
    }

    /// How long a driver started at boot waits before its first dial: a point
    /// in `[0, FIRST_DIAL_STAGGER)` fixed by the seed, so a restart with many
    /// networks on one round robin does not dial them all in one burst.
    pub(crate) fn first_dial_stagger(seed: u64) -> std::time::Duration {
        std::time::Duration::from_millis(
            Self::spread(seed) % Self::FIRST_DIAL_STAGGER.as_millis() as u64,
        )
    }

    /// Where in the vetted address list `attempt` starts (0-based), so
    /// concurrent drivers spread across a round robin and one driver's retries
    /// walk it instead of re-dialling the address that just refused. Every
    /// address is still tried; only the order rotates.
    pub(crate) fn address_rotation(seed: u64, attempt: u64) -> u64 {
        Self::spread(seed).wrapping_add(attempt)
    }

    /// The delay the next [`Backoff::wait`] will sleep, computed exactly as
    /// `wait` computes it. Exposed so the runtime snapshot can say *when* the
    /// next attempt fires, not just that the driver is reconnecting.
    pub(crate) fn next_delay(&self, session_held: bool) -> std::time::Duration {
        let base = if session_held {
            std::time::Duration::from_millis(200)
        } else {
            self.current
        };
        base + self.jitter(base)
    }

    /// Sleep before the next reconnect attempt, then grow the delay for the
    /// attempt after this one. `session_held` says the session that just ended
    /// was a real one (see [`Backoff::session_held`]), which starts the schedule
    /// over.
    pub(crate) async fn wait(&mut self, session_held: bool) {
        if session_held {
            self.current = std::time::Duration::from_millis(200);
        }
        tokio::time::sleep(self.current + self.jitter(self.current)).await;
        self.current = (self.current * 2).min(std::time::Duration::from_secs(30));
    }

    /// Whether the attempt that just ended earns a fresh schedule: it reached
    /// `Connected` *and* stayed up for [`Self::HELD_FOR`]. Elapsed time alone
    /// is not enough — a tarpit that completes the handshake and says nothing
    /// until the registration deadline also lasts that long, and read that way
    /// it kept the driver re-dialling it every 200 ms.
    pub(crate) fn session_held(connected: bool, elapsed: std::time::Duration) -> bool {
        connected && elapsed >= Self::HELD_FOR
    }

    /// How long a connected session must last to count as held.
    pub(crate) const HELD_FOR: std::time::Duration = std::time::Duration::from_secs(10);

    /// The delay before re-dialing an upstream that *refused* the previous
    /// attempt: `floor` doubled per consecutive refusal. A refusal is the
    /// upstream's policy answer, not a lost packet, so it never takes the
    /// sub-second transient schedule above — five registrations inside six
    /// seconds is what earns a public network's throttle or ban.
    pub(crate) fn rejection_delay(
        &self,
        floor: std::time::Duration,
        consecutive_rejections: u32,
    ) -> std::time::Duration {
        // The schedule ends where parking ends it (30s, 1m, 2m, 4m). A refusal
        // that is retried past that point stays at the last step.
        let doublings = consecutive_rejections
            .saturating_sub(1)
            .min(MAX_CONSECUTIVE_REGISTRATION_REJECTIONS - 2);
        let base = floor.saturating_mul(1 << doublings);
        base + self.jitter(base)
    }
}

/// `addresses`, started `rotation` places in (wrapping), so callers dialling
/// the same round robin at once begin at different members and one caller's
/// consecutive attempts begin at different members too. The relative order,
/// and with it the family alternation of [`interleave_address_families`], is
/// kept.
pub(crate) fn rotate_addresses(
    mut addresses: Vec<std::net::SocketAddr>,
    rotation: u64,
) -> Vec<std::net::SocketAddr> {
    if let Some(len) = std::num::NonZeroU64::new(addresses.len() as u64) {
        addresses.rotate_left((rotation % len) as usize);
    }
    addresses
}

/// Outcome of one driver session attempt, for the always-on drivers'
/// reconnect loops: the owner dropped the handle (stop for good), or the
/// upstream connection dropped and the driver should reconnect with backoff.
/// A session never ends the driver: the task dying on the first disconnect
/// would silently drop all later upstream traffic. What a driver carries
/// across sessions is its own (Matrix its login and sync position, Discord
/// its resumable gateway session, Discord and Slack their outbound deliveries
/// and Slack its acked inbound messages — see [`run_with_backoff_carrying`]),
/// so an outage's messages are delivered after it rather than skipped.
pub(crate) enum SessionOutcome {
    Stopped,
    /// A transient session failure that is safe to retry. Carrying the closed,
    /// credential-safe reason in the outcome makes a reasonless reconnect
    /// unrepresentable: every driver must tell monitoring why the attempt
    /// ended before the shared runner can schedule another one.
    Dropped(NetworkFailure),
    /// A registered session the upstream ended with a stated reason (an IRC
    /// `ERROR :Closing Link …`). Retried like [`Self::Dropped`] with
    /// [`NetworkFailure::ConnectionLost`]; the reason is what the owner reads.
    ClosedByUpstream(LinkClosed),
    /// The upstream rejected the credentials. A retry re-sends the same
    /// password and can only fail the same way, while every failure counts
    /// against the account on the upstream, so [`run_with_backoff`] parks on
    /// the first one until the network is reconfigured. An IRC upstream's own
    /// words ride along; a bridge, whose rejection is an HTTP status or a close
    /// code, has none.
    AuthRejected(Option<e6irc_client::SaslRejection>),
    /// The upstream refused registration. What [`run_with_backoff`] does about
    /// it is the refusal's [`e6irc_client::RegistrationRefusal::retry_policy`]:
    /// the slow rejection schedule for as long as a passing refusal lasts, that
    /// schedule and then a park after [`MAX_CONSECUTIVE_REGISTRATION_REJECTIONS`]
    /// of one kind, or a park at once for one only reconfiguration can end.
    RegistrationRejected(e6irc_client::RegistrationRejection),
    /// A bridge's upstream refused something this network's *configuration*
    /// asks for — a room it may not join, a channel that cannot be mapped.
    /// Retrying changes nothing, so it takes the same slow schedule and parks.
    #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
    ConfigurationRejected(ConfigurationRefusal),
    /// The upstream asked for this connection to be replaced (Discord's op 7
    /// Reconnect). Nothing failed, so nothing is recorded: the runner dials
    /// again after [`RECONNECT_REQUEST_PAUSE`], without the failure schedule.
    #[cfg(feature = "discord")]
    ReconnectRequested,
    /// [`Self::Dropped`], and the upstream named how long the next attempt
    /// must wait at the least (Discord's op 9: a fresh IDENTIFY only after a
    /// random one to five seconds; a Slack Web API call answered `429` with
    /// its wait). The runner waits the longer of that and its own backoff.
    #[cfg(any(feature = "discord", feature = "slack"))]
    DroppedFor {
        failure: NetworkFailure,
        at_least: std::time::Duration,
    },
}

/// How long the runner waits before answering an upstream's request to
/// reconnect. Nothing failed, so it is not the backoff schedule; it only
/// bounds how fast an upstream that asks on every connection can make the
/// driver dial.
#[cfg(feature = "discord")]
pub(crate) const RECONNECT_REQUEST_PAUSE: std::time::Duration = std::time::Duration::from_secs(1);

/// Why a bridge cannot serve its configuration, in the closed vocabulary plus a
/// bounded, control-free detail that names the offending room or channel. It
/// never carries provider response text, which can hold request details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigurationRefusal {
    failure: NetworkFailure,
    diagnostic: String,
}

impl ConfigurationRefusal {
    pub fn new(failure: NetworkFailure, diagnostic: &str) -> Self {
        Self {
            failure,
            diagnostic: e6irc_client::bounded_diagnostic(diagnostic),
        }
    }

    pub const fn failure(&self) -> NetworkFailure {
        self.failure
    }

    /// What the runner may do about this refusal, decided by its kind. The
    /// rule: a refusal that nothing but the owner acting can clear parks at
    /// once, since each retry only repeats it; one the upstream can clear by
    /// itself takes the refusal schedule and then parks.
    ///
    /// - [`NetworkFailure::GatewayConfigurationRefused`]: a gateway's answer
    ///   about the bot itself (Discord's shard, sharding, API version and
    ///   intent close codes; Slack's Socket Mode switched off). The owner
    ///   must change the bot or the app — park now.
    /// - [`NetworkFailure::RoomEncrypted`]: a Matrix room cannot turn
    ///   encryption off again — park now.
    /// - [`NetworkFailure::ChannelJoinRefused`]: "not invited" ends when an
    ///   invitation arrives upstream, which the homeserver may be catching up
    ///   on, and a room the account was kicked from ends when the rejoin
    ///   succeeds — the schedule.
    /// - [`NetworkFailure::ChannelMappingFailed`]: a Discord or Slack channel
    ///   name comes from the upstream, and renaming it there clears the
    ///   refusal; a channel the bot cannot see, is not in, or that is
    ///   archived clears when that changes upstream — the schedule.
    pub fn retry_policy(&self) -> e6irc_client::RefusalRetry {
        use e6irc_client::RefusalRetry;
        match self.failure {
            NetworkFailure::GatewayConfigurationRefused | NetworkFailure::RoomEncrypted => {
                RefusalRetry::ParkNow
            }
            _ => RefusalRetry::ScheduleThenPark,
        }
    }

    pub fn diagnostic(&self) -> &str {
        &self.diagnostic
    }
}

/// The upstream's stated reason for ending a registered session, bounded and
/// control-free like every other upstream text the owner reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkClosed {
    diagnostic: String,
}

impl LinkClosed {
    pub fn new(reason: &str) -> Self {
        Self {
            diagnostic: e6irc_client::bounded_diagnostic(reason),
        }
    }

    pub fn diagnostic(&self) -> &str {
        &self.diagnostic
    }
}

/// A refusal the shared runner retries slowly, and parks on when its policy
/// says so, whichever kind of upstream gave it.
enum Refusal {
    Registration(e6irc_client::RegistrationRejection),
    #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
    Configuration(ConfigurationRefusal),
}

/// What kind of refusal one was, so a run of them can be told from a change.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RefusalKind {
    Registration(e6irc_client::RegistrationRefusal),
    #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
    Configuration(NetworkFailure),
}

impl Refusal {
    fn kind(&self) -> RefusalKind {
        match self {
            Self::Registration(rejection) => RefusalKind::Registration(rejection.refusal()),
            #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
            Self::Configuration(refusal) => RefusalKind::Configuration(refusal.failure()),
        }
    }

    /// What the runner may do about this refusal. Parking waits for the owner
    /// to change something: a refusal that ends by itself gives them nothing to
    /// change and is retried at the schedule's last step for as long as it
    /// lasts; one that only a change can end is parked on at once. Each kind
    /// states its own policy in one place: [`e6irc_client::RegistrationRefusal::retry_policy`]
    /// and [`ConfigurationRefusal::retry_policy`].
    fn retry(&self) -> e6irc_client::RefusalRetry {
        match self {
            Self::Registration(rejection) => rejection.refusal().retry_policy(),
            #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
            Self::Configuration(refusal) => refusal.retry_policy(),
        }
    }

    fn retrying(self) -> ConnectionEvent {
        match self {
            Self::Registration(rejection) => ConnectionEvent::RegistrationRetrying(rejection),
            #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
            Self::Configuration(refusal) => ConnectionEvent::ConfigurationRetrying(refusal),
        }
    }

    fn parked(self) -> ConnectionEvent {
        match self {
            Self::Registration(rejection) => ConnectionEvent::RegistrationFailed(rejection),
            #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
            Self::Configuration(refusal) => ConnectionEvent::ConfigurationFailed(refusal),
        }
    }
}

/// Consecutive upstream registration rejections *of one kind* before a driver
/// on the schedule-then-park policy stops re-dialing and parks until the
/// network is reconfigured. A refusal of another kind starts the count over: a
/// services outage or a connection throttle is a long run of refusals that
/// never park, and the 433 that follows it (the driver's own ghost, still
/// holding the nick) is the first of its kind, owed the whole schedule rather
/// than an instant park. Rejected *credentials* and a welcome under another
/// nickname never reach this count: they park on the first rejection.
pub(crate) const MAX_CONSECUTIVE_REGISTRATION_REJECTIONS: u32 = 5;

/// First delay after an upstream refuses registration, doubled per consecutive
/// refusal (30s, 1m, 2m, 4m, then park or stay at 4m). Long enough to outlast a
/// connection throttle and most of a ghost session's ping timeout; tests shrink
/// it through [`DriverEnds::set_rejection_retry_floor`].
pub(crate) const REJECTION_RETRY_FLOOR: std::time::Duration = std::time::Duration::from_secs(30);

/// How long the registry waits for a stopped driver to release its upstream
/// before it proceeds with the replacement or removal. Longer than the bounded
/// work a stopping IRC driver can still have in hand (one
/// [`UPSTREAM_WRITE_DEADLINE`] write, then the goodbye), so a healthy driver
/// always makes it; a wedged one is left to finish on its own, loudly.
pub const SHUTDOWN_WAIT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15);

/// How long one write to an IRC upstream may block. A line only blocks when the
/// peer has stopped draining its side of the socket, so past this the link is
/// treated as dead ([`NetworkFailure::UpstreamWriteFailed`]) rather than left to
/// hold the driver — and, through the registry's wait, every other account's
/// network mutation — for as long as the kernel keeps the connection.
pub const UPSTREAM_WRITE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// Depth of the bounded client→upstream command queue per network (shared by all
/// attached clients). Past this a send is refused (`SendOutcome::Full`) and the
/// client is told loudly, rather than blocking — a blocking send on this *shared*
/// queue would stall every other attached client (see [`NetworkHandle::send`]).
/// Each line is already bounded by `MAX_CLIENT_FRAME_LEN`, so this bounds memory.
const BNC_COMMAND_QUEUE: usize = 256;

/// Why a bridge request that presents the credentials failed. Distinguishes a
/// credential rejection ([`SessionOutcome::AuthRejected`] — stop re-dialing)
/// from any other failure ([`SessionOutcome::Dropped`] — retry with backoff),
/// giving the chat bridges the same "stop hammering the upstream with a bad
/// token" backstop the IRC driver has. The `From<String>` / `From<&str>`
/// conversions make every ordinary `?` fall through as `Transient`, so only
/// [`bridge_send_credentials`] has to name `Auth`.
///
/// Gated on the bridges whose rejection is an HTTP status; Slack signals it in
/// a 200 body (`slack_failure`). The `lint` CI job builds each bridge feature
/// on its own with `-Dwarnings`, so a helper compiled but unused under a
/// single feature is a hard error — hence the narrow gate.
#[cfg(any(feature = "matrix", feature = "discord"))]
pub(crate) enum ConnectFail {
    Auth(String),
    Transient(String),
    /// The upstream will not serve what the configuration asks for: a Matrix
    /// room join it forbids, a Discord channel the bot cannot see or that
    /// does not exist (see [`CredentialRequest`]).
    Configuration(ConfigurationRefusal),
}

#[cfg(any(feature = "matrix", feature = "discord"))]
impl ConnectFail {
    pub(crate) fn into_outcome(self, who: &str) -> SessionOutcome {
        match self {
            Self::Auth(e) => {
                eprintln!("{who}: authentication rejected, will stop retrying: {e}");
                SessionOutcome::AuthRejected(None)
            }
            Self::Transient(e) => {
                eprintln!("{who}: connect failed: {e}");
                SessionOutcome::Dropped(NetworkFailure::UpstreamRequestFailed)
            }
            Self::Configuration(refusal) => {
                eprintln!("{who}: configuration refused: {}", refusal.diagnostic());
                SessionOutcome::ConfigurationRejected(refusal)
            }
        }
    }
}

#[cfg(any(feature = "matrix", feature = "discord"))]
impl From<String> for ConnectFail {
    fn from(e: String) -> Self {
        Self::Transient(e)
    }
}

#[cfg(any(feature = "matrix", feature = "discord"))]
impl From<&str> for ConnectFail {
    fn from(e: &str) -> Self {
        Self::Transient(e.to_string())
    }
}

/// Run `session` forever, reconnecting with backoff whenever it drops.
///
/// Every always-on driver needs exactly this: a transient failure must
/// reconnect rather than kill the network, because a dead driver silently
/// drops every later upstream message; only a dropped handle stops it. The
/// `Disconnected` event is emitted on each drop so an attached client sees the
/// gap rather than an unexplained silence.
///
/// Written once because it is a policy, not a shape. Four copies meant a change
/// to how reconnects are paced reached whichever bridge was being edited and
/// quietly left the other three on the old behaviour.
/// `session` is a plain function returning a boxed future rather than an async
/// closure: the closure form cannot prove `Send` for a higher-ranked borrow of
/// `ends`, and the spawned driver task needs it. One allocation per *reconnect*
/// is not a cost worth contorting the signature to avoid.
pub(crate) type DriverSession<C> =
    for<'a> fn(
        &'a C,
        &'a mut DriverEnds,
    ) -> std::pin::Pin<Box<dyn Future<Output = SessionOutcome> + Send + 'a>>;

/// Announce why the attempt ended, publish when the next one fires, and sleep
/// until then. `upstream_reason` is the upstream's own text for an event that
/// does not carry one (a registered session it closed with a stated reason).
/// Returns `false` when the network was stopped while waiting.
async fn wait_for_reconnect<C>(
    ends: &mut DriverEnds,
    carried: Carried<'_, C>,
    event: ConnectionEvent,
    upstream_reason: Option<&str>,
    delay: std::time::Duration,
    sleep: impl Future<Output = ()>,
) -> bool {
    ends.publish(event, Some(delay), upstream_reason);
    ends.refuse_queued();
    idle_until(ends, carried, sleep).await
}

/// Park a driver the upstream will keep refusing: publish the terminal state,
/// say so in the buffer, and hold the task until the network is reconfigured
/// (which drops the handle). Work the driver carries keeps finishing while it
/// is parked: a message already accepted for delivery is delivered or said to
/// be undelivered, never held without a word for as long as the park lasts.
async fn park<C>(ends: &mut DriverEnds, carried: Carried<'_, C>, event: ConnectionEvent) {
    ends.emit(event);
    ends.refuse_queued();
    ends.emit_line(
        ":*bnc* NOTICE * :upstream rejected this network's credentials or registration; \
         not reconnecting until this network is reconfigured"
            .to_string(),
    );
    idle_until(ends, carried, std::future::pending()).await;
}

/// What one piece of carried work came to, told to the network once it is
/// done: a delivery's echo or undelivered notice, a relayed message's lines.
pub(crate) type CarriedReport = Box<dyn FnOnce(&DriverEnds) + Send>;

/// The next finished piece of the work a driver carries across its sessions
/// (see [`run_with_backoff_carrying`]); pending forever while there is none.
pub(crate) type CarriedNext<C> =
    for<'a> fn(&'a C) -> std::pin::Pin<Box<dyn Future<Output = CarriedReport> + Send + 'a>>;

/// A driver's carried work as the runner holds it: its state, and how to wait
/// for the next finished piece — `None` for a driver that carries nothing.
struct Carried<'a, C> {
    config: &'a C,
    next: Option<CarriedNext<C>>,
}

impl<C> Clone for Carried<'_, C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C> Copy for Carried<'_, C> {}

impl<C> Carried<'_, C> {
    async fn next(self) -> CarriedReport {
        match self.next {
            Some(next) => next(self.config).await,
            None => std::future::pending().await,
        }
    }
}

/// Wait for `until` while telling the network what the carried work finishes;
/// `false` when the network was stopped first.
async fn idle_until<C>(
    ends: &DriverEnds,
    carried: Carried<'_, C>,
    until: impl Future<Output = ()>,
) -> bool {
    let mut stop = std::pin::pin!(ends.stop_signal());
    let mut until = std::pin::pin!(until);
    #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
    let pacer = ends.pacer();
    loop {
        tokio::select! {
            biased;
            () = &mut stop => return false,
            () = &mut until => return true,
            report = async {
                #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
                pacer.wait().await;
                carried.next().await
            } => report(ends),
        }
    }
}

pub(crate) async fn run_with_backoff<C>(
    config: C,
    ends: &mut DriverEnds,
    session: DriverSession<C>,
) {
    run_with_backoff_carrying(config, ends, session, None).await;
}

/// [`run_with_backoff`] for a driver whose sessions leave work behind them
/// that needs no connection of its own to finish — a bridge's REST deliveries,
/// an inbound message waiting on a name lookup. That work belongs to the
/// driver, not the session: a session that ended with it queued dropped it —
/// messages already accepted from a client, or acknowledged to the provider,
/// that nothing would ever deliver or relay. Each session drains it in its
/// own loop; between sessions (the backoff, a refusal's schedule, a park) the
/// runner does, through `carried`.
pub(crate) async fn run_with_backoff_carrying<C>(
    config: C,
    ends: &mut DriverEnds,
    session: DriverSession<C>,
    carried_next: Option<CarriedNext<C>>,
) {
    let carried = Carried {
        config: &config,
        next: carried_next,
    };
    let mut backoff = Backoff::new(ends.reconnect_seed);
    // A driver started at boot holds its first dial back so a restart's worth
    // of drivers reach one round robin spread out, not in a burst.
    let first_dial_delay = ends.first_dial_delay;
    if !first_dial_delay.is_zero() {
        tokio::select! {
            biased;
            _ = ends.shutdown_signalled() => return,
            _ = tokio::time::sleep(first_dial_delay) => {}
        }
    }
    // How many refusals of `last_refusal`'s kind in a row.
    let mut consecutive_rejections: u32 = 0;
    let mut last_refusal: Option<RefusalKind> = None;
    loop {
        // A stop signalled while a session runs is observed inside it (via
        // `next_command`); one signalled while we wait to reconnect is caught
        // here, so a removed network in backoff doesn't linger for the retry.
        if ends.is_shutdown() {
            return;
        }
        ends.begin_attempt();
        let started = tokio::time::Instant::now();
        let ended = match session(&config, ends).await {
            SessionOutcome::Stopped => return,
            SessionOutcome::AuthRejected(rejection) => {
                park(
                    ends,
                    carried,
                    ConnectionEvent::AuthenticationFailed(rejection),
                )
                .await;
                return;
            }
            SessionOutcome::RegistrationRejected(rejection) => {
                Err(Refusal::Registration(rejection))
            }
            #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
            SessionOutcome::ConfigurationRejected(refusal) => Err(Refusal::Configuration(refusal)),
            #[cfg(feature = "discord")]
            SessionOutcome::ReconnectRequested => {
                if idle_until(ends, carried, tokio::time::sleep(RECONNECT_REQUEST_PAUSE)).await {
                    continue;
                }
                return;
            }
            SessionOutcome::Dropped(failure) => Ok((failure, None, std::time::Duration::ZERO)),
            #[cfg(any(feature = "discord", feature = "slack"))]
            SessionOutcome::DroppedFor { failure, at_least } => Ok((failure, None, at_least)),
            SessionOutcome::ClosedByUpstream(closed) => Ok((
                NetworkFailure::ConnectionLost,
                Some(closed),
                std::time::Duration::ZERO,
            )),
        };
        // A refusal takes its own schedule, and may park.
        let (failure, upstream_reason, at_least) = match ended {
            Ok(dropped) => dropped,
            Err(refusal) => {
                match retry_refusal(
                    ends,
                    carried,
                    &backoff,
                    refusal,
                    &mut consecutive_rejections,
                    &mut last_refusal,
                )
                .await
                {
                    RefusalHandled::Retrying => continue,
                    RefusalHandled::Ended => return,
                }
            }
        };
        // Only a session that actually registered proves the upstream accepts
        // this configuration. A drop *before* that (a throttled dial between
        // two refusals, say) neither counts as a refusal nor forgives the ones
        // already counted — otherwise a refusing upstream's own throttle would
        // keep the driver from ever parking.
        let connected = ends.connected_this_attempt();
        if connected {
            consecutive_rejections = 0;
            last_refusal = None;
        }
        let session_held = Backoff::session_held(connected, started.elapsed());
        let delay = backoff.next_delay(session_held).max(at_least);
        let reconnecting = ConnectionEvent::Reconnecting(failure);
        let reason = upstream_reason.as_ref().map(LinkClosed::diagnostic);
        let wait = async {
            tokio::join!(backoff.wait(session_held), tokio::time::sleep(at_least));
        };
        if !wait_for_reconnect(ends, carried, reconnecting, reason, delay, wait).await {
            return;
        }
    }
}

enum RefusalHandled {
    /// The wait for the next attempt ended; dial again.
    Retrying,
    /// The driver parked, or was stopped while waiting.
    Ended,
}

/// Count `refusal` against the run of its kind and act on its retry policy.
async fn retry_refusal<C>(
    ends: &mut DriverEnds,
    carried: Carried<'_, C>,
    backoff: &Backoff,
    refusal: Refusal,
    consecutive_rejections: &mut u32,
    last_refusal: &mut Option<RefusalKind>,
) -> RefusalHandled {
    use e6irc_client::RefusalRetry;
    if last_refusal.replace(refusal.kind()) != Some(refusal.kind()) {
        *consecutive_rejections = 0;
    }
    *consecutive_rejections = consecutive_rejections.saturating_add(1);
    let parks = match refusal.retry() {
        RefusalRetry::ParkNow => true,
        RefusalRetry::ScheduleThenPark => {
            *consecutive_rejections >= MAX_CONSECUTIVE_REGISTRATION_REJECTIONS
        }
        RefusalRetry::UntilItClears => false,
    };
    if parks {
        park(ends, carried, refusal.parked()).await;
        return RefusalHandled::Ended;
    }
    let delay = backoff.rejection_delay(ends.rejection_retry_floor, *consecutive_rejections);
    if wait_for_reconnect(
        ends,
        carried,
        refusal.retrying(),
        None,
        delay,
        tokio::time::sleep(delay),
    )
    .await
    {
        RefusalHandled::Retrying
    } else {
        RefusalHandled::Ended
    }
}

/// What an IRC client's message becomes on a bridge: plain text, or a CTCP
/// `ACTION` (`/me`), which each provider renders its own way (Matrix
/// `m.emote`, Discord and Slack italics). IRC formatting is gone from both:
/// the providers have their own markup, and a `\x02` or `\x03` color code
/// arrives there as noise.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BridgeText {
    Text(String),
    Action(String),
}

#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
impl BridgeText {
    /// An IRC client's message text as a bridge sends it. `None` is a CTCP
    /// other than `ACTION` (`\x01VERSION\x01`): no provider has anything to
    /// answer it with, so the caller refuses it rather than posting the raw
    /// bytes as a message.
    pub(crate) fn outbound(text: &str) -> Option<Self> {
        if let Some(action) = crate::sanitize::ctcp_action(text) {
            return Some(Self::Action(strip_irc_formatting(action)));
        }
        if crate::sanitize::is_ctcp_request(text) {
            return None;
        }
        Some(Self::Text(strip_irc_formatting(text)))
    }

    /// The text with the `/me` rendered as the Markdown italics Discord and
    /// Slack both read (`_waves_`). `escape` is applied to the text first.
    #[cfg(any(feature = "discord", feature = "slack"))]
    pub(crate) fn italic_markdown(&self, escape: impl Fn(&str) -> String) -> String {
        match self {
            Self::Text(text) => escape(text),
            Self::Action(text) => format!("_{}_", escape(text)),
        }
    }
}

/// `text` without IRC formatting: bold `\x02`, color `\x03[fg[,bg]]`, hex
/// color `\x04[rrggbb[,rrggbb]]`, reset `\x0F`, monospace `\x11`, reverse
/// `\x16`, italics `\x1D`, strikethrough `\x1E`, underline `\x1F`. Any other
/// C0 control but tab goes too: none of them means anything to a provider.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
fn strip_irc_formatting(text: &str) -> String {
    /// Consume up to `max` characters matching `accept` from `chars`.
    fn take(
        chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
        max: usize,
        accept: fn(char) -> bool,
    ) -> bool {
        let mut taken = 0;
        while taken < max && chars.peek().is_some_and(|c| accept(*c)) {
            chars.next();
            taken += 1;
        }
        taken > 0
    }
    /// A color argument: `fg`, then optionally `,bg` — the comma only when a
    /// background actually follows, or it is the message's own comma.
    fn color(
        chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
        max: usize,
        accept: fn(char) -> bool,
    ) {
        if take(chars, max, accept) {
            let mut ahead = chars.clone();
            if ahead.next() == Some(',') && ahead.peek().is_some_and(|c| accept(*c)) {
                chars.next();
                take(chars, max, accept);
            }
        }
    }
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{3}' => color(&mut chars, 2, |c| c.is_ascii_digit()),
            '\u{4}' => color(&mut chars, 6, |c| c.is_ascii_hexdigit()),
            '\t' => out.push(c),
            c if c.is_ascii_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// How an inbound bridged message is shown to IRC clients.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InboundKind {
    /// A `PRIVMSG`.
    Message,
    /// A `PRIVMSG` carrying a CTCP `ACTION` (`/me`): Matrix `m.emote`, Slack
    /// `me_message`. (Discord has no action of its own; the `lint` job builds
    /// each bridge alone, so a variant one build never makes is gated out.)
    #[cfg(any(feature = "matrix", feature = "slack"))]
    Action,
    /// A `NOTICE`: Matrix `m.notice`, a bot's message by convention.
    #[cfg(feature = "matrix")]
    Notice,
}

/// Remote text on its way to IRC clients. Built only through
/// [`Inbound::new`], which drops every C0 control but tab and line breaks: a
/// provider message can therefore never reach an attached client as a CTCP
/// request (`\x01VERSION\x01`, which clients answer), nor carry IRC
/// formatting it did not mean. The one `\x01` an inbound line can hold is the
/// `ACTION` wrapper [`render_bridged`] adds itself.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Inbound {
    kind: InboundKind,
    body: String,
}

#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
impl Inbound {
    pub(crate) fn new(kind: InboundKind, body: &str) -> Self {
        Self {
            kind,
            body: body
                .chars()
                .filter(|c| !c.is_ascii_control() || matches!(c, '\t' | '\n'))
                .collect(),
        }
    }

    #[cfg(any(feature = "discord", feature = "slack"))]
    pub(crate) fn message(body: &str) -> Self {
        Self::new(InboundKind::Message, body)
    }
}

/// Classification of a downstream client command by a bridge, so a message
/// that can't be delivered upstream is surfaced rather than silently dropped.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RouteResult {
    /// A PRIVMSG to `target` (as the client named it, less any STATUSMSG
    /// prefix), mapped to the upstream `id`; deliver `text` there.
    Deliver {
        id: String,
        target: String,
        text: BridgeText,
    },
    /// A PRIVMSG to `target` that maps to no bridged channel — surface loss.
    Unmapped(String),
    /// The bridge cannot execute this command; surface a fixed safe reason.
    Rejected(BridgeCommandRejection),
}

#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BridgeCommandRejection {
    MalformedMessage,
    UnsupportedCommand,
    /// A CTCP other than `ACTION`: nothing on the provider can answer it.
    UnsupportedCtcp,
}

/// Classify a downstream client line for a bridge: the single choke point all
/// three bridges share (Discord/Slack/Matrix), so the routing policy lives in
/// one place. `targets` maps a **casefolded** bridged channel name to its
/// upstream id (the drivers insert folded keys), so lookup here folds too.
///
/// Returns one result per resolved target: a `PRIVMSG` may carry a
/// comma-separated target list (`#a,#b`), which real clients send and a normal
/// server splits — so this splits it and routes each independently. A single
/// STATUSMSG prefix (`@#chan`/`+#chan`) is stripped before the lookup: a bridge
/// has no op/voice-only concept, so it delivers to the channel itself. An empty
/// or non-PRIVMSG line yields one explicit rejection, and so does a CTCP other
/// than `ACTION` (see [`BridgeText::outbound`]).
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
pub(crate) fn route_privmsg(
    line: &str,
    targets: &std::collections::HashMap<String, String>,
) -> Vec<RouteResult> {
    let Ok(msg) = e6irc_proto::message::Message::parse(line) else {
        return vec![RouteResult::Rejected(
            BridgeCommandRejection::MalformedMessage,
        )];
    };
    if !msg.command.eq_ignore_ascii_case("PRIVMSG") {
        return vec![RouteResult::Rejected(
            BridgeCommandRejection::UnsupportedCommand,
        )];
    }
    let (Some(target), Some(text)) = (msg.params.first(), msg.params.get(1)) else {
        return vec![RouteResult::Rejected(
            BridgeCommandRejection::MalformedMessage,
        )];
    };
    let Some(text) = BridgeText::outbound(text) else {
        return vec![RouteResult::Rejected(
            BridgeCommandRejection::UnsupportedCtcp,
        )];
    };
    let names = bridge_names();
    let mut out: Vec<RouteResult> = target
        .split(',')
        .filter(|t| !t.is_empty())
        .map(|t| {
            let bare = names.conversation(t);
            match targets.get(&names.fold(bare)) {
                Some(id) => RouteResult::Deliver {
                    id: id.clone(),
                    target: bare.to_string(),
                    text: text.clone(),
                },
                None => RouteResult::Unmapped(bare.to_string()),
            }
        })
        .collect();
    if out.is_empty() {
        out.push(RouteResult::Rejected(
            BridgeCommandRejection::MalformedMessage,
        ));
    }
    out
}

/// The longest provider rate-limit wait a delivery sits out before retrying
/// once. Past it the message is reported undelivered, naming the limit: a
/// client told nothing for minutes would think it was sent.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
pub(crate) const RATE_LIMIT_WAIT_CAP: std::time::Duration = std::time::Duration::from_secs(10);

/// The echo of one routed delivery: the line an attached client sent, as the
/// bridge's own account says it on IRC, to the one target delivered. Emitted
/// only once the provider accepted the message — a refused one is answered by
/// its undelivered notice alone, as a real server answers with its refusal.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
#[derive(Debug)]
pub(crate) struct PendingEcho {
    line: String,
    origin: u64,
}

#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
impl PendingEcho {
    /// The echo of `command` delivered to `target`, or `None` for a line with
    /// no echo (see [`irc_driver::self_echo`]).
    fn of(
        command: &ClientCommand,
        target: &str,
        identity: &irc_driver::SelfIdentity,
    ) -> Option<Self> {
        irc_driver::self_echo_to(&command.line, target, identity).map(|line| Self {
            line,
            origin: command.origin,
        })
    }
}

/// How one routed delivery ended, for [`report_delivery`].
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
#[derive(Debug)]
pub(crate) enum DeliveryOutcome {
    Delivered(Option<PendingEcho>),
    Failed {
        id: String,
        detail: String,
    },
    /// Still rate-limited after the one retry, or asked to wait past
    /// [`RATE_LIMIT_WAIT_CAP`].
    RateLimited {
        id: String,
        retry_after: std::time::Duration,
    },
}

/// Send one routed message, sitting out one provider rate limit of at most
/// [`RATE_LIMIT_WAIT_CAP`] and retrying once. Owns everything it needs, so a
/// WebSocket bridge can run it beside its socket instead of in front of it.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
pub(crate) async fn deliver_with_retry<F, Fut>(
    mut deliver: F,
    id: String,
    text: BridgeText,
    echo: Option<PendingEcho>,
) -> DeliveryOutcome
where
    F: FnMut(String, BridgeText) -> Fut,
    Fut: Future<Output = Result<(), BridgeFailure>>,
{
    let failed = |id: String, failure: BridgeFailure| match failure {
        BridgeFailure::RateLimited(retry_after) => DeliveryOutcome::RateLimited { id, retry_after },
        failure @ (BridgeFailure::Status(_) | BridgeFailure::Failed(_)) => {
            DeliveryOutcome::Failed {
                id,
                detail: failure.to_string(),
            }
        }
    };
    match deliver(id.clone(), text.clone()).await {
        Ok(()) => DeliveryOutcome::Delivered(echo),
        Err(BridgeFailure::RateLimited(wait)) if wait <= RATE_LIMIT_WAIT_CAP => {
            tokio::time::sleep(wait).await;
            match deliver(id.clone(), text).await {
                Ok(()) => DeliveryOutcome::Delivered(echo),
                Err(failure) => failed(id, failure),
            }
        }
        Err(failure) => failed(id, failure),
    }
}

/// Say what became of one delivery: its echo for a delivered message, and for
/// a lost one a counted failure plus a `*bnc*` notice naming the target (and
/// the limit, when it was a rate limit) — never a silent drop (DESIGN §2).
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
pub(crate) fn report_delivery(
    ends: &DriverEnds,
    platform: &str,
    kind: &str,
    outcome: DeliveryOutcome,
) {
    match outcome {
        DeliveryOutcome::Delivered(echo) => {
            if let Some(PendingEcho { line, origin }) = echo {
                ends.emit_echo(line, origin);
            }
        }
        DeliveryOutcome::Failed { id, detail } => {
            eprintln!("{platform}: send to {id} failed: {detail}");
            ends.record_error(NetworkFailure::UpstreamWriteFailed);
            ends.emit_line(undelivered_notice(platform, kind, &id));
        }
        DeliveryOutcome::RateLimited { id, retry_after } => {
            eprintln!("{platform}: send to {id} rate-limited; retry after {retry_after:?}");
            ends.record_error(NetworkFailure::UpstreamWriteFailed);
            ends.emit_line(rate_limited_notice(platform, kind, &id, retry_after));
        }
    }
}

/// Route one client command to its bridged targets, deliver each, and surface
/// the outcome of **each** one to the attached client. `route_privmsg` yields
/// one `RouteResult` per comma-separated target; this consumes the whole list,
/// so a mapped target that fails to send and an unmapped target both produce
/// their own `*bnc*` NOTICE — a multi-target line can't have all-but-one
/// target's non-delivery silently dropped — and each delivered target gets its
/// own echo, as `identity` says it. That fold-N-outcomes-into-one silent drop
/// (DESIGN §2) is exactly what the Matrix bridge did before this was shared:
/// every bridge now routes its per-target outcome through one definition that
/// cannot collapse the list. `deliver` performs the platform's upstream send for
/// a mapped `(id, text)`; it does its session-touching work synchronously and
/// moves owned data into the returned future, so no borrow of the caller's
/// session outlives a single send. The WebSocket bridges queue the same
/// [`deliver_with_retry`] instead of awaiting it (`queue_channel_command`);
/// only Matrix, which has no socket to keep answering, awaits it here.
#[cfg(feature = "matrix")]
pub(crate) async fn relay_routed<F, Fut>(
    ends: &DriverEnds,
    command: &ClientCommand,
    targets: &std::collections::HashMap<String, String>,
    identity: &irc_driver::SelfIdentity,
    platform: &str,
    kind: &str,
    mut deliver: F,
) where
    F: FnMut(String, BridgeText) -> Fut,
    Fut: std::future::Future<Output = Result<(), BridgeFailure>>,
{
    for routed in route_privmsg(&command.line, targets) {
        match routed {
            RouteResult::Deliver { id, target, text } => {
                let echo = PendingEcho::of(command, &target, identity);
                let outcome = deliver_with_retry(&mut deliver, id, text, echo).await;
                report_delivery(ends, platform, kind, outcome);
            }
            RouteResult::Unmapped(target) => {
                ends.emit_line(unmapped_target_notice(platform, kind, &target));
            }
            RouteResult::Rejected(rejection) => {
                ends.emit_line(rejected_bridge_command_notice(platform, rejection));
            }
        }
    }
}

/// Work a WebSocket bridge runs beside its socket, one item at a time, in the
/// order it was queued: a REST delivery or a name lookup can take the whole
/// request timeout, and awaited inside the socket loop it held every ack and
/// heartbeat behind it — Slack re-sent the envelopes it had not seen acked,
/// and they were relayed twice. Serial, because two messages to one channel
/// must arrive in the order they were written; bounded, because a queue that
/// only grows is a leak with a delay.
///
/// [`SerialQueue::next`] is cancel-safe: the item in progress lives in the
/// queue, not in the future `next` returns, so a `select!` that abandons it
/// loses nothing.
#[cfg(any(feature = "discord", feature = "slack"))]
pub(crate) struct SerialQueue<T> {
    capacity: usize,
    waiting: std::collections::VecDeque<std::pin::Pin<Box<dyn Future<Output = T> + Send>>>,
    running: Option<std::pin::Pin<Box<dyn Future<Output = T> + Send>>>,
}

/// The queue already holds its capacity; the item was not queued.
#[cfg(any(feature = "discord", feature = "slack"))]
#[derive(Debug)]
pub(crate) struct QueueFull;

#[cfg(any(feature = "discord", feature = "slack"))]
impl<T> SerialQueue<T> {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            waiting: std::collections::VecDeque::new(),
            running: None,
        }
    }

    pub(crate) fn push(
        &mut self,
        work: impl Future<Output = T> + Send + 'static,
    ) -> Result<(), QueueFull> {
        if self.waiting.len() + usize::from(self.running.is_some()) >= self.capacity {
            return Err(QueueFull);
        }
        self.waiting.push_back(Box::pin(work));
        Ok(())
    }

    /// The next finished item; pending forever while the queue is empty.
    pub(crate) async fn next(&mut self) -> T {
        if self.running.is_none() {
            match self.waiting.pop_front() {
                Some(work) => self.running = Some(work),
                None => return std::future::pending().await,
            }
        }
        let running = self.running.as_mut().expect("an item is running");
        let output = running.await;
        self.running = None;
        output
    }
}

/// Outbound deliveries a WebSocket bridge has accepted and not yet finished.
/// More than this in flight is a provider that has stopped answering; a
/// message past it is refused with the undelivered notice at once.
#[cfg(any(feature = "discord", feature = "slack"))]
pub(crate) const DELIVERY_QUEUE_CAPACITY: usize = 8;

#[cfg(any(feature = "discord", feature = "slack"))]
pub(crate) type DeliveryQueue = SerialQueue<DeliveryOutcome>;

/// Run `work` — the part of a session that needs nothing of `ends`, such as
/// connecting — while telling the network what the driver's carried work
/// (`next`) finishes meanwhile. Connecting can take several request timeouts;
/// the carried work does not wait for it.
#[cfg(any(feature = "discord", feature = "slack"))]
pub(crate) async fn while_carrying<T, F, Fut>(
    ends: &DriverEnds,
    mut next: F,
    work: impl Future<Output = T>,
) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = CarriedReport>,
{
    let mut work = std::pin::pin!(work);
    let pacer = ends.pacer();
    loop {
        tokio::select! {
            biased;
            out = &mut work => return out,
            report = async {
                pacer.wait().await;
                next().await
            } => report(ends),
        }
    }
}

/// A WebSocket bridge's outbound deliveries, which belong to the driver and
/// not to one socket: a REST post needs no gateway, so a reconnect is no
/// reason to lose what a client already had accepted. A session queues into
/// it and reports what finishes while it runs; between sessions the runner
/// does (see [`run_with_backoff_carrying`]), so each delivery ends in its echo
/// or its undelivered notice whatever the socket is doing.
#[cfg(any(feature = "discord", feature = "slack"))]
pub(crate) struct CarriedDeliveries {
    platform: &'static str,
    queue: tokio::sync::Mutex<DeliveryQueue>,
}

#[cfg(any(feature = "discord", feature = "slack"))]
impl CarriedDeliveries {
    pub(crate) fn new(platform: &'static str) -> Self {
        Self {
            platform,
            queue: tokio::sync::Mutex::new(DeliveryQueue::new(DELIVERY_QUEUE_CAPACITY)),
        }
    }

    /// The next finished delivery, as what it tells the network. Cancel-safe
    /// like [`SerialQueue::next`]: the delivery in progress stays queued.
    pub(crate) async fn next_report(&self) -> CarriedReport {
        let outcome = self.queue.lock().await.next().await;
        let platform = self.platform;
        Box::new(move |ends: &DriverEnds| report_delivery(ends, platform, "channel", outcome))
    }

    /// [`queue_channel_command`] into this queue.
    pub(crate) async fn queue_command<F, Fut>(
        &self,
        ends: &DriverEnds,
        command: Option<ClientCommand>,
        channel_to_id: &HashMap<String, String>,
        identity: &irc_driver::SelfIdentity,
        deliver: F,
    ) -> Option<()>
    where
        F: FnMut(String, BridgeText) -> Fut + Clone + Send + 'static,
        Fut: Future<Output = Result<(), BridgeFailure>> + Send + 'static,
    {
        let mut queue = self.queue.lock().await;
        queue_channel_command(
            ends,
            command,
            channel_to_id,
            identity,
            self.platform,
            &mut queue,
            deliver,
        )
    }
}

/// The HTTP client every bridge uses for its REST calls. Bounds each request by
/// `timeout`, refuses redirects (an upstream 3xx can't re-target an internal
/// address), and vets every resolved IP via [`crate::egress::VettingResolver`] — so a bridge's
/// configured host can't point an HTTP call at a cloud-metadata endpoint. One
/// constructor so all three bridges share the discipline rather than each
/// rebuilding it (and drifting).
///
/// The resolver only sees *names*. A URL whose host is an IP literal —
/// `http://127.0.0.1`, but also `http://2130706433` or `http://0x7f.1`, which
/// the URL parser canonicalizes to the same address — never reaches it: the
/// connector dials the literal directly. So the `reqwest::Client` is private,
/// and every request starts in [`BridgeHttp::request`], which judges the URL's
/// host against the same policy before the client sees it. There is no other
/// way to build a bridge request, so no caller can forget the literal check —
/// and what it builds is a [`BridgeRequest`], whose only send reads the
/// status, so no caller can forget that either.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
#[derive(Clone)]
pub(crate) struct BridgeHttp {
    client: reqwest::Client,
    internal_upstreams: crate::egress::InternalUpstreams,
}

#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
impl BridgeHttp {
    pub(crate) fn new(
        timeout: std::time::Duration,
        internal_upstreams: crate::egress::InternalUpstreams,
    ) -> reqwest::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            // Under the default policy nothing a bridge may dial speaks
            // cleartext (see `BridgeHttp::request`), so the client refuses it
            // outright as well.
            .https_only(internal_upstreams == crate::egress::InternalUpstreams::Refuse)
            .dns_resolver(std::sync::Arc::new(crate::egress::VettingResolver::new(
                internal_upstreams,
            )))
            .build()?;
        Ok(Self {
            client,
            internal_upstreams,
        })
    }

    /// Begin a request to `url`, refused here when its host is an address the
    /// policy does not dial. The error names the rule, never the address.
    pub(crate) fn request(
        &self,
        method: reqwest::Method,
        url: &str,
    ) -> Result<BridgeRequest, String> {
        let url = reqwest::Url::parse(url).map_err(|e| format!("bridge request URL: {e}"))?;
        if let Some(refusal) = self.internal_upstreams.refusal_for_url(&url) {
            return Err(refusal.reason().to_string());
        }
        if url.scheme() != "https" && !cleartext_oracle(&url, self.internal_upstreams) {
            return Err(
                "bridge requests must be https://: the network's credentials cross them, and \
                 only a loopback http:// test oracle under internal_upstreams = \"allow\" may \
                 speak cleartext"
                    .into(),
            );
        }
        Ok(BridgeRequest(self.client.request(method, url)))
    }

    pub(crate) fn get(&self, url: &str) -> Result<BridgeRequest, String> {
        self.request(reqwest::Method::GET, url)
    }

    pub(crate) fn post(&self, url: &str) -> Result<BridgeRequest, String> {
        self.request(reqwest::Method::POST, url)
    }

    /// Only the Matrix bridge sends with PUT (the transaction id is in the
    /// path); the `lint` job builds each bridge alone with `-Dwarnings`.
    #[cfg(feature = "matrix")]
    pub(crate) fn put(&self, url: &str) -> Result<BridgeRequest, String> {
        self.request(reqwest::Method::PUT, url)
    }
}

/// A bridge request being built. Its one send, [`BridgeRequest::send`], reads
/// the status before anything else sees the response: a bare
/// `reqwest::RequestBuilder::send` returns `Ok` for a 3xx, a 429 or a 5xx just
/// as for a 200, and a caller that went on to decode the body accepted a
/// redirect's or an error page's JSON and ignored a rate limit's wait. The
/// Slack Web API calls did exactly that until this type left no other way to
/// send.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
#[derive(Debug)]
#[must_use = "a bridge request does nothing until it is sent"]
pub(crate) struct BridgeRequest(reqwest::RequestBuilder);

#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
impl BridgeRequest {
    #[cfg(any(feature = "discord", feature = "slack"))]
    pub(crate) fn header(self, name: &'static str, value: String) -> Self {
        Self(self.0.header(name, value))
    }

    #[cfg(feature = "matrix")]
    pub(crate) fn bearer_auth(self, token: &str) -> Self {
        Self(self.0.bearer_auth(token))
    }

    pub(crate) fn json<T: serde::Serialize + ?Sized>(self, body: &T) -> Self {
        Self(self.0.json(body))
    }

    #[cfg(any(feature = "matrix", feature = "slack"))]
    pub(crate) fn query<T: serde::Serialize + ?Sized>(self, query: &T) -> Self {
        Self(self.0.query(query))
    }

    /// Send the request; anything but a success status is a failure. A 3xx is
    /// one too: the client never follows it (an upstream cannot re-target a
    /// request at an internal address), and a message "sent" with a 302 was
    /// never posted. A `429` is [`BridgeFailure::RateLimited`] with the wait it
    /// asks for; any other status is [`BridgeFailure::Status`], for a caller
    /// that gives statuses a meaning (a refused token, a room it may not join).
    pub(crate) async fn send(self) -> Result<reqwest::Response, BridgeFailure> {
        let response = self.0.send().await.map_err(|e| e.to_string())?;
        let status = response.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(BridgeFailure::RateLimited(rate_limit_wait(response).await));
        }
        if !status.is_success() {
            return Err(BridgeFailure::Status(status));
        }
        Ok(response)
    }
}

/// A bridge's effective API base URL: the configured one (trailing slash
/// stripped), or the provider default when unset. Shared so the two
/// token-based bridges apply the same override rule.
#[cfg(any(feature = "discord", feature = "slack"))]
pub(crate) fn bridge_api_base(configured: &str, default: &str) -> String {
    if configured.is_empty() {
        default.to_string()
    } else {
        configured.trim_end_matches('/').to_string()
    }
}

#[cfg(all(test, any(feature = "discord", feature = "slack")))]
pub(crate) fn assert_bridge_api_base(base: &mut String, default: &str, override_base: &str) {
    assert_eq!(bridge_api_base(base, default), default);
    *base = override_base.into();
    assert_eq!(
        bridge_api_base(base, default),
        override_base.trim_end_matches('/')
    );
}

/// Build the bridge HTTP client, mapping a build failure to the session
/// outcome. Shared so both WebSocket bridges log and fail the same way when
/// the vetted-resolver client can't be built.
#[cfg(any(feature = "discord", feature = "slack"))]
pub(crate) fn bridge_http_or_outcome(
    tag: &str,
    timeout: std::time::Duration,
    internal_upstreams: crate::egress::InternalUpstreams,
) -> Result<BridgeHttp, SessionOutcome> {
    BridgeHttp::new(timeout, internal_upstreams).map_err(|e| {
        eprintln!("{tag}: http client build failed: {e}");
        SessionOutcome::Dropped(NetworkFailure::UpstreamRequestFailed)
    })
}

/// The gateway WebSocket stream type both WebSocket bridges run over.
#[cfg(any(feature = "discord", feature = "slack"))]
pub(crate) type BridgeWs =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Open a bridge gateway WebSocket with a bounded handshake, mapping failure
/// to the session outcome. Shared so both WebSocket bridges apply the same
/// handshake bound and error vocabulary.
#[cfg(any(feature = "discord", feature = "slack"))]
pub(crate) async fn bridge_ws_open(
    url: &str,
    tag: &str,
    transport: &str,
    api_base: &str,
    internal_upstreams: crate::egress::InternalUpstreams,
) -> Result<BridgeWs, SessionOutcome> {
    match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        bridge_ws_connect(url, bridge_ws_config(), api_base, internal_upstreams),
    )
    .await
    {
        Ok(Ok(ws)) => Ok(ws),
        Ok(Err(e)) => {
            eprintln!("{tag}: {transport} connect failed: {e}");
            Err(SessionOutcome::Dropped(NetworkFailure::ConnectionFailed))
        }
        Err(_) => {
            eprintln!("{tag}: {transport} connect timed out");
            Err(SessionOutcome::Dropped(NetworkFailure::ConnectionTimedOut))
        }
    }
}

/// When an upstream, an attached client or a gateway must next show a sign
/// of life; the edge's, since a `/ws/ui` socket's liveness is held there.
pub(crate) use e6irc_edge::peer_write::SilenceDeadline;

/// One frame's outcome from a bridge gateway socket, after the shared
/// handling (idle timeout, ping/pong, non-text frames).
#[cfg(any(feature = "discord", feature = "slack"))]
pub(crate) enum BridgeRead {
    /// A text frame to parse and dispatch.
    Text(String),
    /// Nothing to dispatch — a ping was answered or a non-text frame arrived.
    Skip,
    /// The socket went idle past the read timeout (logged).
    Idle,
    /// The peer sent a Close frame (`Some` code) or the stream ended (`None`).
    Closed(Option<u16>),
    /// A socket read error (logged).
    ReadFailed,
    /// Answering a ping failed — the socket is dead on write.
    WriteFailed,
}

/// Read the next frame from a bridge gateway socket: answer pings, skip
/// non-text frames, and bound idle time. Shared by the two WebSocket bridges
/// so the ping/idle discipline is written once, not kept in step by hand.
/// Send one frame on a bridge's gateway socket, bounded like every other
/// write to a peer ([`crate::peer_write`]): a gateway that stops reading fails
/// the send instead of parking the session, which then could not see its stop
/// signal or its heartbeat going unanswered.
#[cfg(any(feature = "discord", feature = "slack"))]
pub(crate) async fn bridge_ws_send(
    write: &mut futures_util::stream::SplitSink<BridgeWs, tokio_tungstenite::tungstenite::Message>,
    frame: tokio_tungstenite::tungstenite::Message,
) -> Result<(), e6irc_edge::peer_write::SendFailure> {
    use futures_util::SinkExt;
    e6irc_edge::peer_write::within_send_deadline(
        e6irc_edge::peer_write::PEER_WRITE_DEADLINE,
        write.send(frame),
    )
    .await
}

#[cfg(any(feature = "discord", feature = "slack"))]
pub(crate) async fn next_bridge_frame(
    read: &mut futures_util::stream::SplitStream<BridgeWs>,
    write: &mut futures_util::stream::SplitSink<BridgeWs, tokio_tungstenite::tungstenite::Message>,
    silence: &mut SilenceDeadline,
    tag: &str,
    transport: &str,
) -> BridgeRead {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message as Ws;
    let Some(frame) = silence.bound(read.next()).await else {
        eprintln!("{tag}: {transport} idle past timeout; reconnecting");
        return BridgeRead::Idle;
    };
    silence.restart();
    match frame {
        Some(Ok(Ws::Text(t))) => BridgeRead::Text(t.as_str().to_string()),
        Some(Ok(Ws::Ping(p))) => {
            if bridge_ws_send(write, Ws::Pong(p)).await.is_err() {
                BridgeRead::WriteFailed
            } else {
                BridgeRead::Skip
            }
        }
        Some(Ok(Ws::Close(frame))) => BridgeRead::Closed(frame.as_ref().map(|f| u16::from(f.code))),
        None => BridgeRead::Closed(None),
        Some(Ok(_)) => BridgeRead::Skip,
        Some(Err(e)) => {
            eprintln!("{tag}: {transport} read error: {e}");
            BridgeRead::ReadFailed
        }
    }
}

/// Read the next text frame from a one-socket gateway (Discord's), mapping
/// the terminal outcomes (idle, close, read/write failure) to the session
/// outcome. `on_close` decides what a protocol close code means for the
/// provider. Slack reads [`next_bridge_frame`] itself: it holds two sockets
/// across a handover, and one retiring is not the session's end.
#[cfg(feature = "discord")]
pub(crate) async fn next_bridge_text(
    read: &mut futures_util::stream::SplitStream<BridgeWs>,
    write: &mut futures_util::stream::SplitSink<BridgeWs, tokio_tungstenite::tungstenite::Message>,
    silence: &mut SilenceDeadline,
    tag: &str,
    transport: &str,
    on_close: impl FnOnce(Option<u16>) -> SessionOutcome,
) -> Result<Option<String>, SessionOutcome> {
    match next_bridge_frame(read, write, silence, tag, transport).await {
        BridgeRead::Text(t) => Ok(Some(t)),
        BridgeRead::Skip => Ok(None),
        BridgeRead::Idle => Err(SessionOutcome::Dropped(NetworkFailure::KeepaliveTimedOut)),
        BridgeRead::WriteFailed => {
            Err(SessionOutcome::Dropped(NetworkFailure::UpstreamWriteFailed))
        }
        BridgeRead::ReadFailed => Err(SessionOutcome::Dropped(NetworkFailure::ConnectionLost)),
        BridgeRead::Closed(code) => Err(on_close(code)),
    }
}

/// `start` for a bridge driver: build the buffer channel and spawn the
/// reconnecting run loop. Byte-identical for every bridge; the file's `run`
/// (below) carries the provider specifics.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
macro_rules! bridge_start {
    () => {
        fn prepare(self: Box<Self>) -> super::PreparedDriver {
            let (handle, ends) = NetworkHandle::bridge_channels(self.config.buffer_cap);
            super::PreparedDriver::new(handle, run(self.config, ends))
        }
    };
}
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
pub(crate) use bridge_start;

/// Open a bridge gateway WebSocket to `url`, vetting the resolved IP the same way
/// [`crate::egress::VettingResolver`] vets HTTP dials. The gateway URL comes from an upstream
/// REST response, so a hostile/compromised provider could point it at an internal
/// address; `connect_async` would resolve and dial it blind. Instead we resolve
/// the host ourselves, dial a *vetted* address directly, and hand that stream to
/// tungstenite for the TLS handshake (validated against the URL's hostname, not
/// the IP) — closing the SSRF vector with no resolve-then-dial race between the check and the use.
#[cfg(any(feature = "discord", feature = "slack"))]
pub(crate) async fn bridge_ws_connect(
    url: &str,
    config: tokio_tungstenite::tungstenite::protocol::WebSocketConfig,
    api_base: &str,
    internal_upstreams: crate::egress::InternalUpstreams,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    String,
> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let (host, port) = bridge_gateway_authority(url)?;
    require_secure_gateway(url, api_base, internal_upstreams)?;
    let request = url.into_client_request().map_err(|e| e.to_string())?;
    let vetted = resolve_vetted((host.as_str(), port), internal_upstreams)
        .await
        .map_err(|e| e.to_string())?;
    if vetted.is_empty() {
        return Err(format!(
            "{host}: no permitted address (internal or never an upstream)"
        ));
    }
    let tcp = connect_first_reachable(vetted)
        .await
        .map_err(|e| e.to_string())?;
    let (ws, _response) =
        tokio_tungstenite::client_async_tls_with_config(request, tcp, Some(config), None)
            .await
            .map_err(|e| e.to_string())?;
    Ok(ws)
}

/// Resolve `addr`, keep only the addresses the policy permits, and order them so
/// the address families alternate. Every upstream dial — IRC, and a bridge's
/// gateway socket — resolves through here, so a hostname that resolves (now, or
/// after a DNS rebind) to a refused address is refused at connect time.
pub(crate) async fn resolve_vetted<A: tokio::net::ToSocketAddrs>(
    addr: A,
    policy: crate::egress::InternalUpstreams,
) -> std::io::Result<Vec<std::net::SocketAddr>> {
    Ok(interleave_address_families(
        tokio::net::lookup_host(addr)
            .await?
            .filter(|address| policy.permits(address.ip()))
            .collect(),
    ))
}

/// Alternate the address families, keeping each family's own order. Public
/// round robins commonly answer with both IPv6 and IPv4; a host without working
/// IPv6 that only ever tried the first answer retried the same unreachable
/// address forever instead of reaching the IPv4 peer.
pub(crate) fn interleave_address_families(
    addresses: Vec<std::net::SocketAddr>,
) -> Vec<std::net::SocketAddr> {
    let start_with_ipv6 = addresses.first().is_some_and(std::net::SocketAddr::is_ipv6);
    let (ipv6, ipv4): (std::collections::VecDeque<_>, std::collections::VecDeque<_>) = addresses
        .into_iter()
        .partition(std::net::SocketAddr::is_ipv6);
    let (mut first, mut second) = if start_with_ipv6 {
        (ipv6, ipv4)
    } else {
        (ipv4, ipv6)
    };
    let mut ordered = Vec::with_capacity(first.len() + second.len());
    while !first.is_empty() || !second.is_empty() {
        if let Some(address) = first.pop_front() {
            ordered.push(address);
        }
        if let Some(address) = second.pop_front() {
            ordered.push(address);
        }
    }
    ordered
}

/// How long one concrete address may take to answer a TCP handshake. Bounded
/// per address so one black-holed answer cannot consume the whole connection
/// deadline before the next address is tried.
pub(crate) const ADDRESS_DIAL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// Open a TCP connection to the first of `addresses` that answers within
/// [`ADDRESS_DIAL_DEADLINE`]; the error is the last address's when none does.
/// The gateway WebSocket dialer's loop; the IRC driver keeps its own because it
/// also retries the *TLS* handshake on the next address.
#[cfg(any(feature = "discord", feature = "slack"))]
pub(crate) async fn connect_first_reachable(
    addresses: Vec<std::net::SocketAddr>,
) -> std::io::Result<tokio::net::TcpStream> {
    let mut last_error = std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "upstream resolved addresses were exhausted",
    );
    for address in addresses {
        match tokio::time::timeout(
            ADDRESS_DIAL_DEADLINE,
            tokio::net::TcpStream::connect(address),
        )
        .await
        {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => last_error = error,
            Err(_) => {
                last_error = std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "concrete upstream address timed out",
                );
            }
        }
    }
    Err(last_error)
}

/// The gateway socket carries the session's credentials (Discord's IDENTIFY
/// is the bot token), and its URL is whatever the upstream's REST answer
/// said. A `ws://` answer would send them in the clear, so the gateway must
/// be `wss://` — with one exception: a loopback `http://` API base under the
/// operator's allowance is the in-process test oracle, and it speaks
/// cleartext to itself.
#[cfg(any(feature = "discord", feature = "slack"))]
fn require_secure_gateway(
    url: &str,
    api_base: &str,
    internal_upstreams: crate::egress::InternalUpstreams,
) -> Result<(), String> {
    let gateway = url::Url::parse(url)
        .map_err(|_| "gateway URL must be an absolute ws(s) URL".to_string())?;
    if gateway.scheme() == "wss" {
        return Ok(());
    }
    let oracle =
        url::Url::parse(api_base).is_ok_and(|base| cleartext_oracle(&base, internal_upstreams));
    if oracle {
        Ok(())
    } else {
        Err(
            "gateway URL must be wss://: the session credentials cross this socket, and only \
             a loopback http:// API base under internal_upstreams = \"allow\" may speak cleartext"
                .into(),
        )
    }
}

/// Whether `url` is the one place a bridge may speak cleartext: an `http://`
/// loopback test oracle, under the operator's `internal_upstreams = "allow"`.
/// The REST client and the gateway dialer both ask this, so the two
/// transports cannot disagree about when credentials may travel unencrypted.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
fn cleartext_oracle(url: &url::Url, internal_upstreams: crate::egress::InternalUpstreams) -> bool {
    internal_upstreams == crate::egress::InternalUpstreams::Allow
        && url.scheme() == "http"
        && url.host().is_some_and(is_loopback_host)
}

/// Whether a URL's host is a loopback address, as a literal. A name —
/// `localhost` included — is never taken to mean this machine: it is whatever
/// a resolver answers, and a bridge's credentials would follow the answer.
fn is_loopback_host(host: url::Host<&str>) -> bool {
    match host {
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.to_canonical().is_loopback(),
        url::Host::Domain(_) => false,
    }
}

#[cfg(any(feature = "discord", feature = "slack"))]
fn bridge_gateway_authority(url: &str) -> Result<(String, u16), String> {
    let parsed = url::Url::parse(url)
        .map_err(|_| "gateway URL must be an absolute ws(s) URL".to_string())?;
    if !matches!(parsed.scheme(), "ws" | "wss")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err("gateway URL must be absolute ws(s), without credentials or fragment".into());
    }
    let port = parsed
        .port_or_known_default()
        .ok_or("gateway URL has no known default port")?;
    Ok((parsed.host_str().expect("checked host").to_string(), port))
}

/// Largest HTTP response body a bridge will read from an upstream before
/// parsing it as JSON.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
pub(crate) const MAX_BRIDGE_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// How a bridge request failed.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BridgeFailure {
    /// `429`: the upstream asks for this long before the next request. Kept
    /// apart from every other failure so a caller can wait instead of losing
    /// the message, and a sync loop can pause instead of reconnecting — the
    /// reconnect re-did every join, the very writes being limited.
    RateLimited(std::time::Duration),
    /// The upstream answered with this status, which is neither a success
    /// nor a `429` (a 3xx included: a bridge never follows one).
    Status(reqwest::StatusCode),
    /// Anything else, in e6irc's own words (never the provider's body).
    Failed(String),
}

#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
impl std::fmt::Display for BridgeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RateLimited(wait) => write!(f, "upstream rate limit; retry after {wait:?}"),
            Self::Status(status) if status.is_redirection() => write!(
                f,
                "upstream answered HTTP {status}; a bridge never follows a redirect"
            ),
            Self::Status(status) => write!(f, "upstream answered HTTP {status}"),
            Self::Failed(detail) => f.write_str(detail),
        }
    }
}

#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
impl From<String> for BridgeFailure {
    fn from(detail: String) -> Self {
        Self::Failed(detail)
    }
}

#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
impl From<BridgeFailure> for String {
    fn from(failure: BridgeFailure) -> Self {
        failure.to_string()
    }
}

/// The wait a `429` names when it names none a bridge can read (no
/// `Retry-After` header, no `retry_after` / `retry_after_ms` body field).
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
pub(crate) const RATE_LIMIT_UNSTATED_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// The longest rate-limit wait a bridge believes. An upstream's number past
/// it is clamped: the wait is still honoured for an hour, and a nonsense
/// value cannot park a driver for good or overflow the timer.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
const RATE_LIMIT_WAIT_CEILING: std::time::Duration = std::time::Duration::from_secs(3600);

/// The wait a `429` asks for: the body's `retry_after` (Discord, seconds) or
/// `retry_after_ms` (Matrix), else the `Retry-After` header in seconds (every
/// provider), else [`RATE_LIMIT_UNSTATED_WAIT`]; clamped to
/// [`RATE_LIMIT_WAIT_CEILING`].
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
async fn rate_limit_wait(response: reqwest::Response) -> std::time::Duration {
    #[derive(serde::Deserialize)]
    struct RateLimitBody {
        #[serde(default)]
        retry_after: Option<f64>,
        #[serde(default)]
        retry_after_ms: Option<u64>,
    }
    let seconds = |value: f64| {
        (value.is_finite() && value >= 0.0).then(|| {
            std::time::Duration::from_secs_f64(value.min(RATE_LIMIT_WAIT_CEILING.as_secs_f64()))
        })
    };
    let header = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<f64>().ok())
        .and_then(seconds);
    let body = response.bounded_json::<RateLimitBody>().await.ok();
    let from_body = body.and_then(|body| {
        body.retry_after
            .and_then(seconds)
            .or_else(|| body.retry_after_ms.map(std::time::Duration::from_millis))
    });
    from_body
        .or(header)
        .unwrap_or(RATE_LIMIT_UNSTATED_WAIT)
        .min(RATE_LIMIT_WAIT_CEILING)
}

/// What a request that presents the network's credentials asks about, which
/// decides what a refusal of it means (see [`bridge_send_credentials`]).
#[cfg(any(feature = "matrix", feature = "discord"))]
pub(crate) enum CredentialRequest<'a> {
    /// The credentials themselves (a login, the bot's own account): a 401 or
    /// a 403 refuses *them*, which no retry can fix.
    Identity(&'a str),
    /// A Discord channel the configuration names, looked up by id with the
    /// token. Only a 401 refuses the token; a 403 is a channel the bot cannot
    /// see (not in its server, or no View Channel permission) and a 404 one
    /// that does not exist — answers about the configuration, a mapping
    /// refusal naming the channel, rather than a good token called bad or a
    /// missing channel retried forever.
    #[cfg(feature = "discord")]
    DiscordChannel(&'a str),
}

/// [`BridgeRequest::send`] for a request that presents the network's
/// credentials, classified by what it asks about. Written once so every bridge
/// reads the same statuses the same way — the Discord channel lookup used to
/// call a refused token a transient failure while the gateway's refusal of the
/// same token parked the network, and then called a channel the bot could not
/// see a refused token.
#[cfg(any(feature = "matrix", feature = "discord"))]
pub(crate) async fn bridge_send_credentials(
    req: BridgeRequest,
    request: CredentialRequest<'_>,
) -> Result<reqwest::Response, ConnectFail> {
    use reqwest::StatusCode;
    req.send().await.map_err(|failure| {
        let status = match &failure {
            BridgeFailure::Status(status) => Some(*status),
            BridgeFailure::RateLimited(_) | BridgeFailure::Failed(_) => None,
        };
        match request {
            CredentialRequest::Identity(what) => {
                let detail = format!("{what} rejected: {failure}");
                if matches!(
                    status,
                    Some(StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
                ) {
                    ConnectFail::Auth(detail)
                } else {
                    ConnectFail::Transient(detail)
                }
            }
            #[cfg(feature = "discord")]
            CredentialRequest::DiscordChannel(id) => {
                let unmappable = |detail: String| {
                    ConnectFail::Configuration(ConfigurationRefusal::new(
                        NetworkFailure::ChannelMappingFailed,
                        &detail,
                    ))
                };
                match status {
                    Some(StatusCode::UNAUTHORIZED) => {
                        ConnectFail::Auth(format!("channel {id} lookup rejected: {failure}"))
                    }
                    Some(StatusCode::FORBIDDEN) => unmappable(format!(
                        "the bot cannot see Discord channel {id} (HTTP 403): it is not in that \
                         channel's server, or may not view the channel"
                    )),
                    Some(StatusCode::NOT_FOUND) => {
                        unmappable(format!("Discord has no channel {id} (HTTP 404)"))
                    }
                    _ => ConnectFail::Transient(format!("channel {id} lookup failed: {failure}")),
                }
            }
        }
    })
}

/// A WebSocket bridge's whole downstream arm: route the client's command to its
/// bridged channels, refuse what cannot be routed at once, and queue each
/// delivery on `queue` — never awaited here, so the socket keeps being read.
/// `None` means every handle was dropped (or the network was shut down) and
/// the session must stop. Discord and Slack differ only in how one message is
/// sent, which is `deliver`; the loop reports each finished delivery — and
/// emits its echo, as `identity` says it — with [`report_delivery`].
#[cfg(any(feature = "discord", feature = "slack"))]
fn queue_channel_command<F, Fut>(
    ends: &DriverEnds,
    command: Option<ClientCommand>,
    channel_to_id: &HashMap<String, String>,
    identity: &irc_driver::SelfIdentity,
    platform: &str,
    queue: &mut DeliveryQueue,
    deliver: F,
) -> Option<()>
where
    F: FnMut(String, BridgeText) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<(), BridgeFailure>> + Send + 'static,
{
    let command = command?;
    for routed in route_privmsg(&command.line, channel_to_id) {
        match routed {
            RouteResult::Deliver { id, target, text } => {
                let echo = PendingEcho::of(&command, &target, identity);
                let work = deliver_with_retry(deliver.clone(), id.clone(), text, echo);
                if queue.push(work).is_err() {
                    eprintln!(
                        "{platform}: {DELIVERY_QUEUE_CAPACITY} sends in flight; refused one to {id}"
                    );
                    ends.record_error(NetworkFailure::CommandQueueFull);
                    ends.emit_line(undelivered_notice(platform, "channel", &id));
                }
            }
            RouteResult::Unmapped(target) => {
                ends.emit_line(unmapped_target_notice(platform, "channel", &target));
            }
            RouteResult::Rejected(rejection) => {
                ends.emit_line(rejected_bridge_command_notice(platform, rejection));
            }
        }
    }
    Some(())
}

/// WebSocket config for the Discord/Slack gateways: cap the inbound frame and
/// message at the same 16 MiB the HTTP path enforces. tungstenite's defaults
/// (64 MiB message / 16 MiB frame) are *larger* than that deliberate cap, so a
/// hostile or compromised gateway could push a bigger allocation over the socket
/// than the HTTP path allows — one process serves every tenant, so the socket
/// path must share the discipline.
#[cfg(any(feature = "discord", feature = "slack"))]
pub(crate) fn bridge_ws_config() -> tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
    tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(MAX_BRIDGE_RESPONSE_BYTES))
        .max_frame_size(Some(MAX_BRIDGE_RESPONSE_BYTES))
}

/// JSON-parse an upstream HTTP response body under a size cap. `reqwest`'s
/// `.json()`/`.bytes()` buffer the *whole* body first, so a hostile or
/// compromised upstream can return a multi-gigabyte body and exhaust the shared daemon's memory —
/// a cross-tenant DoS, since one process serves every user. This reads chunk by
/// chunk and rejects a body past `MAX_BRIDGE_RESPONSE_BYTES` before buffering it.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
pub(crate) trait BoundedJson {
    async fn bounded_json<T: serde::de::DeserializeOwned>(self) -> Result<T, String>;
}

#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
impl BoundedJson for reqwest::Response {
    async fn bounded_json<T: serde::de::DeserializeOwned>(mut self) -> Result<T, String> {
        if let Some(len) = self.content_length()
            && len as usize > MAX_BRIDGE_RESPONSE_BYTES
        {
            return Err(format!("upstream response too large ({len} bytes)"));
        }
        let mut buf = Vec::new();
        while let Some(chunk) = self.chunk().await.map_err(|e| e.to_string())? {
            if buf.len() + chunk.len() > MAX_BRIDGE_RESPONSE_BYTES {
                return Err("upstream response exceeded the size cap".to_string());
            }
            buf.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&buf).map_err(|e| e.to_string())
    }
}

/// Which IRCv3 message-tag families an attaching client negotiated. Buffered
/// upstream lines are stored fully tagged (server-time/msgid/account); these
/// gate which tags each client is actually sent, since a tag a client didn't
/// negotiate must not appear in its stream.
#[derive(Default, Clone, Copy)]
pub struct AttachCaps {
    pub sasl: bool,
    pub server_time: bool,
    pub message_tags: bool,
    pub account_tag: bool,
    /// echo-message: the attaching client wants its own messages echoed back.
    /// The driver emits exactly one echo per delivered line — the upstream's
    /// own when it echoes, else one it synthesizes — and this decides only
    /// whether the originator is sent it.
    pub echo_message: bool,
    /// batch: the client can receive BATCH-wrapped responses (CHATHISTORY).
    pub batch: bool,
    /// draft/chathistory: the client wants to page backlog via CHATHISTORY.
    pub chathistory: bool,
    /// draft/read-marker: the client wants to set/query per-target read
    /// positions via MARKREAD.
    pub read_marker: bool,
    /// cap-notify: implied by `CAP LS 302`, and then not switched off.
    pub cap_notify: bool,
    /// The client sent `CAP LS 302` (or later): capability values and
    /// multi-line CAP replies are its to receive.
    pub cap_302: bool,
}

impl AttachCaps {
    /// The capabilities as a session record holds them, one bit each in the
    /// order of the fields: every field named, so one added does not compile
    /// until it has its bit.
    pub(crate) fn bits(self) -> u16 {
        let Self {
            sasl,
            server_time,
            message_tags,
            account_tag,
            echo_message,
            batch,
            chathistory,
            read_marker,
            cap_notify,
            cap_302,
        } = self;
        [
            sasl,
            server_time,
            message_tags,
            account_tag,
            echo_message,
            batch,
            chathistory,
            read_marker,
            cap_notify,
            cap_302,
        ]
        .into_iter()
        .enumerate()
        .fold(0, |bits, (at, on)| bits | (u16::from(on) << at))
    }

    /// The capabilities a record's bits name.
    pub(crate) fn from_bits(bits: u16) -> Self {
        let on = |at: u16| bits & (1 << at) != 0;
        Self {
            sasl: on(0),
            server_time: on(1),
            message_tags: on(2),
            account_tag: on(3),
            echo_message: on(4),
            batch: on(5),
            chathistory: on(6),
            read_marker: on(7),
            cap_notify: on(8),
            cap_302: on(9),
        }
    }
}

/// Filter one serialized line to what the recipient negotiated. `TAGMSG` is
/// absent without `message-tags`; for every other command, `time=` needs
/// server-time, `account=` needs account-tag, and remaining tags need
/// message-tags. `None` is a capability-gated omission, not malformed input.
pub(crate) fn filter_tags(line: &str, caps: AttachCaps) -> Option<String> {
    if !caps.message_tags
        && e6irc_proto::message::Message::parse(line)
            .is_ok_and(|message| message.command.eq_ignore_ascii_case("TAGMSG"))
    {
        return None;
    }
    let Some(rest) = line.strip_prefix('@') else {
        return Some(line.to_string());
    };
    // A leading `@` with no following space is a tag section with no message
    // body. Do not turn it into a blank IRC line: surface the whole-line loss
    // with a bounded valid NOTICE, independent of hostile input.
    let Some((tags, body)) = rest.split_once(' ') else {
        return Some(":*bnc* NOTICE * :upstream line omitted: malformed IRC message".to_string());
    };
    let kept: Vec<&str> = tags
        .split(';')
        .filter(|t| {
            let key = t.split('=').next().unwrap_or(t);
            match key {
                "time" => caps.server_time,
                "account" => caps.account_tag,
                _ => caps.message_tags,
            }
        })
        .collect();
    if kept.is_empty() {
        Some(body.to_string())
    } else {
        Some(format!("@{} {}", kept.join(";"), body))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientLineError {
    TooLong,
    Malformed,
}

impl ClientLineError {
    /// Stable human-readable explanation for interactive clients.
    pub const fn message(self) -> &'static str {
        match self {
            Self::TooLong => "message exceeds the IRC wire limit; nothing was sent",
            Self::Malformed => "message is not a complete IRC command; nothing was sent",
        }
    }
}

/// Validate one downstream IRC line under the same message-tags and
/// traditional-body budgets as the main IRC server before it reaches a driver.
pub(crate) fn parse_client_line(
    text: &str,
) -> Result<e6irc_proto::message::Message<'_>, ClientLineError> {
    if !e6irc_proto::message::client_frame_fits(text.as_bytes()) {
        return Err(ClientLineError::TooLong);
    }
    e6irc_proto::message::Message::parse(text).map_err(|_| ClientLineError::Malformed)
}

async fn write_client_line_error<W>(write: &mut W, error: ClientLineError) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let line: &[u8] = match error {
        ClientLineError::TooLong => b":*bnc* 417 * :Input line was too long\r\n",
        ClientLineError::Malformed => b":*bnc* FAIL * INVALID_MESSAGE :Malformed line\r\n",
    };
    write.write_all(line).await?;
    write.flush().await
}

/// An event a driver emits upward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverEvent {
    /// A classified upstream connection state change.
    Status {
        status: DriverConnectionStatus,
        /// Monotonic within this driver instance. An attacher uses the sticky
        /// runtime revision to discard status events that were queued before
        /// its initial status snapshot.
        revision: u64,
    },
    /// One line received from upstream (CRLF stripped), with the ring position
    /// it took.
    Line(BufferedLine),
    /// A safe component notice for attached clients. It intentionally does not
    /// enter the persistence stream: a failed backlog writer cannot retry its
    /// own failure notice forever. Its `seq` is the ring position after it —
    /// its own when it was retained, the newest retained line's when it was
    /// not — so a cursor read off it resumes exactly.
    Notice(BufferedLine),
    /// A synthesized copy of a line an attached client sent. IRC servers do
    /// not echo a sender's own messages unless echo-message was negotiated —
    /// and the driver never negotiates it — so without this the detached
    /// buffer and the account's *other* sessions would only ever record one
    /// side of the conversation. `origin` identifies the sending attachment:
    /// the originator itself is excluded unless it negotiated echo-message on
    /// attach, mirroring how a real server treats that capability.
    Echo { line: BufferedLine, origin: u64 },
    /// Authoritative state for a newly registered IRC upstream session. A
    /// bounded event backlog cannot establish the current nick or memberships:
    /// the relevant NICK/JOIN may have aged out while a stale PART remains.
    /// Attach transports reconcile this snapshot after playback.
    Session(IrcSessionSnapshot),
    /// What the network said about itself in the registration burst that just
    /// ended (its 004 and 005). A client welcomed before it — with a bridge's
    /// defaults, or the previous session's — is told what changed.
    Features(UpstreamFeatures),
    /// One account's read position advanced on an attached client. This event
    /// is never buffered or persisted as conversation history; raw attaches
    /// filter it by authenticated account and negotiated capability.
    ReadMarker {
        account: String,
        target: String,
        timestamp: String,
        origin: u64,
    },
}

impl DriverEvent {
    pub(crate) fn display_line(&self) -> Option<&str> {
        match self {
            Self::Line(entry) | Self::Notice(entry) => Some(&entry.line),
            Self::Status { .. }
            | Self::Echo { .. }
            | Self::Session(_)
            | Self::Features(_)
            | Self::ReadMarker { .. } => None,
        }
    }
}

/// Who decides a network's nick and channel memberships, which decides what an
/// attached client's `NICK` and `JOIN` mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAuthority {
    /// An IRC server: `NICK`, `JOIN` and `PART` are relayed to it, and its
    /// confirmations are the session.
    Upstream,
    /// A bridged provider account: the nick is the account's name and the
    /// channels are the ones the bridge's configuration maps. Only the
    /// provider (a rename) or the owner (a reconfiguration) changes either,
    /// so the attach layer answers `NICK` and `JOIN` itself.
    Provider,
}

/// Current identity and confirmed channel memberships of an IRC network.
///
/// This is deliberately separate from the detached line buffer: the buffer is
/// bounded history, while this value is authoritative current state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrcSessionSnapshot {
    pub nick: String,
    pub channels: Vec<String>,
}

/// Most channels one IRC session is tracked in. The names and their number
/// are the upstream's to choose, and a tenant may point a network at any
/// server, so without a bound one hostile upstream grows this shared daemon's
/// memory at will. Libera's `CHANLIMIT` is 250.
pub const MAX_TRACKED_CHANNELS: usize = 512;

/// An upstream confirmed more memberships than [`MAX_TRACKED_CHANNELS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelLimitExceeded;

/// What one upstream line changed about the tracked session. The IRC driver
/// folds this into its reconnect intent, so the tracker and the next rejoin
/// set read every line through one set of membership rules.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SessionChange {
    /// Our new nickname, when the line renamed us.
    pub nick: Option<String>,
    /// The `user@host` the upstream shows for this session, when the line
    /// revealed it: the source of our own `JOIN`, `PART` or `NICK` echo, or a
    /// `396 RPL_VISIBLEHOST` (host only). The user part is verbatim, tilde
    /// included, since the upstream decides whether identd answered.
    pub shown_identity: Option<ShownIdentity>,
    /// Channels that were not tracked before this line.
    pub joined: Vec<upstream_identity::ConfirmedChannel>,
    /// Channels this line took us out of, as the line named them. A `QUIT`
    /// reports none: it ends the live membership, not the intent to be there.
    pub left: Vec<String>,
    /// The line changed how the network compares names (a 005 with a new
    /// `CASEMAPPING`): every name keyed under the old mapping is keyed anew.
    pub casemapping_changed: bool,
    /// Names the upstream confirmed us in that are not one channel as any IRC
    /// server could mean it, each cut to [`UNTRACKED_NAME_SHOWN`] bytes. They
    /// are not tracked, so they are not rejoined after a reconnect.
    pub untracked: Vec<String>,
}

/// The identity the upstream shows other users for this session, as far as one
/// line revealed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShownIdentity {
    /// The user (ident) part, when the line carried a full prefix.
    pub user: Option<String>,
    pub host: String,
}

/// Bytes of an untrackable channel name repeated back in its notice.
const UNTRACKED_NAME_SHOWN: usize = 64;

impl SessionChange {
    fn leave(
        &mut self,
        channels: &mut std::collections::HashMap<String, upstream_identity::ConfirmedChannel>,
        names: &e6irc_client::NetworkNames,
        channel: &str,
    ) {
        if channels.remove(&names.fold(channel)).is_some() {
            self.left.push(channel.to_string());
        }
    }
}

/// Most ISUPPORT tokens kept from one upstream, and the longest kept: the
/// tokens are the upstream's to choose and are repeated to every attaching
/// client, so a hostile upstream must not grow them without bound. Real
/// networks advertise a few dozen short tokens.
const MAX_UPSTREAM_ISUPPORT_TOKENS: usize = 128;
const MAX_UPSTREAM_ISUPPORT_TOKEN_LEN: usize = 200;

/// What the network told this session about itself in its registration burst:
/// the `RPL_MYINFO` (004) mode lists and the `RPL_ISUPPORT` (005) tokens. An
/// attaching client is welcomed with these, so it parses the network it is
/// actually talking to — its prefixes, channel types, casemapping — rather
/// than a fixed guess.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UpstreamFeatures {
    /// 004's parameters after the server name and version: user modes,
    /// channel modes, and (optionally) channel modes taking a parameter.
    pub myinfo_modes: Option<Vec<String>>,
    /// 005 tokens in the order first advertised, the latest value of each.
    pub isupport: Vec<String>,
    /// Whether the network carries client-only tags (and `TAGMSG`), which an
    /// IRC upstream does only with `message-tags` enabled. When it does not,
    /// the bouncer strips them from what it forwards and says so with
    /// `CLIENTTAGDENY=*` (IRCv3 message-tags).
    pub client_tags: ClientTags,
}

/// Whether a network carries the client-only tags an attached client sends.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ClientTags {
    /// Relayed as the client sent them; the network's own `CLIENTTAGDENY`
    /// (if any) says which it refuses.
    #[default]
    Relayed,
    /// Stripped before the line leaves, and `TAGMSG` answered by the bouncer.
    Denied,
}

impl UpstreamFeatures {
    /// The `CLIENTTAGDENY` token an attached client is told: the network's
    /// own while it carries client tags, and `*` while it cannot.
    pub(crate) fn client_tag_deny(&self) -> Option<String> {
        match self.client_tags {
            ClientTags::Denied => Some("CLIENTTAGDENY=*".to_string()),
            ClientTags::Relayed => self
                .isupport
                .iter()
                .find(|token| isupport_key(token) == "CLIENTTAGDENY")
                .cloned(),
        }
    }

    fn observe_isupport(&mut self, tokens: &[&str]) {
        let key = |token: &str| token.split('=').next().unwrap_or(token).to_string();
        for token in tokens {
            if token.is_empty()
                || token.starts_with(':')
                || token.len() > MAX_UPSTREAM_ISUPPORT_TOKEN_LEN
            {
                continue;
            }
            // `-TOKEN` withdraws an earlier advertisement.
            if let Some(withdrawn) = token.strip_prefix('-') {
                self.isupport.retain(|kept| key(kept) != withdrawn);
                continue;
            }
            let name = key(token);
            let full = self.isupport.len() >= MAX_UPSTREAM_ISUPPORT_TOKENS;
            match self.isupport.iter_mut().find(|kept| key(kept) == name) {
                Some(kept) => *kept = (*token).to_string(),
                None if !full => self.isupport.push((*token).to_string()),
                None => {}
            }
        }
    }
}

#[derive(Debug, Default, Clone)]
struct IrcSessionState {
    nick: Option<String>,
    channels: std::collections::HashMap<String, upstream_identity::ConfirmedChannel>,
    /// Each channel's topic and members, as the session's lines told them
    /// (the session's live state); `None` for the ring's head and for a
    /// mirror of what one attached client has been shown, which need only the
    /// membership: the backlog keeps no member list ([`told_live_only`]).
    views: Option<channel_views::ChannelViews>,
    features: UpstreamFeatures,
    /// How the network names things, from its 005 lines. Kept across sessions
    /// of one network (a new session's 005 updates it), because what was
    /// filed under its names is read back under them before the next 005.
    names: e6irc_client::NetworkNames,
    /// Between a session's welcome and the end of its MOTD: the network's
    /// registration burst, which describes the network to this bouncer and is
    /// never an attached client's to read (§10.4: the bouncer's own ISUPPORT
    /// replaces the network's).
    in_burst: bool,
}

/// The numerics of an upstream's registration burst after `001`: host, date,
/// `RPL_MYINFO`, ISUPPORT, the unique id, LUSERS, and the MOTD (or its
/// absence), plus the visible host some networks set there.
const REGISTRATION_BURST: &[&str] = &[
    "001", "002", "003", "004", "005", "042", "250", "251", "252", "253", "254", "255", "265",
    "266", "372", "375", "376", "396", "422",
];

impl IrcSessionState {
    /// A mirror that compares names the way `names` says.
    fn with_names(names: e6irc_client::NetworkNames) -> Self {
        Self {
            names,
            ..Self::default()
        }
    }

    /// State that follows each channel's topic and members as well: a
    /// session's own.
    fn following_channels() -> Self {
        Self {
            views: Some(channel_views::ChannelViews::default()),
            ..Self::default()
        }
    }

    /// State in `snapshot`, named as `names` and `features` say, with each
    /// channel's topic and members not known.
    fn at(
        snapshot: &IrcSessionSnapshot,
        names: e6irc_client::NetworkNames,
        features: UpstreamFeatures,
    ) -> Self {
        let mut state = Self {
            names,
            features,
            ..Self::default()
        };
        state.replace(snapshot);
        state
    }

    /// What is known of `channel`'s topic and members.
    fn view(&self, channel: &str) -> Option<&channel_views::ChannelView> {
        self.views.as_ref()?.get(&self.names.fold(channel))
    }

    fn begin(&mut self, nick: String) -> IrcSessionSnapshot {
        self.nick = Some(nick);
        self.channels.clear();
        if let Some(views) = &mut self.views {
            views.clear();
        }
        self.features = UpstreamFeatures {
            client_tags: self.features.client_tags,
            ..UpstreamFeatures::default()
        };
        self.snapshot().expect("a begun IRC session has a nick")
    }

    /// Whether `line` is part of the registration burst still arriving, and
    /// so is kept from attached clients. The burst ends at the end of the
    /// MOTD, or at the first line that is not part of one — a server's own
    /// `NOTICE` or our user `MODE`, which some servers interleave, is relayed
    /// without ending it.
    fn in_registration_burst(&mut self, line: &str) -> bool {
        if !self.in_burst {
            return false;
        }
        let Ok(message) = e6irc_proto::message::Message::parse(line) else {
            self.in_burst = false;
            return false;
        };
        let command = message.command;
        if !REGISTRATION_BURST.contains(&command) {
            let from_server = message
                .source
                .as_ref()
                .is_none_or(|source| source.user.is_none() && source.host.is_none());
            let interleaved = (command.eq_ignore_ascii_case("NOTICE") && from_server)
                || command.eq_ignore_ascii_case("MODE");
            if !interleaved {
                self.in_burst = false;
            }
            return false;
        }
        if matches!(command, "376" | "422") {
            self.in_burst = false;
        }
        true
    }

    /// Apply one line. A `JOIN` that would exceed the bound changes nothing.
    fn observe(&mut self, line: &str) -> Result<SessionChange, ChannelLimitExceeded> {
        let mut change = SessionChange::default();
        let Some(current_nick) = self.nick.as_ref() else {
            return Ok(change);
        };
        let Ok(message) = e6irc_proto::message::Message::parse(line) else {
            return Ok(change);
        };
        let own_before = current_nick.clone();
        let names = &self.names;
        let source_nick = message.source.as_ref().map(|source| source.name);
        let is_us = |candidate: Option<&str>| {
            candidate.is_some_and(|candidate| names.eq(candidate, current_nick))
        };
        let we_quit = message.command.eq_ignore_ascii_case("QUIT") && is_us(source_nick);
        let list = |index: usize| -> Vec<&str> {
            message
                .params
                .get(index)
                .map(|value| value.split(',').filter(|item| !item.is_empty()).collect())
                .unwrap_or_default()
        };
        // Our own echoes carry the prefix the upstream shows for us.
        if is_us(source_nick)
            && let Some(source) = &message.source
            && let Some(host) = source.host
        {
            change.shown_identity = Some(ShownIdentity {
                user: source.user.map(str::to_string),
                host: host.to_string(),
            });
        }
        match message.command.to_ascii_uppercase().as_str() {
            "NICK" if is_us(source_nick) => {
                if let Some(nick) = message.params.first() {
                    self.nick = Some((*nick).to_string());
                    change.nick = self.nick.clone();
                }
            }
            // RPL_VISIBLEHOST: `396 <nick> <host> :is now your visible host`.
            "396" if is_us(message.params.first().copied()) => {
                if let Some(host) = message.params.get(1).filter(|host| !host.is_empty()) {
                    change.shown_identity = Some(ShownIdentity {
                        user: None,
                        host: host.to_string(),
                    });
                }
            }
            "JOIN" if is_us(source_nick) => {
                let mut confirmed = std::collections::HashMap::new();
                for name in list(0) {
                    match upstream_identity::ConfirmedChannel::parse(name, names) {
                        Some(channel) => {
                            confirmed.insert(names.fold(channel.as_str()), channel);
                        }
                        None => change.untracked.push(
                            e6irc_proto::message::truncate_on_char_boundary(
                                name,
                                UNTRACKED_NAME_SHOWN,
                            )
                            .to_string(),
                        ),
                    }
                }
                let added = confirmed
                    .keys()
                    .filter(|key| !self.channels.contains_key(*key))
                    .count();
                if self.channels.len() + added > MAX_TRACKED_CHANNELS {
                    return Err(ChannelLimitExceeded);
                }
                for (key, channel) in confirmed {
                    if self.channels.insert(key, channel.clone()).is_none() {
                        change.joined.push(channel);
                    }
                }
            }
            "PART" if is_us(source_nick) => {
                for channel in list(0) {
                    change.leave(&mut self.channels, names, channel);
                }
            }
            "KICK" => {
                let channels = list(0);
                let targets = list(1);
                if channels.len() == targets.len() {
                    for (channel, target) in channels.into_iter().zip(targets) {
                        if is_us(Some(target)) {
                            change.leave(&mut self.channels, names, channel);
                        }
                    }
                } else if channels.len() == 1
                    && targets.into_iter().any(|target| is_us(Some(target)))
                {
                    change.leave(&mut self.channels, names, channels[0]);
                }
            }
            "QUIT" if is_us(source_nick) => self.channels.clear(),
            // RPL_MYINFO: `004 <nick> <server> <version> <umodes> <cmodes> [<cmodes with param>]`.
            "004" if is_us(message.params.first().copied()) && message.params.len() >= 5 => {
                self.features.myinfo_modes = Some(
                    message.params[3..]
                        .iter()
                        .take(3)
                        .filter(|modes| !modes.is_empty() && !modes.starts_with(':'))
                        .map(|modes| (*modes).to_string())
                        .collect(),
                );
            }
            // RPL_ISUPPORT: `005 <nick> <token>... :are supported by this server`.
            "005" if is_us(message.params.first().copied()) && message.params.len() >= 3 => {
                let tokens = &message.params[1..message.params.len() - 1];
                self.features.observe_isupport(tokens);
                let adopted = self.names.adopt_tokens(tokens.iter().copied());
                if adopted.casemapping {
                    self.rekey();
                    change.casemapping_changed = true;
                }
            }
            _ => {}
        }
        if let Some(views) = &mut self.views {
            if we_quit {
                views.clear();
            }
            for channel in &change.left {
                views.left(&self.names.fold(channel));
            }
            for channel in &change.joined {
                views.joined(self.names.fold(channel.as_str()));
            }
            views.observe(&message, &self.names, &self.features, &own_before);
        }
        Ok(change)
    }

    /// Key every channel (and its view) under the names the network uses now.
    fn rekey(&mut self) {
        if let Some(views) = &mut self.views {
            views.rekey(&self.names, &self.channels);
        }
        let names = &self.names;
        self.channels = std::mem::take(&mut self.channels)
            .into_values()
            .map(|channel| (names.fold(channel.as_str()), channel))
            .collect();
    }

    /// Adopt the network's naming rules and features as they are now, keying
    /// what is held anew when the case mapping changed.
    fn adopt(&mut self, names: &e6irc_client::NetworkNames, features: &UpstreamFeatures) {
        let rekeyed = self.names.casemapping() != names.casemapping();
        self.names = names.clone();
        self.features = features.clone();
        if rekeyed {
            self.rekey();
        }
    }

    /// Track `line` as something an attached client is about to read, and
    /// return what that client should read. A replayed backlog can hold the
    /// confirmed channels of many past sessions, so it is bounded like the
    /// live tracker: a line past the bound is withheld, because a membership
    /// the client saw but this mirror does not hold could never be reconciled
    /// against the authoritative snapshot.
    fn mirror<'line>(&mut self, line: &'line str) -> (&'line str, SessionChange) {
        match self.observe(line) {
            Ok(change) => (line, change),
            Err(ChannelLimitExceeded) => (
                ":*bnc* NOTICE * :upstream line omitted: it exceeds the tracked channel limit",
                SessionChange::default(),
            ),
        }
    }

    /// The nick an attached client has been shown: what it was welcomed
    /// under, then every `NICK` it has read since. The bouncer's own numerics
    /// to it are addressed to this nick, as a server's are.
    fn downstream_nick(&self) -> &str {
        self.nick
            .as_deref()
            .expect("an attached client's mirror begins at its welcome, under its nick")
    }

    fn replace(&mut self, snapshot: &IrcSessionSnapshot) {
        if let Some(views) = &mut self.views {
            views.clear();
        }
        let names = &self.names;
        self.nick = Some(snapshot.nick.clone());
        self.channels = snapshot
            .channels
            .iter()
            .filter_map(|channel| upstream_identity::ConfirmedChannel::parse(channel, names))
            .map(|channel| (names.fold(channel.as_str()), channel))
            .collect();
    }

    fn snapshot(&self) -> Option<IrcSessionSnapshot> {
        let nick = self.nick.clone()?;
        let mut channels: Vec<String> = self
            .channels
            .values()
            .map(|channel| channel.as_str().to_string())
            .collect();
        channels.sort_by_key(|channel| self.names.fold(channel));
        Some(IrcSessionSnapshot { nick, channels })
    }
}

/// A driver status event. A non-connected status always carries the precise
/// safe failure class when one exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverConnectionStatus {
    Connected,
    /// Registered under an alternative nickname; not connected.
    RegainingNickname,
    Reconnecting(NetworkFailure),
    AuthenticationFailed,
    RegistrationFailed(NetworkFailure),
}

impl DriverConnectionStatus {
    pub const fn lifecycle(self) -> NetworkLifecycle {
        match self {
            Self::Connected => NetworkLifecycle::Connected,
            Self::RegainingNickname => NetworkLifecycle::RegainingNickname,
            Self::Reconnecting(_) => NetworkLifecycle::Reconnecting,
            Self::AuthenticationFailed => NetworkLifecycle::AuthenticationFailed,
            Self::RegistrationFailed(_) => NetworkLifecycle::RegistrationFailed,
        }
    }

    pub const fn failure(self) -> Option<NetworkFailure> {
        match self {
            Self::Connected => None,
            Self::RegainingNickname => Some(NetworkFailure::NicknameInUse),
            Self::Reconnecting(failure) | Self::RegistrationFailed(failure) => Some(failure),
            Self::AuthenticationFailed => Some(NetworkFailure::AuthenticationRejected),
        }
    }
}

fn status_notice(status: DriverConnectionStatus) -> String {
    match status {
        DriverConnectionStatus::Connected => ":*bnc* NOTICE * :upstream connected".to_string(),
        DriverConnectionStatus::RegainingNickname => format!(
            ":*bnc* NOTICE * :upstream regaining the configured nickname: {} ({})",
            NetworkFailure::NicknameInUse.summary(),
            NetworkFailure::NicknameInUse.code()
        ),
        DriverConnectionStatus::Reconnecting(failure) => format!(
            ":*bnc* NOTICE * :upstream reconnecting: {} ({})",
            failure.summary(),
            failure.code()
        ),
        DriverConnectionStatus::AuthenticationFailed => format!(
            ":*bnc* NOTICE * :upstream authentication failed: {} ({})",
            NetworkFailure::AuthenticationRejected.summary(),
            NetworkFailure::AuthenticationRejected.code()
        ),
        DriverConnectionStatus::RegistrationFailed(failure) => format!(
            ":*bnc* NOTICE * :upstream registration failed: {} ({})",
            failure.summary(),
            failure.code()
        ),
    }
}

pub(crate) fn accept_status_revision(last_seen: &mut u64, candidate: u64) -> bool {
    if candidate <= *last_seen {
        return false;
    }
    *last_seen = candidate;
    true
}

/// A downstream line queued for the upstream, tagged with the attachment
/// that sent it so a synthesized [`DriverEvent::Echo`] can exclude its
/// originator. Origin 0 is the untracked/internal sender (no exclusion).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCommand {
    pub origin: u64,
    pub line: String,
}

/// A connection-state change a driver reports through [`DriverEnds::emit`].
///
/// Deliberately unable to carry a line. Lines must go through
/// [`DriverEnds::emit_line`], which neutralizes embedded CR/LF/NUL *and*
/// records the line in the detached buffer; a driver that could hand a line to
/// `emit` instead would skip both, injecting into attached clients and leaving
/// detached ones with a gap. `NetworkDriver` is a public SPI, so that has to be
/// impossible to write rather than merely documented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionEvent {
    Connected,
    /// The configured nickname was in use, so the session registered under
    /// an alternative and is taking the configured one back (§10.3). It is
    /// not connected: nothing is joined or sent under the alternative.
    RegainingNickname(NicknameRegain),
    /// A classified transient failure ended the current attempt; another
    /// attempt follows. Carrying the reason makes an unclassified disconnect
    /// impossible for every driver using the public SPI.
    Reconnecting(NetworkFailure),
    /// The upstream refused registration and a slower attempt follows. The
    /// refusal rides along so its sanitized upstream text stays visible for
    /// the whole wait instead of only once the driver parks.
    RegistrationRetrying(e6irc_client::RegistrationRejection),
    /// Credential rejection parked the driver until it is reconfigured. The
    /// upstream's sanitized reason rides along when it gave one.
    AuthenticationFailed(Option<e6irc_client::SaslRejection>),
    /// Repeated IRC registration rejection parked the driver until reconfigured.
    RegistrationFailed(e6irc_client::RegistrationRejection),
    /// A bridge's upstream refused what the configuration asks for, and a
    /// slower attempt follows.
    ConfigurationRetrying(ConfigurationRefusal),
    /// Repeated configuration refusal parked the driver until reconfigured. It
    /// shares the registration-failed lifecycle: both mean "this network's
    /// settings do not work against this upstream".
    ConfigurationFailed(ConfigurationRefusal),
}

/// A session registered under an alternative nickname while it takes the
/// configured one back: who it is and who it is waiting to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NicknameRegain {
    diagnostic: String,
}

impl NicknameRegain {
    pub fn new(registered_as: &str, configured: &str) -> Self {
        Self {
            diagnostic: e6irc_client::bounded_diagnostic(&format!(
                "connected as {registered_as}, regaining {configured}"
            )),
        }
    }

    /// "connected as <alternative>, regaining <configured>".
    pub fn diagnostic(&self) -> &str {
        &self.diagnostic
    }
}

/// A handle to a running, always-on network driver. Events are
/// broadcast, so any number of clients can attach concurrently and the
/// driver keeps running while zero are attached.
pub struct NetworkHandle {
    events: tokio::sync::broadcast::Sender<DriverEvent>,
    commands: mpsc::Sender<ClientCommand>,
    /// Per-network attachment id sequence; each attach takes one so its own
    /// synthesized echoes can be excluded unless it opted into echo-message.
    attach_seq: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Authoritative stop signal. The registry (and only the registry) holds
    /// the `Sender`; `attach` clones `commands` but never this, so removing or
    /// replacing a network stops its driver even while a client is attached —
    /// which otherwise pins the command channel open (the upstream connection
    /// and its decrypted SASL password would persist until the last client
    /// detached, so an operator could not sever a compromised network).
    shutdown: tokio::sync::watch::Sender<bool>,
    /// Signals after the driver task has dropped its endpoint and released any
    /// upstream transport.
    stopped: tokio::sync::watch::Receiver<bool>,
    /// Detached buffer of recent upstream lines (newest last).
    buffer: std::sync::Arc<std::sync::Mutex<Buffer>>,
    /// Runtime state and per-network counters, shared with the driver endpoint.
    runtime: std::sync::Arc<NetworkRuntime>,
    irc_session: std::sync::Arc<std::sync::Mutex<IrcSessionState>>,
    /// Where each attachment receives the replies to its own commands.
    reply_routes: ReplyRoutes,
    /// Who decides this network's nick and channels; see [`SessionAuthority`].
    authority: SessionAuthority,
    /// PG-backed history context for CHATHISTORY/MARKREAD on the attach
    /// listener, set when the network is registered with a database.
    history: std::sync::Arc<std::sync::Mutex<Option<NetworkHistory>>>,
    /// Becomes true after persisted history has been restored into `buffer`.
    history_ready: tokio::sync::watch::Sender<bool>,
    telemetry:
        std::sync::Arc<std::sync::Mutex<Option<std::sync::Arc<crate::observability::Telemetry>>>>,
}

/// The database context a BNC attach needs to serve CHATHISTORY and MARKREAD:
/// the pool plus the owner/network keys under which this network's backlog
/// and markers are stored.
#[derive(Clone)]
pub struct NetworkHistory {
    pub pool: sqlx::PgPool,
    pub owner: String,
    pub network: String,
}

/// The lifecycle state of one running network driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkLifecycle {
    Connecting,
    Connected,
    /// Registered under an alternative nickname, taking the configured one
    /// back ([`ConnectionEvent::RegainingNickname`]).
    RegainingNickname,
    Reconnecting,
    AuthenticationFailed,
    RegistrationFailed,
    /// An operator-configured network held stopped because its owning account
    /// is suspended; reactivating the account restarts it.
    OwnerSuspended,
    /// An operator-configured network held stopped because its owning account
    /// was deleted. It stays stopped: its owner is gone.
    OwnerDeleted,
}

impl NetworkLifecycle {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::RegainingNickname => "regaining_nickname",
            Self::Reconnecting => "reconnecting",
            Self::AuthenticationFailed => "authentication_failed",
            Self::RegistrationFailed => "registration_failed",
            Self::OwnerSuspended => "owner_suspended",
            Self::OwnerDeleted => "owner_deleted",
        }
    }
}

/// Why an operator-configured network is held stopped by its owner's account
/// lifecycle (its [`NetworkLifecycle`] while held).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerHold {
    Suspended,
    Deleted,
}

impl OwnerHold {
    const fn lifecycle(self) -> NetworkLifecycle {
        match self {
            Self::Suspended => NetworkLifecycle::OwnerSuspended,
            Self::Deleted => NetworkLifecycle::OwnerDeleted,
        }
    }
}

/// Credential-safe classification of the latest operational failure. Raw
/// upstream errors can contain provider text (and, for some bridges, request
/// details), so monitoring exposes this closed vocabulary instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkFailure {
    ConnectionTimedOut,
    ConnectionFailed,
    SecureConnectionFailed,
    RegistrationTimedOut,
    RegistrationFailed,
    RegistrationRejected,
    InvalidNickname,
    InvalidUsername,
    NicknameInUse,
    /// Services refused to hand the configured nickname back: it is
    /// registered to another account.
    NicknameRegainRefused,
    /// 464 after the configured server password was sent.
    ServerPasswordRejected,
    /// 464 with no server password configured.
    ServerPasswordRequired,
    NetworkBanned,
    AuthenticationRejected,
    SaslUnavailable,
    SaslFailed,
    AutojoinFailed,
    ConnectionLost,
    KeepaliveTimedOut,
    /// The upstream renamed a registered session (a services enforcer moving
    /// an unidentified nickname to `Guest12345`). The session goes on under
    /// the new name, tracked; the owner is told, because it is a name they
    /// did not choose.
    RenamedByUpstream,
    ChannelLimitExceeded,
    UpstreamWriteFailed,
    UpstreamRequestFailed,
    UpstreamProtocolFailed,
    ChannelMappingFailed,
    ChannelJoinRefused,
    /// A bridged Matrix room is end-to-end encrypted, which the bridge cannot
    /// read (it holds no device keys).
    RoomEncrypted,
    /// A chat gateway refused the bot's own configuration: Discord's close
    /// codes for an invalid shard, required sharding, an unsupported API
    /// version, or intents the application may not use; Slack's Socket Mode
    /// switched off. No retry fixes it; the diagnostic names which.
    GatewayConfigurationRefused,
    BacklogStorageFailed,
    BacklogStorageLagged,
    CommandQueueFull,
    DriverStopped,
}

pub const NETWORK_FAILURE_HISTORY_LIMIT: usize = 8;

impl NetworkFailure {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ConnectionTimedOut => "connection_timed_out",
            Self::ConnectionFailed => "connection_failed",
            Self::SecureConnectionFailed => "secure_connection_failed",
            Self::RegistrationTimedOut => "registration_timed_out",
            Self::RegistrationFailed => "registration_failed",
            Self::RegistrationRejected => "registration_rejected",
            Self::InvalidNickname => "invalid_nickname",
            Self::InvalidUsername => "invalid_username",
            Self::NicknameInUse => "nickname_in_use",
            Self::NicknameRegainRefused => "nickname_regain_refused",
            Self::ServerPasswordRejected => "server_password_rejected",
            Self::ServerPasswordRequired => "server_password_required",
            Self::NetworkBanned => "network_banned",
            Self::AuthenticationRejected => "authentication_rejected",
            Self::SaslUnavailable => "sasl_unavailable",
            Self::SaslFailed => "sasl_failed",
            Self::AutojoinFailed => "autojoin_failed",
            Self::ConnectionLost => "connection_lost",
            Self::KeepaliveTimedOut => "keepalive_timed_out",
            Self::RenamedByUpstream => "renamed_by_upstream",
            Self::ChannelLimitExceeded => "channel_limit_exceeded",
            Self::UpstreamWriteFailed => "upstream_write_failed",
            Self::UpstreamRequestFailed => "upstream_request_failed",
            Self::UpstreamProtocolFailed => "upstream_protocol_failed",
            Self::ChannelMappingFailed => "channel_mapping_failed",
            Self::ChannelJoinRefused => "channel_join_refused",
            Self::RoomEncrypted => "room_encrypted",
            Self::GatewayConfigurationRefused => "gateway_configuration_refused",
            Self::BacklogStorageFailed => "backlog_storage_failed",
            Self::BacklogStorageLagged => "backlog_storage_lagged",
            Self::CommandQueueFull => "command_queue_full",
            Self::DriverStopped => "driver_stopped",
        }
    }

    pub const fn summary(self) -> &'static str {
        match self {
            Self::ConnectionTimedOut => "The upstream connection timed out.",
            Self::ConnectionFailed => "The upstream address could not be reached.",
            Self::SecureConnectionFailed => {
                "The secure connection failed; check DNS, port, and TLS identity."
            }
            Self::RegistrationTimedOut => "The upstream did not finish IRC registration in time.",
            Self::RegistrationFailed => "The upstream closed or rejected IRC registration.",
            Self::RegistrationRejected => {
                "The upstream rejected IRC registration; check the nickname and network policy."
            }
            Self::InvalidNickname => "The upstream rejected the configured nickname.",
            Self::InvalidUsername => "The upstream rejected the IRC username.",
            Self::NicknameInUse => "The configured nickname is already in use.",
            Self::NicknameRegainRefused => {
                "The configured nickname belongs to another account; the network will not hand it back."
            }
            Self::ServerPasswordRejected => "The network rejected the configured server password.",
            Self::ServerPasswordRequired => {
                "The network requires a server password, which this network configuration does not supply."
            }
            Self::NetworkBanned => "The upstream network banned this connection.",
            Self::AuthenticationRejected => "The upstream rejected the configured credentials.",
            Self::SaslUnavailable => {
                "The upstream does not offer the SASL authentication this network is configured for."
            }
            Self::SaslFailed => "SASL authentication ended without a verdict on the credentials.",
            Self::AutojoinFailed => "A configured JOIN could not be sent during startup.",
            Self::ConnectionLost => "The established upstream connection was lost.",
            Self::KeepaliveTimedOut => "The upstream stopped responding to keepalive checks.",
            Self::RenamedByUpstream => {
                "The upstream renamed this session to a nickname the owner did not choose."
            }
            Self::ChannelLimitExceeded => {
                "The upstream confirmed more than 512 channels; the session was ended."
            }
            Self::UpstreamWriteFailed => "A message could not be sent to the upstream.",
            Self::UpstreamRequestFailed => "An upstream API request failed.",
            Self::UpstreamProtocolFailed => {
                "The upstream returned an invalid or unsupported response."
            }
            Self::ChannelMappingFailed => {
                "A configured bridged channel could not be mapped safely."
            }
            Self::ChannelJoinRefused => {
                "The upstream refused to let this network join a configured channel."
            }
            Self::RoomEncrypted => {
                "A configured room is end-to-end encrypted, which the bridge cannot read."
            }
            Self::GatewayConfigurationRefused => {
                "The chat gateway refused this bot's configuration; no retry can fix it."
            }
            Self::BacklogStorageFailed => "The detached backlog could not be stored.",
            Self::BacklogStorageLagged => {
                "The detached backlog writer fell behind and missed messages."
            }
            Self::CommandQueueFull => "The upstream command queue is full.",
            Self::DriverStopped => "The network driver is no longer accepting commands.",
        }
    }
}

fn failure_notice(failure: NetworkFailure) -> String {
    format!(
        ":*bnc* NOTICE * :component error: {} ({})",
        failure.summary(),
        failure.code()
    )
}

fn emit_failure_notice(
    buffer: &std::sync::Mutex<Buffer>,
    events: &tokio::sync::broadcast::Sender<DriverEvent>,
    failure: NetworkFailure,
) {
    let line = ingest(failure_notice(failure));
    let buffer = buffer.lock().expect("buffer poisoned");
    // A storage failure repeats for every line the upstream sends while the
    // database is away, and a full command queue for every line a client
    // sends while the upstream drains it: retained, their identical notices
    // would evict the conversation the ring exists to keep, and an attaching
    // client's replay would announce a congestion long over. Each is told
    // live instead, at its position (§10.1: a notice is retained only if it
    // will still be true).
    let live_only = matches!(
        failure,
        NetworkFailure::BacklogStorageFailed
            | NetworkFailure::BacklogStorageLagged
            | NetworkFailure::CommandQueueFull
    );
    let mut buffer = buffer;
    let seq = if live_only {
        buffer.position()
    } else {
        buffer.push_said(line.clone(), None)
    };
    let entry = BufferedLine { seq, line };
    let event = if live_only {
        DriverEvent::Notice(entry)
    } else {
        DriverEvent::Line(entry)
    };
    // Keep the replay boundary atomic for failure lines too.
    drop(events.send(event));
}

/// One classified failure with when it happened — the unit of the bounded
/// per-network failure history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureRecord {
    pub at: e6irc_proto::time::Millis,
    failure: NetworkFailure,
}

impl FailureRecord {
    /// The closed failure code (see [`NetworkFailure::code`]).
    pub fn code(&self) -> &'static str {
        self.failure.code()
    }

    /// The operator-safe summary (see [`NetworkFailure::summary`]).
    pub fn summary(&self) -> &'static str {
        self.failure.summary()
    }
}

/// Owner-safe operational data for one network. It contains counters and
/// timestamps plus a closed, credential-safe failure classification—never raw
/// errors that could echo a provider response containing secrets.
#[derive(Debug, Clone)]
pub struct NetworkRuntimeSnapshot {
    pub lifecycle: NetworkLifecycle,
    pub(crate) status_revision: u64,
    pub state_changed_at: e6irc_proto::time::Millis,
    /// When the next reconnect attempt fires, while the driver is waiting
    /// to retry; `None` when connected or parked.
    pub next_retry_at: Option<e6irc_proto::time::Millis>,
    /// The bounded newest-last failure history (see [`FailureRecord`]).
    pub recent_failures: Vec<FailureRecord>,
    pub connected_at: Option<e6irc_proto::time::Millis>,
    pub last_input_at: Option<e6irc_proto::time::Millis>,
    pub last_output_at: Option<e6irc_proto::time::Millis>,
    pub last_error_at: Option<e6irc_proto::time::Millis>,
    pub last_error: Option<NetworkFailure>,
    /// Bounded, control-safe text supplied by an IRC server for the latest
    /// registration refusal. Arbitrary bridge/provider errors never enter it.
    pub last_error_diagnostic: Option<String>,
    pub connect_latency_ms: Option<u64>,
    pub connection_attempts: u64,
    pub errors: u64,
    pub attached_clients: u64,
    pub lines_in: u64,
    pub bytes_in: u64,
    pub lines_out: u64,
    pub bytes_out: u64,
    pub buffer_lines: usize,
    pub buffer_capacity: usize,
}

struct NetworkRuntimeState {
    phase: NetworkRuntimePhase,
    status_revision: u64,
    /// The last few classified failures, newest last — a flap pattern is a
    /// sequence, and "last error" alone hides it. Bounded; runtime state is
    /// restart-ephemeral by design.
    recent_failures: std::collections::VecDeque<FailureRecord>,
    state_changed_at: e6irc_proto::time::Millis,
    attempt_started: std::time::Instant,
    connect_latency_ms: Option<u64>,
    connection_attempts: u64,
    errors: u64,
    last_error: Option<FailureRecord>,
    last_error_diagnostic: Option<String>,
}

#[derive(Clone, Copy)]
enum FailureDisposition {
    /// Another attempt follows; after this long, when the shared runner is
    /// the one waiting. (A driver that reports a retry through the public
    /// `emit` schedules its own and has no time to give.)
    Retry {
        next_attempt_in: Option<std::time::Duration>,
    },
    /// Registered, but under an alternative nickname: not a connection yet.
    RegainingNickname,
    Terminal(TerminalNetworkLifecycle),
}

#[derive(Clone, Copy)]
enum TerminalNetworkLifecycle {
    AuthenticationFailed,
    RegistrationFailed,
}

impl TerminalNetworkLifecycle {
    const fn lifecycle(self) -> NetworkLifecycle {
        match self {
            Self::AuthenticationFailed => NetworkLifecycle::AuthenticationFailed,
            Self::RegistrationFailed => NetworkLifecycle::RegistrationFailed,
        }
    }
}

#[derive(Clone, Copy)]
enum NetworkRuntimePhase {
    Connecting,
    Reconnecting {
        next_retry_at: Option<e6irc_proto::time::Millis>,
    },
    Connected {
        connected_at: e6irc_proto::time::Millis,
    },
    /// Registered under an alternative nickname, taking the configured one
    /// back; not connected.
    RegainingNickname,
    Terminal(TerminalNetworkLifecycle),
    /// Stopped by its owner's account lifecycle; the driver is gone.
    Held(OwnerHold),
}

impl NetworkRuntimePhase {
    const fn lifecycle(self) -> NetworkLifecycle {
        match self {
            Self::Connecting => NetworkLifecycle::Connecting,
            Self::Reconnecting { .. } => NetworkLifecycle::Reconnecting,
            Self::Connected { .. } => NetworkLifecycle::Connected,
            Self::RegainingNickname => NetworkLifecycle::RegainingNickname,
            Self::Terminal(lifecycle) => lifecycle.lifecycle(),
            Self::Held(hold) => hold.lifecycle(),
        }
    }

    const fn next_retry_at(self) -> Option<e6irc_proto::time::Millis> {
        match self {
            Self::Reconnecting { next_retry_at } => next_retry_at,
            Self::Connecting
            | Self::Connected { .. }
            | Self::RegainingNickname
            | Self::Terminal(_)
            | Self::Held(_) => None,
        }
    }

    const fn connected_at(self) -> Option<e6irc_proto::time::Millis> {
        match self {
            Self::Connected { connected_at } => Some(connected_at),
            Self::Connecting
            | Self::Reconnecting { .. }
            | Self::RegainingNickname
            | Self::Terminal(_)
            | Self::Held(_) => None,
        }
    }
}

struct NetworkRuntime {
    state: std::sync::Mutex<NetworkRuntimeState>,
    /// The registry's owner/name label, assigned once when the network is
    /// registered so lifecycle log lines say *which* network transitioned
    /// (a bare "disconnected" across a fleet of upstreams is undiagnosable).
    label: std::sync::Mutex<Option<String>>,
    attached_clients: std::sync::atomic::AtomicU64,
    lines_in: std::sync::atomic::AtomicU64,
    bytes_in: std::sync::atomic::AtomicU64,
    lines_out: std::sync::atomic::AtomicU64,
    bytes_out: std::sync::atomic::AtomicU64,
    last_input_at: std::sync::atomic::AtomicU64,
    last_output_at: std::sync::atomic::AtomicU64,
}

impl NetworkRuntime {
    /// The registry label for log lines, or the network kind placeholder
    /// before registration assigns one.
    fn label(&self) -> String {
        self.label
            .lock()
            .expect("network label poisoned")
            .clone()
            .unwrap_or_else(|| "unregistered network".to_string())
    }

    fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(NetworkRuntimeState {
                phase: NetworkRuntimePhase::Connecting,
                status_revision: 0,
                recent_failures: std::collections::VecDeque::new(),
                state_changed_at: epoch_millis(),
                attempt_started: std::time::Instant::now(),
                connect_latency_ms: None,
                connection_attempts: 0,
                errors: 0,
                last_error: None,
                last_error_diagnostic: None,
            }),
            label: std::sync::Mutex::new(None),
            attached_clients: std::sync::atomic::AtomicU64::new(0),
            lines_in: std::sync::atomic::AtomicU64::new(0),
            bytes_in: std::sync::atomic::AtomicU64::new(0),
            lines_out: std::sync::atomic::AtomicU64::new(0),
            bytes_out: std::sync::atomic::AtomicU64::new(0),
            last_input_at: std::sync::atomic::AtomicU64::new(0),
            last_output_at: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn begin_attempt(&self) {
        let mut state = self.state.lock().expect("network runtime poisoned");
        state.phase = if state.connection_attempts == 0 {
            NetworkRuntimePhase::Connecting
        } else {
            NetworkRuntimePhase::Reconnecting {
                next_retry_at: None,
            }
        };
        state.connection_attempts = state.connection_attempts.saturating_add(1);
        state.state_changed_at = epoch_millis();
        state.attempt_started = std::time::Instant::now();
    }

    fn is_connected(&self) -> bool {
        let state = self.state.lock().expect("network runtime poisoned");
        matches!(state.phase, NetworkRuntimePhase::Connected { .. })
    }

    /// Record that the network is held stopped by its owner's account
    /// lifecycle. Its driver has stopped, so nothing moves it again.
    fn hold(&self, hold: OwnerHold) {
        let mut state = self.state.lock().expect("network runtime poisoned");
        state.phase = NetworkRuntimePhase::Held(hold);
        state.state_changed_at = epoch_millis();
        state.status_revision = state
            .status_revision
            .checked_add(1)
            .expect("network status revision exhausted");
    }

    fn connected(&self) -> u64 {
        let mut state = self.state.lock().expect("network runtime poisoned");
        if state.connection_attempts == 0 {
            state.connection_attempts = 1;
        }
        let now = epoch_millis();
        state.phase = NetworkRuntimePhase::Connected { connected_at: now };
        state.state_changed_at = now;
        state.connect_latency_ms = Some(
            state
                .attempt_started
                .elapsed()
                .as_millis()
                .min(u64::MAX as u128) as u64,
        );
        state.status_revision = state
            .status_revision
            .checked_add(1)
            .expect("network status revision exhausted");
        state.status_revision
    }

    fn failed(
        &self,
        disposition: FailureDisposition,
        failure: NetworkFailure,
        diagnostic: Option<&str>,
    ) -> u64 {
        let now = epoch_millis();
        let mut state = self.state.lock().expect("network runtime poisoned");
        state.phase = match disposition {
            // The failure and when the next attempt fires are one transition,
            // published under this one lock: a reader must never see a network
            // that is retrying after a failure with no next attempt.
            FailureDisposition::Retry { next_attempt_in } => NetworkRuntimePhase::Reconnecting {
                next_retry_at: next_attempt_in.map(|delay| {
                    e6irc_proto::time::Millis::from_millis(
                        now.as_millis().saturating_add(delay.as_millis() as u64),
                    )
                }),
            },
            FailureDisposition::RegainingNickname => NetworkRuntimePhase::RegainingNickname,
            FailureDisposition::Terminal(lifecycle) => NetworkRuntimePhase::Terminal(lifecycle),
        };
        state.state_changed_at = now;
        Self::set_error(&mut state, now, failure, diagnostic);
        state.status_revision = state
            .status_revision
            .checked_add(1)
            .expect("network status revision exhausted");
        state.status_revision
    }

    fn operational_error(&self, failure: NetworkFailure) {
        let now = epoch_millis();
        let mut state = self.state.lock().expect("network runtime poisoned");
        Self::set_error(&mut state, now, failure, None);
    }

    fn operational_error_with_diagnostic(&self, failure: NetworkFailure, diagnostic: &str) {
        let now = epoch_millis();
        let mut state = self.state.lock().expect("network runtime poisoned");
        Self::set_error(&mut state, now, failure, Some(diagnostic));
    }

    /// Attempts begun so far, the current one included.
    fn connection_attempts(&self) -> u64 {
        self.state
            .lock()
            .expect("network runtime poisoned")
            .connection_attempts
    }

    fn set_error(
        state: &mut NetworkRuntimeState,
        now: e6irc_proto::time::Millis,
        failure: NetworkFailure,
        diagnostic: Option<&str>,
    ) {
        state.errors = state.errors.saturating_add(1);
        let record = FailureRecord { at: now, failure };
        state.last_error = Some(record);
        state.last_error_diagnostic = diagnostic.map(str::to_string);
        state.recent_failures.push_back(record);
        while state.recent_failures.len() > NETWORK_FAILURE_HISTORY_LIMIT {
            state.recent_failures.pop_front();
        }
    }

    fn record_input(&self, bytes: usize) {
        self.lines_in
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.bytes_in
            .fetch_add(bytes as u64, std::sync::atomic::Ordering::Relaxed);
        self.last_input_at.store(
            epoch_millis().as_millis(),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    fn record_output(&self, bytes: usize) {
        self.lines_out
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.bytes_out
            .fetch_add(bytes as u64, std::sync::atomic::Ordering::Relaxed);
        self.last_output_at.store(
            epoch_millis().as_millis(),
            std::sync::atomic::Ordering::Relaxed,
        );
    }
}

fn record_network_error(
    runtime: &NetworkRuntime,
    telemetry: &std::sync::Mutex<Option<std::sync::Arc<crate::observability::Telemetry>>>,
    failure: NetworkFailure,
) {
    runtime.operational_error(failure);
    if let Some(telemetry) = telemetry.lock().expect("telemetry hook poisoned").as_ref() {
        telemetry.record_error(crate::observability::ErrorKind::Bouncer);
    }
}

fn epoch_millis() -> e6irc_proto::time::Millis {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_millis()
        .min(u64::MAX as u128) as u64;
    e6irc_proto::time::Millis::from_millis(millis)
}

fn atomic_millis(value: &std::sync::atomic::AtomicU64) -> Option<e6irc_proto::time::Millis> {
    match value.load(std::sync::atomic::Ordering::Relaxed) {
        0 => None,
        millis => Some(e6irc_proto::time::Millis::from_millis(millis)),
    }
}

/// Counts an attached raw-IRC or web client for exactly the guard's lifetime.
pub struct NetworkAttachment {
    runtime: std::sync::Arc<NetworkRuntime>,
    _telemetry: Option<crate::observability::BncClientConnection>,
}

impl Drop for NetworkAttachment {
    fn drop(&mut self) {
        self.runtime
            .attached_clients
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// A line as the ring holds it: its text and the ring position it occupies.
///
/// The position is what a client hands back to resume: every line pushed to a
/// ring takes the next position, so "everything after position *n*" is exact,
/// whatever the lines say. Event consumers that are not the ring (persistence,
/// raw attaches) read only `line`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferedLine {
    pub seq: u64,
    pub line: String,
}

/// The ring as a reader paging back through one conversation from a cursor
/// sees it: every retained line, oldest first, of which the first
/// `held_after` are at or before the cursor. When `successors_retained`,
/// every line of the conversation after the cursor is still in the ring, so
/// what the reader holds of it after the cursor the ring holds too, and older
/// history can be joined to the conversation's own oldest line in the ring.
/// A conversation's lines leave the ring oldest first, whether from the front
/// or from its share ([`Buffer::evict_one`]), so what the ring holds of it is
/// always its newest lines, none missing between.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingHistory {
    epoch: u64,
    pub lines: Vec<BufferedLine>,
    pub held_after: usize,
    pub successors_retained: bool,
}

impl RingHistory {
    /// The cursor just before the line at `seq`: paging on from it reads the
    /// lines older than that one.
    pub fn cursor_before(&self, seq: u64) -> ReplayCursor {
        ReplayCursor {
            epoch: self.epoch,
            seq: seq.saturating_sub(1),
        }
    }
}

/// What [`NetworkHandle::continue_ring`] did to the positions the driver's
/// lines took before it: each below `below` is `shift` higher now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Renumbered {
    below: u64,
    shift: u64,
}

impl Renumbered {
    /// The position a line announced at `seq` holds now.
    pub(crate) fn now(self, seq: u64) -> u64 {
        if seq < self.below {
            seq + self.shift
        } else {
            seq
        }
    }
}

/// Where a client stopped reading one network's ring: the ring's lifetime and
/// a position in it. Opaque to the client (`<epoch>:<seq>` on the wire), and
/// self-invalidating: a ring that was replaced — the process restarted, the
/// driver rebuilt — has another epoch, and a position the ring has evicted is
/// recognised as gone, so a cursor is either honoured exactly or refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayCursor {
    epoch: u64,
    seq: u64,
}

impl ReplayCursor {
    /// The wire form, or `None` for anything that is not one: the cursor is
    /// opaque and a client presenting something else has nothing to resume.
    pub fn parse(text: &str) -> Option<Self> {
        let (epoch, seq) = text.split_once(':')?;
        Some(Self {
            epoch: epoch.parse().ok()?,
            seq: seq.parse().ok()?,
        })
    }

    /// The ring's epoch and the position, as a session record holds them.
    pub(crate) fn recorded(self) -> (u64, u64) {
        (self.epoch, self.seq)
    }

    /// The cursor a session record held.
    pub(crate) fn from_recorded((epoch, seq): (u64, u64)) -> Self {
        Self { epoch, seq }
    }
}

impl std::fmt::Display for ReplayCursor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}:{}", self.epoch, self.seq)
    }
}

/// One exact attach boundary (see
/// [`NetworkHandle::subscribe_with_replay_snapshot`]): the live receiver, the
/// replay before it, and the session state and upstream features as of that
/// same instant — and the attachment's place in `attached_clients`, taken at
/// that instant too, so a client counted as attached is always one that
/// receives every line published after the count saw it.
pub(crate) struct AttachSnapshot {
    pub attachment: NetworkAttachment,
    pub events: tokio::sync::broadcast::Receiver<DriverEvent>,
    pub replay: Replay,
    pub session: Option<IrcSessionSnapshot>,
    pub features: UpstreamFeatures,
    pub names: e6irc_client::NetworkNames,
    /// The session's state at the oldest replayed line ([`Buffer::head`]),
    /// when it is known.
    head: Option<IrcSessionState>,
    /// The session's state now, with each channel's topic and members.
    current: IrcSessionState,
}

/// What an attach replays: the lines, where the ring stands after them, and
/// whether a presented cursor was honoured (only the lines after it) or the
/// whole ring was replayed instead.
#[derive(Debug)]
pub struct Replay {
    pub lines: Vec<BufferedLine>,
    /// Where upstream sessions began among `lines`: each boundary sits before
    /// the line at its index (`lines.len()` for one after the last line), with
    /// the session's state as it began. A client that reads the lines as a
    /// transcript may ignore them; one that tracks membership from them
    /// reconciles to each, as a live client did when it happened.
    pub boundaries: Vec<(usize, IrcSessionSnapshot)>,
    epoch: u64,
    position: u64,
    pub resumed: bool,
}

impl Replay {
    /// The cursor naming ring position `seq`, for a live line of this ring.
    pub fn cursor_at(&self, seq: u64) -> ReplayCursor {
        ReplayCursor {
            epoch: self.epoch,
            seq,
        }
    }

    /// The cursor naming the ring position after every replayed line.
    pub fn position(&self) -> ReplayCursor {
        self.cursor_at(self.position)
    }
}

/// Which share of a ring a line is held in. A network's lines share one ring,
/// and a busy channel used to evict, oldest first, the private message and the
/// quiet channel's conversation the owner had not read yet. Each conversation
/// now holds a share of its own, and the ring makes room from the largest
/// ([`Buffer::evict_one`]), so a conversation keeps its newest lines for as
/// long as another holds more; the network's cap and bytes still bound the
/// whole. Storage keeps the same shares ([`crate::db::trim_bnc_buffer`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Share {
    /// A message of one conversation, by its folded name (a channel, or the
    /// other party of a private conversation): the conversation storage
    /// files it under (`crate::db::bnc_line_target`).
    Conversation(String),
    /// Everything else that is not the session's own: others' membership, a
    /// numeric, the bouncer's notices.
    Other,
    /// The session's own `NICK`, `JOIN`, `PART`, `QUIT`, a `KICK` of it, and
    /// where a session began: what the ring's head state follows, so they go
    /// only from the front, oldest first, as the head advances past them.
    Pinned,
}

impl Share {
    /// The share of `line`, said while the session's own nick was `own`.
    fn of(line: &str, own: Option<&str>, names: &e6irc_client::NetworkNames) -> Self {
        if let Some(target) = crate::db::bnc_line_target(line, own, names) {
            return Self::Conversation(names.fold(&target));
        }
        let (Ok(message), Some(own)) = (e6irc_proto::message::Message::parse(line), own) else {
            return Self::Other;
        };
        let ours = message
            .source
            .as_ref()
            .is_some_and(|source| names.eq(source.name, own));
        let pinned = match message.command.to_ascii_uppercase().as_str() {
            "NICK" | "JOIN" | "PART" | "QUIT" => ours,
            "KICK" => message
                .params
                .get(1)
                .is_some_and(|kicked| kicked.split(',').any(|kicked| names.eq(kicked, own))),
            _ => false,
        };
        if pinned { Self::Pinned } else { Self::Other }
    }
}

/// One ring position: a line in its share, or where a new upstream session
/// began.
#[derive(Debug, Clone)]
enum RingEntry {
    Line(BufferedLine, Share),
    Session {
        seq: u64,
        snapshot: IrcSessionSnapshot,
    },
}

impl RingEntry {
    fn seq(&self) -> u64 {
        match self {
            Self::Line(line, _) => line.seq,
            Self::Session { seq, .. } => *seq,
        }
    }

    fn line(&self) -> Option<&BufferedLine> {
        match self {
            Self::Line(line, _) => Some(line),
            Self::Session { .. } => None,
        }
    }
}

/// The bytes a network's backlog may hold per line of its `buffer_cap`: a full
/// 512-byte IRC line (RFC 1459's limit on a line without tags). A backlog of
/// `buffer_cap` ordinary lines is held whole; one whose upstream sends
/// kilobytes of tags with every line keeps fewer of them, never more than
/// `buffer_cap` × 512 bytes. The same rate bounds the stored backlog
/// (`crate::db::BNC_BUFFER_BYTES`).
pub(crate) const BACKLOG_BYTES_PER_LINE: usize = e6irc_proto::message::MAX_LINE_LEN;

/// Bounded ring of recent upstream lines, for playback on attach: at most
/// `cap` positions and `byte_cap` bytes of lines, room made from the largest
/// conversation's oldest line first ([`Share`]), and none older than history
/// retention keeps.
pub struct Buffer {
    entries: std::collections::VecDeque<RingEntry>,
    cap: usize,
    /// `cap` lines of [`BACKLOG_BYTES_PER_LINE`].
    byte_cap: usize,
    /// The bytes of the lines held.
    bytes: usize,
    /// How many lines each share holds.
    shares: std::collections::HashMap<Share, usize>,
    /// The newest position the ring has let go of: a cursor at or past it has
    /// every successor still held.
    evicted_through: u64,
    /// The newest position each share has let go of, from the front or from
    /// its middle: its lines go oldest first, so every line of the share
    /// after it is still held.
    let_go: std::collections::HashMap<Share, u64>,
    /// The newest position a share may have let go of that the ring cannot
    /// name the share of: what storage let go of before a continued ring
    /// restored the rest (migration 0103).
    let_go_floor: u64,
    /// Identifies this ring's lifetime; part of every cursor it hands out.
    /// A ring continuing a stored one takes its epoch
    /// ([`NetworkHandle::continue_ring`]).
    epoch: u64,
    /// The position the next pushed line takes. Starts above `cap` so the
    /// lines `preload_front` restores from storage — older than anything
    /// pushed, at most `cap` of them — take positions that stay positive.
    next_seq: u64,
    /// The position the first pushed line took: where the lines pushed
    /// before a restore begin.
    first_seq: u64,
    /// How long history is kept: storage maintenance deletes older lines from
    /// `bnc_buffer`, and this ring neither keeps nor replays them either.
    retention: crate::core::HistoryRetention,
    /// The session's state as of the oldest entry held — its nick and
    /// channels — advanced by every entry the ring evicts from its front, so
    /// an attaching client is brought to it before the replay begins and
    /// reads each replayed line in the state it was said in (§10.1). What the
    /// ring lets go of elsewhere ([`Buffer::evict_one`]) changes none of it.
    /// `None` while the oldest lines are ones restored from rows stored
    /// before migration 0096, whose nick was not stored with them
    /// ([`restored_head`]).
    head: Option<IrcSessionState>,
    /// How the network names things and what it said of itself, which the
    /// head reads its lines with.
    names: e6irc_client::NetworkNames,
    features: UpstreamFeatures,
}

impl Buffer {
    fn new(cap: usize) -> Self {
        // Distinct for every ring this process creates, and for every process:
        // the clock keeps rings of successive processes apart, the counter
        // keeps rings created in the same millisecond apart.
        static RING_EPOCHS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let ordinal = RING_EPOCHS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let epoch = (epoch_millis().as_millis() << 16) | (ordinal & 0xffff);
        Self {
            entries: std::collections::VecDeque::new(),
            cap,
            byte_cap: cap.max(1).saturating_mul(BACKLOG_BYTES_PER_LINE),
            bytes: 0,
            shares: std::collections::HashMap::new(),
            evicted_through: 0,
            let_go: std::collections::HashMap::new(),
            let_go_floor: 0,
            epoch,
            next_seq: cap as u64 + 1,
            first_seq: cap as u64 + 1,
            retention: crate::core::HistoryRetention::default(),
            head: Some(IrcSessionState::default()),
            names: e6irc_client::NetworkNames::default(),
            features: UpstreamFeatures::default(),
        }
    }

    /// Read what the head advances through as the network names things now.
    fn adopt(&mut self, names: &e6irc_client::NetworkNames, features: &UpstreamFeatures) {
        self.names = names.clone();
        self.features = features.clone();
        if let Some(head) = &mut self.head {
            head.adopt(names, features);
        }
    }

    /// The oldest time history retention keeps now, if it keeps any less
    /// than everything.
    fn cutoff(&self) -> Option<e6irc_proto::time::Millis> {
        self.retention.cutoff(epoch_millis())
    }

    /// Whether `line` is kept under `cutoff`: its `time` (every retained line
    /// carries one, see [`ingest`]) is no older. Read only when there is a
    /// cutoff, so a ring with none parses nothing.
    fn keeps(line: &BufferedLine, cutoff: Option<e6irc_proto::time::Millis>) -> bool {
        cutoff.is_none_or(|cutoff| line_time(&line.line).is_none_or(|time| time >= cutoff))
    }

    /// Drop the lines at the front that history retention no longer keeps.
    fn evict_expired(&mut self) {
        let cutoff = self.cutoff();
        while let Some(RingEntry::Line(line, _)) = self.entries.front() {
            if Self::keeps(line, cutoff) {
                break;
            }
            self.evict_oldest();
        }
    }

    /// Account for a line leaving the ring.
    fn forget(&mut self, line: &BufferedLine, share: &Share) {
        self.bytes -= line.line.len();
        self.evicted_through = self.evicted_through.max(line.seq);
        let let_go = self.let_go.entry(share.clone()).or_default();
        *let_go = (*let_go).max(line.seq);
        if let Some(held) = self.shares.get_mut(share) {
            *held -= 1;
            if *held == 0 {
                self.shares.remove(share);
            }
        }
    }

    /// Drop the oldest entry, advancing the head state past it.
    fn evict_oldest(&mut self) {
        match self.entries.pop_front() {
            Some(RingEntry::Line(line, share)) => {
                self.forget(&line, &share);
                if let Some(head) = &mut self.head {
                    // Every line held was published within the channel
                    // bound, so none takes the head past it.
                    drop(head.observe(&line.line));
                }
            }
            Some(RingEntry::Session { seq, snapshot }) => {
                self.evicted_through = self.evicted_through.max(seq);
                self.head = Some(IrcSessionState::at(
                    &snapshot,
                    self.names.clone(),
                    self.features.clone(),
                ));
            }
            None => {}
        }
    }

    /// Make room for one more. The session's own lines and session
    /// boundaries at the front go first: the head takes them in, and an
    /// attaching client is brought to the state they made all the same.
    /// Otherwise the oldest line of the share that holds the most (the oldest
    /// such share's, among equals) goes, wherever it is in the ring — never
    /// the newest line, and never a pinned one but from the front; with no
    /// share holding more than one line, the oldest entry goes.
    fn evict_one(&mut self) {
        if matches!(
            self.entries.front(),
            Some(RingEntry::Session { .. } | RingEntry::Line(_, Share::Pinned))
        ) {
            self.evict_oldest();
            return;
        }
        let largest = self
            .shares
            .iter()
            .filter(|(share, _)| **share != Share::Pinned)
            .map(|(_, held)| *held)
            .max()
            .unwrap_or(0);
        let newest = self.entries.len().saturating_sub(1);
        let victim = (largest > 1)
            .then(|| {
                self.entries.iter().position(|entry| {
                    matches!(entry, RingEntry::Line(_, share)
                        if *share != Share::Pinned && self.shares.get(share) == Some(&largest))
                })
            })
            .flatten()
            .filter(|index| *index > 0 && *index < newest);
        match victim.and_then(|index| self.entries.remove(index)) {
            Some(RingEntry::Line(line, share)) => self.forget(&line, &share),
            Some(RingEntry::Session { .. }) => unreachable!("only a line is chosen"),
            None => self.evict_oldest(),
        }
    }

    /// Take the next position, making room when full.
    fn next_position(&mut self) -> u64 {
        // `>=` (not `==`) so a zero/under-filled cap can never let the ring
        // grow without bound.
        while self.entries.len() >= self.cap.max(1) {
            self.evict_one();
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        seq
    }

    /// Retain `line` as the newest, returning the position it took. Room is
    /// made while the lines held pass `byte_cap` — never from this one, so a
    /// ring always holds its newest line.
    #[cfg(test)]
    fn push(&mut self, line: String) -> u64 {
        self.push_said(line, None)
    }

    /// [`Buffer::push`] of a line said while the session's own nick was
    /// `own`, which decides its [`Share`].
    fn push_said(&mut self, line: String, own: Option<&str>) -> u64 {
        self.evict_expired();
        let share = Share::of(&line, own, &self.names);
        let seq = self.next_position();
        self.bytes += line.len();
        *self.shares.entry(share.clone()).or_default() += 1;
        self.entries
            .push_back(RingEntry::Line(BufferedLine { seq, line }, share));
        while self.bytes > self.byte_cap && self.entries.len() > 1 {
            self.evict_one();
        }
        seq
    }

    /// Retain where a new upstream session began, in the state it began in.
    fn push_session(&mut self, snapshot: IrcSessionSnapshot) {
        let seq = self.next_position();
        self.entries.push_back(RingEntry::Session { seq, snapshot });
    }

    /// The lines held that history retention still keeps.
    fn lines(&self) -> impl Iterator<Item = &BufferedLine> {
        let cutoff = self.cutoff();
        self.entries
            .iter()
            .filter_map(RingEntry::line)
            .filter(move |line| Self::keeps(line, cutoff))
    }

    /// The position of the newest line (or of the ring's start, when empty):
    /// what a live-only event that enters no ring reports as its cursor.
    fn position(&self) -> u64 {
        self.next_seq - 1
    }

    pub fn snapshot(&self) -> Vec<String> {
        self.lines().map(|entry| entry.line.clone()).collect()
    }

    /// The retained lines at or before `through`, when that cursor names a
    /// position of this ring; `None` for another ring's cursor, whose
    /// positions mean nothing here. A position the ring has since evicted
    /// past is honoured: no line at or before it is retained any more.
    fn lines_through(&self, through: ReplayCursor) -> Option<Vec<String>> {
        if through.epoch != self.epoch || through.seq >= self.next_seq {
            return None;
        }
        Some(
            self.lines()
                .take_while(|entry| entry.seq <= through.seq)
                .map(|entry| entry.line.clone())
                .collect(),
        )
    }

    /// Every retained line with its position, as of one instant, and how many
    /// of them are at or before `through`; `None` for another ring's cursor,
    /// or a position the ring has not reached. See [`RingHistory`].
    fn history_through(&self, through: ReplayCursor, conversation: &str) -> Option<RingHistory> {
        if through.epoch != self.epoch || through.seq >= self.next_seq {
            return None;
        }
        let lines: Vec<BufferedLine> = self.lines().cloned().collect();
        let held_after = lines.partition_point(|line| line.seq <= through.seq);
        // Nothing of the conversation after the cursor was let go of: not
        // from its share, nor before what a restore could name the share of,
        // nor by history retention, which lets go of the oldest lines and
        // so of everything at or before the newest it expired.
        let share = Share::Conversation(conversation.to_string());
        let cutoff = self.cutoff();
        let expired = self
            .entries
            .iter()
            .filter_map(|entry| match entry {
                RingEntry::Line(line, held) if *held == share && !Self::keeps(line, cutoff) => {
                    Some(line.seq)
                }
                _ => None,
            })
            .max()
            .unwrap_or(0);
        let let_go = self
            .let_go
            .get(&share)
            .copied()
            .unwrap_or(0)
            .max(self.let_go_floor)
            .max(expired);
        let successors_retained = through.seq >= let_go;
        Some(RingHistory {
            epoch: self.epoch,
            lines,
            held_after,
            successors_retained,
        })
    }

    /// The lines after `after`, when that cursor names a position of this ring
    /// whose every successor is still retained — none was let go of after it,
    /// from the front or from a share ([`Buffer::evict_one`]); otherwise the
    /// whole ring, with `resumed` false so the client knows to start its
    /// transcript over.
    fn replay_after(&self, after: Option<ReplayCursor>) -> Replay {
        let honoured = after.is_some_and(|cursor| {
            cursor.epoch == self.epoch
                && cursor.seq < self.next_seq
                && cursor.seq >= self.evicted_through
                && self
                    .entries
                    .front()
                    .is_none_or(|oldest| cursor.seq + 1 >= oldest.seq())
        });
        let from = after
            .filter(|_| honoured)
            .map_or(0, |cursor| cursor.seq + 1);
        let mut lines = Vec::new();
        let mut boundaries = Vec::new();
        let cutoff = self.cutoff();
        for entry in self.entries.iter().filter(|entry| entry.seq() >= from) {
            match entry {
                RingEntry::Line(line, _) if !Self::keeps(line, cutoff) => {}
                RingEntry::Line(line, _) => lines.push(line.clone()),
                RingEntry::Session { snapshot, .. } => {
                    boundaries.push((lines.len(), snapshot.clone()));
                }
            }
        }
        Replay {
            lines,
            boundaries,
            epoch: self.epoch,
            position: self.position(),
            resumed: honoured,
        }
    }
}

/// The session's state as of the oldest of the restored lines, from the own
/// nicks they were stored with, oldest first: the nick of the first line said
/// under one. The lines before it were said before the session had a nick —
/// the bouncer's own notices before the upstream welcomed it — which no nick
/// changes, so an attach brought to that nick before them reads each line as
/// it was said. A line stored before migration 0096 recorded no nick, so a
/// restore that begins in such lines knows no state (`None`) and its replay
/// starts at the current nick. The channels are not stored: the head joins
/// none, and learns each from the lines it evicts, as the in-memory head does
/// from its own.
fn restored_head<'a>(
    own_nicks: impl Iterator<Item = &'a crate::db::StoredOwnNick>,
    names: e6irc_client::NetworkNames,
    features: UpstreamFeatures,
) -> Option<IrcSessionState> {
    use crate::db::StoredOwnNick;
    let mut head = IrcSessionState {
        names,
        features,
        ..IrcSessionState::default()
    };
    for own_nick in own_nicks {
        match own_nick {
            StoredOwnNick::NotRecorded => return None,
            StoredOwnNick::NoNick => {}
            StoredOwnNick::Nick(nick) => {
                head.nick = Some(nick.clone());
                break;
            }
        }
    }
    Some(head)
}

/// How many reply lines one attachment may have waiting: a `/LIST` of a large
/// network is tens of thousands, sent faster than a slow client reads. Past
/// this the rest of that reply is dropped for that client alone, and it is
/// told how much; nothing else — no other client, no history — waits on it.
const REPLY_ROUTE_CAPACITY: usize = 1024;

/// Where each attachment receives the replies to its own commands.
#[derive(Clone, Default)]
struct ReplyRoutes(std::sync::Arc<std::sync::Mutex<std::collections::HashMap<u64, ReplySink>>>);

struct ReplySink {
    sender: mpsc::Sender<String>,
    /// Replies that did not fit, since the attachment last read one.
    dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl ReplyRoutes {
    fn deliver(&self, origin: u64, line: String) {
        let routes = self.0.lock().expect("reply routes poisoned");
        let Some(sink) = routes.get(&origin) else {
            return;
        };
        if let Err(mpsc::error::TrySendError::Full(_)) = sink.sender.try_send(line) {
            sink.dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// One attachment's end of its replies (see [`NetworkHandle::route_replies`]).
pub struct ReplyRoute {
    id: u64,
    receiver: mpsc::Receiver<String>,
    dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
    routes: ReplyRoutes,
}

impl ReplyRoute {
    /// The next reply line for this attachment. Once the lines that fitted
    /// have been read, the next call says how many after them were lost.
    pub async fn recv(&mut self) -> String {
        if let Ok(line) = self.receiver.try_recv() {
            return line;
        }
        let lost = self.dropped.swap(0, std::sync::atomic::Ordering::Relaxed);
        if lost > 0 {
            return format!(
                ":*bnc* NOTICE * :{lost} line(s) of a reply to your command were dropped: \
                 this client read them more slowly than the network sent them"
            );
        }
        match self.receiver.recv().await {
            Some(line) => line,
            // The sender lives as long as this route is registered, which is
            // as long as this value.
            None => std::future::pending().await,
        }
    }
}

impl Drop for ReplyRoute {
    fn drop(&mut self) {
        self.routes
            .0
            .lock()
            .expect("reply routes poisoned")
            .remove(&self.id);
    }
}

/// A client's line as a network is to be sent it, or `None` when the bouncer
/// answered it instead. A network that does not carry client-only tags
/// (an IRC upstream without `message-tags`, see [`ClientTags`]) would lose
/// them anyway, or — a server that does not parse tags — read the line as an
/// unknown command named after its tag section, so they are stripped, as the
/// `CLIENTTAGDENY=*` attached clients were told promises; and a `TAGMSG`,
/// which is nothing but tags, is answered here, to its sender alone, rather
/// than refused by the network in front of every attached client. The echo of
/// what is sent is made from the returned line, so it never shows a tag the
/// network did not carry. A `NAMES`, `MODE` or `TOPIC` of a channel the
/// session follows is answered from what it follows, as soju and ZNC answer
/// them ([`DriverEnds::answered_by_session`]): clients ask them of every
/// channel on each connect, and each question would otherwise be a line of
/// the upstream's flood allowance.
pub(super) fn carriable(
    cmd: &ClientCommand,
    client_tags: ClientTags,
    ends: &DriverEnds,
) -> Option<String> {
    if let Some(answer) = ends.answered_by_session(&cmd.line) {
        for line in answer {
            ends.answer(cmd.origin, line);
        }
        return None;
    }
    if client_tags == ClientTags::Relayed {
        return Some(cmd.line.clone());
    }
    let Ok(message) = e6irc_proto::message::Message::parse(&cmd.line) else {
        return Some(cmd.line.clone());
    };
    if message.command.eq_ignore_ascii_case("TAGMSG") {
        let target = message.params.first().copied().unwrap_or("*");
        ends.answer(
            cmd.origin,
            crate::core::fail_line(
                "*bnc*",
                "TAGMSG",
                "CLIENT_TAGS_UNSUPPORTED",
                &[target],
                "the network does not carry message tags (CLIENTTAGDENY=*); nothing was sent",
            ),
        );
        return None;
    }
    Some(without_tags(&cmd.line))
}

/// `line` without its tag section.
fn without_tags(line: &str) -> String {
    match line.strip_prefix('@') {
        Some(tagged) => tagged
            .split_once(' ')
            .map_or_else(String::new, |(_, body)| body.trim_start().to_string()),
        None => line.to_string(),
    }
}

/// The nick `line` renames the session to, when it is the `NICK` of the
/// session whose nick is `own`.
fn own_rename(line: &str, own: &str, names: &e6irc_client::NetworkNames) -> Option<String> {
    let message = e6irc_proto::message::Message::parse(line).ok()?;
    let source = message.source.as_ref()?;
    (message.command.eq_ignore_ascii_case("NICK") && names.eq(source.name, own))
        .then(|| message.params.first().map(|nick| (*nick).to_string()))
        .flatten()
}

/// The UTC date of `at`, `YYYY-MM-DD`.
fn utc_date(at: e6irc_proto::time::Millis) -> String {
    e6irc_proto::time::server_time(at)[..10].to_string()
}

/// A replayed message for a client that did not negotiate `server-time`, with
/// the time it was said (its `time`, which every retained line carries) at
/// the head of its text, as ZNC replays a buffer to such a client:
/// `[HH:MM:SS]` in UTC, with the date as well when it was not said `today`,
/// and after `ACTION ` for a `/me`. Anything else — membership, a numeric, a
/// CTCP reply, a line with no valid `time` — is replayed as it is. The text is
/// cut to fit the line, never sent past it.
fn replayed_with_its_time<'line>(line: &'line str, today: &str) -> std::borrow::Cow<'line, str> {
    use std::borrow::Cow;
    let Ok(parsed) = e6irc_proto::message::Message::parse(line) else {
        return Cow::Borrowed(line);
    };
    let command = parsed.command.to_ascii_uppercase();
    let (true, [target, text]) = (
        matches!(command.as_str(), "PRIVMSG" | "NOTICE"),
        parsed.params.as_slice(),
    ) else {
        return Cow::Borrowed(line);
    };
    let Some(said) = line_time(line) else {
        return Cow::Borrowed(line);
    };
    let stamp = e6irc_proto::time::server_time(said);
    let stamp = if stamp[..10] == *today {
        format!("[{}]", &stamp[11..19])
    } else {
        format!("[{} {}]", &stamp[..10], &stamp[11..19])
    };
    let text = match crate::sanitize::ctcp_action(text) {
        Some(action) => format!("\u{1}ACTION {stamp} {action}\u{1}"),
        None if text.starts_with('\u{1}') => return Cow::Borrowed(line),
        None => format!("{stamp} {text}"),
    };
    let tags = line
        .strip_prefix('@')
        .and_then(|rest| rest.split_once(' '))
        .map(|(tags, _)| format!("@{tags} "))
        .unwrap_or_default();
    let source = e6irc_client::OwnedMessage::from(&parsed)
        .source
        .map(|source| format!(":{source} "))
        .unwrap_or_default();
    // The wire's 512 bytes bound the line without its tags.
    let head = format!("{source}{command} {target} :");
    Cow::Owned(format!(
        "{tags}{head}{}",
        crate::core::fit_trailing(&head, &text)
    ))
}

/// Why a line sent to a network that has no session was not sent.
pub(crate) const NOT_CONNECTED: &str =
    "the network is not connected (it is connecting or reconnecting)";

/// What the sender of `line` is told when it was never sent, and `why`: by
/// its command and target, as ZNC's "Your message to #chan got lost" names
/// them.
pub(crate) fn unsent_notice(line: &str, why: &str) -> String {
    let what = match e6irc_proto::message::Message::parse(line) {
        Ok(message) => {
            let command = message.command.to_ascii_uppercase();
            match (command.as_str(), message.params.first()) {
                ("PRIVMSG" | "NOTICE" | "TAGMSG", Some(target)) => {
                    format!("your message to {target}")
                }
                (_, Some(target)) => format!("your {command} {target}"),
                (_, None) => format!("your {command}"),
            }
        }
        Err(_) => "a line you sent".to_string(),
    };
    bnc_notice("*", &format!("{what} was not sent: {why}"))
}

/// A `*bnc*` NOTICE to `target` (`*`, or a channel), its text fitted to the
/// line. The bouncer's own notices carry upstream text — a closing reason, a
/// SASL refusal, a channel name, a bridge's room id — bounded in characters,
/// not in bytes, so a `format!`ed notice could outgrow the line and then be
/// replaced whole by [`ingest`]'s rejection: the notice that exists to say
/// what happened would say nothing. Every such notice is built here.
pub(crate) fn bnc_notice(target: &str, text: &str) -> String {
    crate::core::server_notice("*bnc*", MiddleParam::echo(target).as_str(), text)
}

/// Take one line into the bouncer: neutralized (see
/// [`crate::sanitize::upstream_line`]) and stamped with the time it arrived
/// when it carries no valid `time` of its own, so the ring, the stored backlog
/// and CHATHISTORY all read one time for it, whatever the upstream offers.
fn ingest(line: String) -> String {
    let now = e6irc_proto::time::server_time(epoch_millis());
    stamp_time(crate::sanitize::upstream_line(line), &now)
}

/// The time `line`'s `time` tag names, if it carries a valid one.
fn line_time(line: &str) -> Option<e6irc_proto::time::Millis> {
    e6irc_proto::message::Message::parse(line)
        .ok()?
        .tag("time")?
        .value
        .as_deref()
        .and_then(e6irc_proto::time::parse_server_time_millis)
}

/// `line` with `time` as its `time` tag, unless it carries a valid one.
fn stamp_time(line: String, time: &str) -> String {
    let Ok(message) = e6irc_proto::message::Message::parse(&line) else {
        return line;
    };
    let valid = message
        .tag("time")
        .and_then(|tag| tag.value.as_deref())
        .and_then(e6irc_proto::time::parse_server_time_millis)
        .is_some();
    if valid {
        return line;
    }
    let untimed = without_tag(&line, "time");
    let stamped = match untimed.strip_prefix('@') {
        Some(rest) => format!("@time={time};{rest}"),
        None => format!("@time={time} {untimed}"),
    };
    // A tag section the upstream filled to its budget has no room for one
    // more tag; such a line keeps what it came with.
    if e6irc_proto::message::server_frame_fits(stamped.as_bytes()) {
        stamped
    } else {
        line
    }
}

/// `line` without any `key` tag.
pub(crate) fn without_tag(line: &str, key: &str) -> String {
    let Some(rest) = line.strip_prefix('@') else {
        return line.to_string();
    };
    let Some((tags, body)) = rest.split_once(' ') else {
        return String::new();
    };
    let kept: Vec<&str> = tags
        .split(';')
        .filter(|tag| tag.split('=').next() != Some(key))
        .collect();
    if kept.is_empty() {
        body.to_string()
    } else {
        format!("@{} {body}", kept.join(";"))
    }
}

/// Numerics that say whether a watched nick is online (`MONITOR`'s 730 and
/// 731, `WATCH`'s 600, 601, 604 and 605): presence as it is when they are
/// said.
const PRESENCE_NUMERICS: &[u16] = &[600, 601, 604, 605, 730, 731];

/// Whether a line published to a network is told live only: to whoever is
/// attached now, at the ring's position, and never retained in the ring, the
/// stored backlog or CHATHISTORY. The one rule every way into and out of the
/// backlog reads (publishing a line or an echo, persisting it, restoring it).
///
/// - A `TAGMSG` history keeps nothing of (a typing indicator): a moment, not
///   conversation.
/// - A CTCP request (`\x01VERSION\x01`, `\x01PING …\x01`, a direct
///   file-transfer offer): a question to the clients attached when it was
///   asked. Replayed, every
///   client that attached later answered it again — hours after it was asked,
///   once per attach — as neither ZNC nor soju ever does.
/// - A channel's state as the numerics that follow our own `JOIN` state it
///   ([`replies::JOIN_BURST`]: its modes, topic and member list): what the
///   session follows, which an attaching client is told from the session
///   itself (§10.1). Retained,
///   the member lists that follow every rejoin after a reconnect — hundreds of
///   lines on a heavy user's channels — evicted the conversation the backlog
///   exists to keep, and a replay showed a member list long out of date.
/// - A watched nick's presence ([`PRESENCE_NUMERICS`]): replayed, a client
///   was told a nick that left hours ago is online.
pub(crate) fn told_live_only(line: &str) -> bool {
    let Ok(message) = e6irc_proto::message::Message::parse(line) else {
        return false;
    };
    match message.command.to_ascii_uppercase().as_str() {
        "TAGMSG" => crate::sanitize::is_ephemeral_tagmsg(line),
        "PRIVMSG" => message
            .params
            .get(1)
            .is_some_and(|text| crate::sanitize::is_ctcp_request(text)),
        command => {
            command.len() == 3
                && command.parse::<u16>().is_ok_and(|code| {
                    replies::JOIN_BURST.contains(&code) || PRESENCE_NUMERICS.contains(&code)
                })
        }
    }
}

/// Whether `line` is part of a network's registration burst.
fn is_registration_burst_line(line: &str) -> bool {
    e6irc_proto::message::Message::parse(line)
        .is_ok_and(|message| REGISTRATION_BURST.contains(&message.command))
}

/// A 005 after the registration burst, as an attached client is told it:
/// `None` for any other line, `Some(None)` when nothing is left once the
/// tokens the bouncer answers for itself are removed.
fn live_isupport(line: &str, client_tags: ClientTags) -> Option<Option<String>> {
    let message = e6irc_proto::message::Message::parse(line).ok()?;
    if message.command != "005" || message.params.len() < 3 {
        return None;
    }
    let tokens: Vec<&str> = message.params[1..message.params.len() - 1]
        .iter()
        .copied()
        .filter(|token| {
            let key = isupport_key(token);
            !BOUNCER_OWNED_ISUPPORT.contains(&key)
                || (key == "CLIENTTAGDENY" && client_tags == ClientTags::Relayed)
        })
        .collect();
    if tokens.is_empty() {
        return Some(None);
    }
    let source = message.source.as_ref().map_or_else(String::new, |source| {
        let user = source
            .user
            .map_or_else(String::new, |user| format!("!{user}"));
        let host = source
            .host
            .map_or_else(String::new, |host| format!("@{host}"));
        format!(":{}{user}{host} ", source.name)
    });
    let time = message
        .tag("time")
        .and_then(|tag| tag.value.as_deref())
        .map_or_else(String::new, |time| format!("@time={time} "));
    Some(Some(format!(
        "{time}{source}005 {} {} :{}",
        message.params[0],
        tokens.join(" "),
        message.params[message.params.len() - 1]
    )))
}

/// A `*bnc*` NOTICE telling the client its message was not delivered, because
/// `target` is not a bridged channel on `platform`.
///
/// The point of this notice is that a drop is never silent, so the notice must
/// itself arrive: `target` comes from the client's own line and is bounded only
/// by the frame limit, which is several times the 512 bytes an IRC line gets.
/// Interpolated whole — twice — it produced a line the receiving client's
/// framing discards, and the silence came back. It is truncated to fit.
#[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
pub(crate) fn unmapped_target_notice(platform: &str, kind: &str, target: &str) -> String {
    let shown = MiddleParam::echo(target);
    bnc_notice(
        shown.as_str(),
        &format!("not delivered: no bridged {platform} {kind} for {shown}"),
    )
}

/// A `*bnc*` NOTICE telling the client its message reached a bridged target but
/// the upstream send failed. Same discipline as [`unmapped_target_notice`]: the
/// `target` may be a homeserver-supplied room id (Matrix) bounded only by the
/// frame limit, so it is truncated to a char boundary — an over-long line is
/// discarded whole by the client's framing, and then the failure goes silent,
/// the very outcome this notice exists to prevent.
#[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
pub(crate) fn undelivered_notice(platform: &str, kind: &str, target: &str) -> String {
    let shown = e6irc_proto::message::truncate_on_char_boundary(target, 64);
    bnc_notice(
        "*",
        &format!("not delivered: {platform} send to {kind} {shown} failed"),
    )
}

/// A `*bnc*` NOTICE telling the client its message was not delivered because
/// the provider rate-limited it past what a delivery waits out; bounded like
/// [`undelivered_notice`].
#[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
pub(crate) fn rate_limited_notice(
    platform: &str,
    kind: &str,
    target: &str,
    retry_after: std::time::Duration,
) -> String {
    let shown = e6irc_proto::message::truncate_on_char_boundary(target, 64);
    bnc_notice(
        "*",
        &format!(
            "not delivered: {platform} rate-limited sends to {kind} {shown} (it asked for {}s)",
            retry_after.as_secs_f64().ceil()
        ),
    )
}

#[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
fn rejected_bridge_command_notice(platform: &str, rejection: BridgeCommandRejection) -> String {
    let reason = match rejection {
        BridgeCommandRejection::MalformedMessage => "malformed PRIVMSG",
        BridgeCommandRejection::UnsupportedCommand => "the bridge supports PRIVMSG only",
        BridgeCommandRejection::UnsupportedCtcp => {
            "the bridge relays CTCP ACTION only; nothing there can answer another CTCP"
        }
    };
    format!(":*bnc* NOTICE * :not delivered to {platform}: {reason}")
}

/// The most IRC lines one bridged message is shown in. Remote text is free
/// form and long — a Matrix event runs to 64 KiB, a Slack message to 40,000
/// characters, a Discord one to 4,000, and each newline in it is a line of its
/// own — while every line lands on each attached client and in the backlog. A
/// message of two thousand newlines used to overflow the network's event
/// broadcast by itself: every attached client was detached as too slow and
/// the backlog lost the lines. Sixteen lines of up to ~450 bytes each is some
/// 7 kilobytes — a long paste still reads, and one message is a small part of what
/// the broadcast holds ([`BRIDGE_PACING_HIGH_WATER`] is 512 lines).
#[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
pub(crate) const MAX_BRIDGED_LINES: usize = 16;

/// The IRC lines one bridged message is shown as: at most
/// [`MAX_BRIDGED_LINES`] of it, then — when there was more — one `*bnc*`
/// notice saying how many lines were not shown. Built only by
/// [`render_bridged`] and [`BridgedLines::notice`], so what a driver relays for
/// one message is bounded by construction.
#[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
#[derive(Debug)]
pub(crate) struct BridgedLines(Vec<String>);

#[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
impl BridgedLines {
    /// A message shown as one notice (one the bridge cannot show, say).
    pub(crate) fn notice(line: String) -> Self {
        Self(vec![line])
    }
}

#[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
impl IntoIterator for BridgedLines {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// `line` cut into pieces of at most `budget` bytes, on character boundaries;
/// a character wider than the budget is a piece of its own.
#[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
fn pieces_within(line: &str, budget: usize) -> impl Iterator<Item = &str> {
    let mut rest = line;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let mut cut = budget.min(rest.len());
        while cut > 0 && !rest.is_char_boundary(cut) {
            cut -= 1;
        }
        if cut == 0 {
            cut = rest.char_indices().nth(1).map_or(rest.len(), |(i, _)| i);
        }
        let (piece, after) = rest.split_at(cut);
        rest = after;
        Some(piece)
    })
}

/// Render a bridged message as IRC lines — `PRIVMSG`, a CTCP `ACTION`, or a
/// `NOTICE`, as the [`Inbound`] says: the sender is shown as `who` (from the
/// session's [`BridgedSenders`]).
///
/// Each line of the body is a line on IRC: they are line breaks in the source
/// medium, and [`crate::sanitize::upstream_line`] flattens a newline to a space
/// further down, which would turn a multi-line message into one run-on line. A
/// blank line is left out — IRC has no empty message to show it as, and a run
/// of them only spent the bound below. A line longer than an IRC line
/// ([`e6irc_proto::message::MAX_LINE_LEN`] bytes with its CRLF) is split: the
/// receiving client's framing discards an over-long line *whole*, so the
/// message would vanish with nothing said. Each piece of an action is its own
/// complete `ACTION`.
///
/// At most [`MAX_BRIDGED_LINES`] lines are shown; the rest of a longer message
/// is counted in a `*bnc*` notice after them, never cut off silently. A
/// message with nothing to show still yields one (empty) line: a message was
/// sent, and saying nothing about it would be the silent drop this exists to
/// prevent.
#[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
pub(crate) fn render_bridged(
    who: &irc_driver::SelfIdentity,
    channel: &str,
    message: &Inbound,
) -> BridgedLines {
    use e6irc_proto::message::MAX_LINE_LEN;
    let (command, open, close) = match message.kind {
        InboundKind::Message => ("PRIVMSG", "", ""),
        #[cfg(any(feature = "matrix", feature = "slack"))]
        InboundKind::Action => ("PRIVMSG", "\u{1}ACTION ", "\u{1}"),
        #[cfg(feature = "matrix")]
        InboundKind::Notice => ("NOTICE", "", ""),
    };
    let prefix = format!(
        ":{}!{}@{} {command} {channel} :{open}",
        who.nick, who.user, who.host
    );
    // The nick, user and host are bounded tokens (see `BridgedSenders`), so only
    // a pathologically long configured channel name can exhaust the line. The
    // floor keeps the split making progress if one ever does; the resulting
    // lines would still be over-long, which is a configuration error and not
    // something this function can paper over.
    let budget = (MAX_LINE_LEN - 2)
        .saturating_sub(prefix.len() + close.len())
        .max(1);
    let mut pieces = message
        .body
        .split('\n')
        .filter(|line| !line.trim().is_empty())
        .flat_map(|line| pieces_within(line, budget));
    let mut lines: Vec<String> = pieces
        .by_ref()
        .take(MAX_BRIDGED_LINES)
        .map(|piece| format!("{prefix}{piece}{close}"))
        .collect();
    if lines.is_empty() {
        lines.push(format!("{prefix}{close}"));
    }
    let hidden = pieces.count();
    if hidden > 0 {
        lines.push(bnc_notice(
            channel,
            &format!(
                "… {hidden} more lines of {}'s message not shown (a bridged message is shown \
                 in at most {MAX_BRIDGED_LINES})",
                who.nick
            ),
        ));
    }
    BridgedLines(lines)
}

/// A `*bnc*` NOTICE to `channel` saying a message from `sender` of a kind the
/// bridge cannot show (`what`, the provider's own type name) was not relayed.
/// `what` is upstream text: it is reduced to a bounded token of type-name
/// characters, so it can carry neither controls nor a line's worth of bytes.
/// A message too malformed to name its sender is said to be from an unknown
/// one rather than dropped.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
pub(crate) fn unrelayed_notice(
    platform: &str,
    channel: &str,
    what: &str,
    sender: Option<&str>,
) -> String {
    let what: String = what
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .take(64)
        .collect();
    let what = if what.is_empty() {
        "unnamed"
    } else {
        what.as_str()
    };
    let sender = sender.map_or_else(
        || "an unknown sender".to_string(),
        crate::sanitize::nick_token,
    );
    bnc_notice(
        channel,
        &format!("{platform}: a {what} message from {sender} was not relayed"),
    )
}

/// Events a network's broadcast holds for its slowest live subscriber (an
/// attached client, the backlog writer). One that falls further behind has
/// missed lines: a client is detached as too slow, and the backlog writer
/// records a gap.
const DRIVER_EVENT_CAPACITY: usize = 1024;

/// The fill past which a bridge waits for its subscribers before relaying the
/// next message ([`DriverEnds::relay_bridged`]): half the capacity, so one
/// message — at most [`MAX_BRIDGED_LINES`] lines and a notice — always fits in
/// the other half.
#[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
const BRIDGE_PACING_HIGH_WATER: usize = DRIVER_EVENT_CAPACITY / 2;

/// How long one pacing wait lasts before the lines go out regardless. A
/// subscriber that reads nothing for this long is stuck, not slow: waiting on
/// it would hold every other subscriber (and, for Discord, the heartbeat)
/// behind it, while letting it fall behind detaches it as too slow — the
/// ordinary answer to a stuck client.
#[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
const BRIDGE_PACING_PATIENCE: std::time::Duration = std::time::Duration::from_secs(2);

/// How often a pacing wait looks at the fill again. A broadcast says nothing
/// when a subscriber reads, so the wait polls.
#[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
const BRIDGE_PACING_POLL: std::time::Duration = std::time::Duration::from_millis(5);

/// Outcome of a non-blocking send to a network's shared upstream command queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    /// The line was queued for the upstream.
    Sent,
    /// The bounded queue is full: the upstream is connected and the lines
    /// before this one wait on its flood allowance. The line was not queued;
    /// the caller must tell the client loudly.
    Full,
    /// The network has no session to send it on: it is connecting, or
    /// reconnecting after a drop or a refusal. The line was not queued, as ZNC
    /// ("Your message got lost, you are not connected to IRC") and soju
    /// ("Disconnected from upstream network") refuse it: queued, it waited for
    /// the next session — minutes later, or hours, while a ban or a throttle
    /// was retried — and was then sent out of every context it was written in.
    Disconnected,
    /// The driver is gone; the caller should detach.
    Closed,
    /// Registration or authentication is terminally parked. No driver loop
    /// can drain a queued line until the network is reconfigured.
    Unavailable,
    /// The input was not a valid, bounded IRC client line and was not queued.
    Rejected(ClientLineError),
}

impl NetworkHandle {
    fn emit_notice(&self, failure: NetworkFailure) {
        emit_failure_notice(&self.buffer, &self.events, failure);
    }

    /// Try to hand a raw line to the upstream network **without blocking**.
    ///
    /// The command queue is bounded and *shared by every client attached to the
    /// network*. A blocking send would make one client's backlog (e.g. a burst
    /// paste on a slow flood allowance) stall every *other* attached client's
    /// delivery loop — a cross-tenant head-of-line stall on operator-shared
    /// networks. So this never waits: a full queue returns [`SendOutcome::Full`]
    /// and the caller surfaces it to the client loudly (the same discipline the
    /// core's SendQ uses — bound, then act, never silently block or drop).
    pub fn send(&self, line: &str) -> SendOutcome {
        self.send_from(0, line)
    }

    /// As [`NetworkHandle::send`], but the command carries the sending
    /// attachment's id so its synthesized echo can be routed correctly. The
    /// shared boundary rejects malformed or over-budget IRC lines before they
    /// can enter any driver implementation.
    pub fn send_from(&self, origin: u64, line: &str) -> SendOutcome {
        if let Err(error) = parse_client_line(line) {
            return SendOutcome::Rejected(error);
        }
        match self.runtime_snapshot().lifecycle {
            NetworkLifecycle::AuthenticationFailed | NetworkLifecycle::RegistrationFailed => {
                return SendOutcome::Unavailable;
            }
            NetworkLifecycle::Connecting | NetworkLifecycle::Reconnecting => {
                return SendOutcome::Disconnected;
            }
            // A session registered under an alternative nickname is one: what
            // is sent waits, bounded by the regain window, for the configured
            // nickname (§10.3), and is told it was not sent if that never
            // comes.
            NetworkLifecycle::Connected
            | NetworkLifecycle::RegainingNickname
            | NetworkLifecycle::OwnerSuspended
            | NetworkLifecycle::OwnerDeleted => {}
        }
        match self.commands.try_send(ClientCommand {
            origin,
            line: line.to_string(),
        }) {
            Ok(()) => {
                self.runtime.record_output(line.len());
                if let Some(telemetry) = self
                    .telemetry
                    .lock()
                    .expect("telemetry hook poisoned")
                    .as_ref()
                {
                    telemetry.record_bnc_output(line.len());
                }
                SendOutcome::Sent
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.record_error(NetworkFailure::CommandQueueFull);
                SendOutcome::Full
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.record_error(NetworkFailure::DriverStopped);
                SendOutcome::Closed
            }
        }
    }

    /// Allocate the attachment id an interactive attach uses for its sends.
    pub fn next_attachment_id(&self) -> u64 {
        self.attach_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Apply history retention to this network's backlog: what it keeps and
    /// replays stops at the bound `retention` names, live as it changes.
    pub(crate) fn set_history_retention(&self, retention: crate::core::HistoryRetention) {
        self.buffer.lock().expect("buffer poisoned").retention = retention;
    }

    /// A copy of the current detached buffer (for attach playback).
    pub fn buffer_snapshot(&self) -> Vec<String> {
        self.buffer.lock().expect("buffer poisoned").snapshot()
    }

    /// The detached buffer's lines at or before `through`, or `None` when the
    /// cursor belongs to another ring lifetime (see [`Buffer::lines_through`]).
    /// A reader holding every line after a cursor asks for what came before
    /// it, so what it already has is never sent twice.
    pub fn buffer_through(&self, through: ReplayCursor) -> Option<Vec<String>> {
        self.buffer
            .lock()
            .expect("buffer poisoned")
            .lines_through(through)
    }

    /// [`Self::buffer_through`], and whether every line after `through` is
    /// still retained (see [`Buffer::history_through`]).
    /// `conversation` is the folded name of the conversation paged.
    pub fn history_through(
        &self,
        through: ReplayCursor,
        conversation: &str,
    ) -> Option<RingHistory> {
        self.buffer
            .lock()
            .expect("buffer poisoned")
            .history_through(through, conversation)
    }

    /// Establish one exact boundary between detached-buffer/session replay and
    /// live delivery. Buffered emitters hold these same locks until their event
    /// has been published, so every line and its state effect are either in the
    /// snapshots or receivable from `events`, never both and never neither.
    ///
    /// `after` is the cursor a returning client presents; the replay holds only
    /// the lines past it when the ring can honour it (see
    /// [`Buffer::replay_after`]).
    pub(crate) fn subscribe_with_replay_snapshot(
        &self,
        after: Option<ReplayCursor>,
    ) -> AttachSnapshot {
        let irc_session = self.irc_session.lock().expect("IRC session state poisoned");
        let mut buffer = self.buffer.lock().expect("buffer poisoned");
        // Lines history retention no longer keeps are not replayed, so the
        // head is advanced past them first.
        buffer.evict_expired();
        let events = self.events.subscribe();
        let replay = buffer.replay_after(after);
        AttachSnapshot {
            attachment: self.track_attachment(),
            events,
            replay,
            session: irc_session.snapshot(),
            features: irc_session.features.clone(),
            names: irc_session.names.clone(),
            head: buffer.head.clone(),
            current: irc_session.clone(),
        }
    }

    /// How the network names things, as its 005 lines have said (the
    /// defaults, or what storage remembered, before any has arrived).
    pub fn names(&self) -> e6irc_client::NetworkNames {
        self.irc_session
            .lock()
            .expect("IRC session state poisoned")
            .names
            .clone()
    }

    /// Before the network has said anything this process: compare names under
    /// the case mapping its stored backlog was keyed with, so what was filed
    /// then is found under the same keys.
    pub(crate) fn remember_casemapping(&self, casemapping: e6irc_proto::casemap::CaseMapping) {
        let mut irc_session = self.irc_session.lock().expect("IRC session state poisoned");
        if irc_session.nick.is_none() {
            irc_session.names = e6irc_client::NetworkNames::with_casemapping(casemapping);
            self.buffer
                .lock()
                .expect("buffer poisoned")
                .adopt(&irc_session.names, &irc_session.features);
        }
    }

    /// Receive the replies to the commands attachment `id` sends: answers
    /// meant for it alone, live, never retained (see [`replies`]). Held for
    /// as long as the attachment is.
    pub fn route_replies(&self, id: u64) -> ReplyRoute {
        let (sender, receiver) = mpsc::channel(REPLY_ROUTE_CAPACITY);
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        self.reply_routes
            .0
            .lock()
            .expect("reply routes poisoned")
            .insert(
                id,
                ReplySink {
                    sender,
                    dropped: dropped.clone(),
                },
            );
        ReplyRoute {
            id,
            receiver,
            dropped,
            routes: self.reply_routes.clone(),
        }
    }

    /// Authoritative IRC identity/membership state, once the driver has begun
    /// a session: an IRC upstream's welcome, or a bridge's connect under its
    /// provider account (see [`DriverEnds::begin_bridge_session`]). `None`
    /// before the first one.
    pub fn irc_session_snapshot(&self) -> Option<IrcSessionSnapshot> {
        self.irc_session
            .lock()
            .expect("IRC session state poisoned")
            .snapshot()
    }

    /// What the network's registration burst said about it (004/005), as of
    /// the current session; empty before one has begun, or for a bridge.
    pub fn upstream_features(&self) -> UpstreamFeatures {
        self.irc_session
            .lock()
            .expect("IRC session state poisoned")
            .features
            .clone()
    }

    /// Prepend older (oldest-first) lines to the front of the buffer,
    /// used once at start to restore persisted backlog. Never evicts
    /// lines already present (they are newer); only the remaining
    /// capacity, in lines and in bytes, is filled, keeping the most recent
    /// of `older`.
    ///
    /// Each stored line comes with the time it was stored under, which it is
    /// stamped with when it carries no `time` of its own, and the session's
    /// own nick when it was said, which the ring's head takes from the oldest
    /// line restored ([`restored_head`]). What builds before this one retained
    /// and this one does not is left in storage: a network's registration
    /// burst, whose ISUPPORT would undo the bouncer's own when replayed
    /// (§10.4), and whatever is told live only ([`told_live_only`]).
    pub fn preload_front(&self, older: Vec<crate::db::StoredBacklogLine>) {
        let mut buf = self.buffer.lock().expect("buffer poisoned");
        // Each restored line takes the position just below the current
        // oldest: older than everything pushed, in storage order.
        // A new ring: what did not fit is before its oldest line.
        Self::restore_front(&mut buf, older, |buf, _| {
            buf.entries.front().map_or(buf.next_seq, RingEntry::seq) - 1
        });
    }

    /// Continue the stored ring `epoch`, whose every line through position
    /// `through` is stored (a stop that stored everything said so), with its
    /// lines `older` (oldest first, each with the position it took): a
    /// `ReplayCursor` handed out before the restart names the same line now.
    /// What the driver pushed before this restore — no client has seen it,
    /// since an attach waits for history — moves up past `through`; the
    /// answer says which events' positions moved, and by how much, so their
    /// persistence stores the positions they have now.
    ///
    /// The lines back, changing nothing, when they do not fit the claim: a
    /// line without a position, or positions not rising or past `through`.
    /// The caller then restores them as a new epoch.
    ///
    /// `let_go` is the newest position of the epoch that storage let go of
    /// from among the lines it keeps — a busy conversation's older lines,
    /// trimmed from the middle ([`crate::db::bnc_ring_let_go`]): a cursor
    /// before it is refused, as the running ring refuses one before a line it
    /// let go of.
    pub(crate) fn continue_ring(
        &self,
        epoch: u64,
        through: u64,
        older: Vec<crate::db::StoredBacklogLine>,
        let_go: Option<u64>,
    ) -> Result<Renumbered, Vec<crate::db::StoredBacklogLine>> {
        let mut last = 0u64;
        let fits = older.iter().all(|stored| {
            let fits = stored.seq.is_some_and(|seq| seq > last && seq <= through);
            last = stored.seq.unwrap_or(last);
            fits
        });
        if !fits {
            return Err(older);
        }
        let mut buf = self.buffer.lock().expect("buffer poisoned");
        let renumbered = Renumbered {
            below: buf.next_seq,
            shift: (through + 1).saturating_sub(buf.first_seq),
        };
        for entry in &mut buf.entries {
            match entry {
                RingEntry::Line(line, _) => line.seq += renumbered.shift,
                RingEntry::Session { seq, .. } => *seq += renumbered.shift,
            }
        }
        buf.next_seq += renumbered.shift;
        buf.epoch = epoch;
        let not_restored = Self::restore_front(&mut buf, older, |_, stored| {
            stored.seq.expect("every position checked above")
        });
        buf.let_go_floor = let_go.unwrap_or(0).max(not_restored.unwrap_or(0));
        buf.evicted_through = buf
            .evicted_through
            .max(let_go.unwrap_or(0))
            .max(not_restored.unwrap_or(0));
        Ok(renumbered)
    }

    /// This ring's epoch, and the position of its newest line.
    pub(crate) fn ring_position(&self) -> (u64, u64) {
        let buf = self.buffer.lock().expect("buffer poisoned");
        (buf.epoch, buf.position())
    }

    /// [`Self::preload_front`]'s restore, each line at the position
    /// `position` gives it. The answer is the newest position of a line that
    /// did not fit, when one did not.
    fn restore_front(
        buf: &mut Buffer,
        older: Vec<crate::db::StoredBacklogLine>,
        position: impl Fn(&Buffer, &crate::db::StoredBacklogLine) -> u64,
    ) -> Option<u64> {
        let older: Vec<crate::db::StoredBacklogLine> = older
            .into_iter()
            .filter(|stored| {
                !is_registration_burst_line(&stored.line) && !told_live_only(&stored.line)
            })
            .collect();
        let room = buf.cap.saturating_sub(buf.entries.len());
        // The own nicks of the lines restored, newest first.
        let mut restored = Vec::new();
        let mut not_restored = older.iter().rev().nth(room).and_then(|stored| stored.seq);
        for stored in older.iter().rev().take(room) {
            let seq = position(buf, stored);
            let crate::db::StoredBacklogLine {
                line,
                stored_at,
                own_nick,
                seq: _,
            } = stored;
            // Neutralized here as well as in `emit_line`. These lines come back
            // from storage, which outlives the code that wrote them: a row put
            // there by an older build, a restore, or anything else with database
            // access would otherwise be replayed to an attaching client verbatim.
            // Both ways into the buffer sanitize, so no reader has to ask which
            // one a line arrived through.
            let line = stamp_time(crate::sanitize::upstream_line(line.clone()), stored_at);
            if buf.bytes + line.len() > buf.byte_cap {
                not_restored = not_restored.max(stored.seq);
                break;
            }
            let said_by = match own_nick {
                crate::db::StoredOwnNick::Nick(nick) => Some(nick.as_str()),
                crate::db::StoredOwnNick::NoNick | crate::db::StoredOwnNick::NotRecorded => None,
            };
            let share = Share::of(&line, said_by, &buf.names);
            buf.bytes += line.len();
            *buf.shares.entry(share.clone()).or_default() += 1;
            buf.entries
                .push_front(RingEntry::Line(BufferedLine { seq, line }, share));
            restored.push(own_nick);
        }
        if !restored.is_empty() {
            let (names, features) = (buf.names.clone(), buf.features.clone());
            buf.head = restored_head(restored.into_iter().rev(), names, features);
        }
        not_restored
    }

    /// The most lines the replay buffer holds: the network's `buffer_cap`.
    pub(crate) fn buffer_capacity(&self) -> usize {
        self.buffer.lock().expect("buffer poisoned").cap
    }

    /// Subscribe to the driver's event stream (one receiver per attach).
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<DriverEvent> {
        self.events.subscribe()
    }

    /// Watch the authoritative stop signal, so an out-of-module attach path
    /// (the web-UI socket) can detach when the network is removed/replaced.
    /// The event broadcast does not close while a `NetworkHandle` is held, so
    /// an attacher that only watches `subscribe()` would linger forever on a
    /// stopped network — this is the signal `attach` uses to avoid exactly that.
    pub fn watch_shutdown(&self) -> tokio::sync::watch::Receiver<bool> {
        self.shutdown.subscribe()
    }

    /// Count one attached client until the returned guard is dropped.
    pub(crate) fn track_attachment(&self) -> NetworkAttachment {
        let telemetry = self
            .telemetry
            .lock()
            .expect("telemetry hook poisoned")
            .clone()
            .map(|telemetry| telemetry.observe_bnc_client());
        self.runtime
            .attached_clients
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        NetworkAttachment {
            runtime: self.runtime.clone(),
            _telemetry: telemetry,
        }
    }

    /// A point-in-time operational snapshot for owner-scoped APIs and views.
    pub fn runtime_snapshot(&self) -> NetworkRuntimeSnapshot {
        let state = self.state_snapshot();
        let buffer = self.buffer.lock().expect("buffer poisoned");
        NetworkRuntimeSnapshot {
            lifecycle: state.phase.lifecycle(),
            status_revision: state.status_revision,
            state_changed_at: state.state_changed_at,
            next_retry_at: state.phase.next_retry_at(),
            recent_failures: state.recent_failures.iter().copied().collect(),
            connected_at: state.phase.connected_at(),
            last_input_at: atomic_millis(&self.runtime.last_input_at),
            last_output_at: atomic_millis(&self.runtime.last_output_at),
            last_error_at: state.last_error.map(|record| record.at),
            last_error: state.last_error.map(|record| record.failure),
            last_error_diagnostic: state.last_error_diagnostic.clone(),
            connect_latency_ms: state.connect_latency_ms,
            connection_attempts: state.connection_attempts,
            errors: state.errors,
            attached_clients: self
                .runtime
                .attached_clients
                .load(std::sync::atomic::Ordering::Relaxed),
            lines_in: self
                .runtime
                .lines_in
                .load(std::sync::atomic::Ordering::Relaxed),
            bytes_in: self
                .runtime
                .bytes_in
                .load(std::sync::atomic::Ordering::Relaxed),
            lines_out: self
                .runtime
                .lines_out
                .load(std::sync::atomic::Ordering::Relaxed),
            bytes_out: self
                .runtime
                .bytes_out
                .load(std::sync::atomic::Ordering::Relaxed),
            buffer_lines: buffer.entries.len(),
            buffer_capacity: buffer.cap,
        }
    }

    fn state_snapshot(&self) -> NetworkRuntimeState {
        let state = self.runtime.state.lock().expect("network runtime poisoned");
        NetworkRuntimeState {
            phase: state.phase,
            status_revision: state.status_revision,
            recent_failures: state.recent_failures.clone(),
            state_changed_at: state.state_changed_at,
            attempt_started: state.attempt_started,
            connect_latency_ms: state.connect_latency_ms,
            connection_attempts: state.connection_attempts,
            errors: state.errors,
            last_error: state.last_error,
            last_error_diagnostic: state.last_error_diagnostic.clone(),
        }
    }

    /// Build a handle and the driver-side endpoints. A driver spawns a
    /// task that reads commands, records lines to the buffer, and
    /// broadcasts events through the returned [`DriverEnds`].
    pub fn channels(buffer_cap: usize) -> (NetworkHandle, DriverEnds) {
        Self::channels_with(buffer_cap, SessionAuthority::Upstream)
    }

    /// [`NetworkHandle::channels`] for a bridge: the provider account owns
    /// the session's nick and channels ([`SessionAuthority::Provider`]).
    #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
    pub(crate) fn bridge_channels(buffer_cap: usize) -> (NetworkHandle, DriverEnds) {
        Self::channels_with(buffer_cap, SessionAuthority::Provider)
    }

    /// Who decides this network's nick and channel memberships.
    pub fn session_authority(&self) -> SessionAuthority {
        self.authority
    }

    fn channels_with(
        buffer_cap: usize,
        authority: SessionAuthority,
    ) -> (NetworkHandle, DriverEnds) {
        let (events, _) = tokio::sync::broadcast::channel(DRIVER_EVENT_CAPACITY);
        // Bounded, not unbounded: the driver drains one command per loop
        // iteration, and during a reconnect wait (up to ~30s of backoff) it
        // doesn't drain at all — an unbounded queue would let an attached client's
        // sends grow without limit. A full queue backpressures the sender (the
        // attach/WS read side stops reading the client socket) instead, bounding
        // memory. Shared across all clients attached to this one network.
        let (command_tx, command_rx) = mpsc::channel(BNC_COMMAND_QUEUE);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (stopped_tx, stopped_rx) = tokio::sync::watch::channel(false);
        let buffer = std::sync::Arc::new(std::sync::Mutex::new(Buffer::new(buffer_cap)));
        let runtime = std::sync::Arc::new(NetworkRuntime::new());
        let irc_session =
            std::sync::Arc::new(std::sync::Mutex::new(IrcSessionState::following_channels()));
        let reply_routes = ReplyRoutes::default();
        let telemetry = std::sync::Arc::new(std::sync::Mutex::new(None));
        let history = std::sync::Arc::new(std::sync::Mutex::new(None));
        let (history_ready, _) = tokio::sync::watch::channel(true);
        let handle = NetworkHandle {
            events: events.clone(),
            commands: command_tx,
            attach_seq: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)),
            shutdown: shutdown_tx,
            stopped: stopped_rx,
            history: history.clone(),
            history_ready,
            buffer: buffer.clone(),
            runtime: runtime.clone(),
            irc_session: irc_session.clone(),
            reply_routes: reply_routes.clone(),
            authority,
            telemetry: telemetry.clone(),
        };
        // A process-wide counter gives each driver a distinct, stable jitter
        // seed without an RNG — sequential ids, Fibonacci-hashed in `Backoff`.
        static DRIVER_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let reconnect_seed = DRIVER_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let ends = DriverEnds {
            events,
            commands: command_rx,
            shutdown: shutdown_rx,
            stopped: Some(stopped_tx),
            buffer,
            runtime,
            irc_session,
            reply_routes,
            telemetry,
            reconnect_seed,
            rejection_retry_floor: REJECTION_RETRY_FLOOR,
            first_dial_delay: std::time::Duration::ZERO,
            buffered_status: std::sync::Mutex::new(BufferedStatus::default()),
            #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
            bridge: BridgeRelayState::default(),
        };
        (handle, ends)
    }

    /// Stop the network's driver authoritatively. Called by the registry when a
    /// network is removed or replaced; the driver observes it via `next_command`
    /// / `run_with_backoff` and tears down even while clients are attached.
    pub fn shutdown(&self) {
        self.shutdown.send_replace(true);
    }

    /// Stop the driver and wait until its upstream transport is released, or
    /// until [`SHUTDOWN_WAIT_DEADLINE`] passes — whichever is first. The stop is
    /// signalled either way; the deadline only bounds how long the caller (the
    /// registry, under its one mutation guard) holds still for one driver.
    /// Stop the driver and mark the network held by its owner's account
    /// lifecycle ([`OwnerHold`]); its runtime reports the hold from then on.
    pub(crate) async fn hold(&self, hold: OwnerHold) {
        self.shutdown_and_wait().await;
        self.runtime.hold(hold);
    }

    pub async fn shutdown_and_wait(&self) {
        if !self.shutdown_and_wait_within(SHUTDOWN_WAIT_DEADLINE).await {
            eprintln!(
                "bnc: {} did not release its upstream within {}s of being stopped; \
                 proceeding without it (the stop stands, and the task exits when its \
                 bounded write ends)",
                self.runtime.label(),
                SHUTDOWN_WAIT_DEADLINE.as_secs()
            );
        }
    }

    /// [`NetworkHandle::shutdown_and_wait`] with the deadline stated. `true`
    /// when the driver released its transport before it.
    pub(crate) async fn shutdown_and_wait_within(&self, deadline: std::time::Duration) -> bool {
        self.shutdown();
        let mut stopped = self.stopped.clone();
        tokio::time::timeout(deadline, async move {
            // `Ok` is the driver saying it stopped; `Err` is its endpoints
            // dropped, which is the same release.
            drop(stopped.wait_for(|released| *released).await);
        })
        .await
        .is_ok()
    }

    pub(crate) fn set_telemetry(&self, telemetry: std::sync::Arc<crate::observability::Telemetry>) {
        *self.telemetry.lock().expect("telemetry hook poisoned") = Some(telemetry);
    }

    /// Assign the registry's owner/name label for lifecycle log lines.
    pub(crate) fn set_label(&self, label: String) {
        *self.runtime.label.lock().expect("network label poisoned") = Some(label);
    }

    /// Assign the PG history context (pool + owner/network keys) so the
    /// attach listener can serve CHATHISTORY and MARKREAD.
    pub(crate) fn set_history(&self, pool: sqlx::PgPool, owner: Option<String>, network: String) {
        self.history_ready.send_replace(false);
        *self.history.lock().expect("history context poisoned") = Some(NetworkHistory {
            pool,
            owner: owner.unwrap_or_else(|| "*".to_string()),
            network,
        });
    }

    /// The PG history context, if this network has a database backing it.
    pub fn history(&self) -> Option<NetworkHistory> {
        self.history
            .lock()
            .expect("history context poisoned")
            .clone()
    }

    /// Wait for persisted backlog restore, unless the network is stopped first.
    pub(crate) async fn wait_for_history(&self) -> bool {
        let mut history_ready = self.history_ready.subscribe();
        let mut shutdown = self.shutdown.subscribe();
        loop {
            if *shutdown.borrow() {
                return false;
            }
            if *history_ready.borrow() {
                return true;
            }
            tokio::select! {
                changed = history_ready.changed() => {
                    if changed.is_err() {
                        return false;
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return false;
                    }
                }
            }
        }
    }

    /// Complete the initial history restore after loading succeeds or fails.
    pub(crate) fn history_restored(&self) {
        self.history_ready.send_replace(true);
    }

    pub(crate) fn record_error(&self, failure: NetworkFailure) {
        record_network_error(&self.runtime, &self.telemetry, failure);
        self.emit_notice(failure);
    }

    pub(crate) fn publish_read_marker(
        &self,
        account: &str,
        target: &str,
        timestamp: &str,
        origin: u64,
    ) {
        drop(self.events.send(DriverEvent::ReadMarker {
            account: account.to_string(),
            target: target.to_string(),
            timestamp: timestamp.to_string(),
            origin,
        }));
    }
}

/// The driver-side endpoints of a [`NetworkHandle`]. A [`NetworkDriver`]
/// implementation owns these: it receives downstream commands, records
/// upstream lines to the detached buffer, and broadcasts live events.
pub struct DriverEnds {
    events: tokio::sync::broadcast::Sender<DriverEvent>,
    commands: mpsc::Receiver<ClientCommand>,
    /// Fires (or its sender drops) when the network is stopped; the driver
    /// observes it in `next_command` and `run_with_backoff` so it tears down
    /// promptly on removal, not when the last client happens to detach.
    shutdown: tokio::sync::watch::Receiver<bool>,
    stopped: Option<tokio::sync::watch::Sender<bool>>,
    buffer: std::sync::Arc<std::sync::Mutex<Buffer>>,
    runtime: std::sync::Arc<NetworkRuntime>,
    irc_session: std::sync::Arc<std::sync::Mutex<IrcSessionState>>,
    reply_routes: ReplyRoutes,
    telemetry:
        std::sync::Arc<std::sync::Mutex<Option<std::sync::Arc<crate::observability::Telemetry>>>>,
    /// Stable per-driver value seeding this driver's reconnect jitter, so
    /// concurrent drivers de-correlate (see [`Backoff`]). Assigned once at
    /// construction from a process-wide counter.
    reconnect_seed: u64,
    /// First delay after the upstream refuses registration; see
    /// [`REJECTION_RETRY_FLOOR`].
    rejection_retry_floor: std::time::Duration,
    /// How long the first dial is held back; zero unless the driver was
    /// started at boot (see [`Backoff::first_dial_stagger`]).
    first_dial_delay: std::time::Duration,
    /// The connection states whose notices entered the backlog since the
    /// lifecycle last changed.
    buffered_status: std::sync::Mutex<BufferedStatus>,
    /// What a bridge remembers across its sessions about how it relays.
    #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
    bridge: BridgeRelayState,
}

/// What a bridge's [`DriverEnds`] remembers across sessions about relaying.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
#[derive(Default)]
struct BridgeRelayState {
    /// A session of this bridge has begun before: one that begins
    /// [`SessionStart::Fresh`] after it has lost what was said in between.
    begun: std::sync::atomic::AtomicBool,
    /// A pacing wait ran out of patience and the lines went out anyway (see
    /// [`BridgePacer`]); cleared once the subscribers catch up.
    overrun: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// Waits, before a bridge relays its next message, until the network's
/// subscribers have room for it. A driver that relays a burst — a resumed
/// Matrix sync's hundreds of events, a Discord RESUME's replay, Slack's
/// acknowledged messages finishing their name lookups together — outran them
/// when it published in a tight loop: the broadcast overflowed, every attached
/// client was detached as too slow, and the backlog writer lost lines. Past
/// [`BRIDGE_PACING_HIGH_WATER`] it waits for them, at most
/// [`BRIDGE_PACING_PATIENCE`] per stall.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
#[derive(Clone)]
pub(crate) struct BridgePacer {
    events: tokio::sync::broadcast::Sender<DriverEvent>,
    overrun: std::sync::Arc<std::sync::atomic::AtomicBool>,
    runtime: std::sync::Arc<NetworkRuntime>,
}

#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
impl BridgePacer {
    /// Wait until the broadcast is below [`BRIDGE_PACING_HIGH_WATER`]. A
    /// subscriber still behind after [`BRIDGE_PACING_PATIENCE`] is stuck: the
    /// wait gives up, and until the fill drops again (the stuck subscriber
    /// detached as too slow, or caught up) no further wait is made — each one
    /// would only hold the rest behind it again.
    pub(crate) async fn wait(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        if self.events.len() < BRIDGE_PACING_HIGH_WATER {
            self.overrun.store(false, Relaxed);
            return;
        }
        if self.overrun.load(Relaxed) {
            return;
        }
        let deadline = tokio::time::Instant::now() + BRIDGE_PACING_PATIENCE;
        while self.events.len() >= BRIDGE_PACING_HIGH_WATER {
            if tokio::time::Instant::now() >= deadline {
                eprintln!(
                    "bnc: {} has a subscriber that read nothing for {BRIDGE_PACING_PATIENCE:?}; \
                     relaying without waiting for it",
                    self.runtime.label()
                );
                self.overrun.store(true, Relaxed);
                return;
            }
            tokio::time::sleep(BRIDGE_PACING_POLL).await;
        }
    }
}

/// Where a bridge session starts reading its provider (see
/// [`DriverEnds::begin_bridge_session`]).
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionStart {
    /// Where the previous session stopped: a Matrix sync from its `since`, a
    /// Discord RESUME. What was said meanwhile is delivered, or the provider
    /// says how much was cut (a `limited` Matrix timeline).
    #[cfg(any(feature = "matrix", feature = "discord"))]
    Resumed,
    /// From now: a Matrix initial sync (which only establishes a position), a
    /// Discord IDENTIFY, a Slack socket (Socket Mode keeps no position; what
    /// Slack re-sends is at its discretion).
    Fresh,
}

impl Drop for DriverEnds {
    fn drop(&mut self) {
        if let Some(stopped) = self.stopped.take() {
            stopped.send_replace(true);
        }
    }
}

impl DriverEnds {
    /// Start a newly registered IRC session and publish its authoritative
    /// identity. This clears memberships from the previous transport; JOIN
    /// confirmations repopulate them through [`DriverEnds::emit_session_line`].
    pub fn begin_irc_session(&self, nick: String) {
        let mut irc_session = self.irc_session.lock().expect("IRC session state poisoned");
        let snapshot = irc_session.begin(nick);
        irc_session.in_burst = true;
        self.publish_session(snapshot);
    }

    /// Mark where a session began, in the ring and live, while the caller
    /// holds the session lock: a client replaying past the boundary
    /// reconciles to it exactly as a client attached at the time did.
    fn publish_session(&self, snapshot: IrcSessionSnapshot) {
        let mut buffer = self.buffer.lock().expect("buffer poisoned");
        buffer.push_session(snapshot.clone());
        drop(self.events.send(DriverEvent::Session(snapshot)));
    }

    /// How the network names things, as its 005 lines have said.
    pub(crate) fn names(&self) -> e6irc_client::NetworkNames {
        self.irc_session
            .lock()
            .expect("IRC session state poisoned")
            .names
            .clone()
    }

    /// What the network's registration burst said about it (004/005).
    pub(crate) fn upstream_features(&self) -> UpstreamFeatures {
        self.irc_session
            .lock()
            .expect("IRC session state poisoned")
            .features
            .clone()
    }

    /// Record whether the network carries client-only tags now. A change
    /// while clients are attached is told to them as the ISUPPORT change it
    /// is, live: `CLIENTTAGDENY=*` while the tags are stripped, the network's
    /// own value (or its withdrawal) once they are carried.
    pub(crate) fn set_client_tags(&self, client_tags: ClientTags) {
        let mut irc_session = self.irc_session.lock().expect("IRC session state poisoned");
        if irc_session.features.client_tags == client_tags {
            return;
        }
        irc_session.features.client_tags = client_tags;
        let Some(nick) = irc_session.nick.clone() else {
            return;
        };
        let token = irc_session
            .features
            .client_tag_deny()
            .unwrap_or_else(|| "-CLIENTTAGDENY".to_string());
        let line = ingest(format!(
            ":*bnc* 005 {} {token} :are supported by this server",
            MiddleParam::echo(&nick)
        ));
        let buffer = self.buffer.lock().expect("buffer poisoned");
        drop(self.events.send(DriverEvent::Notice(BufferedLine {
            seq: buffer.position(),
            line,
        })));
    }

    /// Deliver an upstream line that answers attachment `origin`'s command
    /// to that attachment alone, live (see [`replies`]). An attachment that
    /// has detached since it asked has no one waiting for the answer.
    pub(crate) fn emit_reply(&self, origin: u64, line: String) {
        let line = ingest(line);
        self.record_input(line.len());
        self.reply_routes.deliver(origin, line);
    }

    /// The session's own answer to `line` when it asks about one channel the
    /// session is in what the session follows of it: its member list
    /// (`NAMES #chan`), its settings (`MODE #chan`) or its topic (`TOPIC
    /// #chan`), each once it is known. These are what a client asks of every
    /// channel it is shown joined — irssi and WeeChat ask `MODE` and `NAMES`
    /// for each — so asked of the upstream, an attach of a client in a
    /// hundred channels held the queue every attached client shares for
    /// minutes at the upstream's flood allowance, and past the queue's bound
    /// the questions were dropped. soju and ZNC answer them the same way.
    fn answered_by_session(&self, line: &str) -> Option<Vec<String>> {
        let message = e6irc_proto::message::Message::parse(line).ok()?;
        let [channel] = message.params.as_slice() else {
            return None;
        };
        let session = self.irc_session.lock().expect("IRC session state poisoned");
        let nick = MiddleParam::echo(session.nick.as_deref()?).to_string();
        let shown = session.channels.get(&session.names.fold(channel))?;
        let view = session.view(channel)?;
        match message.command.to_ascii_uppercase().as_str() {
            "NAMES" => view.names_reply("*bnc*", &nick, shown.as_str(), &session.features),
            "MODE" => view.modes_reply("*bnc*", &nick, shown.as_str()),
            "TOPIC" => view.topic_reply("*bnc*", &nick, shown.as_str()),
            _ => None,
        }
    }

    /// The bouncer's own answer to attachment `origin`'s command.
    pub(crate) fn answer(&self, origin: u64, line: String) {
        self.reply_routes.deliver(origin, ingest(line));
    }

    /// Begin a bridge's session and report the bridge connected, in one step:
    /// the session's nick is the provider account's, as `identity` (from
    /// [`BridgedSenders::own`]) names it, and its channels are the ones the
    /// bridge maps. An attached client is welcomed under the session's nick
    /// and the echo of what it sends names `identity`, so the two are the same
    /// nick by construction — a client recognises its own echoes, and a
    /// bridge cannot be connected with no session for them to match.
    ///
    /// A channel a client could not be told it is in, or more of them than
    /// [`MAX_TRACKED_CHANNELS`], is a configuration the bridge cannot serve,
    /// and nothing is begun.
    ///
    /// A session that begins [`SessionStart::Fresh`] after an earlier one had
    /// begun could not pick up where that one stopped (a Matrix position the
    /// homeserver refused, a Discord RESUME refused, any Slack reconnect), so
    /// what was said in between is not coming. Each bridged channel is told,
    /// once, here — for every provider, whatever made the position go.
    #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
    pub(crate) fn begin_bridge_session<'a>(
        &self,
        identity: &irc_driver::SelfIdentity,
        channels: impl IntoIterator<Item = &'a String>,
        start: SessionStart,
    ) -> Result<(), SessionOutcome> {
        let refused = |detail: &str| {
            SessionOutcome::ConfigurationRejected(ConfigurationRefusal::new(
                NetworkFailure::ChannelMappingFailed,
                detail,
            ))
        };
        let names = bridge_names();
        let mut bridged = std::collections::HashMap::new();
        let channels: Vec<&String> = channels.into_iter().collect();
        for &channel in &channels {
            let Some(confirmed) = upstream_identity::ConfirmedChannel::parse(channel, &names)
            else {
                return Err(refused(&format!(
                    "{channel} is not a channel name an IRC client can be joined to"
                )));
            };
            bridged.insert(names.fold(channel), confirmed);
        }
        if bridged.len() > MAX_TRACKED_CHANNELS {
            return Err(refused(&format!(
                "the bridge maps {} channels; at most {MAX_TRACKED_CHANNELS} are served",
                bridged.len()
            )));
        }
        {
            let mut irc_session = self.irc_session.lock().expect("IRC session state poisoned");
            irc_session.begin(identity.nick.clone());
            irc_session.channels = bridged;
            let snapshot = irc_session
                .snapshot()
                .expect("a begun IRC session has a nick");
            self.publish_session(snapshot);
        }
        self.emit(ConnectionEvent::Connected);
        let followed_a_session = self
            .bridge
            .begun
            .swap(true, std::sync::atomic::Ordering::Relaxed);
        if followed_a_session && start == SessionStart::Fresh {
            for channel in channels {
                self.emit_line(bnc_notice(
                    channel,
                    "the bridge reconnected without resuming where it stopped; messages sent \
                     while it was disconnected may not have been relayed",
                ));
            }
        }
        Ok(())
    }

    /// Relay one bridged message: its lines recorded and published in order,
    /// once the live subscribers have room for them ([`BridgePacer`]).
    #[cfg(any(feature = "matrix", feature = "discord"))]
    pub(crate) async fn relay_bridged(&self, lines: BridgedLines) {
        self.pacer().wait().await;
        self.emit_bridged(lines);
    }

    /// Record and publish one bridged message's lines, in order. A driver
    /// that relays a burst waits on its [`BridgePacer`] between messages.
    #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
    pub(crate) fn emit_bridged(&self, lines: BridgedLines) {
        for line in lines {
            self.emit_line(line);
        }
    }

    /// What waits for this network's subscribers before the next bridged
    /// message; its own handle, so a driver can wait in one `select!` arm
    /// while another reads its commands.
    #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
    pub(crate) fn pacer(&self) -> BridgePacer {
        BridgePacer {
            events: self.events.clone(),
            overrun: self.bridge.overrun.clone(),
            runtime: self.runtime.clone(),
        }
    }

    fn irc_session_snapshot(&self) -> Option<IrcSessionSnapshot> {
        self.irc_session
            .lock()
            .expect("IRC session state poisoned")
            .snapshot()
    }

    /// Record a recoverable failure that does not end the driver session, such
    /// as one rejected outbound bridge message. Reconnect outcomes are counted
    /// by their lifecycle event instead; this path owns both classification and
    /// accounting so a timestamp can never be recorded without a reason.
    #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
    pub(crate) fn record_error(&self, failure: NetworkFailure) {
        record_network_error(&self.runtime, &self.telemetry, failure);
        self.emit_failure_notice(failure);
    }

    /// Record a line to the detached buffer and broadcast it live. The line
    /// is neutralized first (see [`crate::sanitize::upstream_line`]) so a bridge that
    /// builds it from free-form remote text cannot inject a second IRC line
    /// into an attached client's stream.
    ///
    /// The line does not reach the IRC session tracker; a driver that began an
    /// IRC session reports that session's traffic through
    /// [`DriverEnds::emit_session_line`].
    pub fn emit_line(&self, line: String) {
        let line = ingest(line);
        self.record_input(line.len());
        let own = self
            .irc_session
            .lock()
            .expect("IRC session state poisoned")
            .nick
            .clone();
        self.publish_buffered(line, own.as_deref());
    }

    /// [`DriverEnds::emit_line`] for a line of the IRC session begun with
    /// [`DriverEnds::begin_irc_session`]: the nick and membership tracker reads
    /// it under the same locks that publish it, and the caller learns what it
    /// changed. A line that would take the session past
    /// [`MAX_TRACKED_CHANNELS`] is not published, and the driver ends the
    /// session with [`NetworkFailure::ChannelLimitExceeded`].
    ///
    /// Public because [`DriverEnds::begin_irc_session`] is: a driver that can
    /// begin a session through the SPI must be able to feed it.
    pub fn emit_session_line(&self, line: String) -> Result<SessionChange, ChannelLimitExceeded> {
        self.emit_session_line_from(line, None)
    }

    /// [`DriverEnds::emit_session_line`] for the upstream's echo of a line an
    /// attached client sent (the upstream acknowledged `echo-message`):
    /// tracked and buffered like any session line, but broadcast as
    /// [`DriverEvent::Echo`] so the originator receives it only when it
    /// negotiated echo-message — one echo per line, never two.
    pub fn emit_session_echo(
        &self,
        line: String,
        origin: u64,
    ) -> Result<SessionChange, ChannelLimitExceeded> {
        self.emit_session_line_from(line, Some(origin))
    }

    fn emit_session_line_from(
        &self,
        line: String,
        origin: Option<u64>,
    ) -> Result<SessionChange, ChannelLimitExceeded> {
        let line = ingest(line);
        let mut irc_session = self.irc_session.lock().expect("IRC session state poisoned");
        // The nick the line was said under, before a rename it is.
        let said_by = irc_session.nick.clone();
        let change = irc_session.observe(&line)?;
        self.record_input(line.len());
        // What the network says about itself as it welcomes this session is
        // taken in above and shown to no one: attached clients are told the
        // bouncer's own version of it (§10.4) — as a change to what they were
        // welcomed with, once the burst ends.
        let was_in_burst = irc_session.in_burst;
        let in_burst = irc_session.in_registration_burst(&line);
        if was_in_burst && !irc_session.in_burst {
            let mut buffer = self.buffer.lock().expect("buffer poisoned");
            buffer.adopt(&irc_session.names, &irc_session.features);
            drop(
                self.events
                    .send(DriverEvent::Features(irc_session.features.clone())),
            );
        }
        if in_burst {
            return Ok(change);
        }
        // A later ISUPPORT change is the network's, less what the bouncer
        // answers for itself; it is current state, not history, so it is told
        // to whoever is attached and never retained.
        if let Some(rewritten) = live_isupport(&line, irc_session.features.client_tags) {
            let mut buffer = self.buffer.lock().expect("buffer poisoned");
            buffer.adopt(&irc_session.names, &irc_session.features);
            if let Some(line) = rewritten {
                drop(self.events.send(DriverEvent::Notice(BufferedLine {
                    seq: buffer.position(),
                    line,
                })));
            }
            return Ok(change);
        }
        match origin {
            None => self.publish_buffered(line, said_by.as_deref()),
            Some(origin) => self.publish_echo(line, origin),
        }
        // The raw line was delivered, so the client believes in a membership
        // this session does not hold and will not restore. Say so to whoever is
        // attached; it is not conversation, so it stays out of the backlog.
        for name in &change.untracked {
            let line = ingest(bnc_notice(
                "*",
                &format!("upstream confirmed a channel name e6irc cannot track: {name}"),
            ));
            // Not retained, so it reports the ring's position unchanged — read
            // and published under the ring's lock, in order with the lines
            // around it.
            let buffer = self.buffer.lock().expect("buffer poisoned");
            drop(self.events.send(DriverEvent::Notice(BufferedLine {
                seq: buffer.position(),
                line,
            })));
        }
        Ok(change)
    }

    fn record_input(&self, bytes: usize) {
        self.runtime.record_input(bytes);
        if let Some(telemetry) = self
            .telemetry
            .lock()
            .expect("telemetry hook poisoned")
            .as_ref()
        {
            telemetry.record_bnc_input(bytes);
        }
    }

    /// Retain `line`, said while the session's own nick was `said_by`, and
    /// publish it.
    fn publish_buffered(&self, line: String, said_by: Option<&str>) {
        let mut buffer = self.buffer.lock().expect("buffer poisoned");
        // What the backlog keeps nothing of is told live, at the ring's
        // position, and never retained or stored (the persistence task
        // stores `Line`s, not `Notice`s).
        if told_live_only(&line) {
            let seq = buffer.position();
            drop(
                self.events
                    .send(DriverEvent::Notice(BufferedLine { seq, line })),
            );
            return;
        }
        let seq = buffer.push_said(line.clone(), said_by);
        // A detached network legitimately has no live subscribers; the line is
        // still retained in the buffer above. Keep the buffer lock through the
        // publish: attach takes that lock before subscribing and snapshotting,
        // which makes the replay/live boundary atomic.
        drop(
            self.events
                .send(DriverEvent::Line(BufferedLine { seq, line })),
        );
    }

    /// Publish the echo of a line attachment `origin` sent: retained like any
    /// line of the conversation, unless the backlog keeps nothing of it
    /// ([`told_live_only`]), when it is told live at the ring's position (and
    /// the persistence task skips it).
    fn publish_echo(&self, line: String, origin: u64) {
        let mut buffer = self.buffer.lock().expect("buffer poisoned");
        let seq = if told_live_only(&line) {
            buffer.position()
        } else {
            // An echo is said by the session itself, under the nick it shows.
            let said_by = e6irc_proto::message::Message::parse(&line)
                .ok()
                .and_then(|message| message.source.map(|source| source.name.to_string()));
            buffer.push_said(line.clone(), said_by.as_deref())
        };
        drop(self.events.send(DriverEvent::Echo {
            line: BufferedLine { seq, line },
            origin,
        }));
    }

    #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
    fn emit_failure_notice(&self, failure: NetworkFailure) {
        emit_failure_notice(&self.buffer, &self.events, failure);
    }

    /// Record a synthesized self-echo: a copy of a line an attached client
    /// just sent, prefixed as the upstream identity would present it. Buffered
    /// and persisted exactly like an upstream line (the backlog must hold both
    /// sides of the conversation), but broadcast as [`DriverEvent::Echo`] so
    /// the originator can be excluded unless it negotiated echo-message.
    pub fn emit_echo(&self, line: String, origin: u64) {
        let line = ingest(line);
        self.runtime.record_input(line.len());
        self.publish_echo(line, origin);
    }

    /// Report a connection-state change, updating the sticky connection state
    /// so late subscribers can still read it. Lines have their own entry point
    /// ([`DriverEnds::emit_line`]) because they need sanitizing and buffering;
    /// see [`ConnectionEvent`].
    pub fn emit(&self, event: ConnectionEvent) {
        self.publish(event, None, None);
    }

    /// [`DriverEnds::emit`], with when the next attempt fires for an event that
    /// announces a retry (visible in the runtime snapshot as `next_retry_at`
    /// until the attempt begins), and the upstream's own bounded text for a
    /// [`ConnectionEvent::Reconnecting`] that has one (the other events carry
    /// theirs). One step, so none of the three can be seen apart.
    fn publish(
        &self,
        event: ConnectionEvent,
        next_attempt_in: Option<std::time::Duration>,
        upstream_reason: Option<&str>,
    ) {
        let (status, revision, notice) = match event {
            ConnectionEvent::Connected => {
                let revision = self.runtime.connected();
                eprintln!("bnc: {} connected", self.runtime.label());
                (
                    DriverConnectionStatus::Connected,
                    revision,
                    format!(
                        ":*bnc* NOTICE * :component connected: {}",
                        self.runtime.label()
                    ),
                )
            }
            failure_event => {
                let (status, disposition, failure, diagnostic) = match failure_event {
                    ConnectionEvent::RegainingNickname(ref regain) => (
                        DriverConnectionStatus::RegainingNickname,
                        FailureDisposition::RegainingNickname,
                        NetworkFailure::NicknameInUse,
                        Some(regain.diagnostic()),
                    ),
                    ConnectionEvent::Reconnecting(failure) => (
                        DriverConnectionStatus::Reconnecting(failure),
                        FailureDisposition::Retry { next_attempt_in },
                        failure,
                        upstream_reason,
                    ),
                    ConnectionEvent::RegistrationRetrying(ref rejection) => {
                        let failure = registration_failure(rejection.refusal());
                        (
                            DriverConnectionStatus::Reconnecting(failure),
                            FailureDisposition::Retry { next_attempt_in },
                            failure,
                            Some(rejection.diagnostic()),
                        )
                    }
                    ConnectionEvent::ConfigurationRetrying(ref refusal) => (
                        DriverConnectionStatus::Reconnecting(refusal.failure()),
                        FailureDisposition::Retry { next_attempt_in },
                        refusal.failure(),
                        Some(refusal.diagnostic()),
                    ),
                    ConnectionEvent::ConfigurationFailed(ref refusal) => (
                        DriverConnectionStatus::RegistrationFailed(refusal.failure()),
                        FailureDisposition::Terminal(TerminalNetworkLifecycle::RegistrationFailed),
                        refusal.failure(),
                        Some(refusal.diagnostic()),
                    ),
                    ConnectionEvent::AuthenticationFailed(ref rejection) => (
                        DriverConnectionStatus::AuthenticationFailed,
                        FailureDisposition::Terminal(
                            TerminalNetworkLifecycle::AuthenticationFailed,
                        ),
                        NetworkFailure::AuthenticationRejected,
                        rejection.as_ref().map(|rejection| rejection.diagnostic()),
                    ),
                    ConnectionEvent::RegistrationFailed(ref rejection) => {
                        let failure = registration_failure(rejection.refusal());
                        (
                            DriverConnectionStatus::RegistrationFailed(failure),
                            FailureDisposition::Terminal(
                                TerminalNetworkLifecycle::RegistrationFailed,
                            ),
                            failure,
                            Some(rejection.diagnostic()),
                        )
                    }
                    ConnectionEvent::Connected => {
                        unreachable!("connected handled before failure transition")
                    }
                };
                let revision = self.runtime.failed(disposition, failure, diagnostic);
                if let Some(telemetry) = self
                    .telemetry
                    .lock()
                    .expect("telemetry hook poisoned")
                    .as_ref()
                {
                    telemetry.record_error(crate::observability::ErrorKind::Bouncer);
                }
                match disposition {
                    FailureDisposition::Terminal(lifecycle) => eprintln!(
                        "bnc: {} parked ({}): {}",
                        self.runtime.label(),
                        lifecycle.lifecycle().as_str(),
                        failure.summary(),
                    ),
                    FailureDisposition::Retry { .. } => eprintln!(
                        "bnc: {} disconnected ({}); reconnecting",
                        self.runtime.label(),
                        failure.code(),
                    ),
                    FailureDisposition::RegainingNickname => eprintln!(
                        "bnc: {} registered under an alternative nickname ({}); regaining",
                        self.runtime.label(),
                        failure.code(),
                    ),
                }
                let state = status.lifecycle().as_str();
                (
                    status,
                    revision,
                    lifecycle_notice(state, failure, diagnostic),
                )
            }
        };
        // Connection state is sticky in `connected`; zero live subscribers is
        // therefore not a delivery failure.
        drop(self.events.send(DriverEvent::Status { status, revision }));
        // The backlog records each change of state once. An unreachable
        // upstream repeats the same failure on every retry for as long as the
        // outage lasts; buffering each repeat would evict the conversation the
        // backlog exists to keep, so attached clients hear a repeat live only.
        let notice = ingest(notice);
        let transition = self
            .buffered_status
            .lock()
            .expect("buffered status poisoned")
            .record(status);
        if !transition {
            // Live only: the ring's position is unchanged, read under its lock.
            let buffer = self.buffer.lock().expect("buffer poisoned");
            drop(self.events.send(DriverEvent::Notice(BufferedLine {
                seq: buffer.position(),
                line: notice,
            })));
        } else {
            self.publish_buffered(notice, None);
        }
    }

    fn begin_attempt(&self) {
        self.runtime.begin_attempt();
    }

    /// Whether the attempt that just ended reached `Connected`. Read before
    /// the failure is emitted, while the phase still describes the session.
    fn connected_this_attempt(&self) -> bool {
        self.runtime.is_connected()
    }

    /// Replace the production [`REJECTION_RETRY_FLOOR`]. A driver whose
    /// configuration carries its own floor applies it before its run loop.
    pub fn set_rejection_retry_floor(&mut self, floor: std::time::Duration) {
        self.rejection_retry_floor = floor;
    }

    /// Hold the first dial back by this driver's share of
    /// [`Backoff::FIRST_DIAL_STAGGER`]. A driver started at boot applies it
    /// before its run loop; one started on demand dials at once.
    pub fn stagger_first_dial(&mut self) {
        self.first_dial_delay = Backoff::first_dial_stagger(self.reconnect_seed);
    }

    /// Where in the vetted address list this attempt starts; see
    /// [`Backoff::address_rotation`].
    pub fn dial_rotation(&self) -> u64 {
        Backoff::address_rotation(self.reconnect_seed, self.runtime.connection_attempts())
    }

    /// Record a failure that does not end the session, with the upstream's
    /// own bounded text: counted and shown in the runtime snapshot like a
    /// lifecycle failure, and said once to attached clients and the backlog.
    pub fn record_error_with_upstream_detail(&self, failure: NetworkFailure, diagnostic: &str) {
        let diagnostic = e6irc_client::bounded_diagnostic(diagnostic);
        // Announce first, record second: the notice is written to the buffer
        // synchronously, so anyone who sees the failure in the runtime
        // snapshot is guaranteed to find its notice in the backlog too. The
        // other order let an observer read the snapshot between the two.
        self.emit_line(format!(
            "{}; upstream: {diagnostic}",
            failure_notice(failure)
        ));
        self.runtime
            .operational_error_with_diagnostic(failure, &diagnostic);
        if let Some(telemetry) = self
            .telemetry
            .lock()
            .expect("telemetry hook poisoned")
            .as_ref()
        {
            telemetry.record_error(crate::observability::ErrorKind::Bouncer);
        }
    }

    /// Await the next downstream command; `None` when every handle is dropped
    /// **or** the network is shut down. Every driver's session loop selects on
    /// this, so an authoritative stop from the registry reaches all of them
    /// without each having to grow its own shutdown branch.
    pub async fn next_command(&mut self) -> Option<ClientCommand> {
        tokio::select! {
            biased;
            // `changed()` resolves when the registry sends `true`, or errors if
            // the sender dropped — both mean stop.
            res = self.shutdown.changed() => {
                if res.is_err() || *self.shutdown.borrow() {
                    return None;
                }
                // Spurious (value unchanged from false); fall through to a plain
                // command read.
                self.commands.recv().await
            }
            cmd = self.commands.recv() => cmd,
        }
    }

    /// Whether an attached client's command waits in the queue: what the
    /// driver asks on its own behalf waits for none.
    pub(crate) fn has_queued_commands(&self) -> bool {
        !self.commands.is_empty()
    }

    /// Tell each sender of a line still queued that it was not sent: the
    /// session it was queued for has ended, and the lifecycle published just
    /// before this refuses every later send ([`SendOutcome::Disconnected`],
    /// [`SendOutcome::Unavailable`]), so what is drained here is everything
    /// that will never be. Each is named by its command and target, never its
    /// text, which may be a password for services.
    fn refuse_queued(&mut self) {
        while let Ok(command) = self.commands.try_recv() {
            self.answer(
                command.origin,
                unsent_notice(&command.line, "the network disconnected before it went out"),
            );
        }
    }

    /// Whether the network has been shut down (observed without consuming a
    /// command). Lets `run_with_backoff` abandon its reconnect wait promptly.
    pub fn is_shutdown(&self) -> bool {
        *self.shutdown.borrow()
    }

    /// [`DriverEnds::shutdown_signalled`] as a future that owns its receiver,
    /// for racing against work that itself needs this endpoint.
    pub(crate) fn stop_signal(&self) -> impl Future<Output = ()> + Send + 'static {
        let mut shutdown = self.shutdown.clone();
        async move {
            // `Ok` is the stop flag turning true; `Err` is the registry gone.
            drop(shutdown.wait_for(|stop| *stop).await);
        }
    }

    /// Resolve once the network is shut down; for racing against a driver's
    /// reconnect backoff so removal isn't delayed by a pending retry.
    pub async fn shutdown_signalled(&mut self) {
        // Returns Ok on a value change and Err on sender-drop; both mean stop.
        // If already stopped, don't wait.
        while !*self.shutdown.borrow() {
            if self.shutdown.changed().await.is_err() {
                return;
            }
        }
    }
}

/// Which connection states the backlog has recorded (§10.1: once per
/// transition, lifecycle plus failure code). An unreachable upstream repeats
/// the same failure on every retry for as long as the outage lasts, and a
/// round-robin one alternates between a few (`connection_failed`,
/// `connection_timed_out`) as it rotates addresses; each is recorded once in
/// a stretch of one lifecycle, so the outage cannot evict the conversation,
/// while a new reason within it — a `433`, a K-line, a throttle — is recorded
/// when it first appears.
#[derive(Debug, Default)]
struct BufferedStatus {
    lifecycle: Option<NetworkLifecycle>,
    /// The failures recorded since `lifecycle` began: at most one per
    /// [`NetworkFailure`] variant.
    failures: Vec<Option<NetworkFailure>>,
}

impl BufferedStatus {
    /// Whether `status` is a transition the backlog has not recorded yet,
    /// recording it.
    fn record(&mut self, status: DriverConnectionStatus) -> bool {
        let (lifecycle, failure) = (status.lifecycle(), status.failure());
        if self.lifecycle != Some(lifecycle) {
            self.lifecycle = Some(lifecycle);
            self.failures = vec![failure];
            return true;
        }
        if self.failures.contains(&failure) {
            return false;
        }
        self.failures.push(failure);
        true
    }
}

fn lifecycle_notice(state: &str, failure: NetworkFailure, diagnostic: Option<&str>) -> String {
    let detail = diagnostic.map_or_else(String::new, |value| format!("; upstream: {value}"));
    bnc_notice(
        "*",
        &format!(
            "component {state}: {} ({}){detail}",
            failure.summary(),
            failure.code()
        ),
    )
}

const fn registration_failure(refusal: e6irc_client::RegistrationRefusal) -> NetworkFailure {
    match refusal {
        e6irc_client::RegistrationRefusal::InvalidNickname
        | e6irc_client::RegistrationRefusal::WelcomedAsAnotherNickname => {
            NetworkFailure::InvalidNickname
        }
        e6irc_client::RegistrationRefusal::InvalidUsername => NetworkFailure::InvalidUsername,
        e6irc_client::RegistrationRefusal::NicknameInUse => NetworkFailure::NicknameInUse,
        e6irc_client::RegistrationRefusal::NicknameRegainRefused => {
            NetworkFailure::NicknameRegainRefused
        }
        e6irc_client::RegistrationRefusal::ServerPasswordRejected => {
            NetworkFailure::ServerPasswordRejected
        }
        e6irc_client::RegistrationRefusal::ServerPasswordRequired => {
            NetworkFailure::ServerPasswordRequired
        }
        e6irc_client::RegistrationRefusal::NetworkBanned => NetworkFailure::NetworkBanned,
        e6irc_client::RegistrationRefusal::NotRegistered => NetworkFailure::RegistrationRejected,
        e6irc_client::RegistrationRefusal::SaslUnavailable => NetworkFailure::SaslUnavailable,
        e6irc_client::RegistrationRefusal::SaslAborted
        | e6irc_client::RegistrationRefusal::SaslFailed => NetworkFailure::SaslFailed,
    }
}

/// A network driver: an always-on connection to some upstream (IRC, or a
/// bridge to Matrix/Discord/Slack) presented to the user as a network.
/// `prepare` consumes the driver and builds the handle clients attach to and
/// the task that drives it, without running the task, so whoever starts it can
/// subscribe first and miss nothing the driver says. (DESIGN §10.5)
pub trait NetworkDriver: Send + 'static {
    /// Stable kind name for logs/metrics (`irc`, `loopback`, …).
    fn kind(&self) -> &'static str;
    /// Build the handle and the always-on task, not yet running.
    fn prepare(self: Box<Self>) -> PreparedDriver;
    /// Prepare the driver and run its task at once, for a caller with nothing
    /// to subscribe before the driver speaks.
    fn start(self: Box<Self>) -> NetworkHandle {
        self.prepare().launch()
    }
}

/// A driver's handle and its task, not yet running (see
/// [`NetworkDriver::prepare`]).
pub struct PreparedDriver {
    handle: NetworkHandle,
    run: DriverTask,
}

/// A driver's always-on task, not yet running.
pub struct DriverTask(std::pin::Pin<Box<dyn Future<Output = ()> + Send>>);

impl PreparedDriver {
    pub fn new(handle: NetworkHandle, run: impl Future<Output = ()> + Send + 'static) -> Self {
        Self {
            handle,
            run: DriverTask(Box::pin(run)),
        }
    }

    /// The handle, and the task to run once its first subscribers exist.
    pub fn split(self) -> (NetworkHandle, DriverTask) {
        (self.handle, self.run)
    }

    /// Run the task now and return the handle.
    pub fn launch(self) -> NetworkHandle {
        let (handle, run) = self.split();
        run.spawn();
        handle
    }
}

impl DriverTask {
    /// Run the driver on its own task.
    pub fn spawn(self) {
        tokio::spawn(self.0);
    }
}

/// The `irc` driver as a [`NetworkDriver`]: a persistent IRCv3 client.
pub struct IrcDriver {
    config: NetworkConfig,
}

impl IrcDriver {
    pub fn new(config: NetworkConfig) -> Self {
        Self { config }
    }
}

impl NetworkDriver for IrcDriver {
    fn kind(&self) -> &'static str {
        "irc"
    }
    fn prepare(self: Box<Self>) -> PreparedDriver {
        IrcNetwork::prepare(self.config)
    }
}

/// Reference driver used by the SPI test kit and as a template for real
/// bridges: it registers immediately and echoes every downstream command
/// back as an upstream line, so attach/buffer/relay can be exercised with
/// no external service.
pub struct LoopbackDriver {
    buffer_cap: usize,
}

impl LoopbackDriver {
    pub fn new(buffer_cap: usize) -> Self {
        Self { buffer_cap }
    }
}

impl NetworkDriver for LoopbackDriver {
    fn kind(&self) -> &'static str {
        "loopback"
    }
    fn prepare(self: Box<Self>) -> PreparedDriver {
        let (handle, mut ends) = NetworkHandle::channels(self.buffer_cap);
        PreparedDriver::new(handle, async move {
            ends.emit(ConnectionEvent::Connected);
            while let Some(cmd) = ends.next_command().await {
                ends.emit_line(cmd.line);
            }
        })
    }
}

impl std::fmt::Display for AttachEnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ClientClosed => "the client closed the connection",
            Self::ClientQuit => "the client quit",
            Self::ClientTooSlow => "the client fell too far behind the live stream",
            Self::ClientUnresponsive => "the client stopped answering liveness pings",
            Self::NetworkRemoved => "the network was removed or replaced",
            Self::DriverStopped => "the network's driver stopped",
            Self::Revoked(revocation) => return write!(f, "{revocation}"),
        })
    }
}

/// How long an attached client may stay silent before the bouncer pings it,
/// and again before it gives up on it. A quiet or parked network writes
/// nothing to its clients, so without this a half-open client (a laptop that
/// slept, a NAT that forgot the flow) is never written to, never errors, and
/// holds its task, its socket and its place in `attached_clients` until the
/// next broadcast line — which on a parked network never comes.
pub const ATTACH_LIVENESS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(120);

/// Tell a client whose account's authority or credential ended why, and end
/// its attachment.
async fn detach_revoked<W>(write: &mut W, revocation: Revocation) -> std::io::Result<AttachEnd>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    write.write_all(revocation.notice().as_bytes()).await?;
    write.flush().await?;
    Ok(AttachEnd::Revoked(revocation))
}

/// Why an attachment ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachEnd {
    /// The client closed its side of the stream.
    ClientClosed,
    /// The client sent `QUIT`.
    ClientQuit,
    /// The client fell too far behind the live stream to be resynchronised,
    /// or stopped taking what was written to it.
    ClientTooSlow,
    /// The client answered nothing for two liveness intervals.
    ClientUnresponsive,
    /// The network was removed or replaced.
    NetworkRemoved,
    /// The network's driver is gone.
    DriverStopped,
    /// The account's authority ended — it was suspended or deleted, or its
    /// password changed — or the app password the client signed in with was
    /// revoked.
    Revoked(Revocation),
}

/// Attach a downstream client stream to a running network: welcome it, replay
/// the detached buffer, then bidirectionally relay driver events to the
/// client and client lines to the upstream. Returns when either side
/// closes. This is the session multiplexer's core operation, serving
/// every driver kind (`irc`, `local`, and the bridges) uniformly.
///
/// `input` is what the client already sent on `stream` that nothing handled
/// (see [`ClientInput`]); it is handled first, after the replay, as the
/// attached session's own input.
/// `authority` is the lease on the authenticated account's authority: the
/// account keys the BNC-local per-target read markers (shared networks keep
/// per-account positions), and the attachment ends
/// ([`AttachEnd::Revoked`]) when the account is suspended or deleted or its
/// password changes, or the credential it signed in with is revoked — on any
/// network, the operator's shared and configured ones included. An attachment
/// cannot be made without one.
/// `greeting` names who welcomes the client and the nick it registered with.
/// `liveness` is how long the client may stay silent before it is pinged, and
/// then again before it is given up on ([`ATTACH_LIVENESS_INTERVAL`] in
/// production).
///
/// The client is reached through its session of the core link (`link`,
/// [`AttachLink`]). Every write to it is bounded by the peer write deadline
/// (`e6irc_edge::peer_write`): a client that stops reading ends its attachment
/// as [`AttachEnd::ClientTooSlow`] rather than parking the relay, where it
/// would see neither the network's removal nor its own silence.
pub async fn attach(
    link: AttachLink,
    input: ClientInput,
    handle: &NetworkHandle,
    caps: AttachCaps,
    authority: AccountLease,
    greeting: Greeting<'_>,
    liveness: std::time::Duration,
) -> std::io::Result<AttachEnd> {
    match relay_attached(link, input, handle, caps, authority, greeting, liveness).await {
        Err(error) if e6irc_edge::peer_write::is_stalled(&error) => Ok(AttachEnd::ClientTooSlow),
        ended => ended,
    }
}

/// Who welcomes an attaching client, and the nick it registered with.
#[derive(Debug, Clone, Copy)]
pub struct Greeting<'a> {
    /// The server name the welcome comes from.
    pub server_name: &'a str,
    /// The network as the client selected it, named in the welcome.
    pub network: &'a str,
    /// The nick the client registered with: what it is welcomed under until
    /// the network has a session.
    pub requested_nick: &'a str,
}

/// The up-front status of an attaching client's network, as its runtime
/// snapshot has it: connected, or the lifecycle it is in with the failure that
/// put it there and the upstream's own words, as the lifecycle notice of that
/// transition said them.
fn attach_status_notice(runtime: &NetworkRuntimeSnapshot) -> String {
    match (runtime.lifecycle, runtime.last_error) {
        (NetworkLifecycle::Connected, _) => status_notice(DriverConnectionStatus::Connected),
        (lifecycle, Some(failure)) => lifecycle_notice(
            lifecycle.as_str(),
            failure,
            runtime.last_error_diagnostic.as_deref(),
        ),
        (lifecycle, None) => bnc_notice("*", &format!("upstream {}", lifecycle.as_str())),
    }
}

/// [`attach`]'s relay, over a link whose writes are already bounded.
async fn relay_attached(
    link: AttachLink,
    input: ClientInput,
    handle: &NetworkHandle,
    caps: AttachCaps,
    authority: AccountLease,
    greeting: Greeting<'_>,
    liveness: std::time::Duration,
) -> std::io::Result<AttachEnd> {
    use tokio::io::AsyncWriteExt;

    let account = authority.account().to_string();
    let account = account.as_str();
    let AttachLink {
        lines: client_lines,
        mut write,
        holding,
    } = link;
    // A raw IRC client has no cursor to present. Its account's read markers
    // are its position instead: each conversation is replayed from where the
    // account stopped reading it, the whole of one it has no marker for.
    let read_positions = ReadPositions::of(handle, account).await;
    let OpenedAttachment {
        shutdown,
        attach_id,
        snapshot:
            AttachSnapshot {
                attachment,
                events,
                replay,
                session: session_snapshot,
                features,
                names,
                head,
                current,
            },
        replies,
    } = match open_attachment(handle, &authority, &mut write, None).await? {
        Ok(opened) => opened,
        Err(end) => return Ok(end),
    };

    // The welcome is of the same instant as the replay: an ISUPPORT or
    // CLIENTTAGDENY change made after it reaches this client live, and none
    // made before it is lost between the two (§10.4).
    let history = handle.history().is_some();
    let welcomed = serve::welcome(
        greeting.server_name,
        greeting.network,
        &features,
        session_snapshot
            .as_ref()
            .map(|session| session.nick.as_str()),
        greeting.requested_nick,
        history,
    );
    for line in &welcomed.lines {
        write.write_all(line.as_bytes()).await?;
        write.write_all(b"\r\n").await?;
    }

    // Send the current upstream connection status up front, so a client that
    // attaches to an already-connected (or still-reconnecting) network learns the
    // state now rather than only at the next connect/disconnect transition — the
    // same up-front status `/ws/ui` sends over WebSocket, with the failure and
    // the upstream's own words when it is not connected.
    let runtime = handle.runtime_snapshot();
    let status_revision = runtime.status_revision;
    write
        .write_all(attach_status_notice(&runtime).as_bytes())
        .await?;
    write.write_all(b"\r\n").await?;

    // What this client has been shown: the welcome's nick and ISUPPORT, then
    // every line and reconciliation written to it.
    let mut downstream_session = IrcSessionState::with_names(names);
    downstream_session.begin(welcomed.nick);
    downstream_session.features.isupport = welcomed.isupport;
    let audience = JoinAudience {
        handle,
        caps,
        account,
        attach_id,
    };
    let mut untold = UntoldChannels::default();
    // The client is first brought to the session as it stood at the oldest
    // replayed line, so each line reads as it was said: a line under an old
    // nick is its own, not a stranger's, and a channel's lines follow its
    // JOIN (§10.1).
    if let Some(head) = head.as_ref().filter(|head| head.nick.is_some()) {
        reconcile(
            &mut write,
            &mut downstream_session,
            head,
            audience,
            &mut untold,
        )
        .await?;
    }
    let cursor = replay.position();
    let already_read = replay_to(
        &mut write,
        &mut downstream_session,
        replay,
        &features,
        audience,
        &mut untold,
        Some(&read_positions),
    )
    .await?;
    if already_read > 0 {
        write
            .write_all(
                format!(
                    ":*bnc* NOTICE * :{already_read} message(s) before your read markers \
                     were not replayed; CHATHISTORY pages them\r\n"
                )
                .as_bytes(),
            )
            .await?;
    }
    if let ReadPositions::Unavailable = read_positions {
        write
            .write_all(
                b":*bnc* NOTICE * :read markers are unavailable, so the whole backlog was replayed\r\n",
            )
            .await?;
    }
    catch_up(
        &mut write,
        &mut downstream_session,
        &current,
        audience,
        &mut untold,
    )
    .await?;
    let ClientInput { pending } = input;
    relay_live(LiveAttachment {
        write,
        client_lines,
        handle,
        caps,
        authority,
        greeting,
        liveness,
        shutdown,
        events,
        replies,
        downstream_session,
        status_revision,
        attach_id,
        cursor,
        pending,
        held: holding.and_then(|holding| AttachHeld::new(holding, &greeting, account)),
        _attachment: attachment,
    })
    .await
}

/// Resume on this core an attachment its edge held from a graceful cut
/// (DESIGN §19.3): no welcome — the client was welcomed already — but its
/// mirror as its record says it was shown, the lines after the ring position
/// it was sent everything through, then the session as it is now and any
/// ISUPPORT or status that changed meanwhile. A position the ring cannot
/// honour (lines lost with the last core) is said, never guessed across.
pub(crate) async fn resume_attached(
    link: AttachLink,
    handle: &NetworkHandle,
    authority: AccountLease,
    record: crate::core::record::AttachRecord,
    server_name: &str,
    liveness: std::time::Duration,
) -> std::io::Result<AttachEnd> {
    use tokio::io::AsyncWriteExt;

    let crate::core::record::AttachRecord {
        account: _,
        credential: _,
        shared: _,
        network,
        requested_nick,
        caps,
        cursor,
        shown_nick,
        shown_channels,
        shown_isupport,
        status_revision,
    } = record;
    let caps = AttachCaps::from_bits(caps);
    let greeting = Greeting {
        server_name,
        network: &network,
        requested_nick: &requested_nick,
    };
    let account = authority.account().to_string();
    let account = account.as_str();
    let AttachLink {
        lines: client_lines,
        mut write,
        holding,
    } = link;
    let cursor = cursor.map(ReplayCursor::from_recorded);
    let OpenedAttachment {
        shutdown,
        attach_id,
        snapshot:
            AttachSnapshot {
                attachment,
                events,
                replay,
                features,
                names,
                current,
                ..
            },
        replies,
    } = match open_attachment(handle, &authority, &mut write, cursor).await? {
        Ok(opened) => opened,
        Err(end) => return Ok(end),
    };
    // A relay publishes its record only once the client is welcomed, under a
    // nick.
    let Some(shown_nick) = shown_nick else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the attachment's record shows its client no nick",
        ));
    };
    let mut downstream_session = IrcSessionState::with_names(names);
    downstream_session.replace(&IrcSessionSnapshot {
        nick: shown_nick,
        channels: shown_channels,
    });
    downstream_session.features.isupport = shown_isupport;
    let audience = JoinAudience {
        handle,
        caps,
        account,
        attach_id,
    };
    let mut untold = UntoldChannels::default();
    let position = replay.position();
    if replay.resumed {
        replay_to(
            &mut write,
            &mut downstream_session,
            replay,
            &features,
            audience,
            &mut untold,
            None,
        )
        .await?;
    } else {
        write
            .write_all(
                b":*bnc* NOTICE * :the server restarted, and lines said meanwhile may be \
                  missing here; CHATHISTORY pages them\r\n",
            )
            .await?;
    }
    catch_up(
        &mut write,
        &mut downstream_session,
        &current,
        audience,
        &mut untold,
    )
    .await?;
    // What the network says of itself now, as a change to what this client
    // was told.
    let now = serve::welcome_isupport(&features, handle.history().is_some());
    let changes = serve::isupport_changes(&downstream_session.features.isupport, &now);
    let nick = downstream_session.downstream_nick().to_string();
    for line in serve::isupport_lines(server_name, &nick, &changes) {
        write.write_all(line.as_bytes()).await?;
        write.write_all(b"\r\n").await?;
    }
    downstream_session.features.isupport = now;
    let runtime = handle.runtime_snapshot();
    let mut told_revision = status_revision;
    if accept_status_revision(&mut told_revision, runtime.status_revision) {
        write
            .write_all(attach_status_notice(&runtime).as_bytes())
            .await?;
        write.write_all(b"\r\n").await?;
    }
    write.flush().await?;
    relay_live(LiveAttachment {
        write,
        client_lines,
        handle,
        caps,
        authority,
        greeting,
        liveness,
        shutdown,
        events,
        replies,
        downstream_session,
        status_revision: told_revision,
        attach_id,
        cursor: position,
        pending: Vec::new(),
        held: holding.and_then(|holding| AttachHeld::new(holding, &greeting, account)),
        _attachment: attachment,
    })
    .await
}

/// What an attachment, new or resumed, begins with: its account still
/// authorised (or the client told it is not, and how the attachment ended),
/// the network still there with its history loaded, its id, the replay from
/// `cursor` with the live events from the same instant, and the route its
/// own replies reach it by.
async fn open_attachment<W>(
    handle: &NetworkHandle,
    authority: &AccountLease,
    write: &mut W,
    cursor: Option<ReplayCursor>,
) -> std::io::Result<Result<OpenedAttachment, AttachEnd>>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    // Revoked between the lease and here: the attachment never begins.
    if let Some(revocation) = authority.revocation() {
        return detach_revoked(write, revocation).await.map(Err);
    }
    let Some(shutdown) = network_to_attach(handle, write).await? else {
        return Ok(Err(AttachEnd::NetworkRemoved));
    };
    let attach_id = handle.next_attachment_id();
    let snapshot = handle.subscribe_with_replay_snapshot(cursor);
    // The answers to this client's own commands reach it here, and only here.
    let replies = handle.route_replies(attach_id);
    Ok(Ok(OpenedAttachment {
        shutdown,
        attach_id,
        snapshot,
        replies,
    }))
}

/// See [`open_attachment`].
struct OpenedAttachment {
    shutdown: tokio::sync::watch::Receiver<bool>,
    attach_id: u64,
    snapshot: AttachSnapshot,
    replies: ReplyRoute,
}

/// The network's stop signal, once its history is loaded; `None`, the client
/// told, when it is removed before or meanwhile.
async fn network_to_attach<W>(
    handle: &NetworkHandle,
    write: &mut W,
) -> std::io::Result<Option<tokio::sync::watch::Receiver<bool>>>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    // Detach the client if the network is removed. The broadcast does not close
    // on its own (the registry's `NetworkHandle` keeps an events sender), so
    // without this an attached client would linger on a stopped network — its
    // upstream gone but the session still open.
    let shutdown = handle.shutdown.subscribe();
    // The network may have been removed *between* the caller resolving this
    // handle and here (the same account's own API can delete/replace it, and the
    // handshake/upgrade before attach is a wide window). A `watch::Receiver`
    // subscribed after the shutdown was signalled treats that value as already
    // seen, so `changed()` below would never fire and the client would linger
    // forever on a dead network. Check the current value once, up front.
    if *shutdown.borrow() || !handle.wait_for_history().await {
        write
            .write_all(b":*bnc* NOTICE * :network removed; detaching\r\n")
            .await?;
        write.flush().await?;
        return Ok(None);
    }
    Ok(Some(shutdown))
}

/// Play `replay` to the client: everything buffered while detached, in
/// order, with tags the client didn't negotiate stripped. Where an upstream
/// session began, the client is reconciled to it as a client attached then
/// was. A message of a conversation `read_positions` says the account has read
/// past is not replayed; how many were not is the answer.
async fn replay_to<W>(
    write: &mut W,
    downstream_session: &mut IrcSessionState,
    replay: Replay,
    features: &UpstreamFeatures,
    audience: JoinAudience<'_>,
    untold: &mut UntoldChannels,
    read_positions: Option<&ReadPositions>,
) -> std::io::Result<usize>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let Replay {
        lines, boundaries, ..
    } = replay;
    let mut boundaries = boundaries.into_iter().peekable();
    let mut already_read = 0usize;
    let today = utc_date(epoch_millis());
    for (index, entry) in lines.into_iter().enumerate() {
        while let Some((_, began)) = boundaries.next_if(|(at, _)| *at == index) {
            let began =
                IrcSessionState::at(&began, downstream_session.names.clone(), features.clone());
            reconcile(write, downstream_session, &began, audience, untold).await?;
        }
        // A message of a conversation the account has read past is not
        // replayed: its client already showed it. Only messages have a
        // conversation, so nothing that changes membership is skipped.
        let own_nick = downstream_session.nick.clone();
        if read_positions.is_some_and(|positions| {
            positions.has_read(&entry.line, own_nick.as_deref(), &downstream_session.names)
        }) {
            already_read += 1;
            continue;
        }
        let (line, change) = downstream_session.mirror(&entry.line);
        // A channel joined in the replay is told its topic and members once
        // the replay is over, as the session knows them then: the backlog
        // keeps no member list ([`told_live_only`]).
        for channel in &change.joined {
            untold.untold(
                downstream_session.names.fold(channel.as_str()),
                channel.as_str().to_string(),
            );
        }
        // A client without server-time would show every replayed message as
        // said now; it is told when in the text itself, as ZNC tells it.
        let line = if audience.caps.server_time {
            std::borrow::Cow::Borrowed(line)
        } else {
            replayed_with_its_time(line, &today)
        };
        if let Some(line) = filter_tags(&line, audience.caps) {
            write.write_all(line.as_bytes()).await?;
            write.write_all(b"\r\n").await?;
        }
    }
    for (_, began) in boundaries {
        let began = IrcSessionState::at(&began, downstream_session.names.clone(), features.clone());
        reconcile(write, downstream_session, &began, audience, untold).await?;
    }
    Ok(already_read)
}

/// Bring the client to the session as it is now: every channel it was shown
/// joined without its topic and members is told them, as the session knows
/// them.
async fn catch_up<W>(
    write: &mut W,
    downstream_session: &mut IrcSessionState,
    current: &IrcSessionState,
    audience: JoinAudience<'_>,
    untold: &mut UntoldChannels,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    if current.nick.is_some() {
        reconcile(write, downstream_session, current, audience, untold).await?;
    }
    untold
        .tell(write, downstream_session, Some(current), audience)
        .await?;
    write.flush().await
}

/// What an attachment, welcomed and caught up, relays until it ends.
struct LiveAttachment<'a> {
    write: e6irc_edge::peer_write::DeadlineWriter<e6irc_edge::link::LineWriter>,
    client_lines: ClientLines,
    handle: &'a NetworkHandle,
    caps: AttachCaps,
    authority: AccountLease,
    greeting: Greeting<'a>,
    liveness: std::time::Duration,
    shutdown: tokio::sync::watch::Receiver<bool>,
    events: tokio::sync::broadcast::Receiver<DriverEvent>,
    replies: ReplyRoute,
    downstream_session: IrcSessionState,
    status_revision: u64,
    attach_id: u64,
    /// The ring position the client has been sent everything through.
    cursor: ReplayCursor,
    /// What the client sent before the relay began.
    pending: Vec<e6irc_proto::framing::LineEvent>,
    held: Option<AttachHeld>,
    _attachment: NetworkAttachment,
}

/// What an attachment gives its edge to hold (link version 2): its record,
/// republished whenever what it has shown its client, or read through,
/// changes.
pub(crate) struct AttachHeld {
    record: crate::core::record::AttachRecord,
    format: crate::core::RecordFormatCell,
    origin: crate::core::record::ClockOrigin,
    revision: u64,
    last: Option<bytes::Bytes>,
}

impl AttachHeld {
    /// The record of an attachment whose registration named its identity; an
    /// attachment started without one (a test's) holds none.
    fn new(holding: AttachHolding, greeting: &Greeting<'_>, account: &str) -> Option<Self> {
        let AttachHolding { format, identity } = holding;
        let (credential, shared) = identity?;
        Some(Self {
            record: crate::core::record::AttachRecord {
                account: account.to_owned(),
                credential,
                shared,
                network: greeting.network.to_owned(),
                requested_nick: greeting.requested_nick.to_owned(),
                caps: 0,
                cursor: None,
                shown_nick: None,
                shown_channels: Vec::new(),
                shown_isupport: Vec::new(),
                status_revision: 0,
            },
            format,
            origin: crate::core::record::ClockOrigin::of(
                crate::net::wall_clock(),
                crate::net::mono_clock(),
            ),
            revision: 0,
            last: None,
        })
    }

    /// Republish the record as `live` stands, after what it has written, when
    /// it changed.
    fn publish(&mut self, live: &LiveAttachment<'_>) {
        let shown = live.downstream_session.snapshot();
        self.record.caps = live.caps.bits();
        self.record.cursor = Some(live.cursor.recorded());
        self.record.shown_nick = shown.as_ref().map(|shown| shown.nick.clone());
        self.record.shown_channels = shown.map(|shown| shown.channels).unwrap_or_default();
        self.record
            .shown_isupport
            .clone_from(&live.downstream_session.features.isupport);
        self.record.status_revision = live.status_revision;
        let body = self
            .record
            .encode(self.format.get(), self.origin)
            .expect("an attachment's record is within every body bound");
        if self.last.as_ref() == Some(&body) {
            return;
        }
        self.revision += 1;
        live.write
            .get_ref()
            .link()
            .hold_record(self.revision, body.clone());
        self.last = Some(body);
    }
}

/// An attachment whose edge holds it for the next core: the body format its
/// record is written in, and — once its registration has said them — what
/// the record names beside what the relay knows: the credential, and whether
/// the network is the shared one.
pub(crate) struct AttachHolding {
    format: crate::core::RecordFormatCell,
    identity: Option<(crate::identity::CredentialId, bool)>,
}

impl AttachHolding {
    pub(crate) fn unnamed(format: crate::core::RecordFormatCell) -> Self {
        Self {
            format,
            identity: None,
        }
    }
}

impl AttachLink {
    /// Name what the record holds of the registration: the credential that
    /// authenticated the client, and whether its network is the shared one.
    pub(crate) fn name_holding(&mut self, credential: crate::identity::CredentialId, shared: bool) {
        if let Some(holding) = &mut self.holding {
            holding.identity = Some((credential, shared));
        }
    }
}

/// Relay an attachment until it ends: the network's lines to the client, the
/// client's to the network, the answers to its own commands, its liveness,
/// and its authority's end.
async fn relay_live(mut live: LiveAttachment<'_>) -> std::io::Result<AttachEnd> {
    use tokio::io::AsyncWriteExt;

    let account = live.authority.account().to_string();
    let account = account.as_str();
    let handle = live.handle;
    let attach_id = live.attach_id;
    let greeting = live.greeting;
    let audience = JoinAudience {
        handle,
        caps: live.caps,
        account,
        attach_id,
    };
    let attachment = Attachment {
        handle,
        account,
        id: attach_id,
    };
    for event in std::mem::take(&mut live.pending) {
        if let Some(end) = client_event(
            &mut live.write,
            event,
            &attachment,
            &mut live.caps,
            &live.downstream_session,
        )
        .await?
        {
            return Ok(end);
        }
    }
    let mut held = live.held.take();
    let mut parsed = Vec::new();
    // Anything the client sends shows it is there; only its silence is timed,
    // and lines written *to* it prove nothing about a half-open socket.
    let mut client_silence = SilenceDeadline::new(live.liveness);
    let mut awaiting_pong = false;
    loop {
        if let Some(held) = &mut held {
            held.publish(&live);
        }
        let LiveAttachment {
            write,
            client_lines,
            caps,
            authority,
            shutdown,
            events,
            replies,
            downstream_session,
            status_revision,
            cursor,
            ..
        } = &mut live;
        let caps_now = *caps;
        tokio::select! {
            // The account's authority or the credential ended: tell the
            // client and detach.
            revocation = authority.revoked() => {
                return detach_revoked(write, revocation).await;
            }
            // Network removed/replaced: tell the client and detach.
            res = shutdown.changed() => {
                if res.is_err() || *shutdown.borrow() {
                    // The account lifecycle revokes before it stops the
                    // account's networks, and both can be ready here at once:
                    // the network stopped because the authority ended.
                    if let Some(revocation) = authority.revocation() {
                        return detach_revoked(write, revocation).await;
                    }
                    write
                        .write_all(b":*bnc* NOTICE * :network removed; detaching\r\n")
                        .await?;
                    write.flush().await?;
                    return Ok(AttachEnd::NetworkRemoved);
                }
            }
            // The upstream's answer to this client's own command.
            line = replies.recv() => {
                write_filtered_line(write, &line, caps_now).await?;
            }
            // Upstream -> client.
            ev = events.recv() => match ev {
                Ok(event @ (DriverEvent::Line(_) | DriverEvent::Notice(_))) => {
                    if let DriverEvent::Line(entry) | DriverEvent::Notice(entry) = &event {
                        cursor.seq = entry.seq;
                    }
                    let line = event.display_line().expect("display event carries a line");
                    let (line, _) = downstream_session.mirror(line);
                    write_filtered_line(write, line, caps_now).await?;
                }
                Ok(DriverEvent::Echo { line, origin }) => {
                    // The echo took a ring position whether or not this
                    // client is sent it, so a resume never replays it.
                    cursor.seq = line.seq;
                    // The originator's own echo reaches it only when it
                    // negotiated echo-message — the same contract a real
                    // server has. Every other attached client always gets it.
                    if origin != attach_id || caps_now.echo_message {
                        write_filtered_line(write, &line.line, caps_now).await?;
                    }
                }
                Ok(DriverEvent::Status { status, revision }) => {
                    if !accept_status_revision(status_revision, revision) {
                        continue;
                    }
                    write.write_all(status_notice(status).as_bytes()).await?;
                    write.write_all(b"\r\n").await?;
                    write.flush().await?;
                }
                Ok(DriverEvent::Session(snapshot)) => {
                    downstream_session.names = handle.names();
                    let began = IrcSessionState::at(
                        &snapshot,
                        downstream_session.names.clone(),
                        UpstreamFeatures::default(),
                    );
                    let mut untold = UntoldChannels::default();
                    reconcile(write, downstream_session, &began, audience, &mut untold)
                        .await?;
                    untold
                        .tell(write, downstream_session, None, audience)
                        .await?;
                    write.flush().await?;
                }
                // The session's registration burst ended: what it said about
                // the network is told as a change to what this client was
                // welcomed with, and the client's names follow it.
                Ok(DriverEvent::Features(features)) => {
                    let now = serve::welcome_isupport(&features, handle.history().is_some());
                    let changes =
                        serve::isupport_changes(&downstream_session.features.isupport, &now);
                    let nick = downstream_session.downstream_nick().to_string();
                    for line in serve::isupport_lines(greeting.server_name, &nick, &changes) {
                        write.write_all(line.as_bytes()).await?;
                        write.write_all(b"\r\n").await?;
                    }
                    write.flush().await?;
                    downstream_session.adopt(
                        &handle.names(),
                        &UpstreamFeatures {
                            isupport: now,
                            ..features
                        },
                    );
                }
                Ok(DriverEvent::ReadMarker {
                    account: marker_account,
                    target,
                    timestamp,
                    origin,
                }) => {
                    if caps_now.read_marker
                        && origin != attach_id
                        && e6irc_proto::casemap::CaseMapping::Rfc1459.eq(&marker_account, account)
                    {
                        write
                            .write_all(
                                format!(
                                    ":*bnc* MARKREAD {target} timestamp={timestamp}\r\n"
                                )
                                .as_bytes(),
                            )
                            .await?;
                        write.flush().await?;
                    }
                }
                // A retained live-event gap cannot be repaired without risking
                // stale NICK/channel state. Surface it and detach; a reconnect
                // establishes a fresh atomic replay and authoritative session
                // snapshot instead of continuing a corrupted IRC session.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    write
                        .write_all(
                            format!(":*bnc* NOTICE * :dropped {n} line(s); client too slow\r\n")
                                .as_bytes(),
                        )
                        .await?;
                    write.flush().await?;
                    return Ok(AttachEnd::ClientTooSlow);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    return Ok(AttachEnd::DriverStopped);
                }
            },
            // Client -> upstream.
            n = client_silence.bound(client_lines.next_lines(&mut parsed)) => match n {
                None if awaiting_pong => return Ok(AttachEnd::ClientUnresponsive),
                None => {
                    awaiting_pong = true;
                    client_silence.restart();
                    write.write_all(ATTACH_LIVENESS_PING).await?;
                    write.flush().await?;
                }
                Some(Ok(false)) => return Ok(AttachEnd::ClientClosed),
                Some(Ok(true)) => {
                    awaiting_pong = false;
                    client_silence.restart();
                    for event in parsed.drain(..) {
                        if let Some(end) = client_event(write, event, &attachment, caps, downstream_session).await? {
                            return Ok(end);
                        }
                    }
                }
                Some(Err(e)) => return Err(e),
            },
        }
    }
}

/// What a client sent before [`attach`] took it that nothing has handled
/// yet: the lines the edge framed and handed over with those the registration
/// handshake read. A client need not wait for the welcome before sending — the
/// lines that arrived with its `CAP END` belong to the attached session; the
/// rest of its input it has not handed over yet follows on its link. A fresh
/// link has none.
#[derive(Default)]
pub struct ClientInput {
    pending: Vec<e6irc_proto::framing::LineEvent>,
}

/// Who an attachment is, for [`client_event`]: the network it is attached to,
/// the account it authenticated as, and its id among the network's
/// attachments. Its nick is not here: it is whatever the client has been
/// shown since its welcome ([`IrcSessionState::downstream_nick`]).
struct Attachment<'a> {
    handle: &'a NetworkHandle,
    account: &'a str,
    id: u64,
}

/// Handle one framed line from an attached client: answer what belongs to the
/// attachment itself, and send the rest to the network. `Some` ends the
/// attachment.
async fn client_event<W>(
    write: &mut W,
    event: e6irc_proto::framing::LineEvent,
    attachment: &Attachment<'_>,
    caps: &mut AttachCaps,
    downstream_session: &IrcSessionState,
) -> std::io::Result<Option<AttachEnd>>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use e6irc_proto::framing::LineEvent;
    use tokio::io::AsyncWriteExt;

    match event {
        LineEvent::Line(line) => match String::from_utf8(line) {
            Ok(text) => {
                let msg = match parse_client_line(&text) {
                    Ok(msg) => msg,
                    Err(error) => {
                        write_client_line_error(write, error).await?;
                        return Ok(None);
                    }
                };
                // Attach-local protocol state must never be
                // forwarded onto the account's shared
                // upstream connection. CAP mutates only
                // this downstream's view; SASL is already
                // complete; history and markers belong to
                // the BNC store; liveness and QUIT concern
                // this one downstream transport, while the
                // upstream session outlives every client.
                let mut handled = true;
                let cmd = msg.command.to_ascii_uppercase();
                let params: Vec<&str> = msg.params.to_vec();
                match cmd.as_str() {
                    "PING" => match params.first() {
                        Some(token) => {
                            write.write_all(attach_pong(token).as_bytes()).await?;
                            write.flush().await?;
                        }
                        None => {
                            write_attach_numeric(
                                write,
                                downstream_session.downstream_nick(),
                                409,
                                None,
                                "No origin specified",
                            )
                            .await?;
                        }
                    },
                    // A reply, never a request: it answers
                    // nothing the upstream asked this client.
                    "PONG" => {}
                    "QUIT" => {
                        write.write_all(ATTACH_QUIT_REPLY).await?;
                        write.flush().await?;
                        return Ok(Some(AttachEnd::ClientQuit));
                    }
                    "CAP" => {
                        let target = downstream_session.downstream_nick();
                        let mut cap_open = false;
                        serve::handle_cap(write, "*bnc*", target, &msg, true, &mut cap_open, caps)
                            .await?;
                    }
                    "AUTHENTICATE" => {
                        write_attach_numeric(
                            write,
                            downstream_session.downstream_nick(),
                            907,
                            None,
                            "You have already authenticated",
                        )
                        .await?;
                    }
                    "CHATHISTORY" if caps.chathistory => {
                        chathistory::handle_chathistory(attachment.handle, write, *caps, &params)
                            .await?;
                    }
                    "CHATHISTORY" => chathistory::refuse_without_cap(write).await?,
                    "MARKREAD" if caps.read_marker => {
                        chathistory::handle_markread(
                            attachment.handle,
                            write,
                            attachment.account,
                            attachment.id,
                            &params,
                        )
                        .await?;
                    }
                    "MARKREAD" => {
                        write_attach_numeric(
                            write,
                            downstream_session.downstream_nick(),
                            421,
                            Some(MiddleParam::echo("MARKREAD")),
                            "Unknown command",
                        )
                        .await?;
                    }
                    "NICK" | "JOIN"
                        if attachment.handle.session_authority() == SessionAuthority::Provider =>
                    {
                        answer_provider_session_command(
                            write,
                            &cmd,
                            &params,
                            attachment,
                            *caps,
                            downstream_session,
                        )
                        .await?;
                    }
                    _ => handled = false,
                }
                if !handled {
                    match attachment.handle.send_from(attachment.id, &text) {
                        SendOutcome::Sent => {}
                        // Full: the connected upstream is congested.
                        // Drop this line loudly rather than block —
                        // blocking here would stall every other client
                        // sharing this network's queue. Never silent.
                        SendOutcome::Full => {
                            write
                                .write_all(
                                    b":*bnc* NOTICE * :upstream busy; line not sent, try again\r\n",
                                )
                                .await?;
                            write.flush().await?;
                        }
                        SendOutcome::Closed => {
                            return Ok(Some(AttachEnd::DriverStopped));
                        }
                        SendOutcome::Disconnected => {
                            let notice = unsent_notice(&text, NOT_CONNECTED);
                            write.write_all(format!("{notice}\r\n").as_bytes()).await?;
                            write.flush().await?;
                        }
                        SendOutcome::Unavailable => {
                            write
                                .write_all(
                                    b":*bnc* NOTICE * :upstream registration is parked; reconfigure the network before sending\r\n",
                                )
                                .await?;
                            write.flush().await?;
                        }
                        SendOutcome::Rejected(error) => {
                            // The attach path validates before handling
                            // local commands. Keep the shared queue
                            // boundary authoritative as well, so future
                            // callers cannot bypass the same contract.
                            write_client_line_error(write, error).await?;
                        }
                    }
                }
            }
            // This relay is UTF-8, like the core ingest
            // path; reject a non-UTF-8 line loudly, with the
            // same FAIL the core and the handshake answer.
            Err(error) => {
                let fail = crate::core::invalid_utf8_fail("*bnc*", error.as_bytes());
                write.write_all(format!("{fail}\r\n").as_bytes()).await?;
                write.flush().await?;
            }
        },
        // The framing contract forbids silently dropping an
        // over-long line; tell the client its line was not
        // relayed rather than swallowing it. Its label is not
        // answered under, like every attach-local reply: the
        // attach listener does not offer `labeled-response`.
        LineEvent::TooLong { .. } => {
            write_client_line_error(write, ClientLineError::TooLong).await?;
        }
    }
    Ok(None)
}

/// Answer a `NICK` or `JOIN` on a network whose session a provider account
/// owns ([`SessionAuthority::Provider`]) as a server answers its own client.
/// Neither can change that session — the nick is the account's name and the
/// channels are the bridge's configuration — so neither is sent to the bridge:
///
/// - `NICK` to the nick the client already has is answered with nothing, as a
///   server does; any other nick is refused with `447` (the numeric servers
///   use for "you may not change your nick here"), to this client alone.
/// - `JOIN` of a bridged channel re-states the membership to this client
///   (`JOIN`, and the member list ending in `366`), which is what a client
///   that joins before it speaks — `e6irc send` — waits for. Any other
///   channel is `403`; while the bridge has not connected yet its channels
///   are not known, and every channel is `437` (temporarily unavailable).
async fn answer_provider_session_command<W>(
    write: &mut W,
    command: &str,
    params: &[&str],
    attachment: &Attachment<'_>,
    caps: AttachCaps,
    downstream: &IrcSessionState,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let current = downstream
        .snapshot()
        .expect("downstream IRC state is initialized before a client line is handled");
    let nick = current.nick.as_str();
    let Some(&first) = params.first().filter(|first| !first.is_empty()) else {
        return match command {
            "NICK" => write_attach_numeric(write, nick, 431, None, "No nickname given").await,
            _ => {
                write_attach_numeric(
                    write,
                    nick,
                    461,
                    Some(MiddleParam::echo(command)),
                    "Not enough parameters",
                )
                .await
            }
        };
    };
    if command == "NICK" {
        if downstream.names.eq(first, nick) {
            return Ok(());
        }
        return write_attach_numeric(
            write,
            nick,
            447,
            None,
            "Cannot change nickname: on a bridge the nick is the provider account's name, \
             which only the provider changes",
        )
        .await;
    }
    let connected = attachment.handle.irc_session_snapshot().is_some();
    for channel in first.split(',').filter(|channel| !channel.is_empty()) {
        let shown = MiddleParam::echo(channel);
        match downstream.channels.get(&downstream.names.fold(channel)) {
            Some(bridged) => {
                let audience = JoinAudience {
                    handle: attachment.handle,
                    caps,
                    account: attachment.account,
                    attach_id: attachment.id,
                };
                write_join(write, nick, bridged.as_str(), audience).await?;
                write_unknown_members(write, nick, bridged.as_str(), None, audience, &mut 0)
                    .await?;
            }
            None if !connected => {
                write_attach_numeric(
                    write,
                    nick,
                    437,
                    Some(shown),
                    "The bridge has not connected yet; it is in its channels once it has",
                )
                .await?;
            }
            None => {
                write_attach_numeric(
                    write,
                    nick,
                    403,
                    Some(shown),
                    "No such channel: this bridge relays only the channels its configuration maps",
                )
                .await?;
            }
        }
    }
    write.flush().await
}

/// The bouncer's own liveness check of an attached client. Its `PONG` is
/// consumed by the attach loop like any other, and never reaches the upstream.
const ATTACH_LIVENESS_PING: &[u8] = b":*bnc* PING :*bnc*-liveness\r\n";

async fn write_filtered_line<W>(write: &mut W, line: &str, caps: AttachCaps) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    if let Some(line) = filter_tags(line, caps) {
        write.write_all(line.as_bytes()).await?;
        write.write_all(b"\r\n").await?;
        write.flush().await?;
    }
    Ok(())
}

/// What a raw attached client reads after its `QUIT`, before the stream closes.
const ATTACH_QUIT_REPLY: &[u8] =
    b":*bnc* ERROR :Closing Link: client detached; the network session keeps running\r\n";

/// The bouncer's own answer to an attached client's `PING`, cut to the wire
/// limit the way the delivery funnel cuts any other over-long reply.
fn attach_pong(token: &str) -> String {
    const HEAD: &str = ":*bnc* PONG *bnc* :";
    let budget = e6irc_proto::message::MAX_LINE_LEN - 2 - HEAD.len();
    let token = e6irc_proto::message::truncate_on_char_boundary(token, budget);
    format!("{HEAD}{token}\r\n")
}

/// A `*bnc*` numeric to one attached client. The echoed token is a
/// [`MiddleParam`], so raw client text (`JOIN :#a b`, `JOIN ::x`) cannot reach
/// a middle position; the target nick, the upstream's to choose, is one too,
/// and the trailing is fitted to the line.
async fn write_attach_numeric<W>(
    write: &mut W,
    nick: &str,
    numeric: u16,
    middle: Option<MiddleParam<'_>>,
    trailing: &str,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let nick = MiddleParam::echo(nick);
    let middle = middle.map_or_else(String::new, |value| format!(" {value}"));
    let line = crate::core::fitted_line(format!(":*bnc* {numeric:03} {nick}{middle} :"), trailing);
    write.write_all(format!("{line}\r\n").as_bytes()).await?;
    write.flush().await
}

/// Fuzzing-only re-exports of the internal line-processing functions.
///
/// Compiled *only* under cargo-fuzz's `--cfg fuzzing` (never in a normal build,
/// `cargo test`, or the shipped binary), so it does not widen the crate's real
/// public surface — it exists solely to let a fuzz target reach the functions
/// that turn hostile *upstream* bytes into what an attached client sees. The
/// core fuzzers drive the server side; nothing else reaches these.
#[cfg(fuzzing)]
pub mod fuzz {
    pub use super::AttachCaps;

    /// Wrapper over the crate-private [`super::filter_tags`]; a thin `pub fn`
    /// leaves the original's visibility unchanged (it is not re-exported).
    pub fn filter_tags(line: &str, caps: AttachCaps) -> Option<String> {
        super::filter_tags(line, caps)
    }

    /// Wrapper over [`crate::sanitize::upstream_line`].
    pub fn upstream_line(line: String) -> String {
        crate::sanitize::upstream_line(line)
    }
}

/// Whom a synthesized JOIN is written for: the network, what the client
/// negotiated, the account whose read markers it carries, and the attachment
/// the channel's member list and topic are asked for on behalf of.
#[derive(Clone, Copy)]
struct JoinAudience<'a> {
    handle: &'a NetworkHandle,
    caps: AttachCaps,
    account: &'a str,
    attach_id: u64,
}

/// Where the attaching account stopped reading each conversation of one
/// network (its `draft/read-marker` positions), which decides where its replay
/// of each conversation starts.
enum ReadPositions {
    /// The account has read up to these times, by folded conversation name.
    Known(std::collections::HashMap<String, e6irc_proto::time::Millis>),
    /// The network keeps no read markers.
    None,
    /// The store could not say; the whole backlog is replayed, and the client
    /// is told why.
    Unavailable,
}

impl ReadPositions {
    async fn of(handle: &NetworkHandle, account: &str) -> Self {
        let Some(history) = handle.history() else {
            return Self::None;
        };
        let casemapping = handle.names().casemapping();
        match crate::db::bnc_read_markers(&history.pool, account, &history.network, casemapping)
            .await
        {
            Ok(markers) => Self::Known(
                markers
                    .into_iter()
                    .filter_map(|(target, timestamp)| {
                        e6irc_proto::time::parse_server_time_millis(&timestamp)
                            .map(|read| (target, read))
                    })
                    .collect(),
            ),
            Err(error) => {
                eprintln!(
                    "bnc: read markers of {account}/{} unreadable: {error}",
                    history.network
                );
                Self::Unavailable
            }
        }
    }

    /// Whether `line` is a message of a conversation this account has read
    /// past: at or before its read marker for that conversation.
    fn has_read(
        &self,
        line: &str,
        own_nick: Option<&str>,
        names: &e6irc_client::NetworkNames,
    ) -> bool {
        let Self::Known(read) = self else {
            return false;
        };
        let Some(target) = crate::db::bnc_line_target(line, own_nick, names) else {
            return false;
        };
        let Some(marker) = read.get(&names.fold(&target)) else {
            return false;
        };
        e6irc_proto::message::Message::parse(line)
            .ok()
            .and_then(|message| {
                message
                    .tag("time")
                    .and_then(|tag| tag.value.as_deref())
                    .and_then(e6irc_proto::time::parse_server_time_millis)
            })
            .is_some_and(|sent| sent <= *marker)
    }
}

/// Bring one client from the state it has been shown (`downstream`) to
/// `target`: the `NICK`, `PART`s and `JOIN`s that take it there. A joined
/// channel whose topic and members `target` knows is told them at once, as a
/// server follows a `JOIN`; one it does not is noted in `untold`, to be told
/// what the session knows once the replay is over.
async fn reconcile<W>(
    write: &mut W,
    downstream: &mut IrcSessionState,
    target: &IrcSessionState,
    audience: JoinAudience<'_>,
    untold: &mut UntoldChannels,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let snapshot = target
        .snapshot()
        .expect("a client is reconciled only to a begun session");
    let names = downstream.names.clone();
    let current = downstream
        .snapshot()
        .expect("downstream IRC state is initialized before reconciliation");
    if !names.eq(&current.nick, &snapshot.nick) {
        let nick = format!(":{} NICK :{}", current.nick, snapshot.nick);
        write_synthesized(write, &[nick], "your nick changed").await?;
    }
    let wanted: std::collections::HashMap<String, &str> = snapshot
        .channels
        .iter()
        .map(|channel| (names.fold(channel), channel.as_str()))
        .collect();
    for channel in &current.channels {
        if !wanted.contains_key(&names.fold(channel)) {
            untold.told(&names.fold(channel));
            let nick = &snapshot.nick;
            write_synthesized(
                write,
                &[
                    format!(
                        ":{nick}!{SYNTHESIZED_USER_HOST} PART {channel} :upstream session reset"
                    ),
                    format!(":{nick}!{SYNTHESIZED_USER_HOST} PART {channel}"),
                    format!(":{nick} PART {channel}"),
                ],
                "you left a channel",
            )
            .await?;
        }
    }
    for channel in &snapshot.channels {
        let folded = names.fold(channel);
        if downstream.channels.contains_key(&folded) {
            continue;
        }
        // This JOIN is synthesized because the real one is not in the replay
        // (or, on a bridge, there never was one).
        write_join(write, &snapshot.nick, channel, audience).await?;
        match target.view(channel).filter(|view| view.members_known()) {
            Some(view) => {
                write_view(write, &snapshot.nick, channel, view, &target.features).await?
            }
            None => untold.untold(folded, channel.clone()),
        }
    }
    downstream.replace(&snapshot);
    Ok(())
}

/// Most channels whose member list one attach asks the upstream for, on the
/// attaching client's behalf, when the session does not know it (its list
/// was past [`channel_views::MAX_TRACKED_MEMBERSHIPS`]). Every such question
/// is a line of the network's flood allowance
/// ([`irc_driver::UPSTREAM_LINE_BURST`]) and waits in the queue every
/// attached client shares, so a client joined to hundreds of channels could
/// otherwise hold that queue for minutes with each attach; the rest are
/// named, and `/NAMES` asks for one.
const ATTACH_UPSTREAM_QUERIES: usize = 2;

/// The channels a client was shown joined whose topic and member list it has
/// not been told yet, by folded name, as it was shown them.
#[derive(Default)]
struct UntoldChannels(std::collections::BTreeMap<String, String>);

impl UntoldChannels {
    fn untold(&mut self, folded: String, channel: String) {
        self.0.insert(folded, channel);
    }

    /// The client was told `folded`'s topic and members (the lines that
    /// followed its real `JOIN`), or left it.
    fn told(&mut self, folded: &str) {
        self.0.remove(folded);
    }

    /// Tell the client each channel it is still in: what `known` (the
    /// session now) knows of it, or else its member list asked of the
    /// upstream (at most [`ATTACH_UPSTREAM_QUERIES`] of them) or, when it
    /// cannot be asked, a list naming the client alone and why.
    async fn tell<W>(
        &mut self,
        write: &mut W,
        downstream: &IrcSessionState,
        known: Option<&IrcSessionState>,
        audience: JoinAudience<'_>,
    ) -> std::io::Result<()>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        let nick = downstream.downstream_nick();
        let mut queries = ATTACH_UPSTREAM_QUERIES;
        for (folded, channel) in std::mem::take(&mut self.0) {
            if !downstream.channels.contains_key(&folded) {
                continue;
            }
            let view = known.and_then(|state| state.view(&channel));
            if let (Some(view), Some(known)) = (view.filter(|view| view.members_known()), known) {
                write_view(write, nick, &channel, view, &known.features).await?;
                continue;
            }
            write_unknown_members(write, nick, &channel, view, audience, &mut queries).await?;
        }
        Ok(())
    }
}

/// Tell one client it is in `channel` as `nick`, as a server's `JOIN` does:
/// the JOIN, and the channel's read marker when the client asked for read
/// markers. The topic and members follow from what the session knows.
async fn write_join<W>(
    write: &mut W,
    nick: &str,
    channel: &str,
    audience: JoinAudience<'_>,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let JoinAudience {
        handle,
        caps,
        account,
        ..
    } = audience;
    write_synthesized(
        write,
        &[
            format!(":{nick}!{SYNTHESIZED_USER_HOST} JOIN {channel}"),
            format!(":{nick} JOIN {channel}"),
        ],
        "you are in a channel",
    )
    .await?;
    if caps.read_marker {
        match handle.history() {
            Some(history) => {
                let casemapping = handle.names().casemapping();
                chathistory::send_read_marker(write, &history, casemapping, account, channel)
                    .await?;
            }
            None => {
                let line = crate::core::HistoryFail::TemporarilyUnavailable.line(
                    "*bnc*",
                    "MARKREAD",
                    &[channel],
                    "read markers are not configured",
                );
                write.write_all(format!("{line}\r\n").as_bytes()).await?;
            }
        }
    }
    Ok(())
}

/// A channel's topic (when known) and complete member list, as the server
/// answers a `JOIN` with them.
async fn write_view<W>(
    write: &mut W,
    nick: &str,
    channel: &str,
    view: &channel_views::ChannelView,
    features: &UpstreamFeatures,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let target = MiddleParam::echo(nick).to_string();
    let lines = view
        .topic_reply("*bnc*", &target, channel)
        .into_iter()
        .flatten()
        .chain(
            view.names_reply("*bnc*", &target, channel, features)
                .into_iter()
                .flatten(),
        );
    for line in lines {
        write_synthesized(write, &[line], "the channel's topic or member list").await?;
    }
    Ok(())
}

/// A channel whose member list the session does not know: on an IRC network
/// it is asked for on this client's behalf while `queries` last, and the
/// answer reaches this client alone (§10.1's reply routing), as a server's own
/// answer to a JOIN would; otherwise — a bridge, whose provider has no member
/// list to ask, or an upstream that cannot be asked now — the client is shown
/// alone in it, and on an IRC network told why and how to ask.
async fn write_unknown_members<W>(
    write: &mut W,
    nick: &str,
    channel: &str,
    view: Option<&channel_views::ChannelView>,
    audience: JoinAudience<'_>,
    queries: &mut usize,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let JoinAudience {
        handle, attach_id, ..
    } = audience;
    if handle.session_authority() == SessionAuthority::Upstream {
        let topic_known = view.is_some_and(|view| *view.topic() != channel_views::Topic::Unknown);
        if *queries > 0 {
            let verbs: &[&str] = if topic_known {
                &["NAMES"]
            } else {
                &["TOPIC", "NAMES"]
            };
            let asked = verbs.iter().all(|verb| {
                handle.send_from(attach_id, &format!("{verb} {channel}")) == SendOutcome::Sent
            });
            if asked {
                *queries -= 1;
                return Ok(());
            }
        }
        write_synthesized(
            write,
            &[format!(
                ":*bnc* NOTICE {channel} :the member list is not known here and was not asked \
                 for now (/NAMES asks the network); you are shown alone"
            )],
            "the channel's member list is unavailable",
        )
        .await?;
    }
    let target = MiddleParam::echo(nick);
    write_synthesized(
        write,
        &[format!(":*bnc* 353 {target} = {channel} :{nick}")],
        "the channel's member list",
    )
    .await?;
    let end = format!(":*bnc* 366 {target} {channel} :");
    let end = format!(
        "{end}{}",
        crate::core::fit_trailing(&end, "End of /NAMES list")
    );
    write_synthesized(write, &[end], "the end of the channel's member list").await
}

/// The `user@host` of a prefix the bouncer makes for the session's own nick.
const SYNTHESIZED_USER_HOST: &str = "~bnc@e6irc";

/// Write the first of `candidates` — the same statement, each shorter than
/// the one before — that fits one IRC line. Every name in them is the
/// upstream's to choose, up to what the protocol allows, so none may fit; the
/// client is then told what could not be said, within the limit, rather than
/// sent a line its framing would discard.
async fn write_synthesized<W>(
    write: &mut W,
    candidates: &[String],
    what: &str,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let line = candidates
        .iter()
        .find(|line| line.len() + 2 <= e6irc_proto::message::MAX_LINE_LEN)
        .cloned()
        .unwrap_or_else(|| {
            format!(
                ":*bnc* NOTICE * :a line telling you that {what} was not sent: \
                 its names do not fit one IRC line"
            )
        });
    write.write_all(line.as_bytes()).await?;
    write.write_all(b"\r\n").await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A backlog row stored at `stored_at` before migration 0096, which
    /// recorded no nick with it.
    fn stored_line(line: impl Into<String>, stored_at: &str) -> crate::db::StoredBacklogLine {
        stored_under(line, stored_at, crate::db::StoredOwnNick::NotRecorded)
    }

    /// A backlog row stored at `stored_at` with `own_nick` recorded.
    fn stored_under(
        line: impl Into<String>,
        stored_at: &str,
        own_nick: crate::db::StoredOwnNick,
    ) -> crate::db::StoredBacklogLine {
        crate::db::StoredBacklogLine {
            line: line.into(),
            stored_at: stored_at.into(),
            own_nick,
            seq: None,
        }
    }

    /// `lines` as they were emitted, without the `time` the bouncer stamps
    /// on every line it takes in.
    fn untimed<S: AsRef<str>>(lines: impl IntoIterator<Item = S>) -> Vec<String> {
        lines
            .into_iter()
            .map(|line| without_tag(line.as_ref(), "time"))
            .collect()
    }

    /// The rejection an upstream's pre-welcome `line` makes, read by the same
    /// public table every driver reads.
    fn refused_by(line: &str) -> e6irc_client::RegistrationRejection {
        let parsed = e6irc_proto::message::Message::parse(line).expect("a scripted reply parses");
        e6irc_client::RegistrationRejection::from_reply(
            &e6irc_client::OwnedMessage::from(&parsed),
            e6irc_client::ServerPasswordSent::No,
        )
        .expect("a scripted refusal")
    }

    /// A bridged account shown as `name!name@host`: the first account a fresh
    /// session sees under a name no one else holds.
    #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
    fn shown(host: &str, name: &str) -> irc_driver::SelfIdentity {
        BridgedSenders::new(ProviderAccount {
            id: "the owner",
            name: "the owner",
            user: "the owner",
            host,
        })
        .identity(ProviderAccount {
            id: name,
            name,
            user: name,
            host,
        })
    }

    fn driver_factory_error(
        kind: crate::config::NetworkKind,
        addr: &str,
        nick: &str,
        account: Option<&str>,
        password: Option<&str>,
    ) -> String {
        build_driver(DriverSpec {
            kind,
            owner: Some("owner".into()),
            name: "network".into(),
            addr: addr.into(),
            tls: true,
            nick: nick.into(),
            username: (kind == crate::config::NetworkKind::Irc).then(|| "ident".into()),
            realname: nick.into(),
            autojoin: vec![],
            buffer_cap: 16,
            sasl_account: account.map(str::to_string),
            sasl_password: password.map(str::to_string),
            server_password: None,
            internal_upstreams: crate::egress::InternalUpstreams::Refuse,
            first_dial: FirstDial::Immediate,
        })
        .err()
        .expect("invalid driver configuration should be rejected")
    }

    // A bridge kind's fields are validated in every build; a build without the
    // bridge's feature then refuses a complete, valid network of that kind by
    // name, and never builds a driver of another kind for it. Each test is
    // compiled only where its refusal exists, so the default build (no bridge
    // features) runs all three.

    #[cfg(not(feature = "matrix"))]
    #[test]
    fn a_build_without_matrix_refuses_a_valid_matrix_network_by_name() {
        assert_eq!(
            driver_factory_error(
                crate::config::NetworkKind::Matrix,
                "https://matrix.example",
                "@bot:matrix.example",
                None,
                Some("login password"),
            ),
            "kind=matrix but this binary was built without the `matrix` feature"
        );
    }

    #[cfg(not(feature = "discord"))]
    #[test]
    fn a_build_without_discord_refuses_a_valid_discord_network_by_name() {
        assert_eq!(
            driver_factory_error(
                crate::config::NetworkKind::Discord,
                "https://discord.com/api",
                "",
                None,
                Some("bot-token"),
            ),
            "kind=discord but this binary was built without the `discord` feature"
        );
    }

    #[cfg(not(feature = "slack"))]
    #[test]
    fn a_build_without_slack_refuses_a_valid_slack_network_by_name() {
        assert_eq!(
            driver_factory_error(
                crate::config::NetworkKind::Slack,
                "https://slack.com/api",
                "",
                Some("xoxb-bot-token"),
                Some("xapp-app-token"),
            ),
            "kind=slack but this binary was built without the `slack` feature"
        );
    }

    /// A channel key is a `JOIN` parameter of an IRC channel: a bridge's rooms
    /// and channel ids have none, and a key that is not one parameter is
    /// refused before a driver exists, never shown in the refusal.
    #[test]
    fn a_channel_key_is_irc_only_and_one_parameter() {
        use crate::config::NetworkKind;
        let spec = |kind: NetworkKind, addr: &str, nick: &str, key: &str| DriverSpec {
            kind,
            owner: Some("owner".into()),
            name: "network".into(),
            addr: addr.into(),
            tls: true,
            nick: nick.into(),
            username: (kind == NetworkKind::Irc).then(|| "ident".into()),
            realname: nick.into(),
            autojoin: vec![AutojoinEntry {
                channel: "#staff".into(),
                key: Some(key.into()),
            }],
            buffer_cap: 16,
            sasl_account: None,
            sasl_password: (kind != NetworkKind::Irc).then(|| "token".into()),
            server_password: None,
            internal_upstreams: crate::egress::InternalUpstreams::Refuse,
            first_dial: FirstDial::Immediate,
        };
        let error = build_driver(spec(NetworkKind::Discord, "", "", "k3y"))
            .err()
            .expect("a bridge takes no key");
        assert!(error.contains("does not accept channel keys"), "{error}");
        let error = build_driver(spec(
            NetworkKind::Irc,
            "irc.example:6697",
            "alice",
            "two words",
        ))
        .err()
        .expect("a key is one parameter");
        assert!(error.contains("autojoin keys must be one word"), "{error}");
        assert!(!error.contains("two words"), "{error}");
        assert!(build_driver(spec(NetworkKind::Irc, "irc.example:6697", "alice", "k3y")).is_ok());
    }

    /// A server password is an IRC connection's `PASS`: a bridge has no such
    /// line, and a value that cannot travel in one is refused before a driver
    /// exists, naming the field and never the value.
    #[test]
    fn a_server_password_is_irc_only_and_fits_one_line() {
        use crate::config::NetworkKind;
        let spec = |kind: NetworkKind,
                    addr: &str,
                    nick: &str,
                    password: Option<&str>,
                    server_password: &str| DriverSpec {
            kind,
            owner: Some("owner".into()),
            name: "network".into(),
            addr: addr.into(),
            tls: true,
            nick: nick.into(),
            username: (kind == NetworkKind::Irc).then(|| "ident".into()),
            realname: nick.into(),
            autojoin: vec![],
            buffer_cap: 16,
            sasl_account: None,
            sasl_password: password.map(str::to_string),
            server_password: Some(server_password.into()),
            internal_upstreams: crate::egress::InternalUpstreams::Refuse,
            first_dial: FirstDial::Immediate,
        };
        for (kind, addr, nick) in [
            (
                NetworkKind::Matrix,
                "https://matrix.example",
                "@bot:example",
            ),
            (NetworkKind::Discord, "https://discord.com/api", ""),
            (NetworkKind::Slack, "https://slack.com/api", ""),
        ] {
            let error = build_driver(spec(kind, addr, nick, Some("secret"), "pass"))
                .err()
                .expect("a bridge takes no server password");
            assert!(error.contains("server password"), "{error}");
        }
        let error = build_driver(spec(
            NetworkKind::Irc,
            "irc.example:6697",
            "nick",
            None,
            "open\r\nQUIT",
        ))
        .err()
        .expect("a delimiter cannot travel in PASS");
        assert!(error.contains("server password"), "{error}");
        assert!(!error.contains("QUIT"), "{error}");
        assert!(
            build_driver(spec(
                NetworkKind::Irc,
                "irc.example:6697",
                "nick",
                None,
                "open sesame"
            ))
            .is_ok()
        );
    }

    #[test]
    fn driver_factory_rejects_incomplete_credentials_before_any_connection() {
        use crate::config::NetworkKind;
        assert!(
            driver_factory_error(NetworkKind::Irc, "missing-port", "nick", None, None)
                .contains("host:port")
        );
        assert!(
            driver_factory_error(
                NetworkKind::Irc,
                "irc.example:6697",
                "nick",
                Some("account"),
                None
            )
            .contains("both a SASL account and password")
        );
        assert!(
            driver_factory_error(
                NetworkKind::Matrix,
                "https://matrix.example",
                "@user:example",
                None,
                None,
            )
            .contains("login password")
        );
        assert!(
            driver_factory_error(NetworkKind::Discord, "", "", None, None).contains("bot token")
        );
        assert!(
            driver_factory_error(NetworkKind::Slack, "", "", Some("xoxb-token"), None)
                .contains("app token")
        );
    }

    #[test]
    fn driver_factory_rejects_malformed_bridge_bases_before_feature_gating() {
        use crate::config::NetworkKind;
        let invalid = [
            "ftp://matrix.example",
            "https://user@matrix.example",
            "https://matrix.example?tenant=one",
            "matrix.example",
        ];
        for addr in invalid {
            let error = driver_factory_error(
                NetworkKind::Matrix,
                addr,
                "@user:example",
                None,
                Some("secret"),
            );
            assert!(error.contains("base URL"), "{addr}: {error}");
        }
        assert!(
            driver_factory_error(
                NetworkKind::Matrix,
                "",
                "@user:example",
                None,
                Some("secret")
            )
            .contains("homeserver URL")
        );
    }

    #[test]
    fn stored_bridge_factory_rejects_noncanonical_realname_before_secrets() {
        let row = crate::db::BncNetworkRow {
            kind: crate::config::NetworkKind::Discord,
            name: "discord".into(),
            addr: String::new(),
            tls: true,
            nick: String::new(),
            username: None,
            realname: Some("silently ignored before this invariant".into()),
            autojoin: vec![],
            sasl_account: None,
            sasl_password_sealed: Some("sealed-but-no-key".into()),
            enabled: false,
            server_password_sealed: None,
        };
        let error = driver_from_row(
            &row,
            None,
            "owner",
            crate::egress::InternalUpstreams::Refuse,
            FirstDial::Immediate,
        )
        .err()
        .expect("noncanonical stored bridge should be rejected");
        assert!(error.contains("real name field"), "{error}");
    }

    #[test]
    fn stored_irc_factory_requires_realname() {
        let row = crate::db::BncNetworkRow {
            kind: crate::config::NetworkKind::Irc,
            name: "libera".into(),
            addr: "irc.libera.chat:6697".into(),
            tls: true,
            nick: "alice".into(),
            username: Some("alice".into()),
            realname: None,
            autojoin: vec![],
            sasl_account: None,
            sasl_password_sealed: None,
            enabled: false,
            server_password_sealed: None,
        };
        let error = driver_from_row(
            &row,
            None,
            "owner",
            crate::egress::InternalUpstreams::Refuse,
            FirstDial::Immediate,
        )
        .err()
        .expect("stored IRC network without realname should fail");
        assert!(error.contains("no realname"), "{error}");
    }

    #[test]
    fn a_send_without_a_session_is_refused_not_queued() {
        let (handle, ends) = NetworkHandle::channels(16);
        assert_eq!(
            handle.send("PRIVMSG #room :early"),
            SendOutcome::Disconnected
        );
        ends.begin_attempt();
        ends.emit(ConnectionEvent::Connected);
        assert_eq!(handle.send("PRIVMSG #room :now"), SendOutcome::Sent);
        ends.emit(ConnectionEvent::Reconnecting(
            NetworkFailure::ConnectionLost,
        ));
        assert_eq!(
            handle.send("PRIVMSG #room :late"),
            SendOutcome::Disconnected
        );
        ends.emit(ConnectionEvent::RegainingNickname(NicknameRegain::new(
            "alice_", "alice",
        )));
        assert_eq!(
            handle.send("PRIVMSG #room :waits for the nickname"),
            SendOutcome::Sent,
            "a session under the alternative nickname holds what is sent"
        );
    }

    /// A line still queued when its session ends is never sent: its sender
    /// is told, by command and target and never by its text, as soon as the
    /// driver says it is reconnecting; another attachment hears nothing.
    #[tokio::test]
    async fn a_line_queued_when_the_session_ends_is_told_unsent() {
        let (handle, mut ends) = NetworkHandle::channels(16);
        let mut sender = handle.route_replies(5);
        let mut other = handle.route_replies(6);
        ends.begin_attempt();
        ends.emit(ConnectionEvent::Connected);
        for line in ["PRIVMSG NickServ :IDENTIFY hunter2", "JOIN #later"] {
            assert_eq!(handle.send_from(5, line), SendOutcome::Sent);
        }
        let waited = wait_for_reconnect(
            &mut ends,
            Carried::<()> {
                config: &(),
                next: None,
            },
            ConnectionEvent::Reconnecting(NetworkFailure::ConnectionLost),
            None,
            std::time::Duration::from_secs(1),
            std::future::ready(()),
        )
        .await;
        assert!(waited);
        let first = sender.recv().await;
        assert!(
            first.ends_with(
                "your message to NickServ was not sent: the network disconnected before it went out"
            ),
            "{first}"
        );
        assert!(!first.contains("hunter2"), "{first}");
        assert!(sender.recv().await.ends_with(
            ":your JOIN #later was not sent: the network disconnected before it went out"
        ));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), other.recv())
                .await
                .is_err()
        );
        assert!(
            ends.commands.try_recv().is_err(),
            "nothing is left for the next session"
        );
    }

    /// A full command queue is told live, at the ring's position, and never
    /// retained: it repeats for every line sent while the upstream drains, and
    /// retained it evicted the conversation and was replayed, long after the
    /// congestion ended, to every client that attached.
    #[test]
    fn a_full_command_queue_is_told_live_and_never_retained() {
        let (handle, ends) = NetworkHandle::channels(16);
        handle.runtime.connected();
        ends.emit_line(":peer PRIVMSG #room :kept".to_string());
        let mut events = handle.subscribe();
        for n in 0..BNC_COMMAND_QUEUE {
            assert_eq!(
                handle.send(&format!("PRIVMSG #room :{n}")),
                SendOutcome::Sent
            );
        }
        assert_eq!(handle.send("PRIVMSG #room :one more"), SendOutcome::Full);
        let told = events.try_recv().expect("the congestion is told live");
        assert!(
            matches!(&told, DriverEvent::Notice(line) if line.line.contains("command_queue_full")),
            "{told:?}"
        );
        let backlog = handle.buffer_snapshot();
        assert_eq!(backlog.len(), 1, "{backlog:?}");
        assert!(backlog[0].ends_with(":peer PRIVMSG #room :kept"));
        assert_eq!(
            handle.runtime_snapshot().last_error,
            Some(NetworkFailure::CommandQueueFull)
        );
        drop(ends);
    }

    #[test]
    fn runtime_snapshot_tracks_lifecycle_traffic_buffers_and_attachments() {
        let (handle, ends) = NetworkHandle::channels(16);
        ends.begin_attempt();
        ends.emit(ConnectionEvent::Connected);
        ends.emit_line(":upstream PRIVMSG #room :hello".into());
        assert_eq!(handle.send("PRIVMSG #room :reply"), SendOutcome::Sent);
        let attachment = handle.track_attachment();

        let connected = handle.runtime_snapshot();
        assert_eq!(connected.lifecycle, NetworkLifecycle::Connected);
        assert_eq!(connected.connection_attempts, 1);
        assert_eq!(connected.lines_in, 1);
        assert_eq!(connected.lines_out, 1);
        assert!(connected.bytes_in > connected.bytes_out);
        assert_eq!(connected.buffer_lines, 2);
        assert_eq!(connected.buffer_capacity, 16);
        assert_eq!(connected.attached_clients, 1);
        assert!(connected.connected_at.is_some());
        assert_eq!(connected.next_retry_at, None);
        assert!(connected.last_input_at.is_some());
        assert!(connected.last_output_at.is_some());
        assert_eq!(connected.last_error, None);
        assert!(connected.connect_latency_ms.is_some());

        drop(attachment);
        ends.emit(ConnectionEvent::Reconnecting(
            NetworkFailure::ConnectionLost,
        ));
        let reconnecting = handle.runtime_snapshot();
        assert_eq!(reconnecting.lifecycle, NetworkLifecycle::Reconnecting);
        assert_eq!(reconnecting.errors, 1);
        assert_eq!(reconnecting.attached_clients, 0);
        assert_eq!(reconnecting.connected_at, None);
        assert_eq!(reconnecting.next_retry_at, None);
        assert!(reconnecting.last_error_at.is_some());
        assert_eq!(
            reconnecting.last_error,
            Some(NetworkFailure::ConnectionLost)
        );
        assert_eq!(
            reconnecting.last_error_at,
            reconnecting.recent_failures.last().map(|record| record.at),
            "the latest error and its timestamp come from one record"
        );
        // A driver's own `emit` has no attempt time to give. The shared runner
        // does, and publishes it with the failure rather than after it.

        // A terminal event carries no next attempt, whatever accompanies it:
        // there is no separate scheduling step left to revive a parked network.
        ends.publish(
            ConnectionEvent::AuthenticationFailed(None),
            Some(std::time::Duration::from_secs(1)),
            None,
        );
        let failed = handle.runtime_snapshot();
        assert_eq!(failed.lifecycle, NetworkLifecycle::AuthenticationFailed);
        assert_eq!(failed.connected_at, None);
        assert_eq!(failed.next_retry_at, None);
        assert_eq!(
            failed.last_error,
            Some(NetworkFailure::AuthenticationRejected)
        );
        assert_eq!(
            handle.runtime_snapshot().lifecycle,
            NetworkLifecycle::AuthenticationFailed
        );

        ends.emit(ConnectionEvent::RegistrationFailed(refused_by(
            ":up 432 * bnc :Erroneous nickname",
        )));
        let rejected = handle.runtime_snapshot();
        assert_eq!(rejected.lifecycle, NetworkLifecycle::RegistrationFailed);
        assert_eq!(rejected.last_error, Some(NetworkFailure::InvalidNickname));
        assert_eq!(
            rejected.last_error_diagnostic.as_deref(),
            Some("Erroneous nickname")
        );
        assert_eq!(failed.errors, 2);
        assert_eq!(rejected.buffer_lines, 5);
        assert_eq!(
            untimed(handle.buffer_snapshot()),
            vec![
                ":*bnc* NOTICE * :component connected: unregistered network".to_string(),
                ":upstream PRIVMSG #room :hello".to_string(),
                ":*bnc* NOTICE * :component reconnecting: The established upstream connection was lost. (connection_lost)".to_string(),
                ":*bnc* NOTICE * :component authentication_failed: The upstream rejected the configured credentials. (authentication_rejected)".to_string(),
                ":*bnc* NOTICE * :component registration_failed: The upstream rejected the configured nickname. (invalid_nickname); upstream: Erroneous nickname".to_string(),
            ]
        );
    }

    /// The backlog exists to keep what was said while nobody was attached. An
    /// unreachable upstream retries every few seconds for as long as the
    /// outage lasts, so its identical notices must not push that history out.
    #[test]
    fn repeated_lifecycle_notices_are_buffered_once_per_transition() {
        let (handle, ends) = NetworkHandle::channels(16);
        let mut events = handle.subscribe();
        let live_notices = |events: &mut tokio::sync::broadcast::Receiver<DriverEvent>| {
            let mut buffered = 0;
            let mut live_only = 0;
            while let Ok(event) = events.try_recv() {
                match event {
                    DriverEvent::Line(_) => buffered += 1,
                    DriverEvent::Notice(_) => live_only += 1,
                    _ => {}
                }
            }
            (buffered, live_only)
        };

        ends.emit_line(":peer PRIVMSG #room :said while detached".into());
        for _ in 0..50 {
            ends.emit(ConnectionEvent::Reconnecting(
                NetworkFailure::ConnectionLost,
            ));
        }
        assert_eq!(
            handle.buffer_snapshot().len(),
            2,
            "{:?}",
            handle.buffer_snapshot()
        );
        assert_eq!(
            live_notices(&mut events),
            (2, 49),
            "an attached client still hears every retry"
        );
        assert_eq!(handle.runtime_snapshot().errors, 50);

        // A new reason within the outage is a transition, recorded once: an
        // upstream with several addresses alternates its failures per attempt
        // (one refuses, one black-holes), and a line per attempt would fill
        // the ring over a long outage, but a reason first given mid-outage (a
        // taken nickname, a ban, a throttle) is what an attaching client must
        // learn. A recovery, and the reconnecting that follows it, are
        // transitions.
        for _ in 0..10 {
            ends.emit(ConnectionEvent::Reconnecting(
                NetworkFailure::ConnectionTimedOut,
            ));
            ends.emit(ConnectionEvent::Reconnecting(
                NetworkFailure::ConnectionLost,
            ));
        }
        assert_eq!(
            handle.buffer_snapshot().len(),
            3,
            "each reason of the reconnecting stage is retained once: {:?}",
            handle.buffer_snapshot()
        );
        assert!(
            handle.buffer_snapshot()[2].contains("(connection_timed_out)"),
            "{:?}",
            handle.buffer_snapshot()
        );
        ends.emit(ConnectionEvent::Connected);
        ends.emit(ConnectionEvent::Reconnecting(
            NetworkFailure::ConnectionLost,
        ));
        assert_eq!(
            handle.buffer_snapshot().len(),
            5,
            "a recovery and the reconnecting after it are both transitions: {:?}",
            handle.buffer_snapshot()
        );
        // Three retained (the new reason, the recovery and the reconnecting
        // after it) and nineteen live-only (the repeats within the outage).
        assert_eq!(live_notices(&mut events), (3, 19));
    }

    #[test]
    fn terminally_parked_driver_cannot_accept_an_undeliverable_command() {
        let (handle, mut ends) = NetworkHandle::channels(8);
        ends.emit(ConnectionEvent::AuthenticationFailed(None));
        assert_eq!(
            handle.send("PRIVMSG #room :this cannot drain"),
            SendOutcome::Unavailable
        );
        assert!(ends.commands.try_recv().is_err());
        assert_eq!(handle.runtime_snapshot().lines_out, 0);
    }

    #[test]
    fn replay_boundary_delivers_every_buffered_line_exactly_once() {
        let (handle, ends) = NetworkHandle::channels(8);
        ends.emit_line(":upstream PRIVMSG #room :before boundary".into());

        ends.begin_irc_session("upstream".into());
        let AttachSnapshot {
            mut events,
            replay,
            session,
            ..
        } = handle.subscribe_with_replay_snapshot(None);
        let snapshot = untimed(replay.lines.iter().map(|entry| entry.line.as_str()));
        assert_eq!(snapshot, vec![":upstream PRIVMSG #room :before boundary"]);
        assert_eq!(
            session,
            Some(IrcSessionSnapshot {
                nick: "upstream".into(),
                channels: vec![],
            })
        );
        assert_eq!(
            events.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty),
            "a replayed line must not also be queued as live traffic"
        );

        ends.emit_line(":upstream PRIVMSG #room :after boundary".into());
        assert!(
            matches!(
                events.try_recv(),
                Ok(DriverEvent::Line(BufferedLine { line, .. }))
                    if without_tag(&line, "time") == ":upstream PRIVMSG #room :after boundary"
            ),
            "a post-boundary line must be delivered live"
        );
        assert_eq!(
            snapshot,
            vec![":upstream PRIVMSG #room :before boundary"],
            "the immutable replay side cannot acquire a live line"
        );

        ends.emit_session_line(":upstream!u@h JOIN #after".into())
            .expect("within the channel limit");
        assert!(
            session
                .as_ref()
                .is_some_and(|session| session.channels.is_empty()),
            "post-boundary membership must arrive only through the event stream"
        );
    }

    #[test]
    fn driver_status_events_keep_lifecycle_and_failure_together() {
        let (handle, ends) = NetworkHandle::channels(8);
        let mut events = handle.subscribe();

        ends.emit(ConnectionEvent::Connected);
        assert_eq!(
            events.try_recv(),
            Ok(DriverEvent::Status {
                status: DriverConnectionStatus::Connected,
                revision: 1,
            })
        );
        assert!(matches!(events.try_recv(), Ok(DriverEvent::Line(_))));

        ends.emit(ConnectionEvent::Reconnecting(
            NetworkFailure::ConnectionLost,
        ));
        let reconnecting = DriverConnectionStatus::Reconnecting(NetworkFailure::ConnectionLost);
        assert_eq!(
            events.try_recv(),
            Ok(DriverEvent::Status {
                status: reconnecting,
                revision: 2,
            })
        );
        assert!(matches!(events.try_recv(), Ok(DriverEvent::Line(_))));
        assert_eq!(
            status_notice(reconnecting),
            ":*bnc* NOTICE * :upstream reconnecting: The established upstream connection was lost. (connection_lost)"
        );

        ends.emit(ConnectionEvent::RegistrationFailed(refused_by(
            ":up 432 * bnc :Erroneous nickname",
        )));
        assert_eq!(
            events.try_recv(),
            Ok(DriverEvent::Status {
                status: DriverConnectionStatus::RegistrationFailed(NetworkFailure::InvalidNickname),
                revision: 3,
            })
        );
    }

    #[test]
    fn sticky_status_revision_rejects_every_pre_snapshot_transition() {
        let (handle, ends) = NetworkHandle::channels(8);
        let mut events = handle.subscribe();

        ends.emit(ConnectionEvent::Connected);
        ends.emit(ConnectionEvent::Reconnecting(
            NetworkFailure::ConnectionLost,
        ));
        let snapshot = handle.runtime_snapshot();
        assert_eq!(snapshot.lifecycle, NetworkLifecycle::Reconnecting);
        assert_eq!(snapshot.status_revision, 2);

        let mut last_seen = snapshot.status_revision;
        let queued_revisions: Vec<u64> = std::iter::from_fn(|| events.try_recv().ok())
            .filter_map(|event| match event {
                DriverEvent::Status { revision, .. } => Some(revision),
                _ => None,
            })
            .collect();
        assert_eq!(queued_revisions, vec![1, 2]);
        assert!(
            queued_revisions
                .into_iter()
                .all(|revision| !accept_status_revision(&mut last_seen, revision))
        );

        ends.emit(ConnectionEvent::Connected);
        let revision = std::iter::from_fn(|| events.try_recv().ok())
            .find_map(|event| match event {
                DriverEvent::Status { revision, .. } => Some(revision),
                _ => None,
            })
            .expect("new status event");
        assert!(accept_status_revision(&mut last_seen, revision));
        assert_eq!(last_seen, 3);
    }

    #[test]
    fn lifecycle_notice_keeps_the_safe_upstream_diagnostic() {
        assert_eq!(
            lifecycle_notice(
                "rejected",
                NetworkFailure::RegistrationRejected,
                Some("Too many connections from your IP"),
            ),
            ":*bnc* NOTICE * :component rejected: The upstream rejected IRC registration; check the nickname and network policy. (registration_rejected); upstream: Too many connections from your IP"
        );
    }

    #[test]
    fn recoverable_error_updates_network_and_server_telemetry_together() {
        let (handle, _ends) = NetworkHandle::channels(8);
        let telemetry = std::sync::Arc::new(crate::observability::Telemetry::new());
        handle.set_telemetry(telemetry.clone());

        handle.record_error(NetworkFailure::BacklogStorageFailed);

        let runtime = handle.runtime_snapshot();
        assert_eq!(runtime.errors, 1, "{runtime:?}");
        assert!(runtime.last_error_at.is_some(), "{runtime:?}");
        assert_eq!(
            runtime.last_error,
            Some(NetworkFailure::BacklogStorageFailed),
            "{runtime:?}"
        );
        assert_eq!(telemetry.snapshot(0, 0).errors["bouncer"], 1);
        // Told live, never retained: a database away for an hour repeats this
        // for every upstream line, and a ring full of identical notices is a
        // ring with no conversation left in it.
        assert_eq!(handle.buffer_snapshot(), Vec::<String>::new());
    }

    /// A typing indicator is told live and kept out of the backlog, as the
    /// core keeps it out of history; a reaction is conversation and retained.
    /// The echo of a client's own typing indicator is not retained either.
    #[tokio::test]
    async fn a_typing_indicator_is_told_live_and_not_retained() {
        let (handle, ends) = NetworkHandle::channels(8);
        let mut events = handle.subscribe();
        ends.emit_line("@+typing=active :peer TAGMSG #room".to_string());
        ends.emit_line("@+draft/react=x;+draft/reply=m1 :peer TAGMSG #room".to_string());
        ends.emit_echo("@+draft/typing=paused :me TAGMSG #room".to_string(), 1);
        assert!(
            matches!(events.recv().await.expect("typing"), DriverEvent::Notice(_)),
            "told live, not retained"
        );
        assert!(matches!(
            events.recv().await.expect("reaction"),
            DriverEvent::Line(_)
        ));
        assert!(matches!(
            events.recv().await.expect("echo"),
            DriverEvent::Echo { .. }
        ));
        assert_eq!(
            untimed(handle.buffer_snapshot()),
            vec!["@+draft/react=x;+draft/reply=m1 :peer TAGMSG #room".to_string()]
        );
    }

    /// A CTCP request is a question to the clients attached when it is asked:
    /// told live, never retained, so no client that attaches later answers it
    /// again. A `/me` and a CTCP reply are conversation, and retained.
    #[tokio::test]
    async fn a_ctcp_request_is_told_live_and_never_retained() {
        let (handle, ends) = NetworkHandle::channels(8);
        let mut events = handle.subscribe();
        let position = handle.buffer.lock().expect("buffer").position();
        ends.emit_line(":bob!b@h PRIVMSG me :\u{1}VERSION\u{1}".to_string());
        ends.emit_line(":bob!b@h PRIVMSG #room :\u{1}PING 1234\u{1}".to_string());
        ends.emit_line(":bob!b@h PRIVMSG me :\u{1}DCC SEND f 1 2 3\u{1}".to_string());
        ends.emit_echo("PRIVMSG bob :\u{1}TIME\u{1}".to_string(), 1);
        ends.emit_line(":bob!b@h PRIVMSG #room :\u{1}ACTION waves\u{1}".to_string());
        ends.emit_line(":bob!b@h NOTICE me :\u{1}VERSION irssi\u{1}".to_string());
        for _ in 0..3 {
            assert!(matches!(
                events.recv().await.expect("request"),
                DriverEvent::Notice(_)
            ));
        }
        match events.recv().await.expect("echo") {
            DriverEvent::Echo { line, .. } => assert_eq!(line.seq, position, "not retained"),
            other => panic!("expected the echo, got {other:?}"),
        }
        assert_eq!(
            untimed(handle.buffer_snapshot()),
            vec![
                ":bob!b@h PRIVMSG #room :\u{1}ACTION waves\u{1}".to_string(),
                ":bob!b@h NOTICE me :\u{1}VERSION irssi\u{1}".to_string(),
            ]
        );
    }

    /// The topic and member list that follow our own `JOIN` are the channel's
    /// state, which the session follows and an attaching client is told from
    /// it: told live, never retained, so a rejoin after every reconnect does
    /// not put each channel's member list into the backlog in place of the
    /// conversation. The session still follows them, and answers `NAMES`.
    #[tokio::test]
    async fn a_channels_topic_and_members_are_told_live_and_never_retained() {
        let (handle, ends) = NetworkHandle::channels(8);
        ends.begin_irc_session("me".to_string());
        ends.emit_session_line(":up 376 me :End of MOTD".to_string())
            .expect("the burst ends");
        let mut events = handle.subscribe();
        for line in [
            ":me!u@h JOIN #room",
            ":up 332 me #room :the topic",
            ":up 333 me #room setter 1700000000",
            ":up 353 me = #room :me @op",
            ":up 366 me #room :End of /NAMES list.",
            ":op!o@h PRIVMSG #room :hello",
        ] {
            ends.emit_session_line(line.to_string())
                .expect("within the channel bound");
        }
        let mut kinds = Vec::new();
        for _ in 0..6 {
            kinds.push(match events.recv().await.expect("event") {
                DriverEvent::Line(_) => "line",
                DriverEvent::Notice(_) => "notice",
                other => panic!("unexpected {other:?}"),
            });
        }
        assert_eq!(
            kinds,
            ["line", "notice", "notice", "notice", "notice", "line"]
        );
        let kept: Vec<String> = untimed(handle.buffer_snapshot())
            .into_iter()
            .filter(|line| !line.contains("*bnc*"))
            .collect();
        assert_eq!(kept, [":me!u@h JOIN #room", ":op!o@h PRIVMSG #room :hello"]);
        let answer = ends
            .answered_by_session("NAMES #room")
            .expect("the session follows the member list");
        assert!(answer[0].ends_with("353 me = #room :me @op"), "{answer:?}");
    }

    /// A watched nick's presence is told live, never retained: replayed, it
    /// would say a nick that left long ago is online.
    #[test]
    fn a_watched_nicks_presence_is_told_live_and_never_retained() {
        let (handle, ends) = NetworkHandle::channels(8);
        ends.emit_line(":up 730 me :bob!b@h".to_string());
        ends.emit_line(":up 600 me bob b h 1700000000 :logged online".to_string());
        ends.emit_line(":bob!b@h PRIVMSG me :still here".to_string());
        assert_eq!(
            untimed(handle.buffer_snapshot()),
            [":bob!b@h PRIVMSG me :still here"]
        );
    }

    /// Rows an older build stored of what is now told live only are left in
    /// storage, like a registration burst.
    #[test]
    fn a_restore_leaves_what_is_told_live_only_in_storage() {
        let (handle, _ends) = NetworkHandle::channels(8);
        handle.preload_front(vec![
            stored_line(":up 353 me = #room :me op", "2026-01-01T00:00:00.000Z"),
            stored_line(
                ":bob!b@h PRIVMSG me :\u{1}VERSION\u{1}",
                "2026-01-01T00:00:01.000Z",
            ),
            stored_line(":bob!b@h PRIVMSG #room :kept", "2026-01-01T00:00:02.000Z"),
        ]);
        assert_eq!(
            untimed(handle.buffer_snapshot()),
            [":bob!b@h PRIVMSG #room :kept"]
        );
    }

    /// The live notice still reaches an attached client, at the ring position
    /// it was told at, so a replay cursor taken from it resumes correctly.
    #[tokio::test]
    async fn a_backlog_storage_failure_is_told_live_and_not_retained() {
        let (handle, ends) = NetworkHandle::channels(8);
        let mut events = handle.subscribe();
        ends.emit_line(":peer PRIVMSG #room :kept".to_string());
        let retained = match events.recv().await.expect("line") {
            DriverEvent::Line(line) => line.seq,
            other => panic!("expected the line, got {other:?}"),
        };
        handle.record_error(NetworkFailure::BacklogStorageFailed);
        match events.recv().await.expect("notice") {
            DriverEvent::Notice(notice) => {
                assert_eq!(notice.seq, retained, "the ring did not move");
                assert!(notice.line.contains("backlog_storage_failed"), "{notice:?}");
            }
            other => panic!("expected a live notice, got {other:?}"),
        }
        assert_eq!(
            untimed(handle.buffer_snapshot()),
            vec![":peer PRIVMSG #room :kept".to_string()]
        );
    }

    #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
    #[test]
    fn bridge_error_is_a_component_log_notice() {
        let (handle, ends) = NetworkHandle::channels(8);
        ends.record_error(NetworkFailure::UpstreamRequestFailed);

        assert_eq!(
            handle
                .buffer_snapshot()
                .iter()
                .map(|line| without_tag(line, "time"))
                .collect::<Vec<_>>(),
            vec![failure_notice(NetworkFailure::UpstreamRequestFailed)]
        );
    }

    #[tokio::test]
    async fn history_restore_blocks_attach_snapshot_until_ready_or_shutdown() {
        let (handle, _ends) = NetworkHandle::channels(8);
        let handle = std::sync::Arc::new(handle);
        handle.history_ready.send_replace(false);
        let waiting = tokio::spawn({
            let handle = handle.clone();
            async move { handle.wait_for_history().await }
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        handle.history_restored();
        assert!(waiting.await.expect("history wait task panicked"));

        handle.history_ready.send_replace(false);
        let waiting = tokio::spawn({
            let handle = handle.clone();
            async move { handle.wait_for_history().await }
        });
        handle.shutdown();
        assert!(!waiting.await.expect("history wait task panicked"));
    }

    /// A driver must stop when the registry signals shutdown, even while a
    /// command sender is outstanding (as an attached client holds). Before this,
    /// the driver observed only all-senders-dropped, so an attached client kept
    /// the upstream connection — and its decrypted SASL password — alive after
    /// the network was removed.
    #[tokio::test]
    async fn shutdown_stops_the_driver_with_a_command_sender_outstanding() {
        let (handle, mut ends) = NetworkHandle::channels(16);
        let driver = tokio::spawn(async move { while ends.next_command().await.is_some() {} });
        // Stand in for an attached client: a live clone of the command sender.
        let held = handle.commands.clone();
        // Removing the network stops the driver despite `held` still existing.
        handle.shutdown();
        tokio::time::timeout(std::time::Duration::from_secs(5), driver)
            .await
            .expect("driver did not stop on shutdown")
            .expect("driver task panicked");
        drop(held);
    }

    /// Attaching to a network that was ALREADY shut down (removed between the
    /// caller resolving the handle and the attach) must detach immediately, not
    /// linger forever. A `watch::Receiver` subscribed after the shutdown treats
    /// it as already-seen, so `changed()` never fires — the up-front `borrow()`
    /// check is what closes the client.
    #[tokio::test]
    async fn attach_to_an_already_shutdown_network_detaches_immediately() {
        use tokio::io::AsyncReadExt;
        let (handle, _ends) = NetworkHandle::channels(16);
        handle.shutdown(); // network removed BEFORE the client attaches
        let (client_side, server_side) = tokio::io::duplex(4096);
        // attach must RETURN (not hang) even though the broadcast never closes.
        let attached = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            attach(
                attach_link::over_stream(server_side).await,
                ClientInput::default(),
                &handle,
                AttachCaps::default(),
                account_lease::lease_for_test("testuser"),
                Greeting {
                    server_name: "bnc.test",
                    network: "net",
                    requested_nick: "testuser",
                },
                ATTACH_LIVENESS_INTERVAL,
            ),
        )
        .await;
        assert!(
            attached.is_ok(),
            "attach to an already-dead network must not linger"
        );
        // The client was told why, then the socket closed.
        let (mut cr, _cw) = tokio::io::split(client_side);
        let mut buf = vec![0u8; 256];
        let n = cr.read(&mut buf).await.expect("read");
        assert!(
            String::from_utf8_lossy(&buf[..n]).contains("network removed"),
            "the client gets a detach notice"
        );
    }

    /// A suspension revokes the account's attachments and then stops its
    /// networks, and an attachment can see both at once: it ends as revoked,
    /// and says so. It used to end as often as not as a removed network.
    #[tokio::test]
    async fn an_attachment_whose_network_stops_with_its_authority_ends_as_revoked() {
        use tokio::io::{AsyncBufReadExt, BufReader};
        // The relay's select picks among ready branches at random; each round
        // readies both at once, as a suspension does.
        for _ in 0..20 {
            let (handle, _ends) = NetworkHandle::channels(16);
            let handle = std::sync::Arc::new(handle);
            let revocations = AccountRevocations::new();
            let lease = revocations
                .lease(
                    revocations.ticket(),
                    "alice",
                    crate::identity::CredentialId::AccountPassword,
                )
                .expect("lease");
            let (client_side, server_side) = tokio::io::duplex(4096);
            let attached = tokio::spawn({
                let handle = handle.clone();
                async move {
                    attach(
                        attach_link::over_stream(server_side).await,
                        ClientInput::default(),
                        &handle,
                        AttachCaps::default(),
                        lease,
                        Greeting {
                            server_name: "bnc.test",
                            network: "net",
                            requested_nick: "alice",
                        },
                        ATTACH_LIVENESS_INTERVAL,
                    )
                    .await
                }
            });
            let mut lines = BufReader::new(client_side).lines();
            loop {
                let line = lines.next_line().await.expect("read").expect("welcome");
                if line.contains("NOTICE") && line.contains("upstream") {
                    break;
                }
            }
            // A suspension revokes, then stops the account's networks.
            revocations.revoke("alice");
            handle.shutdown();
            let end = tokio::time::timeout(std::time::Duration::from_secs(5), attached)
                .await
                .expect("the attachment ends")
                .expect("attach task")
                .expect("attach");
            assert_eq!(end, AttachEnd::Revoked(Revocation::Account));
        }
    }

    /// An attachment ends with its account's authority: revoking the lease —
    /// a suspension, deletion or password change — detaches the client from a
    /// network that keeps running (a shared or configured one), and a lease
    /// revoked before the attachment began never starts one.
    #[tokio::test]
    async fn a_revoked_account_lease_detaches_the_client_from_a_running_network() {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let (handle, _ends) = NetworkHandle::channels(16);
        let handle = std::sync::Arc::new(handle);
        let revocations = AccountRevocations::new();
        let lease = revocations
            .lease(
                revocations.ticket(),
                "Alice",
                crate::identity::CredentialId::AccountPassword,
            )
            .expect("lease");
        let (client_side, server_side) = tokio::io::duplex(4096);
        let attached = tokio::spawn({
            let handle = handle.clone();
            async move {
                attach(
                    attach_link::over_stream(server_side).await,
                    ClientInput::default(),
                    &handle,
                    AttachCaps::default(),
                    lease,
                    Greeting {
                        server_name: "bnc.test",
                        network: "net",
                        requested_nick: "alice",
                    },
                    ATTACH_LIVENESS_INTERVAL,
                )
                .await
            }
        });
        let mut lines = BufReader::new(client_side).lines();
        // Attached: the welcome, then the up-front status, arrive.
        loop {
            let line = lines.next_line().await.expect("read").expect("welcome");
            if line.contains("NOTICE") && line.contains("upstream") {
                break;
            }
        }
        assert_eq!(revocations.revoke("ALICE"), 1);
        let end = tokio::time::timeout(std::time::Duration::from_secs(5), attached)
            .await
            .expect("a revoked attachment ends")
            .expect("attach task")
            .expect("attach");
        assert_eq!(end, AttachEnd::Revoked(Revocation::Account));
        let notice = lines.next_line().await.expect("read").expect("notice");
        assert!(notice.contains("suspended or deleted"), "{notice}");
        assert!(
            !*handle.watch_shutdown().borrow(),
            "the network keeps running"
        );

        // Revoked between the lease and the attachment: it never begins.
        let late = revocations
            .lease(
                revocations.ticket(),
                "alice",
                crate::identity::CredentialId::AccountPassword,
            )
            .expect("lease");
        revocations.revoke("alice");
        let (_client_side, server_side) = tokio::io::duplex(4096);
        let end = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            attach(
                attach_link::over_stream(server_side).await,
                ClientInput::default(),
                &handle,
                AttachCaps::default(),
                late,
                Greeting {
                    server_name: "bnc.test",
                    network: "net",
                    requested_nick: "alice",
                },
                ATTACH_LIVENESS_INTERVAL,
            ),
        )
        .await
        .expect("returns at once")
        .expect("attach");
        assert_eq!(end, AttachEnd::Revoked(Revocation::Account));
        assert_eq!(handle.runtime_snapshot().attached_clients, 0);
    }

    /// Revoking the app password an attachment signed in with detaches it,
    /// saying so, from a network that keeps running.
    #[tokio::test]
    async fn a_revoked_credential_detaches_the_client_it_signed_in() {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let revoked = crate::identity::IssuedCredential::AppPassword(7);
        let (handle, _ends) = NetworkHandle::channels(16);
        let revocations = AccountRevocations::new();
        let lease = revocations
            .lease(
                revocations.ticket(),
                "alice",
                crate::identity::CredentialId::Issued(revoked),
            )
            .expect("lease");
        let (client_side, server_side) = tokio::io::duplex(4096);
        let attached = attach(
            attach_link::over_stream(server_side).await,
            ClientInput::default(),
            &handle,
            AttachCaps::default(),
            lease,
            Greeting {
                server_name: "bnc.test",
                network: "net",
                requested_nick: "alice",
            },
            ATTACH_LIVENESS_INTERVAL,
        );
        let revoke = async {
            let mut lines = BufReader::new(client_side).lines();
            loop {
                let line = lines.next_line().await.expect("read").expect("welcome");
                if line.contains("NOTICE") && line.contains("upstream") {
                    break;
                }
            }
            assert_eq!(revocations.revoke_credential(revoked), 1);
            lines.next_line().await.expect("read").expect("notice")
        };
        let (end, notice) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(attached, revoke)
        })
        .await
        .expect("a revoked attachment ends");
        assert_eq!(
            end.expect("attach"),
            AttachEnd::Revoked(Revocation::Credential(revoked))
        );
        assert!(
            notice.contains("the app password you signed in with was revoked"),
            "{notice}"
        );
        assert!(!*handle.watch_shutdown().borrow());
    }

    /// An attached client that stops reading ends its attachment as too slow
    /// at the write deadline. The relay used to park in the write, never seeing
    /// the network's removal or the client's silence, and held the network
    /// handle, its attached count and the connection slot for as long as the
    /// client liked.
    #[tokio::test(start_paused = true)]
    async fn an_attached_client_that_stops_reading_is_detached_as_too_slow() {
        let (handle, ends) = NetworkHandle::channels(16);
        let (_client_side, server_side) = tokio::io::duplex(64);
        let attached = attach(
            attach_link::over_stream(server_side).await,
            ClientInput::default(),
            &handle,
            AttachCaps::default(),
            account_lease::lease_for_test("testuser"),
            Greeting {
                server_name: "bnc.test",
                network: "net",
                requested_nick: "testuser",
            },
            ATTACH_LIVENESS_INTERVAL,
        );
        let feed = async {
            for n in 0..4 {
                tokio::task::yield_now().await;
                ends.emit_line(format!(":peer PRIVMSG #room :line {n} {}", "x".repeat(80)));
            }
            std::future::pending::<()>().await
        };
        let end = tokio::select! {
            end = attached => end,
            () = feed => unreachable!("the feed never ends"),
        };
        assert_eq!(
            end.expect("a stall is an ending, not an error"),
            AttachEnd::ClientTooSlow
        );
        assert_eq!(handle.runtime_snapshot().attached_clients, 0);
    }

    /// A multi-target line surfaces EVERY target's outcome, not just the last.
    /// This is the fold-into-one silent drop the Matrix bridge had before
    /// `relay_routed` was shared: `#a` delivers, `#b`'s upstream send fails, `#c`
    /// is unmapped — the client must see both problems, once each.
    /// The gateway WS dialer refuses a URL that resolves to an SSRF-blocked
    /// address (here a cloud-metadata link-local literal), before opening any
    /// socket — the same control the IRC driver applies. This is the upstream-
    /// controlled vector: the gateway URL comes from a REST response.
    #[tokio::test]
    #[cfg(any(feature = "discord", feature = "slack"))]
    async fn bridge_ws_connect_refuses_an_ssrf_blocked_gateway() {
        for policy in [
            crate::egress::InternalUpstreams::Refuse,
            crate::egress::InternalUpstreams::Allow,
        ] {
            let err = bridge_ws_connect(
                "wss://169.254.169.254/gateway",
                bridge_ws_config(),
                "https://api.example",
                policy,
            )
            .await
            .expect_err("a link-local gateway must be refused");
            assert!(
                err.contains("permitted"),
                "refusal must name the rule, got: {err}"
            );
        }
        // A loopback gateway is internal: refused by default, dialled only
        // under the operator's explicit allowance (here: nothing listens, so
        // the refusal gives way to a connection error).
        let err = bridge_ws_connect(
            "wss://127.0.0.1:9/gateway",
            bridge_ws_config(),
            "https://api.example",
            crate::egress::InternalUpstreams::Refuse,
        )
        .await
        .expect_err("a loopback gateway is refused by default");
        assert!(err.contains("permitted"), "{err}");
        let err = bridge_ws_connect(
            "wss://127.0.0.1:9/gateway",
            bridge_ws_config(),
            "https://api.example",
            crate::egress::InternalUpstreams::Allow,
        )
        .await
        .expect_err("nothing listens on port 9");
        assert!(!err.contains("permitted"), "{err}");
    }

    /// Discord's IDENTIFY carries the bot token over the gateway socket, and the
    /// gateway URL is whatever the REST answer said. A `ws://` answer would send
    /// the token in the clear; only the test oracle — a loopback `http://` API
    /// base under the operator's allowance — may speak cleartext.
    #[tokio::test]
    #[cfg(any(feature = "discord", feature = "slack"))]
    async fn a_cleartext_gateway_is_refused_unless_the_api_base_is_the_loopback_oracle() {
        use crate::egress::InternalUpstreams;
        let cleartext = "ws://127.0.0.1:9/gateway";
        for (api_base, policy) in [
            ("https://discord.com/api/v10", InternalUpstreams::Allow),
            ("http://127.0.0.1:9", InternalUpstreams::Refuse),
            ("https://127.0.0.1:9", InternalUpstreams::Allow),
            ("http://api.example", InternalUpstreams::Allow),
            ("http://10.0.0.5:9", InternalUpstreams::Allow),
        ] {
            let err = bridge_ws_connect(cleartext, bridge_ws_config(), api_base, policy)
                .await
                .expect_err("a cleartext gateway must be refused");
            assert!(err.contains("wss"), "{api_base} under {policy:?}: {err}");
        }
        let err = bridge_ws_connect(
            cleartext,
            bridge_ws_config(),
            "http://localhost:9",
            InternalUpstreams::Allow,
        )
        .await
        .expect_err("a name is not taken to mean loopback");
        assert!(err.contains("wss"), "{err}");
        for api_base in ["http://127.0.0.1:9", "http://[::1]:9"] {
            let err = bridge_ws_connect(
                cleartext,
                bridge_ws_config(),
                api_base,
                InternalUpstreams::Allow,
            )
            .await
            .expect_err("nothing listens on port 9");
            assert!(!err.contains("wss"), "{api_base}: {err}");
        }
    }

    /// `2130706433`, `0x7f.1` and `127.1` are all 127.0.0.1 to the URL parser
    /// and so to the connector, which dials an IP-literal host without asking
    /// the resolver. The request is refused where it is built, before any
    /// socket opens; the never-an-upstream classes are refused under either
    /// policy, and the operator's allowance lets the dial happen.
    #[tokio::test]
    #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
    async fn a_bridge_request_to_a_disguised_internal_literal_never_opens_a_socket() {
        use crate::egress::InternalUpstreams;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            while listener.accept().await.is_ok() {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });
        let refused =
            BridgeHttp::new(std::time::Duration::from_secs(1), InternalUpstreams::Refuse).unwrap();
        for url in [
            format!("http://2130706433:{port}/"),
            format!("http://0x7f.1:{port}/"),
            format!("http://127.1:{port}/"),
            format!("http://0177.0.0.1:{port}/"),
        ] {
            let Err(err) = refused.get(&url) else {
                panic!("{url} was not refused");
            };
            assert!(err.contains("internal"), "{url}: {err}");
        }
        for policy in [InternalUpstreams::Refuse, InternalUpstreams::Allow] {
            let http = BridgeHttp::new(std::time::Duration::from_secs(1), policy).unwrap();
            let err = http
                .get("http://2852039166/latest/meta-data/")
                .expect_err("the metadata endpoint is never an upstream");
            assert!(err.contains("link-local"), "{err}");
        }
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 0);

        let allowed =
            BridgeHttp::new(std::time::Duration::from_secs(1), InternalUpstreams::Allow).unwrap();
        let request = allowed
            .get(&format!("http://2130706433:{port}/"))
            .expect("the operator's allowance admits loopback");
        // The listener answers nothing, so the send fails; the accept is the point.
        drop(request.send().await);
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// A 3xx is a re-targeting the client never follows — and never reads as
    /// success either: a message "sent" with a 302 was not posted.
    #[tokio::test]
    #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
    async fn a_redirecting_upstream_is_a_failed_request_not_a_delivered_one() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = connections.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut request = [0u8; 1024];
                drop(socket.read(&mut request).await);
                drop(
                    socket
                        .write_all(
                            b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/\r\n\
                              Content-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await,
                );
            }
        });
        let http = BridgeHttp::new(
            std::time::Duration::from_secs(2),
            crate::egress::InternalUpstreams::Allow,
        )
        .unwrap();
        let err = http
            .get(&format!("http://127.0.0.1:{port}/"))
            .unwrap()
            .send()
            .await
            .expect_err("a redirect is not a delivered request")
            .to_string();
        assert!(err.contains("302"), "{err}");
        assert_eq!(connections.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn resolved_addresses_alternate_families_without_reordering_each_family() {
        let v6a = "[2001:db8::1]:6697".parse().unwrap();
        let v6b = "[2001:db8::2]:6697".parse().unwrap();
        let v4a = "192.0.2.1:6697".parse().unwrap();
        let v4b = "192.0.2.2:6697".parse().unwrap();
        assert_eq!(
            interleave_address_families(vec![v6a, v6b, v4a, v4b]),
            [v6a, v4a, v6b, v4b]
        );
        assert_eq!(
            interleave_address_families(vec![v4a, v4b, v6a, v6b]),
            [v4a, v6a, v4b, v6b]
        );
    }

    /// The dialer every upstream socket goes through moves past an address
    /// that refuses to the next one, so a v6-first answer on a v4-only host
    /// still connects. (The gateway WebSocket used to take only the first
    /// permitted address; this is the loop it now shares with the IRC driver.)
    #[tokio::test]
    #[cfg(any(feature = "discord", feature = "slack"))]
    async fn the_dialer_moves_past_an_address_that_refuses() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = listener.local_addr().unwrap();
        // Bound, then dropped: the port refuses for the moment nothing is on it.
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let stream = connect_first_reachable(vec![closed, open])
            .await
            .expect("the second address answers");
        assert_eq!(stream.peer_addr().unwrap(), open);
        let err = connect_first_reachable(vec![closed])
            .await
            .expect_err("no address answers");
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
        let err = connect_first_reachable(Vec::new())
            .await
            .expect_err("nothing to dial");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    /// One step a scripted driver session takes, for exercising
    /// [`run_with_backoff`] without a socket.
    enum ScriptedStep {
        Refuse(e6irc_client::RegistrationRejection),
        /// Hold the session for this long — having reached `Connected` or not —
        /// then drop it.
        Drop {
            hold_for: std::time::Duration,
            connected: bool,
        },
        Stop,
    }

    #[derive(Default)]
    struct Script {
        steps: std::sync::Mutex<std::collections::VecDeque<ScriptedStep>>,
        /// When each session began, in order.
        starts: std::sync::Mutex<Vec<tokio::time::Instant>>,
    }

    fn scripted_session<'a>(
        script: &'a Script,
        ends: &'a mut DriverEnds,
    ) -> std::pin::Pin<Box<dyn Future<Output = SessionOutcome> + Send + 'a>> {
        Box::pin(async move {
            script
                .starts
                .lock()
                .unwrap()
                .push(tokio::time::Instant::now());
            let step = script.steps.lock().unwrap().pop_front();
            match step {
                Some(ScriptedStep::Refuse(rejection)) => {
                    SessionOutcome::RegistrationRejected(rejection)
                }
                Some(ScriptedStep::Drop {
                    hold_for,
                    connected,
                }) => {
                    if connected {
                        ends.emit(ConnectionEvent::Connected);
                    }
                    tokio::time::sleep(hold_for).await;
                    SessionOutcome::Dropped(NetworkFailure::ConnectionLost)
                }
                Some(ScriptedStep::Stop) | None => SessionOutcome::Stopped,
            }
        })
    }

    /// Run the script to its end under [`run_with_backoff`]; when each session
    /// began, and the handle whose runtime the run left behind.
    async fn run_script(steps: Vec<ScriptedStep>) -> (Vec<tokio::time::Instant>, NetworkHandle) {
        let (handle, mut ends) = NetworkHandle::channels(8);
        ends.set_rejection_retry_floor(std::time::Duration::from_millis(1));
        let script = Script {
            steps: std::sync::Mutex::new(steps.into_iter().collect()),
            starts: std::sync::Mutex::new(Vec::new()),
        };
        tokio::time::timeout(
            std::time::Duration::from_secs(600),
            run_with_backoff(&script, &mut ends, |script, ends| {
                scripted_session(script, ends)
            }),
        )
        .await
        .expect("the scripted driver parked instead of running its script out");
        let starts = script.starts.lock().unwrap().clone();
        (starts, handle)
    }

    /// A services outage is a run of refusals that never park. When it ends and
    /// the driver's own ghost still holds the nick, that first 433 is the first
    /// of *its* kind: it gets the refusal schedule, not an instant park.
    #[tokio::test]
    async fn refusals_that_never_park_do_not_count_toward_parking_a_later_one() {
        use e6irc_client::RegistrationRefusal;
        // The outage's refusal, from a real exchange: services gone, the
        // upstream no longer offers the mechanism the driver speaks.
        let Err(SessionOutcome::RegistrationRejected(unavailable)) =
            irc_driver::tests::sasl_outcome_against(&[("CAP LS", ":up CAP * LS :sasl=EXTERNAL")])
                .await
        else {
            panic!("an upstream without the mechanism refuses registration");
        };
        assert_eq!(unavailable.refusal(), RegistrationRefusal::SaslUnavailable);
        // The schedule itself runs on the paused clock.
        tokio::time::pause();
        let mut steps: Vec<ScriptedStep> = (0..MAX_CONSECUTIVE_REGISTRATION_REJECTIONS)
            .map(|_| ScriptedStep::Refuse(unavailable.clone()))
            .collect();
        steps.push(ScriptedStep::Refuse(refused_by(
            ":up 433 * bnc :Nickname is already in use",
        )));
        steps.push(ScriptedStep::Stop);
        let (_, handle) = run_script(steps).await;
        let snapshot = handle.runtime_snapshot();
        assert_ne!(
            snapshot.lifecycle,
            NetworkLifecycle::RegistrationFailed,
            "{snapshot:?}"
        );
        assert_eq!(
            snapshot.connection_attempts,
            u64::from(MAX_CONSECUTIVE_REGISTRATION_REJECTIONS) + 2,
            "{snapshot:?}"
        );
    }

    /// Concurrent drivers of one restart must not all begin a round robin at
    /// its first member, nor re-dial the member that just refused: the start
    /// rotates by seed and advances per attempt, and every member stays in.
    #[test]
    fn dial_order_rotates_by_seed_and_by_attempt() {
        let addresses: Vec<std::net::SocketAddr> = (1..=4)
            .map(|index| format!("192.0.2.{index}:6697").parse().unwrap())
            .collect();
        let first = |seed: u64, attempt: u64| {
            rotate_addresses(addresses.clone(), Backoff::address_rotation(seed, attempt))
        };
        assert_ne!(
            first(0, 1)[0],
            first(1, 1)[0],
            "two seeds, one first address"
        );
        assert_ne!(
            first(0, 1)[0],
            first(0, 2)[0],
            "two attempts, one first address"
        );
        for seed in 0..8 {
            let rotated = first(seed, 1);
            let start = addresses
                .iter()
                .position(|address| *address == rotated[0])
                .expect("a rotation begins with a member");
            let expected: Vec<_> = addresses
                .iter()
                .cycle()
                .skip(start)
                .take(4)
                .copied()
                .collect();
            assert_eq!(rotated, expected, "a rotation keeps the order");
        }
        assert!(rotate_addresses(Vec::new(), 7).is_empty());
    }

    /// Jitter is a share of the delay it is added to, so the spread between
    /// drivers grows with the delay: a fixed sub-100 ms spread on a
    /// four-minute step is no spread at all.
    #[test]
    fn jitter_spread_grows_with_the_base_delay() {
        let second = std::time::Duration::from_secs(1);
        let step = std::time::Duration::from_secs(240);
        let mut spreads = std::collections::BTreeSet::new();
        for seed in 0..16 {
            let backoff = Backoff::new(seed);
            assert!(backoff.jitter(second) <= second / 4, "seed {seed}");
            assert_eq!(
                backoff.jitter(step),
                backoff.jitter(second) * 240,
                "seed {seed}: jitter is proportional"
            );
            spreads.insert(backoff.jitter(step));
        }
        assert!(
            spreads.len() > 8,
            "seeds collapse onto few jitters: {spreads:?}"
        );
        assert!(
            spreads
                .iter()
                .any(|jitter| *jitter > std::time::Duration::from_secs(30)),
            "a four-minute step spreads drivers over tens of seconds: {spreads:?}"
        );
        let boot: std::collections::BTreeSet<_> =
            (0..16).map(Backoff::first_dial_stagger).collect();
        assert!(boot.len() > 8, "boot dials collapse: {boot:?}");
        assert!(
            boot.iter()
                .all(|delay| *delay < Backoff::FIRST_DIAL_STAGGER)
        );
    }

    /// A tarpit completes the handshake and says nothing until the registration
    /// deadline. Read as "the session lasted long enough", that reset the
    /// schedule and had the driver re-dial it every 200 ms; only a session that
    /// reached `Connected` and stayed up earns the reset.
    #[tokio::test(start_paused = true)]
    async fn a_long_attempt_that_never_connected_keeps_the_backoff_growing() {
        async fn waits_between(connected: &[bool]) -> Vec<std::time::Duration> {
            let hold_for = Backoff::HELD_FOR;
            let steps = connected
                .iter()
                .map(|&connected| ScriptedStep::Drop {
                    hold_for,
                    connected,
                })
                .chain([ScriptedStep::Stop])
                .collect();
            let (starts, _handle) = run_script(steps).await;
            starts
                .windows(2)
                .map(|pair| pair[1] - pair[0] - hold_for)
                .collect()
        }
        let tarpit = waits_between(&[false, false, false]).await;
        // 200 ms, 400 ms, 800 ms: each attempt waits longer, jitter at most a
        // quarter of each.
        assert!(
            tarpit[0] < std::time::Duration::from_millis(300),
            "{tarpit:?}"
        );
        assert!(
            tarpit[1] >= std::time::Duration::from_millis(400),
            "{tarpit:?}"
        );
        assert!(
            tarpit[2] >= std::time::Duration::from_millis(800),
            "{tarpit:?}"
        );

        let held = waits_between(&[false, true]).await;
        // The held session starts the schedule over.
        assert!(held[1] < std::time::Duration::from_millis(300), "{held:?}");
    }

    /// The registry waits for a stopped driver under its one mutation guard. A
    /// driver wedged in a write it cannot finish must not hold every account's
    /// network mutation with it: the wait is bounded, and says so.
    #[tokio::test]
    async fn the_wait_for_a_stopped_driver_is_bounded() {
        let (handle, ends) = NetworkHandle::channels(8);
        let wedged = tokio::spawn(async move {
            let _ends = ends;
            std::future::pending::<()>().await;
        });
        let released = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            handle.shutdown_and_wait_within(std::time::Duration::from_millis(100)),
        )
        .await
        .expect("the wait returned at its deadline");
        assert!(
            !released,
            "a wedged driver cannot have released its transport"
        );
        wedged.abort();

        let (handle, mut ends) = NetworkHandle::channels(8);
        tokio::spawn(async move { while ends.next_command().await.is_some() {} });
        assert!(
            handle
                .shutdown_and_wait_within(std::time::Duration::from_secs(5))
                .await,
            "a cooperating driver releases its transport"
        );
    }

    #[test]
    #[cfg(any(feature = "discord", feature = "slack"))]
    fn bridge_gateway_url_is_closed_to_websocket_origins() {
        assert_eq!(
            bridge_gateway_authority("wss://gateway.example/socket"),
            Ok(("gateway.example".into(), 443))
        );
        assert_eq!(
            bridge_gateway_authority("ws://127.0.0.1:8080/socket"),
            Ok(("127.0.0.1".into(), 8080))
        );
        for url in [
            "https://gateway.example/socket",
            "wss://user:secret@gateway.example/socket",
            "wss://gateway.example/socket#fragment",
            "/socket",
        ] {
            assert!(bridge_gateway_authority(url).is_err(), "accepted {url}");
        }
    }

    /// A bridge's session is its account's nick in its mapped channels, begun
    /// before it is reported connected; a channel no client could be joined to
    /// refuses the configuration and begins nothing.
    #[test]
    #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
    fn a_bridge_session_is_the_account_in_its_channels_or_nothing() {
        let (handle, ends) = NetworkHandle::bridge_channels(4);
        let mut events = handle.subscribe();
        let identity = shown("test", "my bot");
        let refused = ends.begin_bridge_session(
            &identity,
            [&"#ok".to_string(), &"no spaces allowed".to_string()],
            SessionStart::Fresh,
        );
        match refused {
            Err(SessionOutcome::ConfigurationRejected(refusal)) => {
                assert_eq!(refusal.failure(), NetworkFailure::ChannelMappingFailed);
                assert!(
                    refusal.diagnostic().contains("no spaces allowed"),
                    "{refusal:?}"
                );
            }
            Err(_) => panic!("an untrackable channel was refused as something else"),
            Ok(()) => panic!("an untrackable channel was served"),
        }
        assert_eq!(handle.irc_session_snapshot(), None);
        assert!(
            events.try_recv().is_err(),
            "a refused session announced something"
        );

        assert!(
            ends.begin_bridge_session(
                &identity,
                [&"#Ok".to_string(), &"#two".to_string()],
                SessionStart::Fresh
            )
            .is_ok(),
            "a servable configuration was refused"
        );
        let session = IrcSessionSnapshot {
            nick: "my_bot".to_string(),
            channels: vec!["#Ok".to_string(), "#two".to_string()],
        };
        assert_eq!(
            events.try_recv().ok(),
            Some(DriverEvent::Session(session.clone()))
        );
        assert!(matches!(
            events.try_recv(),
            Ok(DriverEvent::Status {
                status: DriverConnectionStatus::Connected,
                ..
            })
        ));
        assert_eq!(handle.irc_session_snapshot(), Some(session));
        assert_eq!(handle.session_authority(), SessionAuthority::Provider);
    }

    /// A bridge session that cannot pick up where the last one stopped says
    /// so in every bridged channel, once, whatever made the position go; the
    /// first session, and one that resumed, have nothing to say. A Matrix
    /// position forgotten after a kick, or a Discord RESUME refused, used to
    /// start the next session afresh and skip what was said in between
    /// without a word.
    #[test]
    #[cfg(any(feature = "matrix", feature = "discord"))]
    fn a_session_that_cannot_resume_says_so_in_every_channel() {
        let (handle, ends) = NetworkHandle::bridge_channels(16);
        let mut events = handle.subscribe();
        let identity = shown("test", "bot");
        let one = "#one".to_string();
        let two = "#two".to_string();
        let gap_notices = |events: &mut tokio::sync::broadcast::Receiver<DriverEvent>| {
            let mut notices = Vec::new();
            while let Ok(event) = events.try_recv() {
                if let DriverEvent::Line(line) = event
                    && line.line.contains("without resuming")
                {
                    notices.push(without_tag(&line.line, "time"));
                }
            }
            notices
        };
        for (start, expected) in [
            (SessionStart::Fresh, 0),
            (SessionStart::Resumed, 0),
            (SessionStart::Fresh, 2),
            (SessionStart::Resumed, 0),
        ] {
            ends.begin_bridge_session(&identity, [&one, &two], start)
                .unwrap_or_else(|_| panic!("a servable configuration was refused"));
            let notices = gap_notices(&mut events);
            assert_eq!(notices.len(), expected, "{start:?}: {notices:?}");
            if expected > 0 {
                assert_eq!(
                    notices,
                    [
                        ":*bnc* NOTICE #one :the bridge reconnected without resuming where it \
                         stopped; messages sent while it was disconnected may not have been relayed",
                        ":*bnc* NOTICE #two :the bridge reconnected without resuming where it \
                         stopped; messages sent while it was disconnected may not have been relayed",
                    ]
                );
            }
        }
    }

    /// One message is at most `MAX_BRIDGED_LINES` lines and a notice, however
    /// many newlines it holds: two thousand of them overflowed the network's
    /// broadcast by themselves, detaching every attached client. Blank lines
    /// are not shown at all — IRC has no empty message.
    #[test]
    #[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
    fn a_message_of_many_lines_is_bounded_and_says_what_it_left_out() {
        let lines: Vec<String> = render_bridged(
            &shown("discord", "bob"),
            "#c",
            &Inbound::new(InboundKind::Message, &"a\n".repeat(2_000)),
        )
        .into_iter()
        .collect();
        assert_eq!(lines.len(), MAX_BRIDGED_LINES + 1, "{lines:?}");
        assert!(
            lines[..MAX_BRIDGED_LINES]
                .iter()
                .all(|line| line == ":bob!bob@discord PRIVMSG #c :a")
        );
        assert_eq!(
            lines[MAX_BRIDGED_LINES],
            format!(
                ":*bnc* NOTICE #c :… {} more lines of bob's message not shown (a bridged \
                 message is shown in at most {MAX_BRIDGED_LINES})",
                2_000 - MAX_BRIDGED_LINES
            )
        );

        // Blank lines, however many, show nothing and cost nothing.
        let lines: Vec<String> = render_bridged(
            &shown("discord", "bob"),
            "#c",
            &Inbound::new(
                InboundKind::Message,
                &format!("one{}two\n \t \nthree\n\n", "\n".repeat(5_000)),
            ),
        )
        .into_iter()
        .collect();
        assert_eq!(
            lines,
            [
                ":bob!bob@discord PRIVMSG #c :one",
                ":bob!bob@discord PRIVMSG #c :two",
                ":bob!bob@discord PRIVMSG #c :three",
            ]
        );
        // A message of nothing but blank lines is still one (empty) line.
        let lines: Vec<String> = render_bridged(
            &shown("discord", "bob"),
            "#c",
            &Inbound::new(InboundKind::Message, "\n\n  \n"),
        )
        .into_iter()
        .collect();
        assert_eq!(lines, [":bob!bob@discord PRIVMSG #c :"]);
    }

    #[tokio::test]
    #[cfg(feature = "matrix")]
    async fn relay_routed_surfaces_every_target_outcome() {
        let (handle, ends) = NetworkHandle::channels(64);
        let mut map = std::collections::HashMap::new();
        map.insert("#a".to_string(), "id_a".to_string());
        map.insert("#b".to_string(), "id_b".to_string());
        // #c is deliberately absent from the map (unmapped).
        let command = ClientCommand {
            origin: 9,
            line: "PRIVMSG #a,#b,#c :hi".to_string(),
        };
        let identity = shown("test", "me");
        let mut events = handle.subscribe();
        relay_routed(
            &ends,
            &command,
            &map,
            &identity,
            "Test",
            "channel",
            |id, _text| {
                let failed = id == "id_b"; // #b's upstream send fails; #a succeeds.
                async move {
                    if failed {
                        Err(BridgeFailure::Failed("boom".to_string()))
                    } else {
                        Ok(())
                    }
                }
            },
        )
        .await;
        // Only the delivered target is echoed, to the attachment that sent it.
        let mut echoes = Vec::new();
        while let Ok(event) = events.try_recv() {
            if let DriverEvent::Echo { line, origin } = event {
                echoes.push((line.line, origin));
            }
        }
        assert_eq!(echoes.len(), 1, "{echoes:?}");
        assert_eq!(echoes[0].1, 9);
        assert!(
            echoes[0].0.ends_with(" :me!me@test PRIVMSG #a :hi"),
            "{}",
            echoes[0].0
        );
        let runtime = handle.runtime_snapshot();
        assert_eq!(runtime.errors, 1, "{runtime:?}");
        assert!(runtime.last_error_at.is_some(), "{runtime:?}");
        assert_eq!(
            runtime.last_error,
            Some(NetworkFailure::UpstreamWriteFailed),
            "{runtime:?}"
        );
        let lines = handle.buffer_snapshot();
        assert!(
            !lines.iter().any(|l| l.contains("id_a")),
            "a delivered target gets no notice: {lines:#?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("not delivered") && l.contains("id_b")),
            "the failed send is surfaced: {lines:#?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("no bridged") && l.contains("#c")),
            "the unmapped target is surfaced: {lines:#?}"
        );
        let delivery_notices = lines
            .iter()
            .filter(|line| line.contains("not delivered") || line.contains("no bridged"))
            .count();
        assert_eq!(
            delivery_notices, 2,
            "exactly one delivery notice per problem target: {lines:#?}"
        );
        assert!(
            lines.iter().any(|line| without_tag(line, "time")
                == failure_notice(NetworkFailure::UpstreamWriteFailed)),
            "the component diagnostic is retained: {lines:#?}"
        );

        let command = ClientCommand {
            origin: 9,
            line: "JOIN #a".to_string(),
        };
        relay_routed(
            &ends,
            &command,
            &map,
            &identity,
            "Test",
            "channel",
            |_id, _text| async { Ok(()) },
        )
        .await;
        assert!(
            handle
                .buffer_snapshot()
                .iter()
                .any(|line| line.contains("bridge supports PRIVMSG only")),
            "an unsupported bridge command must fail visibly"
        );
    }

    #[test]
    #[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
    fn undelivered_notice_fits_the_line_limit() {
        use e6irc_proto::message::MAX_LINE_LEN;
        // The target comes from the client's own line, bounded only by the
        // frame limit — several times what an IRC line gets. A notice the
        // client's framing discards is the silent drop it exists to prevent.
        let target = "#".to_string() + &"a".repeat(4_000);
        let notice = unmapped_target_notice("Discord", "channel", &target);
        assert!(notice.len() + 2 <= MAX_LINE_LEN, "{} bytes", notice.len());
        // Still says which target, and still parses as one NOTICE.
        assert!(notice.starts_with(":*bnc* NOTICE #aaa"));
        let msg = e6irc_proto::message::Message::parse(&notice).expect("parses");
        assert_eq!(msg.command, "NOTICE");
        // A multi-byte target is cut between characters, not through one.
        let wide = "#".to_string() + &"☃".repeat(4_000);
        let notice = unmapped_target_notice("Matrix", "room", &wide);
        assert!(notice.len() + 2 <= MAX_LINE_LEN);
        assert!(e6irc_proto::message::Message::parse(&notice).is_ok());

        // The delivery-failure notice carries the same discipline: a Matrix
        // room id is homeserver-supplied and unbounded, so it must be truncated
        // or the "not delivered" notice itself is discarded for length.
        let room = "!".to_string() + &"a".repeat(4_000) + ":evil.example";
        let notice = undelivered_notice("Matrix", "room", &room);
        assert!(notice.len() + 2 <= MAX_LINE_LEN, "{} bytes", notice.len());
        let msg = e6irc_proto::message::Message::parse(&notice).expect("parses");
        assert_eq!(msg.command, "NOTICE");
        // Multi-byte room id is cut on a character boundary, not through one.
        let wide_room = "!".to_string() + &"☃".repeat(4_000);
        let notice = undelivered_notice("Matrix", "room", &wide_room);
        assert!(notice.len() + 2 <= MAX_LINE_LEN);
        assert!(e6irc_proto::message::Message::parse(&notice).is_ok());
    }

    #[test]
    #[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
    fn bridged_message_is_split_to_fit_the_line_limit() {
        use e6irc_proto::message::MAX_LINE_LEN;
        // Emitted as one line, a long message is discarded whole by the
        // receiving client's framing, and simply gone.
        let body = "x".repeat(5_000);
        let lines = render_bridged(
            &shown("slack", "U1"),
            "#general",
            &Inbound::new(InboundKind::Message, &body),
        )
        .into_iter()
        .collect::<Vec<_>>();
        assert!(lines.len() > 1, "a 5k body must not be one line");
        for line in &lines {
            assert!(
                line.len() + 2 <= MAX_LINE_LEN,
                "line of {} bytes exceeds the limit",
                line.len()
            );
        }
        // Nothing is lost and nothing is duplicated: the pieces reassemble.
        let prefix = ":U1!U1@slack PRIVMSG #general :";
        let rejoined: String = lines
            .iter()
            .map(|l| l.strip_prefix(prefix).expect("prefix"))
            .collect();
        assert_eq!(rejoined, body);

        // Slack allows 40,000 characters: what is shown fits the line limit
        // too, and what is not is counted.
        let lines = render_bridged(
            &shown("slack", "U1"),
            "#general",
            &Inbound::new(InboundKind::Message, &"x".repeat(40_000)),
        )
        .into_iter()
        .collect::<Vec<_>>();
        assert_eq!(lines.len(), MAX_BRIDGED_LINES + 1);
        assert!(lines.iter().all(|line| line.len() + 2 <= MAX_LINE_LEN));
        assert!(
            lines[MAX_BRIDGED_LINES].starts_with(":*bnc* NOTICE #general :… "),
            "{}",
            lines[MAX_BRIDGED_LINES]
        );
    }

    /// An IRC `/me` is an action on every provider, IRC formatting never
    /// reaches one, and a CTCP nothing there can answer is refused.
    #[test]
    #[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
    fn outbound_text_recognises_actions_and_strips_irc_formatting() {
        assert_eq!(
            BridgeText::outbound("\u{1}ACTION waves\u{1}"),
            Some(BridgeText::Action("waves".into()))
        );
        assert_eq!(
            BridgeText::outbound("\u{1}ACTION \u{2}loudly\u{2}"),
            Some(BridgeText::Action("loudly".into()))
        );
        assert_eq!(BridgeText::outbound("\u{1}VERSION\u{1}"), None);
        assert_eq!(BridgeText::outbound("\u{1}ACTIONX\u{1}"), None);
        for (irc, plain) in [
            (
                "\u{2}bold\u{2} \u{1d}it\u{1d} \u{1f}u\u{1f} \u{1e}s\u{1e} \u{11}m\u{11}",
                "bold it u s m",
            ),
            ("\u{3}4red\u{3} \u{3}04,12both\u{3} \u{3}9,x", "red both ,x"),
            ("\u{3}12,5 after, a comma", " after, a comma"),
            ("\u{3}3, not a background", ", not a background"),
            (
                "\u{4}ff0000hex\u{4}00FF00,0000ffboth\u{f} \u{16}rev",
                "hexboth rev",
            ),
            ("tab\tstays, bell\u{7} goes", "tab\tstays, bell goes"),
            ("1\u{3}2", "1"),
        ] {
            assert_eq!(
                BridgeText::outbound(irc),
                Some(BridgeText::Text(plain.into())),
                "{irc:?}"
            );
        }
    }

    /// Remote text can never deliver a CTCP request to an attached client:
    /// the only `\x01` an inbound line carries is the ACTION wrapper, and an
    /// action split over several lines is a complete ACTION on each.
    #[test]
    #[cfg(feature = "matrix")]
    fn inbound_text_drops_controls_and_wraps_actions() {
        assert_eq!(
            render_bridged(
                &shown("slack", "U1"),
                "#c",
                &Inbound::new(InboundKind::Message, "\u{1}VERSION\u{1}\u{2}\t!")
            )
            .into_iter()
            .collect::<Vec<_>>(),
            vec![":U1!U1@slack PRIVMSG #c :VERSION\t!"]
        );
        assert_eq!(
            render_bridged(
                &shown("matrix", "u"),
                "#c",
                &Inbound::new(InboundKind::Action, "waves\u{1}")
            )
            .into_iter()
            .collect::<Vec<_>>(),
            vec![":u!u@matrix PRIVMSG #c :\u{1}ACTION waves\u{1}"]
        );
        assert_eq!(
            render_bridged(
                &shown("matrix", "u"),
                "#c",
                &Inbound::new(InboundKind::Notice, "a bot")
            )
            .into_iter()
            .collect::<Vec<_>>(),
            vec![":u!u@matrix NOTICE #c :a bot"]
        );
        let long = "y".repeat(2_000);
        let lines = render_bridged(
            &shown("matrix", "u"),
            "#c",
            &Inbound::new(InboundKind::Action, &long),
        )
        .into_iter()
        .collect::<Vec<_>>();
        assert!(lines.len() > 1);
        let mut rejoined = String::new();
        for line in &lines {
            assert!(line.len() + 2 <= e6irc_proto::message::MAX_LINE_LEN);
            let body = line
                .strip_prefix(":u!u@matrix PRIVMSG #c :\u{1}ACTION ")
                .and_then(|rest| rest.strip_suffix('\u{1}'))
                .expect("each piece is a whole ACTION");
            rejoined.push_str(body);
        }
        assert_eq!(rejoined, long);
        // The unrelayed-message notice is bounded and control-free whatever
        // the provider names its message type.
        let notice = unrelayed_notice(
            "matrix",
            "#c",
            "m.\u{1}evil type ".repeat(40).as_str(),
            Some("bob"),
        );
        assert!(
            notice.starts_with(":*bnc* NOTICE #c :matrix: a m.eviltypem.eviltype"),
            "{notice}"
        );
        assert!(!notice.bytes().any(|b| b.is_ascii_control()), "{notice}");
        assert!(notice.len() < 200, "{notice}");
    }

    /// A 429's wait comes from the body when it has one, else the header.
    #[tokio::test]
    #[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
    async fn a_rate_limit_is_typed_with_the_wait_it_asks_for() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let cases: Vec<(Option<&'static str>, serde_json::Value, std::time::Duration)> = vec![
            (
                Some("3"),
                serde_json::json!({}),
                std::time::Duration::from_secs(3),
            ),
            (
                Some("5"),
                serde_json::json!({ "retry_after": 0.25, "global": false }),
                std::time::Duration::from_millis(250),
            ),
            (
                None,
                serde_json::json!({ "errcode": "M_LIMIT_EXCEEDED", "retry_after_ms": 1500 }),
                std::time::Duration::from_millis(1500),
            ),
            (None, serde_json::json!({}), RATE_LIMIT_UNSTATED_WAIT),
            (
                Some("99999999"),
                serde_json::json!({}),
                std::time::Duration::from_secs(3600),
            ),
        ];
        for (header, body, expected) in cases {
            let app = axum::Router::new().route(
                "/",
                axum::routing::get(move || {
                    let body = body.clone();
                    async move {
                        let mut response =
                            (StatusCode::TOO_MANY_REQUESTS, axum::Json(body)).into_response();
                        if let Some(header) = header {
                            response
                                .headers_mut()
                                .insert("Retry-After", header.parse().unwrap());
                        }
                        response
                    }
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let http = BridgeHttp::new(
                std::time::Duration::from_secs(5),
                crate::egress::InternalUpstreams::Allow,
            )
            .unwrap();
            assert_eq!(
                http.get(&format!("{base}/"))
                    .unwrap()
                    .send()
                    .await
                    .unwrap_err(),
                BridgeFailure::RateLimited(expected),
                "{header:?}"
            );
        }
    }

    /// The Matrix password and every bot token cross the REST base, so it is
    /// HTTPS like the gateways — cleartext only for the loopback oracle.
    #[tokio::test]
    #[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
    async fn bridge_rest_refuses_cleartext_outside_the_loopback_oracle() {
        use crate::config::NetworkKind;
        use crate::egress::InternalUpstreams;
        for kind in [
            NetworkKind::Matrix,
            NetworkKind::Discord,
            NetworkKind::Slack,
        ] {
            for base in [
                "http://matrix.example.org",
                "http://10.0.0.5:8008",
                "http://api.example/",
                // A name is whatever a resolver answers; only a loopback
                // address literal may speak cleartext.
                "http://localhost:1",
            ] {
                let err = validate_bridge_base(kind, base).expect_err(base);
                assert!(err.contains("https"), "{err}");
            }
            for base in [
                "https://matrix.example.org",
                "http://127.0.0.1:8008",
                "http://[::1]:9",
            ] {
                validate_bridge_base(kind, base).unwrap_or_else(|err| panic!("{base}: {err}"));
            }
        }
        let allowed =
            BridgeHttp::new(std::time::Duration::from_secs(1), InternalUpstreams::Allow).unwrap();
        let err = allowed
            .get("http://matrix.example.org/_matrix/client/v3/login")
            .expect_err("cleartext");
        assert!(err.contains("https"), "{err}");
        drop(
            allowed
                .get("http://127.0.0.1:9/")
                .expect("the loopback oracle under allow"),
        );
        drop(allowed.get("https://matrix.example.org/").expect("https"));
    }

    #[test]
    #[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
    fn bridged_message_splits_on_newlines() {
        // A newline is a line break in the source medium. Left in, it is
        // flattened to a space downstream and the message reads as a run-on.
        let lines = render_bridged(
            &shown("discord", "bob"),
            "#c",
            &Inbound::new(InboundKind::Message, "one\ntwo\r\nthree"),
        )
        .into_iter()
        .collect::<Vec<_>>();
        assert_eq!(
            lines,
            vec![
                ":bob!bob@discord PRIVMSG #c :one",
                ":bob!bob@discord PRIVMSG #c :two",
                ":bob!bob@discord PRIVMSG #c :three",
            ]
        );
    }

    #[test]
    #[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
    fn bridged_split_lands_on_character_boundaries() {
        // The budget is a byte count; slicing into a multi-byte character
        // panics, and taking the daemon down is what an upstream would want.
        for width in [2usize, 3, 4] {
            let ch = match width {
                2 => 'é',
                3 => '☃',
                _ => '𝄞',
            };
            let body: String = std::iter::repeat_n(ch, 1_500).collect();
            let lines = render_bridged(
                &shown("matrix", "u"),
                "#c",
                &Inbound::new(InboundKind::Message, &body),
            )
            .into_iter()
            .collect::<Vec<_>>();
            let prefix = ":u!u@matrix PRIVMSG #c :";
            let rejoined: String = lines
                .iter()
                .map(|l| l.strip_prefix(prefix).expect("prefix"))
                .collect();
            assert_eq!(rejoined, body, "{width}-byte characters round-trip");
        }
    }

    #[test]
    #[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
    fn empty_bridged_message_still_says_something() {
        // A message was sent. Emitting nothing would be the silent drop this
        // whole function exists to prevent.
        assert_eq!(
            render_bridged(
                &shown("slack", "U1"),
                "#c",
                &Inbound::new(InboundKind::Message, "")
            )
            .into_iter()
            .collect::<Vec<_>>(),
            vec![":U1!U1@slack PRIVMSG #c :"]
        );
    }

    #[test]
    fn sanitize_neutralizes_embedded_crlf_and_nul() {
        // A bridge-synthesized line carrying an embedded newline must not be
        // able to inject a second IRC line into an attached client's stream.
        let injected =
            ":a!a@bridge PRIVMSG #c :hi\r\n:nickserv!s@svc PRIVMSG victim :give me your password";
        let safe = crate::sanitize::upstream_line(injected.to_string());
        assert!(!safe.contains('\r') && !safe.contains('\n'));
        assert!(!safe.contains('\0'));
        // A clean line is returned unchanged (fast path).
        let clean = ":a!a@irc PRIVMSG #c :hello there".to_string();
        assert_eq!(crate::sanitize::upstream_line(clean.clone()), clean);
    }

    #[test]
    fn bouncer_buffer_and_live_event_preserve_the_server_tag_allowance() {
        let (handle, ends) = NetworkHandle::channels(4);
        let mut events = handle.subscribe();
        let tagged = format!("@example={} :srv NOTICE nick :ok", "a".repeat(600));
        assert!(tagged.len() > e6irc_proto::message::MAX_LINE_LEN - 2);

        ends.emit_line(tagged.clone());
        assert_eq!(untimed(handle.buffer_snapshot()), vec![tagged.clone()]);
        assert!(matches!(
            events.try_recv(),
            Ok(DriverEvent::Line(BufferedLine { line, .. })) if without_tag(&line, "time") == tagged
        ));
    }

    #[test]
    fn restored_backlog_is_neutralized_like_live_lines() {
        // Backlog comes back from storage, which outlives the code that wrote
        // it. A row containing an embedded line break must not be replayed to
        // an attaching client as two lines just because it arrived through
        // `preload_front` rather than `emit_line`.
        let (handle, _ends) = NetworkHandle::channels(16);
        handle.preload_front(vec![stored_line(
            ":a!a@bridge PRIVMSG #c :hi\r\n:nickserv!s@svc PRIVMSG victim :send me your password",
            "2026-01-01T00:00:00.000Z",
        )]);
        let snapshot = handle.buffer_snapshot();
        assert_eq!(snapshot.len(), 1, "one stored row stays one line");
        assert!(
            !snapshot[0].contains('\r') && !snapshot[0].contains('\n'),
            "restored line still carries a break: {}",
            snapshot[0]
        );
    }

    /// An attaching client is welcomed with the network's own registration
    /// burst facts — its 004 mode lists and 005 tokens as the upstream sent
    /// them — plus only what the bouncer serves itself, and a complete
    /// 001-004 so it knows it is registered.
    #[test]
    fn welcome_reflects_the_attached_networks_isupport() {
        let (handle, ends) = NetworkHandle::channels(8);
        // Before any session: the bridge defaults, no CHATHISTORY (no store).
        let burst = serve::welcome_to("bnc.test", "net", &handle, "alice").lines;
        let numerics: Vec<&str> = burst
            .iter()
            .map(|line| line.split(' ').nth(1).expect("numeric"))
            .collect();
        assert_eq!(numerics, ["001", "002", "003", "004", "005", "422"]);
        assert!(burst[4].contains(" PREFIX=(qaohv)~&@%+ "), "{burst:#?}");
        assert!(!burst[4].contains("CHATHISTORY"), "{burst:#?}");

        ends.begin_irc_session("alice".to_string());
        for line in [
            ":up.example 004 alice up.example solanum-1 DQRSZaghilopsuwz CFILMPQSTbcefgijklmnopqrstuvz bkloveqjfI",
            ":up.example 005 alice CASEMAPPING=ascii CHANTYPES=# PREFIX=(ov)@+ CHATHISTORY=50 :are supported by this server",
            ":up.example 005 alice NETWORK=Up -CHANTYPES :are supported by this server",
        ] {
            ends.emit_session_line(line.to_string()).expect("tracked");
        }
        let burst = serve::welcome_to("bnc.test", "net", &handle, "alice").lines;
        assert_eq!(
            burst[3],
            ":bnc.test 004 alice bnc.test e6irc-bnc-".to_string()
                + env!("CARGO_PKG_VERSION")
                + " DQRSZaghilopsuwz CFILMPQSTbcefgijklmnopqrstuvz bkloveqjfI"
        );
        assert_eq!(
            burst[4],
            ":bnc.test 005 alice CASEMAPPING=ascii PREFIX=(ov)@+ NETWORK=Up :are supported by this server"
        );
        assert!(burst.iter().all(|line| line.len() + 2 <= 512));
    }

    #[test]
    fn irc_session_snapshot_is_authoritative_beyond_the_bounded_buffer() {
        let (handle, ends) = NetworkHandle::channels(1);
        assert_eq!(handle.irc_session_snapshot(), None);

        ends.begin_irc_session("Alice".to_string());
        ends.emit_session_line(":Alice!u@h JOIN #One,,#Two".to_string())
            .expect("within the channel limit");
        ends.emit_session_line(":srv NOTICE Alice :joined".to_string())
            .expect("within the channel limit");
        assert_eq!(
            untimed(handle.buffer_snapshot()),
            vec![":srv NOTICE Alice :joined"]
        );
        assert_eq!(
            handle.irc_session_snapshot(),
            Some(IrcSessionSnapshot {
                nick: "Alice".to_string(),
                channels: vec!["#One".to_string(), "#Two".to_string()],
            })
        );

        ends.emit_session_line(":Alice!u@h NICK :Alicia".to_string())
            .expect("within the channel limit");
        ends.emit_session_line(":op!u@h KICK #one,#two Alicia,Other :gone".to_string())
            .expect("within the channel limit");
        assert_eq!(
            handle.irc_session_snapshot(),
            Some(IrcSessionSnapshot {
                nick: "Alicia".to_string(),
                channels: vec!["#Two".to_string()],
            })
        );

        // A new transport starts from no confirmed memberships; old JOINs are
        // history, not authority over the replacement connection.
        ends.begin_irc_session("Alicia_".to_string());
        assert_eq!(
            handle.irc_session_snapshot(),
            Some(IrcSessionSnapshot {
                nick: "Alicia_".to_string(),
                channels: vec![],
            })
        );
    }

    /// A reader — the networks API, an attaching client — takes a snapshot
    /// whenever it likes. Recording the failure and then, under a second lock
    /// acquisition, when the next attempt fires left a window in which a
    /// network was "reconnecting" after a failure with no next attempt at all.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_retry_is_published_with_its_next_attempt_time_in_one_step() {
        let (handle, mut ends) = NetworkHandle::channels(4);
        let handle = std::sync::Arc::new(handle);
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader = std::thread::spawn({
            let (handle, stop) = (handle.clone(), stop.clone());
            move || {
                let mut torn = 0_u64;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let snapshot = handle.runtime_snapshot();
                    if snapshot.lifecycle == NetworkLifecycle::Reconnecting
                        && snapshot.last_error.is_some()
                        && snapshot.next_retry_at.is_none()
                    {
                        torn += 1;
                    }
                }
                torn
            }
        });
        for _ in 0..20_000 {
            let waited = wait_for_reconnect(
                &mut ends,
                Carried::<()> {
                    config: &(),
                    next: None,
                },
                ConnectionEvent::Reconnecting(NetworkFailure::ConnectionLost),
                None,
                std::time::Duration::from_secs(30),
                std::future::ready(()),
            )
            .await;
            assert!(waited);
            let after = handle.runtime_snapshot();
            assert!(after.last_error.is_some() && after.next_retry_at.is_some());
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            reader.join().expect("reader"),
            0,
            "snapshots showed a retry with a failure but no next attempt time"
        );
    }

    /// Every driver loop abandons its read whenever something else happens.
    /// Those abandoned reads must not push the silence deadline out.
    #[tokio::test]
    async fn a_silence_window_is_not_restarted_by_abandoned_reads() {
        let silence = SilenceDeadline::new(std::time::Duration::from_millis(100));
        let started = std::time::Instant::now();
        loop {
            tokio::select! {
                read = silence.bound(std::future::pending::<()>()) => {
                    assert_eq!(read, None);
                    break;
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(20)) => {
                    assert!(
                        started.elapsed() < std::time::Duration::from_secs(2),
                        "other activity kept a silent upstream looking alive"
                    );
                }
            }
        }
    }

    #[test]
    fn upstream_confirmed_channels_are_bounded_and_structural() {
        let (handle, ends) = NetworkHandle::channels(4);
        ends.begin_irc_session("alice".to_string());
        let change = ends
            .emit_session_line(":alice!u@h JOIN 0,notachannel,#real".to_string())
            .expect("one channel is within the limit");
        assert_eq!(
            change
                .joined
                .iter()
                .map(|channel| channel.as_str())
                .collect::<Vec<_>>(),
            ["#real"]
        );
        assert_eq!(
            handle.irc_session_snapshot().expect("session").channels,
            vec!["#real".to_string()]
        );
        for index in 1..MAX_TRACKED_CHANNELS {
            ends.emit_session_line(format!(":alice!u@h JOIN #flood{index}"))
                .expect("within the channel limit");
        }
        // A membership that is already tracked is not a new one; our own echo
        // still shows the identity the upstream gives us.
        assert_eq!(
            ends.emit_session_line(":alice!u@h JOIN #REAL".to_string()),
            Ok(SessionChange {
                shown_identity: Some(ShownIdentity {
                    user: Some("u".into()),
                    host: "h".into(),
                }),
                ..SessionChange::default()
            })
        );

        let lines_before = handle.buffer_snapshot();
        assert_eq!(
            ends.emit_session_line(":alice!u@h JOIN #one-too-many,#and-another".to_string()),
            Err(ChannelLimitExceeded)
        );
        assert_eq!(
            handle
                .irc_session_snapshot()
                .expect("session")
                .channels
                .len(),
            MAX_TRACKED_CHANNELS,
            "a refused line changes nothing"
        );
        assert_eq!(
            handle.buffer_snapshot(),
            lines_before,
            "a refused line is not published for attached mirrors to overflow on"
        );
        assert!(
            NetworkFailure::ChannelLimitExceeded
                .summary()
                .contains(&MAX_TRACKED_CHANNELS.to_string()),
            "the summary names the real limit"
        );

        let change = ends
            .emit_session_line(":alice!u@h PART #flood1,#never-joined".to_string())
            .expect("a PART cannot exceed the limit");
        assert_eq!(change.left, ["#flood1"]);
        let change = ends
            .emit_session_line(":alice!u@h QUIT :bye".to_string())
            .expect("a QUIT cannot exceed the limit");
        assert_eq!(
            (change.nick, change.joined, change.left, change.untracked),
            (None, Vec::new(), Vec::new(), Vec::new()),
            "a QUIT ends live membership without touching the reconnect intent"
        );
        assert!(
            handle
                .irc_session_snapshot()
                .expect("session")
                .channels
                .is_empty()
        );
    }

    #[test]
    fn replayed_backlog_cannot_grow_an_attach_mirror_past_the_channel_limit() {
        let mut mirror = IrcSessionState::default();
        mirror.begin("alice".to_string());
        for index in 0..MAX_TRACKED_CHANNELS {
            let line = format!(":alice!u@h JOIN #past{index}");
            assert_eq!(mirror.mirror(&line).0, line);
        }
        let (shown, _) = mirror.mirror(":alice!u@h JOIN #past-the-limit");
        assert!(
            shown.starts_with(":*bnc* NOTICE * :upstream line omitted"),
            "{shown}"
        );
        assert_eq!(mirror.channels.len(), MAX_TRACKED_CHANNELS);
    }

    /// Before a bridge has connected it has no channels to be in: a JOIN is
    /// temporarily unavailable, not relayed to a driver that can only refuse
    /// it, and a NICK is refused as it is once connected.
    #[tokio::test]
    #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
    async fn a_bridge_answers_join_and_nick_itself_before_it_connects() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        let (handle, mut ends) = NetworkHandle::bridge_channels(4);
        let (client, attach) = attach_task(std::sync::Arc::new(handle), AttachCaps::default());
        let (read, mut write) = tokio::io::split(client);
        write
            .write_all(b"NICK alice\r\nNICK bob\r\nJOIN #general\r\nJOIN\r\n")
            .await
            .expect("send");
        let mut lines = tokio::io::BufReader::new(read).lines();
        let mut replies = Vec::new();
        while replies.len() < 3 {
            let line = tokio::time::timeout(std::time::Duration::from_secs(1), lines.next_line())
                .await
                .expect("attach went silent")
                .expect("attach read")
                .expect("attach closed");
            if !line.starts_with(":*bnc* NOTICE") && !line.starts_with(":bnc.test ") {
                replies.push(line);
            }
        }
        assert!(replies[0].starts_with(":*bnc* 447 alice :"), "{replies:?}");
        assert!(
            replies[1].starts_with(":*bnc* 437 alice #general :"),
            "{replies:?}"
        );
        assert_eq!(replies[2], ":*bnc* 461 alice JOIN :Not enough parameters");
        // Nothing reached the driver.
        assert!(
            ends.commands.try_recv().is_err(),
            "a session command was relayed to the bridge"
        );
        drop(write);
        drop(lines);
        attach.await.expect("attach task").expect("attach result");
    }

    /// A bridge's own JOIN answer echoes each requested channel as one middle
    /// parameter: `JOIN :#a b` used to answer `437 alice #a b :…` and
    /// `JOIN ::x` `437 alice :x :…`, both of which shift the reply's
    /// parameters. Each is the `*` placeholder.
    #[tokio::test]
    #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
    async fn a_bridge_join_echoes_an_unframeable_channel_as_a_placeholder() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        let (handle, _ends) = NetworkHandle::bridge_channels(4);
        let (client, attach) = attach_task(std::sync::Arc::new(handle), AttachCaps::default());
        let (read, mut write) = tokio::io::split(client);
        write
            .write_all(b"JOIN :#a b\r\nJOIN ::x\r\n")
            .await
            .expect("send");
        let mut lines = tokio::io::BufReader::new(read).lines();
        let mut replies = Vec::new();
        while replies.len() < 2 {
            let line = tokio::time::timeout(std::time::Duration::from_secs(1), lines.next_line())
                .await
                .expect("attach went silent")
                .expect("attach read")
                .expect("attach closed");
            if !line.starts_with(":*bnc* NOTICE") && !line.starts_with(":bnc.test ") {
                replies.push(line);
            }
        }
        for reply in &replies {
            assert!(reply.starts_with(":*bnc* 437 alice * :"), "{replies:?}");
        }
        drop(write);
        drop(lines);
        attach.await.expect("attach task").expect("attach result");
    }

    /// A channel whose JOIN has aged out of the replay is re-stated with a
    /// synthesized JOIN, and — the session never having received its member
    /// list — its real member list and topic are asked of the upstream on the
    /// attaching client's behalf: the answers follow the JOIN for that client
    /// alone, as a server's own would.
    #[tokio::test]
    async fn raw_attach_snapshot_renames_and_rejoins_the_downstream_client() {
        use tokio::io::AsyncReadExt;

        let (handle, mut ends) = NetworkHandle::channels(4);
        handle.runtime.connected();
        ends.begin_irc_session("upstreamNick".to_string());
        ends.emit_session_line(":upstreamNick!u@h JOIN #current".to_string())
            .expect("within the channel limit");
        // The session's start and its JOIN age out of the bounded ring.
        for index in 0..4 {
            ends.emit_line(format!(":srv NOTICE upstreamNick :filler {index}"));
        }
        let (mut client, attach) = attach_task(std::sync::Arc::new(handle), AttachCaps::default());

        let mut bytes = vec![0; 4096];
        let mut output = String::new();
        while !output.contains(" JOIN #current\r\n") {
            let count =
                tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut bytes))
                    .await
                    .expect("attach output timed out")
                    .expect("read attach output");
            output.push_str(&String::from_utf8_lossy(&bytes[..count]));
        }
        assert!(
            output.starts_with(":bnc.test 001 upstreamNick :"),
            "welcomed under the session's nick: {output}"
        );
        assert!(!output.contains(" NICK "), "{output}");
        assert!(
            output.contains(":upstreamNick!~bnc@e6irc JOIN #current\r\n"),
            "{output}"
        );
        assert!(
            !output.contains(" 353 "),
            "no member list of the bouncer's making: {output}"
        );
        let mut asked = Vec::new();
        while let Ok(command) = ends.commands.try_recv() {
            asked.push((command.origin, command.line));
        }
        let origin = asked.first().map(|(origin, _)| *origin).expect("asked");
        assert_eq!(
            asked,
            [
                (origin, "TOPIC #current".to_string()),
                (origin, "NAMES #current".to_string())
            ]
        );
        for reply in [
            ":up 332 upstreamNick #current :the topic",
            ":up 353 upstreamNick = #current :upstreamNick peer",
            ":up 366 upstreamNick #current :End of /NAMES list",
        ] {
            ends.emit_reply(origin, reply.to_string());
        }
        let mut output = String::new();
        while !output.contains(" 366 ") {
            let count =
                tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut bytes))
                    .await
                    .expect("the member list reached the client")
                    .expect("read attach output");
            output.push_str(&String::from_utf8_lossy(&bytes[..count]));
        }
        assert!(
            output.contains(":up 332 upstreamNick #current :the topic\r\n"),
            "{output}"
        );
        assert!(
            output.contains(":up 353 upstreamNick = #current :upstreamNick peer\r\n"),
            "{output}"
        );
        ends.begin_irc_session("upstreamNick2".to_string());
        let count =
            tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut bytes))
                .await
                .expect("session reset output timed out")
                .expect("read session reset output");
        let output = String::from_utf8_lossy(&bytes[..count]);
        assert!(
            output.contains(":upstreamNick NICK :upstreamNick2\r\n"),
            "{output}"
        );
        assert!(
            output.contains(":upstreamNick2!~bnc@e6irc PART #current :upstream session reset\r\n"),
            "{output}"
        );
        drop(client);
        attach.await.expect("attach task").expect("attach result");
    }

    #[tokio::test]
    async fn registered_attach_keeps_cap_and_sasl_off_the_shared_upstream() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (handle, mut ends) = NetworkHandle::channels(4);
        ends.begin_irc_session("alice".to_string());
        let (mut client, attach) = attach_task(std::sync::Arc::new(handle), AttachCaps::default());

        let mut bytes = vec![0; 4096];
        tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut bytes))
            .await
            .expect("initial attach output")
            .expect("read initial attach output");

        client
            .write_all(b"CAP REQ :message-tags\r\n")
            .await
            .expect("write CAP request");
        let count =
            tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut bytes))
                .await
                .expect("CAP reply")
                .expect("read CAP reply");
        let output = String::from_utf8_lossy(&bytes[..count]);
        assert!(
            output.contains(":*bnc* CAP alice ACK :message-tags\r\n"),
            "{output}"
        );

        client
            .write_all(b"AUTHENTICATE PLAIN\r\n")
            .await
            .expect("write repeated SASL");
        let count =
            tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut bytes))
                .await
                .expect("SASL reply")
                .expect("read SASL reply");
        let output = String::from_utf8_lossy(&bytes[..count]);
        assert!(output.contains(" 907 alice :"), "{output}");
        assert!(matches!(
            ends.commands.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));

        drop(client);
        attach.await.expect("attach task").expect("attach result");
    }

    #[test]
    fn filter_tags_surfaces_a_malformed_tag_only_line() {
        // A hostile upstream can store a line that is a leading `@` with no
        // space — a tag section and no message. It must not reach a no-tags
        // client as a `@`-prefixed line; there is nothing deliverable, so it is
        // replaced with a safe, visible notice. (Found by the bouncer fuzz
        // target.)
        let notice = ":*bnc* NOTICE * :upstream line omitted: malformed IRC message";
        assert_eq!(
            filter_tags("@time=x;msgid=1", AttachCaps::default()),
            Some(notice.into())
        );
        assert_eq!(
            filter_tags(
                "@time=x",
                AttachCaps {
                    server_time: true,
                    ..AttachCaps::default()
                }
            ),
            Some(notice.into())
        );
        // A well-formed line (tags then a space then a body) is unaffected.
        assert_eq!(
            filter_tags("@time=x PRIVMSG #c :hi", AttachCaps::default()),
            Some("PRIVMSG #c :hi".into())
        );
    }

    #[test]
    fn downstream_parser_enforces_each_irc_wire_budget_before_relay() {
        assert!(parse_client_line("PRIVMSG #c :hello").is_ok());
        assert!(matches!(
            parse_client_line(&format!("PRIVMSG #c :{}", "x".repeat(500))),
            Err(ClientLineError::TooLong)
        ));
        assert!(matches!(
            parse_client_line("PRIVMSG #c :bad\0line"),
            Err(ClientLineError::Malformed)
        ));
    }

    #[test]
    fn network_handle_never_queues_invalid_client_lines() {
        let (handle, mut ends) = NetworkHandle::channels(16);
        assert_eq!(
            handle.send("PRIVMSG #c :bad\nJOIN #other"),
            SendOutcome::Rejected(ClientLineError::Malformed)
        );
        assert_eq!(
            handle.send(&format!("PRIVMSG #c :{}", "x".repeat(500))),
            SendOutcome::Rejected(ClientLineError::TooLong)
        );
        assert!(matches!(
            ends.commands.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn filter_tags_gates_each_family_by_negotiated_cap() {
        let line = "@time=2020-01-01T00:00:00.000Z;account=alice;msgid=abc :n!u@h PRIVMSG #c :hi";
        // No caps: every tag is stripped, the tag section disappears entirely.
        let none = filter_tags(line, AttachCaps::default());
        assert_eq!(none.as_deref(), Some(":n!u@h PRIVMSG #c :hi"));
        // server-time only keeps `time=`, drops account/msgid.
        let st = filter_tags(
            line,
            AttachCaps {
                server_time: true,
                ..Default::default()
            },
        );
        assert_eq!(
            st.as_deref(),
            Some("@time=2020-01-01T00:00:00.000Z :n!u@h PRIVMSG #c :hi")
        );
        // account-tag only keeps `account=`.
        let at = filter_tags(
            line,
            AttachCaps {
                account_tag: true,
                ..Default::default()
            },
        );
        assert_eq!(at.as_deref(), Some("@account=alice :n!u@h PRIVMSG #c :hi"));
        // message-tags gates everything else (msgid) but not time/account.
        let mt = filter_tags(
            line,
            AttachCaps {
                message_tags: true,
                ..Default::default()
            },
        );
        assert_eq!(mt.as_deref(), Some("@msgid=abc :n!u@h PRIVMSG #c :hi"));
        // All three: full line preserved in original tag order.
        let all = filter_tags(
            line,
            AttachCaps {
                server_time: true,
                message_tags: true,
                account_tag: true,
                ..Default::default()
            },
        );
        assert_eq!(all.as_deref(), Some(line));
        // A line without a tag section is returned unchanged.
        let bare = ":n!u@h PRIVMSG #c :hi";
        assert_eq!(
            filter_tags(bare, AttachCaps::default()).as_deref(),
            Some(bare)
        );
        assert_eq!(
            filter_tags("@+typing=active :n!u@h TAGMSG #c", AttachCaps::default()),
            None,
            "TAGMSG itself is gated by message-tags"
        );
    }

    /// Lines carrying kilobytes of tags fill a backlog's bytes long before
    /// its line cap: the ring keeps `cap` lines' worth of bytes, oldest going
    /// first, and always its newest line.
    #[test]
    fn a_backlog_is_bounded_in_bytes_as_well_as_lines() {
        let cap = 100;
        let mut ring = Buffer::new(cap);
        let tagged = |i: usize| format!("@+x={} :n!u@h PRIVMSG #c :line{i}", "t".repeat(4_000));
        for i in 0..cap {
            ring.push(tagged(i));
            let held: usize = ring.lines().map(|entry| entry.line.len()).sum();
            assert_eq!(held, ring.bytes);
            assert!(
                held <= cap * BACKLOG_BYTES_PER_LINE,
                "{held} bytes after {i}"
            );
        }
        let kept = ring.snapshot();
        assert!(
            kept.len() < cap / 5,
            "{} four-kilobyte lines kept",
            kept.len()
        );
        assert!(kept.last().is_some_and(|line| line.ends_with("line99")));
        // Ordinary lines are held to the line cap, as before.
        let mut plain = Buffer::new(cap);
        for i in 0..3 * cap {
            plain.push(format!(":n!u@h PRIVMSG #c :line{i}"));
        }
        assert_eq!(plain.snapshot().len(), cap);
        // One line larger than the whole budget is still the newest line held.
        let mut tiny = Buffer::new(1);
        tiny.push(tagged(1));
        tiny.push(tagged(2));
        assert_eq!(tiny.snapshot().len(), 1);
    }

    /// Restoring a stored backlog fills only the bytes left, newest first.
    #[test]
    fn a_restored_backlog_fills_only_the_bytes_left() {
        let (handle, _ends) = NetworkHandle::channels(10);
        let big = format!("@+x={} :n!u@h PRIVMSG #c :old", "t".repeat(2_000));
        let stored: Vec<crate::db::StoredBacklogLine> = (0..10)
            .map(|i| stored_line(format!("{big}{i}"), "2026-01-01T00:00:00.000Z"))
            .collect();
        handle.preload_front(stored);
        let buffer = handle.buffer.lock().expect("buffer");
        let held: usize = buffer.lines().map(|entry| entry.line.len()).sum();
        assert_eq!(held, buffer.bytes);
        assert!(held <= buffer.byte_cap, "{held} bytes");
        let lines = buffer.snapshot();
        assert!(lines.len() < 10 && !lines.is_empty(), "{}", lines.len());
        assert!(lines.last().is_some_and(|line| line.ends_with("old9")));
    }

    #[test]
    fn buffer_never_grows_past_cap() {
        let mut b = Buffer::new(3);
        for i in 0..100 {
            b.push(format!("line{i}"));
        }
        assert_eq!(b.snapshot().len(), 3, "ring must stay bounded at cap");
        // A degenerate cap of 0 must still be bounded, not unbounded.
        let mut z = Buffer::new(0);
        for i in 0..100 {
            z.push(format!("line{i}"));
        }
        assert!(z.snapshot().len() <= 1, "cap 0 must not grow without bound");
    }

    /// History retention bounds the backlog as it bounds `bnc_buffer`: a line
    /// older than it is neither replayed nor kept, and a change of it applies
    /// at once to a ring already holding lines.
    #[test]
    fn a_backlog_does_not_replay_lines_older_than_history_retention() {
        let retention = crate::core::HistoryRetention::default();
        let mut ring = Buffer::new(8);
        ring.retention = retention.clone();
        let day = 24 * 60 * 60 * 1000;
        let at = |ago: u64| {
            e6irc_proto::time::server_time(e6irc_proto::time::Millis::from_millis(
                epoch_millis().as_millis() - ago,
            ))
        };
        ring.push(format!("@time={} :a!a@h PRIVMSG #c :stale", at(3 * day)));
        ring.push(format!("@time={} :a!a@h PRIVMSG #c :fresh", at(day / 2)));
        let texts = |lines: Vec<String>| -> Vec<String> {
            lines
                .iter()
                .map(|line| line.rsplit_once(" :").expect("text").1.to_string())
                .collect()
        };
        assert_eq!(texts(ring.snapshot()), ["stale", "fresh"], "no cutoff set");
        retention.set_days(1);
        assert_eq!(texts(ring.snapshot()), ["fresh"]);
        let replay = ring.replay_after(None);
        assert_eq!(
            texts(replay.lines.iter().map(|line| line.line.clone()).collect()),
            ["fresh"]
        );
        // The next line in evicts what retention no longer keeps.
        ring.push(format!("@time={} :a!a@h PRIVMSG #c :newest", at(0)));
        assert_eq!(ring.entries.len(), 2, "the stale line was evicted");
    }

    /// Each capability has its own bit in an attachment's record, so every
    /// combination comes back as it went.
    #[test]
    fn attach_capabilities_round_trip_through_their_bits() {
        for bits in 0..(1u16 << 10) {
            assert_eq!(AttachCaps::from_bits(bits).bits(), bits);
        }
    }

    /// A ring whose last stop stored every line continues its epoch: each
    /// restored line has the position it had, so a cursor from before the
    /// restart resumes exactly; a line the driver said before the restore
    /// moves past them, and its persistence is told where it moved. Stored
    /// positions that do not fit the claim change nothing.
    #[test]
    fn a_ring_continues_its_stored_epoch_after_a_clean_stop() {
        let (handle, ends) = NetworkHandle::channels(8);
        ends.emit_line(":a!a@h PRIVMSG #c :said before the restore".into());
        let (fresh_epoch, said_at) = handle.ring_position();
        let stored = |text: &str, seq| crate::db::StoredBacklogLine {
            line: format!(":a!a@h PRIVMSG #c :{text}"),
            stored_at: "2026-01-01T00:00:00.000Z".into(),
            own_nick: crate::db::StoredOwnNick::NoNick,
            seq: Some(seq),
        };
        let misfit = handle
            .continue_ring(7, 100, vec![stored("late", 101)], None)
            .expect_err("a position past the claim");
        assert_eq!(misfit.len(), 1);
        assert_eq!(handle.ring_position(), (fresh_epoch, said_at));

        let renumbered = handle
            .continue_ring(
                7,
                100,
                vec![stored("one", 98), stored("two", 99), stored("three", 100)],
                None,
            )
            .expect("the positions fit");
        assert_eq!(renumbered.now(said_at), 101);
        assert_eq!(renumbered.now(200), 200, "a later line did not move");
        assert_eq!(handle.ring_position(), (7, 101));
        let before_restart = ReplayCursor { epoch: 7, seq: 99 };
        let replay = handle
            .buffer
            .lock()
            .expect("buffer")
            .replay_after(Some(before_restart));
        assert!(replay.resumed);
        assert_eq!(
            replayed(&replay),
            [
                ":a!a@h PRIVMSG #c :three",
                ":a!a@h PRIVMSG #c :said before the restore"
            ]
        );
        assert_eq!(
            replay.lines.iter().map(|line| line.seq).collect::<Vec<_>>(),
            [100, 101]
        );
    }

    /// A continued ring refuses a cursor before a position storage let go of
    /// from among what it keeps — a busy conversation's line trimmed from
    /// the middle — and honours one after it.
    #[test]
    fn a_continued_ring_refuses_a_cursor_before_a_line_storage_let_go_of() {
        let (handle, _ends) = NetworkHandle::channels(8);
        let stored = |text: &str, seq| crate::db::StoredBacklogLine {
            line: format!(":a!a@h PRIVMSG #c :{text}"),
            stored_at: "2026-01-01T00:00:00.000Z".into(),
            own_nick: crate::db::StoredOwnNick::NoNick,
            seq: Some(seq),
        };
        handle
            .continue_ring(
                7,
                100,
                vec![stored("one", 97), stored("four", 100)],
                Some(99),
            )
            .expect("the positions fit");
        let buffer = handle.buffer.lock().expect("buffer");
        assert!(
            !buffer
                .replay_after(Some(ReplayCursor { epoch: 7, seq: 97 }))
                .resumed,
            "98 and 99 were trimmed from the middle"
        );
        assert!(
            buffer
                .replay_after(Some(ReplayCursor { epoch: 7, seq: 99 }))
                .resumed
        );
    }

    fn replayed(replay: &Replay) -> Vec<String> {
        untimed(replay.lines.iter().map(|entry| entry.line.as_str()))
    }

    /// `text` said in `channel`, as the ring holds it.
    fn said(channel: &str, text: &str) -> String {
        format!(":peer!p@h PRIVMSG {channel} :{text}")
    }

    #[test]
    fn history_through_says_whether_the_lines_after_the_cursor_are_kept() {
        let mut ring = Buffer::new(2);
        let first = ring.push(said("#c", "one"));
        let second = ring.push(said("#c", "two"));
        let at_first = ring.replay_after(None).cursor_at(first);
        let kept = ring
            .history_through(at_first, "#c")
            .expect("this ring's cursor");
        assert_eq!(kept.lines.len(), 2);
        assert_eq!((kept.held_after, kept.successors_retained), (1, true));
        assert_eq!(kept.cursor_before(second), at_first);
        // "one" is gone, but everything after it is kept.
        ring.push(said("#c", "three"));
        let kept = ring
            .history_through(at_first, "#c")
            .expect("this ring's cursor");
        assert_eq!((kept.held_after, kept.successors_retained), (0, true));
        // "two" is gone too: a reader holding it holds what the ring does not.
        ring.push(said("#c", "four"));
        let evicted = ring
            .history_through(at_first, "#c")
            .expect("this ring's cursor");
        assert_eq!(
            (evicted.held_after, evicted.successors_retained),
            (0, false)
        );
    }

    /// A busy channel's flood lets lines go from the middle of the ring: a
    /// quiet conversation paged from any cursor still finds every line of it
    /// after the cursor held, and a busy one is joinable exactly from the
    /// cursors whose successors it still holds — its lines go oldest first.
    #[test]
    fn history_through_is_exact_when_lines_go_from_the_middle() {
        let mut ring = Buffer::new(6);
        let lobby: Vec<u64> = (1..=4)
            .map(|n| ring.push(said("#lobby", &format!("lobby-{n}"))))
            .collect();
        let busy: Vec<u64> = (1..=20)
            .map(|n| ring.push(said("#busy", &format!("busy-{n}"))))
            .collect();
        let cursor = |seq| ring.replay_after(None).cursor_at(seq);
        let held = |ring: &Buffer, conversation: &str| {
            untimed(ring.snapshot())
                .into_iter()
                .filter(|line| line.contains(&format!("PRIVMSG {conversation} ")))
                .count()
        };
        assert_eq!(held(&ring, "#lobby"), 2, "{:?}", ring.snapshot());
        assert_eq!(held(&ring, "#busy"), 4, "{:?}", ring.snapshot());
        // #lobby lost its two oldest lines: from its second on, the rest is
        // held, so a cursor at it joins; one before it does not.
        let at_lobby_1 = cursor(lobby[1]);
        let paged = ring
            .history_through(at_lobby_1, "#lobby")
            .expect("this ring's cursor");
        assert!(paged.successors_retained);
        let before_lobby_1 = cursor(lobby[0]);
        assert!(
            !ring
                .history_through(before_lobby_1, "#lobby")
                .expect("this ring's cursor")
                .successors_retained
        );
        // #busy lost every line but its last four, from the middle of the
        // ring: a cursor before them does not join, one at the last lost does.
        assert!(
            !ring
                .history_through(cursor(busy[14]), "#busy")
                .expect("this ring's cursor")
                .successors_retained
        );
        assert!(
            ring.history_through(cursor(busy[15]), "#busy")
                .expect("this ring's cursor")
                .successors_retained
        );
        // A conversation the flood never touched is joinable from anywhere.
        assert!(
            ring.history_through(cursor(busy[0]), "#quiet")
                .expect("this ring's cursor")
                .successors_retained
        );
    }

    /// A busy channel makes room from its own oldest lines, not from a quiet
    /// conversation's: the private message and the quiet channel's line said
    /// before a flood of the busy channel are still held after it, while the
    /// ring keeps to its cap.
    #[test]
    fn a_busy_channel_does_not_evict_a_quiet_conversation() {
        let mut ring = Buffer::new(10);
        ring.push_said(":bob!b@h PRIVMSG me :are you there?".into(), Some("me"));
        ring.push_said(":carol!c@h PRIVMSG #quiet :morning".into(), Some("me"));
        for n in 0..100 {
            ring.push_said(format!(":dan!d@h PRIVMSG #busy :flood {n}"), Some("me"));
        }
        let held = untimed(ring.snapshot());
        assert_eq!(held.len(), 10, "{held:?}");
        assert!(held.contains(&":bob!b@h PRIVMSG me :are you there?".to_string()));
        assert!(held.contains(&":carol!c@h PRIVMSG #quiet :morning".to_string()));
        assert_eq!(
            held.last().map(String::as_str),
            Some(":dan!d@h PRIVMSG #busy :flood 99")
        );
        assert!(held.contains(&":dan!d@h PRIVMSG #busy :flood 92".to_string()));
        assert!(!held.contains(&":dan!d@h PRIVMSG #busy :flood 91".to_string()));
    }

    /// A line let go of from the middle of the ring is a gap after every
    /// cursor before it: such a cursor is refused, and the whole ring
    /// replayed, rather than resumed past a line it never showed.
    #[test]
    fn a_cursor_before_a_line_let_go_of_is_refused() {
        let mut ring = Buffer::new(4);
        let first = ring.push_said(":bob!b@h PRIVMSG me :hello".into(), Some("me"));
        ring.push_said(":dan!d@h PRIVMSG #busy :one".into(), Some("me"));
        ring.push_said(":dan!d@h PRIVMSG #busy :two".into(), Some("me"));
        let cursor = ring.replay_after(None).cursor_at(first);
        assert!(ring.replay_after(Some(cursor)).resumed);
        for line in ["three", "four"] {
            ring.push_said(format!(":dan!d@h PRIVMSG #busy :{line}"), Some("me"));
        }
        assert!(
            untimed(ring.snapshot()).contains(&":bob!b@h PRIVMSG me :hello".to_string()),
            "the front was kept"
        );
        assert!(!ring.replay_after(Some(cursor)).resumed);
    }

    /// The session's own rename, joins and parts go only from the front, so
    /// the head state that a replay starts from stays the state at its
    /// oldest line.
    #[test]
    fn the_sessions_own_lines_go_only_from_the_front() {
        let mut ring = Buffer::new(4);
        ring.push_said(":me!u@h NICK :you".into(), Some("me"));
        for n in 0..10 {
            ring.push_said(format!(":dan!d@h PRIVMSG #busy :flood {n}"), Some("you"));
        }
        assert!(
            !untimed(ring.snapshot()).contains(&":me!u@h NICK :you".to_string()),
            "it went from the front"
        );
        assert_eq!(
            ring.head.as_ref().and_then(|head| head.nick.clone()),
            None,
            "a head that began knowing no nick learns none from a rename"
        );
        assert_eq!(ring.shares.get(&Share::Pinned), None);
    }

    /// A cursor is honoured exactly while every line after it is still held;
    /// a position the ring evicted, another ring's cursor, or none at all
    /// replays the whole ring — and says which happened.
    #[test]
    fn replay_after_a_cursor_is_exact_or_refused() {
        let mut ring = Buffer::new(3);
        let first = ring.push("one".into());
        let second = ring.push("two".into());

        let start = ring.replay_after(None);
        assert_eq!(replayed(&start), ["one", "two"]);
        assert!(!start.resumed);
        assert_eq!(start.position(), start.cursor_at(second));

        let resumed = ring.replay_after(Some(start.cursor_at(first)));
        assert_eq!(replayed(&resumed), ["two"]);
        assert!(resumed.resumed);
        let caught_up = ring.replay_after(Some(start.position()));
        assert!(replayed(&caught_up).is_empty());
        assert!(caught_up.resumed, "nothing new is still an exact resume");

        // The position just before the oldest retained line is still exact:
        // everything after it is held.
        ring.push("three".into());
        ring.push("four".into());
        let oldest_retained = ring.lines().next().expect("ring holds lines").seq;
        let edge = ring.replay_after(Some(start.cursor_at(oldest_retained - 1)));
        assert_eq!(replayed(&edge), ["two", "three", "four"]);
        assert!(edge.resumed);
        let evicted = ring.replay_after(Some(start.cursor_at(oldest_retained - 2)));
        assert_eq!(replayed(&evicted), ["two", "three", "four"]);
        assert!(
            !evicted.resumed,
            "a position the ring evicted cannot be resumed"
        );

        // Beyond the newest position nothing was ever pushed: not this ring's.
        let ahead = ring.replay_after(Some(start.cursor_at(ring.position() + 1)));
        assert!(!ahead.resumed);

        let other_ring = Buffer::new(3);
        let foreign = ring.replay_after(Some(other_ring.replay_after(None).position()));
        assert_eq!(replayed(&foreign), ["two", "three", "four"]);
        assert!(!foreign.resumed, "another ring's cursor names nothing here");

        // The wire form round-trips and refuses anything else.
        let cursor = start.cursor_at(first);
        assert_eq!(ReplayCursor::parse(&cursor.to_string()), Some(cursor));
        for text in ["", "7", "7:", ":7", "a:b", "7:-1", "1:2:3"] {
            assert_eq!(ReplayCursor::parse(text), None, "{text:?}");
        }
    }

    /// Lines restored from storage sit below every pushed line, in order, and
    /// an empty ring still answers with a cursor a client can return with.
    #[test]
    fn preloaded_history_takes_positions_below_the_live_lines() {
        let (handle, ends) = NetworkHandle::channels(4);
        let empty = handle.subscribe_with_replay_snapshot(None).replay;
        assert!(replayed(&empty).is_empty());
        let resumed_from_empty = handle
            .subscribe_with_replay_snapshot(Some(empty.position()))
            .replay;
        assert!(resumed_from_empty.resumed);

        ends.emit_line("live".into());
        let stored = |line: &str| stored_line(line, "2026-01-01T00:00:00.000Z");
        handle.preload_front(vec![stored("older"), stored("old")]);
        let replay = handle.subscribe_with_replay_snapshot(None).replay;
        assert_eq!(replayed(&replay), ["older", "old", "live"]);
        let positions: Vec<u64> = replay.lines.iter().map(|entry| entry.seq).collect();
        assert!(
            positions.windows(2).all(|pair| pair[0] + 1 == pair[1]),
            "{positions:?}"
        );
        assert!(
            positions[0] >= 1,
            "restored positions stay positive: {positions:?}"
        );
        let after_older = handle
            .subscribe_with_replay_snapshot(Some(replay.cursor_at(positions[0])))
            .replay;
        assert_eq!(replayed(&after_older), ["old", "live"]);
        assert!(after_older.resumed);
    }

    /// A reader holding every line after a cursor is given only what came at
    /// or before it; another ring's cursor, or one naming a position this ring
    /// never reached, is refused rather than answered with the wrong lines.
    #[test]
    fn buffer_through_returns_only_the_lines_at_or_before_the_cursor() {
        let (handle, ends) = NetworkHandle::channels(3);
        for line in ["a", "b", "c"] {
            ends.emit_line(line.into());
        }
        let replay = handle.subscribe_with_replay_snapshot(None).replay;
        let positions: Vec<u64> = replay.lines.iter().map(|entry| entry.seq).collect();
        assert_eq!(
            handle
                .buffer_through(replay.cursor_at(positions[1]))
                .map(untimed),
            Some(vec!["a".to_string(), "b".to_string()])
        );
        assert_eq!(
            handle.buffer_through(replay.position()).map(untimed),
            Some(vec!["a".to_string(), "b".to_string(), "c".to_string()])
        );
        assert_eq!(
            handle.buffer_through(replay.cursor_at(positions[2] + 1)),
            None,
            "a position the ring has not reached names nothing"
        );
        let foreign =
            ReplayCursor::parse(&format!("{}:{}", replay.epoch + 1, positions[1])).expect("cursor");
        assert_eq!(handle.buffer_through(foreign), None);

        // Evicted past the cursor: nothing at or before it is retained.
        for line in ["d", "e", "f"] {
            ends.emit_line(line.into());
        }
        assert_eq!(
            handle.buffer_through(replay.cursor_at(positions[1])),
            Some(Vec::new())
        );
    }

    /// Read everything an attach writes until it goes quiet.
    async fn attach_output(client: &mut tokio::io::DuplexStream) -> String {
        use tokio::io::AsyncReadExt;
        let mut output = Vec::new();
        let mut bytes = vec![0; 65536];
        while let Ok(Ok(count)) = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            client.read(&mut bytes),
        )
        .await
        {
            if count == 0 {
                break;
            }
            output.extend_from_slice(&bytes[..count]);
        }
        String::from_utf8_lossy(&output).into_owned()
    }

    fn attach_task(
        handle: std::sync::Arc<NetworkHandle>,
        caps: AttachCaps,
    ) -> (
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<std::io::Result<AttachEnd>>,
    ) {
        let (client, server) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(async move {
            attach(
                attach_link::over_stream(server).await,
                ClientInput::default(),
                &handle,
                caps,
                account_lease::lease_for_test("alice"),
                Greeting {
                    server_name: "bnc.test",
                    network: "net",
                    requested_nick: "alice",
                },
                ATTACH_LIVENESS_INTERVAL,
            )
            .await
        });
        (client, task)
    }

    /// Attach with server-time, read everything the attach writes (its
    /// `time` tags stripped) and let it finish.
    async fn attach_to_completion(handle: NetworkHandle) -> String {
        let caps = AttachCaps {
            server_time: true,
            ..AttachCaps::default()
        };
        let (mut client, task) = attach_task(std::sync::Arc::new(handle), caps);
        let output = untimed(attach_output(&mut client).await.lines()).join("\n");
        drop(client);
        task.await.expect("attach task").expect("attach");
        output
    }

    /// On a `CASEMAPPING=ascii` network `dev[m]` and `dev{m}` are two people
    /// and `#a[`, `#a{` two channels: another user's NICK or JOIN is not ours,
    /// and leaving one channel leaves only that one.
    #[test]
    fn the_session_compares_names_the_networks_way() {
        let (handle, ends) = NetworkHandle::channels(16);
        ends.begin_irc_session("dev[m]".to_string());
        ends.emit_session_line(
            ":srv 005 dev[m] CASEMAPPING=ascii CHANTYPES=# :are supported by this server"
                .to_string(),
        )
        .expect("tracked");
        let change = ends
            .emit_session_line(":dev{m}!x@h NICK other".to_string())
            .expect("tracked");
        assert_eq!(change.nick, None, "someone else's rename is not ours");
        ends.emit_session_line(":dev{m}!x@h JOIN #secret".to_string())
            .expect("tracked");
        for channel in ["#a[", "#a{"] {
            ends.emit_session_line(format!(":dev[m]!x@h JOIN {channel}"))
                .expect("tracked");
        }
        let change = ends
            .emit_session_line(":dev[m]!x@h PART #a[".to_string())
            .expect("tracked");
        assert_eq!(change.left, ["#a["]);
        let session = handle.irc_session_snapshot().expect("a session");
        assert_eq!(session.nick, "dev[m]");
        assert_eq!(session.channels, ["#a{"]);
        // Nor are `&` channels channels on a network whose CHANTYPES is `#`.
        let change = ends
            .emit_session_line(":dev[m]!x@h JOIN &local".to_string())
            .expect("an untracked name is not an overflow");
        assert_eq!(change.untracked, ["&local"]);
    }

    /// A line without a `time` is stamped with its arrival as it is taken in,
    /// so the replay and CHATHISTORY (which reads the stored time) agree; a
    /// valid upstream `time` is kept, and so is a stored line's own time.
    #[test]
    fn every_line_is_timed_when_it_is_taken_in() {
        let (handle, ends) = NetworkHandle::channels(8);
        ends.emit_line(":peer!u@h PRIVMSG #room :untimed".to_string());
        ends.emit_line("@time=2026-01-02T03:04:05.006Z :peer!u@h PRIVMSG #room :timed".to_string());
        ends.emit_line("@time=nonsense;+x=y :peer!u@h PRIVMSG #room :bad time".to_string());
        handle.preload_front(vec![stored_line(
            ":peer!u@h PRIVMSG #room :stored",
            "2025-12-31T23:59:59.999Z",
        )]);
        let lines = handle.buffer_snapshot();
        assert_eq!(
            lines[0],
            "@time=2025-12-31T23:59:59.999Z :peer!u@h PRIVMSG #room :stored"
        );
        let arrival = lines[1]
            .strip_prefix("@time=")
            .and_then(|rest| rest.split_once(' '))
            .map(|(time, _)| time)
            .expect("stamped");
        assert!(e6irc_proto::time::parse_server_time_millis(arrival).is_some());
        assert_eq!(
            lines[2],
            "@time=2026-01-02T03:04:05.006Z :peer!u@h PRIVMSG #room :timed"
        );
        let replaced = e6irc_proto::message::Message::parse(&lines[3]).expect("valid");
        assert_eq!(
            replaced.tags.iter().filter(|tag| tag.key == "time").count(),
            1
        );
        assert!(
            replaced
                .tag("time")
                .and_then(|tag| tag.value.as_deref())
                .and_then(e6irc_proto::time::parse_server_time_millis)
                .is_some()
        );
        assert!(replaced.tag("+x").is_some());
    }

    /// The network's registration burst describes it to the bouncer and is
    /// never an attached client's: not relayed, not retained, but read. A
    /// later 005 is told live, less what the bouncer answers for itself.
    #[test]
    fn the_registration_burst_is_read_and_never_relayed() {
        let (handle, ends) = NetworkHandle::channels(64);
        let mut events = handle.subscribe();
        ends.begin_irc_session("alice".to_string());
        drop(events.try_recv());
        for line in [
            ":up 002 alice :Your host is up",
            ":up 003 alice :created",
            ":up 004 alice up v1 i o b",
            ":up 005 alice CHATHISTORY=1000 MSGREFTYPES=msgid NETWORK=Up :are supported by this server",
            ":up 251 alice :There are 3 users",
            ":up 375 alice :- up Message of the Day -",
            ":up 372 alice :- welcome",
            ":up 376 alice :End of /MOTD command.",
        ] {
            ends.emit_session_line(line.to_string()).expect("tracked");
        }
        assert!(
            handle.buffer_snapshot().is_empty(),
            "{:?}",
            handle.buffer_snapshot()
        );
        // Nothing of it is published but what it said, once it has ended: a
        // client welcomed before it is told what changed.
        match events.try_recv() {
            Ok(DriverEvent::Features(features)) => {
                assert_eq!(features, handle.upstream_features());
            }
            other => panic!("expected the burst's features, got {other:?}"),
        }
        assert_eq!(
            events.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        );
        assert!(
            handle
                .upstream_features()
                .isupport
                .contains(&"NETWORK=Up".to_string())
        );
        let welcome = serve::welcome_to("bnc.test", "net", &handle, "alice").lines;
        assert!(
            welcome
                .iter()
                .all(|line| !line.contains("CHATHISTORY=1000")),
            "the network's paging limit is not the bouncer's: {welcome:?}"
        );

        ends.emit_session_line(
            ":up 005 alice CHATHISTORY=1000 AWAYLEN=300 :are supported by this server".to_string(),
        )
        .expect("tracked");
        match events.try_recv() {
            Ok(DriverEvent::Notice(notice)) => assert_eq!(
                without_tag(&notice.line, "time"),
                ":up 005 alice AWAYLEN=300 :are supported by this server"
            ),
            other => panic!("expected the live ISUPPORT change, got {other:?}"),
        }
        ends.emit_session_line(":peer!u@h PRIVMSG #room :after".to_string())
            .expect("tracked");
        assert_eq!(
            untimed(handle.buffer_snapshot()),
            [":peer!u@h PRIVMSG #room :after"],
            "an ISUPPORT change is current state, not history"
        );

        // A burst an older build stored is not restored into the ring either.
        let (restored, _ends) = NetworkHandle::channels(8);
        let stored = |line: &str| stored_line(line, "2026-01-01T00:00:00.000Z");
        restored.preload_front(vec![
            stored(":up 005 alice CHATHISTORY=1000 :are supported by this server"),
            stored(":up 372 alice :- motd"),
            stored(":peer!u@h PRIVMSG #room :kept"),
        ]);
        assert_eq!(
            untimed(restored.buffer_snapshot()),
            [":peer!u@h PRIVMSG #room :kept"]
        );
    }

    /// A network that does not carry client-only tags tells attached clients
    /// so (`CLIENTTAGDENY=*`) in the welcome, and live when it changes.
    #[test]
    fn client_tag_denial_is_advertised() {
        let (handle, ends) = NetworkHandle::channels(8);
        ends.set_client_tags(ClientTags::Denied);
        ends.begin_irc_session("alice".to_string());
        ends.emit_session_line(
            ":up 005 alice CLIENTTAGDENY=typing NETWORK=Up :are supported by this server"
                .to_string(),
        )
        .expect("tracked");
        let welcome = serve::welcome_to("bnc.test", "net", &handle, "alice").lines;
        let isupport = welcome.join("\n");
        assert!(isupport.contains("CLIENTTAGDENY=*"), "{isupport}");
        assert!(!isupport.contains("CLIENTTAGDENY=typing"), "{isupport}");
        let mut events = handle.subscribe();
        ends.set_client_tags(ClientTags::Relayed);
        match events.try_recv() {
            Ok(DriverEvent::Notice(notice)) => assert_eq!(
                without_tag(&notice.line, "time"),
                ":*bnc* 005 alice CLIENTTAGDENY=typing :are supported by this server"
            ),
            other => panic!("expected the ISUPPORT change, got {other:?}"),
        }
        let welcome = serve::welcome_to("bnc.test", "net", &handle, "alice").lines;
        assert!(welcome.join("\n").contains("CLIENTTAGDENY=typing"));
    }

    /// A reconnect is in the ring as the session boundary it was live: a
    /// client replaying across it sees the old session's channels parted
    /// before the new session's JOINs, as a client attached then did.
    #[tokio::test]
    async fn a_replay_across_a_reconnect_parts_before_it_rejoins() {
        let (handle, ends) = NetworkHandle::channels(32);
        ends.begin_irc_session("alice".to_string());
        ends.emit_session_line(":alice!u@h JOIN #a".to_string())
            .expect("tracked");
        ends.emit_session_line(":alice!u@h JOIN #gone".to_string())
            .expect("tracked");
        ends.begin_irc_session("alice".to_string());
        ends.emit_session_line(":alice!u@h JOIN #a".to_string())
            .expect("tracked");
        let (mut client, task) = attach_task(std::sync::Arc::new(handle), AttachCaps::default());
        let output = attach_output(&mut client).await;
        let lines: Vec<&str> = output.lines().collect();
        let position = |wanted: &str| {
            lines
                .iter()
                .position(|line| *line == wanted)
                .unwrap_or_else(|| panic!("{wanted:?} missing from {lines:#?}"))
        };
        let first_join = position(":alice!u@h JOIN #a");
        let parted = position(":alice!~bnc@e6irc PART #a :upstream session reset");
        let gone = position(":alice!~bnc@e6irc PART #gone :upstream session reset");
        let second_join = lines
            .iter()
            .rposition(|line| *line == ":alice!u@h JOIN #a")
            .expect("rejoined");
        assert!(first_join < parted && parted < second_join, "{lines:#?}");
        assert!(gone < second_join, "{lines:#?}");
        drop(client);
        drop(task.await);
    }

    /// Where each of `needles` first appears in `output`, in order; panics
    /// naming the one that does not appear after the one before it.
    fn in_order(output: &str, needles: &[&str]) {
        let mut from = 0;
        for needle in needles {
            let found = output[from..]
                .find(needle)
                .unwrap_or_else(|| panic!("{needle:?} does not follow in: {output}"));
            from += found + needle.len();
        }
    }

    /// A session that joined `#room`, was told its topic and members, and
    /// then said `lines`; the ring holds `cap` entries.
    fn a_session_in_room(cap: usize, lines: &[&str]) -> (NetworkHandle, DriverEnds) {
        let (handle, ends) = NetworkHandle::channels(cap);
        ends.begin_irc_session("alice".to_string());
        for line in [
            ":alice!u@h JOIN #room",
            ":up 332 alice #room :the topic",
            ":up 353 alice = #room :alice @op peer",
            ":up 366 alice #room :End of /NAMES list",
        ]
        .iter()
        .chain(lines)
        {
            ends.emit_session_line(line.to_string()).expect("tracked");
        }
        (handle, ends)
    }

    /// A replay whose window holds a nick change is read in the state each
    /// line was said in: the client is first brought to the nick and channels
    /// of the oldest replayed line — the channel's JOIN before any of its
    /// lines — then shown the lines, then brought to the state now, with the
    /// channel's topic and members as the session knows them. It used to
    /// start at the current nick, so the old nick's own lines read as a
    /// stranger's and its `NICK` as someone taking the client's name, and a
    /// channel whose JOIN had aged out had its lines replayed before it was
    /// joined. The backlog keeps no member list ([`told_live_only`]), so the
    /// one told is the session's now, not one from the ring.
    #[tokio::test]
    async fn a_replay_starts_from_the_state_of_its_oldest_line() {
        let (handle, ends) = a_session_in_room(
            3,
            &[
                ":alice!u@h PRIVMSG #room :before",
                ":alice!u@h NICK :bob",
                ":bob!u@h PRIVMSG #room :after",
            ],
        );
        let output = attach_to_completion(handle).await;
        in_order(
            &output,
            &[
                ":bnc.test 001 bob :",
                ":bob NICK :alice",
                ":alice!~bnc@e6irc JOIN #room",
                ":alice!u@h PRIVMSG #room :before",
                ":alice!u@h NICK :bob",
                ":bob!u@h PRIVMSG #room :after",
                ":*bnc* 332 bob #room :the topic",
                ":*bnc* 353 bob = #room :bob @op peer",
                ":*bnc* 366 bob #room :End of /NAMES list",
            ],
        );
        assert_eq!(output.matches(" JOIN ").count(), 1, "{output}");
        assert_eq!(output.matches(" NICK ").count(), 2, "{output}");
        // Nothing was asked of the upstream: the session knew the channel.
        drop(ends);
    }

    /// A backlog restored from storage after a restart starts its replay
    /// under the nick its oldest line was said under, as an in-memory ring
    /// does: the rows record it (migration 0096). The bouncer's own notices
    /// from before the upstream welcomed the session recorded none, and the
    /// nick of the line after them is theirs. It used to start at the current
    /// nick, so the old nick's lines read as a stranger's.
    #[tokio::test]
    async fn a_restored_replay_starts_from_the_nick_its_oldest_line_was_said_under() {
        use crate::db::StoredOwnNick::{Nick, NoNick};
        let at = "2026-01-01T00:00:00.000Z";
        let (handle, ends) = NetworkHandle::channels(8);
        handle.preload_front(vec![
            stored_under(":*bnc* NOTICE * :connecting", at, NoNick),
            stored_under(":peer!u@h PRIVMSG alice :hello", at, Nick("alice".into())),
            stored_under(":alice!u@h NICK :bob", at, Nick("alice".into())),
            stored_under(":peer!u@h PRIVMSG bob :again", at, Nick("bob".into())),
        ]);
        ends.begin_irc_session("bob".to_string());
        let output = attach_to_completion(handle).await;
        in_order(
            &output,
            &[
                ":bnc.test 001 bob :",
                ":bob NICK :alice",
                ":*bnc* NOTICE * :connecting",
                ":peer!u@h PRIVMSG alice :hello",
                ":alice!u@h NICK :bob",
                ":peer!u@h PRIVMSG bob :again",
            ],
        );
        assert_eq!(output.matches(" NICK ").count(), 2, "{output}");
        drop(ends);
    }

    /// Rows stored before migration 0096 recorded no nick: a replay that
    /// begins in them starts at the current nick, as every restored replay did
    /// before, and a row that recorded one after them does not stand in for
    /// them.
    #[tokio::test]
    async fn a_restored_replay_of_rows_without_a_recorded_nick_starts_at_the_current_nick() {
        let at = "2026-01-01T00:00:00.000Z";
        let (handle, ends) = NetworkHandle::channels(8);
        handle.preload_front(vec![
            stored_line(":peer!u@h PRIVMSG alice :hello", at),
            stored_line(":alice!u@h NICK :bob", at),
            stored_under(
                ":peer!u@h PRIVMSG bob :again",
                at,
                crate::db::StoredOwnNick::Nick("bob".into()),
            ),
        ]);
        ends.begin_irc_session("bob".to_string());
        let output = attach_to_completion(handle).await;
        in_order(
            &output,
            &[
                ":bnc.test 001 bob :",
                ":peer!u@h PRIVMSG alice :hello",
                ":alice!u@h NICK :bob",
                ":peer!u@h PRIVMSG bob :again",
            ],
        );
        assert_eq!(output.matches(" NICK ").count(), 1, "{output}");
        drop(ends);
    }

    /// A channel whose JOIN aged out is joined, with its topic and members as
    /// the session followed them, before any of its replayed lines — and the
    /// upstream is asked nothing: a client in a hundred channels used to cost
    /// two hundred queued questions per attach, which flooded the upstream and
    /// filled the queue every attached client shares.
    #[tokio::test]
    async fn an_attach_to_a_hundred_channels_asks_the_upstream_nothing() {
        let (handle, mut ends) = NetworkHandle::channels(8);
        ends.begin_irc_session("alice".to_string());
        for n in 0..100 {
            for line in [
                format!(":alice!u@h JOIN #c{n}"),
                format!(":up 353 alice = #c{n} :alice peer{n}"),
                format!(":up 366 alice #c{n} :End of /NAMES list"),
            ] {
                ends.emit_session_line(line).expect("tracked");
            }
        }
        // Every JOIN, and every member list, has aged out.
        for n in 0..8 {
            ends.emit_session_line(format!(":peer99!u@h PRIVMSG #c99 :late {n}"))
                .expect("tracked");
        }
        let output = attach_to_completion(handle).await;
        assert!(
            ends.commands.try_recv().is_err(),
            "the attach asked the upstream for what the session knew"
        );
        for n in 0..100 {
            assert!(
                output.contains(&format!(":*bnc* 353 alice = #c{n} :alice peer{n}")),
                "#c{n}: {output}"
            );
        }
        in_order(
            &output,
            &[
                ":alice!~bnc@e6irc JOIN #c99",
                ":peer99!u@h PRIVMSG #c99 :late 0",
            ],
        );
    }

    /// A channel whose member list the session does not know (the upstream
    /// sent none, or it was past the bound) is asked of the upstream for the
    /// attaching client, for at most [`ATTACH_UPSTREAM_QUERIES`] channels; the
    /// rest are told so, and how to ask.
    #[tokio::test]
    async fn unknown_member_lists_are_asked_for_a_bounded_few() {
        let (handle, mut ends) = NetworkHandle::channels(2);
        handle.runtime.connected();
        ends.begin_irc_session("alice".to_string());
        for n in 0..10 {
            ends.emit_session_line(format!(":alice!u@h JOIN #c{n}"))
                .expect("tracked");
        }
        for n in 0..2 {
            ends.emit_line(format!(":srv NOTICE alice :filler {n}"));
        }
        let (mut client, task) = attach_task(std::sync::Arc::new(handle), AttachCaps::default());
        let output = attach_output(&mut client).await;
        drop(client);
        task.await.expect("attach task").expect("attach");
        let mut asked = Vec::new();
        while let Ok(command) = ends.commands.try_recv() {
            asked.push(command.line);
        }
        assert_eq!(asked.len(), 2 * ATTACH_UPSTREAM_QUERIES, "{asked:?}");
        assert_eq!(
            output.matches("was not asked for now").count(),
            10 - ATTACH_UPSTREAM_QUERIES,
            "{output}"
        );
    }

    /// A `NAMES` of a channel whose member list the session follows is
    /// answered from it, to the asking attachment alone, and never reaches
    /// the upstream; one the session cannot answer is the upstream's.
    #[tokio::test]
    async fn a_names_the_session_can_answer_does_not_reach_the_upstream() {
        let (handle, ends) = a_session_in_room(16, &[":peer!u@h PART #room"]);
        let mut replies = handle.route_replies(7);
        let command = |line: &str| ClientCommand {
            origin: 7,
            line: line.to_string(),
        };
        assert_eq!(
            carriable(&command("NAMES #Room"), ClientTags::Relayed, &ends),
            None
        );
        assert_eq!(
            without_tag(&replies.recv().await, "time"),
            ":*bnc* 353 alice = #room :alice @op"
        );
        assert_eq!(
            without_tag(&replies.recv().await, "time"),
            ":*bnc* 366 alice #room :End of /NAMES list"
        );
        for asked in ["NAMES #elsewhere", "NAMES #room,#other", "NAMES"] {
            assert_eq!(
                carriable(&command(asked), ClientTags::Relayed, &ends),
                Some(asked.to_string())
            );
        }
    }

    /// A client without server-time is told when each replayed message was
    /// said in its text, as ZNC tells it: the time today, the date too
    /// before today, after `ACTION ` for a `/me`, within the line; anything
    /// that is not a message, and a CTCP reply, is replayed as it is.
    #[test]
    fn a_replayed_message_carries_its_time_for_a_client_without_server_time() {
        let today = "2026-10-10";
        let at = |time: &str, rest: &str| format!("@time={time};msgid=x {rest}");
        assert_eq!(
            replayed_with_its_time(
                &at(
                    "2026-10-10T09:05:03.250Z",
                    ":bob!b@h PRIVMSG #room :hello there"
                ),
                today
            ),
            "@time=2026-10-10T09:05:03.250Z;msgid=x :bob!b@h PRIVMSG #room :[09:05:03] hello there"
        );
        assert_eq!(
            replayed_with_its_time(
                &at("2026-10-09T23:59:59.000Z", ":bob!b@h NOTICE me :yesterday"),
                today
            ),
            "@time=2026-10-09T23:59:59.000Z;msgid=x :bob!b@h NOTICE me :[2026-10-09 23:59:59] yesterday"
        );
        assert_eq!(
            replayed_with_its_time(
                &at(
                    "2026-10-10T12:00:00.000Z",
                    ":bob!b@h PRIVMSG #room :\u{1}ACTION waves\u{1}"
                ),
                today
            ),
            "@time=2026-10-10T12:00:00.000Z;msgid=x :bob!b@h PRIVMSG #room :\u{1}ACTION [12:00:00] waves\u{1}"
        );
        for kept in [
            at(
                "2026-10-10T12:00:00.000Z",
                ":bob!b@h NOTICE me :\u{1}VERSION irssi\u{1}",
            ),
            at("2026-10-10T12:00:00.000Z", ":bob!b@h JOIN #room"),
            ":bob!b@h PRIVMSG #room :no time of its own".to_string(),
        ] {
            assert_eq!(replayed_with_its_time(&kept, today), kept);
        }
        let long = at(
            "2026-10-10T12:00:00.000Z",
            &format!(":bob!b@h PRIVMSG #room :{}", "x".repeat(480)),
        );
        let stamped = replayed_with_its_time(&long, today);
        let body = stamped.split_once(' ').expect("tagged").1;
        assert_eq!(body.len(), 510, "fitted to the wire");
    }

    /// A channel's settings, once a `324` said them, are followed through
    /// every `MODE` and answer a client's `MODE #chan` with its creation
    /// time; its topic answers `TOPIC #chan`, and a channel that said no
    /// topic before its member list has none. A list mode, a member's status
    /// and a query the session cannot answer are the upstream's.
    #[tokio::test]
    async fn a_mode_or_topic_the_session_can_answer_does_not_reach_the_upstream() {
        let (handle, ends) = a_session_in_room(16, &[]);
        let mut replies = handle.route_replies(7);
        let command = |line: &str| ClientCommand {
            origin: 7,
            line: line.to_string(),
        };
        assert_eq!(
            carriable(&command("MODE #room"), ClientTags::Relayed, &ends),
            Some("MODE #room".to_string()),
            "not known before the upstream said them"
        );
        for line in [
            ":up 324 alice #room +nst",
            ":up 329 alice #room 1700000000",
            ":op!o@h MODE #room +kl-t+bo hunter2 10 *!*@spam peer",
        ] {
            ends.emit_session_line(line.to_string()).expect("tracked");
        }
        assert_eq!(
            carriable(&command("MODE #Room"), ClientTags::Relayed, &ends),
            None
        );
        assert_eq!(
            without_tag(&replies.recv().await, "time"),
            ":*bnc* 324 alice #room +klns hunter2 10"
        );
        assert_eq!(
            without_tag(&replies.recv().await, "time"),
            ":*bnc* 329 alice #room 1700000000"
        );
        assert_eq!(
            carriable(&command("TOPIC #room"), ClientTags::Relayed, &ends),
            None
        );
        assert_eq!(
            without_tag(&replies.recv().await, "time"),
            ":*bnc* 332 alice #room :the topic"
        );
        for asked in [
            "MODE #room b",
            "MODE #room +i",
            "MODE alice",
            "TOPIC #room :new",
            "MODE #other",
        ] {
            assert_eq!(
                carriable(&command(asked), ClientTags::Relayed, &ends),
                Some(asked.to_string()),
                "{asked}"
            );
        }
        ends.emit_session_line(":alice!u@h JOIN #quiet".to_string())
            .expect("tracked");
        ends.emit_session_line(":up 366 alice #quiet :End of /NAMES list".to_string())
            .expect("tracked");
        assert_eq!(
            carriable(&command("TOPIC #quiet"), ClientTags::Relayed, &ends),
            None
        );
        assert_eq!(
            without_tag(&replies.recv().await, "time"),
            ":*bnc* 331 alice #quiet :No topic is set"
        );
    }

    /// The bouncer's own numerics to an attached client are addressed to the
    /// nick the client has now: after a `NICK`, not the one it was welcomed
    /// under.
    #[tokio::test]
    async fn attach_numerics_follow_the_clients_nick() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        let (handle, ends) = NetworkHandle::channels(8);
        ends.begin_irc_session("alice".to_string());
        let (client, task) = attach_task(std::sync::Arc::new(handle), AttachCaps::default());
        let (read, mut write) = tokio::io::split(client);
        let mut lines = tokio::io::BufReader::new(read).lines();
        let mut next = async || {
            tokio::time::timeout(std::time::Duration::from_secs(2), lines.next_line())
                .await
                .expect("attach went silent")
                .expect("attach read")
                .expect("attach closed")
        };
        while !next().await.starts_with(":*bnc* NOTICE * :upstream") {}
        ends.emit_session_line(":alice!u@h NICK :bob".to_string())
            .expect("tracked");
        assert!(next().await.ends_with(":alice!u@h NICK :bob"));
        write
            .write_all(b"PING\r\nAUTHENTICATE PLAIN\r\nMARKREAD #room\r\n")
            .await
            .expect("send");
        assert_eq!(next().await, ":*bnc* 409 bob :No origin specified");
        assert_eq!(
            next().await,
            ":*bnc* 907 bob :You have already authenticated"
        );
        assert_eq!(next().await, ":*bnc* 421 bob MARKREAD :Unknown command");
        drop(write);
        drop(lines);
        task.abort();
    }

    /// A client that attaches before the upstream's registration burst ends
    /// is welcomed with what is known then; once the burst ends it is told,
    /// as one ISUPPORT change, what the network's own 005 changed — the
    /// tokens it now has and the ones it does not.
    #[tokio::test]
    async fn a_client_welcomed_before_the_burst_is_told_what_it_changed() {
        use tokio::io::AsyncBufReadExt;
        let (handle, ends) = NetworkHandle::channels(8);
        ends.begin_irc_session("alice".to_string());
        let (client, task) = attach_task(std::sync::Arc::new(handle), AttachCaps::default());
        let mut lines = tokio::io::BufReader::new(client).lines();
        let mut next = async || {
            tokio::time::timeout(std::time::Duration::from_secs(2), lines.next_line())
                .await
                .expect("attach went silent")
                .expect("attach read")
                .expect("attach closed")
        };
        let mut welcome = Vec::new();
        loop {
            let line = next().await;
            if line.starts_with(":*bnc* NOTICE * :upstream") {
                break;
            }
            welcome.push(line);
        }
        assert!(
            welcome
                .iter()
                .any(|line| line.contains(" CASEMAPPING=rfc1459 ")),
            "welcomed with the defaults: {welcome:?}"
        );
        for line in [
            ":up 004 alice up v1 i o b",
            ":up 005 alice CASEMAPPING=ascii CHANTYPES=# PREFIX=(ov)@+ NETWORK=Up :are supported by this server",
            ":up 376 alice :End of /MOTD command.",
        ] {
            ends.emit_session_line(line.to_string()).expect("tracked");
        }
        assert_eq!(
            next().await,
            ":bnc.test 005 alice CASEMAPPING=ascii CHANTYPES=# PREFIX=(ov)@+ NETWORK=Up \
             -CHANNELLEN -NICKLEN -STATUSMSG :are supported by this server"
        );
        task.abort();
    }

    /// An attaching client is told up front why its network is not
    /// connected — the failure and the upstream's own words — not only that
    /// it is disconnected.
    #[tokio::test]
    async fn the_up_front_status_says_why_the_network_is_down() {
        let (handle, ends) = NetworkHandle::channels(8);
        ends.emit(ConnectionEvent::RegistrationRetrying(refused_by(
            ":up 433 * alice :Nickname is already in use",
        )));
        let (mut client, task) = attach_task(std::sync::Arc::new(handle), AttachCaps::default());
        let output = attach_output(&mut client).await;
        drop(client);
        task.await.expect("attach task").expect("attach");
        let status = output
            .lines()
            .find(|line| line.starts_with(":*bnc* NOTICE * :"))
            .expect("a status line");
        assert!(
            status.contains("component reconnecting:")
                && status.contains("(nickname_in_use)")
                && status.contains("upstream: Nickname is already in use"),
            "{status}"
        );
    }

    /// Every line the bouncer makes from the upstream's names fits one IRC
    /// line, however long the names; one that cannot is said as a notice.
    #[tokio::test]
    async fn synthesized_lines_fit_the_line_limit() {
        // The upstream's own JOIN fits its line; the bouncer's, with a longer
        // user and host, would not.
        let nick = "n".repeat(300);
        let channel = format!("#{}", "c".repeat(194));
        let (handle, ends) = NetworkHandle::channels(1);
        ends.begin_irc_session(nick.clone());
        ends.emit_session_line(format!(":{nick}!u@h JOIN {channel}"))
            .expect("tracked");
        ends.emit_line(":srv NOTICE * :the JOIN has aged out".to_string());
        // A driver that cannot be asked for the member list: the bouncer's
        // own minimal one is what must fit.
        drop(ends);
        let (mut client, task) = attach_task(std::sync::Arc::new(handle), AttachCaps::default());
        let output = attach_output(&mut client).await;
        drop(client);
        let ended = task.await.expect("attach task");
        assert!(ended.is_ok(), "{ended:?}: {output}");
        assert!(!output.is_empty());
        for line in output.lines() {
            assert!(line.len() + 2 <= 512, "{} bytes: {line}", line.len());
        }
        assert!(
            output.contains(&format!(":{nick} JOIN {channel}")),
            "the JOIN, without the user and host that do not fit: {output}"
        );
        assert!(
            output.contains("the member list is not known here and was not asked"),
            "{output}"
        );
        assert!(
            output.contains("the channel's member list was not sent"),
            "{output}"
        );
    }

    /// The answer to one client's command reaches that client, live, and is
    /// neither broadcast nor retained; a reply to a client that has detached
    /// reaches no one.
    #[tokio::test]
    async fn a_reply_reaches_only_its_attachment() {
        let (handle, ends) = NetworkHandle::channels(8);
        let mut events = handle.subscribe();
        let mut asked = handle.route_replies(7);
        let mut other = handle.route_replies(8);
        ends.emit_reply(7, ":up 352 alice #room u h s nick H :0 real".to_string());
        assert_eq!(
            without_tag(&asked.recv().await, "time"),
            ":up 352 alice #room u h s nick H :0 real"
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), other.recv())
                .await
                .is_err()
        );
        assert_eq!(
            events.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        );
        assert!(handle.buffer_snapshot().is_empty());
        // More than the route holds: the rest is dropped for this client
        // alone, and it is told how much.
        for index in 0..REPLY_ROUTE_CAPACITY + 10 {
            ends.emit_reply(7, format!(":up 322 alice #c{index} 1 :t"));
        }
        let mut received = 0;
        let notice = loop {
            let line = asked.recv().await;
            if line.contains("NOTICE") {
                break line;
            }
            received += 1;
        };
        assert!(notice.contains("10 line(s) of a reply"), "{notice}");
        assert_eq!(
            received, REPLY_ROUTE_CAPACITY,
            "every line that fitted first"
        );
        drop(asked);
        ends.emit_reply(7, ":up 315 alice #room :End".to_string());
    }
}
