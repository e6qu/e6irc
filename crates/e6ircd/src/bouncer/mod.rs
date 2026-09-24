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

#[cfg(all(test, feature = "discord", feature = "slack"))]
mod bridge_oracle;
mod chathistory;
#[cfg(feature = "discord")]
mod discord;
mod irc_driver;
mod local_driver;
#[cfg(feature = "matrix")]
mod matrix;
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
pub(crate) use serve::{MutationLane, UnwrittenLines};
pub use serve::{NetworkStatus, Registry, bnc_serve};
#[cfg(feature = "slack")]
pub use slack::{SlackConfig, SlackDriver};
pub use upstream_identity::{
    ConfirmedChannel, UpstreamChannel, UpstreamIdentityError, UpstreamNick, UpstreamRealname,
    UpstreamUsername,
};

/// The conversation a message target belongs to: a STATUSMSG (`@#chan`,
/// `+#chan`) is that channel's conversation with a narrower audience, so its
/// one status sigil comes off; anything else is already the conversation. A
/// sigil in front of something that is not a channel is part of a nickname.
/// Bridge routing and backlog filing both read targets through this, so a
/// message cannot be delivered to one conversation and stored under another.
pub(crate) fn conversation_target(target: &str) -> &str {
    match target.strip_prefix(['@', '+']) {
        Some(channel) if channel.starts_with(['#', '&']) => channel,
        _ => target,
    }
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
        if !crate::sanitize::valid_channel_name(&channel) {
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
    pub autojoin: Vec<String>,
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
            Ok(Box::new(IrcDriver::new(NetworkConfig {
                addr,
                tls,
                nick: nick.parse().map_err(identity_error)?,
                username: username.parse().map_err(identity_error)?,
                realname: realname.parse().map_err(identity_error)?,
                autojoin: UpstreamChannel::parse_list(&autojoin).map_err(identity_error)?,
                buffer_cap,
                sasl,
                server_password,
                keepalive_idle: KEEPALIVE_IDLE,
                rejection_retry_floor: REJECTION_RETRY_FLOOR,
                internal_upstreams,
                first_dial,
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
                    rooms: autojoin,
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
                Ok(Box::new(DiscordDriver::new(DiscordConfig {
                    token,
                    api_base: addr,
                    channels: autojoin,
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
                    channels: autojoin,
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
/// per kind: the password (`sasl_password_sealed`) and the IRC server password
/// (`server_password_sealed`) are always sealed, and for a
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
        autojoin: row.autojoin.clone(),
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
/// its resumable gateway session), so an outage's messages are delivered
/// after it rather than skipped.
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
    ///   on — the schedule.
    /// - [`NetworkFailure::ChannelMappingFailed`]: a Discord or Slack channel
    ///   name comes from the upstream, and renaming it there clears the
    ///   refusal — the schedule.
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
    /// The upstream will not serve what the configuration asks for. Only
    /// Matrix learns that while connecting (a forbidden join); the WebSocket
    /// bridges learn it from `resolve_bridge_channels`, which answers with the
    /// session outcome directly.
    #[cfg(feature = "matrix")]
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
            #[cfg(feature = "matrix")]
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
async fn wait_for_reconnect(
    ends: &mut DriverEnds,
    event: ConnectionEvent,
    upstream_reason: Option<&str>,
    delay: std::time::Duration,
    sleep: impl Future<Output = ()>,
) -> bool {
    ends.publish(event, Some(delay), upstream_reason);
    tokio::select! {
        biased;
        _ = ends.shutdown_signalled() => false,
        _ = sleep => true,
    }
}

/// Park a driver the upstream will keep refusing: publish the terminal state,
/// say so in the buffer, and hold the task until the network is reconfigured
/// (which drops the handle).
async fn park(ends: &mut DriverEnds, event: ConnectionEvent) {
    ends.emit(event);
    ends.emit_line(
        ":*bnc* NOTICE * :upstream rejected this network's credentials or registration; \
         not reconnecting until this network is reconfigured"
            .to_string(),
    );
    ends.shutdown_signalled().await;
}

pub(crate) async fn run_with_backoff<C>(
    config: C,
    ends: &mut DriverEnds,
    session: DriverSession<C>,
) {
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
        let (failure, upstream_reason) = match session(&config, ends).await {
            SessionOutcome::Stopped => return,
            SessionOutcome::AuthRejected(rejection) => {
                park(ends, ConnectionEvent::AuthenticationFailed(rejection)).await;
                return;
            }
            SessionOutcome::RegistrationRejected(rejection) => {
                let refusal = Refusal::Registration(rejection);
                match retry_refusal(
                    ends,
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
            #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
            SessionOutcome::ConfigurationRejected(refusal) => {
                let refusal = Refusal::Configuration(refusal);
                match retry_refusal(
                    ends,
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
            #[cfg(feature = "discord")]
            SessionOutcome::ReconnectRequested => {
                tokio::select! {
                    biased;
                    _ = ends.shutdown_signalled() => return,
                    _ = tokio::time::sleep(RECONNECT_REQUEST_PAUSE) => continue,
                }
            }
            SessionOutcome::Dropped(failure) => (failure, None),
            SessionOutcome::ClosedByUpstream(closed) => {
                (NetworkFailure::ConnectionLost, Some(closed))
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
        let delay = backoff.next_delay(session_held);
        let reconnecting = ConnectionEvent::Reconnecting(failure);
        let reason = upstream_reason.as_ref().map(LinkClosed::diagnostic);
        if !wait_for_reconnect(
            ends,
            reconnecting,
            reason,
            delay,
            backoff.wait(session_held),
        )
        .await
        {
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
async fn retry_refusal(
    ends: &mut DriverEnds,
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
        park(ends, refusal.parked()).await;
        return RefusalHandled::Ended;
    }
    let delay = backoff.rejection_delay(ends.rejection_retry_floor, *consecutive_rejections);
    if wait_for_reconnect(
        ends,
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
        if text.starts_with('\u{1}') {
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
    let casemap = e6irc_proto::casemap::CaseMapping::Rfc1459;
    let mut out: Vec<RouteResult> = target
        .split(',')
        .filter(|t| !t.is_empty())
        .map(|t| {
            let bare = conversation_target(t);
            match targets.get(&casemap.casefold(bare)) {
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
        BridgeFailure::Failed(detail) => DeliveryOutcome::Failed { id, detail },
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

/// A reqwest DNS resolver that vets every resolved address and drops the ones a
/// bridge may not dial — the same control the IRC driver applies at connect
/// time (`crate::egress`: never an upstream, or internal under the server's
/// policy). Resolution happens per request, so a host that resolves to a
/// refused address — now or after a DNS rebind — is refused at dial time, not
/// just at config time.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
struct VettingResolver(crate::egress::InternalUpstreams);

#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
impl reqwest::dns::Resolve for VettingResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let policy = self.0;
        Box::pin(async move {
            let host = name.as_str().to_string();
            let resolved = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let vetted: Vec<std::net::SocketAddr> =
                resolved.filter(|sa| policy.permits(sa.ip())).collect();
            if vetted.is_empty() {
                // Either DNS returned nothing or every address was blocked; both
                // are a refusal, not a silent fall-through to the OS resolver.
                return Err(format!(
                    "{host}: no permitted address (every resolved address is internal or \
                     never an upstream)"
                )
                .into());
            }
            Ok(Box::new(vetted.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// The HTTP client every bridge uses for its REST calls. Bounds each request by
/// `timeout`, refuses redirects (an upstream 3xx can't re-target an internal
/// address), and vets every resolved IP via [`VettingResolver`] — so a bridge's
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
/// way to build a bridge request, so no caller can forget the literal check.
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
            .dns_resolver(std::sync::Arc::new(VettingResolver(internal_upstreams)))
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
    ) -> Result<reqwest::RequestBuilder, String> {
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
        Ok(self.client.request(method, url))
    }

    pub(crate) fn get(&self, url: &str) -> Result<reqwest::RequestBuilder, String> {
        self.request(reqwest::Method::GET, url)
    }

    pub(crate) fn post(&self, url: &str) -> Result<reqwest::RequestBuilder, String> {
        self.request(reqwest::Method::POST, url)
    }

    /// Only the Matrix bridge sends with PUT (the transaction id is in the
    /// path); the `lint` job builds each bridge alone with `-Dwarnings`.
    #[cfg(feature = "matrix")]
    pub(crate) fn put(&self, url: &str) -> Result<reqwest::RequestBuilder, String> {
        self.request(reqwest::Method::PUT, url)
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

/// When an upstream must next show a sign of life.
///
/// A driver's session loop is a `select!` whose every turn abandons the read it
/// was waiting on, so a timeout *started by the read* is restarted by whatever
/// else ends a turn: a downstream command, a heartbeat tick. A silent upstream
/// then looks alive for as long as anything else is happening. The deadline
/// lives here instead, outside the loop's turns, and only [`Self::restart`]
/// moves it.
pub(crate) struct SilenceDeadline {
    window: std::time::Duration,
    at: tokio::time::Instant,
}

impl SilenceDeadline {
    pub(crate) fn new(window: std::time::Duration) -> Self {
        Self {
            window,
            at: tokio::time::Instant::now() + window,
        }
    }

    /// The upstream was heard from (or was just asked to speak): a full window
    /// starts now.
    pub(crate) fn restart(&mut self) {
        self.at = tokio::time::Instant::now() + self.window;
    }

    /// `read`'s output, or `None` once the whole window has passed in silence.
    pub(crate) async fn bound<T>(&self, read: impl Future<Output = T>) -> Option<T> {
        tokio::time::timeout_at(self.at, read).await.ok()
    }
}

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
) -> Result<(), crate::peer_write::SendFailure> {
    use futures_util::SinkExt;
    crate::peer_write::within_send_deadline(
        crate::peer_write::PEER_WRITE_DEADLINE,
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
        fn start(self: Box<Self>) -> NetworkHandle {
            let (handle, ends) = NetworkHandle::bridge_channels(self.config.buffer_cap);
            tokio::spawn(run(self.config, ends));
            handle
        }
    };
}
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
pub(crate) use bridge_start;

/// Open a bridge gateway WebSocket to `url`, vetting the resolved IP the same way
/// [`VettingResolver`] vets HTTP dials. The gateway URL comes from an upstream
/// REST response, so a hostile/compromised provider could point it at an internal
/// address; `connect_async` would resolve and dial it blind. Instead we resolve
/// the host ourselves, dial a *vetted* address directly, and hand that stream to
/// tungstenite for the TLS handshake (validated against the URL's hostname, not
/// the IP) — closing the SSRF vector with no resolve-then-dial TOCTOU.
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
    /// Anything else, in e6irc's own words (never the provider's body).
    Failed(String),
}

#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
impl std::fmt::Display for BridgeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RateLimited(wait) => write!(f, "upstream rate limit; retry after {wait:?}"),
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

/// Send an outbound bridge HTTP request and reject any non-2xx response. Every
/// reverse-direction (IRC→upstream) send whose failure is signalled by HTTP
/// status funnels through here so the raw `reqwest::Response` never reaches
/// delivery-outcome logic: a bare `.send()` returns `Ok(Response)` for a 403 /
/// 429 / 5xx just as for a 200, and treating that as delivered is a silent drop
/// (DESIGN §2). Routing through this makes "send, ignore the status, report
/// success" unwritable. (Slack signals failure in the 200 body via `ok:false`,
/// an application-level check its `check_ok` still performs on top of this.)
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
pub(crate) async fn bridge_send(
    req: reqwest::RequestBuilder,
) -> Result<reqwest::Response, BridgeFailure> {
    bridge_response_status(req.send().await.map_err(|e| e.to_string())?).await
}

/// A bridge response that is not a success is a failed request. A 3xx is
/// named as such: the client never follows one (an upstream cannot re-target
/// a request at an internal address), and `error_for_status` alone let it
/// through — a message "sent" with a 302 was reported delivered and never
/// posted. A `429` is [`BridgeFailure::RateLimited`] with the wait it asks for.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
pub(crate) async fn bridge_response_status(
    response: reqwest::Response,
) -> Result<reqwest::Response, BridgeFailure> {
    let status = response.status();
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Err(BridgeFailure::RateLimited(rate_limit_wait(response).await));
    }
    if status.is_redirection() {
        return Err(BridgeFailure::Failed(format!(
            "upstream answered HTTP {status}; a bridge never follows a redirect"
        )));
    }
    let response = response.error_for_status().map_err(|e| e.to_string())?;
    if response.status().is_success() {
        Ok(response)
    } else {
        Err(BridgeFailure::Failed(format!(
            "upstream answered HTTP {}",
            response.status()
        )))
    }
}

/// [`bridge_send`] for a request that presents the network's credentials: a
/// 401/403 means the upstream rejected *them*, which no retry can fix. Written
/// once so every bridge reads the same statuses the same way — the Discord
/// channel lookup used to call a refused token a transient failure while the
/// gateway's refusal of the same token parked the network.
#[cfg(any(feature = "matrix", feature = "discord"))]
pub(crate) async fn bridge_send_credentials(
    req: reqwest::RequestBuilder,
    what: &str,
) -> Result<reqwest::Response, ConnectFail> {
    let response = req.send().await.map_err(|e| e.to_string())?;
    let status = response.status();
    bridge_response_status(response).await.map_err(|failure| {
        let detail = format!("{what} rejected: {failure}");
        if matches!(
            status,
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
        ) {
            ConnectFail::Auth(detail)
        } else {
            ConnectFail::Transient(detail)
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
pub(crate) fn queue_channel_command<F, Fut>(
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
/// compromised upstream can return a multi-GB body and OOM the shared daemon —
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
    /// RFC1459-folded names of channels this line took us out of. A `QUIT`
    /// reports none: it ends the live membership, not the intent to be there.
    pub left: Vec<String>,
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
        key: String,
    ) {
        if channels.remove(&key).is_some() {
            self.left.push(key);
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
}

impl UpstreamFeatures {
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

#[derive(Debug, Default)]
struct IrcSessionState {
    nick: Option<String>,
    channels: std::collections::HashMap<String, upstream_identity::ConfirmedChannel>,
    features: UpstreamFeatures,
}

impl IrcSessionState {
    fn begin(&mut self, nick: String) -> IrcSessionSnapshot {
        self.nick = Some(nick);
        self.channels.clear();
        self.features = UpstreamFeatures::default();
        self.snapshot().expect("a begun IRC session has a nick")
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
        let casemap = e6irc_proto::casemap::CaseMapping::Rfc1459;
        let source_nick = message.source.as_ref().map(|source| source.name);
        let is_us = |candidate: Option<&str>| {
            candidate.is_some_and(|candidate| casemap.eq(candidate, current_nick))
        };
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
                    match upstream_identity::ConfirmedChannel::parse(name) {
                        Some(channel) => {
                            confirmed.insert(casemap.casefold(channel.as_str()), channel);
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
                    change.leave(&mut self.channels, casemap.casefold(channel));
                }
            }
            "KICK" => {
                let channels = list(0);
                let targets = list(1);
                if channels.len() == targets.len() {
                    for (channel, target) in channels.into_iter().zip(targets) {
                        if is_us(Some(target)) {
                            change.leave(&mut self.channels, casemap.casefold(channel));
                        }
                    }
                } else if channels.len() == 1
                    && targets.into_iter().any(|target| is_us(Some(target)))
                {
                    change.leave(&mut self.channels, casemap.casefold(channels[0]));
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
            }
            _ => {}
        }
        Ok(change)
    }

    /// Track `line` as something an attached client is about to read, and
    /// return what that client should read. A replayed backlog can hold the
    /// confirmed channels of many past sessions, so it is bounded like the
    /// live tracker: a line past the bound is withheld, because a membership
    /// the client saw but this mirror does not hold could never be reconciled
    /// against the authoritative snapshot.
    fn mirror<'line>(&mut self, line: &'line str) -> &'line str {
        match self.observe(line) {
            Ok(_) => line,
            Err(ChannelLimitExceeded) => {
                ":*bnc* NOTICE * :upstream line omitted: it exceeds the tracked channel limit"
            }
        }
    }

    fn replace(&mut self, snapshot: &IrcSessionSnapshot) {
        let casemap = e6irc_proto::casemap::CaseMapping::Rfc1459;
        self.nick = Some(snapshot.nick.clone());
        self.channels = snapshot
            .channels
            .iter()
            .filter_map(|channel| upstream_identity::ConfirmedChannel::parse(channel))
            .map(|channel| (casemap.casefold(channel.as_str()), channel))
            .collect();
    }

    fn snapshot(&self) -> Option<IrcSessionSnapshot> {
        let nick = self.nick.clone()?;
        let mut channels: Vec<String> = self
            .channels
            .values()
            .map(|channel| channel.as_str().to_string())
            .collect();
        channels
            .sort_by_key(|channel| e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(channel));
        Some(IrcSessionSnapshot { nick, channels })
    }
}

/// A driver status event. A non-connected status always carries the precise
/// safe failure class when one exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverConnectionStatus {
    Connected,
    Reconnecting(NetworkFailure),
    AuthenticationFailed,
    RegistrationFailed(NetworkFailure),
}

impl DriverConnectionStatus {
    pub const fn lifecycle(self) -> NetworkLifecycle {
        match self {
            Self::Connected => NetworkLifecycle::Connected,
            Self::Reconnecting(_) => NetworkLifecycle::Reconnecting,
            Self::AuthenticationFailed => NetworkLifecycle::AuthenticationFailed,
            Self::RegistrationFailed(_) => NetworkLifecycle::RegistrationFailed,
        }
    }

    pub const fn failure(self) -> Option<NetworkFailure> {
        match self {
            Self::Connected => None,
            Self::Reconnecting(failure) | Self::RegistrationFailed(failure) => Some(failure),
            Self::AuthenticationFailed => Some(NetworkFailure::AuthenticationRejected),
        }
    }
}

fn status_notice(status: DriverConnectionStatus) -> String {
    match status {
        DriverConnectionStatus::Connected => ":*bnc* NOTICE * :upstream connected".to_string(),
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
    Reconnecting,
    AuthenticationFailed,
    RegistrationFailed,
}

impl NetworkLifecycle {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Reconnecting => "reconnecting",
            Self::AuthenticationFailed => "authentication_failed",
            Self::RegistrationFailed => "registration_failed",
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
    let line = crate::sanitize::upstream_line(failure_notice(failure));
    let buffer = buffer.lock().expect("buffer poisoned");
    // A storage failure repeats for every line the upstream sends while the
    // database is away: retained, its identical notices would evict the
    // conversation the ring exists to keep, and an attaching client's replay
    // would be mostly error notices. It is told live instead, at its position.
    let live_only = matches!(
        failure,
        NetworkFailure::BacklogStorageFailed | NetworkFailure::BacklogStorageLagged
    );
    let mut buffer = buffer;
    let seq = if live_only {
        buffer.position()
    } else {
        buffer.push(line.clone())
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
    Terminal(TerminalNetworkLifecycle),
}

impl NetworkRuntimePhase {
    const fn lifecycle(self) -> NetworkLifecycle {
        match self {
            Self::Connecting => NetworkLifecycle::Connecting,
            Self::Reconnecting { .. } => NetworkLifecycle::Reconnecting,
            Self::Connected { .. } => NetworkLifecycle::Connected,
            Self::Terminal(lifecycle) => lifecycle.lifecycle(),
        }
    }

    const fn next_retry_at(self) -> Option<e6irc_proto::time::Millis> {
        match self {
            Self::Reconnecting { next_retry_at } => next_retry_at,
            Self::Connecting | Self::Connected { .. } | Self::Terminal(_) => None,
        }
    }

    const fn connected_at(self) -> Option<e6irc_proto::time::Millis> {
        match self {
            Self::Connected { connected_at } => Some(connected_at),
            Self::Connecting | Self::Reconnecting { .. } | Self::Terminal(_) => None,
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
}

impl std::fmt::Display for ReplayCursor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}:{}", self.epoch, self.seq)
    }
}

/// What an attach replays: the lines, where the ring stands after them, and
/// whether a presented cursor was honoured (only the lines after it) or the
/// whole ring was replayed instead.
#[derive(Debug)]
pub struct Replay {
    pub lines: Vec<BufferedLine>,
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

/// Bounded ring of recent upstream lines, for playback on attach.
pub struct Buffer {
    lines: std::collections::VecDeque<BufferedLine>,
    cap: usize,
    /// Identifies this ring's lifetime; part of every cursor it hands out.
    epoch: u64,
    /// The position the next pushed line takes. Starts above `cap` so the
    /// lines `preload_front` restores from storage — older than anything
    /// pushed, at most `cap` of them — take positions that stay positive.
    next_seq: u64,
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
            lines: std::collections::VecDeque::new(),
            cap,
            epoch,
            next_seq: cap as u64 + 1,
        }
    }

    /// Retain `line` as the newest, returning the position it took.
    fn push(&mut self, line: String) -> u64 {
        // `>=` (not `==`) so a zero/under-filled cap can never let the ring
        // grow without bound.
        while self.lines.len() >= self.cap.max(1) {
            self.lines.pop_front();
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.lines.push_back(BufferedLine { seq, line });
        seq
    }

    /// The position of the newest line (or of the ring's start, when empty):
    /// what a live-only event that enters no ring reports as its cursor.
    fn position(&self) -> u64 {
        self.next_seq - 1
    }

    pub fn snapshot(&self) -> Vec<String> {
        self.lines.iter().map(|entry| entry.line.clone()).collect()
    }

    /// The lines after `after`, when that cursor names a position of this ring
    /// whose every successor is still retained; otherwise the whole ring, with
    /// `resumed` false so the client knows to start its transcript over.
    fn replay_after(&self, after: Option<ReplayCursor>) -> Replay {
        let honoured = after.is_some_and(|cursor| {
            cursor.epoch == self.epoch
                && cursor.seq < self.next_seq
                && self
                    .lines
                    .front()
                    .is_none_or(|oldest| cursor.seq + 1 >= oldest.seq)
        });
        let lines = match after.filter(|_| honoured) {
            Some(cursor) => self
                .lines
                .iter()
                .filter(|entry| entry.seq > cursor.seq)
                .cloned()
                .collect(),
            None => self.lines.iter().cloned().collect(),
        };
        Replay {
            lines,
            epoch: self.epoch,
            position: self.position(),
            resumed: honoured,
        }
    }
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
    let shown = e6irc_proto::message::truncate_on_char_boundary(target, 64);
    format!(":*bnc* NOTICE {shown} :not delivered: no bridged {platform} {kind} for {shown}")
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
    format!(":*bnc* NOTICE * :not delivered: {platform} send to {kind} {shown} failed")
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
    format!(
        ":*bnc* NOTICE * :not delivered: {platform} rate-limited sends to {kind} {shown} \
         (it asked for {}s)",
        retry_after.as_secs_f64().ceil()
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

/// Render a bridged message as one or more IRC lines — `PRIVMSG`, a CTCP
/// `ACTION`, or a `NOTICE`, as the [`Inbound`] says: the sender is reduced to
/// a safe nick token and the body is split to fit the line limit.
///
/// The body is free-form remote text of arbitrary length — Slack alone allows
/// 40,000 characters — while an IRC line is [`MAX_LINE_LEN`] bytes including
/// its CRLF. Emitting one over-long line does not merely bend the protocol: the
/// receiving client's framing discards an over-long line *whole*, so the
/// message vanishes with nothing said. It is split instead, because a bridged
/// message must not disappear for being long. Each piece of an action is its
/// own complete `ACTION`.
///
/// Embedded newlines split too. They are line breaks in the source medium, and
/// [`crate::sanitize::upstream_line`] flattens them to spaces further down, which would
/// turn a multi-line message into one run-on line.
///
/// An empty body still yields one line: a message was sent, and saying nothing
/// about it would be the silent drop this exists to prevent.
#[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
pub(crate) fn render_bridged(
    host: &str,
    sender: &str,
    channel: &str,
    message: &Inbound,
) -> Vec<String> {
    use e6irc_proto::message::MAX_LINE_LEN;
    let who = bridged_identity(host, sender);
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
    // `nick_token` bounds the nick and `host` is one of three literals, so only
    // a pathologically long configured channel name can exhaust the line. The
    // floor keeps the split making progress if one ever does; the resulting
    // lines would still be over-long, which is a configuration error and not
    // something this function can paper over.
    let budget = (MAX_LINE_LEN - 2)
        .saturating_sub(prefix.len() + close.len())
        .max(1);

    let mut out = Vec::new();
    for piece in message.body.split('\n') {
        let mut rest = piece;
        loop {
            if rest.len() <= budget {
                out.push(format!("{prefix}{rest}{close}"));
                break;
            }
            // Split on a character boundary — `budget` is a byte count, and
            // slicing into the middle of a multi-byte character panics.
            let mut cut = budget;
            while cut > 0 && !rest.is_char_boundary(cut) {
                cut -= 1;
            }
            // A single character wider than the budget: take it whole rather
            // than emit an empty line forever.
            if cut == 0 {
                cut = rest.char_indices().nth(1).map_or(rest.len(), |(i, _)| i);
            }
            out.push(format!("{prefix}{}{close}", &rest[..cut]));
            rest = &rest[cut..];
        }
    }
    out
}

/// How a bridge shows a provider account on IRC: `nick!nick@<platform>`, the
/// nick reduced to a safe token. Every relayed post is prefixed from it, and so
/// is the echo of our own — the line the provider's copy of the post would have
/// been — so the two can never disagree about who the bridge's account is.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
pub(crate) fn bridged_identity(host: &str, name: &str) -> irc_driver::SelfIdentity {
    let nick = crate::sanitize::nick_token(name);
    irc_driver::SelfIdentity {
        user: nick.clone(),
        nick,
        host: host.to_string(),
    }
}

/// A `*bnc*` NOTICE to `channel` saying a message from `sender` of a kind the
/// bridge cannot show (`what`, the provider's own type name) was not relayed.
/// `what` is upstream text: it is reduced to a bounded token of type-name
/// characters, so it can carry neither controls nor a line's worth of bytes.
/// A message too malformed to name its sender is said to be from an unknown
/// one rather than dropped.
#[cfg(any(feature = "matrix", feature = "slack"))]
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
    format!(":*bnc* NOTICE {channel} :{platform}: a {what} message from {sender} was not relayed")
}

/// Outcome of a non-blocking send to a network's shared upstream command queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    /// The line was queued for the upstream.
    Sent,
    /// The bounded queue is full (upstream reconnecting / congested). The line
    /// was not queued; the caller must tell the client loudly.
    Full,
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
    /// during an upstream reconnect) stall every *other* attached client's
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
        if matches!(
            self.runtime_snapshot().lifecycle,
            NetworkLifecycle::AuthenticationFailed | NetworkLifecycle::RegistrationFailed
        ) {
            return SendOutcome::Unavailable;
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

    /// A copy of the current detached buffer (for attach playback).
    pub fn buffer_snapshot(&self) -> Vec<String> {
        self.buffer.lock().expect("buffer poisoned").snapshot()
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
    ) -> (
        tokio::sync::broadcast::Receiver<DriverEvent>,
        Replay,
        Option<IrcSessionSnapshot>,
    ) {
        let irc_session = self.irc_session.lock().expect("IRC session state poisoned");
        let buffer = self.buffer.lock().expect("buffer poisoned");
        let events = self.events.subscribe();
        let replay = buffer.replay_after(after);
        (events, replay, irc_session.snapshot())
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
    /// capacity is filled, keeping the most recent of `older`.
    pub fn preload_front(&self, older: Vec<String>) {
        let mut buf = self.buffer.lock().expect("buffer poisoned");
        let room = buf.cap.saturating_sub(buf.lines.len());
        let skip = older.len().saturating_sub(room);
        for line in older[skip..].iter().rev() {
            // Each restored line takes the position just below the current
            // oldest: older than everything pushed, in storage order.
            let seq = buf.lines.front().map_or(buf.next_seq, |oldest| oldest.seq) - 1;
            // Neutralized here as well as in `emit_line`. These lines come back
            // from storage, which outlives the code that wrote them: a row put
            // there by an older build, a restore, or anything else with database
            // access would otherwise be replayed to an attaching client verbatim.
            // Both ways into the buffer sanitize, so no reader has to ask which
            // one a line arrived through.
            buf.lines.push_front(BufferedLine {
                seq,
                line: crate::sanitize::upstream_line(line.clone()),
            });
        }
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
    pub fn track_attachment(&self) -> NetworkAttachment {
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
            buffer_lines: buffer.lines.len(),
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
        let (events, _) = tokio::sync::broadcast::channel(1024);
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
        let irc_session = std::sync::Arc::new(std::sync::Mutex::new(IrcSessionState::default()));
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
            telemetry,
            reconnect_seed,
            rejection_retry_floor: REJECTION_RETRY_FLOOR,
            first_dial_delay: std::time::Duration::ZERO,
            buffered_status: std::sync::Mutex::new(None),
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
    /// The connection state whose notice last entered the backlog.
    buffered_status: std::sync::Mutex<Option<DriverConnectionStatus>>,
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
        drop(self.events.send(DriverEvent::Session(snapshot)));
    }

    /// Begin a bridge's session and report the bridge connected, in one step:
    /// the session's nick is the provider account's, as `identity` (from
    /// [`bridged_identity`]) names it, and its channels are the ones the
    /// bridge maps. An attached client is welcomed under the session's nick
    /// and the echo of what it sends names `identity`, so the two are the same
    /// nick by construction — a client recognises its own echoes, and a
    /// bridge cannot be connected with no session for them to match.
    ///
    /// A channel a client could not be told it is in, or more of them than
    /// [`MAX_TRACKED_CHANNELS`], is a configuration the bridge cannot serve,
    /// and nothing is begun.
    #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
    pub(crate) fn begin_bridge_session<'a>(
        &self,
        identity: &irc_driver::SelfIdentity,
        channels: impl IntoIterator<Item = &'a String>,
    ) -> Result<(), SessionOutcome> {
        let refused = |detail: &str| {
            SessionOutcome::ConfigurationRejected(ConfigurationRefusal::new(
                NetworkFailure::ChannelMappingFailed,
                detail,
            ))
        };
        let casemap = e6irc_proto::casemap::CaseMapping::Rfc1459;
        let mut bridged = std::collections::HashMap::new();
        for channel in channels {
            let Some(confirmed) = upstream_identity::ConfirmedChannel::parse(channel) else {
                return Err(refused(&format!(
                    "{channel} is not a channel name an IRC client can be joined to"
                )));
            };
            bridged.insert(casemap.casefold(channel), confirmed);
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
            drop(self.events.send(DriverEvent::Session(snapshot)));
        }
        self.emit(ConnectionEvent::Connected);
        Ok(())
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
        let line = crate::sanitize::upstream_line(line);
        self.record_input(line.len());
        self.publish_buffered(line);
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
        let line = crate::sanitize::upstream_line(line);
        let mut irc_session = self.irc_session.lock().expect("IRC session state poisoned");
        let change = irc_session.observe(&line)?;
        self.record_input(line.len());
        match origin {
            None => self.publish_buffered(line),
            Some(origin) => {
                let mut buffer = self.buffer.lock().expect("buffer poisoned");
                let seq = buffer.push(line.clone());
                drop(self.events.send(DriverEvent::Echo {
                    line: BufferedLine { seq, line },
                    origin,
                }));
            }
        }
        // The raw line was delivered, so the client believes in a membership
        // this session does not hold and will not restore. Say so to whoever is
        // attached; it is not conversation, so it stays out of the backlog.
        for name in &change.untracked {
            let line = crate::sanitize::upstream_line(format!(
                ":*bnc* NOTICE * :upstream confirmed a channel name e6irc cannot track: {name}"
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

    fn publish_buffered(&self, line: String) {
        let mut buffer = self.buffer.lock().expect("buffer poisoned");
        let seq = buffer.push(line.clone());
        // A detached network legitimately has no live subscribers; the line is
        // still retained in the buffer above. Keep the buffer lock through the
        // publish: attach takes that lock before subscribing and snapshotting,
        // which makes the replay/live boundary atomic.
        drop(
            self.events
                .send(DriverEvent::Line(BufferedLine { seq, line })),
        );
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
        let line = crate::sanitize::upstream_line(line);
        self.runtime.record_input(line.len());
        let mut buffer = self.buffer.lock().expect("buffer poisoned");
        let seq = buffer.push(line.clone());
        drop(self.events.send(DriverEvent::Echo {
            line: BufferedLine { seq, line },
            origin,
        }));
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
        let notice = crate::sanitize::upstream_line(notice);
        let mut buffered_status = self
            .buffered_status
            .lock()
            .expect("buffered status poisoned");
        // Keyed by lifecycle, not by the failure inside it: a round-robin
        // upstream rotates addresses per attempt, so consecutive retries
        // genuinely alternate (connection_failed, connection_timed_out) and
        // every one of them used to write a retained line — thousands of them
        // across a long outage, into a ring of a thousand.
        let stage = status.lifecycle();
        if buffered_status
            .replace(status)
            .map(DriverConnectionStatus::lifecycle)
            == Some(stage)
        {
            // Live only: the ring's position is unchanged, read under its lock.
            let buffer = self.buffer.lock().expect("buffer poisoned");
            drop(self.events.send(DriverEvent::Notice(BufferedLine {
                seq: buffer.position(),
                line: notice,
            })));
        } else {
            self.publish_buffered(notice);
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

fn lifecycle_notice(state: &str, failure: NetworkFailure, diagnostic: Option<&str>) -> String {
    let detail = diagnostic.map_or_else(String::new, |value| format!("; upstream: {value}"));
    format!(
        ":*bnc* NOTICE * :component {state}: {} ({}){detail}",
        failure.summary(),
        failure.code()
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
/// `start` consumes the driver and spawns its task, returning the handle
/// clients attach to. (DESIGN §10.5)
pub trait NetworkDriver: Send + 'static {
    /// Stable kind name for logs/metrics (`irc`, `loopback`, …).
    fn kind(&self) -> &'static str;
    /// Spawn the always-on task and return its handle.
    fn start(self: Box<Self>) -> NetworkHandle;
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
    fn start(self: Box<Self>) -> NetworkHandle {
        IrcNetwork::start(self.config)
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
    fn start(self: Box<Self>) -> NetworkHandle {
        let (handle, mut ends) = NetworkHandle::channels(self.buffer_cap);
        tokio::spawn(async move {
            ends.emit(ConnectionEvent::Connected);
            while let Some(cmd) = ends.next_command().await {
                ends.emit_line(cmd.line);
            }
        });
        handle
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
}

/// Attach a downstream client stream to a running network: replay the
/// detached buffer, then bidirectionally relay driver events to the
/// client and client lines to the upstream. Returns when either side
/// closes. This is the session multiplexer's core operation, serving
/// every driver kind (`irc`, `local`, and the bridges) uniformly.
///
/// `input` is what the client already sent on `stream` that nothing handled
/// (see [`ClientInput`]); it is handled first, after the replay, as the
/// attached session's own input.
/// `account` is the authenticated account, used to key the BNC-local
/// per-target read markers (shared networks keep per-account positions).
/// `liveness` is how long the client may stay silent before it is pinged, and
/// then again before it is given up on ([`ATTACH_LIVENESS_INTERVAL`] in
/// production).
///
/// Every write to the client is bounded by [`crate::peer_write`]: a client
/// that stops reading ends its attachment as [`AttachEnd::ClientTooSlow`]
/// rather than parking the relay, where it would see neither the network's
/// removal nor its own silence.
pub async fn attach<S>(
    stream: S,
    input: ClientInput,
    handle: &NetworkHandle,
    caps: AttachCaps,
    account: &str,
    downstream_nick: &str,
    liveness: std::time::Duration,
) -> std::io::Result<AttachEnd>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let stream =
        crate::peer_write::DeadlineWriter::new(stream, crate::peer_write::PEER_WRITE_DEADLINE);
    match relay_attached(
        stream,
        input,
        handle,
        caps,
        account,
        downstream_nick,
        liveness,
    )
    .await
    {
        Err(error) if crate::peer_write::is_stalled(&error) => Ok(AttachEnd::ClientTooSlow),
        ended => ended,
    }
}

/// [`attach`]'s relay, over a stream whose writes are already bounded.
async fn relay_attached<S>(
    stream: crate::peer_write::DeadlineWriter<S>,
    input: ClientInput,
    handle: &NetworkHandle,
    mut caps: AttachCaps,
    account: &str,
    downstream_nick: &str,
    liveness: std::time::Duration,
) -> std::io::Result<AttachEnd>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut read, mut write) = tokio::io::split(stream);

    // Detach the client if the network is removed. The broadcast does not close
    // on its own (the registry's `NetworkHandle` keeps an events sender), so
    // without this an attached client would linger on a stopped network — its
    // upstream gone but the session still open.
    let mut shutdown = handle.shutdown.subscribe();
    // The network may have been removed *between* the caller resolving this
    // handle and here (the same account's own API can delete/replace it, and the
    // handshake/upgrade before attach is a wide window). A `watch::Receiver`
    // subscribed after the shutdown was signalled treats that value as already
    // seen, so `changed()` below would never fire and the client would linger
    // forever on a dead network. Check the current value once, up front.
    if *shutdown.borrow() {
        write
            .write_all(b":*bnc* NOTICE * :network removed; detaching\r\n")
            .await?;
        write.flush().await?;
        return Ok(AttachEnd::NetworkRemoved);
    }
    if !handle.wait_for_history().await {
        write
            .write_all(b":*bnc* NOTICE * :network removed; detaching\r\n")
            .await?;
        write.flush().await?;
        return Ok(AttachEnd::NetworkRemoved);
    }
    let _attachment = handle.track_attachment();
    let attach_id = handle.next_attachment_id();
    // A raw IRC client has no cursor to present; it always takes the whole ring.
    let (mut events, replay, session_snapshot) = handle.subscribe_with_replay_snapshot(None);

    // Send the current upstream connection status up front, so a client that
    // attaches to an already-connected (or still-reconnecting) network learns the
    // state now rather than only at the next connect/disconnect transition — the
    // same up-front status `/ws/ui` sends over WebSocket. Live status events
    // below include the classified failure when the upstream is not connected.
    let runtime = handle.runtime_snapshot();
    let mut status_revision = runtime.status_revision;
    let status: &[u8] = if runtime.lifecycle == NetworkLifecycle::Connected {
        b":*bnc* NOTICE * :upstream connected\r\n"
    } else {
        b":*bnc* NOTICE * :upstream disconnected\r\n"
    };
    write.write_all(status).await?;

    // Playback: everything buffered while detached, in order, with tags the
    // client didn't negotiate stripped.
    let mut downstream_session = IrcSessionState::default();
    downstream_session.begin(downstream_nick.to_string());
    for entry in replay.lines {
        let line = downstream_session.mirror(&entry.line);
        if let Some(line) = filter_tags(line, caps) {
            write.write_all(line.as_bytes()).await?;
            write.write_all(b"\r\n").await?;
        }
    }
    if let Some(snapshot) = session_snapshot {
        write_irc_session_snapshot(
            &mut write,
            &mut downstream_session,
            &snapshot,
            JoinAudience {
                handle,
                caps,
                account,
            },
        )
        .await?;
    }
    write.flush().await?;

    let attachment = Attachment {
        handle,
        account,
        id: attach_id,
        nick: downstream_nick,
    };
    let ClientInput {
        mut framing,
        pending,
    } = input;
    for event in pending {
        if let Some(end) = client_event(
            &mut write,
            event,
            &attachment,
            &mut caps,
            &downstream_session,
        )
        .await?
        {
            return Ok(end);
        }
    }
    let mut read_buf = vec![0u8; 8192];
    let mut parsed = Vec::new();
    // Anything the client sends shows it is there; only its silence is timed,
    // and lines written *to* it prove nothing about a half-open socket.
    let mut client_silence = SilenceDeadline::new(liveness);
    let mut awaiting_pong = false;
    loop {
        tokio::select! {
            // Network removed/replaced: tell the client and detach.
            res = shutdown.changed() => {
                if res.is_err() || *shutdown.borrow() {
                    write
                        .write_all(b":*bnc* NOTICE * :network removed; detaching\r\n")
                        .await?;
                    write.flush().await?;
                    return Ok(AttachEnd::NetworkRemoved);
                }
            }
            // Upstream -> client.
            ev = events.recv() => match ev {
                Ok(event @ (DriverEvent::Line(_) | DriverEvent::Notice(_))) => {
                    let line = event.display_line().expect("display event carries a line");
                    let line = downstream_session.mirror(line);
                    write_filtered_line(&mut write, line, caps).await?;
                }
                Ok(DriverEvent::Echo { line, origin }) => {
                    // The originator's own echo reaches it only when it
                    // negotiated echo-message — the same contract a real
                    // server has. Every other attached client always gets it.
                    if origin != attach_id || caps.echo_message {
                        write_filtered_line(&mut write, &line.line, caps).await?;
                    }
                }
                Ok(DriverEvent::Status { status, revision }) => {
                    if !accept_status_revision(&mut status_revision, revision) {
                        continue;
                    }
                    write.write_all(status_notice(status).as_bytes()).await?;
                    write.write_all(b"\r\n").await?;
                    write.flush().await?;
                }
                Ok(DriverEvent::Session(snapshot)) => {
                    write_irc_session_snapshot(
                        &mut write,
                        &mut downstream_session,
                        &snapshot,
                        JoinAudience {
                            handle,
                            caps,
                            account,
                        },
                    )
                    .await?;
                    write.flush().await?;
                }
                Ok(DriverEvent::ReadMarker {
                    account: marker_account,
                    target,
                    timestamp,
                    origin,
                }) => {
                    if caps.read_marker
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
            n = client_silence.bound(read.read(&mut read_buf)) => match n {
                None if awaiting_pong => return Ok(AttachEnd::ClientUnresponsive),
                None => {
                    awaiting_pong = true;
                    client_silence.restart();
                    write.write_all(ATTACH_LIVENESS_PING).await?;
                    write.flush().await?;
                }
                Some(Ok(0)) => return Ok(AttachEnd::ClientClosed),
                Some(Ok(n)) => {
                    awaiting_pong = false;
                    client_silence.restart();
                    framing.feed(&read_buf[..n], &mut parsed);
                    for event in parsed.drain(..) {
                        if let Some(end) = client_event(&mut write, event, &attachment, &mut caps, &downstream_session).await? {
                            return Ok(end);
                        }
                    }
                }
                Some(Err(e)) => return Err(e),
            },
        }
    }
}

/// What a client sent on its stream before [`attach`] took it that nothing
/// has handled yet: the lines already framed, and the start of one still
/// arriving. The attach listener's registration handshake frames the same
/// stream first, and a client need not wait for the welcome before sending —
/// the lines that arrived in the same read as its `CAP END`, and half of the
/// next, belong to the attached session. A fresh stream has none.
pub struct ClientInput {
    framing: e6irc_proto::framing::LineBuffer,
    pending: Vec<e6irc_proto::framing::LineEvent>,
}

impl Default for ClientInput {
    fn default() -> Self {
        Self {
            framing: e6irc_proto::framing::LineBuffer::new(
                e6irc_proto::message::MAX_CLIENT_FRAME_LEN,
            ),
            pending: Vec::new(),
        }
    }
}

/// Who an attachment is, for [`client_event`]: the network it is attached to,
/// the account it authenticated as, its id among the network's attachments,
/// and the nick it was welcomed under.
struct Attachment<'a> {
    handle: &'a NetworkHandle,
    account: &'a str,
    id: u64,
    nick: &'a str,
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
                                attachment.nick,
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
                        let target = downstream_session
                            .snapshot()
                            .map(|session| session.nick)
                            .unwrap_or_else(|| attachment.nick.to_string());
                        let mut cap_open = false;
                        serve::handle_cap(write, "*bnc*", &target, &msg, true, &mut cap_open, caps)
                            .await?;
                    }
                    "AUTHENTICATE" => {
                        write_attach_numeric(
                            write,
                            attachment.nick,
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
                            attachment.nick,
                            421,
                            Some("MARKREAD"),
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
                        // Full: the upstream is congested/reconnecting.
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
        // relayed rather than swallowing it.
        LineEvent::TooLong => {
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
    let casemap = e6irc_proto::casemap::CaseMapping::Rfc1459;
    let current = downstream
        .snapshot()
        .expect("downstream IRC state is initialized before a client line is handled");
    let nick = current.nick.as_str();
    let Some(&first) = params.first().filter(|first| !first.is_empty()) else {
        return match command {
            "NICK" => write_attach_numeric(write, nick, 431, None, "No nickname given").await,
            _ => {
                write_attach_numeric(write, nick, 461, Some(command), "Not enough parameters").await
            }
        };
    };
    if command == "NICK" {
        if casemap.eq(first, nick) {
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
        let shown = e6irc_proto::message::truncate_on_char_boundary(
            channel,
            upstream_identity::ConfirmedChannel::MAX_BYTES,
        );
        match downstream.channels.get(&casemap.casefold(channel)) {
            Some(bridged) => {
                let audience = JoinAudience {
                    handle: attachment.handle,
                    caps,
                    account: attachment.account,
                };
                write_joined(write, nick, bridged.as_str(), audience).await?;
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

async fn write_attach_numeric<W>(
    write: &mut W,
    nick: &str,
    numeric: u16,
    middle: Option<&str>,
    trailing: &str,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let nick = e6irc_proto::message::truncate_on_char_boundary(nick, 64);
    let middle = middle.map_or_else(String::new, |value| format!(" {value}"));
    write
        .write_all(format!(":*bnc* {numeric:03} {nick}{middle} :{trailing}\r\n").as_bytes())
        .await?;
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
/// negotiated, and the account whose read markers it carries.
#[derive(Clone, Copy)]
struct JoinAudience<'a> {
    handle: &'a NetworkHandle,
    caps: AttachCaps,
    account: &'a str,
}

async fn write_irc_session_snapshot<W>(
    write: &mut W,
    downstream: &mut IrcSessionState,
    snapshot: &IrcSessionSnapshot,
    audience: JoinAudience<'_>,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let casemap = e6irc_proto::casemap::CaseMapping::Rfc1459;
    let current = downstream
        .snapshot()
        .expect("downstream IRC state is initialized before reconciliation");
    if !casemap.eq(&current.nick, &snapshot.nick) {
        write
            .write_all(format!(":{} NICK :{}\r\n", current.nick, snapshot.nick).as_bytes())
            .await?;
    }
    let wanted: std::collections::HashMap<String, &str> = snapshot
        .channels
        .iter()
        .map(|channel| (casemap.casefold(channel), channel.as_str()))
        .collect();
    for channel in &current.channels {
        if !wanted.contains_key(&casemap.casefold(channel)) {
            write
                .write_all(
                    format!(
                        ":{}!~bnc@e6irc PART {channel} :upstream session reset\r\n",
                        snapshot.nick
                    )
                    .as_bytes(),
                )
                .await?;
        }
    }
    for channel in &snapshot.channels {
        if !downstream.channels.contains_key(&casemap.casefold(channel)) {
            // This JOIN is synthesized because the real one aged out of the
            // bounded replay (or, on a bridge, there never was one).
            write_joined(write, &snapshot.nick, channel, audience).await?;
        }
    }
    downstream.replace(snapshot);
    Ok(())
}

/// Tell one client it is in `channel` as `nick`, in the shape a server
/// answers a JOIN with: the JOIN, the channel's read marker when the client
/// asked for read markers, and a minimal member list naming itself.
async fn write_joined<W>(
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
    } = audience;

    write
        .write_all(format!(":{nick}!~bnc@e6irc JOIN {channel}\r\n").as_bytes())
        .await?;
    if caps.read_marker {
        match handle.history() {
            Some(history) => {
                chathistory::send_read_marker(write, &history, account, channel).await?;
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
    write
        .write_all(format!(":*bnc* 353 {nick} = {channel} :{nick}\r\n").as_bytes())
        .await?;
    write
        .write_all(format!(":*bnc* 366 {nick} {channel} :End of /NAMES list\r\n").as_bytes())
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

        ends.emit(ConnectionEvent::RegistrationFailed(
            e6irc_client::RegistrationRejection::without_diagnostic(
                e6irc_client::RegistrationRefusal::InvalidNickname,
            ),
        ));
        let rejected = handle.runtime_snapshot();
        assert_eq!(rejected.lifecycle, NetworkLifecycle::RegistrationFailed);
        assert_eq!(rejected.last_error, Some(NetworkFailure::InvalidNickname));
        assert_eq!(
            rejected.last_error_diagnostic.as_deref(),
            Some("no detail from upstream")
        );
        assert_eq!(failed.errors, 2);
        assert_eq!(rejected.buffer_lines, 5);
        assert_eq!(
            handle.buffer_snapshot(),
            vec![
                ":*bnc* NOTICE * :component connected: unregistered network".to_string(),
                ":upstream PRIVMSG #room :hello".to_string(),
                ":*bnc* NOTICE * :component reconnecting: The established upstream connection was lost. (connection_lost)".to_string(),
                ":*bnc* NOTICE * :component authentication_failed: The upstream rejected the configured credentials. (authentication_rejected)".to_string(),
                ":*bnc* NOTICE * :component registration_failed: The upstream rejected the configured nickname. (invalid_nickname); upstream: no detail from upstream".to_string(),
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

        // Another failure *of the same stage* is the same outage continuing:
        // an upstream with several addresses alternates its failures per
        // attempt (one refuses, one black-holes), and a line per attempt would
        // fill the ring over a long outage. A recovery, and the reconnecting
        // that follows it, are transitions.
        ends.emit(ConnectionEvent::Reconnecting(
            NetworkFailure::ConnectionTimedOut,
        ));
        ends.emit(ConnectionEvent::Reconnecting(
            NetworkFailure::ConnectionLost,
        ));
        assert_eq!(
            handle.buffer_snapshot().len(),
            2,
            "an alternating failure is still one reconnecting stage: {:?}",
            handle.buffer_snapshot()
        );
        ends.emit(ConnectionEvent::Connected);
        ends.emit(ConnectionEvent::Reconnecting(
            NetworkFailure::ConnectionLost,
        ));
        assert_eq!(
            handle.buffer_snapshot().len(),
            4,
            "a recovery and the reconnecting after it are both transitions: {:?}",
            handle.buffer_snapshot()
        );
        // Two retained (the recovery and the reconnecting after it) and two
        // live-only (the alternating failures within the one outage).
        assert_eq!(live_notices(&mut events), (2, 2));
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
        let (mut events, replay, session) = handle.subscribe_with_replay_snapshot(None);
        let snapshot: Vec<&str> = replay
            .lines
            .iter()
            .map(|entry| entry.line.as_str())
            .collect();
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
                Ok(DriverEvent::Line(BufferedLine { line, .. })) if line == ":upstream PRIVMSG #room :after boundary"
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

        ends.emit(ConnectionEvent::RegistrationFailed(
            e6irc_client::RegistrationRejection::without_diagnostic(
                e6irc_client::RegistrationRefusal::InvalidNickname,
            ),
        ));
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
            handle.buffer_snapshot(),
            vec![":peer PRIVMSG #room :kept".to_string()]
        );
    }

    #[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
    #[test]
    fn bridge_error_is_a_component_log_notice() {
        let (handle, ends) = NetworkHandle::channels(8);
        ends.record_error(NetworkFailure::UpstreamRequestFailed);

        assert_eq!(
            handle.buffer_snapshot(),
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
                server_side,
                ClientInput::default(),
                &handle,
                AttachCaps::default(),
                "testuser",
                "testuser",
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
            server_side,
            ClientInput::default(),
            &handle,
            AttachCaps::default(),
            "testuser",
            "testuser",
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
        let err = bridge_send(http.get(&format!("http://127.0.0.1:{port}/")).unwrap())
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
        Refuse(e6irc_client::RegistrationRefusal),
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
                Some(ScriptedStep::Refuse(refusal)) => SessionOutcome::RegistrationRejected(
                    e6irc_client::RegistrationRejection::without_diagnostic(refusal),
                ),
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
    #[tokio::test(start_paused = true)]
    async fn refusals_that_never_park_do_not_count_toward_parking_a_later_one() {
        use e6irc_client::RegistrationRefusal;
        let mut steps: Vec<ScriptedStep> = (0..MAX_CONSECUTIVE_REGISTRATION_REJECTIONS)
            .map(|_| ScriptedStep::Refuse(RegistrationRefusal::SaslUnavailable))
            .collect();
        steps.push(ScriptedStep::Refuse(RegistrationRefusal::NicknameInUse));
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
        let identity = bridged_identity("test", "my bot");
        let refused = ends.begin_bridge_session(
            &identity,
            [&"#ok".to_string(), &"no spaces allowed".to_string()],
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
            ends.begin_bridge_session(&identity, [&"#Ok".to_string(), &"#two".to_string()])
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
        let identity = bridged_identity("test", "me");
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
            lines
                .iter()
                .any(|line| line == &failure_notice(NetworkFailure::UpstreamWriteFailed)),
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
        // Slack allows 40,000 characters. Emitted as one line, the receiving
        // client's framing discards it whole and the message is simply gone.
        let body = "x".repeat(40_000);
        let lines = render_bridged(
            "slack",
            "U1",
            "#general",
            &Inbound::new(InboundKind::Message, &body),
        );
        assert!(lines.len() > 1, "a 40k body must not be one line");
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
                "slack",
                "U1",
                "#c",
                &Inbound::new(InboundKind::Message, "\u{1}VERSION\u{1}\u{2}\t!")
            ),
            vec![":U1!U1@slack PRIVMSG #c :VERSION\t!"]
        );
        assert_eq!(
            render_bridged(
                "matrix",
                "u",
                "#c",
                &Inbound::new(InboundKind::Action, "waves\u{1}")
            ),
            vec![":u!u@matrix PRIVMSG #c :\u{1}ACTION waves\u{1}"]
        );
        assert_eq!(
            render_bridged(
                "matrix",
                "u",
                "#c",
                &Inbound::new(InboundKind::Notice, "a bot")
            ),
            vec![":u!u@matrix NOTICE #c :a bot"]
        );
        let long = "y".repeat(2_000);
        let lines = render_bridged(
            "matrix",
            "u",
            "#c",
            &Inbound::new(InboundKind::Action, &long),
        );
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
                bridge_send(http.get(&format!("{base}/")).unwrap())
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
            "discord",
            "bob",
            "#c",
            &Inbound::new(InboundKind::Message, "one\ntwo\r\nthree"),
        );
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
            let body: String = std::iter::repeat_n(ch, 40_000).collect();
            let lines = render_bridged(
                "matrix",
                "u",
                "#c",
                &Inbound::new(InboundKind::Message, &body),
            );
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
            render_bridged("slack", "U1", "#c", &Inbound::new(InboundKind::Message, "")),
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
        assert_eq!(handle.buffer_snapshot(), vec![tagged.clone()]);
        assert!(matches!(
            events.try_recv(),
            Ok(DriverEvent::Line(BufferedLine { line, .. })) if line == tagged
        ));
    }

    #[test]
    fn restored_backlog_is_neutralized_like_live_lines() {
        // Backlog comes back from storage, which outlives the code that wrote
        // it. A row containing an embedded line break must not be replayed to
        // an attaching client as two lines just because it arrived through
        // `preload_front` rather than `emit_line`.
        let (handle, _ends) = NetworkHandle::channels(16);
        handle.preload_front(vec![
            ":a!a@bridge PRIVMSG #c :hi\r\n:nickserv!s@svc PRIVMSG victim :send me your password"
                .to_string(),
        ]);
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
        let (_, burst) = serve::welcome("bnc.test", "net", &handle, "alice".into());
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
        let (_, burst) = serve::welcome("bnc.test", "net", &handle, "alice".into());
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
        assert_eq!(handle.buffer_snapshot(), vec![":srv NOTICE Alice :joined"]);
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
            assert_eq!(mirror.mirror(&line), line);
        }
        let shown = mirror.mirror(":alice!u@h JOIN #past-the-limit");
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

        let (client, server) = tokio::io::duplex(4096);
        let (handle, mut ends) = NetworkHandle::bridge_channels(4);
        let attach = tokio::spawn(async move {
            attach(
                server,
                ClientInput::default(),
                &handle,
                AttachCaps::default(),
                "alice",
                "alice",
                ATTACH_LIVENESS_INTERVAL,
            )
            .await
        });
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
            if !line.starts_with(":*bnc* NOTICE") {
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

    #[tokio::test]
    async fn raw_attach_snapshot_renames_and_rejoins_the_downstream_client() {
        use tokio::io::AsyncReadExt;

        let (mut client, server) = tokio::io::duplex(4096);
        let (handle, ends) = NetworkHandle::channels(4);
        ends.begin_irc_session("upstreamNick".to_string());
        ends.emit_session_line(":upstreamNick!u@h JOIN #current".to_string())
            .expect("within the channel limit");
        let attach = tokio::spawn(async move {
            attach(
                server,
                ClientInput::default(),
                &handle,
                AttachCaps::default(),
                "alice",
                "alice",
                ATTACH_LIVENESS_INTERVAL,
            )
            .await
        });

        let mut bytes = vec![0; 4096];
        let count =
            tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut bytes))
                .await
                .expect("attach output timed out")
                .expect("read attach output");
        let output = String::from_utf8_lossy(&bytes[..count]);
        assert!(output.contains(":alice NICK :upstreamNick\r\n"), "{output}");
        assert!(
            output.contains(":upstreamNick!~bnc@e6irc JOIN #current\r\n"),
            "{output}"
        );
        assert!(
            output.contains(":*bnc* 353 upstreamNick = #current :upstreamNick\r\n"),
            "synthetic JOIN must include a usable NAMES snapshot: {output}"
        );
        assert!(
            output.contains(":*bnc* 366 upstreamNick #current :End of /NAMES list\r\n"),
            "synthetic JOIN must terminate NAMES: {output}"
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

        let (mut client, server) = tokio::io::duplex(4096);
        let (handle, mut ends) = NetworkHandle::channels(4);
        ends.begin_irc_session("alice".to_string());
        let attach = tokio::spawn(async move {
            attach(
                server,
                ClientInput::default(),
                &handle,
                AttachCaps::default(),
                "alice",
                "alice",
                ATTACH_LIVENESS_INTERVAL,
            )
            .await
        });

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

    fn replayed(replay: &Replay) -> Vec<&str> {
        replay
            .lines
            .iter()
            .map(|entry| entry.line.as_str())
            .collect()
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
        let oldest_retained = ring.lines.front().expect("ring holds lines").seq;
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
        let empty = handle.subscribe_with_replay_snapshot(None).1;
        assert!(replayed(&empty).is_empty());
        let resumed_from_empty = handle
            .subscribe_with_replay_snapshot(Some(empty.position()))
            .1;
        assert!(resumed_from_empty.resumed);

        ends.emit_line("live".into());
        handle.preload_front(vec!["older".into(), "old".into()]);
        let replay = handle.subscribe_with_replay_snapshot(None).1;
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
            .1;
        assert_eq!(replayed(&after_older), ["old", "live"]);
        assert!(after_older.resumed);
    }
}
