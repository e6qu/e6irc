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

#[cfg(feature = "discord")]
pub use discord::{DiscordConfig, DiscordDriver};
pub(crate) use irc_driver::KEEPALIVE_IDLE;
pub(crate) use irc_driver::validate_irc_upstream_addr;
pub use irc_driver::{IrcNetwork, IrcPreflight, IrcPreflightFailure, NetworkConfig, preflight_irc};
pub use local_driver::{CoreHandles, LocalDriver};
#[cfg(feature = "matrix")]
pub use matrix::{MatrixConfig, MatrixDriver};
pub use serve::{NetworkStatus, Registry, bnc_serve};
#[cfg(feature = "slack")]
pub use slack::{SlackConfig, SlackDriver};

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
    if value.is_empty()
        || value.len() > maximum
        || value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0))
    {
        Err(format!(
            "credentials must be non-empty, at most {maximum} bytes, and contain no CR, LF or NUL"
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
async fn resolve_bridge_channels<F, Fut, E>(
    provider: &str,
    ids: &[String],
    mut fetch_name: F,
    classify_lookup_error: E,
) -> Result<(HashMap<String, String>, HashMap<String, String>), SessionOutcome>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<String, String>>,
    E: Fn(&str, &str) -> SessionOutcome,
{
    let mut id_to_channel = HashMap::new();
    let mut channel_to_id = HashMap::new();
    for id in ids {
        let name = match fetch_name(id.clone()).await {
            Ok(name) => name,
            Err(error) => return Err(classify_lookup_error(id, &error)),
        };
        let channel = format!("#{name}");
        if !crate::sanitize::valid_channel_name(&channel) {
            eprintln!(
                "{provider}: channel {id} has an unsafe name {name:?}; refusing to bridge it"
            );
            return Err(SessionOutcome::Dropped(
                NetworkFailure::ChannelMappingFailed,
            ));
        }
        let folded = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(&channel);
        if channel_to_id.contains_key(&folded) {
            eprintln!(
                "{provider}: channel {id} name {name:?} collides with an already-bridged \
                 channel {channel:?}; refusing to bridge it"
            );
            return Err(SessionOutcome::Dropped(
                NetworkFailure::ChannelMappingFailed,
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
    let parsed = openidconnect::url::Url::parse(value).map_err(|_| {
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
    Ok(())
}

/// Build the driver for a network of `kind` from its *plaintext* fields — the
/// one feature-gated factory that maps the generic network fields onto each
/// backend's config. A bridge kind whose build feature is absent is a loud
/// error (never a silent fall-through to IRC), and `local` is not creatable as a
/// bouncer network. Used by config-network startup, DB-network boot, runtime
/// create, and re-enable, so no site can construct a driver by kind differently.
#[allow(clippy::too_many_arguments)]
pub fn build_driver(
    kind: crate::config::NetworkKind,
    addr: String,
    tls: bool,
    nick: String,
    realname: String,
    autojoin: Vec<String>,
    buffer_cap: usize,
    sasl_account: Option<String>,
    sasl_password: Option<String>,
) -> Result<Box<dyn NetworkDriver>, String> {
    use crate::config::NetworkKind;
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
    match kind {
        // The Irc arm uses every parameter, so they are never "unused" even in a
        // build with no bridge features — the bridge arms below just don't run.
        NetworkKind::Irc => {
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
            Ok(Box::new(IrcDriver::new(NetworkConfig {
                addr,
                tls,
                nick,
                realname,
                autojoin,
                buffer_cap,
                sasl,
                keepalive_idle: KEEPALIVE_IDLE,
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
                    homeserver: addr,
                    user: nick,
                    password,
                    rooms: autojoin,
                    buffer_cap,
                })))
            }
            #[cfg(not(feature = "matrix"))]
            {
                drop(password);
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
/// per kind: the password (`sasl_password_sealed`) is always sealed, and for a
/// kind whose *account* field carries a secret (Slack's bot token) that is
/// sealed too — an IRC `sasl_account` is a public name and stays plaintext.
pub fn driver_from_row(
    row: &crate::db::BncNetworkRow,
    key: Option<&crate::secret::SecretKeyring>,
    owner: &str,
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
    build_driver(
        row.kind,
        row.addr.clone(),
        row.tls,
        row.nick.clone(),
        row.realname.clone().unwrap_or_else(|| row.nick.clone()),
        row.autojoin.clone(),
        DB_NETWORK_BUFFER_CAP,
        account,
        password,
    )
}

use tokio::sync::mpsc;

/// Jittered exponential reconnect backoff shared by every always-on driver, so
/// their reconnect timing stays identical in one place. Starts at 200ms,
/// doubles per drop, caps at 30s, and resets once a session lasted long enough
/// (≥10s) to have clearly connected — otherwise a flapping-but-reachable
/// upstream would ratchet toward the cap forever. Jitter is a coarse
/// deterministic function of the delay *and* a per-driver seed (no RNG), so it
/// spreads reconnects both across retry rounds and across concurrent drivers.
pub(crate) struct Backoff {
    current: std::time::Duration,
    /// Per-driver jitter offset, so drivers that drop together from one shared
    /// upstream outage do not recompute an *identical* delay and reconnect in
    /// lockstep. Without a per-driver term the jitter is a pure function of
    /// `current`, which every driver advances through the same sequence — so it
    /// spread reconnects across retry *rounds* but not across the drivers within
    /// a round, which is the one thing jitter exists to do.
    jitter_offset: u64,
}

impl Backoff {
    pub(crate) fn new(seed: u64) -> Self {
        Self {
            current: std::time::Duration::from_millis(200),
            // Fibonacci-hash the stable per-driver seed into the jitter window so
            // sequential driver ids spread across the [0,97) range rather than
            // clustering. RNG-free: the offset is fixed for a driver's lifetime.
            jitter_offset: seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) % 97,
        }
    }

    /// The delay the next [`Backoff::wait`] will sleep, computed exactly as
    /// `wait` computes it. Exposed so the runtime snapshot can say *when* the
    /// next attempt fires, not just that the driver is reconnecting.
    pub(crate) fn next_delay(&self, session_ran: std::time::Duration) -> std::time::Duration {
        let base = if session_ran >= std::time::Duration::from_secs(10) {
            std::time::Duration::from_millis(200)
        } else {
            self.current
        };
        let jitter =
            std::time::Duration::from_millis((base.as_millis() as u64 + self.jitter_offset) % 97);
        base + jitter
    }

    /// Sleep before the next reconnect attempt, given how long the session that
    /// just ended lasted, then grow the delay for the attempt after this one.
    pub(crate) async fn wait(&mut self, session_ran: std::time::Duration) {
        if session_ran >= std::time::Duration::from_secs(10) {
            self.current = std::time::Duration::from_millis(200);
        }
        // Combine the per-round delay term with the per-driver offset so both the
        // round and the driver vary; still bounded to a coarse <97ms spread.
        let jitter = std::time::Duration::from_millis(
            (self.current.as_millis() as u64 + self.jitter_offset) % 97,
        );
        tokio::time::sleep(self.current + jitter).await;
        self.current = (self.current * 2).min(std::time::Duration::from_secs(30));
    }
}

/// Outcome of one driver session attempt, for the always-on drivers'
/// reconnect loops: the owner dropped the handle (stop for good), or the
/// upstream connection dropped and the driver should reconnect with backoff.
/// Reconnecting from scratch is intentionally simple (it re-syncs/re-joins
/// rather than resuming); losing that optimization is far better than the
/// task dying on the first disconnect and silently dropping all later
/// upstream traffic.
pub(crate) enum SessionOutcome {
    Stopped,
    /// A transient session failure that is safe to retry. Carrying the closed,
    /// credential-safe reason in the outcome makes a reasonless reconnect
    /// unrepresentable: every driver must tell monitoring why the attempt
    /// ended before the shared runner can schedule another one.
    Dropped(NetworkFailure),
    /// The upstream rejected the credentials (a terminal auth/registration
    /// numeric), which — unlike a transient drop — will not succeed on a plain
    /// retry. [`run_with_backoff`] counts these and stops re-dialing after a few
    /// in a row, so a mistyped or revoked upstream password can't hammer the
    /// upstream forever every ~30s.
    AuthRejected,
    RegistrationRejected(e6irc_client::RegistrationRefusal),
}

/// Consecutive upstream credential or registration rejections before a driver
/// stops re-dialing and parks until the network is reconfigured.
pub(crate) const MAX_CONSECUTIVE_REGISTRATION_REJECTIONS: u32 = 5;

/// Depth of the bounded client→upstream command queue per network (shared by all
/// attached clients). Past this a send is refused (`SendOutcome::Full`) and the
/// client is told loudly, rather than blocking — a blocking send on this *shared*
/// queue would stall every other attached client (see [`NetworkHandle::send`]).
/// Each line is already bounded by `MAX_CLIENT_FRAME_LEN`, so this bounds memory.
const BNC_COMMAND_QUEUE: usize = 256;

/// Whether an HTTP status from a bridge's auth/login call means the *credentials*
/// were rejected (401/403) — a permanent failure retrying won't fix, so the
/// caller returns [`SessionOutcome::AuthRejected`] rather than `Dropped`. Gives
/// the chat bridges the same "stop hammering the upstream with a bad token"
/// backstop the IRC driver already has, instead of reconnecting forever.
///
/// Gated on `matrix` because that is the only bridge whose auth rejection is an
/// HTTP status; Slack signals it in a 200 body (`slack_failure`) and Discord via
/// a gateway close code, each handled inline. The `lint` CI job builds each
/// bridge feature on its own with `-Dwarnings`, so a helper compiled but unused
/// under a single feature is a hard error — hence the narrow gate.
#[cfg(feature = "matrix")]
pub(crate) fn is_http_auth_rejection(status: Option<reqwest::StatusCode>) -> bool {
    matches!(
        status,
        Some(reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN)
    )
}

/// Why a bridge failed to establish a session. Distinguishes a credential
/// rejection ([`SessionOutcome::AuthRejected`] — stop re-dialing) from any other
/// failure ([`SessionOutcome::Dropped`] — retry with backoff). The `From<String>`
/// / `From<&str>` conversions make every ordinary `?` in a bridge's `connect`
/// fall through as `Transient`, so only the one credential-rejection site has to
/// name `Auth` explicitly. Gated on `matrix` — the only bridge with a `connect`
/// that returns a `Result` (see `is_http_auth_rejection` for why the gate is
/// narrow).
#[cfg(feature = "matrix")]
pub(crate) enum ConnectFail {
    Auth(String),
    Transient(String),
}

#[cfg(feature = "matrix")]
impl ConnectFail {
    pub(crate) fn into_outcome(self, who: &str) -> SessionOutcome {
        match self {
            Self::Auth(e) => {
                eprintln!("{who}: authentication rejected, will stop retrying: {e}");
                SessionOutcome::AuthRejected
            }
            Self::Transient(e) => {
                eprintln!("{who}: connect failed: {e}");
                SessionOutcome::Dropped(NetworkFailure::UpstreamRequestFailed)
            }
        }
    }
}

#[cfg(feature = "matrix")]
impl From<String> for ConnectFail {
    fn from(e: String) -> Self {
        Self::Transient(e)
    }
}

#[cfg(feature = "matrix")]
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

async fn wait_for_reconnect(
    ends: &mut DriverEnds,
    backoff: &mut Backoff,
    attempt_elapsed: std::time::Duration,
    failure: NetworkFailure,
) -> bool {
    ends.emit(ConnectionEvent::Reconnecting(failure));
    ends.schedule_retry(backoff.next_delay(attempt_elapsed));
    tokio::select! {
        biased;
        _ = ends.shutdown_signalled() => false,
        _ = backoff.wait(attempt_elapsed) => true,
    }
}

pub(crate) async fn run_with_backoff<C>(
    config: C,
    ends: &mut DriverEnds,
    session: DriverSession<C>,
) {
    let mut backoff = Backoff::new(ends.reconnect_seed);
    let mut consecutive_rejections: u32 = 0;
    loop {
        // A stop signalled while a session runs is observed inside it (via
        // `next_command`); one signalled while we wait to reconnect is caught
        // here, so a removed network in backoff doesn't linger for the retry.
        if ends.is_shutdown() {
            return;
        }
        ends.begin_attempt();
        let started = tokio::time::Instant::now();
        match session(&config, ends).await {
            SessionOutcome::Stopped => return,
            outcome @ (SessionOutcome::AuthRejected | SessionOutcome::RegistrationRejected(_)) => {
                let (failure, event) = match outcome {
                    SessionOutcome::AuthRejected => (
                        NetworkFailure::AuthenticationRejected,
                        ConnectionEvent::AuthenticationFailed,
                    ),
                    SessionOutcome::RegistrationRejected(refusal) => (
                        registration_failure(refusal),
                        ConnectionEvent::RegistrationFailed(refusal),
                    ),
                    _ => unreachable!("matched only terminal rejections"),
                };
                consecutive_rejections += 1;
                if consecutive_rejections >= MAX_CONSECUTIVE_REGISTRATION_REJECTIONS {
                    ends.emit(event);
                    // Stop hammering an upstream that keeps rejecting unchanged
                    // credentials or registration settings. Park until the
                    // network is reconfigured (which drops the handle).
                    ends.emit_line(
                        ":*bnc* NOTICE * :upstream rejected registration repeatedly; \
                         not reconnecting until this network is reconfigured"
                            .to_string(),
                    );
                    ends.shutdown_signalled().await;
                    return;
                }
                if !wait_for_reconnect(ends, &mut backoff, started.elapsed(), failure).await {
                    return;
                }
            }
            SessionOutcome::Dropped(failure) => {
                // A transient (non-auth) drop: a connection-level failure that
                // may well recover, so keep retrying and reset the auth counter.
                consecutive_rejections = 0;
                if !wait_for_reconnect(ends, &mut backoff, started.elapsed(), failure).await {
                    return;
                }
            }
        }
    }
}

/// Classification of a downstream client command by a bridge, so a message
/// that can't be delivered upstream is surfaced rather than silently dropped.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RouteResult {
    /// A PRIVMSG mapped to `(upstream_id, text)`; deliver it.
    Deliver(String, String),
    /// A PRIVMSG to `target` that maps to no bridged channel — surface loss.
    Unmapped(String),
    /// Not a deliverable message command (control/other) — ignore quietly.
    Ignore,
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
/// or non-PRIVMSG line yields a single `Ignore`.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
pub(crate) fn route_privmsg(
    line: &str,
    targets: &std::collections::HashMap<String, String>,
) -> Vec<RouteResult> {
    let Ok(msg) = e6irc_proto::message::Message::parse(line) else {
        return vec![RouteResult::Ignore];
    };
    if !msg.command.eq_ignore_ascii_case("PRIVMSG") {
        return vec![RouteResult::Ignore];
    }
    let (Some(target), Some(text)) = (msg.params.first(), msg.params.get(1)) else {
        return vec![RouteResult::Ignore];
    };
    let casemap = e6irc_proto::casemap::CaseMapping::Rfc1459;
    let mut out: Vec<RouteResult> = target
        .split(',')
        .filter(|t| !t.is_empty())
        .map(|t| {
            // Strip one STATUSMSG prefix; fold for the case-insensitive lookup.
            let bare = t
                .strip_prefix('@')
                .or_else(|| t.strip_prefix('+'))
                .unwrap_or(t);
            match targets.get(&casemap.casefold(bare)) {
                Some(id) => RouteResult::Deliver(id.clone(), text.to_string()),
                None => RouteResult::Unmapped(bare.to_string()),
            }
        })
        .collect();
    if out.is_empty() {
        out.push(RouteResult::Ignore);
    }
    out
}

/// Deliver one already-routed batch of PRIVMSG targets and surface the outcome
/// of **each** one to the attached client. `route_privmsg` yields one
/// `RouteResult` per comma-separated target; this consumes the whole list, so a
/// mapped target that fails to send and an unmapped target both produce their
/// own `*bnc*` NOTICE — a multi-target line can't have all-but-one target's
/// non-delivery silently dropped. That fold-N-outcomes-into-one silent drop
/// (DESIGN §2) is exactly what the Matrix bridge did before this was shared:
/// every bridge now routes its per-target outcome through one definition that
/// cannot collapse the list. `deliver` performs the platform's upstream send for
/// a mapped `(id, text)` and returns `Ok(())` or an error string; it does its
/// session-touching work synchronously and moves owned data into the returned
/// future, so no borrow of the caller's session outlives a single send.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
pub(crate) async fn relay_routed<F, Fut>(
    ends: &DriverEnds,
    routed: Vec<RouteResult>,
    platform: &str,
    kind: &str,
    mut deliver: F,
) where
    F: FnMut(String, String) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    for routed in routed {
        match routed {
            RouteResult::Deliver(id, text) => {
                if let Err(e) = deliver(id.clone(), text).await {
                    eprintln!("{platform}: send to {id} failed: {e}");
                    // A delivery failure is not a silent drop (DESIGN §2).
                    ends.record_error(NetworkFailure::UpstreamWriteFailed);
                    ends.emit_line(undelivered_notice(platform, kind, &id));
                }
            }
            RouteResult::Unmapped(target) => {
                ends.emit_line(unmapped_target_notice(platform, kind, &target));
            }
            RouteResult::Ignore => {}
        }
    }
}

/// A reqwest DNS resolver that vets every resolved address and drops the ones a
/// bridge must never dial — the same SSRF control the IRC driver applies at
/// connect time (`is_blocked_upstream_ip`: cloud-metadata link-local, multicast,
/// broadcast, documentation, unspecified). Resolution happens per request, so a
/// host that resolves to an internal address — now or after a DNS rebind — is
/// refused at dial time, not just at config time.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
struct VettingResolver;

#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
impl reqwest::dns::Resolve for VettingResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let host = name.as_str().to_string();
            let resolved = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let vetted: Vec<std::net::SocketAddr> = resolved
                .filter(|sa| !crate::http::networks::is_blocked_upstream_ip(sa.ip()))
                .collect();
            if vetted.is_empty() {
                // Either DNS returned nothing or every address was blocked; both
                // are a refusal, not a silent fall-through to the OS resolver.
                return Err(format!(
                    "{host}: no permitted address (all resolved addresses are SSRF-blocked)"
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
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
pub(crate) fn bridge_http_client(timeout: std::time::Duration) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(std::sync::Arc::new(VettingResolver))
        .build()
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

/// Build the bridge HTTP client, mapping a build failure to the session
/// outcome. Shared so both WebSocket bridges log and fail the same way when
/// the vetted-resolver client can't be built.
#[cfg(any(feature = "discord", feature = "slack"))]
pub(crate) fn bridge_http_or_outcome(
    tag: &str,
    timeout: std::time::Duration,
) -> Result<reqwest::Client, SessionOutcome> {
    bridge_http_client(timeout).map_err(|e| {
        eprintln!("{tag}: http client build failed: {e}");
        SessionOutcome::Dropped(NetworkFailure::UpstreamRequestFailed)
    })
}

/// The gateway WebSocket stream type both WebSocket bridges run over.
#[cfg(any(feature = "discord", feature = "slack"))]
type BridgeWs =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Open a bridge gateway WebSocket with a bounded handshake, mapping failure
/// to the session outcome. Shared so both WebSocket bridges apply the same
/// handshake bound and error vocabulary.
#[cfg(any(feature = "discord", feature = "slack"))]
pub(crate) async fn bridge_ws_open(
    url: &str,
    tag: &str,
    transport: &str,
) -> Result<BridgeWs, SessionOutcome> {
    match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        bridge_ws_connect(url, bridge_ws_config()),
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
#[cfg(any(feature = "discord", feature = "slack"))]
pub(crate) async fn next_bridge_frame(
    read: &mut futures_util::stream::SplitStream<BridgeWs>,
    write: &mut futures_util::stream::SplitSink<BridgeWs, tokio_tungstenite::tungstenite::Message>,
    read_timeout: std::time::Duration,
    tag: &str,
    transport: &str,
) -> BridgeRead {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message as Ws;
    let frame = match tokio::time::timeout(read_timeout, read.next()).await {
        Ok(frame) => frame,
        Err(_) => {
            eprintln!("{tag}: {transport} idle past timeout; reconnecting");
            return BridgeRead::Idle;
        }
    };
    match frame {
        Some(Ok(Ws::Text(t))) => BridgeRead::Text(t.as_str().to_string()),
        Some(Ok(Ws::Ping(p))) => {
            if write.send(Ws::Pong(p)).await.is_err() {
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

/// Read the next text frame from a bridge gateway socket, mapping the
/// terminal outcomes (idle, close, read/write failure) to the session
/// outcome. `on_close` decides what a protocol close code means for the
/// provider (Discord's fatal auth/intents codes; Slack treats every close as
/// a plain drop).
#[cfg(any(feature = "discord", feature = "slack"))]
pub(crate) async fn next_bridge_text(
    read: &mut futures_util::stream::SplitStream<BridgeWs>,
    write: &mut futures_util::stream::SplitSink<BridgeWs, tokio_tungstenite::tungstenite::Message>,
    read_timeout: std::time::Duration,
    tag: &str,
    transport: &str,
    on_close: impl FnOnce(Option<u16>) -> SessionOutcome,
) -> Result<Option<String>, SessionOutcome> {
    match next_bridge_frame(read, write, read_timeout, tag, transport).await {
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
            let (handle, ends) = NetworkHandle::channels(self.config.buffer_cap);
            tokio::spawn(run(self.config, ends));
            handle
        }
    };
}
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
pub(crate) use bridge_start;

/// The `run` loop for a bridge driver: reconnect from scratch with backoff on
/// any session drop rather than dying and silently dropping all later
/// messages; only a dropped handle stops the driver.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
macro_rules! bridge_run {
    ($config:ty) => {
        async fn run(config: $config, mut ends: DriverEnds) {
            super::run_with_backoff(config, &mut ends, |config, ends| {
                Box::pin(session_once(config, ends))
            })
            .await;
        }
    };
}
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
pub(crate) use bridge_run;

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
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    String,
> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let request = url.into_client_request().map_err(|e| e.to_string())?;
    let uri = request.uri();
    let host = uri.host().ok_or("gateway url has no host")?.to_string();
    // Gateways are always wss:// (TLS); default to 443 when the URL omits a port.
    let port = uri.port_u16().unwrap_or(443);
    let vetted = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|e| e.to_string())?
        .find(|sa| !crate::http::networks::is_blocked_upstream_ip(sa.ip()))
        .ok_or_else(|| format!("{host}: no permitted address (SSRF-blocked)"))?;
    let tcp = tokio::net::TcpStream::connect(vetted)
        .await
        .map_err(|e| e.to_string())?;
    let (ws, _response) =
        tokio_tungstenite::client_async_tls_with_config(request, tcp, Some(config), None)
            .await
            .map_err(|e| e.to_string())?;
    Ok(ws)
}

/// Largest HTTP response body a bridge will read from an upstream before
/// parsing it as JSON.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
pub(crate) const MAX_BRIDGE_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Send an outbound bridge HTTP request and reject any non-2xx response. Every
/// reverse-direction (IRC→upstream) send whose failure is signalled by HTTP
/// status funnels through here so the raw `reqwest::Response` never reaches
/// delivery-outcome logic: a bare `.send()` returns `Ok(Response)` for a 403 /
/// 429 / 5xx just as for a 200, and treating that as delivered is a silent drop
/// (DESIGN §2). Routing through this makes "send, ignore the status, report
/// success" unwritable. (Slack signals failure in the 200 body via `ok:false`,
/// an application-level check its `check_ok` still performs on top of this.)
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
pub(crate) async fn bridge_send(req: reqwest::RequestBuilder) -> Result<reqwest::Response, String> {
    req.send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())
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
/// compromised upstream (the Matrix example config even permits plaintext
/// `http://…`, MITM-able) can return a multi-GB body and OOM the shared daemon —
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
    /// echo-message: the attaching client wants its own messages echoed back
    /// (synthesized by the driver — the upstream is never asked for
    /// echo-message, so there is exactly one echo, never two).
    pub echo_message: bool,
    /// batch: the client can receive BATCH-wrapped responses (CHATHISTORY).
    pub batch: bool,
    /// draft/chathistory: the client wants to page backlog via CHATHISTORY.
    pub chathistory: bool,
    /// draft/read-marker: the client wants to set/query per-target read
    /// positions via MARKREAD.
    pub read_marker: bool,
}

/// Strip from a serialized line any message tags the recipient did not
/// negotiate. `time=` needs server-time, `account=` needs account-tag, and
/// everything else (msgid, client-only tags) needs message-tags. A line with
/// no tag section (no leading `@`) is returned unchanged.
pub(crate) fn filter_tags(line: &str, caps: AttachCaps) -> String {
    let Some(rest) = line.strip_prefix('@') else {
        return line.to_string();
    };
    // A leading `@` with no following space is a tag section with no message
    // body — a malformed line no well-formed upstream produces, but a hostile
    // one can, and it must not reach a client as an un-negotiated `@`-prefixed
    // line. There is nothing deliverable in it, so it is dropped entirely.
    let Some((tags, body)) = rest.split_once(' ') else {
        return String::new();
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
        body.to_string()
    } else {
        format!("@{} {}", kept.join(";"), body)
    }
}

/// An event a driver emits upward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverEvent {
    /// The upstream connection registered successfully.
    Connected,
    /// One line received from upstream (CRLF stripped).
    Line(String),
    /// A synthesized copy of a line an attached client sent. IRC servers do
    /// not echo a sender's own messages unless echo-message was negotiated —
    /// and the driver never negotiates it — so without this the detached
    /// buffer and the account's *other* sessions would only ever record one
    /// side of the conversation. `origin` identifies the sending attachment:
    /// the originator itself is excluded unless it negotiated echo-message on
    /// attach, mirroring how a real server treats that capability.
    Echo { line: String, origin: u64 },
    /// The upstream connection dropped; the driver will retry.
    Disconnected,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionEvent {
    Connected,
    /// A classified transient failure ended the current attempt; another
    /// attempt follows. Carrying the reason makes an unclassified disconnect
    /// impossible for every driver using the public SPI.
    Reconnecting(NetworkFailure),
    /// Repeated credential rejection parked the driver until it is reconfigured.
    AuthenticationFailed,
    /// Repeated IRC registration rejection parked the driver until reconfigured.
    RegistrationFailed(e6irc_client::RegistrationRefusal),
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
    /// Detached buffer of recent upstream lines (newest last).
    buffer: std::sync::Arc<std::sync::Mutex<Buffer>>,
    /// Runtime state and per-network counters, shared with the driver endpoint.
    runtime: std::sync::Arc<NetworkRuntime>,
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
    NicknameInUse,
    ServerPasswordRejected,
    NetworkBanned,
    AuthenticationRejected,
    AutojoinFailed,
    ConnectionLost,
    KeepaliveTimedOut,
    UpstreamWriteFailed,
    UpstreamRequestFailed,
    UpstreamProtocolFailed,
    ChannelMappingFailed,
    BacklogStorageFailed,
    BacklogStorageLagged,
    CommandQueueFull,
    DriverStopped,
}

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
            Self::NicknameInUse => "nickname_in_use",
            Self::ServerPasswordRejected => "server_password_rejected",
            Self::NetworkBanned => "network_banned",
            Self::AuthenticationRejected => "authentication_rejected",
            Self::AutojoinFailed => "autojoin_failed",
            Self::ConnectionLost => "connection_lost",
            Self::KeepaliveTimedOut => "keepalive_timed_out",
            Self::UpstreamWriteFailed => "upstream_write_failed",
            Self::UpstreamRequestFailed => "upstream_request_failed",
            Self::UpstreamProtocolFailed => "upstream_protocol_failed",
            Self::ChannelMappingFailed => "channel_mapping_failed",
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
            Self::NicknameInUse => "The configured nickname is already in use.",
            Self::ServerPasswordRejected => "The upstream rejected the configured server password.",
            Self::NetworkBanned => "The upstream network banned this connection.",
            Self::AuthenticationRejected => "The upstream rejected the configured credentials.",
            Self::AutojoinFailed => "A configured JOIN could not be sent during startup.",
            Self::ConnectionLost => "The established upstream connection was lost.",
            Self::KeepaliveTimedOut => "The upstream stopped responding to keepalive checks.",
            Self::UpstreamWriteFailed => "A message could not be sent to the upstream.",
            Self::UpstreamRequestFailed => "An upstream API request failed.",
            Self::UpstreamProtocolFailed => {
                "The upstream returned an invalid or unsupported response."
            }
            Self::ChannelMappingFailed => {
                "A configured bridged channel could not be mapped safely."
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
    buffer.lock().expect("buffer poisoned").push(line.clone());
    drop(events.send(DriverEvent::Line(line)));
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
    lifecycle: NetworkLifecycle,
    /// When the next reconnect attempt fires (while reconnecting; `None`
    /// once a session connects or the driver parks).
    next_retry_at: Option<e6irc_proto::time::Millis>,
    /// The last few classified failures, newest last — a flap pattern is a
    /// sequence, and "last error" alone hides it. Bounded; runtime state is
    /// restart-ephemeral by design.
    recent_failures: std::collections::VecDeque<FailureRecord>,
    state_changed_at: e6irc_proto::time::Millis,
    connected_at: Option<e6irc_proto::time::Millis>,
    attempt_started: std::time::Instant,
    connect_latency_ms: Option<u64>,
    connection_attempts: u64,
    errors: u64,
    last_error_at: Option<e6irc_proto::time::Millis>,
    last_error: Option<NetworkFailure>,
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
                lifecycle: NetworkLifecycle::Connecting,
                next_retry_at: None,
                recent_failures: std::collections::VecDeque::new(),
                state_changed_at: epoch_millis(),
                connected_at: None,
                attempt_started: std::time::Instant::now(),
                connect_latency_ms: None,
                connection_attempts: 0,
                errors: 0,
                last_error_at: None,
                last_error: None,
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

    fn schedule_retry(&self, delay: std::time::Duration) {
        let mut state = self.state.lock().expect("network runtime poisoned");
        let at = epoch_millis()
            .as_millis()
            .saturating_add(delay.as_millis() as u64);
        state.next_retry_at = Some(e6irc_proto::time::Millis::from_millis(at));
    }

    fn begin_attempt(&self) {
        let mut state = self.state.lock().expect("network runtime poisoned");
        state.next_retry_at = None;
        state.lifecycle = if state.connection_attempts == 0 {
            NetworkLifecycle::Connecting
        } else {
            NetworkLifecycle::Reconnecting
        };
        state.connection_attempts = state.connection_attempts.saturating_add(1);
        state.state_changed_at = epoch_millis();
        state.attempt_started = std::time::Instant::now();
    }

    fn connected(&self) {
        let mut state = self.state.lock().expect("network runtime poisoned");
        if state.connection_attempts == 0 {
            state.connection_attempts = 1;
        }
        let now = epoch_millis();
        state.lifecycle = NetworkLifecycle::Connected;
        state.state_changed_at = now;
        state.connected_at = Some(now);
        state.next_retry_at = None;
        state.connect_latency_ms = Some(
            state
                .attempt_started
                .elapsed()
                .as_millis()
                .min(u64::MAX as u128) as u64,
        );
    }

    fn failed(&self, terminal: Option<NetworkLifecycle>, failure: NetworkFailure) {
        let now = epoch_millis();
        let mut state = self.state.lock().expect("network runtime poisoned");
        state.lifecycle = terminal.unwrap_or(NetworkLifecycle::Reconnecting);
        state.state_changed_at = now;
        state.connected_at = None;
        Self::set_error(&mut state, now, failure);
    }

    fn operational_error(&self, failure: NetworkFailure) {
        let now = epoch_millis();
        let mut state = self.state.lock().expect("network runtime poisoned");
        Self::set_error(&mut state, now, failure);
    }

    /// How many classified failures the per-network history retains.
    const FAILURE_HISTORY: usize = 8;

    fn set_error(
        state: &mut NetworkRuntimeState,
        now: e6irc_proto::time::Millis,
        failure: NetworkFailure,
    ) {
        state.errors = state.errors.saturating_add(1);
        state.last_error_at = Some(now);
        state.last_error = Some(failure);
        state
            .recent_failures
            .push_back(FailureRecord { at: now, failure });
        while state.recent_failures.len() > Self::FAILURE_HISTORY {
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

/// Bounded ring of recent upstream lines, for playback on attach.
#[derive(Default)]
pub struct Buffer {
    lines: std::collections::VecDeque<String>,
    cap: usize,
}

impl Buffer {
    fn new(cap: usize) -> Self {
        Self {
            lines: std::collections::VecDeque::new(),
            cap,
        }
    }
    fn push(&mut self, line: String) {
        // `>=` (not `==`) so a zero/under-filled cap can never let the ring
        // grow without bound.
        while self.lines.len() >= self.cap.max(1) {
            self.lines.pop_front();
        }
        self.lines.push_back(line);
    }
    pub fn snapshot(&self) -> Vec<String> {
        self.lines.iter().cloned().collect()
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
    let shown = truncate_on_char_boundary(target, 64);
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
    let shown = truncate_on_char_boundary(target, 64);
    format!(":*bnc* NOTICE * :not delivered: {platform} send to {kind} {shown} failed")
}

/// `s` cut to at most `max` bytes, never inside a character.
#[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
fn truncate_on_char_boundary(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut cut = max;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    &s[..cut]
}

/// Render a bridged message as one or more IRC `PRIVMSG` lines: the sender is
/// reduced to a safe nick token and the body is split to fit the line limit.
///
/// The body is free-form remote text of arbitrary length — Slack alone allows
/// 40,000 characters — while an IRC line is [`MAX_LINE_LEN`] bytes including
/// its CRLF. Emitting one over-long line does not merely bend the protocol: the
/// receiving client's framing discards an over-long line *whole*, so the
/// message vanishes with nothing said. It is split instead, because a bridged
/// message must not disappear for being long.
///
/// Embedded newlines split too. They are line breaks in the source medium, and
/// [`crate::sanitize::upstream_line`] flattens them to spaces further down, which would
/// turn a multi-line message into one run-on line.
///
/// An empty body still yields one line: a message was sent, and saying nothing
/// about it would be the silent drop this exists to prevent.
#[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
pub(crate) fn render_bridged_privmsg(
    host: &str,
    sender: &str,
    channel: &str,
    body: &str,
) -> Vec<String> {
    use e6irc_proto::message::MAX_LINE_LEN;
    let nick = crate::sanitize::nick_token(sender);
    let prefix = format!(":{nick}!{nick}@{host} PRIVMSG {channel} :");
    // `nick_token` bounds the nick and `host` is one of three literals, so only
    // a pathologically long configured channel name can exhaust the line. The
    // floor keeps the split making progress if one ever does; the resulting
    // lines would still be over-long, which is a configuration error and not
    // something this function can paper over.
    let budget = (MAX_LINE_LEN - 2).saturating_sub(prefix.len()).max(1);

    let mut out = Vec::new();
    for piece in body.split('\n') {
        let piece = piece.strip_suffix('\r').unwrap_or(piece);
        let mut rest = piece;
        loop {
            if rest.len() <= budget {
                out.push(format!("{prefix}{rest}"));
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
            out.push(format!("{prefix}{}", &rest[..cut]));
            rest = &rest[cut..];
        }
    }
    out
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
    /// attachment's id so its synthesized echo can be routed correctly.
    pub fn send_from(&self, origin: u64, line: &str) -> SendOutcome {
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

    /// Prepend older (oldest-first) lines to the front of the buffer,
    /// used once at start to restore persisted backlog. Never evicts
    /// lines already present (they are newer); only the remaining
    /// capacity is filled, keeping the most recent of `older`.
    pub fn preload_front(&self, older: Vec<String>) {
        let mut buf = self.buffer.lock().expect("buffer poisoned");
        let room = buf.cap.saturating_sub(buf.lines.len());
        let skip = older.len().saturating_sub(room);
        for line in older[skip..].iter().rev() {
            // Neutralized here as well as in `emit_line`. These lines come back
            // from storage, which outlives the code that wrote them: a row put
            // there by an older build, a restore, or anything else with database
            // access would otherwise be replayed to an attaching client verbatim.
            // Both ways into the buffer sanitize, so no reader has to ask which
            // one a line arrived through.
            buf.lines
                .push_front(crate::sanitize::upstream_line(line.clone()));
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

    /// The current upstream connection state. Unlike the `Connected` event
    /// this is not lost to subscribe timing — safe to poll after `start`.
    pub fn is_connected(&self) -> bool {
        self.runtime
            .state
            .lock()
            .expect("network runtime poisoned")
            .lifecycle
            == NetworkLifecycle::Connected
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
            lifecycle: state.lifecycle,
            state_changed_at: state.state_changed_at,
            next_retry_at: state.next_retry_at,
            recent_failures: state.recent_failures.iter().copied().collect(),
            connected_at: state.connected_at,
            last_input_at: atomic_millis(&self.runtime.last_input_at),
            last_output_at: atomic_millis(&self.runtime.last_output_at),
            last_error_at: state.last_error_at,
            last_error: state.last_error,
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
            lifecycle: state.lifecycle,
            next_retry_at: state.next_retry_at,
            recent_failures: state.recent_failures.clone(),
            state_changed_at: state.state_changed_at,
            connected_at: state.connected_at,
            attempt_started: state.attempt_started,
            connect_latency_ms: state.connect_latency_ms,
            connection_attempts: state.connection_attempts,
            errors: state.errors,
            last_error_at: state.last_error_at,
            last_error: state.last_error,
        }
    }

    /// Build a handle and the driver-side endpoints. A driver spawns a
    /// task that reads commands, records lines to the buffer, and
    /// broadcasts events through the returned [`DriverEnds`].
    pub fn channels(buffer_cap: usize) -> (NetworkHandle, DriverEnds) {
        let (events, _) = tokio::sync::broadcast::channel(1024);
        // Bounded, not unbounded: the driver drains one command per loop
        // iteration, and during a reconnect wait (up to ~30s of backoff) it
        // doesn't drain at all — an unbounded queue would let an attached client's
        // sends grow without limit. A full queue backpressures the sender (the
        // attach/WS read side stops reading the client socket) instead, bounding
        // memory. Shared across all clients attached to this one network.
        let (command_tx, command_rx) = mpsc::channel(BNC_COMMAND_QUEUE);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let buffer = std::sync::Arc::new(std::sync::Mutex::new(Buffer::new(buffer_cap)));
        let runtime = std::sync::Arc::new(NetworkRuntime::new());
        let telemetry = std::sync::Arc::new(std::sync::Mutex::new(None));
        let history = std::sync::Arc::new(std::sync::Mutex::new(None));
        let (history_ready, _) = tokio::sync::watch::channel(true);
        let handle = NetworkHandle {
            events: events.clone(),
            commands: command_tx,
            attach_seq: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)),
            shutdown: shutdown_tx,
            history: history.clone(),
            history_ready,
            buffer: buffer.clone(),
            runtime: runtime.clone(),
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
            buffer,
            runtime,
            telemetry,
            reconnect_seed,
        };
        (handle, ends)
    }

    /// Stop the network's driver authoritatively. Called by the registry when a
    /// network is removed or replaced; the driver observes it via `next_command`
    /// / `run_with_backoff` and tears down even while clients are attached.
    pub fn shutdown(&self) {
        self.shutdown.send_replace(true);
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
    buffer: std::sync::Arc<std::sync::Mutex<Buffer>>,
    runtime: std::sync::Arc<NetworkRuntime>,
    telemetry:
        std::sync::Arc<std::sync::Mutex<Option<std::sync::Arc<crate::observability::Telemetry>>>>,
    /// Stable per-driver value seeding this driver's reconnect jitter, so
    /// concurrent drivers de-correlate (see [`Backoff`]). Assigned once at
    /// construction from a process-wide counter.
    reconnect_seed: u64,
}

impl DriverEnds {
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
    pub fn emit_line(&self, line: String) {
        self.emit_buffered_line(line, true);
    }

    fn emit_notice(&self, line: String) {
        self.emit_buffered_line(line, false);
    }

    fn emit_buffered_line(&self, line: String, count_as_input: bool) {
        let line = crate::sanitize::upstream_line(line);
        if count_as_input {
            self.runtime.record_input(line.len());
            if let Some(telemetry) = self
                .telemetry
                .lock()
                .expect("telemetry hook poisoned")
                .as_ref()
            {
                telemetry.record_bnc_input(line.len());
            }
        }
        self.buffer
            .lock()
            .expect("buffer poisoned")
            .push(line.clone());
        // A detached network legitimately has no live subscribers; the line is
        // still retained in the buffer above.
        drop(self.events.send(DriverEvent::Line(line)));
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
        self.buffer
            .lock()
            .expect("buffer poisoned")
            .push(line.clone());
        drop(self.events.send(DriverEvent::Echo { line, origin }));
    }

    /// Report a connection-state change, updating the sticky connection state
    /// so late subscribers can still read it. Lines have their own entry point
    /// ([`DriverEnds::emit_line`]) because they need sanitizing and buffering;
    /// see [`ConnectionEvent`].
    pub fn emit(&self, event: ConnectionEvent) {
        let (broadcast, notice) = match event {
            ConnectionEvent::Connected => {
                self.runtime.connected();
                eprintln!("bnc: {} connected", self.runtime.label());
                (
                    DriverEvent::Connected,
                    format!(
                        ":*bnc* NOTICE * :component connected: {}",
                        self.runtime.label()
                    ),
                )
            }
            failure_event => {
                let (terminal, failure) = match failure_event {
                    ConnectionEvent::Reconnecting(failure) => (None, failure),
                    ConnectionEvent::AuthenticationFailed => (
                        Some(NetworkLifecycle::AuthenticationFailed),
                        NetworkFailure::AuthenticationRejected,
                    ),
                    ConnectionEvent::RegistrationFailed(refusal) => (
                        Some(NetworkLifecycle::RegistrationFailed),
                        registration_failure(refusal),
                    ),
                    ConnectionEvent::Connected => {
                        unreachable!("connected handled before failure transition")
                    }
                };
                self.runtime.failed(terminal, failure);
                if let Some(telemetry) = self
                    .telemetry
                    .lock()
                    .expect("telemetry hook poisoned")
                    .as_ref()
                {
                    telemetry.record_error(crate::observability::ErrorKind::Bouncer);
                }
                match terminal {
                    Some(lifecycle) => eprintln!(
                        "bnc: {} parked ({}): {}",
                        self.runtime.label(),
                        lifecycle.as_str(),
                        failure.summary(),
                    ),
                    None => eprintln!(
                        "bnc: {} disconnected ({}); reconnecting",
                        self.runtime.label(),
                        failure.code(),
                    ),
                }
                let state = terminal.map_or("reconnecting", NetworkLifecycle::as_str);
                (
                    DriverEvent::Disconnected,
                    format!(
                        ":*bnc* NOTICE * :component {state}: {} ({})",
                        failure.summary(),
                        failure.code(),
                    ),
                )
            }
        };
        // Connection state is sticky in `connected`; zero live subscribers is
        // therefore not a delivery failure.
        drop(self.events.send(broadcast));
        self.emit_notice(notice);
    }

    fn begin_attempt(&self) {
        self.runtime.begin_attempt();
    }

    /// Record when the next reconnect attempt fires (visible in the runtime
    /// snapshot as `next_retry_at`), then cleared when a session connects.
    fn schedule_retry(&self, delay: std::time::Duration) {
        self.runtime.schedule_retry(delay);
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

const fn registration_failure(refusal: e6irc_client::RegistrationRefusal) -> NetworkFailure {
    match refusal {
        e6irc_client::RegistrationRefusal::InvalidNickname => NetworkFailure::InvalidNickname,
        e6irc_client::RegistrationRefusal::NicknameInUse => NetworkFailure::NicknameInUse,
        e6irc_client::RegistrationRefusal::ServerPasswordRejected => {
            NetworkFailure::ServerPasswordRejected
        }
        e6irc_client::RegistrationRefusal::NetworkBanned => NetworkFailure::NetworkBanned,
        e6irc_client::RegistrationRefusal::NotRegistered => NetworkFailure::RegistrationRejected,
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

/// Attach a downstream client stream to a running network: replay the
/// detached buffer, then bidirectionally relay driver events to the
/// client and client lines to the upstream. Returns when either side
/// closes. This is the session multiplexer's core operation, serving
/// every driver kind (`irc`, `local`, and the bridges) uniformly.
///
/// `account` is the authenticated account, used to key the BNC-local
/// per-target read markers (shared networks keep per-account positions).
pub async fn attach<S>(
    stream: S,
    handle: &NetworkHandle,
    caps: AttachCaps,
    account: &str,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use e6irc_proto::framing::{LineBuffer, LineEvent};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut read, mut write) = tokio::io::split(stream);

    // Subscribe BEFORE snapshotting the buffer, so a line the driver emits
    // during playback is caught by the subscription instead of falling into
    // the gap between the two (a duplicated backlog line is harmless; a lost
    // one is not). This mirrors the persistence task's ordering.
    let mut events = handle.events.subscribe();
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
        return Ok(());
    }
    if !handle.wait_for_history().await {
        write
            .write_all(b":*bnc* NOTICE * :network removed; detaching\r\n")
            .await?;
        write.flush().await?;
        return Ok(());
    }
    let _attachment = handle.track_attachment();
    let attach_id = handle.next_attachment_id();

    // Send the current upstream connection status up front, so a client that
    // attaches to an already-connected (or still-reconnecting) network learns the
    // state now rather than only at the next connect/disconnect transition — the
    // same up-front status `/ws/ui` sends over WebSocket. The wording matches the
    // live `DriverEvent::Connected`/`Disconnected` lines below.
    let status: &[u8] = if handle.is_connected() {
        b":*bnc* NOTICE * :upstream connected\r\n"
    } else {
        b":*bnc* NOTICE * :upstream disconnected\r\n"
    };
    write.write_all(status).await?;

    // Playback: everything buffered while detached, in order, with tags the
    // client didn't negotiate stripped.
    for line in handle.buffer_snapshot() {
        write.write_all(filter_tags(&line, caps).as_bytes()).await?;
        write.write_all(b"\r\n").await?;
    }
    write.flush().await?;

    let mut framing = LineBuffer::new(e6irc_proto::message::MAX_CLIENT_FRAME_LEN);
    let mut read_buf = vec![0u8; 8192];
    let mut parsed = Vec::new();
    loop {
        tokio::select! {
            // Network removed/replaced: tell the client and detach.
            res = shutdown.changed() => {
                if res.is_err() || *shutdown.borrow() {
                    write
                        .write_all(b":*bnc* NOTICE * :network removed; detaching\r\n")
                        .await?;
                    write.flush().await?;
                    return Ok(());
                }
            }
            // Upstream -> client.
            ev = events.recv() => match ev {
                Ok(DriverEvent::Line(line)) => {
                    write.write_all(filter_tags(&line, caps).as_bytes()).await?;
                    write.write_all(b"\r\n").await?;
                    write.flush().await?;
                }
                Ok(DriverEvent::Echo { line, origin }) => {
                    // The originator's own echo reaches it only when it
                    // negotiated echo-message — the same contract a real
                    // server has. Every other attached client always gets it.
                    if origin != attach_id || caps.echo_message {
                        write.write_all(filter_tags(&line, caps).as_bytes()).await?;
                        write.write_all(b"\r\n").await?;
                        write.flush().await?;
                    }
                }
                Ok(DriverEvent::Connected) => {
                    write.write_all(b":*bnc* NOTICE * :upstream connected\r\n").await?;
                    write.flush().await?;
                }
                Ok(DriverEvent::Disconnected) => {
                    write.write_all(b":*bnc* NOTICE * :upstream disconnected\r\n").await?;
                    write.flush().await?;
                }
                // Lagged (slow client): the gap is unrecoverable, but surface
                // it rather than dropping upstream lines silently.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    write
                        .write_all(
                            format!(":*bnc* NOTICE * :dropped {n} line(s); client too slow\r\n")
                                .as_bytes(),
                        )
                        .await?;
                    write.flush().await?;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            },
            // Client -> upstream.
            n = read.read(&mut read_buf) => match n {
                Ok(0) => break, // client detached
                Ok(n) => {
                    framing.feed(&read_buf[..n], &mut parsed);
                    for event in parsed.drain(..) {
                        match event {
                            LineEvent::Line(line) => match String::from_utf8(line) {
                                Ok(text) => {
                                    // BNC-local commands never reach the
                                    // upstream: CHATHISTORY and MARKREAD are
                                    // served from the PG backlog, and only
                                    // when the client negotiated the cap (a
                                    // non-negotiated CHATHISTORY is not ours
                                    // to intercept).
                                    let mut handled = false;
                                    if (caps.chathistory || caps.read_marker)
                                        && let Ok(msg) =
                                            e6irc_proto::message::Message::parse(&text)
                                    {
                                        let cmd = msg.command.to_ascii_uppercase();
                                        let params: Vec<&str> = msg.params.to_vec();
                                        if cmd == "CHATHISTORY" && caps.chathistory {
                                            chathistory::handle_chathistory(
                                                handle, &mut write, caps, &params,
                                            )
                                            .await?;
                                            handled = true;
                                        } else if cmd == "MARKREAD" && caps.read_marker {
                                            chathistory::handle_markread(
                                                handle, &mut write, account, &params,
                                            )
                                            .await?;
                                            handled = true;
                                        }
                                    }
                                    if !handled {
                                        match handle.send_from(attach_id, &text) {
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
                                                return Ok(()); // driver gone
                                            }
                                        }
                                    }
                                }
                                // This relay is UTF-8, like the core ingest
                                // path; reject a non-UTF-8 line loudly rather
                                // than swallowing it.
                                Err(_) => {
                                    write
                                        .write_all(
                                            b":*bnc* NOTICE * :input was not valid UTF-8; not sent upstream\r\n",
                                        )
                                        .await?;
                                    write.flush().await?;
                                }
                            },
                            // The framing contract forbids silently dropping an
                            // over-long line; tell the client its line was not
                            // relayed rather than swallowing it.
                            LineEvent::TooLong => {
                                write
                                    .write_all(
                                        b":*bnc* NOTICE * :input line too long; not sent upstream\r\n",
                                    )
                                    .await?;
                                write.flush().await?;
                            }
                        }
                    }
                }
                Err(e) => return Err(e),
            },
        }
    }
    Ok(())
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
    pub fn filter_tags(line: &str, caps: AttachCaps) -> String {
        super::filter_tags(line, caps)
    }

    /// Wrapper over [`crate::sanitize::upstream_line`].
    pub fn upstream_line(line: String) -> String {
        crate::sanitize::upstream_line(line)
    }
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
        build_driver(
            kind,
            addr.into(),
            true,
            nick.into(),
            nick.into(),
            vec![],
            16,
            account.map(str::to_string),
            password.map(str::to_string),
        )
        .err()
        .expect("invalid driver configuration should be rejected")
    }

    #[test]
    fn driver_factory_rejects_incomplete_credentials_before_any_connection() {
        use crate::config::NetworkKind;
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
            realname: Some("silently ignored before this invariant".into()),
            autojoin: vec![],
            sasl_account: None,
            sasl_password_sealed: Some("sealed-but-no-key".into()),
            enabled: false,
        };
        let error = driver_from_row(&row, None, "owner")
            .err()
            .expect("noncanonical stored bridge should be rejected");
        assert!(error.contains("real name field"), "{error}");
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
        assert!(reconnecting.last_error_at.is_some());
        assert_eq!(
            reconnecting.last_error,
            Some(NetworkFailure::ConnectionLost)
        );

        ends.emit(ConnectionEvent::AuthenticationFailed);
        let failed = handle.runtime_snapshot();
        assert_eq!(failed.lifecycle, NetworkLifecycle::AuthenticationFailed);
        assert_eq!(
            failed.last_error,
            Some(NetworkFailure::AuthenticationRejected)
        );

        ends.emit(ConnectionEvent::RegistrationFailed(
            e6irc_client::RegistrationRefusal::InvalidNickname,
        ));
        let rejected = handle.runtime_snapshot();
        assert_eq!(rejected.lifecycle, NetworkLifecycle::RegistrationFailed);
        assert_eq!(rejected.last_error, Some(NetworkFailure::InvalidNickname));
        assert_eq!(failed.errors, 2);
        assert_eq!(rejected.buffer_lines, 5);
        assert_eq!(
            handle.buffer_snapshot(),
            vec![
                ":*bnc* NOTICE * :component connected: unregistered network".to_string(),
                ":upstream PRIVMSG #room :hello".to_string(),
                ":*bnc* NOTICE * :component reconnecting: The established upstream connection was lost. (connection_lost)".to_string(),
                ":*bnc* NOTICE * :component authentication_failed: The upstream rejected the configured credentials. (authentication_rejected)".to_string(),
                ":*bnc* NOTICE * :component registration_failed: The upstream rejected the configured nickname. (invalid_nickname)".to_string(),
            ]
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
        assert_eq!(
            handle.buffer_snapshot(),
            vec![failure_notice(NetworkFailure::BacklogStorageFailed)]
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
            attach(server_side, &handle, AttachCaps::default(), "testuser"),
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
        let err = bridge_ws_connect("wss://169.254.169.254/gateway", bridge_ws_config())
            .await
            .expect_err("a link-local gateway must be refused");
        assert!(
            err.contains("permitted") || err.contains("SSRF"),
            "refusal must name the SSRF block, got: {err}"
        );
    }

    #[tokio::test]
    #[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
    async fn relay_routed_surfaces_every_target_outcome() {
        let (handle, ends) = NetworkHandle::channels(64);
        let mut map = std::collections::HashMap::new();
        map.insert("#a".to_string(), "id_a".to_string());
        map.insert("#b".to_string(), "id_b".to_string());
        // #c is deliberately absent from the map (unmapped).
        let routed = route_privmsg("PRIVMSG #a,#b,#c :hi", &map);
        relay_routed(&ends, routed, "Test", "channel", |id, _text| {
            let failed = id == "id_b"; // #b's upstream send fails; #a succeeds.
            async move {
                if failed {
                    Err("boom".to_string())
                } else {
                    Ok(())
                }
            }
        })
        .await;
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
        assert_eq!(
            lines.len(),
            2,
            "exactly one notice per problem target — earlier problems not dropped: {lines:#?}"
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
        let lines = render_bridged_privmsg("slack", "U1", "#general", &body);
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

    #[test]
    #[cfg(any(feature = "discord", feature = "matrix", feature = "slack"))]
    fn bridged_message_splits_on_newlines() {
        // A newline is a line break in the source medium. Left in, it is
        // flattened to a space downstream and the message reads as a run-on.
        let lines = render_bridged_privmsg("discord", "bob", "#c", "one\ntwo\r\nthree");
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
            let lines = render_bridged_privmsg("matrix", "u", "#c", &body);
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
            render_bridged_privmsg("slack", "U1", "#c", ""),
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

    #[test]
    fn filter_tags_drops_a_malformed_tag_only_line() {
        // A hostile upstream can store a line that is a leading `@` with no
        // space — a tag section and no message. It must not reach a no-tags
        // client as a `@`-prefixed line; there is nothing deliverable, so it is
        // dropped. (Found by the bouncer fuzz target.)
        assert_eq!(filter_tags("@time=x;msgid=1", AttachCaps::default()), "");
        assert_eq!(
            filter_tags(
                "@time=x",
                AttachCaps {
                    server_time: true,
                    ..AttachCaps::default()
                }
            ),
            ""
        );
        // A well-formed line (tags then a space then a body) is unaffected.
        assert_eq!(
            filter_tags("@time=x PRIVMSG #c :hi", AttachCaps::default()),
            "PRIVMSG #c :hi"
        );
    }

    #[test]
    fn filter_tags_gates_each_family_by_negotiated_cap() {
        let line = "@time=2020-01-01T00:00:00.000Z;account=alice;msgid=abc :n!u@h PRIVMSG #c :hi";
        // No caps: every tag is stripped, the tag section disappears entirely.
        let none = filter_tags(line, AttachCaps::default());
        assert_eq!(none, ":n!u@h PRIVMSG #c :hi");
        // server-time only keeps `time=`, drops account/msgid.
        let st = filter_tags(
            line,
            AttachCaps {
                server_time: true,
                ..Default::default()
            },
        );
        assert_eq!(st, "@time=2020-01-01T00:00:00.000Z :n!u@h PRIVMSG #c :hi");
        // account-tag only keeps `account=`.
        let at = filter_tags(
            line,
            AttachCaps {
                account_tag: true,
                ..Default::default()
            },
        );
        assert_eq!(at, "@account=alice :n!u@h PRIVMSG #c :hi");
        // message-tags gates everything else (msgid) but not time/account.
        let mt = filter_tags(
            line,
            AttachCaps {
                message_tags: true,
                ..Default::default()
            },
        );
        assert_eq!(mt, "@msgid=abc :n!u@h PRIVMSG #c :hi");
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
        assert_eq!(all, line);
        // A line without a tag section is returned unchanged.
        let bare = ":n!u@h PRIVMSG #c :hi";
        assert_eq!(filter_tags(bare, AttachCaps::default()), bare);
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
}
