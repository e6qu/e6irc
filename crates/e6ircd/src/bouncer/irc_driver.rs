//! The `irc` network driver: a persistent outbound IRCv3 client
//! connection to an external network, reusing `e6irc-client`. Runs on
//! its own task with auto-reconnect (exponential backoff + jitter);
//! emits [`DriverEvent`]s and accepts raw command lines.

use std::time::Duration;
use std::time::Instant;

use std::collections::HashMap;

use e6irc_client::{Connection, NetworkNames, OwnedMessage, RelayEvent};

use super::replies::{Correlation, ReplyRouter, Upstream};
use super::upstream_identity::{
    AutojoinChannel, ChannelKey, ConfirmedChannel, UpstreamNick, UpstreamRealname, UpstreamUsername,
};
use super::{ClientTags, ConnectionEvent, DriverEnds, NetworkHandle};

/// Static configuration for one upstream network.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Upstream address (host:port).
    pub addr: String,
    /// Use TLS to the upstream.
    pub tls: bool,
    pub nick: UpstreamNick,
    /// The `USER` name (ident), exactly as sent. Never derived from the nick.
    pub username: UpstreamUsername,
    pub realname: UpstreamRealname,
    /// Channels to auto-join after registering, keyed ones with their keys.
    pub autojoin: Vec<AutojoinChannel>,
    /// Detached buffer capacity.
    pub buffer_cap: usize,
    /// SASL PLAIN credentials for the upstream, when it requires auth.
    pub sasl: Option<(String, String)>,
    /// The network's connection password, sent as `PASS` before registration
    /// when the upstream is a private server that requires one.
    pub server_password: Option<e6irc_client::ServerPassword>,
    /// Idle gap before the driver sends its own keepalive PING (and again
    /// before it declares a silent upstream dead). 120s in production; tests
    /// shrink it to exercise the half-open-upstream path in real time.
    pub keepalive_idle: Duration,
    /// First delay after the upstream refuses registration, doubled per
    /// consecutive refusal. 30s in production; tests shrink it to reach the
    /// parked state in real time.
    pub rejection_retry_floor: Duration,
    /// Whether the upstream may resolve to an address inside this host's own
    /// network (§egress). Every resolved address is judged against it at dial.
    pub internal_upstreams: crate::egress::InternalUpstreams,
    /// Whether the first dial is held back as one of a boot's many.
    pub first_dial: FirstDial,
}

/// When a started driver first dials. A daemon restart starts every stored
/// network within milliseconds; dialled at once they reach one network's round
/// robin as a burst that its connection throttle answers with `ERROR`, so those
/// are spread over [`super::Backoff::FIRST_DIAL_STAGGER`] by each driver's
/// seed. A network the owner just created or enabled is one dial, made at
/// once, so they see its outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstDial {
    Immediate,
    Staggered,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            addr: String::new(),
            tls: false,
            nick: "e6bnc".parse().expect("the default nickname is valid"),
            username: "e6bnc".parse().expect("the default user name is valid"),
            realname: "e6irc bouncer"
                .parse()
                .expect("the default real name is valid"),
            autojoin: Vec::new(),
            buffer_cap: 1000,
            sasl: None,
            server_password: None,
            keepalive_idle: KEEPALIVE_IDLE,
            rejection_retry_floor: super::REJECTION_RETRY_FLOOR,
            internal_upstreams: crate::egress::InternalUpstreams::Refuse,
            first_dial: FirstDial::Immediate,
        }
    }
}

/// A started `irc` network. Dropping the returned [`NetworkHandle`]
/// (its command sender) tells the driver task to stop.
pub struct IrcNetwork;

/// State that survives one driver's reconnects: the channels the upstream has
/// confirmed us in, each with the key it is joined with when it is keyed,
/// keyed by the network's own fold of the name with the server's canonical
/// casing kept. `connect_once` joins the configured autojoin plus everything
/// here, so channels joined at runtime (not just the static config) are
/// restored after a drop — the behaviour ZNC/soju users rely on. In-memory
/// only, learned keys included: a process restart legitimately falls back to
/// the configured autojoin, with its configured keys, which is the owner's
/// declared floor.
#[derive(Debug, Default)]
pub struct JoinedChannels(std::sync::Mutex<Intent>);

#[derive(Debug, Default)]
struct Intent {
    channels: HashMap<String, Intended>,
    /// The naming rules the keys above were folded under: the network's, as
    /// last known.
    names: NetworkNames,
    /// Keys attached clients sent with a `JOIN` the upstream has not
    /// confirmed yet, by folded channel name.
    offered_keys: HashMap<String, ChannelKey>,
}

#[derive(Debug, Clone)]
struct Intended {
    channel: ConfirmedChannel,
    key: Option<ChannelKey>,
}

/// Most keys held for joins not yet confirmed; a refused join's key is never
/// claimed, so the set is emptied past this.
const MAX_OFFERED_KEYS: usize = 64;

impl Intent {
    /// Adopt `names`, re-keying what was folded under the old ones.
    fn adopt(&mut self, names: &NetworkNames) {
        if self.names.casemapping() == names.casemapping() {
            self.names = names.clone();
            return;
        }
        self.names = names.clone();
        let names = &self.names;
        self.channels = std::mem::take(&mut self.channels)
            .into_values()
            .map(|intended| (names.fold(intended.channel.as_str()), intended))
            .collect();
        self.offered_keys.clear();
    }
}

impl JoinedChannels {
    /// Fold one line's membership change into the reconnect intent. The intent
    /// outlives sessions, so it carries the tracker's bound itself: successive
    /// sessions could otherwise each confirm a different full set. A channel
    /// confirmed after a client offered a key for it keeps that key.
    fn apply(
        &self,
        change: super::SessionChange,
        names: &NetworkNames,
    ) -> Result<(), super::ChannelLimitExceeded> {
        let mut intent = self.0.lock().expect("joined set poisoned");
        intent.adopt(names);
        for left in &change.left {
            let key = intent.names.fold(left);
            intent.channels.remove(&key);
        }
        for channel in change.joined {
            let folded = intent.names.fold(channel.as_str());
            if !intent.channels.contains_key(&folded)
                && intent.channels.len() >= super::MAX_TRACKED_CHANNELS
            {
                return Err(super::ChannelLimitExceeded);
            }
            let key = intent.offered_keys.remove(&folded).or_else(|| {
                intent
                    .channels
                    .get(&folded)
                    .and_then(|intended| intended.key.clone())
            });
            intent.channels.insert(folded, Intended { channel, key });
        }
        Ok(())
    }

    /// Remember the keys an attached client's `JOIN` line offers, until the
    /// upstream confirms (or never confirms) the channels they open.
    fn offer_keys(&self, message: &e6irc_proto::message::Message<'_>) {
        let [channels, keys, ..] = message.params.as_slice() else {
            return;
        };
        let mut intent = self.0.lock().expect("joined set poisoned");
        for (channel, key) in channels.split(',').zip(keys.split(',')) {
            let Some(key) = ChannelKey::parse(key) else {
                continue;
            };
            if intent.offered_keys.len() >= MAX_OFFERED_KEYS {
                intent.offered_keys.clear();
            }
            let folded = intent.names.fold(channel);
            intent.offered_keys.insert(folded, key);
        }
    }

    /// Follow a `+k`/`-k` on a channel in the intent.
    fn set_key(&self, channel: &str, key: Option<ChannelKey>) {
        let mut intent = self.0.lock().expect("joined set poisoned");
        let folded = intent.names.fold(channel);
        if let Some(intended) = intent.channels.get_mut(&folded) {
            intended.key = key;
        }
    }

    /// Stop rejoining `channel`. `true` when it was in the intent.
    fn forget(&self, channel: &str) -> bool {
        let mut intent = self.0.lock().expect("joined set poisoned");
        let folded = intent.names.fold(channel);
        intent.channels.remove(&folded).is_some()
    }

    /// The configured autojoin plus every channel the upstream confirmed
    /// before the drop, with the keys they were joined with. Autojoin wins on
    /// a fold-collision: its casing is the owner's. A configured channel is
    /// joined with the key it was last seen with (a `+k` since, or the key a
    /// client joined it with), and otherwise with its configured key.
    fn rejoin(&self, autojoin: &[AutojoinChannel]) -> Vec<(String, Option<ChannelKey>)> {
        let intent = self.0.lock().expect("joined set poisoned");
        let names = &intent.names;
        let mut list: Vec<(String, Option<ChannelKey>)> = autojoin
            .iter()
            .map(|configured| {
                let channel = configured.channel().as_str();
                let key = intent
                    .channels
                    .get(&names.fold(channel))
                    .and_then(|intended| intended.key.clone())
                    .or_else(|| configured.key().cloned());
                (channel.to_string(), key)
            })
            .collect();
        let configured: std::collections::HashSet<String> = autojoin
            .iter()
            .map(|configured| names.fold(configured.channel().as_str()))
            .collect();
        list.extend(
            intent
                .channels
                .iter()
                .filter(|(folded, _)| !configured.contains(*folded))
                .map(|(_, intended)| (intended.channel.as_str().to_string(), intended.key.clone())),
        );
        list
    }
}

impl IrcNetwork {
    /// Start the driver task and return a handle to it.
    pub fn start(config: NetworkConfig) -> NetworkHandle {
        let (handle, ends) = NetworkHandle::channels(config.buffer_cap);
        tokio::spawn(run(config, ends));
        handle
    }
}

/// A successful, side-effect-free IRC upstream qualification. Registration
/// under the configured identity is the qualification: the connection says
/// `QUIT` as soon as it is welcomed and joins nothing, so a test of a network
/// whose channels are public shows those channels no JOIN/QUIT pair. Timings
/// are split at the same boundaries operators must diagnose: name resolution,
/// transport establishment (including TLS), and IRC registration (including
/// SASL).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IrcPreflight {
    pub resolved_addresses: usize,
    pub dns_ms: u64,
    pub connect_ms: u64,
    pub registration_ms: u64,
    pub confirmed_nick: String,
    /// The SASL mechanism that logged in (the strongest the network offered
    /// for the configured password), or `None` when no account is configured.
    pub sasl_mechanism: Option<String>,
}

/// Closed failure taxonomy for an IRC preflight. Raw resolver, TLS, and server
/// errors stay in the server log; the API exposes only these actionable,
/// non-secret stages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrcPreflightFailure {
    InvalidAddress,
    NameResolutionFailed,
    AddressBlocked,
    ConnectionFailed,
    SecureConnectionFailed,
    ConnectionTimedOut,
    /// The upstream rejected the credentials themselves; its own words ride
    /// along when it gave any.
    AuthenticationRejected(Option<e6irc_client::SaslRejection>),
    RegistrationRejected(Option<e6irc_client::RegistrationRejection>),
    InvalidNickname(Option<e6irc_client::RegistrationRejection>),
    InvalidUsername(Option<e6irc_client::RegistrationRejection>),
    NicknameInUse(Option<e6irc_client::RegistrationRejection>),
    ServerPasswordRejected(Option<e6irc_client::RegistrationRejection>),
    ServerPasswordRequired(Option<e6irc_client::RegistrationRejection>),
    NetworkBanned(Option<e6irc_client::RegistrationRejection>),
    SaslUnavailable(e6irc_client::RegistrationRejection),
    SaslFailed(e6irc_client::RegistrationRejection),
    RegistrationFailed,
    RegistrationTimedOut,
}

impl IrcPreflightFailure {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidAddress => "invalid_address",
            Self::NameResolutionFailed => "name_resolution_failed",
            Self::AddressBlocked => "address_blocked",
            Self::ConnectionFailed => "connection_failed",
            Self::SecureConnectionFailed => "secure_connection_failed",
            Self::ConnectionTimedOut => "connection_timed_out",
            Self::AuthenticationRejected(_) => "authentication_rejected",
            Self::RegistrationRejected(_) => "registration_rejected",
            Self::InvalidNickname(_) => "invalid_nickname",
            Self::InvalidUsername(_) => "invalid_username",
            Self::NicknameInUse(_) => "nickname_in_use",
            Self::ServerPasswordRejected(_) => "server_password_rejected",
            Self::ServerPasswordRequired(_) => "server_password_required",
            Self::NetworkBanned(_) => "network_banned",
            Self::SaslUnavailable(_) => "sasl_unavailable",
            Self::SaslFailed(_) => "sasl_failed",
            Self::RegistrationFailed => "registration_failed",
            Self::RegistrationTimedOut => "registration_timed_out",
        }
    }

    pub const fn summary(&self) -> &'static str {
        match self {
            Self::InvalidAddress => "The upstream address is not a valid host and port.",
            Self::NameResolutionFailed => "The upstream hostname could not be resolved.",
            Self::AddressBlocked => {
                "The hostname resolves only to addresses blocked by the upstream safety policy."
            }
            Self::ConnectionFailed => "A TCP connection to the upstream could not be established.",
            Self::SecureConnectionFailed => {
                "The TLS connection or certificate verification failed."
            }
            Self::ConnectionTimedOut => "Connecting to the upstream timed out.",
            Self::AuthenticationRejected(_) => "The upstream rejected the SASL credentials.",
            Self::RegistrationRejected(_) => "The upstream rejected IRC registration.",
            Self::InvalidNickname(_) => "The upstream rejected the configured nickname.",
            Self::InvalidUsername(_) => "The upstream rejected the IRC username.",
            Self::NicknameInUse(_) => "The configured nickname is already in use.",
            Self::ServerPasswordRejected(_) => {
                super::NetworkFailure::ServerPasswordRejected.summary()
            }
            Self::ServerPasswordRequired(_) => {
                super::NetworkFailure::ServerPasswordRequired.summary()
            }
            Self::NetworkBanned(_) => "The upstream network banned this connection.",
            Self::SaslUnavailable(_) => super::NetworkFailure::SaslUnavailable.summary(),
            Self::SaslFailed(_) => super::NetworkFailure::SaslFailed.summary(),
            Self::RegistrationFailed => "IRC registration failed before a welcome was received.",
            Self::RegistrationTimedOut => "IRC registration timed out.",
        }
    }

    pub fn diagnostic(&self) -> Option<&str> {
        match self {
            Self::RegistrationRejected(rejection)
            | Self::InvalidNickname(rejection)
            | Self::InvalidUsername(rejection)
            | Self::NicknameInUse(rejection)
            | Self::ServerPasswordRejected(rejection)
            | Self::ServerPasswordRequired(rejection)
            | Self::NetworkBanned(rejection) => rejection.as_ref().map(|value| value.diagnostic()),
            Self::SaslUnavailable(rejection) | Self::SaslFailed(rejection) => {
                Some(rejection.diagnostic())
            }
            Self::AuthenticationRejected(rejection) => {
                rejection.as_ref().map(|value| value.diagnostic())
            }
            _ => None,
        }
    }
}

/// Resolve, connect, and register exactly as the always-on IRC driver does,
/// without persisting configuration or starting a reconnect loop.
///
/// `budget` bounds the whole test. The stages used to carry 10 + 30 + 30
/// seconds of their own, so the caller's own deadline always fired first: its
/// typed timeouts could never be reported, and the dropped future skipped the
/// goodbye below. Whichever stage is running when the budget ends reports its
/// own timeout, and every exit after the socket opens says `QUIT`.
pub async fn preflight_irc(
    config: &NetworkConfig,
    budget: Duration,
) -> Result<IrcPreflight, IrcPreflightFailure> {
    if upstream_host(&config.addr).is_err() {
        return Err(IrcPreflightFailure::InvalidAddress);
    }
    let deadline = tokio::time::Instant::now() + budget;

    let dns_started = Instant::now();
    let dns_deadline = deadline.min(tokio::time::Instant::now() + Duration::from_secs(10));
    let addresses = tokio::time::timeout_at(
        dns_deadline,
        super::resolve_vetted(config.addr.as_str(), config.internal_upstreams),
    )
    .await
    .map_err(|_| IrcPreflightFailure::ConnectionTimedOut)?
    .map_err(|error| {
        eprintln!("irc preflight: name resolution failed: {error}");
        IrcPreflightFailure::NameResolutionFailed
    })?;
    if addresses.is_empty() {
        return Err(IrcPreflightFailure::AddressBlocked);
    }
    let dns_ms = elapsed_millis(dns_started.elapsed());
    let resolved_addresses = addresses.len();

    let connect_started = Instant::now();
    // One test, one dial: nothing to spread it against.
    let addresses = super::rotate_addresses(addresses, 0);
    let mut connection = tokio::time::timeout_at(deadline, connect_resolved(config, addresses))
        .await
        .map_err(|_| IrcPreflightFailure::ConnectionTimedOut)?
        .map_err(|error| {
            eprintln!("irc preflight: transport failed: {error}");
            if config.tls {
                IrcPreflightFailure::SecureConnectionFailed
            } else {
                IrcPreflightFailure::ConnectionFailed
            }
        })?;
    let connect_ms = elapsed_millis(connect_started.elapsed());

    // Everything from here talks on an open socket, so it runs as one unit
    // whose every outcome -- a refusal, a welcome, the deadline -- is followed
    // by the goodbye below.
    let registration_started = Instant::now();
    let registration = register(config, &mut connection);
    let outcome = match tokio::time::timeout_at(deadline, registration).await {
        Ok(Ok(welcomed)) => {
            configured_nick_was_granted(connection.names(), config.nick.as_str(), welcomed)
                .map_err(|rejection| preflight_refusal(Some(rejection)))
        }
        Ok(Err(error)) => Err(match RegistrationError::classify(error) {
            RegistrationError::CredentialsRejected(rejection) => {
                IrcPreflightFailure::AuthenticationRejected(Some(rejection))
            }
            RegistrationError::Refused(rejection) => preflight_refusal(Some(rejection)),
            // A server that never answered in time (capability negotiation
            // held past its bound) is a timeout, not a failure of its own.
            RegistrationError::Failed(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                eprintln!("irc preflight: registration timed out: {error}");
                IrcPreflightFailure::RegistrationTimedOut
            }
            RegistrationError::Failed(error) => {
                eprintln!("irc preflight: registration failed: {error}");
                IrcPreflightFailure::RegistrationFailed
            }
        }),
        Err(_) => Err(IrcPreflightFailure::RegistrationTimedOut),
    };
    let registration_ms = elapsed_millis(registration_started.elapsed());
    let sasl_mechanism = connection.sasl_mechanism().map(str::to_owned);

    say_goodbye(&mut connection, "connection test complete", "irc preflight").await;

    Ok(IrcPreflight {
        resolved_addresses,
        dns_ms,
        connect_ms,
        registration_ms,
        confirmed_nick: outcome?,
        sasl_mechanism,
    })
}

fn elapsed_millis(elapsed: Duration) -> u64 {
    elapsed.as_millis().min(u64::MAX as u128) as u64
}

/// How long the goodbye may take. The exit is already decided; this only keeps
/// a dead socket from holding it.
const GOODBYE_DEADLINE: Duration = Duration::from_secs(2);

/// Leave as a client would: `QUIT`, then the socket. Dropping the socket
/// instead shows the upstream a read error, and its record of this nick can
/// outlive the close long enough to refuse — as a 433, with the whole refusal
/// schedule behind it — whatever starts from the same settings a moment later:
/// the connection test's driver, or a reconfigured network's replacement. The
/// exit is already decided, so a failed or slow goodbye is only logged.
///
/// After the `QUIT` the socket is read to its end (a server answers `QUIT`
/// with `ERROR` and closes): dropping it with that answer unread makes the
/// kernel send a reset instead of an orderly close, and a reset may discard
/// the `QUIT` itself before the upstream has read it (macOS does).
async fn say_goodbye(connection: &mut Connection, reason: &str, who: &str) {
    let deadline = tokio::time::Instant::now() + GOODBYE_DEADLINE;
    match tokio::time::timeout_at(deadline, connection.send_line(&format!("QUIT :{reason}"))).await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            eprintln!("{who}: quit failed: {error}");
            return;
        }
        Err(_) => {
            eprintln!("{who}: quit timed out");
            return;
        }
    }
    // A server that keeps the connection open past the deadline is simply
    // left: the exit is decided, and what it sent has been read.
    let _closed = tokio::time::timeout_at(deadline, async {
        while let Ok(Some(_)) = connection.next_message().await {}
    })
    .await;
}

/// What a stopped driver says on its way out, whether the network was removed
/// or replaced by its reconfigured successor.
// Neutral on purpose: the driver cannot tell a replace from a removal or a
// process shutdown, and the upstream needs only to know the session ended.
const STOPPED_GOODBYE: &str = "e6irc bouncer stopping";

async fn run(config: NetworkConfig, mut ends: DriverEnds) {
    ends.set_rejection_retry_floor(config.rejection_retry_floor);
    if config.first_dial == FirstDial::Staggered {
        ends.stagger_first_dial();
    }
    // Clean stop: the command channel closed (handle dropped).
    let shared = SharedDriver {
        config,
        joined: std::sync::Arc::new(JoinedChannels::default()),
    };
    super::run_with_backoff(shared, &mut ends, |shared, ends| {
        Box::pin(connect_once(shared, ends))
    })
    .await;
}

/// The per-driver value shared across reconnect attempts: static config plus
/// the runtime joined-channel set.
struct SharedDriver {
    config: NetworkConfig,
    joined: std::sync::Arc<JoinedChannels>,
}

/// What a failed registration means, read from the typed value the client
/// attached to its error — never from the error kind, which cannot tell a
/// rejected password from a server that offers no usable SASL. The driver and
/// the preflight share this so they cannot classify the same upstream
/// differently.
enum RegistrationError {
    /// The upstream rejected the credentials themselves. Never retried.
    CredentialsRejected(e6irc_client::SaslRejection),
    /// The upstream refused registration for a reason it stated.
    Refused(e6irc_client::RegistrationRejection),
    /// Anything else: a transport error, or a peer that is not speaking IRC.
    Failed(std::io::Error),
}

impl RegistrationError {
    fn classify(error: std::io::Error) -> Self {
        if let Some(rejection) = e6irc_client::RegistrationRejection::from_error(&error) {
            return Self::Refused(rejection);
        }
        match e6irc_client::SaslRejection::from_error(&error).map(|sasl| sasl.class()) {
            Some(e6irc_client::SaslRejectionClass::CredentialsRejected(rejection)) => {
                Self::CredentialsRejected(rejection)
            }
            Some(e6irc_client::SaslRejectionClass::RegistrationRefused(rejection)) => {
                Self::Refused(rejection)
            }
            None => Self::Failed(error),
        }
    }
}

/// Register as exactly the configured identity — the one registration the
/// driver and the connection test both perform, so a test cannot pass with an
/// identity the driver would not send.
async fn register(config: &NetworkConfig, connection: &mut Connection) -> std::io::Result<String> {
    // The upstream's own echo is the verdict on a message: it arrives only
    // for a line the upstream accepted. See `PendingEchoes`.
    connection.request_when_offered("echo-message");
    // Labels tell each attached client's replies apart (see
    // `super::replies`); a multi-line answer comes in a batch.
    connection.request_when_offered("batch");
    connection.request_when_offered("labeled-response");
    let identity = e6irc_client::Identity {
        nick: config.nick.as_str(),
        username: config.username.as_str(),
        realname: config.realname.as_str(),
        server_password: config.server_password.as_ref(),
    };
    match &config.sasl {
        Some((account, password)) => connection.register_sasl(&identity, account, password).await,
        None => connection.register(&identity).await,
    }
}

/// The welcomed nickname, when it is the configured one. A server that
/// truncates to its NICKLEN, or renames on registration, welcomes the
/// connection under a name the owner never chose; running under it would be an
/// identity invented on their behalf, with whatever channel access and services
/// relationship that name has. Case is the server's to normalise.
pub(super) fn configured_nick_was_granted(
    names: &NetworkNames,
    configured: &str,
    welcomed: String,
) -> Result<String, e6irc_client::RegistrationRejection> {
    if names.eq(configured, &welcomed) {
        Ok(welcomed)
    } else {
        Err(e6irc_client::RegistrationRejection::welcomed_as(
            configured, &welcomed,
        ))
    }
}

/// What one bounded registration attempt means to the session loop. A refusal
/// of the configured nickname is a refusal like any other: the driver never
/// substitutes a nickname the owner did not choose. It reports the upstream's
/// reason, retries on the slow refusal schedule in case a ghost of its own
/// previous session times out, and parks if the nickname stays taken.
fn registration_outcome(
    result: Result<Result<String, std::io::Error>, tokio::time::error::Elapsed>,
) -> Result<String, super::SessionOutcome> {
    match result {
        Ok(Ok(nick)) => Ok(nick),
        Ok(Err(error)) => Err(match RegistrationError::classify(error) {
            RegistrationError::CredentialsRejected(rejection) => {
                super::SessionOutcome::AuthRejected(Some(rejection))
            }
            RegistrationError::Refused(rejection) => {
                eprintln!("irc registration rejected: {rejection:?}");
                super::SessionOutcome::RegistrationRejected(rejection)
            }
            RegistrationError::Failed(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                dropped(super::NetworkFailure::RegistrationTimedOut)
            }
            RegistrationError::Failed(_) => dropped(super::NetworkFailure::RegistrationFailed),
        }),
        Err(_) => Err(dropped(super::NetworkFailure::RegistrationTimedOut)),
    }
}

fn preflight_refusal(
    rejection: Option<e6irc_client::RegistrationRejection>,
) -> IrcPreflightFailure {
    let Some(rejection) = rejection else {
        return IrcPreflightFailure::RegistrationRejected(None);
    };
    match rejection.refusal() {
        e6irc_client::RegistrationRefusal::InvalidNickname
        | e6irc_client::RegistrationRefusal::WelcomedAsAnotherNickname => {
            IrcPreflightFailure::InvalidNickname(Some(rejection))
        }
        e6irc_client::RegistrationRefusal::InvalidUsername => {
            IrcPreflightFailure::InvalidUsername(Some(rejection))
        }
        e6irc_client::RegistrationRefusal::NicknameInUse => {
            IrcPreflightFailure::NicknameInUse(Some(rejection))
        }
        e6irc_client::RegistrationRefusal::ServerPasswordRejected => {
            IrcPreflightFailure::ServerPasswordRejected(Some(rejection))
        }
        e6irc_client::RegistrationRefusal::ServerPasswordRequired => {
            IrcPreflightFailure::ServerPasswordRequired(Some(rejection))
        }
        e6irc_client::RegistrationRefusal::NetworkBanned => {
            IrcPreflightFailure::NetworkBanned(Some(rejection))
        }
        e6irc_client::RegistrationRefusal::NotRegistered => {
            IrcPreflightFailure::RegistrationRejected(Some(rejection))
        }
        e6irc_client::RegistrationRefusal::SaslUnavailable => {
            IrcPreflightFailure::SaslUnavailable(rejection)
        }
        e6irc_client::RegistrationRefusal::SaslAborted
        | e6irc_client::RegistrationRefusal::SaslFailed => {
            IrcPreflightFailure::SaslFailed(rejection)
        }
    }
}

async fn connect_once(shared: &SharedDriver, ends: &mut DriverEnds) -> super::SessionOutcome {
    let config = &shared.config;
    // Bound connect + registration: an upstream that accepts the TCP handshake
    // but never sends 001 (firewall dropping data, half-open peer) must not
    // wedge the driver forever — that would starve the reconnect loop, the
    // same failure the Matrix driver's timeout guards against.
    let connect_fut = connect(config, ends.dial_rotation());
    let connected = tokio::select! {
        _ = ends.shutdown_signalled() => return super::SessionOutcome::Stopped,
        result = tokio::time::timeout(Duration::from_secs(30), connect_fut) => result,
    };
    let mut conn = match connected {
        Ok(Ok(c)) => c,
        Ok(Err(_)) => {
            let failure = if config.tls {
                super::NetworkFailure::SecureConnectionFailed
            } else {
                super::NetworkFailure::ConnectionFailed
            };
            return dropped(failure);
        }
        Err(_) => return dropped(super::NetworkFailure::ConnectionTimedOut),
    };
    let register_fut = register(config, &mut conn);
    let registration = tokio::select! {
        _ = ends.shutdown_signalled() => None,
        result = tokio::time::timeout(Duration::from_secs(30), register_fut) => Some(result),
    };
    let Some(registration) = registration else {
        // Stopped while registering: the socket is open, so leave properly.
        say_goodbye(&mut conn, STOPPED_GOODBYE, "irc driver").await;
        return super::SessionOutcome::Stopped;
    };
    let welcomed = match registration_outcome(registration) {
        Ok(welcomed) => welcomed,
        Err(outcome) => return outcome,
    };
    let current_nick =
        match configured_nick_was_granted(conn.names(), config.nick.as_str(), welcomed) {
            Ok(nick) => nick,
            Err(rejection) => {
                // Registered, under a name nobody chose: leave as a client would,
                // or the upstream keeps that session until its ping timeout.
                say_goodbye(
                    &mut conn,
                    "registered under an unconfigured nickname",
                    "irc driver",
                )
                .await;
                return super::SessionOutcome::RegistrationRejected(rejection);
            }
        };
    let mut identity = SelfIdentity {
        nick: current_nick,
        // `~` because no identd answered; replaced by whatever the upstream
        // shows once one of our own echoes reveals it.
        user: format!("~{}", config.username.as_str()),
        host: upstream_host(&config.addr)
            .expect("IRC driver starts only from a validated upstream address")
            .to_string(),
    };
    // Join the configured autojoin plus every channel the upstream confirmed
    // us in before the drop (runtime joins are tracked in `shared.joined`),
    // keyed channels with their keys.
    let rejoin = shared.joined.rejoin(&config.autojoin);
    // As few lines as the wire allows, each bounded; the whole burst is still
    // raced against the stop signal so a removal or replacement is not held
    // behind a slow upstream's worth of them.
    let rejoined = tokio::select! {
        _ = ends.shutdown_signalled() => None,
        result = async {
            for line in join_lines(&rejoin) {
                write_bounded(&mut conn, &line, super::UPSTREAM_WRITE_DEADLINE).await?;
            }
            Ok::<(), std::io::Error>(())
        } => Some(result),
    };
    match rejoined {
        None => {
            say_goodbye(&mut conn, STOPPED_GOODBYE, "irc driver").await;
            return super::SessionOutcome::Stopped;
        }
        Some(Err(_)) => return dropped(super::NetworkFailure::AutojoinFailed),
        Some(Ok(())) => {}
    }
    let mut upstream = UpstreamCapabilities::of(&conn);
    ends.set_client_tags(upstream.client_tags());
    ends.begin_irc_session(identity.nick.clone());
    ends.emit(ConnectionEvent::Connected);
    // The mechanism is the client's choice among what the network offered, so
    // the owner is told which one carried the password — and which ones the
    // network refused before any credential was sent, so a weaker one that is
    // used instead is never a silent choice.
    for note in conn.sasl_notes() {
        ends.emit_line(super::bnc_notice("*", &format!("upstream SASL: {note}")));
    }
    if let (Some(mechanism), Some((account, _))) = (conn.sasl_mechanism(), &config.sasl) {
        ends.emit_line(super::bnc_notice(
            "*",
            &format!("upstream logged in as {account} with SASL {mechanism}"),
        ));
    }
    let mut echoes = UpstreamEchoes::default();
    let mut requested_nicks = RequestedNicks::default();
    let mut router = ReplyRouter::default();

    // Keepalive: `connect_once` bounds connect + registration, but the
    // steady-state read below would otherwise block forever on a half-open
    // upstream (firewall silently drops the link, peer vanishes without RST),
    // starving the reconnect loop while `is_connected()` stays true — the exact
    // wedge the registration timeout guards against, just relocated. On an idle
    // gap we send our own PING; if the next gap passes with still no traffic,
    // the link is dead — drop and reconnect. A live server's own PINGs (which
    // we answer) keep a quiet-but-alive connection from ever tripping this.
    //
    // The window is measured from the upstream's last sign of life (see
    // `SilenceDeadline`): a downstream command also ends a turn of this loop,
    // and must not make a silent upstream look alive while someone types.
    let mut awaiting_keepalive = false;
    let mut silence = super::SilenceDeadline::new(config.keepalive_idle);
    loop {
        tokio::select! {
            // Upstream -> buffer + event.
            msg = silence.bound(conn.next_line_relayable()) => match msg {
                Some(Ok(Some(RelayEvent::Line { message: parsed, raw }))) => {
                    awaiting_keepalive = false;
                    silence.restart();
                    // A line that didn't parse (a non-UTF-8 body, say) is never
                    // a PING, a reply or framing, and is simply relayed. A bad
                    // line must not drop the link — it is delivered, not fatal.
                    let Some(message) = parsed else {
                        if track(ends, shared, &mut identity, &mut requested_nicks, ends.emit_session_line(raw)).is_err() {
                            return dropped(super::NetworkFailure::ChannelLimitExceeded);
                        }
                        continue;
                    };
                    // Answer PINGs transparently (keepalive is the driver's
                    // job, not the attached client's).
                    if message.command == "PING" {
                        let token = message.params.first().cloned().unwrap_or_default();
                        if write_bounded(&mut conn, &pong_line(&token), super::UPSTREAM_WRITE_DEADLINE)
                            .await
                            .is_err()
                        {
                            return dropped(super::NetworkFailure::UpstreamWriteFailed);
                        }
                        continue;
                    }
                    // The reply to our *own* keepalive PING is internal
                    // bookkeeping, not conversation — drop it so it doesn't
                    // fill the backlog (one junk line per idle interval,
                    // evicting real messages) and reach attached clients.
                    // Mirrors the local driver's keepalive discipline.
                    if message.command == "PONG"
                        && message.params.last().map(String::as_str) == Some("e6bnc-keepalive")
                    {
                        continue;
                    }
                    // Capabilities are negotiated hop by hop. `CAP NEW` and
                    // `CAP DEL` describe this driver's negotiation with the
                    // upstream, which the connection has already followed;
                    // an attached client negotiated with the bouncer and would
                    // act on them against the wrong hop. What changed changes
                    // how the driver writes from here on.
                    if message.command == "CAP" {
                        for capability in conn.capabilities_to_request() {
                            if write_bounded(&mut conn, &format!("CAP REQ :{capability}"), super::UPSTREAM_WRITE_DEADLINE)
                                .await
                                .is_err()
                            {
                                return dropped(super::NetworkFailure::UpstreamWriteFailed);
                            }
                        }
                        upstream = UpstreamCapabilities::of(&conn);
                        ends.set_client_tags(upstream.client_tags());
                        continue;
                    }
                    // The upstream is closing the link and says why. To an
                    // attached client `ERROR` means *its* connection is
                    // over, and replayed from the backlog days later it
                    // would mean it again; the reason is kept as this
                    // drop's diagnostic and said as a notice instead.
                    if message.command == "ERROR" {
                        let closed = super::LinkClosed::new(
                            message.params.last().map(String::as_str).unwrap_or("no reason given"),
                        );
                        ends.emit_line(super::bnc_notice(
                            "*",
                            &format!("upstream closed the link: {}", closed.diagnostic()),
                        ));
                        return super::SessionOutcome::ClosedByUpstream(closed);
                    }
                    // A refused join of a channel the driver meant to be in: the
                    // channel cannot be joined as it is, so it is not rejoined
                    // again and again after every reconnect (soju does the same).
                    if let Some(channel) = refused_join(&message)
                        && ends.irc_session_snapshot().is_some_and(|session| {
                            !session.channels.iter().any(|joined| conn.names().eq(joined, channel))
                        })
                        && shared.joined.forget(channel)
                    {
                        ends.emit_line(super::bnc_notice(
                            "*",
                            &format!(
                                "{channel} will not be rejoined after a reconnect: \
                                 the upstream refused to join it ({})",
                                message.command
                            ),
                        ));
                    }
                    match router.classify(&message, raw, conn.names(), &identity.nick, std::time::Instant::now()) {
                        // A correlation PING's answer closes what came before
                        // it; the commands forwarded since want one of their own.
                        Upstream::Consumed => {
                            if let Some(barrier) = router.barrier_due()
                                && write_bounded(&mut conn, &barrier, super::UPSTREAM_WRITE_DEADLINE)
                                    .await
                                    .is_err()
                            {
                                return dropped(super::NetworkFailure::UpstreamWriteFailed);
                            }
                        }
                        Upstream::Reply { line, origin } => ends.emit_reply(origin, line),
                        Upstream::Session { line, origin } => {
                            if let Some((channel, key)) = key_change(&message, ends) {
                                shared.joined.set_key(&channel, key);
                            }
                            let emitted = if upstream.echoes {
                                echoes.publish(ends, &message, line, origin, &identity.nick, conn.names())
                            } else {
                                ends.emit_session_line(line)
                            };
                            if track(ends, shared, &mut identity, &mut requested_nicks, emitted).is_err() {
                                return dropped(super::NetworkFailure::ChannelLimitExceeded);
                            }
                        }
                    }
                }
                Some(Ok(Some(RelayEvent::Rejected(rejected)))) => {
                    awaiting_keepalive = false;
                    silence.restart();
                    // Keep the upstream connection alive, but make the whole-line
                    // loss visible to attached clients and the detached buffer.
                    // A syntactically valid local NOTICE is bounded independently
                    // of the rejected payload and cannot itself be discarded.
                    ends.emit_line(super::bnc_notice(
                        "*",
                        &format!("upstream input rejected: {rejected}"),
                    ));
                }
                // Only a genuine EOF or a real I/O error ends the session.
                Some(Ok(None)) | Some(Err(_)) => {
                    return dropped(super::NetworkFailure::ConnectionLost);
                }
                None => {
                    // Idle past the keepalive window.
                    if awaiting_keepalive {
                        return dropped(super::NetworkFailure::KeepaliveTimedOut);
                    }
                    awaiting_keepalive = true;
                    silence.restart();
                    if write_bounded(&mut conn, "PING :e6bnc-keepalive", super::UPSTREAM_WRITE_DEADLINE)
                        .await
                        .is_err()
                    {
                        return dropped(super::NetworkFailure::UpstreamWriteFailed);
                    }
                }
            },
            // Downstream command -> upstream.
            cmd = ends.next_command() => match cmd {
                Some(cmd) => {
                    let Some(line) = outgoing(&cmd, &upstream, ends, shared) else {
                        continue;
                    };
                    let written = router.forward(
                        cmd.origin,
                        &line,
                        upstream.correlation,
                        conn.names(),
                        std::time::Instant::now(),
                    );
                    if write_bounded(&mut conn, &written, super::UPSTREAM_WRITE_DEADLINE)
                        .await
                        .is_err()
                    {
                        return dropped(super::NetworkFailure::UpstreamWriteFailed);
                    }
                    if let Some(barrier) = router.barrier_due()
                        && write_bounded(&mut conn, &barrier, super::UPSTREAM_WRITE_DEADLINE)
                            .await
                            .is_err()
                    {
                        return dropped(super::NetworkFailure::UpstreamWriteFailed);
                    }
                    // The detached buffer and the account's other sessions
                    // must see both sides of the conversation, and the
                    // originator sees its echo exactly when it negotiated
                    // echo-message on attach. An upstream that echoes is
                    // waited for — a refused line then has no echo, and the
                    // refusal is the verdict; one that does not echo gets
                    // the echo manufactured here, one per target, from the
                    // line as the upstream was sent it.
                    requested_nicks.observe(&line);
                    if upstream.echoes {
                        if upstream.correlation == Correlation::Order {
                            echoes.sent(&line, cmd.origin, conn.names());
                        }
                    } else {
                        for echo in self_echoes(&line, &identity) {
                            ends.emit_echo(echo, cmd.origin);
                        }
                    }
                    // A barrier's answer may already be due; the loop reads it.
                }
                // Stopped by the registry, or every handle dropped: the
                // successor (if any) must not meet this session's ghost.
                None => {
                    say_goodbye(&mut conn, STOPPED_GOODBYE, "irc driver").await;
                    return super::SessionOutcome::Stopped;
                }
            },
        }
    }
}

/// What the upstream has enabled that decides how the driver writes: whether
/// it echoes, whether it carries client-only tags, and how its replies are
/// told apart. Re-read whenever a `CAP` line changes what is enabled.
struct UpstreamCapabilities {
    /// With `echo-message` the upstream echoes each message it accepts, and
    /// only those: its echo is relayed as the one echo of the line. Without it
    /// the driver synthesizes the echo when it writes the line.
    echoes: bool,
    message_tags: bool,
    correlation: Correlation,
}

impl UpstreamCapabilities {
    fn of(conn: &Connection) -> Self {
        let message_tags = conn.enabled("message-tags");
        let labels = message_tags && conn.enabled("batch") && conn.enabled("labeled-response");
        Self {
            echoes: conn.enabled("echo-message"),
            message_tags,
            correlation: if labels {
                Correlation::Labels
            } else {
                Correlation::Order
            },
        }
    }

    fn client_tags(&self) -> ClientTags {
        if self.message_tags {
            ClientTags::Relayed
        } else {
            ClientTags::Denied
        }
    }
}

/// Fold what one published session line changed into the driver's own state:
/// the identity the upstream shows, a rename (announced when nobody asked for
/// it), and the reconnect intent.
fn track(
    ends: &DriverEnds,
    shared: &SharedDriver,
    identity: &mut SelfIdentity,
    requested_nicks: &mut RequestedNicks,
    emitted: Result<super::SessionChange, super::ChannelLimitExceeded>,
) -> Result<(), super::ChannelLimitExceeded> {
    let mut change = emitted?;
    if let Some(shown) = change.shown_identity.take() {
        if let Some(user) = shown.user {
            identity.user = user;
        }
        identity.host = shown.host;
    }
    if let Some(nick) = change.nick.take() {
        // Tracked, so the session goes on under it. A name an attached client
        // asked for is the owner's own choice, confirmed; any other is
        // announced, because the owner did not choose it (a services
        // enforcer, typically).
        let names = ends.names();
        if !requested_nicks.confirms(&nick, &names) {
            ends.record_error_with_upstream_detail(
                super::NetworkFailure::RenamedByUpstream,
                &format!(
                    "upstream renamed this session from {} to {nick}",
                    identity.nick
                ),
            );
        }
        identity.nick = nick;
    }
    // QUIT clears live membership for attached-client state, but the reconnect
    // intent survives a transport drop: only a confirmed JOIN/PART/KICK changes
    // it, so an unrelated numeric cannot erase channels still awaiting
    // confirmation on this new session.
    shared.joined.apply(change, &ends.names())
}

/// A client's line as the upstream is to be sent it (see
/// [`super::carriable`]), or `None` when the bouncer answered it instead. A
/// `PART` of a channel the reconnect intent holds but this session is not in
/// (its rejoin failed) removes it from the intent — the one way a client can
/// — and says so, before the upstream's own answer.
fn outgoing(
    cmd: &super::ClientCommand,
    upstream: &UpstreamCapabilities,
    ends: &DriverEnds,
    shared: &SharedDriver,
) -> Option<String> {
    let line = super::carriable(cmd, upstream.client_tags(), ends)?;
    let Ok(message) = e6irc_proto::message::Message::parse(&line) else {
        return Some(line);
    };
    match message.command.to_ascii_uppercase().as_str() {
        "JOIN" => shared.joined.offer_keys(&message),
        "PART" => {
            let live = ends
                .irc_session_snapshot()
                .map(|session| session.channels)
                .unwrap_or_default();
            let names = ends.names();
            for channel in message
                .params
                .first()
                .map(|channels| channels.split(',').collect::<Vec<_>>())
                .unwrap_or_default()
            {
                if !live.iter().any(|joined| names.eq(joined, channel))
                    && shared.joined.forget(channel)
                {
                    ends.answer(
                        cmd.origin,
                        super::bnc_notice(
                            "*",
                            &format!(
                                "{channel}: no longer rejoined after a reconnect \
                                 (this session is not in it)"
                            ),
                        ),
                    );
                }
            }
        }
        _ => {}
    }
    Some(line)
}

/// The channel an upstream refused to let us join, when `message` is such a
/// refusal: it does not exist (403), or is full, invite-only, banned or keyed
/// (471, 473, 474, 475).
fn refused_join(message: &OwnedMessage) -> Option<&str> {
    matches!(
        message.command.as_str(),
        "403" | "471" | "473" | "474" | "475"
    )
    .then(|| e6irc_client::numeric_subject(message))
    .flatten()
}

/// The key change a channel `MODE` line makes: `+k <key>` sets it, `-k`
/// clears it. Which modes take a parameter is the network's to say
/// (`CHANMODES`, `PREFIX`), so the key's position is read with them.
fn key_change(message: &OwnedMessage, ends: &DriverEnds) -> Option<(String, Option<ChannelKey>)> {
    if !message.command.eq_ignore_ascii_case("MODE") {
        return None;
    }
    let [channel, modes, arguments @ ..] = message.params.as_slice() else {
        return None;
    };
    if !modes.contains('k') {
        return None;
    }
    let features = ends.upstream_features();
    let token = |name: &str| {
        features.isupport.iter().find_map(|token| {
            token
                .strip_prefix(name)
                .and_then(|rest| rest.strip_prefix('='))
                .map(str::to_string)
        })
    };
    let chanmodes = token("CHANMODES").unwrap_or_else(|| "beI,k,l,imnpst".to_string());
    let prefix = token("PREFIX").unwrap_or_else(|| "(ov)@+".to_string());
    let membership = prefix
        .strip_prefix('(')
        .and_then(|rest| rest.split_once(')'))
        .map_or("", |(modes, _)| modes);
    let mut kinds = chanmodes.split(',');
    let (always, parameter, when_set) = (
        kinds.next().unwrap_or(""),
        kinds.next().unwrap_or(""),
        kinds.next().unwrap_or(""),
    );
    let mut arguments = arguments.iter();
    let mut adding = true;
    let mut change = None;
    for mode in modes.chars() {
        match mode {
            '+' => adding = true,
            '-' => adding = false,
            mode => {
                let takes = always.contains(mode)
                    || parameter.contains(mode)
                    || membership.contains(mode)
                    || (adding && when_set.contains(mode));
                let argument = if takes { arguments.next() } else { None };
                if mode == 'k' {
                    change = Some(if adding {
                        argument.and_then(|key| ChannelKey::parse(key))
                    } else {
                        None
                    });
                }
            }
        }
    }
    Some((channel.clone(), change?))
}

fn dropped(failure: super::NetworkFailure) -> super::SessionOutcome {
    super::SessionOutcome::Dropped(failure)
}

/// The prefix the upstream shows other users for this session, as far as the
/// driver has seen it: the nick it registered (or was renamed to), and the
/// user and host from its own echoes. Until an echo reveals them, the user is
/// the configured one behind a `~` and the host is the server's name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SelfIdentity {
    pub(crate) nick: String,
    /// Verbatim, tilde included.
    pub(crate) user: String,
    pub(crate) host: String,
}

/// The widest `JOIN` line the wire allows: 512 bytes less the CRLF.
/// The answer to an upstream `PING`, fitted to the wire like every other
/// trailing parameter: a token the upstream padded to the line limit (or
/// past it, on a peer a tenant points at) would otherwise leave here as an
/// over-long line the upstream's framing discards whole, and then reaps the
/// link as unanswered.
fn pong_line(token: &str) -> String {
    let head = "PONG :";
    format!("{head}{}", crate::core::fit_trailing(head, token))
}

const JOIN_LINE_BUDGET: usize = 510;

/// `channels` as the fewest `JOIN` lines that fit the wire, names comma-joined
/// in order and keyed channels first, their keys in a second comma list: a
/// key is matched to its channel by position, so no unkeyed channel may come
/// before a keyed one on a line. One line per channel exceeded Solanum's flood
/// allowance on a reconnect with many channels, which it answers by closing
/// the link ("Excess Flood"); a comma list is one command to the flood
/// counter.
pub(super) fn join_lines(channels: &[(String, Option<ChannelKey>)]) -> Vec<String> {
    let render = |names: &[&str], keys: &[&str]| {
        if keys.is_empty() {
            format!("JOIN {}", names.join(","))
        } else {
            format!("JOIN {} {}", names.join(","), keys.join(","))
        }
    };
    let ordered = channels
        .iter()
        .filter(|(_, key)| key.is_some())
        .chain(channels.iter().filter(|(_, key)| key.is_none()));
    let mut lines = Vec::new();
    let (mut names, mut keys): (Vec<&str>, Vec<&str>) = (Vec::new(), Vec::new());
    for (channel, key) in ordered {
        let mut with_names = names.clone();
        with_names.push(channel);
        let mut with_keys = keys.clone();
        if let Some(key) = key {
            with_keys.push(key.as_str());
        }
        if !names.is_empty() && render(&with_names, &with_keys).len() > JOIN_LINE_BUDGET {
            lines.push(render(&names, &keys));
            names.clear();
            keys.clear();
            names.push(channel);
            keys.extend(key.as_ref().map(ChannelKey::as_str));
        } else {
            names = with_names;
            keys = with_keys;
        }
    }
    if !names.is_empty() {
        lines.push(render(&names, &keys));
    }
    lines
}

/// Build the self-echoes of a client command: one per target it names, as an
/// upstream echoes (and delivers) a message to each target separately — or
/// none when the command is not a message an upstream would echo. The prefix
/// is our current upstream identity (`nick!user@host` as the upstream shows
/// it, see [`SelfIdentity`]), valid client-only tags ride along exactly as a
/// real echo-message would return them, and a fresh authoritative `time=` tag
/// stamps when the bouncer accepted the line so backlog playback orders it
/// against upstream traffic. A target list is never one conversation: `#a,#b`
/// filed as a channel of that name would be in neither channel's history.
pub(super) fn self_echoes(line: &str, identity: &SelfIdentity) -> Vec<String> {
    let Ok(parsed) = e6irc_proto::message::Message::parse(line) else {
        return Vec::new();
    };
    let Some(targets) = parsed.params.first() else {
        return Vec::new();
    };
    targets
        .split(',')
        .filter(|target| !target.is_empty())
        .filter_map(|target| echo_of(line, Some(target), identity))
        .collect()
}

/// [`self_echo`] of a message as delivered to one `target` of its list: a
/// bridge delivers each target separately, and echoes each delivery that the
/// provider accepted on its own.
#[cfg(any(feature = "matrix", feature = "discord", feature = "slack"))]
pub(super) fn self_echo_to(line: &str, target: &str, identity: &SelfIdentity) -> Option<String> {
    echo_of(line, Some(target), identity)
}

/// The echo of `line`, to `to` in place of the targets the line names when
/// given.
fn echo_of(line: &str, to: Option<&str>, identity: &SelfIdentity) -> Option<String> {
    let parsed = e6irc_proto::message::Message::parse(line).ok()?;
    let prefix = format!(":{}!{}@{}", identity.nick, identity.user, identity.host);
    let body = match parsed.command.to_ascii_uppercase().as_str() {
        command @ ("PRIVMSG" | "NOTICE") => {
            let [target, text] = parsed.params.as_slice() else {
                return None;
            };
            let target = to.unwrap_or(target);
            if target.is_empty() || text.is_empty() {
                return None;
            }
            let head = format!("{prefix} {command} {target} :");
            let visible = if crate::sanitize::sensitive_service_command(target, text) {
                crate::sanitize::SENSITIVE_SERVICE_COMMAND_REDACTED
            } else {
                text
            };
            format!("{head}{}", crate::core::fit_trailing(&head, visible))
        }
        "TAGMSG" => {
            let [target] = parsed.params.as_slice() else {
                return None;
            };
            let target = to.unwrap_or(target);
            if target.is_empty() {
                return None;
            }
            format!("{prefix} TAGMSG {target}")
        }
        _ => return None,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_millis() as u64;
    let time = e6irc_proto::time::server_time(e6irc_proto::time::Millis::from_millis(now));
    let client_tags = crate::sanitize::client_tag_string(&parsed);
    let all_tags = if client_tags.is_empty() {
        format!("time={time}")
    } else {
        format!("time={time};{client_tags}")
    };
    let echo = format!("@{all_tags} {body}");
    e6irc_proto::message::server_frame_fits(echo.as_bytes()).then_some(echo)
}

/// What identifies a message's echo: its command, its one target (folded as
/// the network folds names) and its text. The upstream echoes a message to
/// several targets once per target, so a client's line has one key per
/// target.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EchoKey {
    command: String,
    target: String,
    text: String,
}

impl EchoKey {
    fn new(command: &str, target: &str, text: &str, names: &NetworkNames) -> Option<Self> {
        (!target.is_empty()).then(|| Self {
            command: command.to_string(),
            target: names.fold(target),
            text: text.to_string(),
        })
    }

    /// The keys of a message an attached client sent, one per target, when
    /// the upstream will echo it.
    fn of_client_line(line: &str, names: &NetworkNames) -> Vec<Self> {
        let Ok(parsed) = e6irc_proto::message::Message::parse(line) else {
            return Vec::new();
        };
        let command = parsed.command.to_ascii_uppercase();
        let (targets, text) = match (command.as_str(), parsed.params.as_slice()) {
            ("PRIVMSG" | "NOTICE", [targets, text]) if !text.is_empty() => (*targets, *text),
            ("TAGMSG", [targets]) => (*targets, ""),
            _ => return Vec::new(),
        };
        targets
            .split(',')
            .filter_map(|target| Self::new(&command, target, text, names))
            .collect()
    }

    /// The key of an upstream line when it is the echo of our own message,
    /// with the length of what precedes its text on the wire — which decides
    /// how much of a long text the upstream could echo.
    fn of_upstream_echo(
        message: &OwnedMessage,
        own_nick: &str,
        names: &NetworkNames,
    ) -> Option<(Self, usize)> {
        let source = message.source.as_deref()?;
        let nick = source.split_once('!').map_or(source, |(nick, _)| nick);
        if !names.eq(nick, own_nick) {
            return None;
        }
        let command = message.command.to_ascii_uppercase();
        let (target, text) = match (command.as_str(), message.params.as_slice()) {
            ("PRIVMSG" | "NOTICE", [target, text]) if !text.is_empty() => (target, text.as_str()),
            ("TAGMSG", [target]) => (target, ""),
            _ => return None,
        };
        // `:<source> <COMMAND> <target> :`
        let head = 1 + source.len() + 1 + command.len() + 1 + target.len() + 2;
        Some((Self::new(&command, target, text, names)?, head))
    }

    /// Whether this echo, `head` bytes before its text, is `sent` as the
    /// upstream cut it to fit one line: a server truncates a text that would
    /// not fit its line with our prefix, and echoes (and delivers) what is
    /// left.
    fn is_truncation_of(&self, sent: &Self, head: usize) -> bool {
        self.command == sent.command
            && self.target == sent.target
            && !self.text.is_empty()
            && self.text.len() < sent.text.len()
            && sent.text.starts_with(&self.text)
            && head + sent.text.len() + 2 > e6irc_proto::message::MAX_LINE_LEN
    }
}

/// Most lines awaiting their upstream echo. A line the upstream refuses is
/// never echoed, so its entry would wait forever; the oldest is dropped past
/// this bound, costing at most the routing of one late echo.
const MAX_PENDING_ECHOES: usize = 256;

/// The messages written upstream whose echo has not arrived yet, oldest
/// first, each with the attachment that sent it. An echo is matched to the
/// oldest entry with its key, so identical lines from two attachments are
/// echoed to each in the order they were sent.
#[derive(Default)]
struct PendingEchoes(std::collections::VecDeque<(EchoKey, u64)>);

impl PendingEchoes {
    fn push(&mut self, key: EchoKey, origin: u64) {
        if self.0.len() == MAX_PENDING_ECHOES {
            self.0.pop_front();
        }
        self.0.push_back((key, origin));
    }

    /// The attachment that sent the line `echo` echoes, when one is waiting:
    /// the same text, or failing that the text the upstream had to cut.
    fn take(&mut self, echo: &EchoKey, head: usize) -> Option<u64> {
        let position = self
            .0
            .iter()
            .position(|(pending, _)| pending == echo)
            .or_else(|| {
                self.0
                    .iter()
                    .position(|(pending, _)| echo.is_truncation_of(pending, head))
            })?;
        self.0.remove(position).map(|(_, origin)| origin)
    }
}

/// The echoes of an upstream with `echo-message`: its echo of our own message
/// is relayed as the one echo of the line, routed to the attachment that sent
/// it — by its label, or, when replies are told apart by order, by matching it
/// against the lines awaiting one. The `irc` and `local` drivers route them
/// here alike.
#[derive(Default)]
pub(super) struct UpstreamEchoes(PendingEchoes);

impl UpstreamEchoes {
    /// Await the echo of `line`, which attachment `origin` sent, once per
    /// target it names.
    pub(super) fn sent(&mut self, line: &str, origin: u64, names: &NetworkNames) {
        for key in EchoKey::of_client_line(line, names) {
            self.0.push(key, origin);
        }
    }

    /// Publish a session line of the upstream, as the echo of an attachment's
    /// line when it is one (`origin` is its label's attachment, when it had
    /// one), with a services command that can carry a secret redacted.
    pub(super) fn publish(
        &mut self,
        ends: &DriverEnds,
        message: &OwnedMessage,
        line: String,
        origin: Option<u64>,
        own_nick: &str,
        names: &NetworkNames,
    ) -> Result<super::SessionChange, super::ChannelLimitExceeded> {
        let Some((key, head)) = EchoKey::of_upstream_echo(message, own_nick, names) else {
            return ends.emit_session_line(line);
        };
        let origin = origin.or_else(|| self.0.take(&key, head));
        let line = redact_sensitive_echo(line, message);
        match origin {
            Some(origin) => ends.emit_session_echo(line, origin),
            None => ends.emit_session_line(line),
        }
    }
}

/// Most nick changes an attached client may have asked for that the upstream
/// has not confirmed. One it refuses (433, 432) is never confirmed, so the
/// oldest is dropped past this bound.
const MAX_REQUESTED_NICKS: usize = 8;

/// The nicknames attached clients asked this session for with `NICK`, oldest
/// first. The upstream's confirmation of one is the owner's own choice taking
/// effect; a rename to any other name was not asked for.
#[derive(Default)]
struct RequestedNicks(std::collections::VecDeque<String>);

impl RequestedNicks {
    /// Remember the nickname `line` asks for, when it is a `NICK`.
    fn observe(&mut self, line: &str) {
        let Ok(parsed) = e6irc_proto::message::Message::parse(line) else {
            return;
        };
        if !parsed.command.eq_ignore_ascii_case("NICK") {
            return;
        }
        let Some(nick) = parsed.params.first().filter(|nick| !nick.is_empty()) else {
            return;
        };
        if self.0.len() == MAX_REQUESTED_NICKS {
            self.0.pop_front();
        }
        self.0.push_back(nick.to_string());
    }

    /// Whether the upstream renaming this session to `nick` confirms a
    /// request. The request is consumed, with every older one it supersedes.
    fn confirms(&mut self, nick: &str, names: &NetworkNames) -> bool {
        match self
            .0
            .iter()
            .position(|requested| names.eq(requested, nick))
        {
            Some(position) => {
                self.0.drain(..=position);
                true
            }
            None => false,
        }
    }
}

/// The upstream's echo of our own message, with a services command that can
/// carry a secret replaced by the same redaction the synthesized echo uses:
/// the backlog must never hold the password the upstream reflected back.
fn redact_sensitive_echo(raw: String, message: &OwnedMessage) -> String {
    let [target, text] = message.params.as_slice() else {
        return raw;
    };
    let command = message.command.to_ascii_uppercase();
    if !matches!(command.as_str(), "PRIVMSG" | "NOTICE")
        || !crate::sanitize::sensitive_service_command(target, text)
    {
        return raw;
    }
    let tags = raw
        .strip_prefix('@')
        .and_then(|rest| rest.split_once(' '))
        .map(|(tags, _)| format!("@{tags} "))
        .unwrap_or_default();
    let source = message.source.as_deref().unwrap_or_default();
    format!(
        "{tags}:{source} {command} {target} :{}",
        crate::sanitize::SENSITIVE_SERVICE_COMMAND_REDACTED
    )
}

/// Idle gap before the driver sends a keepalive PING (and again before it
/// declares a silent upstream dead). A live server PINGs well within this, so a
/// quiet-but-alive connection never trips it; a half-open one is caught within
/// `2 × KEEPALIVE_IDLE`.
pub(crate) const KEEPALIVE_IDLE: Duration = Duration::from_secs(120);

/// `rotation` is where in the vetted list this attempt starts; see
/// [`super::rotate_addresses`].
async fn connect(config: &NetworkConfig, rotation: u64) -> std::io::Result<Connection> {
    // SSRF control: resolve the upstream address ourselves and dial a *vetted*
    // resolved IP directly, rather than handing the hostname to the OS resolver
    // inside `TcpStream::connect`. The creation-time literal check
    // (`upstream_addr_is_internal`) can't see where a *hostname* resolves, and a
    // bare `TcpStream::connect(host)` re-resolves — so a hostname pointing at
    // `169.254.169.254` (or a DNS rebind between creation and now) would reach an
    // internal target. Connecting to the specific vetted socket address closes
    // both: resolution can't differ between the check and the connect.
    let vetted = super::resolve_vetted(config.addr.as_str(), config.internal_upstreams).await?;
    if vetted.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "upstream address resolves only to addresses this server does not connect to \
             (internal or never an upstream)",
        ));
    }
    connect_resolved(config, super::rotate_addresses(vetted, rotation)).await
}

/// One write to the upstream, bounded by `deadline`; the timeout is an
/// `io::Error` like any other write failure, so every caller reads it as
/// [`super::NetworkFailure::UpstreamWriteFailed`].
async fn write_bounded(
    connection: &mut Connection,
    line: &str,
    deadline: Duration,
) -> std::io::Result<()> {
    tokio::time::timeout(deadline, connection.send_line(line))
        .await
        .unwrap_or_else(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the upstream stopped draining its socket; the write did not finish in time",
            ))
        })
}

async fn connect_resolved(
    config: &NetworkConfig,
    vetted: Vec<std::net::SocketAddr>,
) -> std::io::Result<Connection> {
    // Try every vetted result, from wherever the caller rotated the list to.
    // Public round robins commonly return both IPv6 and IPv4; selecting only
    // the first made a host without working IPv6 retry the same unreachable
    // address forever instead of reaching the IPv4 peer. Each concrete dial is
    // bounded so one black-holed address cannot consume the entire outer
    // connection deadline.
    let server_name = upstream_host(&config.addr)?;
    let mut last_error = std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "upstream resolved addresses were exhausted",
    );
    for address in vetted {
        let stream = match tokio::time::timeout(
            super::ADDRESS_DIAL_DEADLINE,
            tokio::net::TcpStream::connect(address),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                last_error = error;
                continue;
            }
            Err(_) => {
                last_error = std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "concrete upstream address timed out",
                );
                continue;
            }
        };
        let connected = if config.tls {
            match tokio::time::timeout(
                super::ADDRESS_DIAL_DEADLINE,
                Connection::from_tcp_tls(stream, server_name, e6irc_client::webpki_root_store()),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "TLS handshake to concrete upstream address timed out",
                )),
            }
        } else {
            Connection::from_tcp(stream)
        };
        match connected {
            Ok(connection) => return Ok(connection),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

fn upstream_host(addr: &str) -> std::io::Result<&str> {
    let (host, port) = if let Some(bracketed) = addr.strip_prefix('[') {
        let (host, suffix) = bracketed
            .split_once(']')
            .ok_or_else(invalid_upstream_addr)?;
        let port = suffix
            .strip_prefix(':')
            .filter(|port| !port.is_empty())
            .ok_or_else(invalid_upstream_addr)?;
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(invalid_upstream_addr());
        }
        (host, port)
    } else {
        let (host, port) = addr.rsplit_once(':').ok_or_else(invalid_upstream_addr)?;
        if host.contains(':') {
            return Err(invalid_upstream_addr());
        }
        (host, port)
    };
    if host.is_empty()
        || host
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'/' | b'[' | b']'))
        || port.parse::<u16>().ok().filter(|port| *port != 0).is_none()
    {
        return Err(invalid_upstream_addr());
    }
    Ok(host)
}

fn invalid_upstream_addr() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "upstream address must be host:port with a nonzero numeric port",
    )
}

/// Syntactic IRC upstream validation shared by configuration and HTTP mutation
/// paths. DNS and SSRF checks remain dial-time concerns.
pub(crate) fn validate_irc_upstream_addr(addr: &str) -> bool {
    upstream_host(addr).is_ok()
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    #[test]
    fn an_upstream_ping_token_is_answered_within_the_line_limit() {
        assert_eq!(pong_line("irc.example"), "PONG :irc.example");
        let padded = "a".repeat(600);
        let pong = pong_line(&padded);
        assert_eq!(pong.len(), 510, "PONG + CRLF must fit 512 bytes");
        assert!(pong.starts_with("PONG :aaaa"));
        // Cut on a character boundary, never inside a multi-byte sequence.
        let wide = "é".repeat(400);
        let pong = pong_line(&wide);
        assert!(pong.len() <= 510);
        assert!(std::str::from_utf8(pong.as_bytes()).is_ok());
    }

    /// A hostname is judged where it resolves. `localhost` resolves to loopback
    /// only, which the default policy refuses and the operator's allowance
    /// admits; the always-refused classes are dropped under both.
    #[tokio::test]
    async fn a_hostname_is_judged_by_what_it_resolves_to() {
        use crate::egress::InternalUpstreams;
        let refused = super::super::resolve_vetted("localhost:6667", InternalUpstreams::Refuse)
            .await
            .expect("resolution itself succeeds");
        assert!(refused.is_empty(), "{refused:?}");
        let allowed = super::super::resolve_vetted("localhost:6667", InternalUpstreams::Allow)
            .await
            .expect("resolution itself succeeds");
        assert!(
            allowed.iter().all(|address| address.ip().is_loopback()),
            "{allowed:?}"
        );
        assert!(!allowed.is_empty());
        let never = super::super::resolve_vetted("169.254.169.254:80", InternalUpstreams::Allow)
            .await
            .expect("a literal resolves to itself");
        assert!(never.is_empty(), "{never:?}");
    }

    #[test]
    fn upstream_tls_host_handles_dns_and_bracketed_ipv6() {
        assert_eq!(
            upstream_host("irc.libera.chat:6697").expect("DNS host"),
            "irc.libera.chat"
        );
        assert_eq!(
            upstream_host("[2001:db8::1]:6697").expect("IPv6"),
            "2001:db8::1"
        );
        assert!(upstream_host("missing-port").is_err());
        assert!(upstream_host("irc.example:not-a-port").is_err());
        assert!(upstream_host("irc.example:0").is_err());
        assert!(upstream_host("2001:db8::1:6697").is_err());
        assert!(upstream_host("[irc.example]:6697").is_err());
    }

    /// A peer that stops draining its socket makes every write block once the
    /// kernel buffers fill. The bound turns that into a write failure the
    /// session loop ends on, instead of a driver held for as long as the
    /// kernel keeps the connection.
    #[tokio::test]
    async fn a_write_the_peer_never_drains_fails_at_the_deadline() {
        let server = tokio::net::TcpSocket::new_v4().unwrap();
        server.set_recv_buffer_size(4096).unwrap();
        server.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = server.listen(1).unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::net::TcpSocket::new_v4().unwrap();
        client.set_send_buffer_size(4096).unwrap();
        let stream = client.connect(address).await.unwrap();
        // Accepted and then never read from.
        let (_held, _) = listener.accept().await.unwrap();
        let mut connection = Connection::from_tcp(stream).unwrap();
        let line = format!("PRIVMSG #room :{}", "x".repeat(400));
        let outcome = tokio::time::timeout(Duration::from_secs(5), async {
            for _ in 0..100_000 {
                if let Err(error) =
                    write_bounded(&mut connection, &line, Duration::from_millis(200)).await
                {
                    return error;
                }
            }
            panic!("100k lines were accepted by a peer that never reads");
        })
        .await
        .expect("the bounded write returned within the test budget");
        assert_eq!(outcome.kind(), std::io::ErrorKind::TimedOut, "{outcome}");
    }

    fn confirmed(names: &[String]) -> super::super::SessionChange {
        super::super::SessionChange {
            joined: names
                .iter()
                .map(|name| {
                    super::super::upstream_identity::ConfirmedChannel::parse(
                        name,
                        &NetworkNames::default(),
                    )
                    .expect("test channel")
                })
                .collect(),
            ..Default::default()
        }
    }

    fn owned(line: &str) -> OwnedMessage {
        OwnedMessage::from(&e6irc_proto::message::Message::parse(line).expect("test line"))
    }

    /// A message to several targets is echoed by the upstream once per
    /// target, so it waits for one echo per target, and a bouncer-made echo
    /// is one per target too: never one line to a conversation named `#a,#b`.
    #[test]
    fn a_message_to_several_targets_is_echoed_per_target() {
        let names = NetworkNames::default();
        let mut pending = PendingEchoes::default();
        for key in EchoKey::of_client_line("PRIVMSG #a,#B :hi", &names) {
            pending.push(key, 7);
        }
        for echo in [":alice!u@h PRIVMSG #a :hi", ":alice!u@h PRIVMSG #b :hi"] {
            let (key, head) =
                EchoKey::of_upstream_echo(&owned(echo), "alice", &names).expect("our echo");
            assert_eq!(pending.take(&key, head), Some(7), "{echo}");
        }
        let echoes = self_echoes("PRIVMSG #a,#b :hi", &alice());
        assert_eq!(echoes.len(), 2, "{echoes:?}");
        assert!(echoes[0].ends_with(" PRIVMSG #a :hi"), "{echoes:?}");
        assert!(echoes[1].ends_with(" PRIVMSG #b :hi"), "{echoes:?}");
    }

    /// An upstream cuts a text that does not fit its line with our prefix,
    /// and echoes what is left: that echo is still the echo of the line sent.
    /// A shorter text that is not a cut is not mistaken for one.
    #[test]
    fn an_echo_the_upstream_truncated_is_still_the_lines_echo() {
        let names = NetworkNames::default();
        let text = "x".repeat(480);
        let mut pending = PendingEchoes::default();
        for key in EchoKey::of_client_line(&format!("PRIVMSG #room :{text}"), &names) {
            pending.push(key, 7);
        }
        for key in EchoKey::of_client_line("PRIVMSG #room :hello world", &names) {
            pending.push(key, 8);
        }
        let short = ":alice!~alice@host.example PRIVMSG #room :hello";
        let (key, head) =
            EchoKey::of_upstream_echo(&owned(short), "alice", &names).expect("our echo");
        assert_eq!(
            pending.take(&key, head),
            None,
            "hello is not a cut of hello world"
        );
        let prefix = ":alice!~alice@host.example PRIVMSG #room :";
        let cut = format!("{prefix}{}", &text[..510 - prefix.len()]);
        let (key, head) =
            EchoKey::of_upstream_echo(&owned(&cut), "alice", &names).expect("our echo");
        assert_eq!(pending.take(&key, head), Some(7));
    }

    /// A keyed channel is rejoined with its key, from the client's JOIN and
    /// from a later `+k`; a `-k` forgets it; keyed channels lead each JOIN
    /// line so every key lands on its channel.
    #[test]
    fn a_keyed_channel_is_rejoined_with_its_key() {
        let names = NetworkNames::default();
        let joined = JoinedChannels::default();
        let join = e6irc_proto::message::Message::parse("JOIN #priv,#open,#other hunter2")
            .expect("a JOIN");
        joined.offer_keys(&join);
        joined
            .apply(
                confirmed(&["#open".into(), "#Priv".into(), "#other".into()]),
                &names,
            )
            .expect("fits");
        let rejoin = joined.rejoin(&[]);
        let keyed: Vec<(&str, Option<&str>)> = rejoin
            .iter()
            .map(|(channel, key)| (channel.as_str(), key.as_ref().map(ChannelKey::as_str)))
            .collect();
        assert!(keyed.contains(&("#Priv", Some("hunter2"))), "{keyed:?}");
        assert!(keyed.contains(&("#open", None)), "{keyed:?}");
        let lines = join_lines(&rejoin);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("JOIN #Priv,"), "{lines:?}");
        assert!(lines[0].ends_with(" hunter2"), "{lines:?}");

        joined.set_key("#open", ChannelKey::parse("newkey"));
        joined.set_key("#priv", None);
        let rejoin = joined.rejoin(&[]);
        let line = &join_lines(&rejoin)[0];
        assert!(
            line.starts_with("JOIN #open,") && line.ends_with(" newkey"),
            "{line}"
        );
        assert!(!line.contains("hunter2"), "{line}");
        assert!(
            !format!("{rejoin:?}").contains("newkey"),
            "keys are never shown"
        );

        assert!(joined.forget("#PRIV"));
        assert!(!joined.forget("#priv"), "gone");
        assert!(
            joined
                .rejoin(&[])
                .iter()
                .all(|(channel, _)| channel != "#Priv")
        );
    }

    /// A configured key joins its channel after every connect, including the
    /// first one after a restart, when nothing was learned yet; a key seen
    /// since (a `+k`) is the one the channel is rejoined with.
    #[test]
    fn a_configured_key_joins_its_channel_until_another_is_seen() {
        let configured: Vec<AutojoinChannel> = ["#staff hunter2", "#open"]
            .iter()
            .map(|entry| entry.parse().expect("an autojoin entry"))
            .collect();
        let joined = JoinedChannels::default();
        let rejoin = joined.rejoin(&configured);
        assert_eq!(join_lines(&rejoin), ["JOIN #staff,#open hunter2"]);
        joined
            .apply(
                confirmed(&["#staff".into(), "#open".into()]),
                &NetworkNames::default(),
            )
            .expect("fits");
        joined.set_key("#STAFF", ChannelKey::parse("rotated"));
        assert_eq!(
            join_lines(&joined.rejoin(&configured)),
            ["JOIN #staff,#open rotated"]
        );
        assert!(!format!("{configured:?}").contains("hunter2"));
    }

    /// A key's place among a MODE line's parameters is decided by which modes
    /// take one, as the network's CHANMODES and PREFIX say.
    #[test]
    fn a_key_is_read_from_a_mode_line_with_the_networks_chanmodes() {
        let (_handle, ends) = NetworkHandle::channels(4);
        ends.begin_irc_session("me".into());
        ends.emit_session_line(
            ":s 005 me CHANMODES=beIq,k,fl,imnst PREFIX=(ov)@+ :are supported by this server"
                .into(),
        )
        .expect("tracked");
        let mode = |line: &str| {
            key_change(&owned(line), &ends)
                .map(|(channel, key)| (channel, key.map(|key| key.as_str().to_string())))
        };
        assert_eq!(
            mode(":op!u@h MODE #c +bfok ban!*@* 5 nick secret"),
            Some(("#c".to_string(), Some("secret".to_string())))
        );
        assert_eq!(
            mode(":op!u@h MODE #c -lk *"),
            Some(("#c".to_string(), None))
        );
        assert_eq!(mode(":op!u@h MODE #c +o nick"), None);
    }

    #[test]
    fn many_keyed_channels_take_several_lines_each_within_the_limit() {
        let key = ChannelKey::parse(&"k".repeat(40)).expect("a key");
        let channels: Vec<(String, Option<ChannelKey>)> = (0..20)
            .map(|index| (format!("#keyed-channel-{index:02}"), Some(key.clone())))
            .chain((0..20).map(|index| (format!("#open-{index:02}"), None)))
            .collect();
        let lines = join_lines(&channels);
        assert!(lines.len() > 1);
        for line in &lines {
            assert!(line.len() <= JOIN_LINE_BUDGET, "{line}");
            let mut parts = line.split(' ');
            assert_eq!(parts.next(), Some("JOIN"));
            let names: Vec<&str> = parts.next().expect("channels").split(',').collect();
            let keys: Vec<&str> = parts
                .next()
                .map_or_else(Vec::new, |keys| keys.split(',').collect());
            assert!(
                names[..keys.len()]
                    .iter()
                    .all(|name| name.starts_with("#keyed")),
                "a key would land on an unkeyed channel: {line}"
            );
        }
        let joined: usize = lines
            .iter()
            .map(|line| line.split(' ').nth(1).expect("channels").split(',').count())
            .sum();
        assert_eq!(joined, 40);
    }

    /// The intent is kept across sessions, so a hostile upstream confirming a
    /// different set on each one must hit the same bound the tracker has.
    #[test]
    fn reconnect_intent_is_bounded_across_sessions_and_follows_departures() {
        let joined = JoinedChannels::default();
        let first: Vec<String> = (0..super::super::MAX_TRACKED_CHANNELS)
            .map(|index| format!("#session-one-{index}"))
            .collect();
        joined
            .apply(confirmed(&first), &NetworkNames::default())
            .expect("a full set fits");
        // Re-confirming a rejoined channel on the next session is not growth.
        joined
            .apply(
                confirmed(&["#SESSION-ONE-0".to_string()]),
                &NetworkNames::default(),
            )
            .expect("already intended");
        assert_eq!(
            joined.apply(
                confirmed(&["#session-two-0".to_string()]),
                &NetworkNames::default()
            ),
            Err(super::super::ChannelLimitExceeded)
        );
        assert_eq!(
            joined.0.lock().expect("joined set").channels.len(),
            super::super::MAX_TRACKED_CHANNELS
        );

        joined
            .apply(
                super::super::SessionChange {
                    left: vec!["#session-one-1".to_string()],
                    ..Default::default()
                },
                &NetworkNames::default(),
            )
            .expect("a departure cannot exceed the limit");
        joined
            .apply(
                confirmed(&["#session-two-0".to_string()]),
                &NetworkNames::default(),
            )
            .expect("the departure made room");
    }

    /// Register the real client, with SASL configured, against an upstream that
    /// answers each expected line prefix with its scripted reply, and return
    /// the driver's reading of how that ended.
    pub(in crate::bouncer) async fn sasl_outcome_against(
        script: &'static [(&'static str, &'static str)],
    ) -> Result<String, super::super::SessionOutcome> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let upstream = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = socket.into_split();
            let mut lines = tokio::io::BufReader::new(reader).lines();
            for (expected, reply) in script {
                let line = lines.next_line().await.unwrap().expect("driver line");
                assert!(line.starts_with(expected), "{line:?} is not {expected:?}");
                if !reply.is_empty() {
                    writer
                        .write_all(format!("{reply}\r\n").as_bytes())
                        .await
                        .unwrap();
                }
            }
            // Hold the socket: the outcome must come from what was said.
            while lines.next_line().await.unwrap().is_some() {}
        });
        let mut connection = Connection::connect(&address).await.unwrap();
        let outcome = registration_outcome(
            tokio::time::timeout(
                Duration::from_secs(5),
                connection.register_sasl(
                    &e6irc_client::Identity {
                        nick: "bncbot",
                        username: "bncbot",
                        realname: "real",
                        server_password: None,
                    },
                    "account",
                    "secret",
                ),
            )
            .await,
        );
        drop(connection);
        upstream.await.expect("scripted upstream");
        outcome
    }

    /// The scenario that parked a correctly configured network: the upstream
    /// offers SASL, but not the mechanism the driver speaks.
    #[tokio::test]
    async fn a_missing_sasl_mechanism_is_a_worded_refusal_not_rejected_credentials() {
        let outcome = sasl_outcome_against(&[(
            "CAP LS",
            ":up CAP * LS :sasl=EXTERNAL,ECDSA-NIST256P-CHALLENGE",
        )])
        .await;
        let Err(super::super::SessionOutcome::RegistrationRejected(rejection)) = outcome else {
            panic!("a mechanism the upstream does not offer is not a credential rejection");
        };
        assert_eq!(
            rejection.refusal(),
            e6irc_client::RegistrationRefusal::SaslUnavailable
        );
        assert_eq!(
            rejection.diagnostic(),
            "requested one of SCRAM-SHA-512, SCRAM-SHA-256, PLAIN; the server offers EXTERNAL,ECDSA-NIST256P-CHALLENGE"
        );
    }

    #[tokio::test]
    async fn rejected_credentials_keep_the_upstream_reason() {
        let outcome = sasl_outcome_against(&[
            ("CAP LS", ":up CAP * LS :sasl=PLAIN"),
            ("CAP REQ :sasl", ":up CAP * ACK :sasl"),
            ("AUTHENTICATE PLAIN", "AUTHENTICATE +"),
            ("NICK ", ""),
            ("USER ", ""),
            ("AUTHENTICATE ", ":up 904 * :Invalid password for account"),
        ])
        .await;
        let Err(super::super::SessionOutcome::AuthRejected(Some(rejection))) = outcome else {
            panic!("a 904 for an offered mechanism is a credential rejection");
        };
        assert_eq!(rejection.diagnostic(), "Invalid password for account");
    }

    #[test]
    fn generic_registration_error_is_not_mislabeled_as_a_server_refusal() {
        let error = std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "server refused registration",
        );
        assert!(matches!(
            registration_outcome(Ok(Err(error))),
            Err(super::super::SessionOutcome::Dropped(
                super::super::NetworkFailure::RegistrationFailed
            ))
        ));
    }

    /// A server that never answered in time is retried as a timeout. Reported
    /// as the server lacking SASL, it sent the owner looking for a missing
    /// capability that Libera does offer once its ident check is done.
    #[test]
    fn a_server_that_answered_too_late_is_a_registration_timeout() {
        let error = std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "the server did not answer capability negotiation within 20 s",
        );
        assert!(matches!(
            registration_outcome(Ok(Err(error))),
            Err(super::super::SessionOutcome::Dropped(
                super::super::NetworkFailure::RegistrationTimedOut
            ))
        ));
    }

    /// The one echo of a single-target line.
    fn self_echo(line: &str, identity: &SelfIdentity) -> Option<String> {
        let mut echoes = self_echoes(line, identity);
        assert!(echoes.len() <= 1, "one target, one echo: {echoes:?}");
        echoes.pop()
    }

    /// The identity every echo test speaks as, before any echo revealed more.
    fn alice() -> SelfIdentity {
        SelfIdentity {
            nick: "alice".into(),
            user: "~alice".into(),
            host: "irc.example".into(),
        }
    }

    #[test]
    fn self_echo_mints_provenance_and_keeps_only_valid_client_tags() {
        let echo = self_echo(
            "@time=forged;msgid=forged;+typing=old;+typing=active;+bad.foo=x PRIVMSG #room :hello",
            &alice(),
        )
        .expect("message has an echo");
        let parsed = e6irc_proto::message::Message::parse(&echo).expect("valid echo");
        assert_eq!(
            parsed.tags.iter().filter(|tag| tag.key == "time").count(),
            1
        );
        assert_ne!(
            parsed.tag("time").and_then(|tag| tag.value.as_deref()),
            Some("forged")
        );
        assert_eq!(parsed.tag("msgid"), None);
        assert_eq!(
            parsed.tag("+typing").and_then(|tag| tag.value.as_deref()),
            Some("active")
        );
        assert_eq!(parsed.tag("+bad.foo"), None);
        assert!(echo.ends_with(" PRIVMSG #room :hello"), "{echo}");
    }

    #[test]
    fn self_echo_adds_a_prefix_without_exceeding_the_wire_budget() {
        let line = format!("privmsg #room :{}é", "x".repeat(490));
        assert!(e6irc_proto::message::client_frame_fits(line.as_bytes()));
        let echo = self_echo(&line, &alice()).expect("a valid message has a bounded echo");
        assert!(e6irc_proto::message::server_frame_fits(echo.as_bytes()));
        assert!(echo.contains(" PRIVMSG #room :"));
        assert!(
            !echo.ends_with('é'),
            "the multi-byte boundary is not split: {echo}"
        );
        e6irc_proto::message::Message::parse(&echo).expect("echo remains valid IRC");
    }

    #[test]
    fn self_echo_never_retains_nickserv_credentials_or_verification_tokens() {
        for line in [
            "PRIVMSG NickServ :REGISTER correct-horse alice@example.test",
            "PRIVMSG nickserv@services.example :IDENTIFY alice correct-horse",
            "NOTICE NS :VERIFY REGISTER alice mail-token",
            "PRIVMSG NickServ :SET PASSWORD replacement-secret",
            "PRIVMSG NickServ :SETPASS alice reset-code replacement-secret",
            "PRIVMSG NickServ :RESETPASS alice reset-code",
            "PRIVMSG Q@CServe.quakenet.org :AUTH alice correct-horse",
            "PRIVMSG X@channels.undernet.org :LOGIN alice correct-horse",
            "PRIVMSG AuthServ :AUTH alice correct-horse",
        ] {
            let echo = self_echo(line, &alice())
                .expect("service message still has a visible redacted echo");
            assert!(
                echo.contains(crate::sanitize::SENSITIVE_SERVICE_COMMAND_REDACTED),
                "{echo}"
            );
            for secret in [
                "correct-horse",
                "alice@example.test",
                "mail-token",
                "replacement-secret",
                "reset-code",
            ] {
                assert!(!echo.contains(secret), "{echo}");
            }
        }
        let help = self_echo("PRIVMSG NickServ :HELP REGISTER", &alice())
            .expect("non-sensitive help is echoed");
        assert!(help.ends_with("PRIVMSG NickServ :HELP REGISTER"), "{help}");
    }

    #[test]
    fn self_echo_rejects_commands_the_upstream_would_not_echo() {
        assert!(self_echo("PRIVMSG #room", &alice()).is_none());
        assert!(self_echo("PRIVMSG #room :", &alice()).is_none());
        assert!(self_echo("TAGMSG", &alice()).is_none());
        assert!(self_echo("PING :token", &alice()).is_none());
    }

    #[test]
    fn only_a_requested_nick_is_a_confirmation() {
        let mut requested = RequestedNicks::default();
        requested.observe("PRIVMSG #room :NICK chosen");
        assert!(
            !requested.confirms("chosen", &NetworkNames::default()),
            "not a NICK command"
        );
        requested.observe("nick First");
        requested.observe("NICK :second");
        assert!(
            requested.confirms("SECOND", &NetworkNames::default()),
            "casefolded, either form"
        );
        assert!(
            !requested.confirms("first", &NetworkNames::default()),
            "an older request is superseded by the one confirmed after it"
        );
        assert!(
            !requested.confirms("enforced", &NetworkNames::default()),
            "never asked for"
        );
        for n in 0..=MAX_REQUESTED_NICKS {
            requested.observe(&format!("NICK refused{n}"));
        }
        assert!(
            !requested.confirms("refused0", &NetworkNames::default()),
            "the oldest is dropped"
        );
        assert!(requested.confirms(
            &format!("refused{MAX_REQUESTED_NICKS}"),
            &NetworkNames::default()
        ));
    }

    async fn assert_live_driver(network: &str, addr: &str, autojoin: &[&str]) {
        for attempt in 0..2 {
            let nick = format!("e6b{:04}{attempt}", std::process::id() % 10000);
            let handle = IrcNetwork::start(NetworkConfig {
                addr: addr.into(),
                tls: true,
                nick: nick.parse().expect("probe nickname"),
                realname: "e6irc BNC interop probe".parse().expect("test real name"),
                buffer_cap: 32,
                autojoin: autojoin
                    .iter()
                    .map(|channel| channel.parse().expect("probe channel"))
                    .collect(),
                internal_upstreams: crate::egress::InternalUpstreams::Allow,
                ..NetworkConfig::default()
            });
            let connected = tokio::time::timeout(Duration::from_secs(35), async {
                loop {
                    let runtime = handle.runtime_snapshot();
                    if runtime.lifecycle == super::super::NetworkLifecycle::Connected {
                        break runtime;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{network} driver did not connect: {:?}",
                    handle.runtime_snapshot()
                )
            });
            assert!(connected.connect_latency_ms.is_some());
            assert!(connected.lines_in > 0, "{connected:?}");
            assert_eq!(connected.last_error, None, "{connected:?}");
            if let Some(channel) = autojoin.first() {
                tokio::time::timeout(Duration::from_secs(15), async {
                    loop {
                        if handle
                            .buffer_snapshot()
                            .iter()
                            .any(|line| line.contains(channel))
                        {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                })
                .await
                .unwrap_or_else(|_| {
                    panic!("{network} did not receive channel traffic for {channel}")
                });
            }
            handle.shutdown();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "live network: twice registers, joins #libera, and reads traffic from Libera.Chat"]
    async fn live_driver_connects_to_libera() {
        assert_live_driver("Libera.Chat", "irc.libera.chat:6697", &["#libera"]).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "live network: twice connects the BNC driver to OFTC"]
    async fn live_driver_connects_to_oftc() {
        assert_live_driver("OFTC", "irc.oftc.net:6697", &[]).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "live network: twice connects the BNC driver to the Ergo test network"]
    async fn live_driver_connects_to_ergo() {
        assert_live_driver("Ergo", "testnet.ergo.chat:6697", &[]).await;
    }
}
