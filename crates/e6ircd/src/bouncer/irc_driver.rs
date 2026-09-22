//! The `irc` network driver: a persistent outbound IRCv3 client
//! connection to an external network, reusing `e6irc-client`. Runs on
//! its own task with auto-reconnect (exponential backoff + jitter);
//! emits [`DriverEvent`]s and accepts raw command lines.

use std::time::Duration;
use std::time::Instant;

use e6irc_client::{Connection, RelayEvent};

use super::upstream_identity::{UpstreamChannel, UpstreamNick, UpstreamRealname, UpstreamUsername};
use super::{ConnectionEvent, DriverEnds, NetworkHandle};

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
    /// Channels to auto-join after registering.
    pub autojoin: Vec<UpstreamChannel>,
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

/// State that survives one driver's reconnects: the set of channels the
/// upstream has confirmed us in, keyed by RFC1459-folded name with the
/// server's canonical casing as the value. `connect_once` joins the
/// configured autojoin plus everything here, so channels joined at runtime
/// (not just the static config) are restored after a drop — the behaviour
/// ZNC/soju users rely on. In-memory only: a process restart legitimately
/// falls back to the configured autojoin, which is the operator-declared
/// floor.
#[derive(Debug, Default)]
pub struct JoinedChannels(
    std::sync::Mutex<std::collections::HashMap<String, super::upstream_identity::ConfirmedChannel>>,
);

impl JoinedChannels {
    /// Fold one line's membership change into the reconnect intent. The intent
    /// outlives sessions, so it carries the tracker's bound itself: successive
    /// sessions could otherwise each confirm a different full set.
    fn apply(&self, change: super::SessionChange) -> Result<(), super::ChannelLimitExceeded> {
        let casemap = e6irc_proto::casemap::CaseMapping::Rfc1459;
        let mut desired = self.0.lock().expect("joined set poisoned");
        for left in &change.left {
            desired.remove(left);
        }
        for channel in change.joined {
            let key = casemap.casefold(channel.as_str());
            if !desired.contains_key(&key) && desired.len() >= super::MAX_TRACKED_CHANNELS {
                return Err(super::ChannelLimitExceeded);
            }
            desired.insert(key, channel);
        }
        Ok(())
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
        Ok(Ok(welcomed)) => configured_nick_was_granted(config.nick.as_str(), welcomed)
            .map_err(|rejection| preflight_refusal(Some(rejection))),
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
async fn say_goodbye(connection: &mut Connection, reason: &str, who: &str) {
    match tokio::time::timeout(
        GOODBYE_DEADLINE,
        connection.send_line(&format!("QUIT :{reason}")),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!("{who}: quit failed: {error}"),
        Err(_) => eprintln!("{who}: quit timed out"),
    }
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
    configured: &str,
    welcomed: String,
) -> Result<String, e6irc_client::RegistrationRejection> {
    if e6irc_proto::casemap::CaseMapping::Rfc1459.eq(configured, &welcomed) {
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
    let current_nick = match configured_nick_was_granted(config.nick.as_str(), welcomed) {
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
    // us in before the drop (runtime joins are tracked in `shared.joined`).
    // Autojoin wins on a fold-collision: its casing is the operator's.
    let rejoin: Vec<String> = {
        let mut list: Vec<String> = config.autojoin.iter().map(ToString::to_string).collect();
        let casemap = e6irc_proto::casemap::CaseMapping::Rfc1459;
        let folded: std::collections::HashSet<String> = config
            .autojoin
            .iter()
            .map(|c| casemap.casefold(c.as_str()))
            .collect();
        let extras: Vec<String> = shared
            .joined
            .0
            .lock()
            .expect("joined set poisoned")
            .iter()
            .filter(|(key, _)| !folded.contains(*key))
            .map(|(_, display)| display.as_str().to_string())
            .collect();
        list.extend(extras);
        list
    };
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
    ends.begin_irc_session(identity.nick.clone());
    ends.emit(ConnectionEvent::Connected);
    // The mechanism is the client's choice among what the network offered, so
    // the owner is told which one carried the password — and which ones the
    // network refused before any credential was sent, so a weaker one that is
    // used instead is never a silent choice.
    for note in conn.sasl_notes() {
        ends.emit_line(format!(":*bnc* NOTICE * :upstream SASL: {note}"));
    }
    if let (Some(mechanism), Some((account, _))) = (conn.sasl_mechanism(), &config.sasl) {
        ends.emit_line(format!(
            ":*bnc* NOTICE * :upstream logged in as {account} with SASL {mechanism}"
        ));
    }
    // With `echo-message` the upstream echoes each message it accepts, and
    // only those: its echo is relayed as the one echo of the line. Without it
    // the driver synthesizes the echo when it writes the line.
    let upstream_echoes = conn.enabled("echo-message");
    let mut pending_echoes = PendingEchoes::default();

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
                    // Keepalive filtering applies only to lines we could parse;
                    // a line that didn't parse (a non-UTF-8 body, say) is never
                    // a PING and is simply relayed. A bad line must not drop the
                    // link — it is delivered, not fatal.
                    if let Some(m) = &parsed {
                        // Answer PINGs transparently (keepalive is the
                        // driver's job, not the attached client's).
                        if m.command == "PING" {
                            let token = m.params.first().cloned().unwrap_or_default();
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
                        if m.command == "PONG"
                            && m.params.last().map(String::as_str) == Some("e6bnc-keepalive")
                        {
                            continue;
                        }
                        // Capabilities are negotiated hop by hop. `CAP NEW` and
                        // `CAP DEL` describe this driver's negotiation with the
                        // upstream; an attached client negotiated with the
                        // bouncer and would act on them against the wrong hop.
                        // There is no separate server-log stream to keep them
                        // in, so they end here.
                        if m.command == "CAP" {
                            continue;
                        }
                        // The upstream is closing the link and says why. To an
                        // attached client `ERROR` means *its* connection is
                        // over, and replayed from the backlog days later it
                        // would mean it again; the reason is kept as this
                        // drop's diagnostic and said as a notice instead.
                        if m.command == "ERROR" {
                            let closed = super::LinkClosed::new(
                                m.params.last().map(String::as_str).unwrap_or("no reason given"),
                            );
                            ends.emit_line(format!(
                                ":*bnc* NOTICE * :upstream closed the link: {}",
                                closed.diagnostic()
                            ));
                            return super::SessionOutcome::ClosedByUpstream(closed);
                        }
                    }
                    // The upstream's own line: attached clients and the detached
                    // buffer get what the network sent, tags and all. `attach`
                    // strips the tags a client did not negotiate.
                    //
                    // A send with zero subscribers is fine — the driver
                    // is always-on regardless of attach.
                    //
                    // QUIT clears live membership for attached-client state, but
                    // the reconnect intent survives a transport drop: only a
                    // confirmed JOIN/PART/KICK changes it, so an unrelated
                    // numeric cannot erase channels still awaiting confirmation
                    // on this new session.
                    // Our own message, echoed by the upstream: the echo of the
                    // line an attachment sent, routed to it.
                    let echo = parsed
                        .as_ref()
                        .filter(|_| upstream_echoes)
                        .and_then(|message| EchoKey::of_upstream_echo(message, &identity.nick))
                        .map(|key| (key, parsed.as_ref()));
                    let (raw, origin) = match echo {
                        Some((key, Some(message))) => (
                            redact_sensitive_echo(raw, message),
                            pending_echoes.take(&key),
                        ),
                        _ => (raw, None),
                    };
                    let emitted = match origin {
                        Some(origin) => ends.emit_session_echo(raw, origin),
                        None => ends.emit_session_line(raw),
                    };
                    let tracked = emitted.and_then(|mut change| {
                        if let Some(shown) = change.shown_identity.take() {
                            if let Some(user) = shown.user {
                                identity.user = user;
                            }
                            identity.host = shown.host;
                        }
                        if let Some(nick) = change.nick.take() {
                            // Tracked, so the session goes on under it — and
                            // announced, because it is a name the owner did
                            // not choose (a services enforcer, typically).
                            ends.record_error_with_upstream_detail(
                                super::NetworkFailure::RenamedByUpstream,
                                &format!(
                                    "upstream renamed this session from {} to {nick}",
                                    identity.nick
                                ),
                            );
                            identity.nick = nick;
                        }
                        shared.joined.apply(change)
                    });
                    if tracked.is_err() {
                        return dropped(super::NetworkFailure::ChannelLimitExceeded);
                    }
                }
                Some(Ok(Some(RelayEvent::Rejected(rejected)))) => {
                    awaiting_keepalive = false;
                    silence.restart();
                    // Keep the upstream connection alive, but make the whole-line
                    // loss visible to attached clients and the detached buffer.
                    // A syntactically valid local NOTICE is bounded independently
                    // of the rejected payload and cannot itself be discarded.
                    ends.emit_line(format!(
                        ":e6irc NOTICE * :upstream input rejected: {rejected}"
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
                    if write_bounded(&mut conn, &cmd.line, super::UPSTREAM_WRITE_DEADLINE)
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
                    // the echo manufactured here.
                    if upstream_echoes {
                        if let Some(key) = EchoKey::of_client_line(&cmd.line) {
                            pending_echoes.push(key, cmd.origin);
                        }
                    } else if let Some(echo) = self_echo(&cmd.line, &identity) {
                        ends.emit_echo(echo, cmd.origin);
                    }
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

fn dropped(failure: super::NetworkFailure) -> super::SessionOutcome {
    super::SessionOutcome::Dropped(failure)
}

/// The prefix the upstream shows other users for this session, as far as the
/// driver has seen it: the nick it registered (or was renamed to), and the
/// user and host from its own echoes. Until an echo reveals them, the user is
/// the configured one behind a `~` and the host is the server's name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SelfIdentity {
    pub(super) nick: String,
    /// Verbatim, tilde included.
    pub(super) user: String,
    pub(super) host: String,
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
/// in order. One line per channel exceeded Solanum's flood allowance on a
/// reconnect with many channels, which it answers by closing the link ("Excess
/// Flood"); a comma list is one command to the flood counter.
pub(super) fn join_lines(channels: &[String]) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for channel in channels {
        match lines.last_mut() {
            Some(line) if line.len() + 1 + channel.len() <= JOIN_LINE_BUDGET => {
                line.push(',');
                line.push_str(channel);
            }
            _ => lines.push(format!("JOIN {channel}")),
        }
    }
    lines
}

/// Build the self-echo line for a client command, or `None` when the command
/// is not a message an upstream would echo. The prefix is our current
/// upstream identity (`nick!user@host` as the upstream shows it, see
/// [`SelfIdentity`]), valid client-only tags ride along exactly as a real
/// echo-message would return them, and a fresh authoritative `time=` tag stamps
/// when the bouncer accepted the line so backlog playback orders it against
/// upstream traffic.
pub(super) fn self_echo(line: &str, identity: &SelfIdentity) -> Option<String> {
    let parsed = e6irc_proto::message::Message::parse(line).ok()?;
    let prefix = format!(":{}!{}@{}", identity.nick, identity.user, identity.host);
    let body = match parsed.command.to_ascii_uppercase().as_str() {
        command @ ("PRIVMSG" | "NOTICE") => {
            let [target, text] = parsed.params.as_slice() else {
                return None;
            };
            if target.is_empty() || text.is_empty() {
                return None;
            }
            let head = format!("{prefix} {command} {target} :");
            let visible = if sensitive_nickserv_command(target, text) {
                "[sensitive NickServ command redacted]"
            } else {
                text
            };
            format!("{head}{}", crate::core::fit_trailing(&head, visible))
        }
        "TAGMSG" => {
            let [target] = parsed.params.as_slice() else {
                return None;
            };
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

/// What identifies a message's echo: its command, its target (casefolded) and
/// its text. The upstream's echo of a line carries the same three.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EchoKey {
    command: String,
    target: String,
    text: String,
}

impl EchoKey {
    fn new(command: &str, params: &[String]) -> Option<Self> {
        let command = command.to_ascii_uppercase();
        let (target, text) = match (command.as_str(), params) {
            ("PRIVMSG" | "NOTICE", [target, text]) if !text.is_empty() => (target, text.as_str()),
            ("TAGMSG", [target]) => (target, ""),
            _ => return None,
        };
        (!target.is_empty()).then(|| Self {
            command,
            target: e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(target),
            text: text.to_string(),
        })
    }

    /// The key of a message an attached client sent, when the upstream will
    /// echo it.
    fn of_client_line(line: &str) -> Option<Self> {
        let parsed = e6irc_proto::message::Message::parse(line).ok()?;
        let params: Vec<String> = parsed.params.iter().map(ToString::to_string).collect();
        Self::new(parsed.command, &params)
    }

    /// The key of an upstream line when it is the echo of our own message.
    fn of_upstream_echo(message: &e6irc_client::OwnedMessage, own_nick: &str) -> Option<Self> {
        let source = message.source.as_deref()?;
        let nick = source.split_once('!').map_or(source, |(nick, _)| nick);
        if !e6irc_proto::casemap::CaseMapping::Rfc1459.eq(nick, own_nick) {
            return None;
        }
        Self::new(&message.command, &message.params)
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

    /// The attachment that sent the line `key` echoes, when one is waiting.
    fn take(&mut self, key: &EchoKey) -> Option<u64> {
        let position = self.0.iter().position(|(pending, _)| pending == key)?;
        self.0.remove(position).map(|(_, origin)| origin)
    }
}

/// The upstream's echo of our own message, with a NickServ command that can
/// carry a secret replaced by the same redaction the synthesized echo uses:
/// the backlog must never hold the password the upstream reflected back.
fn redact_sensitive_echo(raw: String, message: &e6irc_client::OwnedMessage) -> String {
    let [target, text] = message.params.as_slice() else {
        return raw;
    };
    let command = message.command.to_ascii_uppercase();
    if !matches!(command.as_str(), "PRIVMSG" | "NOTICE")
        || !sensitive_nickserv_command(target, text)
    {
        return raw;
    }
    let tags = raw
        .strip_prefix('@')
        .and_then(|rest| rest.split_once(' '))
        .map(|(tags, _)| format!("@{tags} "))
        .unwrap_or_default();
    let source = message.source.as_deref().unwrap_or_default();
    format!("{tags}:{source} {command} {target} :[sensitive NickServ command redacted]")
}

/// NickServ commands that can carry passwords, email addresses, recovery
/// tokens, or verification codes. A downstream client still sends the exact
/// command upstream, but the synthesized echo and persistent backlog must not
/// retain it. The whole argument string is redacted because service dialects
/// disagree about which position is secret.
fn sensitive_nickserv_command(target: &str, text: &str) -> bool {
    let service = target.split_once('@').map_or(target, |(name, _)| name);
    if !service.eq_ignore_ascii_case("NickServ") && !service.eq_ignore_ascii_case("NS") {
        return false;
    }
    let mut words = text.split_whitespace();
    let command = words.next().unwrap_or_default();
    if matches_ignore_ascii_case(
        command,
        &[
            "REGISTER", "IDENTIFY", "GHOST", "RECOVER", "REGAIN", "RELEASE", "SENDPASS", "VERIFY",
            "CONFIRM", "DROP", "GROUP",
        ],
    ) {
        return true;
    }
    command.eq_ignore_ascii_case("SET")
        && words.next().is_some_and(|setting| {
            matches_ignore_ascii_case(setting, &["PASSWORD", "EMAIL", "PUBKEY"])
        })
}

fn matches_ignore_ascii_case(candidate: &str, expected: &[&str]) -> bool {
    expected
        .iter()
        .any(|value| candidate.eq_ignore_ascii_case(value))
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
mod tests {
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
                    super::super::upstream_identity::ConfirmedChannel::parse(name)
                        .expect("test channel")
                })
                .collect(),
            ..Default::default()
        }
    }

    /// The intent is kept across sessions, so a hostile upstream confirming a
    /// different set on each one must hit the same bound the tracker has.
    #[test]
    fn reconnect_intent_is_bounded_across_sessions_and_follows_departures() {
        let joined = JoinedChannels::default();
        let first: Vec<String> = (0..super::super::MAX_TRACKED_CHANNELS)
            .map(|index| format!("#session-one-{index}"))
            .collect();
        joined.apply(confirmed(&first)).expect("a full set fits");
        // Re-confirming a rejoined channel on the next session is not growth.
        joined
            .apply(confirmed(&["#SESSION-ONE-0".to_string()]))
            .expect("already intended");
        assert_eq!(
            joined.apply(confirmed(&["#session-two-0".to_string()])),
            Err(super::super::ChannelLimitExceeded)
        );
        assert_eq!(
            joined.0.lock().expect("joined set").len(),
            super::super::MAX_TRACKED_CHANNELS
        );

        joined
            .apply(super::super::SessionChange {
                left: vec!["#session-one-1".to_string()],
                ..Default::default()
            })
            .expect("a departure cannot exceed the limit");
        joined
            .apply(confirmed(&["#session-two-0".to_string()]))
            .expect("the departure made room");
    }

    /// Register the real client, with SASL configured, against an upstream that
    /// answers each expected line prefix with its scripted reply, and return
    /// the driver's reading of how that ended.
    async fn sasl_outcome_against(
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
        ] {
            let echo = self_echo(line, &alice())
                .expect("service message still has a visible redacted echo");
            assert!(
                echo.contains("[sensitive NickServ command redacted]"),
                "{echo}"
            );
            for secret in [
                "correct-horse",
                "alice@example.test",
                "mail-token",
                "replacement-secret",
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
