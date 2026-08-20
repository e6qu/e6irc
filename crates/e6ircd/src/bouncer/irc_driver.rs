//! The `irc` network driver: a persistent outbound IRCv3 client
//! connection to an external network, reusing `e6irc-client`. Runs on
//! its own task with auto-reconnect (exponential backoff + jitter);
//! emits [`DriverEvent`]s and accepts raw command lines.

use std::time::Duration;
use std::time::Instant;

use e6irc_client::{Connection, RelayEvent};

use super::{ConnectionEvent, DriverEnds, NetworkHandle};

/// Static configuration for one upstream network.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Upstream address (host:port).
    pub addr: String,
    /// Use TLS to the upstream.
    pub tls: bool,
    pub nick: String,
    pub realname: String,
    /// Channels to auto-join after registering.
    pub autojoin: Vec<String>,
    /// Detached buffer capacity.
    pub buffer_cap: usize,
    /// SASL PLAIN credentials for the upstream, when it requires auth.
    pub sasl: Option<(String, String)>,
    /// Idle gap before the driver sends its own keepalive PING (and again
    /// before it declares a silent upstream dead). 120s in production; tests
    /// shrink it to exercise the half-open-upstream path in real time.
    pub keepalive_idle: Duration,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            addr: String::new(),
            tls: false,
            nick: "e6bnc".into(),
            realname: "e6irc bouncer".into(),
            autojoin: Vec::new(),
            buffer_cap: 1000,
            sasl: None,
            keepalive_idle: KEEPALIVE_IDLE,
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
pub struct JoinedChannels(std::sync::Mutex<std::collections::HashMap<String, String>>);

impl JoinedChannels {
    fn apply_session_delta(
        &self,
        before: &super::IrcSessionSnapshot,
        after: &super::IrcSessionSnapshot,
        retain_departures: bool,
    ) {
        let casemap = e6irc_proto::casemap::CaseMapping::Rfc1459;
        let before_keys: std::collections::HashSet<String> = before
            .channels
            .iter()
            .map(|channel| casemap.casefold(channel))
            .collect();
        let after_by_key: std::collections::HashMap<String, String> = after
            .channels
            .iter()
            .map(|channel| (casemap.casefold(channel), channel.clone()))
            .collect();
        let after_keys: std::collections::HashSet<String> = after_by_key.keys().cloned().collect();
        let mut desired = self.0.lock().expect("joined set poisoned");
        if !retain_departures {
            for removed in before_keys.difference(&after_keys) {
                desired.remove(removed);
            }
        }
        for (key, display) in after_by_key {
            if !before_keys.contains(&key) {
                desired.insert(key, display);
            }
        }
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

/// A successful, side-effect-free IRC upstream qualification. The connection
/// is closed after registration and no channels are joined. Timings are split
/// at the same boundaries operators must diagnose: name resolution, transport
/// establishment (including TLS), and IRC registration (including SASL).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IrcPreflight {
    pub resolved_addresses: usize,
    pub dns_ms: u64,
    pub connect_ms: u64,
    pub registration_ms: u64,
    pub confirmed_nick: String,
    pub joined_channels: Vec<String>,
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
    AuthenticationRejected,
    RegistrationRejected(Option<e6irc_client::RegistrationRejection>),
    InvalidNickname(Option<e6irc_client::RegistrationRejection>),
    InvalidUsername(Option<e6irc_client::RegistrationRejection>),
    NicknameInUse(Option<e6irc_client::RegistrationRejection>),
    ServerPasswordRejected(Option<e6irc_client::RegistrationRejection>),
    NetworkBanned(Option<e6irc_client::RegistrationRejection>),
    RegistrationFailed,
    RegistrationTimedOut,
    ChannelJoinFailed,
    ChannelJoinTimedOut,
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
            Self::AuthenticationRejected => "authentication_rejected",
            Self::RegistrationRejected(_) => "registration_rejected",
            Self::InvalidNickname(_) => "invalid_nickname",
            Self::InvalidUsername(_) => "invalid_username",
            Self::NicknameInUse(_) => "nickname_in_use",
            Self::ServerPasswordRejected(_) => "server_password_rejected",
            Self::NetworkBanned(_) => "network_banned",
            Self::RegistrationFailed => "registration_failed",
            Self::RegistrationTimedOut => "registration_timed_out",
            Self::ChannelJoinFailed => "channel_join_failed",
            Self::ChannelJoinTimedOut => "channel_join_timed_out",
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
            Self::AuthenticationRejected => "The upstream rejected the SASL credentials.",
            Self::RegistrationRejected(_) => "The upstream rejected IRC registration.",
            Self::InvalidNickname(_) => "The upstream rejected the configured nickname.",
            Self::InvalidUsername(_) => "The upstream rejected the IRC username.",
            Self::NicknameInUse(_) => "The configured nickname is already in use.",
            Self::ServerPasswordRejected(_) => {
                "The upstream rejected the configured server password."
            }
            Self::NetworkBanned(_) => "The upstream network banned this connection.",
            Self::RegistrationFailed => "IRC registration failed before a welcome was received.",
            Self::RegistrationTimedOut => "IRC registration timed out.",
            Self::ChannelJoinFailed => "The upstream rejected a configured channel join.",
            Self::ChannelJoinTimedOut => {
                "The upstream did not confirm a configured channel join in time."
            }
        }
    }

    pub fn diagnostic(&self) -> Option<&str> {
        match self {
            Self::RegistrationRejected(rejection)
            | Self::InvalidNickname(rejection)
            | Self::InvalidUsername(rejection)
            | Self::NicknameInUse(rejection)
            | Self::ServerPasswordRejected(rejection)
            | Self::NetworkBanned(rejection) => rejection.as_ref().map(|value| value.diagnostic()),
            _ => None,
        }
    }
}

/// Resolve, connect, and register exactly as the always-on IRC driver does,
/// without persisting configuration or starting a reconnect loop.
pub async fn preflight_irc(config: &NetworkConfig) -> Result<IrcPreflight, IrcPreflightFailure> {
    if upstream_host(&config.addr).is_err() {
        return Err(IrcPreflightFailure::InvalidAddress);
    }

    let dns_started = Instant::now();
    let addresses = tokio::time::timeout(Duration::from_secs(10), resolve_vetted(&config.addr))
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
    let mut connection =
        tokio::time::timeout(Duration::from_secs(30), connect_resolved(config, addresses))
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

    let registration_started = Instant::now();
    let registration = async {
        match &config.sasl {
            Some((account, password)) => {
                connection
                    .register_sasl(&config.nick, &config.realname, account, password)
                    .await
            }
            None => connection.register(&config.nick, &config.realname).await,
        }
    };
    let confirmed_nick = match tokio::time::timeout(Duration::from_secs(30), registration).await {
        Ok(Ok(confirmed_nick)) => confirmed_nick,
        Ok(Err(error))
            if let Some(rejection) = e6irc_client::RegistrationRejection::from_error(&error) =>
        {
            return Err(preflight_refusal(Some(rejection)));
        }
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(IrcPreflightFailure::AuthenticationRejected);
        }
        Ok(Err(error))
            if matches!(
                error.kind(),
                std::io::ErrorKind::AlreadyExists
                    | std::io::ErrorKind::Other
                    | std::io::ErrorKind::Unsupported
            ) =>
        {
            return Err(IrcPreflightFailure::RegistrationRejected(None));
        }
        Ok(Err(error)) => {
            eprintln!("irc preflight: registration failed: {error}");
            return Err(IrcPreflightFailure::RegistrationFailed);
        }
        Err(_) => return Err(IrcPreflightFailure::RegistrationTimedOut),
    };

    let mut joined_channels = Vec::with_capacity(config.autojoin.len());
    for channel in &config.autojoin {
        match tokio::time::timeout(
            Duration::from_secs(30),
            connection.join_with_latest_history(channel, 0),
        )
        .await
        {
            Ok(Ok(_)) => joined_channels.push(channel.clone()),
            Ok(Err(error)) => {
                eprintln!("irc preflight: channel join failed: {error}");
                return Err(IrcPreflightFailure::ChannelJoinFailed);
            }
            Err(_) => return Err(IrcPreflightFailure::ChannelJoinTimedOut),
        }
    }

    Ok(IrcPreflight {
        resolved_addresses,
        dns_ms,
        connect_ms,
        registration_ms: elapsed_millis(registration_started.elapsed()),
        confirmed_nick,
        joined_channels,
    })
}

fn elapsed_millis(elapsed: Duration) -> u64 {
    elapsed.as_millis().min(u64::MAX as u128) as u64
}

async fn run(config: NetworkConfig, mut ends: DriverEnds) {
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

/// The typed outcome of a timed-out registration attempt. Shared between the
/// first attempt and the 433-retry so the two paths cannot diverge on what
/// each `io::ErrorKind` means.
enum RegistrationResult {
    Ok(String),
    AuthRejected,
    NickInUse(e6irc_client::RegistrationRejection),
    Rejected(e6irc_client::RegistrationRejection),
    Failed,
    TimedOut,
}

fn classify_registration(
    result: Result<Result<String, std::io::Error>, tokio::time::error::Elapsed>,
) -> RegistrationResult {
    match result {
        Ok(Ok(nick)) => RegistrationResult::Ok(nick),
        Ok(Err(e)) if let Some(rejection) = e6irc_client::RegistrationRejection::from_error(&e) => {
            eprintln!("irc registration rejected: {e}");
            match rejection.refusal() {
                e6irc_client::RegistrationRefusal::NicknameInUse => {
                    RegistrationResult::NickInUse(rejection)
                }
                _ => RegistrationResult::Rejected(rejection),
            }
        }
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            RegistrationResult::AuthRejected
        }
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::Unsupported => {
            RegistrationResult::Rejected(e6irc_client::RegistrationRejection::without_diagnostic(
                e6irc_client::RegistrationRefusal::NotRegistered,
            ))
        }
        Ok(Err(e))
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::Other
            ) =>
        {
            RegistrationResult::Failed
        }
        Ok(Err(_)) => RegistrationResult::Failed,
        Err(_) => RegistrationResult::TimedOut,
    }
}

/// Map a [`RegistrationResult`] to the session-loop's terminal outcome when
/// the caller is *not* taking the 433-retry branch.
fn into_outcome(result: RegistrationResult) -> Result<String, super::SessionOutcome> {
    match result {
        RegistrationResult::Ok(nick) => Ok(nick),
        RegistrationResult::AuthRejected => Err(super::SessionOutcome::AuthRejected),
        RegistrationResult::NickInUse(rejection) => {
            Err(super::SessionOutcome::RegistrationRejected(rejection))
        }
        RegistrationResult::Rejected(rejection) => {
            Err(super::SessionOutcome::RegistrationRejected(rejection))
        }
        RegistrationResult::Failed => Err(dropped(super::NetworkFailure::RegistrationFailed)),
        RegistrationResult::TimedOut => Err(dropped(super::NetworkFailure::RegistrationTimedOut)),
    }
}

fn preflight_refusal(
    rejection: Option<e6irc_client::RegistrationRejection>,
) -> IrcPreflightFailure {
    let Some(rejection) = rejection else {
        return IrcPreflightFailure::RegistrationRejected(None);
    };
    match rejection.refusal() {
        e6irc_client::RegistrationRefusal::InvalidNickname => {
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
        e6irc_client::RegistrationRefusal::NetworkBanned => {
            IrcPreflightFailure::NetworkBanned(Some(rejection))
        }
        e6irc_client::RegistrationRefusal::NotRegistered => {
            IrcPreflightFailure::RegistrationRejected(Some(rejection))
        }
    }
}

async fn connect_once(shared: &SharedDriver, ends: &mut DriverEnds) -> super::SessionOutcome {
    let config = &shared.config;
    // Bound connect + registration: an upstream that accepts the TCP handshake
    // but never sends 001 (firewall dropping data, half-open peer) must not
    // wedge the driver forever — that would starve the reconnect loop, the
    // same failure the Matrix driver's timeout guards against.
    let connect_fut = connect(config);
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
    let register_fut = async {
        match &config.sasl {
            Some((account, password)) => {
                conn.register_sasl(&config.nick, &config.realname, account, password)
                    .await
            }
            None => conn.register(&config.nick, &config.realname).await,
        }
    };
    let registration = tokio::select! {
        _ = ends.shutdown_signalled() => return super::SessionOutcome::Stopped,
        result = tokio::time::timeout(Duration::from_secs(30), register_fut) => result,
    };
    let mut current_nick = match classify_registration(registration) {
        RegistrationResult::NickInUse(_) if config.sasl.is_none() => {
            // A lingering ghost of our own previous session (not yet timed out
            // upstream) holds the nick. Offer one replacement rather than
            // parking a healthy network until an operator intervenes. SASL
            // registrations skip the retry: their conflict means the account's
            // nick is genuinely claimed elsewhere, and silently renaming would
            // mask that.
            let alt = format!("{}_", config.nick);
            let retry = tokio::select! {
                _ = ends.shutdown_signalled() => return super::SessionOutcome::Stopped,
                result = tokio::time::timeout(Duration::from_secs(30), conn.retry_nick(&alt)) => result,
            };
            match into_outcome(classify_registration(retry)) {
                Ok(nick) => nick,
                Err(outcome) => return outcome,
            }
        }
        result => match into_outcome(result) {
            Ok(nick) => nick,
            Err(outcome) => return outcome,
        },
    };
    // Join the configured autojoin plus every channel the upstream confirmed
    // us in before the drop (runtime joins are tracked in `shared.joined`).
    // Autojoin wins on a fold-collision: its casing is the operator's.
    let rejoin: Vec<String> = {
        let mut list = config.autojoin.clone();
        let casemap = e6irc_proto::casemap::CaseMapping::Rfc1459;
        let folded: std::collections::HashSet<String> = config
            .autojoin
            .iter()
            .map(|c| casemap.casefold(c))
            .collect();
        let extras: Vec<String> = shared
            .joined
            .0
            .lock()
            .expect("joined set poisoned")
            .iter()
            .filter(|(key, _)| !folded.contains(*key))
            .map(|(_, display)| display.clone())
            .collect();
        list.extend(extras);
        list
    };
    for chan in &rejoin {
        if conn.send_line(&format!("JOIN {chan}")).await.is_err() {
            return dropped(super::NetworkFailure::AutojoinFailed);
        }
    }
    ends.begin_irc_session(current_nick.clone());
    ends.emit(ConnectionEvent::Connected);

    // Keepalive: `connect_once` bounds connect + registration, but the
    // steady-state read below would otherwise block forever on a half-open
    // upstream (firewall silently drops the link, peer vanishes without RST),
    // starving the reconnect loop while `is_connected()` stays true — the exact
    // wedge the registration timeout guards against, just relocated. On an idle
    // gap we send our own PING; if the next gap passes with still no traffic,
    // the link is dead — drop and reconnect. A live server's own PINGs (which
    // we answer) keep a quiet-but-alive connection from ever tripping this.
    let mut awaiting_keepalive = false;
    // The host half of synthesized self-echo prefixes.
    let upstream = upstream_host(&config.addr)
        .expect("IRC driver starts only from a validated upstream address")
        .to_string();
    loop {
        tokio::select! {
            // Upstream -> buffer + event.
            msg = tokio::time::timeout(config.keepalive_idle, conn.next_line_relayable()) => match msg {
                Ok(Ok(Some(RelayEvent::Line { message: parsed, raw }))) => {
                    awaiting_keepalive = false;
                    // Keepalive filtering applies only to lines we could parse;
                    // a line that didn't parse (a non-UTF-8 body, say) is never
                    // a PING and is simply relayed. A bad line must not drop the
                    // link — it is delivered, not fatal.
                    if let Some(m) = &parsed {
                        // Answer PINGs transparently (keepalive is the
                        // driver's job, not the attached client's).
                        if m.command == "PING" {
                            let token = m.params.first().cloned().unwrap_or_default();
                            if conn.send_line(&format!("PONG :{token}")).await.is_err() {
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
                    }
                    // The upstream's own line: attached clients and the detached
                    // buffer get what the network sent, tags and all. `attach`
                    // strips the tags a client did not negotiate.
                    //
                    // A send with zero subscribers is fine — the driver
                    // is always-on regardless of attach.
                    let before = ends.irc_session_snapshot();
                    ends.emit_line(raw);
                    if let (Some(before), Some(session)) =
                        (before, ends.irc_session_snapshot())
                    {
                        // QUIT clears live membership for attached-client state,
                        // but the reconnect intent survives a transport drop.
                        // JOIN/PART/KICK deltas update that intent without an
                        // unrelated numeric erasing channels still awaiting
                        // confirmation on this new session.
                        let quit = parsed
                            .as_ref()
                            .is_some_and(|message| message.command == "QUIT");
                        shared
                            .joined
                            .apply_session_delta(&before, &session, quit);
                        current_nick = session.nick;
                    }
                }
                Ok(Ok(Some(RelayEvent::Rejected(rejected)))) => {
                    awaiting_keepalive = false;
                    // Keep the upstream connection alive, but make the whole-line
                    // loss visible to attached clients and the detached buffer.
                    // A syntactically valid local NOTICE is bounded independently
                    // of the rejected payload and cannot itself be discarded.
                    ends.emit_line(format!(
                        ":e6irc NOTICE * :upstream input rejected: {rejected}"
                    ));
                }
                // Only a genuine EOF or a real I/O error ends the session.
                Ok(Ok(None)) | Ok(Err(_)) => {
                    return dropped(super::NetworkFailure::ConnectionLost);
                }
                Err(_) => {
                    // Idle past the keepalive window.
                    if awaiting_keepalive {
                        return dropped(super::NetworkFailure::KeepaliveTimedOut);
                    }
                    awaiting_keepalive = true;
                    if conn.send_line("PING :e6bnc-keepalive").await.is_err() {
                        return dropped(super::NetworkFailure::UpstreamWriteFailed);
                    }
                }
            },
            // Downstream command -> upstream.
            cmd = ends.next_command() => match cmd {
                Some(cmd) => {
                    if conn.send_line(&cmd.line).await.is_err() {
                        return dropped(super::NetworkFailure::UpstreamWriteFailed);
                    }
                    // The upstream never echoes our own messages (we do not
                    // request echo-message — one synthesized echo beats two
                    // sources), so manufacture it: the detached buffer and the
                    // account's other sessions must see both sides of the
                    // conversation, and the originator sees it exactly when it
                    // negotiated echo-message on attach.
                    if let Some(echo) = self_echo(&cmd.line, &current_nick, &config.nick, &upstream) {
                        ends.emit_echo(echo, cmd.origin);
                    }
                }
                None => return super::SessionOutcome::Stopped, // handle dropped
            },
        }
    }
}

fn dropped(failure: super::NetworkFailure) -> super::SessionOutcome {
    super::SessionOutcome::Dropped(failure)
}

/// Build the self-echo line for a client command, or `None` when the command
/// is not a message an upstream would echo. The prefix is our current
/// upstream identity (`nick!~ident@host`; `~` because no identd answered),
/// valid client-only tags ride along exactly as a real echo-message would
/// return them, and a fresh authoritative `time=` tag stamps when the bouncer
/// accepted the line so backlog playback orders it against upstream traffic.
fn self_echo(line: &str, nick: &str, ident: &str, host: &str) -> Option<String> {
    let body = match line.strip_prefix('@') {
        Some(rest) => match rest.split_once(' ') {
            Some((_, body)) => body,
            None => return None,
        },
        None => line,
    };
    let parsed = e6irc_proto::message::Message::parse(line).ok()?;
    if !parsed.command.eq_ignore_ascii_case("PRIVMSG")
        && !parsed.command.eq_ignore_ascii_case("NOTICE")
        && !parsed.command.eq_ignore_ascii_case("TAGMSG")
    {
        return None;
    }
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
    Some(format!("@{all_tags} :{nick}!~{ident}@{host} {body}"))
}

/// Idle gap before the driver sends a keepalive PING (and again before it
/// declares a silent upstream dead). A live server PINGs well within this, so a
/// quiet-but-alive connection never trips it; a half-open one is caught within
/// `2 × KEEPALIVE_IDLE`.
pub(crate) const KEEPALIVE_IDLE: Duration = Duration::from_secs(120);

async fn connect(config: &NetworkConfig) -> std::io::Result<Connection> {
    // SSRF control: resolve the upstream address ourselves and dial a *vetted*
    // resolved IP directly, rather than handing the hostname to the OS resolver
    // inside `TcpStream::connect`. The creation-time literal check
    // (`upstream_addr_is_internal`) can't see where a *hostname* resolves, and a
    // bare `TcpStream::connect(host)` re-resolves — so a hostname pointing at
    // `169.254.169.254` (or a DNS rebind between creation and now) would reach an
    // internal target. Connecting to the specific vetted socket address closes
    // both: resolution can't differ between the check and the connect.
    let vetted = resolve_vetted(&config.addr).await?;
    if vetted.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "upstream address resolves only to blocked/internal targets",
        ));
    }
    connect_resolved(config, vetted).await
}

async fn resolve_vetted(addr: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
    Ok(interleave_address_families(
        tokio::net::lookup_host(addr)
            .await?
            .filter(|address| !crate::http::networks::is_blocked_upstream_ip(address.ip()))
            .collect(),
    ))
}

async fn connect_resolved(
    config: &NetworkConfig,
    vetted: Vec<std::net::SocketAddr>,
) -> std::io::Result<Connection> {
    // Try every vetted result. Public round robins commonly return both IPv6
    // and IPv4; selecting only the first made a host without working IPv6 retry
    // the same unreachable address forever instead of reaching the IPv4 peer.
    // Each concrete dial is bounded so one black-holed address cannot consume
    // the entire outer connection deadline.
    let server_name = upstream_host(&config.addr)?;
    let mut last_error = std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "upstream resolved addresses were exhausted",
    );
    for address in vetted {
        let stream = match tokio::time::timeout(
            Duration::from_secs(5),
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
                Duration::from_secs(5),
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

fn interleave_address_families(addresses: Vec<std::net::SocketAddr>) -> Vec<std::net::SocketAddr> {
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

    #[test]
    fn generic_registration_error_is_not_mislabeled_as_a_server_refusal() {
        let error = std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "server refused registration",
        );
        assert!(matches!(
            classify_registration(Ok(Err(error))),
            RegistrationResult::Failed
        ));
    }

    #[test]
    fn self_echo_mints_provenance_and_keeps_only_valid_client_tags() {
        let echo = self_echo(
            "@time=forged;msgid=forged;+typing=old;+typing=active;+bad.foo=x PRIVMSG #room :hello",
            "alice",
            "alice",
            "irc.example",
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

    async fn assert_live_driver(network: &str, addr: &str, autojoin: &[&str]) {
        for attempt in 0..2 {
            let nick = format!("e6b{:04}{attempt}", std::process::id() % 10000);
            let handle = IrcNetwork::start(NetworkConfig {
                addr: addr.into(),
                tls: true,
                nick,
                realname: "e6irc BNC interop probe".into(),
                buffer_cap: 32,
                autojoin: autojoin
                    .iter()
                    .map(|channel| (*channel).to_string())
                    .collect(),
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
