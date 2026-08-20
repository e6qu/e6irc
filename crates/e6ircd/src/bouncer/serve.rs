//! BNC listener glue: a registry of always-on networks and the
//! per-client serve loop. A client must authenticate with SASL PLAIN
//! against its account, then selects a network from the `nick/network`
//! suffix; the loop greets it as the bouncer and hands off to `attach`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sqlx::PgPool;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{NetworkConfig, NetworkHandle, attach};
use crate::config::NetworkEntry;
use e6irc_proto::framing::{LineBuffer, LineEvent};
use e6irc_proto::message::Message;

/// Registry key: the owning account (`None` = shared) and the network
/// name the client selects with the `/network` suffix.
///
/// Both fields are stored casefolded so selection is case-insensitive, like
/// every other IRC identifier. A key correct only while every producer spells
/// the name the same way is the wrong kind of correct: a miss on the owned key
/// falls through to a shared network of the same name, so a casing mismatch
/// (`/network Foo` for an owned `foo`) would silently attach the client to an
/// operator's network instead of its own (DESIGN §2). Network names are
/// restricted to `[A-Za-z0-9._-]` (`network_name_ok`), which excludes RFC1459's
/// `[]\^` specials, so the fold here matches the DB's `lower(name)` (unique
/// index + lookups, migration 0034) by construction. [`NetworkKey::new`] is the
/// only way to build one, so that cannot drift.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NetworkKey {
    owner: Option<String>,
    name: String,
}

impl NetworkKey {
    fn new(owner: Option<&str>, name: &str) -> Self {
        let fold = |s: &str| e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(s);
        Self {
            owner: owner.map(fold),
            name: fold(name),
        }
    }

    /// The owner half for log lines: a shared (server-configured) network
    /// reads as `*` — matching the persistence key — rather than vanishing.
    fn display_owner(&self) -> &str {
        self.owner.as_deref().unwrap_or("*")
    }
}

/// All active networks, each running an always-on driver, keyed by
/// `(owner, name)`. Mutable at runtime so accounts can add and remove
/// their own networks. When a database is present, each network's
/// upstream lines are persisted and its recent backlog is restored on
/// start.
pub struct Registry {
    networks: Mutex<HashMap<NetworkKey, Slot>>,
    /// Serializes durable runtime mutations with their registry side effect.
    /// A database update and `add`/`remove` are one logical transition: without
    /// this gate, a concurrent delete could remove the row, then lose a race to
    /// an older edit adding its driver back as an untracked live network.
    mutations: tokio::sync::Mutex<()>,
    pool: Option<PgPool>,
    telemetry: Option<Arc<crate::observability::Telemetry>>,
}

/// A registered network: its driver handle plus the persistence task that
/// mirrors upstream lines to the database.
struct Slot {
    handle: Arc<NetworkHandle>,
    persistence: Option<tokio::task::JoinHandle<()>>,
    /// The driver's stable kind (`irc`, `matrix`, `discord`, `slack`, …),
    /// captured before `start()` consumes the driver — for status views.
    kind: &'static str,
}

/// A read-only snapshot of one registered network, for status/management views.
pub struct NetworkStatus {
    /// Owning account (casefolded), or `None` for a server-level shared network.
    pub owner: Option<String>,
    pub name: String,
    pub kind: &'static str,
    pub connected: bool,
    pub runtime: super::NetworkRuntimeSnapshot,
}

impl Slot {
    /// Stop the driver authoritatively and the persistence task with it.
    ///
    /// The driver observes `handle.shutdown()` regardless of who still holds a
    /// command sender — an attached client clones `commands`, so relying on
    /// refcount alone would keep the upstream connection (and its decrypted
    /// SASL password) alive until the last client detached. The persistence
    /// task is aborted too so it stops writing for a network that is gone.
    async fn stop(self) {
        self.handle.shutdown_and_wait().await;
        if let Some(task) = self.persistence {
            task.abort();
        }
    }
}

/// How many recent lines to restore into a network's buffer at start.
const PRELOAD_LIMIT: i64 = 1000;

impl Registry {
    /// Start a driver per configured (server-level) network. `pool`, when
    /// present, enables buffer persistence and backlog restore; `core`
    /// (the in-process handles) is required for any `local` network.
    pub fn start(
        entries: &[NetworkEntry],
        pool: Option<PgPool>,
        core: super::CoreHandles,
    ) -> Result<Self, String> {
        Self::start_inner(entries, pool, core, None)
    }

    pub(crate) fn start_observed(
        entries: &[NetworkEntry],
        pool: Option<PgPool>,
        core: super::CoreHandles,
        telemetry: Arc<crate::observability::Telemetry>,
    ) -> Result<Self, String> {
        Self::start_inner(entries, pool, core, Some(telemetry))
    }

    fn start_inner(
        entries: &[NetworkEntry],
        pool: Option<PgPool>,
        core: super::CoreHandles,
        telemetry: Option<Arc<crate::observability::Telemetry>>,
    ) -> Result<Self, String> {
        use crate::config::NetworkKind;
        let registry = Self {
            networks: Mutex::new(HashMap::new()),
            mutations: tokio::sync::Mutex::new(()),
            pool,
            telemetry,
        };
        for e in entries {
            // `local` needs the in-process core handles, so it stays special; all
            // other kinds go through the shared feature-gated `build_driver`
            // factory (the same one the DB create/boot/re-enable paths use).
            let realname = match e.kind {
                NetworkKind::Irc | NetworkKind::Local => e.realname.clone().ok_or_else(|| {
                    format!(
                        "network '{}' (kind={}) requires realname",
                        e.name,
                        e.kind.as_db_str()
                    )
                })?,
                NetworkKind::Matrix | NetworkKind::Discord | NetworkKind::Slack => String::new(),
            };
            let driver: Box<dyn super::NetworkDriver> = if e.kind == NetworkKind::Local {
                let config = NetworkConfig {
                    addr: e.addr.clone(),
                    tls: e.tls,
                    nick: e.nick.clone(),
                    realname,
                    autojoin: e.autojoin.clone(),
                    buffer_cap: e.buffer_cap,
                    sasl: None,
                    keepalive_idle: super::KEEPALIVE_IDLE,
                };
                Box::new(super::LocalDriver::new(core.clone(), config))
            } else {
                super::build_driver(
                    e.kind,
                    e.addr.clone(),
                    e.tls,
                    e.nick.clone(),
                    realname,
                    e.autojoin.clone(),
                    e.buffer_cap,
                    e.sasl_account.clone(),
                    e.sasl_password.clone(),
                )
                .map_err(|msg| format!("network '{}': {msg}", e.name))?
            };
            registry.add(e.owner.as_deref(), &e.name, driver);
        }
        Ok(registry)
    }

    /// Enter the one serialized control-plane mutation path. Callers hold this
    /// guard across the database write and the matching registry transition.
    pub(crate) async fn mutation_guard(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.mutations.lock().await
    }

    /// Start a driver for `(owner, name)` and register it, replacing any
    /// existing driver under that key (the old handle drops, stopping it).
    /// With a database, restore recent backlog and persist new lines.
    pub fn add(&self, owner: Option<&str>, name: &str, driver: Box<dyn super::NetworkDriver>) {
        let key = NetworkKey::new(owner, name);
        // Capture the kind before `start()` consumes the driver.
        let kind = driver.kind();
        let handle = Arc::new(driver.start());
        handle.set_label(format!("{}/{}", key.display_owner(), name));
        if let Some(telemetry) = &self.telemetry {
            handle.set_telemetry(telemetry.clone());
        }
        // The persistence task keys `bnc_buffer` rows by the same casefolded
        // owner the registry uses, so a buffer cannot be written under one
        // spelling and looked up under another.
        let persistence = self.pool.clone().map(|pool| {
            handle.set_history(pool.clone(), key.owner.clone(), key.name.clone());
            spawn_persistence(pool, key.owner.clone(), key.name.clone(), handle.clone())
        });
        let slot = Slot {
            handle,
            persistence,
            kind,
        };
        let old = self
            .networks
            .lock()
            .expect("registry poisoned")
            .insert(key, slot);
        assert!(
            old.is_none(),
            "registry add replaced a live network; use replace instead"
        );
    }

    /// Replace one live driver only after its predecessor has disconnected.
    pub async fn replace(
        &self,
        owner: Option<&str>,
        name: &str,
        driver: Box<dyn super::NetworkDriver>,
    ) {
        let old = self
            .networks
            .lock()
            .expect("registry poisoned")
            .remove(&NetworkKey::new(owner, name));
        if let Some(old) = old {
            old.stop().await;
        }
        self.add(owner, name, driver);
    }

    /// Remove `owner`'s network `name`, stopping its driver. Returns
    /// whether a network was removed.
    pub async fn remove(&self, owner: Option<&str>, name: &str) -> bool {
        let removed = self
            .networks
            .lock()
            .expect("registry poisoned")
            .remove(&NetworkKey::new(owner, name));
        match removed {
            Some(slot) => {
                slot.stop().await;
                true
            }
            None => false,
        }
    }

    /// Stop every active upstream owned by one account while preserving its
    /// durable definitions for possible reactivation.
    pub async fn remove_owner(&self, owner: &str) -> usize {
        let owner = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(owner);
        let removed: Vec<Slot> = {
            let mut networks = self.networks.lock().expect("registry poisoned");
            let keys: Vec<NetworkKey> = networks
                .keys()
                .filter(|key| key.owner.as_deref() == Some(owner.as_str()))
                .cloned()
                .collect();
            keys.into_iter()
                .filter_map(|key| networks.remove(&key))
                .collect()
        };
        let count = removed.len();
        for slot in removed {
            slot.stop().await;
        }
        count
    }

    /// The account's OWN active network of that name, if any. Deliberately does
    /// NOT fall through to a shared network: a disabled owned network is removed
    /// from the registry, so a blind fall-through would silently attach the
    /// client to an operator's shared network of the same name (DESIGN §2). The
    /// caller (`bnc_serve`) distinguishes "you own it but it's disabled" from
    /// "you don't own one" via the database, then decides whether the shared
    /// network is an acceptable target.
    pub fn get_owned(&self, account: &str, name: &str) -> Option<Arc<NetworkHandle>> {
        self.networks
            .lock()
            .expect("registry poisoned")
            .get(&NetworkKey::new(Some(account), name))
            .map(|slot| slot.handle.clone())
    }

    /// A shared (ownerless) network of that name, if any.
    pub fn get_shared(&self, name: &str) -> Option<Arc<NetworkHandle>> {
        self.networks
            .lock()
            .expect("registry poisoned")
            .get(&NetworkKey::new(None, name))
            .map(|slot| slot.handle.clone())
    }

    /// A snapshot of every registered network — its owner, name, driver kind,
    /// and live connection state — for the console's status/integration views.
    pub fn list(&self) -> Vec<NetworkStatus> {
        self.networks
            .lock()
            .expect("registry poisoned")
            .iter()
            .map(|(key, slot)| {
                let runtime = slot.handle.runtime_snapshot();
                NetworkStatus {
                    owner: key.owner.clone(),
                    name: key.name.clone(),
                    kind: slot.kind,
                    connected: runtime.lifecycle == super::NetworkLifecycle::Connected,
                    runtime,
                }
            })
            .collect()
    }
}

/// Restore a network's persisted backlog into its buffer, then persist
/// every new upstream line. Subscribes before the backlog read so no
/// line broadcast during the read is lost (up to the channel's backlog).
fn spawn_persistence(
    pool: PgPool,
    owner: Option<String>,
    network: String,
    handle: Arc<NetworkHandle>,
) -> tokio::task::JoinHandle<()> {
    use super::DriverEvent;
    let owner_key = owner.unwrap_or_else(|| "*".to_string());
    tokio::spawn(async move {
        let mut events = handle.subscribe();
        match crate::db::recent_bnc_lines(&pool, &owner_key, &network, PRELOAD_LIMIT).await {
            Ok(lines) => handle.preload_front(lines),
            Err(e) => {
                handle.record_error(super::NetworkFailure::BacklogStorageFailed);
                eprintln!("bnc: buffer restore failed for {owner_key}/{network}: {e}");
            }
        }
        handle.history_restored();
        // This task is the only writer for this network, so counting its own
        // appends is what makes the amortized trim reach every network — see
        // `db::BNC_TRIM_INTERVAL`.
        let mut since_trim = 0u64;
        loop {
            let (line, own_nick) = match events.recv().await {
                // A synthesized self-echo is part of the conversation record:
                // persist it like an upstream line so a reattached client sees
                // both sides after a restart.
                Ok(DriverEvent::Line(line)) => {
                    let own_nick = handle.irc_session_snapshot().map(|session| session.nick);
                    (line, own_nick)
                }
                Ok(DriverEvent::Echo { line, .. }) => {
                    // The echo carries the exact identity used when it was
                    // synthesized. Derive ownership from that line instead of
                    // a later sticky snapshot: the persistence task may lag
                    // behind a subsequent NICK and must not split the two
                    // halves of a direct-message conversation.
                    let own_nick = e6irc_proto::message::Message::parse(&line)
                        .ok()
                        .and_then(|message| message.source.map(|source| source.name.to_string()));
                    (line, own_nick)
                }
                Ok(_) => continue,
                // A persistence lag means upstream lines were never written:
                // the stored backlog now has a gap. Surface it rather than
                // dropping it silently.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    handle.record_error(super::NetworkFailure::BacklogStorageLagged);
                    eprintln!(
                        "bnc: persistence lagged for {owner_key}/{network}; {n} upstream \
                         line(s) missing from stored backlog"
                    );
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };
            if let Err(e) = persist_and_trim(
                &pool,
                &owner_key,
                &network,
                own_nick.as_deref(),
                &line,
                &mut since_trim,
            )
            .await
            {
                handle.record_error(super::NetworkFailure::BacklogStorageFailed);
                eprintln!("bnc: buffer persist or trim failed for {owner_key}/{network}: {e}");
            }
        }
    })
}

async fn persist_and_trim(
    pool: &PgPool,
    owner: &str,
    network: &str,
    own_nick: Option<&str>,
    line: &str,
    since_trim: &mut u64,
) -> Result<(), crate::db::DbError> {
    crate::db::persist_bnc_line(pool, owner, network, own_nick, line).await?;
    *since_trim += 1;
    if *since_trim >= crate::db::BNC_TRIM_INTERVAL {
        *since_trim = 0;
        crate::db::trim_bnc_buffer(pool, owner, network).await?;
    }
    Ok(())
}

/// Outcome of the BNC registration handshake.
enum Registered {
    /// Client authenticated as `account` and selected `network`, negotiating
    /// `caps` (which message tags it may receive on attach).
    Ok {
        account: String,
        network: String,
        requested_nick: String,
        caps: super::AttachCaps,
    },
    /// The client hung up or violated the handshake; the loop returns.
    Closed,
}

/// Serve one BNC client: authenticate it with SASL PLAIN against the
/// account store, pick the network from the `nick/network` suffix,
/// greet, and attach. The client's NICK/USER are consumed here (the
/// driver owns the upstream registration).
pub async fn bnc_serve<S>(
    stream: S,
    registry: Arc<Registry>,
    pool: &PgPool,
    server_name: &str,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut read, mut write) = tokio::io::split(stream);

    // Bound the pre-attach handshake: a client that connects and never
    // completes registration (sends nothing, or authenticates but never ends
    // CAP negotiation) must not hold a task + socket indefinitely.
    let (account, network, requested_nick, caps) = match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        handshake(&mut read, &mut write, pool, server_name),
    )
    .await
    {
        Ok(Ok(Registered::Ok {
            account,
            network,
            requested_nick,
            caps,
        })) => (account, network, requested_nick, caps),
        Ok(Ok(Registered::Closed)) => return Ok(()),
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            write
                .write_all(
                    format!(":{server_name} ERROR :Closing Link: BNC registration timed out\r\n")
                        .as_bytes(),
                )
                .await?;
            write.flush().await?;
            return Ok(());
        }
    };

    // Resolve the target network without silently substituting one for another:
    // the account's own active network wins; if it owns a network of that name
    // that is *not* active (disabled), say so rather than falling through to a
    // shared network of the same name; only a name the account does not own at
    // all falls through to a shared (ownerless) network.
    let handle = if let Some(handle) = registry.get_owned(&account, &network) {
        handle
    } else {
        match crate::db::get_bnc_network(pool, &account, &network).await {
            // Owned but not live: disabled. Say so rather than falling through
            // to a shared network of the same name.
            Ok(Some(_)) => {
                write
                    .write_all(
                        format!(
                            ":{server_name} NOTICE * :Your network '{network}' is disabled.\r\n"
                        )
                        .as_bytes(),
                    )
                    .await?;
                return Ok(());
            }
            // DB error: ownership is unresolved. Fail closed — never fall
            // through to a shared network, which could silently attach the
            // client to a *different* (operator-owned) network of the same name
            // (DESIGN §2: no silent fallbacks).
            Err(e) => {
                eprintln!("bnc: attach ownership lookup for {account}/{network} failed: {e}");
                write
                    .write_all(
                        format!(
                            ":{server_name} NOTICE * :Network '{network}' is temporarily unavailable.\r\n"
                        )
                        .as_bytes(),
                    )
                    .await?;
                return Ok(());
            }
            // Not owned at all: a shared (ownerless) network of that name is a
            // legitimate fallback.
            Ok(None) => {
                if let Some(handle) = registry.get_shared(&network) {
                    handle
                } else {
                    write
                        .write_all(
                            format!(":{server_name} NOTICE * :Unknown network '{network}'.\r\n")
                                .as_bytes(),
                        )
                        .await?;
                    return Ok(());
                }
            }
        }
    };

    // Complete the client's registration burst (001 + end-of-MOTD) so it
    // considers itself registered, then attach.
    // The attach selector is registration input, not the client's IRC
    // identity. Once the upstream session exists, 001 must name its actual nick
    // so clients classify the following JOIN/NICK traffic as their own.
    let downstream_nick = handle
        .irc_session_snapshot()
        .map_or(requested_nick, |session| session.nick);
    for line in [
        format!(
            ":{server_name} 001 {downstream_nick} :Welcome to e6irc BNC, attached to '{network}'"
        ),
        format!(
            ":{server_name} 005 {downstream_nick} CASEMAPPING=rfc1459 CHANTYPES=#& \
             CHANNELLEN=64 NICKLEN=30 PREFIX=(qaohv)~&@%+ CHATHISTORY={} \
             MSGREFTYPES=timestamp,msgid :are supported by this server",
            super::chathistory::CHATHISTORY_LIMIT_MAX,
        ),
        format!(":{server_name} 422 {downstream_nick} :MOTD is on the upstream network"),
    ] {
        write.write_all(line.as_bytes()).await?;
        write.write_all(b"\r\n").await?;
    }
    write.flush().await?;

    let joined = read.unsplit(write);
    attach(joined, &handle, caps, &account, &downstream_nick).await
}

/// Drive registration to a `Registered` verdict. Requires a successful
/// SASL PLAIN exchange before the client is allowed to attach: an
/// unauthenticated CAP END or a bad credential closes the connection.
async fn handshake<R, W>(
    read: &mut R,
    write: &mut W,
    pool: &PgPool,
    server_name: &str,
) -> std::io::Result<Registered>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut framing = LineBuffer::new(e6irc_proto::message::MAX_CLIENT_FRAME_LEN);
    let mut buf = vec![0u8; 4096];
    let mut events = Vec::new();

    let mut nick: Option<String> = None;
    let mut have_user = false;
    let mut cap_open = false;
    let mut awaiting_payload = false;
    // Accumulates 400-byte AUTHENTICATE continuation chunks until a short line
    // completes the payload (SASL spec), mirroring the main IRC path. Both use
    // the protocol crate's shared bound so a client cannot grow it without end.
    let mut sasl_buf = String::new();
    let mut credential_attempts = crate::identity::CredentialAttemptBudget::default();
    let mut account: Option<String> = None;
    let mut caps = super::AttachCaps::default();

    loop {
        // Registration is complete only once the client has a nick, has
        // sent USER, has authenticated, and has closed CAP negotiation.
        if nick.is_some() && have_user && account.is_some() && !cap_open {
            break;
        }
        let n = read.read(&mut buf).await?;
        if n == 0 {
            return Ok(Registered::Closed);
        }
        framing.feed(&buf[..n], &mut events);
        for ev in events.drain(..) {
            let LineEvent::Line(line) = ev else {
                super::write_client_line_error(write, super::ClientLineError::TooLong).await?;
                continue;
            };
            let Ok(text) = std::str::from_utf8(&line) else {
                write
                    .write_all(b":*bnc* FAIL * INVALID_UTF8 :Message rejected, not valid UTF-8\r\n")
                    .await?;
                continue;
            };
            let msg = match super::parse_client_line(text) {
                Ok(msg) => msg,
                Err(error) => {
                    super::write_client_line_error(write, error).await?;
                    continue;
                }
            };
            match msg.command.to_ascii_uppercase().as_str() {
                "NICK" => match msg.params.as_slice() {
                    [candidate] if attach_selector_ok(candidate) => {
                        nick = Some(candidate.to_string());
                    }
                    [candidate, ..] => {
                        handshake_numeric(
                            write,
                            server_name,
                            nick.as_deref(),
                            432,
                            Some(candidate),
                            "Erroneous nickname/network selector",
                        )
                        .await?;
                    }
                    [] => {
                        handshake_numeric(
                            write,
                            server_name,
                            nick.as_deref(),
                            431,
                            None,
                            "No nickname given",
                        )
                        .await?;
                    }
                },
                "USER" => {
                    if msg.params.len() != 4 {
                        handshake_numeric(
                            write,
                            server_name,
                            nick.as_deref(),
                            461,
                            Some("USER"),
                            "Not enough parameters",
                        )
                        .await?;
                    } else {
                        have_user = true;
                    }
                }
                "CAP" => {
                    cap_open = true;
                    handle_cap(
                        write,
                        server_name,
                        "*",
                        &msg,
                        false,
                        &mut cap_open,
                        &mut caps,
                    )
                    .await?;
                }
                "AUTHENTICATE" => {
                    if msg.params.len() != 1 {
                        reject_sasl(write, server_name).await?;
                        continue;
                    }
                    let arg = msg.params.first().copied().unwrap_or("");
                    if !caps.sasl {
                        reject_sasl(write, server_name).await?;
                        continue;
                    }
                    if account.is_some() {
                        handshake_numeric(
                            write,
                            server_name,
                            nick.as_deref(),
                            907,
                            None,
                            "You have already authenticated",
                        )
                        .await?;
                        continue;
                    }
                    if arg.len() > e6irc_proto::sasl::MAX_AUTHENTICATE_CHUNK_LEN {
                        awaiting_payload = false;
                        sasl_buf.clear();
                        handshake_numeric(
                            write,
                            server_name,
                            nick.as_deref(),
                            905,
                            None,
                            "SASL message too long",
                        )
                        .await?;
                        continue;
                    }
                    if !awaiting_payload {
                        // Mechanism selection. Only PLAIN is offered.
                        if arg.eq_ignore_ascii_case("PLAIN") {
                            awaiting_payload = true;
                            write.write_all(b"AUTHENTICATE +\r\n").await?;
                        } else {
                            reject_sasl(write, server_name).await?;
                        }
                    } else if arg == "*" {
                        // Client abort.
                        awaiting_payload = false;
                        sasl_buf.clear();
                        handshake_numeric(
                            write,
                            server_name,
                            nick.as_deref(),
                            906,
                            None,
                            "SASL authentication aborted",
                        )
                        .await?;
                    } else {
                        // Continuation: a full 400-char line means more follows;
                        // a shorter line (or "+", the empty final chunk)
                        // completes the payload.
                        let piece = if arg == "+" { "" } else { arg };
                        if sasl_buf.len() + piece.len()
                            > e6irc_proto::sasl::MAX_AUTHENTICATE_PAYLOAD_LEN
                        {
                            awaiting_payload = false;
                            sasl_buf.clear();
                            reject_sasl(write, server_name).await?;
                        } else {
                            sasl_buf.push_str(piece);
                            if arg.len() != e6irc_proto::sasl::MAX_AUTHENTICATE_CHUNK_LEN {
                                awaiting_payload = false;
                                let payload = std::mem::take(&mut sasl_buf);
                                match verify_plain(pool, &payload, &mut credential_attempts).await {
                                    PlainVerification::Rejected => {
                                        // A failed attach authentication is a
                                        // security event; one bounded line per
                                        // rejection, without the credential.
                                        eprintln!(
                                            "bnc: SASL authentication failed on the attach listener"
                                        );
                                        reject_sasl(write, server_name).await?;
                                    }
                                    PlainVerification::Unavailable => {
                                        write
                                            .write_all(
                                                format!(
                                                    ":{server_name} 904 * :SASL authentication temporarily unavailable\r\n"
                                                )
                                                .as_bytes(),
                                            )
                                            .await?;
                                    }
                                    PlainVerification::Accepted(acct) => {
                                        write
                                            .write_all(
                                                format!(
                                                    ":{server_name} 900 * * {acct} :You are now logged in as {acct}\r\n\
                                                     :{server_name} 903 * :SASL authentication successful\r\n"
                                                )
                                                .as_bytes(),
                                            )
                                            .await?;
                                        account = Some(acct);
                                    }
                                    PlainVerification::AttemptsExhausted => {
                                        write
                                            .write_all(
                                                format!(
                                                    ":{server_name} ERROR :Closing Link: too many authentication attempts\r\n"
                                                )
                                                .as_bytes(),
                                            )
                                            .await?;
                                        return Ok(Registered::Closed);
                                    }
                                }
                            }
                            // else: 400-char chunk, keep awaiting_payload = true
                        }
                    }
                }
                "PING" => {
                    if let Some(token) = msg.params.first() {
                        write
                            .write_all(format!("PONG :{token}\r\n").as_bytes())
                            .await?;
                    } else {
                        handshake_numeric(
                            write,
                            server_name,
                            nick.as_deref(),
                            409,
                            None,
                            "No origin specified",
                        )
                        .await?;
                    }
                }
                "PONG" => {}
                "QUIT" => return Ok(Registered::Closed),
                command => {
                    handshake_numeric(
                        write,
                        server_name,
                        nick.as_deref(),
                        421,
                        Some(command),
                        "Unknown command",
                    )
                    .await?;
                }
            }
        }

        // A client that finished CAP + registration without ever
        // authenticating is refused rather than silently attached. A
        // SASL exchange still in flight (awaiting_payload) is not yet a
        // failure.
        if nick.is_some() && have_user && !cap_open && !awaiting_payload && account.is_none() {
            write
                .write_all(
                    format!(
                        ":{server_name} NOTICE * :Authentication required — attach with SASL PLAIN.\r\n"
                    )
                    .as_bytes(),
                )
                .await?;
            return Ok(Registered::Closed);
        }
    }

    let raw = nick.expect("checked");
    let account = account.expect("checked");
    // ZNC/soju `<nick>/<network>` addressing; a slash-less nick selects the
    // in-process `local` network (DESIGN §10.4: bare `alice` = `local`), so a
    // client that doesn't know the convention still reaches a working network
    // rather than being turned away.
    let (requested_nick, network) = raw.split_once('/').map_or(
        (raw.as_str(), super::local_driver::LOCAL_NETWORK),
        |(nick, network)| (nick, network),
    );
    Ok(Registered::Ok {
        account,
        network: network.to_string(),
        requested_nick: requested_nick.to_string(),
        caps,
    })
}

fn attach_selector_ok(selector: &str) -> bool {
    match selector.split_once('/') {
        Some((nick, network)) => {
            crate::sanitize::valid_nick(nick, 30) && crate::sanitize::valid_network_name(network)
        }
        None => crate::sanitize::valid_nick(selector, 30),
    }
}

async fn handshake_numeric<W>(
    write: &mut W,
    server_name: &str,
    nick: Option<&str>,
    numeric: u16,
    middle: Option<&str>,
    trailing: &str,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let target = nick.map(attach_reply_token).unwrap_or("*");
    let middle = middle
        .map(|value| format!(" {}", attach_reply_token(value)))
        .unwrap_or_default();
    write
        .write_all(
            format!(":{server_name} {numeric:03} {target}{middle} :{trailing}\r\n").as_bytes(),
        )
        .await
}

fn attach_reply_token(token: &str) -> &str {
    if token.is_empty() || token.starts_with(':') {
        "*"
    } else {
        e6irc_proto::message::truncate_on_char_boundary(token, 64)
    }
}

#[derive(Clone, Copy)]
enum AttachCapability {
    Sasl,
    ServerTime,
    MessageTags,
    AccountTag,
    EchoMessage,
    Batch,
    Chathistory,
    ReadMarker,
}

impl AttachCapability {
    const ALL: [Self; 8] = [
        Self::Sasl,
        Self::ServerTime,
        Self::MessageTags,
        Self::AccountTag,
        Self::EchoMessage,
        Self::Batch,
        Self::Chathistory,
        Self::ReadMarker,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Sasl => "sasl",
            Self::ServerTime => "server-time",
            Self::MessageTags => "message-tags",
            Self::AccountTag => "account-tag",
            Self::EchoMessage => "echo-message",
            Self::Batch => "batch",
            Self::Chathistory => "draft/chathistory",
            Self::ReadMarker => "draft/read-marker",
        }
    }

    fn parse(token: &str) -> Option<(Self, bool)> {
        let (name, enabled) = match token.strip_prefix('-') {
            Some(name) => (name, false),
            None => (token, true),
        };
        let capability = Self::ALL
            .into_iter()
            .find(|capability| capability.name() == name)?;
        Some((capability, enabled))
    }

    fn set(self, caps: &mut super::AttachCaps, enabled: bool) {
        match self {
            Self::Sasl => caps.sasl = enabled,
            Self::ServerTime => caps.server_time = enabled,
            Self::MessageTags => caps.message_tags = enabled,
            Self::AccountTag => caps.account_tag = enabled,
            Self::EchoMessage => caps.echo_message = enabled,
            Self::Batch => caps.batch = enabled,
            Self::Chathistory => caps.chathistory = enabled,
            Self::ReadMarker => caps.read_marker = enabled,
        }
    }

    fn enabled(self, caps: super::AttachCaps) -> bool {
        match self {
            Self::Sasl => caps.sasl,
            Self::ServerTime => caps.server_time,
            Self::MessageTags => caps.message_tags,
            Self::AccountTag => caps.account_tag,
            Self::EchoMessage => caps.echo_message,
            Self::Batch => caps.batch,
            Self::Chathistory => caps.chathistory,
            Self::ReadMarker => caps.read_marker,
        }
    }
}

fn cap_names(caps: Option<super::AttachCaps>) -> String {
    AttachCapability::ALL
        .into_iter()
        .filter(|capability| caps.is_none_or(|caps| capability.enabled(caps)))
        .map(AttachCapability::name)
        .collect::<Vec<_>>()
        .join(" ")
}

fn cap_reply(server_name: &str, target: &str, verb: &str, request: &str) -> (bool, String) {
    let head = format!(":{server_name} CAP {target} {verb} :");
    let budget = e6irc_proto::message::MAX_LINE_LEN - 2 - head.len();
    let fitted = request
        .char_indices()
        .take_while(|(index, character)| index + character.len_utf8() <= budget)
        .map(|(_, character)| character)
        .collect::<String>();
    (fitted.len() == request.len(), format!("{head}{fitted}\r\n"))
}

/// Answer a CAP command during BNC attach negotiation.
pub(super) async fn handle_cap<W>(
    write: &mut W,
    server_name: &str,
    target: &str,
    msg: &Message<'_>,
    registered: bool,
    cap_open: &mut bool,
    caps: &mut super::AttachCaps,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    match msg
        .params
        .first()
        .map(|s| s.to_ascii_uppercase())
        .as_deref()
    {
        Some("LS") => {
            write
                .write_all(
                    format!(":{server_name} CAP {target} LS :{}\r\n", cap_names(None)).as_bytes(),
                )
                .await?;
        }
        Some("LIST") => {
            write
                .write_all(
                    format!(
                        ":{server_name} CAP {target} LIST :{}\r\n",
                        cap_names(Some(*caps))
                    )
                    .as_bytes(),
                )
                .await?;
        }
        Some("REQ") => {
            let req = msg.params.get(1).copied().unwrap_or("");
            let mut requested = *caps;
            let all_known = !req.is_empty()
                && req
                    .split_whitespace()
                    .all(|token| match AttachCapability::parse(token) {
                        Some((capability, enabled)) => {
                            capability.set(&mut requested, enabled);
                            true
                        }
                        None => false,
                    });
            let (fits, ack) = cap_reply(server_name, target, "ACK", req);
            if all_known && fits {
                *caps = requested;
            }
            let reply = if all_known && fits {
                ack
            } else {
                cap_reply(server_name, target, "NAK", req).1
            };
            write.write_all(reply.as_bytes()).await?;
        }
        Some("END") if !registered => *cap_open = false,
        Some("END") => {}
        invalid => {
            let subcommand = invalid.map(attach_reply_token).unwrap_or("*");
            write
                .write_all(
                    format!(":{server_name} 410 {target} {subcommand} :Invalid CAP subcommand\r\n")
                        .as_bytes(),
                )
                .await?;
        }
    }
    Ok(())
}

async fn reject_sasl<W>(write: &mut W, server_name: &str) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write
        .write_all(format!(":{server_name} 904 * :SASL authentication failed\r\n").as_bytes())
        .await
}

/// Verify a SASL PLAIN payload (`base64(authzid \0 authcid \0 passwd)`)
/// against the account store. Returns the canonical account name.
enum PlainVerification {
    Accepted(String),
    Rejected,
    Unavailable,
    AttemptsExhausted,
}

async fn verify_plain(
    pool: &PgPool,
    payload: &str,
    attempts: &mut crate::identity::CredentialAttemptBudget,
) -> PlainVerification {
    if !attempts.consume() {
        return PlainVerification::AttemptsExhausted;
    }
    let Some(credentials) = e6irc_proto::sasl::parse_plain_payload(payload) else {
        return PlainVerification::Rejected;
    };
    // A DB failure is not an auth rejection (verify_credentials' contract):
    // fail closed, but surface the error instead of silently masking it as a
    // bad password.
    match crate::db::verify_credentials(pool, &credentials.account, &credentials.password).await {
        Ok(Some(name)) => PlainVerification::Accepted(name),
        Ok(None) => PlainVerification::Rejected,
        Err(e) => {
            eprintln!("bnc: credential check failed (database error): {e}");
            PlainVerification::Unavailable
        }
    }
}

#[cfg(test)]
mod cap_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn attach_capabilities_have_one_advertised_and_requested_set() {
        let mut caps = super::super::AttachCaps::default();
        for capability in AttachCapability::ALL {
            let (parsed, enabled) = AttachCapability::parse(capability.name()).expect("known cap");
            parsed.set(&mut caps, enabled);
        }
        assert_eq!(cap_names(Some(caps)), cap_names(None));

        let (capability, enabled) = AttachCapability::parse("-echo-message").expect("known cap");
        capability.set(&mut caps, enabled);
        assert!(!cap_names(Some(caps)).contains("echo-message"));
        assert!(AttachCapability::parse("unknown").is_none());
    }

    #[test]
    fn cap_reply_never_exceeds_the_wire_limit() {
        let request = std::iter::repeat_n("server-time", 80)
            .collect::<Vec<_>>()
            .join(" ");
        let (fits, reply) = cap_reply("bnc.example", "*", "ACK", &request);
        assert!(!fits);
        assert!(reply.len() <= e6irc_proto::message::MAX_LINE_LEN);
    }

    #[tokio::test]
    async fn cap_list_reports_only_enabled_attach_capabilities() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let mut caps = super::super::AttachCaps::default();
        let mut cap_open = false;
        let request = Message::parse("CAP REQ :sasl echo-message").expect("CAP request");
        handle_cap(
            &mut server,
            "bnc.example",
            "*",
            &request,
            false,
            &mut cap_open,
            &mut caps,
        )
        .await
        .expect("CAP request reply");
        let list = Message::parse("CAP LIST").expect("CAP list");
        handle_cap(
            &mut server,
            "bnc.example",
            "*",
            &list,
            false,
            &mut cap_open,
            &mut caps,
        )
        .await
        .expect("CAP list reply");
        server.shutdown().await.expect("close server half");

        let mut replies = String::new();
        client
            .read_to_string(&mut replies)
            .await
            .expect("read replies");
        assert!(replies.contains(" CAP * ACK :sasl echo-message\r\n"));
        assert!(replies.contains(" CAP * LIST :sasl echo-message\r\n"));
    }

    #[tokio::test]
    async fn invalid_cap_subcommand_fails_loudly() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let mut caps = super::super::AttachCaps::default();
        let mut cap_open = false;
        let request = Message::parse("CAP SURPRISE").expect("CAP request");
        handle_cap(
            &mut server,
            "bnc.example",
            "*",
            &request,
            false,
            &mut cap_open,
            &mut caps,
        )
        .await
        .expect("CAP rejection");
        server.shutdown().await.expect("close server half");
        let mut reply = String::new();
        client.read_to_string(&mut reply).await.expect("read reply");
        assert_eq!(
            reply,
            ":bnc.example 410 * SURPRISE :Invalid CAP subcommand\r\n"
        );
    }
}

#[cfg(test)]
mod handshake_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn attach_selector_uses_the_shared_bounded_network_name_language() {
        assert!(attach_selector_ok("alice/libera"));
        assert!(attach_selector_ok("alice"));
        assert!(!attach_selector_ok("alice/"));
        assert!(!attach_selector_ok("alice/bad/name"));
        assert!(!attach_selector_ok(&format!("alice/{}", "x".repeat(65))));
    }

    #[tokio::test]
    async fn attach_sasl_rejects_an_oversized_chunk_and_resets_the_attempt() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1/unused")
            .expect("lazy pool");
        let (client, server) = tokio::io::duplex(16 * 1024);
        let (mut client_read, mut client_write) = tokio::io::split(client);
        let (mut server_read, mut server_write) = tokio::io::split(server);
        let task = tokio::spawn(async move {
            handshake(&mut server_read, &mut server_write, &pool, "bnc.example").await
        });
        client_write
            .write_all(
                format!(
                    "CAP REQ :sasl\r\nAUTHENTICATE PLAIN\r\nAUTHENTICATE {}\r\nAUTHENTICATE PLAIN\r\nAUTHENTICATE *\r\nQUIT :done\r\n",
                    "x".repeat(e6irc_proto::sasl::MAX_AUTHENTICATE_CHUNK_LEN + 1)
                )
                .as_bytes(),
            )
            .await
            .expect("write handshake");
        client_write.shutdown().await.expect("close input");

        let mut replies = String::new();
        client_read
            .read_to_string(&mut replies)
            .await
            .expect("read replies");
        assert!(
            replies.contains(" 905 * :SASL message too long\r\n"),
            "{replies}"
        );
        assert_eq!(
            replies.matches("AUTHENTICATE +\r\n").count(),
            2,
            "{replies}"
        );
        assert!(
            replies.contains(" 906 * :SASL authentication aborted\r\n"),
            "{replies}"
        );
        assert!(matches!(
            task.await
                .expect("handshake task")
                .expect("handshake result"),
            Registered::Closed
        ));
    }

    #[tokio::test]
    async fn malformed_attach_sasl_attempts_cannot_bypass_the_budget() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1/unused")
            .expect("lazy pool");
        let mut attempts = crate::identity::CredentialAttemptBudget::default();
        for _ in 0..8 {
            assert!(matches!(
                verify_plain(&pool, "not-base64!", &mut attempts).await,
                PlainVerification::Rejected
            ));
        }
        assert!(matches!(
            verify_plain(&pool, "not-base64!", &mut attempts).await,
            PlainVerification::AttemptsExhausted
        ));
    }

    #[tokio::test]
    async fn malformed_and_unknown_handshake_input_fails_loudly() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1/unused")
            .expect("lazy pool");
        let (client, server) = tokio::io::duplex(16 * 1024);
        let (mut client_read, mut client_write) = tokio::io::split(client);
        let (mut server_read, mut server_write) = tokio::io::split(server);
        let task = tokio::spawn(async move {
            handshake(&mut server_read, &mut server_write, &pool, "bnc.example").await
        });
        client_write
            .write_all(
                b"NICK alice/libera\r\nUSER only-one-param\r\nWAT value\r\nBAD\0LINE\r\nCAP SURPRISE\r\nPING :token\r\nQUIT :done\r\n",
            )
            .await
            .expect("write handshake");
        client_write.shutdown().await.expect("close input");
        let mut replies = String::new();
        client_read
            .read_to_string(&mut replies)
            .await
            .expect("read replies");
        assert!(replies.contains(" 461 alice/libera USER :Not enough parameters\r\n"));
        assert!(replies.contains(" 421 alice/libera WAT :Unknown command\r\n"));
        assert!(replies.contains(" FAIL * INVALID_MESSAGE :Malformed line\r\n"));
        assert!(replies.contains(" 410 * SURPRISE :Invalid CAP subcommand\r\n"));
        assert!(replies.contains("PONG :token\r\n"));
        assert!(matches!(
            task.await
                .expect("handshake task")
                .expect("handshake result"),
            Registered::Closed
        ));
    }
}

#[cfg(test)]
mod key_tests {
    use super::*;

    #[test]
    fn registry_key_folds_owner_and_name_so_casing_cannot_miss() {
        // A miss does not error: `get` falls through to the shared network, so
        // either field spelled differently than it was registered would silently
        // attach a client to the operator's network instead of its own.
        let registered = NetworkKey::new(Some("Alice"), "libera");
        assert_eq!(registered, NetworkKey::new(Some("alice"), "libera"));
        assert_eq!(registered, NetworkKey::new(Some("ALICE"), "libera"));
        // RFC1459 folds these too, and nicks may contain them.
        assert_eq!(
            NetworkKey::new(Some("Ali[ce]"), "n"),
            NetworkKey::new(Some("ali{ce}"), "n")
        );
        // The network name is folded too: `/network Foo` must resolve to an owned
        // `foo`, not fall through to an operator's shared network of that name.
        assert_eq!(registered, NetworkKey::new(Some("alice"), "Libera"));
        assert_eq!(registered, NetworkKey::new(Some("alice"), "LIBERA"));
        // A different account is still a different key, and the shared owner
        // stays distinct from any account.
        assert_ne!(registered, NetworkKey::new(Some("bob"), "libera"));
        assert_ne!(registered, NetworkKey::new(None, "libera"));
        // A genuinely different name is still a different key.
        assert_ne!(registered, NetworkKey::new(Some("alice"), "oftc"));
    }

    #[tokio::test]
    async fn remove_owner_stops_exactly_that_accounts_networks() {
        let registry = Registry {
            networks: Mutex::new(HashMap::new()),
            mutations: tokio::sync::Mutex::new(()),
            pool: None,
            telemetry: None,
        };
        registry.add(
            Some("Alice"),
            "libera",
            Box::new(crate::bouncer::LoopbackDriver::new(16)),
        );
        registry.add(
            Some("alice"),
            "oftc",
            Box::new(crate::bouncer::LoopbackDriver::new(16)),
        );
        registry.add(
            Some("Bob"),
            "libera",
            Box::new(crate::bouncer::LoopbackDriver::new(16)),
        );
        registry.add(
            None,
            "shared",
            Box::new(crate::bouncer::LoopbackDriver::new(16)),
        );
        let alice_libera = registry
            .get_owned("ALICE", "LIBERA")
            .expect("Alice network");
        let alice_oftc = registry.get_owned("alice", "oftc").expect("Alice network");
        let bob = registry.get_owned("bob", "libera").expect("Bob network");
        let shared = registry.get_shared("shared").expect("shared network");

        assert_eq!(registry.remove_owner("aLICE").await, 2);
        assert!(*alice_libera.watch_shutdown().borrow());
        assert!(*alice_oftc.watch_shutdown().borrow());
        assert!(!*bob.watch_shutdown().borrow());
        assert!(!*shared.watch_shutdown().borrow());
        assert!(registry.get_owned("alice", "libera").is_none());
        assert!(registry.get_owned("alice", "oftc").is_none());
        assert!(registry.get_owned("bob", "libera").is_some());
        assert!(registry.get_shared("shared").is_some());
        assert_eq!(
            registry.remove_owner("alice").await,
            0,
            "retries are idempotent"
        );
    }
}
