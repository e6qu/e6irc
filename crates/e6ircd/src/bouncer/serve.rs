//! BNC listener glue: a registry of always-on networks and the
//! per-client serve loop. A client must authenticate with SASL PLAIN
//! against its account, then selects a network from the `nick/network`
//! suffix; the loop greets it as the bouncer and hands off to `attach`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sqlx::PgPool;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::{AccountRevocations, BufferedLine, NetworkConfig, NetworkHandle, OwnerHold, attach};
use crate::config::NetworkEntry;
use e6irc_proto::framing::LineEvent;
use e6irc_proto::message::{Message, MiddleParam};

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
    networks: Mutex<Networks>,
    /// Serializes durable runtime mutations with their registry side effect.
    /// A database update and `add`/`remove` are one logical transition: without
    /// this gate, a concurrent delete could remove the row, then lose a race to
    /// an older edit adding its driver back as an untracked live network.
    mutations: Arc<tokio::sync::Mutex<()>>,
    pool: Option<PgPool>,
    /// The master keyring, which seals the keys of the channels a stored
    /// network remembers; `None` when the server has none, and then no key
    /// is stored.
    secret_keys: Option<Arc<crate::secret::SecretKeyring>>,
    telemetry: Option<Arc<crate::observability::Telemetry>>,
    /// The server's policy on upstreams inside its own network, applied to
    /// every driver this registry builds.
    internal_upstreams: crate::egress::InternalUpstreams,
    /// How long history is kept — the core's own cell, so every network's
    /// backlog ages out at the bound the core's rings do, live as it changes.
    history_retention: crate::core::HistoryRetention,
    /// The in-process core, for restarting a configured `local` network its
    /// owner's reactivation releases; `None` only in tests that start none.
    core: Option<super::CoreHandles>,
    /// Every attachment's lease on its account's authority; the account
    /// lifecycle revokes them on the mutation lane.
    revocations: Arc<AccountRevocations>,
    /// What this server has applied of each account's authority, so a change
    /// is applied here once whichever server committed it.
    authority: crate::account_authority::AuthorityLedger,
}

/// What the registry holds: the running networks, and what an attaching
/// client is told about a stored network that is not among them.
#[derive(Default)]
struct Networks {
    slots: HashMap<NetworkKey, Slot>,
    /// Networks whose driver a mutation is replacing: taken out of `slots`
    /// while the old driver stops, back once its successor starts.
    replacing: std::collections::HashSet<NetworkKey>,
    /// Enabled stored networks whose driver could not be built at boot, with
    /// why, until a mutation starts one.
    unstartable: HashMap<NetworkKey, String>,
    /// Set once a process shutdown has stopped every driver: from then on no
    /// driver starts, so none dials an upstream it would never say `QUIT` to.
    closed: bool,
}

/// Why an attaching client finds no driver for a network it owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NotRunning {
    /// A mutation is stopping the old driver to start its successor.
    Replacing,
    /// The driver could not be built at boot, for this reason.
    FailedToStart(String),
    /// Nothing runs and nothing is on the way.
    Absent,
}

/// A registry transition refused because the process is shutting down: the
/// drivers have been stopped for good, and one started now would dial an
/// upstream it never leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RegistryClosed;

impl std::fmt::Display for RegistryClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the server is shutting down; no network is started")
    }
}

impl std::error::Error for RegistryClosed {}

/// Why a registry transition that starts a driver did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegistryRefusal {
    ConfiguredNetworkHeld(ConfiguredNetworkHeld),
    Closed(RegistryClosed),
}

impl From<ConfiguredNetworkHeld> for RegistryRefusal {
    fn from(held: ConfiguredNetworkHeld) -> Self {
        Self::ConfiguredNetworkHeld(held)
    }
}

impl From<RegistryClosed> for RegistryRefusal {
    fn from(closed: RegistryClosed) -> Self {
        Self::Closed(closed)
    }
}

impl std::fmt::Display for RegistryRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConfiguredNetworkHeld(held) => held.fmt(f),
            Self::Closed(closed) => closed.fmt(f),
        }
    }
}

impl std::error::Error for RegistryRefusal {}

/// Why [`Registry::add`] started no driver: a live one is already registered
/// under the key, or the registry has closed.
#[derive(Debug)]
pub(crate) enum AddRefused {
    AlreadyRunning { label: String },
    Closed(RegistryClosed),
}

impl std::fmt::Display for AddRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyRunning { label } => write!(f, "network '{label}' is already running"),
            Self::Closed(closed) => closed.fmt(f),
        }
    }
}

impl std::error::Error for AddRefused {}

/// A registry transition refused because the key is held by a network the
/// server's configuration defines: the operator owns it, so no account-level
/// mutation (create, edit, enable, disable, delete) may replace or stop it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfiguredNetworkHeld;

impl std::fmt::Display for ConfiguredNetworkHeld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "the server configuration defines this network; only the operator can change it",
        )
    }
}

impl std::error::Error for ConfiguredNetworkHeld {}

/// What a configuration-defined network states, without its secrets: the
/// fields an owner or administrator view shows, with each credential reduced
/// to whether it is present (an IRC SASL account is a public login and is
/// shown; a bridge's account field is a token and is not).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredNetwork {
    /// The name as the configuration spells it.
    pub name: String,
    /// The owning account as the configuration spells it; `None` when shared.
    pub owner: Option<String>,
    pub kind: crate::config::NetworkKind,
    pub addr: String,
    pub tls: bool,
    pub nick: String,
    pub username: Option<String>,
    pub realname: Option<String>,
    pub autojoin: Vec<String>,
    pub sasl_account: Option<String>,
    pub has_sasl_account: bool,
    pub has_sasl_password: bool,
    pub has_server_password: bool,
    /// The fingerprints of the client certificate the configuration names,
    /// as read when the network last started.
    pub client_certificate: Option<e6irc_client::Fingerprints>,
}

impl ConfiguredNetwork {
    /// The view of `entry`, presenting `certificate` (read from the files
    /// the entry names).
    pub(crate) fn from_entry(
        entry: &NetworkEntry,
        certificate: Option<&e6irc_client::ClientCertificate>,
    ) -> Self {
        Self {
            client_certificate: certificate.map(|certificate| e6irc_client::Fingerprints {
                sha256: certificate.fingerprint_sha256(),
                sha512: certificate.fingerprint_sha512(),
            }),
            name: entry.name.clone(),
            owner: entry.owner.clone(),
            kind: entry.kind,
            addr: entry.addr.clone(),
            tls: entry.tls,
            nick: entry.nick.clone(),
            username: entry.username.clone(),
            realname: entry.realname.clone(),
            autojoin: entry.autojoin.clone(),
            sasl_account: entry
                .sasl_account
                .clone()
                .filter(|_| !entry.kind.account_is_secret()),
            has_sasl_account: entry.sasl_account.is_some(),
            has_sasl_password: entry.sasl_password.is_some(),
            has_server_password: entry.server_password.is_some(),
        }
    }
}

/// Where a registered network is defined, which decides who may change it
/// and what its stored lines may name.
#[derive(Debug, Clone)]
pub enum NetworkDefinition {
    /// A network in the server's configuration: the operator's.
    Configured(Arc<ConfiguredNetwork>),
    /// A `bnc_networks` row an account created: the account's.
    Stored,
}

impl NetworkDefinition {
    fn storage(&self) -> crate::db::BncNetworkDefinition {
        match self {
            Self::Configured(_) => crate::db::BncNetworkDefinition::Configured,
            Self::Stored => crate::db::BncNetworkDefinition::Stored,
        }
    }
}

/// What a registry stores its networks' state in: the database, and the
/// master keyring that seals the secrets it writes there. Without a pool
/// nothing is stored.
#[derive(Default)]
pub(crate) struct Storage {
    pub(crate) pool: Option<PgPool>,
    pub(crate) secret_keys: Option<Arc<crate::secret::SecretKeyring>>,
    /// The channels each configured IRC network remembered when the process
    /// last stopped, by its folded owner (`None` when shared) and name.
    pub(crate) configured_channels: ConfiguredChannels,
}

/// [`Storage::configured_channels`].
pub(crate) type ConfiguredChannels =
    HashMap<(Option<String>, String), Vec<super::RememberedChannel>>;

/// The client certificate a configured network names, read and checked.
fn configured_certificate(
    e: &NetworkEntry,
) -> Result<Option<e6irc_client::ClientCertificate>, String> {
    e.client_certificate
        .as_ref()
        .map(crate::config::ClientCertificateFiles::load)
        .transpose()
        .map_err(|error| format!("network '{}': {error}", e.name))
}

/// A registered network: its driver handle, the persistence task that
/// mirrors upstream lines to the database, and where it is defined.
struct Slot {
    handle: Arc<NetworkHandle>,
    persistence: Option<Persistence>,
    /// For a stored IRC network with a database, the writer of the channels it
    /// rejoins after a restart.
    memory: Option<super::channel_memory::ChannelMemory>,
    /// The driver's stable kind (`irc`, `matrix`, `discord`, `slack`, …),
    /// captured before `start()` consumes the driver — for status views.
    kind: &'static str,
    definition: NetworkDefinition,
    /// For a configured network, the entry it was started from — what its
    /// owner's reactivation restarts it with. `None` for a stored network.
    restart: Option<Arc<NetworkEntry>>,
    /// Set while a configured network is held stopped by its owner's account
    /// lifecycle; its handle's driver has stopped.
    hold: Option<OwnerHold>,
}

impl Slot {
    fn is_configured(&self) -> bool {
        matches!(self.definition, NetworkDefinition::Configured(_))
    }

    /// A configured network held stopped from the start: its owner was
    /// suspended or deleted before this process began. No driver runs; the
    /// handle only reports the hold.
    fn held(
        label: String,
        entry: &NetworkEntry,
        definition: NetworkDefinition,
        hold: OwnerHold,
        remembered: Vec<super::RememberedChannel>,
    ) -> Self {
        let (handle, ends) = NetworkHandle::channels(entry.buffer_cap);
        drop(ends);
        // Kept while held: the release carries them over to the driver it
        // starts.
        handle.joined_channels().remember(remembered);
        handle.set_label(label);
        handle.runtime.hold(hold);
        Self {
            handle: Arc::new(handle),
            persistence: None,
            memory: None,
            kind: entry.kind.as_db_str(),
            definition,
            restart: Some(Arc::new(entry.clone())),
            hold: Some(hold),
        }
    }
}

/// The driver for a configuration-defined network, built from its entry by
/// the one parser configuration validation uses
/// ([`NetworkEntry::upstream_identity`]), so an entry accepted when it was
/// saved starts. `local` needs the in-process core handles.
fn configured_driver(
    e: &NetworkEntry,
    core: Option<&super::CoreHandles>,
    internal_upstreams: crate::egress::InternalUpstreams,
    certificate: Option<e6irc_client::ClientCertificate>,
    remembered_channels: Vec<super::RememberedChannel>,
) -> Result<Box<dyn super::NetworkDriver>, String> {
    use crate::config::NetworkKind;
    if e.kind == NetworkKind::Local {
        let core = core.ok_or_else(|| {
            format!(
                "network '{}': a local network needs the in-process core",
                e.name
            )
        })?;
        let identity = e
            .upstream_identity()
            .map_err(|error| format!("network '{}': {error}", e.name))?;
        let config = NetworkConfig {
            addr: e.addr.clone(),
            tls: e.tls,
            nick: identity.nick,
            username: identity.username,
            realname: identity.realname,
            autojoin: identity.autojoin,
            buffer_cap: e.buffer_cap,
            sasl: None,
            client_certificate: None,
            remembered_channels: Vec::new(),
            tls_roots: None,
            server_password: None,
            keepalive_idle: super::KEEPALIVE_IDLE,
            rejection_retry_floor: super::REJECTION_RETRY_FLOOR,
            internal_upstreams,
            first_dial: super::FirstDial::Immediate,
            nick_regain: super::NickRegainTiming::default(),
        };
        return Ok(Box::new(super::LocalDriver::new(core.clone(), config)));
    }
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
    super::build_driver(super::DriverSpec {
        kind: e.kind,
        owner: e.owner.clone(),
        name: e.name.clone(),
        addr: e.addr.clone(),
        tls: e.tls,
        nick: e.nick.clone(),
        username: e.username.clone(),
        realname,
        autojoin: e.autojoin_entries(),
        buffer_cap: e.buffer_cap,
        sasl_account: e.sasl_account.clone(),
        sasl_password: e.sasl_password.clone(),
        server_password: e.server_password.clone(),
        client_certificate: certificate,
        remembered_channels,
        internal_upstreams,
        first_dial: super::FirstDial::Immediate,
    })
    .map_err(|msg| format!("network '{}': {msg}", e.name))
}

/// A read-only snapshot of one registered network, for status/management views.
pub struct NetworkStatus {
    /// Owning account (casefolded), or `None` for a server-level shared network.
    pub owner: Option<String>,
    pub name: String,
    pub kind: &'static str,
    pub connected: bool,
    pub runtime: super::NetworkRuntimeSnapshot,
    /// What the configuration states, for a configuration-defined network;
    /// `None` for an account's stored network.
    pub configured: Option<Arc<ConfiguredNetwork>>,
    /// The channels the session rejoins besides its autojoin.
    pub remembered: Vec<super::RememberedChannel>,
}

/// A network's persistence task and the signal that ends it.
struct Persistence {
    stop: tokio::sync::oneshot::Sender<UnwrittenLines>,
    task: tokio::task::JoinHandle<()>,
}

/// What a stopping network's persistence task does with the lines its driver
/// said last, which it has received but not yet written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnwrittenLines {
    /// Write them: the network's rows outlive the stop (an edit, a disable,
    /// a suspension), and its backlog must not lose its last lines — the
    /// driver's own goodbye among them.
    Store,
    /// Drop them: the network's rows are about to be deleted.
    Discard,
}

impl Persistence {
    /// End the task between two writes and wait until it has: when this
    /// returns, no statement of this task is in flight or still to come. An
    /// abort cancelled the task wherever it was — possibly with an INSERT
    /// already sent — so a caller deleting the network's rows next could race
    /// the task's last line.
    async fn stop(self, unwritten: UnwrittenLines) {
        report_persistence_end(self.signal(unwritten).await);
    }

    /// [`Persistence::stop`] bounded by `deadline`, for a process shutdown:
    /// the task writes what it still holds until then, and only a task still
    /// writing at the deadline (a wedged database) is aborted. `true` when it
    /// finished before the deadline.
    async fn stop_by(self, unwritten: UnwrittenLines, deadline: tokio::time::Instant) -> bool {
        let mut task = self.signal(unwritten);
        match tokio::time::timeout_at(deadline, &mut task).await {
            Ok(ended) => {
                report_persistence_end(ended);
                true
            }
            Err(_elapsed) => {
                task.abort();
                false
            }
        }
    }

    /// Send the stop and hand back the task to join.
    fn signal(self, unwritten: UnwrittenLines) -> tokio::task::JoinHandle<()> {
        // A task that already ended (its event stream closed) cannot take
        // the signal; the join still reports how it ended.
        if self.stop.send(unwritten).is_err() {
            eprintln!("bnc: persistence task had already stopped");
        }
        self.task
    }
}

fn report_persistence_end(ended: Result<(), tokio::task::JoinError>) {
    if let Err(error) = ended {
        eprintln!("bnc: persistence task ended abnormally: {error}");
    }
}

/// How a process shutdown's stop of every driver went: of `running` networks,
/// how many released their upstream, and how many wrote their last backlog
/// lines, before the shutdown deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverStops {
    pub running: usize,
    pub released: usize,
    pub backlog_written: usize,
}

impl Slot {
    /// Stop the driver authoritatively and the persistence task with it.
    ///
    /// The driver observes `handle.shutdown()` regardless of who still holds a
    /// command sender — an attached client clones `commands`, so relying on
    /// refcount alone would keep the upstream connection (and its decrypted
    /// SASL password) alive until the last client detached. The persistence
    /// task then finishes the line it is writing and ends, so a caller that
    /// deletes the network's rows after this returns cannot be overtaken by a
    /// late line.
    async fn stop(self, unwritten: UnwrittenLines) {
        self.handle.shutdown_and_wait().await;
        if let Some(persistence) = self.persistence {
            persistence.stop(unwritten).await;
        }
        if let Some(memory) = self.memory {
            memory.stop(unwritten).await;
        }
    }
}

impl Registry {
    /// The server's policy on upstreams inside its own network.
    pub fn internal_upstreams(&self) -> crate::egress::InternalUpstreams {
        self.internal_upstreams
    }

    /// Start a driver per configured (server-level) network. `pool`, when
    /// present, enables buffer persistence and backlog restore; `core`
    /// (the in-process handles) is required for any `local` network.
    /// `holds` names the owners whose account is suspended or deleted (by
    /// folded name): their configured networks are registered held, and
    /// start no driver.
    pub(crate) fn start_observed(
        entries: &[NetworkEntry],
        holds: &HashMap<String, OwnerHold>,
        storage: Storage,
        core: super::CoreHandles,
        telemetry: Arc<crate::observability::Telemetry>,
        internal_upstreams: crate::egress::InternalUpstreams,
    ) -> Result<Self, String> {
        Self::start_inner(
            entries,
            holds,
            storage,
            core,
            Some(telemetry),
            internal_upstreams,
        )
    }

    fn start_inner(
        entries: &[NetworkEntry],
        holds: &HashMap<String, OwnerHold>,
        storage: Storage,
        core: super::CoreHandles,
        telemetry: Option<Arc<crate::observability::Telemetry>>,
        internal_upstreams: crate::egress::InternalUpstreams,
    ) -> Result<Self, String> {
        let registry = Self {
            networks: Mutex::new(Networks::default()),
            mutations: Arc::new(tokio::sync::Mutex::new(())),
            pool: storage.pool,
            secret_keys: storage.secret_keys,
            telemetry,
            internal_upstreams,
            history_retention: core.core_tx.history_retention(),
            core: Some(core),
            revocations: AccountRevocations::new(),
            authority: crate::account_authority::AuthorityLedger::default(),
        };
        let mut configured_channels = storage.configured_channels;
        for e in entries {
            let certificate = configured_certificate(e)?;
            let definition = NetworkDefinition::Configured(Arc::new(
                ConfiguredNetwork::from_entry(e, certificate.as_ref()),
            ));
            let key = NetworkKey::new(e.owner.as_deref(), &e.name);
            let remembered = configured_channels
                .remove(&(key.owner.clone(), key.name.clone()))
                .unwrap_or_default();
            let hold = e.owner.as_deref().and_then(|owner| {
                holds
                    .get(&e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(owner))
                    .copied()
            });
            if let Some(hold) = hold {
                // Built anyway, so an entry that could never start still fails
                // the boot as it would for an active owner.
                configured_driver(
                    e,
                    registry.core.as_ref(),
                    internal_upstreams,
                    certificate,
                    Vec::new(),
                )?;
                let label = format!("{}/{}", key.display_owner(), e.name);
                let mut networks = registry.networks.lock().expect("registry poisoned");
                if networks.slots.contains_key(&key) {
                    return Err(AddRefused::AlreadyRunning { label }.to_string());
                }
                networks
                    .slots
                    .insert(key, Slot::held(label, e, definition, hold, remembered));
                continue;
            }
            let driver = configured_driver(
                e,
                registry.core.as_ref(),
                internal_upstreams,
                certificate,
                remembered,
            )?;
            registry
                .insert(
                    e.owner.as_deref(),
                    &e.name,
                    definition,
                    driver,
                    Some(Arc::new(e.clone())),
                    None,
                )
                .map_err(|error| error.to_string())?;
        }
        Ok(registry)
    }

    /// Every attachment's lease on its account's authority.
    pub fn account_revocations(&self) -> &Arc<AccountRevocations> {
        &self.revocations
    }

    /// Run `work` on the one serialized control-plane mutation path, to
    /// completion: callers hold the lane across the database write and the
    /// matching registry transition.
    ///
    /// The work runs as its own task, and the caller only awaits it. An HTTP
    /// request abandoned at its deadline therefore abandons only the waiting,
    /// never a transition half made — a driver stopped whose replacement never
    /// starts, or an account suspended in the database whose sessions the core
    /// never heard about. The registry's transitions exist only on the
    /// [`MutationLane`] this hands to `work`, so none can be run anywhere else.
    pub(crate) async fn mutate<T, F, Fut>(self: &Arc<Self>, work: F) -> T
    where
        F: FnOnce(MutationLane) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let registry = self.clone();
        let mutation = tokio::spawn(async move {
            let serialized = registry.mutations.clone().lock_owned().await;
            work(MutationLane {
                registry,
                _serialized: serialized,
            })
            .await
        });
        match mutation.await {
            Ok(done) => done,
            Err(error) => match error.try_into_panic() {
                Ok(panic) => std::panic::resume_unwind(panic),
                Err(error) => {
                    panic!("a registry mutation was cancelled by the runtime stopping: {error}")
                }
            },
        }
    }

    /// Start a driver for `(owner, name)` and register it. With a database,
    /// restore recent backlog and persist new lines; `definition` says whether
    /// those lines belong to a stored network's row (see
    /// [`crate::db::open_bnc_buffer`]).
    ///
    /// A key that already holds a live driver is refused *before* the new
    /// driver starts, so a caller can never leave two upstream sessions racing
    /// for one network, and so is every start once a shutdown has closed the
    /// registry. Callers that mean "supersede" use [`MutationLane::replace`];
    /// callers that mean "make sure it runs" use
    /// [`MutationLane::ensure_running`]. Private: past construction, only the
    /// mutation lane starts a driver.
    fn add(
        &self,
        owner: Option<&str>,
        name: &str,
        definition: NetworkDefinition,
        driver: Box<dyn super::NetworkDriver>,
    ) -> Result<(), AddRefused> {
        self.insert(owner, name, definition, driver, None, None)
    }

    /// [`Registry::add`], remembering the configuration entry a configured
    /// network can be restarted from.
    fn insert(
        &self,
        owner: Option<&str>,
        name: &str,
        definition: NetworkDefinition,
        driver: Box<dyn super::NetworkDriver>,
        restart: Option<Arc<NetworkEntry>>,
        predecessor: Option<Arc<NetworkHandle>>,
    ) -> Result<(), AddRefused> {
        let key = NetworkKey::new(owner, name);
        // Held across the start, so the occupancy check cannot race a second
        // writer between check and insert.
        let mut networks = self.networks.lock().expect("registry poisoned");
        if networks.closed {
            return Err(AddRefused::Closed(RegistryClosed));
        }
        if networks.slots.contains_key(&key) {
            return Err(AddRefused::AlreadyRunning {
                label: format!("{}/{}", key.display_owner(), name),
            });
        }
        // Capture the kind before `prepare()` consumes the driver.
        let kind = driver.kind();
        let (handle, run) = driver.prepare().split();
        let handle = Arc::new(handle);
        handle.set_label(format!("{}/{}", key.display_owner(), name));
        handle.set_history_retention(self.history_retention.clone());
        if let Some(telemetry) = &self.telemetry {
            handle.set_telemetry(telemetry.clone());
        }
        // The persistence task keys `bnc_buffer` rows by the same casefolded
        // owner the registry uses, so a buffer cannot be written under one
        // spelling and looked up under another. It subscribes before the
        // driver runs, so it receives every line the driver ever says.
        let persistence = self.pool.clone().map(|pool| {
            handle.set_history(pool.clone(), key.owner.clone(), key.name.clone());
            spawn_persistence(
                pool,
                key.owner.clone(),
                key.name.clone(),
                definition.storage(),
                handle.clone(),
            )
        });
        // A stored IRC network remembers the channels its session is in
        // across restarts; a configured one has no row to remember them in.
        let memory = match (&self.pool, &definition, kind) {
            (Some(pool), definition, "irc") => Some(super::channel_memory::spawn(
                super::channel_memory::ChannelStore {
                    pool: pool.clone(),
                    owner: key.owner.clone(),
                    network: key.name.clone(),
                    definition: definition.storage(),
                    keys: self.secret_keys.clone(),
                },
                handle.clone(),
            )),
            _ => None,
        };
        // A reconfigured network goes on from where its predecessor was, keys
        // it learned included; written by the writer above, which is already
        // listening.
        if let Some(predecessor) = predecessor.filter(|_| kind == "irc") {
            handle
                .joined_channels()
                .carry_over(predecessor.joined_channels());
        }
        run.spawn();
        networks.unstartable.remove(&key);
        networks.slots.insert(
            key,
            Slot {
                handle,
                persistence,
                memory,
                kind,
                definition,
                restart,
                hold: None,
            },
        );
        Ok(())
    }

    /// Register a stored network at boot, through the mutation lane like
    /// every later start. A configuration-file network already holding the
    /// key wins, loudly.
    pub(crate) async fn start_stored(
        self: &Arc<Self>,
        owner: String,
        name: String,
        driver: Box<dyn super::NetworkDriver>,
    ) -> Result<(), AddRefused> {
        self.mutate(move |lane| async move {
            lane.registry
                .add(Some(&owner), &name, NetworkDefinition::Stored, driver)
        })
        .await
    }

    /// Remember that the stored network `(owner, name)` is enabled but its
    /// driver could not be built, so an attaching client is told why instead
    /// of being told it is disabled.
    pub(crate) fn record_unstartable(&self, owner: &str, name: &str, reason: String) {
        self.networks
            .lock()
            .expect("registry poisoned")
            .unstartable
            .insert(NetworkKey::new(Some(owner), name), reason);
    }

    /// Why the account's network `name` has no running driver, as far as the
    /// registry knows. The caller checks the stored row for whether it is
    /// enabled at all.
    pub(crate) fn not_running(&self, account: &str, name: &str) -> NotRunning {
        let networks = self.networks.lock().expect("registry poisoned");
        let key = NetworkKey::new(Some(account), name);
        if networks.replacing.contains(&key) {
            return NotRunning::Replacing;
        }
        match networks.unstartable.get(&key) {
            Some(reason) => NotRunning::FailedToStart(reason.clone()),
            None => NotRunning::Absent,
        }
    }

    /// Stop every driver, all at once, for a process shutdown: each says its
    /// goodbye (`QUIT`) and releases its upstream, so the restarted daemon does
    /// not meet its own ghosts, and its persistence task then writes the lines
    /// the driver said last — the rows outlive the process, so the backlog must
    /// not lose them. Both steps share one `deadline`; only a persistence task
    /// still writing when it passes is aborted.
    ///
    /// The drain takes the mutation lane first, so a transition in flight — a
    /// replace waiting for its old driver — finishes before it, and its new
    /// driver is stopped with the rest rather than started into an emptied
    /// registry. The registry is then closed: empty afterwards, and every
    /// later start is refused.
    pub async fn stop_all_within(&self, deadline: std::time::Duration) -> DriverStops {
        let deadline = tokio::time::Instant::now() + deadline;
        let slots: Vec<Slot> = {
            let _serialized = self.mutations.clone().lock_owned().await;
            let mut networks = self.networks.lock().expect("registry poisoned");
            networks.closed = true;
            networks.replacing.clear();
            networks.slots.drain().map(|(_, slot)| slot).collect()
        };
        let mut stops = tokio::task::JoinSet::new();
        for slot in slots {
            stops.spawn(async move {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                let released = slot.handle.shutdown_and_wait_within(remaining).await;
                let written = match slot.persistence {
                    Some(persistence) => persistence.stop_by(UnwrittenLines::Store, deadline).await,
                    None => true,
                };
                if let Some(memory) = slot.memory {
                    memory.stop_by(UnwrittenLines::Store, deadline).await;
                }
                (released, written)
            });
        }
        let mut report = DriverStops {
            running: stops.len(),
            released: 0,
            backlog_written: 0,
        };
        while let Some(outcome) = stops.join_next().await {
            let (released, written) = outcome.expect("a driver stop does not panic");
            report.released += usize::from(released);
            report.backlog_written += usize::from(written);
        }
        report
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
            .slots
            .get(&NetworkKey::new(Some(account), name))
            .map(|slot| slot.handle.clone())
    }

    /// The driver of the account's STORED network of that name, if one runs.
    /// A configuration-defined network under the same key is not it: its
    /// runtime must not be shown against, or read through, a stored row.
    pub fn get_stored(&self, account: &str, name: &str) -> Option<Arc<NetworkHandle>> {
        self.networks
            .lock()
            .expect("registry poisoned")
            .slots
            .get(&NetworkKey::new(Some(account), name))
            .filter(|slot| !slot.is_configured())
            .map(|slot| slot.handle.clone())
    }

    /// Whether the configuration defines the network `(owner, name)` running
    /// here — the operator's, which no account-level mutation may touch.
    pub fn holds_configured(&self, owner: Option<&str>, name: &str) -> bool {
        self.networks
            .lock()
            .expect("registry poisoned")
            .slots
            .get(&NetworkKey::new(owner, name))
            .is_some_and(Slot::is_configured)
    }

    /// The networks the server configuration defines for `account`, with
    /// their drivers, by name.
    pub fn configured_owned(
        &self,
        account: &str,
    ) -> Vec<(Arc<ConfiguredNetwork>, Arc<NetworkHandle>)> {
        let owner = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(account);
        let mut owned: Vec<_> = self
            .networks
            .lock()
            .expect("registry poisoned")
            .slots
            .iter()
            .filter(|(key, _)| key.owner.as_deref() == Some(owner.as_str()))
            .filter_map(|(key, slot)| match &slot.definition {
                NetworkDefinition::Configured(configured) => {
                    Some((key.name.clone(), configured.clone(), slot.handle.clone()))
                }
                NetworkDefinition::Stored => None,
            })
            .collect();
        owned.sort_by(|left, right| left.0.cmp(&right.0));
        owned
            .into_iter()
            .map(|(_, configured, handle)| (configured, handle))
            .collect()
    }

    /// The configuration-defined network `(account, name)`, with its driver.
    pub fn get_configured_owned(
        &self,
        account: &str,
        name: &str,
    ) -> Option<(Arc<ConfiguredNetwork>, Arc<NetworkHandle>)> {
        self.networks
            .lock()
            .expect("registry poisoned")
            .slots
            .get(&NetworkKey::new(Some(account), name))
            .and_then(|slot| match &slot.definition {
                NetworkDefinition::Configured(configured) => {
                    Some((configured.clone(), slot.handle.clone()))
                }
                NetworkDefinition::Stored => None,
            })
    }

    /// A shared (ownerless) network of that name, if any.
    pub fn get_shared(&self, name: &str) -> Option<Arc<NetworkHandle>> {
        self.networks
            .lock()
            .expect("registry poisoned")
            .slots
            .get(&NetworkKey::new(None, name))
            .map(|slot| slot.handle.clone())
    }

    /// A snapshot of every registered network — its owner, name, driver kind,
    /// and live connection state — for the console's status/integration views.
    pub fn list(&self) -> Vec<NetworkStatus> {
        self.networks
            .lock()
            .expect("registry poisoned")
            .slots
            .iter()
            .map(|(key, slot)| {
                let runtime = slot.handle.runtime_snapshot();
                NetworkStatus {
                    owner: key.owner.clone(),
                    name: key.name.clone(),
                    kind: slot.kind,
                    connected: runtime.lifecycle == super::NetworkLifecycle::Connected,
                    runtime,
                    configured: match &slot.definition {
                        NetworkDefinition::Configured(configured) => Some(configured.clone()),
                        NetworkDefinition::Stored => None,
                    },
                    remembered: slot.handle.joined_channels().remembered(),
                }
            })
            .collect()
    }
}

/// The registry's serialized mutation lane, held for one
/// [`Registry::mutate`] unit of work: the only place its transitions run.
pub(crate) struct MutationLane {
    registry: Arc<Registry>,
    _serialized: tokio::sync::OwnedMutexGuard<()>,
}

impl std::ops::Deref for MutationLane {
    type Target = Registry;

    fn deref(&self) -> &Registry {
        &self.registry
    }
}

impl MutationLane {
    /// The stored network's slot under `(owner, name)`, taken out of the
    /// registry, or `None` when nothing runs there; with `replacing`, the key
    /// is marked as being replaced until its successor starts. A
    /// configuration-defined network there is refused and left running: the
    /// operator owns it.
    fn take_stored(
        &self,
        owner: Option<&str>,
        name: &str,
        replacing: bool,
    ) -> Result<Option<Slot>, ConfiguredNetworkHeld> {
        let mut networks = self.registry.networks.lock().expect("registry poisoned");
        let key = NetworkKey::new(owner, name);
        if networks.slots.get(&key).is_some_and(Slot::is_configured) {
            return Err(ConfiguredNetworkHeld);
        }
        networks.unstartable.remove(&key);
        let slot = networks.slots.remove(&key);
        if replacing {
            networks.replacing.insert(key);
        }
        Ok(slot)
    }

    /// Replace one live driver of a stored network only after its predecessor
    /// has disconnected; meanwhile an attaching client is told the network is
    /// being reconfigured. A configuration-defined network under the key is
    /// refused and keeps running, and nothing starts once a shutdown has
    /// closed the registry.
    pub(crate) async fn replace(
        &self,
        owner: Option<&str>,
        name: &str,
        driver: Box<dyn super::NetworkDriver>,
    ) -> Result<(), RegistryRefusal> {
        if self
            .registry
            .networks
            .lock()
            .expect("registry poisoned")
            .closed
        {
            return Err(RegistryClosed.into());
        }
        let predecessor = match self.take_stored(owner, name, true)? {
            Some(old) => {
                let handle = old.handle.clone();
                old.stop(UnwrittenLines::Store).await;
                Some(handle)
            }
            None => None,
        };
        let added = self.registry.insert(
            owner,
            name,
            NetworkDefinition::Stored,
            driver,
            None,
            predecessor,
        );
        self.registry
            .networks
            .lock()
            .expect("registry poisoned")
            .replacing
            .remove(&NetworkKey::new(owner, name));
        match added {
            Ok(()) => Ok(()),
            // Only a shutdown closes the registry, and it waits for this lane.
            Err(AddRefused::Closed(closed)) => Err(closed.into()),
            Err(AddRefused::AlreadyRunning { label }) => {
                unreachable!("the mutation lane serializes registry writers, yet {label} runs")
            }
        }
    }

    /// Make the stored network `(owner, name)` run: start `driver` when nothing is registered,
    /// supersede a driver the upstream parked, and leave a working or still
    /// retrying one alone. Enabling an already-enabled network therefore never
    /// drops a healthy upstream session. Returns whether `driver` was started.
    pub(crate) async fn ensure_running(
        &self,
        owner: Option<&str>,
        name: &str,
        driver: Box<dyn super::NetworkDriver>,
    ) -> Result<bool, RegistryRefusal> {
        let running = {
            let networks = self.registry.networks.lock().expect("registry poisoned");
            match networks.slots.get(&NetworkKey::new(owner, name)) {
                Some(slot) if slot.is_configured() => return Err(ConfiguredNetworkHeld.into()),
                Some(slot) => Some(slot.handle.runtime_snapshot().lifecycle),
                None => None,
            }
        };
        match running {
            Some(
                super::NetworkLifecycle::Connecting
                | super::NetworkLifecycle::Connected
                | super::NetworkLifecycle::RegainingNickname
                | super::NetworkLifecycle::Reconnecting,
            ) => Ok(false),
            Some(
                super::NetworkLifecycle::AuthenticationFailed
                | super::NetworkLifecycle::RegistrationFailed
                | super::NetworkLifecycle::OwnerSuspended
                | super::NetworkLifecycle::OwnerDeleted,
            )
            | None => {
                self.replace(owner, name, driver).await?;
                Ok(true)
            }
        }
    }

    /// Remove `owner`'s stored network `name`, stopping its driver. Returns
    /// whether a network was removed; a configuration-defined network under
    /// the key is refused and keeps running.
    pub(crate) async fn remove(
        &self,
        owner: Option<&str>,
        name: &str,
        unwritten: UnwrittenLines,
    ) -> Result<bool, ConfiguredNetworkHeld> {
        match self.take_stored(owner, name, false)? {
            Some(slot) => {
                slot.stop(unwritten).await;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// End every attachment `account` holds, on any network, and refuse the
    /// attachments of credential checks already under way for it: the
    /// account was suspended or deleted, or its password changed. Returns how
    /// many attachments were told.
    pub(crate) fn revoke_account(&self, account: &str) -> usize {
        self.registry.revocations.revoke(account)
    }

    /// What this server has applied of each account's authority: a change is
    /// recorded in the same turn on this lane as it is applied.
    pub(crate) fn authority_ledger(&self) -> &crate::account_authority::AuthorityLedger {
        &self.registry.authority
    }

    /// Hold stopped every network the configuration defines for `owner`: its
    /// account was suspended ([`OwnerHold::Suspended`], which reactivation
    /// releases) or deleted ([`OwnerHold::Deleted`], which nothing releases —
    /// the owner is gone). Each stays registered, so its key stays the
    /// operator's and the administrator inventory shows why it is stopped.
    /// Returns how many were running and stopped now.
    pub(crate) async fn hold_configured_owned(&self, owner: &str, hold: OwnerHold) -> usize {
        let owner = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(owner);
        let owned: Vec<(NetworkKey, Slot)> = {
            let mut networks = self.registry.networks.lock().expect("registry poisoned");
            let keys: Vec<NetworkKey> = networks
                .slots
                .iter()
                .filter(|(key, slot)| {
                    key.owner.as_deref() == Some(owner.as_str()) && slot.is_configured()
                })
                .map(|(key, _)| key.clone())
                .collect();
            keys.into_iter()
                .filter_map(|key| networks.slots.remove(&key).map(|slot| (key, slot)))
                .collect()
        };
        let mut stops = tokio::task::JoinSet::new();
        for (key, mut slot) in owned {
            stops.spawn(async move {
                let was_running = slot.hold.is_none();
                slot.handle.hold(hold).await;
                if let Some(persistence) = slot.persistence.take() {
                    persistence.stop(UnwrittenLines::Store).await;
                }
                slot.hold = Some(hold);
                (key, slot, was_running)
            });
        }
        let mut stopped = 0;
        while let Some(held) = stops.join_next().await {
            let (key, slot, was_running) = held.expect("a driver stop does not panic");
            stopped += usize::from(was_running);
            self.registry
                .networks
                .lock()
                .expect("registry poisoned")
                .slots
                .insert(key, slot);
        }
        stopped
    }

    /// Restart every configured network of `owner` its suspension held: the
    /// account was reactivated. A network held because its owner was deleted
    /// stays held. Returns the names restarted, and those whose entry no
    /// longer builds a driver with why — each stays held, said out loud.
    pub(crate) fn release_configured_owned(&self, owner: &str) -> (Vec<String>, Vec<String>) {
        let owner = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(owner);
        let mut networks = self.registry.networks.lock().expect("registry poisoned");
        let held: Vec<NetworkKey> = networks
            .slots
            .iter()
            .filter(|(key, slot)| {
                key.owner.as_deref() == Some(owner.as_str())
                    && slot.hold == Some(OwnerHold::Suspended)
            })
            .map(|(key, _)| key.clone())
            .collect();
        let (mut started, mut failed) = (Vec::new(), Vec::new());
        for key in held {
            let slot = networks.slots.get(&key).expect("listed under the lock");
            let entry = slot.restart.clone();
            let predecessor = slot.handle.clone();
            let built = entry
                .as_deref()
                .ok_or_else(|| format!("network '{}': no configuration entry to restart", key.name))
                .and_then(|entry| {
                    // Read again: the files may have been replaced (a
                    // rotation) while the network was held.
                    let certificate = configured_certificate(entry)?;
                    let definition = NetworkDefinition::Configured(Arc::new(
                        ConfiguredNetwork::from_entry(entry, certificate.as_ref()),
                    ));
                    configured_driver(
                        entry,
                        self.registry.core.as_ref(),
                        self.registry.internal_upstreams,
                        certificate,
                        Vec::new(),
                    )
                    .map(|driver| (driver, definition))
                });
            match built {
                // A shutdown closed the registry: the network stays held, as
                // every other driver stays stopped.
                Ok(_) if networks.closed => {
                    failed.push(format!("network '{}': {RegistryClosed}", key.name))
                }
                Ok((driver, definition)) => {
                    let name = entry.as_ref().map_or(key.name.clone(), |e| e.name.clone());
                    networks.slots.remove(&key);
                    // The lock is released for the start: `insert` takes it.
                    // Only a shutdown closes the registry, and it takes this
                    // lane first, so the key is free and the registry open.
                    drop(networks);
                    self.registry
                        .insert(
                            key.owner.as_deref(),
                            &name,
                            definition,
                            driver,
                            entry,
                            Some(predecessor),
                        )
                        .expect("the mutation lane serializes registry writers");
                    networks = self.registry.networks.lock().expect("registry poisoned");
                    started.push(name);
                }
                Err(error) => failed.push(error),
            }
        }
        (started, failed)
    }

    /// Stop every active stored upstream owned by one account while preserving
    /// its durable definitions for possible reactivation. The account's
    /// drivers stop concurrently, as a process shutdown stops them, so one
    /// slow goodbye does not hold up the rest. A network the configuration
    /// defines for the account is the operator's: the account lifecycle holds
    /// it instead ([`MutationLane::hold_configured_owned`]).
    pub(crate) async fn remove_owner(&self, owner: &str, unwritten: UnwrittenLines) -> usize {
        let owner = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(owner);
        let removed: Vec<Slot> = {
            let mut networks = self.registry.networks.lock().expect("registry poisoned");
            let keys: Vec<NetworkKey> = networks
                .slots
                .iter()
                .filter(|(key, slot)| {
                    key.owner.as_deref() == Some(owner.as_str()) && !slot.is_configured()
                })
                .map(|(key, _)| key.clone())
                .collect();
            keys.into_iter()
                .filter_map(|key| networks.slots.remove(&key))
                .collect()
        };
        let count = removed.len();
        let mut stops = tokio::task::JoinSet::new();
        for slot in removed {
            stops.spawn(slot.stop(unwritten));
        }
        while let Some(stopped) = stops.join_next().await {
            stopped.expect("a driver stop does not panic");
        }
        count
    }
}

/// Restore a network's persisted backlog into its buffer, trim it to the
/// cap, then persist every new upstream line until stopped. Subscribes before
/// the backlog read so no line broadcast during the read is lost (up to the
/// channel's backlog).
fn spawn_persistence(
    pool: PgPool,
    owner: Option<String>,
    network: String,
    definition: crate::db::BncNetworkDefinition,
    handle: Arc<NetworkHandle>,
) -> Persistence {
    use super::DriverEvent;
    let (stop, stopped) = tokio::sync::oneshot::channel::<UnwrittenLines>();
    let owner_key = owner.clone().unwrap_or_else(|| "*".to_string());
    // Subscribed before the task is spawned, not on its first poll: a
    // broadcast reaches only the receivers that exist when a line is sent, so
    // anything the driver emitted in between was kept in the ring and never
    // written to the backlog. The local driver reaches the in-process core
    // fast enough for that window to be real.
    let events = handle.subscribe();
    let task = tokio::spawn(async move {
        // The whole buffer the network is configured to replay: its
        // `buffer_cap` is bounded by what storage keeps
        // (`config::MAX_NETWORK_BUFFER_CAP`), so a restart restores it all.
        let restore = i64::try_from(handle.buffer_capacity()).unwrap_or(i64::MAX);
        let renumbered = restore_ring(&pool, &owner_key, &network, restore, &handle).await;
        // Until the network says how it compares names, they are compared as
        // its stored conversations were keyed, so CHATHISTORY finds them.
        match crate::db::bnc_buffer_casemapping(&pool, &owner_key, &network).await {
            Ok(Some(casemapping)) => handle.remember_casemapping(casemapping),
            Ok(None) => {}
            Err(e) => {
                handle.record_error(super::NetworkFailure::BacklogStorageFailed);
                eprintln!("bnc: stored case mapping unreadable for {owner_key}/{network}: {e}");
            }
        }
        handle.history_restored();
        let buffer =
            match crate::db::open_bnc_buffer(&pool, owner.as_deref(), &network, definition).await {
                Ok(buffer) => buffer,
                Err(e) => {
                    // Without its row a stored network's lines would belong to
                    // nothing; none are written, and the failure is visible on the
                    // network's runtime state as well as here.
                    handle.record_error(super::NetworkFailure::BacklogStorageFailed);
                    eprintln!(
                        "bnc: backlog of {owner_key}/{network} cannot be stored, so none is: {e}"
                    );
                    return;
                }
            };
        // The amortized trim below counts only this task's own appends, and a
        // network restarted before its thousandth line would never reach it:
        // each start trims once, so the cap holds across restarts.
        if let Err(e) = crate::db::trim_bnc_buffer(&pool, &buffer).await {
            handle.record_error(super::NetworkFailure::BacklogStorageFailed);
            eprintln!("bnc: backlog trim at start failed for {owner_key}/{network}: {e}");
        }
        // This task is the only writer for this network, so counting its own
        // appends is what makes the amortized trim reach every network — see
        // `db::BNC_TRIM_INTERVAL`.
        let mut since_trim = 0u64;
        // The case mapping every stored conversation is keyed under once
        // this task has re-keyed what was not; `None` until it has.
        let mut keyed_under = None;
        // Whether the last write failed, so an outage logs once, and its end
        // logs once.
        let mut storage_failing = false;
        // Whether a line this ring took was never stored: then no stop is
        // clean, and the next start begins a new epoch.
        let mut lost_a_line = false;
        let mut feed = PersistenceFeed {
            events,
            stopped,
            draining: None,
        };
        // A stop is honoured only between two writes: a write in progress
        // always completes (or fails) before the task ends.
        let mut own = OwnNick(handle.irc_session_snapshot().map(|session| session.nick));
        while let Some(event) = feed.next().await {
            let (line, own_nick, seq) = match event {
                Ok(DriverEvent::Session(snapshot)) => {
                    own = OwnNick(Some(snapshot.nick));
                    continue;
                }
                // A synthesized self-echo is part of the conversation record:
                // persist it like an upstream line so a reattached client sees
                // both sides after a restart.
                Ok(DriverEvent::Line(BufferedLine { line, seq })) => {
                    let own_nick = own.for_line(&line, &handle.names());
                    (line, own_nick, seq)
                }
                Ok(DriverEvent::Echo {
                    line: BufferedLine { line, seq },
                    ..
                }) => {
                    // The echo carries the exact identity used when it was
                    // synthesized. Derive ownership from that line instead of
                    // a later sticky snapshot: the persistence task may lag
                    // behind a subsequent NICK and must not split the two
                    // halves of a direct-message conversation.
                    let own_nick = e6irc_proto::message::Message::parse(&line)
                        .ok()
                        .and_then(|message| message.source.map(|source| source.name.to_string()));
                    (line, own_nick, seq)
                }
                Ok(_) => continue,
                // A persistence lag means upstream lines were never written:
                // the stored backlog now has a gap. Surface it rather than
                // dropping it silently.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    // What was missed may have renamed the session.
                    own = OwnNick(handle.irc_session_snapshot().map(|session| session.nick));
                    lost_a_line = true;
                    handle.record_error(super::NetworkFailure::BacklogStorageLagged);
                    eprintln!(
                        "bnc: persistence lagged for {owner_key}/{network}; {n} upstream \
                         line(s) missing from stored backlog"
                    );
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };
            // An echo the backlog keeps nothing of is told live and never
            // stored, like the line it echoes (`publish_echo`).
            if super::told_live_only(&line) {
                continue;
            }
            let names = handle.names();
            let stored = async {
                // A conversation is keyed the network's way. When that way is
                // not the one this buffer's rows were keyed under — the first
                // line after a restart, or a network that changed its
                // CASEMAPPING — they are re-keyed first, so a page never mixes
                // the two.
                if keyed_under != Some(names.casemapping()) {
                    crate::db::rekey_bnc_targets(&pool, &buffer, names.casemapping()).await?;
                    keyed_under = Some(names.casemapping());
                }
                persist_and_trim(
                    &pool,
                    &buffer,
                    own_nick.as_deref(),
                    &line,
                    &names,
                    renumbered.map_or(seq, |renumbered| renumbered.now(seq)),
                    &mut since_trim,
                )
                .await
            };
            match stored.await {
                Err(e) => {
                    lost_a_line = true;
                    handle.record_error(super::NetworkFailure::BacklogStorageFailed);
                    // One line per outage, not one per upstream message: a
                    // database away for an hour under a busy channel wrote
                    // stderr at the channel's full rate.
                    if !storage_failing {
                        storage_failing = true;
                        eprintln!(
                            "bnc: buffer persist or trim failed for {owner_key}/{network}: {e}; \
                             further failures are counted, not logged, until it stores again"
                        );
                    }
                }
                Ok(()) => {
                    if storage_failing {
                        storage_failing = false;
                        eprintln!("bnc: buffer storage recovered for {owner_key}/{network}");
                    }
                }
            }
        }
        // A stop that kept its lines wrote every one the ring took (the driver
        // had stopped, and the drain took what it said last): the next start
        // continues this epoch, and a cursor handed out now stays valid.
        if feed.draining.is_some() && !lost_a_line {
            let (epoch, through) = handle.ring_position();
            if through > 0
                && let Err(e) =
                    crate::db::bnc_ring_stopped_cleanly(&pool, &owner_key, &network, epoch, through)
                        .await
            {
                eprintln!(
                    "bnc: could not record that {owner_key}/{network} stored every line; its \
                     next start begins a new ring, and clients replay it whole: {e}"
                );
            }
        }
    });
    Persistence { stop, task }
}

/// Restore `(owner, network)`'s ring from storage and claim it for this run.
/// A ring whose last stop stored every line continues its epoch, each line at
/// the position it had, so a `ReplayCursor` from before the restart still
/// names it; the answer then says how the positions the driver's first lines
/// took have moved. Any other ring begins a new epoch, its stored lines below
/// everything pushed, and every older cursor is refused (the client replays
/// the ring whole).
async fn restore_ring(
    pool: &PgPool,
    owner: &str,
    network: &str,
    restore: i64,
    handle: &NetworkHandle,
) -> Option<super::Renumbered> {
    let stored = match crate::db::bnc_ring(pool, owner, network).await {
        Ok(stored) => stored,
        Err(e) => {
            handle.record_error(super::NetworkFailure::BacklogStorageFailed);
            eprintln!(
                "bnc: the stored ring of {owner}/{network} is unreadable, so it begins anew: {e}"
            );
            None
        }
    };
    let renumbered = match crate::db::recent_bnc_backlog(pool, owner, network, restore).await {
        Ok(lines) => match stored {
            Some(crate::db::StoredRing {
                epoch,
                clean_through: Some(through),
            }) => match handle.continue_ring(
                epoch,
                through,
                lines,
                match crate::db::bnc_ring_let_go(pool, owner, network, restore).await {
                    Ok(let_go) => let_go,
                    // Unknown: every position stored is taken as let go of,
                    // so no cursor of the old ring resumes past a gap.
                    Err(e) => {
                        eprintln!("bnc: what {owner}/{network} let go of is unreadable: {e}");
                        Some(through)
                    }
                },
            ) {
                Ok(renumbered) => Some(renumbered),
                Err(lines) => {
                    eprintln!(
                        "bnc: the stored positions of {owner}/{network} do not fit its ring; it \
                         begins anew, and clients replay it whole"
                    );
                    handle.preload_front(lines);
                    None
                }
            },
            Some(crate::db::StoredRing {
                clean_through: None,
                ..
            })
            | None => {
                handle.preload_front(lines);
                None
            }
        },
        Err(e) => {
            handle.record_error(super::NetworkFailure::BacklogStorageFailed);
            eprintln!("bnc: buffer restore failed for {owner}/{network}: {e}");
            None
        }
    };
    let (epoch, _) = handle.ring_position();
    if let Err(e) = crate::db::claim_bnc_ring(pool, owner, network, epoch).await {
        handle.record_error(super::NetworkFailure::BacklogStorageFailed);
        eprintln!(
            "bnc: could not claim the ring of {owner}/{network}: {e}; its next start begins a \
             new ring"
        );
    }
    renumbered
}

/// The session's own nick as of each line the persistence task writes, which
/// decides the conversation a direct message is filed under: followed through
/// the lines themselves, in order, because the task reaches a line only after
/// the session may have been renamed again (reading the session's nick then
/// filed the lines before a `NICK` under the name after it).
struct OwnNick(Option<String>);

impl OwnNick {
    /// The nick that was the session's own when `line` was said, following
    /// the rename `line` is.
    fn for_line(&mut self, line: &str, names: &e6irc_client::NetworkNames) -> Option<String> {
        let own = self.0.clone();
        if let Some(renamed) = own
            .as_deref()
            .and_then(|own| super::own_rename(line, own, names))
        {
            self.0 = Some(renamed);
        }
        own
    }
}

/// What a network's persistence task writes: the driver's events as they
/// come, until a stop. A stop that keeps unwritten lines then yields exactly
/// the events still queued at that moment — the driver has stopped by then, so
/// that is everything it said, and the drain is finite — and one that discards
/// them ends at once.
struct PersistenceFeed {
    events: tokio::sync::broadcast::Receiver<super::DriverEvent>,
    stopped: tokio::sync::oneshot::Receiver<UnwrittenLines>,
    /// After a keeping stop: how many of the queued events remain.
    draining: Option<usize>,
}

impl PersistenceFeed {
    async fn next(
        &mut self,
    ) -> Option<Result<super::DriverEvent, tokio::sync::broadcast::error::RecvError>> {
        use tokio::sync::broadcast::error::{RecvError, TryRecvError};
        loop {
            match &mut self.draining {
                Some(0) => return None,
                Some(left) => {
                    *left -= 1;
                    return match self.events.try_recv() {
                        Ok(event) => Some(Ok(event)),
                        Err(TryRecvError::Lagged(n)) => Some(Err(RecvError::Lagged(n))),
                        Err(TryRecvError::Empty | TryRecvError::Closed) => None,
                    };
                }
                None => tokio::select! {
                    biased;
                    stop = &mut self.stopped => match stop {
                        Ok(UnwrittenLines::Store) => self.draining = Some(self.events.len()),
                        Ok(UnwrittenLines::Discard) | Err(_) => return None,
                    },
                    event = self.events.recv() => return Some(event),
                },
            }
        }
    }
}

async fn persist_and_trim(
    pool: &PgPool,
    buffer: &crate::db::BncBuffer,
    own_nick: Option<&str>,
    line: &str,
    names: &e6irc_client::NetworkNames,
    seq: u64,
    since_trim: &mut u64,
) -> Result<(), crate::db::DbError> {
    crate::db::persist_bnc_line(pool, buffer, own_nick, line, names, seq).await?;
    *since_trim += crate::db::bnc_trim_weight(line);
    if *since_trim >= crate::db::BNC_TRIM_INTERVAL {
        *since_trim = 0;
        crate::db::trim_bnc_buffer(pool, buffer).await?;
    }
    Ok(())
}

/// Outcome of the BNC registration handshake.
enum Registered {
    /// Client authenticated as `account` and selected `network`, negotiating
    /// `caps` (which message tags it may receive on attach).
    Ok {
        account: String,
        /// The credential that authenticated it, which the attachment's lease
        /// holds.
        credential: crate::identity::CredentialId,
        network: String,
        requested_nick: String,
        caps: super::AttachCaps,
        /// What the client sent after registering, for the attached session.
        input: super::ClientInput,
    },
    /// The client hung up or violated the handshake; the loop returns.
    Closed,
}

/// Serve one BNC client: authenticate it with SASL PLAIN against the
/// account store, pick the network from the `nick/network` suffix,
/// greet, and attach. The client's NICK/USER are consumed here (the
/// driver owns the upstream registration).
pub(crate) async fn bnc_serve(
    link: super::AttachLink,
    registry: Arc<Registry>,
    pool: &PgPool,
    server_name: &str,
    peer: e6irc_edge::address::ClientIp,
) -> std::io::Result<()> {
    // Every write here is bounded like `attach`'s, so a client that stops
    // reading during registration or its welcome is dropped at the deadline.
    let super::AttachLink {
        mut lines,
        mut write,
        holding,
    } = link;

    // Taken before any credential is checked, so a suspension, deletion or
    // password change that lands while this client registers refuses its
    // attachment below, even after its password verified.
    let ticket = registry.account_revocations().ticket();

    // Bound the pre-attach handshake: a client that connects and never
    // completes registration (sends nothing, or authenticates but never ends
    // CAP negotiation) must not hold a task + socket indefinitely.
    let (account, credential, network, requested_nick, caps, input) = match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        handshake(&mut lines, &mut write, pool, server_name, peer),
    )
    .await
    {
        Ok(Ok(Registered::Ok {
            account,
            credential,
            network,
            requested_nick,
            caps,
            input,
        })) => (account, credential, network, requested_nick, caps, input),
        Ok(Ok(Registered::Closed)) => return Ok(()),
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            let goodbye =
                crate::sanitize::closing_link(&peer.to_string(), "BNC registration timed out");
            write.write_all(format!("{goodbye}\r\n").as_bytes()).await?;
            write.flush().await?;
            return Ok(());
        }
    };

    // Resolve the target network without silently substituting one for another:
    // the account's own active network wins; if it owns a network of that name
    // that is *not* active, say why rather than falling through to a shared
    // network of the same name; only a name the account does not own at all
    // falls through to a shared (ownerless) network.
    let (handle, shared) = if let Some(handle) = registry.get_owned(&account, &network) {
        (handle, false)
    } else {
        match crate::db::get_bnc_network(pool, &account, &network).await {
            // Owned but not live. Say why rather than falling through to a
            // shared network of the same name.
            Ok(Some(row)) => {
                let why = not_running_notice(
                    &network,
                    row.enabled,
                    registry.not_running(&account, &network),
                );
                let notice = crate::core::server_notice(server_name, "*", &why);
                write.write_all(format!("{notice}\r\n").as_bytes()).await?;
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
                    (handle, true)
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

    // The account's authority and the credential's, held for as long as the
    // attachment lives.
    let authority = match registry
        .account_revocations()
        .lease(ticket, &account, credential)
    {
        Ok(authority) => authority,
        Err(revoked) => {
            write
                .write_all(format!(":{server_name} ERROR :Closing Link: {revoked}\r\n").as_bytes())
                .await?;
            write.flush().await?;
            return Ok(());
        }
    };

    // Attach: the welcome (registration burst, ISUPPORT, end-of-MOTD) is
    // written there, from the same instant as the replay.
    let mut link = super::AttachLink {
        lines,
        write,
        holding,
    };
    link.name_holding(credential, shared);
    let end = attach(
        link,
        input,
        &handle,
        caps,
        authority,
        super::Greeting {
            server_name,
            network: &network,
            requested_nick: &requested_nick,
        },
        super::ATTACH_LIVENESS_INTERVAL,
    )
    .await?;
    // Why it ended, not just that it did: "client quit" and "client stopped
    // answering" are different stories to whoever reads this log.
    eprintln!("bnc: {account} detached from '{network}': {end}");
    Ok(())
}

/// Resume an attachment a rebuild takes from its edge's record (DESIGN
/// §19.3): its network as the record names it — the account's own, or the
/// shared one — and its authority leased again, then the relay from where the
/// record says the client was. A network gone, or an authority revoked
/// meanwhile, ends it saying so. The record's login was checked against the
/// database before this (the rebuild's re-authorization).
pub(crate) async fn bnc_resume(
    link: super::AttachLink,
    registry: Arc<Registry>,
    server_name: &str,
    peer: e6irc_edge::address::ClientIp,
    record: crate::core::record::AttachRecord,
) -> std::io::Result<()> {
    let mut link = link;
    let handle = if record.shared {
        registry.get_shared(&record.network)
    } else {
        registry.get_owned(&record.account, &record.network)
    };
    let Some(handle) = handle else {
        let goodbye = crate::sanitize::closing_link(
            &peer.to_string(),
            &format!("network '{}' is gone", record.network),
        );
        link.write
            .write_all(format!("{goodbye}\r\n").as_bytes())
            .await?;
        link.write.flush().await?;
        return Ok(());
    };
    let ticket = registry.account_revocations().ticket();
    let authority =
        match registry
            .account_revocations()
            .lease(ticket, &record.account, record.credential)
        {
            Ok(authority) => authority,
            Err(revoked) => {
                link.write
                    .write_all(
                        format!(":{server_name} ERROR :Closing Link: {revoked}\r\n").as_bytes(),
                    )
                    .await?;
                link.write.flush().await?;
                return Ok(());
            }
        };
    link.name_holding(record.credential, record.shared);
    let (account, network) = (record.account.clone(), record.network.clone());
    let end = super::resume_attached(
        link,
        &handle,
        authority,
        record,
        server_name,
        super::ATTACH_LIVENESS_INTERVAL,
    )
    .await?;
    eprintln!("bnc: {account} detached from '{network}' after a restart: {end}");
    Ok(())
}

/// What an attaching client is told about its own network that has no running
/// driver: disabled only when its row says so; otherwise what the registry
/// knows — being reconfigured, or failed to start and why.
fn not_running_notice(network: &str, enabled: bool, registry: NotRunning) -> String {
    if !enabled {
        return format!("Your network '{network}' is disabled.");
    }
    match registry {
        NotRunning::Replacing => {
            format!("Your network '{network}' is being reconfigured; attach again in a moment.")
        }
        NotRunning::FailedToStart(reason) => {
            format!("Your network '{network}' failed to start: {reason}")
        }
        NotRunning::Absent => format!(
            "Your network '{network}' is enabled but not running; re-enable it to start it."
        ),
    }
}

/// RPL_MYINFO's mode lists to go with [`super::BRIDGE_ISUPPORT`] (what a
/// network that has said nothing of its own is welcomed with): no user modes the
/// bridge implements beyond invisibility, and the membership modes its
/// `PREFIX` names (each takes a nick).
const BRIDGE_MYINFO_MODES: &[&str] = &["i", "qaohv", "qaohv"];

/// The most ISUPPORT tokens one 005 line carries: with the nick and the
/// trailing text that is the 15 parameters a message may hold.
const ISUPPORT_TOKENS_PER_LINE: usize = 13;

/// An attaching client's welcome: the nick it is welcomed under, its
/// registration burst (001-004, ISUPPORT and end-of-MOTD), and the ISUPPORT
/// tokens that burst told it — what a later change is told against.
pub(super) struct Welcome {
    pub(super) nick: String,
    pub(super) lines: Vec<String>,
    pub(super) isupport: Vec<String>,
}

/// The welcome of a client attaching to `network` as the session stood at the
/// attach boundary: `features` and `session_nick` are of that one instant, so
/// nothing that changes between the welcome and the replay is lost.
///
/// The attach selector is registration input, not the client's IRC identity:
/// once the network has a session, 001 names the session's nick — an IRC
/// upstream's, or a bridge's provider account — so the client classifies the
/// JOIN, NICK and echoed traffic that follows as its own. Before then it is
/// the nick the client asked for, and the session's arrives as a NICK when it
/// begins.
///
/// The mode lists and ISUPPORT are the network's own, as its registration
/// burst reported them (the local network's are the core's, read the same
/// way), so the client parses the network it is actually on — its prefixes,
/// channel types and casemapping; see [`welcome_isupport`].
pub(super) fn welcome(
    server_name: &str,
    network: &str,
    features: &super::UpstreamFeatures,
    session_nick: Option<&str>,
    requested_nick: &str,
    history: bool,
) -> Welcome {
    let nick = session_nick.unwrap_or(requested_nick).to_string();
    let isupport = welcome_isupport(features, history);
    let modes = features
        .myinfo_modes
        .clone()
        .unwrap_or_else(|| BRIDGE_MYINFO_MODES.iter().map(|m| m.to_string()).collect());
    let version = concat!("e6irc-bnc-", env!("CARGO_PKG_VERSION"));
    let mut lines = vec![
        format!(":{server_name} 001 {nick} :Welcome to e6irc BNC, attached to '{network}'"),
        format!(":{server_name} 002 {nick} :Your host is {server_name}, running version {version}"),
        format!(":{server_name} 003 {nick} :This server was created at build time"),
        format!(
            ":{server_name} 004 {nick} {server_name} {version} {}",
            modes.join(" ")
        ),
    ];
    lines.extend(isupport_lines(server_name, &nick, &isupport));
    lines.push(format!(
        ":{server_name} 422 {nick} :MOTD is on the upstream network"
    ));
    Welcome {
        nick,
        lines,
        isupport,
    }
}

/// The ISUPPORT tokens a client of a network with `features` is told: the
/// network's own, or a bridge's fixed set when the network has reported none.
/// The bouncer answers for itself only what it decides
/// ([`super::BOUNCER_OWNED_ISUPPORT`]): CHATHISTORY and MSGREFTYPES, and those
/// only when the network has a history store to page; and CLIENTTAGDENY,
/// which is `*` while the network cannot carry client-only tags.
pub(super) fn welcome_isupport(features: &super::UpstreamFeatures, history: bool) -> Vec<String> {
    let mut isupport = if features.isupport.is_empty() {
        super::BRIDGE_ISUPPORT
            .iter()
            .map(|t| t.to_string())
            .collect()
    } else {
        features.isupport.clone()
    };
    isupport.retain(|token| {
        let key = token.split('=').next().unwrap_or(token);
        !super::BOUNCER_OWNED_ISUPPORT.contains(&key)
    });
    isupport.extend(features.client_tag_deny());
    if history {
        isupport.push(format!(
            "CHATHISTORY={}",
            super::chathistory::CHATHISTORY_LIMIT_MAX
        ));
        isupport.push("MSGREFTYPES=timestamp,msgid".to_string());
    }
    isupport
}

/// `tokens` as `005` lines to `nick`, each within one IRC line and
/// [`ISUPPORT_TOKENS_PER_LINE`].
pub(super) fn isupport_lines(server_name: &str, nick: &str, tokens: &[String]) -> Vec<String> {
    let head = format!(":{server_name} 005 {nick}");
    let tail = " :are supported by this server";
    let mut lines = Vec::new();
    let mut line = head.clone();
    let mut on_line = 0;
    for token in tokens {
        if on_line == ISUPPORT_TOKENS_PER_LINE
            || line.len() + 1 + token.len() + tail.len() + 2 > e6irc_proto::message::MAX_LINE_LEN
        {
            lines.push(format!("{line}{tail}"));
            line = head.clone();
            on_line = 0;
        }
        line.push(' ');
        line.push_str(token);
        on_line += 1;
    }
    if on_line > 0 {
        lines.push(format!("{line}{tail}"));
    }
    lines
}

/// What changed from the ISUPPORT tokens a client was told (`told`) to the
/// ones it would be told now (`now`): each token that is new or has a new
/// value, then a `-TOKEN` for each one withdrawn.
pub(super) fn isupport_changes(told: &[String], now: &[String]) -> Vec<String> {
    let key = |token: &str| token.split('=').next().unwrap_or(token).to_string();
    let mut changes: Vec<String> = now
        .iter()
        .filter(|token| !told.contains(token))
        .cloned()
        .collect();
    changes.extend(
        told.iter()
            .map(|token| key(token))
            .filter(|told_key| !now.iter().any(|token| key(token) == *told_key))
            .map(|withdrawn| format!("-{withdrawn}")),
    );
    changes
}

/// [`welcome`] of a client attaching to `handle` now, for tests that look at
/// the welcome alone.
#[cfg(test)]
pub(super) fn welcome_to(
    server_name: &str,
    network: &str,
    handle: &NetworkHandle,
    requested_nick: &str,
) -> Welcome {
    welcome(
        server_name,
        network,
        &handle.upstream_features(),
        handle
            .irc_session_snapshot()
            .as_ref()
            .map(|session| session.nick.as_str()),
        requested_nick,
        handle.history().is_some(),
    )
}

/// Drive registration to a `Registered` verdict. Requires a successful
/// SASL PLAIN exchange before the client is allowed to attach: an
/// unauthenticated CAP END or a bad credential closes the connection.
async fn handshake<W>(
    lines: &mut super::ClientLines,
    write: &mut W,
    pool: &PgPool,
    server_name: &str,
    peer: e6irc_edge::address::ClientIp,
) -> std::io::Result<Registered>
where
    W: AsyncWrite + Unpin,
{
    // The attached session reads on from where the handshake stops.
    let mut input = super::ClientInput::default();
    let mut events = Vec::new();

    let mut nick: Option<String> = None;
    let mut have_user = false;
    let mut username: Option<String> = None;
    let mut cap_open = false;
    let mut awaiting_payload = false;
    // Accumulates 400-byte AUTHENTICATE continuation chunks until a short line
    // completes the payload (SASL spec), mirroring the main IRC path. Both use
    // the protocol crate's shared bound so a client cannot grow it without end.
    let mut sasl_buf = String::new();
    let mut credential_attempts = crate::identity::CredentialAttemptBudget::default();
    let mut account: Option<crate::db::VerifiedSignIn> = None;
    // The network the SASL username named, if it named one (soju's form).
    let mut sasl_network: Option<String> = None;
    let mut caps = super::AttachCaps::default();

    // Registration is complete only once the client has a nick, has sent
    // USER, has authenticated, and has closed CAP negotiation.
    let registered =
        |nick: &Option<String>,
         have_user: bool,
         account: &Option<crate::db::VerifiedSignIn>,
         cap_open: bool| { nick.is_some() && have_user && account.is_some() && !cap_open };
    'handshake: loop {
        if registered(&nick, have_user, &account, cap_open) {
            break;
        }
        if !lines.next_lines(&mut events).await? {
            return Ok(Registered::Closed);
        }
        let mut arrived = std::mem::take(&mut events).into_iter();
        while let Some(ev) = arrived.next() {
            // What follows the line that completed registration is the
            // attached session's input, not the handshake's: a client that
            // sends its first JOIN in the same write as `CAP END` must not
            // have it refused here as an unknown command.
            if registered(&nick, have_user, &account, cap_open) {
                input.pending.push(ev);
                input.pending.extend(arrived);
                break 'handshake;
            }
            let LineEvent::Line(line) = ev else {
                super::write_client_line_error(write, super::ClientLineError::TooLong).await?;
                continue;
            };
            let Ok(text) = std::str::from_utf8(&line) else {
                let fail = crate::core::invalid_utf8_fail("*bnc*", &line);
                write.write_all(format!("{fail}\r\n").as_bytes()).await?;
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
                            Some(MiddleParam::echo(candidate)),
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
                            Some(MiddleParam::echo("USER")),
                            "Not enough parameters",
                        )
                        .await?;
                    } else {
                        have_user = true;
                        username = Some(msg.params[0].to_string());
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
                        reject_sasl(write, server_name, nick.as_deref()).await?;
                        continue;
                    }
                    let arg = msg.params.first().copied().unwrap_or("");
                    if !caps.sasl {
                        reject_sasl(write, server_name, nick.as_deref()).await?;
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
                    if arg == "*" {
                        // Client abort — answered 906 whether or not an
                        // exchange is open, as the core answers it: `*` is
                        // never a mechanism name.
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
                    } else if !awaiting_payload {
                        // Mechanism selection. Only PLAIN is offered; any
                        // other is answered with the list (908) before the
                        // failure (904), as the SASL spec orders them.
                        if arg.eq_ignore_ascii_case(ATTACH_SASL_MECHANISMS) {
                            awaiting_payload = true;
                            write.write_all(b"AUTHENTICATE +\r\n").await?;
                        } else {
                            handshake_numeric(
                                write,
                                server_name,
                                nick.as_deref(),
                                908,
                                Some(MiddleParam::echo(ATTACH_SASL_MECHANISMS)),
                                "are available SASL mechanisms",
                            )
                            .await?;
                            reject_sasl(write, server_name, nick.as_deref()).await?;
                        }
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
                            reject_sasl(write, server_name, nick.as_deref()).await?;
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
                                        reject_sasl(write, server_name, nick.as_deref()).await?;
                                    }
                                    PlainVerification::Throttled(retry_after) => {
                                        handshake_numeric(
                                            write,
                                            server_name,
                                            nick.as_deref(),
                                            904,
                                            None,
                                            &retry_after.explanation(),
                                        )
                                        .await?;
                                    }
                                    PlainVerification::Unavailable => {
                                        handshake_numeric(
                                            write,
                                            server_name,
                                            nick.as_deref(),
                                            904,
                                            None,
                                            "SASL authentication temporarily unavailable",
                                        )
                                        .await?;
                                    }
                                    PlainVerification::Accepted(signed_in, selected) => {
                                        let acct = signed_in.account.name();
                                        // RPL_LOGGEDIN names the client and
                                        // its mask as far as they are known:
                                        // the nick it gave, the user name
                                        // from USER, the address it came from.
                                        let mask = logged_in_mask(
                                            nick.as_deref(),
                                            username.as_deref(),
                                            peer,
                                        );
                                        let target =
                                            MiddleParam::echo(nick.as_deref().unwrap_or("*"));
                                        let line = crate::core::fitted_line(
                                            format!(
                                                ":{server_name} 900 {target} {mask} {} :",
                                                MiddleParam::echo(acct)
                                            ),
                                            &format!("You are now logged in as {acct}"),
                                        );
                                        write.write_all(format!("{line}\r\n").as_bytes()).await?;
                                        handshake_numeric(
                                            write,
                                            server_name,
                                            nick.as_deref(),
                                            903,
                                            None,
                                            "SASL authentication successful",
                                        )
                                        .await?;
                                        account = Some(signed_in);
                                        sasl_network = selected;
                                    }
                                    PlainVerification::AttemptsExhausted => {
                                        let goodbye = crate::sanitize::closing_link(
                                            &peer.to_string(),
                                            "Too many authentication attempts",
                                        );
                                        write
                                            .write_all(format!("{goodbye}\r\n").as_bytes())
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
                        // `PONG :` is one byte longer than the `PING ` that
                        // carried a maximal token, so the echo is fitted like
                        // every other relay of client text.
                        let token = crate::core::fit_trailing("PONG :", token);
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
                        Some(MiddleParam::echo(command)),
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
    let nick_network = raw.split_once('/').map(|(_, network)| network.to_string());
    // Both forms name a network, so both are accepted -- but never two
    // different answers to the same question: a client that says one network
    // in its nickname and another in its SASL username is told, not guessed
    // at.
    if let (Some(from_nick), Some(from_sasl)) = (&nick_network, &sasl_network)
        && !e6irc_proto::casemap::CaseMapping::Rfc1459.eq(from_nick, from_sasl)
    {
        handshake_numeric(
            write,
            server_name,
            Some(&raw),
            432,
            Some(MiddleParam::echo(&raw)),
            &format!(
                "Nickname selects network {from_nick} but the SASL user name selects {from_sasl}"
            ),
        )
        .await?;
        return Ok(Registered::Closed);
    }
    // ZNC/soju `<nick>/<network>` addressing; a slash-less nick selects the
    // in-process `local` network (DESIGN §10.4: bare `alice` = `local`), so a
    // client that doesn't know the convention still reaches a working network
    // rather than being turned away.
    let (requested_nick, network) = raw.split_once('/').map_or(
        (
            raw.as_str(),
            sasl_network
                .as_deref()
                .unwrap_or(super::local_driver::LOCAL_NETWORK),
        ),
        |(nick, network)| (nick, network),
    );
    Ok(Registered::Ok {
        account: account.account.into_name(),
        credential: account.credential,
        network: network.to_string(),
        requested_nick: requested_nick.to_string(),
        caps,
        input,
    })
}

/// Whether `selector` is `<nick>` or `<nick>/<network>` in the attach
/// grammar. The nickname is held to the longest any e6irc admits
/// ([`crate::config::MAX_NICKLEN`]):
/// the network it names — the in-process one, whose `nicklen` may be that
/// long, or an upstream with its own — judges it further.
fn attach_selector_ok(selector: &str) -> bool {
    const LONGEST: usize = crate::config::MAX_NICKLEN;
    match selector.split_once('/') {
        Some((nick, network)) => {
            crate::sanitize::valid_nick(nick, LONGEST)
                && crate::sanitize::valid_network_name(network)
        }
        None => crate::sanitize::valid_nick(selector, LONGEST),
    }
}

/// A numeric of the attach handshake. The target and any echoed client token
/// are [`MiddleParam`]s, so a token that cannot stand as one parameter (`NICK
/// :a b`) is shown as `*` rather than splitting the reply, and the trailing is
/// fitted to the line.
async fn handshake_numeric<W>(
    write: &mut W,
    server_name: &str,
    nick: Option<&str>,
    numeric: u16,
    middle: Option<MiddleParam<'_>>,
    trailing: &str,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let target = MiddleParam::echo(nick.unwrap_or("*"));
    let middle = middle.map(|value| format!(" {value}")).unwrap_or_default();
    let line = crate::core::fitted_line(
        format!(":{server_name} {numeric:03} {target}{middle} :"),
        trailing,
    );
    write.write_all(format!("{line}\r\n").as_bytes()).await
}

/// The SASL mechanisms the attach listener accepts, as `sasl=` advertises
/// them to a 302 client and RPL_SASLMECHS (908) lists them.
const ATTACH_SASL_MECHANISMS: &str = "PLAIN";

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
    CapNotify,
}

impl AttachCapability {
    const ALL: [Self; 9] = [
        Self::Sasl,
        Self::ServerTime,
        Self::MessageTags,
        Self::AccountTag,
        Self::EchoMessage,
        Self::Batch,
        Self::Chathistory,
        Self::ReadMarker,
        Self::CapNotify,
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
            Self::CapNotify => "cap-notify",
        }
    }

    /// The CAP LS token: a 302 client is told the SASL mechanisms on offer.
    fn ls_token(self, v302: bool) -> String {
        match self {
            Self::Sasl if v302 => format!("sasl={ATTACH_SASL_MECHANISMS}"),
            other => other.name().to_string(),
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
            // A 302 client's cap-notify is implied and stays on
            // (capability negotiation 3.2); only an older client toggles it.
            Self::CapNotify => caps.cap_notify = enabled || caps.cap_302,
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
            Self::CapNotify => caps.cap_notify,
        }
    }
}

/// The capabilities on offer (`caps: None`) or enabled, as CAP tokens.
fn cap_names(caps: Option<super::AttachCaps>, v302: bool) -> Vec<String> {
    AttachCapability::ALL
        .into_iter()
        .filter(|capability| caps.is_none_or(|caps| capability.enabled(caps)))
        .map(|capability| match caps {
            None => capability.ls_token(v302),
            Some(_) => capability.name().to_string(),
        })
        .collect()
}

fn cap_reply(server_name: &str, target: &str, verb: &str, request: &str) -> (bool, String) {
    let head = format!(":{server_name} CAP {target} {verb} :");
    let budget = (e6irc_proto::message::MAX_LINE_LEN - 2).saturating_sub(head.len());
    let fitted = e6irc_proto::message::truncate_on_char_boundary(request, budget);
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
    // The nick is the upstream's to choose once attached; every reply below
    // repeats it, so it is bounded once, as `write_attach_numeric` bounds it.
    let target = MiddleParam::echo(target).as_str();
    match msg
        .params
        .first()
        .map(|s| s.to_ascii_uppercase())
        .as_deref()
    {
        // The core's version rule and line splitting: `CAP LS 302` or later
        // gets values, multi-line replies and cap-notify.
        Some("LS") => {
            let v302 = crate::core::cap_version_302(msg.params.get(1).copied());
            if v302 {
                caps.cap_302 = true;
                caps.cap_notify = true;
            }
            let tokens = cap_names(None, v302);
            for line in crate::core::cap_reply_lines(server_name, target, "LS", &tokens, v302) {
                write.write_all(format!("{line}\r\n").as_bytes()).await?;
            }
        }
        Some("LIST") => {
            let tokens = cap_names(Some(*caps), caps.cap_302);
            for line in
                crate::core::cap_reply_lines(server_name, target, "LIST", &tokens, caps.cap_302)
            {
                write.write_all(format!("{line}\r\n").as_bytes()).await?;
            }
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
            let subcommand = MiddleParam::echo(invalid.unwrap_or("*"));
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

async fn reject_sasl<W>(write: &mut W, server_name: &str, nick: Option<&str>) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    handshake_numeric(
        write,
        server_name,
        nick,
        904,
        None,
        "SASL authentication failed",
    )
    .await
}

/// `nick!user@host` for RPL_LOGGEDIN: the nick part of the attach selector
/// (a `nick/network` selector names the nick first), the USER name, and the
/// client's address — each `*` while not yet known.
fn logged_in_mask(
    nick: Option<&str>,
    username: Option<&str>,
    host: e6irc_edge::address::ClientIp,
) -> String {
    let nick = MiddleParam::echo(nick.map_or("*", |selector| {
        selector.split_once('/').map_or(selector, |(nick, _)| nick)
    }));
    let user = MiddleParam::echo(username.unwrap_or("*"));
    format!("{nick}!{user}@{host}")
}

/// Verify a SASL PLAIN payload (`base64(authzid \0 authcid \0 passwd)`)
/// against the account store. Returns the canonical account name.
enum PlainVerification {
    /// The sign-in, and the network its SASL username selected (soju's
    /// `<account>/<network>`), if it carried one.
    Accepted(crate::db::VerifiedSignIn, Option<String>),
    Rejected,
    /// The account name has spent its password attempts for the window.
    Throttled(crate::db::LoginRetryAfter),
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
    // soju addresses a network in the SASL username: `<account>/<network>`.
    // Every client can set that, while `<nick>/<network>` -- ZNC's way, which
    // this listener also accepts -- asks for a nickname containing `/`, which
    // is not a legal nickname and which many clients refuse to send. Both are
    // accepted; the caller reconciles them.
    let (account, network) = match credentials.account.split_once('/') {
        Some((account, network)) if crate::sanitize::valid_network_name(network) => {
            (account, Some(network.to_string()))
        }
        // A `/` that is not a network selector is left in the account name, so
        // it fails as the bad credential it is rather than as a bad network.
        _ => (credentials.account.as_str(), None),
    };
    // A DB failure is not an auth rejection (verify_credentials' contract):
    // fail closed, but surface the error instead of silently masking it as a
    // bad password.
    match crate::db::verify_credentials(pool, account, &credentials.password).await {
        Ok(Some(signed_in)) => PlainVerification::Accepted(signed_in, network),
        Ok(None) => PlainVerification::Rejected,
        Err(crate::db::DbError::LoginThrottled(retry_after)) => {
            PlainVerification::Throttled(retry_after)
        }
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
        assert_eq!(cap_names(Some(caps), false), cap_names(None, false));

        let (capability, enabled) = AttachCapability::parse("-echo-message").expect("known cap");
        capability.set(&mut caps, enabled);
        assert!(!cap_names(Some(caps), false).contains(&"echo-message".to_string()));
        // A 302 client is told the mechanisms, and cannot drop cap-notify.
        assert!(cap_names(None, true).contains(&"sasl=PLAIN".to_string()));
        caps.cap_302 = true;
        let (capability, enabled) = AttachCapability::parse("-cap-notify").expect("known cap");
        capability.set(&mut caps, enabled);
        assert!(caps.cap_notify);
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

    /// The target is the client's nick, which the upstream can change to
    /// anything after attach. A head longer than the line used to underflow
    /// the budget: a panic in debug, an over-long line in release.
    #[tokio::test]
    async fn a_long_target_cannot_overflow_any_cap_reply() {
        let target = "n".repeat(e6irc_proto::message::MAX_LINE_LEN);
        let (fits, _) = cap_reply("bnc.example", &target, "ACK", "server-time");
        assert!(
            !fits,
            "a head that fills the line leaves no room, and says so"
        );

        for command in [
            "CAP LS 302",
            "CAP LIST",
            "CAP REQ :server-time",
            "CAP REQ :bogus",
        ] {
            let (mut client, mut server) = tokio::io::duplex(8192);
            handle_cap(
                &mut server,
                "bnc.example",
                &target,
                &Message::parse(command).expect("CAP command"),
                false,
                &mut false,
                &mut super::super::AttachCaps::default(),
            )
            .await
            .expect("CAP reply");
            server.shutdown().await.expect("close server half");
            let mut reply = String::new();
            client.read_to_string(&mut reply).await.expect("reply");
            assert!(
                !reply.is_empty() && reply.len() <= e6irc_proto::message::MAX_LINE_LEN,
                "{command}: {} bytes",
                reply.len()
            );
        }
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

    /// A subcommand in trailing form can hold a space or open with `:`; echoed
    /// raw it split the reply (`410 * a b :…`). It is the `*` placeholder.
    #[tokio::test]
    async fn an_unframeable_cap_subcommand_is_echoed_as_a_placeholder() {
        for command in ["CAP :a b", "CAP ::x"] {
            let (mut client, mut server) = tokio::io::duplex(1024);
            handle_cap(
                &mut server,
                "bnc.example",
                "*",
                &Message::parse(command).expect("CAP request"),
                false,
                &mut false,
                &mut super::super::AttachCaps::default(),
            )
            .await
            .expect("CAP rejection");
            server.shutdown().await.expect("close server half");
            let mut reply = String::new();
            client.read_to_string(&mut reply).await.expect("read reply");
            assert_eq!(
                reply, ":bnc.example 410 * * :Invalid CAP subcommand\r\n",
                "{command}"
            );
        }
    }
}

#[cfg(test)]
mod handshake_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Run the handshake over `input` (then end of input); what it wrote, and
    /// its verdict.
    async fn handshake_replies(input: &[u8]) -> (String, Registered) {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1/unused")
            .expect("lazy pool");
        let (client, server) = tokio::io::duplex(16 * 1024);
        let (mut client_read, mut client_write) = tokio::io::split(client);
        let super::super::AttachLink {
            mut lines,
            mut write,
            holding: _,
        } = super::super::attach_link::over_stream(server).await;
        let task = tokio::spawn(async move {
            handshake(
                &mut lines,
                &mut write,
                &pool,
                "bnc.example",
                e6irc_edge::address::ClientIp::new("192.0.2.1".parse().expect("address")),
            )
            .await
        });
        client_write
            .write_all(input)
            .await
            .expect("write handshake");
        client_write.shutdown().await.expect("close input");
        let mut replies = String::new();
        client_read
            .read_to_string(&mut replies)
            .await
            .expect("read replies");
        let registered = task
            .await
            .expect("handshake task")
            .expect("handshake result");
        (replies, registered)
    }

    #[test]
    fn attach_selector_uses_the_shared_bounded_network_name_language() {
        assert!(attach_selector_ok("alice/libera"));
        assert!(attach_selector_ok("alice"));
        assert!(!attach_selector_ok("alice/"));
        assert!(!attach_selector_ok("alice/bad/name"));
        assert!(!attach_selector_ok(&format!("alice/{}", "x".repeat(65))));
    }

    /// The nickname in a selector is held to the longest nickname any e6irc
    /// admits — the most a server's `nicklen` can be —
    /// not to a literal 30, which turned away a 40-byte nickname the
    /// server itself would have accepted.
    #[test]
    fn a_selector_admits_every_nickname_length_the_server_does() {
        let longest = format!("n{}", "x".repeat(crate::config::MAX_NICKLEN - 1));
        assert!(attach_selector_ok(&longest));
        assert!(attach_selector_ok(&format!("{longest}/libera")));
        assert!(attach_selector_ok(&"a".repeat(40)));
        let longer = format!("{longest}x");
        assert!(!attach_selector_ok(&longer));
        assert!(!attach_selector_ok(&format!("{longer}/libera")));
    }

    /// A refused nick or unknown command is echoed as one middle parameter:
    /// `NICK :a b` used to answer `432 * a b :…`, which a client reads as the
    /// nick `a` and a reply text of `b`.
    #[tokio::test]
    async fn an_unframeable_handshake_token_is_echoed_as_a_placeholder() {
        let (replies, registered) =
            handshake_replies(b"NICK :a b\r\nNICK ::x\r\n:src FROB\r\nQUIT :done\r\n").await;
        assert_eq!(
            replies
                .matches(":bnc.example 432 * * :Erroneous nickname/network selector\r\n")
                .count(),
            2,
            "{replies}"
        );
        assert!(
            replies.contains(":bnc.example 421 * FROB :Unknown command\r\n"),
            "{replies}"
        );
        assert!(matches!(registered, Registered::Closed));
    }

    #[tokio::test]
    async fn attach_sasl_rejects_an_oversized_chunk_and_resets_the_attempt() {
        let (replies, registered) = handshake_replies(format!(
                    "CAP REQ :sasl\r\nAUTHENTICATE PLAIN\r\nAUTHENTICATE {}\r\nAUTHENTICATE PLAIN\r\nAUTHENTICATE *\r\nQUIT :done\r\n",
                    "x".repeat(e6irc_proto::sasl::MAX_AUTHENTICATE_CHUNK_LEN + 1)
                )
                .as_bytes(),).await;
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
        assert!(matches!(registered, Registered::Closed));
    }

    /// `AUTHENTICATE *` is an abort whether or not an exchange is open — 906,
    /// as the core answers it — never a mechanism name to be refused with the
    /// mechanism list.
    #[tokio::test]
    async fn attach_sasl_abort_outside_an_exchange_is_906() {
        let (replies, registered) = handshake_replies(
            b"CAP REQ :sasl\r\nNICK alice/libera\r\nAUTHENTICATE *\r\nQUIT :done\r\n",
        )
        .await;
        assert!(
            replies.contains(":bnc.example 906 alice/libera :SASL authentication aborted\r\n"),
            "{replies}"
        );
        assert!(!replies.contains(" 908 "), "{replies}");
        assert!(!replies.contains(" 904 "), "{replies}");
        assert!(matches!(registered, Registered::Closed));
    }

    /// The attach listener negotiates like the core: `CAP LS 302` gets the
    /// mechanism list as `sasl=`'s value and cap-notify it cannot drop; an
    /// unsupported mechanism is answered with RPL_SASLMECHS (908) before the
    /// failure (904), addressed to the nick the client gave; a line that is
    /// not UTF-8 is refused under the command it carried.
    #[tokio::test]
    async fn attach_negotiation_follows_the_302_and_sasl_specs() {
        let (replies, registered) = handshake_replies(b"CAP LS 303\r\nNICK alice/libera\r\nCAP REQ :sasl -cap-notify\r\nCAP LIST\r\nAUTHENTICATE SCRAM-SHA-256\r\nPRIVMSG #c :caf\xe9\r\nQUIT :done\r\n").await;
        let lines: Vec<&str> = replies.split("\r\n").filter(|l| !l.is_empty()).collect();
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with(":bnc.example CAP * LS :")
                    && l.split(' ')
                        .any(|t| t.trim_start_matches(':') == "sasl=PLAIN")),
            "{lines:#?}"
        );
        let list = lines
            .iter()
            .find(|l| l.contains(" CAP alice/libera LIST ") || l.contains(" CAP * LIST "))
            .expect("CAP LIST reply");
        assert!(
            list.contains("cap-notify") && list.contains("sasl"),
            "{list}"
        );
        let mechs = lines.iter().position(|l| {
            *l == ":bnc.example 908 alice/libera PLAIN :are available SASL mechanisms"
        });
        let failed = lines
            .iter()
            .position(|l| *l == ":bnc.example 904 alice/libera :SASL authentication failed");
        assert!(
            mechs.is_some() && mechs.map(|at| at + 1) == failed,
            "{lines:#?}"
        );
        assert!(
            lines.contains(&":*bnc* FAIL PRIVMSG INVALID_UTF8 :Message rejected, not valid UTF-8"),
            "{lines:#?}"
        );
        assert!(matches!(registered, Registered::Closed));
    }

    #[test]
    fn logged_in_mask_names_what_is_known() {
        let host = |text: &str| e6irc_edge::address::ClientIp::new(text.parse().expect("address"));
        assert_eq!(
            logged_in_mask(Some("alice/libera"), Some("al"), host("192.0.2.1")),
            "alice!al@192.0.2.1"
        );
        assert_eq!(
            logged_in_mask(None, None, host("192.0.2.1")),
            "*!*@192.0.2.1"
        );
        // A dual-stack attach listener sees an IPv4 client IPv4-mapped; the
        // mask shows the address as every other listener does.
        assert_eq!(
            logged_in_mask(None, None, host("::ffff:192.0.2.1")),
            "*!*@192.0.2.1"
        );
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
        // The last PING carries a maximal token: `PING ` plus 505 bytes fills
        // the 510-byte input frame, and the `PONG :` echo is one byte longer.
        let long_token = "a".repeat(505);
        let (replies, registered) = handshake_replies(format!(
                    "NICK alice/libera\r\nUSER only-one-param\r\nWAT value\r\nBAD\0LINE\r\nCAP SURPRISE\r\nPING :token\r\nPING {long_token}\r\nQUIT :done\r\n"
                )
                .as_bytes(),).await;
        assert!(replies.contains(" 461 alice/libera USER :Not enough parameters\r\n"));
        assert!(replies.contains(" 421 alice/libera WAT :Unknown command\r\n"));
        assert!(replies.contains(" FAIL * INVALID_MESSAGE :Malformed line\r\n"));
        assert!(replies.contains(" 410 * SURPRISE :Invalid CAP subcommand\r\n"));
        assert!(replies.contains("PONG :token\r\n"));
        let long_pong = replies
            .split("\r\n")
            .find(|line| line.starts_with("PONG :aaaa"))
            .expect("the maximal PING is answered");
        assert!(
            long_pong.len() + 2 <= 512,
            "PONG must fit the wire: {} bytes",
            long_pong.len() + 2
        );
        assert!(matches!(registered, Registered::Closed));
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

    fn empty_registry() -> Registry {
        Registry {
            networks: Mutex::new(Networks::default()),
            mutations: Arc::new(tokio::sync::Mutex::new(())),
            pool: None,
            secret_keys: None,
            telemetry: None,
            internal_upstreams: crate::egress::InternalUpstreams::Refuse,
            history_retention: crate::core::HistoryRetention::default(),
            core: None,
            revocations: AccountRevocations::new(),
            authority: crate::account_authority::AuthorityLedger::default(),
        }
    }

    #[tokio::test]
    async fn adding_over_a_live_network_is_refused_before_a_second_driver_starts() {
        let registry = empty_registry();
        registry
            .add(
                Some("alice"),
                "libera",
                NetworkDefinition::Stored,
                Box::new(crate::bouncer::LoopbackDriver::new(16)),
            )
            .expect("a fresh key");
        let first = registry.get_owned("alice", "libera").expect("first driver");

        let error = registry
            .add(
                Some("ALICE"),
                "Libera",
                NetworkDefinition::Stored,
                Box::new(crate::bouncer::LoopbackDriver::new(16)),
            )
            .expect_err("the casefolded key is occupied");
        assert_eq!(
            error.to_string(),
            "network 'alice/Libera' is already running"
        );
        let still = registry.get_owned("alice", "libera").expect("same driver");
        assert!(Arc::ptr_eq(&first, &still));
        assert!(!*first.watch_shutdown().borrow());
    }

    /// Saving a configured network and starting it are one judgement: an
    /// entry the configuration validator accepts starts, and one the start
    /// would refuse — refusing it made the daemon exit at the next boot — is
    /// refused when it is saved. (A nick with a space, a keyed or unprefixed
    /// autojoin entry, and a control character in the real name were saved,
    /// then bricked the next start.)
    /// A configured network's client certificate is files on the host: read
    /// and checked when the network starts — a pair that does not match, or a
    /// file that is not there, fails the start by name — and its fingerprints
    /// are what the operator's and owner's views show. It needs TLS.
    #[tokio::test]
    async fn a_configured_client_certificate_is_read_and_checked_at_start() {
        let dir = std::env::temp_dir().join(format!(
            "e6irc-configured-certificate-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mine = crate::bouncer::client_certificates::generate(
            crate::bouncer::client_certificates::GeneratedKey::Ed25519,
            "operator/oftc",
        )
        .unwrap();
        let other = crate::bouncer::client_certificates::generate(
            crate::bouncer::client_certificates::GeneratedKey::Ed25519,
            "operator/other",
        )
        .unwrap();
        let write = |file: &str, text: &str| {
            let path = dir.join(file);
            std::fs::write(&path, text).unwrap();
            path
        };
        let certificate = write("cert.pem", &mine.certificate);
        let key = write("key.pem", &mine.key);
        let other_key = write("other-key.pem", &other.key);
        let entry = |tls: bool, key: &std::path::Path| NetworkEntry {
            client_certificate: Some(crate::config::ClientCertificateFiles {
                certificate: certificate.clone(),
                key: key.to_path_buf(),
            }),
            tls,
            ..owned_configured_entry()
        };
        let start = |entry: NetworkEntry| {
            Registry::start_inner(
                &[entry],
                &HashMap::new(),
                Storage::default(),
                test_core(),
                None,
                crate::egress::InternalUpstreams::Allow,
            )
        };

        let registry = start(entry(true, &key)).expect("a matching pair starts");
        let (configured, _) = registry
            .get_configured_owned("alice", "libera")
            .expect("the configured network");
        let expected =
            e6irc_client::ClientCertificate::from_pem(&mine.certificate, &mine.key).unwrap();
        assert_eq!(
            configured.client_certificate,
            Some(e6irc_client::Fingerprints {
                sha256: expected.fingerprint_sha256(),
                sha512: expected.fingerprint_sha512(),
            })
        );
        registry
            .stop_all_within(std::time::Duration::from_secs(5))
            .await;

        let refused = start(entry(true, &other_key))
            .err()
            .expect("a mismatched key");
        assert!(refused.contains("does not belong"), "{refused}");
        let refused = start(entry(true, &dir.join("missing.pem")))
            .err()
            .expect("a missing key file");
        assert!(refused.contains("missing.pem"), "{refused}");
        assert!(
            entry(false, &key)
                .validate_connection_intent()
                .unwrap_err()
                .contains("over TLS")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn a_configured_network_validates_exactly_when_it_starts() {
        use crate::config::NetworkKind;
        let entry = |kind, nick: &str, realname: &str, autojoin: &[&str]| NetworkEntry {
            kind,
            name: "net".into(),
            owner: None,
            addr: "127.0.0.1:1".into(),
            tls: false,
            nick: nick.into(),
            username: Some("ident".into()),
            realname: Some(realname.into()),
            autojoin: autojoin.iter().map(|channel| channel.to_string()).collect(),
            buffer_cap: 16,
            sasl_account: None,
            sasl_password: None,
            server_password: None,
            client_certificate: None,
        };
        let cases = [
            (
                entry(NetworkKind::Irc, "alice", "Alice Liddell", &["#ops"]),
                true,
            ),
            (entry(NetworkKind::Irc, "alice smith", "Alice", &[]), false),
            (entry(NetworkKind::Irc, "alice", "Al\rice", &[]), false),
            (
                entry(NetworkKind::Irc, "alice", "Alice", &["#ops key"]),
                false,
            ),
            (entry(NetworkKind::Irc, "alice", "Alice", &["ops"]), false),
            (entry(NetworkKind::Irc, "alice", "Alice", &["#a,#b"]), false),
            (entry(NetworkKind::Local, "alice", "Alice", &["#ops"]), true),
            (
                entry(NetworkKind::Local, "alice smith", "Alice", &[]),
                false,
            ),
            (
                entry(NetworkKind::Local, "alice", "Alice", &["#ops key"]),
                false,
            ),
        ];
        for (network, valid) in cases {
            let validated = network.validate_connection_intent();
            assert_eq!(validated.is_ok(), valid, "{network:?}: {validated:?}");
            let (core_tx, _core_rx) = e6irc_queue::queue(e6irc_queue::Config {
                name: "configured-network-test-core",
                capacity: 16,
                policy: e6irc_queue::Policy::Fifo,
            });
            let started = Registry::start_inner(
                std::slice::from_ref(&network),
                &HashMap::new(),
                Storage::default(),
                super::super::CoreHandles {
                    core_tx: crate::core::CoreIngress::single(core_tx),
                    next_conn: Arc::new(crate::core::ConnectionIdAllocator::new(
                        std::num::NonZeroU64::MIN,
                    )),
                    sendq_bytes: 64 * 512,
                },
                None,
                crate::egress::InternalUpstreams::Allow,
            );
            assert_eq!(
                started.is_ok(),
                valid,
                "{network:?} validated {validated:?} but started {:?}",
                started.as_ref().err()
            );
            if let Ok(registry) = started {
                registry
                    .stop_all_within(std::time::Duration::from_secs(5))
                    .await;
            }
        }
    }

    fn configured_definition(owner: Option<&str>, name: &str) -> NetworkDefinition {
        NetworkDefinition::Configured(Arc::new(ConfiguredNetwork::from_entry(
            &crate::config::NetworkEntry {
                kind: crate::config::NetworkKind::Irc,
                name: name.into(),
                owner: owner.map(str::to_string),
                addr: "irc.example.test:6697".into(),
                tls: true,
                nick: "alice".into(),
                username: Some("alice".into()),
                realname: Some("Alice".into()),
                autojoin: vec!["#e6irc".into()],
                buffer_cap: 100,
                sasl_account: None,
                sasl_password: None,
                server_password: None,
                client_certificate: None,
            },
            None,
        )))
    }

    fn owned_configured_entry() -> NetworkEntry {
        NetworkEntry {
            kind: crate::config::NetworkKind::Irc,
            name: "Libera".into(),
            owner: Some("Alice".into()),
            addr: "127.0.0.1:1".into(),
            tls: false,
            nick: "alice".into(),
            username: Some("alice".into()),
            realname: Some("Alice".into()),
            autojoin: vec![],
            buffer_cap: 100,
            sasl_account: None,
            sasl_password: None,
            server_password: None,
            client_certificate: None,
        }
    }

    fn test_core() -> super::super::CoreHandles {
        let (core_tx, _core_rx) = e6irc_queue::queue(e6irc_queue::Config {
            name: "configured-hold-test-core",
            capacity: 16,
            policy: e6irc_queue::Policy::Fifo,
        });
        super::super::CoreHandles {
            core_tx: crate::core::CoreIngress::single(core_tx),
            next_conn: Arc::new(crate::core::ConnectionIdAllocator::new(
                std::num::NonZeroU64::MIN,
            )),
            sendq_bytes: 64 * 512,
        }
    }

    fn lifecycle(registry: &Registry) -> super::super::NetworkLifecycle {
        registry
            .get_configured_owned("alice", "libera")
            .expect("still registered")
            .1
            .runtime_snapshot()
            .lifecycle
    }

    /// The account lifecycle, not an owner route, decides whether the
    /// operator's network for an account runs: suspending the owner holds it
    /// stopped (still registered, its key still the operator's, its status
    /// saying why), reactivation restarts it from its configuration entry,
    /// and deleting the owner holds it for good.
    #[tokio::test]
    async fn a_configured_network_stops_and_restarts_with_its_owners_account() {
        use super::super::NetworkLifecycle;
        let registry = Arc::new(
            Registry::start_inner(
                &[owned_configured_entry()],
                &HashMap::new(),
                Storage::default(),
                test_core(),
                None,
                crate::egress::InternalUpstreams::Allow,
            )
            .expect("start"),
        );
        let running = registry.get_owned("alice", "libera").expect("running");
        let held = registry
            .mutate(|lane| async move {
                lane.hold_configured_owned("ALICE", OwnerHold::Suspended)
                    .await
            })
            .await;
        assert_eq!(held, 1);
        assert!(*running.watch_shutdown().borrow(), "the driver stopped");
        assert_eq!(lifecycle(&registry), NetworkLifecycle::OwnerSuspended);
        assert!(
            registry.holds_configured(Some("alice"), "libera"),
            "the key stays the operator's"
        );
        let status = registry
            .list()
            .into_iter()
            .find(|status| status.name == "libera")
            .expect("listed");
        assert_eq!(status.runtime.lifecycle.as_str(), "owner_suspended");
        assert!(!status.connected);

        let (restarted, unbuildable) = registry
            .mutate(|lane| async move { lane.release_configured_owned("alice") })
            .await;
        assert_eq!(
            (restarted, unbuildable),
            (vec!["Libera".to_string()], vec![])
        );
        let again = registry.get_owned("alice", "libera").expect("restarted");
        assert!(!Arc::ptr_eq(&running, &again));
        assert!(!*again.watch_shutdown().borrow(), "a new driver runs");
        assert!(!matches!(
            lifecycle(&registry),
            NetworkLifecycle::OwnerSuspended | NetworkLifecycle::OwnerDeleted
        ));

        let held = registry
            .mutate(|lane| async move {
                let held = lane
                    .hold_configured_owned("alice", OwnerHold::Deleted)
                    .await;
                (held, lane.release_configured_owned("alice"))
            })
            .await;
        assert_eq!(
            held,
            (1, (vec![], vec![])),
            "a deleted owner's network stays held"
        );
        assert_eq!(lifecycle(&registry), NetworkLifecycle::OwnerDeleted);
        registry
            .stop_all_within(std::time::Duration::from_secs(5))
            .await;
    }

    /// A process that starts after the owner was suspended or deleted starts
    /// the owner's configured network held, and dials nothing.
    #[tokio::test]
    async fn a_configured_network_of_an_inactive_owner_starts_held() {
        use super::super::NetworkLifecycle;
        for (hold, lifecycle_now) in [
            (OwnerHold::Suspended, NetworkLifecycle::OwnerSuspended),
            (OwnerHold::Deleted, NetworkLifecycle::OwnerDeleted),
        ] {
            let registry = Registry::start_inner(
                &[owned_configured_entry()],
                &HashMap::from([("alice".to_string(), hold)]),
                Storage::default(),
                test_core(),
                None,
                crate::egress::InternalUpstreams::Allow,
            )
            .expect("start");
            assert_eq!(lifecycle(&registry), lifecycle_now);
            assert_eq!(
                registry
                    .get_configured_owned("alice", "libera")
                    .expect("registered")
                    .1
                    .runtime_snapshot()
                    .connection_attempts,
                0,
                "no driver dialed"
            );
            let registry = Arc::new(registry);
            let restarted = registry
                .mutate(|lane| async move { lane.release_configured_owned("alice").0 })
                .await;
            assert_eq!(restarted.len(), usize::from(hold == OwnerHold::Suspended));
            registry
                .stop_all_within(std::time::Duration::from_secs(5))
                .await;
        }
    }

    /// A network the configuration defines is the operator's: every
    /// account-level transition under its key is refused and leaves it running,
    /// and the stored-network lookups do not mistake it for the account's row.
    #[tokio::test]
    async fn a_configured_network_refuses_every_account_level_transition() {
        let registry = Arc::new(empty_registry());
        registry
            .add(
                Some("alice"),
                "libera",
                configured_definition(Some("alice"), "libera"),
                Box::new(crate::bouncer::LoopbackDriver::new(16)),
            )
            .expect("a fresh key");
        let configured = registry.get_owned("alice", "libera").expect("running");
        assert!(registry.holds_configured(Some("ALICE"), "Libera"));
        assert!(registry.get_stored("alice", "libera").is_none());
        assert_eq!(registry.configured_owned("Alice").len(), 1);
        assert!(registry.get_configured_owned("alice", "LIBERA").is_some());
        let refusals = registry
            .mutate(|lane| async move {
                (
                    lane.replace(
                        Some("alice"),
                        "libera",
                        Box::new(crate::bouncer::LoopbackDriver::new(16)),
                    )
                    .await,
                    lane.ensure_running(
                        Some("alice"),
                        "libera",
                        Box::new(crate::bouncer::LoopbackDriver::new(16)),
                    )
                    .await,
                    lane.remove(Some("alice"), "libera", UnwrittenLines::Store)
                        .await,
                )
            })
            .await;
        assert_eq!(
            refusals,
            (
                Err(ConfiguredNetworkHeld.into()),
                Err(ConfiguredNetworkHeld.into()),
                Err(ConfiguredNetworkHeld)
            )
        );
        let still = registry
            .get_owned("alice", "libera")
            .expect("still running");
        assert!(Arc::ptr_eq(&configured, &still));
        assert!(!*configured.watch_shutdown().borrow());
    }

    /// Starts `(alice, libera)` through the mutation lane unless a working
    /// driver already holds it; whether it started one.
    async fn ensure_alice_libera(registry: &Arc<Registry>) -> bool {
        registry
            .mutate(|lane| async move {
                lane.ensure_running(
                    Some("alice"),
                    "libera",
                    Box::new(crate::bouncer::LoopbackDriver::new(16)),
                )
                .await
                .expect("no configured network holds the key")
            })
            .await
    }

    #[tokio::test]
    async fn ensure_running_leaves_a_live_driver_alone_and_starts_an_absent_one() {
        let registry = Arc::new(empty_registry());
        assert!(ensure_alice_libera(&registry).await);
        let first = registry.get_owned("alice", "libera").expect("started");
        assert!(
            !ensure_alice_libera(&registry).await,
            "enabling an already-running network must not restart it"
        );
        let still = registry.get_owned("alice", "libera").expect("same driver");
        assert!(Arc::ptr_eq(&first, &still));
        assert!(!*first.watch_shutdown().borrow());
    }

    #[tokio::test]
    async fn remove_owner_stops_exactly_that_accounts_networks() {
        let registry = Arc::new(empty_registry());
        registry
            .add(
                Some("Alice"),
                "libera",
                NetworkDefinition::Stored,
                Box::new(crate::bouncer::LoopbackDriver::new(16)),
            )
            .expect("a fresh key");
        registry
            .add(
                Some("alice"),
                "oftc",
                NetworkDefinition::Stored,
                Box::new(crate::bouncer::LoopbackDriver::new(16)),
            )
            .expect("a fresh key");
        registry
            .add(
                Some("Bob"),
                "libera",
                NetworkDefinition::Stored,
                Box::new(crate::bouncer::LoopbackDriver::new(16)),
            )
            .expect("a fresh key");
        registry
            .add(
                None,
                "shared",
                NetworkDefinition::Stored,
                Box::new(crate::bouncer::LoopbackDriver::new(16)),
            )
            .expect("a fresh key");
        registry
            .add(
                Some("alice"),
                "home",
                configured_definition(Some("alice"), "home"),
                Box::new(crate::bouncer::LoopbackDriver::new(16)),
            )
            .expect("a fresh key");
        let alice_libera = registry
            .get_owned("ALICE", "LIBERA")
            .expect("Alice network");
        let alice_oftc = registry.get_owned("alice", "oftc").expect("Alice network");
        let alice_home = registry.get_owned("alice", "home").expect("configured");
        let bob = registry.get_owned("bob", "libera").expect("Bob network");
        let shared = registry.get_shared("shared").expect("shared network");

        let remove_owner = |owner: &'static str| {
            registry.mutate(move |lane| async move {
                lane.remove_owner(owner, UnwrittenLines::Store).await
            })
        };
        assert_eq!(remove_owner("aLICE").await, 2);
        assert!(*alice_libera.watch_shutdown().borrow());
        assert!(*alice_oftc.watch_shutdown().borrow());
        assert!(
            !*alice_home.watch_shutdown().borrow(),
            "the operator's configured network is not the account's to stop"
        );
        assert!(!*bob.watch_shutdown().borrow());
        assert!(!*shared.watch_shutdown().borrow());
        assert!(registry.get_owned("alice", "libera").is_none());
        assert!(registry.get_owned("alice", "oftc").is_none());
        assert!(registry.get_owned("bob", "libera").is_some());
        assert!(registry.get_shared("shared").is_some());
        assert_eq!(remove_owner("alice").await, 0, "retries are idempotent");
    }

    /// The persistence task files each line under the nick the session had
    /// when it was said: a direct message the session sent before a rename is
    /// its own even when the task reaches it after the rename. It used to read
    /// the session's nick at write time, and a lagging task filed the old
    /// nick's own messages as a conversation with the old nick.
    #[test]
    fn a_line_is_stored_under_the_nick_it_was_said_under() {
        let names = e6irc_client::NetworkNames::default();
        let mut own = OwnNick(Some("alice".into()));
        let lines = [
            ":alice!u@h PRIVMSG peer :before",
            ":Alice!u@h NICK :bob",
            ":bob!u@h PRIVMSG peer :after",
            ":peer!u@h NICK :other",
        ];
        let owners: Vec<Option<String>> = lines
            .iter()
            .map(|line| own.for_line(line, &names))
            .collect();
        assert_eq!(
            owners,
            [
                Some("alice".to_string()),
                Some("alice".to_string()),
                Some("bob".to_string()),
                Some("bob".to_string()),
            ]
        );
        assert_eq!(
            crate::db::bnc_line_target(lines[0], owners[0].as_deref(), &names),
            Some("peer".to_string())
        );
    }

    /// A driver that takes `linger` to release its upstream once stopped, and
    /// hands out its stop signal so a test can see whether it was stopped.
    struct SlowToStop {
        linger: std::time::Duration,
        stopped: Arc<Mutex<Option<tokio::sync::watch::Receiver<bool>>>>,
    }

    impl super::super::NetworkDriver for SlowToStop {
        fn kind(&self) -> &'static str {
            "slow"
        }

        fn prepare(self: Box<Self>) -> super::super::PreparedDriver {
            let (handle, mut ends) = super::super::NetworkHandle::channels(16);
            *self.stopped.lock().expect("stop signal") = Some(handle.watch_shutdown());
            let linger = self.linger;
            super::super::PreparedDriver::new(handle, async move {
                ends.shutdown_signalled().await;
                tokio::time::sleep(linger).await;
                drop(ends);
            })
        }
    }

    /// A process shutdown that meets a replace in flight — its old driver
    /// still saying goodbye — waits for it and stops the new driver with the
    /// rest. It used to drain the registry at once, and the replace then
    /// started its new driver into the emptied registry: a session dialled
    /// during shutdown, never stopped, meeting the restarted daemon as a
    /// ghost. Once closed, the registry starts nothing.
    #[tokio::test]
    async fn a_shutdown_stops_the_driver_a_replace_in_flight_starts() {
        let registry = Arc::new(empty_registry());
        let old_signal = Arc::new(Mutex::new(None));
        registry
            .add(
                Some("alice"),
                "libera",
                NetworkDefinition::Stored,
                Box::new(SlowToStop {
                    linger: std::time::Duration::from_millis(300),
                    stopped: old_signal.clone(),
                }),
            )
            .expect("a fresh key");
        let new_signal = Arc::new(Mutex::new(None));
        let replace = {
            let registry = registry.clone();
            let new_signal = new_signal.clone();
            tokio::spawn(async move {
                registry
                    .mutate(move |lane| async move {
                        lane.replace(
                            Some("alice"),
                            "libera",
                            Box::new(SlowToStop {
                                linger: std::time::Duration::ZERO,
                                stopped: new_signal,
                            }),
                        )
                        .await
                    })
                    .await
            })
        };
        // The replace is waiting for the old driver.
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while registry.not_running("alice", "libera") != NotRunning::Replacing {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the replace began");
        let stops = registry
            .stop_all_within(std::time::Duration::from_secs(5))
            .await;
        assert_eq!(replace.await.expect("replace task"), Ok(()));
        assert_eq!(
            stops.running, 1,
            "the replacement was stopped with the rest"
        );
        assert!(registry.get_owned("alice", "libera").is_none());
        let new_stopped = new_signal
            .lock()
            .expect("stop signal")
            .clone()
            .expect("the replacement was built");
        assert!(
            *new_stopped.borrow(),
            "the replacement's driver was stopped"
        );
        // Closed: nothing starts after the shutdown.
        let refused = registry
            .mutate(|lane| async move {
                lane.ensure_running(
                    Some("alice"),
                    "libera",
                    Box::new(crate::bouncer::LoopbackDriver::new(16)),
                )
                .await
            })
            .await;
        assert_eq!(refused, Err(RegistryRefusal::Closed(RegistryClosed)));
        assert!(registry.get_owned("alice", "libera").is_none());
    }

    /// An owned network with no driver is disabled only when its row says so.
    /// An enabled one being replaced is being reconfigured, and one whose
    /// driver could not be built at boot says why; every one of them used to
    /// be called disabled.
    #[tokio::test]
    async fn an_owned_network_without_a_driver_says_why() {
        let registry = Arc::new(empty_registry());
        assert_eq!(registry.not_running("alice", "libera"), NotRunning::Absent);
        assert_eq!(
            not_running_notice("libera", false, NotRunning::Absent),
            "Your network 'libera' is disabled."
        );
        registry.record_unstartable("Alice", "Libera", "no master key is configured".into());
        let failed = registry.not_running("alice", "libera");
        assert_eq!(
            failed,
            NotRunning::FailedToStart("no master key is configured".into())
        );
        assert_eq!(
            not_running_notice("libera", true, failed.clone()),
            "Your network 'libera' failed to start: no master key is configured"
        );
        assert_eq!(
            not_running_notice("libera", false, failed),
            "Your network 'libera' is disabled.",
            "the row's flag decides disabled, whatever boot said"
        );
        // A replace in flight marks the network as being reconfigured, and a
        // start clears what boot recorded.
        let signal = Arc::new(Mutex::new(None));
        registry
            .add(
                Some("alice"),
                "libera",
                NetworkDefinition::Stored,
                Box::new(SlowToStop {
                    linger: std::time::Duration::from_millis(300),
                    stopped: signal,
                }),
            )
            .expect("a fresh key");
        let replace = {
            let registry = registry.clone();
            tokio::spawn(async move {
                registry
                    .mutate(|lane| async move {
                        lane.replace(
                            Some("alice"),
                            "libera",
                            Box::new(crate::bouncer::LoopbackDriver::new(16)),
                        )
                        .await
                    })
                    .await
            })
        };
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while registry.not_running("alice", "libera") != NotRunning::Replacing {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the replace began");
        assert_eq!(
            not_running_notice("libera", true, NotRunning::Replacing),
            "Your network 'libera' is being reconfigured; attach again in a moment."
        );
        assert_eq!(replace.await.expect("replace task"), Ok(()));
        assert!(registry.get_owned("alice", "libera").is_some());
        assert_eq!(registry.not_running("alice", "libera"), NotRunning::Absent);
    }

    /// A mutation whose caller is dropped part-way — an HTTP request abandoned
    /// at its deadline — still completes: the stop of the old driver and the
    /// start of the new one are never separated.
    #[tokio::test]
    async fn a_mutation_whose_caller_is_dropped_still_completes() {
        let registry = Arc::new(empty_registry());
        assert!(ensure_alice_libera(&registry).await);
        let first = registry.get_owned("alice", "libera").expect("started");
        let (entered_tx, entered) = tokio::sync::oneshot::channel();
        let (proceed_tx, proceed) = tokio::sync::oneshot::channel::<()>();
        let caller = {
            let registry = registry.clone();
            tokio::spawn(async move {
                registry
                    .mutate(|lane| async move {
                        entered_tx.send(()).expect("the test awaits entry");
                        drop(proceed.await);
                        lane.replace(
                            Some("alice"),
                            "libera",
                            Box::new(crate::bouncer::LoopbackDriver::new(16)),
                        )
                        .await
                        .expect("no configured network holds the key");
                    })
                    .await;
            })
        };
        entered.await.expect("the mutation started");
        // The caller goes away mid-transition, as a request past its deadline.
        caller.abort();
        drop(caller.await);
        drop(proceed_tx);
        // The lane is taken only once the abandoned work has finished.
        let replaced = registry
            .mutate(|lane| async move { lane.get_owned("alice", "libera") })
            .await
            .expect("the replacement started although its caller was gone");
        assert!(!Arc::ptr_eq(&first, &replaced));
        assert!(*first.watch_shutdown().borrow());
    }

    /// A slot whose persistence task is `persist`, fed by a network that said
    /// `said` lines and has already released its upstream.
    fn slot_with_persistence<F, Fut>(said: usize, persist: F) -> Slot
    where
        F: FnOnce(PersistenceFeed) -> Fut,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let (handle, ends) = super::super::NetworkHandle::channels(16);
        let events = handle.subscribe();
        for n in 0..said {
            ends.emit_line(format!(":peer PRIVMSG #room :last words {n}"));
        }
        drop(ends);
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(persist(PersistenceFeed {
            events,
            stopped,
            draining: None,
        }));
        Slot {
            handle: Arc::new(handle),
            persistence: Some(Persistence { stop, task }),
            memory: None,
            kind: "loopback",
            definition: NetworkDefinition::Stored,
            restart: None,
            hold: None,
        }
    }

    /// A process shutdown keeps the network's rows, so the lines the driver
    /// said last reach the backlog even when writing them is slow — they used
    /// to be lost to an abort the moment the driver released its upstream.
    #[tokio::test]
    async fn a_process_shutdown_writes_the_last_backlog_lines() {
        let registry = empty_registry();
        let written = Arc::new(Mutex::new(Vec::new()));
        let slot = slot_with_persistence(3, {
            let written = written.clone();
            |mut feed| async move {
                while let Some(event) = feed.next().await {
                    // A database write takes time; the shutdown waits for it.
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    if let Ok(super::super::DriverEvent::Line(line)) = event {
                        written.lock().expect("written").push(line.line);
                    }
                }
            }
        });
        registry
            .networks
            .lock()
            .expect("registry")
            .slots
            .insert(NetworkKey::new(Some("alice"), "libera"), slot);
        let stops = registry
            .stop_all_within(std::time::Duration::from_secs(5))
            .await;
        assert_eq!(
            stops,
            DriverStops {
                running: 1,
                released: 1,
                backlog_written: 1,
            }
        );
        assert_eq!(written.lock().expect("written").len(), 3);
    }

    /// A persistence task that cannot finish (a wedged database) is ended at
    /// the shutdown deadline, and the report says its lines were not written.
    #[tokio::test]
    async fn a_wedged_backlog_write_is_aborted_at_the_shutdown_deadline() {
        struct Dropped(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let registry = empty_registry();
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let slot = slot_with_persistence(1, {
            let guard = Dropped(dropped.clone());
            |_feed| async move {
                let _held = guard;
                std::future::pending::<()>().await;
            }
        });
        registry
            .networks
            .lock()
            .expect("registry")
            .slots
            .insert(NetworkKey::new(None, "shared"), slot);
        let stops = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            registry.stop_all_within(std::time::Duration::from_millis(100)),
        )
        .await
        .expect("the stop returns at its deadline");
        assert_eq!(stops.backlog_written, 0);
        assert_eq!(stops.released, 1);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !dropped.load(std::sync::atomic::Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the wedged task was aborted");
    }

    /// A stop that keeps the network's rows writes the lines its driver said
    /// last; one ahead of a deletion drops them.
    #[tokio::test]
    async fn a_stop_that_keeps_the_rows_writes_what_was_still_queued() {
        for (unwritten, kept) in [(UnwrittenLines::Store, 3), (UnwrittenLines::Discard, 0)] {
            let (handle, ends) = super::super::NetworkHandle::channels(16);
            let events = handle.subscribe();
            for n in 0..3 {
                ends.emit_line(format!(":peer PRIVMSG #room :last words {n}"));
            }
            let (stop, stopped) = tokio::sync::oneshot::channel();
            stop.send(unwritten).expect("stop");
            let mut feed = PersistenceFeed {
                events,
                stopped,
                draining: None,
            };
            // Finite: the drain ends at what was queued, without waiting for
            // a driver that will say nothing more.
            let written = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                let mut written = 0;
                while let Some(event) = feed.next().await {
                    event.expect("no lag");
                    written += 1;
                }
                written
            })
            .await
            .expect("the drain ends");
            assert_eq!(written, kept, "{unwritten:?}");
            drop(ends);
        }
    }
}
