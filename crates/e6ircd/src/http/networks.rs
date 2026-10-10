//! Per-account BNC networks and their buffers.

use super::*;

// ---- per-account BNC networks -------------------------------------------

/// A safe, user-facing failure from a network mutation. Keeping the problem
/// fields typed until the HTTP edge lets the JSON API render problem+json while
/// server-rendered forms show the same precise reason.
#[derive(Debug)]
pub(super) struct NetworkMutationError {
    status: StatusCode,
    title: &'static str,
    detail: Option<String>,
    /// The form field the failure belongs to, when it has one. Server-rendered
    /// forms render the message inline at that field (and mark it
    /// `aria-invalid`) instead of leaving the user to map a top-of-page banner
    /// to the offending input; fieldless failures keep the banner.
    field: Option<&'static str>,
}

impl NetworkMutationError {
    pub(super) fn new(status: StatusCode, title: &'static str, detail: Option<&str>) -> Self {
        Self {
            status,
            title,
            detail: detail.map(str::to_string),
            field: None,
        }
    }

    pub(super) fn with_field(mut self, field: &'static str) -> Self {
        self.field = Some(field);
        self
    }

    pub(super) fn message(&self) -> String {
        match &self.detail {
            Some(detail) => format!("{}: {detail}", self.title),
            None => self.title.to_string(),
        }
    }

    pub(super) fn into_response(self) -> Response {
        problem_at_field(self.status, self.title, self.detail.as_deref(), self.field)
    }
}

fn network_error(
    status: StatusCode,
    title: &'static str,
    detail: Option<&str>,
) -> NetworkMutationError {
    NetworkMutationError::new(status, title, detail)
}

/// An account-level mutation met a network the server's configuration defines
/// for the account: the operator owns it, so it is refused rather than
/// replaced, stopped or shadowed.
impl From<crate::bouncer::ConfiguredNetworkHeld> for NetworkMutationError {
    fn from(held: crate::bouncer::ConfiguredNetworkHeld) -> Self {
        network_error(
            StatusCode::CONFLICT,
            "Network defined by the server configuration",
            Some(&held.to_string()),
        )
    }
}

/// A start the registry refused: the configuration holds the key, or the
/// process is shutting down and starts nothing more.
impl From<crate::bouncer::RegistryRefusal> for NetworkMutationError {
    fn from(refusal: crate::bouncer::RegistryRefusal) -> Self {
        match refusal {
            crate::bouncer::RegistryRefusal::ConfiguredNetworkHeld(held) => held.into(),
            crate::bouncer::RegistryRefusal::Closed(closed) => network_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Server shutting down",
                Some(&closed.to_string()),
            ),
        }
    }
}

/// Refuse to create `(account, name)` when the server configuration defines
/// that network — running now, or saved to start at the next restart — so an
/// account's network can never share a key with the operator's.
async fn refuse_configured_network_name(
    state: &AppState,
    lane: &crate::bouncer::MutationLane,
    account: &str,
    name: &str,
) -> Result<(), NetworkMutationError> {
    let fold = |value: &str| e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(value);
    let saved = match &state.managed_config {
        Some(config) => config.read().await.settings.networks.iter().any(|network| {
            network.owner.as_deref().map(fold) == Some(fold(account))
                && fold(&network.name) == fold(name)
        }),
        None => false,
    };
    if saved || lane.holds_configured(Some(account), name) {
        return Err(crate::bouncer::ConfiguredNetworkHeld.into());
    }
    Ok(())
}

/// Record a command about to be sent to a network's upstream on the owner's
/// behalf. The command is not a database mutation, so there is no transaction
/// to share: the record is written first, and a command that cannot be
/// recorded is not sent.
async fn audit_network_command(
    state: &AppState,
    account: &str,
    network: &str,
    command: &str,
) -> Result<(), crate::db::DbError> {
    let folded = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(account);
    crate::db::insert_audit_log(
        pool_of(state),
        &crate::db::AuditPrincipal::account(&folded),
        "NETWORK_ACCOUNT_COMMAND",
        &crate::db::AuditPrincipal::network(&format!("{folded}/{network}")),
        command,
    )
    .await
}

/// Normalize the shared result contract of owner-scoped network updates. This
/// keeps "missing row" and database failure semantics identical across edit
/// and enable/disable mutations.
fn require_network_updated(
    result: Result<bool, crate::db::DbError>,
    operation: &str,
) -> Result<(), NetworkMutationError> {
    match result {
        Ok(true) => Ok(()),
        Ok(false) => Err(network_error(
            StatusCode::NOT_FOUND,
            "No such network",
            None,
        )),
        Err(error) => {
            eprintln!("http: network {operation}: {error}");
            Err(network_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            ))
        }
    }
}

/// A curated public IRC network whose connection defaults can be selected in
/// the chat client's add dialog. `id` is the stable selector and `name` the
/// network name it fills in, both deliberately distinct from the human `label`
/// so spaces cannot leak into URL/client addressing.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub(super) struct IrcNetworkPreset {
    pub(super) id: &'static str,
    pub(super) label: &'static str,
    pub(super) name: &'static str,
    pub(super) addr: &'static str,
    pub(super) tls: bool,
}

/// Public connection endpoints from the networks' own documentation, each
/// verified by a TLS registration through this driver on 2026-09-21 (the
/// certificate the round robin's members present is valid for the preset's
/// hostname, and the registration is welcomed):
/// - <https://libera.chat/guides/connect>
/// - <https://www.oftc.net/>
/// - <https://snoonet.org/help/>
///
/// EFnet is not offered: `irc.efnet.org` is a round robin of independently
/// run servers whose certificates name themselves (`efnet.tngnet.nl`,
/// `irc.colosolutions.net`, …), none valid for `irc.efnet.org`, so a preset
/// for it fails `secure_connection_failed` on every address, forever.
///
/// Keep this catalog small and authoritative: a stale preset is worse than
/// making a custom endpoint explicit, and a network that cannot connect must
/// not be offered.
pub(super) const IRC_NETWORK_PRESETS: &[IrcNetworkPreset] = &[
    IrcNetworkPreset {
        id: "libera",
        label: "Libera Chat",
        name: "libera",
        addr: "irc.libera.chat:6697",
        tls: true,
    },
    IrcNetworkPreset {
        id: "oftc",
        label: "OFTC",
        name: "oftc",
        addr: "irc.oftc.net:6697",
        tls: true,
    },
    IrcNetworkPreset {
        id: "snoonet",
        label: "Snoonet",
        name: "snoonet",
        addr: "irc.snoonet.org:6697",
        tls: true,
    },
];

#[derive(serde::Serialize)]
struct NetworkPresetsResponse {
    presets: &'static [IrcNetworkPreset],
}

/// The curated catalog, for every client that offers "pick a known network":
/// the chat client's add dialog reads it here rather than keeping a copy, so
/// an endpoint is corrected in one place.
pub(super) async fn network_presets() -> Response {
    json_response(NetworkPresetsResponse {
        presets: IRC_NETWORK_PRESETS,
    })
}

/// Complete, kind-specific network creation request.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub(super) enum CreateNetwork {
    Irc {
        name: String,
        addr: String,
        tls: bool,
        nick: String,
        /// The IRC `USER` name. Required: it is never derived from the nick.
        username: String,
        realname: String,
        autojoin: Vec<String>,
        #[serde(default)]
        sasl_account: Option<String>,
        #[serde(default)]
        sasl_password: Option<String>,
        /// The network's connection password (`PASS`), for a private server
        /// that requires one. IRC only: a bridge variant has no such field.
        #[serde(default)]
        server_password: Option<String>,
    },
    Matrix {
        name: String,
        addr: String,
        tls: bool,
        nick: String,
        autojoin: Vec<String>,
        sasl_password: String,
    },
    Discord {
        name: String,
        addr: String,
        tls: bool,
        autojoin: Vec<String>,
        sasl_password: String,
    },
    Slack {
        name: String,
        addr: String,
        tls: bool,
        autojoin: Vec<String>,
        sasl_account: String,
        sasl_password: String,
    },
}

#[derive(Clone)]
struct NetworkCreation {
    kind: crate::config::NetworkKind,
    name: String,
    addr: String,
    tls: bool,
    nick: String,
    /// `Some` exactly for `kind=irc`; a bridge request cannot carry one.
    username: Option<String>,
    realname: String,
    /// As the request wrote each entry: `#channel`, or `#channel key`.
    autojoin: Vec<crate::bouncer::AutojoinEntry>,
    sasl_account: Option<String>,
    sasl_password: Option<String>,
    /// `None` for every bridge: only an IRC request can carry one.
    server_password: Option<String>,
}

/// The autojoin entries a request states, each `#channel` or `#channel key`.
fn submitted_autojoin(autojoin: &[String]) -> Vec<crate::bouncer::AutojoinEntry> {
    autojoin
        .iter()
        .map(|entry| crate::bouncer::AutojoinEntry::from_submitted(entry))
        .collect()
}

impl From<CreateNetwork> for NetworkCreation {
    fn from(request: CreateNetwork) -> Self {
        use crate::config::NetworkKind;
        match request {
            CreateNetwork::Irc {
                name,
                addr,
                tls,
                nick,
                username,
                realname,
                autojoin,
                sasl_account,
                sasl_password,
                server_password,
            } => Self {
                kind: NetworkKind::Irc,
                name,
                addr,
                tls,
                nick,
                username: Some(username),
                realname,
                autojoin: submitted_autojoin(&autojoin),
                sasl_account,
                sasl_password,
                server_password,
            },
            CreateNetwork::Matrix {
                name,
                addr,
                tls,
                nick,
                autojoin,
                sasl_password,
            } => Self {
                kind: NetworkKind::Matrix,
                name,
                addr,
                tls,
                nick,
                username: None,
                realname: String::new(),
                autojoin: submitted_autojoin(&autojoin),
                sasl_account: None,
                sasl_password: Some(sasl_password),
                server_password: None,
            },
            CreateNetwork::Discord {
                name,
                addr,
                tls,
                autojoin,
                sasl_password,
            } => Self {
                kind: NetworkKind::Discord,
                name,
                addr,
                tls,
                nick: String::new(),
                username: None,
                realname: String::new(),
                autojoin: submitted_autojoin(&autojoin),
                sasl_account: None,
                sasl_password: Some(sasl_password),
                server_password: None,
            },
            CreateNetwork::Slack {
                name,
                addr,
                tls,
                autojoin,
                sasl_account,
                sasl_password,
            } => Self {
                kind: NetworkKind::Slack,
                name,
                addr,
                tls,
                nick: String::new(),
                username: None,
                realname: String::new(),
                autojoin: submitted_autojoin(&autojoin),
                sasl_account: Some(sasl_account),
                sasl_password: Some(sasl_password),
                server_password: None,
            },
        }
    }
}

/// An ephemeral qualification request. It intentionally omits the durable
/// network name, registers the configured identity, joins nothing, and
/// persists nothing; its channels are validated as a save would validate them.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreflightNetwork {
    pub(super) addr: String,
    pub(super) tls: bool,
    pub(super) nick: String,
    pub(super) username: String,
    pub(super) realname: String,
    #[serde(default)]
    pub(super) autojoin: Vec<String>,
    #[serde(default)]
    pub(super) sasl_account: Option<String>,
    #[serde(default)]
    pub(super) sasl_password: Option<String>,
    #[serde(default)]
    pub(super) server_password: Option<String>,
}

/// One closed NickServ account-registration action. These are ordinary IRC
/// service commands under the hood; the typed HTTP shape exists so the console
/// can guide the email round trip without ever accepting an arbitrary raw line.
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum NetworkAccountCommand {
    Register { email: String, password: String },
    Verify { code: String },
}

#[derive(serde::Serialize)]
struct NetworkAccountCommandResponse {
    queued: bool,
    command: &'static str,
    transcript: String,
}

#[derive(serde::Serialize)]
struct PreflightNetworkResponse {
    ok: bool,
    #[serde(flatten)]
    result: crate::bouncer::IrcPreflight,
}

#[derive(serde::Serialize)]
pub(super) struct NetworkRuntimeResponse {
    state: &'static str,
    state_changed_at: String,
    next_retry_at: Option<String>,
    recent_failures: Vec<NetworkFailureResponse>,
    connected_at: Option<String>,
    last_input_at: Option<String>,
    last_output_at: Option<String>,
    last_error_at: Option<String>,
    last_error: Option<NetworkFailureResponse>,
    connect_latency_ms: Option<u64>,
    connection_attempts: u64,
    errors: u64,
    attached_clients: u64,
    traffic: NetworkTrafficResponse,
    buffer: NetworkBufferResponse,
}

#[derive(serde::Serialize)]
struct NetworkFailureResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    at: Option<String>,
    code: &'static str,
    summary: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostic: Option<String>,
}

#[derive(serde::Serialize)]
struct NetworkTrafficResponse {
    lines_in: u64,
    bytes_in: u64,
    lines_out: u64,
    bytes_out: u64,
}

#[derive(serde::Serialize)]
struct NetworkBufferResponse {
    lines: usize,
    capacity: usize,
}

pub(super) fn runtime_response(
    runtime: &crate::bouncer::NetworkRuntimeSnapshot,
) -> NetworkRuntimeResponse {
    let timestamp =
        |value: Option<e6irc_proto::time::Millis>| value.map(e6irc_proto::time::server_time);
    NetworkRuntimeResponse {
        state: runtime.lifecycle.as_str(),
        state_changed_at: e6irc_proto::time::server_time(runtime.state_changed_at),
        next_retry_at: timestamp(runtime.next_retry_at),
        recent_failures: runtime
            .recent_failures
            .iter()
            .map(|record| NetworkFailureResponse {
                at: Some(e6irc_proto::time::server_time(record.at)),
                code: record.code(),
                summary: record.summary(),
                diagnostic: None,
            })
            .collect(),
        connected_at: timestamp(runtime.connected_at),
        last_input_at: timestamp(runtime.last_input_at),
        last_output_at: timestamp(runtime.last_output_at),
        last_error_at: timestamp(runtime.last_error_at),
        last_error: runtime.last_error.map(|error| NetworkFailureResponse {
            at: None,
            code: error.code(),
            summary: error.summary(),
            diagnostic: runtime.last_error_diagnostic.clone(),
        }),
        connect_latency_ms: runtime.connect_latency_ms,
        connection_attempts: runtime.connection_attempts,
        errors: runtime.errors,
        attached_clients: runtime.attached_clients,
        traffic: NetworkTrafficResponse {
            lines_in: runtime.lines_in,
            bytes_in: runtime.bytes_in,
            lines_out: runtime.lines_out,
            bytes_out: runtime.bytes_out,
        },
        buffer: NetworkBufferResponse {
            lines: runtime.buffer_lines,
            capacity: runtime.buffer_capacity,
        },
    }
}

#[derive(serde::Serialize)]
pub(super) struct NetworkResponse {
    name: String,
    kind: &'static str,
    addr: String,
    tls: bool,
    nick: String,
    /// The IRC `USER` name; `null` for a bridge.
    username: Option<String>,
    realname: Option<String>,
    /// The channels, without their keys.
    autojoin: Vec<String>,
    /// The channels among `autojoin` that have a sealed key stored. The key
    /// itself is never shown.
    autojoin_keyed: Vec<String>,
    sasl_account: Option<String>,
    has_sasl_account: bool,
    has_sasl_password: bool,
    /// Whether a sealed server password is stored. The value is never shown.
    has_server_password: bool,
    enabled: bool,
    connected: Option<bool>,
    runtime: Option<NetworkRuntimeResponse>,
    /// Whether the server configuration defines this network: the operator's,
    /// read-only through the account API.
    configured: bool,
}

#[derive(serde::Serialize)]
struct NetworkListResponse {
    networks: Vec<NetworkResponse>,
}

#[derive(serde::Serialize)]
struct NetworkCreatedResponse {
    name: String,
    attach: String,
}

#[derive(serde::Serialize)]
struct NetworkBufferLinesResponse {
    lines: Vec<String>,
}

#[derive(serde::Serialize)]
struct NetworkEnabledResponse {
    name: String,
    enabled: bool,
}

#[derive(serde::Serialize)]
struct AdminNetworkEnabledResponse {
    owner: String,
    name: String,
    enabled: bool,
}

#[derive(serde::Serialize)]
pub(super) struct AdminNetworkResponse {
    #[serde(flatten)]
    kind: AdminNetworkKind,
}

#[derive(serde::Serialize)]
#[serde(untagged)]
enum AdminNetworkKind {
    Owned {
        owner: String,
        #[serde(flatten)]
        network: NetworkResponse,
    },
    Shared {
        owner: &'static str,
        name: String,
        kind: &'static str,
        enabled: bool,
        connected: bool,
        runtime: NetworkRuntimeResponse,
        shared: bool,
    },
}

pub(super) fn owned_admin_network_response(
    owner: String,
    network: NetworkResponse,
) -> AdminNetworkResponse {
    AdminNetworkResponse {
        kind: AdminNetworkKind::Owned { owner, network },
    }
}

pub(super) fn shared_admin_network_response(
    status: crate::bouncer::NetworkStatus,
) -> AdminNetworkResponse {
    AdminNetworkResponse {
        kind: AdminNetworkKind::Shared {
            owner: "shared",
            name: status.name,
            kind: status.kind,
            enabled: true,
            connected: status.connected,
            runtime: runtime_response(&status.runtime),
            shared: true,
        },
    }
}

pub(super) fn network_response(
    network: crate::db::BncNetworkRow,
    runtime: Option<&crate::bouncer::NetworkRuntimeSnapshot>,
) -> NetworkResponse {
    let has_sasl_account = network.sasl_account.is_some();
    let has_sasl_password = network.sasl_password_sealed.is_some();
    let has_server_password = network.server_password_sealed.is_some();
    let autojoin_keyed = network
        .autojoin
        .iter()
        .filter(|entry| entry.key_sealed.is_some())
        .map(|entry| entry.channel.clone())
        .collect();
    let autojoin = network
        .autojoin
        .into_iter()
        .map(|entry| entry.channel)
        .collect();
    let account = if network.kind.account_is_secret() {
        None
    } else {
        network.sasl_account.clone()
    };
    NetworkResponse {
        name: network.name,
        kind: network.kind.as_db_str(),
        addr: network.addr,
        tls: network.tls,
        nick: network.nick,
        username: network.username,
        realname: network.realname,
        autojoin,
        autojoin_keyed,
        sasl_account: account,
        has_sasl_account,
        has_sasl_password,
        has_server_password,
        enabled: network.enabled,
        connected: runtime.map(|r| r.lifecycle == crate::bouncer::NetworkLifecycle::Connected),
        runtime: runtime.map(runtime_response),
        configured: false,
    }
}

/// A network the server configuration defines for an account, in the owner
/// view's shape: always enabled (only the operator can stop it), credentials as
/// presence booleans, and `configured` so a client offers no edit.
pub(super) fn configured_network_response(
    network: &crate::bouncer::ConfiguredNetwork,
    runtime: &crate::bouncer::NetworkRuntimeSnapshot,
) -> NetworkResponse {
    NetworkResponse {
        name: network.name.clone(),
        kind: network.kind.as_db_str(),
        addr: network.addr.clone(),
        tls: network.tls,
        nick: network.nick.clone(),
        username: network.username.clone(),
        realname: network.realname.clone(),
        autojoin: network.autojoin.clone(),
        autojoin_keyed: Vec::new(),
        sasl_account: network.sasl_account.clone(),
        has_sasl_account: network.has_sasl_account,
        has_sasl_password: network.has_sasl_password,
        has_server_password: network.has_server_password,
        enabled: true,
        connected: Some(runtime.lifecycle == crate::bouncer::NetworkLifecycle::Connected),
        runtime: Some(runtime_response(runtime)),
        configured: true,
    }
}

/// The account's own networks (metadata only — never the secret): its stored
/// networks, then those the server configuration defines for it.
pub(super) async fn list_networks(
    State(state): State<Arc<AppState>>,
    Authenticated(account, _): Authenticated,
) -> Response {
    let registry = registry_of(&state);
    let pool = pool_of(&state);
    match crate::db::list_bnc_networks(pool, &account).await {
        Ok(rows) => {
            let mut networks: Vec<NetworkResponse> = rows
                .into_iter()
                .map(|n| {
                    let handle = registry.get_stored(&account, &n.name);
                    let runtime = handle.as_ref().map(|handle| handle.runtime_snapshot());
                    network_response(n, runtime.as_ref())
                })
                .collect();
            networks.extend(registry.configured_owned(&account).into_iter().map(
                |(configured, handle)| {
                    configured_network_response(&configured, &handle.runtime_snapshot())
                },
            ));
            json_no_store(NetworkListResponse { networks })
        }
        Err(e) => {
            eprintln!("http: network list failed: {e}");
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            )
        }
    }
}

/// One owner-scoped network with its stored configuration and live runtime
/// diagnostics. Secret material is represented only by presence booleans.
pub(super) async fn get_network(
    State(state): State<Arc<AppState>>,
    Authenticated(account, _): Authenticated,
    PathParams(name): PathParams<String>,
) -> Response {
    let registry = registry_of(&state);
    let pool = pool_of(&state);
    let network = match crate::db::get_bnc_network(pool, &account, &name).await {
        Ok(Some(network)) => network,
        Ok(None) => {
            return match registry.get_configured_owned(&account, &name) {
                Some((configured, handle)) => json_no_store(configured_network_response(
                    &configured,
                    &handle.runtime_snapshot(),
                )),
                None => problem(StatusCode::NOT_FOUND, "No such network", None),
            };
        }
        Err(e) => {
            eprintln!("http: network read failed: {e}");
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            );
        }
    };
    let handle = registry.get_stored(&account, &name);
    let runtime = handle.as_ref().map(|handle| handle.runtime_snapshot());
    json_no_store(network_response(network, runtime.as_ref()))
}

/// Create a network the caller owns, persist it, and start its always-on
/// driver.
pub(super) async fn create_network(
    State(state): State<Arc<AppState>>,
    Authenticated(account, _): Authenticated,
    JsonBody(req): JsonBody<CreateNetwork>,
) -> Response {
    let registry = registry_of(&state);
    let req = NetworkCreation::from(req);

    match create_network_core(&state, registry, &account, &req).await {
        Ok(()) => (
            StatusCode::CREATED,
            axum::Json(NetworkCreatedResponse {
                attach: format!("{account}/{}", req.name),
                name: req.name,
            }),
        )
            .into_response(),
        Err(error) => error.into_response(),
    }
}

/// Resolve, connect, negotiate TLS, and register against an IRC upstream using
/// the exact production driver path. No row is written and no reconnecting
/// driver survives the response.
pub(super) async fn preflight_network(
    State(state): State<Arc<AppState>>,
    permit: PreflightPermit,
    JsonBody(req): JsonBody<PreflightNetwork>,
) -> Response {
    if let Err(refused) = refuse_test_of_a_running_network(&state, permit.account(), &req).await {
        return refused.into_response();
    }
    match preflight_network_core(req, state.internal_upstreams).await {
        Ok(result) => axum::Json(PreflightNetworkResponse { ok: true, result }).into_response(),
        Err(error) => error.into_response(),
    }
}

/// A connection test registers the requested identity itself. While the
/// account's network with that upstream and nickname is running, its driver
/// holds the nickname, so the test can only end `nickname_in_use` — which says
/// nothing about the settings. Refused with the way out.
async fn refuse_test_of_a_running_network(
    state: &AppState,
    account: &str,
    req: &PreflightNetwork,
) -> Result<(), NetworkMutationError> {
    let registry = registry_of(state);
    let rows = crate::db::list_bnc_networks(pool_of(state), account)
        .await
        .map_err(|error| {
            eprintln!("http: connection test network lookup: {error}");
            network_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            )
        })?;
    let casemap = e6irc_proto::casemap::CaseMapping::Rfc1459;
    let holds_the_nick = |kind: crate::config::NetworkKind, addr: &str, nick: &str| {
        kind == crate::config::NetworkKind::Irc
            && addr.eq_ignore_ascii_case(&req.addr)
            && casemap.eq(nick, &req.nick)
    };
    if let Some(row) = rows.iter().find(|row| {
        holds_the_nick(row.kind, &row.addr, &row.nick)
            && registry.get_stored(account, &row.name).is_some()
    }) {
        return Err(network_error(
            StatusCode::CONFLICT,
            "Network is running",
            Some(&format!(
                "network '{}' is running; disable it to test its settings",
                row.name
            )),
        ));
    }
    // A network the server configuration defines for the account holds the
    // nickname just the same, and only the operator can stop it.
    if let Some((configured, _)) = registry
        .configured_owned(account)
        .into_iter()
        .find(|(configured, _)| holds_the_nick(configured.kind, &configured.addr, &configured.nick))
    {
        return Err(network_error(
            StatusCode::CONFLICT,
            "Network is running",
            Some(&format!(
                "network '{}', defined by the server configuration, is running with this \
                 upstream and nickname",
                configured.name
            )),
        ));
    }
    Ok(())
}

pub(super) async fn preflight_network_core(
    req: PreflightNetwork,
    internal_upstreams: crate::egress::InternalUpstreams,
) -> Result<crate::bouncer::IrcPreflight, NetworkMutationError> {
    let identity = validate_irc_upstream(
        &req.addr,
        &req.nick,
        Some(&req.username),
        Some(&req.realname),
        &submitted_autojoin(&req.autojoin),
        internal_upstreams,
    )?;
    refuse_cleartext_credentials(
        &req.addr,
        req.tls,
        req.sasl_password.is_some(),
        req.server_password.is_some(),
        internal_upstreams,
    )?;
    let sasl_account = req
        .sasl_account
        .as_deref()
        .map(parse_sasl_account)
        .transpose()?;
    if let Some(password) = req.sasl_password.as_deref() {
        validate_credential_field(password, MAX_UPSTREAM_PASSWORD_LEN)
            .map_err(|e| e.with_field("sasl_password"))?;
    }
    if sasl_account.is_some() != req.sasl_password.is_some() {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Incomplete upstream SASL",
            Some("provide both sasl_account and sasl_password, or neither"),
        )
        .with_field("sasl_password"));
    }
    let server_password = req.server_password.map(parse_server_password).transpose()?;

    let config = crate::bouncer::NetworkConfig {
        addr: req.addr,
        tls: req.tls,
        nick: identity.nick,
        username: identity.username,
        realname: identity
            .realname
            .expect("the preflight request's realname was supplied and parsed"),
        autojoin: identity.autojoin,
        buffer_cap: 1,
        sasl: sasl_account
            .map(crate::bouncer::UpstreamSaslAccount::into_string)
            .zip(req.sasl_password),
        server_password,
        keepalive_idle: crate::bouncer::KEEPALIVE_IDLE,
        rejection_retry_floor: crate::bouncer::REJECTION_RETRY_FLOOR,
        internal_upstreams,
        first_dial: crate::bouncer::FirstDial::Immediate,
        nick_regain: crate::bouncer::NickRegainTiming::default(),
    };
    // Below the request deadline, so the test's own typed timeout is what the
    // caller reads rather than a generic "request timed out".
    crate::bouncer::preflight_irc(&config, REQUEST_DEADLINE - Duration::from_secs(5))
        .await
        .map_err(|failure| {
            network_error(
                StatusCode::BAD_GATEWAY,
                "IRC network preflight failed",
                Some(&match failure.diagnostic() {
                    Some(detail) => format!("{} ({}): {detail}", failure.summary(), failure.code()),
                    None => format!("{} ({})", failure.summary(), failure.code()),
                }),
            )
        })
}

/// Queue a standard NickServ REGISTER or VERIFY REGISTER command on one live,
/// caller-owned IRC network. Replies remain ordinary upstream IRC lines and
/// are visible in the same live/persisted transcript as every other command.
pub(super) async fn network_account_command(
    State(state): State<Arc<AppState>>,
    Authenticated(account, _): Authenticated,
    PathParams(name): PathParams<String>,
    JsonBody(request): JsonBody<NetworkAccountCommand>,
) -> Response {
    let network = match crate::db::get_bnc_network(pool_of(&state), &account, &name).await {
        Ok(Some(network)) => network,
        Ok(None) => return problem(StatusCode::NOT_FOUND, "No such network", None),
        Err(error) => {
            eprintln!("http: network account registration lookup: {error}");
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            );
        }
    };
    if network.kind != crate::config::NetworkKind::Irc {
        return problem(
            StatusCode::CONFLICT,
            "IRC account registration unavailable",
            Some("NickServ registration applies only to IRC networks"),
        );
    }
    let Some(handle) = registry_of(&state).get_stored(&account, &network.name) else {
        return problem(
            StatusCode::CONFLICT,
            "IRC network is not running",
            Some(
                "enable the network and wait for a connected state before sending NickServ commands",
            ),
        );
    };
    let runtime = handle.runtime_snapshot();
    if runtime.lifecycle != crate::bouncer::NetworkLifecycle::Connected {
        let detail = match (runtime.last_error, runtime.last_error_diagnostic.as_deref()) {
            (Some(failure), Some(diagnostic)) => {
                format!("{} Upstream: {diagnostic}", failure.summary())
            }
            (Some(failure), None) => failure.summary().to_string(),
            (None, _) => "wait for the network to reach connected state and try again".to_string(),
        };
        return problem(
            StatusCode::CONFLICT,
            "IRC network is not connected",
            Some(&detail),
        );
    }
    let (command, kind) = match request {
        NetworkAccountCommand::Register { email, password } => {
            let email = match crate::identity::ContactEmail::parse(&email) {
                Ok(email) => email,
                Err(error) => {
                    return problem(
                        StatusCode::BAD_REQUEST,
                        "Invalid email address",
                        Some(&error.to_string()),
                    );
                }
            };
            if let Err(detail) = validate_single_service_token(&password, 200, "password") {
                return problem(
                    StatusCode::BAD_REQUEST,
                    "Invalid NickServ password",
                    Some(&detail),
                );
            }
            (
                format!("PRIVMSG NickServ :REGISTER {password} {}", email.as_str()),
                "register",
            )
        }
        NetworkAccountCommand::Verify { code } => {
            if let Err(detail) = validate_single_service_token(&code, 200, "verification code") {
                return problem(
                    StatusCode::BAD_REQUEST,
                    "Invalid verification code",
                    Some(&detail),
                );
            }
            // NickServ verifies the account named after the nick this session
            // holds now, which a `/nick` since connecting made different from
            // the configured one.
            let Some(session) = handle.irc_session_snapshot() else {
                return problem(
                    StatusCode::CONFLICT,
                    "IRC network is not connected",
                    Some("wait for the network to reach connected state and try again"),
                );
            };
            (
                format!("PRIVMSG NickServ :VERIFY REGISTER {} {code}", session.nick),
                "verify",
            )
        }
    };
    if let Err(error) = audit_network_command(&state, &account, &network.name, kind).await {
        eprintln!("http: network account command audit failed: {error}");
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Database unavailable",
            Some("nothing was sent: the command could not be recorded"),
        );
    }
    match handle.send(&command) {
        crate::bouncer::SendOutcome::Sent => (
            StatusCode::ACCEPTED,
            axum::Json(NetworkAccountCommandResponse {
                queued: true,
                command: kind,
                transcript: format!("/console/networks/{}", network.name),
            }),
        )
            .into_response(),
        crate::bouncer::SendOutcome::Full => retry_later(
            "Upstream command queue is full",
            "nothing was sent; retry after the interval in the Retry-After header",
            retry_after_seconds(crate::bouncer::UPSTREAM_WRITE_DEADLINE),
        ),
        crate::bouncer::SendOutcome::Closed
        | crate::bouncer::SendOutcome::Unavailable
        | crate::bouncer::SendOutcome::Disconnected => problem(
            StatusCode::CONFLICT,
            "IRC network is not connected",
            Some("nothing was sent; repair or enable the network before registering an account"),
        ),
        crate::bouncer::SendOutcome::Rejected(error) => problem(
            StatusCode::BAD_REQUEST,
            "NickServ command rejected",
            Some(error.message()),
        ),
    }
}

fn validate_single_service_token(value: &str, maximum: usize, field: &str) -> Result<(), String> {
    crate::bouncer::validate_network_credential(value, maximum)?;
    if value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(format!("{field} must be one token without whitespace"));
    }
    Ok(())
}

/// A network name is a client-facing `/network` selector that is interpolated
/// into URL path segments, HTML attributes and JavaScript-string confirm dialogs.
/// Restricting it to an unambiguous token charset (letters, digits, `-`, `_`,
/// `.`) makes URL-significant, quote/angle (XSS), whitespace and control
/// characters unrepresentable in a name rather than relying on correct escaping
/// at every render site (DESIGN §2). `.`/`..` are excluded so a name can never
/// resolve to a path-traversal segment.
pub(super) fn network_name_ok(name: &str) -> bool {
    crate::sanitize::valid_network_name(name)
}

/// Longest upstream address (`host:port`, or a bridge's API base) a network
/// may state, in bytes. The OpenAPI network-field schema reads it.
pub(super) const MAX_UPSTREAM_ADDR_LEN: usize = 255;

/// Longest SASL password — or bridge password or token — a network may state,
/// in bytes. The OpenAPI network-field schema reads it.
pub(super) const MAX_UPSTREAM_PASSWORD_LEN: usize = 512;

/// Longest account field a network may state, in bytes: an IRC SASL login
/// ([`crate::bouncer::UpstreamSaslAccount`]) or a Slack bot token. The OpenAPI
/// network-field schema reads it.
pub(super) const MAX_UPSTREAM_ACCOUNT_LEN: usize = crate::bouncer::UpstreamSaslAccount::MAX_BYTES;

/// Bounds/injection/SSRF checks on the connection/identity fields, shared by
/// create (all kinds) and edit. Length-bounds `addr`/`nick`/`realname`/
/// `autojoin`, rejects CR/LF/NUL in them (a line-injection primitive into the
/// upstream NICK/USER/JOIN), and refuses an obviously-internal `addr` (SSRF).
/// Does *not* check presence — a bridge kind legitimately has no addr/nick.
pub(super) fn check_upstream_bounds(
    addr: &str,
    nick: &str,
    realname: Option<&str>,
    autojoin: &[crate::bouncer::AutojoinEntry],
    internal_upstreams: crate::egress::InternalUpstreams,
) -> Result<(), NetworkMutationError> {
    use crate::bouncer::{AutojoinEntry, UpstreamChannel, UpstreamNick, UpstreamRealname};
    let overlong = if addr.len() > MAX_UPSTREAM_ADDR_LEN {
        Some((
            "addr",
            format!("addr is limited to {MAX_UPSTREAM_ADDR_LEN} bytes"),
        ))
    } else if nick.len() > UpstreamNick::MAX_BYTES {
        Some((
            "nick",
            format!("nick is limited to {} bytes", UpstreamNick::MAX_BYTES),
        ))
    } else if realname.is_some_and(|r| r.len() > UpstreamRealname::MAX_BYTES) {
        Some((
            "realname",
            format!(
                "realname is limited to {} bytes",
                UpstreamRealname::MAX_BYTES
            ),
        ))
    } else if autojoin.len() > AutojoinEntry::MAX_CONFIGURED
        || autojoin
            .iter()
            .any(|entry| entry.channel.len() > UpstreamChannel::MAX_BYTES)
    {
        Some((
            "autojoin",
            format!(
                "autojoin is limited to {} channels of {} bytes",
                AutojoinEntry::MAX_CONFIGURED,
                UpstreamChannel::MAX_BYTES
            ),
        ))
    } else {
        None
    };
    if let Some((field, detail)) = overlong {
        return Err(
            network_error(StatusCode::BAD_REQUEST, "Field too long", Some(&detail))
                .with_field(field),
        );
    }
    let has_control = |s: &str| s.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0);
    let controlled = if has_control(addr) {
        Some("addr")
    } else if has_control(nick) {
        Some("nick")
    } else if realname.is_some_and(has_control) {
        Some("realname")
    } else if autojoin
        .iter()
        .any(|entry| has_control(&entry.channel) || entry.key.as_deref().is_some_and(has_control))
    {
        Some("autojoin")
    } else {
        None
    };
    if let Some(field) = controlled {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Invalid character",
            Some("connection fields must not contain CR, LF or NUL"),
        )
        .with_field(field));
    }
    // Judged from the literal here; a hostname is judged, resolved, at dial
    // time (`crate::egress`).
    if let Some(refusal) = internal_upstreams.refusal_for_addr(addr) {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Disallowed upstream address",
            Some(refusal.reason()),
        )
        .with_field("addr"));
    }
    Ok(())
}

/// Refuse, by field, a SASL password or server password an IRC upstream would
/// carry in cleartext ([`crate::egress::InternalUpstreams::cleartext_credential`]).
pub(super) fn refuse_cleartext_credentials(
    addr: &str,
    tls: bool,
    sasl_password: bool,
    server_password: bool,
    internal_upstreams: crate::egress::InternalUpstreams,
) -> Result<(), NetworkMutationError> {
    match internal_upstreams.cleartext_credential(addr, tls, sasl_password, server_password) {
        Some(credential) => Err(network_error(
            StatusCode::BAD_REQUEST,
            "Credentials require TLS",
            Some(credential.reason()),
        )
        .with_field(credential.field())),
        None => Ok(()),
    }
}

/// The identity fields of an IRC upstream, parsed. Holding the parsed values is
/// what lets the preflight build a driver configuration without a second,
/// possibly different, notion of what a valid nickname is.
#[derive(Debug)]
pub(super) struct IrcUpstreamIdentity {
    pub(super) nick: crate::bouncer::UpstreamNick,
    pub(super) username: crate::bouncer::UpstreamUsername,
    pub(super) realname: Option<crate::bouncer::UpstreamRealname>,
    pub(super) autojoin: Vec<crate::bouncer::AutojoinChannel>,
}

fn identity_problem(error: crate::bouncer::UpstreamIdentityError) -> NetworkMutationError {
    network_error(
        StatusCode::BAD_REQUEST,
        "Invalid IRC identity",
        Some(&error.to_string()),
    )
    .with_field(error.field())
}

/// Full validation for an IRC upstream's connection/identity fields (create and
/// edit): `addr`/`nick` required, the shared [`check_upstream_bounds`], and the
/// one identity grammar the driver factory also applies.
pub(super) fn validate_irc_upstream(
    addr: &str,
    nick: &str,
    username: Option<&str>,
    realname: Option<&str>,
    autojoin: &[crate::bouncer::AutojoinEntry],
    internal_upstreams: crate::egress::InternalUpstreams,
) -> Result<IrcUpstreamIdentity, NetworkMutationError> {
    // Required, and never derived from the nick: a legal nickname (`_bot`) is
    // not a legal user name, and an upstream answers a bad one by closing the
    // link. Absent is said before anything else so a client that predates the
    // field learns which one it is missing.
    let Some(username) = username else {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Missing required fields",
            Some("username is required for IRC networks"),
        )
        .with_field("username"));
    };
    if addr.is_empty() || nick.is_empty() {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Missing required fields",
            Some(if addr.is_empty() {
                "addr is required"
            } else {
                "nick is required"
            }),
        )
        .with_field(if addr.is_empty() { "addr" } else { "nick" }));
    }
    if !crate::bouncer::validate_irc_upstream_addr(addr) {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Invalid upstream address",
            Some("addr must be host:port with a nonzero numeric port; bracket IPv6 addresses"),
        )
        .with_field("addr"));
    }
    check_upstream_bounds(addr, nick, realname, autojoin, internal_upstreams)?;
    Ok(IrcUpstreamIdentity {
        nick: nick.parse().map_err(identity_problem)?,
        username: username.parse().map_err(identity_problem)?,
        realname: realname
            .map(str::parse)
            .transpose()
            .map_err(identity_problem)?,
        autojoin: crate::bouncer::AutojoinChannel::parse_list(autojoin)
            .map_err(identity_problem)?,
    })
}

/// Resolve one owner-scoped row for an API mutation. A network the server
/// configuration defines under the same key is the operator's, and every
/// account-level mutation of it is refused here, before anything changes.
async fn editable_network(
    state: &AppState,
    lane: &crate::bouncer::MutationLane,
    account: &str,
    name: &str,
    operation: &str,
) -> Result<crate::db::BncNetworkRow, NetworkMutationError> {
    if lane.holds_configured(Some(account), name) {
        return Err(crate::bouncer::ConfiguredNetworkHeld.into());
    }
    let row = match crate::db::get_bnc_network(pool_of(state), account, name).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return Err(network_error(
                StatusCode::NOT_FOUND,
                "No such network",
                None,
            ));
        }
        Err(error) => {
            eprintln!("http: network {operation} lookup: {error}");
            return Err(network_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            ));
        }
    };
    Ok(row)
}

/// How an edit mutates write-only upstream credentials. Optional fields inside
/// `Set` mean "preserve this one secret", while `Keep` preserves the complete
/// credential set and `Remove` is supported only by IRC (bridges require their
/// credentials to remain constructible).
enum NetworkCredentialUpdate<'a> {
    Keep,
    Remove,
    Set {
        account: Option<&'a str>,
        password: Option<&'a str>,
    },
}

fn seal_network_secret(
    state: &AppState,
    owner: &str,
    value: &str,
) -> Result<String, NetworkMutationError> {
    let key = state.secret_key.as_ref().ok_or_else(|| {
        network_error(
            StatusCode::CONFLICT,
            "No master key configured",
            Some("the server cannot store upstream credentials without [secrets]"),
        )
    })?;
    Ok(key.seal(value, &crate::bouncer::bnc_secret_context(owner)))
}

/// Parse a submitted server password at its field: the one rule for create,
/// replace, and the connection test, so none of them can store or send a value
/// the `PASS` line cannot carry. The refusal names the rule, never the value.
fn parse_server_password(
    password: String,
) -> Result<e6irc_client::ServerPassword, NetworkMutationError> {
    e6irc_client::ServerPassword::parse(password).map_err(|error| {
        network_error(
            StatusCode::BAD_REQUEST,
            "Invalid server password",
            Some(&error.to_string()),
        )
        .with_field("server_password")
    })
}

/// Apply a replace's explicit server-password action. Only an IRC network
/// sends `PASS`, so a bridge can only keep the none it has.
fn apply_server_password(
    state: &AppState,
    owner: &str,
    row: &mut crate::db::BncNetworkRow,
    update: UpdateServerPassword,
) -> Result<(), NetworkMutationError> {
    match (row.kind, update) {
        (_, UpdateServerPassword::Keep {}) => Ok(()),
        (crate::config::NetworkKind::Irc, UpdateServerPassword::Remove {}) => {
            row.server_password_sealed = None;
            Ok(())
        }
        (crate::config::NetworkKind::Irc, UpdateServerPassword::Set { password }) => {
            let password = parse_server_password(password)?;
            row.server_password_sealed = Some(
                seal_network_secret(state, owner, password.as_str())
                    .map_err(|error| error.with_field("server_password"))?,
            );
            Ok(())
        }
        (_, UpdateServerPassword::Remove {} | UpdateServerPassword::Set { .. }) => {
            Err(network_error(
                StatusCode::BAD_REQUEST,
                "Unsupported credential field",
                Some("only an IRC network has a server password; send {\"action\":\"keep\"}"),
            )
            .with_field("server_password"))
        }
    }
}

/// The IRC SASL account a create, edit or connection test states, parsed by
/// the one grammar all three share ([`crate::bouncer::UpstreamSaslAccount`]).
fn parse_sasl_account(
    account: &str,
) -> Result<crate::bouncer::UpstreamSaslAccount, NetworkMutationError> {
    account
        .parse()
        .map_err(|error: crate::bouncer::UpstreamIdentityError| {
            network_error(
                StatusCode::BAD_REQUEST,
                "Invalid upstream credentials",
                Some(&error.to_string()),
            )
            .with_field(error.field())
        })
}

fn validate_credential_field(value: &str, maximum: usize) -> Result<(), NetworkMutationError> {
    crate::bouncer::validate_network_credential(value, maximum).map_err(|error| {
        network_error(
            StatusCode::BAD_REQUEST,
            "Invalid upstream credentials",
            Some(&error),
        )
    })
}

/// Where a network's stored secrets are sent: the IRC server (host, port, and
/// whether the hop is encrypted) or the bridge provider's origin. Two rows
/// with the same destination send a secret to the same party.
#[derive(Debug, PartialEq, Eq)]
enum SecretDestination {
    Irc {
        host: String,
        port: Option<u16>,
        tls: bool,
    },
    /// A bridge's API base; `None` is the provider default an empty base
    /// means.
    Bridge(Option<url::Origin>),
    /// An address that does not parse, compared as written.
    Unparsed(String),
}

impl SecretDestination {
    fn of(row: &crate::db::BncNetworkRow) -> Self {
        if row.kind.is_bridge() {
            if row.addr.is_empty() {
                return Self::Bridge(None);
            }
            return url::Url::parse(&row.addr).map_or_else(
                |_| Self::Unparsed(row.addr.clone()),
                |url| Self::Bridge(Some(url.origin())),
            );
        }
        match url::Url::parse(&format!("irc://{}", row.addr)) {
            Ok(url) if url.host_str().is_some() => Self::Irc {
                host: url.host_str().unwrap_or_default().to_ascii_lowercase(),
                port: url.port(),
                tls: row.tls,
            },
            _ => Self::Unparsed(row.addr.clone()),
        }
    }

    /// Whether a secret sent to `self` may keep going to `next` without its
    /// owner entering it again. Encrypting a hop that was cleartext sends it
    /// to the same party more safely; every other change is a new audience.
    fn admits(&self, next: &Self) -> bool {
        match (self, next) {
            (
                Self::Irc { host, port, tls },
                Self::Irc {
                    host: next_host,
                    port: next_port,
                    tls: next_tls,
                },
            ) => host == next_host && port == next_port && (*next_tls || !*tls),
            _ => self == next,
        }
    }
}

/// A replace's actions on the network's write-only secrets: the SASL (or
/// bridge) credentials, the server password, and the autojoin channels' keys.
struct SecretActions {
    credentials: UpdateNetworkCredentials,
    server_password: UpdateServerPassword,
    /// The autojoin list as the request wrote it, with any new keys inline.
    autojoin: Vec<crate::bouncer::AutojoinEntry>,
    autojoin_keys: UpdateAutojoinKeys,
}

/// Apply a replace's credential actions to `row`, the one place a stored
/// secret can be carried from `before` into an edited network.
///
/// A stored secret is write-only: the API never shows it. Keeping one while
/// pointing the network somewhere else would send it to whoever answers
/// there — the plaintext recovered by anyone who may edit the network. So
/// when the destination changes, every secret must be entered again or
/// removed: one carried over unchanged (by `keep`, or by replacing only the
/// other half of a pair) is refused, naming its field.
fn apply_credential_actions(
    state: &AppState,
    owner: &str,
    before: &crate::db::BncNetworkRow,
    row: &mut crate::db::BncNetworkRow,
    actions: SecretActions,
) -> Result<(), NetworkMutationError> {
    apply_network_credentials(state, owner, row, actions.credentials)?;
    apply_server_password(state, owner, row, actions.server_password)?;
    apply_autojoin_keys(
        state,
        owner,
        before,
        row,
        actions.autojoin,
        actions.autojoin_keys,
    )?;
    if SecretDestination::of(before).admits(&SecretDestination::of(row)) {
        return Ok(());
    }
    let carried =
        |before: &Option<String>, after: &Option<String>| after.is_some() && before == after;
    let account_carried =
        row.kind.account_is_secret() && carried(&before.sasl_account, &row.sasl_account);
    let key_carried = row.autojoin.iter().any(|entry| {
        before
            .autojoin
            .iter()
            .any(|stored| carried(&stored.key_sealed, &entry.key_sealed))
    });
    let field =
        if account_carried || carried(&before.sasl_password_sealed, &row.sasl_password_sealed) {
            "credentials"
        } else if carried(&before.server_password_sealed, &row.server_password_sealed) {
            "server_password"
        } else if key_carried {
            "autojoin"
        } else {
            return Ok(());
        };
    Err(network_error(
        StatusCode::CONFLICT,
        "Credentials must be entered again",
        Some(
            "the network now points somewhere else, and a stored password, token, or channel \
             key is never sent to a new destination; set it again or remove it",
        ),
    )
    .with_field(field))
}

/// The one spelling-insensitive comparison of two autojoin channel names: two
/// names that differ only in ASCII case are the same channel on every network,
/// whatever its case mapping.
fn same_channel(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Set `row.autojoin` from a replace: each entry written with a key stores
/// that key, sealed; each channel named in `keys.keep` carries the key stored
/// for it; every other channel has none. A kept channel must be listed without
/// a new key and have a stored key to keep, so a keep that would do nothing,
/// or a key both kept and replaced, is refused rather than read one way.
fn apply_autojoin_keys(
    state: &AppState,
    owner: &str,
    before: &crate::db::BncNetworkRow,
    row: &mut crate::db::BncNetworkRow,
    autojoin: Vec<crate::bouncer::AutojoinEntry>,
    keys: UpdateAutojoinKeys,
) -> Result<(), NetworkMutationError> {
    let refused = |detail: &str| {
        network_error(
            StatusCode::BAD_REQUEST,
            "Invalid channel key action",
            Some(detail),
        )
        .with_field("autojoin")
    };
    let stored_key = |channel: &str| {
        before
            .autojoin
            .iter()
            .find(|stored| same_channel(&stored.channel, channel))
            .and_then(|stored| stored.key_sealed.clone())
    };
    // Each kept channel is one autojoin entry, so no more can be named than
    // autojoin may hold.
    if keys.keep.len() > crate::bouncer::AutojoinEntry::MAX_CONFIGURED {
        return Err(refused(&format!(
            "autojoin_keys.keep names at most {} channels",
            crate::bouncer::AutojoinEntry::MAX_CONFIGURED
        )));
    }
    for kept in &keys.keep {
        match autojoin
            .iter()
            .find(|entry| same_channel(&entry.channel, kept))
        {
            None => {
                return Err(refused(&format!(
                    "{kept} keeps its key but is not in autojoin"
                )));
            }
            Some(entry) if entry.key.is_some() => {
                return Err(refused(&format!(
                    "{kept} both keeps its stored key and sets a new one"
                )));
            }
            Some(_) => {}
        }
        if stored_key(kept).is_none() {
            return Err(refused(&format!("{kept} has no stored key to keep")));
        }
    }
    row.autojoin = autojoin
        .into_iter()
        .map(|entry| {
            let key_sealed = match &entry.key {
                Some(key) => Some(
                    seal_network_secret(state, owner, key)
                        .map_err(|error| error.with_field("autojoin"))?,
                ),
                None if keys
                    .keep
                    .iter()
                    .any(|kept| same_channel(kept, &entry.channel)) =>
                {
                    stored_key(&entry.channel)
                }
                None => None,
            };
            Ok(crate::db::BncAutojoin {
                channel: entry.channel,
                key_sealed,
            })
        })
        .collect::<Result<_, NetworkMutationError>>()?;
    Ok(())
}

fn apply_network_credentials(
    state: &AppState,
    owner: &str,
    row: &mut crate::db::BncNetworkRow,
    update: UpdateNetworkCredentials,
) -> Result<(), NetworkMutationError> {
    use crate::config::NetworkKind;
    let update = match &update {
        UpdateNetworkCredentials::Keep {} => NetworkCredentialUpdate::Keep,
        UpdateNetworkCredentials::Remove {} => NetworkCredentialUpdate::Remove,
        UpdateNetworkCredentials::Set { account, password } => NetworkCredentialUpdate::Set {
            account: account.as_deref(),
            password: password.as_deref(),
        },
    };
    match (row.kind, update) {
        (_, NetworkCredentialUpdate::Keep) => Ok(()),
        (NetworkKind::Irc, NetworkCredentialUpdate::Remove) => {
            row.sasl_account = None;
            row.sasl_password_sealed = None;
            Ok(())
        }
        (_, NetworkCredentialUpdate::Remove) => Err(network_error(
            StatusCode::BAD_REQUEST,
            "Bridge credentials are required",
            Some("replace bridge credentials or keep the stored values"),
        )),
        (NetworkKind::Irc, NetworkCredentialUpdate::Set { account, password }) => {
            let Some(account) = account else {
                return Err(network_error(
                    StatusCode::BAD_REQUEST,
                    "Incomplete upstream SASL",
                    Some("enter a SASL account or explicitly remove the stored credentials"),
                ));
            };
            row.sasl_account = Some(parse_sasl_account(account)?.into_string());
            if let Some(password) = password {
                validate_credential_field(password, MAX_UPSTREAM_PASSWORD_LEN)?;
                row.sasl_password_sealed = Some(seal_network_secret(state, owner, password)?);
            } else if row.sasl_password_sealed.is_none() {
                return Err(network_error(
                    StatusCode::BAD_REQUEST,
                    "Incomplete upstream SASL",
                    Some("enter a password for this SASL account"),
                ));
            }
            Ok(())
        }
        (
            NetworkKind::Matrix | NetworkKind::Discord,
            NetworkCredentialUpdate::Set { account, password },
        ) => {
            if account.is_some() {
                return Err(network_error(
                    StatusCode::BAD_REQUEST,
                    "Unsupported credential field",
                    Some("Matrix and Discord use only the password/token field"),
                ));
            }
            let Some(password) = password else {
                return Err(network_error(
                    StatusCode::BAD_REQUEST,
                    "Incomplete bridge credentials",
                    Some("provide a replacement password/token or keep the stored value"),
                ));
            };
            validate_credential_field(password, MAX_UPSTREAM_PASSWORD_LEN)?;
            row.sasl_account = None;
            row.sasl_password_sealed = Some(seal_network_secret(state, owner, password)?);
            Ok(())
        }
        (NetworkKind::Slack, NetworkCredentialUpdate::Set { account, password }) => {
            if account.is_none() && password.is_none() {
                return Err(network_error(
                    StatusCode::BAD_REQUEST,
                    "Incomplete bridge credentials",
                    Some("replace at least one Slack token or keep the stored values"),
                ));
            }
            if let Some(account) = account {
                validate_credential_field(account, MAX_UPSTREAM_ACCOUNT_LEN)?;
                row.sasl_account = Some(seal_network_secret(state, owner, account)?);
            } else if row.sasl_account.is_none() {
                return Err(network_error(
                    StatusCode::BAD_REQUEST,
                    "Incomplete bridge credentials",
                    Some("enter the Slack bot token"),
                ));
            }
            if let Some(password) = password {
                validate_credential_field(password, MAX_UPSTREAM_PASSWORD_LEN)?;
                row.sasl_password_sealed = Some(seal_network_secret(state, owner, password)?);
            } else if row.sasl_password_sealed.is_none() {
                return Err(network_error(
                    StatusCode::BAD_REQUEST,
                    "Incomplete bridge credentials",
                    Some("enter the Slack app token"),
                ));
            }
            Ok(())
        }
        (NetworkKind::Local, _) => Err(network_error(
            StatusCode::BAD_REQUEST,
            "Unsupported network kind",
            Some("local networks are configured at the server level"),
        )),
    }
}

/// The connection fields of a bridge network as a request states them, named:
/// seven positional strings and flags were one transposition from a real name
/// checked as a user name.
struct BridgeUpstreamFields<'a> {
    addr: &'a str,
    tls: bool,
    nick: &'a str,
    username: Option<&'a str>,
    realname: Option<&'a str>,
    autojoin: &'a [crate::bouncer::AutojoinEntry],
}

fn validate_bridge_upstream(
    kind: crate::config::NetworkKind,
    fields: BridgeUpstreamFields<'_>,
    internal_upstreams: crate::egress::InternalUpstreams,
) -> Result<(), NetworkMutationError> {
    use crate::config::NetworkKind;
    let BridgeUpstreamFields {
        addr,
        tls,
        nick,
        username,
        realname,
        autojoin,
    } = fields;
    check_upstream_bounds(addr, nick, realname, autojoin, internal_upstreams)?;
    if username.is_some() {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Unsupported bridge field",
            Some("username applies only to IRC networks"),
        )
        .with_field("username"));
    }
    if autojoin.iter().any(|entry| entry.key.is_some()) {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Unsupported bridge field",
            Some("channel keys apply only to IRC networks; list each room or channel id alone"),
        )
        .with_field("autojoin"));
    }
    if !tls {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Invalid bridge transport",
            Some(
                "bridge transports require tls=true; their endpoint scheme controls HTTP security",
            ),
        ));
    }
    if realname.is_some() {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Unsupported bridge field",
            Some("realname applies only to IRC networks"),
        ));
    }
    crate::bouncer::validate_bridge_base(kind, addr).map_err(|error| {
        network_error(
            StatusCode::BAD_REQUEST,
            "Invalid bridge endpoint",
            Some(&error),
        )
    })?;
    match kind {
        NetworkKind::Matrix if addr.is_empty() || nick.is_empty() => Err(network_error(
            StatusCode::BAD_REQUEST,
            "Missing Matrix fields",
            Some("Matrix requires a homeserver URL and provider user"),
        )),
        NetworkKind::Discord | NetworkKind::Slack if !nick.is_empty() => Err(network_error(
            StatusCode::BAD_REQUEST,
            "Unsupported bridge field",
            Some("nick applies only to IRC and Matrix networks"),
        )),
        NetworkKind::Matrix | NetworkKind::Discord | NetworkKind::Slack => Ok(()),
        _ => Err(network_error(StatusCode::BAD_REQUEST, "Not a bridge", None)),
    }
}

/// Construct and validate a prospective driver before durable state changes.
/// Disabled IRC networks may be repaired without opening an unreadable old
/// secret; bridge edits always validate their required credentials and typed
/// endpoint, even while paused.
fn prospective_network_driver(
    state: &AppState,
    account: &str,
    row: &crate::db::BncNetworkRow,
    should_run: bool,
    validate_while_stopped: bool,
) -> Result<Option<Box<dyn crate::bouncer::NetworkDriver>>, NetworkMutationError> {
    if !should_run && !validate_while_stopped {
        return Ok(None);
    }
    let driver = stored_network_driver(state, account, row)?;
    Ok(should_run.then_some(driver))
}

/// The driver a stored row describes, or the conflict that keeps it from
/// starting (a missing master key, a bridge feature this binary lacks).
fn stored_network_driver(
    state: &AppState,
    account: &str,
    row: &crate::db::BncNetworkRow,
) -> Result<Box<dyn crate::bouncer::NetworkDriver>, NetworkMutationError> {
    crate::bouncer::driver_from_row(
        row,
        state.secret_key.as_deref(),
        account,
        state.internal_upstreams,
        crate::bouncer::FirstDial::Immediate,
    )
    .map_err(|error| network_error(StatusCode::CONFLICT, "Cannot start network", Some(&error)))
}

/// The registry mutation lane, entered for an owner whose drivers may run.
///
/// Suspension keeps `bnc_networks.enabled` set so that reactivation can restore
/// the owner's networks, which makes that flag alone the wrong question for
/// "may this driver start?". Suspension stops the owner's drivers while holding
/// this same lane, so an owner found active on entry stays active until the
/// lane is released — and because the lane is the only way this module starts
/// a driver, a start for a suspended owner has no path: not an administrator
/// toggling the network, not a create or edit authorized a moment before the
/// suspension committed.
struct ActiveOwnerLane<'a> {
    lane: &'a crate::bouncer::MutationLane,
    owner: &'a str,
}

impl<'a> ActiveOwnerLane<'a> {
    async fn enter(
        state: &AppState,
        lane: &'a crate::bouncer::MutationLane,
        owner: &'a str,
    ) -> Result<Self, NetworkMutationError> {
        match crate::db::account_flags(pool_of(state), owner).await {
            Ok(Some(flags)) if flags.is_suspended() => Err(network_error(
                StatusCode::CONFLICT,
                "Owner suspended",
                Some("a suspended account's networks cannot run; reactivate the account first"),
            )),
            Ok(Some(_)) => Ok(Self { lane, owner }),
            Ok(None) => Err(network_error(
                StatusCode::NOT_FOUND,
                "No such network",
                None,
            )),
            Err(error) => {
                eprintln!("http: network owner posture lookup: {error}");
                Err(network_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Database unavailable",
                    None,
                ))
            }
        }
    }

    /// Stop any predecessor, then start `driver` (create and edit).
    async fn supersede(
        &self,
        name: &str,
        driver: Box<dyn crate::bouncer::NetworkDriver>,
    ) -> Result<(), crate::bouncer::RegistryRefusal> {
        self.lane.replace(Some(self.owner), name, driver).await
    }

    /// Start `driver` unless a working one is already registered (enable).
    async fn ensure_running(
        &self,
        name: &str,
        driver: Box<dyn crate::bouncer::NetworkDriver>,
    ) -> Result<(), crate::bouncer::RegistryRefusal> {
        self.lane
            .ensure_running(Some(self.owner), name, driver)
            .await
            .map(|_started| ())
    }
}

/// Update all mutable configuration of one caller-owned network and replace its
/// running driver. The registry mutation lane makes the database write and
/// runtime transition one serialized control-plane operation, which runs to
/// completion even if the request is abandoned.
pub(super) async fn update_network_core(
    state: &Arc<AppState>,
    registry: &Arc<crate::bouncer::Registry>,
    account: &str,
    name: &str,
    req: UpdateNetwork,
) -> Result<(), NetworkMutationError> {
    let (state, account, name) = (state.clone(), account.to_owned(), name.to_owned());
    registry
        .mutate(move |lane| async move {
            update_network_in_lane(&state, &lane, &account, &name, req).await
        })
        .await
}

async fn update_network_in_lane(
    state: &AppState,
    lane: &crate::bouncer::MutationLane,
    account: &str,
    name: &str,
    req: UpdateNetwork,
) -> Result<(), NetworkMutationError> {
    let UpdateNetwork {
        addr,
        tls,
        nick,
        username,
        realname,
        autojoin,
        autojoin_keys,
        credentials,
        server_password,
    } = req;
    let autojoin = submitted_autojoin(&autojoin);
    let (addr, nick, username, realname) = (
        addr.as_str(),
        nick.as_str(),
        username.as_deref(),
        realname.as_deref(),
    );
    let lane = ActiveOwnerLane::enter(state, lane, account).await?;
    let pool = pool_of(state);
    let mut row = editable_network(state, lane.lane, account, name, "update").await?;
    let before = row.clone();
    if row.kind == crate::config::NetworkKind::Irc && realname.is_none() {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Missing required fields",
            Some("realname is required for IRC networks"),
        )
        .with_field("realname"));
    }
    if row.kind == crate::config::NetworkKind::Irc {
        validate_irc_upstream(
            addr,
            nick,
            username,
            realname,
            &autojoin,
            state.internal_upstreams,
        )?;
    } else {
        validate_bridge_upstream(
            row.kind,
            BridgeUpstreamFields {
                addr,
                tls,
                nick,
                username,
                realname,
                autojoin: &autojoin,
            },
            state.internal_upstreams,
        )?;
    }
    row.addr = addr.to_string();
    row.tls = tls;
    row.nick = nick.to_string();
    row.username = username.map(str::to_string);
    row.realname = realname.map(str::to_string);
    apply_credential_actions(
        state,
        account,
        &before,
        &mut row,
        SecretActions {
            credentials,
            server_password,
            autojoin,
            autojoin_keys,
        },
    )?;
    // Judged on the row as it will be stored: a kept credential on a network
    // edited to tls=false is refused like a new one.
    if row.kind == crate::config::NetworkKind::Irc {
        refuse_cleartext_credentials(
            &row.addr,
            row.tls,
            row.sasl_password_sealed.is_some(),
            row.server_password_sealed.is_some(),
            state.internal_upstreams,
        )?;
    }
    let driver =
        prospective_network_driver(state, account, &row, row.enabled, row.kind.is_bridge())?;

    let detail = network_audit_detail(row.kind, "changed", &changed_network_fields(&before, &row));
    require_network_updated(
        crate::db::update_bnc_network(
            pool,
            account,
            name,
            &row,
            crate::db::NetworkAudit {
                actor: account,
                detail: &detail,
            },
        )
        .await,
        "update failed",
    )?;
    if let Some(driver) = driver {
        lane.supersede(name, driver).await?;
    }
    Ok(())
}

/// The network fields whose stored value differs between `before` and
/// `after`, by name. Named here in one place so the audit detail can list what
/// an edit touched without ever copying a value (the address, the nick, and
/// the sealed password are all values an audit reader must not see).
fn changed_network_fields(
    before: &crate::db::BncNetworkRow,
    after: &crate::db::BncNetworkRow,
) -> Vec<&'static str> {
    let mut changed = Vec::new();
    let mut note = |name: &'static str, differs: bool| {
        if differs {
            changed.push(name);
        }
    };
    note("addr", before.addr != after.addr);
    note("tls", before.tls != after.tls);
    note("nick", before.nick != after.nick);
    note("username", before.username != after.username);
    note("realname", before.realname != after.realname);
    let channels = |row: &crate::db::BncNetworkRow| -> Vec<String> {
        row.autojoin
            .iter()
            .map(|entry| entry.channel.clone())
            .collect()
    };
    let keys = |row: &crate::db::BncNetworkRow| -> Vec<Option<String>> {
        row.autojoin
            .iter()
            .map(|entry| entry.key_sealed.clone())
            .collect()
    };
    note("autojoin", channels(before) != channels(after));
    note("autojoin_keys", keys(before) != keys(after));
    note("sasl_account", before.sasl_account != after.sasl_account);
    note(
        "sasl_password",
        before.sasl_password_sealed != after.sasl_password_sealed,
    );
    note(
        "server_password",
        before.server_password_sealed != after.server_password_sealed,
    );
    note("enabled", before.enabled != after.enabled);
    changed
}

/// The fields a new network row carries a value for, by name.
fn present_network_fields(row: &crate::db::BncNetworkRow) -> Vec<&'static str> {
    let mut present = vec!["addr", "tls", "nick"];
    if row.username.is_some() {
        present.push("username");
    }
    if row.realname.is_some() {
        present.push("realname");
    }
    if !row.autojoin.is_empty() {
        present.push("autojoin");
    }
    if row.autojoin.iter().any(|entry| entry.key_sealed.is_some()) {
        present.push("autojoin_keys");
    }
    if row.sasl_account.is_some() {
        present.push("sasl_account");
    }
    if row.sasl_password_sealed.is_some() {
        present.push("sasl_password");
    }
    if row.server_password_sealed.is_some() {
        present.push("server_password");
    }
    present
}

/// `NETWORK_CREATE`/`NETWORK_UPDATE` detail: the kind and the field names.
fn network_audit_detail(
    kind: crate::config::NetworkKind,
    relation: &str,
    fields: &[&'static str],
) -> String {
    format!(
        "{}; {relation}: {}",
        kind.as_db_str(),
        if fields.is_empty() {
            "nothing".to_string()
        } else {
            fields.join(", ")
        }
    )
}

#[cfg(test)]
mod secret_destination_tests {
    use super::SecretDestination;
    use crate::config::NetworkKind;

    fn destination(kind: NetworkKind, addr: &str, tls: bool) -> SecretDestination {
        SecretDestination::of(&crate::db::BncNetworkRow {
            kind,
            name: "work".into(),
            addr: addr.into(),
            tls,
            nick: String::new(),
            username: None,
            realname: None,
            autojoin: Vec::new(),
            sasl_account: None,
            sasl_password_sealed: None,
            server_password_sealed: None,
            enabled: true,
        })
    }

    #[test]
    fn a_secret_follows_only_the_same_server_or_origin() {
        let irc = |addr, tls| destination(NetworkKind::Irc, addr, tls);
        let here = irc("irc.example:6697", true);
        assert!(here.admits(&irc("IRC.Example:6697", true)), "host case");
        assert!(
            !here.admits(&irc("irc.attacker.example:6697", true)),
            "host"
        );
        assert!(!here.admits(&irc("irc.example:7000", true)), "port");
        assert!(!here.admits(&irc("irc.example:6697", false)), "TLS off");
        assert!(
            irc("irc.example:6697", false).admits(&irc("irc.example:6697", true)),
            "encrypting the same hop is not a new audience"
        );
        assert!(!here.admits(&irc("[2001:db8::1]:6697", true)));

        for kind in [
            NetworkKind::Matrix,
            NetworkKind::Discord,
            NetworkKind::Slack,
        ] {
            let bridge = |addr| destination(kind, addr, true);
            let here = bridge("https://api.example");
            assert!(
                here.admits(&bridge("https://api.example/v10/")),
                "same origin"
            );
            assert!(
                !here.admits(&bridge("https://api.attacker.example")),
                "{kind:?}"
            );
            assert!(
                !here.admits(&bridge("https://api.example:8443")),
                "{kind:?}"
            );
            assert!(!here.admits(&bridge("http://api.example")), "{kind:?}");
            assert!(
                !here.admits(&bridge("")),
                "provider default is another origin"
            );
            assert!(!bridge("").admits(&here), "{kind:?}");
        }
    }
}

#[cfg(test)]
mod audit_detail_tests {
    use super::{changed_network_fields, network_audit_detail, present_network_fields};

    fn row() -> crate::db::BncNetworkRow {
        crate::db::BncNetworkRow {
            kind: crate::config::NetworkKind::Irc,
            name: "work".into(),
            addr: "irc.example:6697".into(),
            tls: true,
            nick: "alice".into(),
            username: Some("alice".into()),
            realname: Some("Alice".into()),
            autojoin: vec!["#work".into()],
            sasl_account: None,
            sasl_password_sealed: None,
            server_password_sealed: None,
            enabled: true,
        }
    }

    #[test]
    fn an_edit_of_addr_is_audited_by_name_only() {
        let before = row();
        let mut after = row();
        after.addr = "irc.elsewhere.example:6697".into();
        let changed = changed_network_fields(&before, &after);
        assert_eq!(changed, ["addr"]);
        let detail = network_audit_detail(after.kind, "changed", &changed);
        assert_eq!(detail, "irc; changed: addr");
        assert!(!detail.contains("elsewhere"), "{detail}");
        assert_eq!(
            network_audit_detail(
                after.kind,
                "changed",
                &changed_network_fields(&before, &before)
            ),
            "irc; changed: nothing"
        );
    }

    #[test]
    fn a_created_row_lists_the_fields_it_carries() {
        let mut created = row();
        created.sasl_account = Some("alice".into());
        created.sasl_password_sealed = Some("sealed".into());
        created.server_password_sealed = Some("sealed".into());
        assert_eq!(
            network_audit_detail(created.kind, "fields", &present_network_fields(&created)),
            "irc; fields: addr, tls, nick, username, realname, autojoin, sasl_account, \
             sasl_password, server_password"
        );
        let mut replaced = created.clone();
        replaced.server_password_sealed = Some("resealed".into());
        assert_eq!(
            changed_network_fields(&created, &replaced),
            ["server_password"]
        );
    }
}

/// Create a network: validated, stored and started as one unit on the registry
/// mutation lane, which runs to completion even if the request is abandoned.
async fn create_network_core(
    state: &Arc<AppState>,
    registry: &Arc<crate::bouncer::Registry>,
    account: &str,
    req: &NetworkCreation,
) -> Result<(), NetworkMutationError> {
    let (state, account, req) = (state.clone(), account.to_owned(), req.clone());
    registry
        .mutate(
            move |lane| async move { create_network_in_lane(&state, &lane, &account, &req).await },
        )
        .await
}

async fn create_network_in_lane(
    state: &AppState,
    lane: &crate::bouncer::MutationLane,
    account: &str,
    req: &NetworkCreation,
) -> Result<(), NetworkMutationError> {
    // The name is the client-facing /network selector; see network_name_ok.
    if !network_name_ok(&req.name) {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Invalid network name",
            Some(
                "name must be non-empty, not '.'/'..', and use only letters, digits, '-', '_' or '.'",
            ),
        )
        .with_field("name"));
    }
    refuse_configured_network_name(state, lane, account, &req.name).await?;
    use crate::config::NetworkKind;
    let kind = req.kind;
    // A bridge kind can only run on a binary built with its feature, and `local`
    // is not creatable as a bouncer network — reject up front (before any insert)
    // rather than persist a row whose driver could never start.
    if !kind_feature_available(kind) {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Unsupported network kind",
            Some(match kind {
                NetworkKind::Local => "kind=local is not a creatable bouncer network",
                _ => "this server was not built with that bridge's feature",
            }),
        ));
    }
    // Bound + injection-check + SSRF-check the connection/identity fields (the
    // subset shared with the edit path). `addr`/`nick`/`realname`/`autojoin` are
    // interpolated into NICK/USER/JOIN lines, so a CR/LF/NUL there is a
    // line-injection primitive; `addr` is SSRF-vetted; all are length-bounded.
    if kind == NetworkKind::Irc {
        validate_irc_upstream(
            &req.addr,
            &req.nick,
            req.username.as_deref(),
            Some(&req.realname),
            &req.autojoin,
            state.internal_upstreams,
        )?;
        refuse_cleartext_credentials(
            &req.addr,
            req.tls,
            req.sasl_password.is_some(),
            req.server_password.is_some(),
            state.internal_upstreams,
        )?;
    } else {
        validate_bridge_upstream(
            kind,
            BridgeUpstreamFields {
                addr: &req.addr,
                tls: req.tls,
                nick: &req.nick,
                username: req.username.as_deref(),
                realname: None,
                autojoin: &req.autojoin,
            },
            state.internal_upstreams,
        )?;
    }
    // Fields that are create-only (the name) or SASL-specific (bounds + the NUL
    // check that matters because PLAIN uses NUL as its field separator, and the
    // sealed-secret size cap) are checked here rather than in the shared helper.
    // An IRC account is a login name, parsed as the edit and the connection
    // test parse it; Slack's account field is its bot token, a secret checked
    // only for what could not travel.
    if let Some(account) = req.sasl_account.as_deref() {
        if kind == NetworkKind::Irc {
            parse_sasl_account(account)?;
        } else {
            validate_credential_field(account, MAX_UPSTREAM_ACCOUNT_LEN)
                .map_err(|e| e.with_field("sasl_account"))?;
        }
    }
    if let Some(password) = req.sasl_password.as_deref() {
        validate_credential_field(password, MAX_UPSTREAM_PASSWORD_LEN)
            .map_err(|e| e.with_field("sasl_password"))?;
    }
    // For IRC the SASL pair is both-or-neither (account = login name, password =
    // secret). Bridges don't follow that rule — their required fields are checked
    // above — so this only applies to IRC.
    if kind == NetworkKind::Irc && req.sasl_account.is_some() != req.sasl_password.is_some() {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Incomplete upstream SASL",
            Some("provide both sasl_account and sasl_password, or neither"),
        )
        .with_field("sasl_password"));
    }
    let server_password = req
        .server_password
        .clone()
        .map(parse_server_password)
        .transpose()?;
    if matches!(kind, NetworkKind::Matrix | NetworkKind::Discord) && req.sasl_account.is_some() {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Unsupported credential field",
            Some("Matrix and Discord use only sasl_password for their password/token"),
        ));
    }
    // Seal secrets for storage, per kind. The password is always a secret and is
    // sealed. The account field is a secret *only* for Slack (its bot token), so
    // it is sealed there too; an IRC `sasl_account` is a public login name and is
    // stored in the clear (and read back verbatim). Sealing binds to the owning
    // account so a blob can never be opened for a different account's row.
    let need_key = req.sasl_password.is_some()
        || server_password.is_some()
        || req.autojoin.iter().any(|entry| entry.key.is_some())
        || (kind.account_is_secret() && req.sasl_account.is_some());
    let key = match (&state.secret_key, need_key) {
        (Some(k), _) => Some(k),
        (None, false) => None,
        (None, true) => {
            return Err(network_error(
                StatusCode::CONFLICT,
                "No master key configured",
                Some("the server cannot store upstream credentials without [secrets]"),
            ));
        }
    };
    let context = crate::bouncer::bnc_secret_context(account);
    let sealed_password = req.sasl_password.as_ref().map(|p| {
        key.expect("key present when a password is")
            .seal(p, &context)
    });
    let stored_account = match &req.sasl_account {
        Some(a) if kind.account_is_secret() => Some(
            key.expect("key present when the account is secret")
                .seal(a, &context),
        ),
        other => other.clone(),
    };
    let sealed_server_password = server_password.as_ref().map(|password| {
        key.expect("key present when a server password is")
            .seal(password.as_str(), &context)
    });
    let stored_autojoin = req
        .autojoin
        .iter()
        .map(|entry| crate::db::BncAutojoin {
            channel: entry.channel.clone(),
            key_sealed: entry.key.as_ref().map(|channel_key| {
                key.expect("key present when a channel key is")
                    .seal(channel_key, &context)
            }),
        })
        .collect();

    // Build before inserting. A factory rejection must not create durable state
    // that then depends on a best-effort compensating delete.
    let driver = crate::bouncer::build_driver(crate::bouncer::DriverSpec {
        kind,
        owner: Some(account.to_string()),
        name: req.name.clone(),
        addr: req.addr.clone(),
        tls: req.tls,
        nick: req.nick.clone(),
        username: req.username.clone(),
        realname: req.realname.clone(),
        autojoin: req.autojoin.clone(),
        buffer_cap: 1000,
        sasl_account: req.sasl_account.clone(),
        sasl_password: req.sasl_password.clone(),
        server_password: server_password.map(|password| password.as_str().to_owned()),
        internal_upstreams: state.internal_upstreams,
        first_dial: crate::bouncer::FirstDial::Immediate,
    })
    .map_err(|error| network_error(StatusCode::CONFLICT, "Cannot start network", Some(&error)))?;

    let row = crate::db::BncNetworkRow {
        kind,
        name: req.name.clone(),
        addr: req.addr.clone(),
        tls: req.tls,
        nick: req.nick.clone(),
        username: req.username.clone(),
        realname: (kind == NetworkKind::Irc).then(|| req.realname.clone()),
        autojoin: stored_autojoin,
        sasl_account: stored_account,
        sasl_password_sealed: sealed_password,
        server_password_sealed: sealed_server_password,
        enabled: true,
    };
    let pool = state.pool().expect("caller checked the pool");
    // The per-account network cap is enforced atomically inside
    // `create_bnc_network` (count + insert in one locked transaction), so
    // there is no racy list-then-insert here — two concurrent creates can't both
    // slip past cap-1 and each spawn an always-on driver.
    let lane = ActiveOwnerLane::enter(state, lane, account).await?;
    let detail = network_audit_detail(kind, "fields", &present_network_fields(&row));
    match crate::db::create_bnc_network(
        pool,
        account,
        &row,
        crate::db::NetworkAudit {
            actor: account,
            detail: &detail,
        },
    )
    .await
    {
        Ok(_) => {}
        Err(crate::db::DbError::TooManyNetworks) => {
            return Err(network_error(
                StatusCode::CONFLICT,
                "Network limit reached",
                Some("this account has reached its maximum number of networks"),
            ));
        }
        Err(crate::db::DbError::DuplicateNetwork(_)) => {
            return Err(network_error(
                StatusCode::CONFLICT,
                "Network already exists",
                None,
            ));
        }
        Err(e) => {
            eprintln!("http: network create failed: {e}");
            return Err(network_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            ));
        }
    }
    // The row was just inserted under the uniqueness constraint, and a
    // configured network under this key was refused above on the same lane, so
    // anything still registered here has no durable definition: supersede it.
    lane.supersede(&req.name, driver).await?;
    Ok(())
}

/// Whether a network of `kind` can actually run on this binary: `irc` always,
/// each bridge only if built with its feature, `local` never (it is an
/// in-process network, not a creatable bouncer network).
pub(super) fn kind_feature_available(kind: crate::config::NetworkKind) -> bool {
    use crate::config::NetworkKind;
    match kind {
        NetworkKind::Irc => true,
        NetworkKind::Local => false,
        NetworkKind::Matrix => cfg!(feature = "matrix"),
        NetworkKind::Discord => cfg!(feature = "discord"),
        NetworkKind::Slack => cfg!(feature = "slack"),
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BufferQuery {
    pub(super) limit: Option<usize>,
    /// A live-socket replay cursor: only the lines at or before it. A reader
    /// that already holds every line after it asks this way, so no line
    /// reaches it twice and nothing has to be matched up by content.
    pub(super) through: Option<String>,
}

/// A `through` cursor this read cannot bound: it belongs to another ring
/// lifetime (the network restarted), or the network is stopped and the lines
/// are persisted history, which has no ring positions. Answering with lines
/// anyway would hand the reader copies of what it already holds.
fn unhonoured_buffer_cursor() -> Response {
    problem_at_field(
        StatusCode::CONFLICT,
        "Buffer cursor not honoured",
        Some(
            "The cursor does not name a position of this network's live buffer; read without `through`.",
        ),
        Some("through"),
    )
}

/// Recent bouncer lines for one caller-owned network, oldest-first — the same
/// Lines `GET /me/networks/{name}/buffer` returns when the request names no
/// `limit`; the OpenAPI document advertises the same value.
pub(super) const DEFAULT_BUFFER_READ_LIMIT: usize = 200;

/// stream attach playback replays. A running driver provides its live bounded
/// buffer; a stopped driver falls back to persisted history.
pub(super) async fn network_buffer(
    State(state): State<Arc<AppState>>,
    Authenticated(account, _): Authenticated,
    PathParams(name): PathParams<String>,
    QueryParams(params): QueryParams<BufferQuery>,
) -> Response {
    let pool = pool_of(&state);
    let handle = match owned_network_handle(&state, &account, &name).await {
        Ok(handle) => handle,
        Err(response) => return response.into(),
    };
    let limit = match bounded_query_limit(params.limit, DEFAULT_BUFFER_READ_LIMIT, 1000, "buffer") {
        Ok(limit) => limit,
        Err(response) => return response.into(),
    };
    let through = match params
        .through
        .as_deref()
        .map(crate::bouncer::ReplayCursor::parse)
    {
        None => None,
        Some(Some(cursor)) => Some(cursor),
        Some(None) => {
            return problem_at_field(
                StatusCode::BAD_REQUEST,
                "Invalid buffer cursor",
                Some("`through` must be a cursor the live chat socket handed out."),
                Some("through"),
            );
        }
    };
    if let Some(handle) = handle {
        let lines = match through {
            None => handle.buffer_snapshot(),
            Some(cursor) => match handle.buffer_through(cursor) {
                Some(lines) => lines,
                None => return unhonoured_buffer_cursor(),
            },
        };
        let skip = lines.len().saturating_sub(limit as usize);
        return json_no_store(NetworkBufferLinesResponse {
            lines: lines[skip..].to_vec(),
        });
    }
    // Persisted history holds no ring positions, so a cursor cannot bound it.
    if through.is_some() {
        return unhonoured_buffer_cursor();
    }
    // The DB buffer API canonicalizes the owner/network composite key, matching
    // the live registry even when this URL uses a different case.
    match crate::db::recent_bnc_lines(pool, &account, &name, limit).await {
        Ok(lines) => json_no_store(NetworkBufferLinesResponse { lines }),
        Err(e) => {
            eprintln!("http: network buffer read failed: {e}");
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            )
        }
    }
}

/// The caller's own network `name`, and its running driver when it runs: its
/// stored row, or a network the server configuration defines for it — no
/// cross-account reads. The running driver is that network's own, never the
/// other kind's under the same name.
async fn owned_network_handle(
    state: &AppState,
    account: &str,
    name: &str,
) -> ResponseResult<Option<Arc<crate::bouncer::NetworkHandle>>> {
    let registry = registry_of(state);
    match crate::db::get_bnc_network(pool_of(state), account, name).await {
        Ok(Some(_)) => Ok(registry.get_stored(account, name)),
        Ok(None) => match registry.get_configured_owned(account, name) {
            Some((_, handle)) => Ok(Some(handle)),
            None => Err(problem(StatusCode::NOT_FOUND, "No such network", None).into()),
        },
        Err(e) => {
            eprintln!("http: network lookup failed: {e}");
            Err(problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            )
            .into())
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConversationHistoryQuery {
    pub(super) target: String,
    pub(super) limit: Option<usize>,
    /// The page to read: older than a `/ws/ui` replay cursor (the reader holds
    /// every line after it), or than a previous page's `before`.
    pub(super) before: Option<String>,
    /// Older than this exact stored line, which the reader holds — when no
    /// cursor can say where its transcript begins (the network restarted or
    /// stopped since it was read). `held` says how many byte-identical copies
    /// of it the reader holds.
    pub(super) seam: Option<String>,
    pub(super) held: Option<i64>,
}

/// Lines `GET /me/networks/{name}/history` returns when the request names no
/// `limit`; the OpenAPI document advertises the same value.
pub(super) const DEFAULT_HISTORY_READ_LIMIT: usize = 100;
/// The most it returns at once.
pub(super) const MAX_HISTORY_READ_LIMIT: usize = 500;

/// A page cursor naming a stored row: the next page is older than it.
const STORED_PAGE_PREFIX: &str = "row:";

#[derive(serde::Serialize)]
struct ConversationHistoryResponse {
    /// Oldest first.
    lines: Vec<String>,
    /// Where the next older page begins, or `null` when nothing older is held.
    before: Option<String>,
}

/// The `before` or `seam` a page cannot be joined to exactly.
fn unjoinable_history(detail: &'static str, field: &'static str) -> Response {
    problem_at_field(
        StatusCode::CONFLICT,
        "History cannot be joined here",
        Some(detail),
        Some(field),
    )
}

/// One conversation's history, older than what the reader holds, a page at a
/// time: the running network's ring first, then the persisted backlog, so it
/// reaches past the ring and works while the network is stopped.
///
/// Nothing is matched by content. The ring part is the conversation's ring
/// lines at or before the reader's cursor, a ring position that survives a
/// restart which stored every line (migration 0102). Storage is joined at the
/// stored row of the conversation's oldest ring line: the row stored at that
/// line's ring position, or — for a line a new epoch restored at another
/// position — the row with its exact millisecond-stamped text past as many
/// identical copies as the ring holds. That is sound only when the reader
/// holds every ring line after its cursor (409 otherwise). Storage then pages
/// by row id, since positions repeat across epochs and ids do not.
pub(super) async fn network_history(
    State(state): State<Arc<AppState>>,
    Authenticated(account, _): Authenticated,
    PathParams(name): PathParams<String>,
    QueryParams(params): QueryParams<ConversationHistoryQuery>,
) -> Response {
    let handle = match owned_network_handle(&state, &account, &name).await {
        Ok(handle) => handle,
        Err(response) => return response.into(),
    };
    // A ring is paged once its stored backlog is restored into it, as an
    // attach replays it: before, a just-started network's ring is not yet
    // the one a reader's cursor names (a clean restart continues its epoch
    // only then), and the cursor was refused as unjoinable. One stopped
    // meanwhile is paged from storage alone.
    let handle = match handle {
        Some(handle) if handle.wait_for_history().await => Some(handle),
        _ => None,
    };
    if params.target.is_empty() {
        return problem_at_field(
            StatusCode::BAD_REQUEST,
            "Invalid history request",
            Some("`target` must name a conversation."),
            Some("target"),
        );
    }
    let limit = match bounded_query_limit(
        params.limit,
        DEFAULT_HISTORY_READ_LIMIT,
        MAX_HISTORY_READ_LIMIT,
        "history",
    ) {
        Ok(limit) => limit,
        Err(response) => return response.into(),
    };
    let pool = pool_of(&state);
    // How the network names things: the running driver's rules, else the case
    // mapping its stored conversations were keyed under.
    let names = match &handle {
        Some(handle) => handle.names(),
        None => {
            let mut names = e6irc_client::NetworkNames::default();
            match crate::db::bnc_buffer_casemapping(pool, &account, &name).await {
                Ok(Some(casemapping)) => {
                    names.adopt_tokens([
                        format!("CASEMAPPING={}", casemapping.isupport_token()).as_str()
                    ]);
                }
                Ok(None) => {}
                Err(e) => return history_unavailable(e),
            }
            names
        }
    };
    let target = names.fold(&params.target);
    // Rows stored before row `before` (all, without one).
    let read = |before: Option<i64>, limit: i64| {
        let (account, name, target) = (account.clone(), name.clone(), target.clone());
        async move {
            crate::db::bnc_conversation_history(pool, &account, &name, &target, before, limit).await
        }
    };
    // The stored row of `line`, the copy `which` names.
    let locate = |line: String, which: crate::db::StoredCopy| {
        let (account, name, target) = (account.clone(), name.clone(), target.clone());
        async move {
            crate::db::bnc_conversation_line(pool, &account, &name, &target, &line, which).await
        }
    };
    let stored_page = |rows: Vec<crate::db::ConversationHistoryRow>, asked: i64| {
        let before = (rows.len() as i64 == asked)
            .then(|| {
                rows.first()
                    .map(|row| format!("{STORED_PAGE_PREFIX}{}", row.id))
            })
            .flatten();
        (
            rows.into_iter().map(|row| row.line).collect::<Vec<_>>(),
            before,
        )
    };
    match (params.before.as_deref(), params.seam, params.held) {
        (Some(before), None, None) => {
            if let Some(id) = before.strip_prefix(STORED_PAGE_PREFIX) {
                let Ok(id) = id.parse::<i64>() else {
                    return problem_at_field(
                        StatusCode::BAD_REQUEST,
                        "Invalid history cursor",
                        Some(
                            "`before` must be a cursor this API or the live chat socket handed out.",
                        ),
                        Some("before"),
                    );
                };
                return match read(Some(id), limit).await {
                    Ok(rows) => {
                        let (lines, before) = stored_page(rows, limit);
                        json_no_store(ConversationHistoryResponse { lines, before })
                    }
                    Err(e) => history_unavailable(e),
                };
            }
            let Some(cursor) = crate::bouncer::ReplayCursor::parse(before) else {
                return problem_at_field(
                    StatusCode::BAD_REQUEST,
                    "Invalid history cursor",
                    Some("`before` must be a cursor this API or the live chat socket handed out."),
                    Some("before"),
                );
            };
            let Some(ring) = handle
                .as_ref()
                .and_then(|handle| handle.history_through(cursor, &target))
            else {
                return unjoinable_history(
                    "The cursor names no position of this network's running buffer; read with `seam`.",
                    "before",
                );
            };
            if !ring.successors_retained {
                return unjoinable_history(
                    "The buffer no longer holds every line after the cursor; read with `seam`.",
                    "before",
                );
            }
            let own_nick = handle
                .as_ref()
                .and_then(|handle| handle.irc_session_snapshot())
                .map(|session| session.nick);
            let in_conversation = |line: &str| {
                crate::db::bnc_line_target(line, own_nick.as_deref(), &names)
                    .is_some_and(|display| names.fold(&display) == target)
            };
            let conversation: Vec<&crate::bouncer::BufferedLine> = ring
                .lines
                .iter()
                .filter(|line| in_conversation(&line.line))
                .collect();
            let older: Vec<&crate::bouncer::BufferedLine> = ring.lines[..ring.held_after]
                .iter()
                .filter(|line| in_conversation(&line.line))
                .collect();
            let skip = older.len().saturating_sub(limit as usize);
            let mut lines: Vec<String> =
                older[skip..].iter().map(|line| line.line.clone()).collect();
            // A page the ring fills to its limit goes on from before its
            // oldest line, ring or storage: storage is read only for what
            // the page has room for, and a page with none left used to end
            // the paging there.
            if skip > 0 || (lines.len() as i64 == limit && !older.is_empty()) {
                let before = ring.cursor_before(older[skip].seq).to_string();
                return json_no_store(ConversationHistoryResponse {
                    lines,
                    before: Some(before),
                });
            }
            // The ring holds nothing older: storage continues before the stored
            // copy of the conversation's oldest ring line that storage holds
            // (one it failed to store has no copy, and nothing between that
            // and the next is stored either), or from the newest stored row
            // when it holds none of them.
            let remaining = limit - lines.len() as i64;
            let mut seam = None;
            'lines: for line in &conversation {
                // By its ring position, which storage keeps with each line
                // (migration 0102): exact within this epoch, identical lines
                // included. A line a new epoch restored sits at another
                // position than it was stored at; it is found by its exact
                // text, past the identical copies the ring holds.
                let held = conversation
                    .iter()
                    .filter(|other| other.line == line.line)
                    .count() as i64;
                for which in [
                    crate::db::StoredCopy::AtPosition(line.seq),
                    crate::db::StoredCopy::OldestOfHeld(held),
                ] {
                    match locate(line.line.clone(), which).await {
                        Ok(Some(id)) => {
                            seam = Some(id);
                            break 'lines;
                        }
                        Ok(None) => {}
                        Err(e) => return history_unavailable(e),
                    }
                }
            }
            let rows = match read(seam, remaining).await {
                Ok(rows) => rows,
                Err(e) => return history_unavailable(e),
            };
            let (mut older_stored, before) = stored_page(rows, remaining);
            older_stored.append(&mut lines);
            json_no_store(ConversationHistoryResponse {
                lines: older_stored,
                before,
            })
        }
        (None, Some(seam), held) => {
            let held = held.unwrap_or(1);
            if held < 1 {
                return problem_at_field(
                    StatusCode::BAD_REQUEST,
                    "Invalid history request",
                    Some("`held` counts the copies of `seam` held: at least 1."),
                    Some("held"),
                );
            }
            let id = match locate(seam, crate::db::StoredCopy::OldestOfHeld(held)).await {
                Ok(Some(id)) => id,
                Ok(None) => {
                    return unjoinable_history(
                        "The stored history holds no such line in this conversation.",
                        "seam",
                    );
                }
                Err(e) => return history_unavailable(e),
            };
            match read(Some(id), limit).await {
                Ok(rows) => {
                    let (lines, before) = stored_page(rows, limit);
                    json_no_store(ConversationHistoryResponse { lines, before })
                }
                Err(e) => history_unavailable(e),
            }
        }
        (None, None, None) => match read(None, limit).await {
            Ok(rows) => {
                let (lines, before) = stored_page(rows, limit);
                json_no_store(ConversationHistoryResponse { lines, before })
            }
            Err(e) => history_unavailable(e),
        },
        (_, None, Some(_)) => problem_at_field(
            StatusCode::BAD_REQUEST,
            "Invalid history request",
            Some("`held` goes with `seam`."),
            Some("held"),
        ),
        _ => problem_at_field(
            StatusCode::BAD_REQUEST,
            "Invalid history request",
            Some("Give `before` or `seam`, not both."),
            Some("seam"),
        ),
    }
}

fn history_unavailable(e: crate::db::DbError) -> Response {
    eprintln!("http: conversation history read failed: {e}");
    problem(
        StatusCode::SERVICE_UNAVAILABLE,
        "Database unavailable",
        None,
    )
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PatchNetwork {
    pub(super) enabled: bool,
}

/// Full mutable IRC-network configuration for `PUT`. Credential handling is a
/// required tagged action so omitted JSON can never ambiguously mean either
/// preserve or erase a write-only secret.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UpdateNetwork {
    pub(super) addr: String,
    pub(super) tls: bool,
    pub(super) nick: String,
    /// Required when the stored network is `kind=irc`, refused for a bridge;
    /// which one applies is known only once the row is loaded.
    #[serde(default)]
    pub(super) username: Option<String>,
    #[serde(default)]
    pub(super) realname: Option<String>,
    /// Required: `PUT` replaces the whole configuration, so an omitted list
    /// cannot mean "keep" — and read as "none", it silently cleared the stored
    /// channels. An empty list is how a replace says "join nothing". An entry
    /// is `#channel`, or `#channel key` to set that channel's key.
    pub(super) autojoin: Vec<String>,
    /// Which stored channel keys carry over. Required for the reason
    /// `credentials` is: a key is write-only, so an entry written without one
    /// could otherwise mean either keep or remove it.
    pub(super) autojoin_keys: UpdateAutojoinKeys,
    pub(super) credentials: UpdateNetworkCredentials,
    /// Required for the same reason as `credentials`: an omitted field would
    /// have to mean either keep or erase a write-only secret.
    pub(super) server_password: UpdateServerPassword,
}

/// What a replace does with the autojoin channels' stored keys: each channel
/// in `keep` (listed in `autojoin` without a new key) keeps the key stored for
/// it; every other channel has the key written in its entry, or none.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UpdateAutojoinKeys {
    pub(super) keep: Vec<String>,
}

/// What a replace does with the stored server password (`PASS`).
#[derive(serde::Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum UpdateServerPassword {
    // Braced for the reason given on `UpdateNetworkCredentials`.
    Keep {},
    Remove {},
    Set { password: String },
}

#[derive(serde::Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum UpdateNetworkCredentials {
    // Empty braces, not unit variants: serde lets a unit variant of an
    // internally tagged enum ignore stray fields, so `{"action":"keep",
    // "password":"…"}` would silently drop a typed password.
    Keep {},
    Remove {},
    Set {
        #[serde(default)]
        account: Option<String>,
        #[serde(default)]
        password: Option<String>,
    },
}

/// Replace all mutable configuration of one caller-owned network and restart
/// its driver. The stored kind selects the exact IRC/bridge field contract; the
/// stable name, driver kind, and enabled state are unchanged.
pub(super) async fn update_network(
    State(state): State<Arc<AppState>>,
    Authenticated(account, _): Authenticated,
    PathParams(name): PathParams<String>,
    JsonBody(req): JsonBody<UpdateNetwork>,
) -> Response {
    let registry = registry_of(&state);
    if let Err(error) = update_network_core(&state, registry, &account, &name, req).await {
        return error.into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

/// Persist a network's enabled flag and start or stop its always-on driver,
/// answering with the network's stored name. Enabling builds from the stored
/// row first, so a missing key/factory failure cannot require a compensating
/// database rollback. Disabling needs no active owner: stopping a suspended
/// account's network is always allowed.
pub(super) async fn set_network_enabled_core(
    state: &Arc<AppState>,
    registry: &Arc<crate::bouncer::Registry>,
    actor: &str,
    account: &str,
    name: &str,
    enabled: bool,
) -> Result<String, NetworkMutationError> {
    let toggle = NetworkToggle {
        actor: actor.to_owned(),
        account: account.to_owned(),
        name: name.to_owned(),
        enabled,
    };
    let state = state.clone();
    registry
        .mutate(move |lane| async move { set_network_enabled_in_lane(&state, &lane, toggle).await })
        .await
}

/// Who turns which network on or off.
struct NetworkToggle {
    actor: String,
    account: String,
    name: String,
    enabled: bool,
}

async fn set_network_enabled_in_lane(
    state: &AppState,
    lane: &crate::bouncer::MutationLane,
    toggle: NetworkToggle,
) -> Result<String, NetworkMutationError> {
    let NetworkToggle {
        actor,
        account,
        name,
        enabled,
    } = toggle;
    let (actor, account, name) = (actor.as_str(), account.as_str(), name.as_str());
    let pool = pool_of(state);
    let audit = crate::db::NetworkAudit {
        actor,
        detail: if enabled { "enabled" } else { "disabled" },
    };
    let stored_name = if enabled {
        let owner_lane = ActiveOwnerLane::enter(state, lane, account).await?;
        let row = editable_network(state, lane, account, name, "enable").await?;
        let driver = stored_network_driver(state, account, &row)?;
        require_network_updated(
            crate::db::set_bnc_network_enabled(pool, account, name, true, audit).await,
            "enable failed",
        )?;
        owner_lane.ensure_running(&row.name, driver).await?;
        row.name
    } else {
        let row = editable_network(state, lane, account, name, "disable").await?;
        require_network_updated(
            crate::db::set_bnc_network_enabled(pool, account, name, false, audit).await,
            "disable failed",
        )?;
        lane.remove(
            Some(account),
            &row.name,
            crate::bouncer::UnwrittenLines::Store,
        )
        .await?;
        row.name
    };
    Ok(stored_name)
}

/// Delete one owner-scoped network and stop its driver under the same mutation
/// gate used by create/edit/toggle, so concurrent control-plane operations
/// cannot resurrect a driver whose durable row was removed.
///
/// The driver stops first — and its persistence task with it, between two
/// writes — so nothing it was about to write can land after the rows are gone
/// (the `bnc_buffer.network_id` foreign key makes such a line fail rather
/// than orphan). If the database then refuses the deletion, the network is
/// restarted from its stored row, so a failed delete leaves it as it was.
pub(super) async fn delete_network_core(
    state: &Arc<AppState>,
    registry: &Arc<crate::bouncer::Registry>,
    account: &str,
    name: &str,
) -> Result<(), NetworkMutationError> {
    let (state, account, name) = (state.clone(), account.to_owned(), name.to_owned());
    registry
        .mutate(
            move |lane| async move { delete_network_in_lane(&state, &lane, &account, &name).await },
        )
        .await
}

async fn delete_network_in_lane(
    state: &AppState,
    registry: &crate::bouncer::MutationLane,
    account: &str,
    name: &str,
) -> Result<(), NetworkMutationError> {
    let row = editable_network(state, registry, account, name, "delete").await?;
    // Built before anything stops, so a restart after a refused delete does
    // not depend on anything that could change meanwhile. A running network
    // whose row no longer builds (a rotated master key) can still be deleted;
    // it is said here that a refused delete would leave it stopped.
    let running = registry.get_stored(account, &row.name).is_some();
    let restart = if running {
        match stored_network_driver(state, account, &row) {
            Ok(driver) => Some(driver),
            Err(error) => {
                eprintln!(
                    "http: network {account}/{} cannot be rebuilt ({}); if the delete is \
                     refused it stays stopped",
                    row.name,
                    error.message()
                );
                None
            }
        }
    } else {
        None
    };
    registry
        .remove(
            Some(account),
            &row.name,
            crate::bouncer::UnwrittenLines::Discard,
        )
        .await?;
    let deleted = crate::db::delete_bnc_network(
        pool_of(state),
        account,
        name,
        crate::db::NetworkAudit {
            actor: account,
            detail: "",
        },
    )
    .await;
    // Only a refusal restarts it: `Ok(false)` means the row is already gone,
    // and a network with no row must not run.
    if deleted.is_err()
        && let Some(driver) = restart
        && let Err(held) = registry.replace(Some(account), &row.name, driver).await
    {
        eprintln!(
            "http: network {account}/{} not restarted after a refused delete: {held}",
            row.name
        );
    }
    require_network_updated(deleted, "delete failed")
}

/// Enable or disable one of the caller's networks (REST): persist the flag and
/// start/stop its always-on driver.
pub(super) async fn patch_network(
    State(state): State<Arc<AppState>>,
    Authenticated(account, _): Authenticated,
    PathParams(name): PathParams<String>,
    JsonBody(req): JsonBody<PatchNetwork>,
) -> Response {
    let registry = registry_of(&state);
    match set_network_enabled_core(&state, registry, &account, &account, &name, req.enabled).await {
        Ok(name) => axum::Json(NetworkEnabledResponse {
            name,
            enabled: req.enabled,
        })
        .into_response(),
        Err(error) => error.into_response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdminNetworkPatch {
    enabled: bool,
}

/// Enable or disable any owner's network (administrator only). The actor is
/// distinct from the owner so the existing audit event preserves provenance.
pub(super) async fn patch_admin_network(
    State(state): State<Arc<AppState>>,
    AdminAccount(actor): AdminAccount,
    PathParams((owner, name)): PathParams<(String, String)>,
    JsonBody(req): JsonBody<AdminNetworkPatch>,
) -> Response {
    let registry = registry_of(&state);
    match set_network_enabled_core(&state, registry, &actor, &owner, &name, req.enabled).await {
        Ok(name) => json_no_store(AdminNetworkEnabledResponse {
            owner,
            name,
            enabled: req.enabled,
        }),
        Err(error) => error.into_response(),
    }
}

/// Delete one of the caller's networks and stop its driver.
pub(super) async fn delete_network(
    State(state): State<Arc<AppState>>,
    Authenticated(account, _): Authenticated,
    PathParams(name): PathParams<String>,
) -> Response {
    let registry = registry_of(&state);
    match delete_network_core(&state, registry, &account, &name).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BridgeUpstreamFields, BufferQuery, CreateNetwork, IRC_NETWORK_PRESETS,
        NetworkAccountCommand, PreflightNetwork, UpdateNetwork, UpdateServerPassword,
        network_name_ok, parse_server_password, runtime_response, validate_bridge_upstream,
        validate_irc_upstream, validate_single_service_token,
    };

    #[test]
    fn network_creation_is_complete_and_kind_specific() {
        let irc = r#"{"kind":"irc","name":"libera","addr":"irc.libera.chat:6697","tls":true,"nick":"alice","username":"alice","realname":"Alice","autojoin":[]}"#;
        assert!(serde_json::from_str::<CreateNetwork>(irc).is_ok());
        assert!(serde_json::from_str::<CreateNetwork>(
            r#"{"name":"implicit","addr":"irc.example:6697","tls":true,"nick":"alice","username":"alice","realname":"Alice","autojoin":[]}"#
        )
        .is_err());
        assert!(serde_json::from_str::<CreateNetwork>(
            r#"{"kind":"irc","name":"incomplete","addr":"irc.example:6697","nick":"alice","username":"alice","realname":"Alice","autojoin":[]}"#
        )
        .is_err());
        assert!(serde_json::from_str::<CreateNetwork>(
            r#"{"kind":"discord","name":"wrong","addr":"","tls":true,"nick":"alice","autojoin":[],"sasl_password":"token"}"#
        )
        .is_err());
    }

    /// A replace states what happens to the server password, as it does for
    /// the SASL credentials: an omitted field would have to mean keep or
    /// erase, and a `set` without a password is not a set.
    #[test]
    fn a_replace_states_its_server_password_action() {
        let replace = |server_password: &str| {
            serde_json::from_str::<UpdateNetwork>(&format!(
                r#"{{"addr":"irc.example:6697","tls":true,"nick":"alice","username":"alice","realname":"Alice","autojoin":[],"autojoin_keys":{{"keep":[]}},"credentials":{{"action":"keep"}}{server_password}}}"#
            ))
            .map(|request| request.server_password)
        };
        assert!(replace("").is_err(), "omitted");
        assert!(matches!(
            replace(r#","server_password":{"action":"keep"}"#),
            Ok(UpdateServerPassword::Keep {})
        ));
        assert!(matches!(
            replace(r#","server_password":{"action":"remove"}"#),
            Ok(UpdateServerPassword::Remove {})
        ));
        assert!(matches!(
            replace(r#","server_password":{"action":"set","password":"open sesame"}"#),
            Ok(UpdateServerPassword::Set { password }) if password == "open sesame"
        ));
        for refused in [
            r#","server_password":{"action":"set"}"#,
            r#","server_password":null"#,
            r#","server_password":"open sesame""#,
            r#","server_password":{"action":"keep","password":"x"}"#,
        ] {
            assert!(replace(refused).is_err(), "{refused}");
        }
        // The same holds for the credential action: a stray password beside
        // `keep` is refused, not dropped.
        assert!(
            serde_json::from_str::<UpdateNetwork>(
                r#"{"addr":"irc.example:6697","tls":true,"nick":"alice","autojoin":[],"autojoin_keys":{"keep":[]},"credentials":{"action":"keep","password":"typed"},"server_password":{"action":"keep"}}"#
            )
            .is_err()
        );
        // And for the channel keys: omitted, they would have to mean keep or
        // remove; a stray field beside `keep` is refused.
        let keys = |autojoin_keys: &str| {
            serde_json::from_str::<UpdateNetwork>(&format!(
                r##"{{"addr":"irc.example:6697","tls":true,"nick":"alice","autojoin":["#a"]{autojoin_keys},"credentials":{{"action":"keep"}},"server_password":{{"action":"keep"}}}}"##
            ))
            .map(|request| request.autojoin_keys.keep)
        };
        assert_eq!(
            keys(r##","autojoin_keys":{"keep":["#a"]}"##).expect("keep"),
            ["#a"]
        );
        for refused in [
            "",
            r#","autojoin_keys":null"#,
            r#","autojoin_keys":{}"#,
            r##","autojoin_keys":{"keep":[],"set":{"#a":"k"}}"##,
        ] {
            assert!(keys(refused).is_err(), "{refused}");
        }
        let error = parse_server_password("a\r\nQUIT".into()).expect_err("a delimiter");
        assert_eq!(error.field, Some("server_password"));
        assert!(!error.message().contains("QUIT"), "{}", error.message());
    }

    #[test]
    fn preflight_requires_explicit_transport_and_identity() {
        assert!(
            serde_json::from_str::<PreflightNetwork>(
                r#"{"addr":"irc.example:6697","tls":true,"nick":"alice","username":"alice","realname":"Alice"}"#
            )
            .is_ok()
        );
        assert!(
            serde_json::from_str::<PreflightNetwork>(
                r#"{"addr":"irc.example:6697","nick":"alice","realname":"Alice"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn runtime_json_exposes_only_the_safe_failure_classification() {
        let (handle, ends) = crate::bouncer::NetworkHandle::channels(8);
        ends.emit(crate::bouncer::ConnectionEvent::Reconnecting(
            crate::bouncer::NetworkFailure::SecureConnectionFailed,
        ));
        let json = serde_json::to_value(runtime_response(&handle.runtime_snapshot()))
            .expect("runtime response is serializable");
        assert_eq!(
            json["last_error"]["code"], "secure_connection_failed",
            "{json}"
        );
        assert_eq!(
            json["last_error"]["summary"],
            "The secure connection failed; check DNS, port, and TLS identity.",
            "{json}"
        );
        assert!(
            json.get("raw_error").is_none(),
            "raw provider errors must never enter the owner API: {json}"
        );
        assert!(json["last_error"].get("diagnostic").is_none(), "{json}");

        ends.emit(crate::bouncer::ConnectionEvent::RegistrationFailed(
            e6irc_client::RegistrationRejection::from_reply(
                &e6irc_client::OwnedMessage::from(
                    &e6irc_proto::message::Message::parse(
                        "ERROR :Closing link: too many host connections",
                    )
                    .expect("a scripted reply parses"),
                ),
                e6irc_client::ServerPasswordSent::No,
            )
            .expect("a pre-welcome ERROR refuses registration"),
        ));
        let rejected = serde_json::to_value(runtime_response(&handle.runtime_snapshot()))
            .expect("runtime response is serializable");
        assert_eq!(
            rejected["last_error"]["diagnostic"], "Closing link: too many host connections",
            "the IRC parser's bounded owner-safe detail remains actionable: {rejected}"
        );
    }

    #[test]
    fn account_registration_commands_are_closed_and_single_token() {
        assert!(
            serde_json::from_str::<NetworkAccountCommand>(
                r#"{"action":"register","email":"alice@example.test","password":"secret"}"#
            )
            .is_ok()
        );
        assert!(
            serde_json::from_str::<NetworkAccountCommand>(
                r#"{"action":"verify","code":"mail-code"}"#
            )
            .is_ok()
        );
        for malformed in [
            r#"{"action":"register","email":"alice@example.test"}"#,
            r#"{"action":"verify","code":"mail-code","extra":true}"#,
            r#"{"action":"raw","line":"OPER root secret"}"#,
        ] {
            assert!(
                serde_json::from_str::<NetworkAccountCommand>(malformed).is_err(),
                "accepted {malformed}"
            );
        }
        assert!(validate_single_service_token("one-token", 32, "code").is_ok());
        assert!(validate_single_service_token("two tokens", 32, "code").is_err());
        assert!(validate_single_service_token("x\nPRIVMSG #other :injected", 64, "code").is_err());
    }

    #[test]
    fn public_irc_presets_are_safe_tls_endpoints() {
        assert!(
            IRC_NETWORK_PRESETS
                .iter()
                .any(|preset| preset.id == "libera"),
            "Libera is the primary interop target"
        );
        assert!(
            IRC_NETWORK_PRESETS
                .iter()
                .all(|preset| !preset.addr.contains("efnet")),
            "irc.efnet.org's members present certificates that are not valid for it"
        );
        for preset in IRC_NETWORK_PRESETS {
            assert_eq!(preset.id, preset.name);
            assert!(network_name_ok(preset.name), "{preset:?}");
            assert!(preset.tls, "public preset must default to TLS: {preset:?}");
            assert!(
                preset.addr.ends_with(":6697"),
                "preset must include its secure IRC port: {preset:?}"
            );
        }
    }

    #[test]
    fn buffer_query_rejects_unknown_fields() {
        let uri = "/?extra=1".parse().expect("query URI");
        assert!(axum::extract::Query::<BufferQuery>::try_from_uri(&uri).is_err());
    }

    /// The user name is stated by the owner. A nickname that is legal but whose
    /// first ten bytes are not a legal user name (`_bot`) used to get its network
    /// refused by the upstream with nothing the owner could correct.
    #[test]
    fn an_irc_network_states_its_username_and_a_bridge_cannot() {
        let with_username = |username: Option<&str>| {
            validate_irc_upstream(
                "irc.example:6697",
                "_bot",
                username,
                Some("Bot"),
                &[],
                crate::egress::InternalUpstreams::Refuse,
            )
        };
        assert_eq!(
            with_username(Some("bot"))
                .expect("stated")
                .username
                .as_str(),
            "bot"
        );
        for (username, detail) in [
            (None, "username is required for IRC networks"),
            (Some(""), "username is required"),
            (
                Some("_bot"),
                "username must begin with an ASCII letter or digit",
            ),
            (
                Some("first.last"),
                "username may contain only ASCII letters, digits, '_' and '-'",
            ),
            (Some("elevenbytes"), "username is limited to 10 bytes"),
        ] {
            let error = with_username(username).expect_err("must be refused");
            assert_eq!(error.status, axum::http::StatusCode::BAD_REQUEST);
            assert_eq!(error.field, Some("username"), "{username:?}: {error:?}");
            assert!(error.message().ends_with(detail), "{username:?}: {error:?}");
        }

        let bridge = validate_bridge_upstream(
            crate::config::NetworkKind::Discord,
            BridgeUpstreamFields {
                addr: "",
                tls: true,
                nick: "",
                username: Some("bot"),
                realname: None,
                autojoin: &[],
            },
            crate::egress::InternalUpstreams::Refuse,
        )
        .expect_err("a bridge has no IRC registration");
        assert_eq!(bridge.field, Some("username"));
        assert!(
            bridge
                .message()
                .ends_with("username applies only to IRC networks")
        );
        // A bridge's rooms and channel ids have no key.
        let keyed = validate_bridge_upstream(
            crate::config::NetworkKind::Discord,
            BridgeUpstreamFields {
                addr: "",
                tls: true,
                nick: "",
                username: None,
                realname: None,
                autojoin: &super::submitted_autojoin(&["123 secret".to_string()]),
            },
            crate::egress::InternalUpstreams::Refuse,
        )
        .expect_err("a bridge's channel takes no key");
        assert_eq!(keyed.field, Some("autojoin"));
        assert!(!keyed.message().contains("secret"), "{keyed:?}");

        // The request shapes themselves: required on create and on the
        // connection test, and not a field a bridge request has at all.
        let irc = |username: &str| {
            format!(
                r#"{{"kind":"irc","name":"libera","addr":"irc.libera.chat:6697","tls":true,"nick":"alice",{username}"realname":"Alice","autojoin":[]}}"#
            )
        };
        assert!(serde_json::from_str::<CreateNetwork>(&irc(r#""username":"alice","#)).is_ok());
        assert!(serde_json::from_str::<CreateNetwork>(&irc("")).is_err());
        assert!(
            serde_json::from_str::<CreateNetwork>(
                r#"{"kind":"discord","name":"d","addr":"","tls":true,"autojoin":[],"sasl_password":"t","username":"bot"}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<PreflightNetwork>(
                r#"{"addr":"irc.example:6697","tls":true,"nick":"alice","realname":"Alice"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_irc_upstream_is_rejected_before_it_can_be_persisted() {
        for addr in ["irc.example", "irc.example:0", "irc.example:not-a-port"] {
            let error = validate_irc_upstream(
                addr,
                "alice",
                Some("alice"),
                None,
                &[],
                crate::egress::InternalUpstreams::Refuse,
            )
            .expect_err("malformed address must fail");
            assert!(error.message().contains("host:port"), "{addr}: {error:?}");
        }
    }

    #[test]
    fn an_identity_that_would_reshape_a_wire_line_is_refused_at_its_field() {
        let ok = |nick: &str, realname: Option<&str>, autojoin: &[&str]| {
            let autojoin: Vec<String> = autojoin.iter().map(ToString::to_string).collect();
            let autojoin = super::submitted_autojoin(&autojoin);
            validate_irc_upstream(
                "irc.example:6697",
                nick,
                Some("ident"),
                realname,
                &autojoin,
                crate::egress::InternalUpstreams::Refuse,
            )
        };
        let identity = ok(
            "alice",
            Some("Alice Example"),
            &["#e6irc", "&local", "#staff hunter2"],
        )
        .expect("an ordinary identity");
        assert_eq!(identity.nick.as_str(), "alice");
        assert_eq!(identity.username.as_str(), "ident");
        assert_eq!(identity.autojoin.len(), 3);
        assert_eq!(identity.autojoin[2].channel().as_str(), "#staff");
        assert_eq!(
            identity.autojoin[2].key().map(|key| key.as_str()),
            Some("hunter2")
        );

        for (nick, realname, autojoin, field) in [
            // `NICK al ice` carries two parameters.
            ("al ice", Some("Alice"), &[][..], "nick"),
            ("#alice", Some("Alice"), &[][..], "nick"),
            ("alice!x@y", Some("Alice"), &[][..], "nick"),
            ("alice", Some("two\u{1b}[2Jlines"), &[][..], "realname"),
            // `JOIN 0` leaves every channel.
            ("alice", Some("Alice"), &["0"][..], "autojoin"),
            // A key that is not one parameter, and a second channel in one
            // entry.
            ("alice", Some("Alice"), &["#a two words"][..], "autojoin"),
            ("alice", Some("Alice"), &["#a :key"][..], "autojoin"),
            ("alice", Some("Alice"), &["#a,#b"][..], "autojoin"),
            ("alice", Some("Alice"), &["#a k,ey"][..], "autojoin"),
            ("alice", Some("Alice"), &["e6irc"][..], "autojoin"),
        ] {
            let error = ok(nick, realname, autojoin).expect_err("must be refused");
            assert_eq!(
                error.status,
                axum::http::StatusCode::BAD_REQUEST,
                "{error:?}"
            );
            assert_eq!(error.field, Some(field), "{nick:?} {autojoin:?}: {error:?}");
            assert!(error.message().contains(field), "{error:?}");
        }
    }

    #[test]
    fn network_name_charset_is_restricted() {
        // Plain token names are accepted.
        assert!(network_name_ok("libera"));
        assert!(network_name_ok("my-net_1"));
        assert!(network_name_ok("irc.example"));
        // URL-significant characters cannot become ambiguous route components.
        assert!(!network_name_ok("foo?bar"));
        assert!(!network_name_ok("foo#bar"));
        assert!(!network_name_ok("foo%41"));
        assert!(!network_name_ok("a&b"));
        assert!(!network_name_ok("a/b"));
        // Quote/angle — the JavaScript-string / HTML-attribute XSS vectors.
        assert!(!network_name_ok("'-alert(1)-'"));
        assert!(!network_name_ok("<script>"));
        assert!(!network_name_ok("a\"b"));
        // Whitespace, control and empty.
        assert!(!network_name_ok(""));
        assert!(!network_name_ok("a b"));
        assert!(!network_name_ok("a\nb"));
        assert!(!network_name_ok(&"x".repeat(65)));
        // Path-traversal segments.
        assert!(!network_name_ok("."));
        assert!(!network_name_ok(".."));
    }
}
