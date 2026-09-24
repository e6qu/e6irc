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
        &folded,
        "NETWORK_ACCOUNT_COMMAND",
        &format!("{folded}/{network}"),
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
/// the console. `name` is the stable e6irc selector, deliberately distinct from
/// the human label so spaces cannot leak into URL/client addressing.
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
/// the chat client reads it here and the console renders the same constant, so
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
    autojoin: Vec<String>,
    sasl_account: Option<String>,
    sasl_password: Option<String>,
    /// `None` for every bridge: only an IRC request can carry one.
    server_password: Option<String>,
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
                autojoin,
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
                autojoin,
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
                autojoin,
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
                autojoin,
                sasl_account: Some(sasl_account),
                sasl_password: Some(sasl_password),
                server_password: None,
            },
        }
    }
}

/// An ephemeral qualification request. It intentionally omits the durable
/// network name but exercises the configured connection and channel joins
/// without persisting anything.
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
    autojoin: Vec<String>,
    sasl_account: Option<String>,
    has_sasl_account: bool,
    has_sasl_password: bool,
    /// Whether a sealed server password is stored. The value is never shown.
    has_server_password: bool,
    enabled: bool,
    connected: Option<bool>,
    runtime: Option<NetworkRuntimeResponse>,
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

impl AdminNetworkResponse {
    pub(super) fn owner(&self) -> &str {
        match &self.kind {
            AdminNetworkKind::Owned { owner, .. } => owner,
            AdminNetworkKind::Shared { owner, .. } => owner,
        }
    }

    pub(super) fn name(&self) -> &str {
        match &self.kind {
            AdminNetworkKind::Owned { network, .. } => &network.name,
            AdminNetworkKind::Shared { name, .. } => name,
        }
    }
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
        autojoin: network.autojoin,
        sasl_account: account,
        has_sasl_account,
        has_sasl_password,
        has_server_password,
        enabled: network.enabled,
        connected: runtime.map(|r| r.lifecycle == crate::bouncer::NetworkLifecycle::Connected),
        runtime: runtime.map(runtime_response),
    }
}

/// The account's own networks (metadata only — never the secret).
pub(super) async fn list_networks(
    State(state): State<Arc<AppState>>,
    Authenticated(account, _): Authenticated,
) -> Response {
    // A read of "my networks" with no bouncer is an empty collection, not an
    // error: returning 200 `{networks:[]}` lets the web client's network picker
    // render cleanly (a 404 here shows up as a failed resource load in the
    // browser console). The mutation endpoints still 404 when the bouncer is off.
    let Some(registry) = &state.bnc_registry else {
        return json_no_store(NetworkListResponse {
            networks: Vec::new(),
        });
    };
    let pool = pool_of(&state);
    match crate::db::list_bnc_networks(pool, &account).await {
        Ok(rows) => {
            let networks: Vec<NetworkResponse> = rows
                .into_iter()
                .map(|n| {
                    let handle = registry.get_owned(&account, &n.name);
                    let runtime = handle.as_ref().map(|handle| handle.runtime_snapshot());
                    network_response(n, runtime.as_ref())
                })
                .collect();
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
    Path(name): Path<String>,
) -> Response {
    let pool = pool_of(&state);
    let network = match crate::db::get_bnc_network(pool, &account, &name).await {
        Ok(Some(network)) => network,
        Ok(None) => return problem(StatusCode::NOT_FOUND, "No such network", None),
        Err(e) => {
            eprintln!("http: network read failed: {e}");
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            );
        }
    };
    let handle = state
        .bnc_registry
        .as_ref()
        .and_then(|registry| registry.get_owned(&account, &name));
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
    let Some(registry) = &state.bnc_registry else {
        return problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None);
    };
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
    let Some(registry) = state.bnc_registry.as_ref() else {
        return Ok(());
    };
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
    let running = rows.iter().find(|row| {
        row.kind == crate::config::NetworkKind::Irc
            && row.addr.eq_ignore_ascii_case(&req.addr)
            && casemap.eq(&row.nick, &req.nick)
            && registry.get_owned(account, &row.name).is_some()
    });
    match running {
        Some(row) => Err(network_error(
            StatusCode::CONFLICT,
            "Network is running",
            Some(&format!(
                "network '{}' is running; disable it to test its settings",
                row.name
            )),
        )),
        None => Ok(()),
    }
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
        &req.autojoin,
        internal_upstreams,
    )?;
    refuse_cleartext_credentials(
        &req.addr,
        req.tls,
        req.sasl_password.is_some(),
        req.server_password.is_some(),
        internal_upstreams,
    )?;
    if let Some(account) = req.sasl_account.as_deref() {
        validate_credential_field(account, 255).map_err(|e| e.with_field("sasl_account"))?;
    }
    if let Some(password) = req.sasl_password.as_deref() {
        validate_credential_field(password, 512).map_err(|e| e.with_field("sasl_password"))?;
    }
    if req.sasl_account.is_some() != req.sasl_password.is_some() {
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
        sasl: req.sasl_account.zip(req.sasl_password),
        server_password,
        keepalive_idle: crate::bouncer::KEEPALIVE_IDLE,
        rejection_retry_floor: crate::bouncer::REJECTION_RETRY_FLOOR,
        internal_upstreams,
        first_dial: crate::bouncer::FirstDial::Immediate,
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
    Path(name): Path<String>,
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
    let Some(handle) = state
        .bnc_registry
        .as_ref()
        .and_then(|registry| registry.get_owned(&account, &network.name))
    else {
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
        crate::bouncer::SendOutcome::Full => problem(
            StatusCode::TOO_MANY_REQUESTS,
            "Upstream command queue is full",
            Some("nothing was sent; wait for the upstream to recover and try again"),
        ),
        crate::bouncer::SendOutcome::Closed | crate::bouncer::SendOutcome::Unavailable => problem(
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
/// into URL path segments, HTML attributes and JS-string confirm dialogs.
/// Restricting it to an unambiguous token charset (letters, digits, `-`, `_`,
/// `.`) makes URL-significant, quote/angle (XSS), whitespace and control
/// characters unrepresentable in a name rather than relying on correct escaping
/// at every render site (DESIGN §2). `.`/`..` are excluded so a name can never
/// resolve to a path-traversal segment.
pub(super) fn network_name_ok(name: &str) -> bool {
    crate::sanitize::valid_network_name(name)
}

/// Bounds/injection/SSRF checks on the connection/identity fields, shared by
/// create (all kinds) and edit. Length-bounds `addr`/`nick`/`realname`/
/// `autojoin`, rejects CR/LF/NUL in them (a line-injection primitive into the
/// upstream NICK/USER/JOIN), and refuses an obviously-internal `addr` (SSRF).
/// Does *not* check presence — a bridge kind legitimately has no addr/nick.
pub(super) fn check_upstream_bounds(
    addr: &str,
    nick: &str,
    realname: Option<&str>,
    autojoin: &[String],
    internal_upstreams: crate::egress::InternalUpstreams,
) -> Result<(), NetworkMutationError> {
    let overlong = if addr.len() > 255 {
        Some(("addr", "addr is limited to 255 bytes"))
    } else if nick.len() > 64 {
        Some(("nick", "nick is limited to 64 bytes"))
    } else if realname.is_some_and(|r| r.len() > 128) {
        Some(("realname", "realname is limited to 128 bytes"))
    } else if autojoin.len() > 64 || autojoin.iter().any(|c| c.len() > 64) {
        Some(("autojoin", "autojoin is limited to 64 channels of 64 bytes"))
    } else {
        None
    };
    if let Some((field, detail)) = overlong {
        return Err(
            network_error(StatusCode::BAD_REQUEST, "Field too long", Some(detail))
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
    } else if autojoin.iter().any(|c| has_control(c)) {
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
    pub(super) autojoin: Vec<crate::bouncer::UpstreamChannel>,
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
    autojoin: &[String],
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
        autojoin: crate::bouncer::UpstreamChannel::parse_list(autojoin)
            .map_err(identity_problem)?,
    })
}

/// Resolve one owner-scoped row for an API mutation.
async fn editable_network(
    state: &AppState,
    account: &str,
    name: &str,
    operation: &str,
) -> Result<crate::db::BncNetworkRow, NetworkMutationError> {
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

fn validate_credential_field(value: &str, maximum: usize) -> Result<(), NetworkMutationError> {
    crate::bouncer::validate_network_credential(value, maximum).map_err(|error| {
        network_error(
            StatusCode::BAD_REQUEST,
            "Invalid upstream credentials",
            Some(&error),
        )
    })
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
            let account = account.map(str::trim).filter(|value| !value.is_empty());
            let Some(account) = account else {
                return Err(network_error(
                    StatusCode::BAD_REQUEST,
                    "Incomplete upstream SASL",
                    Some("enter a SASL account or explicitly remove the stored credentials"),
                ));
            };
            validate_credential_field(account, 255)?;
            row.sasl_account = Some(account.to_string());
            if let Some(password) = password {
                validate_credential_field(password, 512)?;
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
            validate_credential_field(password, 512)?;
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
                validate_credential_field(account, 255)?;
                row.sasl_account = Some(seal_network_secret(state, owner, account)?);
            } else if row.sasl_account.is_none() {
                return Err(network_error(
                    StatusCode::BAD_REQUEST,
                    "Incomplete bridge credentials",
                    Some("enter the Slack bot token"),
                ));
            }
            if let Some(password) = password {
                validate_credential_field(password, 512)?;
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
    autojoin: &'a [String],
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
    async fn supersede(&self, name: &str, driver: Box<dyn crate::bouncer::NetworkDriver>) {
        self.lane.replace(Some(self.owner), name, driver).await;
    }

    /// Start `driver` unless a working one is already registered (enable).
    async fn ensure_running(&self, name: &str, driver: Box<dyn crate::bouncer::NetworkDriver>) {
        self.lane
            .ensure_running(Some(self.owner), name, driver)
            .await;
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
        credentials,
        server_password,
    } = req;
    let (addr, nick, username, realname, autojoin) = (
        addr.as_str(),
        nick.as_str(),
        username.as_deref(),
        realname.as_deref(),
        autojoin.as_slice(),
    );
    let lane = ActiveOwnerLane::enter(state, lane, account).await?;
    let pool = pool_of(state);
    let mut row = editable_network(state, account, name, "update").await?;
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
            autojoin,
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
                autojoin,
            },
            state.internal_upstreams,
        )?;
    }
    row.addr = addr.to_string();
    row.tls = tls;
    row.nick = nick.to_string();
    row.username = username.map(str::to_string);
    row.realname = realname.map(str::to_string);
    row.autojoin = autojoin.to_vec();
    apply_network_credentials(state, account, &mut row, credentials)?;
    apply_server_password(state, account, &mut row, server_password)?;
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
        lane.supersede(name, driver).await;
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
    note("autojoin", before.autojoin != after.autojoin);
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
    if let Some(account) = req.sasl_account.as_deref() {
        validate_credential_field(account, 255).map_err(|e| e.with_field("sasl_account"))?;
    }
    if let Some(password) = req.sasl_password.as_deref() {
        validate_credential_field(password, 512).map_err(|e| e.with_field("sasl_password"))?;
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
        autojoin: req.autojoin.clone(),
        sasl_account: stored_account,
        sasl_password_sealed: sealed_password,
        server_password_sealed: sealed_server_password,
        enabled: true,
    };
    let pool = state.pool.as_ref().expect("caller checked the pool");
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
    // The row was just inserted under the uniqueness constraint, so anything
    // already registered under this key has no durable definition: supersede it.
    lane.supersede(&req.name, driver).await;
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
    Path(name): Path<String>,
    QueryParams(params): QueryParams<BufferQuery>,
) -> Response {
    if state.bnc_registry.is_none() {
        return problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None);
    }
    let pool = pool_of(&state);
    // The network must belong to the caller — no cross-account reads.
    match crate::db::get_bnc_network(pool, &account, &name).await {
        Ok(Some(_)) => {}
        Ok(None) => return problem(StatusCode::NOT_FOUND, "No such network", None),
        Err(e) => {
            eprintln!("http: network buffer lookup failed: {e}");
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            );
        }
    }
    let limit = match bounded_query_limit(params.limit, DEFAULT_BUFFER_READ_LIMIT, 1000, "buffer") {
        Ok(limit) => limit,
        Err(response) => return response.into(),
    };
    if let Some(handle) = state
        .bnc_registry
        .as_ref()
        .and_then(|registry| registry.get_owned(&account, &name))
    {
        let lines = handle.buffer_snapshot();
        let skip = lines.len().saturating_sub(limit as usize);
        return json_no_store(NetworkBufferLinesResponse {
            lines: lines[skip..].to_vec(),
        });
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
    #[serde(default)]
    pub(super) autojoin: Vec<String>,
    pub(super) credentials: UpdateNetworkCredentials,
    /// Required for the same reason as `credentials`: an omitted field would
    /// have to mean either keep or erase a write-only secret.
    pub(super) server_password: UpdateServerPassword,
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
    Path(name): Path<String>,
    JsonBody(req): JsonBody<UpdateNetwork>,
) -> Response {
    let Some(registry) = &state.bnc_registry else {
        return problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None);
    };
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
        let row = editable_network(state, account, name, "enable").await?;
        let driver = stored_network_driver(state, account, &row)?;
        require_network_updated(
            crate::db::set_bnc_network_enabled(pool, account, name, true, audit).await,
            "enable failed",
        )?;
        owner_lane.ensure_running(&row.name, driver).await;
        row.name
    } else {
        let row = editable_network(state, account, name, "disable").await?;
        require_network_updated(
            crate::db::set_bnc_network_enabled(pool, account, name, false, audit).await,
            "disable failed",
        )?;
        lane.remove(
            Some(account),
            &row.name,
            crate::bouncer::UnwrittenLines::Store,
        )
        .await;
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
    let row = editable_network(state, account, name, "delete").await?;
    // Built before anything stops, so a restart after a refused delete does
    // not depend on anything that could change meanwhile. A running network
    // whose row no longer builds (a rotated master key) can still be deleted;
    // it is said here that a refused delete would leave it stopped.
    let running = registry.get_owned(account, &row.name).is_some();
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
        .await;
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
    {
        registry.replace(Some(account), &row.name, driver).await;
    }
    require_network_updated(deleted, "delete failed")
}

/// Enable or disable one of the caller's networks (REST): persist the flag and
/// start/stop its always-on driver.
pub(super) async fn patch_network(
    State(state): State<Arc<AppState>>,
    Authenticated(account, _): Authenticated,
    Path(name): Path<String>,
    JsonBody(req): JsonBody<PatchNetwork>,
) -> Response {
    let Some(registry) = &state.bnc_registry else {
        return problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None);
    };
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
    Path((owner, name)): Path<(String, String)>,
    JsonBody(req): JsonBody<AdminNetworkPatch>,
) -> Response {
    let Some(registry) = &state.bnc_registry else {
        return problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None);
    };
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
    Path(name): Path<String>,
) -> Response {
    let Some(registry) = &state.bnc_registry else {
        return problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None);
    };
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
                r#"{{"addr":"irc.example:6697","tls":true,"nick":"alice","username":"alice","realname":"Alice","autojoin":[],"credentials":{{"action":"keep"}}{server_password}}}"#
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
                r#"{"addr":"irc.example:6697","tls":true,"nick":"alice","credentials":{"action":"keep","password":"typed"},"server_password":{"action":"keep"}}"#
            )
            .is_err()
        );
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
            e6irc_client::RegistrationRejection::without_diagnostic(
                e6irc_client::RegistrationRefusal::NotRegistered,
            ),
        ));
        let rejected = serde_json::to_value(runtime_response(&handle.runtime_snapshot()))
            .expect("runtime response is serializable");
        assert_eq!(
            rejected["last_error"]["diagnostic"], "no detail from upstream",
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
            validate_irc_upstream(
                "irc.example:6697",
                nick,
                Some("ident"),
                realname,
                &autojoin,
                crate::egress::InternalUpstreams::Refuse,
            )
        };
        let identity = ok("alice", Some("Alice Example"), &["#e6irc", "&local"])
            .expect("an ordinary identity");
        assert_eq!(identity.nick.as_str(), "alice");
        assert_eq!(identity.username.as_str(), "ident");
        assert_eq!(identity.autojoin.len(), 2);

        for (nick, realname, autojoin, field) in [
            // `NICK al ice` carries two parameters.
            ("al ice", Some("Alice"), &[][..], "nick"),
            ("#alice", Some("Alice"), &[][..], "nick"),
            ("alice!x@y", Some("Alice"), &[][..], "nick"),
            ("alice", Some("two\u{1b}[2Jlines"), &[][..], "realname"),
            // `JOIN 0` leaves every channel.
            ("alice", Some("Alice"), &["0"][..], "autojoin"),
            // A key nobody configured, and a second channel in one entry.
            ("alice", Some("Alice"), &["#a key"][..], "autojoin"),
            ("alice", Some("Alice"), &["#a,#b"][..], "autojoin"),
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
        // Quote/angle — the JS-string / HTML-attribute XSS vectors.
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
