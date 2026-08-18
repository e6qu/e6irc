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

    #[cfg(test)]
    pub(super) fn message(&self) -> String {
        match &self.detail {
            Some(detail) => format!("{}: {detail}", self.title),
            None => self.title.to_string(),
        }
    }

    pub(super) fn into_response(self) -> Response {
        problem(self.status, self.title, self.detail.as_deref())
    }
}

fn network_error(
    status: StatusCode,
    title: &'static str,
    detail: Option<&str>,
) -> NetworkMutationError {
    NetworkMutationError::new(status, title, detail)
}

/// Record one network mutation in the audit trail. The mutation itself is
/// already committed (audit is a trail, not a gate), so a failed insert
/// cannot roll it back — but it is logged, never silently lost.
async fn audit_network_mutation(
    state: &AppState,
    actor: &str,
    action: &'static str,
    account: &str,
    name: &str,
    detail: &str,
) {
    if let Err(error) = crate::db::insert_audit_log(
        pool_of(state),
        actor,
        action,
        &format!("{account}/{name}"),
        detail,
    )
    .await
    {
        eprintln!("http: network {action} audit for {account}/{name}: {error}");
    }
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
#[derive(Debug, Clone, Copy)]
pub(super) struct IrcNetworkPreset {
    pub(super) id: &'static str,
    pub(super) label: &'static str,
    pub(super) name: &'static str,
    pub(super) addr: &'static str,
    pub(super) tls: bool,
}

/// Public connection endpoints from the networks' own documentation, verified
/// 2026-07-29:
/// - <https://libera.chat/guides/connect>
/// - <https://www.oftc.net/>
/// - <https://www.efnet.org/>
/// - <https://snoonet.org/help/>
///
/// Keep this catalog small and authoritative: a stale preset is worse than
/// making a custom endpoint explicit.
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
        id: "efnet",
        label: "EFnet",
        name: "efnet",
        addr: "irc.efnet.org:6697",
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

pub(super) fn irc_network_preset(id: &str) -> Option<IrcNetworkPreset> {
    IRC_NETWORK_PRESETS
        .iter()
        .copied()
        .find(|preset| preset.id == id)
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
        realname: String,
        autojoin: Vec<String>,
        #[serde(default)]
        sasl_account: Option<String>,
        #[serde(default)]
        sasl_password: Option<String>,
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

struct NetworkCreation {
    kind: crate::config::NetworkKind,
    name: String,
    addr: String,
    tls: bool,
    nick: String,
    realname: String,
    autojoin: Vec<String>,
    sasl_account: Option<String>,
    sasl_password: Option<String>,
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
                realname,
                autojoin,
                sasl_account,
                sasl_password,
            } => Self {
                kind: NetworkKind::Irc,
                name,
                addr,
                tls,
                nick,
                realname,
                autojoin,
                sasl_account,
                sasl_password,
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
                realname: String::new(),
                autojoin,
                sasl_account: None,
                sasl_password: Some(sasl_password),
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
                realname: String::new(),
                autojoin,
                sasl_account: None,
                sasl_password: Some(sasl_password),
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
                realname: String::new(),
                autojoin,
                sasl_account: Some(sasl_account),
                sasl_password: Some(sasl_password),
            },
        }
    }
}

/// An ephemeral qualification request. It intentionally omits the durable
/// network name and autojoin list: preflight proves the transport,
/// authentication, and registration boundary without persisting anything or
/// producing channel traffic.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreflightNetwork {
    pub(super) addr: String,
    pub(super) tls: bool,
    pub(super) nick: String,
    pub(super) realname: String,
    #[serde(default)]
    pub(super) sasl_account: Option<String>,
    #[serde(default)]
    pub(super) sasl_password: Option<String>,
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
    realname: Option<String>,
    autojoin: Vec<String>,
    sasl_account: Option<String>,
    has_sasl_account: bool,
    has_sasl_password: bool,
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
        realname: network.realname,
        autojoin: network.autojoin,
        sasl_account: account,
        has_sasl_account,
        has_sasl_password,
        enabled: network.enabled,
        connected: runtime.map(|r| r.lifecycle == crate::bouncer::NetworkLifecycle::Connected),
        runtime: runtime.map(runtime_response),
    }
}

/// The account's own networks (metadata only — never the secret).
pub(super) async fn list_networks(
    State(state): State<Arc<AppState>>,
    Authenticated(account): Authenticated,
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
    Authenticated(account): Authenticated,
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
    Authenticated(account): Authenticated,
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
    Authenticated(_account): Authenticated,
    JsonBody(req): JsonBody<PreflightNetwork>,
) -> Response {
    match preflight_network_core(req).await {
        Ok(result) => axum::Json(PreflightNetworkResponse { ok: true, result }).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(super) async fn preflight_network_core(
    req: PreflightNetwork,
) -> Result<crate::bouncer::IrcPreflight, NetworkMutationError> {
    validate_irc_upstream(&req.addr, &req.nick, Some(&req.realname), &[])?;
    if let Some(account) = req.sasl_account.as_deref()
        && let Err(error) = validate_credential_field(account, 255)
    {
        return Err(error);
    }
    if let Some(password) = req.sasl_password.as_deref()
        && let Err(error) = validate_credential_field(password, 512)
    {
        return Err(error);
    }
    if req.sasl_account.is_some() != req.sasl_password.is_some() {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Incomplete upstream SASL",
            Some("provide both sasl_account and sasl_password, or neither"),
        ));
    }

    let config = crate::bouncer::NetworkConfig {
        addr: req.addr,
        tls: req.tls,
        nick: req.nick,
        realname: req.realname,
        autojoin: Vec::new(),
        buffer_cap: 1,
        sasl: req.sasl_account.zip(req.sasl_password),
        keepalive_idle: crate::bouncer::KEEPALIVE_IDLE,
    };
    crate::bouncer::preflight_irc(&config)
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

/// Whether `addr` has an IP-literal host that points at a target that is never a
/// legitimate upstream and that the server must not be tricked into dialing: the
/// cloud-metadata link-local range (169.254/fe80), unspecified, multicast,
/// broadcast, and documentation ranges.
///
/// Accepts both an IRC `host:port` (IPv6 bracketed) **and** a bridge base URL
/// (`scheme://host[:port]/path`): a bridge address is a URL, and the bridge HTTP
/// client only routes *named* hosts through its dial-time vetting resolver — an
/// IP-literal URL host would otherwise reach an internal target unvetted, the
/// exact metadata-SSRF this exists to stop. Extracting the host from either form
/// closes that at the create boundary for every kind.
///
/// Loopback and RFC-1918 / unique-local *private* ranges are deliberately
/// **allowed** — a self-hosted or LAN upstream (including `127.0.0.1`) is a
/// first-class e6irc use case. A hostname (non-literal) returns `false` here —
/// the concrete reported vector is the IP literal; hostname resolution is vetted
/// at dial time.
fn upstream_addr_is_internal(addr: &str) -> bool {
    // Strip a URL scheme and any path/query/fragment, leaving `host[:port]`.
    let hostport = addr.split_once("://").map_or(addr, |(_, rest)| rest);
    let hostport = hostport.split(['/', '?', '#']).next().unwrap_or(hostport);
    let host = if let Some(rest) = hostport.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest) // [ipv6]:port
    } else {
        hostport
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(hostport)
    };
    let Ok(ip) = host.parse::<std::net::IpAddr>() else {
        return false; // hostname — not classifiable without DNS (vetted at dial)
    };
    is_blocked_upstream_ip(ip)
}

/// Is `ip` an SSRF-blocked upstream target — link-local (incl. the cloud
/// metadata endpoint `169.254.169.254`), broadcast, documentation, unspecified,
/// or multicast? Loopback and RFC-1918 / unique-local are deliberately *allowed*
/// (a self-hosted or LAN upstream is a first-class use case).
///
/// The address is canonicalized first: a V4-mapped V6 literal like
/// `::ffff:169.254.169.254` connects, at the kernel, to the V4 address, so it
/// must be classified by the V4 rules — the V6-only link-local test
/// (`fe80::/10`) is `false` for a mapped form and would otherwise wave the
/// metadata endpoint straight through. Used both on the creation-time literal
/// and, crucially, on every *resolved* address at dial time (`irc_driver`), so a
/// hostname that resolves — now or after a DNS rebind — to an internal target
/// cannot be reached.
pub(crate) fn is_blocked_upstream_ip(ip: std::net::IpAddr) -> bool {
    let ip = ip.to_canonical();
    if ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_link_local() || v4.is_broadcast() || v4.is_documentation()
        }
        // Unique-local (fc00::/7) is the private analogue of RFC-1918 and is
        // allowed, like loopback; `to_canonical` has already mapped any
        // V4-in-V6 form to V4, so what reaches here is a genuine V6 address.
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// A network name is a client-facing `/network` selector that is interpolated
/// into URL path segments, HTML attributes and JS-string confirm dialogs.
/// Restricting it to an unambiguous token charset (letters, digits, `-`, `_`,
/// `.`) makes URL-significant, quote/angle (XSS), whitespace and control
/// characters unrepresentable in a name rather than relying on correct escaping
/// at every render site (DESIGN §2). `.`/`..` are excluded so a name can never
/// resolve to a path-traversal segment.
pub(super) fn network_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
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
    if upstream_addr_is_internal(addr) {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Disallowed upstream address",
            Some(
                "addr must not be a link-local, unspecified, multicast, broadcast, or documentation IP",
            ),
        )
        .with_field("addr"));
    }
    Ok(())
}

/// Full validation for an IRC upstream's connection/identity fields (create and
/// edit): `addr`/`nick` required, plus the shared [`check_upstream_bounds`].
pub(super) fn validate_irc_upstream(
    addr: &str,
    nick: &str,
    realname: Option<&str>,
    autojoin: &[String],
) -> Result<(), NetworkMutationError> {
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
    check_upstream_bounds(addr, nick, realname, autojoin)
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
pub(super) enum NetworkCredentialUpdate<'a> {
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
    update: NetworkCredentialUpdate<'_>,
) -> Result<(), NetworkMutationError> {
    use crate::config::NetworkKind;
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

fn validate_bridge_upstream(
    kind: crate::config::NetworkKind,
    addr: &str,
    tls: bool,
    nick: &str,
    realname: Option<&str>,
    autojoin: &[String],
) -> Result<(), NetworkMutationError> {
    use crate::config::NetworkKind;
    check_upstream_bounds(addr, nick, realname, autojoin)?;
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
    let driver = crate::bouncer::driver_from_row(row, state.secret_key.as_deref(), account)
        .map_err(|error| {
            network_error(StatusCode::CONFLICT, "Cannot start network", Some(&error))
        })?;
    Ok(should_run.then_some(driver))
}

/// Update all mutable configuration of one caller-owned network and replace its
/// running driver. The registry mutation gate makes the database write and
/// runtime transition one serialized control-plane operation.
#[allow(clippy::too_many_arguments)]
pub(super) async fn update_network_core(
    state: &AppState,
    registry: &crate::bouncer::Registry,
    account: &str,
    name: &str,
    addr: &str,
    tls: bool,
    nick: &str,
    realname: Option<&str>,
    autojoin: &[String],
    credentials: NetworkCredentialUpdate<'_>,
) -> Result<(), NetworkMutationError> {
    let _mutation = registry.mutation_guard().await;
    let pool = pool_of(state);
    let mut row = editable_network(state, account, name, "update").await?;
    if row.kind == crate::config::NetworkKind::Irc && realname.is_none() {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Missing required fields",
            Some("realname is required for IRC networks"),
        )
        .with_field("realname"));
    }
    if row.kind == crate::config::NetworkKind::Irc {
        validate_irc_upstream(addr, nick, realname, autojoin)?;
    } else {
        validate_bridge_upstream(row.kind, addr, tls, nick, realname, autojoin)?;
    }
    row.addr = addr.to_string();
    row.tls = tls;
    row.nick = nick.to_string();
    row.realname = realname.map(str::to_string);
    row.autojoin = autojoin.to_vec();
    apply_network_credentials(state, account, &mut row, credentials)?;
    let driver =
        prospective_network_driver(state, account, &row, row.enabled, row.kind.is_bridge())?;

    require_network_updated(
        crate::db::update_bnc_network(pool, account, name, &row).await,
        "update failed",
    )?;
    if let Some(driver) = driver {
        registry.replace(Some(account), name, driver).await;
    }
    audit_network_mutation(
        state,
        account,
        "NETWORK_UPDATE",
        account,
        name,
        row.kind.as_db_str(),
    )
    .await;
    Ok(())
}

async fn create_network_core(
    state: &AppState,
    registry: &crate::bouncer::Registry,
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
        validate_irc_upstream(&req.addr, &req.nick, Some(&req.realname), &req.autojoin)?;
    } else {
        validate_bridge_upstream(kind, &req.addr, req.tls, &req.nick, None, &req.autojoin)?;
    }
    // Fields that are create-only (the name) or SASL-specific (bounds + the NUL
    // check that matters because PLAIN uses NUL as its field separator, and the
    // sealed-secret size cap) are checked here rather than in the shared helper.
    if req.name.len() > 64 {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Field too long",
            Some("network names are limited to 64 bytes"),
        )
        .with_field("name"));
    }
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
    let need_key =
        req.sasl_password.is_some() || (kind.account_is_secret() && req.sasl_account.is_some());
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

    // Build before inserting. A factory rejection must not create durable state
    // that then depends on a best-effort compensating delete.
    let driver = crate::bouncer::build_driver(
        kind,
        req.addr.clone(),
        req.tls,
        req.nick.clone(),
        req.realname.clone(),
        req.autojoin.clone(),
        1000,
        req.sasl_account.clone(),
        req.sasl_password.clone(),
    )
    .map_err(|error| network_error(StatusCode::CONFLICT, "Cannot start network", Some(&error)))?;

    let row = crate::db::BncNetworkRow {
        kind,
        name: req.name.clone(),
        addr: req.addr.clone(),
        tls: req.tls,
        nick: req.nick.clone(),
        realname: (kind == NetworkKind::Irc).then(|| req.realname.clone()),
        autojoin: req.autojoin.clone(),
        sasl_account: stored_account,
        sasl_password_sealed: sealed_password,
        enabled: true,
    };
    let pool = state.pool.as_ref().expect("caller checked the pool");
    // The per-account network cap is enforced atomically inside
    // `create_bnc_network` (count + insert in one FOR UPDATE transaction), so
    // there is no racy list-then-insert here — two concurrent creates can't both
    // slip past cap-1 and each spawn an always-on driver.
    let _mutation = registry.mutation_guard().await;
    match crate::db::create_bnc_network(pool, account, &row).await {
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
    registry.add(Some(account), &req.name, driver);
    audit_network_mutation(
        state,
        account,
        "NETWORK_CREATE",
        account,
        &req.name,
        kind.as_db_str(),
    )
    .await;
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
/// stream attach playback replays. A running driver provides its live bounded
/// buffer; a stopped driver falls back to persisted history.
pub(super) async fn network_buffer(
    State(state): State<Arc<AppState>>,
    Authenticated(account): Authenticated,
    Path(name): Path<String>,
    axum::extract::Query(params): axum::extract::Query<BufferQuery>,
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
    let limit = match bounded_query_limit(params.limit, 200, 1000, "buffer") {
        Ok(limit) => limit,
        Err(response) => return response,
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
    #[serde(default)]
    pub(super) realname: Option<String>,
    #[serde(default)]
    pub(super) autojoin: Vec<String>,
    pub(super) credentials: UpdateNetworkCredentials,
}

#[derive(serde::Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum UpdateNetworkCredentials {
    Keep,
    Remove,
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
    Authenticated(account): Authenticated,
    Path(name): Path<String>,
    JsonBody(req): JsonBody<UpdateNetwork>,
) -> Response {
    let Some(registry) = &state.bnc_registry else {
        return problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None);
    };
    let credentials = match &req.credentials {
        UpdateNetworkCredentials::Keep => NetworkCredentialUpdate::Keep,
        UpdateNetworkCredentials::Remove => NetworkCredentialUpdate::Remove,
        UpdateNetworkCredentials::Set { account, password } => NetworkCredentialUpdate::Set {
            account: account.as_deref(),
            password: password.as_deref(),
        },
    };
    if let Err(error) = update_network_core(
        &state,
        registry,
        &account,
        &name,
        &req.addr,
        req.tls,
        &req.nick,
        req.realname.as_deref(),
        &req.autojoin,
        credentials,
    )
    .await
    {
        return error.into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

/// Persist a network's enabled flag and start or stop its always-on driver.
/// Enabling builds from the stored row first, so a missing key/factory failure
/// cannot require a compensating database rollback.
pub(super) async fn set_network_enabled_core(
    state: &AppState,
    registry: &crate::bouncer::Registry,
    actor: &str,
    account: &str,
    name: &str,
    enabled: bool,
) -> Result<(), NetworkMutationError> {
    let _mutation = registry.mutation_guard().await;
    let pool = pool_of(state);

    let driver = if enabled {
        let row = match crate::db::get_bnc_network(pool, account, name).await {
            Ok(Some(row)) => row,
            Ok(None) => {
                return Err(network_error(
                    StatusCode::NOT_FOUND,
                    "No such network",
                    None,
                ));
            }
            Err(error) => {
                eprintln!("http: network enable lookup failed: {error}");
                return Err(network_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Database unavailable",
                    None,
                ));
            }
        };
        prospective_network_driver(state, account, &row, true, false)?
    } else {
        None
    };

    require_network_updated(
        crate::db::set_bnc_network_enabled(pool, account, name, enabled).await,
        "enable/disable failed",
    )?;
    if let Some(driver) = driver {
        registry.add(Some(account), name, driver);
    } else {
        registry.remove(Some(account), name).await;
    }
    audit_network_mutation(
        state,
        actor,
        "NETWORK_TOGGLE",
        account,
        name,
        if enabled { "enabled" } else { "disabled" },
    )
    .await;
    Ok(())
}

/// Delete one owner-scoped network and stop its driver under the same mutation
/// gate used by create/edit/toggle, so concurrent control-plane operations
/// cannot resurrect a driver whose durable row was removed.
pub(super) async fn delete_network_core(
    state: &AppState,
    registry: &crate::bouncer::Registry,
    account: &str,
    name: &str,
) -> Result<(), NetworkMutationError> {
    let _mutation = registry.mutation_guard().await;
    editable_network(state, account, name, "delete").await?;
    require_network_updated(
        crate::db::delete_bnc_network(pool_of(state), account, name).await,
        "delete failed",
    )?;
    registry.remove(Some(account), name).await;
    audit_network_mutation(state, account, "NETWORK_DELETE", account, name, "").await;
    Ok(())
}

/// Enable or disable one of the caller's networks (REST): persist the flag and
/// start/stop its always-on driver.
pub(super) async fn patch_network(
    State(state): State<Arc<AppState>>,
    Authenticated(account): Authenticated,
    Path(name): Path<String>,
    JsonBody(req): JsonBody<PatchNetwork>,
) -> Response {
    let Some(registry) = &state.bnc_registry else {
        return problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None);
    };
    if let Err(error) =
        set_network_enabled_core(&state, registry, &account, &account, &name, req.enabled).await
    {
        return error.into_response();
    }
    axum::Json(NetworkEnabledResponse {
        name,
        enabled: req.enabled,
    })
    .into_response()
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
    if let Err(error) =
        set_network_enabled_core(&state, registry, &actor, &owner, &name, req.enabled).await
    {
        return error.into_response();
    }
    json_no_store(AdminNetworkEnabledResponse {
        owner,
        name,
        enabled: req.enabled,
    })
}

/// Delete one of the caller's networks and stop its driver.
pub(super) async fn delete_network(
    State(state): State<Arc<AppState>>,
    Authenticated(account): Authenticated,
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
        BufferQuery, CreateNetwork, IRC_NETWORK_PRESETS, PreflightNetwork, network_name_ok,
        runtime_response, upstream_addr_is_internal, validate_irc_upstream,
    };

    #[test]
    fn network_creation_is_complete_and_kind_specific() {
        let irc = r#"{"kind":"irc","name":"libera","addr":"irc.libera.chat:6697","tls":true,"nick":"alice","realname":"Alice","autojoin":[]}"#;
        assert!(serde_json::from_str::<CreateNetwork>(irc).is_ok());
        assert!(serde_json::from_str::<CreateNetwork>(
            r#"{"name":"implicit","addr":"irc.example:6697","tls":true,"nick":"alice","realname":"Alice","autojoin":[]}"#
        )
        .is_err());
        assert!(serde_json::from_str::<CreateNetwork>(
            r#"{"kind":"irc","name":"incomplete","addr":"irc.example:6697","nick":"alice","realname":"Alice","autojoin":[]}"#
        )
        .is_err());
        assert!(serde_json::from_str::<CreateNetwork>(
            r#"{"kind":"discord","name":"wrong","addr":"","tls":true,"nick":"alice","autojoin":[],"sasl_password":"token"}"#
        )
        .is_err());
    }

    #[test]
    fn preflight_requires_explicit_transport_and_identity() {
        assert!(
            serde_json::from_str::<PreflightNetwork>(
                r#"{"addr":"irc.example:6697","tls":true,"nick":"alice","realname":"Alice"}"#
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
    }

    #[test]
    fn public_irc_presets_are_safe_tls_endpoints() {
        assert!(
            IRC_NETWORK_PRESETS
                .iter()
                .any(|preset| preset.id == "libera"),
            "Libera is the primary interop target"
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

    #[test]
    fn malformed_irc_upstream_is_rejected_before_it_can_be_persisted() {
        for addr in ["irc.example", "irc.example:0", "irc.example:not-a-port"] {
            let error = validate_irc_upstream(addr, "alice", None, &[])
                .expect_err("malformed address must fail");
            assert!(error.message().contains("host:port"), "{addr}: {error:?}");
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
        // Path-traversal segments.
        assert!(!network_name_ok("."));
        assert!(!network_name_ok(".."));
    }

    #[test]
    fn internal_upstream_addresses_are_refused() {
        // The cloud link-local metadata range, unspecified, multicast, broadcast
        // and documentation ranges are refused so a tenant can't make the server
        // dial them — none is ever a legitimate IRC upstream.
        assert!(upstream_addr_is_internal("169.254.169.254:80")); // cloud metadata
        assert!(upstream_addr_is_internal("0.0.0.0:6667"));
        assert!(upstream_addr_is_internal("255.255.255.255:6667")); // broadcast
        assert!(upstream_addr_is_internal("[fe80::1]:6697")); // v6 link-local
        assert!(upstream_addr_is_internal("203.0.113.7:6697")); // TEST-NET-3 (documentation)
        // V4-mapped V6 literals connect to the V4 address at the kernel, so the
        // mapped spelling of a blocked target must be caught too — the metadata
        // endpoint written as `::ffff:169.254.169.254` was the SSRF bypass.
        assert!(upstream_addr_is_internal("[::ffff:169.254.169.254]:80"));
        assert!(upstream_addr_is_internal("[::ffff:0.0.0.0]:6667"));
        // The mapped form of an *allowed* address stays allowed (canonicalized to
        // the V4 loopback/private rules, not the V6 ones).
        assert!(!upstream_addr_is_internal("[::ffff:127.0.0.1]:6667"));
        assert!(!upstream_addr_is_internal("[::ffff:10.0.0.5]:6667"));
        // Loopback and private ranges ARE allowed: a self-hosted / LAN IRC
        // upstream (including 127.0.0.1) is a first-class use case.
        assert!(!upstream_addr_is_internal("127.0.0.1:6667"));
        assert!(!upstream_addr_is_internal("[::1]:6697"));
        assert!(!upstream_addr_is_internal("10.0.0.5:6667"));
        assert!(!upstream_addr_is_internal("192.168.1.10:6667"));
        assert!(!upstream_addr_is_internal("[fc00::1]:6697")); // v6 unique-local (private)
        // Real public IPs and hostnames are allowed (the dialer resolves names).
        assert!(!upstream_addr_is_internal("93.184.216.34:6697"));
        assert!(!upstream_addr_is_internal("irc.libera.chat:6697"));
    }

    #[test]
    fn bridge_url_addr_ssrf_is_classified() {
        // A bridge base is a URL. An IP-literal host in URL form must be
        // classified the same as `host:port` — the metadata endpoint reached via
        // `http://169.254.169.254` bypassed the check before (URL didn't parse as
        // host:port) and was never vetted by the HTTP client's named-host-only
        // resolver.
        assert!(upstream_addr_is_internal("http://169.254.169.254"));
        assert!(upstream_addr_is_internal("https://169.254.169.254/gateway"));
        assert!(upstream_addr_is_internal(
            "http://169.254.169.254:8443/x?y=1"
        ));
        assert!(upstream_addr_is_internal("https://[fe80::1]/api"));
        assert!(upstream_addr_is_internal("http://[::ffff:169.254.169.254]"));
        // A real homeserver / API base (hostname, or an allowed private literal).
        assert!(!upstream_addr_is_internal("https://matrix.org"));
        assert!(!upstream_addr_is_internal("https://slack.com/api"));
        assert!(!upstream_addr_is_internal("http://127.0.0.1:8008")); // self-hosted, allowed
        assert!(!upstream_addr_is_internal("http://192.168.1.10:8008")); // LAN, allowed
    }
}
