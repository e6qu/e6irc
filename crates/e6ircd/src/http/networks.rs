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
}

impl NetworkMutationError {
    pub(super) fn new(status: StatusCode, title: &'static str, detail: Option<&str>) -> Self {
        Self {
            status,
            title,
            detail: detail.map(str::to_string),
        }
    }

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

#[derive(Deserialize)]
pub(super) struct CreateNetwork {
    /// Driver kind; defaults to `irc`. A bridge kind requires its build feature.
    #[serde(default)]
    pub(super) kind: crate::config::NetworkKind,
    pub(super) name: String,
    pub(super) addr: String,
    #[serde(default)]
    pub(super) tls: bool,
    pub(super) nick: String,
    #[serde(default)]
    pub(super) realname: Option<String>,
    #[serde(default)]
    pub(super) autojoin: Vec<String>,
    /// Kind-specific account/login field. Plaintext over the API; sealed when
    /// the selected driver treats it as a secret.
    #[serde(default)]
    pub(super) sasl_account: Option<String>,
    #[serde(default)]
    pub(super) sasl_password: Option<String>,
}

fn runtime_json(runtime: &crate::bouncer::NetworkRuntimeSnapshot) -> serde_json::Value {
    let timestamp =
        |value: Option<e6irc_proto::time::Millis>| value.map(e6irc_proto::time::server_time);
    serde_json::json!({
        "state": runtime.lifecycle.as_str(),
        "state_changed_at": e6irc_proto::time::server_time(runtime.state_changed_at),
        "connected_at": timestamp(runtime.connected_at),
        "last_input_at": timestamp(runtime.last_input_at),
        "last_output_at": timestamp(runtime.last_output_at),
        "last_error_at": timestamp(runtime.last_error_at),
        "last_error": runtime.last_error.map(|error| serde_json::json!({
            "code": error.code(),
            "summary": error.summary(),
        })),
        "connect_latency_ms": runtime.connect_latency_ms,
        "connection_attempts": runtime.connection_attempts,
        "errors": runtime.errors,
        "attached_clients": runtime.attached_clients,
        "traffic": {
            "lines_in": runtime.lines_in,
            "bytes_in": runtime.bytes_in,
            "lines_out": runtime.lines_out,
            "bytes_out": runtime.bytes_out,
        },
        "buffer": {
            "lines": runtime.buffer_lines,
            "capacity": runtime.buffer_capacity,
        },
    })
}

fn network_json(
    network: crate::db::BncNetworkRow,
    runtime: Option<&crate::bouncer::NetworkRuntimeSnapshot>,
) -> serde_json::Value {
    let has_sasl_account = network.sasl_account.is_some();
    let has_sasl_password = network.sasl_password_sealed.is_some();
    let account = if network.kind.account_is_secret() {
        serde_json::Value::Null
    } else {
        serde_json::json!(&network.sasl_account)
    };
    serde_json::json!({
        "name": network.name,
        "kind": network.kind.as_db_str(),
        "addr": network.addr,
        "tls": network.tls,
        "nick": network.nick,
        "realname": network.realname,
        "autojoin": network.autojoin,
        "sasl_account": account,
        "has_sasl_account": has_sasl_account,
        "has_sasl_password": has_sasl_password,
        "enabled": network.enabled,
        "connected": runtime.map(|r| {
            r.lifecycle == crate::bouncer::NetworkLifecycle::Connected
        }),
        "runtime": runtime.map(runtime_json),
    })
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
        return (
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::json!({ "networks": [] }).to_string(),
        )
            .into_response();
    };
    let pool = pool_of(&state);
    match crate::db::list_bnc_networks(pool, &account).await {
        Ok(rows) => {
            let nets: Vec<serde_json::Value> = rows
                .into_iter()
                .map(|n| {
                    let handle = registry.get_owned(&account, &n.name);
                    let runtime = handle.as_ref().map(|handle| handle.runtime_snapshot());
                    network_json(n, runtime.as_ref())
                })
                .collect();
            (
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::json!({ "networks": nets }).to_string(),
            )
                .into_response()
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
    (
        [(header::CONTENT_TYPE, "application/json")],
        network_json(network, runtime.as_ref()).to_string(),
    )
        .into_response()
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

    match create_network_core(&state, registry, &account, &req).await {
        Ok(()) => (
            StatusCode::CREATED,
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::json!({ "name": req.name, "attach": format!("{}/{}", account, req.name) })
                .to_string(),
        )
            .into_response(),
        Err(error) => error.into_response(),
    }
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
    if addr.len() > 255
        || nick.len() > 64
        || realname.is_some_and(|r| r.len() > 128)
        || autojoin.len() > 64
        || autojoin.iter().any(|c| c.len() > 64)
    {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Field too long",
            Some("network fields exceed their length bounds"),
        ));
    }
    let has_control = |s: &str| s.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0);
    if has_control(addr)
        || has_control(nick)
        || realname.is_some_and(has_control)
        || autojoin.iter().any(|c| has_control(c))
    {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Invalid character",
            Some("addr, nick, realname and autojoin must not contain CR, LF or NUL"),
        ));
    }
    if upstream_addr_is_internal(addr) {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Disallowed upstream address",
            Some(
                "addr must not be a link-local, unspecified, multicast, broadcast, or documentation IP",
            ),
        ));
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
            Some("addr and nick are required"),
        ));
    }
    if !crate::bouncer::validate_irc_upstream_addr(addr) {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Invalid upstream address",
            Some("addr must be host:port with a nonzero numeric port; bracket IPv6 addresses"),
        ));
    }
    check_upstream_bounds(addr, nick, realname, autojoin)
}

/// Which stored driver kinds a mutation surface is allowed to edit. The IRC and
/// Integrations forms use disjoint variants so posting one form to another
/// kind's URL cannot reinterpret its generic storage columns.
#[derive(Clone, Copy)]
pub(super) enum EditableNetworkKind {
    Any,
    Irc,
    Bridge,
}

fn editable_kind_accepts(
    editable_kind: EditableNetworkKind,
    kind: crate::config::NetworkKind,
) -> bool {
    match editable_kind {
        EditableNetworkKind::Any => true,
        EditableNetworkKind::Irc => kind == crate::config::NetworkKind::Irc,
        EditableNetworkKind::Bridge => kind.is_bridge(),
    }
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
    editable_kind: EditableNetworkKind,
    addr: &str,
    tls: bool,
    nick: &str,
    realname: Option<&str>,
    autojoin: &[String],
    credentials: NetworkCredentialUpdate<'_>,
) -> Result<(), NetworkMutationError> {
    let _mutation = registry.mutation_guard().await;
    let pool = pool_of(state);
    let mut row = match crate::db::get_bnc_network(pool, account, name).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return Err(network_error(
                StatusCode::NOT_FOUND,
                "No such network",
                None,
            ));
        }
        Err(error) => {
            eprintln!("http: network update lookup: {error}");
            return Err(network_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            ));
        }
    };
    if !editable_kind_accepts(editable_kind, row.kind) {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Wrong network editor",
            Some(if row.kind.is_bridge() {
                "bridges are managed on the Integrations page"
            } else {
                "IRC networks are managed on the BNC networks page"
            }),
        ));
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
        registry.add(Some(account), name, driver);
    }
    Ok(())
}

pub(super) async fn create_network_core(
    state: &AppState,
    registry: &crate::bouncer::Registry,
    account: &str,
    req: &CreateNetwork,
) -> Result<(), NetworkMutationError> {
    // The name is the client-facing /network selector; see network_name_ok.
    if !network_name_ok(&req.name) {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Invalid network name",
            Some(
                "name must be non-empty, not '.'/'..', and use only letters, digits, '-', '_' or '.'",
            ),
        ));
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
    // Per-kind required fields (mirrors the config-file validation): an IRC/Matrix
    // upstream needs an address and nick; every bridge needs its secret token(s).
    let missing = match kind {
        NetworkKind::Irc => req.addr.is_empty() || req.nick.is_empty(),
        NetworkKind::Matrix => {
            req.addr.is_empty() || req.nick.is_empty() || req.sasl_password.is_none()
        }
        NetworkKind::Discord => req.sasl_password.is_none(),
        NetworkKind::Slack => req.sasl_account.is_none() || req.sasl_password.is_none(),
        NetworkKind::Local => true,
    };
    if missing {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Missing required fields for this network kind",
            Some(match kind {
                NetworkKind::Matrix => {
                    "matrix requires addr (homeserver), nick (user), sasl_password (password)"
                }
                NetworkKind::Discord => "discord requires sasl_password (bot token)",
                NetworkKind::Slack => {
                    "slack requires sasl_account (bot token) and sasl_password (app token)"
                }
                _ => "addr and nick are required",
            }),
        ));
    }
    // Bound + injection-check + SSRF-check the connection/identity fields (the
    // subset shared with the edit path). `addr`/`nick`/`realname`/`autojoin` are
    // interpolated into NICK/USER/JOIN lines, so a CR/LF/NUL there is a
    // line-injection primitive; `addr` is SSRF-vetted; all are length-bounded.
    if kind == NetworkKind::Irc {
        validate_irc_upstream(&req.addr, &req.nick, req.realname.as_deref(), &req.autojoin)?;
    } else {
        validate_bridge_upstream(
            kind,
            &req.addr,
            req.tls,
            &req.nick,
            req.realname.as_deref(),
            &req.autojoin,
        )?;
    }
    // Fields that are create-only (the name) or SASL-specific (bounds + the NUL
    // check that matters because PLAIN uses NUL as its field separator, and the
    // sealed-secret size cap) are checked here rather than in the shared helper.
    if req.name.len() > 64 {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Field too long",
            Some("network names are limited to 64 bytes"),
        ));
    }
    if let Some(account) = req.sasl_account.as_deref() {
        validate_credential_field(account, 255)?;
    }
    if let Some(password) = req.sasl_password.as_deref() {
        validate_credential_field(password, 512)?;
    }
    // For IRC the SASL pair is both-or-neither (account = login name, password =
    // secret). Bridges don't follow that rule — their required fields are checked
    // above — so this only applies to IRC.
    if kind == NetworkKind::Irc && req.sasl_account.is_some() != req.sasl_password.is_some() {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Incomplete upstream SASL",
            Some("provide both sasl_account and sasl_password, or neither"),
        ));
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
        req.realname.clone().unwrap_or_else(|| req.nick.clone()),
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
        realname: req.realname.clone(),
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
pub(super) struct BufferQuery {
    pub(super) limit: Option<usize>,
}

/// Recent upstream lines the bouncer buffered for one of the caller's
/// networks, oldest-first — the same backlog attach playback replays.
/// Served from the persisted buffer, so it works whether or not the
/// network's driver is currently running.
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
    // The DB buffer API canonicalizes the owner/network composite key, matching
    // the live registry even when this URL uses a different case.
    match crate::db::recent_bnc_lines(pool, &account, &name, limit).await {
        Ok(lines) => (
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::json!({ "lines": lines }).to_string(),
        )
            .into_response(),
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
        EditableNetworkKind::Any,
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
        registry.remove(Some(account), name);
    }
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
    editable_kind: EditableNetworkKind,
) -> Result<(), NetworkMutationError> {
    let _mutation = registry.mutation_guard().await;
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
            eprintln!("http: network delete lookup: {error}");
            return Err(network_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            ));
        }
    };
    if !editable_kind_accepts(editable_kind, row.kind) {
        return Err(network_error(
            StatusCode::BAD_REQUEST,
            "Wrong network editor",
            Some(if row.kind.is_bridge() {
                "bridges are managed on the Integrations page"
            } else {
                "IRC networks are managed on the BNC networks page"
            }),
        ));
    }
    require_network_updated(
        crate::db::delete_bnc_network(pool_of(state), account, name).await,
        "delete failed",
    )?;
    registry.remove(Some(account), name);
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
        set_network_enabled_core(&state, registry, &account, &name, req.enabled).await
    {
        return error.into_response();
    }
    (
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::json!({ "name": name, "enabled": req.enabled }).to_string(),
    )
        .into_response()
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
    match delete_network_core(&state, registry, &account, &name, EditableNetworkKind::Any).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        IRC_NETWORK_PRESETS, network_name_ok, runtime_json, upstream_addr_is_internal,
        validate_irc_upstream,
    };

    #[test]
    fn runtime_json_exposes_only_the_safe_failure_classification() {
        let (handle, ends) = crate::bouncer::NetworkHandle::channels(8);
        ends.emit(crate::bouncer::ConnectionEvent::Reconnecting(
            crate::bouncer::NetworkFailure::SecureConnectionFailed,
        ));
        let json = runtime_json(&handle.runtime_snapshot());
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
