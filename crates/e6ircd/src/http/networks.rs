//! Per-account BNC networks and their buffers.

use super::*;

// ---- per-account BNC networks -------------------------------------------

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
    /// Upstream SASL account + password (plaintext over the API; stored
    /// sealed). Both or neither.
    #[serde(default)]
    pub(super) sasl_account: Option<String>,
    #[serde(default)]
    pub(super) sasl_password: Option<String>,
}

/// The account's own networks (metadata only — never the secret).
pub(super) async fn list_networks(
    State(state): State<Arc<AppState>>,
    Authenticated(account): Authenticated,
) -> Response {
    let Some(registry) = &state.bnc_registry else {
        return problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None);
    };
    let pool = pool_of(&state);
    match crate::db::list_bnc_networks(pool, &account).await {
        Ok(rows) => {
            let nets: Vec<serde_json::Value> = rows
                .into_iter()
                .map(|n| {
                    // Live upstream state from the always-on driver, if the
                    // registry is holding a handle for this account's own network
                    // (never a shared network of the same name).
                    let connected = registry
                        .get_owned(&account, &n.name)
                        .map(|h| h.is_connected());
                    // `sasl_account` is a public login name for IRC, but a
                    // *secret* (sealed) for a kind like Slack — never echo the
                    // sealed ciphertext; expose only its presence, like the
                    // password. IRC keeps returning the plaintext name.
                    let account = if n.kind.account_is_secret() {
                        serde_json::Value::Null
                    } else {
                        serde_json::json!(n.sasl_account)
                    };
                    serde_json::json!({
                        "name": n.name,
                        "kind": n.kind.as_db_str(),
                        "addr": n.addr,
                        "tls": n.tls,
                        "nick": n.nick,
                        "realname": n.realname,
                        "autojoin": n.autojoin,
                        "sasl_account": account,
                        "has_sasl_account": n.sasl_account.is_some(),
                        "has_sasl_password": n.sasl_password_sealed.is_some(),
                        "enabled": n.enabled,
                        "connected": connected,
                    })
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
        Err(response) => response,
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

pub(super) async fn create_network_core(
    state: &AppState,
    registry: &crate::bouncer::Registry,
    account: &str,
    req: &CreateNetwork,
) -> Result<(), Response> {
    // The name is the client-facing /network selector: no separator or
    // whitespace, and non-empty.
    if req.name.is_empty() || req.name.contains('/') || req.name.chars().any(char::is_whitespace) {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "Invalid network name",
            Some("name must be non-empty and contain no '/' or whitespace"),
        ));
    }
    use crate::config::NetworkKind;
    let kind = req.kind;
    // A bridge kind can only run on a binary built with its feature, and `local`
    // is not creatable as a bouncer network — reject up front (before any insert)
    // rather than persist a row whose driver could never start.
    if !kind_feature_available(kind) {
        return Err(problem(
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
        return Err(problem(
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
    // `nick`/`realname`/`autojoin` are interpolated into NICK/USER/JOIN lines to
    // the upstream; a CR/LF would inject a second command. Reject it at the
    // boundary (this only affects the caller's own upstream, but a line-injection
    // primitive should never be constructible). Bound every field so a caller
    // can't store an oversized value or an unbounded autojoin list.
    let too_long = req.name.len() > 64
        || req.addr.len() > 255
        || req.nick.len() > 64
        || req.realname.as_ref().is_some_and(|r| r.len() > 128)
        || req.autojoin.len() > 64
        || req.autojoin.iter().any(|c| c.len() > 64)
        // The SASL pair is sealed and stored per network; unbounded, a caller
        // could persist megabytes of dead secret per row. 512 accommodates
        // long OAuth-style tokens used as SASL passwords.
        || req.sasl_account.as_ref().is_some_and(|a| a.len() > 255)
        || req.sasl_password.as_ref().is_some_and(|p| p.len() > 512);
    if too_long {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "Field too long",
            Some("network fields exceed their length bounds"),
        ));
    }
    let has_control = |s: &str| s.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0);
    // The SASL pair is included because PLAIN uses NUL as its field separator:
    // a NUL inside either value would shift the authzid/authcid/passwd fields
    // the upstream parses — the same injection-primitive class as CR/LF in a
    // command line.
    if has_control(&req.name)
        || has_control(&req.addr)
        || has_control(&req.nick)
        || req.realname.as_deref().is_some_and(has_control)
        || req.autojoin.iter().any(|c| has_control(c))
        || req.sasl_account.as_deref().is_some_and(has_control)
        || req.sasl_password.as_deref().is_some_and(has_control)
    {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "Invalid character",
            Some("nick, realname, autojoin and SASL fields must not contain CR, LF or NUL"),
        ));
    }
    // Refuse an upstream address that points at an obviously-internal target
    // (loopback, the cloud link-local metadata range, unspecified, multicast).
    // Any authenticated user can create a network that the server then dials on
    // a reconnect loop, so without this a tenant could probe 169.254.169.254 and
    // similar. RFC-1918 private ranges are allowed, since a self-hosted upstream
    // on a LAN is legitimate. (Hostnames are resolved by the dialer; this bounds
    // the IP-literal vector reported.)
    if upstream_addr_is_internal(&req.addr) {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "Disallowed upstream address",
            Some("addr must not be a loopback, link-local, unspecified or multicast IP"),
        ));
    }
    // For IRC the SASL pair is both-or-neither (account = login name, password =
    // secret). Bridges don't follow that rule — their required fields are checked
    // above — so this only applies to IRC.
    if kind == NetworkKind::Irc && req.sasl_account.is_some() != req.sasl_password.is_some() {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "Incomplete upstream SASL",
            Some("provide both sasl_account and sasl_password, or neither"),
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
            return Err(problem(
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
    match crate::db::create_bnc_network(pool, account, &row).await {
        Ok(_) => {}
        Err(crate::db::DbError::TooManyNetworks) => {
            return Err(problem(
                StatusCode::CONFLICT,
                "Network limit reached",
                Some("this account has reached its maximum number of networks"),
            ));
        }
        Err(crate::db::DbError::DuplicateNetwork(_)) => {
            return Err(problem(
                StatusCode::CONFLICT,
                "Network already exists",
                None,
            ));
        }
        Err(e) => {
            eprintln!("http: network create failed: {e}");
            return Err(problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            ));
        }
    }

    // Build the driver from the *plaintext* creds (the row stored the sealed
    // forms) via the one feature-gated factory. Feature availability was checked
    // up front, so an error here is unexpected — undo the insert rather than
    // leave a row whose driver never started.
    let driver = match crate::bouncer::build_driver(
        kind,
        req.addr.clone(),
        req.tls,
        req.nick.clone(),
        req.realname.clone().unwrap_or_else(|| req.nick.clone()),
        req.autojoin.clone(),
        1000,
        req.sasl_account.clone(),
        req.sasl_password.clone(),
    ) {
        Ok(driver) => driver,
        Err(e) => {
            if let Err(re) = crate::db::delete_bnc_network(pool, account, &req.name).await {
                eprintln!("http: rollback after driver-build failure failed: {re}");
            }
            return Err(problem(
                StatusCode::CONFLICT,
                "Cannot start network",
                Some(&e),
            ));
        }
    };
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
    let limit = params.limit.unwrap_or(200).clamp(1, 1000) as i64;
    // Buffers are stored under the casefolded owner (the registry key), so the
    // read has to fold too or it would look up a spelling nothing writes.
    let owner = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(&account);
    match crate::db::recent_bnc_lines(pool, &owner, &name, limit).await {
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

/// Enable or disable one of the caller's networks: persist the flag and
/// start (enable) or stop (disable) its always-on driver. Config and
/// buffers are untouched — a disabled network can be re-enabled later.
pub(super) async fn patch_network(
    State(state): State<Arc<AppState>>,
    Authenticated(account): Authenticated,
    Path(name): Path<String>,
    JsonBody(req): JsonBody<PatchNetwork>,
) -> Response {
    let Some(registry) = &state.bnc_registry else {
        return problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None);
    };
    let pool = pool_of(&state);

    // Persist the flag first; a miss means the caller owns no such network.
    match crate::db::set_bnc_network_enabled(pool, &account, &name, req.enabled).await {
        Ok(true) => {}
        Ok(false) => return problem(StatusCode::NOT_FOUND, "No such network", None),
        Err(e) => {
            eprintln!("http: network enable/disable failed: {e}");
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            );
        }
    }

    if req.enabled {
        // Rebuild the driver from the persisted row and (re)start it.
        let row = match crate::db::get_bnc_network(pool, &account, &name).await {
            Ok(Some(row)) => row,
            // We just updated it; a miss here means a concurrent delete.
            Ok(None) => return problem(StatusCode::NOT_FOUND, "No such network", None),
            Err(e) => {
                eprintln!("http: network reload failed: {e}");
                return problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Database unavailable",
                    None,
                );
            }
        };
        let driver =
            match crate::bouncer::driver_from_row(&row, state.secret_key.as_deref(), &account) {
                Ok(driver) => driver,
                Err(e) => {
                    // Can't start it — undo the enable so the flag matches reality.
                    if let Err(re) =
                        crate::db::set_bnc_network_enabled(pool, &account, &name, false).await
                    {
                        eprintln!("http: failed to roll back enable after start error: {re}");
                    }
                    return problem(StatusCode::CONFLICT, "Cannot start network", Some(&e));
                }
            };
        registry.add(Some(&account), &name, driver);
    } else {
        registry.remove(Some(&account), &name);
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
    let pool = pool_of(&state);
    match crate::db::delete_bnc_network(pool, &account, &name).await {
        Ok(true) => {
            registry.remove(Some(&account), &name);
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => problem(StatusCode::NOT_FOUND, "No such network", None),
        Err(e) => {
            eprintln!("http: network delete failed: {e}");
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::upstream_addr_is_internal;

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
