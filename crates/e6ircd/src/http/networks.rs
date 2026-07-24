//! Per-account BNC networks and their buffers.

use super::*;

// ---- per-account BNC networks -------------------------------------------

#[derive(Deserialize)]
pub(super) struct CreateNetwork {
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
                    // registry is holding a handle for this network.
                    let connected = registry.get(&account, &n.name).map(|h| h.is_connected());
                    serde_json::json!({
                        "name": n.name,
                        "addr": n.addr,
                        "tls": n.tls,
                        "nick": n.nick,
                        "realname": n.realname,
                        "autojoin": n.autojoin,
                        "sasl_account": n.sasl_account,
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

/// The one create path: validate, seal the upstream secret, persist, and
/// start the driver. Used by both the JSON API and the account form.
/// Cap on BNC networks per account. Each network spawns an always-on driver
/// (which dials a caller-supplied address on a reconnect loop) plus a
/// persistence task, so an unbounded count is task/socket exhaustion and an
/// outbound-connection amplifier toward a third party.
pub(super) const MAX_NETWORKS_PER_ACCOUNT: usize = 32;

/// Whether `addr` (`host:port`, IPv6 bracketed) has an IP-literal host that
/// points at an obviously-internal target the server must not be tricked into
/// dialing. Loopback, link-local (cloud metadata), unspecified and multicast are
/// refused; RFC-1918 private ranges are allowed (a LAN self-host is legitimate).
/// A hostname (non-literal) returns `false` here — the concrete reported vector
/// is the IP literal; hostname resolution lives in the dialer.
fn upstream_addr_is_internal(addr: &str) -> bool {
    let host = if let Some(rest) = addr.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest) // [ipv6]:port
    } else {
        addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr)
    };
    let Ok(ip) = host.parse::<std::net::IpAddr>() else {
        return false; // hostname — not classifiable without DNS
    };
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_link_local() || v4.is_broadcast() || v4.is_documentation()
        }
        // IPv6 link-local (fe80::/10) and unique-local (fc00::/7).
        std::net::IpAddr::V6(v6) => {
            let head = v6.segments()[0];
            (head & 0xffc0) == 0xfe80 || (head & 0xfe00) == 0xfc00
        }
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
    if req.addr.is_empty() || req.nick.is_empty() {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "addr and nick are required",
            None,
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
        || req.autojoin.iter().any(|c| c.len() > 64);
    if too_long {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "Field too long",
            Some("network fields exceed their length bounds"),
        ));
    }
    let has_control = |s: &str| s.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0);
    if has_control(&req.nick)
        || req.realname.as_deref().is_some_and(has_control)
        || req.autojoin.iter().any(|c| has_control(c))
    {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "Invalid character",
            Some("nick, realname and autojoin must not contain CR, LF or NUL"),
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
    // Upstream SASL is both-or-neither.
    let upstream = match (&req.sasl_account, &req.sasl_password) {
        (Some(a), Some(p)) => Some((a.clone(), p.clone())),
        (None, None) => None,
        _ => {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                "Incomplete upstream SASL",
                Some("provide both sasl_account and sasl_password, or neither"),
            ));
        }
    };
    // Seal the upstream password for storage; requires a master key.
    let sealed = match &upstream {
        Some((_, password)) => {
            let Some(key) = &state.secret_key else {
                return Err(problem(
                    StatusCode::CONFLICT,
                    "No master key configured",
                    Some("the server cannot store upstream credentials without [secrets]"),
                ));
            };
            Some(key.seal(password))
        }
        None => None,
    };

    let row = crate::db::BncNetworkRow {
        name: req.name.clone(),
        addr: req.addr.clone(),
        tls: req.tls,
        nick: req.nick.clone(),
        realname: req.realname.clone(),
        autojoin: req.autojoin.clone(),
        sasl_account: upstream.as_ref().map(|(a, _)| a.clone()),
        sasl_password_sealed: sealed,
        enabled: true,
    };
    let pool = state.pool.as_ref().expect("caller checked the pool");
    // Bound networks per account before spawning anything.
    match crate::db::list_bnc_networks(pool, account).await {
        Ok(existing) if existing.len() >= MAX_NETWORKS_PER_ACCOUNT => {
            return Err(problem(
                StatusCode::CONFLICT,
                "Network limit reached",
                Some("this account has reached its maximum number of networks"),
            ));
        }
        Ok(_) => {}
        Err(e) => {
            eprintln!("http: network count query failed: {e}");
            return Err(problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            ));
        }
    }
    match crate::db::create_bnc_network(pool, account, &row).await {
        Ok(_) => {}
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

    registry.add(
        Some(account),
        &req.name,
        Box::new(crate::bouncer::IrcDriver::new(
            crate::bouncer::NetworkConfig {
                addr: req.addr.clone(),
                tls: req.tls,
                nick: req.nick.clone(),
                realname: req.realname.clone().unwrap_or_else(|| req.nick.clone()),
                autojoin: req.autojoin.clone(),
                buffer_cap: 1000,
                sasl: upstream,
            },
        )),
    );
    Ok(())
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
        let cfg = match crate::bouncer::network_config_from_row(&row, state.secret_key.as_deref()) {
            Ok(cfg) => cfg,
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
        registry.add(
            Some(&account),
            &name,
            Box::new(crate::bouncer::IrcDriver::new(cfg)),
        );
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
        // Loopback, the cloud link-local metadata range, unspecified and
        // multicast are refused so a tenant can't make the server dial them.
        assert!(upstream_addr_is_internal("127.0.0.1:6667"));
        assert!(upstream_addr_is_internal("169.254.169.254:80")); // cloud metadata
        assert!(upstream_addr_is_internal("0.0.0.0:6667"));
        assert!(upstream_addr_is_internal("[::1]:6697"));
        assert!(upstream_addr_is_internal("[fe80::1]:6697")); // v6 link-local
        assert!(upstream_addr_is_internal("[fc00::1]:6697")); // v6 unique-local
        // A documentation range is never a real upstream, so it's refused too.
        assert!(upstream_addr_is_internal("203.0.113.7:6697")); // TEST-NET-3
        // A real public IP and a hostname are allowed (the dialer resolves
        // hostnames); RFC-1918 is allowed for a legitimate LAN self-host.
        assert!(!upstream_addr_is_internal("93.184.216.34:6697"));
        assert!(!upstream_addr_is_internal("irc.libera.chat:6697"));
        assert!(!upstream_addr_is_internal("10.0.0.5:6667"));
        assert!(!upstream_addr_is_internal("192.168.1.10:6667"));
    }
}
