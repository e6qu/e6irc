//! Who a client is, as every per-client decision keys it: its canonical
//! address ([`ClientIp`]), the slot a per-address limit charges it to
//! ([`PeerLimitKey`]), the per-address connection cap ([`ConnLimiter`]), and
//! the summarised log of refused peers ([`PeerRefusalLog`]).

use std::sync::Arc;

/// A client's address as every per-client decision keys it: a limiter slot, a
/// refusal summary, a rate bucket, a trusted-proxy match, a session's host
/// (what WHOIS shows and a DLINE or KLINE matches). A dual-stack (`[::]`)
/// listener presents every IPv4 client as IPv4-mapped IPv6
/// (`::ffff:a.b.c.d`); the constructor canonicalizes that to the IPv4 form, so
/// one address can never be split between two spellings — two limiter
/// budgets, a ban written in natural IPv4 notation that silently misses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientIp(std::net::IpAddr);

impl ClientIp {
    pub fn new(address: std::net::IpAddr) -> Self {
        Self(address.to_canonical())
    }

    pub fn ip(self) -> std::net::IpAddr {
        self.0
    }

    /// The slot every per-address limiter charges this client to; see
    /// [`PeerLimitKey`].
    pub fn limit_key(self) -> PeerLimitKey {
        PeerLimitKey::of(self.0)
    }
}

/// An address range in the spelling a [`ClientIp`] is matched in. A client's
/// address is canonical (IPv4, never IPv4-mapped IPv6), so an IPv4-mapped
/// network is its IPv4 equivalent — `::ffff:203.0.113.0/120` is
/// `203.0.113.0/24` — or it could never contain anyone. `None` for a mapped
/// network shorter than `/96`: it also spans addresses that are not
/// IPv4-mapped, so it names no IPv4 range, and no single intent. Every
/// operator-written range (a ban, a trusted proxy, a SASL-only range) goes
/// through this one conversion where it is read.
pub fn canonical_network(net: ipnet::IpNet) -> Option<ipnet::IpNet> {
    let ipnet::IpNet::V6(v6) = net else {
        return Some(net);
    };
    let Some(v4) = v6.addr().to_ipv4_mapped() else {
        return Some(net);
    };
    let prefix = v6.prefix_len().checked_sub(96)?;
    ipnet::Ipv4Net::new(v4, prefix).ok().map(ipnet::IpNet::V4)
}

impl std::fmt::Display for ClientIp {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

/// What a per-address limit counts against: an IPv4 address, or the IPv6
/// `/64` an address belongs to. One subscriber is routinely handed a whole
/// `/64` (and autoconfigured privacy addresses rotate through it), so a limiter keyed by
/// the full 128 bits gives each client 2^64 fresh budgets for the asking. Every
/// limiter — the per-address connection cap, the in-flight HTTP request bound,
/// the HTTP authentication bucket, and the core's account-creation bucket —
/// takes this type, and its only constructor applies the prefix, so no limiter
/// can be keyed by a raw address. The raw [`ClientIp`] stays what is logged,
/// shown, and matched by bans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerLimitKey(std::net::IpAddr);

impl PeerLimitKey {
    /// Leading IPv6 bits a limiter treats as one client.
    pub const IPV6_PREFIX_BITS: u32 = 64;

    fn of(address: std::net::IpAddr) -> Self {
        match address.to_canonical() {
            std::net::IpAddr::V4(v4) => Self(std::net::IpAddr::V4(v4)),
            std::net::IpAddr::V6(v6) => {
                let mask = u128::MAX << (128 - Self::IPV6_PREFIX_BITS);
                Self(std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                    u128::from(v6) & mask,
                )))
            }
        }
    }

    /// The key for a session opened with `host`: the host is the canonical
    /// address text the listeners pass the core ([`ClientIp`]'s spelling), or
    /// a name for an in-process session, which has no address and is counted
    /// under its name.
    pub fn for_session_host(host: &str) -> SessionLimitKey {
        match host.parse::<std::net::IpAddr>() {
            Ok(address) => SessionLimitKey::Address(Self::of(address)),
            Err(_) => SessionLimitKey::InProcess(host.to_string()),
        }
    }
}

/// Where a core session's per-address limits are charged, fixed when it opens:
/// a later `SETHOST` changes what the session shows, never what it is counted
/// against.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SessionLimitKey {
    Address(PeerLimitKey),
    /// A session opened in-process (the bouncer's `local` driver) under a name
    /// rather than an address.
    InProcess(String),
}

/// A refused or failed connection attempt from one peer, by class; each class
/// is summarised separately so a TLS scanner and an over-limit client from the
/// same address are two stories, not one count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerRefusal {
    PerIpLimit,
    ConnectionIdExhausted,
    SocketSetup,
    TlsHandshakeFailed,
    TlsHandshakeTimedOut,
    HttpHeaderTimedOut,
    UnusableForwardedFor,
}

impl PeerRefusal {
    const fn label(self) -> &'static str {
        match self {
            Self::HttpHeaderTimedOut => "HTTP request headers not received in time",
            Self::PerIpLimit => "per-IP connection limit reached",
            Self::ConnectionIdExhausted => "no connection identifier available",
            Self::SocketSetup => "socket setup failed",
            Self::TlsHandshakeFailed => "TLS handshake failed",
            Self::TlsHandshakeTimedOut => "TLS handshake timed out",
            Self::UnusableForwardedFor => {
                "request from a trusted proxy refused: its X-Forwarded-For is misconfigured"
            }
        }
    }
}

/// After the first line for a (peer, class), further occurrences are counted
/// and reported once per window.
const PEER_REFUSAL_LOG_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
/// Distinct (peer, class) pairs remembered at once; past it the oldest quiet
/// entries are evicted, and an entry that cannot be remembered is logged
/// immediately rather than dropped.
const PEER_REFUSAL_LOG_CAPACITY: usize = 4_096;

/// Per-peer, per-class log summariser for connection refusals. The first
/// occurrence is logged at once; within the following window the rest are only
/// counted, and the next occurrence after the window logs again with the count
/// it stands for. A scanner or a stuck client therefore costs one line per
/// minute per class, never one per attempt, while the counters the metrics
/// export are unchanged (they are incremented by the caller, not here).
pub struct PeerRefusalLog {
    window: std::time::Duration,
    entries:
        std::sync::Mutex<std::collections::HashMap<(ClientIp, PeerRefusal), PeerRefusalWindow>>,
}

#[derive(Debug, Clone, Copy)]
struct PeerRefusalWindow {
    last_logged: std::time::Instant,
    /// Occurrences since `last_logged` that were not logged.
    suppressed: u64,
}

impl PeerRefusalLog {
    pub fn new(window: std::time::Duration) -> Self {
        Self {
            window,
            entries: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Log one occurrence now, if it is this window's line.
    pub fn note(
        &self,
        peer: ClientIp,
        refusal: PeerRefusal,
        detail: Option<&dyn std::fmt::Display>,
    ) {
        if let Some(line) = self.line_at(std::time::Instant::now(), peer, refusal, detail) {
            eprintln!("{line}");
        }
    }

    /// The line to log for one occurrence at `now`, or `None` when it is
    /// counted into the open window instead.
    pub(crate) fn line_at(
        &self,
        now: std::time::Instant,
        peer: ClientIp,
        refusal: PeerRefusal,
        detail: Option<&dyn std::fmt::Display>,
    ) -> Option<String> {
        let describe = |suppressed: u64| {
            let mut line = format!("refused {peer}: {}", refusal.label());
            if let Some(detail) = detail {
                line.push_str(&format!(": {detail}"));
            }
            if suppressed > 0 {
                line.push_str(&format!(
                    " ({suppressed} more from this peer in the last {}s not logged)",
                    self.window.as_secs()
                ));
            }
            line
        };
        let mut entries = self.entries.lock().expect("peer refusal log poisoned");
        if let Some(entry) = entries.get_mut(&(peer, refusal)) {
            if now.duration_since(entry.last_logged) < self.window {
                entry.suppressed += 1;
                return None;
            }
            let suppressed = entry.suppressed;
            *entry = PeerRefusalWindow {
                last_logged: now,
                suppressed: 0,
            };
            return Some(describe(suppressed));
        }
        if entries.len() >= PEER_REFUSAL_LOG_CAPACITY {
            let window = self.window;
            entries.retain(|_, entry| now.duration_since(entry.last_logged) < window);
        }
        if entries.len() < PEER_REFUSAL_LOG_CAPACITY {
            entries.insert(
                (peer, refusal),
                PeerRefusalWindow {
                    last_logged: now,
                    suppressed: 0,
                },
            );
        }
        Some(describe(0))
    }
}

/// Per-IP concurrent-connection cap. When `max_per_ip` is `None` the
/// limiter is a no-op; otherwise it refuses connections beyond the cap
/// and releases the slot when the connection's guard drops.
#[derive(Clone)]
pub struct ConnLimiter {
    counts: Arc<std::sync::Mutex<std::collections::HashMap<PeerLimitKey, usize>>>,
    max_per_ip: Option<usize>,
    /// Per-peer admission failures are summarised here rather than logged one
    /// line per attempt; it travels with the limiter because every listener
    /// that admits peers (IRC, WS-IRC, BNC) already shares this one value.
    refusals: Arc<PeerRefusalLog>,
}

impl ConnLimiter {
    pub fn new(max_per_ip: Option<usize>) -> Self {
        Self {
            counts: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            max_per_ip,
            refusals: Arc::new(PeerRefusalLog::new(PEER_REFUSAL_LOG_WINDOW)),
        }
    }

    /// The shared per-peer refusal summariser.
    pub fn refusals(&self) -> &Arc<PeerRefusalLog> {
        &self.refusals
    }

    /// Reserve a slot for `client`'s [`PeerLimitKey`], or `None` if that key
    /// is already at the cap.
    pub fn try_acquire(&self, client: ClientIp) -> Option<ConnGuard> {
        let ip = client.limit_key();
        let Some(max) = self.max_per_ip else {
            return Some(ConnGuard { limiter: None, ip });
        };
        let mut counts = self.counts.lock().expect("conn limiter poisoned");
        let count = counts.entry(ip).or_insert(0);
        if *count >= max {
            return None;
        }
        *count += 1;
        Some(ConnGuard {
            limiter: Some(self.clone()),
            ip,
        })
    }

    fn release(&self, ip: PeerLimitKey) {
        let mut counts = self.counts.lock().expect("conn limiter poisoned");
        if let Some(c) = counts.get_mut(&ip) {
            *c -= 1;
            if *c == 0 {
                counts.remove(&ip);
            }
        }
    }
}

/// Releases its per-IP slot when the connection ends (on drop).
pub struct ConnGuard {
    limiter: Option<ConnLimiter>,
    ip: PeerLimitKey,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if let Some(limiter) = &self.limiter {
            limiter.release(self.ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One subscriber's IPv6 `/64` is one client to every per-address limit;
    /// IPv4 addresses, and an IPv4 client however the listener spells it, are
    /// counted one address each.
    #[test]
    fn per_address_limits_count_an_ipv6_slash_64_as_one_client() {
        let client = |text: &str| ClientIp::new(text.parse().unwrap());
        let limiter = ConnLimiter::new(Some(1));
        let _held = limiter
            .try_acquire(client("2001:db8:1:2::1"))
            .expect("the first connection");
        assert!(
            limiter
                .try_acquire(client("2001:db8:1:2:ffff::2"))
                .is_none(),
            "another address in the same /64 shares the budget"
        );
        let _other = limiter
            .try_acquire(client("2001:db8:1:3::1"))
            .expect("the next /64 is another client");
        let _v4 = limiter
            .try_acquire(client("192.0.2.1"))
            .expect("an IPv4 client");
        assert!(limiter.try_acquire(client("::ffff:192.0.2.1")).is_none());
        let _neighbour = limiter
            .try_acquire(client("192.0.2.2"))
            .expect("each IPv4 address is its own client");
        assert_eq!(
            client("2001:db8:1:2:aaaa:bbbb:cccc:dddd").limit_key(),
            client("2001:db8:1:2::").limit_key()
        );
        assert_eq!(
            PeerLimitKey::for_session_host("2001:db8:1:2::9"),
            SessionLimitKey::Address(client("2001:db8:1:2::1").limit_key())
        );
        assert_eq!(
            PeerLimitKey::for_session_host("local"),
            SessionLimitKey::InProcess("local".to_string())
        );
    }

    #[test]
    fn peer_refusals_log_once_per_window_with_the_suppressed_count() {
        use std::time::{Duration, Instant};
        let log = PeerRefusalLog::new(Duration::from_secs(60));
        let peer = ClientIp::new("203.0.113.9".parse().unwrap());
        let other = ClientIp::new("203.0.113.10".parse().unwrap());
        let start = Instant::now();
        let first = log
            .line_at(start, peer, PeerRefusal::PerIpLimit, None)
            .expect("the first occurrence is logged at once");
        assert_eq!(
            first,
            "refused 203.0.113.9: per-IP connection limit reached"
        );
        for i in 1..=500u64 {
            assert!(
                log.line_at(
                    start + Duration::from_millis(i),
                    peer,
                    PeerRefusal::PerIpLimit,
                    None,
                )
                .is_none(),
                "occurrence {i} inside the window must only be counted"
            );
        }
        // Another class from the same peer, and the same class from another
        // peer, are their own windows.
        let error = std::io::Error::other("bad record mac");
        assert_eq!(
            log.line_at(start, peer, PeerRefusal::TlsHandshakeFailed, Some(&error))
                .as_deref(),
            Some("refused 203.0.113.9: TLS handshake failed: bad record mac")
        );
        assert!(
            log.line_at(start, other, PeerRefusal::PerIpLimit, None)
                .is_some()
        );
        let later = log
            .line_at(
                start + Duration::from_secs(60),
                peer,
                PeerRefusal::PerIpLimit,
                None,
            )
            .expect("the window has passed");
        assert_eq!(
            later,
            "refused 203.0.113.9: per-IP connection limit reached (500 more from this peer in \
             the last 60s not logged)"
        );
        assert!(
            log.line_at(
                start + Duration::from_secs(61),
                peer,
                PeerRefusal::PerIpLimit,
                None,
            )
            .is_none(),
            "a new window opened at the second line"
        );
    }

    #[test]
    fn peer_refusal_log_is_bounded_and_never_drops_a_first_line() {
        use std::time::{Duration, Instant};
        let log = PeerRefusalLog::new(Duration::from_secs(60));
        let start = Instant::now();
        for i in 0..PEER_REFUSAL_LOG_CAPACITY as u32 {
            let peer = ClientIp::new(std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                0x0A00_0000 + i,
            )));
            assert!(
                log.line_at(start, peer, PeerRefusal::PerIpLimit, None)
                    .is_some()
            );
        }
        // Full, and every entry's window is still open: the newcomer is logged
        // (not remembered), and logged again on its next attempt.
        let newcomer = ClientIp::new("198.51.100.1".parse().unwrap());
        assert!(
            log.line_at(start, newcomer, PeerRefusal::PerIpLimit, None)
                .is_some()
        );
        assert!(
            log.line_at(start, newcomer, PeerRefusal::PerIpLimit, None)
                .is_some(),
            "an entry the bound could not remember must not be silently dropped"
        );
        assert!(log.entries.lock().unwrap().len() <= PEER_REFUSAL_LOG_CAPACITY);
        // Once the windows have passed, the quiet entries are evicted for it.
        assert!(
            log.line_at(
                start + Duration::from_secs(61),
                newcomer,
                PeerRefusal::PerIpLimit,
                None,
            )
            .is_some()
        );
        assert!(
            log.entries
                .lock()
                .unwrap()
                .contains_key(&(newcomer, PeerRefusal::PerIpLimit))
        );
    }
}
