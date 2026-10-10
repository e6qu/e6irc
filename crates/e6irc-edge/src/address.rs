//! Who a client is, as every per-client decision keys it: its canonical
//! address ([`ClientIp`]), the slot a per-address limit charges it to
//! ([`PeerLimitKey`]), the per-address connection cap ([`ConnLimiter`]), and
//! the summarised log of refused peers ([`PeerRefusalLog`]), and the client
//! a trusted proxy's `X-Forwarded-For` names ([`client_ip`]).

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

impl SessionLimitKey {
    /// The host text [`PeerLimitKey::for_session_host`] maps back to this very
    /// key: how a key is carried where only text travels (a core's cut state).
    pub fn as_host(&self) -> String {
        match self {
            Self::Address(PeerLimitKey(address)) => address.to_string(),
            Self::InProcess(name) => name.clone(),
        }
    }
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
    /// A listener that reads the PROXY protocol got no header it accepts.
    ProxyHeader,
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
            Self::ProxyHeader => "connection refused: no PROXY protocol header it could take",
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

/// The proxies whose word about their clients is believed (`trusted_proxies`):
/// a forwarded address, or a PROXY protocol header. Shared, so an edge can
/// follow the list its core gives it at each link.
#[derive(Clone, Default)]
pub struct TrustedProxies(Arc<std::sync::RwLock<Vec<ipnet::IpNet>>>);

impl TrustedProxies {
    pub fn new(networks: Vec<ipnet::IpNet>) -> Self {
        Self(Arc::new(std::sync::RwLock::new(networks)))
    }

    /// Follow a new list.
    pub fn set(&self, networks: Vec<ipnet::IpNet>) {
        *self.0.write().expect("trusted proxies lock") = networks;
    }

    /// Whether `peer`, in its canonical spelling, is a trusted proxy.
    pub fn contains(&self, peer: std::net::IpAddr) -> bool {
        let peer = ClientIp::new(peer).ip();
        self.0
            .read()
            .expect("trusted proxies lock")
            .iter()
            .any(|network| network.contains(&peer))
    }
}

/// Per-IP concurrent-connection cap. With no cap (`None`) it refuses nobody;
/// otherwise it refuses connections beyond the cap and releases the slot when
/// the connection's guard drops. Every slot is counted either way, so a cap
/// set later ([`ConnLimiter::set_max`]: an edge following the core's limit)
/// counts the connections already open.
#[derive(Clone)]
pub struct ConnLimiter {
    state: Arc<std::sync::Mutex<LimiterState>>,
    /// Per-peer admission failures are summarised here rather than logged one
    /// line per attempt; it travels with the limiter because every listener
    /// that admits peers (IRC, WS-IRC, BNC) already shares this one value.
    refusals: Arc<PeerRefusalLog>,
}

struct LimiterState {
    counts: std::collections::HashMap<PeerLimitKey, usize>,
    max_per_ip: Option<usize>,
}

impl ConnLimiter {
    pub fn new(max_per_ip: Option<usize>) -> Self {
        Self {
            state: Arc::new(std::sync::Mutex::new(LimiterState {
                counts: std::collections::HashMap::new(),
                max_per_ip,
            })),
            refusals: Arc::new(PeerRefusalLog::new(PEER_REFUSAL_LOG_WINDOW)),
        }
    }

    /// The shared per-peer refusal summariser.
    pub fn refusals(&self) -> &Arc<PeerRefusalLog> {
        &self.refusals
    }

    /// Change the cap. Connections already over a lowered cap keep their
    /// slots; new ones are refused until the count is under it.
    pub fn set_max(&self, max_per_ip: Option<usize>) {
        self.state.lock().expect("conn limiter poisoned").max_per_ip = max_per_ip;
    }

    /// Reserve a slot for `client`'s [`PeerLimitKey`], or `None` if that key
    /// is already at the cap.
    pub fn try_acquire(&self, client: ClientIp) -> Option<ConnGuard> {
        let ip = client.limit_key();
        let mut state = self.state.lock().expect("conn limiter poisoned");
        let max = state.max_per_ip;
        let count = state.counts.entry(ip).or_insert(0);
        if max.is_some_and(|max| *count >= max) {
            return None;
        }
        *count += 1;
        Some(ConnGuard {
            limiter: self.clone(),
            ip,
        })
    }

    fn release(&self, ip: PeerLimitKey) {
        let mut state = self.state.lock().expect("conn limiter poisoned");
        if let Some(c) = state.counts.get_mut(&ip) {
            *c -= 1;
            if *c == 0 {
                state.counts.remove(&ip);
            }
        }
    }
}

/// Releases its per-IP slot when the connection ends (on drop).
pub struct ConnGuard {
    limiter: ConnLimiter,
    ip: PeerLimitKey,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.limiter.release(self.ip);
    }
}

/// A trusted proxy passed on an `X-Forwarded-For` entry that is not an address
/// before any client address, reading from the right: the chain it vouches for
/// is broken there (nginx writes `unix:` for a client on a Unix socket), what
/// lies left of the entry is only what the client wrote, and no client address
/// can be told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnusableForwardedFor {
    /// The trusted proxy that sent it.
    proxy: ClientIp,
    /// The entry, as sent.
    entry: String,
}

impl UnusableForwardedFor {
    /// The trusted proxy that sent the entry.
    pub fn proxy(&self) -> ClientIp {
        self.proxy
    }
}

impl std::error::Error for UnusableForwardedFor {}

impl std::fmt::Display for UnusableForwardedFor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Header text is printable ASCII, but only the proxy's own share of it
        // is its: bound what a client can put in the log line.
        let entry: String = self.entry.chars().take(64).collect();
        write!(
            formatter,
            "entry {entry:?} is not an address; the proxy must forward its \
             client's address (for nginx, `$proxy_add_x_forwarded_for` on a TCP listener)"
        )
    }
}

/// Resolve the real client IP: if the socket peer is a trusted proxy, take the
/// rightmost non-trusted `X-Forwarded-For` entry (the client the proxy chain
/// received from); otherwise the peer is the client. `X-Forwarded-For` is only consulted for
/// trusted peers so a direct client cannot spoof its IP with the header. An
/// entry that is not an address, reached before that client, refuses the
/// request ([`UnusableForwardedFor`]): skipping it would walk on into entries
/// the client wrote.
pub fn client_ip(
    peer: std::net::IpAddr,
    headers: &axum::http::HeaderMap,
    trusted: &[ipnet::IpNet],
) -> Result<ClientIp, UnusableForwardedFor> {
    // Every address is judged in its canonical spelling: a dual-stack listener
    // presents an IPv4 proxy mapped, and a proxy may forward a mapped client.
    let peer = ClientIp::new(peer);
    let is_trusted = |address: ClientIp| trusted.iter().any(|net| net.contains(&address.ip()));
    if !is_trusted(peer) {
        return Ok(peer);
    }
    // Concatenate *every* X-Forwarded-For header in header order before scanning
    // right-to-left for the first non-trusted entry (the real client the trusted
    // proxy chain saw). Reading only the first header (`get`) would miss the
    // trusted proxy's appended entry when a proxy emits a *separate* header
    // rather than merging, letting a client-supplied earlier header win — a
    // spoofed key that collapses per-IP rate limits/bans. Whole-string rsplit
    // over the joined value handles both the merged and multi-header forms.
    let joined = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(",");
    // A header with no entries at all names no client, as no header does.
    if joined.trim().is_empty() {
        return Ok(peer);
    }
    for part in joined.rsplit(',') {
        let Some(ip) = parse_forwarded_ip(part) else {
            return Err(UnusableForwardedFor {
                proxy: peer,
                entry: part.trim().to_string(),
            });
        };
        if !is_trusted(ip) {
            return Ok(ip);
        }
    }
    Ok(peer)
}

/// Whether a request reached this server over HTTPS, which only a trusted
/// proxy can say: the direct peer must be in `trusted`, and every
/// `X-Forwarded-Proto` entry it passed on — all headers, all comma-separated
/// values — must be `https`. A client's own `https` to which a plaintext hop
/// appended `http` is plaintext, and so is an entry that is not text, a
/// request with no such header, or one from any other peer: the HTTP listener
/// itself never terminates TLS.
pub fn forwarded_https(
    peer: std::net::IpAddr,
    headers: &axum::http::HeaderMap,
    trusted: &[ipnet::IpNet],
) -> bool {
    let peer = ClientIp::new(peer);
    if !trusted.iter().any(|net| net.contains(&peer.ip())) {
        return false;
    }
    let mut entries = headers
        .get_all("x-forwarded-proto")
        .iter()
        .flat_map(|value| value.to_str().unwrap_or("").split(','))
        .map(str::trim)
        .peekable();
    entries.peek().is_some() && entries.all(|entry| entry.eq_ignore_ascii_case("https"))
}

/// Parse one `X-Forwarded-For` entry to an IP, tolerating the `ip:port` and
/// bracketed-IPv6 forms some proxies emit (`203.0.113.9:443`, `[2001:db8::1]`,
/// `[2001:db8::1]:443`). A bare `parse::<IpAddr>()` rejects all of those, which
/// would make `client_ip` refuse every request from such a proxy. Returns
/// `None` only for an entry that is not an address.
fn parse_forwarded_ip(entry: &str) -> Option<ClientIp> {
    let s = entry.trim();
    let address = if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        Some(ip) // bare IPv4 or unbracketed IPv6
    } else if let Ok(sock) = s.parse::<std::net::SocketAddr>() {
        Some(sock.ip()) // ip:port or [ip]:port
    } else {
        // `[ip]` with no port.
        s.strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .and_then(|inner| inner.parse::<std::net::IpAddr>().ok())
    };
    address.map(ClientIp::new)
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

    /// A cap set after connections opened counts them: an edge that learns
    /// the core's limit only once linked refuses past it at once.
    #[test]
    fn a_cap_set_later_counts_the_connections_already_open() {
        let client = ClientIp::new("198.51.100.4".parse().unwrap());
        let limiter = ConnLimiter::new(None);
        let first = limiter.try_acquire(client).expect("no cap");
        let _second = limiter.try_acquire(client).expect("no cap");
        limiter.set_max(Some(2));
        assert!(limiter.try_acquire(client).is_none(), "two are open");
        drop(first);
        let _third = limiter.try_acquire(client).expect("one slot freed");
        limiter.set_max(None);
        let _fourth = limiter.try_acquire(client).expect("the cap is gone");
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

#[cfg(test)]
mod forwarded_for_tests {
    use super::ClientIp;

    /// The client a request resolves to, when it resolves to one.
    fn client_ip(
        peer: std::net::IpAddr,
        headers: &axum::http::HeaderMap,
        trusted: &[ipnet::IpNet],
    ) -> ClientIp {
        super::client_ip(peer, headers, trusted).expect("a resolvable forwarded chain")
    }

    fn xff(value: &str) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-forwarded-for", value.parse().unwrap());
        h
    }
    fn ip(s: &str) -> std::net::IpAddr {
        s.parse().unwrap()
    }
    fn client(s: &str) -> ClientIp {
        ClientIp::new(ip(s))
    }
    fn net(s: &str) -> ipnet::IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn untrusted_peer_ignores_forwarded_header() {
        // A direct (untrusted) client can spoof X-Forwarded-For; we must use
        // the real socket peer, never the header, or rate limits are bypassed.
        let trusted = [net("10.0.0.0/8")];
        let got = client_ip(ip("203.0.113.7"), &xff("1.2.3.4"), &trusted);
        assert_eq!(got, client("203.0.113.7"));
    }

    #[test]
    fn trusted_proxy_uses_rightmost_untrusted_forwarded_entry() {
        // Behind a trusted proxy, the client is the rightmost `X-Forwarded-For` entry that
        // isn't itself a trusted hop — a client-appended left entry can't
        // impersonate someone else.
        let trusted = [net("10.0.0.0/8")];
        let got = client_ip(
            ip("10.0.0.1"),
            &xff("9.9.9.9, 203.0.113.7, 10.0.0.2"),
            &trusted,
        );
        assert_eq!(got, client("203.0.113.7"));
    }

    /// A WebSocket is secure (umode +Z) only when a trusted proxy says every
    /// hop was HTTPS: a direct client's own header, a mixed chain, or a
    /// missing header is plaintext.
    #[test]
    fn only_a_trusted_all_https_forwarded_proto_is_secure() {
        let trusted = [net("10.0.0.0/8")];
        let proto = |values: &[&str]| {
            let mut headers = axum::http::HeaderMap::new();
            for value in values {
                headers.append("x-forwarded-proto", value.parse().expect("header"));
            }
            headers
        };
        let secure = |peer: &str, values: &[&str]| {
            super::forwarded_https(ip(peer), &proto(values), &trusted)
        };
        assert!(secure("10.0.0.1", &["https"]));
        assert!(secure("10.0.0.1", &["HTTPS", "https"]));
        assert!(!secure("203.0.113.7", &["https"]), "untrusted peer");
        assert!(!secure("10.0.0.1", &["https, http"]), "a plaintext hop");
        assert!(!secure("10.0.0.1", &["https", "http"]), "a plaintext hop");
        assert!(!secure("10.0.0.1", &[]), "no header");
    }

    #[test]
    fn trusted_proxy_without_header_falls_back_to_peer() {
        let trusted = [net("10.0.0.0/8")];
        let got = client_ip(ip("10.0.0.1"), &axum::http::HeaderMap::new(), &trusted);
        assert_eq!(got, client("10.0.0.1"));
    }

    #[test]
    fn all_forwarded_entries_trusted_falls_back_to_peer() {
        let trusted = [net("10.0.0.0/8")];
        let got = client_ip(ip("10.0.0.1"), &xff("10.0.0.9, 10.0.0.8"), &trusted);
        assert_eq!(got, client("10.0.0.1"));
    }

    #[test]
    fn multiple_forwarded_headers_are_joined_in_order() {
        // A proxy that appends a *separate* X-Forwarded-For header rather than
        // merging: the client-supplied first header must not win over the
        // proxy's appended one. The real client (the appended header's rightmost
        // untrusted entry) is returned, not the spoofed 6.6.6.6 in the first.
        let trusted = [net("10.0.0.0/8")];
        let mut h = axum::http::HeaderMap::new();
        h.append("x-forwarded-for", "6.6.6.6".parse().unwrap());
        h.append("x-forwarded-for", "203.0.113.7, 10.0.0.2".parse().unwrap());
        assert_eq!(
            client_ip(ip("10.0.0.1"), &h, &trusted),
            client("203.0.113.7")
        );
    }

    #[test]
    fn port_annotated_and_bracketed_forwarded_entries_are_parsed() {
        // Some proxies emit `ip:port` / `[ip6]:port`. A bare IpAddr parse would
        // reject these and skip past the real client to a spoofable entry or the
        // proxy IP; the resolver must recover the address.
        let trusted = [net("10.0.0.0/8")];
        // Rightmost non-trusted entry is a port-annotated IPv4 client.
        assert_eq!(
            client_ip(
                ip("10.0.0.1"),
                &xff("1.2.3.4, 203.0.113.7:52833, 10.0.0.2"),
                &trusted
            ),
            client("203.0.113.7"),
        );
        // Bracketed IPv6 with a port.
        assert_eq!(
            client_ip(
                ip("10.0.0.1"),
                &xff("[2001:db8::5]:443, 10.0.0.2"),
                &trusted
            ),
            client("2001:db8::5"),
        );
        // Bracketed IPv6 with no port.
        assert_eq!(
            client_ip(ip("10.0.0.1"), &xff("[2001:db8::9]"), &trusted),
            client("2001:db8::9"),
        );
        // A port-annotated *trusted* hop is still recognized as trusted (parsed,
        // then matched), so it's skipped rather than mis-returned as the client.
        assert_eq!(
            client_ip(ip("10.0.0.1"), &xff("203.0.113.7, 10.0.0.2:9000"), &trusted),
            client("203.0.113.7"),
        );
    }

    /// A dual-stack listener presents an IPv4 proxy or client in its mapped
    /// IPv6 spelling. The trusted-proxy match, each forwarded entry, and the
    /// resolved key are all judged in the canonical IPv4 form, or a mapped
    /// proxy is not recognised as trusted and every client behind it collapses
    /// onto the proxy's address.
    #[test]
    fn mapped_ipv4_peers_and_entries_are_canonical() {
        let trusted = [net("10.0.0.0/8")];
        let got = client_ip(ip("::ffff:10.0.0.1"), &xff("203.0.113.7"), &trusted);
        assert_eq!(got, client("203.0.113.7"));
        assert_eq!(got.ip(), ip("203.0.113.7"));
        assert_eq!(
            client_ip(
                ip("::ffff:10.0.0.1"),
                &xff("::ffff:203.0.113.7, ::ffff:10.0.0.2"),
                &trusted
            )
            .ip(),
            ip("203.0.113.7"),
        );
        assert_eq!(
            client_ip(ip("::ffff:198.51.100.4"), &xff("1.2.3.4"), &trusted).ip(),
            ip("198.51.100.4"),
            "an untrusted mapped peer is its own IPv4 address"
        );
        assert_eq!(client("::ffff:192.0.2.1").to_string(), "192.0.2.1");
    }
    /// An entry a trusted proxy passed on that is not an address — nginx
    /// writes `unix:` for a client on a Unix socket — breaks the chain it
    /// vouches for: what lies left of it is only what the client wrote.
    /// Skipping it let a client choose its own address (its per-IP slots, its
    /// authentication budget, a ban it evades); the request is refused.
    #[test]
    fn an_unusable_forwarded_entry_before_the_client_is_refused() {
        let trusted = [net("10.0.0.0/8")];
        for chain in [
            "6.6.6.6, unix:",
            "6.6.6.6, unix:, 10.0.0.2",
            "6.6.6.6,, 10.0.0.2",
            "6.6.6.6, garbage",
        ] {
            let refused = super::client_ip(ip("10.0.0.1"), &xff(chain), &trusted)
                .expect_err("the chain is broken before any client address");
            assert!(
                refused.to_string().contains("is not an address"),
                "{refused}"
            );
        }
        // Past the client's own address nothing further left is read, so an
        // unusable entry there is the client's own business.
        assert_eq!(
            client_ip(
                ip("10.0.0.1"),
                &xff("unix:, 203.0.113.7, 10.0.0.2"),
                &trusted
            ),
            client("203.0.113.7")
        );
        // A header with no entries names no client, as no header does.
        assert_eq!(
            client_ip(ip("10.0.0.1"), &xff(" "), &trusted),
            client("10.0.0.1")
        );
        // An untrusted peer's header is never read.
        assert_eq!(
            client_ip(ip("203.0.113.9"), &xff("unix:"), &trusted),
            client("203.0.113.9")
        );
    }
}
