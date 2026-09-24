//! Where a network driver may connect to.
//!
//! An account holder types an upstream address and e6irc dials it from the
//! server's own network position. Some destinations are never a network — the
//! cloud metadata endpoint, multicast, broadcast, the unspecified address — and
//! are refused always. Loopback and the private ranges are refused too, by
//! default: on a host that sits beside internal services, letting any account
//! ask the daemon to connect to `10.0.0.5:5432` and report whether it answers
//! is an internal port probe. The daemon has no internal upstream of its own to
//! reach, so nothing is lost. `internal_upstreams = "allow"` in the server
//! configuration is the one, operator-level exception; the test harnesses set
//! it because their upstreams are in-process listeners on loopback.
//!
//! Every dial goes through here with the *resolved* address, not only the
//! literal an account typed: a hostname that resolves — now or after a DNS
//! rebind — to a refused address is refused at connect time.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The server-level policy on upstream addresses inside the host's own network.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InternalUpstreams {
    /// Loopback, RFC 1918, carrier-grade NAT and unique-local addresses are
    /// refused as upstreams. The default.
    #[default]
    Refuse,
    /// They may be dialled. For test harnesses whose upstreams listen on
    /// loopback, and for nothing else yet.
    Allow,
}

/// Why an address may not be dialled as an upstream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpstreamRefusal {
    /// Never a network: link-local (the cloud metadata endpoint among them),
    /// broadcast, documentation, multicast or unspecified.
    NeverAnUpstream,
    /// Inside the host's own network, and the policy is [`InternalUpstreams::Refuse`].
    Internal,
}

impl UpstreamRefusal {
    /// The sentence a refusal shows. It describes the rule, never the address,
    /// so a refusal cannot itself be used to map what the rule protects.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::NeverAnUpstream => {
                "addr must not be a link-local, unspecified, multicast, broadcast, or documentation IP"
            }
            Self::Internal => {
                "addr must not be a loopback or private (internal) IP; this server does not connect to internal infrastructure"
            }
        }
    }
}

/// The IPv4 address a V6 address reaches when the V6 form carries it at a fixed
/// place, so the V4 rules judge it: the well-known NAT64 prefix `64:ff9b::/96`
/// (RFC 6052), 6to4 `2002::/16` (RFC 3056), and the deprecated IPv4-compatible
/// `::a.b.c.d` (RFC 4291). On a host with NAT64 or a 6to4 relay each of these
/// connects to the embedded V4 address, internal ones included.
fn embedded_ipv4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let [.., a, b, c, d] = v6.octets();
    match v6.segments() {
        [0x0064, 0xff9b, 0, 0, 0, 0, _, _] => Some(Ipv4Addr::new(a, b, c, d)),
        [0x2002, high, low, ..] => Some(Ipv4Addr::from((u32::from(high) << 16) | u32::from(low))),
        // `::` and `::1` are V6's own unspecified and loopback addresses.
        [0, 0, 0, 0, 0, 0, _, _] if !v6.is_unspecified() && !v6.is_loopback() => {
            Some(Ipv4Addr::new(a, b, c, d))
        }
        _ => None,
    }
}

impl InternalUpstreams {
    /// Why `ip` may not be dialled under this policy, or `None` when it may.
    ///
    /// The address is canonicalized first: a V4-mapped V6 literal like
    /// `::ffff:169.254.169.254` connects, at the kernel, to the V4 address, so
    /// it is classified by the V4 rules.
    pub fn refusal(self, ip: IpAddr) -> Option<UpstreamRefusal> {
        let ip = ip.to_canonical();
        if let IpAddr::V6(v6) = ip
            && let Some(v4) = embedded_ipv4(v6)
        {
            return self.refusal(IpAddr::V4(v4));
        }
        if ip.is_unspecified() || ip.is_multicast() {
            return Some(UpstreamRefusal::NeverAnUpstream);
        }
        let (never, internal) = match ip {
            IpAddr::V4(v4) => (
                v4.is_link_local() || v4.is_broadcast() || v4.is_documentation(),
                v4.is_loopback() || v4.is_private() || is_carrier_grade_nat(v4),
            ),
            // `to_canonical` and `embedded_ipv4` have already mapped every
            // V4-in-V6 form with a fixed place for the V4 address to V4.
            IpAddr::V6(v6) => {
                let [first, second, third, ..] = v6.segments();
                (
                    // Link-local, and the documentation prefix 2001:db8::/32.
                    (first & 0xffc0) == 0xfe80 || (first == 0x2001 && second == 0x0db8),
                    // Loopback, unique-local fc00::/7, and the local-use NAT64
                    // prefix 64:ff9b:1::/48 (RFC 8215), which translates to
                    // IPv4 at a site-chosen offset and so is judged whole.
                    v6.is_loopback()
                        || (first & 0xfe00) == 0xfc00
                        || (first == 0x0064 && second == 0xff9b && third == 0x0001),
                )
            }
        };
        if never {
            Some(UpstreamRefusal::NeverAnUpstream)
        } else if internal && self == Self::Refuse {
            Some(UpstreamRefusal::Internal)
        } else {
            None
        }
    }

    /// Whether `ip` may be dialled under this policy.
    pub fn permits(self, ip: IpAddr) -> bool {
        self.refusal(ip).is_none()
    }

    /// Why the address an account typed may not be an upstream, judged from its
    /// literal form: `host[:port]`, `[v6]:port`, or a URL. A hostname cannot be
    /// judged without DNS and passes here; it is judged, resolved, at dial time.
    ///
    /// The host is read as the URL parser reads it, because that is what the
    /// HTTP client dials: `2130706433`, `0x7f000001`, `127.1`, `0177.0.0.1` and
    /// `%31%32%37.0.0.1` are all `127.0.0.1` to it (and to the kernel), while
    /// none of them is an address to `IpAddr::from_str`. Judging the parsed
    /// form closes the whole family of spellings at once. Whatever scheme the
    /// address came with is replaced by `http` for the reading: only the
    /// special schemes canonicalize IPv4 numbers, and the scheme is not what
    /// is being judged.
    pub fn refusal_for_addr(self, addr: &str) -> Option<UpstreamRefusal> {
        let rest = addr.split_once("://").map_or(addr, |(_, rest)| rest);
        let url = url::Url::parse(&format!("http://{rest}")).ok()?;
        self.refusal_for_url(&url)
    }

    /// Why a parsed URL's host may not be an upstream, judged from its literal
    /// form. A domain passes here and is judged, resolved, at dial time.
    pub fn refusal_for_url(self, url: &url::Url) -> Option<UpstreamRefusal> {
        match url.host()? {
            url::Host::Ipv4(ip) => self.refusal(IpAddr::V4(ip)),
            url::Host::Ipv6(ip) => self.refusal(IpAddr::V6(ip)),
            url::Host::Domain(_) => None,
        }
    }
}

/// A credential an IRC upstream would be sent in cleartext, named by the field
/// that carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleartextCredential {
    SaslPassword,
    ServerPassword,
}

impl CleartextCredential {
    pub const fn field(self) -> &'static str {
        match self {
            Self::SaslPassword => "sasl_password",
            Self::ServerPassword => "server_password",
        }
    }

    /// The sentence a refusal shows.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::SaslPassword => {
                "sasl_password requires tls=true: without TLS the upstream password is readable by \
                 everything on the path"
            }
            Self::ServerPassword => {
                "server_password requires tls=true: without TLS the server password is readable by \
                 everything on the path"
            }
        }
    }
}

impl InternalUpstreams {
    /// The credential an IRC upstream at `addr` would carry in cleartext, or
    /// `None` when it may carry what it has.
    ///
    /// Credentials cross only TLS — or a plaintext connection to this
    /// machine's loopback address, when the operator allows internal upstreams
    /// (the test harnesses, whose upstreams are in-process listeners). Judged
    /// from the address literal: a name is never trusted to mean loopback. The
    /// connection enforces the same rule again by the address it actually
    /// dialled (`e6irc_client::Connection` writes no credential to a plaintext
    /// peer off loopback), so this is the refusal a person reads, not the only
    /// guard.
    pub fn cleartext_credential(
        self,
        addr: &str,
        tls: bool,
        sasl_password: bool,
        server_password: bool,
    ) -> Option<CleartextCredential> {
        let credential = if sasl_password {
            CleartextCredential::SaslPassword
        } else if server_password {
            CleartextCredential::ServerPassword
        } else {
            return None;
        };
        if tls || (self == Self::Allow && is_loopback_literal(addr)) {
            None
        } else {
            Some(credential)
        }
    }
}

/// Whether `addr` (`host:port`, `[v6]:port`) names a loopback address as a
/// literal, read as the URL parser (and so the kernel) reads it.
fn is_loopback_literal(addr: &str) -> bool {
    url::Url::parse(&format!("http://{addr}"))
        .ok()
        .and_then(|url| match url.host()? {
            url::Host::Ipv4(ip) => Some(ip.is_loopback()),
            url::Host::Ipv6(ip) => Some(ip.to_canonical().is_loopback()),
            url::Host::Domain(_) => Some(false),
        })
        .unwrap_or(false)
}

/// RFC 6598 shared address space, `100.64.0.0/10`: the inside of a carrier or
/// cloud provider's NAT, which is internal for this purpose.
fn is_carrier_grade_nat(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    a == 100 && (64..=127).contains(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_cross_only_tls_or_an_allowed_loopback_literal() {
        use CleartextCredential::{SaslPassword, ServerPassword};
        let refuse = InternalUpstreams::Refuse;
        let allow = InternalUpstreams::Allow;
        assert_eq!(
            refuse.cleartext_credential("irc.example:6667", true, true, true),
            None
        );
        assert_eq!(
            refuse.cleartext_credential("irc.example:6667", false, false, false),
            None
        );
        assert_eq!(
            refuse.cleartext_credential("irc.example:6667", false, true, false),
            Some(SaslPassword)
        );
        assert_eq!(
            allow.cleartext_credential("irc.example:6667", false, false, true),
            Some(ServerPassword)
        );
        // A name is never taken to mean this machine.
        assert_eq!(
            allow.cleartext_credential("localhost:6667", false, true, false),
            Some(SaslPassword)
        );
        for loopback in [
            "127.0.0.1:6667",
            "[::1]:6667",
            "[::ffff:127.0.0.1]:6667",
            "2130706433:6667",
        ] {
            assert_eq!(
                allow.cleartext_credential(loopback, false, true, true),
                None,
                "{loopback}"
            );
            assert_eq!(
                refuse.cleartext_credential(loopback, false, true, false),
                Some(SaslPassword),
                "{loopback}"
            );
        }
        assert_eq!(
            allow.cleartext_credential("10.0.0.5:6667", false, true, false),
            Some(SaslPassword)
        );
    }

    fn refusal(policy: InternalUpstreams, addr: &str) -> Option<UpstreamRefusal> {
        policy.refusal_for_addr(addr)
    }

    #[test]
    fn what_is_never_an_upstream_is_refused_under_either_policy() {
        for addr in [
            "169.254.169.254:80", // cloud metadata
            "0.0.0.0:6667",
            "255.255.255.255:6667",
            "[fe80::1]:6697",
            "203.0.113.7:6697", // TEST-NET-3
            "224.0.0.1:6667",
            "[::ffff:169.254.169.254]:80",
            "[::ffff:0.0.0.0]:6667",
            "[2001:db8::1]:6697", // v6 documentation
            // The metadata endpoint inside NAT64, 6to4, and IPv4-compatible
            // forms, which reach it at the kernel on a host that routes them.
            "[64:ff9b::a9fe:a9fe]:80",
            "[2002:a9fe:a9fe::]:80",
            "[::169.254.169.254]:80",
            "http://169.254.169.254",
            "https://[fe80::1]/api",
            // The metadata endpoint as one decimal number, and in hex: what
            // the URL parser and the kernel read as 169.254.169.254.
            "http://2852039166/latest/meta-data/",
            "http://0xa9fea9fe/",
            "2852039166:80",
        ] {
            for policy in [InternalUpstreams::Refuse, InternalUpstreams::Allow] {
                assert_eq!(
                    refusal(policy, addr),
                    Some(UpstreamRefusal::NeverAnUpstream),
                    "{addr} under {policy:?}"
                );
            }
        }
    }

    #[test]
    fn internal_addresses_are_refused_by_default_and_only_by_default() {
        for addr in [
            "127.0.0.1:6667",
            "[::1]:6697",
            "10.0.0.5:6667",
            "172.16.4.4:6667",
            "192.168.1.10:6667",
            "100.64.0.9:6667", // carrier-grade NAT
            "[fc00::1]:6697",
            "[fd12::1]:6697",
            "[::ffff:127.0.0.1]:6667",
            "[::ffff:10.0.0.5]:6667",
            "[64:ff9b::a00:5]:5432", // NAT64 of 10.0.0.5
            "[64:ff9b:1::1]:5432",   // local-use NAT64
            "[2002:7f00:1::]:6667",  // 6to4 of 127.0.0.1
            "[::10.0.0.5]:6667",     // IPv4-compatible
            "http://127.0.0.1:8008",
            "http://192.168.1.10:8008",
            // Loopback in every spelling the URL parser canonicalizes: one
            // decimal number, hex, two- and three-part dotted forms, octal,
            // percent-encoded octets, and behind user information.
            "http://2130706433:8008",
            "http://0x7f.1/",
            "http://127.1/",
            "http://0x7f000001:8008",
            "http://0177.0.0.1:8008",
            "http://%31%32%37.0.0.1/",
            "http://alice@127.0.0.1/",
            "2130706433:6667",
            "0x7f.1:6667",
        ] {
            assert_eq!(
                refusal(InternalUpstreams::Refuse, addr),
                Some(UpstreamRefusal::Internal),
                "{addr}"
            );
            assert_eq!(refusal(InternalUpstreams::Allow, addr), None, "{addr}");
        }
    }

    #[test]
    fn public_addresses_and_hostnames_pass_the_literal_check() {
        for addr in [
            "93.184.216.34:6697",
            "[2606:4700::1111]:6697",
            "[64:ff9b::5db8:d822]:6697", // NAT64 of a public address
            "irc.libera.chat:6697",
            "https://matrix.org",
            "100.128.0.1:6667", // just past the CGNAT block
            "172.32.0.1:6667",  // just past 172.16/12
        ] {
            assert_eq!(refusal(InternalUpstreams::Refuse, addr), None, "{addr}");
        }
    }

    #[test]
    fn a_refusal_names_the_rule_and_not_the_address() {
        for refusal in [UpstreamRefusal::NeverAnUpstream, UpstreamRefusal::Internal] {
            assert!(refusal.reason().starts_with("addr must not be"));
        }
    }

    #[test]
    fn the_policy_reads_from_configuration_and_refuses_by_default() {
        #[derive(serde::Deserialize)]
        struct Holder {
            #[serde(default)]
            internal_upstreams: InternalUpstreams,
        }
        let holder: Holder = toml::from_str("").unwrap();
        assert_eq!(holder.internal_upstreams, InternalUpstreams::Refuse);
        let holder: Holder = toml::from_str("internal_upstreams = \"allow\"").unwrap();
        assert_eq!(holder.internal_upstreams, InternalUpstreams::Allow);
        assert!(toml::from_str::<Holder>("internal_upstreams = \"yes\"").is_err());
    }
}
