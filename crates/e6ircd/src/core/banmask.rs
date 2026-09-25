//! What a stored ban-like mask *means*, and whether a user matches it.
//!
//! A channel list mode (`+b/+q/+e/+I`) and a server K-line/D-line both store a
//! mask string, but not every mask is a hostmask glob. Solanum (as deployed on
//! Libera) gives three shapes meaning, and this module is the one place that
//! decides which shape a mask is and how it matches:
//!
//! - a **glob** over `nick!user@host` (or `user@host` for a K-line), tried
//!   against the host the user shows *and* against its real address, so a
//!   `SETHOST` cloak cannot slip a ban written against the address;
//! - a **CIDR** host (`*!*@203.0.113.0/24`, `*!*@2001:db8::/32`, a bare
//!   `203.0.113.0/24` D-line), matched against the connection's real address —
//!   the immutable one it connected from, never the displayed host;
//! - an **account extban** (`$a`, `$a:name`, negated `$~a`/`$~a:name`,
//!   Solanum's `extb_account`), matched against the services account.
//!
//! The shape is decided once, when the mask is stored ([`MaskShape::parse`]),
//! so every match — each channel message tests up to `MAXLIST` of them — reads
//! a parsed network, not the string. A mask that claims a shape it cannot hold
//! (an extban type not implemented here, a CIDR whose prefix is out of range)
//! is refused where it is added, never stored as a mask nothing could match.

use std::net::IpAddr;

use e6irc_proto::casemap::CaseMapping;

/// The extended-ban prefix advertised as `EXTBAN=$,…`.
pub(crate) const EXTBAN_PREFIX: char = '$';
/// The extended-ban types [`MaskShape::parse`] accepts, advertised as
/// `EXTBAN=$,<these>`. Only the account extban exists here; advertising a type
/// the parser refuses would tell a client a ban works that the server rejects.
pub(crate) const EXTBAN_TYPES: &str = "a";
/// The account extban's type, advertised as `ACCOUNTEXTBAN` (Solanum/Libera).
pub(crate) const ACCOUNT_EXTBAN: char = 'a';

/// A mask's meaning, decided once when it is stored.
#[derive(Debug, Clone)]
pub(crate) enum MaskShape {
    /// A `*`/`?` glob over the whole subject.
    Glob,
    /// A host that is an address or a CIDR range: the part before the last `@`
    /// (`None` when there was no `@`, as in a bare D-line) is still a glob over
    /// the subject's `nick!user` / `user`.
    Cidr {
        head: Option<Box<str>>,
        net: ipnet::IpNet,
    },
    /// `$a` (any logged-in user) or `$a:<glob>` (an account matching the glob);
    /// `negated` is the `$~a` form, which matches exactly who `$a` does not.
    Account {
        negated: bool,
        pattern: Option<Box<str>>,
    },
}

/// Why a mask was refused where it was added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MaskError {
    /// `$x…` for an extban type not in [`EXTBAN_TYPES`].
    UnknownExtban,
    /// `$a` followed by something other than nothing or `:<non-empty glob>`,
    /// or carrying a `$#channel` ban forward (not implemented).
    MalformedExtban,
    /// A host of the form `<address>/<bits>` whose prefix length is not one the
    /// address family has.
    MalformedCidr,
}

impl MaskError {
    /// The text an ERR_INVALIDMODEPARAM (or an operator notice) carries.
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Self::UnknownExtban => "Unsupported extended ban type (EXTBAN lists those supported)",
            Self::MalformedExtban => "Malformed extended ban (want $a or $a:<account mask>)",
            Self::MalformedCidr => "Malformed CIDR mask (prefix length out of range)",
        }
    }
}

impl MaskShape {
    /// Decide what `mask` means. Strict: an `Err` is a mask no user could ever
    /// match as intended, so the caller refuses it rather than storing it.
    pub(crate) fn parse(mask: &str) -> Result<Self, MaskError> {
        if let Some(extban) = mask.strip_prefix(EXTBAN_PREFIX) {
            return Self::parse_extban(extban);
        }
        let (head, host) = match mask.rsplit_once('@') {
            Some((head, host)) => (Some(head), host),
            None => (None, mask),
        };
        let net = match host.split_once('/') {
            // `<address>/<bits>`. A host with a `/` whose left side is not an
            // address is an ordinary glob — Libera's cloaks (`user/alice`)
            // are exactly that.
            Some((address, _)) if address.parse::<IpAddr>().is_ok() => host
                .parse::<ipnet::IpNet>()
                .map_err(|_| MaskError::MalformedCidr)?,
            Some(_) => return Ok(Self::Glob),
            // A bare address is its own single-address network, so every
            // spelling of it (`2001:DB8::1`, `2001:db8:0::1`) matches alike.
            None => match host.parse::<IpAddr>() {
                Ok(address) => ipnet::IpNet::from(address.to_canonical()),
                Err(_) => return Ok(Self::Glob),
            },
        };
        Ok(Self::Cidr {
            head: head.map(Box::from),
            net,
        })
    }

    fn parse_extban(extban: &str) -> Result<Self, MaskError> {
        let (negated, rest) = match extban.strip_prefix('~') {
            Some(rest) => (true, rest),
            None => (false, extban),
        };
        let mut chars = rest.chars();
        let kind = chars
            .next()
            .map(|c| c.to_ascii_lowercase())
            .ok_or(MaskError::MalformedExtban)?;
        if !EXTBAN_TYPES.contains(kind) {
            return Err(MaskError::UnknownExtban);
        }
        debug_assert_eq!(kind, ACCOUNT_EXTBAN, "the one implemented extban type");
        let pattern = match chars.as_str() {
            "" => None,
            data => {
                let pattern = data.strip_prefix(':').ok_or(MaskError::MalformedExtban)?;
                if pattern.is_empty() || pattern.contains(EXTBAN_PREFIX) {
                    return Err(MaskError::MalformedExtban);
                }
                Some(Box::from(pattern))
            }
        };
        Ok(Self::Account { negated, pattern })
    }

    /// Whether `subject` matches this shape. `display` is the stored mask
    /// itself, the glob a [`MaskShape::Glob`] is.
    pub(crate) fn matches(
        &self,
        casemap: CaseMapping,
        display: &str,
        subject: &MaskSubject<'_>,
    ) -> bool {
        let glob = |mask: &str, text: &str| e6irc_proto::mask::matches(casemap, mask, text);
        match self {
            Self::Glob => {
                glob(display, subject.shown)
                    || subject
                        .by_address
                        .as_deref()
                        .is_some_and(|by_address| glob(display, by_address))
            }
            Self::Cidr { head, net } => {
                let in_net = subject
                    .address
                    .is_some_and(|address| net.contains(&address));
                let head_matches = head
                    .as_deref()
                    .is_none_or(|head| glob(head, subject.head()));
                (in_net && head_matches) || glob(display, subject.shown)
            }
            Self::Account { negated, pattern } => {
                let hit = match (subject.account, pattern) {
                    (Some(_), None) => true,
                    (Some(account), Some(pattern)) => glob(pattern, account),
                    (None, _) => false,
                };
                hit != *negated
            }
        }
    }
}

/// Who a mask is tested against.
pub(crate) struct MaskSubject<'a> {
    /// `nick!user@host` (a channel mask), `user@host` (a K-line), or the
    /// address text (a D-line), with the host the user currently shows.
    shown: &'a str,
    /// The real address the connection came from, when it has one (an
    /// in-process bouncer session does not). Fixed at connect: a `SETHOST`
    /// changes what is shown, never this.
    address: Option<IpAddr>,
    /// `shown` with its host replaced by the address text — what a glob over
    /// the address (`*!*@203.0.113.*`) is tried against. `None` when the user
    /// has no address, or already shows it.
    by_address: Option<String>,
    account: Option<&'a str>,
}

impl<'a> MaskSubject<'a> {
    pub(crate) fn new(shown: &'a str, address: Option<IpAddr>, account: Option<&'a str>) -> Self {
        let by_address = address.and_then(|address| {
            let (head, host) = shown.rsplit_once('@')?;
            let address = address.to_string();
            (host != address).then(|| format!("{head}@{address}"))
        });
        Self {
            shown,
            address,
            by_address,
            account,
        }
    }

    /// `shown` before its last `@`: `nick!user` or `user`.
    fn head(&self) -> &str {
        self.shown
            .rsplit_once('@')
            .map_or(self.shown, |(head, _)| head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CASEMAP: CaseMapping = CaseMapping::Rfc1459;

    fn hit(mask: &str, subject: &MaskSubject<'_>) -> bool {
        MaskShape::parse(mask)
            .expect("valid mask")
            .matches(CASEMAP, mask, subject)
    }

    fn user(shown: &str, address: &str, account: Option<&'static str>) -> MaskSubject<'static> {
        MaskSubject::new(
            Box::leak(shown.to_string().into_boxed_str()),
            Some(address.parse().expect("address")),
            account,
        )
    }

    #[test]
    fn a_cidr_host_matches_the_real_address_whatever_is_shown() {
        let cloaked = user("n!u@cloak.test", "203.0.113.9", None);
        assert!(hit("*!*@203.0.113.0/24", &cloaked));
        assert!(!hit("*!*@203.0.114.0/24", &cloaked));
        assert!(hit("n!*@203.0.113.0/24", &cloaked));
        assert!(
            !hit("x!*@203.0.113.0/24", &cloaked),
            "the head still applies"
        );
        // A glob over the address text, and a bare address, match it too.
        assert!(hit("*!*@203.0.113.*", &cloaked));
        assert!(hit("*!*@203.0.113.9", &cloaked));
        let v6 = user("n!u@2001:db8::5", "2001:db8::5", None);
        assert!(hit("*!*@2001:db8::/32", &v6));
        assert!(hit("*!*@2001:DB8:0::5", &v6), "any spelling of the address");
        assert!(!hit("*!*@2001:db9::/32", &v6));
        assert!(!hit("*!*@203.0.113.0/24", &v6), "another family");
    }

    #[test]
    fn a_glob_still_matches_the_shown_host() {
        let cloaked = user("n!u@user/alice", "203.0.113.9", None);
        assert!(
            hit("*!*@user/alice", &cloaked),
            "a cloak with a / is a glob"
        );
        assert!(matches!(
            MaskShape::parse("*!*@user/alice"),
            Ok(MaskShape::Glob)
        ));
    }

    #[test]
    fn an_account_extban_follows_solanum() {
        let alice = user("n!u@h", "192.0.2.1", Some("Alice"));
        let anonymous = user("n!u@h", "192.0.2.1", None);
        assert!(hit("$a", &alice));
        assert!(!hit("$a", &anonymous));
        assert!(hit("$a:alice", &alice), "account names fold");
        assert!(hit("$A:al*", &alice), "the type letter folds");
        assert!(!hit("$a:bob", &alice));
        assert!(hit("$~a", &anonymous));
        assert!(!hit("$~a", &alice));
        assert!(hit("$~a:bob", &alice));
        assert!(hit("$~a:bob", &anonymous));
    }

    #[test]
    fn a_mask_that_could_never_match_as_written_is_refused() {
        for (mask, error) in [
            ("$x:foo", MaskError::UnknownExtban),
            ("$j:#chan", MaskError::UnknownExtban),
            ("$", MaskError::MalformedExtban),
            ("$~", MaskError::MalformedExtban),
            ("$a:", MaskError::MalformedExtban),
            ("$ab", MaskError::MalformedExtban),
            ("$a:alice$#forward", MaskError::MalformedExtban),
            ("*!*@203.0.113.0/33", MaskError::MalformedCidr),
            ("*!*@203.0.113.0/x", MaskError::MalformedCidr),
            ("*!*@2001:db8::/129", MaskError::MalformedCidr),
            ("203.0.113.0/", MaskError::MalformedCidr),
        ] {
            assert_eq!(MaskShape::parse(mask).err(), Some(error), "{mask}");
        }
    }

    #[test]
    fn every_advertised_extban_type_parses() {
        for kind in EXTBAN_TYPES.chars() {
            assert!(MaskShape::parse(&format!("${kind}")).is_ok(), "{kind}");
        }
        assert!(EXTBAN_TYPES.contains(ACCOUNT_EXTBAN));
    }

    #[test]
    fn a_bare_dline_range_needs_no_head() {
        let subject = MaskSubject::new(
            "198.51.100.7",
            Some("198.51.100.7".parse().expect("address")),
            None,
        );
        assert!(hit("198.51.100.0/24", &subject));
        assert!(hit("198.51.100.*", &subject));
        assert!(!hit("198.51.101.0/24", &subject));
    }
}
