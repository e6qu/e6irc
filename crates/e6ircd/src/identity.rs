//! Identity values that cross IRC, HTTP, and PostgreSQL boundaries.

use std::fmt;

/// Lifetime authentication budget for one IRC or BNC connection.
///
/// Keeping the counter and limit together prevents a new authentication edge
/// from incrementing a bare integer with different exhaustion semantics.
#[derive(Debug, Default)]
pub(crate) struct CredentialAttemptBudget {
    used: u8,
}

impl CredentialAttemptBudget {
    /// Maximum expensive credential verifications one connection may request.
    const LIMIT: u8 = 8;

    /// Consume one verification slot. Once exhausted, it stays exhausted.
    pub(crate) fn consume(&mut self) -> bool {
        if self.used >= Self::LIMIT {
            return false;
        }
        self.used += 1;
        true
    }
}

/// Maximum stored contact-email length, following the conventional mailbox
/// limit used by registration systems.
pub const MAX_CONTACT_EMAIL_LEN: usize = 254;

/// A bounded, normalized contact email.
///
/// e6irc does not claim to verify mailbox ownership. This type guarantees the
/// smaller contract it can enforce locally: one ordinary dot-atom local part,
/// one DNS-style domain, no whitespace/control bytes, and a bounded canonical
/// representation with a lowercase domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactEmail(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidContactEmail;

impl fmt::Display for InvalidContactEmail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("contact email must be a valid address of at most 254 bytes")
    }
}

impl std::error::Error for InvalidContactEmail {}

impl ContactEmail {
    pub fn parse(raw: &str) -> Result<Self, InvalidContactEmail> {
        if raw.is_empty()
            || raw.len() > MAX_CONTACT_EMAIL_LEN
            || !raw.is_ascii()
            || raw
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(InvalidContactEmail);
        }
        let Some((local, domain)) = raw.split_once('@') else {
            return Err(InvalidContactEmail);
        };
        if local.is_empty()
            || local.len() > 64
            || local.starts_with('.')
            || local.ends_with('.')
            || local.contains("..")
            || local.bytes().any(|byte| {
                !(byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'.' | b'!'
                            | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'/'
                            | b'='
                            | b'?'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'{'
                            | b'|'
                            | b'}'
                            | b'~'
                    ))
            })
        {
            return Err(InvalidContactEmail);
        }
        let domain = domain.to_ascii_lowercase();
        if !valid_email_domain(&domain) {
            return Err(InvalidContactEmail);
        }
        Ok(Self(format!("{local}@{domain}")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn local_part(&self) -> &str {
        self.0
            .split_once('@')
            .map(|(local, _)| local)
            .expect("ContactEmail construction requires @")
    }

    pub fn domain(&self) -> &str {
        self.0
            .rsplit_once('@')
            .map(|(_, domain)| domain)
            .expect("ContactEmail construction requires @")
    }
}

/// A canonical DNS email domain used by OpenID Connect admission policy.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(transparent)]
pub struct EmailDomain(String);

impl EmailDomain {
    pub fn parse(raw: &str) -> Result<Self, InvalidEmailDomain> {
        let domain = raw.trim().to_ascii_lowercase();
        if !valid_email_domain(&domain) {
            return Err(InvalidEmailDomain);
        }
        Ok(Self(domain))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn admits(&self, email: &ContactEmail) -> bool {
        self.0 == email.domain()
    }
}

impl<'de> serde::Deserialize<'de> for EmailDomain {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidEmailDomain;

impl fmt::Display for InvalidEmailDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("email domain must be a DNS name such as example.com")
    }
}

impl std::error::Error for InvalidEmailDomain {}

fn valid_email_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 || domain.ends_with('.') || !domain.is_ascii() {
        return false;
    }
    let mut labels = domain.split('.');
    labels.clone().count() >= 2
        && labels.all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

/// A permission that can be carried by a personal access token.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ApiTokenScope {
    Read,
    Write,
    Administrator,
    Irc,
}

impl ApiTokenScope {
    pub const ALL: [Self; 4] = [Self::Read, Self::Write, Self::Administrator, Self::Irc];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Administrator => "administrator",
            Self::Irc => "irc",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|scope| scope.as_str() == value)
    }
}

/// A non-empty, canonical set of personal-access-token permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiTokenScopes(u8);

impl ApiTokenScopes {
    pub fn new(scopes: impl IntoIterator<Item = ApiTokenScope>) -> Option<Self> {
        let mut bits = 0u8;
        for scope in scopes {
            bits |= 1 << scope as u8;
        }
        (bits != 0).then_some(Self(bits))
    }

    pub const fn full_access() -> Self {
        Self(0b1111)
    }

    pub fn device_access() -> Self {
        Self::new([
            ApiTokenScope::Read,
            ApiTokenScope::Write,
            ApiTokenScope::Irc,
        ])
        .expect("device access is non-empty")
    }

    pub const fn contains(self, scope: ApiTokenScope) -> bool {
        self.0 & (1 << scope as u8) != 0
    }

    pub fn iter(self) -> impl Iterator<Item = ApiTokenScope> {
        ApiTokenScope::ALL
            .into_iter()
            .filter(move |scope| self.contains(*scope))
    }

    pub fn database_values(self) -> Vec<&'static str> {
        self.iter().map(ApiTokenScope::as_str).collect()
    }

    pub fn from_database(values: Vec<String>) -> Result<Self, InvalidApiTokenScopes> {
        let scopes = values
            .iter()
            .map(|value| ApiTokenScope::parse(value).ok_or(InvalidApiTokenScopes))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(scopes).ok_or(InvalidApiTokenScopes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidApiTokenScopes;

impl fmt::Display for InvalidApiTokenScopes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("personal access token scopes must be a non-empty closed set")
    }
}

impl std::error::Error for InvalidApiTokenScopes {}

macro_rules! bounded_lifetime_days {
    ($(#[$meta:meta])* $name:ident, default = $default:literal, max = $max:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name(u16);

        impl $name {
            pub const DEFAULT: Self = Self($default);
            pub const MAX: u16 = $max;

            pub fn new(days: u16) -> Option<Self> {
                (1..=Self::MAX).contains(&days).then_some(Self(days))
            }

            pub const fn value(self) -> u16 {
                self.0
            }
        }
    };
}

bounded_lifetime_days!(
    /// A bounded personal-access-token lifetime in whole days.
    ApiTokenLifetimeDays,
    default = 30,
    max = 365
);

bounded_lifetime_days!(
    /// A bounded account-invitation lifetime in whole days.
    AccountInvitationLifetimeDays,
    default = 7,
    max = 30
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contact_email_parses_once_and_normalizes_only_the_domain() {
        let email = ContactEmail::parse("Alice+IRC@Example.COM").expect("valid");
        assert_eq!(email.as_str(), "Alice+IRC@example.com");
        assert_eq!(email.local_part(), "Alice+IRC");
    }

    #[test]
    fn contact_email_rejects_ambiguous_unbounded_and_non_dns_forms() {
        for invalid in [
            "",
            "alice",
            "@example.com",
            "alice@",
            ".alice@example.com",
            "alice..irc@example.com",
            "alice@example",
            "alice@-example.com",
            "alice@example-.com",
            "alice@example.com.",
            "alice @example.com",
            "alice@example.com\n",
            "alice@@example.com",
        ] {
            assert!(
                ContactEmail::parse(invalid).is_err(),
                "{invalid:?} must be rejected"
            );
        }
        let oversized = format!("{}@example.com", "a".repeat(MAX_CONTACT_EMAIL_LEN));
        assert!(ContactEmail::parse(&oversized).is_err());
    }

    #[test]
    fn email_domains_are_canonical_exact_admission_values() {
        let domain = EmailDomain::parse(" Example.COM ").expect("valid domain");
        assert_eq!(domain.as_str(), "example.com");
        assert!(
            domain.admits(&ContactEmail::parse("alice@example.com").expect("valid contact email"))
        );
        assert!(
            !domain.admits(
                &ContactEmail::parse("alice@sub.example.com").expect("valid contact email")
            )
        );
        for invalid in [
            "",
            "localhost",
            ".example.com",
            "-example.com",
            "example.com.",
        ] {
            assert!(
                EmailDomain::parse(invalid).is_err(),
                "{invalid:?} must be rejected"
            );
        }
    }

    #[test]
    fn invitation_lifetime_is_closed_and_bounded() {
        assert_eq!(AccountInvitationLifetimeDays::DEFAULT.value(), 7);
        assert!(AccountInvitationLifetimeDays::new(0).is_none());
        assert_eq!(
            AccountInvitationLifetimeDays::new(30).map(AccountInvitationLifetimeDays::value),
            Some(30)
        );
        assert!(AccountInvitationLifetimeDays::new(31).is_none());
    }

    #[test]
    fn api_token_scopes_are_non_empty_canonical_and_closed() {
        let scopes = ApiTokenScopes::new([
            ApiTokenScope::Write,
            ApiTokenScope::Read,
            ApiTokenScope::Write,
        ])
        .expect("non-empty");
        assert_eq!(scopes.database_values(), vec!["read", "write"]);
        assert!(scopes.contains(ApiTokenScope::Read));
        assert!(!scopes.contains(ApiTokenScope::Administrator));
        assert!(ApiTokenScopes::new([]).is_none());
        assert!(ApiTokenScopes::from_database(vec!["future".into()]).is_err());
    }

    #[test]
    fn api_token_lifetime_has_closed_bounds() {
        assert!(ApiTokenLifetimeDays::new(0).is_none());
        assert_eq!(ApiTokenLifetimeDays::new(1).expect("minimum").value(), 1);
        assert_eq!(
            ApiTokenLifetimeDays::new(ApiTokenLifetimeDays::MAX)
                .expect("maximum")
                .value(),
            ApiTokenLifetimeDays::MAX
        );
        assert!(ApiTokenLifetimeDays::new(ApiTokenLifetimeDays::MAX + 1).is_none());
    }

    #[test]
    fn credential_attempt_budget_stays_exhausted() {
        let mut budget = CredentialAttemptBudget::default();
        for _ in 0..CredentialAttemptBudget::LIMIT {
            assert!(budget.consume());
        }
        assert!(!budget.consume());
        assert!(!budget.consume(), "exhaustion must not wrap or reset");
    }
}
