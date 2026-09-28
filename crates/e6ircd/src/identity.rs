//! Identity values that cross IRC, HTTP, and PostgreSQL boundaries.

use std::fmt;

/// Longest password any surface accepts, in bytes.
pub const MAX_PASSWORD_LEN: usize = 512;

/// The shortest a new password may be, in characters, unless
/// `registration.minimum_password_length` says otherwise: NIST SP 800-63B
/// §5.1.1.2's floor for a memorized secret the subscriber chooses.
pub const DEFAULT_MINIMUM_PASSWORD_CHARS: usize = 8;

/// The highest `registration.minimum_password_length` may be: a character is
/// at most four UTF-8 bytes, so a password of this many characters fits in
/// [`MAX_PASSWORD_LEN`] in every script. A higher minimum would refuse, in
/// some scripts, every password long enough to meet it.
pub const MAX_MINIMUM_PASSWORD_CHARS: usize = MAX_PASSWORD_LEN / 4;

/// Why a password cannot be set on an account. Each carries the minimum in
/// force, which the explanation states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordRefusal {
    /// Fewer characters than the minimum — the empty password among them,
    /// which SASL PLAIN, the web login and the REST API all refuse.
    TooShort { minimum: usize },
    /// Longer than [`MAX_PASSWORD_LEN`].
    TooLong { minimum: usize },
}

impl PasswordRefusal {
    /// The one wording every surface uses for the rule.
    pub fn explanation(self) -> String {
        let (Self::TooShort { minimum } | Self::TooLong { minimum }) = self;
        let characters = if minimum == 1 {
            "character"
        } else {
            "characters"
        };
        format!(
            "Passwords must be at least {minimum} {characters} and at most {MAX_PASSWORD_LEN} \
             bytes."
        )
    }
}

/// The rule for a password being set: at least
/// `registration.minimum_password_length` characters and at most
/// [`MAX_PASSWORD_LEN`] bytes. One cell, shared by the IRC core, NickServ, the
/// web and the REST API, and set live when the setting changes, so every
/// surface applies the same minimum at the same moment. Until it is set it
/// holds [`DEFAULT_MINIMUM_PASSWORD_CHARS`].
#[derive(Debug, Clone)]
pub struct PasswordPolicy(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self(std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(
            DEFAULT_MINIMUM_PASSWORD_CHARS,
        )))
    }
}

impl PasswordPolicy {
    /// Require at least `characters` of every password set from now on. The
    /// configuration has held it to 1 through [`MAX_MINIMUM_PASSWORD_CHARS`].
    pub fn set_minimum_chars(&self, characters: usize) {
        assert!(
            (1..=MAX_MINIMUM_PASSWORD_CHARS).contains(&characters),
            "the configuration bounds the password minimum, and {characters} is outside it"
        );
        self.0
            .store(characters, std::sync::atomic::Ordering::Relaxed);
    }

    /// The minimum in force, in characters.
    pub fn minimum_chars(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// `raw` as a password an account may be given, or why not.
    pub fn new_password(&self, raw: &str) -> Result<NewPassword, PasswordRefusal> {
        let minimum = self.minimum_chars();
        if raw.chars().count() < minimum {
            Err(PasswordRefusal::TooShort { minimum })
        } else if raw.len() > MAX_PASSWORD_LEN {
            Err(PasswordRefusal::TooLong { minimum })
        } else {
            Ok(NewPassword(raw.to_owned()))
        }
    }
}

/// A password an account may be given, as the [`PasswordPolicy`] in force
/// admitted it. Every surface that sets one — IRC `REGISTER`, NickServ
/// `REGISTER`, the web and the REST API — parses it there, and account
/// creation takes only this type, so no path can store a password another
/// surface refuses. The minimum governs passwords being set; an existing
/// password is verified as it was stored.
#[derive(Clone, PartialEq, Eq)]
pub struct NewPassword(String);

impl std::ops::Deref for NewPassword {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

/// A secret: never printed, even in a debug dump of the request carrying it.
impl fmt::Debug for NewPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NewPassword(..)")
    }
}

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

    /// The slots spent, as a session's record keeps them: a rebuild resumes
    /// the budget where it was, so restarting a core buys no guesses.
    pub(crate) fn used(&self) -> u8 {
        self.used
    }

    /// The budget of a session that has spent `used` slots, never past the
    /// limit.
    pub(crate) fn resumed(used: u8) -> Self {
        Self {
            used: used.min(Self::LIMIT),
        }
    }
}

/// The credential a sign-in presented, which an IRC session and a bouncer
/// attachment keep for as long as they live, so revoking that one credential
/// ends exactly what it opened. SASL PLAIN, NickServ `IDENTIFY` and the attach
/// listener accept the account password or an app password; SASL OAUTHBEARER
/// accepts a personal access token; IRC and NickServ `REGISTER` sign in with
/// the password they just set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialId {
    /// The account's primary password. It is never revoked on its own:
    /// changing or removing it changes the account's authority, which ends
    /// every session the account has, however it signed in.
    AccountPassword,
    /// A credential issued alongside the password, revocable by itself.
    Issued(IssuedCredential),
}

/// A credential issued to an account besides its password, named by its row:
/// revoking it deletes that row, and the table announces the deletion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IssuedCredential {
    /// An app password, by its `account_credentials` id.
    AppPassword(i64),
    /// A personal access token, by its `api_tokens` id.
    ApiToken(i64),
}

impl IssuedCredential {
    /// What kind of credential this is, in words.
    pub fn kind(self) -> &'static str {
        match self {
            Self::AppPassword(_) => "app password",
            Self::ApiToken(_) => "personal access token",
        }
    }

    /// Why a session or attachment this credential opened is closed when it is
    /// revoked.
    pub fn revocation_reason(self) -> &'static str {
        match self {
            Self::AppPassword(_) => "App password revoked",
            Self::ApiToken(_) => "Personal access token revoked",
        }
    }
}

impl fmt::Display for IssuedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (Self::AppPassword(id) | Self::ApiToken(id)) = self;
        write!(f, "{} {id}", self.kind())
    }
}

/// Casefolded nicks the built-in services pseudo-clients occupy. No session may
/// take one (NICK refuses it, and PRIVMSG to it is intercepted), and no account
/// may be named after one.
pub(crate) const SERVICE_NICKS: [&str; 2] = ["nickserv", "chanserv"];

/// Why a name cannot become an account's (see
/// [`ReservedAccountNames::claimable`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameClaimRefusal {
    /// A services pseudo-client's nick.
    ServiceNick,
    /// A configured administrator's name, which only a privileged flow creates.
    ConfiguredAdministrator,
}

/// The configured administrators (`http.admin_accounts` /
/// `E6IRC_ADMIN_ACCOUNTS`), and so the account names only privileged flows may
/// bring into being. Such a name carries administrator authority the moment an
/// account holds it, so whoever claimed it first — over NickServ `REGISTER` or
/// `GROUP`, the IRCv3 `REGISTER` command, or an account invitation — would be
/// an administrator. Only OIDC provisioning and the bootstrap/recovery flows
/// may create one. Names are held casefolded, so no spelling of one slips past.
/// Built once from the configuration and shared by the core, the HTTP state,
/// and the deletion procedure.
#[derive(Debug, Clone, Default)]
pub struct ReservedAccountNames(std::sync::Arc<std::collections::HashSet<String>>);

impl ReservedAccountNames {
    pub fn new<'a>(names: impl IntoIterator<Item = &'a str>) -> Self {
        Self(std::sync::Arc::new(
            names
                .into_iter()
                .map(|name| e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(name))
                .collect(),
        ))
    }

    /// Whether `name`, in any spelling, is a configured administrator.
    pub fn reserves(&self, name: &str) -> bool {
        self.0
            .contains(&e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(name))
    }

    /// The configured administrators, casefolded, for storage queries.
    pub fn folded_names(&self) -> Vec<String> {
        self.0.iter().cloned().collect()
    }

    /// The one answer to "may an ordinary claim make `name` an account's name
    /// or nick?" — NickServ `REGISTER` and `GROUP`, the IRCv3 `REGISTER`
    /// command, an account an administrator creates, and an invitation all ask
    /// it, so a new claim path cannot forget one of the rules. (Storage refuses
    /// a services nick to every creation path, the privileged ones included.)
    pub fn claimable(&self, name: &str) -> Result<(), NameClaimRefusal> {
        let folded = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(name);
        if SERVICE_NICKS.contains(&folded.as_str()) {
            return Err(NameClaimRefusal::ServiceNick);
        }
        if self.0.contains(&folded) {
            return Err(NameClaimRefusal::ConfiguredAdministrator);
        }
        Ok(())
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
    fn a_new_password_holds_eight_characters_to_512_bytes_by_default() {
        let policy = PasswordPolicy::default();
        const EIGHT: usize = DEFAULT_MINIMUM_PASSWORD_CHARS;
        assert_eq!(
            policy.new_password("").err(),
            Some(PasswordRefusal::TooShort { minimum: EIGHT })
        );
        assert_eq!(
            policy.new_password("hunter2").err(),
            Some(PasswordRefusal::TooShort { minimum: EIGHT }),
            "seven characters are one too few"
        );
        assert!(policy.new_password("hunter22").is_ok(), "eight is enough");
        assert!(
            policy.new_password("pässwörd").is_ok(),
            "characters are counted, not bytes"
        );
        assert_eq!(
            policy.new_password("äöüäöüä").err(),
            Some(PasswordRefusal::TooShort { minimum: EIGHT }),
            "fourteen bytes are still seven characters"
        );
        assert_eq!(
            policy.new_password(&"p".repeat(513)).err(),
            Some(PasswordRefusal::TooLong { minimum: EIGHT })
        );
        assert_eq!(
            &*policy.new_password(&"p".repeat(512)).expect("fits"),
            "p".repeat(512)
        );
        assert_eq!(
            format!("{:?}", policy.new_password("hunter22").expect("fits")),
            "NewPassword(..)",
            "never printed"
        );
        assert_eq!(
            PasswordRefusal::TooShort { minimum: EIGHT }.explanation(),
            "Passwords must be at least 8 characters and at most 512 bytes."
        );
    }

    /// The minimum is one cell every surface reads: a change of it applies
    /// to the next password set, through every clone.
    #[test]
    fn the_password_minimum_is_followed_live() {
        let policy = PasswordPolicy::default();
        let surface = policy.clone();
        policy.set_minimum_chars(1);
        assert!(surface.new_password("sesame").is_ok());
        assert!(surface.new_password("x").is_ok());
        assert_eq!(
            surface.new_password("").err(),
            Some(PasswordRefusal::TooShort { minimum: 1 })
        );
        assert_eq!(
            PasswordRefusal::TooShort { minimum: 1 }.explanation(),
            "Passwords must be at least 1 character and at most 512 bytes."
        );
        policy.set_minimum_chars(MAX_MINIMUM_PASSWORD_CHARS);
        let longest_script = "\u{10348}".repeat(MAX_MINIMUM_PASSWORD_CHARS);
        assert_eq!(longest_script.len(), MAX_PASSWORD_LEN);
        assert!(
            surface.new_password(&longest_script).is_ok(),
            "the highest minimum is met in four-byte characters"
        );
        assert!(surface.new_password(&"p".repeat(127)).is_err());
    }

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
