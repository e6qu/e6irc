//! The PostgreSQL URL, read once into the connection it describes.
//!
//! sqlx reads a connection URL leniently: a query parameter it does not know
//! (`ssl_mode=verify-full`, a misspelt `sslmode` key) is dropped with a log line
//! nobody reads, and every field the URL leaves out is taken from libpq's
//! environment variables (`PGSSLMODE`, `PGHOST`, `PGPASSWORD`, ...) and from
//! `~/.pgpass`. A URL that asked for certificate verification in a spelling
//! sqlx does not read connected with `prefer` — no verification — and a stray
//! `PGSSLMODE=disable` in the service's environment turned TLS off.
//!
//! [`DatabaseUrl`] is parsed when the configuration is read. Every query key
//! must be one of [`QUERY_KEYS`] (the set `tools/postgres-url-environment.py`
//! accepts too, so a backup connects where the daemon does), each field may be
//! stated once, and the connection options are built field by field from what
//! the URL says: no password file is consulted, and the process connects to
//! no database while any of [`LIBPQ_ENVIRONMENT`] is set
//! ([`refuse_libpq_process_environment`], called by every entry point that
//! connects — the daemon's start, its database subcommands — and by `e6ircd
//! check`), because sqlx's only constructor fills the fields a URL leaves out
//! from them. The process environment is read there, at the process's own
//! boundary, so neither parsing a configuration nor building connection
//! options depends on the host they run on.
//!
//! No message about a URL repeats any of it: a malformed URL can put a
//! fragment of its password anywhere a parser looks. The URL's `Debug` and
//! `Display` forms show everything but the password.

use sqlx::postgres::{PgConnectOptions, PgSslMode};

/// One connection field a URL can state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UrlField {
    Host,
    Port,
    Database,
    User,
    Password,
    SslMode,
    SslRootCert,
    SslCert,
    SslKey,
    ApplicationName,
    Options,
    StatementCacheCapacity,
}

impl UrlField {
    /// The field's name in a refusal: its canonical query key.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Port => "port",
            Self::Database => "dbname",
            Self::User => "user",
            Self::Password => "password",
            Self::SslMode => "sslmode",
            Self::SslRootCert => "sslrootcert",
            Self::SslCert => "sslcert",
            Self::SslKey => "sslkey",
            Self::ApplicationName => "application_name",
            Self::Options => "options",
            Self::StatementCacheCapacity => "statement-cache-capacity",
        }
    }
}

/// Every query key the daemon reads, and the field each states. The closed
/// set: any other key is refused. `tools/postgres-url-environment.py` accepts
/// exactly these keys (a test compares the two lists); libpq's `hostaddr` and
/// `connect_timeout` are in neither, because sqlx cannot honour them as libpq
/// does (`hostaddr` would replace the name a certificate is verified against;
/// the daemon bounds every connection attempt itself).
pub(crate) const QUERY_KEYS: [(&str, UrlField); 17] = [
    ("host", UrlField::Host),
    ("port", UrlField::Port),
    ("dbname", UrlField::Database),
    ("user", UrlField::User),
    ("password", UrlField::Password),
    ("sslmode", UrlField::SslMode),
    ("ssl-mode", UrlField::SslMode),
    ("sslrootcert", UrlField::SslRootCert),
    ("ssl-root-cert", UrlField::SslRootCert),
    ("ssl-ca", UrlField::SslRootCert),
    ("sslcert", UrlField::SslCert),
    ("ssl-cert", UrlField::SslCert),
    ("sslkey", UrlField::SslKey),
    ("ssl-key", UrlField::SslKey),
    ("application_name", UrlField::ApplicationName),
    ("options", UrlField::Options),
    ("statement-cache-capacity", UrlField::StatementCacheCapacity),
];

/// libpq's environment variables that sqlx reads into every connection a URL
/// leaves a field of unstated. They are refused while the daemon is
/// configured with a database, rather than silently deciding where it
/// connects or whether TLS is verified.
pub const LIBPQ_ENVIRONMENT: [&str; 12] = [
    "PGHOST",
    "PGHOSTADDR",
    "PGPORT",
    "PGUSER",
    "PGPASSWORD",
    "PGDATABASE",
    "PGSSLMODE",
    "PGSSLROOTCERT",
    "PGSSLCERT",
    "PGSSLKEY",
    "PGAPPNAME",
    "PGOPTIONS",
];

/// Refuse while one of [`LIBPQ_ENVIRONMENT`] is set in `environment`. sqlx
/// fills every field a URL leaves out from them, so `PGSSLMODE=disable` left
/// in a service's environment would turn TLS off and `PGHOST` would redirect
/// the connection, each without a word. The URL is the whole description of
/// the connection; the refusal names every variable set and none of their
/// values. A variable set to the empty string counts as unset.
pub(crate) fn refuse_libpq_environment(
    environment: &impl Fn(&str) -> crate::environment_config::Lookup,
) -> Result<(), String> {
    let set: Vec<&str> = LIBPQ_ENVIRONMENT
        .into_iter()
        .filter(|variable| {
            !matches!(
                crate::environment_config::optional(environment, variable),
                Ok(None)
            )
        })
        .collect();
    if set.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{} set in the environment: e6ircd connects with what database.url states and \
         nothing else, so state the connection there and unset {}",
        set.join(", "),
        if set.len() == 1 { "it" } else { "them" }
    ))
}

/// [`refuse_libpq_environment`] against this process's environment: what every
/// entry point that connects to the database calls first.
pub fn refuse_libpq_process_environment() -> Result<(), super::DbError> {
    refuse_libpq_environment(&crate::environment_config::process_environment)
        .map_err(super::DbError::LibpqEnvironment)
}

/// Why a URL cannot be used. Says what is wrong, never what the URL holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseUrlError(String);

impl std::fmt::Display for DatabaseUrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "database.url cannot be used: {}", self.0)
    }
}

impl std::error::Error for DatabaseUrlError {}

fn refused(reason: impl Into<String>) -> DatabaseUrlError {
    DatabaseUrlError(reason.into())
}

/// Where the server is: a TCP host, or the directory of a Unix socket.
#[derive(Clone, PartialEq, Eq)]
enum Host {
    Network(String),
    SocketDirectory(String),
}

/// A PostgreSQL connection URL, parsed. See the module documentation.
#[derive(Clone, PartialEq, Eq)]
pub struct DatabaseUrl {
    host: Option<Host>,
    port: Option<u16>,
    database: Option<String>,
    user: Option<String>,
    password: Option<String>,
    ssl_mode: Option<SslMode>,
    ssl_root_cert: Option<String>,
    ssl_cert: Option<String>,
    ssl_key: Option<String>,
    application_name: Option<String>,
    /// `options`, as the run-time settings it states.
    options: Option<Vec<(String, String)>>,
    statement_cache_capacity: Option<usize>,
}

/// `sslmode`'s closed set of values, libpq's spelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SslMode {
    Disable,
    Allow,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

impl SslMode {
    const ALL: [(&'static str, Self); 6] = [
        ("disable", Self::Disable),
        ("allow", Self::Allow),
        ("prefer", Self::Prefer),
        ("require", Self::Require),
        ("verify-ca", Self::VerifyCa),
        ("verify-full", Self::VerifyFull),
    ];

    fn parse(value: &str) -> Result<Self, DatabaseUrlError> {
        Self::ALL
            .iter()
            .find(|(name, _)| *name == value)
            .map(|(_, mode)| *mode)
            .ok_or_else(|| {
                refused(
                    "its sslmode is none of disable, allow, prefer, require, verify-ca, \
                     verify-full",
                )
            })
    }

    fn name(self) -> &'static str {
        Self::ALL
            .iter()
            .find(|(_, mode)| *mode == self)
            .map(|(name, _)| *name)
            .expect("every sslmode has a name")
    }

    const fn to_sqlx(self) -> PgSslMode {
        match self {
            Self::Disable => PgSslMode::Disable,
            Self::Allow => PgSslMode::Allow,
            Self::Prefer => PgSslMode::Prefer,
            Self::Require => PgSslMode::Require,
            Self::VerifyCa => PgSslMode::VerifyCa,
            Self::VerifyFull => PgSslMode::VerifyFull,
        }
    }
}

/// `encoded` with its `%XX` escapes decoded, as sqlx and libpq's clients
/// decode it: a `%` not followed by two hexadecimal digits stands for itself.
fn decoded(component: &str, encoded: &str) -> Result<String, DatabaseUrlError> {
    let bytes = encoded.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let escape = match bytes.get(at..at + 3) {
            Some([b'%', high, low]) if high.is_ascii_hexdigit() && low.is_ascii_hexdigit() => {
                std::str::from_utf8(&[*high, *low])
                    .ok()
                    .and_then(|hex| u8::from_str_radix(hex, 16).ok())
            }
            _ => None,
        };
        match escape {
            Some(byte) => {
                out.push(byte);
                at += 3;
            }
            None => {
                out.push(bytes[at]);
                at += 1;
            }
        }
    }
    let value = String::from_utf8(out)
        .map_err(|_| refused(format!("its {component} is not percent-encoded UTF-8")))?;
    if value.contains('\0') {
        return Err(refused(format!("its {component} contains a NUL byte")));
    }
    Ok(value)
}

/// `value` with every byte outside the URL's unreserved set escaped.
fn encoded(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// libpq's `options`, read as the run-time settings it can carry: `-c
/// name=value`, `-cname=value` or `--name=value`, separated by whitespace, a
/// backslash escaping the character after it. sqlx sends settings, not a raw
/// command line, so anything else is refused rather than dropped.
fn settings_of(options: &str) -> Result<Vec<(String, String)>, DatabaseUrlError> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut characters = options.chars();
    while let Some(character) = characters.next() {
        match character {
            '\\' => {
                word.push(characters.next().ok_or_else(|| {
                    refused("its options end in a backslash that escapes nothing")
                })?);
                in_word = true;
            }
            character if character.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            character => {
                word.push(character);
                in_word = true;
            }
        }
    }
    if in_word {
        words.push(word);
    }
    let mut settings = Vec::new();
    let mut words = words.into_iter();
    while let Some(word) = words.next() {
        let setting = if word == "-c" {
            words.next()
        } else {
            word.strip_prefix("--")
                .or_else(|| word.strip_prefix("-c"))
                .map(str::to_owned)
        };
        let Some((name, value)) = setting
            .as_deref()
            .and_then(|setting| setting.split_once('='))
            .filter(|(name, _)| !name.is_empty())
        else {
            return Err(refused(
                "its options are not all run-time settings (-c name=value)",
            ));
        };
        settings.push((name.to_owned(), value.to_owned()));
    }
    if settings.is_empty() {
        return Err(refused("its options state no setting"));
    }
    Ok(settings)
}

/// Record `value` for `field`, refusing a field stated twice.
fn state<T>(slot: &mut Option<T>, field: UrlField, value: T) -> Result<(), DatabaseUrlError> {
    if slot.is_some() {
        return Err(refused(format!(
            "it states its {} more than once",
            field.name()
        )));
    }
    *slot = Some(value);
    Ok(())
}

fn host_of(value: String) -> Host {
    if value.starts_with('/') {
        Host::SocketDirectory(value)
    } else {
        Host::Network(value)
    }
}

impl DatabaseUrl {
    /// Parse `text`, refusing anything it cannot state exactly.
    pub fn parse(text: &str) -> Result<Self, DatabaseUrlError> {
        let (scheme, rest) = text
            .split_once("://")
            .ok_or_else(|| refused("it is not a URL"))?;
        if scheme != "postgres" && scheme != "postgresql" {
            return Err(refused(
                "its scheme is neither postgres:// nor postgresql://",
            ));
        }
        if rest.contains('#') {
            return Err(refused(
                "it contains a bare '#'; write one inside a value as %23",
            ));
        }
        let (before_query, query) = rest.split_once('?').unwrap_or((rest, ""));
        let (netloc, path) = before_query
            .find('/')
            .map_or((before_query, ""), |at| before_query.split_at(at));
        let mut url = Self {
            host: None,
            port: None,
            database: None,
            user: None,
            password: None,
            ssl_mode: None,
            ssl_root_cert: None,
            ssl_cert: None,
            ssl_key: None,
            application_name: None,
            options: None,
            statement_cache_capacity: None,
        };
        let (credentials, authority) = netloc.rsplit_once('@').unwrap_or(("", netloc));
        let (user, password) = credentials
            .split_once(':')
            .map_or((credentials, None), |(user, password)| {
                (user, Some(password))
            });
        if !user.is_empty() {
            url.user = Some(decoded("user name", user)?);
        }
        if let Some(password) = password {
            url.password = Some(decoded("password", password)?);
        }
        if authority.contains(',') {
            return Err(refused(
                "it lists several hosts; e6ircd connects to exactly one",
            ));
        }
        let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
            let (host, rest) = bracketed
                .split_once(']')
                .ok_or_else(|| refused("its bracketed host address is malformed"))?;
            if !rest.is_empty() && !rest.starts_with(':') {
                return Err(refused("its bracketed host address is malformed"));
            }
            (host, rest.strip_prefix(':').unwrap_or(""))
        } else {
            authority.split_once(':').unwrap_or((authority, ""))
        };
        if !host.is_empty() {
            url.host = Some(host_of(decoded("host", host)?));
        }
        if !port.is_empty() {
            url.port = Some(Self::port(port)?);
        }
        if let Some(database) = path.strip_prefix('/')
            && !database.is_empty()
        {
            if database.contains('/') {
                return Err(refused("its path names more than a database"));
            }
            url.database = Some(decoded("database name", database)?);
        }
        for pair in query.split('&').filter(|pair| !pair.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let key = decoded("query string", key)?;
            let Some((_, field)) = QUERY_KEYS.iter().find(|(known, _)| *known == key) else {
                let supported: Vec<&str> = QUERY_KEYS.iter().map(|(key, _)| *key).collect();
                return Err(refused(format!(
                    "it has a query parameter other than the supported {}",
                    supported.join(", ")
                )));
            };
            if value.contains('+') {
                return Err(refused(format!(
                    "its query parameter {key:?} has a bare '+', which one PostgreSQL client \
                     reads as a space and another as a plus sign; write %20 or %2B"
                )));
            }
            let value = decoded(&format!("query parameter {key:?}"), value)?;
            url.set(*field, value)?;
        }
        Ok(url)
    }

    fn port(value: &str) -> Result<u16, DatabaseUrlError> {
        value
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0 && value.bytes().all(|byte| byte.is_ascii_digit()))
            .ok_or_else(|| refused("its port is not a number from 1 to 65535"))
    }

    fn set(&mut self, field: UrlField, value: String) -> Result<(), DatabaseUrlError> {
        match field {
            UrlField::Host => state(&mut self.host, field, host_of(value)),
            UrlField::Port => state(&mut self.port, field, Self::port(&value)?),
            UrlField::Database => state(&mut self.database, field, value),
            UrlField::User => state(&mut self.user, field, value),
            UrlField::Password => state(&mut self.password, field, value),
            UrlField::SslMode => state(&mut self.ssl_mode, field, SslMode::parse(&value)?),
            UrlField::SslRootCert => state(&mut self.ssl_root_cert, field, value),
            UrlField::SslCert => state(&mut self.ssl_cert, field, value),
            UrlField::SslKey => state(&mut self.ssl_key, field, value),
            UrlField::ApplicationName => state(&mut self.application_name, field, value),
            UrlField::Options => state(&mut self.options, field, settings_of(&value)?),
            UrlField::StatementCacheCapacity => {
                let capacity = value
                    .parse::<usize>()
                    .map_err(|_| refused("its statement-cache-capacity is not a whole number"))?;
                state(&mut self.statement_cache_capacity, field, capacity)
            }
        }
    }

    /// The options every connection is made with. Each field is set from the
    /// URL or to libpq's documented default (port 5432, `sslmode=prefer`); no
    /// password file is read. sqlx's constructor still consults libpq's
    /// environment for the fields that have no way to be unset (the password,
    /// the certificates, `options`), which is why the process refuses to
    /// connect at all while one of [`LIBPQ_ENVIRONMENT`] is set
    /// ([`refuse_libpq_process_environment`]).
    pub fn connect_options(&self) -> PgConnectOptions {
        let mut options = PgConnectOptions::new_without_pgpass()
            .port(self.port.unwrap_or(5432))
            .ssl_mode(self.ssl_mode.unwrap_or(SslMode::Prefer).to_sqlx())
            .statement_cache_capacity(self.statement_cache_capacity.unwrap_or(100));
        match &self.host {
            Some(Host::Network(host)) => options = options.host(host),
            Some(Host::SocketDirectory(directory)) => options = options.socket(directory),
            None => {}
        }
        if let Some(user) = &self.user {
            options = options.username(user);
        }
        if let Some(password) = &self.password {
            options = options.password(password);
        }
        if let Some(database) = &self.database {
            options = options.database(database);
        }
        if let Some(path) = &self.ssl_root_cert {
            options = options.ssl_root_cert(path);
        }
        if let Some(path) = &self.ssl_cert {
            options = options.ssl_client_cert(path);
        }
        if let Some(path) = &self.ssl_key {
            options = options.ssl_client_key(path);
        }
        if let Some(name) = &self.application_name {
            options = options.application_name(name);
        }
        if let Some(settings) = &self.options {
            options = options.options(settings.iter().map(|(name, value)| (name, value)));
        }
        options
    }
}

impl std::str::FromStr for DatabaseUrl {
    type Err = DatabaseUrlError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

impl<'de> serde::Deserialize<'de> for DatabaseUrl {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = zeroize::Zeroizing::new(String::deserialize(deserializer)?);
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// Everything but the password, in URL form, so a log line or a `Debug` dump
/// says where the server connects without saying how it authenticates.
impl std::fmt::Display for DatabaseUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            host,
            port,
            database,
            user,
            password,
            ssl_mode,
            ssl_root_cert,
            ssl_cert,
            ssl_key,
            application_name,
            options,
            statement_cache_capacity,
        } = self;
        let encode = encoded;
        write!(f, "postgres://")?;
        if let Some(user) = user {
            write!(f, "{}", encode(user))?;
        }
        if password.is_some() {
            write!(f, ":<redacted>")?;
        }
        if user.is_some() || password.is_some() {
            write!(f, "@")?;
        }
        if let Some(Host::Network(host)) = host {
            if host.contains(':') {
                write!(f, "[{host}]")?;
            } else {
                write!(f, "{}", encode(host))?;
            }
        }
        if let Some(port) = port {
            write!(f, ":{port}")?;
        }
        if let Some(database) = database {
            write!(f, "/{}", encode(database))?;
        }
        let mut query = Vec::new();
        if let Some(Host::SocketDirectory(directory)) = host {
            query.push(format!("host={}", encode(directory)));
        }
        if let Some(mode) = ssl_mode {
            query.push(format!("sslmode={}", mode.name()));
        }
        for (key, value) in [
            ("sslrootcert", ssl_root_cert),
            ("sslcert", ssl_cert),
            ("sslkey", ssl_key),
            ("application_name", application_name),
        ] {
            if let Some(value) = value {
                query.push(format!("{key}={}", encode(value)));
            }
        }
        if let Some(settings) = options {
            let line: Vec<String> = settings
                .iter()
                .map(|(name, value)| format!("-c {name}={value}"))
                .collect();
            query.push(format!("options={}", encode(&line.join(" "))));
        }
        if let Some(capacity) = statement_cache_capacity {
            query.push(format!("statement-cache-capacity={capacity}"));
        }
        if !query.is_empty() {
            write!(f, "?{}", query.join("&"))?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for DatabaseUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DatabaseUrl({self})")
    }
}

impl Drop for DatabaseUrl {
    fn drop(&mut self) {
        if let Some(password) = &mut self.password {
            zeroize::Zeroize::zeroize(password);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal(text: &str) -> String {
        DatabaseUrl::parse(text)
            .expect_err("the URL must be refused")
            .to_string()
    }

    #[test]
    fn an_unknown_query_key_is_refused_without_repeating_the_url() {
        for text in [
            "postgres://u:hunter2@db.example/e6irc?ssl_mode=verify-full",
            "postgres://u:hunter2@db.example/e6irc?target_session_attrs=hunter2",
            "postgres://u:hunter2@db.example/e6irc?connect_timeout=5",
            "postgres://u:hunter2@db.example/e6irc?hostaddr=192.0.2.1",
            "postgres://u:hunter2@db.example/e6irc?options[search_path]=hunter2",
        ] {
            let message = refusal(text);
            assert!(message.contains("query parameter other than"), "{message}");
            assert!(!message.contains("hunter2"), "{message}");
            assert!(!message.contains("db.example"), "{message}");
        }
    }

    #[test]
    fn a_misspelt_sslmode_value_is_refused() {
        for mode in ["verify_full", "Verify-Full", "verify-ful", ""] {
            let message = refusal(&format!("postgres://db.example/e6irc?sslmode={mode}"));
            assert!(message.contains("sslmode is none of"), "{mode}: {message}");
        }
    }

    #[test]
    fn a_field_stated_twice_is_refused() {
        for text in [
            "postgres://db.example/e6irc?sslmode=require&ssl-mode=verify-full",
            "postgres://alice@db.example/e6irc?user=bob",
            "postgres://db.example/e6irc?host=other.example",
            "postgres://db.example/e6irc?dbname=other",
            "postgres://db.example/e6irc?options=-c%20a%3D1&options=-c%20b%3D2",
        ] {
            assert!(refusal(text).contains("more than once"), "{text}");
        }
    }

    #[test]
    fn malformed_urls_are_refused_by_what_is_wrong() {
        for (text, reason) in [
            ("mysql://db.example/e6irc", "scheme"),
            ("db.example/e6irc", "not a URL"),
            ("postgres://u:hunter2#x@db.example/e6irc", "'#'"),
            (
                "postgres://u:hunter2@one.example,two.example/e6irc",
                "several hosts",
            ),
            ("postgres://u:hunter2@db.example:hunter2/e6irc", "port"),
            ("postgres://u:hunter2@db.example:0/e6irc", "port"),
            (
                "postgres://u:hunter%FF2@db.example/e6irc",
                "percent-encoded",
            ),
            ("postgres://db.example/e6irc?options=-c+x", "bare '+'"),
            ("postgres://db.example/a/b", "more than a database"),
            ("postgres://[::1/e6irc", "bracketed"),
        ] {
            let message = refusal(text);
            assert!(message.contains(reason), "{text}: {message}");
            assert!(!message.contains("hunter"), "{message}");
        }
    }

    #[test]
    fn every_accepted_key_reaches_the_connection_options() {
        let url = DatabaseUrl::parse(
            "postgresql://e6irc%20user:p%40ss@db.example:6543/e6irc_db?sslmode=verify-full\
             &sslrootcert=/etc/ca.pem&sslcert=/etc/client.pem&sslkey=/etc/client.key\
             &application_name=e6ircd&options=-c%20search_path%3Dpublic\
             &statement-cache-capacity=7",
        )
        .expect("a complete URL");
        let options = url.connect_options();
        assert_eq!(options.get_host(), "db.example");
        assert_eq!(options.get_port(), 6543);
        assert_eq!(options.get_username(), "e6irc user");
        assert_eq!(options.get_database(), Some("e6irc_db"));
        assert!(matches!(options.get_ssl_mode(), PgSslMode::VerifyFull));
        assert_eq!(options.get_application_name(), Some("e6ircd"));
        assert_eq!(options.get_options(), Some("-c search_path=public"));
        // The remaining fields have no getter; their Debug form names them.
        let debug = format!("{options:?}");
        for expected in [
            "/etc/ca.pem",
            "/etc/client.pem",
            "/etc/client.key",
            "statement_cache_capacity: 7",
            "p@ss",
        ] {
            assert!(debug.contains(expected), "{expected} in {debug}");
        }
    }

    #[test]
    fn every_alias_states_the_field_its_canonical_key_does() {
        for (key, field) in QUERY_KEYS {
            let value = match field {
                UrlField::Port => "6543",
                UrlField::SslMode => "require",
                UrlField::StatementCacheCapacity => "3",
                UrlField::Options => "-c%20a%3Db",
                _ => "x",
            };
            let url = DatabaseUrl::parse(&format!("postgres:///?{key}={value}"))
                .unwrap_or_else(|error| panic!("{key}: {error}"));
            let canonical = DatabaseUrl::parse(&format!("postgres:///?{}={value}", field.name()))
                .unwrap_or_else(|error| panic!("{key}: {error}"));
            assert!(url == canonical, "{key} states {}", field.name());
        }
    }

    #[test]
    fn a_url_without_sslmode_connects_with_libpq_s_default_whatever_the_environment_says() {
        let options = DatabaseUrl::parse("postgres://db.example/e6irc")
            .expect("URL")
            .connect_options();
        assert!(matches!(options.get_ssl_mode(), PgSslMode::Prefer));
        assert_eq!(options.get_port(), 5432);
    }

    #[test]
    fn a_socket_directory_host_connects_through_the_socket() {
        let url = DatabaseUrl::parse("postgres:///e6irc?host=%2Fvar%2Frun%2Fpostgresql")
            .expect("socket URL");
        assert_eq!(
            url.connect_options().get_socket(),
            Some(&std::path::PathBuf::from("/var/run/postgresql"))
        );
        let bracketed = DatabaseUrl::parse("postgres://[::1]:5524/e6irc").expect("IPv6 URL");
        assert_eq!(bracketed.connect_options().get_host(), "::1");
        assert_eq!(bracketed.to_string(), "postgres://[::1]:5524/e6irc");
    }

    #[test]
    fn the_shown_form_never_carries_the_password() {
        let url = DatabaseUrl::parse(
            "postgres://alice:hunter2@db.example:5433/e6irc?password=x&sslmode=require",
        );
        assert!(url.is_err(), "a password stated twice is refused");
        let url =
            DatabaseUrl::parse("postgres://alice:hunter2@db.example:5433/e6irc?sslmode=require")
                .expect("URL");
        for shown in [url.to_string(), format!("{url:?}")] {
            assert!(!shown.contains("hunter2"), "{shown}");
            assert!(
                shown.contains("alice:<redacted>@db.example:5433/e6irc"),
                "{shown}"
            );
            assert!(shown.contains("sslmode=require"), "{shown}");
        }
        let in_query =
            DatabaseUrl::parse("postgres://db.example/e6irc?password=hunter2").expect("URL");
        assert!(!format!("{in_query:?}").contains("hunter2"));
    }

    /// `tools/postgres-url-environment.py` splits the same URL for libpq's
    /// clients (backups, restores). A key one of them accepts and the other
    /// does not would make a backup connect somewhere the daemon does not, or
    /// the daemon refuse a URL its backups use.
    #[test]
    fn the_backup_tools_accept_exactly_the_keys_the_daemon_does() {
        let tool = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tools/postgres-url-environment.py"
        ))
        .expect("read tools/postgres-url-environment.py");
        let quoted_keys = |start: &str, end: &str| -> Vec<String> {
            let block = tool
                .split_once(start)
                .and_then(|(_, rest)| rest.split_once(end))
                .map(|(block, _)| block)
                .unwrap_or_else(|| panic!("the tool defines {start}"));
            block
                .lines()
                .filter_map(|line| {
                    let line = line.trim();
                    let quoted = line.strip_prefix('"')?;
                    quoted.split_once('"').map(|(key, _)| key.to_owned())
                })
                .collect()
        };
        let mut tool_keys = quoted_keys("QUERY_PARAMETERS = {", "}");
        tool_keys.extend(quoted_keys("DAEMON_ONLY_PARAMETERS = {", "}"));
        tool_keys.sort();
        let mut daemon_keys: Vec<String> = QUERY_KEYS
            .iter()
            .map(|(key, _)| (*key).to_owned())
            .collect();
        daemon_keys.sort();
        assert_eq!(tool_keys, daemon_keys);
    }

    /// A libpq variable set in the environment is refused by name — sqlx
    /// would otherwise read it into every connection the URL leaves a field
    /// of unstated — and one set to the empty string counts as unset.
    #[test]
    fn a_libpq_variable_in_the_environment_is_refused_by_name() {
        let environment = |variable: &str| -> crate::environment_config::Lookup {
            Ok(match variable {
                "PGSSLMODE" => Some("disable".into()),
                "PGHOST" => Some("elsewhere.example".into()),
                "PGPASSWORD" => Some(String::new()),
                _ => None,
            })
        };
        let refusal = super::refuse_libpq_environment(&environment)
            .expect_err("PGSSLMODE and PGHOST are refused");
        assert!(refusal.contains("PGHOST, PGSSLMODE set"), "{refusal}");
        assert!(
            !refusal.contains("PGPASSWORD"),
            "set-but-empty is unset: {refusal}"
        );
        assert!(!refusal.contains("disable") && !refusal.contains("elsewhere"));
        assert!(super::refuse_libpq_environment(&|_: &str| Ok(None)).is_ok());
    }
}
