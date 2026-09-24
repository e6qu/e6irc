//! The daemon's configuration, stated as environment variables.
//!
//! A container deployment injects plain settings and secrets (the database
//! URL, the OpenID Connect client secret) as environment variables. A shell
//! entrypoint used to render them into a TOML file for the daemon to read,
//! which kept a shell and a secrets-bearing temporary file in the image and
//! made TOML quoting a bug class of its own. The daemon now builds the same
//! document itself, in memory: `e6ircd --config-from-environment`. The result
//! goes through exactly the parser and validation a configuration file does,
//! so the two ingresses cannot disagree about what a valid configuration is.
//!
//! Required:  `E6IRC_SERVER_NAME`  `E6IRC_PUBLIC_URL`  `E6IRC_DATABASE_URL`
//!            `APPLICATION_RELEASE_REVISION`
//! Optional:  `E6IRC_NETWORK_NAME` (default `e6qu`)
//!            `E6IRC_HTTP_ADDR` (default `0.0.0.0:8080`)
//!            `E6IRC_IRC_ADDR` (default `127.0.0.1:6667`: IRC is reached over
//!              `/ws/irc` publicly; the raw port stays internal)
//!            `E6IRC_SECURE_COOKIES` (exactly `true` or `false`; default `true`)
//!            `E6IRC_HSTS_INCLUDE_SUBDOMAINS` (exactly `true` or `false`;
//!              default `false`: HSTS covers this origin only)
//!            `E6IRC_ADMIN_ACCOUNTS` (comma-separated)
//!            `E6IRC_BOOTSTRAP_TOKEN` (one-time first-administrator secret)
//!            `E6IRC_DATABASE_MAX_CONNECTIONS` (a whole number, 2 to 200;
//!              default sized to the host — see `database.max_connections`)
//!            OpenID Connect, all required together once the issuer is set:
//!              `E6IRC_OIDC_ISSUER`  `E6IRC_OIDC_CLIENT_ID`
//!              `E6IRC_OIDC_CLIENT_SECRET`  `E6IRC_OIDC_END_SESSION`
//!              `E6IRC_OIDC_NAME` (default `shauth`)
//!              `E6IRC_OIDC_ACCOUNT_CLAIM` (default `preferred_username`)
//!              `E6IRC_OIDC_TOKEN_AUTH` (default `client_secret_post`: the
//!                method belongs to the client registration, so discovery
//!                cannot report it)
//!
//! `E6IRC_SECRET_KEY` and `E6IRC_PREVIOUS_SECRET_KEYS` are read by the
//! configuration itself, whichever way it was stated.
//!
//! A variable that is set but empty is unset, as it was for the shell. No
//! refusal ever prints a value: every one of them may be a secret.

use toml::{Table, Value};

/// Where the HTTP listener binds when `E6IRC_HTTP_ADDR` is unset. `e6ircd
/// healthcheck` falls back to the same value, so the probe and the listener
/// cannot drift apart.
pub const DEFAULT_HTTP_ADDR: &str = "0.0.0.0:8080";
/// The variable naming the HTTP listener address.
pub const HTTP_ADDR_VARIABLE: &str = "E6IRC_HTTP_ADDR";

const DEFAULT_IRC_ADDR: &str = "127.0.0.1:6667";
const DEFAULT_NETWORK_NAME: &str = "e6qu";
const DEFAULT_OIDC_NAME: &str = "shauth";
const DEFAULT_OIDC_ACCOUNT_CLAIM: &str = "preferred_username";
const DEFAULT_OIDC_TOKEN_AUTH: &str = "client_secret_post";

/// Variables the shell entrypoint honoured that have nothing left to mean.
/// Ignoring one would be a silent no-op for an operator who still sets it.
const RETIRED: [(&str, &str); 2] = [
    (
        "E6IRC_CONFIG_PATH",
        "the configuration is built in memory and never written to a file",
    ),
    (
        "E6IRC_BINARY",
        "the daemon reads the environment itself; there is no entrypoint script to redirect",
    ),
];

/// Why the environment does not state a configuration. Names variables, never
/// their values.
#[derive(Debug, PartialEq, Eq)]
pub enum EnvironmentConfigError {
    Missing {
        variable: &'static str,
        /// The variable whose presence made this one required, if any.
        because_of: Option<&'static str>,
    },
    NotUnicode(&'static str),
    ControlCharacter(&'static str),
    NotBoolean(&'static str),
    NotWholeNumber(&'static str),
    Retired {
        variable: &'static str,
        reason: &'static str,
    },
}

impl std::fmt::Display for EnvironmentConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing {
                variable,
                because_of: None,
            } => write!(f, "{variable} is required"),
            Self::Missing {
                variable,
                because_of: Some(cause),
            } => write!(f, "{variable} is required when {cause} is set"),
            Self::NotUnicode(variable) => write!(f, "{variable} is not valid Unicode"),
            Self::ControlCharacter(variable) => write!(
                f,
                "{variable} contains a control character (a carriage return or newline pasted \
                 with the value?)"
            ),
            Self::NotBoolean(variable) => write!(f, "{variable} must be exactly true or false"),
            Self::NotWholeNumber(variable) => write!(f, "{variable} must be a whole number"),
            Self::Retired { variable, reason } => {
                write!(f, "{variable} is no longer honoured: {reason}; unset it")
            }
        }
    }
}

impl std::error::Error for EnvironmentConfigError {}

/// One variable as the process sees it: absent, or its value, or not Unicode.
pub type Lookup = Result<Option<String>, std::ffi::OsString>;

/// The process environment, as [`configuration_table`] reads it.
pub fn process_environment(variable: &str) -> Lookup {
    match std::env::var(variable) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(raw)) => Err(raw),
    }
}

struct Environment<'a, E: Fn(&str) -> Lookup>(&'a E);

impl<E: Fn(&str) -> Lookup> Environment<'_, E> {
    /// A set, non-empty value. A control character cannot be part of any of
    /// these settings; it arrives as the line break of a value pasted into a
    /// secret store, and is refused by name here rather than surfacing later
    /// as an unexplained connection failure.
    fn optional(&self, variable: &'static str) -> Result<Option<String>, EnvironmentConfigError> {
        let value = (self.0)(variable).map_err(|_| EnvironmentConfigError::NotUnicode(variable))?;
        match value {
            Some(value) if value.chars().any(char::is_control) => {
                Err(EnvironmentConfigError::ControlCharacter(variable))
            }
            Some(value) if !value.is_empty() => Ok(Some(value)),
            Some(_) | None => Ok(None),
        }
    }

    fn required(
        &self,
        variable: &'static str,
        because_of: Option<&'static str>,
    ) -> Result<Value, EnvironmentConfigError> {
        self.optional(variable)?
            .map(Value::String)
            .ok_or(EnvironmentConfigError::Missing {
                variable,
                because_of,
            })
    }

    fn or_default(
        &self,
        variable: &'static str,
        default: &str,
    ) -> Result<Value, EnvironmentConfigError> {
        Ok(Value::String(
            self.optional(variable)?
                .unwrap_or_else(|| default.to_owned()),
        ))
    }
}

/// One variable read outside [`configuration_table`] by the same rule it
/// applies: set-but-empty is unset, and a control character is refused by
/// name. Every environment read goes through this rule, so a value cannot mean
/// "unset" to one reader and an error or a different value to another.
pub fn optional(
    environment: &impl Fn(&str) -> Lookup,
    variable: &'static str,
) -> Result<Option<String>, EnvironmentConfigError> {
    Environment(environment).optional(variable)
}

/// The address the HTTP listener binds, as [`configuration_table`] states it;
/// `e6ircd healthcheck` probes the same address the server bound.
pub fn http_addr(environment: &impl Fn(&str) -> Lookup) -> Result<String, EnvironmentConfigError> {
    Ok(optional(environment, HTTP_ADDR_VARIABLE)?.unwrap_or_else(|| DEFAULT_HTTP_ADDR.to_owned()))
}

/// Every OIDC setting that means something only beside `E6IRC_OIDC_ISSUER`.
const OIDC_DEPENDENTS: [&str; 6] = [
    "E6IRC_OIDC_NAME",
    "E6IRC_OIDC_CLIENT_ID",
    "E6IRC_OIDC_CLIENT_SECRET",
    "E6IRC_OIDC_ACCOUNT_CLAIM",
    "E6IRC_OIDC_TOKEN_AUTH",
    "E6IRC_OIDC_END_SESSION",
];

/// The configuration document the environment states, ready for the same
/// parser a configuration file goes through.
pub fn configuration_table(
    environment: &impl Fn(&str) -> Lookup,
) -> Result<Table, EnvironmentConfigError> {
    let environment = Environment(environment);
    for (variable, reason) in RETIRED {
        if environment.optional(variable)?.is_some() {
            return Err(EnvironmentConfigError::Retired { variable, reason });
        }
    }

    let mut root = Table::new();
    root.insert(
        "server_name".into(),
        environment.required("E6IRC_SERVER_NAME", None)?,
    );
    root.insert(
        "network_name".into(),
        environment.or_default("E6IRC_NETWORK_NAME", DEFAULT_NETWORK_NAME)?,
    );
    root.insert(
        "application_release_revision".into(),
        environment.required("APPLICATION_RELEASE_REVISION", None)?,
    );

    let mut listener = Table::new();
    listener.insert(
        "addr".into(),
        environment.or_default("E6IRC_IRC_ADDR", DEFAULT_IRC_ADDR)?,
    );
    root.insert(
        "listeners".into(),
        Value::Array(vec![Value::Table(listener)]),
    );

    let mut http = Table::new();
    http.insert("addr".into(), Value::String(http_addr(environment.0)?));
    http.insert(
        "public_url".into(),
        environment.required("E6IRC_PUBLIC_URL", None)?,
    );
    let secure_cookies = match environment.optional("E6IRC_SECURE_COOKIES")?.as_deref() {
        None | Some("true") => true,
        Some("false") => false,
        Some(_) => return Err(EnvironmentConfigError::NotBoolean("E6IRC_SECURE_COOKIES")),
    };
    http.insert("secure_cookies".into(), Value::Boolean(secure_cookies));
    let hsts_include_subdomains = match environment
        .optional("E6IRC_HSTS_INCLUDE_SUBDOMAINS")?
        .as_deref()
    {
        None | Some("false") => false,
        Some("true") => true,
        Some(_) => {
            return Err(EnvironmentConfigError::NotBoolean(
                "E6IRC_HSTS_INCLUDE_SUBDOMAINS",
            ));
        }
    };
    http.insert(
        "hsts_include_subdomains".into(),
        Value::Boolean(hsts_include_subdomains),
    );
    if let Some(accounts) = environment.optional("E6IRC_ADMIN_ACCOUNTS")? {
        // An empty field (a trailing or doubled comma) names no account.
        let accounts = accounts
            .split(',')
            .filter(|account| !account.is_empty())
            .map(|account| Value::String(account.to_owned()))
            .collect();
        http.insert("admin_accounts".into(), Value::Array(accounts));
    }
    root.insert("http".into(), Value::Table(http));

    let mut database = Table::new();
    database.insert(
        "url".into(),
        environment.required("E6IRC_DATABASE_URL", None)?,
    );
    const MAX_CONNECTIONS: &str = "E6IRC_DATABASE_MAX_CONNECTIONS";
    if let Some(stated) = environment.optional(MAX_CONNECTIONS)? {
        // The bounds are the configuration's to enforce, by the same parser a
        // file goes through; this only turns the text into a number.
        let connections: i64 = stated
            .parse()
            .map_err(|_| EnvironmentConfigError::NotWholeNumber(MAX_CONNECTIONS))?;
        database.insert("max_connections".into(), Value::Integer(connections));
    }
    root.insert("database".into(), Value::Table(database));

    if let Some(token) = environment.optional("E6IRC_BOOTSTRAP_TOKEN")? {
        let mut bootstrap = Table::new();
        bootstrap.insert("token".into(), Value::String(token));
        root.insert("bootstrap".into(), Value::Table(bootstrap));
    }

    const ISSUER: &str = "E6IRC_OIDC_ISSUER";
    if let Some(issuer) = environment.optional(ISSUER)? {
        let mut provider = Table::new();
        provider.insert(
            "name".into(),
            environment.or_default("E6IRC_OIDC_NAME", DEFAULT_OIDC_NAME)?,
        );
        provider.insert("issuer_url".into(), Value::String(issuer));
        provider.insert(
            "client_id".into(),
            environment.required("E6IRC_OIDC_CLIENT_ID", Some(ISSUER))?,
        );
        provider.insert(
            "client_secret".into(),
            environment.required("E6IRC_OIDC_CLIENT_SECRET", Some(ISSUER))?,
        );
        // `OidcProviderConfig::account_claim` carries no serde default, so the
        // default is stated here rather than left for the parser to refuse.
        provider.insert(
            "account_claim".into(),
            environment.or_default("E6IRC_OIDC_ACCOUNT_CLAIM", DEFAULT_OIDC_ACCOUNT_CLAIM)?,
        );
        provider.insert(
            "token_endpoint_auth_method".into(),
            environment.or_default("E6IRC_OIDC_TOKEN_AUTH", DEFAULT_OIDC_TOKEN_AUTH)?,
        );
        provider.insert(
            "end_session_endpoint".into(),
            environment.required("E6IRC_OIDC_END_SESSION", Some(ISSUER))?,
        );
        root.insert("oidc".into(), Value::Array(vec![Value::Table(provider)]));
    } else {
        // Without the issuer the rest configure nothing; starting with sign-in
        // off while they sit set would be a silent no-op (a misspelt issuer).
        for dependent in OIDC_DEPENDENTS {
            if environment.optional(dependent)?.is_some() {
                return Err(EnvironmentConfigError::Missing {
                    variable: ISSUER,
                    because_of: Some(dependent),
                });
            }
        }
    }

    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

    fn minimal() -> Vec<(&'static str, &'static str)> {
        vec![
            ("E6IRC_SERVER_NAME", "irc.example"),
            ("E6IRC_PUBLIC_URL", "https://irc.example"),
            (
                "E6IRC_DATABASE_URL",
                "postgres://e6irc:pa\"ss\\word@db.example/e6irc",
            ),
            ("APPLICATION_RELEASE_REVISION", REVISION),
        ]
    }

    fn with(
        mut base: Vec<(&'static str, &'static str)>,
        extra: &[(&'static str, &'static str)],
    ) -> Vec<(&'static str, &'static str)> {
        base.extend_from_slice(extra);
        base
    }

    fn table(pairs: &[(&'static str, &'static str)]) -> Result<Table, EnvironmentConfigError> {
        configuration_table(&|variable: &str| {
            Ok(pairs
                .iter()
                .rev()
                .find(|(name, _)| *name == variable)
                .map(|(_, value)| (*value).to_owned()))
        })
    }

    fn config(pairs: &[(&'static str, &'static str)]) -> Config {
        Config::from_table(table(pairs).expect("environment states a configuration"))
            .expect("the stated configuration is valid")
    }

    #[test]
    fn the_minimal_environment_is_a_valid_configuration_with_the_documented_defaults() {
        let table = table(&minimal()).unwrap();
        assert_eq!(table["network_name"].as_str(), Some("e6qu"));
        assert_eq!(table["http"]["addr"].as_str(), Some(DEFAULT_HTTP_ADDR));
        assert_eq!(table["http"]["secure_cookies"].as_bool(), Some(true));
        assert_eq!(
            table["listeners"][0]["addr"].as_str(),
            Some("127.0.0.1:6667")
        );
        assert!(!table.contains_key("oidc"));
        assert!(!table.contains_key("bootstrap"));
        // A value needs no quoting on its way in: what the daemon gets is what
        // the operator stated, quotes and backslashes included.
        assert_eq!(
            table["database"]["url"].as_str(),
            Some("postgres://e6irc:pa\"ss\\word@db.example/e6irc")
        );
        config(&minimal());
    }

    /// Every field the provider struct requires must be present, or the whole
    /// configuration fails to parse and the container never listens.
    #[test]
    fn an_issuer_brings_a_complete_provider_block() {
        let oidc = [
            ("E6IRC_OIDC_ISSUER", "https://auth.example"),
            ("E6IRC_OIDC_CLIENT_ID", "e6irc"),
            ("E6IRC_OIDC_CLIENT_SECRET", "client-secret"),
            ("E6IRC_OIDC_END_SESSION", "https://auth.example/logout"),
        ];
        let stated = with(minimal(), &oidc);
        let table = table(&stated).unwrap();
        let provider = &table["oidc"][0];
        assert_eq!(provider["name"].as_str(), Some("shauth"));
        assert_eq!(
            provider["account_claim"].as_str(),
            Some("preferred_username")
        );
        assert_eq!(
            provider["token_endpoint_auth_method"].as_str(),
            Some("client_secret_post")
        );
        config(&stated);

        // ...and the claim stays operator-selectable.
        let stated = with(stated, &[("E6IRC_OIDC_ACCOUNT_CLAIM", "email")]);
        assert_eq!(
            self::table(&stated).unwrap()["oidc"][0]["account_claim"].as_str(),
            Some("email")
        );

        for missing in [
            "E6IRC_OIDC_CLIENT_ID",
            "E6IRC_OIDC_CLIENT_SECRET",
            "E6IRC_OIDC_END_SESSION",
        ] {
            let partial: Vec<_> = with(minimal(), &oidc)
                .into_iter()
                .filter(|(name, _)| *name != missing)
                .collect();
            assert_eq!(
                self::table(&partial),
                Err(EnvironmentConfigError::Missing {
                    variable: missing,
                    because_of: Some("E6IRC_OIDC_ISSUER"),
                })
            );
        }
    }

    #[test]
    fn an_oidc_setting_without_the_issuer_is_refused_rather_than_ignored() {
        for dependent in OIDC_DEPENDENTS {
            assert_eq!(
                table(&with(minimal(), &[(dependent, "stated")])),
                Err(EnvironmentConfigError::Missing {
                    variable: "E6IRC_OIDC_ISSUER",
                    because_of: Some(dependent),
                })
            );
        }
    }

    #[test]
    fn the_healthcheck_reads_an_empty_http_address_as_the_default_like_the_server() {
        let lookup = |value: &'static str| {
            move |variable: &str| Ok((variable == HTTP_ADDR_VARIABLE).then(|| value.to_owned()))
        };
        assert_eq!(http_addr(&lookup("")), Ok(DEFAULT_HTTP_ADDR.to_owned()));
        assert_eq!(
            http_addr(&lookup("127.0.0.1:9")),
            Ok("127.0.0.1:9".to_owned())
        );
        let empty = with(minimal(), &[(HTTP_ADDR_VARIABLE, "")]);
        assert_eq!(
            table(&empty).unwrap()["http"]["addr"].as_str(),
            Some(DEFAULT_HTTP_ADDR)
        );
    }

    #[test]
    fn each_required_variable_is_refused_by_name_when_absent_or_empty() {
        for required in [
            "E6IRC_SERVER_NAME",
            "E6IRC_PUBLIC_URL",
            "E6IRC_DATABASE_URL",
            "APPLICATION_RELEASE_REVISION",
        ] {
            let absent: Vec<_> = minimal()
                .into_iter()
                .filter(|(name, _)| *name != required)
                .collect();
            let expected = Err(EnvironmentConfigError::Missing {
                variable: required,
                because_of: None,
            });
            assert_eq!(table(&absent), expected);
            assert_eq!(table(&with(absent, &[(required, "")])), expected);
        }
    }

    #[test]
    fn the_database_pool_size_is_a_bounded_whole_number() {
        let stated = with(minimal(), &[("E6IRC_DATABASE_MAX_CONNECTIONS", "48")]);
        assert_eq!(
            config(&stated)
                .database
                .expect("database")
                .pool_size()
                .get(),
            48
        );
        assert_eq!(
            table(&with(
                minimal(),
                &[("E6IRC_DATABASE_MAX_CONNECTIONS", "many")]
            )),
            Err(EnvironmentConfigError::NotWholeNumber(
                "E6IRC_DATABASE_MAX_CONNECTIONS"
            ))
        );
        for out_of_bounds in ["1", "201"] {
            let stated = with(
                minimal(),
                &[("E6IRC_DATABASE_MAX_CONNECTIONS", out_of_bounds)],
            );
            let error = Config::from_table(table(&stated).expect("a whole number"))
                .expect_err("outside 2..=200");
            assert!(
                error.to_string().contains("database.max_connections"),
                "{error}"
            );
        }
    }

    #[test]
    fn empty_administrator_fields_name_no_account() {
        for (stated, expected) in [
            ("alice", vec!["alice"]),
            ("alice,", vec!["alice"]),
            ("alice,,bob,", vec!["alice", "bob"]),
        ] {
            let table = table(&with(minimal(), &[("E6IRC_ADMIN_ACCOUNTS", stated)])).unwrap();
            let accounts: Vec<_> = table["http"]["admin_accounts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|account| account.as_str().unwrap())
                .collect();
            assert_eq!(accounts, expected, "{stated}");
        }
    }

    #[test]
    fn a_refusal_names_the_variable_and_never_the_value() {
        let pasted = "postgres://e6irc:hunter2@db.example/e6irc\r\n";
        let error = table(&with(minimal(), &[("E6IRC_DATABASE_URL", pasted)])).unwrap_err();
        assert_eq!(
            error,
            EnvironmentConfigError::ControlCharacter("E6IRC_DATABASE_URL")
        );
        assert!(!error.to_string().contains("hunter2"), "{error}");

        let error = table(&with(minimal(), &[("E6IRC_SECURE_COOKIES", "yes")])).unwrap_err();
        assert_eq!(
            error,
            EnvironmentConfigError::NotBoolean("E6IRC_SECURE_COOKIES")
        );
        assert_eq!(
            table(&with(minimal(), &[("E6IRC_SECURE_COOKIES", "false")])).unwrap()["http"]
                ["secure_cookies"]
                .as_bool(),
            Some(false)
        );

        let not_unicode = configuration_table(&|variable: &str| {
            if variable == "E6IRC_SERVER_NAME" {
                Err(std::ffi::OsString::from("raw"))
            } else {
                Ok(None)
            }
        });
        assert_eq!(
            not_unicode,
            Err(EnvironmentConfigError::NotUnicode("E6IRC_SERVER_NAME"))
        );
    }

    /// The shell entrypoint honoured these. Still setting one is refused, not
    /// ignored: an operator who points the rendered file somewhere expects a
    /// file there.
    #[test]
    fn a_variable_the_shell_entrypoint_honoured_is_refused_not_ignored() {
        for retired in ["E6IRC_CONFIG_PATH", "E6IRC_BINARY"] {
            let error = table(&with(minimal(), &[(retired, "/somewhere")])).unwrap_err();
            assert!(
                matches!(error, EnvironmentConfigError::Retired { variable, .. } if variable == retired),
                "{error}"
            );
            assert!(error.to_string().contains("unset it"), "{error}");
        }
    }
}
