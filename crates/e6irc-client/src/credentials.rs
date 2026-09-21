//! Where a native client's SASL credentials and server password come from.
//!
//! A secret typed on the command line is readable by every local user through
//! the process list, and is kept by the shell's history. Each secret can
//! therefore also come from a file only its owner can read, or from the
//! environment; the command-line form still works and its `--help` says what it
//! costs. The CLI and the TUI share this resolver so the two cannot disagree
//! about precedence or about which combinations are a mistake.

use std::io;
use std::path::PathBuf;

use crate::token_cache::{default_token_path, load_token, read_secret_file};
use crate::{Authentication, ServerPassword};

/// Environment variable consulted for the SASL PLAIN password.
pub const PASSWORD_ENVIRONMENT: &str = "E6IRC_PASSWORD";
/// Environment variable consulted for the SASL OAUTHBEARER token.
pub const OAUTH_TOKEN_ENVIRONMENT: &str = "E6IRC_OAUTH_TOKEN";
/// Environment variable consulted for the network's server password (`PASS`).
pub const SERVER_PASSWORD_ENVIRONMENT: &str = "E6IRC_SERVER_PASSWORD";

/// One secret's three possible sources. At most one of `argument` and `file`
/// may be given; the environment is consulted only when neither is.
#[derive(Debug, Default, Clone)]
pub struct SecretSources {
    pub argument: Option<String>,
    pub file: Option<PathBuf>,
}

impl SecretSources {
    fn given(&self) -> bool {
        self.argument.is_some() || self.file.is_some()
    }

    /// The secret, from the command line, else the file, else `variable`.
    pub fn resolve(
        self,
        variable: &str,
        environment: &impl Fn(&str) -> io::Result<Option<String>>,
    ) -> io::Result<Option<String>> {
        match (self.argument, self.file) {
            (Some(_), Some(_)) => Err(invalid(format!(
                "give the secret on the command line or in a file, not both ({variable})"
            ))),
            (Some(argument), None) => Ok(Some(argument)),
            (None, Some(file)) => read_secret_file(&file).map(Some),
            (None, None) => match environment(variable)? {
                Some(value) if value.is_empty() => {
                    Err(invalid(format!("{variable} is set but empty")))
                }
                value => Ok(value),
            },
        }
    }
}

/// Everything the command line said about authentication.
#[derive(Debug, Default, Clone)]
pub struct CredentialArguments {
    pub account: Option<String>,
    pub password: SecretSources,
    pub oauth_token: SecretSources,
    pub oauth_from_cache: bool,
    /// Token-cache path for `oauth_from_cache`; the platform default when absent.
    pub token_file: Option<PathBuf>,
    /// Send a cached token to an IRC server whose host is not the host of the
    /// API origin that issued it. Without this, that is refused: the token is
    /// the account's API credential, and any IRC server it is sent to can use
    /// it against the API.
    pub allow_oauth_token_for_other_server: bool,
}

impl CredentialArguments {
    /// The one authentication these arguments select, or why they select none.
    /// What was said on the command line decides the mode; the environment only
    /// supplies a secret the chosen mode still lacks, so a variable exported in
    /// a shell profile never overrides an explicit flag.
    ///
    /// `irc_address` is the `host:port` the credentials are for: a cached
    /// token is released only to the host of the origin that issued it.
    pub fn resolve(
        self,
        irc_address: &str,
        environment: &impl Fn(&str) -> io::Result<Option<String>>,
    ) -> io::Result<Authentication> {
        let modes = [
            self.account.is_some() || self.password.given(),
            self.oauth_token.given(),
            self.oauth_from_cache,
        ];
        if modes.iter().filter(|chosen| **chosen).count() > 1 {
            return Err(invalid(
                "choose one of --account with a password, an OAuth token, or --oauth-from-cache"
                    .into(),
            ));
        }
        if let Some(account) = self.account {
            let password = self
                .password
                .resolve(PASSWORD_ENVIRONMENT, environment)?
                .ok_or_else(|| {
                    invalid(format!(
                        "--account needs a password: --password-file, {PASSWORD_ENVIRONMENT}, \
                         or --password"
                    ))
                })?;
            return Ok(Authentication::Plain { account, password });
        }
        if self.password.given() {
            return Err(invalid("a password needs --account".into()));
        }
        if self.oauth_from_cache {
            let path = self.token_file.map_or_else(default_token_path, Ok)?;
            let cached = load_token(&path)?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no cached token at {}; run e6irc login", path.display()),
                )
            })?;
            let issuer = origin_host(cached.base_url()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "the cached token at {} names no origin host",
                        path.display()
                    ),
                )
            })?;
            let server = normalized_host(crate::tls_server_name(irc_address)?);
            if server != issuer && !self.allow_oauth_token_for_other_server {
                return Err(invalid(format!(
                    "the cached token was issued by {issuer}; refusing to send it to the IRC \
                     server {server}, which could use it against that API. Connect to \
                     {issuer}, or pass --allow-oauth-token-for-other-server"
                )));
            }
            return Ok(Authentication::OAuthBearer {
                token: cached.access_token().to_owned(),
            });
        }
        Ok(
            match self
                .oauth_token
                .resolve(OAUTH_TOKEN_ENVIRONMENT, environment)?
            {
                Some(token) => Authentication::OAuthBearer { token },
                None => Authentication::None,
            },
        )
    }
}

/// The host of an `http(s)://host[:port]` origin, lowercased and without a
/// trailing dot or IPv6 brackets; `None` when there is none.
fn origin_host(origin: &str) -> Option<String> {
    let (_, rest) = origin.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = match authority.strip_prefix('[') {
        Some(bracketed) => bracketed.split_once(']')?.0,
        None => authority.split(':').next()?,
    };
    (!host.is_empty()).then(|| normalized_host(host))
}

/// One spelling per host: DNS names are case-insensitive, and a trailing dot
/// names the same host.
fn normalized_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// The network's server password, from the command line, else the file, else
/// [`SERVER_PASSWORD_ENVIRONMENT`] — or none. Independent of the SASL mode: a
/// private server's connection password and an account's credentials are
/// different things, and either may be given without the other. A value that
/// cannot travel in one `PASS` line is refused here, before anything dials.
pub fn resolve_server_password(
    sources: SecretSources,
    environment: &impl Fn(&str) -> io::Result<Option<String>>,
) -> io::Result<Option<ServerPassword>> {
    sources
        .resolve(SERVER_PASSWORD_ENVIRONMENT, environment)?
        .map(|password| {
            ServerPassword::parse(password)
                .map_err(|error| invalid(format!("the server password is not usable: {error}")))
        })
        .transpose()
}

/// The process environment as [`CredentialArguments::resolve`] reads it. A
/// value that is not Unicode is an error, not an absent variable.
pub fn process_environment(variable: &str) -> io::Result<Option<String>> {
    match std::env::var(variable) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(invalid(format!("{variable} is not valid Unicode")))
        }
    }
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment(
        pairs: &'static [(&'static str, &'static str)],
    ) -> impl Fn(&str) -> io::Result<Option<String>> {
        move |variable| {
            Ok(pairs
                .iter()
                .find(|(name, _)| *name == variable)
                .map(|(_, value)| (*value).to_owned()))
        }
    }

    fn argument(value: &str) -> SecretSources {
        SecretSources {
            argument: Some(value.into()),
            file: None,
        }
    }

    fn resolved(arguments: CredentialArguments, pairs: &'static [(&str, &str)]) -> String {
        match arguments.resolve("irc.example:6697", &environment(pairs)) {
            Ok(Authentication::None) => "anonymous".into(),
            Ok(Authentication::Plain { account, password }) => {
                format!("plain {account} {password}")
            }
            Ok(Authentication::OAuthBearer { token }) => format!("bearer {token}"),
            Err(error) => format!("error: {error}"),
        }
    }

    #[test]
    fn a_secret_never_has_to_be_typed_on_the_command_line() {
        let account = || CredentialArguments {
            account: Some("alice".into()),
            ..Default::default()
        };
        assert_eq!(
            resolved(account(), &[(PASSWORD_ENVIRONMENT, "from-env")]),
            "plain alice from-env"
        );
        assert_eq!(
            resolved(
                CredentialArguments::default(),
                &[(OAUTH_TOKEN_ENVIRONMENT, "env-token")]
            ),
            "bearer env-token"
        );
        assert_eq!(resolved(CredentialArguments::default(), &[]), "anonymous");
        // The command line still works, and wins over the environment.
        let mut typed = account();
        typed.password = argument("typed");
        assert_eq!(
            resolved(typed, &[(PASSWORD_ENVIRONMENT, "from-env")]),
            "plain alice typed"
        );
    }

    #[test]
    fn an_exported_variable_never_overrides_what_the_command_line_chose() {
        let mut plain = CredentialArguments {
            account: Some("alice".into()),
            ..Default::default()
        };
        plain.password = argument("typed");
        assert_eq!(
            resolved(plain, &[(OAUTH_TOKEN_ENVIRONMENT, "env-token")]),
            "plain alice typed"
        );
        let bearer = CredentialArguments {
            oauth_token: argument("typed-token"),
            ..Default::default()
        };
        assert_eq!(
            resolved(bearer, &[(PASSWORD_ENVIRONMENT, "from-env")]),
            "bearer typed-token"
        );
    }

    #[test]
    fn half_given_and_contradictory_credentials_are_errors_not_anonymous() {
        let cases: [(CredentialArguments, &[(&str, &str)]); 5] = [
            (
                CredentialArguments {
                    account: Some("alice".into()),
                    ..Default::default()
                },
                &[],
            ),
            (
                CredentialArguments {
                    password: argument("orphan"),
                    ..Default::default()
                },
                &[],
            ),
            (
                CredentialArguments {
                    account: Some("alice".into()),
                    ..Default::default()
                },
                &[(PASSWORD_ENVIRONMENT, "")],
            ),
            (
                CredentialArguments {
                    account: Some("alice".into()),
                    password: argument("typed"),
                    oauth_token: argument("token"),
                    ..Default::default()
                },
                &[],
            ),
            (
                CredentialArguments {
                    oauth_token: SecretSources {
                        argument: Some("typed".into()),
                        file: Some("/nonexistent".into()),
                    },
                    ..Default::default()
                },
                &[],
            ),
        ];
        for (arguments, pairs) in cases {
            let outcome = resolved(arguments.clone(), pairs);
            assert!(outcome.starts_with("error: "), "{arguments:?} -> {outcome}");
        }
    }

    #[test]
    fn a_server_password_comes_from_the_same_sources_under_the_same_rules() {
        let resolved = |sources: SecretSources, pairs: &'static [(&str, &str)]| {
            resolve_server_password(sources, &environment(pairs))
                .map(|password| password.map(|password| password.as_str().to_owned()))
                .map_err(|error| error.to_string())
        };
        assert_eq!(resolved(SecretSources::default(), &[]), Ok(None));
        assert_eq!(
            resolved(
                SecretSources::default(),
                &[(SERVER_PASSWORD_ENVIRONMENT, "from-env")]
            ),
            Ok(Some("from-env".to_owned()))
        );
        assert_eq!(
            resolved(
                argument("typed"),
                &[(SERVER_PASSWORD_ENVIRONMENT, "from-env")]
            ),
            Ok(Some("typed".to_owned()))
        );
        for (sources, pairs) in [
            (
                SecretSources::default(),
                &[(SERVER_PASSWORD_ENVIRONMENT, "")][..],
            ),
            (argument("a\r\nQUIT"), &[][..]),
            (
                SecretSources {
                    argument: Some("typed".into()),
                    file: Some("/nonexistent".into()),
                },
                &[][..],
            ),
        ] {
            let outcome = resolved(sources.clone(), pairs);
            assert!(outcome.is_err(), "{sources:?} -> {outcome:?}");
            assert!(
                !format!("{outcome:?}").contains("QUIT"),
                "the refusal names the rule, not the value: {outcome:?}"
            );
        }
    }

    /// The cached token is the account's API credential. An IRC server it is
    /// sent to can replay it against the API, so it goes only to the host of
    /// the origin that issued it, unless the user says otherwise.
    #[test]
    #[cfg(unix)]
    fn a_cached_token_is_sent_only_to_the_host_that_issued_it() {
        let directory =
            std::env::temp_dir().join(format!("e6irc-credentials-issuer-{}", std::process::id()));
        let path = directory.join("token.json");
        let cached =
            crate::token_cache::CachedToken::new("https://IRC.Example:8443".into(), "t0k".into())
                .unwrap();
        crate::token_cache::store_token(&path, &cached).unwrap();
        let from_cache = |allow: bool| CredentialArguments {
            oauth_from_cache: true,
            token_file: Some(path.clone()),
            allow_oauth_token_for_other_server: allow,
            ..Default::default()
        };
        let outcome = |arguments: CredentialArguments, server: &str| match arguments
            .resolve(server, &environment(&[]))
        {
            Ok(Authentication::OAuthBearer { token }) => format!("bearer {token}"),
            Ok(_) => "other".into(),
            Err(error) => format!("error: {error}"),
        };
        assert_eq!(
            outcome(from_cache(false), "irc.example.:6697"),
            "bearer t0k"
        );
        let refused = outcome(from_cache(false), "irc.elsewhere:6697");
        assert!(refused.starts_with("error: "), "{refused}");
        assert!(refused.contains("irc.example"), "{refused}");
        assert!(
            refused.contains("--allow-oauth-token-for-other-server"),
            "{refused}"
        );
        assert!(!refused.contains("t0k"), "{refused}");
        assert_eq!(
            outcome(from_cache(true), "irc.elsewhere:6697"),
            "bearer t0k"
        );
        std::fs::remove_dir_all(directory).unwrap();

        assert_eq!(origin_host("http://[::1]:8080/").as_deref(), Some("::1"));
        assert_eq!(
            origin_host("https://user@Host.example").as_deref(),
            Some("host.example")
        );
        assert_eq!(origin_host("not a url"), None);
    }
}
