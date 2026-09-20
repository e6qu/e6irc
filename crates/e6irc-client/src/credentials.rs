//! Where a native client's SASL credentials come from.
//!
//! A secret typed on the command line is readable by every local user through
//! the process list, and is kept by the shell's history. Each secret can
//! therefore also come from a file only its owner can read, or from the
//! environment; the command-line form still works and its `--help` says what it
//! costs. The CLI and the TUI share this resolver so the two cannot disagree
//! about precedence or about which combinations are a mistake.

use std::io;
use std::path::PathBuf;

use crate::Authentication;
use crate::token_cache::{default_token_path, load_token, read_secret_file};

/// Environment variable consulted for the SASL PLAIN password.
pub const PASSWORD_ENVIRONMENT: &str = "E6IRC_PASSWORD";
/// Environment variable consulted for the SASL OAUTHBEARER token.
pub const OAUTH_TOKEN_ENVIRONMENT: &str = "E6IRC_OAUTH_TOKEN";

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
}

impl CredentialArguments {
    /// The one authentication these arguments select, or why they select none.
    /// What was said on the command line decides the mode; the environment only
    /// supplies a secret the chosen mode still lacks, so a variable exported in
    /// a shell profile never overrides an explicit flag.
    pub fn resolve(
        self,
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
        match arguments.resolve(&environment(pairs)) {
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
}
