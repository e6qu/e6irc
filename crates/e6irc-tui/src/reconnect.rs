//! What the client does after a connection attempt fails.
//!
//! A fixed short delay retried forever turns every permanent failure into a
//! full TLS + SASL attempt every couple of seconds: wrong credentials are
//! re-sent until the account is locked, and a ban is answered by hammering the
//! server that issued it. The decision is made here, from the typed value the
//! client library attaches to its error, so the loop in `main` cannot retry
//! something this module said to stop.

use std::io;
use std::time::{Duration, Instant};

use e6irc_client::{RegistrationRefusal, RegistrationRejection, SaslRejection, SaslRejectionClass};

/// Longest wait between attempts, however many have failed.
pub const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(300);

/// How long a session must stay up for its end to start the backoff afresh:
/// one liveness window, the time the client takes to tell a live server from
/// a dead one. A server that welcomes the client and drops it at once is
/// failing, however often registration succeeds, and must not be answered by
/// a reconnect every `--reconnect-delay` forever.
pub const STABLE_SESSION: Duration = e6irc_client::liveness::LIVENESS_WINDOW;

/// The next step after a failed attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AfterFailure {
    /// Trying again cannot succeed and may do harm. The text is the final
    /// status shown to the user.
    Stop(String),
    /// Try again after this long.
    RetryAfter(Duration),
}

/// Capped exponential backoff from the user's `--reconnect-delay`, reset only
/// by a session that stayed up for [`STABLE_SESSION`].
#[derive(Debug)]
pub struct ReconnectPolicy {
    floor: Duration,
    consecutive_failures: u32,
    /// When the live session began.
    connected_at: Instant,
}

impl ReconnectPolicy {
    /// The policy for a session that registered at `connected_at`.
    pub fn new(floor: Duration, connected_at: Instant) -> Self {
        Self {
            floor,
            consecutive_failures: 0,
            connected_at,
        }
    }

    /// A new session registered at `at`. It does not reset the backoff: only
    /// staying up does.
    pub fn connected(&mut self, at: Instant) {
        self.connected_at = at;
    }

    /// The wait before the first attempt after the live session ended at
    /// `at`. A session that stayed up for [`STABLE_SESSION`] starts the
    /// backoff afresh from `--reconnect-delay`; one that ended sooner counts
    /// as one more failure.
    pub fn session_ended(&mut self, at: Instant) -> Duration {
        if at.saturating_duration_since(self.connected_at) >= STABLE_SESSION {
            self.consecutive_failures = 0;
        }
        self.backoff()
    }

    pub fn after(&mut self, error: &io::Error) -> AfterFailure {
        if let Some(reason) = permanent_refusal(error) {
            return AfterFailure::Stop(format!(
                "{reason}; not reconnecting — restart with corrected settings"
            ));
        }
        AfterFailure::RetryAfter(self.backoff())
    }

    /// The wait for one more failure, doubling with each since the backoff
    /// last started afresh.
    fn backoff(&mut self) -> Duration {
        let doublings = self.consecutive_failures.min(16);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.floor
            .saturating_mul(1 << doublings)
            .min(MAX_RECONNECT_DELAY)
    }
}

/// Why `error` will be the answer to every further attempt, when it will.
fn permanent_refusal(error: &io::Error) -> Option<String> {
    if let Some(SaslRejectionClass::CredentialsRejected(rejection)) =
        SaslRejection::from_error(error).map(SaslRejection::class)
    {
        return Some(format!(
            "the server rejected the credentials ({})",
            rejection.diagnostic()
        ));
    }
    let rejection = RegistrationRejection::from_error(error)?;
    let what = match rejection.refusal() {
        RegistrationRefusal::NetworkBanned => "the server banned this connection",
        RegistrationRefusal::ServerPasswordRejected => {
            "the network rejected the configured server password"
        }
        RegistrationRefusal::ServerPasswordRequired => {
            "the network requires a server password; give one with --server-password-file, \
             E6IRC_SERVER_PASSWORD, or --server-password"
        }
        RegistrationRefusal::InvalidNickname
        | RegistrationRefusal::InvalidUsername
        | RegistrationRefusal::NicknameInUse
        | RegistrationRefusal::NotRegistered
        | RegistrationRefusal::WelcomedAsAnotherNickname
        | RegistrationRefusal::SaslUnavailable
        | RegistrationRefusal::SaslAborted
        | RegistrationRefusal::SaslFailed => return None,
    };
    Some(format!("{what} ({})", rejection.diagnostic()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use e6irc_client::{Authentication, ConnectionOptions};

    /// The error the real client returns when a server answers each line that
    /// starts with a scripted prefix with the scripted reply.
    async fn registration_error(
        authentication: Authentication,
        script: &'static [(&'static str, &'static str)],
    ) -> io::Error {
        registration_error_with(authentication, None, script).await
    }

    async fn registration_error_with(
        authentication: Authentication,
        server_password: Option<e6irc_client::ServerPassword>,
        script: &'static [(&'static str, &'static str)],
    ) -> io::Error {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = socket.into_split();
            let mut lines = tokio::io::BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if let Some((_, reply)) = script.iter().find(|(prefix, _)| line.starts_with(prefix))
                {
                    writer
                        .write_all(format!("{reply}\r\n").as_bytes())
                        .await
                        .unwrap();
                }
            }
        });
        ConnectionOptions {
            address,
            tls: false,
            tls_server_name: None,
            nick: "nick".into(),
            username: "ident".into(),
            realname: "real".into(),
            authentication,
            response_deadline: Duration::from_secs(5),
            cleartext_credentials: e6irc_client::CleartextCredentials::Refuse,
            server_password,
        }
        .connect_registered()
        .await
        .err()
        .expect("the scripted server refuses registration")
    }

    fn plain() -> Authentication {
        Authentication::Plain {
            account: "account".into(),
            password: "wrong".into(),
        }
    }

    #[tokio::test]
    async fn rejected_credentials_and_bans_are_never_retried() {
        let mut policy = ReconnectPolicy::new(Duration::from_secs(2), Instant::now());
        let rejected = registration_error(
            plain(),
            &[
                ("CAP LS", ":srv CAP * LS :sasl=PLAIN"),
                ("CAP REQ", ":srv CAP * ACK :sasl"),
                ("AUTHENTICATE PLAIN", "AUTHENTICATE +"),
                ("AUTHENTICATE ", ":srv 904 * :Invalid password"),
            ],
        )
        .await;
        let AfterFailure::Stop(status) = policy.after(&rejected) else {
            panic!("rejected credentials were scheduled for another attempt");
        };
        assert!(status.contains("Invalid password"), "{status}");
        assert!(status.contains("not reconnecting"), "{status}");

        let banned = registration_error(
            Authentication::None,
            &[("CAP LS", ":srv 465 * :You are banned from this server")],
        )
        .await;
        let AfterFailure::Stop(status) = policy.after(&banned) else {
            panic!("a ban was scheduled for another attempt");
        };
        assert!(status.contains("You are banned"), "{status}");
    }

    /// A 464 is a configuration fault either way — a password the network
    /// wants and was not given, or one it rejected — and says which.
    #[tokio::test]
    async fn a_missing_or_rejected_server_password_is_never_retried() {
        let mut policy = ReconnectPolicy::new(Duration::from_secs(2), Instant::now());
        let script: &[(&str, &str)] = &[("CAP LS", ":srv 464 * :Password required")];
        let missing = registration_error(Authentication::None, script).await;
        let AfterFailure::Stop(status) = policy.after(&missing) else {
            panic!("a missing server password was scheduled for another attempt");
        };
        assert!(status.contains("requires a server password"), "{status}");
        assert!(status.contains("--server-password-file"), "{status}");

        let password = e6irc_client::ServerPassword::parse("wrong-pass".into()).expect("valid");
        let rejected = registration_error_with(Authentication::None, Some(password), script).await;
        let AfterFailure::Stop(status) = policy.after(&rejected) else {
            panic!("a rejected server password was scheduled for another attempt");
        };
        assert!(
            status.contains("rejected the configured server password"),
            "{status}"
        );
        assert!(!status.contains("wrong-pass"), "{status}");
    }

    /// A server that offers no usable SASL says nothing about the password, and
    /// a taken nickname frees up: both wait, neither hammers.
    #[tokio::test]
    async fn other_failures_back_off_exponentially_to_a_cap_and_reset_on_success() {
        let mut policy = ReconnectPolicy::new(Duration::from_secs(2), Instant::now());
        let in_use = registration_error(
            Authentication::None,
            &[
                ("CAP LS", ":srv CAP * LS :"),
                ("CAP END", ":srv 433 * nick :Nickname is already in use"),
            ],
        )
        .await;
        let no_mechanism =
            registration_error(plain(), &[("CAP LS", ":srv CAP * LS :sasl=EXTERNAL")]).await;
        let refused = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");

        let waits: Vec<_> = [&in_use, &no_mechanism, &refused, &refused]
            .into_iter()
            .map(|error| policy.after(error))
            .collect();
        assert_eq!(
            waits,
            [2, 4, 8, 16].map(|seconds| AfterFailure::RetryAfter(Duration::from_secs(seconds)))
        );
        for _ in 0..40 {
            policy.after(&refused);
        }
        assert_eq!(
            policy.after(&refused),
            AfterFailure::RetryAfter(MAX_RECONNECT_DELAY)
        );
        let connected = Instant::now();
        policy.connected(connected);
        assert_eq!(
            policy.session_ended(connected + STABLE_SESSION),
            Duration::from_secs(2),
            "a session that stayed up starts the backoff afresh"
        );
        assert_eq!(
            policy.after(&refused),
            AfterFailure::RetryAfter(Duration::from_secs(4))
        );
    }

    /// A server that welcomes the client and drops it at once is failing:
    /// each such session is one more failure, not a fresh start, so the
    /// client does not reconnect every two seconds forever.
    #[test]
    fn sessions_that_end_before_they_are_stable_keep_backing_off() {
        let start = Instant::now();
        let mut policy = ReconnectPolicy::new(Duration::from_secs(2), start);
        let mut now = start;
        let mut waits = Vec::new();
        for _ in 0..5 {
            now += Duration::from_secs(1);
            let wait = policy.session_ended(now);
            waits.push(wait.as_secs());
            now += wait;
            policy.connected(now);
        }
        assert_eq!(waits, [2, 4, 8, 16, 32]);
        now += STABLE_SESSION;
        assert_eq!(policy.session_ended(now), Duration::from_secs(2));
    }
}
