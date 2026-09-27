//! Which browser credentials still authorize, and the stream of changes to
//! them.
//!
//! A long-lived socket is opened by one browser session or personal access
//! token and must end when that credential does. Migration 0077 makes the two
//! credential tables announce every committed delete or update themselves, so
//! whichever path revokes a credential — in this process or another — the
//! announcement is made; this module reads the announcements and answers
//! "does this credential still authorize, and until when?".
//!
//! Migration 0095 has the accounts table announce on the same channel: each
//! account created or deleted, and each change of its authority (suspension,
//! reactivation, a primary password added, replaced or removed), which the
//! row counts in `authority_generation`. [`AccountAuthority`] is that row as
//! a listener re-reads it.

use super::{ACCOUNT_FLAG_SUSPENDED, DbError, query_error, token_hash};

/// The notification channel migration 0077's triggers publish on.
const CREDENTIAL_CHANGED_CHANNEL: &str = "e6irc_credential_changed";

/// The table a revocable credential lives in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum RevocableCredentialKind {
    BrowserSession,
    ApiToken,
}

impl RevocableCredentialKind {
    /// The kind tag the trigger writes before the digest.
    const fn notification_tag(self) -> &'static str {
        match self {
            Self::BrowserSession => "session",
            Self::ApiToken => "token",
        }
    }
}

/// One stored credential, named by its table and the SHA-256 digest that is
/// its primary key there. The plaintext is never retained.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RevocableCredential {
    kind: RevocableCredentialKind,
    digest: Vec<u8>,
}

impl RevocableCredential {
    /// The browser session a cookie carries.
    pub fn browser_session(token: &str) -> Self {
        Self {
            kind: RevocableCredentialKind::BrowserSession,
            digest: token_hash(token),
        }
    }

    /// The personal access token a bearer header carries.
    pub fn api_token(bearer: &str) -> Self {
        Self {
            kind: RevocableCredentialKind::ApiToken,
            digest: token_hash(bearer),
        }
    }

    /// The credential a trigger notification names, or `None` for a payload
    /// no shipped trigger writes.
    fn from_notification(payload: &str) -> Option<Self> {
        let (tag, hex) = payload.split_once(':')?;
        let kind = [
            RevocableCredentialKind::BrowserSession,
            RevocableCredentialKind::ApiToken,
        ]
        .into_iter()
        .find(|kind| kind.notification_tag() == tag)?;
        if hex.len() % 2 != 0 {
            return None;
        }
        let digest = (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(hex.get(at..at + 2)?, 16).ok())
            .collect::<Option<Vec<u8>>>()?;
        Some(Self { kind, digest })
    }
}

/// How much longer `credential` authorizes its account: `None` once it has
/// been revoked, has expired, or belongs to a suspended account. The time is
/// PostgreSQL's, the clock the expiry was written against.
pub async fn credential_remaining(
    pool: &sqlx::PgPool,
    credential: &RevocableCredential,
) -> Result<Option<std::time::Duration>, DbError> {
    let query = match credential.kind {
        RevocableCredentialKind::BrowserSession => {
            "SELECT (EXTRACT(EPOCH FROM (c.expires_at - now())) * 1000)::BIGINT
             FROM web_sessions c JOIN accounts a ON a.id = c.account_id
             WHERE c.token_hash = $1 AND c.expires_at > now() AND (a.flags & $2) = 0"
        }
        RevocableCredentialKind::ApiToken => {
            "SELECT (EXTRACT(EPOCH FROM (c.expires_at - now())) * 1000)::BIGINT
             FROM api_tokens c JOIN accounts a ON a.id = c.account_id
             WHERE c.token_hash = $1 AND c.expires_at > now() AND (a.flags & $2) = 0"
        }
    };
    let remaining: Option<i64> = sqlx::query_scalar(query)
        .bind(&credential.digest)
        .bind(ACCOUNT_FLAG_SUSPENDED)
        .fetch_optional(pool)
        .await
        .map_err(query_error)?;
    Ok(remaining.map(|millis| std::time::Duration::from_millis(millis.max(0).unsigned_abs())))
}

/// An account the store announced: created, deleted, or its authority
/// changed. The folded name is carried so a deleted account can still be
/// named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountAnnouncement {
    pub id: i64,
    pub folded: String,
}

impl AccountAnnouncement {
    /// The notification tag migration 0095's account triggers write.
    const TAG: &'static str = "account";

    /// The account an `account:<id>:<folded name>` payload names.
    fn from_notification(payload: &str) -> Option<Self> {
        let rest = payload.strip_prefix(Self::TAG)?.strip_prefix(':')?;
        let (id, folded) = rest.split_once(':')?;
        let id = id.parse().ok().filter(|id: &i64| *id > 0)?;
        (!folded.is_empty()).then(|| Self {
            id,
            folded: folded.to_string(),
        })
    }
}

/// One account's authority as the store has it: how many times it has changed
/// (migration 0095's `authority_generation`) and whether it is suspended now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountAuthority {
    pub id: i64,
    pub folded: String,
    pub generation: i64,
    pub suspended: bool,
}

/// The columns an [`AccountAuthority`] is read from, `$1` binding
/// [`ACCOUNT_FLAG_SUSPENDED`].
macro_rules! account_authority_select {
    ($rest:literal) => {
        concat!(
            "SELECT id, name_folded, authority_generation, (flags & $1) <> 0 AS suspended \
             FROM accounts",
            $rest
        )
    };
}

type AccountAuthorityRow = (i64, String, i64, bool);

fn account_authority_of(
    (id, folded, generation, suspended): AccountAuthorityRow,
) -> AccountAuthority {
    AccountAuthority {
        id,
        folded,
        generation,
        suspended,
    }
}

/// The account `id`'s authority now, or `None` once it is deleted.
pub async fn account_authority<'e, E>(
    executor: E,
    id: i64,
) -> Result<Option<AccountAuthority>, DbError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let row: Option<AccountAuthorityRow> =
        sqlx::query_as(account_authority_select!(" WHERE id = $2"))
            .bind(ACCOUNT_FLAG_SUSPENDED)
            .bind(id)
            .fetch_optional(executor)
            .await
            .map_err(query_error)?;
    Ok(row.map(account_authority_of))
}

/// Every account's authority now: what a listener compares against after it
/// has missed announcements.
pub async fn every_account_authority(
    pool: &sqlx::PgPool,
) -> Result<Vec<AccountAuthority>, DbError> {
    let rows: Vec<AccountAuthorityRow> = sqlx::query_as(account_authority_select!(""))
        .bind(ACCOUNT_FLAG_SUSPENDED)
        .fetch_all(pool)
        .await
        .map_err(query_error)?;
    Ok(rows.into_iter().map(account_authority_of).collect())
}

/// What the credential-change listener heard.
#[derive(Debug, PartialEq, Eq)]
pub enum CredentialChange {
    /// This credential was deleted or changed.
    Changed(RevocableCredential),
    /// This account was created or deleted, or its authority changed.
    Account(AccountAnnouncement),
    /// The listening connection was lost and re-established: announcements
    /// made in between are gone, so every watched credential must be read
    /// again.
    Resynchronize,
}

/// A dedicated connection listening for credential changes.
pub struct CredentialChangeListener(sqlx::postgres::PgListener);

impl CredentialChangeListener {
    /// Connect and start listening. The listener has its own connection, not
    /// one of the shared pool's, which it would hold for the process lifetime.
    pub async fn connect(url: &super::DatabaseUrl) -> Result<Self, DbError> {
        let mut listener = super::notification_listener(url).await?;
        listener
            .listen(CREDENTIAL_CHANGED_CHANNEL)
            .await
            .map_err(query_error)?;
        Ok(Self(listener))
    }

    /// The next change. An error means the connection could not be
    /// re-established; the caller connects again.
    pub async fn next(&mut self) -> Result<CredentialChange, DbError> {
        let Some(notification) = self.0.try_recv().await.map_err(query_error)? else {
            return Ok(CredentialChange::Resynchronize);
        };
        // A payload no shipped trigger writes still says *something* changed;
        // not knowing what, every watched credential is read again.
        let payload = notification.payload();
        Ok(RevocableCredential::from_notification(payload)
            .map(CredentialChange::Changed)
            .or_else(|| {
                AccountAnnouncement::from_notification(payload).map(CredentialChange::Account)
            })
            .unwrap_or(CredentialChange::Resynchronize))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_notification_names_the_credential_whose_digest_it_carries() {
        let session = RevocableCredential::browser_session("cookie-value");
        let hex: String = session
            .digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            RevocableCredential::from_notification(&format!("session:{hex}")),
            Some(session)
        );
        assert_eq!(
            RevocableCredential::from_notification(&format!("token:{hex}")),
            Some(RevocableCredential {
                kind: RevocableCredentialKind::ApiToken,
                digest: RevocableCredential::browser_session("cookie-value").digest,
            })
        );
        for junk in ["", "session", "other:00", "session:0", "session:zz"] {
            assert_eq!(RevocableCredential::from_notification(junk), None, "{junk}");
        }
    }

    #[test]
    fn an_account_notification_names_the_account_by_id_and_folded_name() {
        assert_eq!(
            AccountAnnouncement::from_notification("account:42:ali:ce"),
            Some(AccountAnnouncement {
                id: 42,
                folded: "ali:ce".into(),
            })
        );
        for junk in [
            "account",
            "account:",
            "account:42",
            "account:42:",
            "account:x:alice",
            "account:0:alice",
            "account:-1:alice",
            "accounts:42:alice",
            "session:42:alice",
        ] {
            assert_eq!(AccountAnnouncement::from_notification(junk), None, "{junk}");
        }
    }
}
