//! The stream of changes to the stored managed settings.
//!
//! Several processes write `server_settings`: every replica's console, and
//! `e6ircd rotate-secrets` re-sealing its credentials. Migration 0090 makes
//! the table announce every committed write itself, so each running server
//! hears about a revision it did not write and can adopt it
//! (`crate::settings_watch`), whichever process wrote it.

use super::{DatabaseUrl, DbError, query_error};

/// The notification channel migration 0090's trigger publishes on.
const SETTINGS_CHANGED_CHANNEL: &str = "e6irc_server_settings_changed";

/// What the settings-change listener heard. Either way the stored row is read
/// again: a notification says a revision was committed, and a re-established
/// connection may have missed any number of them.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SettingsChange {
    /// A revision was committed.
    Committed,
    /// The listening connection was lost and re-established.
    Resynchronize,
}

/// A dedicated connection listening for committed settings revisions.
pub(crate) struct SettingsChangeListener(sqlx::postgres::PgListener);

impl SettingsChangeListener {
    pub(crate) async fn connect(url: &DatabaseUrl) -> Result<Self, DbError> {
        let mut listener = super::notification_listener(url).await?;
        listener
            .listen(SETTINGS_CHANGED_CHANNEL)
            .await
            .map_err(query_error)?;
        Ok(Self(listener))
    }

    /// The next change. An error means the connection could not be
    /// re-established; the caller connects again.
    pub(crate) async fn next(&mut self) -> Result<SettingsChange, DbError> {
        Ok(match self.0.try_recv().await.map_err(query_error)? {
            Some(_) => SettingsChange::Committed,
            None => SettingsChange::Resynchronize,
        })
    }
}
