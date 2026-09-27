//! Following what the store announces.
//!
//! Tables announce their own committed changes with `NOTIFY` (credentials and
//! accounts, migrations 0077 and 0095; the managed settings, 0090; the serving
//! lease, 0098). Every follower in the process does the same thing with them:
//! listen on a connection of its own, act on each announcement, and — because
//! what is announced while the connection is down is not heard — re-establish
//! a lost connection with a bounded backoff and resynchronize from the table
//! once it is back. [`follow_announcements`] is that loop, once.

use super::{DatabaseUrl, DbError, query_error};

/// What a listener heard.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Announcement {
    /// A committed change, with the payload its trigger wrote.
    Notified(String),
    /// The listening connection was (re-)established: announcements made
    /// before it are gone, so the follower reads what it follows again.
    Resynchronize,
}

/// A dedicated connection listening on one channel.
pub(crate) struct Announcements(sqlx::postgres::PgListener);

impl Announcements {
    /// Connect and start listening. The listener has its own connection, not
    /// one of the shared pool's, which it would hold for the process lifetime.
    pub(crate) async fn connect(url: &DatabaseUrl, channel: &str) -> Result<Self, DbError> {
        let mut listener = super::notification_listener(url).await?;
        listener.listen(channel).await.map_err(query_error)?;
        Ok(Self(listener))
    }

    /// The next announcement. An error means the connection could not be
    /// re-established; the caller connects again.
    pub(crate) async fn next(&mut self) -> Result<Announcement, DbError> {
        Ok(match self.0.try_recv().await.map_err(query_error)? {
            Some(notification) => Announcement::Notified(notification.payload().to_owned()),
            None => Announcement::Resynchronize,
        })
    }
}

/// What follows one channel's announcements.
pub(crate) trait Follower: Send {
    /// Act on one announcement. An error is said, and the connection is made
    /// again, which resynchronizes.
    fn on_change(
        &mut self,
        announcement: Announcement,
    ) -> impl std::future::Future<Output = Result<(), String>> + Send;

    /// The listening connection is now its `generation`th: 0 for one the
    /// caller connected, then one more for each connection made again (a new
    /// one, or one `PgListener` re-established by itself). Called before the
    /// [`Announcement::Resynchronize`] that follows each reconnection, so a
    /// follower can tell what it read under an earlier connection from what
    /// it reads under this one.
    fn reconnected(&mut self, _generation: u64) {}
}

/// Follow `channel` for the life of the process, handing each announcement to
/// `follower`. A connection this makes is followed by one
/// [`Announcement::Resynchronize`] before anything it hears; `connected`, a
/// listener the caller already holds (and has read its baseline under), is
/// not. A failure to act or a lost connection is said on stderr under `what`,
/// and the connection is made again — so what was missed is read again.
/// Returns only if the task is cancelled.
pub(crate) async fn follow_announcements(
    url: DatabaseUrl,
    channel: &'static str,
    what: &'static str,
    connected: Option<Announcements>,
    mut follower: impl Follower,
) {
    const RETRY_MIN: std::time::Duration = std::time::Duration::from_secs(1);
    const RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(30);
    let mut generation: u64 = 0;
    let mut listener = connected;
    let mut retry = RETRY_MIN;
    loop {
        let mut connected = match listener.take() {
            Some(connected) => connected,
            None => {
                let reconnected = match Announcements::connect(&url, channel).await {
                    Ok(connected) => {
                        generation += 1;
                        follower.reconnected(generation);
                        follower
                            .on_change(Announcement::Resynchronize)
                            .await
                            .map(|()| connected)
                            .map_err(|error| {
                                format!("could not read again what it follows: {error}")
                            })
                    }
                    Err(error) => Err(format!("listener unavailable: {error}")),
                };
                match reconnected {
                    Ok(connected) => connected,
                    Err(error) => {
                        eprintln!("{what}: {error}; retrying in {}s", retry.as_secs());
                        tokio::time::sleep(retry).await;
                        retry = (retry * 2).min(RETRY_MAX);
                        continue;
                    }
                }
            }
        };
        retry = RETRY_MIN;
        loop {
            let followed = match connected.next().await {
                Ok(announcement) => {
                    if announcement == Announcement::Resynchronize {
                        generation += 1;
                        follower.reconnected(generation);
                    }
                    follower.on_change(announcement).await
                }
                Err(error) => Err(format!("listener lost: {error}")),
            };
            if let Err(error) = followed {
                // What is announced from here until the connection is back is
                // not heard; the reconnection reads it all again.
                eprintln!("{what}: {error}; listening again");
                break;
            }
        }
    }
}

/// The channel migration 0090's trigger announces each committed settings
/// revision on.
pub(crate) const SETTINGS_CHANGED_CHANNEL: &str = "e6irc_server_settings_changed";
/// The channel migrations 0077 and 0095's triggers announce credential and
/// account changes on ([`super::CredentialChange`]).
pub(crate) const CREDENTIAL_CHANGED_CHANNEL: &str = "e6irc_credential_changed";
/// The channel migration 0098's trigger announces each change of the serving
/// lease's holder on, a release included.
pub(crate) const SERVING_LEASE_CHANNEL: &str = "e6irc_serving_lease";
