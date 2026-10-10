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
    /// one, or one `PgListener` re-established by itself). Awaited before the
    /// [`Announcement::Resynchronize`] that follows each reconnection: what a
    /// follower must settle before it re-reads what it missed — work read
    /// while nothing listened, whose result could land after the re-read —
    /// it settles here. An error is said, and the connection is made again.
    fn reconnected(
        &mut self,
        _generation: u64,
    ) -> impl std::future::Future<Output = Result<(), String>> + Send {
        async { Ok(()) }
    }
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
                        resynchronize(&mut follower, generation)
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
                Ok(Announcement::Resynchronize) => {
                    generation += 1;
                    resynchronize(&mut follower, generation).await
                }
                Ok(announcement) => follower.on_change(announcement).await,
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

/// A reconnection, as every follower is told of it: first what it settles
/// before re-reading ([`Follower::reconnected`]), then the re-read.
async fn resynchronize(follower: &mut impl Follower, generation: u64) -> Result<(), String> {
    follower.reconnected(generation).await?;
    follower.on_change(Announcement::Resynchronize).await
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
/// The channel migration 0101's trigger announces each change of the body
/// format the cores write for their edges on.
pub(crate) const RECORD_FORMAT_CHANNEL: &str = "e6irc_record_format";

#[cfg(test)]
mod tests {
    use super::*;

    /// Records what it is told, and refuses to settle when told to.
    #[derive(Default)]
    struct Recording {
        seen: Vec<String>,
        refuse_to_settle: bool,
    }

    impl Follower for Recording {
        async fn on_change(&mut self, announcement: Announcement) -> Result<(), String> {
            self.seen.push(format!("{announcement:?}"));
            Ok(())
        }

        async fn reconnected(&mut self, generation: u64) -> Result<(), String> {
            self.seen.push(format!("reconnected {generation}"));
            if self.refuse_to_settle {
                Err("could not settle".into())
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn a_reconnection_settles_before_it_re_reads_and_not_at_all_if_it_cannot() {
        let mut follower = Recording::default();
        resynchronize(&mut follower, 3).await.expect("settled");
        assert_eq!(follower.seen, ["reconnected 3", "Resynchronize"]);

        let mut refusing = Recording {
            refuse_to_settle: true,
            ..Recording::default()
        };
        assert_eq!(
            resynchronize(&mut refusing, 4).await,
            Err("could not settle".to_owned())
        );
        assert_eq!(refusing.seen, ["reconnected 4"], "nothing is re-read");
    }
}
