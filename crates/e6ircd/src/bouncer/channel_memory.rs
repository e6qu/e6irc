//! An IRC network's remembered channels, kept in PostgreSQL (DESIGN §10.3):
//! every channel the upstream confirmed the session in, with the key it is
//! joined with, so a process restart rejoins them as a reconnect does — a
//! stored network's by its row, a configured one's by its owner and name.
//!
//! The driver keeps the set in memory ([`super::irc_driver::JoinedChannels`]);
//! this task, which the registry runs beside each IRC network's driver,
//! writes the whole set after each change. Writing is never on the driver's
//! path: a database that is away holds no upstream line, the last set written
//! stays whole, and the write is retried until it lands.

use std::sync::Arc;

use sqlx::PgPool;

use super::serve::UnwrittenLines;
use super::{NetworkFailure, NetworkHandle};

/// How long a failed write waits before it is tried again, when nothing has
/// changed in the meantime.
const RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(5);

/// A network's remembered-channel writer and the signal that ends it.
pub(super) struct ChannelMemory {
    stop: tokio::sync::oneshot::Sender<UnwrittenLines>,
    task: tokio::task::JoinHandle<()>,
}

/// Where a network's remembered channels are written, and what seals their
/// keys.
pub(super) struct ChannelStore {
    pub(super) pool: PgPool,
    /// The owning account, as the registry keys it; `None` for a configured
    /// network shared by every account.
    pub(super) owner: Option<String>,
    pub(super) network: String,
    /// Whether the network is a stored row or the configuration's.
    pub(super) definition: crate::db::BncNetworkDefinition,
    /// Without a master key a learned key cannot be sealed, so it is not
    /// stored: the channel is remembered without it.
    pub(super) keys: Option<Arc<crate::secret::SecretKeyring>>,
}

impl ChannelStore {
    /// Write what `handle`'s session remembers now, the whole set.
    async fn write(&self, handle: &NetworkHandle) -> Result<(), crate::db::DbError> {
        let context = super::bnc_secret_context(self.owner.as_deref().unwrap_or("*"));
        let mut remembered = handle.joined_channels().remembered();
        remembered.sort_by(|a, b| a.channel().cmp(b.channel()));
        let rows: Vec<crate::db::BncAutojoin> = remembered
            .iter()
            .map(|channel| crate::db::BncAutojoin {
                channel: channel.channel().to_owned(),
                key_sealed: channel
                    .key()
                    .zip(self.keys.as_deref())
                    .map(|(key, keys)| keys.seal(key, &context)),
            })
            .collect();
        crate::db::replace_bnc_remembered_channels(
            &self.pool,
            crate::db::RememberedChannelsOf {
                definition: self.definition,
                owner: self.owner.as_deref(),
                network: &self.network,
            },
            &rows,
        )
        .await
    }
}

/// Start writing `handle`'s remembered channels to `store` after each change,
/// until stopped. What the driver was seeded with is already stored, so only a
/// change after this starts is written.
pub(super) fn spawn(store: ChannelStore, handle: Arc<NetworkHandle>) -> ChannelMemory {
    let (stop, mut stopped) = tokio::sync::oneshot::channel::<UnwrittenLines>();
    let mut changes = handle.joined_channels().changes();
    changes.mark_unchanged();
    let task = tokio::spawn(async move {
        let label = format!(
            "{}/{}",
            store.owner.as_deref().unwrap_or("*"),
            store.network
        );
        // A change not yet written, and whether the last write failed (so an
        // outage logs once, and its end once).
        let mut dirty = false;
        let mut failing = false;
        loop {
            tokio::select! {
                biased;
                stop = &mut stopped => {
                    // A stop that keeps the network's rows writes the change
                    // still unwritten; one that deletes them writes nothing.
                    let pending = dirty || changes.has_changed().unwrap_or(false);
                    if pending && matches!(stop, Ok(UnwrittenLines::Store))
                        && let Err(error) = store.write(&handle).await
                    {
                        eprintln!(
                            "bnc: remembered channels of {label} not stored at stop: {error}"
                        );
                    }
                    return;
                }
                changed = changes.changed(), if !dirty => {
                    if changed.is_err() {
                        return;
                    }
                    dirty = true;
                }
                () = tokio::time::sleep(RETRY_AFTER), if dirty => {}
            }
            // Seen before the set is read: a change during the write is
            // written next.
            changes.mark_unchanged();
            match store.write(&handle).await {
                Ok(()) => {
                    dirty = false;
                    if failing {
                        failing = false;
                        eprintln!("bnc: remembered channels of {label} stored again");
                    }
                }
                Err(error) => {
                    handle.record_error(NetworkFailure::RememberedChannelsStorageFailed);
                    if !failing {
                        failing = true;
                        eprintln!(
                            "bnc: remembered channels of {label} not stored: {error}; retrying \
                             every {}s",
                            RETRY_AFTER.as_secs()
                        );
                    }
                }
            }
        }
    });
    ChannelMemory { stop, task }
}

impl ChannelMemory {
    /// End the writer, writing a pending change first when `unwritten` keeps
    /// the rows, and wait until it has.
    pub(super) async fn stop(self, unwritten: UnwrittenLines) {
        if self.stop.send(unwritten).is_err() {
            eprintln!("bnc: remembered-channel writer had already stopped");
        }
        if let Err(error) = self.task.await {
            eprintln!("bnc: remembered-channel writer ended abnormally: {error}");
        }
    }

    /// [`ChannelMemory::stop`] bounded by `deadline`, for a process shutdown.
    pub(super) async fn stop_by(self, unwritten: UnwrittenLines, deadline: tokio::time::Instant) {
        if self.stop.send(unwritten).is_err() {
            eprintln!("bnc: remembered-channel writer had already stopped");
        }
        let mut task = self.task;
        if tokio::time::timeout_at(deadline, &mut task).await.is_err() {
            task.abort();
            eprintln!("bnc: remembered-channel writer still writing at the shutdown deadline");
        }
    }
}
