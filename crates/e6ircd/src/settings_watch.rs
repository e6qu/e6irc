//! The serving process follows the stored managed settings, whoever writes
//! them.
//!
//! One process serves a database (DESIGN §18), but it is not the settings
//! row's only writer: `e6ircd rotate-secrets` re-seals the stored credentials
//! and bumps the revision from a process of its own. The server keeps the
//! stored revision in memory: the console answers from it and saves against
//! it, storage maintenance and the observability sampler read it every cycle,
//! and the BNC attach listener is bound to what it says. The table announces
//! every committed write (migration 0090); this follows the announcements and
//! adopts a revision another process committed exactly as a console save in
//! this process applies its own: the snapshot is replaced (which the
//! maintenance loops and the console read) and the attach listener is rebound
//! when its settings differ. Nothing restart-only is applied: a console save
//! does not apply it either, and says so.

use std::sync::Arc;

use crate::db::{
    Announcement, DatabaseUrl, Follower, ManagedConfigSnapshot, SETTINGS_CHANGED_CHANNEL,
    follow_announcements, load_managed_config,
};
use crate::net::BncListenerController;

/// The shared, in-memory stored revision.
pub(crate) type SharedSettings = Arc<tokio::sync::RwLock<ManagedConfigSnapshot>>;

/// Follow the store's settings announcements for the life of the process.
/// Every announcement, and every re-established connection (which may have
/// missed any number of them), reads the stored row again.
pub(crate) async fn run(
    url: DatabaseUrl,
    pool: sqlx::PgPool,
    settings: SharedSettings,
    bnc_listener: Option<Arc<BncListenerController>>,
    core: crate::core::CoreIngress,
) {
    follow_announcements(
        url,
        SETTINGS_CHANGED_CHANNEL,
        "managed configuration: settings-change listener",
        None,
        SettingsFollower {
            pool,
            settings,
            bnc_listener,
            core,
        },
    )
    .await;
}

struct SettingsFollower {
    pool: sqlx::PgPool,
    settings: SharedSettings,
    bnc_listener: Option<Arc<BncListenerController>>,
    core: crate::core::CoreIngress,
}

impl Follower for SettingsFollower {
    /// Whatever was announced, the stored row is read again. A read that
    /// fails is an error, so the connection is made again and the row read
    /// once more: swallowed, the announced revision would wait for the next.
    async fn on_change(&mut self, _: Announcement) -> Result<(), String> {
        adopt_stored(
            &self.pool,
            &self.settings,
            self.bnc_listener.as_deref(),
            &self.core,
        )
        .await
    }
}

/// Read the stored row and make it this process's live settings when it is a
/// later revision than the one held, and apply what a console save applies
/// live: what the core follows ([`crate::core::CoreIngress::adopt_live_settings`]:
/// the history retention it and the bouncer serve memory to, and the
/// QUIT-comment delay), and the attach listener. The attach listener is brought to what
/// the held revision says every time, not only when the revision moves: a
/// save here that found its revision stale reloaded the snapshot itself
/// (`crate::db::save_managed_config_over`) without touching the listener, and
/// this is what follows it.
async fn adopt_stored(
    pool: &sqlx::PgPool,
    settings: &SharedSettings,
    bnc_listener: Option<&BncListenerController>,
    core: &crate::core::CoreIngress,
) -> Result<(), String> {
    let mut current = settings.write().await;
    match load_managed_config(pool).await {
        Ok(stored) if stored.revision > current.revision => *current = stored,
        Ok(_) => {}
        Err(error) => {
            return Err(format!(
                "the stored revision could not be read, still serving revision {}: {error}",
                current.revision
            ));
        }
    }
    core.adopt_live_settings(&current.settings);
    if let Some(listener) = bnc_listener
        && let Err(UnboundBncListener { wanted, error }) =
            follow_bnc_listener(listener, &current).await
    {
        eprintln!(
            "managed configuration: revision {} moves the BNC attach listener to {wanted}, \
             which could not be bound: {error}; the previous listener stays",
            current.revision
        );
    }
    Ok(())
}

/// A revision's attach listener that could not be bound: where it was wanted,
/// and why not. The listener that was serving is still serving.
#[derive(Debug)]
pub(crate) struct UnboundBncListener {
    pub(crate) wanted: std::net::SocketAddr,
    pub(crate) error: std::io::Error,
}

/// Bind, rebind or stop the attach listener so it serves what `current`
/// states: the one way the listener is brought to a stored revision, whether
/// another writer's revision is adopted here or a console save here found its
/// own revision stale and reloaded the stored one. A replacement that cannot
/// bind leaves the working listener in place (`BncListenerController::enable`)
/// and is returned for the caller to report in its own terms.
pub(crate) async fn follow_bnc_listener(
    listener: &BncListenerController,
    current: &ManagedConfigSnapshot,
) -> Result<(), UnboundBncListener> {
    let wanted = current.settings.bnc();
    let serving = listener.status().await.map(|(configured, _)| configured);
    if serving == wanted {
        return Ok(());
    }
    match &wanted {
        Some(bnc) => listener
            .enable(bnc)
            .await
            .map(|_| ())
            .map_err(|error| UnboundBncListener {
                wanted: bnc.addr,
                error,
            }),
        None => {
            listener.stop().await;
            Ok(())
        }
    }
}
