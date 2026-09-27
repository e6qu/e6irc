//! Every running server follows the stored managed settings, whoever writes
//! them.
//!
//! More than one replica may serve one database, and `e6ircd rotate-secrets`
//! writes the settings row from a process of its own. Each server keeps the
//! stored revision in memory: the console answers from it and saves against
//! it, storage maintenance and the observability sampler read it every cycle,
//! and the BNC attach listener is bound to what it says. The table announces
//! every committed write (migration 0090, [`crate::db::SettingsChangeListener`]);
//! this follows the announcements and adopts a revision another process
//! committed exactly as a console save in this process applies its own: the
//! snapshot is replaced (which the maintenance loops and the console read) and
//! the attach listener is rebound when its settings differ. Nothing
//! restart-only is applied: a console save does not apply it either, and says
//! so.

use std::sync::Arc;

use crate::db::{
    DatabaseUrl, ManagedConfigSnapshot, SettingsChange, SettingsChangeListener, load_managed_config,
};
use crate::net::BncListenerController;

/// The shared, in-memory stored revision.
pub(crate) type SharedSettings = Arc<tokio::sync::RwLock<ManagedConfigSnapshot>>;

/// Follow the store's settings announcements for the life of the process. A
/// lost connection is re-established with a bounded backoff, and the stored
/// row is read again once it is, because what was announced in between was
/// not heard.
pub(crate) async fn run(
    url: DatabaseUrl,
    pool: sqlx::PgPool,
    settings: SharedSettings,
    bnc_listener: Option<Arc<BncListenerController>>,
    core: crate::core::CoreIngress,
) {
    const RETRY_MIN: std::time::Duration = std::time::Duration::from_secs(1);
    const RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(30);
    let mut retry = RETRY_MIN;
    loop {
        let mut listener = match SettingsChangeListener::connect(&url).await {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!(
                    "managed configuration: settings-change listener unavailable, retrying in \
                     {}s: {error}",
                    retry.as_secs()
                );
                tokio::time::sleep(retry).await;
                retry = (retry * 2).min(RETRY_MAX);
                continue;
            }
        };
        retry = RETRY_MIN;
        adopt_stored(&pool, &settings, bnc_listener.as_deref(), &core).await;
        loop {
            match listener.next().await {
                Ok(SettingsChange::Committed | SettingsChange::Resynchronize) => {
                    adopt_stored(&pool, &settings, bnc_listener.as_deref(), &core).await;
                }
                Err(error) => {
                    eprintln!("managed configuration: settings-change listener lost: {error}");
                    break;
                }
            }
        }
    }
}

/// Read the stored row and make it this process's live settings when it is a
/// later revision than the one held, and apply what a console save applies
/// live: the history retention the core and the bouncer serve memory to, and
/// the attach listener. The attach listener is brought to what
/// the held revision says every time, not only when the revision moves: a
/// save here that found its revision stale reloaded the snapshot itself
/// (`crate::db::save_managed_config_over`) without touching the listener, and
/// this is what follows it.
async fn adopt_stored(
    pool: &sqlx::PgPool,
    settings: &SharedSettings,
    bnc_listener: Option<&BncListenerController>,
    core: &crate::core::CoreIngress,
) {
    let mut current = settings.write().await;
    match load_managed_config(pool).await {
        Ok(stored) if stored.revision > current.revision => *current = stored,
        Ok(_) => {}
        Err(error) => {
            eprintln!(
                "managed configuration: the stored revision could not be read, still serving \
                 revision {}: {error}",
                current.revision
            );
            return;
        }
    }
    core.set_history_retention_days(current.settings.storage.history_retention_days);
    if let Some(listener) = bnc_listener {
        follow_bnc_listener(listener, &current).await;
    }
}

/// Bind, rebind or stop the attach listener so it serves what `current`
/// states. A replacement that cannot bind leaves the working listener in
/// place (`BncListenerController::enable`) and is reported, as a console save
/// that could not bind is.
async fn follow_bnc_listener(listener: &BncListenerController, current: &ManagedConfigSnapshot) {
    let wanted = current.settings.bnc();
    let serving = listener.status().await.map(|(configured, _)| configured);
    if serving == wanted {
        return;
    }
    match &wanted {
        Some(bnc) => {
            if let Err(error) = listener.enable(bnc).await {
                eprintln!(
                    "managed configuration: revision {} moves the BNC attach listener to {}, \
                     which could not be bound: {error}; the previous listener stays",
                    current.revision, bnc.addr
                );
            }
        }
        None => listener.stop().await,
    }
}
