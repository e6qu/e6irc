//! The core's own sessions across a graceful restart (decision D13): the
//! `local` bouncer network's in-process sessions, which no client socket
//! carries and so no edge holds as it holds its clients'.
//!
//! In edge mode each such session's link is a holding one, so its shard
//! publishes the session's record as it does any edge session's; the driver
//! hands each record it takes here ([`LocalHomes::hold`]). At the cut the core
//! waits until every record published by the cut is taken
//! ([`LocalHomes::gathered`]) and homes each session on an edge that holds the
//! cut (`Home`), the edge holding the record — and, through the slot-0
//! replicas routed to it, the session's channel memberships — for the next
//! core. That core rebuilds the session like any other and parks its link
//! here ([`LocalHomes::resume`]) for the network's driver, which takes it up
//! ([`LocalHomes::take_resumed`]) instead of registering again: the session's
//! channels see no QUIT and no JOIN.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use e6irc_edge::link::{EdgeSession, Held, HeldSignal};

use super::ConnId;

/// Which `local` network a session is: its owner — none for a shared one —
/// and its name, each folded as the bouncer folds them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct LocalHomeKey {
    pub(crate) owner: Option<String>,
    pub(crate) network: String,
}

impl LocalHomeKey {
    pub(crate) fn new(owner: Option<&str>, network: &str) -> Self {
        let fold = |text: &str| e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(text);
        Self {
            owner: owner.map(fold),
            network: fold(network),
        }
    }
}

impl std::fmt::Display for LocalHomeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}",
            self.owner.as_deref().unwrap_or("*"),
            self.network
        )
    }
}

/// A session a rebuild resumed for its network's driver to take up.
pub(crate) struct ResumedLocal {
    pub(crate) conn: ConnId,
    /// The edge's end of its link: the driver reads its output from here.
    pub(crate) edge: EdgeSession,
    /// The nick and user it is registered under.
    pub(crate) nick: String,
    pub(crate) user: String,
    /// The channels it is in, as their names are spelled.
    pub(crate) channels: Vec<String>,
    /// Held until its driver has taken it up — or given up on it, or it is
    /// closed unclaimed — while the edges' input waits
    /// ([`LocalHomes::restored_within`]).
    pub(crate) restoring: Restoring,
}

/// One session of the core's own being restored: counted while it lives.
pub(crate) struct Restoring(Arc<tokio::sync::watch::Sender<usize>>);

impl Drop for Restoring {
    fn drop(&mut self) {
        self.0.send_modify(|count| *count -= 1);
    }
}

/// One session's record as the cut homes it.
pub(crate) struct HomedRecord {
    pub(crate) conn: ConnId,
    pub(crate) key: LocalHomeKey,
    pub(crate) revision: u64,
    /// The session's record body, as its shard wrote it.
    pub(crate) body: Bytes,
}

/// The core's own sessions, as held across a cut.
pub(crate) struct LocalHomes {
    /// Whether the core is in edge mode, where its own sessions are homed.
    homing: AtomicBool,
    state: Mutex<Homes>,
    /// How many sessions a rebuild resumed are not yet taken up.
    restoring: Arc<tokio::sync::watch::Sender<usize>>,
}

impl Default for LocalHomes {
    fn default() -> Self {
        Self {
            homing: AtomicBool::default(),
            state: Mutex::default(),
            restoring: Arc::new(tokio::sync::watch::Sender::new(0)),
        }
    }
}

#[derive(Default)]
struct Homes {
    live: HashMap<ConnId, Homed>,
    resumed: HashMap<LocalHomeKey, ResumedLocal>,
}

struct Homed {
    key: LocalHomeKey,
    /// What says the shard published something not yet taken.
    signal: HeldSignal,
    record: Option<(u64, Bytes)>,
}

impl LocalHomes {
    /// The core is in edge mode: its own sessions are opened to be homed.
    pub(crate) fn enable(&self) {
        self.homing.store(true, Ordering::Relaxed);
    }

    /// Whether the core's own sessions are opened to be homed.
    pub(crate) fn homing(&self) -> bool {
        self.homing.load(Ordering::Relaxed)
    }

    /// Follow `conn`, network `key`'s session on the holding link whose edge
    /// end is `edge`, until the guard is dropped.
    pub(crate) fn follow(
        self: &Arc<Self>,
        conn: ConnId,
        key: LocalHomeKey,
        edge: &EdgeSession,
    ) -> FollowedHome {
        self.state.lock().expect("local homes").live.insert(
            conn,
            Homed {
                key,
                signal: edge.held_signal(),
                record: None,
            },
        );
        FollowedHome {
            homes: self.clone(),
            conn,
        }
    }

    /// Take what `conn`'s shard published for it that the driver has read
    /// past: the newest record is kept, an acknowledgement — of input no edge
    /// numbers — is not.
    pub(crate) fn hold(&self, conn: ConnId, edge: &mut EdgeSession) {
        let mut state = self.state.lock().expect("local homes");
        let Some(homed) = state.live.get_mut(&conn) else {
            return;
        };
        for held in edge.take_held() {
            match held {
                Held::Record { revision, body } => homed.record = Some((revision, body)),
                Held::Ack(_) => {}
            }
        }
    }

    /// Every followed session's newest record once each has taken what its
    /// shard published, waiting at most `bound` — the cut calls this after
    /// cutting the shards, which publish every record whole. A session whose
    /// driver did not take its record in time is left out, and named.
    pub(crate) async fn gathered(&self, bound: std::time::Duration) -> Vec<HomedRecord> {
        let deadline = tokio::time::Instant::now() + bound;
        loop {
            let pending: Vec<ConnId> = self
                .state
                .lock()
                .expect("local homes")
                .live
                .iter()
                .filter(|(_, homed)| homed.signal.pending())
                .map(|(conn, _)| *conn)
                .collect();
            if pending.is_empty() || tokio::time::Instant::now() >= deadline {
                let state = self.state.lock().expect("local homes");
                for conn in &pending {
                    eprintln!(
                        "e6ircd: the local session {} did not take its record within {}s of \
                         the cut; it is not homed, and ends with this core",
                        conn.0,
                        bound.as_secs()
                    );
                }
                return state
                    .live
                    .iter()
                    .filter(|(conn, _)| !pending.contains(conn))
                    .filter_map(|(conn, homed)| {
                        let (revision, body) = homed.record.clone()?;
                        Some(HomedRecord {
                            conn: *conn,
                            key: homed.key.clone(),
                            revision,
                            body,
                        })
                    })
                    .collect();
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    /// Park `resumed`, network `key`'s session a rebuild resumed, for its
    /// driver.
    pub(crate) fn resume(&self, key: LocalHomeKey, resumed: ResumedLocal) {
        self.state
            .lock()
            .expect("local homes")
            .resumed
            .insert(key, resumed);
    }

    /// Count one session a rebuild resumes until the guard is dropped.
    pub(crate) fn restoring(&self) -> Restoring {
        self.restoring.send_modify(|count| *count += 1);
        Restoring(self.restoring.clone())
    }

    /// Wait, at most `bound`, until every session a rebuild resumed has been
    /// taken up by its driver: whether every one was.
    pub(crate) async fn restored_within(&self, bound: std::time::Duration) -> bool {
        let mut count = self.restoring.subscribe();
        tokio::time::timeout(bound, count.wait_for(|count| *count == 0))
            .await
            .is_ok()
    }

    /// Network `key`'s resumed session, for its driver to take up.
    pub(crate) fn take_resumed(&self, key: &LocalHomeKey) -> Option<ResumedLocal> {
        self.state.lock().expect("local homes").resumed.remove(key)
    }

    /// Every resumed session no driver took up, with its network.
    pub(crate) fn unclaimed(&self) -> Vec<(LocalHomeKey, ResumedLocal)> {
        self.state
            .lock()
            .expect("local homes")
            .resumed
            .drain()
            .collect()
    }
}

/// A session [`LocalHomes`] follows, until this is dropped.
pub(crate) struct FollowedHome {
    homes: Arc<LocalHomes>,
    conn: ConnId,
}

impl Drop for FollowedHome {
    fn drop(&mut self) {
        self.homes
            .state
            .lock()
            .expect("local homes")
            .live
            .remove(&self.conn);
    }
}
