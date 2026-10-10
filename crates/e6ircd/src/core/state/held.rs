//! What a shard publishes for its sessions' edges to hold, and what a shard
//! rebuilds from (DESIGN §19.2, §19.3).
//!
//! After every event the shard republishes what the event touched
//! ([`ServerState::publish_changed_sessions`], [`ServerState::publish_changed_channels`]):
//! each touched session's record and the acknowledgement of its input, on the
//! session's own link, and each touched channel's replica to every edge that
//! hosts one of its members. Those two functions are the only writers, so a
//! change cannot reach what the edges hold by another path, nor miss it.
//!
//! A record is built from a session by destructuring the session whole
//! ([`Session::record`]) and a session from a record by a total conversion
//! ([`ServerState::rebuild_session`]): a session field that is neither
//! recorded nor named as rebuilt from somewhere else does not compile.
//!
//! Acknowledge after effect (DESIGN §2): a session's input lines are counted
//! as the shard handles them, and the lines an accumulation holds — the
//! `AUTHENTICATE` chunks of a payload not yet complete ([`SaslBuffer`]), the
//! lines of an open multiline batch — are listed by the accumulation itself,
//! so an accumulation that completes or is abandoned takes its lines with it
//! and no line can stay retained, or stop being retained, by a call someone
//! forgot.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use bytes::Bytes;
use e6irc_link::{Ack, Replica, ReplicaChange};

use super::{
    Caps, ChanKey, Channel, ChannelMemberProfile, ConnId, CoreShardId, IdleSince, ListEntry, Login,
    MaskKey, MemberIdentity, MemberModes, MultilineBatch, NickChangeThrottle, NickEnforcement,
    NickKey, Recipient, Registration, SaslState, ServerState, Session, SessionOwner, Topic,
};
use crate::core::record::{
    ChannelState, ClockOrigin, MemberEntry, RecordFormat, RecordedLogin, RecordedPacedReply,
    RecordedRegistration, RecordedRing, RecordedSasl, RecordedWhowas, SessionRecord,
};

/// The body format every shard writes (D11), shared and set live: the format
/// before this release's newest until the operator advances it.
#[derive(Clone)]
pub(crate) struct RecordFormatCell(Arc<AtomicU16>);

impl Default for RecordFormatCell {
    fn default() -> Self {
        Self(Arc::new(AtomicU16::new(RecordFormat::NEWEST.number())))
    }
}

impl RecordFormatCell {
    pub(crate) fn get(&self) -> RecordFormat {
        RecordFormat::read(self.0.load(Ordering::Relaxed))
            .expect("the cell holds only formats this release writes")
    }

    pub(crate) fn set(&self, format: RecordFormat) {
        self.0.store(format.number(), Ordering::Relaxed);
    }
}

/// Where a shard sends channel replicas: to the edge holding a slot, on this
/// shard's stream of that edge's link.
pub(crate) trait ReplicaSink: Send + Sync + 'static {
    fn send(&self, slot: u16, shard: CoreShardId, replica: Replica);
}

/// What every shard shares of the held state: the format it writes and, in
/// edge mode, where channel replicas go (set once, when the link server is).
#[derive(Clone, Default)]
pub(crate) struct HeldSinks {
    pub(crate) format: RecordFormatCell,
    pub(crate) replicas: Arc<std::sync::OnceLock<Arc<dyn ReplicaSink>>>,
    /// Whether the rebuild of what the edges hold is over (DESIGN §19.3):
    /// until it is, the core opens no session of its own — the `local`
    /// driver's — which would make channels the rebuild is about to restore.
    pub(crate) rebuilt: RebuildDone,
}

/// Whether the core has rebuilt what its edges held; true where there is
/// nothing to rebuild.
#[derive(Clone)]
pub(crate) struct RebuildDone(Arc<tokio::sync::watch::Sender<bool>>);

impl Default for RebuildDone {
    fn default() -> Self {
        Self(Arc::new(tokio::sync::watch::Sender::new(true)))
    }
}

impl RebuildDone {
    /// A rebuild is to come: the core's own sessions wait for it.
    pub(crate) fn pending(&self) {
        self.0.send_replace(false);
    }

    /// The rebuild is over, or there is none.
    pub(crate) fn done(&self) {
        self.0.send_replace(true);
    }

    /// Resolves once the rebuild is over.
    pub(crate) async fn wait(&self) {
        let mut done = self.0.subscribe();
        // The sender lives as long as this handle: `wait_for` ends only on
        // the value.
        drop(done.wait_for(|done| *done).await);
    }
}

/// `AUTHENTICATE` chunks accumulating toward a payload, with the input lines
/// that carried them: retained for replay until the payload completes or the
/// exchange is abandoned, which takes them.
#[derive(Debug, Default)]
pub(crate) struct SaslBuffer {
    text: String,
    lines: Vec<u64>,
}

impl SaslBuffer {
    pub(crate) fn len(&self) -> usize {
        self.text.len()
    }

    /// Add `piece`, carried by input line `line`.
    pub(crate) fn push(&mut self, piece: &str, line: u64) {
        self.text.push_str(piece);
        self.lines.push(line);
    }

    pub(crate) fn clear(&mut self) {
        self.text.clear();
        self.lines.clear();
    }

    /// The payload, complete: its lines are done with.
    pub(crate) fn take(&mut self) -> String {
        self.lines.clear();
        std::mem::take(&mut self.text)
    }
}

/// What a session last published for its edge to hold, and how many of its
/// input lines the shard has handled on its current link.
#[derive(Debug, Default)]
pub(crate) struct HeldMarks {
    handled: u64,
    record: Option<Bytes>,
    revision: u64,
    ack: Ack,
}

/// What the edges have been told of one channel: its state, each member's
/// entry, and the revision they were told at.
#[derive(Debug, Default)]
pub(crate) struct ReplicaLedger {
    revision: u64,
    state: Option<Bytes>,
    members: HashMap<ConnId, MemberEntry>,
    slots: HashSet<u16>,
}

/// The slot of the edge `conn`'s session is on: its identifier's top bits.
pub(crate) fn slot_of(conn: ConnId) -> u16 {
    u16::try_from(conn.0 >> e6irc_link::SLOT_SHIFT).expect("a slot is 14 bits")
}

impl Session {
    /// The number of the input line the shard is handling now (the count of
    /// lines handled on this link, this one included).
    pub(crate) fn input_line(&self) -> u64 {
        self.held_marks.handled
    }

    /// The input lines accumulations hold, in order.
    fn retained(&self) -> Vec<u64> {
        let mut retained = self.sasl_buf.lines.clone();
        if let Some(batch) = &self.multiline {
            retained.extend_from_slice(&batch.input_lines);
        }
        retained.sort_unstable();
        retained
    }

    /// The session's record, with the `conversations` it takes part in that
    /// are never stored. Every field is named: each is recorded, or is
    /// rebuilt from elsewhere, or is empty at a cut, as the comment beside it
    /// says.
    fn record(&self, conversations: Vec<RecordedRing>) -> SessionRecord {
        let Session {
            // The link the rebuild opens.
            output: _,
            directory_key,
            host,
            // Rebuilt from the address the edge opened the session with.
            real_ip: _,
            limit_key: _,
            transport,
            tls,
            reg,
            cap_negotiating,
            cap_302,
            caps,
            login,
            sasl,
            sasl_verify,
            // Its chunks' lines are retained, and replayed.
            sasl_buf: _,
            credential_attempts,
            pending_identify,
            // The next core's credential epoch starts afresh.
            verify_epoch: _,
            pending_register,
            nick_enforcement,
            drop_confirmation,
            away,
            oper,
            invisible,
            wallops,
            bot,
            registered_only,
            // From the channel replicas.
            channels: _,
            // Empty at a cut: every JOIN in flight is answered first.
            pending_joins: _,
            part_on_join: _,
            last_knock,
            nick_changes,
            monitoring,
            // Its lines are retained, and replayed.
            multiline: _,
            channel_list,
            channel_names,
            paced_who,
            // Empty at a cut: every labeled answer is gathered first.
            label_groups: _,
            anon_read_markers,
            // From the oper status the record holds.
            flood_exempt: _,
            idle_since,
            // From the edge's milliseconds since the last input line.
            last_received: _,
            signon,
            opened_at,
            awaiting_pong,
            last_ping_sent,
            // Empty at a cut: every database round trip completes first.
            deferred_replies: _,
            held: _,
            history_requests_in_flight: _,
            // Republished from the rebuilt session.
            published: _,
            // What was published of it, which this is.
            held_marks: _,
        } = self;
        let NickEnforcement { held, deadlines } = nick_enforcement;
        let NickChangeThrottle { count, last } = nick_changes;
        let pending_label = |reply: &Option<super::PendingServiceReply>| {
            reply.as_ref().map(|reply| reply.label.clone())
        };
        SessionRecord {
            directory_key: directory_key.get(),
            host: host.clone(),
            transport: *transport,
            tls: tls.clone(),
            registration: match reg {
                Registration::Registering {
                    nick,
                    user,
                    realname,
                    refused_nick,
                } => RecordedRegistration::Registering {
                    nick: nick.clone(),
                    user: user.clone(),
                    realname: realname.clone(),
                    refused_nick: refused_nick.clone(),
                },
                Registration::Registered {
                    nick,
                    user,
                    realname,
                } => RecordedRegistration::Registered {
                    nick: nick.clone(),
                    user: user.clone(),
                    realname: realname.clone(),
                },
            },
            cap_negotiating: *cap_negotiating,
            cap_302: *cap_302,
            caps: caps_bits(*caps),
            login: login.as_ref().map(|login| RecordedLogin {
                account: login.account.clone(),
                credential: login.credential,
                expires_at: login.expires_at,
            }),
            sasl: match sasl {
                SaslState::Idle => RecordedSasl::Idle,
                SaslState::PlainPending => RecordedSasl::PlainPending,
                SaslState::BearerPending => RecordedSasl::BearerPending,
                SaslState::Verifying => RecordedSasl::Verifying,
            },
            sasl_verify: pending_label(sasl_verify),
            credential_attempts: credential_attempts.used(),
            pending_identify: pending_label(pending_identify),
            pending_register: pending_label(pending_register),
            nick_held: held.as_ref().map(|key| key.0.clone()),
            nick_deadlines: deadlines
                .iter()
                .map(|(key, deadline)| (key.0.clone(), *deadline))
                .collect(),
            drop_confirmation: drop_confirmation
                .as_ref()
                .map(|(account, key)| (account.0.clone(), key.clone())),
            away: away.clone(),
            oper: oper.clone(),
            invisible: *invisible,
            wallops: *wallops,
            bot: *bot,
            registered_only: *registered_only,
            last_knock: *last_knock,
            nick_changes: (*count, *last),
            monitoring: monitoring
                .iter()
                .map(|(key, display)| (key.0.clone(), display.clone()))
                .collect(),
            channel_list: channel_list.as_ref().map(|cursor| cursor.recorded()),
            channel_names: channel_names.as_ref().map(|cursor| cursor.recorded()),
            paced_who: paced_who
                .iter()
                .flat_map(|paced| paced.replies.iter())
                .map(|reply| RecordedPacedReply {
                    batch: reply
                        .batch
                        .as_ref()
                        .map(|batch| (batch.label.clone(), batch.reference.clone(), batch.opened)),
                    lines: reply.lines.iter().cloned().collect(),
                })
                .collect(),
            anon_read_markers: anon_read_markers
                .iter()
                .map(|(target, at)| (target.0.clone(), *at))
                .collect(),
            idle_since: idle_since.get(),
            signon: *signon,
            opened_at: *opened_at,
            awaiting_pong: *awaiting_pong,
            last_ping_sent: *last_ping_sent,
            conversations,
        }
    }
}

/// A session's negotiated capabilities as the bits a record holds, in the
/// order of [`Caps`]' fields: every field named, so a capability added to
/// `Caps` does not compile until it is placed here.
pub(crate) fn caps_bits(caps: Caps) -> u32 {
    let Caps {
        server_time,
        echo_message,
        message_tags,
        cap_notify,
        multi_prefix,
        userhost_in_names,
        extended_join,
        away_notify,
        account_notify,
        account_tag,
        setname,
        invite_notify,
        batch,
        chathistory,
        read_marker,
        labeled_response,
        chghost,
        extended_monitor,
        standard_replies,
        sasl,
        account_registration,
        multiline,
    } = caps;
    [
        server_time,
        echo_message,
        message_tags,
        cap_notify,
        multi_prefix,
        userhost_in_names,
        extended_join,
        away_notify,
        account_notify,
        account_tag,
        setname,
        invite_notify,
        batch,
        chathistory,
        read_marker,
        labeled_response,
        chghost,
        extended_monitor,
        standard_replies,
        sasl,
        account_registration,
        multiline,
    ]
    .into_iter()
    .enumerate()
    .fold(0, |bits, (index, set)| bits | (u32::from(set) << index))
}

/// The capabilities [`caps_bits`] wrote.
pub(crate) fn caps_from_bits(bits: u32) -> Caps {
    let set = |index: u32| bits & (1 << index) != 0;
    Caps {
        server_time: set(0),
        echo_message: set(1),
        message_tags: set(2),
        cap_notify: set(3),
        multi_prefix: set(4),
        userhost_in_names: set(5),
        extended_join: set(6),
        away_notify: set(7),
        account_notify: set(8),
        account_tag: set(9),
        setname: set(10),
        invite_notify: set(11),
        batch: set(12),
        chathistory: set(13),
        read_marker: set(14),
        labeled_response: set(15),
        chghost: set(16),
        extended_monitor: set(17),
        standard_replies: set(18),
        sasl: set(19),
        account_registration: set(20),
        multiline: set(21),
    }
}

/// A session a rebuild resumes: its record, and what the rebuild gives it
/// beside it.
#[derive(Debug)]
pub struct SessionRebuild {
    pub(crate) conn: ConnId,
    pub(crate) record: SessionRecord,
    pub(crate) tx: crate::core::SendQueue,
    /// Allocated in the records' original order.
    pub(crate) directory_key: super::DirectoryKey,
    /// The address the edge opened the session with, as `Open` gives it.
    pub(crate) address: String,
    /// Milliseconds since the client's last input line, as its edge counts.
    pub(crate) since_input_ms: u64,
    /// The channels the replicas hold it in, by folded name.
    pub(crate) channels: Vec<String>,
    /// Shared with its channels' member profiles.
    pub(crate) idle_since: IdleSince,
    /// Lines its edge sent the core before this one that were neither
    /// acknowledged nor retained: of unknown fate (D5).
    pub(crate) unconfirmed: u32,
}

/// A channel a rebuild resumes: its state from the replica of the highest
/// revision, and its members from every edge's.
#[derive(Debug)]
pub struct ChannelRebuild {
    pub(crate) key: ChanKey,
    pub(crate) state: ChannelState,
    pub(crate) revision: u64,
    pub(crate) members: Vec<RebuiltMember>,
}

/// One member of a rebuilt channel, as its record shows it.
#[derive(Debug)]
pub struct RebuiltMember {
    pub(crate) recipient: Recipient,
    pub(crate) entry: MemberEntry,
    pub(crate) identity: MemberIdentity,
    pub(crate) profile: ChannelMemberProfile,
}

impl RebuiltMember {
    /// The member `conn` whose record is `record`, homed on `shard`; `None`
    /// for a session not registered, which no channel can hold.
    pub(crate) fn of(
        conn: ConnId,
        shard: CoreShardId,
        record: &SessionRecord,
        address: &str,
        entry: MemberEntry,
        idle_since: IdleSince,
    ) -> Option<Self> {
        let RecordedRegistration::Registered {
            nick,
            user,
            realname,
        } = &record.registration
        else {
            return None;
        };
        let prefix = format!("{nick}!{user}@{}", record.host);
        Some(Self {
            recipient: Recipient::new(SessionOwner::new(conn, shard), caps_from_bits(record.caps)),
            entry,
            identity: MemberIdentity::new(nick.clone(), prefix, record.invisible),
            profile: ChannelMemberProfile {
                user: user.clone(),
                host: record.host.clone(),
                real_ip: real_ip_of(address),
                realname: realname.clone(),
                account: record.login.as_ref().map(|login| login.account.clone()),
                away: record.away.is_some(),
                oper: record.oper.is_some(),
                bot: record.bot,
                idle_since,
            },
        })
    }
}

/// The address a session opened with, as it keeps it ([`Session::real_ip`]).
fn real_ip_of(address: &str) -> Option<std::net::IpAddr> {
    address
        .parse::<std::net::IpAddr>()
        .ok()
        .map(|address| address.to_canonical())
}

/// What stops a shard being cut exactly: work in flight, named.
#[derive(Debug, Default)]
pub struct Unsettled {
    /// Sessions waiting on something, each with what.
    pub(crate) sessions: Vec<(ConnId, &'static str)>,
    /// The shard's own waits.
    pub(crate) shard: Vec<&'static str>,
}

impl Unsettled {
    pub(crate) fn is_empty(&self) -> bool {
        self.sessions.is_empty() && self.shard.is_empty()
    }
}

impl ServerState {
    /// Count one input line of `conn`'s as handled: the line the shard is
    /// about to handle.
    pub(crate) fn note_input_line(&mut self, conn: ConnId) {
        if let Some(session) = self.sessions.get_mut(&conn) {
            session.held_marks.handled += 1;
        }
    }

    /// The conversations `conn` takes part in that are never stored: those
    /// with an unauthenticated party (D6).
    fn unstored_conversations(&self, conn: ConnId) -> Vec<RecordedRing> {
        let identity = self.conn_identity(conn);
        self.history
            .conversations_of(&identity)
            .filter(|key| {
                key.participants()
                    .is_some_and(|(lo, hi)| lo.starts_with('~') || hi.starts_with('~'))
            })
            .filter_map(|key| {
                let ring = self.history.get(key)?;
                Some(RecordedRing {
                    key: key.as_str().to_owned(),
                    complete: ring.complete(),
                    shed_through: ring.shed_through().cloned(),
                    entries: ring.entries().iter().cloned().collect(),
                })
            })
            .collect()
    }

    /// Republish the record and acknowledgement of each of `conns` whose edge
    /// holds them, where they changed. Reached only from
    /// [`Self::publish_changed_sessions`], after every event, and from the
    /// cut, which republishes every session through it.
    pub(super) fn publish_held_sessions(&mut self, conns: &[ConnId]) {
        let format = self.held_sinks.format.get();
        let origin = self.clock_origin;
        for conn in conns {
            let Some(session) = self.sessions.get(conn) else {
                continue;
            };
            if !session.output.holds() {
                continue;
            }
            let conversations = self.unstored_conversations(*conn);
            let session = &self.sessions[conn];
            let body = session
                .record(conversations)
                .encode(format, origin)
                .expect("a session's state is within every body bound");
            let ack = Ack {
                through: session.held_marks.handled,
                retained: session.retained(),
            };
            let session = self.sessions.output_mut(conn).expect("present above");
            if session.held_marks.record.as_ref() != Some(&body) {
                session.held_marks.revision += 1;
                session
                    .output
                    .hold_record(session.held_marks.revision, body.clone());
                session.held_marks.record = Some(body);
            }
            if session.held_marks.ack != ack {
                session.output.hold_ack(ack.clone());
                session.held_marks.ack = ack;
            }
        }
    }

    /// Republish the replica of each of `keys` to the edges hosting its
    /// members, where it changed; a channel gone, or gone from an edge, is
    /// withdrawn from it. Reached only from
    /// [`Self::publish_changed_channels`] and the cut.
    pub(super) fn publish_held_channels(&mut self, keys: &[ChanKey]) {
        let Some(sink) = self.held_sinks.replicas.get().cloned() else {
            for key in keys {
                if let Some(channel) = self.channels.channels.get_mut(key) {
                    channel.replica_dirty.clear();
                }
            }
            return;
        };
        let format = self.held_sinks.format.get();
        let origin = self.clock_origin;
        for key in keys {
            let name = Bytes::from(key.as_str().to_owned());
            let Some(channel) = self.channels.channels.get_mut(key) else {
                if let Some(ledger) = self.replicated.remove(key) {
                    let revision = ledger.revision + 1;
                    for slot in ledger.slots {
                        sink.send(
                            slot,
                            self.shard,
                            Replica {
                                channel: name.clone(),
                                revision,
                                change: ReplicaChange::Gone,
                            },
                        );
                    }
                }
                continue;
            };
            let dirty = std::mem::take(&mut channel.replica_dirty);
            let state = channel_state(channel)
                .encode(format, origin)
                .expect("a channel's state is within every body bound");
            let ledger = self.replicated.entry(key.clone()).or_default();
            let mut members_by_slot: HashMap<u16, Vec<(ConnId, MemberEntry)>> = HashMap::new();
            for (conn, modes) in channel.members() {
                members_by_slot
                    .entry(slot_of(conn))
                    .or_default()
                    .push((conn, entry_of(modes)));
            }
            let mut changes: Vec<(u16, ReplicaChange)> = Vec::new();
            let state_changed = ledger.state.as_ref() != Some(&state);
            for (slot, members) in &members_by_slot {
                let told = ledger.slots.contains(slot);
                if state_changed || !told {
                    changes.push((*slot, ReplicaChange::State(state.clone())));
                }
                if !told {
                    for (conn, entry) in members {
                        ledger.members.insert(*conn, *entry);
                        changes.push((*slot, member_change(*conn, *entry, format, origin)));
                    }
                }
            }
            for conn in dirty {
                if !ledger.slots.contains(&slot_of(conn)) {
                    // A slot told above already has every member.
                    continue;
                }
                match channel.member(conn).map(entry_of) {
                    Some(entry) => {
                        if ledger.members.insert(conn, entry) != Some(entry) {
                            changes
                                .push((slot_of(conn), member_change(conn, entry, format, origin)));
                        }
                    }
                    None => {
                        if ledger.members.remove(&conn).is_some() {
                            let session = e6irc_link::SessionId::new(conn.0)
                                .expect("a connection is never 0");
                            changes.push((slot_of(conn), ReplicaChange::MemberGone(session)));
                        }
                    }
                }
            }
            let gone: Vec<u16> = ledger
                .slots
                .iter()
                .copied()
                .filter(|slot| !members_by_slot.contains_key(slot))
                .collect();
            for slot in &gone {
                ledger.members.retain(|conn, _| slot_of(*conn) != *slot);
                changes.push((*slot, ReplicaChange::Gone));
            }
            ledger.slots = members_by_slot.keys().copied().collect();
            ledger.state = Some(state);
            if changes.is_empty() {
                continue;
            }
            ledger.revision += 1;
            channel.revision = ledger.revision;
            for (slot, change) in changes {
                sink.send(
                    slot,
                    self.shard,
                    Replica {
                        channel: name.clone(),
                        revision: ledger.revision,
                        change,
                    },
                );
            }
        }
    }

    /// Close, with `reason`, every session of this shard whose edge holds
    /// nothing for the next core — in edge mode the `local` driver's, which
    /// lives in the core itself, and any on a version 1 link — so its client
    /// and its channels hear it end before the cut rather than nothing. How
    /// many were closed.
    pub(crate) fn close_unheld(&mut self, reason: &str) -> usize {
        let unheld: Vec<ConnId> = self
            .sessions
            .iter()
            .filter(|(_, session)| !session.output.holds())
            .map(|(conn, _)| *conn)
            .collect();
        for conn in &unheld {
            self.close_with_error(*conn, reason);
        }
        unheld.len()
    }

    /// What keeps this shard from being cut exactly now.
    pub(crate) fn unsettled(&self) -> Unsettled {
        let mut unsettled = Unsettled::default();
        for (conn, session) in &self.sessions {
            let waiting = if session.deferred_replies > 0 || !session.held.is_empty() {
                Some("a deferred reply")
            } else if !session.label_groups.is_empty() {
                Some("a labeled response in pieces")
            } else if !session.pending_joins.is_empty() {
                Some("a JOIN in flight")
            } else if session.sasl == SaslState::Verifying || session.sasl_verify.is_some() {
                Some("a SASL verification")
            } else if session.pending_identify.is_some() {
                Some("a NickServ IDENTIFY")
            } else if session.pending_register.is_some() {
                Some("a registration")
            } else if session.history_requests_in_flight > 0 {
                Some("a CHATHISTORY page")
            } else if [&session.channel_list, &session.channel_names]
                .into_iter()
                .flatten()
                .any(crate::core::list::ChannelListCursor::page_in_flight)
            {
                Some("a LIST page")
            } else {
                None
            };
            if let Some(waiting) = waiting {
                unsettled.sessions.push((*conn, waiting));
            }
        }
        for (pending, what) in [
            (
                !self.pending_channel_registrations.is_empty(),
                "a channel registration",
            ),
            (!self.pending_channel_topics.is_empty(), "a retained topic"),
            (!self.pending_server_bans.is_empty(), "a server ban"),
            (
                !self.pending_admin_channel_drops.is_empty(),
                "a channel drop",
            ),
            (!self.pending_admin_server_bans.is_empty(), "a server ban"),
            (
                !self.pending_connection_lists.is_empty(),
                "a connection list",
            ),
            (
                !self.pending_channel_controls.is_empty(),
                "a channel control",
            ),
            (!self.pending_read_markers.is_empty(), "a read marker"),
            (
                !self.user_events_in_progress.is_empty(),
                "a user event in pieces",
            ),
        ] {
            if pending {
                unsettled.shard.push(what);
            }
        }
        unsettled
    }

    /// Cut this shard: republish every session and channel whole where it
    /// changed, so the edges hold the state as it is now, and stop — nothing
    /// is handled after this, so nothing can follow the cut. The
    /// account-creation buckets are the cut state this shard contributes.
    pub(crate) fn cut(&mut self) -> Vec<(String, f64, e6irc_proto::time::MonoMillis)> {
        let conns: Vec<ConnId> = self.sessions.iter().map(|(conn, _)| *conn).collect();
        self.publish_held_sessions(&conns);
        let keys: Vec<ChanKey> = self.channels.channels.keys().cloned().collect();
        self.publish_held_channels(&keys);
        self.frozen = true;
        self.registration_buckets
            .iter()
            .map(|(key, (tokens, refilled))| (key.as_host(), *tokens, *refilled))
            .collect()
    }

    /// Whether this shard has been cut and handles nothing more.
    pub(crate) fn is_cut(&self) -> bool {
        self.frozen
    }

    /// Take the account-creation buckets a cut carried: each shard counts
    /// the addresses its sessions open from, and any may open from any.
    pub(crate) fn adopt_registration_buckets(
        &mut self,
        buckets: &[(String, f64, e6irc_proto::time::MonoMillis)],
    ) {
        for (key, tokens, refilled) in buckets {
            self.registration_buckets.insert(
                e6irc_edge::address::PeerLimitKey::for_session_host(key),
                (*tokens, *refilled),
            );
        }
    }

    /// Resume the session a rebuild hands this shard. The record is taken
    /// whole: every session field comes from it, from what the rebuild gives
    /// beside it, or starts empty as it is at a cut.
    pub(crate) fn rebuild_session(&mut self, rebuild: SessionRebuild) {
        let SessionRebuild {
            conn,
            record,
            tx,
            directory_key,
            address,
            since_input_ms,
            channels,
            idle_since,
            unconfirmed,
        } = rebuild;
        let SessionRecord {
            directory_key: _,
            host,
            transport,
            tls,
            registration,
            cap_negotiating,
            cap_302,
            caps,
            login,
            sasl,
            sasl_verify,
            credential_attempts,
            pending_identify,
            pending_register,
            nick_held,
            nick_deadlines,
            drop_confirmation,
            away,
            oper,
            invisible,
            wallops,
            bot,
            registered_only,
            last_knock,
            nick_changes,
            monitoring,
            channel_list,
            channel_names,
            paced_who,
            anon_read_markers,
            idle_since: idle_at,
            signon,
            opened_at,
            awaiting_pong,
            last_ping_sent,
            conversations,
        } = record;
        let now = (self.config.mono_clock)();
        idle_since.set(idle_at);
        let registered = matches!(registration, RecordedRegistration::Registered { .. });
        let reg = match registration {
            RecordedRegistration::Registering {
                nick,
                user,
                realname,
                refused_nick,
            } => Registration::Registering {
                nick,
                user,
                realname,
                refused_nick,
            },
            RecordedRegistration::Registered {
                nick,
                user,
                realname,
            } => Registration::Registered {
                nick,
                user,
                realname,
            },
        };
        let pending = |label: Option<Option<String>>| label.map(super::PendingServiceReply::new);
        let recorded_sweeps =
            usize::from(channel_list.is_some()) + usize::from(channel_names.is_some());
        let channel_list = channel_list.and_then(|sweep| self.resumed_sweep(sweep));
        let channel_names = channel_names.and_then(|sweep| self.resumed_sweep(sweep));
        let sweeps_lost = recorded_sweeps
            - usize::from(channel_list.is_some())
            - usize::from(channel_names.is_some());
        let session = Session {
            output: super::SessionOutput::new(tx, self.drained.clone()),
            directory_key,
            host,
            real_ip: real_ip_of(&address),
            limit_key: e6irc_edge::address::PeerLimitKey::for_session_host(&address),
            transport,
            tls,
            reg,
            cap_negotiating,
            cap_302,
            caps: caps_from_bits(caps),
            login: login.map(|login| Login {
                account: login.account,
                credential: login.credential,
                expires_at: login.expires_at,
            }),
            sasl: match sasl {
                RecordedSasl::Idle => SaslState::Idle,
                RecordedSasl::PlainPending => SaslState::PlainPending,
                RecordedSasl::BearerPending => SaslState::BearerPending,
                RecordedSasl::Verifying => SaslState::Verifying,
            },
            sasl_verify: pending(sasl_verify),
            sasl_buf: SaslBuffer::default(),
            credential_attempts: crate::identity::CredentialAttemptBudget::resumed(
                credential_attempts,
            ),
            pending_identify: pending(pending_identify),
            verify_epoch: self.credential_epoch,
            pending_register: pending(pending_register),
            nick_enforcement: NickEnforcement {
                held: nick_held.map(|nick| self.nick_key(&nick)),
                deadlines: nick_deadlines
                    .into_iter()
                    .map(|(nick, deadline)| (self.nick_key(&nick), deadline))
                    .collect(),
            },
            drop_confirmation: drop_confirmation
                .map(|(account, key)| (self.account_key(&account), key)),
            away,
            oper,
            invisible,
            wallops,
            bot,
            registered_only,
            channels: channels.iter().map(|key| self.chan_key(key)).collect(),
            pending_joins: HashMap::new(),
            part_on_join: HashMap::new(),
            last_knock,
            nick_changes: NickChangeThrottle {
                count: nick_changes.0,
                last: nick_changes.1,
            },
            monitoring: monitoring
                .into_iter()
                .map(|(key, display)| (self.nick_key(&key), display))
                .collect(),
            multiline: None,
            channel_list,
            channel_names,
            paced_who: (!paced_who.is_empty()).then(|| {
                let mut paced = crate::core::paced::PacedReplies::default();
                for reply in paced_who {
                    paced.push(crate::core::paced::PacedReply {
                        batch: reply.batch.map(|(label, reference, opened)| {
                            crate::core::paced::PacedBatch {
                                label,
                                reference,
                                opened,
                            }
                        }),
                        lines: reply.lines.into_iter().collect(),
                    });
                }
                paced
            }),
            label_groups: HashMap::new(),
            anon_read_markers: anon_read_markers
                .into_iter()
                .map(|(target, at)| (super::MarkerTarget::stored(target), at))
                .collect(),
            flood_exempt: false,
            idle_since,
            last_received: now
                .saturating_sub(e6irc_proto::time::MonoMillis::from_millis(since_input_ms)),
            signon,
            opened_at,
            awaiting_pong,
            last_ping_sent,
            deferred_replies: 0,
            held: crate::core::HeldOutput::default(),
            history_requests_in_flight: 0,
            published: None,
            held_marks: HeldMarks::default(),
        };
        let previous = self.sessions.insert(conn, session);
        assert!(previous.is_none(), "a rebuild resumes a session once");
        // The directories every other shard asks, kept by their own upkeep.
        let nick = self.sessions[&conn].nick().map(str::to_owned);
        if let Some(nick) = &nick {
            let key = self.nick_key(nick);
            self.nicks
                .claim(key.clone(), SessionOwner::new(conn, self.shard), registered);
        }
        for key in &channels {
            self.memberships.join(conn, self.chan_key(key));
        }
        for key in self.sessions[&conn]
            .monitoring
            .keys()
            .cloned()
            .collect::<Vec<_>>()
        {
            self.monitors.watch(key, conn);
        }
        if let Some(login) = &self.sessions[&conn].login {
            let key = self.account_key(&login.account);
            let credential = login.credential;
            self.account_sessions.entry(key).or_default().insert(conn);
            self.signed_in_credentials.hold(credential);
        }
        let session = &self.sessions[&conn];
        if session.channel_list.is_some()
            || session.channel_names.is_some()
            || session.paced_who.is_some()
        {
            self.pacing.insert(conn);
        }
        for ring in conversations {
            self.history.restore(
                super::HistoryKey(ring.key),
                ring.complete,
                ring.shed_through,
                ring.entries,
            );
        }
        // The operator exemption the record's oper status carries reaches the
        // edge's meter.
        self.sync_flood_exemption(conn);
        self.settle_interrupted(conn);
        self.tell_unconfirmed(conn, unconfirmed);
        self.reauthorize_address(conn);
        if sweeps_lost > 0 {
            let notice = self.server_notice_line(
                conn,
                "Your LIST or NAMES in progress could not be resumed after the server restarted; \
                 please send it again.",
            );
            self.send(conn, &notice);
        }
    }

    /// A session whose record says a verification or registration was awaited
    /// when its core went — never after a graceful cut, which waits for each —
    /// is told that answer is not coming, as the design's crash column has it:
    /// `906` for SASL, a NickServ notice for the rest.
    fn settle_interrupted(&mut self, conn: ConnId) {
        let session = self.sessions.get_mut(&conn).expect("rebuilt above");
        let sasl = session.sasl_verify.take().is_some() || session.sasl == SaslState::Verifying;
        if sasl {
            session.sasl = SaslState::Idle;
        }
        let identify = session.pending_identify.take().is_some();
        let register = session.pending_register.take().is_some();
        if sasl {
            self.numeric(
                conn,
                e6irc_proto::numerics::ERR_SASLABORTED,
                &[],
                Some("SASL authentication aborted: the server restarted during the check"),
            );
        }
        for (interrupted, what) in [(identify, "identification"), (register, "registration")] {
            if interrupted {
                self.service_notice(
                    conn,
                    "NickServ",
                    &format!(
                        "Your {what} was interrupted when the server restarted; please try again."
                    ),
                );
            }
        }
    }

    /// Tell a session how many of its lines are of unknown fate (D5): never
    /// after a graceful cut, which acknowledges every line.
    fn tell_unconfirmed(&mut self, conn: ConnId, unconfirmed: u32) {
        if unconfirmed == 0 {
            return;
        }
        let text = format!(
            "{unconfirmed} line(s) you sent while the server restarted may not have been \
             handled; send again what you need"
        );
        let line = if self.sessions[&conn].caps.standard_replies {
            format!(
                ":{} NOTE * INPUT_UNCONFIRMED {unconfirmed} :{text}",
                self.config.server_name
            )
        } else {
            self.server_notice_line(conn, &text)
        };
        self.send(conn, &line);
    }

    /// A rebuilt session is held to the server bans in force now, as the live
    /// path holds every session when a ban is set (DESIGN §2: rebuilt
    /// sessions are re-authorized, never trusted from a record).
    fn reauthorize_address(&mut self, conn: ConnId) {
        let session = &self.sessions[&conn];
        if !session.is_registered() {
            // Registration itself checks the bans.
            return;
        }
        let Some((kind, reason)) = self.ban_match(&session.server_ban_subject()) else {
            return;
        };
        let reason = super::public_ban_reason(&reason);
        self.close_with_error(conn, &format!("{}d: {reason}", kind.label()));
    }

    /// A LIST or NAMES a record holds, resumed over this core's shards.
    fn resumed_sweep(
        &mut self,
        sweep: crate::core::record::RecordedSweep,
    ) -> Option<crate::core::list::ChannelListCursor> {
        use crate::core::list::{ChannelListCursor, ChannelSweep, ListFilter};
        use crate::core::record::RecordedQuestion;
        let question = match sweep.question {
            RecordedQuestion::List {
                parameter,
                parsed_at_secs,
            } => match ListFilter::parse(parameter.as_deref(), parsed_at_secs, self.casemap) {
                Ok(filter) => ChannelSweep::List(Arc::new(filter)),
                // It was read when the LIST began; a parameter that no longer
                // reads is a record this release cannot resume.
                Err(_) => return None,
            },
            RecordedQuestion::Names {
                multi_prefix,
                userhost_in_names,
            } => ChannelSweep::Names {
                multi_prefix,
                userhost_in_names,
            },
        };
        let id = self.next_channel_list_id();
        Some(ChannelListCursor::resumed(
            id,
            question,
            sweep.batch,
            sweep.sent_through.map(|key| self.chan_key(&key)),
            self.channels.shard_count(),
        ))
    }

    /// Resume the channel a rebuild hands this shard, its owner: its state
    /// from the highest revision any edge held, its members from every edge's.
    /// It is the incarnation it was — `created_at` kept, so the history floor
    /// holds — and its history ring, which the database refills, is not the
    /// whole record.
    pub(crate) fn rebuild_channel(&mut self, rebuild: ChannelRebuild) {
        let ChannelRebuild {
            key: chan_key,
            state,
            revision,
            members,
        } = rebuild;
        let ChannelState {
            name,
            created_at,
            topic,
            flags,
            key,
            limit,
            bans,
            quiets,
            ban_exceptions,
            invite_exceptions,
            invited,
            last_knock,
        } = state;
        let mut modes = super::ChanModes::default();
        for flag in flags.chars() {
            if let Some(set) = modes.flag_mut(flag) {
                *set = true;
            }
        }
        modes.key = key;
        modes.limit = limit;
        let casemap = self.casemap;
        let list = |entries: Vec<crate::core::record::RecordedListEntry>| -> Vec<ListEntry> {
            entries
                .into_iter()
                .map(|entry| ListEntry {
                    mask: MaskKey::new(&entry.mask, casemap),
                    set_by: entry.set_by,
                    set_at_secs: entry.set_at_secs,
                })
                .collect()
        };
        let mut channel = Channel::new(
            name,
            topic.map(|(text, set_by, set_at_secs)| Topic {
                text,
                set_by,
                set_at_secs,
            }),
            modes,
            created_at,
        );
        channel.bans = list(bans);
        channel.quiets = list(quiets);
        channel.ban_exceptions = list(ban_exceptions);
        channel.invite_exceptions = list(invite_exceptions);
        channel.invited = invited.into_iter().map(ConnId).collect();
        channel.last_knock = last_knock;
        channel.revision = revision;
        channel.history_whole = false;
        for member in members {
            let RebuiltMember {
                recipient,
                entry,
                identity,
                profile,
            } = member;
            let MemberEntry { op, voice } = entry;
            channel.add_member_with_profile(
                recipient,
                profile,
                identity,
                MemberModes { op, voice },
            );
        }
        // What the edges hold is what this rebuilt: nothing to tell them.
        channel.replica_dirty.clear();
        let slots: HashSet<u16> = channel.members().map(|(conn, _)| slot_of(conn)).collect();
        let ledger = ReplicaLedger {
            revision,
            state: Some(
                channel_state(&channel)
                    .encode(self.held_sinks.format.get(), self.clock_origin)
                    .expect("a channel's state is within every body bound"),
            ),
            members: channel
                .members()
                .map(|(conn, modes)| (conn, entry_of(modes)))
                .collect(),
            slots,
        };
        self.replicated.insert(chan_key.clone(), ledger);
        self.channels.entry(chan_key).or_insert(channel);
    }
}

/// A member's ranks as a replica holds them.
fn entry_of(modes: &MemberModes) -> MemberEntry {
    let MemberModes { op, voice } = modes;
    MemberEntry {
        op: *op,
        voice: *voice,
    }
}

fn member_change(
    conn: ConnId,
    entry: MemberEntry,
    format: RecordFormat,
    origin: ClockOrigin,
) -> ReplicaChange {
    ReplicaChange::Member(
        e6irc_link::SessionId::new(conn.0).expect("a connection is never 0"),
        entry
            .encode(format, origin)
            .expect("a member entry is within every body bound"),
    )
}

/// A channel's own state, as its replicas hold it: every field named, so a
/// channel field added does not compile until it is placed here.
fn channel_state(channel: &Channel) -> ChannelState {
    let Channel {
        name,
        topic,
        // Each edge holds its own members' entries beside the state.
        members: _,
        recipients: _,
        modes,
        bans,
        quiets,
        ban_exceptions,
        invite_exceptions,
        invited,
        last_knock,
        created_at,
        // The replica's own bookkeeping.
        revision: _,
        replica_dirty: _,
        // True only of a channel never rebuilt.
        history_whole: _,
    } = channel;
    let list = |entries: &[ListEntry]| {
        entries
            .iter()
            .map(|entry| crate::core::record::RecordedListEntry {
                mask: entry.mask.as_str().to_owned(),
                set_by: entry.set_by.clone(),
                set_at_secs: entry.set_at_secs,
            })
            .collect()
    };
    let mut invited: Vec<u64> = invited.iter().map(|conn| conn.0).collect();
    invited.sort_unstable();
    ChannelState {
        name: name.clone(),
        created_at: *created_at,
        topic: topic
            .as_ref()
            .map(|topic| (topic.text.clone(), topic.set_by.clone(), topic.set_at_secs)),
        flags: super::ChanModes::FLAGS
            .chars()
            .filter(|flag| modes.flag(*flag) == Some(true))
            .collect(),
        key: modes.key.clone(),
        limit: modes.limit,
        bans: list(bans),
        quiets: list(quiets),
        ban_exceptions: list(ban_exceptions),
        invite_exceptions: list(invite_exceptions),
        invited,
        last_knock: *last_knock,
    }
}

/// The WHOWAS records and the LUSERS maximum every shard shares, as the cut
/// state carries them.
pub(crate) fn export_shared(directories: &super::CoreDirectories) -> (Vec<RecordedWhowas>, u64) {
    let whowas = directories
        .whowas
        .newest_first
        .lock()
        .expect("whowas directory poisoned")
        .iter()
        .map(|(key, entry)| RecordedWhowas {
            key: key.0.clone(),
            nick: entry.nick.clone(),
            user: entry.user.clone(),
            host: entry.host.clone(),
            realname: entry.realname.clone(),
            signoff: entry.signoff,
        })
        .collect();
    let most = directories
        .census
        .most_users
        .load(std::sync::atomic::Ordering::Relaxed);
    (whowas, u64::try_from(most).unwrap_or(u64::MAX))
}

/// Take the WHOWAS records and the LUSERS maximum a cut carried.
pub(crate) fn adopt_shared(
    directories: &super::CoreDirectories,
    casemap: e6irc_proto::casemap::CaseMapping,
    whowas: Vec<RecordedWhowas>,
    most_users: u64,
) {
    let mut ring = directories
        .whowas
        .newest_first
        .lock()
        .expect("whowas directory poisoned");
    ring.clear();
    for entry in whowas.into_iter().take(super::WHOWAS_CAP) {
        ring.push_back((
            NickKey(casemap.casefold(&entry.key)),
            super::WhowasEntry {
                nick: entry.nick,
                user: entry.user,
                host: entry.host,
                realname: entry.realname,
                signoff: entry.signoff,
            },
        ));
    }
    directories.census.most_users.fetch_max(
        usize::try_from(most_users).unwrap_or(usize::MAX),
        std::sync::atomic::Ordering::Relaxed,
    );
}

impl MultilineBatch {
    /// Note that input line `line` went into the batch: it is retained until
    /// the batch closes or is abandoned.
    pub(crate) fn took_line(&mut self, line: u64) {
        self.input_lines.push(line);
    }
}
