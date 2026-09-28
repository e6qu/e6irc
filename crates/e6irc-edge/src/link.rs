//! The core link as one process runs it (DESIGN §19.1, §19.2): one client
//! session's frames between the core and the edge, carried in memory.
//!
//! [`session`] opens a session's link and gives its two ends. The core holds
//! the [`SessionLink`]: the session's *remote send queue* — the send-queue
//! bound, in bytes, kept where the core decides what to send — and the frames
//! it sends the edge. The edge holds the [`EdgeSession`]: the send-queue
//! *buffer* its writer drains, and the frames it sends back. In process a
//! frame is a call on one end that the other end observes:
//!
//! | Frame | Direction | In process |
//! |---|---|---|
//! | `Output` | core → edge | [`SessionLink::output`]: one line into the buffer, admitted by the bound |
//! | `Kill` | core → edge | [`SessionLink::kill`]: the buffer discarded, then one final line |
//! | `End` | core → edge | dropping the [`SessionLink`]: the edge drains what is buffered, then closes, and stops reading at once ([`EdgeSession::session_over`]) |
//! | flood exemption | core → edge | [`SessionLink::set_flood_exempt`], read by the edge's [`crate::meter::LineMeter`] |
//! | `Drained` | edge → core | [`EdgeSession::written`]: bytes written to the client socket |
//!
//! `Open`, `Line`, `OverlongLine` and `Closed` go edge to core through the
//! [`crate::connection::CorePort`], and the `Credit` a line waits for is room
//! in the core's own queue, which the port's push awaits.
//!
//! The bound is measured at the client socket (DESIGN §2): a line counts
//! against it from the moment the core sends it until the edge reports it
//! written, not merely until the edge's writer takes it out of the buffer. The
//! edge's buffer is itself bounded at the same size by the same rule
//! ([`e6irc_queue::fits`]), as the edge's own cap on a core that over-sends;
//! since the buffer never holds more than the core counts in flight, it never
//! refuses a line the core's account admitted ([`OutputRefused::EdgeOverrun`]
//! is that invariant broken).

use std::sync::{Arc, OnceLock};

use e6irc_queue::{Envelope, Progress, PushError, Receiver, Sender, SendersGone};
use tokio::sync::Notify;

use crate::connection::Output;
use crate::meter::{CommandFlood, FloodExemption, LineMeter};

/// The bytes one output line holds against its session's send-queue bound,
/// its CRLF included: the one weight the core's account and the edge's buffer
/// both count.
pub fn weight(output: &Output) -> usize {
    output.0.len()
}

/// Open one session's link with a send-queue bound of `sendq_bytes`: the
/// core's end and the edge's end.
pub fn session(name: &'static str, sendq_bytes: usize) -> (SessionLink, EdgeSession) {
    let (buffer, taken) = e6irc_queue::weighted_queue(
        e6irc_queue::Config {
            name,
            capacity: sendq_bytes,
            policy: e6irc_queue::Policy::Fifo,
        },
        weight,
    );
    let shared = Arc::new(Shared {
        written: Progress::default(),
        drained_wake: OnceLock::new(),
        exemption: FloodExemption::default(),
    });
    (
        SessionLink {
            buffer,
            capacity: sendq_bytes,
            sent: 0,
            shared: shared.clone(),
        },
        EdgeSession {
            buffer: taken,
            shared,
            taken: 0,
            written: 0,
        },
    )
}

/// What both ends of one session's link share in process.
struct Shared {
    /// The bytes the edge has written to the client socket: every `Drained`.
    written: Progress,
    /// Whom a `Drained` wakes when the core asked to be woken
    /// ([`SessionLink::arm_drained_wake`]): the core shard the session lives on.
    drained_wake: OnceLock<Arc<Notify>>,
    exemption: FloodExemption,
}

/// The core's end of one session's link: its remote send queue, and the frames
/// the core sends the edge. Dropping it is the `End` frame.
#[derive(Debug)]
pub struct SessionLink {
    /// In process, the edge's buffer itself; nothing else ever pushes into it.
    buffer: Sender<Output>,
    capacity: usize,
    /// Every byte sent that the buffer took: with what the edge reports
    /// written, what is in flight.
    sent: u64,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("written", &self.written)
            .finish_non_exhaustive()
    }
}

/// What became of a line the core sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sent {
    /// In the edge's buffer, and counted in flight until the edge reports it
    /// written.
    Buffered,
    /// The edge's end is gone: the connection is over, and the core hears of
    /// it (`Closed`) if it has not already. Nothing is counted in flight.
    EdgeGone,
}

/// Why a line was not sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputRefused {
    /// It does not fit the bound beside what is in flight: "SendQ exceeded".
    OverBound,
    /// The edge's own cap refused a line the core's account admitted — the
    /// invariant this module's documentation states, broken.
    EdgeOverrun,
}

impl SessionLink {
    /// The bound, in bytes.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Bytes sent to the edge and not yet reported written to the client.
    pub fn in_flight(&self) -> usize {
        self.in_flight_given(self.shared.written.get())
    }

    fn in_flight_given(&self, written: u64) -> usize {
        usize::try_from(self.sent - written).expect("in flight is bounded by the send queue")
    }

    /// Send `line` (the `Output` frame), if it fits the bound beside what is
    /// in flight — by the queue's own admission rule, so a line heavier than
    /// the whole bound still goes to a session with nothing in flight.
    pub fn output(&mut self, line: Output) -> Result<Sent, OutputRefused> {
        let weight = weight(&line);
        if !e6irc_queue::fits(self.in_flight(), weight, self.capacity) {
            return Err(OutputRefused::OverBound);
        }
        match self.buffer.try_push(line) {
            Ok(_sequence) => {
                self.sent += weight as u64;
                Ok(Sent::Buffered)
            }
            Err(PushError::Closed(_)) => Ok(Sent::EdgeGone),
            Err(PushError::Full(_)) => Err(OutputRefused::EdgeOverrun),
        }
    }

    /// Discard everything the edge has not yet taken of this session's
    /// output, and send `line` as the last (the `Kill` frame): for a session
    /// killed because its client could not take what it was sent. The line
    /// is not held to the bound — the buffer it enters is empty.
    pub fn kill(&mut self, line: Output) {
        drop(self.buffer.take_queued());
        match self.buffer.try_push(line) {
            Ok(_) | Err(PushError::Closed(_)) => {}
            // This end is the buffer's only producer, and it was just emptied.
            Err(PushError::Full(_)) => unreachable!("an emptied buffer admits any one line"),
        }
    }

    /// Ask to be woken by the edge's next `Drained`, then say what is in
    /// flight: room that appears after this reading always wakes the shard
    /// ([`Progress::arm`]).
    pub fn arm_drained_wake(&self) -> usize {
        self.in_flight_given(self.shared.written.arm())
    }

    /// Whom this session's `Drained` wakes once armed: the core shard it
    /// lives on. Set once, when the session opens there.
    pub fn wake_on_drained(&self, shard: Arc<Notify>) {
        assert!(
            self.shared.drained_wake.set(shard).is_ok(),
            "a session opens on one shard, once"
        );
    }

    /// Whether the edge meters this session's lines: an IRC operator's are
    /// exempt.
    pub fn set_flood_exempt(&self, exempt: bool) {
        self.shared.exemption.set(exempt);
    }
}

/// The edge's end of one session's link: the send-queue buffer its writer
/// drains, and the frames the edge sends the core.
#[derive(Debug)]
pub struct EdgeSession {
    buffer: Receiver<Output>,
    shared: Arc<Shared>,
    /// Bytes taken out of the buffer, and of those, reported written: a
    /// report of bytes never taken is a writer's bug, caught here.
    taken: u64,
    written: u64,
}

impl EdgeSession {
    /// The next line to write to the client socket, waiting for one; `None`
    /// once the core has ended the session and everything it sent has been
    /// taken. It counts against the bound until the writer reports it
    /// [`Self::written`].
    pub async fn take(&mut self) -> Option<Envelope<Output>> {
        let envelope = self.buffer.pop().await?;
        Some(self.taken(envelope))
    }

    /// The next line to write to the client socket, if one is buffered; see
    /// [`Self::take`].
    pub fn try_take(&mut self) -> Option<Envelope<Output>> {
        let envelope = self.buffer.try_pop()?;
        Some(self.taken(envelope))
    }

    fn taken(&mut self, envelope: Envelope<Output>) -> Envelope<Output> {
        self.taken += weight(&envelope.payload) as u64;
        envelope
    }

    /// The next line, waiting for one, taken and reported written at once:
    /// for a session that is its own writer, with no socket to wait on — the
    /// bouncer's in-process `local` session, or a test reading as a client
    /// that keeps up. A socket's writer [`Self::take`]s instead, and reports
    /// only what the socket took.
    pub async fn pop(&mut self) -> Option<Envelope<Output>> {
        let envelope = self.take().await?;
        Some(self.delivered(envelope))
    }

    /// The next line if one is buffered, taken and reported written at once;
    /// see [`Self::pop`].
    pub fn try_pop(&mut self) -> Option<Envelope<Output>> {
        let envelope = self.try_take()?;
        Some(self.delivered(envelope))
    }

    fn delivered(&mut self, envelope: Envelope<Output>) -> Envelope<Output> {
        self.written(weight(&envelope.payload));
        envelope
    }

    /// Report `bytes` more of what was taken written to the client socket
    /// (the `Drained` frame), waking the core's shard if it asked.
    pub fn written(&mut self, bytes: usize) {
        self.written += bytes as u64;
        assert!(
            self.written <= self.taken,
            "reported written: {} bytes of {} taken",
            self.written,
            self.taken
        );
        if self.shared.written.advance(bytes as u64)
            && let Some(shard) = self.shared.drained_wake.get()
        {
            shard.notify_one();
        }
    }

    /// Resolves once the core has ended the session (`End` or `Kill`),
    /// however much is still buffered: the moment the edge stops reading.
    pub fn session_over(&self) -> SendersGone<Output> {
        self.buffer.senders_gone()
    }

    /// This session's command allowance of `flood`'s shape, exempt while the
    /// core says so.
    pub fn line_meter(&self, flood: Option<CommandFlood>) -> LineMeter {
        LineMeter::new(
            flood,
            self.shared.exemption.clone(),
            tokio::time::Instant::now(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn line(bytes: usize) -> Output {
        assert!(bytes >= 2);
        let mut text = vec![b'x'; bytes - 2];
        text.extend_from_slice(b"\r\n");
        Output(Bytes::from(text))
    }

    /// Everything buffered, taken and reported written, as a writer that
    /// keeps up does.
    fn write_everything(edge: &mut EdgeSession) -> usize {
        let mut bytes = 0;
        while let Some(envelope) = edge.try_take() {
            bytes += weight(&envelope.payload);
        }
        edge.written(bytes);
        bytes
    }

    #[test]
    fn a_line_counts_until_it_is_written_not_until_it_is_taken() {
        let (mut core, mut edge) = session("t", 100);
        assert_eq!(core.output(line(60)), Ok(Sent::Buffered));
        let taken = edge.try_take().expect("buffered");
        // Taken by the writer, not yet on the socket: still in flight.
        assert_eq!(core.in_flight(), 60);
        assert_eq!(core.output(line(60)), Err(OutputRefused::OverBound));
        edge.written(weight(&taken.payload));
        assert_eq!(core.in_flight(), 0);
        assert_eq!(core.output(line(60)), Ok(Sent::Buffered));
    }

    #[test]
    fn a_line_heavier_than_the_bound_goes_only_to_a_session_with_nothing_in_flight() {
        let (mut core, mut edge) = session("t", 100);
        assert_eq!(core.output(line(250)), Ok(Sent::Buffered));
        assert_eq!(core.output(line(2)), Err(OutputRefused::OverBound));
        assert_eq!(write_everything(&mut edge), 250);
        assert_eq!(core.output(line(2)), Ok(Sent::Buffered));
    }

    #[test]
    fn kill_discards_the_backlog_and_sends_one_final_line_past_the_bound() {
        let (mut core, mut edge) = session("t", 100);
        assert_eq!(core.output(line(90)), Ok(Sent::Buffered));
        core.kill(line(80));
        drop(core);
        let final_line = edge.try_take().expect("the final line");
        assert_eq!(final_line.payload, line(80));
        assert!(edge.try_take().is_none(), "the backlog went");
    }

    #[test]
    fn a_line_to_a_gone_edge_is_not_counted_in_flight() {
        let (mut core, edge) = session("t", 100);
        drop(edge);
        assert_eq!(core.output(line(60)), Ok(Sent::EdgeGone));
        assert_eq!(core.in_flight(), 0);
    }

    #[tokio::test]
    async fn ending_the_link_is_seen_at_once_and_what_was_sent_still_drains() {
        let (mut core, mut edge) = session("t", 100);
        assert_eq!(core.output(line(10)), Ok(Sent::Buffered));
        let over = edge.session_over();
        drop(core);
        over.wait().await;
        assert_eq!(edge.take().await.expect("still buffered").payload, line(10));
        assert!(edge.take().await.is_none());
    }

    #[tokio::test]
    async fn an_armed_core_is_woken_by_the_next_drained_and_only_then() {
        let (mut core, mut edge) = session("t", 100);
        let shard = Arc::new(Notify::new());
        core.wake_on_drained(shard.clone());
        assert_eq!(core.output(line(40)), Ok(Sent::Buffered));
        let taken = edge.try_take().expect("buffered");
        edge.written(10);
        // Not armed: no wake is owed.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(5), shard.notified())
                .await
                .is_err()
        );
        assert_eq!(core.arm_drained_wake(), 30);
        edge.written(weight(&taken.payload) - 10);
        shard.notified().await;
        assert_eq!(core.in_flight(), 0);
    }

    #[test]
    fn a_session_that_is_its_own_writer_frees_room_as_it_reads() {
        let (mut core, mut edge) = session("t", 100);
        assert_eq!(core.output(line(60)), Ok(Sent::Buffered));
        assert_eq!(edge.try_pop().expect("buffered").payload, line(60));
        assert_eq!(core.in_flight(), 0);
        assert_eq!(core.output(line(60)), Ok(Sent::Buffered));
    }

    #[test]
    #[should_panic(expected = "reported written")]
    fn reporting_bytes_never_taken_is_a_writers_bug() {
        let (mut core, mut edge) = session("t", 100);
        assert_eq!(core.output(line(10)), Ok(Sent::Buffered));
        edge.written(10);
    }

    /// The account and the buffer under a long random interleaving of the
    /// core sending, the writer taking and the writer reporting, as a
    /// seeded simulation: the buffer never refuses what the account
    /// admitted, never holds more than the account counts in flight, and
    /// the account never counts more than the bound plus one line; every
    /// admitted line reaches the writer, in order.
    #[test]
    fn the_account_bounds_the_buffer_under_any_interleaving() {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = |bound: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % bound
        };
        for capacity in [2, 7, 100, 512, 4096] {
            let (mut core, mut edge) = session("t", capacity);
            let mut admitted = std::collections::VecDeque::new();
            let mut taken_unwritten = 0usize;
            for step in 0..20_000u64 {
                match next(3) {
                    0 => {
                        let bytes = 2 + next(2 * capacity as u64) as usize;
                        let sent = line(bytes);
                        let fits = e6irc_queue::fits(core.in_flight(), bytes, capacity);
                        match core.output(sent.clone()) {
                            Ok(Sent::Buffered) => {
                                assert!(fits);
                                admitted.push_back(sent);
                            }
                            Err(OutputRefused::OverBound) => assert!(!fits),
                            other => panic!("step {step}: {other:?}"),
                        }
                    }
                    1 => {
                        if let Some(envelope) = edge.try_take() {
                            assert_eq!(Some(envelope.payload.clone()), admitted.pop_front());
                            taken_unwritten += weight(&envelope.payload);
                        }
                    }
                    _ => {
                        let bytes = next(taken_unwritten as u64 + 1) as usize;
                        edge.written(bytes);
                        taken_unwritten -= bytes;
                    }
                }
                let buffered: usize = admitted.iter().map(weight).sum();
                assert_eq!(core.in_flight(), buffered + taken_unwritten);
                assert!(core.in_flight() <= capacity.max(2 * capacity + 1));
            }
        }
    }
}
