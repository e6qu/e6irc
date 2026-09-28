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
//! in the queue its session's input enters, which the port's push awaits.
//!
//! A session the core serves outside a shard — a bouncer attach, a `/ws/ui`
//! socket — is opened with [`waiting_session`]: its core end never refuses a
//! line over the bound, but waits for room ([`SessionLink::poll_output`]),
//! and a writer that wants what it wrote on the socket before it goes on waits
//! for everything to be reported written ([`SessionLink::poll_written_out`]).
//! That is the backpressure a socket written directly gave, bounded by the
//! same write deadline. Such a session's `End` may carry a WebSocket close
//! frame ([`SessionLink::close_on_end`]), and an edge whose writer failed
//! says how ([`EdgeSession::writer_failed`]), so the core's writer ends as it
//! would have on the socket itself.
//!
//! The bound is measured at the client socket (DESIGN §2): a line counts
//! against it from the moment the core sends it until the edge reports it
//! written, not merely until the edge's writer takes it out of the buffer. The
//! edge's buffer is itself bounded at the same size by the same rule
//! ([`e6irc_queue::fits`]), as the edge's own cap on a core that over-sends;
//! since the buffer never holds more than the core counts in flight, it never
//! refuses a line the core's account admitted ([`OutputRefused::EdgeOverrun`]
//! is that invariant broken).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use e6irc_queue::{Envelope, Progress, PushError, Receiver, Sender, SendersGone};
use tokio::sync::{Notify, futures::OwnedNotified};

use crate::connection::Output;
use crate::meter::{CommandFlood, FloodExemption, LineMeter};
use crate::peer_write::SendFailure;

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
        edge_gone: AtomicBool::new(false),
        writer_failure: OnceLock::new(),
        close: OnceLock::new(),
    });
    (
        SessionLink {
            buffer,
            capacity: sendq_bytes,
            sent: 0,
            shared: shared.clone(),
            waiting: None,
        },
        EdgeSession {
            buffer: taken,
            shared,
            taken: 0,
            written: 0,
        },
    )
}

/// Open one session's link whose core end waits for room instead of refusing
/// a line over the bound: a session the core serves outside a shard (bouncer
/// attach, `/ws/ui`), for which a full queue is backpressure, as the socket
/// written directly was, and never "SendQ exceeded". Its `Drained` wakes the
/// core end itself.
pub fn waiting_session(name: &'static str, sendq_bytes: usize) -> (SessionLink, EdgeSession) {
    let (link, edge) = session(name, sendq_bytes);
    link.wake_on_drained(Arc::default());
    (link, edge)
}

/// What both ends of one session's link share in process.
struct Shared {
    /// The bytes the edge has written to the client socket: every `Drained`.
    written: Progress,
    /// Whom a `Drained` wakes when the core asked to be woken
    /// ([`SessionLink::arm_drained_wake`]): the core shard the session lives
    /// on, or, for a [`waiting_session`], its own core end.
    drained_wake: OnceLock<Arc<Notify>>,
    exemption: FloodExemption,
    /// The edge's end is gone: nothing more will be written.
    edge_gone: AtomicBool,
    /// How the edge's writer failed, when it did.
    writer_failure: OnceLock<SendFailure>,
    /// The WebSocket close frame this session's `End` carries.
    close: OnceLock<CloseFrame>,
}

/// A WebSocket close frame: its code and the reason a client can show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseFrame {
    pub code: u16,
    pub reason: &'static str,
}

/// The edge's end of a session is gone, so the core's end can send nothing
/// more; how its writer failed, if it did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeEnded(pub Option<SendFailure>);

impl EdgeEnded {
    /// The ending as a failed send: a stall when the writer stalled, a
    /// transport failure otherwise.
    pub fn failure(self) -> SendFailure {
        self.0.unwrap_or(SendFailure::Transport)
    }
}

impl From<EdgeEnded> for io::Error {
    fn from(ended: EdgeEnded) -> Self {
        ended.failure().into_error()
    }
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
    /// A [`waiting_session`]'s wait for its next `Drained`, while it waits.
    waiting: Option<Pin<Box<OwnedNotified>>>,
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

    fn ended(&self) -> EdgeEnded {
        EdgeEnded(self.shared.writer_failure.get().cloned())
    }

    /// Wait, on a [`waiting_session`], until `ready` holds or the edge is
    /// gone: armed before each check, so a `Drained` between the check and
    /// the wait still wakes it ([`Progress::arm`]).
    fn poll_until(
        &mut self,
        cx: &mut Context<'_>,
        ready: impl Fn(&Self) -> bool,
    ) -> Poll<Result<(), EdgeEnded>> {
        loop {
            if self.shared.edge_gone.load(Ordering::SeqCst) {
                self.waiting = None;
                return Poll::Ready(Err(self.ended()));
            }
            if ready(self) {
                self.waiting = None;
                return Poll::Ready(Ok(()));
            }
            if self.waiting.is_none() {
                let wake = self
                    .shared
                    .drained_wake
                    .get()
                    .expect("a waiting session wakes its own core end")
                    .clone();
                self.waiting = Some(Box::pin(wake.notified_owned()));
            }
            self.shared.written.arm();
            if self.shared.edge_gone.load(Ordering::SeqCst) || ready(self) {
                continue;
            }
            let waiting = self.waiting.as_mut().expect("set above");
            match waiting.as_mut().poll(cx) {
                Poll::Ready(()) => self.waiting = None,
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    /// Send `pending` once the bound has room for it (the `Output` frame),
    /// taking it: backpressure, never "SendQ exceeded". For a
    /// [`waiting_session`].
    pub fn poll_output(
        &mut self,
        cx: &mut Context<'_>,
        pending: &mut Option<Output>,
    ) -> Poll<Result<(), EdgeEnded>> {
        let Some(weight) = pending.as_ref().map(weight) else {
            return Poll::Ready(Ok(()));
        };
        ready!(self.poll_until(cx, |link| {
            e6irc_queue::fits(link.in_flight(), weight, link.capacity)
        }))?;
        let line = pending.take().expect("checked above");
        match self.output(line) {
            Ok(Sent::Buffered) => Poll::Ready(Ok(())),
            Ok(Sent::EdgeGone) => Poll::Ready(Err(self.ended())),
            // Room was just seen, and only this end adds to what is in flight.
            Err(OutputRefused::OverBound) => unreachable!("room seen is room held here"),
            Err(OutputRefused::EdgeOverrun) => {
                debug_assert!(false, "the edge refused output the send queue admitted");
                Poll::Ready(Err(EdgeEnded(None)))
            }
        }
    }

    /// Wait until everything sent is reported written to the client socket.
    /// For a [`waiting_session`].
    pub fn poll_written_out(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), EdgeEnded>> {
        self.poll_until(cx, |link| link.in_flight() == 0)
    }

    /// Send `line` once there is room, and wait until it is on the client
    /// socket: a frame written as a socket write returns. For a
    /// [`waiting_session`].
    pub async fn deliver(&mut self, line: Output) -> Result<(), EdgeEnded> {
        let mut pending = Some(line);
        std::future::poll_fn(|cx| self.poll_output(cx, &mut pending)).await?;
        std::future::poll_fn(|cx| self.poll_written_out(cx)).await
    }

    /// Have this session's `End` carry a WebSocket close frame, which the edge
    /// sends once what is buffered is written. The first close set stands.
    pub fn close_on_end(&self, frame: CloseFrame) {
        self.shared.close.get_or_init(|| frame);
    }
}

/// The core's end of a session whose output is a byte stream of IRC lines —
/// a bouncer attach, whose logic writes as it wrote to its socket: each line,
/// once its CRLF is written, is sent over the link, waiting for room, and a
/// flush waits until everything is on the client socket. Bytes that end no
/// line at a flush are refused as the writer's error, never sent as a line.
pub struct LineWriter {
    link: SessionLink,
    partial: Vec<u8>,
    pending: Option<Output>,
}

impl LineWriter {
    pub fn new(link: SessionLink) -> Self {
        Self {
            link,
            partial: Vec::new(),
            pending: None,
        }
    }

    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.link
            .poll_output(cx, &mut self.pending)
            .map_err(io::Error::from)
    }
}

impl tokio::io::AsyncWrite for LineWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_pending(cx))?;
        let (ends_line, taken) = match buf.iter().position(|&byte| byte == b'\n') {
            Some(end) => (true, end + 1),
            None => (false, buf.len()),
        };
        this.partial.extend_from_slice(&buf[..taken]);
        if ends_line {
            this.pending = Some(Output(Bytes::from(std::mem::take(&mut this.partial))));
            // Sent now if it fits; otherwise the next write or flush waits.
            if let Poll::Ready(Err(error)) = this.poll_pending(cx) {
                return Poll::Ready(Err(error));
            }
        }
        Poll::Ready(Ok(taken))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_pending(cx))?;
        if !this.partial.is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "flushed output that ends no line",
            )));
        }
        this.link.poll_written_out(cx).map_err(io::Error::from)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
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

    /// Say how the writer to the client socket failed, before this end goes:
    /// a core end waiting on it ends as a write to the socket would have.
    pub fn writer_failed(&self, failure: SendFailure) {
        self.shared.writer_failure.get_or_init(|| failure);
    }

    /// The close frame the core's `End` carried, once it has ended the
    /// session with one ([`SessionLink::close_on_end`]).
    pub fn close_frame(&self) -> Option<CloseFrame> {
        self.shared.close.get().copied()
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

/// The edge's end going is seen by a core end waiting on it, which is woken
/// if it asked.
impl Drop for EdgeSession {
    fn drop(&mut self) {
        self.shared.edge_gone.store(true, Ordering::SeqCst);
        if self.shared.written.advance(0)
            && let Some(wake) = self.shared.drained_wake.get()
        {
            wake.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A waiting session's core end is backpressured, never refused: a line
    /// over the bound waits until the edge reports enough written, and then
    /// goes.
    #[tokio::test]
    async fn a_waiting_session_waits_for_room_instead_of_refusing() {
        let (mut core, mut edge) = waiting_session("t", 100);
        let mut first = Some(line(80));
        std::future::poll_fn(|cx| core.poll_output(cx, &mut first))
            .await
            .expect("room");
        let sender = tokio::spawn(async move {
            let mut second = Some(line(80));
            std::future::poll_fn(|cx| core.poll_output(cx, &mut second))
                .await
                .expect("room once the first is written");
            core
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(!sender.is_finished(), "no room yet: it waits");
        let taken = edge.try_take().expect("the first line");
        edge.written(weight(&taken.payload));
        let core = sender.await.expect("sender");
        assert_eq!(core.in_flight(), 80);
    }

    /// Delivering waits until the line is on the socket, as a write to it
    /// returned; an edge that goes ends the wait with how its writer failed.
    #[tokio::test]
    async fn delivery_waits_for_the_socket_and_ends_with_the_edge() {
        let (mut core, mut edge) = waiting_session("t", 100);
        let writer = tokio::spawn(async move {
            let taken = edge.take().await.expect("the line");
            edge.written(weight(&taken.payload));
            edge
        });
        core.deliver(line(10)).await.expect("written");
        assert_eq!(core.in_flight(), 0);
        let edge = writer.await.expect("writer");
        let waiting = tokio::spawn(async move { core.deliver(line(10)).await });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        edge.writer_failed(SendFailure::Stalled);
        drop(edge);
        let ended = waiting.await.expect("waiter");
        assert_eq!(ended, Err(EdgeEnded(Some(SendFailure::Stalled))));
        assert!(crate::peer_write::is_stalled(&io::Error::from(
            ended.expect_err("ended")
        )));
    }

    #[test]
    fn a_close_frame_rides_the_end() {
        let (core, edge) = waiting_session("t", 100);
        let frame = CloseFrame {
            code: 1008,
            reason: "policy",
        };
        core.close_on_end(frame);
        drop(core);
        assert_eq!(edge.close_frame(), Some(frame));
    }

    /// The line writer sends each line once its line feed is written, and a
    /// flush returns once every line is on the socket; bytes that end no
    /// line are the writer's error at a flush, never sent.
    #[tokio::test]
    async fn the_line_writer_sends_whole_lines_and_flushes_to_the_socket() {
        use tokio::io::AsyncWriteExt;
        let (core, mut edge) = waiting_session("t", 1024);
        let mut writer = LineWriter::new(core);
        let reader = tokio::spawn(async move {
            let mut lines = Vec::new();
            while let Some(envelope) = edge.take().await {
                edge.written(weight(&envelope.payload));
                lines.push(envelope.payload.0);
            }
            lines
        });
        writer.write_all(b"NOTICE * :one").await.expect("write");
        writer
            .write_all(b"\r\nNOTICE * :two\r\n")
            .await
            .expect("write");
        writer.flush().await.expect("flushed onto the socket");
        writer.write_all(b"half a line").await.expect("write");
        let refused = writer.flush().await.expect_err("an unterminated line");
        assert_eq!(refused.kind(), io::ErrorKind::InvalidData);
        drop(writer);
        assert_eq!(
            reader.await.expect("reader"),
            [
                Bytes::from_static(b"NOTICE * :one\r\n"),
                Bytes::from_static(b"NOTICE * :two\r\n")
            ]
        );
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
