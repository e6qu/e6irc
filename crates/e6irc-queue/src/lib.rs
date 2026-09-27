//! Bounded MPSC queue used by the core, database worker, SendQs, WebSocket
//! output, and local driver (DESIGN §7.3). The driver/attach layer also uses
//! bounded tokio channels. This queue is built in-repo so it has an explicit
//! manual-pop primitive for deterministic tests and can be model-checked with
//! loom. A whole-core scheduler/trace-replay layer is a design target, not
//! part of this crate today.
//!
//! Guarantees:
//! - **Delivered or returned**: `try_push` never loses an event; on a
//!   full or closed queue the event comes back to the producer.
//! - **Per-queue total order**: every accepted event gets a monotonic
//!   sequence number assigned in push order.
//! - **FIFO by default**; queues may opt into an adaptive degraded mode
//!   that dequeues LIFO above a high watermark (freshest-first under
//!   overload) and returns to FIFO below a low watermark. Mode changes
//!   are observable, never silent.
//! - **Bounded by weight**: a queue built with [`weighted_queue`] bounds the
//!   sum of its events' weights (a SendQ, its lines' bytes) rather than their
//!   number; [`queue`] weighs every event 1. Depth, capacity, the watermarks
//!   and every admission decision are in that one unit, so a queue cannot be
//!   bounded in one unit and reported or paced in another.

use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

#[cfg(loom)]
use loom::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
#[cfg(loom)]
use loom::sync::{Arc, Mutex};
#[cfg(not(loom))]
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
#[cfg(not(loom))]
use std::sync::{Arc, Mutex};

/// Static configuration of one queue.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Diagnostic name included in construction failures.
    pub name: &'static str,
    /// Most total weight buffered (events, for a [`queue`]); `try_push` fails
    /// beyond it.
    pub capacity: usize,
    pub policy: Policy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Strict FIFO — for queues whose ordering is semantic.
    Fifo,
    /// FIFO normally; LIFO while depth is at/above `high_watermark`,
    /// back to FIFO once depth drains to/below `low_watermark`.
    AdaptiveLifo {
        high_watermark: usize,
        low_watermark: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    Fifo,
    Lifo,
}

/// A point-in-time, payload-free view of a queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueSnapshot {
    pub name: &'static str,
    pub depth: usize,
    pub capacity: usize,
    pub mode: Mode,
    pub mode_switches: u64,
}

/// A clonable, payload-free handle for exporting bounded queue telemetry.
#[derive(Clone)]
pub struct QueueMonitor {
    name: &'static str,
    capacity: usize,
    metrics: Arc<QueueMetrics>,
}

struct QueueMetrics {
    enabled: AtomicBool,
    depth: AtomicUsize,
    mode: AtomicU8,
    mode_switches: AtomicU64,
}

impl QueueMonitor {
    pub fn snapshot(&self) -> QueueSnapshot {
        QueueSnapshot {
            name: self.name,
            depth: self.metrics.depth.load(Ordering::Relaxed),
            capacity: self.capacity,
            mode: if self.metrics.mode.load(Ordering::Relaxed) == Mode::Fifo as u8 {
                Mode::Fifo
            } else {
                Mode::Lifo
            },
            mode_switches: self.metrics.mode_switches.load(Ordering::Relaxed),
        }
    }
}

impl std::fmt::Debug for QueueMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueueMonitor")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

/// An accepted event with its per-queue identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope<T> {
    /// Monotonic per-queue sequence number, assigned in push order.
    pub seq: u64,
    pub payload: T,
}

/// The event always comes back on failure — no silent loss.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushError<T> {
    Full(T),
    Closed(T),
}

/// Create a queue whose capacity counts events. Panics on nonsensical
/// configuration (zero capacity, watermarks out of order or beyond capacity) —
/// misconfiguration is a programmer error and fails loudly at construction.
pub fn queue<T>(config: Config) -> (Sender<T>, Receiver<T>) {
    weighted_queue(config, |_| 1)
}

/// Create a queue whose capacity, depth and watermarks are in the unit `weigh`
/// measures each event in (at least 1 each, so no event is free). An event is
/// admitted while the total stays within capacity — or into an empty queue,
/// so an event heavier than the whole capacity is not unsendable, and the
/// queue holds at most `capacity` plus one event's weight. `weigh` is asked
/// once per event, when it is pushed.
pub fn weighted_queue<T>(config: Config, weigh: fn(&T) -> usize) -> (Sender<T>, Receiver<T>) {
    assert!(
        config.capacity > 0,
        "queue {:?}: capacity must be > 0",
        config.name
    );
    if let Policy::AdaptiveLifo {
        high_watermark,
        low_watermark,
    } = config.policy
    {
        assert!(
            low_watermark < high_watermark && high_watermark <= config.capacity,
            "queue {:?}: watermarks must satisfy low < high <= capacity",
            config.name,
        );
    }
    let shared = Arc::new(Shared {
        config,
        weigh,
        metrics: Arc::new(QueueMetrics {
            enabled: AtomicBool::new(false),
            depth: AtomicUsize::new(0),
            mode: AtomicU8::new(Mode::Fifo as u8),
            mode_switches: AtomicU64::new(0),
        }),
        state: Mutex::new(State {
            // `capacity` is an admission bound, not an allocation request.
            // SendQs use this queue per connection; eagerly reserving the
            // default 1,024 output envelopes here would consume gigabytes of
            // idle memory at the server's target connection count.
            buf: VecDeque::new(),
            load: 0,
            next_seq: 0,
            mode: Mode::Fifo,
            mode_switches: 0,
            sender_count: 1,
            receiver_alive: true,
            waker: None,
            push_wakers: VecDeque::new(),
            next_push_waiter: 0,
        }),
    });
    (
        Sender {
            shared: shared.clone(),
        },
        Receiver { shared },
    )
}

/// Producer handle; clonable (MPSC).
pub struct Sender<T> {
    shared: Arc<Shared<T>>,
}

/// Consumer handle; exactly one exists per queue.
pub struct Receiver<T> {
    shared: Arc<Shared<T>>,
}

struct Shared<T> {
    config: Config,
    weigh: fn(&T) -> usize,
    metrics: Arc<QueueMetrics>,
    state: Mutex<State<T>>,
}

struct State<T> {
    /// Each event with the weight it was admitted at.
    buf: VecDeque<(Envelope<T>, usize)>,
    /// The sum of `buf`'s weights: the queue's depth.
    load: usize,
    next_seq: u64,
    mode: Mode,
    mode_switches: u64,
    sender_count: usize,
    receiver_alive: bool,
    waker: Option<Waker>,
    /// Producers parked in an async `push` or `room_for`, in arrival order,
    /// each awaiting room for its event's weight.
    push_wakers: VecDeque<PushWaiter>,
    next_push_waiter: u64,
}

/// One parked producer: its place in line, the weight it waits to fit, and
/// how to wake it.
struct PushWaiter {
    id: u64,
    weight: usize,
    waker: Waker,
}

/// The one admission rule: an event of `weight` fits a queue holding `load`
/// when the total stays within `capacity`, or when the queue is empty (see
/// [`weighted_queue`]).
fn fits(load: usize, weight: usize, capacity: usize) -> bool {
    load == 0 || load.saturating_add(weight) <= capacity
}

impl<T> State<T> {
    fn next_sequence(&mut self) -> u64 {
        let sequence = self.next_seq;
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .expect("queue sequence identity exhausted");
        sequence
    }

    /// Whether an event of `weight` fits now: within capacity, or into an
    /// empty queue (see [`weighted_queue`]).
    fn admits(&self, weight: usize, capacity: usize) -> bool {
        fits(self.load, weight, capacity)
    }

    /// Take, from the front of the line, every parked producer whose event
    /// fits once the ones ahead of it have pushed theirs — the same
    /// [`State::admits`] rule, applied as if each woken producer had already
    /// pushed. The line stays FIFO: a producer whose event does not fit
    /// blocks the ones behind it, so a stream of light events cannot starve a
    /// heavy one. A pop that frees too little for the front producer wakes
    /// nobody (waking it would only have it find the queue still full).
    fn take_admitted_waiters(&mut self, capacity: usize) -> Vec<Waker> {
        let mut load = self.load;
        let mut admitted = 0;
        for waiter in &self.push_wakers {
            if !fits(load, waiter.weight, capacity) {
                break;
            }
            load = load.saturating_add(waiter.weight);
            admitted += 1;
        }
        self.push_wakers
            .drain(..admitted)
            .map(|waiter| waiter.waker)
            .collect()
    }

    fn enqueue(&mut self, envelope: Envelope<T>, weight: usize) {
        self.load += weight;
        self.buf.push_back((envelope, weight));
    }

    fn dequeue(&mut self) -> Option<Envelope<T>> {
        let (envelope, weight) = match self.mode {
            Mode::Fifo => self.buf.pop_front(),
            Mode::Lifo => self.buf.pop_back(),
        }?;
        self.load -= weight;
        Some(envelope)
    }

    fn update_mode(&mut self, policy: Policy) {
        let Policy::AdaptiveLifo {
            high_watermark,
            low_watermark,
        } = policy
        else {
            return;
        };
        match self.mode {
            Mode::Fifo if self.load >= high_watermark => {
                self.mode = Mode::Lifo;
                self.mode_switches += 1;
            }
            Mode::Lifo if self.load <= low_watermark => {
                self.mode = Mode::Fifo;
                self.mode_switches += 1;
            }
            _ => {}
        }
    }
}

impl<T> Shared<T> {
    fn weight_of(&self, payload: &T) -> usize {
        (self.weigh)(payload).max(1)
    }

    fn lock(&self) -> impl std::ops::DerefMut<Target = State<T>> + '_ {
        self.state.lock().expect("queue mutex poisoned")
    }

    fn publish(&self, state: &State<T>) {
        if !self.metrics.enabled.load(Ordering::Acquire) {
            return;
        }
        self.publish_unconditionally(state);
    }

    fn publish_unconditionally(&self, state: &State<T>) {
        self.metrics.depth.store(state.load, Ordering::Relaxed);
        self.metrics.mode.store(state.mode as u8, Ordering::Relaxed);
        self.metrics
            .mode_switches
            .store(state.mode_switches, Ordering::Relaxed);
    }
}

impl<T> Sender<T> {
    /// Push an event. Returns its sequence number, or the event back
    /// inside the error on a full or closed queue.
    pub fn try_push(&self, payload: T) -> Result<u64, PushError<T>> {
        let waker;
        let seq;
        let weight = self.shared.weight_of(&payload);
        {
            let mut state = self.shared.lock();
            if !state.receiver_alive {
                return Err(PushError::Closed(payload));
            }
            if !state.admits(weight, self.shared.config.capacity) {
                return Err(PushError::Full(payload));
            }
            seq = state.next_sequence();
            state.enqueue(Envelope { seq, payload }, weight);
            state.update_mode(self.shared.config.policy);
            self.shared.publish(&state);
            waker = state.waker.take();
        }
        if let Some(waker) = waker {
            waker.wake();
        }
        Ok(seq)
    }

    /// The total weight buffered (events, for a [`queue`]).
    pub fn depth(&self) -> usize {
        self.shared.lock().load
    }

    /// The most weight the queue buffers ([`Config::capacity`]).
    pub fn capacity(&self) -> usize {
        self.shared.config.capacity
    }

    pub fn monitor(&self) -> QueueMonitor {
        let state = self.shared.lock();
        self.shared.publish_unconditionally(&state);
        self.shared.metrics.enabled.store(true, Ordering::Release);
        QueueMonitor {
            name: self.shared.config.name,
            capacity: self.shared.config.capacity,
            metrics: self.shared.metrics.clone(),
        }
    }

    /// Await capacity, then push. `Err(payload)` if the receiver is
    /// gone — the event still comes back, never silently lost. This is
    /// the backpressure primitive: a connection reader that awaits here
    /// simply stops reading its socket until the consumer catches up.
    pub fn push(&self, payload: T) -> Push<'_, T> {
        Push {
            parked: ParkedProducer::new(self, self.shared.weight_of(&payload)),
            payload: Some(payload),
        }
    }

    /// Await the moment the queue has room for `pending` (or its receiver is
    /// gone), without committing it to the wait. For a producer that must keep
    /// doing other work while it waits — it holds its events itself, selects on
    /// this beside its other duties, and offers `pending` with
    /// [`Sender::try_push`] once it resolves. Room is judged by the same
    /// admission rule `try_push` applies to `pending`'s weight, so on a
    /// weighted queue it does not resolve for room a heavier event cannot use.
    /// Room seen is not room held: another producer may take it first, and the
    /// `try_push` then says so.
    pub fn room_for(&self, pending: &T) -> Room<'_, T> {
        Room {
            parked: ParkedProducer::new(self, self.shared.weight_of(pending)),
        }
    }
}

/// One producer's place in a full queue's FIFO line of waiters, waiting for
/// room for `weight`.
///
/// Dropping it while still in line leaves the line, so a cancelled producer
/// cannot consume a later wakeup and leave a live producer parked. Dropping it
/// after a pop already chose it — the room it was woken for will not be used
/// by it — offers that room to the line again, for the same reason.
struct ParkedProducer<'a, T> {
    sender: &'a Sender<T>,
    weight: usize,
    waiter: Option<u64>,
}

impl<'a, T> ParkedProducer<'a, T> {
    fn new(sender: &'a Sender<T>, weight: usize) -> Self {
        Self {
            sender,
            weight,
            waiter: None,
        }
    }

    /// Whether this producer's event fits now.
    fn admitted(&self, state: &State<T>) -> bool {
        state.admits(self.weight, self.sender.shared.config.capacity)
    }

    /// Join the line (once), or refresh the waker already in it.
    fn park(&mut self, state: &mut State<T>, cx: &Context<'_>) {
        let waiter = match self.waiter {
            Some(waiter) => waiter,
            None => {
                let waiter = state.next_push_waiter;
                state.next_push_waiter = state
                    .next_push_waiter
                    .checked_add(1)
                    .expect("queue push-waiter identity exhausted");
                self.waiter = Some(waiter);
                waiter
            }
        };
        match state
            .push_wakers
            .iter_mut()
            .find(|candidate| candidate.id == waiter)
        {
            Some(registered) => registered.waker.clone_from(cx.waker()),
            None => state.push_wakers.push_back(PushWaiter {
                id: waiter,
                weight: self.weight,
                waker: cx.waker().clone(),
            }),
        }
    }

    /// The wait is over: this producer got what it was in line for.
    fn served(&mut self, state: &mut State<T>) {
        remove_push_waiter(state, self.waiter.take());
    }
}

impl<T> Drop for ParkedProducer<'_, T> {
    fn drop(&mut self) {
        let Some(waiter) = self.waiter.take() else {
            return;
        };
        let next;
        {
            let mut state = self.sender.shared.lock();
            let still_parked = remove_push_waiter(&mut state, Some(waiter));
            // Parked once and no longer listed: a pop took this registration
            // and counted this producer's event against the room it freed. It
            // will never use that room, so the line must be offered it again —
            // nothing else wakes the next producer while the consumer waits on
            // an empty queue.
            next = if still_parked {
                Vec::new()
            } else {
                state.take_admitted_waiters(self.sender.shared.config.capacity)
            };
        }
        for waker in next {
            waker.wake();
        }
    }
}

/// A cancellation-safe asynchronous queue push.
///
/// A full queue registers this future once in FIFO waiter order; see
/// [`ParkedProducer`] for what dropping it does.
pub struct Push<'a, T> {
    parked: ParkedProducer<'a, T>,
    payload: Option<T>,
}

impl<T> Unpin for Push<'_, T> {}

impl<T> Future for Push<'_, T> {
    type Output = Result<u64, T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let sender = this.parked.sender;
        let mut receiver_waker = None;
        let result;
        {
            let mut state = sender.shared.lock();
            if !state.receiver_alive {
                this.parked.served(&mut state);
                return Poll::Ready(Err(this
                    .payload
                    .take()
                    .expect("push future polled after ready")));
            }
            if this.parked.admitted(&state) {
                this.parked.served(&mut state);
                let seq = state.next_sequence();
                let payload = this.payload.take().expect("push future polled after ready");
                state.enqueue(Envelope { seq, payload }, this.parked.weight);
                state.update_mode(sender.shared.config.policy);
                sender.shared.publish(&state);
                receiver_waker = state.waker.take();
                result = Poll::Ready(Ok(seq));
            } else {
                this.parked.park(&mut state, cx);
                result = Poll::Pending;
            }
        }
        if let Some(waker) = receiver_waker {
            waker.wake();
        }
        result
    }
}

/// Resolves once the queue has room for the pending event or its receiver is
/// gone; see [`Sender::room_for`].
pub struct Room<'a, T> {
    parked: ParkedProducer<'a, T>,
}

impl<T> Future for Room<'_, T> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        let sender = this.parked.sender;
        let mut state = sender.shared.lock();
        if !state.receiver_alive || this.parked.admitted(&state) {
            this.parked.served(&mut state);
            Poll::Ready(())
        } else {
            this.parked.park(&mut state, cx);
            Poll::Pending
        }
    }
}

/// Remove `waiter`'s registration; whether it was still registered.
fn remove_push_waiter<T>(state: &mut State<T>, waiter: Option<u64>) -> bool {
    let Some(waiter) = waiter else {
        return false;
    };
    let parked = state.push_wakers.len();
    state.push_wakers.retain(|candidate| candidate.id != waiter);
    state.push_wakers.len() != parked
}

impl<T> Receiver<T> {
    /// Non-blocking pop; also the primitive a deterministic stepper
    /// drives. `None` means "currently empty", not "closed".
    pub fn try_pop(&mut self) -> Option<Envelope<T>> {
        let (env, wakers);
        {
            let mut state = self.shared.lock();
            env = state.dequeue()?;
            state.update_mode(self.shared.config.policy);
            self.shared.publish(&state);
            wakers = state.take_admitted_waiters(self.shared.config.capacity);
        }
        for waker in wakers {
            waker.wake();
        }
        Some(env)
    }

    /// Await the next event; resolves to `None` once every `Sender` is
    /// dropped and the buffer is drained.
    pub async fn pop(&mut self) -> Option<Envelope<T>> {
        poll_fn(|cx| self.poll_pop(cx)).await
    }

    fn poll_pop(&mut self, cx: &mut Context<'_>) -> Poll<Option<Envelope<T>>> {
        let (popped, wakers);
        {
            let mut state = self.shared.lock();
            popped = state.dequeue();
            match popped {
                Some(_) => {
                    state.update_mode(self.shared.config.policy);
                    self.shared.publish(&state);
                    wakers = state.take_admitted_waiters(self.shared.config.capacity);
                }
                None => {
                    if state.sender_count == 0 {
                        return Poll::Ready(None);
                    }
                    state.waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
            }
        }
        for waker in wakers {
            waker.wake();
        }
        Poll::Ready(popped)
    }

    /// The total weight buffered (events, for a [`queue`]).
    pub fn depth(&self) -> usize {
        self.shared.lock().load
    }

    pub fn mode(&self) -> Mode {
        self.shared.lock().mode
    }

    /// Number of FIFO<->LIFO transitions so far (observability: a mode
    /// change is never silent).
    pub fn mode_switches(&self) -> u64 {
        self.shared.lock().mode_switches
    }
}

impl<T> std::fmt::Debug for Sender<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sender")
            .field("queue", &self.shared.config.name)
            .finish()
    }
}

impl<T> std::fmt::Debug for Receiver<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Receiver")
            .field("queue", &self.shared.config.name)
            .finish()
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        self.shared.lock().sender_count += 1;
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let waker;
        {
            let mut state = self.shared.lock();
            state.sender_count -= 1;
            if state.sender_count > 0 {
                return;
            }
            // Last sender gone: wake the receiver so a pending pop can
            // resolve to None once the buffer drains.
            waker = state.waker.take();
        }
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let wakers;
        {
            let mut state = self.shared.lock();
            state.receiver_alive = false;
            // Parked pushes must observe the close and get their
            // payloads back.
            wakers = std::mem::take(&mut state.push_wakers);
        }
        for waiter in wakers {
            waiter.waker.wake();
        }
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    #[test]
    fn construction_does_not_preallocate_the_admission_limit() {
        let (sender, _receiver) = queue::<[u8; 128]>(Config {
            name: "lazy-allocation",
            capacity: 65_536,
            policy: Policy::Fifo,
        });
        assert_eq!(
            sender.shared.lock().buf.capacity(),
            0,
            "a queue bound must not become an eager per-queue allocation"
        );
    }
    use std::future::Future;
    use std::pin::pin;
    use std::sync::Arc as StdArc;
    use std::task::Wake;
    use std::thread;
    use std::time::Duration;

    fn fifo(capacity: usize) -> (Sender<u32>, Receiver<u32>) {
        queue(Config {
            name: "test",
            capacity,
            policy: Policy::Fifo,
        })
    }

    struct ThreadWaker(thread::Thread);
    impl Wake for ThreadWaker {
        fn wake(self: StdArc<Self>) {
            self.0.unpark();
        }
    }

    fn block_on<F: Future>(fut: F) -> F::Output {
        let mut fut = pin!(fut);
        let waker = Waker::from(StdArc::new(ThreadWaker(thread::current())));
        let mut cx = Context::from_waker(&waker);
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => thread::park(),
            }
        }
    }

    #[test]
    fn fifo_order_with_monotonic_seq() {
        let (tx, mut rx) = fifo(8);
        for i in 0..5u32 {
            assert_eq!(tx.try_push(i).unwrap(), u64::from(i));
        }
        for i in 0..5u32 {
            let env = rx.try_pop().unwrap();
            assert_eq!(env.payload, i);
            assert_eq!(env.seq, u64::from(i));
        }
        assert_eq!(rx.try_pop(), None);
    }

    #[test]
    fn full_queue_returns_the_event() {
        let (tx, mut rx) = fifo(2);
        tx.try_push(1).unwrap();
        tx.try_push(2).unwrap();
        assert_eq!(tx.try_push(3), Err(PushError::Full(3)));
        assert_eq!(rx.try_pop().unwrap().payload, 1);
        // space freed: push succeeds again, seq keeps counting
        assert_eq!(tx.try_push(3).unwrap(), 2);
    }

    /// A weighted queue is bounded by the sum of its events' weights, not
    /// their number: two heavy events fill what a hundred light ones would
    /// not, and depth reports the same unit the bound is in.
    #[test]
    fn a_weighted_queue_is_bounded_by_weight_not_count() {
        let (tx, mut rx) = weighted_queue::<Vec<u8>>(
            Config {
                name: "bytes",
                capacity: 100,
                policy: Policy::Fifo,
            },
            Vec::len,
        );
        tx.try_push(vec![0; 60]).unwrap();
        assert_eq!(tx.depth(), 60);
        assert_eq!(
            tx.try_push(vec![0; 41]),
            Err(PushError::Full(vec![0; 41])),
            "60 + 41 bytes exceed a 100-byte queue"
        );
        tx.try_push(vec![0; 40]).unwrap();
        assert_eq!(rx.depth(), 100);
        assert_eq!(rx.try_pop().unwrap().payload.len(), 60);
        assert_eq!(tx.depth(), 40);
        // An empty event still weighs something, so a flood of them is bounded.
        for _ in 0..60 {
            tx.try_push(Vec::new()).unwrap();
        }
        assert!(matches!(tx.try_push(Vec::new()), Err(PushError::Full(_))));
    }

    /// An event heavier than the whole capacity is admitted into an empty
    /// queue — otherwise it could never be sent — and nowhere else.
    #[test]
    fn an_event_heavier_than_the_capacity_enters_only_an_empty_queue() {
        let (tx, mut rx) = weighted_queue::<Vec<u8>>(
            Config {
                name: "bytes",
                capacity: 10,
                policy: Policy::Fifo,
            },
            Vec::len,
        );
        tx.try_push(vec![0; 25]).unwrap();
        assert!(matches!(tx.try_push(vec![0; 1]), Err(PushError::Full(_))));
        rx.try_pop().unwrap();
        assert_eq!(tx.depth(), 0);
        tx.try_push(vec![0; 1]).unwrap();
        assert!(matches!(tx.try_push(vec![0; 25]), Err(PushError::Full(_))));
    }

    #[test]
    fn adaptive_lifo_flips_with_hysteresis() {
        let (tx, mut rx) = queue::<u32>(Config {
            name: "adaptive",
            capacity: 10,
            policy: Policy::AdaptiveLifo {
                high_watermark: 8,
                low_watermark: 2,
            },
        });
        for i in 0..7 {
            tx.try_push(i).unwrap();
        }
        let monitor = tx.monitor();
        assert_eq!(monitor.snapshot().depth, 7);
        assert_eq!(rx.mode(), Mode::Fifo);
        tx.try_push(7).unwrap(); // depth hits high watermark
        assert_eq!(rx.mode(), Mode::Lifo);
        assert_eq!(rx.mode_switches(), 1);
        assert_eq!(
            monitor.snapshot(),
            QueueSnapshot {
                name: "adaptive",
                depth: 8,
                capacity: 10,
                mode: Mode::Lifo,
                mode_switches: 1,
            }
        );

        // LIFO: freshest first
        assert_eq!(rx.try_pop().unwrap().payload, 7);
        assert_eq!(rx.try_pop().unwrap().payload, 6);
        // a push while degraded is served before older backlog
        tx.try_push(100).unwrap();
        assert_eq!(rx.try_pop().unwrap().payload, 100);

        // drain LIFO until depth reaches the low watermark (6→2): mode restores
        for expected in [5, 4, 3, 2] {
            assert_eq!(rx.try_pop().unwrap().payload, expected);
        }
        assert_eq!(rx.mode(), Mode::Fifo);
        assert_eq!(rx.mode_switches(), 2);
        assert_eq!(monitor.snapshot().mode, Mode::Fifo);
        assert_eq!(monitor.snapshot().mode_switches, 2);

        // back in FIFO: oldest of the remainder first
        assert_eq!(rx.try_pop().unwrap().payload, 0);
        assert_eq!(rx.try_pop().unwrap().payload, 1);

        // between watermarks nothing flips
        for i in 0..7 {
            tx.try_push(200 + i).unwrap();
        }
        assert_eq!(rx.mode(), Mode::Fifo);
        assert_eq!(rx.mode_switches(), 2);
    }

    #[test]
    fn strict_fifo_never_flips() {
        let (tx, mut rx) = fifo(4);
        for i in 0..4 {
            tx.try_push(i).unwrap();
        }
        assert_eq!(rx.mode(), Mode::Fifo);
        assert_eq!(rx.mode_switches(), 0);
        assert_eq!(rx.try_pop().unwrap().payload, 0);
    }

    #[test]
    fn dropped_receiver_closes_queue() {
        let (tx, rx) = fifo(4);
        drop(rx);
        assert_eq!(tx.try_push(9), Err(PushError::Closed(9)));
    }

    #[test]
    fn dropped_senders_end_pop_after_drain() {
        let (tx, mut rx) = fifo(4);
        let tx2 = tx.clone();
        tx.try_push(1).unwrap();
        tx2.try_push(2).unwrap();
        drop(tx);
        drop(tx2);
        assert_eq!(block_on(rx.pop()).unwrap().payload, 1);
        assert_eq!(block_on(rx.pop()).unwrap().payload, 2);
        assert_eq!(block_on(rx.pop()), None);
    }

    #[test]
    fn pop_wakes_on_push() {
        let (tx, mut rx) = fifo(4);
        let pusher = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            tx.try_push(42).unwrap();
        });
        assert_eq!(block_on(rx.pop()).unwrap().payload, 42);
        pusher.join().unwrap();
    }

    #[test]
    fn concurrent_no_loss_no_duplication() {
        const PRODUCERS: u64 = 4;
        const PER_PRODUCER: u64 = 10_000;
        let (tx, mut rx) = queue::<u64>(Config {
            name: "stress",
            capacity: 512,
            policy: Policy::Fifo,
        });
        let handles: Vec<_> = (0..PRODUCERS)
            .map(|p| {
                let tx = tx.clone();
                thread::spawn(move || {
                    for i in 0..PER_PRODUCER {
                        let mut v = p * PER_PRODUCER + i;
                        loop {
                            match tx.try_push(v) {
                                Ok(_) => break,
                                Err(PushError::Full(back)) => {
                                    v = back;
                                    thread::yield_now();
                                }
                                Err(PushError::Closed(_)) => panic!("closed early"),
                            }
                        }
                    }
                })
            })
            .collect();
        drop(tx);

        let mut seen_values = vec![false; (PRODUCERS * PER_PRODUCER) as usize];
        let mut seen_seqs = vec![false; (PRODUCERS * PER_PRODUCER) as usize];
        while let Some(env) = block_on(rx.pop()) {
            let v = env.payload as usize;
            assert!(!seen_values[v], "value {v} delivered twice");
            seen_values[v] = true;
            let s = env.seq as usize;
            assert!(!seen_seqs[s], "seq {s} assigned twice");
            seen_seqs[s] = true;
        }
        for h in handles {
            h.join().unwrap();
        }
        assert!(seen_values.iter().all(|&b| b), "events lost");
        assert!(seen_seqs.iter().all(|&b| b), "seq gaps");
    }

    #[test]
    fn async_push_waits_for_space() {
        let (tx, mut rx) = fifo(2);
        tx.try_push(1).unwrap();
        tx.try_push(2).unwrap();
        let popper = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            assert_eq!(rx.try_pop().unwrap().payload, 1);
            rx // keep receiver alive
        });
        // full now; push must block until the popper frees a slot
        let seq = block_on(tx.push(3)).unwrap();
        assert_eq!(seq, 2);
        let mut rx = popper.join().unwrap();
        assert_eq!(rx.try_pop().unwrap().payload, 2);
        assert_eq!(rx.try_pop().unwrap().payload, 3);
    }

    #[test]
    fn async_push_returns_payload_when_receiver_drops() {
        let (tx, rx) = fifo(1);
        tx.try_push(1).unwrap();
        let dropper = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            drop(rx);
        });
        assert_eq!(block_on(tx.push(2)), Err(2));
        dropper.join().unwrap();
    }

    #[test]
    fn async_push_immediate_when_space() {
        let (tx, mut rx) = fifo(4);
        assert_eq!(block_on(tx.push(7)).unwrap(), 0);
        assert_eq!(rx.try_pop().unwrap().payload, 7);
    }

    struct CountWakes(std::sync::atomic::AtomicUsize);

    impl Wake for CountWakes {
        fn wake(self: StdArc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl CountWakes {
        fn count(&self) -> usize {
            self.0.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    /// A producer parked on a full queue, with a count of its wakeups.
    struct Parked<'a> {
        push: Pin<Box<Push<'a, u32>>>,
        wakes: StdArc<CountWakes>,
    }

    impl<'a> Parked<'a> {
        fn on(sender: &'a Sender<u32>, payload: u32) -> Self {
            let mut parked = Self {
                push: Box::pin(sender.push(payload)),
                wakes: StdArc::new(CountWakes(Default::default())),
            };
            assert!(parked.poll().is_pending(), "the queue is full");
            parked
        }

        fn poll(&mut self) -> Poll<Result<u64, u32>> {
            let waker = Waker::from(self.wakes.clone());
            self.push.as_mut().poll(&mut Context::from_waker(&waker))
        }
    }

    #[test]
    fn one_free_slot_wakes_one_live_producer_and_cancelled_waiters_leave() {
        let (tx, mut rx) = fifo(1);
        tx.try_push(0).unwrap();
        let cancelled = Parked::on(&tx, 1);
        let live = Parked::on(&tx, 2);
        let cancelled_wakes = cancelled.wakes.clone();

        drop(cancelled);
        assert_eq!(rx.try_pop().unwrap().payload, 0);
        assert_eq!(cancelled_wakes.count(), 0);
        assert_eq!(live.wakes.count(), 1);
    }

    /// The cancellation the test above misses: a producer dropped *after* the
    /// pop chose it. The pop already took its registration and spent the one
    /// wakeup on it, so dropping it then must pass the free slot on — otherwise
    /// the next producer stays parked beside an empty slot until some later
    /// pop, which on a queue the consumer has drained never comes.
    #[test]
    fn a_producer_dropped_after_its_wakeup_hands_the_slot_to_the_next() {
        let (tx, mut rx) = fifo(1);
        tx.try_push(0).unwrap();
        let woken_then_dropped = Parked::on(&tx, 1);
        let mut next = Parked::on(&tx, 2);

        assert_eq!(rx.try_pop().unwrap().payload, 0);
        assert_eq!(woken_then_dropped.wakes.count(), 1);
        assert_eq!(next.wakes.count(), 0);
        drop(woken_then_dropped);
        assert_eq!(
            next.wakes.count(),
            1,
            "the free slot was not offered to the next producer"
        );
        assert!(next.poll().is_ready());
        assert_eq!(rx.try_pop().unwrap().payload, 2);
    }

    struct CountedRoom<'a> {
        room: Pin<Box<Room<'a, u32>>>,
        wakes: StdArc<CountWakes>,
    }

    impl<'a> CountedRoom<'a> {
        fn on(sender: &'a Sender<u32>) -> Self {
            Self {
                room: Box::pin(sender.room_for(&0)),
                wakes: StdArc::new(CountWakes(Default::default())),
            }
        }

        fn poll(&mut self) -> Poll<()> {
            let waker = Waker::from(self.wakes.clone());
            self.room.as_mut().poll(&mut Context::from_waker(&waker))
        }
    }

    #[test]
    fn room_waits_for_a_pop_without_holding_a_payload() {
        let (tx, mut rx) = fifo(1);
        assert!(
            CountedRoom::on(&tx).poll().is_ready(),
            "an empty queue has room"
        );
        tx.try_push(0).unwrap();
        let mut waiting = CountedRoom::on(&tx);
        assert!(waiting.poll().is_pending());
        assert_eq!(rx.try_pop().unwrap().payload, 0);
        assert_eq!(waiting.wakes.count(), 1);
        assert!(waiting.poll().is_ready());
        // Room seen is not room held: the slot is still there to push into.
        tx.try_push(1).unwrap();
        assert_eq!(rx.try_pop().unwrap().payload, 1);
    }

    #[test]
    fn room_resolves_when_the_receiver_is_gone() {
        let (tx, rx) = fifo(1);
        tx.try_push(0).unwrap();
        let mut waiting = CountedRoom::on(&tx);
        assert!(waiting.poll().is_pending());
        drop(rx);
        assert_eq!(waiting.wakes.count(), 1);
        assert!(
            waiting.poll().is_ready(),
            "so the push can report the close"
        );
        assert!(matches!(tx.try_push(1), Err(PushError::Closed(1))));
    }

    #[test]
    fn a_room_waiter_dropped_after_its_wakeup_hands_the_slot_to_the_next() {
        let (tx, mut rx) = fifo(1);
        tx.try_push(0).unwrap();
        let mut woken_then_dropped = CountedRoom::on(&tx);
        assert!(woken_then_dropped.poll().is_pending());
        let mut next = Parked::on(&tx, 2);
        assert_eq!(rx.try_pop().unwrap().payload, 0);
        assert_eq!(next.wakes.count(), 0);
        drop(woken_then_dropped);
        assert_eq!(next.wakes.count(), 1);
        assert!(next.poll().is_ready());
    }

    fn bytes(capacity: usize) -> (Sender<Vec<u8>>, Receiver<Vec<u8>>) {
        weighted_queue(
            Config {
                name: "bytes",
                capacity,
                policy: Policy::Fifo,
            },
            Vec::len,
        )
    }

    /// Poll `future` once with a waker that counts its wakeups.
    fn poll_counting<F: Future>(
        future: Pin<&mut F>,
        wakes: &StdArc<CountWakes>,
    ) -> Poll<F::Output> {
        let waker = Waker::from(wakes.clone());
        future.poll(&mut Context::from_waker(&waker))
    }

    fn counter() -> StdArc<CountWakes> {
        StdArc::new(CountWakes(Default::default()))
    }

    /// Room is room for the pending event's weight, by the admission rule
    /// `try_push` applies — not "below capacity". Otherwise a producer holding
    /// a 41-byte event beside a 90-byte load sees room, is refused by
    /// `try_push`, and waits for room again: a busy spin.
    #[test]
    fn room_on_a_weighted_queue_waits_until_the_pending_event_fits() {
        let (tx, mut rx) = bytes(100);
        tx.try_push(vec![0; 60]).unwrap();
        tx.try_push(vec![0; 30]).unwrap();
        let pending = vec![0; 41];
        let wakes = counter();
        let mut room = Box::pin(tx.room_for(&pending));
        assert!(
            poll_counting(room.as_mut(), &wakes).is_pending(),
            "90 + 41 bytes do not fit a 100-byte queue"
        );
        assert_eq!(rx.try_pop().unwrap().payload.len(), 60);
        assert_eq!(wakes.count(), 1);
        assert!(poll_counting(room.as_mut(), &wakes).is_ready());
        tx.try_push(pending).unwrap();
    }

    /// A pop wakes, in line order, every parked producer whose event fits once
    /// those ahead of it have pushed — not exactly one regardless of how much
    /// it freed, which leaves producers parked beside room they could use.
    #[test]
    fn a_pop_wakes_every_parked_producer_whose_event_fits() {
        let (tx, mut rx) = bytes(10);
        tx.try_push(vec![0; 10]).unwrap();
        let mut parked: Vec<_> = [3, 3, 5]
            .into_iter()
            .map(|weight| (Box::pin(tx.push(vec![0; weight])), counter()))
            .collect();
        for (push, wakes) in &mut parked {
            assert!(poll_counting(push.as_mut(), wakes).is_pending());
        }
        rx.try_pop().unwrap();
        let woken: Vec<_> = parked.iter().map(|(_, wakes)| wakes.count()).collect();
        assert_eq!(woken, [1, 1, 0], "3 + 3 bytes fit; 3 + 3 + 5 do not");
        for (push, wakes) in &mut parked[..2] {
            assert!(poll_counting(push.as_mut(), wakes).is_ready());
        }
        assert_eq!(tx.depth(), 6);
    }

    /// The line is FIFO by weight too: a pop that frees too little for the
    /// front producer wakes nobody — not the front producer, who would only
    /// find the queue still full, and not a lighter one behind it, who would
    /// overtake it and could starve it indefinitely.
    #[test]
    fn a_pop_that_frees_too_little_for_the_front_producer_wakes_nobody() {
        let (tx, mut rx) = bytes(10);
        tx.try_push(vec![0; 5]).unwrap();
        tx.try_push(vec![0; 5]).unwrap();
        let (heavy_wakes, light_wakes) = (counter(), counter());
        let mut heavy = Box::pin(tx.push(vec![0; 8]));
        let mut light = Box::pin(tx.push(vec![0; 1]));
        assert!(poll_counting(heavy.as_mut(), &heavy_wakes).is_pending());
        assert!(poll_counting(light.as_mut(), &light_wakes).is_pending());
        rx.try_pop().unwrap();
        assert_eq!((heavy_wakes.count(), light_wakes.count()), (0, 0));
        // Emptied: 8 + 1 bytes fit, so both go, the heavy one first.
        rx.try_pop().unwrap();
        assert_eq!((heavy_wakes.count(), light_wakes.count()), (1, 1));
        assert!(poll_counting(heavy.as_mut(), &heavy_wakes).is_ready());
        assert!(poll_counting(light.as_mut(), &light_wakes).is_ready());
        assert_eq!(rx.try_pop().unwrap().payload.len(), 8);
    }

    /// The handoff when a woken producer is dropped unused is weight-aware
    /// too: the room it was counted against goes to every producer that now
    /// fits.
    #[test]
    fn a_weighted_producer_dropped_after_its_wakeup_hands_its_room_on() {
        let (tx, mut rx) = bytes(10);
        tx.try_push(vec![0; 10]).unwrap();
        let (dropped_wakes, first_wakes, second_wakes) = (counter(), counter(), counter());
        let mut dropped = Box::pin(tx.push(vec![0; 10]));
        let mut first = Box::pin(tx.push(vec![0; 4]));
        let mut second = Box::pin(tx.push(vec![0; 4]));
        assert!(poll_counting(dropped.as_mut(), &dropped_wakes).is_pending());
        assert!(poll_counting(first.as_mut(), &first_wakes).is_pending());
        assert!(poll_counting(second.as_mut(), &second_wakes).is_pending());
        rx.try_pop().unwrap();
        assert_eq!(dropped_wakes.count(), 1);
        assert_eq!((first_wakes.count(), second_wakes.count()), (0, 0));
        drop(dropped);
        assert_eq!((first_wakes.count(), second_wakes.count()), (1, 1));
    }

    #[test]
    #[should_panic(expected = "capacity must be > 0")]
    fn zero_capacity_is_a_loud_construction_error() {
        let _ = fifo(0);
    }

    #[test]
    #[should_panic(expected = "watermarks must satisfy low < high <= capacity")]
    fn inverted_watermarks_are_a_loud_construction_error() {
        let _ = queue::<u32>(Config {
            name: "bad",
            capacity: 10,
            policy: Policy::AdaptiveLifo {
                high_watermark: 2,
                low_watermark: 8,
            },
        });
    }
}

#[cfg(all(test, loom))]
mod loom_tests {
    use super::*;

    /// The async backpressure path — atomic parked-waker registration in
    /// `push`, and `pop`'s FIFO wake — under contention: two senders block on a
    /// full capacity-1 queue while the receiver pops both. A lost wakeup parks
    /// a task forever, which loom surfaces as a deadlocked branch; delivery
    /// stays exactly-once. The try_push/try_pop model below can't see this:
    /// the waker protocol only runs in the async path.
    #[test]
    fn async_push_pop_wakers_lose_no_wakeup_under_all_interleavings() {
        bounded_model(|| {
            let (tx, mut rx) = queue::<u32>(Config {
                name: "loom-async",
                capacity: 1,
                policy: Policy::Fifo,
            });
            let tx2 = tx.clone();
            let t1 = loom::thread::spawn(move || {
                loom::future::block_on(tx.push(1)).expect("receiver alive");
            });
            let t2 = loom::thread::spawn(move || {
                loom::future::block_on(tx2.push(2)).expect("receiver alive");
            });
            let mut got = Vec::new();
            for _ in 0..2 {
                let env = loom::future::block_on(rx.pop()).expect("two pushes in flight");
                got.push(env.payload);
            }
            t1.join().unwrap();
            t2.join().unwrap();
            got.sort_unstable();
            assert_eq!(got, vec![1, 2]);
        });
    }

    /// The cross-shard lane's way of producing — hold the event, wait for
    /// `room_for` it, offer it with `try_push` — under contention: two such producers
    /// share a capacity-1 queue. A lost wakeup parks one forever (a deadlocked
    /// branch in loom); losing the race for a slot must only mean waiting again.
    #[test]
    fn room_then_try_push_loses_no_wakeup_under_all_interleavings() {
        async fn offer(tx: Sender<u32>, mut payload: u32) {
            loop {
                match tx.try_push(payload) {
                    Ok(_) => return,
                    Err(PushError::Full(back)) => {
                        payload = back;
                        tx.room_for(&payload).await;
                    }
                    Err(PushError::Closed(_)) => panic!("receiver alive"),
                }
            }
        }
        bounded_model(|| {
            let (tx, mut rx) = queue::<u32>(Config {
                name: "loom-room",
                capacity: 1,
                policy: Policy::Fifo,
            });
            let tx2 = tx.clone();
            let t1 = loom::thread::spawn(move || loom::future::block_on(offer(tx, 1)));
            let t2 = loom::thread::spawn(move || loom::future::block_on(offer(tx2, 2)));
            let mut got = Vec::new();
            for _ in 0..2 {
                let env = loom::future::block_on(rx.pop()).expect("two offers in flight");
                got.push(env.payload);
            }
            t1.join().unwrap();
            t2.join().unwrap();
            got.sort_unstable();
            assert_eq!(got, vec![1, 2]);
        });
    }

    /// Bounded exploration: three threads of async machinery explode the
    /// unbounded state space past any CI budget. A preemption bound of 2 is
    /// loom's own recommended setting — most real bugs (including lost
    /// wakeups, which need exactly one preemption between registration and
    /// re-check) surface within it.
    fn bounded_model(body: impl Fn() + Sync + Send + 'static) {
        let mut model = loom::model::Builder::new();
        model.preemption_bound = Some(2);
        model.check(body);
    }

    /// The handoff in `ParkedProducer::drop`: a producer parks on a full queue
    /// and is then dropped, in every order relative to the pop that frees the
    /// slot. Dropped after that pop chose it, it must pass the wakeup on, or
    /// the other parked producer waits forever beside a drained queue — a
    /// deadlocked branch in loom.
    #[test]
    fn a_parked_producer_dropped_after_its_wakeup_loses_no_wakeup() {
        bounded_model(|| {
            let (tx, mut rx) = queue::<u32>(Config {
                name: "loom-handoff",
                capacity: 1,
                policy: Policy::Fifo,
            });
            tx.try_push(0).unwrap();
            let tx2 = tx.clone();
            let t1 = loom::thread::spawn(move || {
                let mut push = tx.push(1);
                let mut cx = Context::from_waker(Waker::noop());
                // Poll once, then give up: dropped while parked, or after.
                match Pin::new(&mut push).poll(&mut cx) {
                    Poll::Ready(result) => result.is_ok(),
                    Poll::Pending => false,
                }
            });
            let t2 = loom::thread::spawn(move || {
                loom::future::block_on(tx2.push(2)).expect("receiver alive");
            });
            let mut got = Vec::new();
            while !got.contains(&2) {
                let env = loom::future::block_on(rx.pop()).expect("a push in flight");
                got.push(env.payload);
            }
            let pushed_one = t1.join().unwrap();
            t2.join().unwrap();
            while let Some(env) = rx.try_pop() {
                got.push(env.payload);
            }
            got.sort_unstable();
            let expected = if pushed_one {
                vec![0, 1, 2]
            } else {
                vec![0, 2]
            };
            assert_eq!(got, expected);
        });
    }

    /// The receiver goes away while producers are parked on its full queue:
    /// every one of them is woken and gets its own payload back.
    #[test]
    fn a_dropped_receiver_returns_every_parked_payload() {
        bounded_model(|| {
            let (tx, rx) = queue::<u32>(Config {
                name: "loom-close",
                capacity: 1,
                policy: Policy::Fifo,
            });
            tx.try_push(0).unwrap();
            let tx2 = tx.clone();
            let t1 = loom::thread::spawn(move || loom::future::block_on(tx.push(1)));
            let t2 = loom::thread::spawn(move || loom::future::block_on(tx2.push(2)));
            drop(rx);
            assert_eq!(t1.join().unwrap(), Err(1));
            assert_eq!(t2.join().unwrap(), Err(2));
        });
    }

    /// The last sender goes away while the receiver is parked in `pop`: the
    /// pop drains what was pushed and then resolves to `None`, never waits on.
    #[test]
    fn a_parked_pop_resolves_to_none_when_the_last_sender_drops() {
        bounded_model(|| {
            let (tx, mut rx) = queue::<u32>(Config {
                name: "loom-senders-gone",
                capacity: 1,
                policy: Policy::Fifo,
            });
            let tx2 = tx.clone();
            let t1 = loom::thread::spawn(move || {
                tx.try_push(1).unwrap();
                drop(tx);
            });
            let t2 = loom::thread::spawn(move || drop(tx2));
            let first = loom::future::block_on(rx.pop()).map(|env| env.payload);
            assert_eq!(first, Some(1));
            assert_eq!(loom::future::block_on(rx.pop()), None);
            t1.join().unwrap();
            t2.join().unwrap();
        });
    }

    /// Two producers race one consumer: every accepted event is delivered
    /// exactly once with a unique seq, across all interleavings.
    #[test]
    fn exactly_once_delivery_under_all_interleavings() {
        loom::model(|| {
            let (tx, mut rx) = queue::<u32>(Config {
                name: "loom",
                capacity: 4,
                policy: Policy::Fifo,
            });
            let tx2 = tx.clone();
            let t1 = loom::thread::spawn(move || {
                tx.try_push(1).unwrap();
                tx.try_push(2).unwrap();
            });
            let t2 = loom::thread::spawn(move || {
                tx2.try_push(3).unwrap();
                tx2.try_push(4).unwrap();
            });
            t1.join().unwrap();
            t2.join().unwrap();

            let mut got = Vec::new();
            while let Some(env) = rx.try_pop() {
                got.push(env.payload);
            }
            got.sort_unstable();
            assert_eq!(got, vec![1, 2, 3, 4]);
        });
    }
}
