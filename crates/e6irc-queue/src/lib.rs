//! Bounded MPSC queue: the only inter-subsystem communication primitive
//! in e6ircd (DESIGN §7.3). Built in-repo — instead of a channel crate —
//! so it can be step-scheduled in deterministic tests, traced, and
//! model-checked with loom.
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

use std::collections::VecDeque;
use std::future::poll_fn;
use std::task::{Context, Poll, Waker};

#[cfg(loom)]
use loom::sync::{Arc, Mutex};
#[cfg(not(loom))]
use std::sync::{Arc, Mutex};

/// Static configuration of one queue.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Name for traces and metrics.
    pub name: &'static str,
    /// Maximum number of buffered events; `try_push` fails beyond it.
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
pub enum Mode {
    Fifo,
    Lifo,
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

/// Create a queue. Panics on nonsensical configuration (zero capacity,
/// watermarks out of order or beyond capacity) — misconfiguration is a
/// programmer error and fails loudly at construction.
pub fn queue<T>(config: Config) -> (Sender<T>, Receiver<T>) {
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
        state: Mutex::new(State {
            buf: VecDeque::with_capacity(config.capacity),
            next_seq: 0,
            mode: Mode::Fifo,
            mode_switches: 0,
            sender_count: 1,
            receiver_alive: true,
            waker: None,
            push_wakers: Vec::new(),
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
    state: Mutex<State<T>>,
}

struct State<T> {
    buf: VecDeque<Envelope<T>>,
    next_seq: u64,
    mode: Mode,
    mode_switches: u64,
    sender_count: usize,
    receiver_alive: bool,
    waker: Option<Waker>,
    /// Producers parked in an async `push` awaiting a free slot.
    push_wakers: Vec<Waker>,
}

impl<T> State<T> {
    fn update_mode(&mut self, policy: Policy) {
        let Policy::AdaptiveLifo {
            high_watermark,
            low_watermark,
        } = policy
        else {
            return;
        };
        match self.mode {
            Mode::Fifo if self.buf.len() >= high_watermark => {
                self.mode = Mode::Lifo;
                self.mode_switches += 1;
            }
            Mode::Lifo if self.buf.len() <= low_watermark => {
                self.mode = Mode::Fifo;
                self.mode_switches += 1;
            }
            _ => {}
        }
    }
}

impl<T> Shared<T> {
    fn lock(&self) -> impl std::ops::DerefMut<Target = State<T>> + '_ {
        self.state.lock().expect("queue mutex poisoned")
    }
}

impl<T> Sender<T> {
    /// Push an event. Returns its sequence number, or the event back
    /// inside the error on a full or closed queue.
    pub fn try_push(&self, payload: T) -> Result<u64, PushError<T>> {
        let waker;
        let seq;
        {
            let mut state = self.shared.lock();
            if !state.receiver_alive {
                return Err(PushError::Closed(payload));
            }
            if state.buf.len() == self.shared.config.capacity {
                return Err(PushError::Full(payload));
            }
            seq = state.next_seq;
            state.next_seq += 1;
            state.buf.push_back(Envelope { seq, payload });
            state.update_mode(self.shared.config.policy);
            waker = state.waker.take();
        }
        if let Some(waker) = waker {
            waker.wake();
        }
        Ok(seq)
    }

    pub fn depth(&self) -> usize {
        self.shared.lock().buf.len()
    }

    /// Await capacity, then push. `Err(payload)` if the receiver is
    /// gone — the event still comes back, never silently lost. This is
    /// the backpressure primitive: a connection reader that awaits here
    /// simply stops reading its socket until the consumer catches up.
    pub async fn push(&self, payload: T) -> Result<u64, T> {
        let mut payload = Some(payload);
        poll_fn(move |cx| {
            match self.try_push(payload.take().expect("polled after ready")) {
                Ok(seq) => Poll::Ready(Ok(seq)),
                Err(PushError::Closed(p)) => Poll::Ready(Err(p)),
                Err(PushError::Full(p)) => {
                    payload = Some(p);
                    self.shared.lock().push_wakers.push(cx.waker().clone());
                    // Re-check: a pop may have raced our registration.
                    match self.try_push(payload.take().expect("just stored")) {
                        Ok(seq) => Poll::Ready(Ok(seq)),
                        Err(PushError::Closed(p)) => Poll::Ready(Err(p)),
                        Err(PushError::Full(p)) => {
                            payload = Some(p);
                            Poll::Pending
                        }
                    }
                }
            }
        })
        .await
    }
}

impl<T> Receiver<T> {
    /// Non-blocking pop; also the primitive a deterministic stepper
    /// drives. `None` means "currently empty", not "closed".
    pub fn try_pop(&mut self) -> Option<Envelope<T>> {
        let (env, wakers);
        {
            let mut state = self.shared.lock();
            env = match state.mode {
                Mode::Fifo => state.buf.pop_front(),
                Mode::Lifo => state.buf.pop_back(),
            }?;
            state.update_mode(self.shared.config.policy);
            wakers = std::mem::take(&mut state.push_wakers);
        }
        for w in wakers {
            w.wake();
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
            popped = match state.mode {
                Mode::Fifo => state.buf.pop_front(),
                Mode::Lifo => state.buf.pop_back(),
            };
            match popped {
                Some(_) => {
                    state.update_mode(self.shared.config.policy);
                    wakers = std::mem::take(&mut state.push_wakers);
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
        for w in wakers {
            w.wake();
        }
        Poll::Ready(popped)
    }

    pub fn depth(&self) -> usize {
        self.shared.lock().buf.len()
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
        for w in wakers {
            w.wake();
        }
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
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
        assert_eq!(rx.mode(), Mode::Fifo);
        tx.try_push(7).unwrap(); // depth hits high watermark
        assert_eq!(rx.mode(), Mode::Lifo);
        assert_eq!(rx.mode_switches(), 1);

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

    #[test]
    #[should_panic]
    fn zero_capacity_is_a_loud_construction_error() {
        let _ = fifo(0);
    }

    #[test]
    #[should_panic]
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

    /// The async backpressure path — parked-waker registration with the
    /// post-registration re-check in `push`, and `pop`'s waker slot — under
    /// contention: two senders block on a full capacity-1 queue while the
    /// receiver pops both. A lost wakeup (a pop racing between a pusher's
    /// registration and its re-check, or vice versa) parks a task forever,
    /// which loom surfaces as a deadlocked branch; delivery stays
    /// exactly-once. The try_push/try_pop model below can't see this: the
    /// waker protocol only runs in the async path.
    #[test]
    fn async_push_pop_wakers_lose_no_wakeup_under_all_interleavings() {
        // Bounded exploration: three threads of async machinery explode the
        // unbounded state space past any CI budget. A preemption bound of 2
        // is loom's own recommended setting — most real bugs (including lost
        // wakeups, which need exactly one preemption between registration and
        // re-check) surface within it.
        let mut model = loom::model::Builder::new();
        model.preemption_bound = Some(2);
        model.check(|| {
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
