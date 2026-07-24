//! e6irc load harness: open many concurrent client connections, measure
//! connect+register throughput, then measure channel fan-out — one
//! sender bursts messages into a shared channel and every other client
//! counts deliveries. Reports connect rate and fan-out throughput.
//!
//! Usage:
//!   e6irc-load [--addr host:port] [--clients N] [--channel #c]
//!              [--burst K] [--tls]
//!
//! It exercises the exact paths the server's scale target stresses
//! (thousands of sessions, wide fan-out) without any test framework.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use e6irc_client::Connection;
use tokio::sync::Barrier;

struct Args {
    addr: String,
    clients: usize,
    /// Channel-name prefix; the actual channel is `{channel}{index}`.
    channel: String,
    /// Spread clients across this many channels (default 1). A realistic
    /// large deployment has many channels — one giant channel makes the
    /// join phase O(N²) (each join sends a NAMES list of all members) and
    /// masks true throughput.
    channels: usize,
    burst: usize,
    tls: bool,
}

impl Args {
    /// The channel a client belongs to.
    fn channel_of(&self, id: usize) -> String {
        format!("{}{}", self.channel, id % self.channels)
    }
    /// Clients `0..channels` are the per-channel senders.
    fn is_sender(&self, id: usize) -> bool {
        id < self.channels
    }
}

fn parse_args() -> Args {
    let mut args = Args {
        addr: "127.0.0.1:6667".to_string(),
        clients: 100,
        channel: "#load".to_string(),
        channels: 1,
        burst: 10,
        tls: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--addr" => args.addr = it.next().unwrap_or_else(|| die("--addr needs a value")),
            "--clients" => args.clients = parse_num(&it.next().unwrap_or_default(), "--clients"),
            "--channel" => {
                args.channel = it.next().unwrap_or_else(|| die("--channel needs a value"))
            }
            "--channels" => args.channels = parse_num(&it.next().unwrap_or_default(), "--channels"),
            "--burst" => args.burst = parse_num(&it.next().unwrap_or_default(), "--burst"),
            "--tls" => args.tls = true,
            other => die(&format!("unknown argument: {other}")),
        }
    }
    if args.channels < 1 {
        die("--channels must be at least 1");
    }
    // Each channel needs its sender plus at least one receiver.
    if args.clients <= args.channels {
        die("--clients must exceed --channels (each channel needs a sender + a receiver)");
    }
    args
}

fn parse_num(s: &str, flag: &str) -> usize {
    s.parse()
        .unwrap_or_else(|_| die(&format!("{flag} needs a number")))
}

fn die(msg: &str) -> ! {
    eprintln!("e6irc-load: {msg}");
    std::process::exit(2);
}

async fn connect(args: &Args) -> std::io::Result<Connection> {
    if args.tls {
        let name = args
            .addr
            .rsplit_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| args.addr.clone());
        Connection::connect_tls(&args.addr, &name, e6irc_client::webpki_root_store()).await
    } else {
        Connection::connect(&args.addr).await
    }
}

fn main() {
    let args = parse_args();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(run(args));
}

/// Shared timing/counters across the client tasks.
struct Metrics {
    /// Wall time (ms since `run_start`) when the last client finished
    /// connect+register+join.
    connect_max_ms: AtomicU64,
    /// Longest per-receiver fan-out duration (ms from barrier release to
    /// having counted its whole share).
    fanout_max_ms: AtomicU64,
    /// Total burst messages delivered across all receivers.
    received: AtomicU64,
    /// Send time (ns since `run_start`) of each burst message, indexed by
    /// its sequence number; the sender fills these as it emits.
    sent_ns: Vec<AtomicU64>,
    /// Per-delivery latencies (ns), pooled from every receiver.
    latencies_ns: std::sync::Mutex<Vec<u64>>,
}

/// Percentile (0.0–1.0) of a sorted slice, in microseconds.
fn pctl_us(sorted_ns: &[u64], p: f64) -> f64 {
    if sorted_ns.is_empty() {
        return 0.0;
    }
    let idx = ((sorted_ns.len() - 1) as f64 * p).round() as usize;
    sorted_ns[idx] as f64 / 1000.0
}

async fn run(args: Args) {
    let args = Arc::new(args);
    println!(
        "e6irc-load: {} clients across {} channel(s) -> {} (burst {})",
        args.clients, args.channels, args.addr, args.burst
    );

    let run_start = Instant::now();
    let ready = Arc::new(Barrier::new(args.clients));
    let metrics = Arc::new(Metrics {
        connect_max_ms: AtomicU64::new(0),
        fanout_max_ms: AtomicU64::new(0),
        received: AtomicU64::new(0),
        // One send-time slot per (channel, seq).
        sent_ns: (0..args.channels * args.burst)
            .map(|_| AtomicU64::new(0))
            .collect(),
        latencies_ns: std::sync::Mutex::new(Vec::new()),
    });
    let mut handles = Vec::with_capacity(args.clients);
    for id in 0..args.clients {
        let args = args.clone();
        let ready = ready.clone();
        let metrics = metrics.clone();
        handles.push(tokio::spawn(async move {
            client(id, args, ready, metrics, run_start).await
        }));
    }

    let mut failures = 0usize;
    for h in handles {
        match h.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                failures += 1;
                if failures <= 5 {
                    eprintln!("client error: {e}");
                }
            }
            Err(e) => {
                failures += 1;
                eprintln!("client task panicked: {e}");
            }
        }
    }

    let ok = args.clients - failures;
    let connect_secs = metrics.connect_max_ms.load(Ordering::Relaxed) as f64 / 1000.0;
    println!(
        "connect+register+join: {ok}/{} in {connect_secs:.2}s ({:.0} clients/s)",
        args.clients,
        ok as f64 / connect_secs.max(1e-9),
    );
    if failures > 0 {
        println!("{failures} client(s) failed");
    }

    let delivered = metrics.received.load(Ordering::Relaxed);
    // Every non-sender receives its channel sender's burst; there is one
    // sender per channel.
    let expected = (args.burst * ok.saturating_sub(args.channels)) as u64;
    let fanout_secs = metrics.fanout_max_ms.load(Ordering::Relaxed) as f64 / 1000.0;
    if fanout_secs > 0.0 {
        println!(
            "fan-out: {delivered}/{expected} messages in {fanout_secs:.3}s ({:.0} msg/s)",
            delivered as f64 / fanout_secs,
        );
    } else {
        println!("fan-out: {delivered}/{expected} messages delivered");
    }

    let mut lat = metrics
        .latencies_ns
        .lock()
        .expect("latency pool poisoned")
        .clone();
    if !lat.is_empty() {
        lat.sort_unstable();
        println!(
            "latency (µs): p50 {:.1}  p90 {:.1}  p99 {:.1}  max {:.1}",
            pctl_us(&lat, 0.50),
            pctl_us(&lat, 0.90),
            pctl_us(&lat, 0.99),
            pctl_us(&lat, 1.0),
        );
    }
}

/// One client: connect, register, join, sync on the barrier, then either
/// send the burst (client 0) or count and time deliveries.
async fn client(
    id: usize,
    args: Arc<Args>,
    ready: Arc<Barrier>,
    metrics: Arc<Metrics>,
    run_start: Instant,
) -> std::io::Result<()> {
    let channel = args.channel_of(id);
    // Setup phase. A failure here must NOT bypass the barrier: if a client
    // returned early with `?`, the remaining clients would block on the
    // barrier forever (the exact at-capacity scenario the harness measures).
    // The phase is also bounded in time: a server that accepts the TCP
    // connection but stalls before 001/366 is precisely the at-capacity
    // behavior this harness exists to report, and an unbounded await here
    // would wedge every client behind the barrier with zero output instead.
    let setup = async {
        let mut conn = connect(&args).await?;
        conn.register(&format!("load{id}"), "load").await?;
        conn.send_line(&format!("JOIN {channel}")).await?;
        // Wait for end-of-names (366) so we know the join completed.
        loop {
            match conn.next_message().await? {
                Some(m) if m.command == "366" => break,
                Some(_) => {}
                None => return Err(std::io::Error::other("closed before join")),
            }
        }
        metrics
            .connect_max_ms
            .fetch_max(run_start.elapsed().as_millis() as u64, Ordering::Relaxed);
        Ok::<_, std::io::Error>(conn)
    };
    let setup = match tokio::time::timeout(Duration::from_secs(30), setup).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "setup (connect/register/join) took over 30s",
        )),
    };

    // Everyone reaches the barrier exactly once — even a client that failed
    // setup releases its slot so the survivors are never wedged. Then propagate
    // any setup error (counted as a failure by the caller).
    ready.wait().await;
    let mut conn = setup?;
    let fanout_start = Instant::now();

    // The channel index doubles as this channel's sender id (ids
    // `0..channels` are senders) and as the sent-time base.
    let chan_idx = id % args.channels;
    if args.is_sender(id) {
        let base = chan_idx * args.burst;
        for n in 0..args.burst {
            // Stamp the send time before emitting so receivers can
            // compute end-to-end latency for this (channel, seq).
            metrics.sent_ns[base + n]
                .store(run_start.elapsed().as_nanos() as u64, Ordering::Relaxed);
            conn.send_line(&format!("PRIVMSG {channel} :load {n}"))
                .await?;
        }
        return Ok(());
    }

    // Receiver: count this channel's sender's burst until complete or a
    // timeout, recording end-to-end latency per delivery.
    let sender_prefix = format!("load{chan_idx}!");
    let base = chan_idx * args.burst;
    let mut count = 0u64;
    let mut latencies = Vec::with_capacity(args.burst);
    let _ = tokio::time::timeout(Duration::from_secs(30), async {
        while count < args.burst as u64 {
            match conn.next_message().await {
                Ok(Some(m))
                    if m.command == "PRIVMSG"
                        && m.params.first().map(String::as_str) == Some(&channel)
                        && m.source
                            .as_deref()
                            .is_some_and(|s| s.starts_with(&sender_prefix)) =>
                {
                    let recv_ns = run_start.elapsed().as_nanos() as u64;
                    if let Some(seq) = m
                        .params
                        .get(1)
                        .and_then(|b| b.strip_prefix("load "))
                        .and_then(|n| n.parse::<usize>().ok())
                        && let Some(slot) = metrics.sent_ns.get(base + seq)
                    {
                        let sent = slot.load(Ordering::Relaxed);
                        if sent > 0 && recv_ns >= sent {
                            latencies.push(recv_ns - sent);
                        }
                    }
                    count += 1;
                }
                Ok(Some(_)) => {}
                _ => break,
            }
        }
    })
    .await;
    if count > 0 {
        metrics
            .fanout_max_ms
            .fetch_max(fanout_start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
    metrics.received.fetch_add(count, Ordering::Relaxed);
    metrics
        .latencies_ns
        .lock()
        .expect("latency pool poisoned")
        .extend(latencies);
    Ok(())
}
