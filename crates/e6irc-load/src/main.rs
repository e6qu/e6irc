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

use std::process::ExitCode;
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
    minimum_connect_rate: Option<f64>,
    minimum_fanout_rate: Option<f64>,
    maximum_p99_ms: Option<f64>,
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

fn parse_args() -> Result<Args, String> {
    parse_args_from(std::env::args().skip(1))
}

fn parse_args_from(arguments: impl IntoIterator<Item = String>) -> Result<Args, String> {
    let mut args = Args {
        addr: "127.0.0.1:6667".to_string(),
        clients: 100,
        channel: "#load".to_string(),
        channels: 1,
        burst: 10,
        tls: false,
        minimum_connect_rate: None,
        minimum_fanout_rate: None,
        maximum_p99_ms: None,
    };
    let mut it = arguments.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--addr" => {
                args.addr = it
                    .next()
                    .ok_or_else(|| "--addr needs a value".to_string())?
            }
            "--clients" => {
                args.clients = parse_num(
                    &it.next()
                        .ok_or_else(|| "--clients needs a value".to_string())?,
                    "--clients",
                )?
            }
            "--channel" => {
                args.channel = it
                    .next()
                    .ok_or_else(|| "--channel needs a value".to_string())?
            }
            "--channels" => {
                args.channels = parse_num(
                    &it.next()
                        .ok_or_else(|| "--channels needs a value".to_string())?,
                    "--channels",
                )?
            }
            "--burst" => {
                args.burst = parse_num(
                    &it.next()
                        .ok_or_else(|| "--burst needs a value".to_string())?,
                    "--burst",
                )?
            }
            "--tls" => args.tls = true,
            "--minimum-connect-rate" => {
                args.minimum_connect_rate = Some(parse_positive_float(
                    &it.next()
                        .ok_or_else(|| "--minimum-connect-rate needs a value".to_string())?,
                    "--minimum-connect-rate",
                )?);
            }
            "--minimum-fanout-rate" => {
                args.minimum_fanout_rate = Some(parse_positive_float(
                    &it.next()
                        .ok_or_else(|| "--minimum-fanout-rate needs a value".to_string())?,
                    "--minimum-fanout-rate",
                )?);
            }
            "--maximum-p99-ms" => {
                args.maximum_p99_ms = Some(parse_positive_float(
                    &it.next()
                        .ok_or_else(|| "--maximum-p99-ms needs a value".to_string())?,
                    "--maximum-p99-ms",
                )?);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    if args.channels < 1 {
        return Err("--channels must be at least 1".into());
    }
    if args.burst < 1 {
        return Err("--burst must be at least 1".into());
    }
    // Each channel needs its sender plus at least one receiver.
    if args.clients <= args.channels {
        return Err(
            "--clients must exceed --channels (each channel needs a sender + a receiver)".into(),
        );
    }
    Ok(args)
}

fn parse_num(s: &str, flag: &str) -> Result<usize, String> {
    s.parse().map_err(|_| format!("{flag} needs a number"))
}

fn parse_positive_float(s: &str, flag: &str) -> Result<f64, String> {
    let value: f64 = s
        .parse()
        .map_err(|_| format!("{flag} needs a positive number"))?;
    if !value.is_finite() || value <= 0.0 {
        return Err(format!("{flag} needs a positive finite number"));
    }
    Ok(value)
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

fn main() -> ExitCode {
    let args = parse_args().unwrap_or_else(|error| die(&error));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if runtime.block_on(run(args)) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Shared timing/counters across the client tasks.
struct Metrics {
    /// Wall time (ns since `run_start`) when the last client finished
    /// connect+register+join.
    connect_max_ns: AtomicU64,
    /// Longest per-receiver fan-out duration (ns from barrier release to
    /// having counted its whole share).
    fanout_max_ns: AtomicU64,
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

fn elapsed_nanos(start: Instant) -> u64 {
    start.elapsed().as_nanos().min((u64::MAX - 1) as u128) as u64
}

struct DeliverySet {
    seen: Vec<bool>,
}

impl DeliverySet {
    fn new(expected: usize) -> Self {
        Self {
            seen: vec![false; expected],
        }
    }

    fn accept(&mut self, sequence: usize) -> std::io::Result<()> {
        let Some(seen) = self.seen.get_mut(sequence) else {
            return Err(std::io::Error::other(format!(
                "matching load message carried out-of-range sequence {sequence}"
            )));
        };
        if *seen {
            return Err(std::io::Error::other(format!(
                "duplicate delivery for sequence {sequence}"
            )));
        }
        *seen = true;
        Ok(())
    }
}

async fn run(args: Args) -> bool {
    let args = Arc::new(args);
    println!(
        "e6irc-load: {} clients across {} channel(s) -> {} (burst {})",
        args.clients, args.channels, args.addr, args.burst
    );

    let run_start = Instant::now();
    let ready = Arc::new(Barrier::new(args.clients));
    let metrics = Arc::new(Metrics {
        connect_max_ns: AtomicU64::new(0),
        fanout_max_ns: AtomicU64::new(0),
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
    let connect_secs = metrics.connect_max_ns.load(Ordering::Relaxed) as f64 / 1_000_000_000.0;
    let connect_rate = ok as f64 / connect_secs.max(1e-9);
    println!(
        "connect+register+join: {ok}/{} in {connect_secs:.2}s ({:.0} clients/s)",
        args.clients, connect_rate,
    );
    if failures > 0 {
        println!("{failures} client(s) failed");
    }

    let delivered = metrics.received.load(Ordering::Relaxed);
    // Every non-sender receives its channel sender's burst; there is one
    // sender per channel.
    let expected = (args.burst * (args.clients - args.channels)) as u64;
    let fanout_secs = metrics.fanout_max_ns.load(Ordering::Relaxed) as f64 / 1_000_000_000.0;
    let fanout_rate = delivered as f64 / fanout_secs.max(1e-9);
    if fanout_secs > 0.0 {
        println!(
            "fan-out: {delivered}/{expected} messages in {fanout_secs:.3}s ({:.0} msg/s)",
            fanout_rate,
        );
    } else {
        println!("fan-out: {delivered}/{expected} messages delivered");
    }

    let mut lat = metrics
        .latencies_ns
        .lock()
        .expect("latency pool poisoned")
        .clone();
    let p99_us = if lat.is_empty() {
        None
    } else {
        lat.sort_unstable();
        let p99_us = pctl_us(&lat, 0.99);
        println!(
            "latency (µs): p50 {:.1}  p90 {:.1}  p99 {:.1}  max {:.1}",
            pctl_us(&lat, 0.50),
            pctl_us(&lat, 0.90),
            p99_us,
            pctl_us(&lat, 1.0),
        );
        Some(p99_us)
    };
    if delivered != expected {
        eprintln!("incomplete fan-out: received {delivered} of {expected} required deliveries");
    }
    let mut thresholds_met = true;
    if let Some(minimum) = args.minimum_connect_rate
        && connect_rate < minimum
    {
        thresholds_met = false;
        eprintln!("connect-rate threshold failed: {connect_rate:.1} < {minimum:.1} clients/s");
    }
    if let Some(minimum) = args.minimum_fanout_rate
        && fanout_rate < minimum
    {
        thresholds_met = false;
        eprintln!("fan-out threshold failed: {fanout_rate:.1} < {minimum:.1} messages/s");
    }
    if let Some(maximum_ms) = args.maximum_p99_ms {
        match p99_us {
            Some(observed_us) if observed_us <= maximum_ms * 1000.0 => {}
            Some(observed_us) => {
                thresholds_met = false;
                eprintln!(
                    "latency threshold failed: p99 {:.3} ms > {maximum_ms:.3} ms",
                    observed_us / 1000.0
                );
            }
            None => {
                thresholds_met = false;
                eprintln!("latency threshold failed: no deliveries were timed");
            }
        }
    }
    failures == 0 && delivered == expected && thresholds_met
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
            .connect_max_ns
            .fetch_max(elapsed_nanos(run_start), Ordering::Relaxed);
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
            metrics.sent_ns[base + n].store(elapsed_nanos(run_start) + 1, Ordering::Relaxed);
            conn.send_line(&format!("PRIVMSG {channel} :load {n}"))
                .await?;
        }
        // Same-sender ordering makes this a fan-out fence: every receiver sees
        // all burst deliveries (including any erroneous duplicates) before
        // this marker. A receiver validates its exact set only at the marker.
        conn.send_line(&format!("PRIVMSG {channel} :load-complete"))
            .await?;
        return Ok(());
    }

    // Receiver: count this channel's sender's burst until complete or a
    // timeout, recording end-to-end latency per delivery.
    let sender_prefix = format!("load{chan_idx}!");
    let base = chan_idx * args.burst;
    let mut count = 0u64;
    // Elapsed at the *last message actually counted*, not at loop exit: an
    // incomplete run exits via the 30s timeout, and recording that deadline
    // would pin the fan-out duration (the throughput denominator, a `fetch_max`
    // across receivers) to ~30s and understate msg/s — exactly in the
    // near-capacity regime the harness exists to measure. This tracks the real
    // delivery time instead.
    let mut last_delivery_ns = 0u64;
    let mut latencies = Vec::with_capacity(args.burst);
    let mut deliveries = DeliverySet::new(args.burst);
    let receive = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match conn.next_message().await {
                Ok(Some(m))
                    if m.command == "PRIVMSG"
                        && m.params.first().map(String::as_str) == Some(&channel)
                        && m.source
                            .as_deref()
                            .is_some_and(|s| s.starts_with(&sender_prefix)) =>
                {
                    let recv_ns = elapsed_nanos(run_start);
                    let body = m.params.get(1).map(String::as_str).unwrap_or("");
                    if body == "load-complete" {
                        if count != args.burst as u64 {
                            return Err(std::io::Error::other(format!(
                                "incomplete sequence set at sender fence: received {count} of {}",
                                args.burst
                            )));
                        }
                        break;
                    }
                    let seq = body
                        .strip_prefix("load ")
                        .and_then(|n| n.parse::<usize>().ok())
                        .ok_or_else(|| {
                            std::io::Error::other(
                                "matching load message carried no numeric sequence",
                            )
                        })?;
                    deliveries.accept(seq)?;
                    let sent_plus_one = metrics.sent_ns[base + seq].load(Ordering::Relaxed);
                    if sent_plus_one == 0 {
                        return Err(std::io::Error::other(format!(
                            "delivery for sequence {seq} arrived without a send timestamp"
                        )));
                    }
                    let sent = sent_plus_one - 1;
                    if recv_ns < sent {
                        return Err(std::io::Error::other(
                            "monotonic delivery timestamp preceded its send",
                        ));
                    }
                    latencies.push(recv_ns - sent);
                    count += 1;
                    last_delivery_ns = elapsed_nanos(fanout_start);
                }
                Ok(Some(_)) => {}
                Ok(None) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "server closed before complete fan-out",
                    ));
                }
                Err(error) => return Err(error),
            }
        }
        Ok::<(), std::io::Error>(())
    })
    .await;
    if count > 0 {
        metrics
            .fanout_max_ns
            .fetch_max(last_delivery_ns, Ordering::Relaxed);
    }
    metrics.received.fetch_add(count, Ordering::Relaxed);
    metrics
        .latencies_ns
        .lock()
        .expect("latency pool poisoned")
        .extend(latencies);
    match receive {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("fan-out timed out after {count}/{} deliveries", args.burst),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Result<Args, String> {
        parse_args_from(values.iter().map(|value| (*value).to_owned()))
    }

    #[test]
    fn arguments_reject_vacuous_runs_and_invalid_thresholds() {
        assert!(args(&["--burst", "0"]).is_err());
        assert!(args(&["--clients", "8", "--channels", "8"]).is_err());
        assert!(args(&["--minimum-connect-rate", "0"]).is_err());
        assert!(args(&["--maximum-p99-ms", "NaN"]).is_err());
        let parsed = args(&[
            "--clients",
            "64",
            "--channels",
            "8",
            "--burst",
            "4",
            "--minimum-connect-rate",
            "10",
            "--minimum-fanout-rate",
            "100",
            "--maximum-p99-ms",
            "5000",
        ])
        .unwrap();
        assert_eq!(parsed.clients, 64);
        assert_eq!(parsed.minimum_connect_rate, Some(10.0));
        assert_eq!(parsed.minimum_fanout_rate, Some(100.0));
        assert_eq!(parsed.maximum_p99_ms, Some(5000.0));
    }

    #[test]
    fn delivery_set_refuses_duplicates_and_out_of_range_sequences() {
        let mut deliveries = DeliverySet::new(3);
        deliveries.accept(2).unwrap();
        deliveries.accept(0).unwrap();
        assert!(
            deliveries
                .accept(2)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
        assert!(
            deliveries
                .accept(3)
                .unwrap_err()
                .to_string()
                .contains("out-of-range")
        );
    }

    #[test]
    fn percentile_uses_nearest_rank_over_sorted_nanoseconds() {
        let samples = [1_000, 2_000, 3_000, 4_000, 5_000];
        assert_eq!(pctl_us(&samples, 0.50), 3.0);
        assert_eq!(pctl_us(&samples, 0.99), 5.0);
        assert_eq!(pctl_us(&[], 0.99), 0.0);
    }
}
