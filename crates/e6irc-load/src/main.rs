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

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use e6irc_client::Connection;
use serde::Serialize;
use tokio::sync::Barrier;

const MAX_CLIENTS: usize = 100_000;
const MAX_TRACKED_MESSAGES: usize = 10_000_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Sha256Digest(String);

impl Sha256Digest {
    fn parse(value: String, flag: &str) -> Result<Self, String> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!("{flag} needs a 64-character SHA-256 hex digest"));
        }
        Ok(Self(value.to_ascii_lowercase()))
    }
}

#[derive(Clone)]
struct Workload {
    clients: usize,
    channels: usize,
    burst: usize,
    sender_slots: usize,
    expected_deliveries: u64,
}

impl Workload {
    fn new(clients: usize, channels: usize, burst: usize) -> Result<Self, String> {
        if clients > MAX_CLIENTS {
            return Err(format!("--clients must not exceed {MAX_CLIENTS}"));
        }
        if channels == 0 {
            return Err("--channels must be at least 1".into());
        }
        if burst == 0 {
            return Err("--burst must be at least 1".into());
        }
        let receivers = clients
            .checked_sub(channels)
            .filter(|count| *count > 0)
            .ok_or_else(|| {
                "--clients must exceed --channels (each channel needs a sender + a receiver)"
                    .to_string()
            })?;
        let sender_slots = channels
            .checked_mul(burst)
            .filter(|slots| *slots <= MAX_TRACKED_MESSAGES)
            .ok_or_else(|| {
                format!("--channels × --burst must not exceed {MAX_TRACKED_MESSAGES}")
            })?;
        let expected_deliveries = receivers
            .checked_mul(burst)
            .filter(|deliveries| *deliveries <= MAX_TRACKED_MESSAGES)
            .ok_or_else(|| {
                format!("(--clients − --channels) × --burst must not exceed {MAX_TRACKED_MESSAGES}")
            })?;
        Ok(Self {
            clients,
            channels,
            burst,
            sender_slots,
            expected_deliveries: expected_deliveries as u64,
        })
    }
}

#[derive(Clone)]
struct Args {
    addr: String,
    workload: Workload,
    /// Channel-name prefix; the actual channel is `{channel}{index}`.
    channel: String,
    tls: bool,
    minimum_connect_rate: Option<f64>,
    minimum_fanout_rate: Option<f64>,
    maximum_p99_ms: Option<f64>,
    /// Linux process whose resident memory is sampled during the run.
    server_pid: Option<u32>,
    /// Maximum incremental peak resident bytes divided by the requested
    /// connection count. Requires `server_pid`.
    maximum_server_rss_per_connection_bytes: Option<u64>,
    host_provenance_sha256: Option<Sha256Digest>,
    report_json: Option<PathBuf>,
}

impl Args {
    /// The channel a client belongs to.
    fn channel_of(&self, id: usize) -> String {
        format!("{}{}", self.channel, id % self.workload.channels)
    }
    /// Clients `0..channels` are the per-channel senders.
    fn is_sender(&self, id: usize) -> bool {
        id < self.workload.channels
    }
}

fn parse_args() -> Result<Args, String> {
    parse_args_from(std::env::args().skip(1))
}

fn parse_args_from(arguments: impl IntoIterator<Item = String>) -> Result<Args, String> {
    let mut clients = 100;
    let mut channels = 1;
    let mut burst = 10;
    let mut args = Args {
        addr: "127.0.0.1:6667".to_string(),
        workload: Workload::new(100, 1, 10).expect("default workload is valid"),
        channel: "#load".to_string(),
        tls: false,
        minimum_connect_rate: None,
        minimum_fanout_rate: None,
        maximum_p99_ms: None,
        server_pid: None,
        maximum_server_rss_per_connection_bytes: None,
        host_provenance_sha256: None,
        report_json: None,
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
                clients = parse_num(
                    &it.next()
                        .ok_or_else(|| "--clients needs a value".to_string())?,
                    "--clients",
                )?;
            }
            "--channel" => {
                args.channel = it
                    .next()
                    .ok_or_else(|| "--channel needs a value".to_string())?
            }
            "--channels" => {
                channels = parse_num(
                    &it.next()
                        .ok_or_else(|| "--channels needs a value".to_string())?,
                    "--channels",
                )?
            }
            "--burst" => {
                burst = parse_num(
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
            "--server-pid" => {
                let value = parse_positive_u64(
                    &it.next()
                        .ok_or_else(|| "--server-pid needs a value".to_string())?,
                    "--server-pid",
                )?;
                args.server_pid = Some(
                    u32::try_from(value)
                        .map_err(|_| "--server-pid exceeds the platform PID range".to_string())?,
                );
            }
            "--maximum-server-rss-per-connection-bytes" => {
                args.maximum_server_rss_per_connection_bytes = Some(parse_positive_u64(
                    &it.next().ok_or_else(|| {
                        "--maximum-server-rss-per-connection-bytes needs a value".to_string()
                    })?,
                    "--maximum-server-rss-per-connection-bytes",
                )?);
            }
            "--host-provenance-sha256" => {
                args.host_provenance_sha256 = Some(Sha256Digest::parse(
                    it.next()
                        .ok_or_else(|| "--host-provenance-sha256 needs a value".to_string())?,
                    "--host-provenance-sha256",
                )?);
            }
            "--report-json" => {
                args.report_json = Some(PathBuf::from(
                    it.next()
                        .ok_or_else(|| "--report-json needs a path".to_string())?,
                ));
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    args.workload = Workload::new(clients, channels, burst)?;
    if args.maximum_server_rss_per_connection_bytes.is_some() && args.server_pid.is_none() {
        return Err("--maximum-server-rss-per-connection-bytes requires --server-pid".to_string());
    }
    if args.host_provenance_sha256.is_some()
        && (args.report_json.is_none()
            || args.server_pid.is_none()
            || args.maximum_server_rss_per_connection_bytes.is_none()
            || args.minimum_connect_rate.is_none()
            || args.minimum_fanout_rate.is_none()
            || args.maximum_p99_ms.is_none())
    {
        return Err(
            "--host-provenance-sha256 requires --report-json, --server-pid, and all acceptance thresholds"
                .to_string(),
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

fn parse_positive_u64(s: &str, flag: &str) -> Result<u64, String> {
    let value: u64 = s
        .parse()
        .map_err(|_| format!("{flag} needs a positive integer"))?;
    if value == 0 {
        return Err(format!("{flag} needs a positive integer"));
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
    let report = match runtime.block_on(run(args.clone())) {
        Ok(report) => RunReport::Completed(report),
        Err(error) => {
            eprintln!("e6irc-load: {error}");
            RunReport::Failed(FailedRunReport::new(&args, error))
        }
    };
    if let Some(path) = args.report_json.as_deref()
        && let Err(error) = write_report(path, &report)
    {
        eprintln!("e6irc-load: failed to write {}: {error}", path.display());
        return ExitCode::FAILURE;
    }
    if report.passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[derive(Serialize)]
struct Thresholds {
    minimum_connect_rate: Option<f64>,
    minimum_fanout_rate: Option<f64>,
    maximum_p99_ms: Option<f64>,
    maximum_server_rss_per_connection_bytes: Option<u64>,
}

#[derive(Serialize)]
struct LatencyReport {
    p50_us: f64,
    p90_us: f64,
    p99_us: f64,
    max_us: f64,
}

#[derive(Serialize)]
struct ServerRssReport {
    baseline_bytes: u64,
    peak_bytes: u64,
    incremental_bytes: u64,
    per_connection_bytes: u64,
}

#[derive(Serialize)]
struct RunRequest {
    addr: String,
    clients: usize,
    channels: usize,
    burst: usize,
    tls: bool,
    host_provenance_sha256: Option<Sha256Digest>,
    thresholds: Thresholds,
}

impl RunRequest {
    fn from_args(args: &Args) -> Self {
        Self {
            addr: args.addr.clone(),
            clients: args.workload.clients,
            channels: args.workload.channels,
            burst: args.workload.burst,
            tls: args.tls,
            host_provenance_sha256: args.host_provenance_sha256.clone(),
            thresholds: Thresholds {
                minimum_connect_rate: args.minimum_connect_rate,
                minimum_fanout_rate: args.minimum_fanout_rate,
                maximum_p99_ms: args.maximum_p99_ms,
                maximum_server_rss_per_connection_bytes: args
                    .maximum_server_rss_per_connection_bytes,
            },
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "status", content = "report", rename_all = "snake_case")]
enum RunReport {
    Completed(CompletedRunReport),
    Failed(FailedRunReport),
}

impl RunReport {
    fn passed(&self) -> bool {
        matches!(self, Self::Completed(report) if report.outcome == CompletedOutcome::Passed)
    }
}

#[derive(Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CompletedOutcome {
    Passed,
    Rejected,
}

#[derive(Serialize)]
struct CompletedRunReport {
    format_version: u8,
    request: RunRequest,
    successful_clients: usize,
    failed_clients: usize,
    expected_deliveries: u64,
    received_deliveries: u64,
    connect_seconds: f64,
    connect_rate: f64,
    fanout_seconds: f64,
    fanout_rate: f64,
    latency: Option<LatencyReport>,
    server_rss: Option<ServerRssReport>,
    outcome: CompletedOutcome,
}

#[derive(Serialize)]
struct FailedRunReport {
    format_version: u8,
    request: RunRequest,
    error: String,
}

impl FailedRunReport {
    fn new(args: &Args, error: String) -> Self {
        Self {
            format_version: 2,
            request: RunRequest::from_args(args),
            error,
        }
    }
}

fn write_report(path: &Path, report: &RunReport) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(report)
        .map_err(|error| std::io::Error::other(format!("encode report: {error}")))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()
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

#[cfg(target_os = "linux")]
fn read_server_rss_bytes(pid: u32) -> std::io::Result<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    parse_linux_rss_bytes(&status)
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_rss_bytes(status: &str) -> std::io::Result<u64> {
    let mut fields = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .ok_or_else(|| std::io::Error::other("VmRSS is absent from the server process status"))?
        .split_ascii_whitespace();
    let (Some(amount), Some("kB"), None) = (fields.next(), fields.next(), fields.next()) else {
        return Err(std::io::Error::other(
            "VmRSS does not use the expected '<integer> kB' form",
        ));
    };
    let kilobytes = amount
        .parse::<u64>()
        .map_err(|_| std::io::Error::other("VmRSS is not an integer"))?;
    kilobytes
        .checked_mul(1024)
        .ok_or_else(|| std::io::Error::other("server resident-memory count overflowed bytes"))
}

#[cfg(not(target_os = "linux"))]
fn read_server_rss_bytes(_pid: u32) -> std::io::Result<u64> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "--server-pid resident-memory sampling is supported on Linux",
    ))
}

async fn sample_server_rss(
    pid: u32,
    baseline: u64,
    finished: Arc<AtomicBool>,
) -> std::io::Result<u64> {
    let mut peak = baseline;
    while !finished.load(Ordering::Relaxed) {
        peak = peak.max(read_server_rss_bytes(pid)?);
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Ok(peak.max(read_server_rss_bytes(pid)?))
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

async fn run(args: Args) -> Result<CompletedRunReport, String> {
    let args = Arc::new(args);
    println!(
        "e6irc-load: {} clients across {} channel(s) -> {} (burst {})",
        args.workload.clients, args.workload.channels, args.addr, args.workload.burst
    );

    let rss_finished = Arc::new(AtomicBool::new(false));
    let rss_measurement = match args.server_pid {
        Some(pid) => match read_server_rss_bytes(pid) {
            Ok(baseline) => {
                let finished = rss_finished.clone();
                Some((
                    baseline,
                    tokio::spawn(sample_server_rss(pid, baseline, finished)),
                ))
            }
            Err(error) => {
                return Err(format!(
                    "server RSS measurement failed before the run: {error}"
                ));
            }
        },
        None => None,
    };
    let run_start = Instant::now();
    let ready = Arc::new(Barrier::new(args.workload.clients));
    let metrics = Arc::new(Metrics {
        connect_max_ns: AtomicU64::new(0),
        fanout_max_ns: AtomicU64::new(0),
        received: AtomicU64::new(0),
        // One send-time slot per (channel, seq).
        sent_ns: (0..args.workload.sender_slots)
            .map(|_| AtomicU64::new(0))
            .collect(),
        latencies_ns: std::sync::Mutex::new(Vec::new()),
    });
    let mut handles = Vec::with_capacity(args.workload.clients);
    for id in 0..args.workload.clients {
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
    rss_finished.store(true, Ordering::Relaxed);
    let rss_report = match rss_measurement {
        Some((baseline, task)) => match task.await {
            Ok(Ok(peak)) => Some((baseline, peak)),
            Ok(Err(error)) => {
                return Err(format!(
                    "server RSS measurement failed during the run: {error}"
                ));
            }
            Err(error) => {
                return Err(format!("server RSS sampler task failed: {error}"));
            }
        },
        None => None,
    };

    let ok = args.workload.clients - failures;
    let connect_secs = metrics.connect_max_ns.load(Ordering::Relaxed) as f64 / 1_000_000_000.0;
    let connect_rate = ok as f64 / connect_secs.max(1e-9);
    println!(
        "connect+register+join: {ok}/{} in {connect_secs:.2}s ({:.0} clients/s)",
        args.workload.clients, connect_rate,
    );
    if failures > 0 {
        println!("{failures} client(s) failed");
    }

    let delivered = metrics.received.load(Ordering::Relaxed);
    // Every non-sender receives its channel sender's burst; there is one
    // sender per channel.
    let expected = args.workload.expected_deliveries;
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
    let latency = if lat.is_empty() {
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
        Some(LatencyReport {
            p50_us: pctl_us(&lat, 0.50),
            p90_us: pctl_us(&lat, 0.90),
            p99_us,
            max_us: pctl_us(&lat, 1.0),
        })
    };
    if delivered != expected {
        eprintln!("incomplete fan-out: received {delivered} of {expected} required deliveries");
    }
    let mut thresholds_met = true;
    let server_rss = if let Some((baseline, peak)) = rss_report {
        let incremental = peak.saturating_sub(baseline);
        let per_connection = incremental.saturating_add(args.workload.clients as u64 - 1)
            / args.workload.clients as u64;
        println!(
            "server RSS: baseline {baseline} bytes, peak {peak} bytes, \
             incremental {incremental} bytes ({per_connection} bytes/connection)"
        );
        if let Some(maximum) = args.maximum_server_rss_per_connection_bytes
            && per_connection > maximum
        {
            thresholds_met = false;
            eprintln!("server RSS threshold failed: {per_connection} > {maximum} bytes/connection");
        }
        Some(ServerRssReport {
            baseline_bytes: baseline,
            peak_bytes: peak,
            incremental_bytes: incremental,
            per_connection_bytes: per_connection,
        })
    } else {
        None
    };
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
        match latency.as_ref() {
            Some(observed) if observed.p99_us <= maximum_ms * 1000.0 => {}
            Some(observed) => {
                thresholds_met = false;
                eprintln!(
                    "latency threshold failed: p99 {:.3} ms > {maximum_ms:.3} ms",
                    observed.p99_us / 1000.0
                );
            }
            None => {
                thresholds_met = false;
                eprintln!("latency threshold failed: no deliveries were timed");
            }
        }
    }
    Ok(CompletedRunReport {
        format_version: 2,
        request: RunRequest::from_args(&args),
        successful_clients: ok,
        failed_clients: failures,
        expected_deliveries: expected,
        received_deliveries: delivered,
        connect_seconds: connect_secs,
        connect_rate,
        fanout_seconds: fanout_secs,
        fanout_rate,
        latency,
        server_rss,
        outcome: if failures == 0 && delivered == expected && thresholds_met {
            CompletedOutcome::Passed
        } else {
            CompletedOutcome::Rejected
        },
    })
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
    let chan_idx = id % args.workload.channels;
    if args.is_sender(id) {
        let base = chan_idx * args.workload.burst;
        for n in 0..args.workload.burst {
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
    let base = chan_idx * args.workload.burst;
    let mut count = 0u64;
    // Elapsed at the *last message actually counted*, not at loop exit: an
    // incomplete run exits via the 30s timeout, and recording that deadline
    // would pin the fan-out duration (the throughput denominator, a `fetch_max`
    // across receivers) to ~30s and understate msg/s — exactly in the
    // near-capacity regime the harness exists to measure. This tracks the real
    // delivery time instead.
    let mut last_delivery_ns = 0u64;
    let mut latencies = Vec::with_capacity(args.workload.burst);
    let mut deliveries = DeliverySet::new(args.workload.burst);
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
                        if count != args.workload.burst as u64 {
                            return Err(std::io::Error::other(format!(
                                "incomplete sequence set at sender fence: received {count} of {}",
                                args.workload.burst
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
            format!(
                "fan-out timed out after {count}/{} deliveries",
                args.workload.burst
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Result<Args, String> {
        parse_args_from(values.iter().map(|value| (*value).to_owned()))
    }

    fn sample_report() -> CompletedRunReport {
        CompletedRunReport {
            format_version: 2,
            request: RunRequest {
                addr: "127.0.0.1:6667".into(),
                clients: 64,
                channels: 8,
                burst: 4,
                tls: false,
                host_provenance_sha256: None,
                thresholds: Thresholds {
                    minimum_connect_rate: Some(10.0),
                    minimum_fanout_rate: Some(100.0),
                    maximum_p99_ms: Some(5_000.0),
                    maximum_server_rss_per_connection_bytes: Some(1_048_576),
                },
            },
            successful_clients: 64,
            failed_clients: 0,
            expected_deliveries: 224,
            received_deliveries: 224,
            connect_seconds: 1.0,
            connect_rate: 64.0,
            fanout_seconds: 1.0,
            fanout_rate: 224.0,
            latency: None,
            server_rss: None,
            outcome: CompletedOutcome::Passed,
        }
    }

    #[test]
    fn arguments_reject_vacuous_runs_and_invalid_thresholds() {
        assert!(args(&["--burst", "0"]).is_err());
        assert!(args(&["--clients", "8", "--channels", "8"]).is_err());
        assert!(args(&["--minimum-connect-rate", "0"]).is_err());
        assert!(args(&["--maximum-p99-ms", "NaN"]).is_err());
        assert!(args(&["--maximum-server-rss-per-connection-bytes", "1048576"]).is_err());
        assert!(args(&["--server-pid", "0"]).is_err());
        assert!(
            args(&[
                "--host-provenance-sha256",
                "a3b4c5d6e7f80910a3b4c5d6e7f80910a3b4c5d6e7f80910a3b4c5d6e7f80910",
            ])
            .is_err()
        );
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
            "--server-pid",
            "123",
            "--maximum-server-rss-per-connection-bytes",
            "1048576",
            "--host-provenance-sha256",
            "A3b4c5d6e7f80910a3b4c5d6e7f80910a3b4c5d6e7f80910a3b4c5d6e7f80910",
            "--report-json",
            "result.json",
        ])
        .unwrap();
        assert_eq!(parsed.workload.clients, 64);
        assert_eq!(parsed.minimum_connect_rate, Some(10.0));
        assert_eq!(parsed.minimum_fanout_rate, Some(100.0));
        assert_eq!(parsed.maximum_p99_ms, Some(5000.0));
        assert_eq!(parsed.server_pid, Some(123));
        assert_eq!(
            parsed.maximum_server_rss_per_connection_bytes,
            Some(1_048_576)
        );
        assert_eq!(parsed.report_json, Some(PathBuf::from("result.json")));
        assert_eq!(
            parsed.host_provenance_sha256,
            Some(Sha256Digest(
                "a3b4c5d6e7f80910a3b4c5d6e7f80910a3b4c5d6e7f80910a3b4c5d6e7f80910".into()
            ))
        );
        assert!(args(&["--host-provenance-sha256", "not-a-digest"]).is_err());
    }

    #[test]
    fn workload_rejects_unrepresentable_measurements() {
        assert!(args(&["--clients", "100001"]).is_err());
        assert!(args(&["--clients", "100000", "--channels", "100000"]).is_err());
        assert!(args(&["--clients", "2", "--channels", "1", "--burst", "10000001"]).is_err());
        assert!(args(&["--clients", "100000", "--channels", "1", "--burst", "102"]).is_err());

        let workload = Workload::new(100_000, 200, 20).expect("target workload is valid");
        assert_eq!(workload.sender_slots, 4_000);
        assert_eq!(workload.expected_deliveries, 1_996_000);
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

    #[test]
    fn linux_rss_parser_requires_the_kernel_status_shape() {
        assert_eq!(
            parse_linux_rss_bytes("Name:\te6ircd\nVmRSS:\t1234 kB\n").unwrap(),
            1_263_616
        );
        assert!(parse_linux_rss_bytes("Name:\te6ircd\n").is_err());
        assert!(parse_linux_rss_bytes("VmRSS:\t12 MB\n").is_err());
        assert!(parse_linux_rss_bytes("VmRSS:\tnot-a-number kB\n").is_err());
    }

    #[test]
    fn report_has_a_versioned_machine_contract() {
        let json =
            serde_json::to_value(RunReport::Completed(sample_report())).expect("serialize report");
        assert_eq!(json["status"], "completed");
        assert_eq!(json["report"]["format_version"], 2);
        assert_eq!(json["report"]["expected_deliveries"], 224);
        assert_eq!(
            json["report"]["request"]["thresholds"]["maximum_p99_ms"],
            5_000.0
        );
        assert_eq!(json["report"]["outcome"], "passed");
        assert!(json["report"]["request"]["host_provenance_sha256"].is_null());
    }

    #[test]
    fn failed_report_keeps_the_requested_contract() {
        let report = RunReport::Failed(FailedRunReport::new(
            &args(&["--clients", "64", "--channels", "8"]).expect("valid arguments"),
            "server RSS measurement failed before the run: no such process".into(),
        ));
        let json = serde_json::to_value(report).expect("serialize failed report");
        assert_eq!(json["status"], "failed");
        assert_eq!(json["report"]["format_version"], 2);
        assert_eq!(json["report"]["request"]["clients"], 64);
        assert!(
            json["report"]["error"]
                .as_str()
                .is_some_and(|error| error.contains("RSS"))
        );
    }

    #[test]
    fn only_a_completed_passed_report_succeeds() {
        assert!(RunReport::Completed(sample_report()).passed());
        let mut rejected = sample_report();
        rejected.outcome = CompletedOutcome::Rejected;
        assert!(!RunReport::Completed(rejected).passed());
        assert!(
            !RunReport::Failed(FailedRunReport::new(
                &args(&[]).expect("default arguments"),
                "connection failed".into(),
            ))
            .passed()
        );
    }

    #[test]
    fn report_does_not_replace_prior_evidence() {
        let path = std::env::temp_dir().join(format!("e6irc-load-report-{}", std::process::id()));
        let report = RunReport::Completed(sample_report());
        write_report(&path, &report).expect("write report");
        assert!(write_report(&path, &report).is_err());
        std::fs::remove_file(path).expect("remove report");
    }
}
