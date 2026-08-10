//! Fixed-cardinality runtime telemetry shared by the socket, core, database,
//! and HTTP layers.
//!
//! Only numeric counters, gauges, bounded histograms, and a fixed error
//! taxonomy are recorded. Untrusted input and secrets therefore cannot become
//! metric labels or enter persisted monitoring history.

use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

pub(crate) const SNAPSHOT_SCHEMA_VERSION: u32 = 3;

const LATENCY_BUCKETS_US: [u64; 15] = [
    100,
    250,
    500,
    1_000,
    2_500,
    5_000,
    10_000,
    25_000,
    50_000,
    100_000,
    250_000,
    500_000,
    1_000_000,
    5_000_000,
    u64::MAX,
];

#[derive(Debug, Clone, Copy)]
pub(crate) enum LatencyKind {
    Core,
    Database,
    Http,
}

impl LatencyKind {
    const COUNT: usize = 3;

    const fn index(self) -> usize {
        match self {
            Self::Core => 0,
            Self::Database => 1,
            Self::Http => 2,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Database => "database",
            Self::Http => "http",
        }
    }
}

/// A closed error taxonomy prevents untrusted details from becoming labels.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ErrorKind {
    Accept,
    ConnectionSetup,
    TlsHandshake,
    Read,
    Write,
    SendQueue,
    Database,
    Bouncer,
    Http,
}

impl ErrorKind {
    pub(crate) const COUNT: usize = 9;
    pub(crate) const ALL: [Self; Self::COUNT] = [
        Self::Accept,
        Self::ConnectionSetup,
        Self::TlsHandshake,
        Self::Read,
        Self::Write,
        Self::SendQueue,
        Self::Database,
        Self::Bouncer,
        Self::Http,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Accept => 0,
            Self::ConnectionSetup => 1,
            Self::TlsHandshake => 2,
            Self::Read => 3,
            Self::Write => 4,
            Self::SendQueue => 5,
            Self::Database => 6,
            Self::Bouncer => 7,
            Self::Http => 8,
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::ConnectionSetup => "connection_setup",
            Self::TlsHandshake => "tls_handshake",
            Self::Read => "read",
            Self::Write => "write",
            Self::SendQueue => "send_queue",
            Self::Database => "database",
            Self::Bouncer => "bouncer",
            Self::Http => "http",
        }
    }
}

struct LatencyHistogram {
    buckets: [AtomicU64; LATENCY_BUCKETS_US.len()],
    count: AtomicU64,
    sum_us: AtomicU64,
    max_us: AtomicU64,
}

impl LatencyHistogram {
    fn new() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            count: AtomicU64::new(0),
            sum_us: AtomicU64::new(0),
            max_us: AtomicU64::new(0),
        }
    }

    fn observe(&self, elapsed: Duration) {
        let micros = elapsed.as_micros().min(u64::MAX as u128) as u64;
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_us.fetch_add(micros, Ordering::Relaxed);
        self.max_us.fetch_max(micros, Ordering::Relaxed);
        for (upper, bucket) in LATENCY_BUCKETS_US.iter().zip(&self.buckets) {
            if micros <= *upper {
                bucket.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn snapshot(&self) -> LatencySnapshot {
        let count = self.count.load(Ordering::Relaxed);
        let max_us = self.max_us.load(Ordering::Relaxed);
        let buckets: Vec<u64> = self
            .buckets
            .iter()
            .map(|bucket| bucket.load(Ordering::Relaxed))
            .collect();
        LatencySnapshot {
            count,
            sum_us: self.sum_us.load(Ordering::Relaxed),
            max_us,
            p50_us: percentile(&buckets, count, 50, max_us),
            p95_us: percentile(&buckets, count, 95, max_us),
            p99_us: percentile(&buckets, count, 99, max_us),
            buckets,
        }
    }
}

fn percentile(buckets: &[u64], count: u64, percent: u64, max_us: u64) -> u64 {
    if count == 0 {
        return 0;
    }
    let wanted = count.saturating_mul(percent).div_ceil(100);
    buckets
        .iter()
        .position(|seen| *seen >= wanted)
        .map(|index| {
            let upper = LATENCY_BUCKETS_US[index];
            if upper == u64::MAX { max_us } else { upper }
        })
        .unwrap_or(max_us)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct LatencySnapshot {
    pub count: u64,
    pub sum_us: u64,
    pub max_us: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    #[serde(skip)]
    buckets: Vec<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Snapshot {
    pub schema_version: u32,
    pub sampled_at_ms: u64,
    pub uptime_seconds: u64,
    pub core_heartbeat_age_ms: u64,
    pub active_connections: u64,
    pub registered_connections: u64,
    pub unregistered_connections: u64,
    pub channels: u64,
    pub connections_opened_total: u64,
    pub connections_closed_total: u64,
    pub connections_rejected_total: u64,
    pub irc_lines_in_total: u64,
    pub irc_bytes_in_total: u64,
    pub irc_lines_out_total: u64,
    pub irc_bytes_out_total: u64,
    pub bnc_lines_in_total: u64,
    pub bnc_bytes_in_total: u64,
    pub bnc_lines_out_total: u64,
    pub bnc_bytes_out_total: u64,
    pub bnc_client_connections: u64,
    pub bnc_client_connections_opened_total: u64,
    pub sendq_kills_total: u64,
    pub http_requests_total: u64,
    pub http_server_errors_total: u64,
    pub database_requests_total: u64,
    pub bnc_networks: u64,
    pub bnc_connected: u64,
    #[serde(default)]
    pub queues: BTreeMap<String, QueueSnapshot>,
    pub errors: BTreeMap<String, u64>,
    pub error_last_seen_ms: BTreeMap<String, u64>,
    pub core_latency: LatencySnapshot,
    pub database_latency: LatencySnapshot,
    pub http_latency: LatencySnapshot,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct QueueSnapshot {
    pub depth: u64,
    pub capacity: u64,
    pub mode: QueueMode,
    pub mode_switches: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum QueueMode {
    Fifo,
    Lifo,
}

impl QueueMode {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Fifo => "fifo",
            Self::Lifo => "lifo",
        }
    }
}

pub(crate) struct Telemetry {
    started: Instant,
    queue_monitors: Vec<e6irc_queue::QueueMonitor>,
    active_connections: AtomicU64,
    registered_connections: AtomicU64,
    unregistered_connections: AtomicU64,
    channels: AtomicU64,
    connections_opened_total: AtomicU64,
    connections_closed_total: AtomicU64,
    connections_rejected_total: AtomicU64,
    irc_lines_in_total: AtomicU64,
    irc_bytes_in_total: AtomicU64,
    irc_lines_out_total: AtomicU64,
    irc_bytes_out_total: AtomicU64,
    bnc_lines_in_total: AtomicU64,
    bnc_bytes_in_total: AtomicU64,
    bnc_lines_out_total: AtomicU64,
    bnc_bytes_out_total: AtomicU64,
    bnc_client_connections: AtomicU64,
    bnc_client_connections_opened_total: AtomicU64,
    sendq_kills_total: AtomicU64,
    http_requests_total: AtomicU64,
    http_server_errors_total: AtomicU64,
    database_requests_total: AtomicU64,
    core_seen: AtomicBool,
    core_heartbeat_elapsed_ms: AtomicU64,
    errors: [AtomicU64; ErrorKind::COUNT],
    error_last_seen_ms: [AtomicU64; ErrorKind::COUNT],
    latency: [LatencyHistogram; LatencyKind::COUNT],
}

pub(crate) struct BncClientConnection {
    telemetry: std::sync::Arc<Telemetry>,
}

impl Drop for BncClientConnection {
    fn drop(&mut self) {
        self.telemetry
            .bnc_client_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

impl Telemetry {
    pub(crate) fn new() -> Self {
        Self {
            started: Instant::now(),
            queue_monitors: Vec::new(),
            active_connections: AtomicU64::new(0),
            registered_connections: AtomicU64::new(0),
            unregistered_connections: AtomicU64::new(0),
            channels: AtomicU64::new(0),
            connections_opened_total: AtomicU64::new(0),
            connections_closed_total: AtomicU64::new(0),
            connections_rejected_total: AtomicU64::new(0),
            irc_lines_in_total: AtomicU64::new(0),
            irc_bytes_in_total: AtomicU64::new(0),
            irc_lines_out_total: AtomicU64::new(0),
            irc_bytes_out_total: AtomicU64::new(0),
            bnc_lines_in_total: AtomicU64::new(0),
            bnc_bytes_in_total: AtomicU64::new(0),
            bnc_lines_out_total: AtomicU64::new(0),
            bnc_bytes_out_total: AtomicU64::new(0),
            bnc_client_connections: AtomicU64::new(0),
            bnc_client_connections_opened_total: AtomicU64::new(0),
            sendq_kills_total: AtomicU64::new(0),
            http_requests_total: AtomicU64::new(0),
            http_server_errors_total: AtomicU64::new(0),
            database_requests_total: AtomicU64::new(0),
            core_seen: AtomicBool::new(false),
            core_heartbeat_elapsed_ms: AtomicU64::new(0),
            errors: std::array::from_fn(|_| AtomicU64::new(0)),
            error_last_seen_ms: std::array::from_fn(|_| AtomicU64::new(0)),
            latency: std::array::from_fn(|_| LatencyHistogram::new()),
        }
    }

    pub(crate) fn observing_queues(
        core: impl IntoIterator<Item = e6irc_queue::QueueMonitor>,
        database: e6irc_queue::QueueMonitor,
    ) -> Self {
        let mut telemetry = Self::new();
        telemetry.queue_monitors = core.into_iter().collect();
        telemetry.queue_monitors.push(database);
        telemetry
    }

    pub(crate) fn record_connection_opened(&self) {
        self.connections_opened_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_connections_closed(&self, count: usize) {
        self.connections_closed_total
            .fetch_add(count as u64, Ordering::Relaxed);
    }

    pub(crate) fn record_connection_rejected(&self) {
        self.connections_rejected_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_irc_input(&self, bytes: usize) {
        self.irc_lines_in_total.fetch_add(1, Ordering::Relaxed);
        self.irc_bytes_in_total
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(crate) fn record_irc_output(&self, bytes: usize) {
        self.irc_lines_out_total.fetch_add(1, Ordering::Relaxed);
        self.irc_bytes_out_total
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(crate) fn record_bnc_input(&self, bytes: usize) {
        self.bnc_lines_in_total.fetch_add(1, Ordering::Relaxed);
        self.bnc_bytes_in_total
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(crate) fn record_bnc_output(&self, bytes: usize) {
        self.bnc_lines_out_total.fetch_add(1, Ordering::Relaxed);
        self.bnc_bytes_out_total
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(crate) fn observe_bnc_client(self: &std::sync::Arc<Self>) -> BncClientConnection {
        self.bnc_client_connections.fetch_add(1, Ordering::Relaxed);
        self.bnc_client_connections_opened_total
            .fetch_add(1, Ordering::Relaxed);
        BncClientConnection {
            telemetry: self.clone(),
        }
    }

    pub(crate) fn record_sendq_kill(&self) {
        self.sendq_kills_total.fetch_add(1, Ordering::Relaxed);
        self.record_error(ErrorKind::SendQueue);
    }

    pub(crate) fn record_database_request(&self, elapsed: Duration) {
        self.database_requests_total.fetch_add(1, Ordering::Relaxed);
        self.observe_latency(LatencyKind::Database, elapsed);
    }

    pub(crate) fn record_http_request(&self, elapsed: Duration, server_error: bool) {
        self.http_requests_total.fetch_add(1, Ordering::Relaxed);
        self.observe_latency(LatencyKind::Http, elapsed);
        if server_error {
            self.http_server_errors_total
                .fetch_add(1, Ordering::Relaxed);
            self.record_error(ErrorKind::Http);
        }
    }

    pub(crate) fn observe_latency(&self, kind: LatencyKind, elapsed: Duration) {
        self.latency[kind.index()].observe(elapsed);
    }

    pub(crate) fn record_error(&self, kind: ErrorKind) {
        self.errors[kind.index()].fetch_add(1, Ordering::Relaxed);
        self.error_last_seen_ms[kind.index()].store(epoch_millis(), Ordering::Relaxed);
    }

    pub(crate) fn adjust_core_gauges(
        &self,
        previous: (usize, usize, usize),
        current: (usize, usize, usize),
    ) {
        adjust_gauge(&self.active_connections, previous.0, current.0);
        adjust_gauge(&self.registered_connections, previous.1, current.1);
        adjust_gauge(&self.channels, previous.2, current.2);
        let previous_unregistered = previous.0.saturating_sub(previous.1);
        let current_unregistered = current.0.saturating_sub(current.1);
        adjust_gauge(
            &self.unregistered_connections,
            previous_unregistered,
            current_unregistered,
        );
        self.core_seen.store(true, Ordering::Relaxed);
        self.core_heartbeat_elapsed_ms.store(
            self.started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
    }

    pub(crate) fn core_is_fresh(&self, maximum_age: Duration) -> bool {
        if !self.core_seen.load(Ordering::Relaxed) {
            return false;
        }
        let now = self.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        now.saturating_sub(self.core_heartbeat_elapsed_ms.load(Ordering::Relaxed))
            <= maximum_age.as_millis().min(u64::MAX as u128) as u64
    }

    pub(crate) fn snapshot(&self, bnc_networks: u64, bnc_connected: u64) -> Snapshot {
        let elapsed_ms = self.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        let errors = ErrorKind::ALL
            .into_iter()
            .map(|kind| {
                (
                    kind.label().to_string(),
                    self.errors[kind.index()].load(Ordering::Relaxed),
                )
            })
            .collect();
        let error_last_seen_ms = ErrorKind::ALL
            .into_iter()
            .map(|kind| {
                (
                    kind.label().to_string(),
                    self.error_last_seen_ms[kind.index()].load(Ordering::Relaxed),
                )
            })
            .collect();
        let queues = self
            .queue_monitors
            .iter()
            .map(|monitor| {
                let snapshot = monitor.snapshot();
                (
                    snapshot.name.to_string(),
                    QueueSnapshot {
                        depth: snapshot.depth as u64,
                        capacity: snapshot.capacity as u64,
                        mode: match snapshot.mode {
                            e6irc_queue::Mode::Fifo => QueueMode::Fifo,
                            e6irc_queue::Mode::Lifo => QueueMode::Lifo,
                        },
                        mode_switches: snapshot.mode_switches,
                    },
                )
            })
            .collect();
        Snapshot {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            sampled_at_ms: epoch_millis(),
            uptime_seconds: elapsed_ms / 1000,
            core_heartbeat_age_ms: elapsed_ms
                .saturating_sub(self.core_heartbeat_elapsed_ms.load(Ordering::Relaxed)),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            registered_connections: self.registered_connections.load(Ordering::Relaxed),
            unregistered_connections: self.unregistered_connections.load(Ordering::Relaxed),
            channels: self.channels.load(Ordering::Relaxed),
            connections_opened_total: self.connections_opened_total.load(Ordering::Relaxed),
            connections_closed_total: self.connections_closed_total.load(Ordering::Relaxed),
            connections_rejected_total: self.connections_rejected_total.load(Ordering::Relaxed),
            irc_lines_in_total: self.irc_lines_in_total.load(Ordering::Relaxed),
            irc_bytes_in_total: self.irc_bytes_in_total.load(Ordering::Relaxed),
            irc_lines_out_total: self.irc_lines_out_total.load(Ordering::Relaxed),
            irc_bytes_out_total: self.irc_bytes_out_total.load(Ordering::Relaxed),
            bnc_lines_in_total: self.bnc_lines_in_total.load(Ordering::Relaxed),
            bnc_bytes_in_total: self.bnc_bytes_in_total.load(Ordering::Relaxed),
            bnc_lines_out_total: self.bnc_lines_out_total.load(Ordering::Relaxed),
            bnc_bytes_out_total: self.bnc_bytes_out_total.load(Ordering::Relaxed),
            bnc_client_connections: self.bnc_client_connections.load(Ordering::Relaxed),
            bnc_client_connections_opened_total: self
                .bnc_client_connections_opened_total
                .load(Ordering::Relaxed),
            sendq_kills_total: self.sendq_kills_total.load(Ordering::Relaxed),
            http_requests_total: self.http_requests_total.load(Ordering::Relaxed),
            http_server_errors_total: self.http_server_errors_total.load(Ordering::Relaxed),
            database_requests_total: self.database_requests_total.load(Ordering::Relaxed),
            bnc_networks,
            bnc_connected,
            queues,
            errors,
            error_last_seen_ms,
            core_latency: self.latency[LatencyKind::Core.index()].snapshot(),
            database_latency: self.latency[LatencyKind::Database.index()].snapshot(),
            http_latency: self.latency[LatencyKind::Http.index()].snapshot(),
        }
    }

    pub(crate) fn prometheus(&self, bnc_networks: u64, bnc_connected: u64) -> String {
        let snapshot = self.snapshot(bnc_networks, bnc_connected);
        let mut out = String::new();
        // Build identity as an info gauge, so a scraped fleet can answer
        // "which version/revision is running where" without a side channel.
        out.push_str(
            "# HELP e6irc_build_info Build and revision of the running binary.\n\
             # TYPE e6irc_build_info gauge\n",
        );
        out.push_str(&format!(
            "e6irc_build_info{{version=\"{}\",revision=\"{}\"}} 1\n",
            env!("CARGO_PKG_VERSION"),
            option_env!("E6IRC_BUILD_REVISION").unwrap_or("unknown"),
        ));
        one_metric(
            &mut out,
            "e6irc_uptime_seconds",
            "Process uptime in seconds.",
            "gauge",
            snapshot.uptime_seconds,
        );
        state_gauge(
            &mut out,
            "e6irc_connections",
            "Current IRC connections by registration state.",
            &[
                ("registered", snapshot.registered_connections),
                ("unregistered", snapshot.unregistered_connections),
            ],
        );
        one_metric(
            &mut out,
            "e6irc_channels",
            "Current live IRC channels.",
            "gauge",
            snapshot.channels,
        );
        for (name, help, value) in [
            (
                "e6irc_connections_opened_total",
                "IRC sessions opened since process start.",
                snapshot.connections_opened_total,
            ),
            (
                "e6irc_connections_closed_total",
                "IRC sessions closed since process start.",
                snapshot.connections_closed_total,
            ),
            (
                "e6irc_connections_rejected_total",
                "Connections refused by admission limits.",
                snapshot.connections_rejected_total,
            ),
            (
                "e6irc_irc_lines_in_total",
                "Complete IRC lines received.",
                snapshot.irc_lines_in_total,
            ),
            (
                "e6irc_irc_bytes_in_total",
                "IRC line payload bytes received.",
                snapshot.irc_bytes_in_total,
            ),
            (
                "e6irc_irc_lines_out_total",
                "IRC lines admitted to client send queues.",
                snapshot.irc_lines_out_total,
            ),
            (
                "e6irc_irc_bytes_out_total",
                "IRC line payload bytes admitted to client send queues.",
                snapshot.irc_bytes_out_total,
            ),
            (
                "e6irc_bnc_lines_in_total",
                "Complete lines received from BNC upstreams.",
                snapshot.bnc_lines_in_total,
            ),
            (
                "e6irc_bnc_bytes_in_total",
                "Line bytes received from BNC upstreams.",
                snapshot.bnc_bytes_in_total,
            ),
            (
                "e6irc_bnc_lines_out_total",
                "Lines admitted to BNC upstream command queues.",
                snapshot.bnc_lines_out_total,
            ),
            (
                "e6irc_bnc_bytes_out_total",
                "Line bytes admitted to BNC upstream command queues.",
                snapshot.bnc_bytes_out_total,
            ),
            (
                "e6irc_bnc_client_connections_opened_total",
                "Authenticated raw IRC and web BNC attachments opened since process start.",
                snapshot.bnc_client_connections_opened_total,
            ),
            (
                "e6irc_sendq_kills_total",
                "Connections terminated after their send queue filled.",
                snapshot.sendq_kills_total,
            ),
            (
                "e6irc_http_requests_total",
                "HTTP requests completed.",
                snapshot.http_requests_total,
            ),
            (
                "e6irc_http_server_errors_total",
                "HTTP responses with a 5xx status.",
                snapshot.http_server_errors_total,
            ),
            (
                "e6irc_database_requests_total",
                "Measured database operations completed.",
                snapshot.database_requests_total,
            ),
        ] {
            one_metric(&mut out, name, help, "counter", value);
        }
        state_gauge(
            &mut out,
            "e6irc_bnc_networks",
            "Configured live BNC drivers by connection state.",
            &[
                ("connected", bnc_connected),
                ("disconnected", bnc_networks.saturating_sub(bnc_connected)),
            ],
        );
        one_metric(
            &mut out,
            "e6irc_bnc_client_connections",
            "Current authenticated raw IRC and web BNC attachments.",
            "gauge",
            snapshot.bnc_client_connections,
        );
        render_queues(&mut out, &snapshot.queues);
        out.push_str("# HELP e6irc_errors_total Operational errors by fixed subsystem.\n");
        out.push_str("# TYPE e6irc_errors_total counter\n");
        for kind in ErrorKind::ALL {
            let value = snapshot.errors.get(kind.label()).copied().unwrap_or(0);
            out.push_str(&format!(
                "e6irc_errors_total{{kind=\"{}\"}} {value}\n",
                kind.label()
            ));
        }
        for (kind, latency) in [
            (LatencyKind::Core, &snapshot.core_latency),
            (LatencyKind::Database, &snapshot.database_latency),
            (LatencyKind::Http, &snapshot.http_latency),
        ] {
            render_histogram(&mut out, kind, latency);
        }
        out
    }
}

fn adjust_gauge(gauge: &AtomicU64, previous: usize, current: usize) {
    if current >= previous {
        gauge.fetch_add((current - previous) as u64, Ordering::Relaxed);
    } else {
        gauge.fetch_sub((previous - current) as u64, Ordering::Relaxed);
    }
}

fn render_queues(out: &mut String, queues: &BTreeMap<String, QueueSnapshot>) {
    out.push_str("# HELP e6irc_queue_depth Events currently waiting in a runtime queue.\n");
    out.push_str("# TYPE e6irc_queue_depth gauge\n");
    out.push_str("# HELP e6irc_queue_capacity Maximum events accepted by a runtime queue.\n");
    out.push_str("# TYPE e6irc_queue_capacity gauge\n");
    out.push_str("# HELP e6irc_queue_mode Current runtime queue delivery mode.\n");
    out.push_str("# TYPE e6irc_queue_mode gauge\n");
    out.push_str("# HELP e6irc_queue_mode_switches_total Runtime queue FIFO/LIFO transitions.\n");
    out.push_str("# TYPE e6irc_queue_mode_switches_total counter\n");
    for (name, queue) in queues {
        out.push_str(&format!(
            "e6irc_queue_depth{{queue=\"{name}\"}} {}\n",
            queue.depth
        ));
        out.push_str(&format!(
            "e6irc_queue_capacity{{queue=\"{name}\"}} {}\n",
            queue.capacity
        ));
        for mode in [QueueMode::Fifo, QueueMode::Lifo] {
            out.push_str(&format!(
                "e6irc_queue_mode{{queue=\"{name}\",mode=\"{}\"}} {}\n",
                mode.label(),
                u8::from(queue.mode == mode)
            ));
        }
        out.push_str(&format!(
            "e6irc_queue_mode_switches_total{{queue=\"{name}\"}} {}\n",
            queue.mode_switches
        ));
    }
}

pub(crate) async fn run_sampler(
    pool: sqlx::PgPool,
    telemetry: std::sync::Arc<Telemetry>,
    registry: Option<std::sync::Arc<crate::bouncer::Registry>>,
    settings: std::sync::Arc<tokio::sync::RwLock<crate::db::ManagedConfigSnapshot>>,
) {
    let mut last_sample = Instant::now();
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let config = settings.read().await.settings.observability.clone();
        if !config.enabled {
            last_sample = Instant::now();
            continue;
        }
        if last_sample.elapsed() < Duration::from_secs(config.sample_interval_seconds) {
            continue;
        }
        let (networks, connected) = registry
            .as_ref()
            .map(|registry| {
                let statuses = registry.list();
                (
                    statuses.len() as u64,
                    statuses.iter().filter(|network| network.connected).count() as u64,
                )
            })
            .unwrap_or_default();
        let snapshot = telemetry.snapshot(networks, connected);
        let started = Instant::now();
        if let Err(error) =
            crate::db::store_observability_sample(&pool, &snapshot, config.retention_hours).await
        {
            telemetry.record_error(ErrorKind::Database);
            eprintln!("observability sample persistence failed: {error}");
        }
        telemetry.record_database_request(started.elapsed());
        last_sample = Instant::now();
    }
}

/// Supervised database hygiene independent of whether historical monitoring is
/// enabled. A fixed cadence plus bounded per-table batches prevents both
/// expired credentials and durable history/audit data from growing forever,
/// while the next tick makes saturation self-draining without a tight loop.
pub(crate) async fn run_storage_maintenance(
    pool: sqlx::PgPool,
    telemetry: std::sync::Arc<Telemetry>,
    settings: std::sync::Arc<tokio::sync::RwLock<crate::db::ManagedConfigSnapshot>>,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(300));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // `interval`'s first tick is immediate. Consume it so startup never races
    // migrations, listener binding, or the first operator request with a
    // six-table maintenance transaction.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let storage = settings.read().await.settings.storage.clone();
        let started = Instant::now();
        match crate::db::run_storage_maintenance(
            &pool,
            storage.history_retention_days,
            storage.audit_retention_days,
        )
        .await
        {
            Ok(report) if report.saturated => {
                eprintln!(
                    "storage maintenance filled a bounded batch \
                     (messages={}, audit_events={}, web_sessions={}, api_tokens={}, \
                     device_grants={}, logout_tokens={}, account_invitations={}); expired rows remain eligible \
                     for the next cycle",
                    report.messages,
                    report.audit_events,
                    report.web_sessions,
                    report.api_tokens,
                    report.device_grants,
                    report.logout_tokens,
                    report.account_invitations,
                );
            }
            Ok(_report) => {}
            Err(error) => {
                telemetry.record_error(ErrorKind::Database);
                eprintln!("storage maintenance failed: {error}");
            }
        }
        telemetry.record_database_request(started.elapsed());
    }
}

impl Default for Telemetry {
    fn default() -> Self {
        Self::new()
    }
}

fn epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn one_metric(out: &mut String, name: &str, help: &str, kind: &str, value: u64) {
    out.push_str(&format!(
        "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
    ));
}

fn state_gauge(out: &mut String, name: &str, help: &str, values: &[(&str, u64)]) {
    out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} gauge\n"));
    for (state, value) in values {
        out.push_str(&format!("{name}{{state=\"{state}\"}} {value}\n"));
    }
}

fn render_histogram(out: &mut String, kind: LatencyKind, latency: &LatencySnapshot) {
    let name = format!("e6irc_{}_latency_seconds", kind.label());
    out.push_str(&format!(
        "# HELP {name} End-to-end {} operation latency in seconds.\n# TYPE {name} histogram\n",
        kind.label()
    ));
    for (upper, count) in LATENCY_BUCKETS_US.iter().zip(&latency.buckets) {
        if *upper == u64::MAX {
            out.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {count}\n"));
        } else {
            out.push_str(&format!(
                "{name}_bucket{{le=\"{}\"}} {count}\n",
                *upper as f64 / 1_000_000.0
            ));
        }
    }
    out.push_str(&format!(
        "{name}_sum {}\n{name}_count {}\n",
        latency.sum_us as f64 / 1_000_000.0,
        latency.count
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_has_fixed_errors_and_latency_percentiles() {
        let telemetry = Telemetry::new();
        telemetry.record_connection_opened();
        telemetry.record_irc_input(42);
        telemetry.record_error(ErrorKind::Read);
        telemetry.observe_latency(LatencyKind::Core, Duration::from_micros(900));
        telemetry.observe_latency(LatencyKind::Core, Duration::from_micros(4_000));
        telemetry.adjust_core_gauges((0, 0, 0), (3, 2, 1));

        let snapshot = telemetry.snapshot(4, 3);
        assert_eq!(snapshot.schema_version, SNAPSHOT_SCHEMA_VERSION);
        assert_eq!(snapshot.active_connections, 3);
        assert_eq!(snapshot.registered_connections, 2);
        assert_eq!(snapshot.irc_bytes_in_total, 42);
        assert_eq!(snapshot.errors["read"], 1);
        assert_eq!(snapshot.errors.len(), ErrorKind::COUNT);
        assert_eq!(snapshot.core_latency.count, 2);
        assert_eq!(snapshot.core_latency.p50_us, 1_000);
        assert_eq!(snapshot.core_latency.p95_us, 5_000);
    }

    #[test]
    fn latency_above_the_last_finite_bucket_uses_the_observed_maximum() {
        let telemetry = Telemetry::new();
        telemetry.observe_latency(LatencyKind::Http, Duration::from_secs(7));

        let snapshot = telemetry.snapshot(0, 0);
        assert_eq!(snapshot.http_latency.max_us, 7_000_000);
        assert_eq!(snapshot.http_latency.p99_us, 7_000_000);
    }

    #[test]
    fn prometheus_output_has_bounded_labels_and_histograms() {
        let telemetry = Telemetry::new();
        telemetry.record_http_request(Duration::from_millis(12), true);
        let output = telemetry.prometheus(2, 1);
        assert!(output.contains("e6irc_connections{state=\"registered\"}"));
        assert!(output.contains("e6irc_errors_total{kind=\"http\"} 1"));
        assert!(output.contains("e6irc_http_latency_seconds_bucket{le=\"+Inf\"} 1"));
    }

    #[test]
    fn queue_pressure_reaches_snapshots_and_prometheus() {
        let (core_tx, _core_rx) = e6irc_queue::queue::<u8>(e6irc_queue::Config {
            name: "core",
            capacity: 4,
            policy: e6irc_queue::Policy::Fifo,
        });
        let (database_tx, _database_rx) = e6irc_queue::queue::<u8>(e6irc_queue::Config {
            name: "db",
            capacity: 8,
            policy: e6irc_queue::Policy::Fifo,
        });
        let telemetry = Telemetry::observing_queues([core_tx.monitor()], database_tx.monitor());
        core_tx.try_push(1).unwrap();
        core_tx.try_push(2).unwrap();

        let snapshot = telemetry.snapshot(0, 0);
        assert_eq!(snapshot.queues["core"].depth, 2);
        assert_eq!(snapshot.queues["core"].capacity, 4);
        assert_eq!(snapshot.queues["core"].mode, QueueMode::Fifo);
        assert_eq!(snapshot.queues["db"].depth, 0);

        let output = telemetry.prometheus(0, 0);
        assert!(output.contains("e6irc_queue_depth{queue=\"core\"} 2"));
        assert!(output.contains("e6irc_queue_capacity{queue=\"db\"} 8"));
        assert!(output.contains("e6irc_queue_mode{queue=\"core\",mode=\"fifo\"} 1"));
        assert!(output.contains("e6irc_queue_mode_switches_total{queue=\"core\"} 0"));
    }

    #[test]
    fn version_two_history_without_queue_data_remains_readable() {
        let mut encoded = serde_json::to_value(Telemetry::new().snapshot(0, 0)).unwrap();
        let object = encoded.as_object_mut().unwrap();
        object.insert("schema_version".into(), 2.into());
        object.remove("queues");

        let decoded: Snapshot = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded.schema_version, 2);
        assert!(decoded.queues.is_empty());
    }

    #[test]
    fn readiness_requires_a_core_heartbeat() {
        let telemetry = Telemetry::new();
        assert!(!telemetry.core_is_fresh(Duration::from_secs(45)));
        telemetry.adjust_core_gauges((0, 0, 0), (0, 0, 0));
        assert!(telemetry.core_is_fresh(Duration::from_secs(45)));
    }

    #[test]
    fn bouncer_handle_records_both_traffic_directions() {
        let telemetry = std::sync::Arc::new(Telemetry::new());
        let (handle, ends) = crate::bouncer::NetworkHandle::channels(8);
        handle.set_telemetry(telemetry.clone());
        ends.emit_line(":upstream NOTICE * :hello".into());
        assert_eq!(
            handle.send("PING :token"),
            crate::bouncer::SendOutcome::Sent
        );
        let snapshot = telemetry.snapshot(1, 1);
        assert_eq!(snapshot.bnc_lines_in_total, 1);
        assert_eq!(snapshot.bnc_lines_out_total, 1);
        assert!(snapshot.bnc_bytes_in_total > snapshot.bnc_bytes_out_total);

        let attachment = handle.track_attachment();
        let snapshot = telemetry.snapshot(1, 1);
        assert_eq!(snapshot.bnc_client_connections, 1);
        assert_eq!(snapshot.bnc_client_connections_opened_total, 1);
        drop(attachment);
        let snapshot = telemetry.snapshot(1, 1);
        assert_eq!(snapshot.bnc_client_connections, 0);
        assert_eq!(snapshot.bnc_client_connections_opened_total, 1);
    }
}
