//! An edge's own metrics (DESIGN §19.1, "Phase 3 as built"): what it counts,
//! served in the Prometheus text format the core serves its own in, on a
//! listener of its own (`[metrics]`), to a scraper presenting the
//! deployment's monitoring token as a Bearer credential.
//!
//! The listener is separate from the web port, whose every request belongs to
//! the core (decision D17), so a scrape never reaches the core and answers
//! while no core is linked, which is when it matters most.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode, header};
use axum::response::IntoResponse;
use e6irc_link::EdgeName;

use crate::connection::{ConnectionTasks, TransportError, TransportTelemetry};
use crate::core_link::remote::RemoteCore;
use crate::core_link::web::problem;

/// Whether a presented Bearer credential is the deployment's monitoring
/// token. The check is the embedding binary's (e6ircd's, the same one its
/// core's monitoring routes use), so the two cannot disagree.
#[derive(Clone)]
pub struct MonitoringToken(Arc<dyn Fn(&str) -> bool + Send + Sync>);

impl MonitoringToken {
    pub fn new(check: impl Fn(&str) -> bool + Send + Sync + 'static) -> Self {
        Self(Arc::new(check))
    }

    fn admits(&self, headers: &HeaderMap) -> bool {
        headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .is_some_and(|token| (self.0)(token))
    }
}

/// The transport error kinds, labelled as the core labels its own
/// (`e6irc_errors_total{kind}`).
const ERROR_KINDS: [(TransportError, &str); 6] = [
    (TransportError::Accept, "accept"),
    (TransportError::ConnectionSetup, "connection_setup"),
    (TransportError::TlsHandshake, "tls_handshake"),
    (TransportError::Read, "read"),
    (TransportError::Write, "write"),
    (TransportError::Http, "http"),
];

fn error_index(kind: TransportError) -> usize {
    match kind {
        TransportError::Accept => 0,
        TransportError::ConnectionSetup => 1,
        TransportError::TlsHandshake => 2,
        TransportError::Read => 3,
        TransportError::Write => 4,
        TransportError::Http => 5,
    }
}

/// What the edge counts: each transport error kind, connections refused by
/// the per-address limit, and links made.
#[derive(Default)]
pub struct EdgeTelemetry {
    errors: [AtomicU64; ERROR_KINDS.len()],
    rejected: AtomicU64,
    links: AtomicU64,
}

impl TransportTelemetry for EdgeTelemetry {
    fn record_error(&self, kind: TransportError) {
        self.errors[error_index(kind)].fetch_add(1, Ordering::Relaxed);
    }

    fn record_connection_rejected(&self) {
        self.rejected.fetch_add(1, Ordering::Relaxed);
    }
}

impl EdgeTelemetry {
    /// A link to a core was made.
    pub fn record_link(&self) {
        self.links.fetch_add(1, Ordering::Relaxed);
    }

    /// Each error kind's label and count, then the refused connections.
    fn counts(&self) -> ([(&'static str, u64); ERROR_KINDS.len()], u64) {
        let errors = std::array::from_fn(|index| {
            (
                ERROR_KINDS[index].1,
                self.errors[index].load(Ordering::Relaxed),
            )
        });
        (errors, self.rejected.load(Ordering::Relaxed))
    }

    /// Say, every `interval`, what failed and what was refused since the
    /// last time anything did, for an operator reading the edge's log.
    pub async fn report(self: Arc<Self>, name: EdgeName, interval: std::time::Duration) {
        let mut said = self.counts();
        let mut ticks = tokio::time::interval(interval);
        ticks.tick().await;
        loop {
            ticks.tick().await;
            let now = self.counts();
            if now == said {
                continue;
            }
            let mut parts: Vec<String> = now
                .0
                .iter()
                .zip(said.0)
                .filter(|((_, count), (_, before))| count > before)
                .map(|((label, count), (_, before))| format!("{} {label} errors", count - before))
                .collect();
            if now.1 > said.1 {
                parts.push(format!("{} connections refused by limit", now.1 - said.1));
            }
            eprintln!(
                "e6ircd edge {name}: in the last {}s: {}",
                interval.as_secs(),
                parts.join(", ")
            );
            said = now;
        }
    }
}

/// What the metrics listener reads.
pub struct EdgeMetrics {
    pub name: EdgeName,
    pub telemetry: Arc<EdgeTelemetry>,
    pub core: RemoteCore,
    pub connections: ConnectionTasks,
    pub token: MonitoringToken,
}

impl EdgeMetrics {
    pub fn router(self: Arc<Self>) -> axum::Router {
        axum::Router::new()
            .route("/metrics", axum::routing::get(serve))
            .fallback(|| async {
                problem(
                    StatusCode::NOT_FOUND,
                    "Not found",
                    "An edge's metrics listener serves /metrics only.",
                )
            })
            .with_state(self)
    }

    /// The exposition, in the core's format and naming, each series labelled
    /// with the edge's name.
    pub fn exposition(&self) -> String {
        let edge = &self.name;
        let link = self.core.current();
        let mut out = String::new();
        let mut gauge = |name: &str, help: &str, kind: &str, value: u64| {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} {kind}\n{name}{{edge=\"{edge}\"}} {value}\n"
            ));
        };
        gauge(
            "e6irc_edge_link_version",
            "The newest core-link version each linked edge speaks.",
            "gauge",
            u64::from(e6irc_link::LINK_VERSION),
        );
        gauge(
            "e6irc_edge_linked",
            "Whether the edge is linked to a core now.",
            "gauge",
            u64::from(link.is_some()),
        );
        gauge(
            "e6irc_edge_core_epoch",
            "The serving-lease epoch of the core the edge is linked to; 0 while unlinked.",
            "gauge",
            link.as_ref().map_or(0, |link| link.welcome().epoch),
        );
        gauge(
            "e6irc_edge_links_total",
            "Links the edge has made to a core.",
            "counter",
            self.telemetry.links.load(Ordering::Relaxed),
        );
        gauge(
            "e6irc_edge_connections",
            "Client connections the edge holds: IRC, WebSocket and attach.",
            "gauge",
            self.connections.live() as u64,
        );
        let (errors, rejected) = self.telemetry.counts();
        gauge(
            "e6irc_connections_rejected_total",
            "Connections refused by admission limits.",
            "counter",
            rejected,
        );
        out.push_str(
            "# HELP e6irc_errors_total Operational errors by fixed subsystem.\n\
             # TYPE e6irc_errors_total counter\n",
        );
        for (kind, count) in errors {
            out.push_str(&format!(
                "e6irc_errors_total{{edge=\"{edge}\",kind=\"{kind}\"}} {count}\n"
            ));
        }
        out
    }
}

async fn serve(State(metrics): State<Arc<EdgeMetrics>>, headers: HeaderMap) -> Response<Body> {
    if !metrics.token.admits(&headers) {
        let mut response = problem(
            StatusCode::UNAUTHORIZED,
            "Monitoring token required",
            "Present the deployment's monitoring token as a Bearer credential.",
        );
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"e6irc-monitoring\""),
        );
        return response;
    }
    let mut response = metrics.exposition().into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each kind counts in the slot its label is read from.
    #[test]
    fn every_error_kind_counts_under_its_own_label() {
        let telemetry = EdgeTelemetry::default();
        for (index, (kind, _)) in ERROR_KINDS.iter().enumerate() {
            for _ in 0..=index {
                telemetry.record_error(*kind);
            }
        }
        let (errors, _) = telemetry.counts();
        for (index, (label, count)) in errors.iter().enumerate() {
            assert_eq!(*label, ERROR_KINDS[index].1);
            assert_eq!(*count, index as u64 + 1, "{label}");
        }
    }
}
