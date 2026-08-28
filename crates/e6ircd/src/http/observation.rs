// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deployment-neutral application monitoring for Shauth and other operators.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::{AppState, bnc_counts, database_is_ready, json_no_store, no_store, problem};

const SCHEMA_VERSION: &str = "e6qu.monitoring/v2";

#[derive(Serialize)]
struct Observation {
    schema_version: &'static str,
    observed_at: String,
    resources: Vec<Resource>,
}

#[derive(Serialize)]
struct Resource {
    id: &'static str,
    name: &'static str,
    kind: &'static str,
    health: &'static str,
    metrics: Vec<Metric>,
}

#[derive(Serialize)]
struct Metric {
    name: &'static str,
    label: &'static str,
    value: f64,
    unit: &'static str,
    status: &'static str,
}

fn metric(name: &'static str, label: &'static str, value: u64, unit: &'static str) -> Metric {
    Metric {
        name,
        label,
        value: value as f64,
        unit,
        status: "available",
    }
}

fn authorized(headers: &HeaderMap, expected: Option<&[u8; 32]>) -> bool {
    let Some(expected) = expected else {
        return false;
    };
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return false;
    };
    let actual = super::bootstrap_token_digest(token);
    aws_lc_rs::constant_time::verify_slices_are_equal(expected, &actual).is_ok()
}

fn unauthorized() -> Response {
    let mut response = (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        "Bearer realm=\"e6irc-monitoring\""
            .parse()
            .expect("static authentication challenge"),
    );
    no_store(response.headers_mut());
    response
}

fn unavailable(title: &str) -> Response {
    let mut response = problem(StatusCode::SERVICE_UNAVAILABLE, title, None);
    no_store(response.headers_mut());
    response
}

pub(super) async fn application_observation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if !authorized(&headers, state.monitoring_token_digest.as_ref()) {
        return unauthorized();
    }

    let core_ready = state.telemetry.core_is_fresh(Duration::from_secs(45));
    let database_ready = match &state.pool {
        Some(pool) => {
            let started = Instant::now();
            let ready = database_is_ready(pool).await;
            state.telemetry.record_database_request(started.elapsed());
            if !ready {
                state
                    .telemetry
                    .record_error(crate::observability::ErrorKind::Database);
            }
            ready
        }
        None => true,
    };
    let (networks, connected) = bnc_counts(&state);
    let snapshot = state.telemetry.snapshot(networks, connected);
    let queue_depth = snapshot.queues.values().map(|queue| queue.depth).sum();
    let queue_capacity = snapshot.queues.values().map(|queue| queue.capacity).sum();
    let observed_at = match OffsetDateTime::now_utc().format(&Rfc3339) {
        Ok(observed_at) => observed_at,
        Err(error) => {
            eprintln!("monitoring observation timestamp failed: {error}");
            return unavailable("Monitoring observation unavailable");
        }
    };

    json_no_store(Observation {
        schema_version: SCHEMA_VERSION,
        observed_at,
        resources: vec![Resource {
            id: "e6irc-process",
            name: "e6irc",
            kind: "application",
            health: if core_ready && database_ready {
                "healthy"
            } else {
                "unhealthy"
            },
            metrics: vec![
                metric(
                    "connections.active",
                    "Active IRC connections",
                    snapshot.active_connections,
                    "connections",
                ),
                metric(
                    "connections.registered",
                    "Registered IRC connections",
                    snapshot.registered_connections,
                    "connections",
                ),
                metric(
                    "channels.active",
                    "Active channels",
                    snapshot.channels,
                    "channels",
                ),
                metric(
                    "bnc.clients",
                    "Attached BNC clients",
                    snapshot.bnc_client_connections,
                    "connections",
                ),
                metric(
                    "bnc.networks",
                    "Configured BNC networks",
                    snapshot.bnc_networks,
                    "networks",
                ),
                metric(
                    "bnc.connected",
                    "Connected BNC networks",
                    snapshot.bnc_connected,
                    "networks",
                ),
                metric(
                    "queues.depth",
                    "Queued operations",
                    queue_depth,
                    "operations",
                ),
                metric(
                    "queues.capacity",
                    "Queue capacity",
                    queue_capacity,
                    "operations",
                ),
                metric(
                    "errors.total",
                    "Recorded operational errors",
                    snapshot.errors.values().sum(),
                    "errors",
                ),
                metric(
                    "uptime",
                    "Process uptime",
                    snapshot.uptime_seconds,
                    "seconds",
                ),
            ],
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monitoring_bearer_is_exact_and_constant_time_checked() {
        let token = "0123456789abcdef0123456789abcdef";
        let expected = super::super::bootstrap_token_digest(token);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        assert!(authorized(&headers, Some(&expected)));

        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}x").parse().unwrap(),
        );
        assert!(!authorized(&headers, Some(&expected)));
        assert!(!authorized(&HeaderMap::new(), Some(&expected)));
        assert!(!authorized(&headers, None));
    }

    #[test]
    fn observation_contract_omits_fabricated_costs() {
        let encoded = serde_json::to_value(Observation {
            schema_version: SCHEMA_VERSION,
            observed_at: "2026-08-28T00:00:00Z".into(),
            resources: vec![Resource {
                id: "e6irc-process",
                name: "e6irc",
                kind: "application",
                health: "healthy",
                metrics: vec![metric("uptime", "Process uptime", 1, "seconds")],
            }],
        })
        .unwrap();
        assert_eq!(encoded["schema_version"], "e6qu.monitoring/v2");
        assert!(encoded.get("cost_estimate").is_none());
        assert_eq!(encoded["resources"][0]["metrics"][0]["status"], "available");
    }
}
