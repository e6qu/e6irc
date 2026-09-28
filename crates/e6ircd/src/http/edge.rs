//! HTTP from an edge (DESIGN §19.1, "Plain HTTP"): the requests an edge
//! forwards over its link connections, served by the same routers the core's
//! own listeners serve, and the WebSocket upgrades the core authorizes for the
//! edge to complete.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::http::{HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use e6irc_edge::core_link::headers;

/// A WebSocket upgrade an edge asks the core to authorize: the edge
/// completes it, and opens the session under `conn`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EdgeUpgrade {
    pub(crate) conn: crate::core::ConnId,
}

/// The routers a link connection serves: the whole application, and the
/// `/ws/irc`-only one of a WebSocket IRC listener.
#[derive(Clone)]
pub(crate) struct LinkRouters {
    pub(crate) full: Router,
    pub(crate) websocket_irc: Router,
}

impl LinkRouters {
    pub(crate) fn for_state(state: &Arc<super::AppState>) -> Self {
        Self {
            full: super::router(state.clone()),
            websocket_irc: super::ws_irc_router(state.clone()),
        }
    }
}

/// The request an edge forwarded, as the routers take it: the client's
/// address as the connection's peer, and an upgrade to authorize as
/// [`EdgeUpgrade`]. `Err` is the answer to a request that did not come from
/// an edge as the link carries them.
fn from_edge(
    mut request: Request<axum::body::Body>,
) -> Result<(Request<axum::body::Body>, bool), Box<Response>> {
    let wire = request.headers_mut();
    let client = wire
        .remove(headers::CLIENT)
        .and_then(|value| value.to_str().ok()?.parse::<std::net::IpAddr>().ok());
    let upgrade = wire
        .remove(headers::UPGRADE)
        .map(|value| value.to_str().ok()?.parse::<u64>().ok());
    let websocket_irc = wire
        .remove(headers::LISTENER)
        .is_some_and(|value| value == headers::WEBSOCKET_IRC_LISTENER);
    let Some(client) = client else {
        return Err(Box::new(super::problem(
            StatusCode::BAD_REQUEST,
            "Request without its client",
            Some("A request forwarded over a core link names the client it came from."),
        )));
    };
    let extensions = request.extensions_mut();
    extensions.insert(axum::extract::ConnectInfo(SocketAddr::new(client, 0)));
    match upgrade {
        None => {}
        Some(Some(conn)) => {
            extensions.insert(EdgeUpgrade {
                conn: crate::core::ConnId(conn),
            });
        }
        Some(None) => {
            return Err(Box::new(super::problem(
                StatusCode::BAD_REQUEST,
                "Invalid upgrade identifier",
                None,
            )));
        }
    }
    Ok((request, websocket_irc))
}

/// Serve the HTTP/1.1 requests one edge link connection carries until the
/// edge closes it or its link ends (`over`).
pub(crate) async fn serve_link<S>(
    stream: S,
    routers: LinkRouters,
    over: impl Future<Output = ()> + Send + 'static,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    use tower::ServiceExt;
    let service = tower::service_fn(move |request: Request<hyper::body::Incoming>| {
        let routers = routers.clone();
        async move {
            match from_edge(request.map(axum::body::Body::new)) {
                Ok((request, true)) => routers.websocket_irc.oneshot(request).await,
                Ok((request, false)) => routers.full.oneshot(request).await,
                Err(refused) => Ok(*refused),
            }
        }
    });
    let connection = hyper::server::conn::http1::Builder::new()
        .timer(hyper_util::rt::TokioTimer::new())
        // A pooled link connection waits idle between requests; the edge,
        // which the link authenticates, decides when it is done with one.
        .header_read_timeout(None)
        .serve_connection(
            hyper_util::rt::TokioIo::new(stream),
            hyper_util::service::TowerToHyperService::new(service),
        );
    tokio::pin!(connection);
    tokio::pin!(over);
    tokio::select! {
        served = connection.as_mut() => {
            if let Err(error) = served {
                eprintln!("e6ircd: an edge's HTTP link connection failed: {error}");
            }
        }
        () = &mut over => {
            connection.as_mut().graceful_shutdown();
            drop(connection.await);
        }
    }
}

/// The answer to an upgrade the core authorized: the grant headers the edge
/// completes it by. Every value is text the core wrote — a kind, an address,
/// a transport, a subprotocol the client offered, a number — so each is a
/// valid header value; one that is not is a bug here, not a refusal.
pub(crate) fn grant_response(grant: &[(&'static str, String)]) -> Response {
    let mut response = StatusCode::OK.into_response();
    for (name, value) in grant {
        let value = HeaderValue::from_str(value)
            .unwrap_or_else(|_| panic!("the grant header {name} is written as a valid value"));
        response.headers_mut().insert(*name, value);
    }
    response
}
