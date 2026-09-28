//! An edge's web port (DESIGN §19.1, "Plain HTTP", decision D17): the edge
//! holds the public HTTP listener, forwards every request to the core as
//! HTTP/1.1 over a pool of link connections, and completes the WebSocket
//! upgrades of `/ws/irc` and `/ws/ui` itself once the core has authorized
//! each — so the socket, its framing and its liveness are the edge's, and the
//! session reaches the core over the link like any other.
//!
//! A request that finds no core linked waits for one for at most
//! [`OPEN_WAIT`], and is then answered `503` with `Retry-After`; a request
//! whose link connection fails before the core answers is answered `502`.
//! `/healthz` is the edge's own: it answers while the edge runs, linked or
//! not, so a load balancer does not take the edge out of service for a core's
//! gap.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{ConnectInfo, FromRequestParts, State};
use axum::http::{HeaderMap, HeaderValue, Request, Response, StatusCode, header};
use axum::response::IntoResponse;
use e6irc_link::SessionKind;

use super::headers;
use super::remote::{Link, OPEN_WAIT, RemoteCore};
use crate::connection::{
    ConnectionIdAllocator, ConnectionTasks, ConnectionTransport, TransportTelemetry,
};
use crate::http::UpgradedStream;
use crate::websocket::{
    IrcSocketEnd, IrcSocketSession, MAX_IRC_WS_MESSAGE, MAX_UI_WS_MESSAGE, WsFrameMode,
};

/// Link connections kept open between requests.
const IDLE_CONNECTIONS: usize = 32;

/// The seconds a client is told to wait after a `503`.
const RETRY_AFTER_SECONDS: u64 = 5;

/// The headers that describe one hop of a connection, not the request
/// (RFC 9110 §7.6.1), and are not forwarded.
const HOP_BY_HOP: [&str; 7] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Why a request was not answered by the core.
enum ForwardError {
    /// No core was linked within the wait.
    Unavailable,
    /// The link connection failed before the core answered.
    Failed(String),
}

/// The pool of HTTP connections to the current core.
struct CoreHttp {
    core: RemoteCore,
    idle: Mutex<Vec<(usize, hyper::client::conn::http1::SendRequest<Body>)>>,
}

/// A link's identity for pooling: its address in memory, for as long as the
/// pool holds a connection of it (the pool holds the link too).
fn link_key(link: &Arc<Link>) -> usize {
    Arc::as_ptr(link) as usize
}

impl CoreHttp {
    async fn send(
        self: &Arc<Self>,
        request: Request<Body>,
    ) -> Result<Response<hyper::body::Incoming>, ForwardError> {
        let link = self
            .core
            .linked_within(OPEN_WAIT)
            .await
            .ok_or(ForwardError::Unavailable)?;
        let key = link_key(&link);
        let mut sender = match self.idle_sender(key) {
            Some(sender) => sender,
            None => {
                let connection = link.http_connection().await.map_err(ForwardError::Failed)?;
                let (sender, driver) =
                    hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(connection))
                        .await
                        .map_err(|error| ForwardError::Failed(error.to_string()))?;
                let over = link.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        driven = driver => {
                            if let Err(error) = driven {
                                eprintln!("e6ircd edge: an HTTP link connection failed: {error}");
                            }
                        }
                        () = over.over() => {}
                    }
                });
                sender
            }
        };
        let response = sender
            .send_request(request)
            .await
            .map_err(|error| ForwardError::Failed(error.to_string()))?;
        // Back to the pool once the response's body is done with.
        let pool = self.clone();
        tokio::spawn(async move {
            if sender.ready().await.is_ok() && !link.over_now() {
                pool.keep(key, sender);
            }
        });
        Ok(response)
    }

    fn idle_sender(&self, key: usize) -> Option<hyper::client::conn::http1::SendRequest<Body>> {
        let mut idle = self.idle.lock().expect("idle link connections");
        // Connections of an earlier link are no use: that core is gone.
        idle.retain(|(link, sender)| *link == key && !sender.is_closed());
        idle.pop().map(|(_, sender)| sender)
    }

    fn keep(&self, key: usize, sender: hyper::client::conn::http1::SendRequest<Body>) {
        let mut idle = self.idle.lock().expect("idle link connections");
        if idle.len() < IDLE_CONNECTIONS {
            idle.push((key, sender));
        }
    }
}

/// What an edge's web port serves with.
pub struct EdgeWeb {
    core: RemoteCore,
    http: Arc<CoreHttp>,
    ids: Arc<ConnectionIdAllocator>,
    telemetry: Arc<dyn TransportTelemetry>,
    connections: ConnectionTasks,
    /// A WebSocket IRC listener: every path is `/ws/irc` and nothing else is
    /// served.
    websocket_irc: bool,
}

impl EdgeWeb {
    pub fn new(
        core: RemoteCore,
        ids: Arc<ConnectionIdAllocator>,
        telemetry: Arc<dyn TransportTelemetry>,
        connections: ConnectionTasks,
        websocket_irc: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            http: Arc::new(CoreHttp {
                core: core.clone(),
                idle: Mutex::default(),
            }),
            core,
            ids,
            telemetry,
            connections,
            websocket_irc,
        })
    }

    /// The router the web port serves.
    pub fn router(self: &Arc<Self>) -> axum::Router {
        axum::Router::new()
            .fallback(handle)
            .with_state(self.clone())
    }
}

/// A problem document, as the core answers its own refusals.
pub(crate) fn problem(status: StatusCode, title: &str, detail: &str) -> Response<Body> {
    let body = format!(
        "{{\"type\":\"about:blank\",\"title\":{},\"status\":{},\"detail\":{}}}",
        json_string(title),
        status.as_u16(),
        json_string(detail)
    );
    let mut response = (status, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    response
}

fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            character if character.is_control() => {
                out.push_str(&format!("\\u{:04x}", u32::from(character)));
            }
            character => out.push(character),
        }
    }
    out.push('"');
    out
}

/// The request's headers as they go to the core: without the hops', without
/// any link header a client sent, with the client's address.
fn forwarded_headers(headers: &mut HeaderMap, client: SocketAddr, websocket_irc: bool) {
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
    headers::strip(headers);
    headers.insert(
        headers::CLIENT,
        HeaderValue::from_str(&crate::address::ClientIp::new(client.ip()).to_string())
            .expect("an address is a header value"),
    );
    if websocket_irc {
        headers.insert(
            headers::LISTENER,
            HeaderValue::from_static(headers::WEBSOCKET_IRC_LISTENER),
        );
    }
}

async fn handle(
    State(web): State<Arc<EdgeWeb>>,
    ConnectInfo(client): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if !web.websocket_irc && request.uri().path() == "/healthz" {
        return (StatusCode::OK, "ok").into_response();
    }
    let upgrade_path = web.websocket_irc || matches!(request.uri().path(), "/ws/irc" | "/ws/ui");
    let (mut parts, body) = request.into_parts();
    if upgrade_path {
        let upgraded = parts.extensions.get::<UpgradedStream>().cloned();
        // An upgrade the edge cannot complete goes to the core as it is, whose
        // refusal the client gets exactly as from a core it reached itself.
        if let Ok(ws) = WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
            return upgrade(&web, ws, &parts, client, upgraded).await;
        }
    }
    let mut request = Request::from_parts(parts, body);
    forwarded_headers(request.headers_mut(), client, web.websocket_irc);
    match web.http.send(request).await {
        Ok(response) => relayed(response),
        Err(error) => unanswered(&*web.telemetry, error),
    }
}

/// The core's answer as the client gets it: without any link header, which
/// is the edge's alone to read.
fn relayed(mut response: Response<hyper::body::Incoming>) -> Response<Body> {
    headers::strip(response.headers_mut());
    response.map(Body::new)
}

/// The answer to a request the core did not answer.
fn unanswered(telemetry: &dyn TransportTelemetry, error: ForwardError) -> Response<Body> {
    match error {
        ForwardError::Unavailable => {
            let mut response = problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Server unavailable",
                "The server is restarting; retry after the interval in the Retry-After header.",
            );
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(RETRY_AFTER_SECONDS));
            response
        }
        ForwardError::Failed(error) => {
            telemetry.record_error(crate::connection::TransportError::Http);
            eprintln!("e6ircd edge: a request forwarded to the core failed: {error}");
            problem(
                StatusCode::BAD_GATEWAY,
                "Bad gateway",
                "The server went away before it answered; retry the request.",
            )
        }
    }
}

/// Ask the core to authorize `ws`, and complete it when it does.
async fn upgrade(
    web: &Arc<EdgeWeb>,
    ws: WebSocketUpgrade,
    parts: &axum::http::request::Parts,
    client: SocketAddr,
    upgraded: Option<UpgradedStream>,
) -> Response<Body> {
    let conn = match web.ids.allocate() {
        Ok(conn) => conn,
        Err(error) => {
            eprintln!("e6ircd edge: WebSocket connection refused: {error}");
            web.telemetry
                .record_error(crate::connection::TransportError::ConnectionSetup);
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Connection service unavailable",
                "No connection identifier is available.",
            );
        }
    };
    let mut authorization = Request::builder()
        .method(parts.method.clone())
        .uri(parts.uri.clone())
        .body(Body::empty())
        .expect("a method and a URI make a request");
    *authorization.headers_mut() = parts.headers.clone();
    forwarded_headers(authorization.headers_mut(), client, web.websocket_irc);
    authorization
        .headers_mut()
        .insert(headers::UPGRADE, HeaderValue::from(conn.0));
    let answer = match web.http.send(authorization).await {
        Ok(answer) => answer,
        Err(error) => return unanswered(&*web.telemetry, error),
    };
    let grant = answer
        .headers()
        .get(headers::GRANT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let Some(grant) = grant else {
        // A refusal: the client gets the core's answer.
        return relayed(answer);
    };
    let text = |name: &str| {
        answer
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let task = web.connections.task();
    let stream = upgraded.and_then(|upgraded| upgraded.claim());
    match grant.as_str() {
        "irc" => {
            let (Some(address), Some(transport)) = (
                text(headers::GRANT_ADDRESS).and_then(|address| address.parse().ok()),
                text(headers::GRANT_TRANSPORT).and_then(|transport| match transport.as_str() {
                    "websocket" => Some(ConnectionTransport::WebSocket),
                    "wss" => Some(ConnectionTransport::SecureWebSocket),
                    _ => None,
                }),
            ) else {
                return malformed_grant();
            };
            let protocol = text(headers::GRANT_PROTOCOL);
            let mode = match protocol.as_deref() {
                Some("binary.ircv3.net") => WsFrameMode::Binary,
                Some("text.ircv3.net") => WsFrameMode::Text,
                _ => WsFrameMode::Auto,
            };
            let mut ws = ws
                .max_message_size(MAX_IRC_WS_MESSAGE)
                .max_frame_size(MAX_IRC_WS_MESSAGE);
            if let Some(protocol) = protocol {
                ws = ws.protocols([protocol]);
            }
            let (core, telemetry) = (web.core.clone(), web.telemetry.clone());
            let sendq_bytes = web
                .core
                .current()
                .map_or(0, |link| link.welcome().terms.sendq_bytes as usize);
            ws.on_upgrade(move |socket| async move {
                let _task = task;
                let session = IrcSocketSession {
                    conn,
                    host: crate::address::ClientIp::new(address).to_string(),
                    transport,
                    mode,
                    sendq_bytes,
                };
                let end = crate::websocket::serve_irc_socket(
                    socket,
                    session,
                    core.port(SessionKind::Irc),
                    &*telemetry,
                )
                .await;
                close_lingering(end == IrcSocketEnd::Finished, stream).await;
            })
        }
        "ui" => {
            let Some(liveness) = text(headers::GRANT_LIVENESS_MS)
                .and_then(|liveness| liveness.parse::<u64>().ok())
                .map(std::time::Duration::from_millis)
            else {
                return malformed_grant();
            };
            let core = web.core.clone();
            let transport = ConnectionTransport::WebSocket;
            let address = client.ip();
            ws.max_message_size(MAX_UI_WS_MESSAGE)
                .max_frame_size(MAX_UI_WS_MESSAGE)
                .on_upgrade(move |socket| async move {
                    let _task = task;
                    let mut socket = socket;
                    let Some((edge, inbound)) = core.open_ui(conn, address, transport).await else {
                        crate::websocket::send_close(&mut socket, 1012, "Server restarting".into())
                            .await;
                        return;
                    };
                    crate::websocket::serve_ui_socket(socket, edge, inbound, liveness).await;
                    close_lingering(true, stream).await;
                })
        }
        _ => malformed_grant(),
    }
}

/// Close the stream under an upgraded connection without letting unread input
/// reset away its last frames, when its socket was left cleanly.
async fn close_lingering(finished: bool, stream: Option<crate::http::HttpStreamReclaim>) {
    if !finished {
        return;
    }
    if let Some(stream) = stream
        && let Ok(mut stream) = stream.await
    {
        crate::lingering_close::close_within_bound(&mut stream).await;
    }
}

fn malformed_grant() -> Response<Body> {
    eprintln!("e6ircd edge: the core answered an upgrade with a grant it does not complete");
    problem(
        StatusCode::BAD_GATEWAY,
        "Bad gateway",
        "The server's answer to the WebSocket upgrade could not be used.",
    )
}
