//! HTTP admission and serving (DESIGN §19.1): every HTTP listener — the
//! single process's `[http]` and WebSocket IRC listeners, a standby's health
//! listener, an edge's web port — accepts and serves its connections here.
//!
//! Written out rather than `axum::serve`, which builds its connection builder
//! without a timer: hyper then silently drops its header-read timeout, and a
//! peer that sends half a header block — or holds a kept-alive connection idle
//! — keeps its socket and task forever. Here every connection has a timer and
//! [`HTTP_HEADER_READ_TIMEOUT`], its writes are bounded by
//! [`crate::peer_write::PEER_WRITE_DEADLINE`] (so a client that asks for a
//! large response and stops reading loses the connection instead of holding
//! it), and the per-address connection cap is applied at accept, before any
//! work is spent on the peer.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;

use crate::address::{
    ClientIp, ConnGuard, ConnLimiter, PeerRefusal, PeerRefusalLog, TrustedProxies,
};
use crate::connection::{TransportError, TransportTelemetry};

/// How long a client may take to send one request's complete header block.
/// hyper starts the same timer the moment a kept-alive connection goes idle
/// (waiting for the next request's headers), so this is also the idle
/// keep-alive timeout: a connection that sends nothing for this long is closed.
pub const HTTP_HEADER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// HTTP connections one address may hold open at once. A browser opens a
/// handful per origin; this leaves room for many behind one address. A
/// trusted reverse proxy is exempt — every client behind it shares its
/// address — and its clients are bounded per request, by forwarded address.
pub const MAX_HTTP_CONNECTIONS_PER_IP: usize = 128;

/// Who may open an HTTP connection: at most [`MAX_HTTP_CONNECTIONS_PER_IP`]
/// from one address, except a trusted reverse proxy. One instance per
/// listener — an HTTP connection is not an IRC session, and must not spend the
/// IRC listeners' per-address budget.
pub struct HttpAdmission {
    connections: ConnLimiter,
    trusted_proxies: TrustedProxies,
    /// Every connection starts with a PROXY protocol header naming its
    /// client ([`crate::proxy_protocol`]).
    proxy_protocol: bool,
}

impl HttpAdmission {
    pub fn new(trusted_proxies: TrustedProxies) -> Self {
        Self {
            connections: ConnLimiter::new(Some(MAX_HTTP_CONNECTIONS_PER_IP)),
            trusted_proxies,
            proxy_protocol: false,
        }
    }

    /// Read a PROXY protocol header from every connection first.
    pub fn with_proxy_protocol(self) -> Self {
        Self {
            proxy_protocol: true,
            ..self
        }
    }

    /// A slot for `client`'s connection: `Ok(None)` for a trusted proxy,
    /// which holds none.
    fn admit(&self, client: ClientIp) -> Result<Option<ConnGuard>, ()> {
        if self.trusted_proxies.contains(client.ip()) {
            return Ok(None);
        }
        self.connections.try_acquire(client).map(Some).ok_or(())
    }
}

/// Serve HTTP/1.1 (with WebSocket upgrades) on `listener`.
pub async fn serve_http(
    listener: TcpListener,
    router: axum::Router,
    admission: HttpAdmission,
    telemetry: Arc<dyn TransportTelemetry>,
) {
    let admission = Arc::new(admission);
    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                // Transient accept errors (EMFILE etc.) must not kill the
                // listener; retrying is the correct handling.
                telemetry.record_error(TransportError::Accept);
                eprintln!("http accept error: {error}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let refusals = admission.connections.refusals().clone();
        if !admission.proxy_protocol {
            let client = ClientIp::new(peer.ip());
            let Ok(guard) = admission.admit(client) else {
                telemetry.record_connection_rejected();
                refusals.note(client, PeerRefusal::PerIpLimit, None);
                continue;
            };
            tokio::spawn(serve_http_connection(
                stream,
                peer,
                router.clone(),
                guard,
                refusals,
                telemetry.clone(),
                crate::peer_write::PEER_WRITE_DEADLINE,
            ));
            continue;
        }
        let (router, admission, telemetry) = (router.clone(), admission.clone(), telemetry.clone());
        tokio::spawn(async move {
            let client = match crate::proxy_protocol::relayed_client(
                &mut stream,
                peer,
                &admission.trusted_proxies,
            )
            .await
            {
                Ok(client) => client,
                Err(error) => {
                    telemetry.record_error(TransportError::ConnectionSetup);
                    refusals.note(
                        ClientIp::new(peer.ip()),
                        PeerRefusal::ProxyHeader,
                        Some(&error),
                    );
                    return;
                }
            };
            let Ok(guard) = admission.admit(ClientIp::new(client.ip())) else {
                telemetry.record_connection_rejected();
                refusals.note(ClientIp::new(client.ip()), PeerRefusal::PerIpLimit, None);
                return;
            };
            serve_http_connection(
                stream,
                client,
                router,
                guard,
                refusals,
                telemetry,
                crate::peer_write::PEER_WRITE_DEADLINE,
            )
            .await;
        });
    }
}

async fn serve_http_connection(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    router: axum::Router,
    _guard: Option<ConnGuard>,
    refusals: Arc<PeerRefusalLog>,
    telemetry: Arc<dyn TransportTelemetry>,
    write_deadline: std::time::Duration,
) {
    use tower::ServiceExt;
    let client = ClientIp::new(peer.ip());
    if let Err(error) = stream.set_nodelay(true) {
        telemetry.record_error(TransportError::ConnectionSetup);
        refusals.note(client, PeerRefusal::SocketSetup, Some(&error));
        return;
    }
    // Whether this connection has carried a request: hyper reports the same
    // header timeout for a peer that never finished its first request and for
    // a kept-alive connection that sat idle after one, and only the first is a
    // refusal. A reverse proxy holding idle upstream connections hit the second
    // every ten seconds and filled the log with "refused" lines.
    let served_a_request = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let served_flag = served_a_request.clone();
    // Every write — a response body, an upgraded WebSocket's frames — fails
    // once the peer has taken nothing for `write_deadline`, which ends the
    // connection ([`crate::peer_write`]). A refusal answered before the
    // request was read (a body over the limit) closes without a reset that
    // would discard the answer ([`crate::lingering_close`]). The stream is
    // lent to hyper reclaimably, so an upgraded connection's own task can
    // close it the same way when it is done with it.
    let (stream, reclaim) =
        crate::lingering_close::Reclaimable::new(crate::peer_write::DeadlineWriter::new(
            crate::lingering_close::LingeringClose::new(stream),
            write_deadline,
        ));
    let upgraded = UpgradedStream(Arc::new(std::sync::Mutex::new(Some(reclaim))));
    // `ConnectInfo` so handlers see the socket peer (rate limiting, and the
    // forwarded-address resolution behind a trusted proxy).
    let service = router.map_request(move |mut request: axum::http::Request<_>| {
        served_flag.store(true, std::sync::atomic::Ordering::Relaxed);
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(peer));
        request.extensions_mut().insert(upgraded.clone());
        request
    });
    let served = hyper::server::conn::http1::Builder::new()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HTTP_HEADER_READ_TIMEOUT)
        .serve_connection(
            hyper_util::rt::TokioIo::new(stream),
            hyper_util::service::TowerToHyperService::new(service),
        )
        .with_upgrades()
        .await;
    match served {
        Ok(()) => {}
        // An idle kept-alive connection closed at the bound: ordinary.
        Err(error)
            if error.is_timeout()
                && served_a_request.load(std::sync::atomic::Ordering::Relaxed) => {}
        Err(error) if error.is_timeout() => {
            refusals.note(client, PeerRefusal::HttpHeaderTimedOut, None);
        }
        // A peer that resets or abandons its connection mid-request: counted,
        // not logged per occurrence.
        Err(_) => telemetry.record_error(TransportError::Http),
    }
}

/// The stream under an HTTP connection, as every request on it is handed it
/// (a request extension). hyper drops an upgraded connection's stream without
/// shutting it down, which with unread input is a reset that can destroy the
/// last frames written; the handler that takes the upgrade claims this, and
/// gets the stream back when the upgraded socket is dropped, to close it
/// properly ([`crate::lingering_close::close_within_bound`]).
#[derive(Clone)]
pub struct UpgradedStream(Arc<std::sync::Mutex<Option<HttpStreamReclaim>>>);

/// The stream an HTTP connection serves.
pub type HttpStream = crate::peer_write::DeadlineWriter<
    crate::lingering_close::LingeringClose<tokio::net::TcpStream>,
>;

/// Resolves to the HTTP connection's stream once hyper has dropped it.
pub type HttpStreamReclaim = tokio::sync::oneshot::Receiver<HttpStream>;

impl UpgradedStream {
    /// Claim the stream for the upgrade this request asks for; `None` once
    /// claimed (a connection is upgraded at most once).
    pub fn claim(&self) -> Option<HttpStreamReclaim> {
        self.0.lock().expect("upgraded stream lock").take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Uncounted;

    impl TransportTelemetry for Uncounted {
        fn record_error(&self, _kind: TransportError) {}
        fn record_connection_rejected(&self) {}
    }

    /// A client that asks for a large response and never reads it held its
    /// connection (and a slot of its address's connection cap) for as long as
    /// it liked: nothing bounded a stalled body write. The connection now ends
    /// once the client has taken nothing for the write deadline.
    #[tokio::test]
    async fn an_http_client_that_stops_reading_a_large_response_loses_the_connection() {
        use std::time::Duration;
        use tokio::io::AsyncWriteExt;
        const BODY: usize = 32 * 1024 * 1024;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let client = tokio::net::TcpSocket::new_v4().expect("socket");
        client.set_recv_buffer_size(4096).expect("receive buffer");
        let mut client = client.connect(address).await.expect("connect");
        let (stream, peer) = listener.accept().await.expect("accept");
        socket2::SockRef::from(&stream)
            .set_send_buffer_size(4096)
            .expect("send buffer");
        let router =
            axum::Router::new().route("/large", axum::routing::get(|| async { vec![b'x'; BODY] }));
        let served = tokio::spawn(serve_http_connection(
            stream,
            peer,
            router,
            None,
            Arc::new(PeerRefusalLog::new(Duration::from_secs(60))),
            Arc::new(Uncounted),
            Duration::from_millis(200),
        ));
        client
            .write_all(b"GET /large HTTP/1.1\r\nhost: test\r\n\r\n")
            .await
            .expect("request");
        // The client never reads; the server's write stalls within the first
        // few hundred kilobytes and must give up.
        tokio::time::timeout(Duration::from_secs(20), served)
            .await
            .expect("a stalled response write ends the connection")
            .expect("the connection task");
        drop(client);
    }
}
