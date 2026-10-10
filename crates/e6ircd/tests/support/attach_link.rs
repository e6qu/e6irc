//! An attaching client on an in-memory stream, reached through the edge.
//!
//! The attach listener serves every client as a session of the core link: the
//! edge (`e6irc_edge::connection::serve_conn`) holds the connection, and the
//! attach logic reaches it through an `AttachPort`. A test that attaches a
//! client directly does the same, so what it exercises is the path a real
//! client takes.

use std::sync::{Arc, Mutex};

use e6irc_edge::connection::{
    AcceptedConnection, ConnId, ConnectionTasks, ConnectionTransport, Outbound, TransportError,
    TransportTelemetry, serve_conn,
};
use e6ircd::bouncer::{AttachLink, AttachPort};

/// Counts nothing: these tests look at what the client is sent.
struct Uncounted;

impl TransportTelemetry for Uncounted {
    fn record_error(&self, _kind: TransportError) {}
    fn record_connection_rejected(&self) {}
}

/// The attach logic's end of a client on `stream`, the edge serving it as the
/// attach listener serves an accepted connection.
pub async fn over_stream<S>(stream: S) -> AttachLink
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let (opened, link) = tokio::sync::oneshot::channel();
    let opened = Mutex::new(Some(opened));
    let port = AttachPort::new(
        move |link, _client| {
            let opened = opened.lock().expect("test port").take();
            if let Some(opened) = opened {
                drop(opened.send(link));
            }
        },
        |_, _, _| unreachable!("the test port resumes nothing"),
    );
    tokio::spawn(serve_conn(
        stream,
        AcceptedConnection {
            conn: ConnId(1),
            peer: "192.0.2.1:6697".parse().expect("test peer"),
            transport: ConnectionTransport::Tcp,
            task: ConnectionTasks::default().task(),
            tls: None,
        },
        port,
        Outbound::with_sendq(64 * 1024),
        Arc::new(Uncounted),
    ));
    link.await.expect("the edge opened the session")
}
