//! Client connections on the IRC listeners: listening, accepting, and each
//! connection's reader and writer. Everything inward is the core, reached
//! through a [`CorePort`].
//!
//! Data flow per connection:
//!   socket reads → LineBuffer → the session's meter → `CorePort::push` into
//!     the core (await = the credit: a full core stops socket reads)
//!   core → the session's link (`crate::link`) → send-queue buffer → writer
//!     half → socket → `Drained` back to the core's account of the bound
//!     (a line past the bound = the core dooms the connection)

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use e6irc_proto::framing::{LineBuffer, LineEvent};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::address::{ClientIp, ConnLimiter, PeerRefusal, PeerRefusalLog};
use crate::link::EdgeSession;
use crate::meter::{CommandFlood, LineMeter};
use crate::peer_write::SendFailure;

/// Traditional 512-byte line minus CRLF, plus the 4096-byte client tag
/// allowance (message-tags spec); the body-only limit is enforced in
/// the core after the tag section is split off.
const LINE_LIMIT: usize = e6irc_proto::message::MAX_CLIENT_FRAME_LEN;
const READ_BUF: usize = 4096;
const ACCEPT_BATCH: usize = 64;

/// Cap on the TLS handshake. A session only reaches the core — and thus the
/// liveness reaper — *after* the handshake completes, so a peer that finishes
/// the TCP connect but never sends (or dribbles) a ClientHello would otherwise
/// hold a task, an fd, and its per-IP slot indefinitely, invisible to the
/// reaper. A plaintext peer has no such window (it hits `serve_conn` at once).
/// A real handshake completes in well under a second; 30s matches the
/// registration budget a plaintext peer already gets.
const TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 30;

/// Complete the TLS handshake on `stream`, accepted from `client`, within
/// [`TLS_HANDSHAKE_TIMEOUT_SECS`]. A handshake that fails or runs out of time
/// is counted and noted in `refusals` under its own class, and gives `None`:
/// the connection is over. Every TLS listener — the IRC listeners and the
/// attach listener — accepts through this one bound.
pub async fn tls_handshake<S>(
    acceptor: &TlsAcceptor,
    stream: S,
    client: ClientIp,
    refusals: &PeerRefusalLog,
    telemetry: &dyn TransportTelemetry,
) -> Option<tokio_rustls::server::TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let handshake = tokio::time::timeout(
        std::time::Duration::from_secs(TLS_HANDSHAKE_TIMEOUT_SECS),
        acceptor.accept(stream),
    )
    .await;
    match handshake {
        Ok(Ok(tls_stream)) => Some(tls_stream),
        Ok(Err(e)) => {
            telemetry.record_error(TransportError::TlsHandshake);
            refusals.note(client, PeerRefusal::TlsHandshakeFailed, Some(&e));
            None
        }
        Err(_) => {
            telemetry.record_error(TransportError::TlsHandshake);
            refusals.note(client, PeerRefusal::TlsHandshakeTimedOut, None);
            None
        }
    }
}

/// How long a connection whose session is over — ended by the core, or
/// half-closed by its client — may take to receive what it is still owed (the
/// replies to what it sent, its closing `ERROR`) before it is torn down
/// regardless. Its reader has stopped; this bounds the writer, whose own
/// deadline counts only stalls, so a client reading a byte at a time cannot
/// keep a finished session's socket, task and per-IP slot.
pub const CLOSING_DRAIN: std::time::Duration = std::time::Duration::from_secs(5);

/// Every task that serves a client connection — an IRC socket, plaintext or
/// TLS, an IRC WebSocket, a bouncer attach — holds a [`ConnectionTask`] from
/// here, the only place one is made. Graceful shutdown waits for them, bounded
/// (e6ircd's `SHUTDOWN_CONNECTION_DRAIN_TIMEOUT`), so a client's closing
/// `ERROR` is delivered rather than cancelled with the runtime.
#[derive(Clone, Default)]
pub struct ConnectionTasks(Arc<ConnectionTasksInner>);

#[derive(Default)]
struct ConnectionTasksInner {
    live: std::sync::atomic::AtomicUsize,
    idle: tokio::sync::Notify,
}

/// One live connection task, counted by its [`ConnectionTasks`] until dropped.
pub struct ConnectionTask(ConnectionTasks);

impl ConnectionTasks {
    pub fn task(&self) -> ConnectionTask {
        self.0
            .live
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        ConnectionTask(self.clone())
    }

    fn live(&self) -> usize {
        self.0.live.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Wait until no connection task is left, or `bound` has passed; how many
    /// are left.
    pub async fn drained_within(&self, bound: std::time::Duration) -> usize {
        let drained = async {
            loop {
                let idle = self.0.idle.notified();
                tokio::pin!(idle);
                idle.as_mut().enable();
                if self.live() == 0 {
                    return;
                }
                idle.await;
            }
        };
        // Expiry is reported by the count still live.
        drop(tokio::time::timeout(bound, drained).await);
        self.live()
    }
}

impl Drop for ConnectionTask {
    fn drop(&mut self) {
        let inner = &(self.0).0;
        if inner.live.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) == 1 {
            inner.idle.notify_waiters();
        }
    }
}

/// The identifier of one client session: the key every core structure holds
/// it by, drawn from a [`ConnectionIdAllocator`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnId(pub u64);

/// One process-wide source of live connection identifiers.
///
/// Production seeds this counter from the operating system's cryptographically
/// secure random number generator on every boot. All ingress paths share the
/// allocator, so identifiers remain ordered for keyset pagination, cannot
/// collide within a process, and do not predictably name a different
/// connection after a restart. Exhaustion is an explicit error instead of
/// wrapping onto an existing identifier.
#[derive(Debug)]
pub struct ConnectionIdAllocator {
    next: AtomicU64,
}

impl ConnectionIdAllocator {
    pub fn new(first: NonZeroU64) -> Self {
        Self {
            next: AtomicU64::new(first.get()),
        }
    }

    pub fn allocate(&self) -> Result<ConnId, ConnectionIdExhausted> {
        self.next
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map(ConnId)
            .map_err(|_| ConnectionIdExhausted)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionIdExhausted;

impl std::fmt::Display for ConnectionIdExhausted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("live connection identifier space exhausted")
    }
}

impl std::error::Error for ConnectionIdExhausted {}

/// The ingress path that owns one live core connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionTransport {
    Tcp,
    Tls,
    /// A WebSocket whose upgrade did not come over HTTPS through a trusted
    /// proxy: plaintext somewhere between the client and this server.
    WebSocket,
    /// A WebSocket a trusted proxy says its client reached over HTTPS (every
    /// `X-Forwarded-Proto` entry is `https`); the listener itself never
    /// terminates TLS.
    SecureWebSocket,
    Local,
}

impl ConnectionTransport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Tls => "tls",
            Self::WebSocket => "websocket",
            Self::SecureWebSocket => "wss",
            Self::Local => "local",
        }
    }
}

/// One wire line out to a connection I/O task, CRLF included. Socket
/// close is signaled by the session's link ending ([`crate::link`]), never by
/// an in-band event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output(pub Bytes);

/// A failure the transport counts, each one of the core's error kinds of the
/// same name (its `observability::ErrorKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    Accept,
    ConnectionSetup,
    TlsHandshake,
    Read,
    Write,
}

/// Where the transport counts what happens to its connections: e6ircd's
/// telemetry, so the counters the metrics export are the ones they always
/// were.
pub trait TransportTelemetry: Send + Sync + 'static {
    fn record_error(&self, kind: TransportError);
    fn record_connection_rejected(&self);
}

/// The core as a session's edge tasks reach it: the edge-to-core frames of
/// the core link (DESIGN §19.2) — `Open`, `Line` and `OverlongLine`,
/// `Closed` — and the terms the edge follows. The core-to-edge frames and
/// `Drained` travel on each session's own link ([`crate::link`]). This crate
/// names no core type; in the single process e6ircd implements it over the
/// core's own ingress.
pub trait CorePort: Clone + Send + Sync + 'static {
    /// Open `conn`'s session (the `Open` frame), with a send-queue bound of
    /// `sendq_bytes`: the edge's end of its link, or `None` when the core is
    /// gone.
    fn open(
        &self,
        conn: ConnId,
        host: String,
        transport: ConnectionTransport,
        sendq_bytes: usize,
    ) -> impl Future<Output = Option<EdgeSession>> + Send;

    /// The shape every session's command allowance has (DESIGN §7.2), or
    /// `None` for a core that meters nothing.
    fn command_flood(&self) -> Option<CommandFlood>;

    /// Hand one framed event of `conn`'s to the core (a `Line`, or an
    /// `OverlongLine`), once the core has room for it: that room is the
    /// credit a line waits for (DESIGN §19.2), granted first come first
    /// served, so a session out of room waits in line behind the sessions
    /// that asked before it, and a noisy one cannot starve the rest. `false`
    /// when the core is gone, so the connection stops rather than queueing
    /// into a void.
    fn push(&self, conn: ConnId, event: LineEvent) -> impl Future<Output = bool> + Send;

    /// Tell the core `conn` ended, and why (the `Closed` frame). For a session
    /// the core already ended this is a no-op, and a core that is gone needs
    /// no telling.
    fn closed(&self, conn: ConnId, reason: SessionClosed) -> impl Future<Output = ()> + Send;
}

/// Why a session ended on the edge's side (the `Closed` frame's reason). Its
/// text is what the core shows as the session's quit reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionClosed {
    /// The client closed its sending side.
    ByClient,
    /// Reading from the client failed, as the error said.
    ReadFailed(String),
    /// A WebSocket message past the ceiling (closed with 1009).
    MessageTooBig,
    /// The client could not be written to.
    WriteFailed(SendFailure),
    /// The task writing to the client panicked.
    WriterPanicked,
    /// A session that is its own edge — the bouncer's in-process `local`
    /// session — ended itself, for the reason given.
    Stopped(&'static str),
}

impl std::fmt::Display for SessionClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ByClient => f.write_str("Connection closed"),
            Self::ReadFailed(error) => write!(f, "Read error: {error}"),
            Self::MessageTooBig => f.write_str("Message too big"),
            Self::WriteFailed(failure) => f.write_str(failure.reason()),
            Self::WriterPanicked => f.write_str("Write task panicked"),
            Self::Stopped(reason) => f.write_str(reason),
        }
    }
}

/// Hand every framed event in `events` to the core through `core`, spending
/// `meter` for each first: a session past its allowance waits here, in its
/// own socket buffers, before its line reaches the core. `false` when the
/// core is gone.
pub async fn hand_over<C: CorePort>(
    core: &C,
    meter: &mut LineMeter,
    conn: ConnId,
    events: &mut Vec<LineEvent>,
) -> bool {
    for event in events.drain(..) {
        meter.spend().await;
        if !core.push(conn, event).await {
            return false;
        }
    }
    true
}

/// Bind a listening socket as `tokio::net::TcpListener::bind` does (address
/// reuse off Windows, backlog 1024), except that the IPv6 wildcard `[::]` is
/// dual-stack on every platform. Linux defaults a v6 socket to dual-stack,
/// Windows and several BSDs to v6-only, so the same configuration refused IPv4
/// clients on some hosts and not others.
pub fn bind_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    if let SocketAddr::V6(v6) = addr
        && v6.ip().is_unspecified()
    {
        socket.set_only_v6(false)?;
    }
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

/// Accept on `listener` until the task is aborted, in batches of up to
/// [`ACCEPT_BATCH`] per wakeup, serving each connection with `context`.
pub async fn accept_loop<C: CorePort>(listener: TcpListener, context: AcceptContext<C>) {
    let telemetry = &context.telemetry;
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                // Transient accept errors (EMFILE etc.) must not kill
                // the listener; retrying is the correct handling.
                eprintln!("accept error: {e}");
                telemetry.record_error(TransportError::Accept);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        spawn_accepted(stream, peer, &context);

        for _ in 1..ACCEPT_BATCH {
            let accepted = std::future::poll_fn(|context| match listener.poll_accept(context) {
                std::task::Poll::Ready(result) => std::task::Poll::Ready(Some(result)),
                std::task::Poll::Pending => std::task::Poll::Ready(None),
            })
            .await;
            match accepted {
                Some(Ok((stream, peer))) => spawn_accepted(stream, peer, &context),
                None => break,
                Some(Err(e)) => {
                    eprintln!("accept error: {e}");
                    telemetry.record_error(TransportError::Accept);
                    break;
                }
            }
        }
    }
}

/// What an IRC listener serves each accepted connection with.
pub struct AcceptContext<C> {
    pub tls: Option<TlsAcceptor>,
    pub core_tx: C,
    pub next_conn: Arc<ConnectionIdAllocator>,
    pub sendq_bytes: usize,
    pub limiter: ConnLimiter,
    pub telemetry: Arc<dyn TransportTelemetry>,
    pub connections: ConnectionTasks,
}

fn spawn_accepted<C: CorePort>(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    context: &AcceptContext<C>,
) {
    let refusals = context.limiter.refusals().clone();
    let client = ClientIp::new(peer.ip());
    let Some(guard) = context.limiter.try_acquire(client) else {
        refusals.note(client, PeerRefusal::PerIpLimit, None);
        context.telemetry.record_connection_rejected();
        return;
    };
    let conn = match context.next_conn.allocate() {
        Ok(conn) => conn,
        Err(error) => {
            refusals.note(client, PeerRefusal::ConnectionIdExhausted, Some(&error));
            context
                .telemetry
                .record_error(TransportError::ConnectionSetup);
            return;
        }
    };
    let core_tx = context.core_tx.clone();
    let tls = context.tls.clone();
    let telemetry = context.telemetry.clone();
    let sendq_bytes = context.sendq_bytes;
    let task = context.connections.task();
    tokio::spawn(async move {
        let _guard = guard;
        if let Err(e) = stream.set_nodelay(true) {
            refusals.note(client, PeerRefusal::SocketSetup, Some(&e));
            telemetry.record_error(TransportError::ConnectionSetup);
            return;
        }
        match tls {
            Some(acceptor) => {
                let Some(tls_stream) =
                    tls_handshake(&acceptor, stream, client, &refusals, &*telemetry).await
                else {
                    return;
                };
                serve_conn(
                    tls_stream,
                    AcceptedConnection {
                        conn,
                        peer,
                        transport: ConnectionTransport::Tls,
                        task,
                    },
                    core_tx,
                    Outbound::with_sendq(sendq_bytes),
                    telemetry,
                )
                .await
            }
            None => {
                serve_conn(
                    stream,
                    AcceptedConnection {
                        conn,
                        peer,
                        transport: ConnectionTransport::Tcp,
                        task,
                    },
                    core_tx,
                    Outbound::with_sendq(sendq_bytes),
                    telemetry,
                )
                .await
            }
        }
    });
}

/// The bounds on what a connection is sent: its SendQ capacity in bytes, how
/// long one write may wait for a client that has stopped reading, and how long
/// the whole of what is left may take once the session is over.
pub struct Outbound {
    pub sendq_bytes: usize,
    pub write_deadline: std::time::Duration,
    pub closing_drain: std::time::Duration,
}

impl Outbound {
    pub fn with_sendq(sendq_bytes: usize) -> Self {
        Self {
            sendq_bytes,
            write_deadline: crate::peer_write::PEER_WRITE_DEADLINE,
            closing_drain: CLOSING_DRAIN,
        }
    }
}

/// One accepted client connection: its identifier, its peer, how it arrived,
/// and its place among the tasks shutdown waits for.
pub struct AcceptedConnection {
    pub conn: ConnId,
    pub peer: SocketAddr,
    pub transport: ConnectionTransport,
    pub task: ConnectionTask,
}

/// Serve one accepted connection until it ends: open its session, read its
/// lines to the core and write the core's output to it, then close it.
pub async fn serve_conn<S, C: CorePort>(
    stream: S,
    accepted: AcceptedConnection,
    core_tx: C,
    outbound: Outbound,
    telemetry: Arc<dyn TransportTelemetry>,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let AcceptedConnection {
        conn,
        peer,
        transport,
        task: _task,
    } = accepted;
    let (mut read_half, write_half) = tokio::io::split(stream);
    let Some(edge) = core_tx
        .open(
            conn,
            // The canonical IPv4 spelling of a mapped peer (`ClientIp`): the
            // subject `ban_match` tests and WHOIS shows.
            ClientIp::new(peer.ip()).to_string(),
            transport,
            outbound.sendq_bytes,
        )
        .await
    else {
        return; // core gone: shutting down
    };
    // The core ends the session by ending its link (`End` or `Kill`).
    let session_over = edge.session_over();
    let meter = edge.line_meter(core_tx.command_flood());
    let write_half = crate::peer_write::DeadlineWriter::new(write_half, outbound.write_deadline);
    let mut writer = tokio::spawn(write_loop(write_half, edge, telemetry.clone()));
    let written_first = tokio::select! {
        // The client closed its sending side (or errored), or the core queue is
        // gone. `read_loop` has told the core, which answers what the client
        // sent before closing — a pipelined `NICK`/`USER`/`QUIT` from a
        // half-closing client is owed its welcome and its `ERROR` — and then
        // ends the session.
        () = read_loop(&mut read_half, conn, &core_tx, meter, &*telemetry) => None,
        // The core ended the session (QUIT, KILL, SendQ, shutdown). Nothing the
        // client sends is wanted any more, so reading stops here, and no line
        // is pushed for a connection the core has forgotten.
        () = session_over.wait() => None,
        end = &mut writer => Some(end),
    };
    let end = match written_first {
        Some(end) => end,
        // The session is over: what it is still owed goes out within
        // `closing_drain`, or not at all.
        None => match tokio::time::timeout(outbound.closing_drain, &mut writer).await {
            Ok(end) => end,
            Err(_elapsed) => {
                writer.abort();
                return;
            }
        },
    };
    let reason = match end {
        Ok(WriterEnd::Drained(write_half)) => {
            // Everything was written: close without letting unread input turn
            // the close into a reset that could destroy the closing `ERROR`.
            let stream = read_half.unsplit(write_half.into_inner());
            crate::lingering_close::close_within_bound(
                &mut crate::lingering_close::LingeringClose::new(stream),
            )
            .await;
            return;
        }
        Ok(WriterEnd::Failed(failure)) => SessionClosed::WriteFailed(failure),
        Err(_join_error) => SessionClosed::WriterPanicked,
    };
    // A write failed or stalled while the session may still be live; the core
    // must hear of it. For a session it already ended this is a no-op, and a
    // closed queue means the core itself is gone.
    core_tx.closed(conn, reason).await;
}

/// Frame `read_half` into lines and hand them to the core, metered by
/// `meter`, until the client closes or fails; then tell the core the session
/// ended.
pub async fn read_loop<R, C: CorePort>(
    mut read_half: R,
    conn: ConnId,
    core_tx: &C,
    mut meter: LineMeter,
    telemetry: &dyn TransportTelemetry,
) where
    R: AsyncRead + Unpin,
{
    let mut framing = LineBuffer::new(LINE_LIMIT);
    let mut buf = [0u8; READ_BUF];
    let mut events = Vec::new();
    let reason = loop {
        match read_half.read(&mut buf).await {
            Ok(0) => break SessionClosed::ByClient,
            Ok(n) => {
                framing.feed(&buf[..n], &mut events);
                // Nothing more is read until these lines are through the
                // meter: a client past its allowance waits in its own socket.
                if !hand_over(core_tx, &mut meter, conn, &mut events).await {
                    return; // core gone
                }
            }
            Err(e) => {
                telemetry.record_error(TransportError::Read);
                break SessionClosed::ReadFailed(e.to_string());
            }
        }
    };
    // Queue closure means the core has already removed all connection state.
    core_tx.closed(conn, reason).await;
}

/// How a connection's writer ended.
enum WriterEnd<W> {
    /// The core ended the session and everything it queued was written; the
    /// writer hands its half of the stream back for the close.
    Drained(W),
    /// The peer could not be written to, as said — which the caller reports
    /// to the core as the session's end ([`CorePort::closed`]).
    Failed(SendFailure),
}

/// Drain the session's send-queue buffer to the socket until the core ends
/// the session (its link ended) or a write fails, distinguishing the two so
/// neither is conflated nor silently skipped. Each batch, once written and
/// flushed, is reported to the core (`Drained`), which counts it against the
/// bound until then.
async fn write_loop<W>(
    mut write_half: W,
    mut edge: EdgeSession,
    telemetry: Arc<dyn TransportTelemetry>,
) -> WriterEnd<W>
where
    W: AsyncWrite + Unpin,
{
    let mut batch = Vec::new();
    loop {
        let Some(envelope) = edge.take().await else {
            return WriterEnd::Drained(write_half);
        };
        // Drain everything currently queued and present the shared Bytes as
        // vectored slices. Fan-out already serialized each capability variant
        // once; concatenating here copied every recipient's wire bytes again.
        batch.clear();
        batch.push(envelope.payload.0);
        while let Some(e) = edge.try_take() {
            batch.push(e.payload.0);
        }
        let written = match write_all_vectored(&mut write_half, &batch).await {
            Ok(()) => write_half.flush().await,
            Err(error) => Err(error),
        };
        if written.is_ok() {
            edge.written(batch.iter().map(Bytes::len).sum());
        }
        if let Err(error) = written {
            telemetry.record_error(TransportError::Write);
            // A broken pipe / RST, or a peer that stopped reading while output
            // was queued for it.
            let failure = SendFailure::of(&error);
            edge.writer_failed(failure.clone());
            return WriterEnd::Failed(failure);
        }
    }
}

/// Write every byte from `chunks`, correctly advancing across partial vectored
/// writes. At most 64 slices are offered per call, staying below every
/// supported platform's scatter/gather limit while still amortizing a full
/// SendQ drain. Writers without native vectored support consume the first slice
/// through their default implementation and remain correct.
async fn write_all_vectored<W>(writer: &mut W, chunks: &[bytes::Bytes]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    const MAX_SLICES: usize = 64;
    let mut index = 0usize;
    let mut offset = 0usize;
    while index < chunks.len() {
        if offset == chunks[index].len() {
            index += 1;
            offset = 0;
            continue;
        }
        let slices: Vec<std::io::IoSlice<'_>> =
            std::iter::once(std::io::IoSlice::new(&chunks[index][offset..]))
                .chain(
                    chunks[index + 1..]
                        .iter()
                        .take(MAX_SLICES - 1)
                        .map(|chunk| std::io::IoSlice::new(chunk)),
                )
                .collect();
        let written = writer.write_vectored(&slices).await?;
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to write queued IRC output",
            ));
        }
        let mut remaining = written;
        while index < chunks.len() {
            let available = chunks[index].len() - offset;
            if remaining < available {
                offset += remaining;
                break;
            }
            remaining -= available;
            index += 1;
            offset = 0;
            if remaining == 0 {
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;

    /// Counts nothing: what these tests check is how a writer ends.
    struct Uncounted;

    impl TransportTelemetry for Uncounted {
        fn record_error(&self, _kind: TransportError) {}
        fn record_connection_rejected(&self) {}
    }

    use std::task::{Context, Poll};

    #[derive(Default)]
    struct PartialVectoredSink {
        bytes: Vec<u8>,
        maximum_per_write: usize,
        vectored_calls: usize,
    }

    impl AsyncWrite for PartialVectoredSink {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            let amount = buffer.len().min(self.maximum_per_write);
            self.bytes.extend_from_slice(&buffer[..amount]);
            Poll::Ready(Ok(amount))
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffers: &[std::io::IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            self.vectored_calls += 1;
            let mut remaining = self.maximum_per_write;
            let mut written = 0usize;
            for buffer in buffers {
                let amount = buffer.len().min(remaining);
                self.bytes.extend_from_slice(&buffer[..amount]);
                written += amount;
                remaining -= amount;
                if remaining == 0 {
                    break;
                }
            }
            Poll::Ready(Ok(written))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct FlushFails;

    impl AsyncWrite for FlushFails {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "flush failed",
            )))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn vectored_writer_advances_across_partial_chunk_boundaries() {
        let mut writer = PartialVectoredSink {
            maximum_per_write: 5,
            ..PartialVectoredSink::default()
        };
        write_all_vectored(
            &mut writer,
            &[
                bytes::Bytes::from_static(b"abc"),
                bytes::Bytes::from_static(b"defg"),
                bytes::Bytes::from_static(b"h"),
            ],
        )
        .await
        .expect("vectored write");
        assert_eq!(writer.bytes, b"abcdefgh");
        assert_eq!(
            writer.vectored_calls, 2,
            "partial progress should resume at the exact byte, not rewrite a chunk"
        );
    }

    #[tokio::test]
    async fn flush_failure_is_a_connection_write_error() {
        let (mut core, edge) = crate::link::session("t-sendq", 1);
        core.output(Output(bytes::Bytes::from_static(b"NOTICE * :hello\r\n")))
            .expect("test output");

        assert!(matches!(
            write_loop(FlushFails, edge, Arc::new(Uncounted)).await,
            WriterEnd::Failed(SendFailure::Transport)
        ));
        assert_eq!(
            core.in_flight(),
            17,
            "a line that was not written still counts"
        );
    }

    /// What a writer writes counts against the bound until it is flushed,
    /// and not after: the writer reports each batch written once it is.
    #[tokio::test]
    async fn a_written_batch_is_reported_drained_once_flushed() {
        let (mut core, edge) = crate::link::session("t-sendq", 1024);
        let line = bytes::Bytes::from_static(b"NOTICE * :hello\r\n");
        for _ in 0..3 {
            core.output(Output(line.clone())).expect("room");
        }
        assert_eq!(core.in_flight(), 3 * line.len());
        let sink = PartialVectoredSink {
            maximum_per_write: 5,
            ..PartialVectoredSink::default()
        };
        let writer = tokio::spawn(write_loop(sink, edge, Arc::new(Uncounted)));
        while core.in_flight() > 0 {
            tokio::task::yield_now().await;
        }
        // Everything was written and reported; ending the link ends the writer.
        drop(core);
        match writer.await.expect("writer task") {
            WriterEnd::Drained(sink) => assert_eq!(sink.bytes.len(), 3 * line.len()),
            WriterEnd::Failed(failure) => panic!("{failure:?}"),
        }
    }

    /// Counts the TLS handshakes it is told failed.
    #[derive(Default)]
    struct HandshakeFailures(std::sync::atomic::AtomicUsize);

    impl TransportTelemetry for HandshakeFailures {
        fn record_error(&self, kind: TransportError) {
            assert_eq!(kind, TransportError::TlsHandshake);
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn record_connection_rejected(&self) {}
    }

    /// An acceptor serving a fresh self-signed certificate for `localhost`,
    /// and a connector that trusts it.
    fn tls_pair(name: &str) -> (TlsAcceptor, tokio_rustls::TlsConnector) {
        crate::certificate::install_crypto_provider();
        let dir = std::env::temp_dir().join(format!("e6irc-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        let files = crate::certificate::TlsConfig {
            cert_path: dir.join("cert.pem"),
            key_path: dir.join("key.pem"),
        };
        let trusted = crate::certificate::write_self_signed(&files);
        let acceptor = crate::certificate::CertificateReloads::default()
            .acceptor(&files)
            .expect("acceptor");
        std::fs::remove_dir_all(&dir).expect("remove the scratch directory");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(trusted).expect("root");
        let connector = tokio_rustls::TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        (acceptor, connector)
    }

    fn client() -> ClientIp {
        ClientIp::new("192.0.2.7".parse().unwrap())
    }

    /// A completed handshake gives the stream, and counts nothing.
    #[tokio::test]
    async fn a_completed_handshake_gives_the_stream() {
        let (acceptor, connector) = tls_pair("handshake-ok");
        let (near, far) = tokio::io::duplex(64 * 1024);
        let refusals = PeerRefusalLog::new(std::time::Duration::from_secs(60));
        let failures = HandshakeFailures::default();
        // The client's end is kept open until the server's side is done.
        let client_side = tokio::spawn(async move {
            connector
                .connect("localhost".try_into().expect("name"), far)
                .await
        });
        let served = tls_handshake(&acceptor, near, client(), &refusals, &failures).await;
        let connected = client_side
            .await
            .expect("client task")
            .expect("client handshake");
        assert!(served.is_some(), "the handshake completes");
        drop(connected);
        assert_eq!(failures.0.load(Ordering::SeqCst), 0);
    }

    /// A peer that sends something other than a ClientHello fails the
    /// handshake: counted, and noted under its own class.
    #[tokio::test]
    async fn a_failed_handshake_is_counted_and_noted() {
        let (acceptor, _connector) = tls_pair("handshake-failed");
        let (near, mut far) = tokio::io::duplex(64 * 1024);
        far.write_all(b"NICK alice\r\nUSER alice 0 * :Alice\r\n")
            .await
            .expect("send plaintext");
        let refusals = PeerRefusalLog::new(std::time::Duration::from_secs(60));
        let failures = HandshakeFailures::default();
        let served = tls_handshake(&acceptor, near, client(), &refusals, &failures).await;
        assert!(served.is_none());
        assert_eq!(failures.0.load(Ordering::SeqCst), 1);
        let now = std::time::Instant::now();
        assert!(
            refusals
                .line_at(now, client(), PeerRefusal::TlsHandshakeFailed, None)
                .is_none(),
            "the failure was noted, so its window is open"
        );
        assert!(
            refusals
                .line_at(now, client(), PeerRefusal::TlsHandshakeTimedOut, None)
                .is_some(),
            "and not as a timeout"
        );
    }

    /// A peer that connects and never sends a ClientHello is given up on at
    /// the bound, rather than holding its task and slot for as long as it
    /// likes.
    #[tokio::test(start_paused = true)]
    async fn a_silent_peer_times_out_at_the_bound() {
        let (acceptor, _connector) = tls_pair("handshake-silent");
        let (near, _far) = tokio::io::duplex(64 * 1024);
        let refusals = PeerRefusalLog::new(std::time::Duration::from_secs(60));
        let failures = HandshakeFailures::default();
        let started = tokio::time::Instant::now();
        let served = tls_handshake(&acceptor, near, client(), &refusals, &failures).await;
        assert!(served.is_none());
        assert_eq!(
            started.elapsed(),
            std::time::Duration::from_secs(TLS_HANDSHAKE_TIMEOUT_SECS)
        );
        assert_eq!(failures.0.load(Ordering::SeqCst), 1);
        assert!(
            refusals
                .line_at(
                    std::time::Instant::now(),
                    client(),
                    PeerRefusal::TlsHandshakeTimedOut,
                    None,
                )
                .is_none(),
            "the timeout was noted, so its window is open"
        );
    }

    #[test]
    fn allocation_is_ordered_and_refuses_to_wrap() {
        let allocator =
            ConnectionIdAllocator::new(NonZeroU64::new(7).expect("non-zero test start"));
        assert_eq!(allocator.allocate().expect("first identifier").0, 7);
        assert_eq!(allocator.allocate().expect("second identifier").0, 8);

        let exhausted =
            ConnectionIdAllocator::new(NonZeroU64::new(u64::MAX - 1).expect("non-zero"));
        assert_eq!(
            exhausted.allocate().expect("last identifier").0,
            u64::MAX - 1
        );
        assert!(exhausted.allocate().is_err());
    }
}
