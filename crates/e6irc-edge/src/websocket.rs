//! WebSocket framing for IRC over WebSocket (`/ws/irc`, DESIGN §13.4) and the
//! live web UI socket (`/ws/ui`, DESIGN §13.2): the message ceiling, the frame
//! mode the ircv3 subprotocol fixes, and every frame written within the peer
//! write deadline ([`crate::peer_write`]) — and a `/ws/irc` connection's
//! whole life ([`serve_irc_socket`]).

use axum::extract::ws::{Message as WsMessage, WebSocket};
use e6irc_proto::framing::LineEvent;
use e6irc_queue::PushError;

use crate::connection::{
    CLOSING_DRAIN, ConnId, ConnectionTransport, CorePort, SessionClosed, TransportError,
    TransportTelemetry, hand_over,
};
use crate::peer_write::{PEER_WRITE_DEADLINE, SendFailure, within_send_deadline};

/// The largest WebSocket message `/ws/irc` reads. IRCv3 WebSocket carries one
/// IRC line per message; one over the line limit is refused with 417 and the
/// connection kept, as an over-long TCP line is. But a message is read whole
/// before it can be judged, so one past this is not read at all: the
/// connection is closed with 1009 (message too big).
pub const MAX_IRC_WS_MESSAGE: usize = 64 * 1024;

/// Write one frame, giving up on a peer that has stopped reading
/// ([`crate::peer_write`]).
pub async fn send_frame(socket: &mut WebSocket, frame: WsMessage) -> Result<(), SendFailure> {
    within_send_deadline(PEER_WRITE_DEADLINE, socket.send(frame)).await
}

/// Outbound WebSocket frame discipline, fixed for the connection by ircv3
/// subprotocol negotiation (<https://ircv3.net/specs/extensions/websocket>).
#[derive(Clone, Copy)]
pub enum WsFrameMode {
    /// `binary.ircv3.net`: every line is a binary frame (raw bytes verbatim).
    Binary,
    /// `text.ircv3.net`: every line is a text frame; non-UTF-8 bytes are lossily
    /// replaced with U+FFFD, since a WebSocket text frame must be valid UTF-8.
    Text,
    /// No subprotocol negotiated: text when the line is valid UTF-8, otherwise
    /// binary — so arbitrary IRC bytes survive. The historical behavior the
    /// existing `/ws/irc` clients rely on.
    Auto,
}

/// Send one core Output line as one frame. The core's Output is a full wire
/// line terminated with exactly "\r\n" (the core's `send_bytes`). Strip only
/// that terminator: `trim_end()` would eat significant trailing spaces in a
/// `:`-prefixed trailing parameter, silently dropping content.
pub async fn send_irc_line(
    socket: &mut WebSocket,
    mode: WsFrameMode,
    bytes: &[u8],
) -> Result<(), SendFailure> {
    let line = bytes
        .strip_suffix(b"\r\n")
        .or_else(|| bytes.strip_suffix(b"\n"))
        .unwrap_or(bytes);
    // Frame type follows the negotiated subprotocol. Under Auto (no
    // subprotocol) a non-UTF-8 body goes out as a binary frame rather than
    // being corrupted by lossy U+FFFD replacement; under the text subprotocol
    // the client asked for text, so it is replaced.
    match mode {
        WsFrameMode::Binary => send_frame(socket, WsMessage::binary(line.to_vec())).await,
        WsFrameMode::Text => {
            send_frame(
                socket,
                WsMessage::text(String::from_utf8_lossy(line).into_owned()),
            )
            .await
        }
        WsFrameMode::Auto => match std::str::from_utf8(line) {
            Ok(text) => send_frame(socket, WsMessage::text(text)).await,
            Err(_) => send_frame(socket, WsMessage::binary(line.to_vec())).await,
        },
    }
}

/// Close the socket with `code` and a reason the client can show.
pub async fn send_close(socket: &mut WebSocket, code: u16, reason: std::borrow::Cow<'static, str>) {
    let close = axum::extract::ws::CloseFrame {
        code,
        reason: reason.into_owned().into(),
    };
    drop(send_frame(socket, WsMessage::Close(Some(close))).await);
}

/// One `/ws/irc` session as it reaches the core: its identifier, the address
/// its client is shown under, how it arrived, its frame mode and its
/// send-queue bound.
pub struct IrcSocketSession {
    pub conn: ConnId,
    /// The client's canonical address (`ClientIp`'s spelling): the subject
    /// server bans match and WHOIS shows, so a `/ws/irc` user cannot evade a
    /// K-line or D-line by coming in over the web.
    pub host: String,
    pub transport: ConnectionTransport,
    pub mode: WsFrameMode,
    pub sendq_bytes: usize,
}

/// How a `/ws/irc` connection's socket was left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrcSocketEnd {
    /// Everything owed was sent, closing frame included: the stream under it
    /// is closed lingering ([`crate::lingering_close`]), so unread input does
    /// not reset away the last frames.
    Finished,
    /// The socket failed, stalled past its bound, or the core is gone: the
    /// stream is dropped as it is.
    Abandoned,
}

/// How a `/ws/irc` connection's loop ended.
enum Ended {
    /// The core ended the session; what it still queued is owed.
    SessionOver,
    /// The client closed, or its side failed or overran the message ceiling;
    /// the core is told why.
    ClientGone {
        reason: SessionClosed,
        /// The close frame owed to the client, if any.
        close: Option<(u16, &'static str)>,
    },
    /// A frame could not be written; the core is told why.
    WriteFailed(SendFailure),
    /// The core is gone.
    CoreGone,
}

/// Serve one `/ws/irc` connection until it ends: each inbound text or binary
/// message is one IRC line to the core, metered as a TCP client's lines are;
/// each line the core sends is one outbound frame, reported written
/// (`Drained`) once sent. The IRC-over-WebSocket counterpart of
/// [`crate::connection::serve_conn`]: one task owns the socket and selects
/// between inbound frames and the session's send-queue buffer, so a client
/// past its command allowance keeps receiving while its input waits.
pub async fn serve_irc_socket<C: CorePort>(
    mut socket: WebSocket,
    session: IrcSocketSession,
    core: C,
    telemetry: &dyn TransportTelemetry,
) -> IrcSocketEnd {
    let IrcSocketSession {
        conn,
        host,
        transport,
        mode,
        sendq_bytes,
    } = session;
    let Some(mut edge) = core.open(conn, host, transport, sendq_bytes).await else {
        return IrcSocketEnd::Abandoned;
    };
    // The core ends the session by ending its link (`End` or `Kill`).
    let session_over = edge.session_over();
    let mut meter = edge.line_meter(core.command_flood());
    let end = loop {
        // Past its command allowance the connection is not read until a
        // token is back, while what the core sends it keeps flowing.
        let blocked = meter.blocked_until(tokio::time::Instant::now());
        tokio::select! {
            () = tokio::time::sleep_until(blocked.unwrap_or_else(tokio::time::Instant::now)), if blocked.is_some() => {}
            // The core ended the session (QUIT, KILL, SendQ, shutdown): the
            // client is not read from again, and what it is owed is sent below.
            () = session_over.wait() => break Ended::SessionOver,
            // Outbound: a core Output line becomes one frame.
            out = edge.take() => {
                let Some(envelope) = out else { break Ended::SessionOver };
                let line = envelope.payload.0;
                if let Err(failure) = send_irc_line(&mut socket, mode, &line).await {
                    telemetry.record_error(TransportError::Write);
                    edge.writer_failed(failure.clone());
                    break Ended::WriteFailed(failure);
                }
                edge.written(line.len());
            }
            // Inbound: one message -> one line -> the core.
            frame = socket.recv(), if blocked.is_none() => {
                let data: Vec<u8> = match frame {
                    Some(Ok(WsMessage::Text(text))) => text.as_bytes().to_vec(),
                    Some(Ok(WsMessage::Binary(bytes))) => bytes.to_vec(),
                    // Tungstenite queues matching Pong and Close replies while
                    // reading control frames; the next read flushes them.
                    Some(Ok(_)) => continue,
                    Some(Err(error)) => break read_failure(error, telemetry),
                    None => break Ended::ClientGone {
                        reason: SessionClosed::ByClient,
                        close: None,
                    },
                };
                // IRCv3 WebSocket messages are already framed: one message is
                // one IRC line, with no CR/LF terminator. Feed the whole value
                // to the parser so an embedded delimiter is rejected as one
                // malformed command rather than forged into a second command.
                // A message over the line limit is refused (417) under its
                // label when one is recoverable, and the connection kept, as
                // an over-long TCP line is.
                let event = if e6irc_proto::message::client_frame_fits(&data) {
                    LineEvent::Line(data)
                } else {
                    LineEvent::too_long(&data)
                };
                if !hand_over(&core, &mut meter, conn, &mut vec![event]).await {
                    break Ended::CoreGone;
                }
            }
        }
    };
    match end {
        Ended::SessionOver => {
            // Everything still queued, then a normal close, within the bound a
            // finished session's output has on every transport.
            let delivered = tokio::time::timeout(CLOSING_DRAIN, async {
                while let Some(envelope) = edge.take().await {
                    let line = envelope.payload.0;
                    send_irc_line(&mut socket, mode, &line).await?;
                    edge.written(line.len());
                }
                send_frame(
                    &mut socket,
                    WsMessage::Close(Some(axum::extract::ws::CloseFrame {
                        code: axum::extract::ws::close_code::NORMAL,
                        reason: "".into(),
                    })),
                )
                .await
            })
            .await;
            if !matches!(delivered, Ok(Ok(()))) {
                return IrcSocketEnd::Abandoned;
            }
        }
        Ended::ClientGone { reason, close } => {
            core.closed(conn, reason).await;
            if let Some((code, text)) = close
                && tokio::time::timeout(CLOSING_DRAIN, send_close(&mut socket, code, text.into()))
                    .await
                    .is_err()
            {
                return IrcSocketEnd::Abandoned;
            }
        }
        Ended::WriteFailed(failure) => {
            core.closed(conn, SessionClosed::WriteFailed(failure)).await;
            return IrcSocketEnd::Abandoned;
        }
        Ended::CoreGone => return IrcSocketEnd::Abandoned,
    }
    IrcSocketEnd::Finished
}

/// How a failed read ends the connection: a message past the ceiling is
/// closed with 1009 (message too big); anything else is a broken connection.
fn read_failure(error: axum::Error, telemetry: &dyn TransportTelemetry) -> Ended {
    use tokio_tungstenite::tungstenite::Error as Tungstenite;
    let error = error.into_inner();
    if let Some(Tungstenite::Capacity(_)) = error.downcast_ref::<Tungstenite>() {
        return Ended::ClientGone {
            reason: SessionClosed::MessageTooBig,
            close: Some((axum::extract::ws::close_code::SIZE, "Message too big")),
        };
    }
    telemetry.record_error(TransportError::Read);
    Ended::ClientGone {
        reason: SessionClosed::ReadFailed(error.to_string()),
        close: None,
    }
}

/// One message a `/ws/ui` client sent, as the edge hands it to the core (the
/// `Ui` session kind's inbound frame, DESIGN §19.2): a text message (a
/// composer request), or the fact of a binary one, which the core refuses by
/// its kind alone. What it weighs against the queues it waits in is
/// [`crate::core_link::remote::ui_message_weight`].
pub use e6irc_link::UiMessage;

/// The largest `/ws/ui` message the edge reads (the link's own bound on a
/// `Message`): JSON can escape one input byte as six ASCII bytes, so a
/// wire-sized composer command fits with room for its envelope.
pub const MAX_UI_WS_MESSAGE: usize = e6irc_link::MAX_UI_MESSAGE_LEN;

/// How a `/ws/ui` socket's loop ended.
enum UiEnded {
    /// The core ended the session; what it sent, then its close frame, are
    /// owed.
    SessionOver,
    /// The client closed, failed, stopped answering, or could not be written
    /// to: the socket is done with.
    ClientGone,
}

/// Serve one `/ws/ui` socket's transport until it ends: each text message the
/// core sends (`Output`) is one text frame, reported written once sent; each
/// message the client sends goes to the core over `inbound`, whose room is
/// the credit it waits for — while it waits the socket is not read, but what
/// the core sends keeps flowing. The socket's liveness is held here: after
/// one `liveness` interval without a frame the client is sent a WebSocket
/// Ping, and after a second it is given up on. Any frame is a sign of life.
/// When the core ends the session, what it sent goes out, then the close frame
/// its `End` carries, within [`CLOSING_DRAIN`]; when the client goes, the core
/// hears it as `inbound` ending.
pub async fn serve_ui_socket(
    mut socket: WebSocket,
    mut edge: crate::link::EdgeSession,
    inbound: e6irc_queue::Sender<UiMessage>,
    liveness: std::time::Duration,
) {
    let session_over = edge.session_over();
    let mut silence = crate::peer_write::SilenceDeadline::new(liveness);
    let mut awaiting_pong = false;
    // A message the core has no room for yet.
    let mut held: Option<UiMessage> = None;
    let ended = loop {
        tokio::select! {
            () = session_over.wait() => break UiEnded::SessionOver,
            out = edge.take() => {
                let Some(envelope) = out else { break UiEnded::SessionOver };
                let text = envelope.payload.0;
                match send_ui_text(&mut socket, &text).await {
                    Ok(()) => edge.written(text.len()),
                    Err(failure) => {
                        edge.writer_failed(failure);
                        break UiEnded::ClientGone;
                    }
                }
            }
            () = room_for_held(&inbound, held.as_ref()) => {
                if let Some(message) = held.take()
                    && let Err(refused) = inbound.try_push(message)
                {
                    match refused {
                        PushError::Full(message) => held = Some(message),
                        // The core's end stopped reading: it is ending the
                        // session.
                        PushError::Closed(_) => break UiEnded::SessionOver,
                    }
                }
            }
            frame = silence.bound(socket.recv()), if held.is_none() => {
                let Some(frame) = frame else {
                    if awaiting_pong {
                        break UiEnded::ClientGone;
                    }
                    awaiting_pong = true;
                    silence.restart();
                    if send_frame(&mut socket, WsMessage::Ping(Default::default())).await.is_err() {
                        break UiEnded::ClientGone;
                    }
                    continue;
                };
                awaiting_pong = false;
                silence.restart();
                let message = match frame {
                    Some(Ok(WsMessage::Text(text))) => UiMessage::Text(text.to_string()),
                    Some(Ok(WsMessage::Binary(_))) => UiMessage::Binary,
                    // Tungstenite answers a Ping itself, queueing the Pong
                    // while it reads and flushing it with the next read or
                    // write.
                    Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_))) => continue,
                    Some(Ok(WsMessage::Close(_)) | Err(_)) | None => break UiEnded::ClientGone,
                };
                match inbound.try_push(message) {
                    Ok(_) => {}
                    Err(PushError::Full(message)) => held = Some(message),
                    Err(PushError::Closed(_)) => break UiEnded::SessionOver,
                }
            }
        }
    };
    // The core hears the client is gone, or has already gone itself.
    drop(inbound);
    if let UiEnded::ClientGone = ended {
        return;
    }
    let delivered = tokio::time::timeout(CLOSING_DRAIN, async {
        while let Some(envelope) = edge.take().await {
            let text = envelope.payload.0;
            send_ui_text(&mut socket, &text).await?;
            edge.written(text.len());
        }
        if let Some(close) = edge.close_frame() {
            send_close(&mut socket, close.code, close.reason).await;
        }
        Ok::<(), SendFailure>(())
    })
    .await;
    drop(delivered);
}

/// Send one text message the core sent a `/ws/ui` client. The core writes
/// JSON, which is text.
async fn send_ui_text(socket: &mut WebSocket, text: &[u8]) -> Result<(), SendFailure> {
    send_frame(
        socket,
        WsMessage::text(String::from_utf8_lossy(text).into_owned()),
    )
    .await
}

/// Resolves once the core has room for `held` (or its end of the queue is
/// gone); never, when nothing is held.
async fn room_for_held(inbound: &e6irc_queue::Sender<UiMessage>, held: Option<&UiMessage>) {
    match held {
        Some(message) => inbound.room_for(message).await,
        None => std::future::pending().await,
    }
}
