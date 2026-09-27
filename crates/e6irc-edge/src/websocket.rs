//! WebSocket framing for IRC over WebSocket (`/ws/irc`, DESIGN §13.4) and the
//! live web UI socket (`/ws/ui`, DESIGN §13.2): the message ceiling, the frame
//! mode the ircv3 subprotocol fixes, and every frame written within the peer
//! write deadline ([`crate::peer_write`]).

use axum::extract::ws::{Message as WsMessage, WebSocket};

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

/// The reason the core is given ([`crate::connection::CorePort::closed`]) for a
/// frame the client did not take.
pub fn write_failure_reason(failure: &SendFailure) -> &'static str {
    match failure {
        SendFailure::Stalled => "Write timeout",
        SendFailure::Transport => "Write error",
    }
}

/// Close the socket with `code` and a reason the client can show.
pub async fn send_close(socket: &mut WebSocket, code: u16, reason: &'static str) {
    let close = axum::extract::ws::CloseFrame {
        code,
        reason: reason.into(),
    };
    drop(send_frame(socket, WsMessage::Close(Some(close))).await);
}
