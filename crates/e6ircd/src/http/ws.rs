//! WebSocket endpoints: IRCv3-over-WebSocket and the live web UI socket.

use super::*;

// ---- ws-irc (IRCv3-over-WebSocket, DESIGN §13.4) -------------------------

use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};

pub(super) async fn ws_irc(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    // Enforce the same per-IP connection cap the raw IRC listeners apply,
    // keyed on the real client IP (X-Forwarded-For behind a trusted proxy) so
    // /ws/irc can't be used to sidestep it. The guard is held for the
    // connection's lifetime and releases the slot on drop.
    let ip = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let Some(guard) = state.conn_limiter.try_acquire(ip) else {
        return problem(
            StatusCode::TOO_MANY_REQUESTS,
            "Per-IP connection limit reached",
            None,
        );
    };
    ws.on_upgrade(move |socket| ws_irc_conn(state, socket, guard))
}

/// Bridge one WebSocket to the IRC core: each inbound text frame is one
/// IRC line; each core Output line is one outbound text frame. Mirrors
/// the TCP connection path (net::serve_conn) over the WS transport. A
/// single task owns the socket and selects between inbound frames and
/// the drained SendQ — no split, so no extra dependency.
pub(super) async fn ws_irc_conn(
    state: Arc<AppState>,
    mut socket: WebSocket,
    _conn_guard: crate::net::ConnGuard,
) {
    use crate::core::{ConnId, Input, Output};
    use e6irc_proto::framing::{LineBuffer, LineEvent};
    use std::sync::atomic::Ordering;

    // Held for the whole connection; its Drop releases the per-IP slot.
    let conn = ConnId(state.next_conn.fetch_add(1, Ordering::Relaxed));
    let (out_tx, mut out_rx) = e6irc_queue::queue::<Output>(e6irc_queue::Config {
        name: "ws-sendq",
        capacity: state.sendq,
        policy: e6irc_queue::Policy::Fifo,
    });
    if state
        .core_tx
        .push(Input::Open {
            conn,
            tx: out_tx,
            host: "websocket".into(),
        })
        .await
        .is_err()
    {
        return;
    }
    let core_tx = state.core_tx.clone();
    let mut framing = LineBuffer::new(e6irc_proto::message::MAX_CLIENT_FRAME_LEN);
    let mut events = Vec::new();

    'conn: loop {
        tokio::select! {
            // Outbound: a core Output line becomes one text frame.
            out = out_rx.pop() => {
                let Some(env) = out else { break };
                let bytes = env.payload.0;
                // The core's Output is a full wire line terminated with exactly
                // "\r\n" (state.rs `send_bytes`). Strip only that terminator:
                // `trim_end()` would eat significant trailing spaces in a
                // `:`-prefixed trailing parameter, silently dropping content.
                let line = bytes
                    .strip_suffix(b"\r\n")
                    .or_else(|| bytes.strip_suffix(b"\n"))
                    .unwrap_or(&bytes);
                // A WebSocket text frame must be valid UTF-8, but IRC message
                // bodies may carry non-UTF-8 bytes. Send those as a binary frame
                // rather than corrupting them with lossy U+FFFD replacement —
                // both frame types are valid under the ircv3 WS subprotocol.
                let sent = match std::str::from_utf8(line) {
                    Ok(text) => socket.send(WsMessage::text(text)).await,
                    Err(_) => socket.send(WsMessage::binary(line.to_vec())).await,
                };
                if sent.is_err() {
                    break;
                }
            }
            // Inbound: frame(s) -> lines -> core.
            frame = socket.recv() => {
                let data: Vec<u8> = match frame {
                    Some(Ok(WsMessage::Text(t))) => t.as_bytes().to_vec(),
                    Some(Ok(WsMessage::Binary(b))) => b.to_vec(),
                    Some(Ok(_)) => continue,
                    _ => break, // close or error
                };
                let mut with_nl = data;
                with_nl.push(b'\n');
                framing.feed(&with_nl, &mut events);
                for event in events.drain(..) {
                    let input = match event {
                        LineEvent::Line(line) => Input::Line { conn, line },
                        LineEvent::TooLong => Input::OverlongLine { conn },
                    };
                    if core_tx.push(input).await.is_err() {
                        break 'conn; // core gone: stop the connection directly
                    }
                }
            }
        }
    }
    let _ = core_tx
        .push(Input::Closed {
            conn,
            reason: "WebSocket closed".into(),
        })
        .await;
}

// ---- live web UI socket (DESIGN §13.2) ----------------------------------

#[derive(Deserialize)]
pub(super) struct UiParams {
    /// Which of the caller's networks to attach this UI socket to.
    pub(super) network: String,
}

/// The web client's live socket: cookie-authenticated, attaches to one
/// of the caller's networks, and pushes ready-to-swap HTML fragments
/// (the browser side runs htmx's WS extension). Composer text sent up
/// the socket is relayed to the upstream network. This is the same
/// multiplexer attach path an IRC client uses — the web client *is* an
/// attached client.
pub(super) async fn ws_ui(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Authenticated(account): Authenticated,
    Query(params): Query<UiParams>,
    ws: WebSocketUpgrade,
) -> Response {
    // Reject a cross-origin WebSocket upgrade when a public_url is configured.
    // SameSite=Lax already blocks the classic cross-site hijack (a Lax cookie
    // isn't sent on a cross-site WS handshake); an explicit Origin allowlist
    // also closes the same-site-subdomain gap. A missing Origin (a non-browser
    // client) is allowed — it carries no ambient cookie authority.
    if let Some(public) = state.public_url.as_deref()
        && let Some(origin) = headers
            .get(axum::http::header::ORIGIN)
            .and_then(|v| v.to_str().ok())
        && !same_origin(origin, public)
    {
        return problem(
            StatusCode::FORBIDDEN,
            "Cross-origin WebSocket rejected",
            None,
        );
    }
    let Some(registry) = &state.bnc_registry else {
        return problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None);
    };
    let Some(handle) = registry.get(&account, &params.network) else {
        return problem(StatusCode::NOT_FOUND, "No such network", None);
    };
    ws.on_upgrade(move |socket| ws_ui_conn(handle, socket))
}

pub(super) async fn ws_ui_conn(
    handle: std::sync::Arc<crate::bouncer::NetworkHandle>,
    mut socket: WebSocket,
) {
    use crate::bouncer::DriverEvent;
    use tokio::sync::broadcast::error::RecvError;

    // Subscribe BEFORE snapshotting the buffer, so a line the driver emits
    // during playback is caught by the subscription instead of falling into the
    // gap between the two (a duplicated backlog line is harmless; a lost one is
    // not). This mirrors attach()'s ordering — the same invariant over WS.
    let mut events = handle.subscribe();

    // Send the current connection status up front: a driver is always-on, so a
    // client attaching to an already-connected network would otherwise see no
    // status until the next connect/disconnect transition. The sticky flag
    // exists precisely to close this subscribe-timing gap.
    let status = if handle.is_connected() {
        ConnStatus::Connected
    } else {
        ConnStatus::Disconnected
    };
    if socket
        .send(WsMessage::text(render_status_fragment(status)))
        .await
        .is_err()
    {
        return;
    }

    // Playback: everything buffered while detached, as fragments.
    for line in handle.buffer_snapshot() {
        if socket
            .send(WsMessage::text(render_line_fragment(&line)))
            .await
            .is_err()
        {
            return;
        }
    }
    loop {
        tokio::select! {
            ev = events.recv() => match ev {
                Ok(DriverEvent::Line(line)) => {
                    if socket
                        .send(WsMessage::text(render_line_fragment(&line)))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(DriverEvent::Connected) => {
                    let _ = socket.send(WsMessage::text(render_status_fragment(ConnStatus::Connected))).await;
                }
                Ok(DriverEvent::Disconnected) => {
                    let _ = socket.send(WsMessage::text(render_status_fragment(ConnStatus::Disconnected))).await;
                }
                Err(RecvError::Lagged(n)) => {
                    // Slow client: the broadcast buffer overwrote lines this
                    // socket hadn't read. They're unrecoverable, but surface
                    // the gap rather than let it vanish silently.
                    let notice = format!(":*bnc* NOTICE * :{n} line(s) skipped (slow connection)");
                    let _ = socket.send(WsMessage::text(render_line_fragment(&notice))).await;
                }
                Err(RecvError::Closed) => break,      // driver gone
            },
            frame = socket.recv() => match frame {
                Some(Ok(WsMessage::Text(t))) => {
                    // One composer frame is exactly one upstream line; the
                    // other client→upstream paths run bytes through LineBuffer,
                    // so match that invariant here (no CRLF injection, bounded
                    // length) instead of sending the raw frame unframed.
                    if !handle.send(&sanitize_composer_line(&composer_to_irc(&t))) {
                        break; // driver gone
                    }
                }
                Some(Ok(_)) => {}
                _ => break, // close or error
            },
        }
    }
}

/// Reduce a composer-derived line to exactly one framed IRC line: cut at the
/// first embedded CR/LF (which would otherwise inject a second upstream line)
/// and bound the length to the same cap the framed transports use, truncating
/// on a UTF-8 char boundary.
pub(super) fn sanitize_composer_line(line: &str) -> String {
    let end = line.find(['\r', '\n']).unwrap_or(line.len());
    let mut line = line[..end].to_string();
    let max = e6irc_proto::message::MAX_CLIENT_FRAME_LEN;
    line.truncate(e6irc_proto::message::floor_char_boundary(&line, max));
    line
}

/// Translate a composer frame into an IRC line. The htmx web composer
/// sends a JSON form (`{"target": "#c", "message": "hi", ...}`) which
/// becomes `PRIVMSG #c :hi`, with a small set of slash-commands. A
/// non-JSON frame (e.g. a raw line from a script or test) is relayed
/// unchanged.
pub(super) fn composer_to_irc(frame: &str) -> String {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(frame) else {
        return frame.to_string();
    };
    let Some(message) = v.get("message").and_then(|m| m.as_str()) else {
        return frame.to_string();
    };
    let target = v.get("target").and_then(|t| t.as_str()).unwrap_or("");
    slash_to_irc(message, target)
}

/// Map a composer message (with the current `target`) to an IRC line.
/// Recognised slash-commands: `/raw`, `/me`, `/msg`, `/join`, `/part`,
/// `/nick`, `/topic`. Anything else is a PRIVMSG to `target`.
pub(super) fn slash_to_irc(message: &str, target: &str) -> String {
    let (cmd, rest) = match message.strip_prefix('/') {
        Some(body) => match body.split_once(' ') {
            Some((c, r)) => (c.to_ascii_lowercase(), r),
            None => (body.to_ascii_lowercase(), ""),
        },
        None => {
            return if target.is_empty() {
                message.to_string()
            } else {
                format!("PRIVMSG {target} :{message}")
            };
        }
    };
    match cmd.as_str() {
        "raw" => rest.to_string(),
        "me" => format!("PRIVMSG {target} :\u{1}ACTION {rest}\u{1}"),
        "join" | "part" | "nick" => format!("{} {rest}", cmd.to_ascii_uppercase()),
        "topic" => format!("TOPIC {target} :{rest}"),
        // `/msg <target> <text>`
        "msg" => match rest.split_once(' ') {
            Some((to, text)) => format!("PRIVMSG {to} :{text}"),
            None => rest.to_string(),
        },
        // Unknown slash-command: pass it through raw (server answers 421).
        _ => format!("{} {rest}", cmd.to_ascii_uppercase()),
    }
}

/// Escape text for safe interpolation into an HTML fragment.
pub(super) fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// One upstream line as an out-of-band append into the buffer element.
pub(super) fn render_line_fragment(line: &str) -> String {
    // Drop any IRCv3 tag prefix: the buffer stores fully-tagged lines, but the
    // web view renders the message text, not the tags.
    let line = line
        .strip_prefix('@')
        .and_then(|rest| rest.split_once(' '))
        .map_or(line, |(_, body)| body);
    format!(
        "<div hx-swap-oob=\"beforeend:#buffer\"><div class=\"line\">{}</div></div>",
        html_escape(line)
    )
}

/// A connection-status change as an OOB swap of the status element.
/// Connection state shown in the web UI's status fragment. An enum (not a
/// free `&str`) so the value interpolated into the `class` attribute is
/// closed and can never carry untrusted text.
#[derive(Clone, Copy)]
pub(super) enum ConnStatus {
    Connected,
    Disconnected,
}

impl ConnStatus {
    fn label(self) -> &'static str {
        match self {
            ConnStatus::Connected => "connected",
            ConnStatus::Disconnected => "disconnected",
        }
    }
}

pub(super) fn render_status_fragment(status: ConnStatus) -> String {
    let s = status.label();
    format!("<div id=\"status\" hx-swap-oob=\"true\" class=\"status status-{s}\">{s}</div>")
}
