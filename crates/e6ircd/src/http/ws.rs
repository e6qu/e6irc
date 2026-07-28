//! WebSocket endpoints: IRCv3-over-WebSocket and the live web UI socket.

#![deny(clippy::let_underscore_must_use)]

use super::*;

// ---- ws-irc (IRCv3-over-WebSocket, DESIGN §13.4) -------------------------

use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};

/// Inbound WebSocket frame cap. The tungstenite default (64 MiB message /
/// 16 MiB frame) is buffered whole *before* the LineBuffer can enforce the
/// IRC frame limit — an ingress asymmetry the raw-TCP path doesn't have (it
/// emits TooLong while streaming, never buffering megabytes). 64 KiB is
/// generous for pipelined IRC lines or a UI command while bounding what one
/// unauthenticated socket can pin.
const MAX_WS_FRAME: usize = 64 * 1024;

/// Outbound WebSocket frame discipline, fixed for the connection by ircv3
/// subprotocol negotiation (<https://ircv3.net/specs/extensions/websocket>).
#[derive(Clone, Copy)]
pub(super) enum WsFrameMode {
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
        state.telemetry.record_connection_rejected();
        return problem(
            StatusCode::TOO_MANY_REQUESTS,
            "Per-IP connection limit reached",
            None,
        );
    };
    // ircv3 WebSocket subprotocol negotiation: pick the client's first-offered
    // of binary.ircv3.net / text.ircv3.net (client preference order — the suite
    // requires the *client's* first choice, not the server's). Passing exactly
    // that one to `.protocols()` makes axum echo it in the response. With none
    // offered we fall back to per-line Auto framing.
    let chosen = headers
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .and_then(|list| {
            list.split(',')
                .map(str::trim)
                .find(|p| *p == "binary.ircv3.net" || *p == "text.ircv3.net")
                .map(String::from)
        });
    let mode = match chosen.as_deref() {
        Some("binary.ircv3.net") => WsFrameMode::Binary,
        Some("text.ircv3.net") => WsFrameMode::Text,
        _ => WsFrameMode::Auto,
    };
    let mut upgrade = ws
        .max_message_size(MAX_WS_FRAME)
        .max_frame_size(MAX_WS_FRAME);
    if let Some(proto) = chosen {
        upgrade = upgrade.protocols([proto]);
    }
    upgrade.on_upgrade(move |socket| ws_irc_conn(state, socket, guard, ip, mode))
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
    ip: std::net::IpAddr,
    mode: WsFrameMode,
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
            // The real client IP (X-Forwarded-For only via a trusted proxy),
            // exactly as the raw-TCP path uses `peer.ip()`. A literal here would
            // give every WS user the same hostmask, letting a banned user evade
            // KLINE/DLINE through /ws/irc and making per-user host bans impossible.
            host: ip.to_string(),
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
                // Frame type follows the negotiated subprotocol. Under Auto (no
                // subprotocol) a non-UTF-8 body goes out as a binary frame rather
                // than being corrupted by lossy U+FFFD replacement; under the
                // text subprotocol the client asked for text, so it is replaced.
                let sent = match mode {
                    WsFrameMode::Binary => socket.send(WsMessage::binary(line.to_vec())).await,
                    WsFrameMode::Text => {
                        socket
                            .send(WsMessage::text(String::from_utf8_lossy(line).into_owned()))
                            .await
                    }
                    WsFrameMode::Auto => match std::str::from_utf8(line) {
                        Ok(text) => socket.send(WsMessage::text(text)).await,
                        Err(_) => socket.send(WsMessage::binary(line.to_vec())).await,
                    },
                };
                if sent.is_err() {
                    state
                        .telemetry
                        .record_error(crate::observability::ErrorKind::Write);
                    break;
                }
            }
            // Inbound: frame(s) -> lines -> core.
            frame = socket.recv() => {
                let data: Vec<u8> = match frame {
                    Some(Ok(WsMessage::Text(t))) => t.as_bytes().to_vec(),
                    Some(Ok(WsMessage::Binary(b))) => b.to_vec(),
                    Some(Ok(_)) => continue,
                    Some(Err(_)) => {
                        state
                            .telemetry
                            .record_error(crate::observability::ErrorKind::Read);
                        break;
                    }
                    None => break,
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
    // Queue closure means the core is already gone, which has already closed
    // this connection's authoritative state.
    drop(
        core_tx
            .push(Input::Closed {
                conn,
                reason: "WebSocket closed".into(),
            })
            .await,
    );
}

// ---- live web UI socket (DESIGN §13.2) ----------------------------------

#[derive(Deserialize)]
pub(super) struct UiParams {
    /// Which of the caller's networks to attach this UI socket to.
    pub(super) network: String,
}

/// The web client's live socket: cookie-authenticated, attaches to one
/// of the caller's networks, and pushes line, status, and replay-complete JSON
/// events that the browser client parses into buffers and a member list.
/// Composer text sent up the socket is relayed to the upstream network. This
/// is the same multiplexer attach path an IRC client uses — the web client
/// *is* an attached client.
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
    // The UI only lists the account's own networks, so resolve the owned network
    // directly — never fall through to a shared network of the same name.
    let Some(handle) = registry.get_owned(&account, &params.network) else {
        return problem(StatusCode::NOT_FOUND, "No such network", None);
    };
    ws.max_message_size(MAX_WS_FRAME)
        .max_frame_size(MAX_WS_FRAME)
        .on_upgrade(move |socket| ws_ui_conn(handle, socket))
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
    // Watch the stop signal too. The event broadcast never closes while this
    // task holds an `Arc<NetworkHandle>` (the handle keeps a sender), so
    // `RecvError::Closed` alone can never fire — without this, removing or
    // disabling the network would leave the web socket open forever on a dead
    // network, leaking the task and its handle. attach() over raw IRC guards
    // the same way.
    let mut shutdown = handle.watch_shutdown();
    // The network may already have been removed between the route resolving this
    // handle and here (the whole WS upgrade handshake sits in that window). A
    // `watch::Receiver` subscribed after the shutdown was signalled treats the
    // value as already seen, so `changed()` below would never fire — check it now
    // and close, or the socket would linger forever on a dead network. attach()
    // over raw IRC guards the same way.
    if *shutdown.borrow() {
        send_unavailable(&mut socket).await;
        return;
    }
    let _attachment = handle.track_attachment();

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
        .send(WsMessage::text(status_event(status)))
        .await
        .is_err()
    {
        return;
    }

    // Playback: everything buffered while detached, as JSON line events.
    for line in handle.buffer_snapshot() {
        if socket
            .send(WsMessage::text(line_event(&line)))
            .await
            .is_err()
        {
            return;
        }
    }
    // Delimit replay from live traffic. The browser waits for this typed
    // boundary before requesting authoritative NAMES snapshots, so old NAMES
    // rows in the detached buffer cannot race and overwrite the fresh result.
    if socket
        .send(WsMessage::text(snapshot_event()))
        .await
        .is_err()
    {
        return;
    }
    loop {
        tokio::select! {
            // Network removed/replaced/disabled: send a typed terminal status
            // and detach. The browser uses it to stop its ordinary reconnect
            // loop instead of retrying a network that cannot accept a socket.
            res = shutdown.changed() => {
                if res.is_err() || *shutdown.borrow() {
                    send_unavailable(&mut socket).await;
                    break;
                }
            }
            ev = events.recv() => match ev {
                Ok(DriverEvent::Line(line)) => {
                    if socket
                        .send(WsMessage::text(line_event(&line)))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(DriverEvent::Connected) => {
                    if socket
                        .send(WsMessage::text(status_event(ConnStatus::Connected)))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(DriverEvent::Disconnected) => {
                    if socket
                        .send(WsMessage::text(status_event(ConnStatus::Disconnected)))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(RecvError::Lagged(n)) => {
                    // Slow client: the broadcast buffer overwrote lines this
                    // socket hadn't read. They're unrecoverable, but surface
                    // the gap rather than let it vanish silently.
                    let notice = format!(":*bnc* NOTICE * :{n} line(s) skipped (slow connection)");
                    if socket
                        .send(WsMessage::text(line_event(&notice)))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(RecvError::Closed) => {
                    send_unavailable(&mut socket).await;
                    break;
                }
            },
            frame = socket.recv() => match frame {
                Some(Ok(WsMessage::Text(t))) => {
                    // One composer frame is exactly one upstream line; the
                    // other client→upstream paths run bytes through LineBuffer,
                    // so match that invariant here (no CRLF injection, bounded
                    // length) instead of sending the raw frame unframed.
                    match handle.send(&sanitize_composer_line(&composer_to_irc(&t))) {
                        crate::bouncer::SendOutcome::Sent => {}
                        // Full: upstream congested/reconnecting. Tell the client
                        // its line was not sent rather than block (which would
                        // stall other clients sharing the queue) or drop silently.
                        crate::bouncer::SendOutcome::Full => {
                            let notice =
                                ":*bnc* NOTICE * :upstream busy; line not sent, try again";
                            if socket
                                .send(WsMessage::text(line_event(notice)))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        crate::bouncer::SendOutcome::Closed => {
                            send_unavailable(&mut socket).await;
                            break;
                        }
                    }
                }
                Some(Ok(_)) => {}
                _ => break, // close or error
            },
        }
    }
}

async fn send_unavailable(socket: &mut WebSocket) {
    // This is a terminal courtesy event; a failed send means the peer already
    // detached, so there is no second observer to notify.
    drop(
        socket
            .send(WsMessage::text(status_event(ConnStatus::Unavailable)))
            .await,
    );
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

/// Translate a composer frame into an IRC line. The web composer sends a JSON
/// object (`{"target": "#c", "message": "hi", ...}`) which
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

/// One upstream line as a JSON event for the web client:
/// `{"t":"line","v":"<raw IRC line>"}`. The client parses the IRC line itself
/// (routing it to a buffer, updating the nick list) and renders via safe DOM
/// APIs, so no HTML is produced here. IRCv3 tags stay intact: `server-time`
/// gives the live and persisted timelines the same clock, while `msgid` gives
/// their overlap a stable identity. `serde_json` handles all escaping.
pub(super) fn line_event(line: &str) -> String {
    serde_json::json!({ "t": "line", "v": line }).to_string()
}

/// Marks the point after detached-buffer replay and before live traffic.
pub(super) fn snapshot_event() -> String {
    serde_json::json!({ "t": "snapshot", "v": "complete" }).to_string()
}

/// Connection state sent to the web client. An enum (not a free `&str`) so the
/// emitted value is closed and can never carry untrusted text.
#[derive(Clone, Copy)]
pub(super) enum ConnStatus {
    Connected,
    Disconnected,
    Unavailable,
}

impl ConnStatus {
    fn label(self) -> &'static str {
        match self {
            ConnStatus::Connected => "connected",
            ConnStatus::Disconnected => "disconnected",
            ConnStatus::Unavailable => "unavailable",
        }
    }
}

/// A connection-status change as a JSON event: `{"t":"status","v":"connected"}`.
pub(super) fn status_event(status: ConnStatus) -> String {
    serde_json::json!({ "t": "status", "v": status.label() }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ui_line_event_preserves_message_identity_and_server_time() {
        let line = "@time=2026-07-28T20:00:00.000Z;msgid=m1 :alice!u@h PRIVMSG #chat :hello";
        let event: serde_json::Value =
            serde_json::from_str(&line_event(line)).expect("line event JSON");
        assert_eq!(event["t"], "line");
        assert_eq!(event["v"], line);
    }

    #[test]
    fn ui_snapshot_event_is_a_closed_replay_boundary() {
        let event: serde_json::Value =
            serde_json::from_str(&snapshot_event()).expect("snapshot event JSON");
        assert_eq!(
            event,
            serde_json::json!({ "t": "snapshot", "v": "complete" })
        );
    }
}
