//! WebSocket endpoints: IRCv3-over-WebSocket and the live web UI socket.

#![deny(clippy::let_underscore_must_use)]

use super::*;

// ---- ws-irc (IRCv3-over-WebSocket, DESIGN §13.4) -------------------------

use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};

/// IRCv3 WebSocket carries exactly one CRLF-stripped IRC line per message, so
/// the protocol's full client frame allowance is also the transport cap.
const MAX_IRC_WS_FRAME: usize = e6irc_proto::message::MAX_CLIENT_FRAME_LEN;
/// JSON can escape one input byte as six ASCII bytes. Bound the UI envelope
/// before deserialization while admitting every wire-sized composer command.
const MAX_UI_WS_FRAME: usize = e6irc_proto::message::MAX_CLIENT_FRAME_LEN * 6 + 512;

/// How long one outbound frame may wait for the peer to take it.
const SOCKET_SEND_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// Why an outbound frame was not delivered. Either way the connection is over.
#[derive(Debug)]
enum SendFailure {
    Transport,
    Stalled,
}

/// Write one frame, giving up on a peer that has stopped reading.
///
/// A peer that keeps the connection open but advertises a zero receive window
/// parks a bare `send` forever. The task would then never observe its network
/// being removed or its send queue being closed, and would hold the network
/// handle and the per-IP connection slot for as long as the peer liked.
async fn send_frame(socket: &mut WebSocket, frame: WsMessage) -> Result<(), SendFailure> {
    within_send_deadline(SOCKET_SEND_DEADLINE, socket.send(frame)).await
}

async fn within_send_deadline<E>(
    deadline: std::time::Duration,
    send: impl Future<Output = Result<(), E>>,
) -> Result<(), SendFailure> {
    match tokio::time::timeout(deadline, send).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(SendFailure::Transport),
        Err(_) => Err(SendFailure::Stalled),
    }
}

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
        .max_message_size(MAX_IRC_WS_FRAME)
        .max_frame_size(MAX_IRC_WS_FRAME);
    if let Some(proto) = chosen {
        upgrade = upgrade.protocols([proto]);
    }
    let conn = match state.next_conn.allocate() {
        Ok(conn) => conn,
        Err(error) => {
            eprintln!("ws-irc connection refused: {error}");
            state
                .telemetry
                .record_error(crate::observability::ErrorKind::ConnectionSetup);
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Connection service unavailable",
                None,
            );
        }
    };
    upgrade.on_upgrade(move |socket| ws_irc_conn(state, socket, guard, ip, mode, conn))
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
    ip: crate::net::ClientIp,
    mode: WsFrameMode,
    conn: crate::core::ConnId,
) {
    use crate::core::{Input, Output};
    // Held for the whole connection; its Drop releases the per-IP slot.
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
            transport: crate::core::ConnectionTransport::WebSocket,
        })
        .await
        .is_err()
    {
        return;
    }
    let core_tx = state.core_tx.clone();
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
                    WsFrameMode::Binary => send_frame(&mut socket, WsMessage::binary(line.to_vec())).await,
                    WsFrameMode::Text => {
                        send_frame(&mut socket, WsMessage::text(String::from_utf8_lossy(line).into_owned())).await
                    }
                    WsFrameMode::Auto => match std::str::from_utf8(line) {
                        Ok(text) => send_frame(&mut socket, WsMessage::text(text)).await,
                        Err(_) => send_frame(&mut socket, WsMessage::binary(line.to_vec())).await,
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
                    // Tungstenite queues matching Pong and Close replies while
                    // reading control frames; the next read flushes them.
                    Some(Ok(_)) => continue,
                    Some(Err(_)) => {
                        state
                            .telemetry
                            .record_error(crate::observability::ErrorKind::Read);
                        break;
                    }
                    None => break,
                };
                // IRCv3 WebSocket messages are already framed: one message is
                // one IRC line, with no CR/LF terminator. Feed the whole value
                // to the parser so an embedded delimiter is rejected as one
                // malformed command rather than forged into a second command.
                let input = if e6irc_proto::message::client_frame_fits(&data) {
                    Input::Line { conn, line: data }
                } else {
                    Input::OverlongLine { conn }
                };
                if core_tx.push(input).await.is_err() {
                    break 'conn; // core gone: stop the connection directly
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
#[serde(deny_unknown_fields)]
pub(super) struct UiParams {
    /// Which of the caller's networks to attach this UI socket to.
    pub(super) network: String,
    /// The cursor of the last line this client handled on an earlier socket,
    /// as a `line` or `snapshot` event carried it. Replay then holds only the
    /// lines after it; a cursor the ring cannot honour (another ring lifetime,
    /// an evicted position, or not a cursor at all) is answered with a
    /// `replay full` event and the whole ring.
    pub(super) after: Option<String>,
}

/// Whether composer frames from this socket may reach the upstream.
///
/// The upgrade is a `GET`, so the method-to-scope rule admits a `read` token.
/// Reading the stream is what `read` grants; speaking as the owner on a
/// third-party network — `/raw` included — is a write.
#[derive(Clone, Copy)]
pub(super) enum ComposerAuthority {
    MaySend,
    ReadOnly,
}

impl From<&RequestCredential> for ComposerAuthority {
    fn from(credential: &RequestCredential) -> Self {
        if credential.grants_write() {
            Self::MaySend
        } else {
            Self::ReadOnly
        }
    }
}

/// Refuse a browser upgrade from any origin but this application's.
///
/// `SameSite=Lax` keeps the session cookie off a cross-*site* handshake, but a
/// sibling subdomain is same-site: its page could open this socket with the
/// owner's cookie, read private-message replay, and send `/raw`. The origin to
/// compare against is the configured public URL; without one it is the
/// authority the browser itself addressed (`Host`), and an `Origin` that
/// matches neither is refused rather than waved through. A request with no
/// `Origin` is not a browser and carries no ambient cookie authority.
fn require_same_origin_upgrade(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> ResponseResult<()> {
    let Some(origin) = headers.get(header::ORIGIN) else {
        return Ok(());
    };
    let verified = origin
        .to_str()
        .is_ok_and(|origin| match state.public_url.as_deref() {
            Some(public) => same_origin(origin, public),
            None => headers
                .get(header::HOST)
                .and_then(|host| host.to_str().ok())
                .is_some_and(|host| origin_names_host(origin, host)),
        });
    if verified {
        return Ok(());
    }
    Err(ResponseRejection::from(problem(
        StatusCode::FORBIDDEN,
        "Cross-origin WebSocket rejected",
        Some(if state.public_url.is_some() {
            "The Origin header does not match the configured public URL."
        } else {
            "The Origin header does not match the Host header. Configure the public URL when a proxy rewrites Host."
        }),
    )))
}

/// Whether a serialized `Origin` (`scheme://host[:port]`) names exactly the
/// authority in `Host`. Both come from the same browser, which omits a default
/// port from both, so the comparison needs no knowledge of the scheme — which
/// the server does not have behind a TLS-terminating proxy.
fn origin_names_host(origin: &str, host: &str) -> bool {
    origin.split_once("://").is_some_and(|(scheme, authority)| {
        matches!(scheme, "http" | "https")
            && !authority.is_empty()
            && authority.eq_ignore_ascii_case(host)
    })
}

/// Most live chat sockets one account may hold at once, across all of its
/// networks and browser sessions. The web client holds one per open tab, so
/// this matches the most browser sessions an account may have
/// (`MAX_BROWSER_SESSIONS_PER_ACCOUNT`). Each socket is a task, a broadcast
/// subscription with its replay, and a slot in the service-wide connection
/// bound; without a per-account bound one credential could take all of them.
pub(crate) const MAX_UI_SOCKETS_PER_ACCOUNT: usize = 32;

/// WebSocket close code 1008, "policy violation" (RFC 6455 §7.4.1).
const CLOSE_POLICY_VIOLATION: u16 = 1008;

/// What a refused socket's close frame says. The web client shows a close
/// reason verbatim; a close reason is at most 123 bytes.
const UI_SOCKET_LIMIT_REASON: &str = "This account has 32 live chat connections open, the most allowed. Close another tab and retry.";

/// Live chat sockets open per folded account.
pub(crate) struct UiSocketLimiter {
    open: Mutex<HashMap<String, usize>>,
}

/// One account's admission to hold one live chat socket, for as long as the
/// socket's task runs.
pub(crate) struct UiSocketSlot {
    limiter: Arc<UiSocketLimiter>,
    account: String,
}

impl UiSocketLimiter {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            open: Mutex::default(),
        })
    }

    /// A slot for `account`, or `None` when it already holds
    /// [`MAX_UI_SOCKETS_PER_ACCOUNT`].
    fn admit(self: &Arc<Self>, account: &str) -> Option<UiSocketSlot> {
        let account = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(account);
        let mut open = self.open.lock().expect("live chat socket limiter lock");
        let held = open.entry(account.clone()).or_insert(0);
        if *held >= MAX_UI_SOCKETS_PER_ACCOUNT {
            return None;
        }
        *held += 1;
        Some(UiSocketSlot {
            limiter: self.clone(),
            account,
        })
    }
}

impl Drop for UiSocketSlot {
    fn drop(&mut self) {
        let mut open = self
            .limiter
            .open
            .lock()
            .expect("live chat socket limiter lock");
        if let Some(held) = open.get_mut(&self.account) {
            *held -= 1;
            if *held == 0 {
                open.remove(&self.account);
            }
        }
    }
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
    Authenticated(account, credential): Authenticated,
    QueryParams(params): QueryParams<UiParams>,
    ws: WebSocketUpgrade,
) -> Response {
    if let Err(refusal) = require_same_origin_upgrade(&state, &headers) {
        return refusal.into();
    }
    let composer = ComposerAuthority::from(&credential);
    let Some(registry) = &state.bnc_registry else {
        return problem(StatusCode::NOT_FOUND, "Bouncer not enabled", None);
    };
    // The UI only lists the account's own networks, so resolve the owned network
    // directly — never fall through to a shared network of the same name.
    let Some(handle) = registry.get_owned(&account, &params.network) else {
        return problem(StatusCode::NOT_FOUND, "No such network", None);
    };
    // Counted before the upgrade, so sockets still in their handshake count.
    let slot = state.ui_sockets.admit(&account);
    let resume = params.after.as_deref().map(ReplayRequest::from_cursor);
    ws.max_message_size(MAX_UI_WS_FRAME)
        .max_frame_size(MAX_UI_WS_FRAME)
        .on_upgrade(move |socket| {
            ws_ui_conn(
                handle,
                socket,
                composer,
                slot,
                resume,
                crate::bouncer::ATTACH_LIVENESS_INTERVAL,
            )
        })
}

/// What a returning client asked replay to start from.
#[derive(Clone, Copy)]
pub(super) enum ReplayRequest {
    /// A well-formed cursor; the ring decides whether it can still honour it.
    After(crate::bouncer::ReplayCursor),
    /// Text that is not a cursor. The client believes it has history, so it
    /// is told to start over rather than left to guess.
    Unknown,
}

impl ReplayRequest {
    fn from_cursor(text: &str) -> Self {
        crate::bouncer::ReplayCursor::parse(text).map_or(Self::Unknown, Self::After)
    }
}

/// Serve one live chat socket until either side ends it.
///
/// `slot` is the account's admission; without one the socket is closed at once
/// with a policy-violation code and a reason — after the upgrade, because a
/// browser gives its page no status or body for a refused upgrade, only a
/// close frame's code and reason.
///
/// `liveness` bounds how long a silent peer is believed: after one interval
/// without a frame it is sent a WebSocket Ping, and after a second it is given
/// up on. A browser answers Ping by itself, so a live peer on a quiet network
/// costs one small frame per interval, and a half-open connection — a laptop
/// that slept, a NAT that forgot the flow — stops holding its task, its socket,
/// and its place in the attached-client count.
pub(super) async fn ws_ui_conn(
    handle: std::sync::Arc<crate::bouncer::NetworkHandle>,
    mut socket: WebSocket,
    composer: ComposerAuthority,
    slot: Option<UiSocketSlot>,
    resume: Option<ReplayRequest>,
    liveness: std::time::Duration,
) {
    use crate::bouncer::DriverEvent;
    use tokio::sync::broadcast::error::RecvError;

    let Some(_slot) = slot else {
        let close = axum::extract::ws::CloseFrame {
            code: CLOSE_POLICY_VIOLATION,
            reason: UI_SOCKET_LIMIT_REASON.into(),
        };
        drop(send_frame(&mut socket, WsMessage::Close(Some(close))).await);
        return;
    };

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
    if !handle.wait_for_history().await {
        send_unavailable(&mut socket).await;
        return;
    }
    let _attachment = handle.track_attachment();
    let attach_id = handle.next_attachment_id();
    let after = match resume {
        Some(ReplayRequest::After(cursor)) => Some(cursor),
        Some(ReplayRequest::Unknown) | None => None,
    };
    let (mut events, replay, session_snapshot) = handle.subscribe_with_replay_snapshot(after);
    // Every line event names the ring position after it, so a client that
    // loses this socket can hand back exactly where it stopped. A live event
    // that entered no ring keeps the position where it was.
    let mut cursor = replay.position();

    // Send the current connection status up front: a driver is always-on, so a
    // client attaching to an already-connected network would otherwise see no
    // status until the next connect/disconnect transition. The sticky flag
    // exists precisely to close this subscribe-timing gap.
    let runtime = handle.runtime_snapshot();
    let mut status_revision = runtime.status_revision;
    if send_frame(&mut socket, WsMessage::text(runtime_status_event(&runtime)))
        .await
        .is_err()
    {
        return;
    }

    // A client that presented a cursor the ring could not honour holds a
    // transcript this replay does not continue: say so first, so it starts
    // over instead of showing the ring twice.
    if resume.is_some()
        && !replay.resumed
        && send_frame(&mut socket, WsMessage::text(replay_full_event()))
            .await
            .is_err()
    {
        return;
    }

    // Playback: everything buffered while detached (or after the cursor), as
    // JSON line events.
    for entry in &replay.lines {
        let entry_cursor = replay.cursor_at(entry.seq);
        if send_frame(
            &mut socket,
            WsMessage::text(line_event(&entry.line, entry_cursor)),
        )
        .await
        .is_err()
        {
            return;
        }
    }
    // A bounded replay is history, not current state. Reconcile the driver's
    // authoritative identity and memberships after it so an aged-out JOIN or a
    // stale PART cannot leave the browser attached to the wrong conversations.
    if let Some(session) = session_snapshot
        && send_frame(&mut socket, WsMessage::text(session_event(&session)))
            .await
            .is_err()
    {
        return;
    }
    // Delimit replay from live traffic. The browser waits for this typed
    // boundary before requesting authoritative NAMES snapshots, so old NAMES
    // rows in the detached buffer cannot race and overwrite the fresh result.
    // It carries the ring position after the replay, so a client that saw no
    // line still has a cursor to return with.
    if send_frame(&mut socket, WsMessage::text(snapshot_event(cursor)))
        .await
        .is_err()
    {
        return;
    }
    let mut peer_silence = crate::bouncer::SilenceDeadline::new(liveness);
    let mut awaiting_pong = false;
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
                Ok(DriverEvent::Line(entry) | DriverEvent::Notice(entry)) => {
                    cursor = replay.cursor_at(entry.seq);
                    if send_frame(&mut socket, WsMessage::text(line_event(&entry.line, cursor))).await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(DriverEvent::Echo { line: entry, origin }) => {
                    // The echo took a ring position whether or not this socket
                    // renders it, so the cursor moves past it either way: a
                    // resume must not replay this client its own line.
                    cursor = replay.cursor_at(entry.seq);
                    // This socket already rendered its own line optimistically
                    // with the correlated `sent` acknowledgement; an echo of it
                    // would double-render. Echoes from the account's *other*
                    // sessions are real conversation and render normally.
                    if origin != attach_id
                        && send_frame(&mut socket, WsMessage::text(line_event(&entry.line, cursor))).await
                            .is_err()
                    {
                        break;
                    }
                }
                Ok(DriverEvent::Status { status, revision }) => {
                    if !crate::bouncer::accept_status_revision(&mut status_revision, revision) {
                        continue;
                    }
                    if send_frame(&mut socket, WsMessage::text(driver_status_event(status))).await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(DriverEvent::Session(session)) => {
                    if send_frame(&mut socket, WsMessage::text(session_event(&session))).await
                        .is_err()
                    {
                        break;
                    }
                }
                // Browser chat does not negotiate the raw IRC read-marker
                // capability; account-scoped marker fanout belongs only to
                // authenticated raw attaches that opted into it.
                Ok(DriverEvent::ReadMarker { .. }) => {}
                Err(RecvError::Lagged(n)) => {
                    // The cursor still names the last line this socket sent, so
                    // the reconnect below resumes with exactly the skipped
                    // lines — the ring holds them even though the broadcast
                    // queue dropped them.
                    let notice = format!(":*bnc* NOTICE * :{n} line(s) skipped (slow connection)");
                    if send_frame(&mut socket, WsMessage::text(line_event(&notice, cursor))).await
                        .is_err()
                    {
                        break;
                    }
                    // Continuing after a lost state-changing line could leave
                    // the browser on a stale nick or channel set. Detach so its
                    // ordinary reconnect establishes a fresh atomic replay and
                    // authoritative session snapshot.
                    break;
                }
                Err(RecvError::Closed) => {
                    send_unavailable(&mut socket).await;
                    break;
                }
            },
            frame = peer_silence.bound(socket.recv()) => {
                let Some(frame) = frame else {
                    if awaiting_pong {
                        break;
                    }
                    awaiting_pong = true;
                    peer_silence.restart();
                    if send_frame(&mut socket, WsMessage::Ping(Default::default())).await.is_err() {
                        break;
                    }
                    continue;
                };
                // Any frame is a sign of life, not only the Pong.
                awaiting_pong = false;
                peer_silence.restart();
                match frame {
                Some(Ok(WsMessage::Text(t))) => {
                    let request = match composer_request(&t) {
                        Ok(request) => request,
                        Err(error) => {
                            let event = composer_result_event(cursor, ComposerResult::Rejected {
                                request_id: error.request_id.as_ref().map(ComposerRequestId::as_str),
                                message: error.message,
                            });
                            if send_frame(&mut socket, WsMessage::text(event)).await.is_err() {
                                break;
                            }
                            continue;
                        }
                    };
                    if let ComposerAuthority::ReadOnly = composer {
                        let event = composer_result_event(cursor, ComposerResult::Rejected {
                            request_id: request.request_id.as_ref().map(ComposerRequestId::as_str),
                            message: "this token is read-only; sending needs the write scope. Nothing was sent",
                        });
                        if send_frame(&mut socket, WsMessage::text(event)).await.is_err() {
                            break;
                        }
                        continue;
                    }
                    match handle.send_from(attach_id, &request.line) {
                        crate::bouncer::SendOutcome::Sent => {
                            if let Some(request_id) = request.request_id
                                && send_frame(
                                    &mut socket,
                                    WsMessage::text(composer_result_event(cursor, ComposerResult::Sent(
                                        request_id.as_str(),
                                    ))),
                                )
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        crate::bouncer::SendOutcome::Full => {
                            let event = composer_result_event(cursor, ComposerResult::Rejected {
                                request_id: request.request_id.as_ref().map(ComposerRequestId::as_str),
                                message: "upstream busy; line not sent, try again",
                            });
                            if send_frame(&mut socket, WsMessage::text(event)).await.is_err() {
                                break;
                            }
                        }
                        crate::bouncer::SendOutcome::Closed => {
                            send_unavailable(&mut socket).await;
                            break;
                        }
                        crate::bouncer::SendOutcome::Unavailable => {
                            let event = composer_result_event(cursor, ComposerResult::Rejected {
                                request_id: request.request_id.as_ref().map(ComposerRequestId::as_str),
                                message: "upstream registration is parked; reconfigure the network before sending",
                            });
                            if send_frame(&mut socket, WsMessage::text(event)).await.is_err() {
                                break;
                            }
                        }
                        crate::bouncer::SendOutcome::Rejected(error) => {
                            let event = composer_result_event(cursor, ComposerResult::Rejected {
                                request_id: request.request_id.as_ref().map(ComposerRequestId::as_str),
                                message: error.message(),
                            });
                            if send_frame(&mut socket, WsMessage::text(event)).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                Some(Ok(WsMessage::Binary(_))) => {
                    let event = composer_result_event(cursor, ComposerResult::Rejected {
                        request_id: None,
                        message: "composer requests must be text JSON",
                    });
                    if send_frame(&mut socket, WsMessage::text(event)).await.is_err() {
                        break;
                    }
                }
                Some(Ok(WsMessage::Ping(payload))) => {
                    if send_frame(&mut socket, WsMessage::Pong(payload)).await.is_err() {
                        break;
                    }
                }
                Some(Ok(WsMessage::Pong(_))) => {}
                Some(Ok(WsMessage::Close(_))) | Some(Err(_)) | None => break,
                }
            },
        }
    }
}

async fn send_unavailable(socket: &mut WebSocket) {
    drop(
        send_frame(
            socket,
            WsMessage::text(status_event(ConnStatus::Unavailable, None)),
        )
        .await,
    );
}

#[derive(Debug)]
struct ComposerRequest {
    line: String,
    request_id: Option<ComposerRequestId>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposerFrame {
    #[serde(default, deserialize_with = "composer_request_id")]
    id: Option<ComposerRequestId>,
    target: String,
    message: String,
}

#[derive(Debug)]
struct ComposerRequestId(String);

impl ComposerRequestId {
    fn parse(value: String) -> Result<Self, ComposerRequestError> {
        if !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Ok(Self(value));
        }
        Err(ComposerRequestError {
            request_id: None,
            message: "invalid composer request identifier",
        })
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

fn composer_request_id<'de, D>(deserializer: D) -> Result<Option<ComposerRequestId>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct RequestId;

    impl<'de> serde::de::Visitor<'de> for RequestId {
        type Value = Option<ComposerRequestId>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a composer request identifier")
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let value = String::deserialize(deserializer)?;
            ComposerRequestId::parse(value)
                .map(Some)
                .map_err(|error| serde::de::Error::custom(error.message))
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Err(E::custom("composer request identifier cannot be null"))
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            self.visit_none()
        }
    }

    deserializer.deserialize_option(RequestId)
}

#[derive(Debug)]
struct ComposerRequestError {
    request_id: Option<ComposerRequestId>,
    message: &'static str,
}

/// Why the composer will not send `command` upstream, if it will not.
///
/// The upstream session belongs to the bouncer: it stays connected while no
/// browser is open, so a `QUIT` from one tab would end what the product exists
/// to keep. Liveness, capability negotiation, authentication, history, and read
/// markers are the attach layer's conversation with its own client — the raw
/// attach path answers them locally and never forwards them. This is asked of
/// the command the final line parses to, so `/raw`, `/quote`, tags, a source
/// prefix, or letter case cannot carry one past it.
fn composer_command_refusal(command: &str) -> Option<&'static str> {
    const SESSION: &str = "QUIT would disconnect this always-on network; disable the network instead. Nothing was sent";
    const ATTACH_LAYER: &str =
        "e6irc answers this command itself, so the network never sees it. Nothing was sent";
    match command.to_ascii_uppercase().as_str() {
        "QUIT" => Some(SESSION),
        "PING" | "PONG" | "CAP" | "AUTHENTICATE" | "CHATHISTORY" | "MARKREAD" => Some(ATTACH_LAYER),
        _ => None,
    }
}

/// Parse and bound one browser composer frame.
fn composer_request(frame: &str) -> Result<ComposerRequest, ComposerRequestError> {
    if frame.len() > MAX_UI_WS_FRAME {
        return Err(ComposerRequestError {
            request_id: None,
            message: "composer request exceeds the bounded envelope",
        });
    }
    let frame = serde_json::from_str::<ComposerFrame>(frame).map_err(|_| ComposerRequestError {
        request_id: None,
        message: "invalid composer request",
    })?;
    let line = match slash_to_irc(&frame.message, &frame.target) {
        Ok(line) => line,
        Err(message) => {
            return Err(ComposerRequestError {
                request_id: frame.id,
                message,
            });
        }
    };
    if line.contains(['\r', '\n', '\0']) {
        return Err(ComposerRequestError {
            request_id: frame.id,
            message: "message contains an invalid line delimiter; nothing was sent",
        });
    }
    if !e6irc_proto::message::client_frame_fits(line.as_bytes()) {
        return Err(ComposerRequestError {
            request_id: frame.id,
            message: "message exceeds the IRC wire limit; nothing was sent",
        });
    }
    let refusal = match e6irc_proto::message::Message::parse(&line) {
        Ok(message) => composer_command_refusal(message.command),
        Err(_) => Some("message is not a complete IRC command; nothing was sent"),
    };
    if let Some(message) = refusal {
        return Err(ComposerRequestError {
            request_id: frame.id,
            message,
        });
    }
    Ok(ComposerRequest {
        line,
        request_id: frame.id,
    })
}

enum ComposerResult<'a> {
    Sent(&'a str),
    Rejected {
        request_id: Option<&'a str>,
        message: &'a str,
    },
}

#[derive(serde::Serialize)]
#[serde(tag = "t")]
enum UiEvent<'a> {
    #[serde(rename = "line")]
    Line {
        v: &'a str,
        /// The ring position after this line, to resume from (`?after=`).
        cursor: String,
    },
    #[serde(rename = "sent")]
    Sent { v: &'a str },
    #[serde(rename = "send-error")]
    SendError { v: &'a str, message: &'a str },
    #[serde(rename = "snapshot")]
    Snapshot { v: &'static str, cursor: String },
    /// The presented cursor could not be honoured; the whole ring follows and
    /// the client's transcript starts over.
    #[serde(rename = "replay")]
    Replay { v: &'static str },
    #[serde(rename = "session")]
    Session {
        nick: &'a str,
        channels: &'a [String],
    },
    #[serde(rename = "status")]
    Status {
        v: ConnStatus,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<&'a str>,
    },
}

fn ui_event(event: UiEvent<'_>) -> String {
    serde_json::to_string(&event).expect("UI event serialization is infallible")
}

/// `cursor` is the socket's current ring position: a rejection that cannot be
/// correlated is shown as a notice line, and a notice line, like every line,
/// says where the ring stands (unchanged — it entered no ring).
fn composer_result_event(
    cursor: crate::bouncer::ReplayCursor,
    result: ComposerResult<'_>,
) -> String {
    match result {
        ComposerResult::Sent(request_id) => ui_event(UiEvent::Sent { v: request_id }),
        ComposerResult::Rejected {
            request_id: Some(request_id),
            message,
        } => ui_event(UiEvent::SendError {
            v: request_id,
            message,
        }),
        ComposerResult::Rejected {
            request_id: None,
            message,
        } => line_event(&format!(":*bnc* NOTICE * :{message}"), cursor),
    }
}

/// Map a composer message to one complete IRC command.
pub(super) fn slash_to_irc(message: &str, target: &str) -> Result<String, &'static str> {
    let (cmd, rest) = match message.strip_prefix('/') {
        Some(body) => match body.split_once(' ') {
            Some((c, r)) => (c.to_ascii_lowercase(), r),
            None => (body.to_ascii_lowercase(), ""),
        },
        None => {
            if target.is_empty() {
                return Err("select a channel or direct message before sending; nothing was sent");
            }
            if message.is_empty() {
                return Err("message is empty; nothing was sent");
            }
            return Ok(format!("PRIVMSG {target} :{message}"));
        }
    };
    let rest = rest.trim_start();
    let line = match cmd.as_str() {
        "" => return Err("slash command is empty; nothing was sent"),
        "raw" if rest.is_empty() => return Err("/raw requires an IRC command; nothing was sent"),
        "raw" => rest.to_string(),
        "me" if target.is_empty() => {
            return Err("/me requires an active conversation; nothing was sent");
        }
        "me" if rest.is_empty() => return Err("/me requires action text; nothing was sent"),
        "me" => format!("PRIVMSG {target} :\u{1}ACTION {rest}\u{1}"),
        "join" if rest.is_empty() => return Err("/join requires a channel; nothing was sent"),
        "join" => format!("JOIN {rest}"),
        "part" if rest.is_empty() && target.is_empty() => {
            return Err("/part requires an active channel or channel name; nothing was sent");
        }
        "part" if rest.is_empty() => format!("PART {target}"),
        "part" => format!("PART {rest}"),
        "nick" if rest.is_empty() => return Err("/nick requires a nickname; nothing was sent"),
        "nick" => format!("NICK {rest}"),
        "topic" if target.is_empty() => {
            return Err("/topic requires an active channel; nothing was sent");
        }
        "topic" => format!("TOPIC {target} :{rest}"),
        // `/msg <target> <text>`
        "msg" => {
            let Some((to, text)) = rest.split_once(char::is_whitespace) else {
                return Err("/msg requires a target and message; nothing was sent");
            };
            let text = text.trim_start();
            if to.is_empty() || text.is_empty() {
                return Err("/msg requires a target and message; nothing was sent");
            }
            format!("PRIVMSG {to} :{text}")
        }
        "notice" => {
            let Some((to, text)) = rest.split_once(char::is_whitespace) else {
                return Err("/notice requires a target and message; nothing was sent");
            };
            let text = text.trim_start();
            if to.is_empty() || text.is_empty() {
                return Err("/notice requires a target and message; nothing was sent");
            }
            format!("NOTICE {to} :{text}")
        }
        "quote" if rest.is_empty() => {
            return Err("/quote requires an IRC command; nothing was sent");
        }
        "quote" => rest.to_string(),
        // Unknown slash-command: pass it through raw (server answers 421).
        _ => format!("{} {rest}", cmd.to_ascii_uppercase()),
    };
    Ok(line)
}

/// One upstream line as a JSON event for the web client:
/// `{"t":"line","v":"<raw IRC line>"}`. The client parses the IRC line itself
/// (routing it to a buffer, updating the nick list) and renders via safe DOM
/// APIs, so no HTML is produced here. IRCv3 tags stay intact: `server-time`
/// gives the live and persisted timelines the same clock, while `msgid` gives
/// their overlap a stable identity. `serde_json` handles all escaping.
pub(super) fn line_event(line: &str, cursor: crate::bouncer::ReplayCursor) -> String {
    ui_event(UiEvent::Line {
        v: line,
        cursor: cursor.to_string(),
    })
}

/// Marks the point after detached-buffer replay and before live traffic, and
/// names the ring position there.
pub(super) fn snapshot_event(cursor: crate::bouncer::ReplayCursor) -> String {
    ui_event(UiEvent::Snapshot {
        v: "complete",
        cursor: cursor.to_string(),
    })
}

/// Tells a returning client its cursor was not honoured: the whole ring
/// follows, and its transcript starts over.
pub(super) fn replay_full_event() -> String {
    ui_event(UiEvent::Replay { v: "full" })
}

fn session_event(session: &crate::bouncer::IrcSessionSnapshot) -> String {
    ui_event(UiEvent::Session {
        nick: &session.nick,
        channels: &session.channels,
    })
}

/// Connection state sent to the web client. An enum (not a free `&str`) so the
/// emitted value is closed and can never carry untrusted text.
#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ConnStatus {
    Connected,
    Disconnected,
    Unavailable,
}

fn runtime_status_event(runtime: &crate::bouncer::NetworkRuntimeSnapshot) -> String {
    let (status, reason) = if runtime.lifecycle == crate::bouncer::NetworkLifecycle::Connected {
        (ConnStatus::Connected, None)
    } else {
        (
            ConnStatus::Disconnected,
            runtime.last_error.map(|failure| failure.summary()),
        )
    };
    status_event(status, reason)
}

fn driver_status_event(status: crate::bouncer::DriverConnectionStatus) -> String {
    let ui_status = if status.lifecycle() == crate::bouncer::NetworkLifecycle::Connected {
        ConnStatus::Connected
    } else {
        ConnStatus::Disconnected
    };
    status_event(ui_status, status.failure().map(|failure| failure.summary()))
}

/// A connection-status change as a JSON event:
/// `{"t":"status","v":"disconnected","reason":"…"}`. The optional reason is
/// the classified failure summary, so the chat UI can say *why* the upstream
/// is reconnecting instead of leaving the user to guess.
pub(super) fn status_event(status: ConnStatus, reason: Option<&str>) -> String {
    ui_event(UiEvent::Status { v: status, reason })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connected_sticky_status_does_not_serialize_a_historical_failure() {
        let (handle, ends) = crate::bouncer::NetworkHandle::channels(8);
        ends.emit(crate::bouncer::ConnectionEvent::Reconnecting(
            crate::bouncer::NetworkFailure::ConnectionLost,
        ));
        ends.emit(crate::bouncer::ConnectionEvent::Connected);

        let event: serde_json::Value =
            serde_json::from_str(&runtime_status_event(&handle.runtime_snapshot()))
                .expect("status event JSON");
        assert_eq!(
            event,
            serde_json::json!({ "t": "status", "v": "connected" })
        );
    }

    fn cursor(text: &str) -> crate::bouncer::ReplayCursor {
        crate::bouncer::ReplayCursor::parse(text).expect("test cursor")
    }

    #[test]
    fn ui_line_event_preserves_message_identity_and_server_time() {
        let line = "@time=2026-07-28T20:00:00.000Z;msgid=m1 :alice!u@h PRIVMSG #chat :hello";
        let event: serde_json::Value =
            serde_json::from_str(&line_event(line, cursor("7:42"))).expect("line event JSON");
        assert_eq!(event["t"], "line");
        assert_eq!(event["v"], line);
        assert_eq!(event["cursor"], "7:42");
    }

    #[test]
    fn ui_snapshot_event_is_a_closed_replay_boundary() {
        let event: serde_json::Value =
            serde_json::from_str(&snapshot_event(cursor("7:42"))).expect("snapshot event JSON");
        assert_eq!(
            event,
            serde_json::json!({ "t": "snapshot", "v": "complete", "cursor": "7:42" })
        );
    }

    #[test]
    fn ui_events_have_exact_shapes() {
        let cases = [
            (
                line_event("PING :server", cursor("7:42")),
                serde_json::json!({ "t": "line", "v": "PING :server", "cursor": "7:42" }),
            ),
            (
                replay_full_event(),
                serde_json::json!({ "t": "replay", "v": "full" }),
            ),
            (
                composer_result_event(cursor("7:42"), ComposerResult::Sent("a1")),
                serde_json::json!({ "t": "sent", "v": "a1" }),
            ),
            (
                composer_result_event(
                    cursor("7:42"),
                    ComposerResult::Rejected {
                        request_id: Some("a1"),
                        message: "not sent",
                    },
                ),
                serde_json::json!({ "t": "send-error", "v": "a1", "message": "not sent" }),
            ),
            (
                composer_result_event(
                    cursor("7:42"),
                    ComposerResult::Rejected {
                        request_id: None,
                        message: "not sent",
                    },
                ),
                serde_json::json!({ "t": "line", "v": ":*bnc* NOTICE * :not sent", "cursor": "7:42" }),
            ),
            (
                status_event(ConnStatus::Connected, None),
                serde_json::json!({ "t": "status", "v": "connected" }),
            ),
            (
                status_event(ConnStatus::Disconnected, Some("connection lost")),
                serde_json::json!({ "t": "status", "v": "disconnected", "reason": "connection lost" }),
            ),
            (
                status_event(ConnStatus::Unavailable, None),
                serde_json::json!({ "t": "status", "v": "unavailable" }),
            ),
            (
                session_event(&crate::bouncer::IrcSessionSnapshot {
                    nick: "alice".to_string(),
                    channels: vec!["#one".to_string(), "#two".to_string()],
                }),
                serde_json::json!({
                    "t": "session",
                    "nick": "alice",
                    "channels": ["#one", "#two"]
                }),
            ),
        ];
        for (wire, expected) in cases {
            let event: serde_json::Value = serde_json::from_str(&wire).expect("UI event JSON");
            assert_eq!(event, expected, "{wire}");
        }
    }

    #[test]
    fn driver_status_event_preserves_the_emitted_failure() {
        let event: serde_json::Value = serde_json::from_str(&driver_status_event(
            crate::bouncer::DriverConnectionStatus::RegistrationFailed(
                crate::bouncer::NetworkFailure::InvalidNickname,
            ),
        ))
        .expect("status JSON");
        assert_eq!(
            event,
            serde_json::json!({
                "t": "status",
                "v": "disconnected",
                "reason": "The upstream rejected the configured nickname."
            })
        );
    }

    #[test]
    fn ui_query_rejects_unknown_fields() {
        let uri = "/?network=libera&extra=1".parse().expect("query URI");
        assert!(Query::<UiParams>::try_from_uri(&uri).is_err());
    }

    #[test]
    fn composer_request_is_correlated_and_never_truncated() {
        let request =
            composer_request(r##"{"id":"send-1","target":"#rust","message":"hi"}"##).unwrap();
        assert_eq!(
            request.request_id.as_ref().map(ComposerRequestId::as_str),
            Some("send-1")
        );
        assert_eq!(request.line, "PRIVMSG #rust :hi");

        let injection =
            composer_request(r##"{"id":"send-2","target":"#rust","message":"hi\r\nJOIN #bad"}"##)
                .expect_err("embedded delimiter must reject the whole request");
        assert_eq!(
            injection.request_id.as_ref().map(ComposerRequestId::as_str),
            Some("send-2")
        );
        assert!(injection.message.contains("nothing was sent"));

        let frame = serde_json::json!({
            "id": "send-3",
            "target": "#rust",
            "message": "x".repeat(e6irc_proto::message::MAX_LINE_LEN),
        })
        .to_string();
        let overlong = composer_request(&frame).expect_err("over-long line must be refused");
        assert_eq!(
            overlong.request_id.as_ref().map(ComposerRequestId::as_str),
            Some("send-3")
        );
        assert!(overlong.message.contains("wire limit"));

        let tagged = serde_json::json!({
            "id": "send-tags",
            "target": "",
            "message": format!("/raw @example={} TAGMSG #rust", "a".repeat(600)),
        })
        .to_string();
        assert!(
            composer_request(&tagged)
                .expect("the independent client-tag allowance")
                .line
                .starts_with("@example=")
        );

        let oversized_envelope = "x".repeat(MAX_UI_WS_FRAME + 1);
        assert!(
            composer_request(&oversized_envelope)
                .expect_err("oversized JSON envelope")
                .message
                .contains("bounded envelope")
        );

        for malformed in [
            r##"{"id":"send-4","target":"","message":"/raw"}"##,
            r##"{"id":"send-5","target":"","message":""}"##,
            r##"{"id":"send-6","target":"#rust","message":"/msg bob"}"##,
            r##"{"id":"send-7","target":"","message":"hello"}"##,
            r##"{"id":"send-8","target":"","message":"/me waves"}"##,
        ] {
            let error = composer_request(malformed)
                .expect_err("an empty IRC command must not be acknowledged as sent");
            assert!(error.message.contains("nothing was sent"), "{error:?}");
        }
    }

    #[test]
    fn composer_refuses_commands_that_are_not_the_upstreams_to_answer() {
        for message in [
            "/quit",
            "/QUIT bye",
            "/raw QUIT :bye",
            "/quote quit",
            "/raw @label=x :nick QUIT",
            "/ping x",
            "/raw PONG :x",
            "/raw CAP LS",
            "/raw AUTHENTICATE PLAIN",
            "/chathistory LATEST #rust * 10",
            "/raw MARKREAD #rust",
        ] {
            let frame = serde_json::json!({ "id": "a1", "target": "#rust", "message": message });
            let error = composer_request(&frame.to_string()).expect_err(message);
            assert_eq!(
                error.request_id.as_ref().map(ComposerRequestId::as_str),
                Some("a1")
            );
            assert!(
                error.message.contains("othing was sent"),
                "{message}: {}",
                error.message
            );
        }
        // Text that merely mentions a command is conversation.
        for message in ["QUIT", "/me will QUIT soon", "/msg friend PING me"] {
            let frame = serde_json::json!({ "target": "#rust", "message": message });
            assert!(composer_request(&frame.to_string()).is_ok(), "{message}");
        }
    }

    #[test]
    fn composer_request_is_a_closed_json_contract() {
        let uncorrelated = composer_request(r##"{"target":"","message":"/join #rust"}"##)
            .expect("uncorrelated command");
        assert_eq!(uncorrelated.line, "JOIN #rust");
        assert!(uncorrelated.request_id.is_none());

        for frame in [
            "not JSON",
            "null",
            "[]",
            r##"{}"##,
            r##"{"target":"#rust"}"##,
            r##"{"message":"hello"}"##,
            r##"{"target":1,"message":"hello"}"##,
            r##"{"target":"#rust","message":1}"##,
            r##"{"id":null,"target":"#rust","message":"hello"}"##,
            r##"{"id":"bad_id","target":"#rust","message":"hello"}"##,
            &format!(
                r##"{{"id":"{}","target":"#rust","message":"hello"}}"##,
                "x".repeat(65)
            ),
            r##"{"target":"#rust","message":"hello","extra":true}"##,
        ] {
            assert!(composer_request(frame).is_err(), "accepted {frame}");
        }
    }

    #[test]
    fn composer_results_are_typed_and_request_correlated() {
        let accepted: serde_json::Value = serde_json::from_str(&composer_result_event(
            cursor("7:42"),
            ComposerResult::Sent("a1"),
        ))
        .unwrap();
        assert_eq!(accepted, serde_json::json!({ "t": "sent", "v": "a1" }));

        let rejected: serde_json::Value = serde_json::from_str(&composer_result_event(
            cursor("7:42"),
            ComposerResult::Rejected {
                request_id: Some("a2"),
                message: "not sent",
            },
        ))
        .unwrap();
        assert_eq!(rejected["t"], "send-error");
        assert_eq!(rejected["v"], "a2");
        assert_eq!(rejected["message"], "not sent");
    }
}

#[cfg(test)]
mod send_deadline_tests {
    use super::{SendFailure, within_send_deadline};

    #[tokio::test]
    async fn a_peer_that_never_takes_the_frame_ends_the_send() {
        let deadline = std::time::Duration::from_millis(20);
        let stalled =
            within_send_deadline(deadline, std::future::pending::<Result<(), ()>>()).await;
        assert!(matches!(stalled, Err(SendFailure::Stalled)));
        let delivered = within_send_deadline(deadline, async { Ok::<(), ()>(()) }).await;
        assert!(delivered.is_ok());
        let failed = within_send_deadline(deadline, async { Err::<(), ()>(()) }).await;
        assert!(matches!(failed, Err(SendFailure::Transport)));
    }
}

#[cfg(test)]
mod ui_socket_bound_tests {
    use super::*;
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message as Peer;

    const LIVENESS: std::time::Duration = std::time::Duration::from_millis(150);

    /// Serve `ws_ui_conn` for one test network on a loopback port.
    async fn serve(
        handle: Arc<crate::bouncer::NetworkHandle>,
        limiter: Arc<UiSocketLimiter>,
    ) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("address");
        let app = Router::new().route(
            "/ws",
            get(move |ws: WebSocketUpgrade| {
                let (handle, limiter) = (handle.clone(), limiter.clone());
                async move {
                    let slot = limiter.admit("Alice");
                    ws.on_upgrade(move |socket| {
                        ws_ui_conn(
                            handle,
                            socket,
                            ComposerAuthority::MaySend,
                            slot,
                            None,
                            LIVENESS,
                        )
                    })
                }
            }),
        );
        tokio::spawn(async move { axum::serve(listener, app).await });
        addr
    }

    fn attachable_network() -> (
        Arc<crate::bouncer::NetworkHandle>,
        crate::bouncer::DriverEnds,
    ) {
        let (handle, ends) = crate::bouncer::NetworkHandle::channels(8);
        handle.history_restored();
        (Arc::new(handle), ends)
    }

    async fn attached_clients_become(handle: &crate::bouncer::NetworkHandle, expected: u64) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while handle.runtime_snapshot().attached_clients != expected {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "attached clients stayed at {}, expected {expected}",
                handle.runtime_snapshot().attached_clients
            )
        });
    }

    /// A peer whose TCP connection stays open but which never answers — a
    /// laptop that slept, a NAT that forgot the flow — must not hold its task,
    /// its socket, and its place in the attached-client count forever.
    #[tokio::test]
    async fn a_peer_that_stops_answering_pings_is_detached() {
        let (handle, _ends) = attachable_network();
        let addr = serve(handle.clone(), UiSocketLimiter::new()).await;
        // Never polled again after the handshake, so it never answers a ping.
        let (_silent, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
            .await
            .expect("connect");
        attached_clients_become(&handle, 1).await;
        attached_clients_become(&handle, 0).await;
    }

    #[tokio::test]
    async fn a_quiet_peer_that_answers_pings_stays_attached() {
        let (handle, _ends) = attachable_network();
        let addr = serve(handle.clone(), UiSocketLimiter::new()).await;
        let (mut peer, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
            .await
            .expect("connect");
        // Reading is what lets the client library answer each ping.
        let mut pings = 0;
        let quiet = tokio::time::timeout(LIVENESS * 5, async {
            while let Some(frame) = peer.next().await {
                match frame.expect("frame") {
                    Peer::Ping(_) => pings += 1,
                    Peer::Close(_) => return,
                    _ => {}
                }
            }
        })
        .await;
        assert!(
            quiet.is_err(),
            "the server closed a peer that was answering"
        );
        assert!(
            pings >= 2,
            "the server pinged {pings} time(s) across five intervals"
        );
        assert_eq!(handle.runtime_snapshot().attached_clients, 1);
    }

    #[tokio::test]
    async fn one_account_holds_a_bounded_number_of_sockets_and_is_told_why() {
        let (handle, _ends) = attachable_network();
        let limiter = UiSocketLimiter::new();
        let addr = serve(handle.clone(), limiter.clone()).await;
        let held: Vec<_> = (0..MAX_UI_SOCKETS_PER_ACCOUNT)
            .map(|_| limiter.admit("alice").expect("under the cap"))
            .collect();
        assert!(
            limiter.admit("ALICE").is_none(),
            "the cap is per folded account"
        );
        assert!(
            limiter.admit("bob").is_some(),
            "another account is unaffected"
        );

        let (mut refused, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
            .await
            .expect("the upgrade itself succeeds so the browser can read the reason");
        let close = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            match refused.next().await {
                Some(Ok(Peer::Close(frame))) => frame.expect("close frame"),
                Some(Ok(other)) => panic!("sent {other:?} to a refused socket"),
                other => panic!("no close frame: {other:?}"),
            }
        })
        .await
        .expect("close");
        assert_eq!(u16::from(close.code), 1008);
        assert!(close.reason.contains("32"), "{}", close.reason);
        assert_eq!(handle.runtime_snapshot().attached_clients, 0);

        drop(held);
        assert!(
            limiter.admit("alice").is_some(),
            "a closed socket frees its slot"
        );
    }
}
