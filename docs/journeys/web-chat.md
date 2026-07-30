# Web chat journeys

The bundled web client is a dependency-free production JavaScript application.
It uses authenticated REST for network discovery/history and `/ws/ui` for the
live event stream and composer. It is not an IRC-over-WebSocket client; that
separate protocol endpoint is `/ws/irc`.

## Enter chat and choose a network

**Actor and goal.** A signed-in account holder wants to reach a usable
conversation.

**Preconditions.** The built web assets are embedded (`embed-web`) or served by
the deployment’s external asset host. PostgreSQL and the BNC registry are
available; at least one owned/shared network is enabled for chat.

**Flow.**

1. `/` loads the application shell and resolves `/api/v1/me`.
2. `/api/v1/me/networks` supplies the owner-scoped network catalog and enabled
   state.
3. With no networks, the application shows an explicit empty state pointing to
   BNC network configuration.
4. Selecting a network opens `/ws/ui` for that network and renders connection
   state; it never invents “connected” from stored configuration alone.
5. The initial snapshot/replay establishes buffers before live events are
   applied.

**Visible failures and recovery.** An expired session redirects to login.
REST failure, WebSocket authentication failure, absent/disabled network,
registry unavailability, upstream connection failure, and socket closure each
produce a visible state. Retrying must create one new attachment rather than
stacking duplicate handlers.

**Security and observability.** Network inventory and attachment are
cookie-authenticated and owner-scoped; the WebSocket enforces same-origin
policy. Server-controlled text reaches the document only through text nodes,
and connection/attachment/error state is counted without user text in metric
labels.

**Evidence.** The embedded-shell, authentication, zero-network, deliberate
REST-failure, network-creation, and authenticated WebSocket states are
browser-tested against a real daemon. Focused client-state cases use browser
doubles; the primary entry journey uses the real network catalog and
attachment.

## Receive replay and live messages without gaps or duplicates

**Actor and goal.** A reconnecting user wants stored backlog followed by live
traffic in one ordered conversation.

**Preconditions.** The selected network exists, the browser session and
WebSocket attachment are valid, and PostgreSQL is configured when replay must
survive process restart.

**Flow.**

1. Attachment subscribes to the network before or as replay boundaries are
   established, so a message arriving during history load is not lost.
2. Persisted backlog and current driver replay are normalized into line events.
3. The client uses message identifiers and event identity to deduplicate the
   history/live overlap.
4. Server-time determines presentation ordering where supplied; arrival order
   remains the fallback.
5. Channel and direct-message buffers are created on demand and remain bounded.

**Visible failures and recovery.** History failure is shown without discarding
the working live stream. Socket closure marks the connection disconnected.
Malformed events are rejected or ignored according to their explicit protocol
contract without corrupting other buffers.

**Security and observability.** History and replay use the same owner/network
authorization. Buffers, requested history, and deduplication indexes are
bounded; upstream text is rendered as text, while replay/database failures are
visible and classified without logging conversation bodies.

**Evidence.** Browser tests exercise replay boundaries, history races, and
deduplication with deterministic transport. The full-stack browser case also
drives a real upstream line through persistence, the multiplexer, and
WebSocket into Chromium, gracefully restarts the daemon, and verifies that the
same session can inspect the persisted line afterward.

## Join, converse, and leave

**Actor and goal.** A user wants to join a channel or open a direct
conversation, send and receive messages, and close it intentionally.

**Preconditions.** The selected WebSocket attachment is connected, the
upstream session permits the requested target/action, and the browser has a
current network and conversation selection.

**Flow.**

1. The composer sends `{id, target, message}`; `/raw ` deliberately requests
   one complete IRC line instead.
2. The server validates the whole derived line, admits it to the selected
   driver's bounded queue, and returns a correlated `sent` or `send-error`
   event.
3. Only `sent` creates local echo and sent-history. A rejection keeps the text
   available for retry, so displayed success means server-side queue
   admission—not merely a browser socket write.
4. JOIN/NAMES/NICK/PART/KICK/QUIT events maintain member state and buffer
   labels.
5. Direct messages create query buffers. Closing a query removes only the
   local view; leaving a channel sends PART and waits for the resulting state.
6. Errors from the driver or IRC server appear in the relevant status path.

**Visible failures and recovery.** A disconnected composer cannot display a
false successful send. CR/LF/NUL input, an over-limit complete line, more than
64 pending sends, a full driver queue, and socket replacement/closure all fail
visibly without truncating the message into different content. Removing the
selected network detaches the WebSocket. Channel leave and direct-message
close are different actions and remain different in both UI and wire behavior.

**Security and observability.** Browser text is validated as a complete IRC
line at the WebSocket boundary and again by the driver/core path. Pending
sends, buffers, members, and sent-history are bounded; acceptance/refusal is
correlated by opaque request identifier and message bodies stay out of metrics.

**Evidence.** Browser state tests cover NAMES, direct-message close, channel
leave, delayed acknowledgement, and refusal without false echo. A real local
IRC peer observes the Chromium composer’s exact PRIVMSG after a correlated
server acknowledgement and sends a peer message back through the driver and
`/ws/ui`; protocol tests cover injection/length rejection, queue admission,
and detachment on network removal.

## Navigate account and operational surfaces

**Actor and goal.** A user wants chat, network configuration, channel
governance, sessions, and account access to feel like one product.

**Preconditions.** The user has a valid browser session; administrator-only
destinations additionally require the account to be in the effective
administrator set.

**Flow.**

- Global navigation exposes the surfaces allowed by the signed-in role.
- User surfaces are BNC networks, registered channels, own sessions, and
  account/access.
- Administrators additionally see overview, accounts, channel registry,
  server bans, monitoring, audit, configuration, all live connections, and
  integrations.
- Sign out leaves the application at a public, reload-safe confirmation page
  with a clear route back to authentication.

**Visible failures and recovery.** A non-administrator receives the same authorization
boundary at the handler, regardless of whether a link was hidden. Server
errors render an error state rather than an empty collection. Expired sessions
return to authentication, and sign-out ends at the reload-safe signed-out page.

**Security and observability.** Navigation visibility is only presentation;
each destination independently authenticates, authorizes, and applies CSRF to
mutations. Private pages are non-cacheable and use a restrictive content
security policy; errors expose a safe problem rather than secrets or raw
database/provider text.

**Evidence.** Role gating and each server-rendered page are covered at HTTP
level. Browser coverage proves application navigation around authentication
and logout, but does not click every self-service and administrator mutation.
