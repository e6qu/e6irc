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

**Evidence.** The embedded-shell, authentication, zero-network, deliberate
REST-failure, network-creation, and authenticated WebSocket states are
browser-tested against a real daemon. Focused client-state cases use browser
doubles; the primary entry journey uses the real network catalog and
attachment.

## Receive replay and live messages without gaps or duplicates

**Actor and goal.** A reconnecting user wants stored backlog followed by live
traffic in one ordered conversation.

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

**Evidence.** Browser tests exercise replay boundaries, history races, and
deduplication with deterministic transport. The full-stack browser case also
drives a real upstream line through persistence, the multiplexer, and
WebSocket into Chromium, gracefully restarts the daemon, and verifies that the
same session can inspect the persisted line afterward.

## Join, converse, and leave

**Actor and goal.** A user wants to join a channel or open a direct
conversation, send and receive messages, and close it intentionally.

**Flow.**

1. The composer sends `{target, message}`; `/raw ` deliberately sends an IRC
   line instead.
2. The server converts normal composer input to PRIVMSG and relays it through
   the selected driver.
3. JOIN/NAMES/NICK/PART/KICK/QUIT events maintain member state and buffer
   labels.
4. Direct messages create query buffers. Closing a query removes only the
   local view; leaving a channel sends PART and waits for the resulting state.
5. Errors from the driver or IRC server appear in the relevant status path.

**Visible failures and recovery.** A disconnected composer cannot display a
false successful send. Removing the selected network detaches the WebSocket.
Channel leave and direct-message close are different actions and remain
different in both UI and wire behavior.

**Evidence.** Browser state tests cover NAMES, direct-message close, and
channel leave. A real local IRC peer observes the Chromium composer’s exact
PRIVMSG and sends a peer message back through the driver and `/ws/ui`; separate
protocol tests cover detachment on network removal.

## Navigate account and operational surfaces

**Actor and goal.** A user wants chat, network configuration, channel
governance, sessions, and account access to feel like one product.

**Flow.**

- Global navigation exposes the surfaces allowed by the signed-in role.
- User surfaces are BNC networks, registered channels, own sessions, and
  account/access.
- Administrators additionally see overview, accounts, channel registry,
  server bans, monitoring, audit, configuration, all live connections, and
  integrations.
- Sign out leaves the application at a public, reload-safe confirmation page
  with a clear route back to authentication.

**Failure contract.** A non-administrator receives the same authorization
boundary at the handler, regardless of whether a link was hidden. Server
errors render an error state rather than an empty collection.

**Evidence.** Role gating and each server-rendered page are covered at HTTP
level. Browser coverage proves application navigation around authentication
and logout, but does not click every self-service and administrator mutation.
