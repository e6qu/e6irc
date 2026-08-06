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
6. A skip link reaches the chat region, and conversation/member activation uses
   native buttons so keyboard and assistive-technology behavior follows the
   browser's standard interaction model.
7. Each conversation control names its target, unread count, and any unread
   direct mentions. Decorative numeric and mention badges are not announced a
   second time; opening that conversation clears its own counters.

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
browser-tested against a real daemon. The same journey verifies the semantic
conversation and member controls plus the skip-to-chat focus target. Focused
client-state cases use browser doubles; the primary entry journey uses the real
network catalog and attachment.

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
contract without corrupting other buffers. A transient socket closure keeps its
bounded retry schedule but also offers **Retry now**; the control creates one
fresh attachment and is removed on success. Terminal network unavailability
remains configuration recovery, not a retry loop.

**Accessibility.** Replacing a historical transcript marks the log busy and
temporarily mutes its live region, so a buffer switch does not announce old
messages as new; subsequent live additions remain politely announced.

**Rejected sends.** A correlated server refusal never creates a local echo or
automatically retries. It leaves the reason visible and offers a **Restore
message** control that places the exact text back in the composer for the user
to review and deliberately send again.

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
6. Inactive conversations retain both unread traffic and unread direct-mention
   counts, so attention-worthy traffic is distinguishable before switching.
7. Errors from the driver or IRC server appear in the relevant status path.

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

## Personalize web chat and desktop notifications

**Actor and goal.** A web-chat user wants a readable light, dark, or
system-matched appearance and optional operating-system notifications for
important messages while the chat tab is hidden.

**Preconditions.** The user has loaded the web application in a browser.
Desktop notifications additionally require a browser that implements the
Notifications API and permission from the user; neither is required to use
chat.

**Flow.**

1. **Preferences** offers system, light, and dark themes. Choosing a theme
   applies it immediately to the document and stores the typed choice in
   browser-local preferences.
2. Reloading the application restores the selected theme. System mode follows
   the browser/operating-system color preference rather than freezing the
   color observed when it was selected.
3. Desktop notifications are off by default. Enabling them is an explicit
   action that requests browser permission at that moment, never on page load.
4. With permission granted and notifications enabled, a hidden tab asks the
   browser to present a notification for a direct message or a message that
   mentions the current nickname. Ordinary channel traffic and messages
   received while the page is visible remain in the application only.
5. The notification identifies the sender/conversation and contains the
   bounded message preview. Its stable conversation tag lets the browser
   coalesce repeated updates according to platform policy.
6. Turning notifications off takes effect immediately and persists across
   reloads without revoking the browser-wide permission.

**Visible failures and recovery.** An unsupported Notifications API, denied
permission, or notification-construction error leaves notifications disabled
and explains the condition through an application alert or the server buffer.
Unavailable or corrupt local storage does not prevent chat: the application
uses a safe in-tab preference value, reports the storage failure, and can
persist again when the browser facility recovers. Invalid stored preference
shapes are rejected rather than partially applied.

**Security and observability.** The application requests no notification
permission without a user gesture and never stores a session, token, password,
or message in preferences. Notification content is emitted only after explicit
opt-in, only for the bounded direct-message/mention cases, and only while the
document is hidden. The browser owns operating-system presentation, retention,
and privacy controls; e6irc keeps notification bodies out of server logs and
metric labels.

**Evidence.** Client unit tests cover typed preference validation and
unavailable, rejected, corrupt, or unsupported storage values. The real
Chromium, Firefox, and WebKit journeys select and reload a dark theme, verify
typed persistence, cross an explicit granted-permission boundary, and record
the exact notification produced by a direct message. The Chromium CI journey
additionally requires the engine to honor Playwright’s native permission
grant; headless engines that do not expose that platform surface receive only
the controlled granted boundary. The suite also proves that notification-
construction failure disables the setting and surfaces an alert, while
permission denial and an absent browser API leave the persisted opt-in false
with a visible explanation. Restoring a working API then proves explicit
opt-in and opt-out both persist.

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
level. The real Chromium journey crosses OpenID Connect and local
authentication, visits account/network/channel and every administrator
directory, edits every managed-configuration subsection and credential
collection, adds and removes a server ban, verifies its audit trail, inspects
live queue monitoring, and completes the reload-safe sign-out/recovery flow.
Focused HTTP journeys prove the remaining owner and administrator mutation
families with their role and CSRF boundaries.
