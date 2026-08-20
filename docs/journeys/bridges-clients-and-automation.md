# Bridges, native clients, and automation journeys

## Add and operate a bridge

**Actor and goal.** An administrator wants an external chat system represented
as an always-on e6irc network.

**Preconditions.** PostgreSQL, a stable master key, and the matching compiled
bridge feature are available. The administrator has valid platform
credentials/endpoints and owns the configured bridge network.

**Flow.**

1. Build `e6ircd` with the required bridge feature (`matrix`, `discord`, or
   `slack`).
2. Open **Integrations**. Every supported platform is visible and explicitly
   marked built in or not built.
3. Create a bridge with platform-specific endpoint/credential/channel fields.
   The shared network mutation path validates sizes, endpoint policy, feature
   availability, and secret-key availability before sealing credentials.
4. Edit the bridge from **Integrations** when its endpoint, Matrix user,
   channels, or credentials change. Stored secrets are shown only as presence:
   blank inputs preserve them, Matrix/Discord replace their single
   password/token, and Slack can rotate either token independently.
5. The bridge starts as a normal `NetworkDriver`; web/BNC attachments,
   buffering, lifecycle, traffic, latency, and error monitoring use the same
   owner/network model as IRC.
6. Pause/resume/delete from **Integrations**; inspect detailed runtime state
   through the corresponding network.

**Visible failures and recovery.** A driver not compiled into the binary is
shown and rejected explicitly. Invalid/rejected credentials are fatal until
configuration changes rather than retried forever. Network/transient failures
use bounded backoff and visible error categories. A failed bridge-inventory
read is announced in each affected platform list and offers an in-place retry.
Inbound identities/channel names are sanitized and validated before entering
IRC state.
Reverse delivery supports `PRIVMSG`; malformed messages, unsupported commands,
unmapped targets, and provider send failures each produce an explicit bounded
`*bnc*` notice rather than disappearing after queue admission.

**Security and observability.** Integration forms are administrator-only and
CSRF-protected; platform credentials are sealed, write-only, and excluded from
audit/log/metrics output. Driver lifecycle, traffic, latency, attachments, and
closed failure categories use the common network snapshot.

**Evidence.** Evidence differs by driver:

- **Local:** proven in-process through the common driver conformance and BNC
  path.
- **IRC:** proven against a local upstream for connect, SASL, relay, reconnect,
  buffering, and lifecycle; live Libera is opt-in.
- **Matrix:** proven both ways in CI against pinned Conduit.
- **Discord:** parsing/mapping/routing/backoff and the real HTTP/WebSocket
  client transport are CI-proven against a strict provider oracle, including
  authorization, discovery, HELLO/IDENTIFY/READY, inbound dispatch, and
  outbound REST. A real Discord bot/guild remains externally qualified.
- **Slack:** parsing/mapping/routing/backoff and the real HTTP/WebSocket client
  transport are CI-proven against the same oracle framework, including token
  placement, channel/user lookup, Socket Mode open/event/ACK, inbound mapping,
  and outbound Web API. A real Slack app/workspace remains externally
  qualified.

The integrations console creates/edits/toggles/deletes bridges through a
dedicated platform-aware form and the same general network API mutation core.
The real PostgreSQL HTTP journey creates stored Matrix,
Discord, and Slack rows, opens the edit UI without exposing their plaintext,
updates every request shape, proves partial Slack rotation preserves the other
ciphertext, and proves malformed endpoints cannot change durable state. The
database CI lane compiles this journey with every bridge feature.

## Use the scripting CLI

**Actor and goal.** A shell script or person wants one bounded IRC/API action
with a meaningful exit status.

**Preconditions.** The target IRC or HTTP endpoint is reachable, required TLS
trust is installed, and the caller supplies one complete authentication mode
or deliberately chooses anonymous IRC.

**Flow.**

- `e6irc send TARGET MESSAGE` connects, optionally authenticates with SASL
  PLAIN, joins a channel when needed, sends, drains the server response, and
  exits nonzero on join/delivery failure.
- `e6irc tail TARGET [--count N]` follows matching PRIVMSG lines and answers
  PING; `--json` emits one object per message with source, target, text, and
  structured IRCv3 tags.
- `e6irc raw` sends stdin IRC lines.
- `e6irc history TARGET [--count N]` negotiates/queries CHATHISTORY.
- `e6irc login --base ORIGIN` starts the RFC 8628 device flow, prints the
  verification URI and user code, polls within the server's explicit bounds,
  and atomically saves the issued bearer token.
- `e6irc api METHOD PATH` performs one bounded HTTP/HTTPS REST request. An
  explicit token, `E6IRC_API_TOKEN`, or the login cache supplies bearer
  authentication; with no `--base`, it uses the cached issuing origin or
  fails if none exists.
- IRC authentication is anonymous, paired SASL PLAIN, direct OAUTHBEARER, or
  OAUTHBEARER from that same cache.
- IRC connections support plaintext or public-CA TLS with an explicit server
  name override.

**Visible failures and recovery.** Supplying only one SASL PLAIN field is an
error, not unauthenticated fallback. Join refusal, send rejection, disconnect,
TLS validation failure, oversized API body/response, and non-2xx HTTP produce
nonzero exit. A token is never printed. Cached tokens are origin-bound for API
use; malformed, oversized, or group/other-readable Unix cache files fail
rather than falling back to anonymous. Device denial, expiry, an unknown
device error, or invalid server polling bounds fail explicitly. Server output
is terminal-sanitized and JSON output is serializer-escaped.

**Security and observability.** Secrets may come from explicit arguments,
environment, or the private origin-bound cache but are never printed. All
input/output is bounded and terminal-sanitized; process exit status is the
automation-facing outcome while the server records normal fixed-category
connection/API telemetry.

**Evidence.** Real-socket/API tests cover send, delivery failure, PLAIN and
OAUTHBEARER, credential-shape rejection, history, structured tail, TLS, and
REST. The database job drives the actual binary through e6ircd's device
endpoint, approves its real PostgreSQL grant, verifies the private cache, and
uses its cached origin/token against `/api/v1/me`.

## Use the terminal UI

**Actor and goal.** A person wants a lightweight interactive IRC terminal.

**Preconditions.** The terminal supports the alternate screen, the selected
IRC/BNC endpoint is reachable, and any direct or cached credential is valid and
private to the current user.

**Flow.**

1. Connect to one `host:port` with a nick and initial channel, using plaintext
   or public-CA TLS with an optional certificate-name override.
2. Register anonymously, with SASL PLAIN, or with direct/cached SASL
   OAUTHBEARER. For a BNC attachment, `--account account/network` selects the
   owned network. The shared client chunks encoded SASL responses at 400 bytes,
   emits the required empty terminator after an exact chunk, and treats every
   terminal SASL numeric as a visible registration failure.
3. Require the history/read-marker capabilities in use, join the initial
   channel, load bounded history after its shared marker (or the latest bounded
   window), and advance the marker only while the current buffer is at its live
   edge. New traffic encountered during scrollback remains unread until the
   person returns to the latest message.
4. Use the route/status strip and active-first conversation rail to see the
   current destination, connection state, and unread work. Receive into bounded
   buffers, switch with Alt-Left/Right, scroll with Page Up/Down, return live
   with Ctrl-End, edit the composer with character-safe cursor movement, and
   use `/help`, `/join`, `/msg`, one-based or named `/win`, `/raw`, `//` for a
   literal leading slash, and `/quit`. Malformed or unknown commands remain
   editable and explain their refusal.
5. Channel/direct messages create and update RFC1459-casefolded buffers;
   history/live overlap with the same message ID is represented once;
   server-originated text
   is represented by terminal-safe types.
6. A live disconnect starts bounded-delay reconnect attempts with the same
   explicit transport/authentication request, rejoins every channel whose
   self-JOIN was confirmed, and reloads marker-relative history. The composer
   visibly marks itself offline and retains editable input, while submission is
   refused. Anything racing the disconnect is counted and reported rather than
   replayed late or shown as a false successful send.
7. The composer and outbound writer queue are bounded. A complete over-limit
   line or full queue retains/refuses input without local echo; accepted input
   is echoed only after queue admission, and a read-marker write remains
   pending when admission is temporarily unavailable.

**Visible failures and recovery.** Transport, TLS, SASL, capability, history,
writer-queue, line-limit, and server-protocol failures are visible in the
interface. Reconnect is bounded and reuses the same request; terminal teardown
restores the screen even after failure.

**Security and observability.** Server text is converted to terminal-safe
types, buffers and both input queues are bounded, and cache permission/origin
checks match the CLI. Credentials never enter rendered buffers; the server sees
the ordinary authenticated connection and traffic telemetry.

**Evidence.** The terminal-independent application state is unit-tested and
fuzzed with arbitrary server messages; authentication/transport argument
shapes, disconnect refusal, transport failure, and bounded queue/scrollback
behavior are tested. Duplex protocol tests prove capability refusal,
marker-relative CHATHISTORY, and batch completion. A pseudo-terminal test
drives the real full-screen binary against a real e6ircd, proves the relay-desk
route/status/conversation framing, command help, inbound rendering, and
outbound delivery, enters `/quit`, and requires clean alternate-screen
restoration.
Shared-client tests also prove that anonymous, PLAIN, and OAUTHBEARER
registration request the same metadata capabilities and that malformed or
over-limit steady-state input is a typed, visible rejection rather than a
disconnect or silent loss.

**Product shape.** Device approval is performed once through `e6irc login`;
the TUI consumes its shared cache. “Multi-buffer” means channel/query buffers
inside one connection, not simultaneous servers—the BNC connection supplies
cross-network multiplexing.

## Build another native client

**Actor and goal.** A Rust application wants shared, tested IRC transport and
protocol behavior.

**Preconditions.** The application uses the supported Rust toolchain and
constructs an owned `ConnectionOptions` value with a reachable address, valid
TLS name where applicable, and one explicit authentication variant.

**Flow.**

- `e6irc-client` provides plaintext/public-CA TLS connection, framing through
  `e6irc-proto`, registration, SASL PLAIN, SASL OAUTHBEARER, uniform optional
  metadata-capability requests, PING handling, owned messages, typed
  steady-state message/relay/rejection events, terminal-safe output, explicit
  capability requirements, marker-aware CHATHISTORY helpers, and the
  cross-platform token-cache policy.
- `ConnectionOptions` owns the transport, TLS name, registration identity, and
  an authentication enum whose variants make half-specified SASL impossible.
  A reconnecting caller can therefore reuse the exact request.
- The caller owns reconnect policy, UI state, and higher-level network
  selection; it can reuse the shared device-token storage rather than defining
  a second cache format.

**Visible failures and recovery.** EOF, strict-handshake invalid/oversized lines,
TLS/authentication failure, and write failure are returned. Tolerant
steady-state reading contains a non-UTF-8 server line without terminating the
whole client, while malformed/oversized per-line rejections remain explicit
events callers must handle.

**Security and observability.** Authentication variants make partial SASL
unrepresentable, token-cache reads enforce provenance and permissions, and all
framing/queues are bounded. The library returns typed outcomes so its caller
can report failures without logging credentials or raw hostile terminal text.

**Evidence.** Library behavior is covered by unit tests and indirectly by CLI,
TUI fuzz, load harness, and live server e2e tests.

## Automate the REST API

**Actor and goal.** A program wants versioned, owner-scoped management without
HTML.

**Preconditions.** The HTTP API is reachable, the caller has a valid personal
access token or approved device token, and administrator endpoints additionally
name that account in managed administrator configuration.

**Flow.**

1. Discover `/api/v1/server` and `/api/v1/openapi.json`.
2. Obtain a personal access token through the console/API/device flow.
3. Use bearer authentication for `/api/v1/me/*`; administrators use the same
   identity plus role checks for `/api/v1/admin/*`.
4. Manage identities, sessions, connections, tokens, password, channels,
   credentials, networks/buffers, history, directories, bans, audit,
   observability, and metrics.
5. Honor problem responses, status codes, cursor/page bounds, and no-store
   response headers for sensitive posture.

**Visible failures and recovery.** Unknown routes are problem+JSON 404s.
Authentication, role, owner scope, validation, conflict, stale state,
dependency, and rate-limit failures retain distinct status/problem behavior.
List endpoints never return secret plaintext.

**Security and observability.** Bearer tokens are bounded, hashed at rest, and
owner/role checked at each resource boundary. Sensitive responses are
non-cacheable, inputs and pages are bounded, and audit/metrics expose fixed
safe fields rather than tokens, passwords, cookies, or unbounded user labels.

**Evidence.** One route catalog constructs the Axum API method routers and the
complete method/path inventory; the hand-authored OpenAPI semantics must match
that inventory exactly. Drift fails a unit test and the live endpoint returns
an explicit 500 rather than an incomplete contract. Resource families retain
direct HTTP/PostgreSQL integration tests for their behavior.
