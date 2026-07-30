# Bridges, native clients, and automation journeys

## Add and operate a bridge

**Actor and goal.** An administrator wants an external chat system represented
as an always-on e6irc network.

**Flow.**

1. Build `e6ircd` with the required bridge feature (`matrix`, `discord`, or
   `slack`).
2. Open **Integrations**. Every supported platform is visible and explicitly
   marked built in or not built.
3. Create a bridge with platform-specific endpoint/credential/channel fields.
   The shared network mutation path validates sizes, endpoint policy, feature
   availability, and secret-key availability before sealing credentials.
4. The bridge starts as a normal `NetworkDriver`; web/BNC attachments,
   buffering, lifecycle, traffic, latency, and error monitoring use the same
   owner/network model as IRC.
5. Pause/resume/delete from **Integrations**; inspect detailed runtime state
   through the corresponding network.

**Visible failures and recovery.** A driver not compiled into the binary is
shown and rejected explicitly. Invalid/rejected credentials are fatal until
configuration changes rather than retried forever. Network/transient failures
use bounded backoff and visible error categories. Inbound identities/channel
names are sanitized and validated before entering IRC state.

**Evidence by driver.**

- **Local:** proven in-process through the common driver conformance and BNC
  path.
- **IRC:** proven against a local upstream for connect, SASL, relay, reconnect,
  buffering, and lifecycle; live Libera is opt-in.
- **Matrix:** proven both ways in CI against pinned Conduit.
- **Discord:** parsing/mapping/routing/backoff is CI-proven offline; the actual
  gateway/REST journey requires a real bot/guild and is externally qualified.
- **Slack:** parsing/mapping/routing/backoff is CI-proven offline; the actual
  Socket Mode/Web API journey requires a real app/workspace and is externally
  qualified.

The integrations console creates/toggles/deletes bridges; editing a bridge’s
fields uses the general network API only where that driver’s request shape is
supported. There is no dedicated bridge edit form.

## Use the scripting CLI

**Actor and goal.** A shell script or person wants one bounded IRC/API action
with a meaningful exit status.

**Shipped flow.**

- `e6irc send TARGET MESSAGE` connects, optionally authenticates with SASL
  PLAIN, joins a channel when needed, sends, drains the server response, and
  exits nonzero on join/delivery failure.
- `e6irc tail TARGET [--count N]` follows matching PRIVMSG lines and answers
  PING.
- `e6irc raw` sends stdin IRC lines.
- `e6irc history TARGET [--count N]` negotiates/queries CHATHISTORY.
- `e6irc api METHOD PATH` performs one bounded plain-HTTP REST request using a
  bearer token from the flag or `E6IRC_API_TOKEN`.
- IRC connections support plaintext or public-CA TLS with an explicit server
  name override.

**Visible failures and recovery.** Supplying only one SASL PLAIN field is an
error, not unauthenticated fallback. Join refusal, send rejection, disconnect,
TLS validation failure, oversized API body/response, and non-2xx HTTP produce
nonzero exit. Server output is terminal-sanitized.

**Evidence.** Proven against real e6ircd sockets/API by CLI e2e tests for send,
delivery failure, SASL, credential-shape rejection, history, TLS, and REST.

**Current product boundary.** The binary does not ship `login`, device-flow
orchestration, OS-keyring/file token caching, or JSON output for `tail`.
OAUTHBEARER exists in the client library and server, but the CLI exposes only
SASL PLAIN flags for IRC commands.

## Use the terminal UI

**Actor and goal.** A person wants a lightweight interactive IRC terminal.

**Shipped flow.**

1. Connect to one `host:port` with a nick and initial channel, using plaintext
   or public-CA TLS with an optional certificate-name override.
2. Register anonymously, with SASL PLAIN, or with SASL OAUTHBEARER. For a BNC
   attachment, `--account account/network` selects the owned network.
3. Receive into bounded buffers, switch buffers with Alt-Left/Right, scroll
   with Page Up/Down, and use `/join`, `/win`, and `/quit`.
4. Channel/direct messages create and update buffers; server-originated text
   is represented by terminal-safe types.
5. A live disconnect starts bounded-delay reconnect attempts with the same
   explicit transport/authentication request. Input is disabled while
   disconnected, and anything racing the disconnect is counted and reported
   rather than replayed late or shown as a false successful send.

**Evidence.** The terminal-independent application state is unit-tested and
fuzzed with arbitrary server messages; authentication/transport argument
shapes, disconnect refusal, transport failure, and bounded queue/scrollback
behavior are tested. TLS and authentication use the same connection request
as the real-socket CLI coverage. There is no pseudo-terminal/full-screen e2e.

**Current product boundary.** The TUI does not orchestrate device login,
CHATHISTORY loading, or shared read-marker state. “Multi-buffer” means
channel/query buffers inside one connection, not simultaneous servers.

## Build another native client

**Actor and goal.** A Rust application wants shared, tested IRC transport and
protocol behavior.

**Flow.**

- `e6irc-client` provides plaintext/public-CA TLS connection, framing through
  `e6irc-proto`, registration, SASL PLAIN, SASL OAUTHBEARER, PING handling,
  owned messages, terminal-safe output, and shared CHATHISTORY helpers.
- `ConnectionOptions` owns the transport, TLS name, registration identity, and
  an authentication enum whose variants make half-specified SASL impossible.
  A reconnecting caller can therefore reuse the exact request.
- The caller owns reconnect policy, credential acquisition/storage, UI state,
  and higher-level network selection.

**Failure contract.** EOF, invalid/oversized lines, TLS/authentication failure,
and write failure are returned. Lossy steady-state reading contains a
non-UTF-8 server line without terminating the whole client.

**Evidence.** Library behavior is covered by unit tests and indirectly by CLI,
TUI fuzz, load harness, and live server e2e tests.

## Automate the REST API

**Actor and goal.** A program wants versioned, owner-scoped management without
HTML.

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

**Evidence.** One route catalog constructs the Axum API method routers and the
complete method/path inventory; the hand-authored OpenAPI semantics must match
that inventory exactly. Drift fails a unit test and the live endpoint returns
an explicit 500 rather than an incomplete contract. Resource families retain
direct HTTP/PostgreSQL integration tests for their behavior.
