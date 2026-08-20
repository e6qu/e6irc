# IRC and services journeys

The IRC listener is the local e6irc network. The BNC listener is a distinct
authenticated gateway to always-on external/bridge networks; its journey is in
`networks-and-bouncer.md`.

## Connect and register

**Actor and goal.** An IRC client wants a usable local-network session.

**Preconditions.** At least one compatible IRC listener is enabled and
reachable. The client has any credential required by registration policy and
trusts the configured TLS endpoint when TLS is used.

**Flow.**

1. Open a configured plaintext or TLS listener. A trusted load balancer may
   supply PROXY protocol v2 only where that listener explicitly permits it.
2. Frame input at the IRC line limit and check the message-tag and traditional
   body allowances independently; invalid or overlong input receives a
   protocol error or disconnect instead of truncation. IRC-over-WebSocket
   accepts exactly one unterminated IRC line per WebSocket message.
3. Negotiate `CAP LS 302`, request supported capabilities, and complete SASL
   where required. SASL responses use at most 400 bytes per chunk, an exact
   400-byte final chunk is followed by `AUTHENTICATE +`, and a 905 resets the
   exchange for a fresh mechanism attempt.
4. Submit NICK and USER. Nick, user, host/IP, real name, registration rate,
   connection limits, and K/D/X-line policy are validated before registration.
5. Receive 001–005, LUSERS, and MOTD; the connection becomes visible in the
   owner/admin live-connection directory.
6. Respond to server PINGs until QUIT, timeout, operator disconnect, SendQ
   overflow, or shutdown.

**Visible failures and recovery.** Unsupported capabilities are rejected explicitly.
Nickname collision, bad registration sequence, authentication failure, ban,
flooding, timeout, and SendQ overflow produce the appropriate numeric/ERROR and
close when required. Valid and malformed completed authentication exchanges
share one permanent per-connection attempt budget. Input and output queues
remain bounded. A second SASL exchange after success receives 907 and cannot
replace the connection's authenticated account.

**Security and observability.** PROXY metadata is accepted only from configured
trusted peers, credentials are never logged, and registration policy is
applied before the session becomes visible. Connection lifecycle, traffic,
latency, and fixed failure categories feed the live directories and metrics.

**Evidence.** Proven over real sockets across core/e2e/DB tests, TLS tests,
irctest, persistence-backed irctest services, property tests, and stateful
fuzzing.

## Join and participate in a channel

**Actor and goal.** A registered client wants to discover, join, and converse
in a channel.

**Preconditions.** The client has completed registration, and the requested
channel name and any key/invitation/access state satisfy the server’s channel
policy.

**Flow.**

1. `LIST`, `WHO`, `WHOIS`, `NAMES`, `MONITOR`, and `ISON` discover public and
   permitted state under visibility rules.
2. `JOIN #channel` applies channel limits, invitations, keys, bans, registered
   access, and mode locks.
3. A successful join emits JOIN/extended-join, topic, and NAMES state.
4. `PRIVMSG`, `NOTICE`, and `TAGMSG` enforce membership/status-message and
   moderation rules, preserve negotiated tags, and fan out through bounded
   SendQs.
5. Operators use TOPIC, MODE, INVITE, KICK, and KNOCK according to channel
   privilege.
6. PART, KICK, QUIT, or disconnect updates membership and visibility.

**Visible failures and recovery.** Admission and send failures return specific numerics;
there is no join-and-drop or send-and-discard success. Secret/private channel
state is not disclosed to unauthorized queries. A slow recipient is
disconnected rather than making fan-out memory unbounded.

**Security and observability.** Channel visibility and every mutation are
checked against current membership and privilege. Messages and member lists are
bounded by protocol and SendQ limits; connection, traffic, and moderation
events remain available to authorized operators without exposing secret keys.

**Evidence.** Broadly proven by core integration tests and both irctest jobs,
including channel admission, modes, STATUSMSG, visibility, multiline/batch,
and services behavior.

## Send a direct message

**Actor and goal.** One registered client wants to message another nick and
later recover the conversation.

**Preconditions.** Both live participants are registered for immediate
delivery. Durable recovery additionally requires authenticated accounts and
PostgreSQL history storage.

**Flow.**

1. `PRIVMSG nick` resolves the live recipient using IRC casemapping.
2. Delivery observes account tags, echo-message, away state, and negotiated
   message tags.
3. If history storage is configured, the direct message is associated with
   both authenticated participants’ conversation target.
4. REST history and CHATHISTORY expose only conversations the requesting
   account participated in.

**Visible failures and recovery.** A missing nick or prohibited send returns a numeric.
Offline history resolution does not make an unauthenticated peer’s messages
globally readable. Message identifiers are scoped to their target.

**Security and observability.** History authorization is participant-scoped at
both request and storage boundaries. Message text and peer names never become
metric labels; delivery and persistence failures use bounded categories and do
not fabricate a durable success.

**Evidence.** Proven by direct-message core tests and PostgreSQL tests for
offline correspondents, target enumeration, authorization, and pagination.

## Resume history and synchronize read state

**Actor and goal.** A user reconnecting on another device wants bounded,
ordered history and a shared read position.

**Preconditions.** The account is authenticated, the requested capabilities
are negotiated, and PostgreSQL is configured for restart-spanning history and
read markers.

**Flow.**

1. Negotiate `chathistory` and any independently useful metadata/framing
   capabilities (`batch`, `server-time`, message tags), plus
   `draft/read-marker` as applicable. CHATHISTORY remains usable without
   `batch`; when `batch` is active, the page uses its specified envelope.
2. Query `CHATHISTORY LATEST`, `BEFORE`, `AFTER`, `AROUND`, or `BETWEEN`, or
   enumerate `TARGETS`.
3. The hot in-memory ring answers recent ranges; PostgreSQL answers older or
   restart-spanning ranges without changing ordering/labels.
4. `MARKREAD` writes an account-and-target position. REST lists the same
   positions for web/native consumers.
5. Pagination pivots remain within the requested target and stable even when
   multiple messages share a timestamp.

**Visible failures and recovery.** Invalid selectors, unsupported ranges, unauthorized
targets, and database failures return protocol/API errors. A database miss
does not silently become an incomplete “success.”

**Security and observability.** Target enumeration and every page are
account-authorized. Limits are clamped before allocation, selectors cannot
cross targets, and database failure is recorded without message content or
account names in metric labels.

**Evidence.** Proven by core history tests, extensive PostgreSQL selector and
restart tests, persistence-backed irctest CHATHISTORY, REST history, and read
marker tests. Duplex native-client tests prove capability negotiation and
marker-relative history, while the TUI model tests shared-marker advancement,
unread state, and history/live overlap.

## Register an account or channel through services

**Actor and goal.** A client wants an IRC-native account and channel-governance
workflow.

**Preconditions.** PostgreSQL is ready, services are enabled through the
account store, and the client has the authentication or channel privilege
required by the requested NickServ or ChanServ command.

**Flow.**

- NickServ supports REGISTER, IDENTIFY, GHOST, LOGOUT, and HELP.
- ChanServ supports REGISTER, DROP, FLAGS, OP, SET FOUNDER, SET KEEPTOPIC,
  and SET MLOCK.
- Registered channel state persists in PostgreSQL and is boot-loaded.
  Founder status, retained topics, mode locks, and access flags are enforced
  when the channel is recreated.
- The console/API offers the same channel-governance outcomes through typed,
  owner-scoped operations.

**Visible failures and recovery.** Commands require the correct account/founder/access
state and return NOTICE/FAIL on denial or persistence failure. `SET GUARD` is
explicitly declined rather than accepted as a no-op.

**Security and observability.** Password commands share the bounded credential
verification path. Founder/access checks are repeated in the core, durable
mutations cross the database worker, and privileged outcomes are recorded
without credential or private-channel leakage.

**Evidence.** Proven by core services tests, persistence-backed irctest account
registration, PostgreSQL persistence tests, and console/API channel tests.

## Operate and protect the network through IRC

**Actor and goal.** An authorized operator wants to intervene in live network
state.

**Preconditions.** A named operator credential is present in managed
configuration, the client is registered, and the target connection or policy
resource exists where the command requires one.

**Flow.**

1. `OPER` validates a named operator credential from managed configuration.
2. `KILL`, `WALLOPS`, and `SETHOST` affect exact live state.
3. KLINE/UNKLINE, DLINE/UNDLINE, and XLINE/UNXLINE mutate the shared persisted
   ban model and disconnect newly prohibited sessions where applicable.
4. Each privileged action records actor, action, target, detail, and time in
   the audit log.

**Visible failures and recovery.** Non-operators receive an explicit denial. Database-backed
ban mutation and audit are atomic; the server does not enforce an unaudited
write or report a persisted ban that was not stored.

**Security and observability.** Operator elevation and every privileged command
are authorized in the core. Audit records contain actor, action, target,
redacted detail, and time; operator credentials and connection-private data do
not enter metrics or audit text.

**Evidence.** Proven by core operator/ban tests and real-PostgreSQL atomicity,
boot-load, directory, and audit tests.

## Connect through IRC-over-WebSocket

**Actor and goal.** A third-party web IRC client wants the normal IRC protocol
over WebSocket.

**Preconditions.** The HTTP `/ws/irc` route or dedicated WebSocket listener is
reachable, the browser’s Origin is accepted where required, and the client can
speak one of the IRCv3 WebSocket framing modes.

**Flow.**

1. Connect to `/ws/irc` on the HTTP listener or `/` on a dedicated WebSocket
   IRC listener.
2. Subprotocol negotiation honors the client’s first offered
   `binary.ircv3.net` or `text.ircv3.net`; absent either, framing is selected
   per line.
3. IRC registration and all later commands follow the same core path as TCP.
4. Close, invalid framing, or backpressure terminates the connection visibly.

**Visible failures and recovery.** Unsupported upgrades, invalid frames,
oversized IRC lines, authentication/registration failures, and SendQ overflow
close or reject the connection explicitly. Reconnection starts a new IRC
session rather than silently resuming an unauthenticated transport.

**Security and observability.** The upgrade applies the HTTP origin policy and
then uses the same bounded parser, authentication, connection identifiers,
traffic accounting, and close reasons as TCP. Browser-controlled text is never
trusted as HTML.

**Evidence.** Proven by `crates/e6ircd/tests/ws_irc.rs` and included in
cross-platform workspace testing.
