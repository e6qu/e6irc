# IRC and services journeys

The IRC listener is the local e6irc network. The BNC listener is a distinct
authenticated gateway to always-on external/bridge networks; its journey is in
`networks-and-bouncer.md`.

## Connect and register

**Actor and goal.** An IRC client wants a usable local-network session.

**Flow.**

1. Open a configured plaintext or TLS listener. A trusted load balancer may
   supply PROXY protocol v2 only where that listener explicitly permits it.
2. Frame input at the IRC line limit; invalid or overlong input receives a
   protocol error or disconnect instead of truncation.
3. Negotiate `CAP LS 302`, request supported capabilities, and complete SASL
   where required.
4. Submit NICK and USER. Nick, user, host/IP, real name, registration rate,
   connection limits, and K/D/X-line policy are validated before registration.
5. Receive 001–005, LUSERS, and MOTD; the connection becomes visible in the
   owner/admin live-connection directory.
6. Respond to server PINGs until QUIT, timeout, operator disconnect, SendQ
   overflow, or shutdown.

**Failure contract.** Unsupported capabilities are rejected explicitly.
Nickname collision, bad registration sequence, authentication failure, ban,
flooding, timeout, and SendQ overflow produce the appropriate numeric/ERROR and
close when required. Input and output queues remain bounded.

**Evidence.** Proven over real sockets across core/e2e/DB tests, TLS tests,
irctest, persistence-backed irctest services, property tests, and stateful
fuzzing.

## Join and participate in a channel

**Actor and goal.** A registered client wants to discover, join, and converse
in a channel.

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

**Failure contract.** Admission and send failures return specific numerics;
there is no join-and-drop or send-and-discard success. Secret/private channel
state is not disclosed to unauthorized queries. A slow recipient is
disconnected rather than making fan-out memory unbounded.

**Evidence.** Broadly proven by core integration tests and both irctest jobs,
including channel admission, modes, STATUSMSG, visibility, multiline/batch,
and services behavior.

## Send a direct message

**Actor and goal.** One registered client wants to message another nick and
later recover the conversation.

**Flow.**

1. `PRIVMSG nick` resolves the live recipient using IRC casemapping.
2. Delivery observes account tags, echo-message, away state, and negotiated
   message tags.
3. If history storage is configured, the direct message is associated with
   both authenticated participants’ conversation target.
4. REST history and CHATHISTORY expose only conversations the requesting
   account participated in.

**Failure contract.** A missing nick or prohibited send returns a numeric.
Offline history resolution does not make an unauthenticated peer’s messages
globally readable. Message identifiers are scoped to their target.

**Evidence.** Proven by direct-message core tests and PostgreSQL tests for
offline correspondents, target enumeration, authorization, and pagination.

## Resume history and synchronize read state

**Actor and goal.** A user reconnecting on another device wants bounded,
ordered history and a shared read position.

**Flow.**

1. Negotiate `chathistory`, `batch`, `server-time`, and
   `draft/read-marker` as applicable.
2. Query `CHATHISTORY LATEST`, `BEFORE`, `AFTER`, `AROUND`, or `BETWEEN`, or
   enumerate `TARGETS`.
3. The hot in-memory ring answers recent ranges; PostgreSQL answers older or
   restart-spanning ranges without changing ordering/labels.
4. `MARKREAD` writes an account-and-target position. REST lists the same
   positions for web/native consumers.
5. Pagination pivots remain within the requested target and stable even when
   multiple messages share a timestamp.

**Failure contract.** Invalid selectors, unsupported ranges, unauthorized
targets, and database failures return protocol/API errors. A database miss
does not silently become an incomplete “success.”

**Evidence.** Proven by core history tests, extensive PostgreSQL selector and
restart tests, persistence-backed irctest CHATHISTORY, REST history, and read
marker tests. Duplex native-client tests prove capability negotiation and
marker-relative history, while the TUI model tests shared-marker advancement,
unread state, and history/live overlap.

## Register an account or channel through services

**Actor and goal.** A client wants an IRC-native account and channel-governance
workflow.

**Flow.**

- NickServ supports REGISTER, IDENTIFY, GHOST, LOGOUT, and HELP.
- ChanServ supports REGISTER, DROP, FLAGS, OP, SET FOUNDER, SET KEEPTOPIC,
  and SET MLOCK.
- Registered channel state persists in PostgreSQL and is boot-loaded.
  Founder status, retained topics, mode locks, and access flags are enforced
  when the channel is recreated.
- The console/API offers the same channel-governance outcomes through typed,
  owner-scoped operations.

**Failure contract.** Commands require the correct account/founder/access
state and return NOTICE/FAIL on denial or persistence failure. `SET GUARD` is
explicitly declined rather than accepted as a no-op.

**Evidence.** Proven by core services tests, persistence-backed irctest account
registration, PostgreSQL persistence tests, and console/API channel tests.

## Operate and protect the network through IRC

**Actor and goal.** An authorized operator wants to intervene in live network
state.

**Flow.**

1. `OPER` validates a named operator credential from managed configuration.
2. `KILL`, `WALLOPS`, and `SETHOST` affect exact live state.
3. KLINE/UNKLINE, DLINE/UNDLINE, and XLINE/UNXLINE mutate the shared persisted
   ban model and disconnect newly prohibited sessions where applicable.
4. Each privileged action records actor, action, target, detail, and time in
   the audit log.

**Failure contract.** Non-operators receive an explicit denial. Database-backed
ban mutation and audit are atomic; the server does not enforce an unaudited
write or report a persisted ban that was not stored.

**Evidence.** Proven by core operator/ban tests and real-PostgreSQL atomicity,
boot-load, directory, and audit tests.

## Connect through IRC-over-WebSocket

**Actor and goal.** A third-party web IRC client wants the normal IRC protocol
over WebSocket.

**Flow.**

1. Connect to `/ws/irc` on the HTTP listener or `/` on a dedicated WebSocket
   IRC listener.
2. Subprotocol negotiation honors the client’s first offered
   `binary.ircv3.net` or `text.ircv3.net`; absent either, framing is selected
   per line.
3. IRC registration and all later commands follow the same core path as TCP.
4. Close, invalid framing, or backpressure terminates the connection visibly.

**Evidence.** Proven by `crates/e6ircd/tests/ws_irc.rs` and included in
cross-platform workspace testing.
