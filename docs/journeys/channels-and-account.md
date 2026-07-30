# Channel governance and account self-service journeys

## Register and configure a channel

**Actor and goal.** An authenticated account holder wants durable ownership
and policy for an IRC channel.

**Preconditions.** PostgreSQL is ready, the caller is authenticated, and
registration requires the live channel privilege or founder authority required
by the selected control plane.

**Flow.**

1. Register through ChanServ or **Registered channels**. The channel name is
   validated and uniqueness follows IRC casemapping.
2. The registering account becomes founder; the initial topic is stored in
   the same insert so a crash cannot create half-registered state.
3. Set the retained topic and KEEPTOPIC behavior.
4. Set an MLOCK string. Validation rejects unsupported/contradictory modes
   before storage; the core enforces the stored lock.
5. Add, update, or remove per-account access flags within a hard per-channel
   cap.
6. Transfer founder to an existing account, or drop registration.
7. The hot core state is updated through the database worker and survives
   restart.

**Visible failures and recovery.** Non-founders cannot mutate founder-only
state. Transfer to an absent account, invalid channel/mode/access values,
duplicate registration, and persistence failure return explicit errors. The
console re-renders safely with escaped values; forms require CSRF.

**Security and observability.** Founder/access checks are repeated in the core
for console, REST, and services requests. Collections and inputs are bounded,
and durable privileged changes create redacted audit evidence without topic or
credential leakage.

**Evidence.** Proven by core services/mode tests, PostgreSQL topic/KEEPTOPIC/
MLOCK/access/founder tests, and the complete owner-scoped API and console
integration tests.

## Recreate a registered channel

**Actor and goal.** A founder expects durable policy to return when an empty
channel is created again.

**Preconditions.** The channel is registered with persisted founder, access,
topic, KEEPTOPIC, and/or mode-lock state, and PostgreSQL state was successfully
loaded at boot.

**Flow.**

1. Registered ownership, topic, KEEPTOPIC, MLOCK, and access rows load before
   the listener accepts normal traffic.
2. The founder joins an absent/empty channel.
3. Founder operator status, retained topic, and mode lock are applied.
4. Later joins and mutations use the same registered access state.

**Visible failures and recovery.** The server does not claim registered behavior if its
database-backed state could not be loaded. A failed persistence mutation does
not update only the hot state.

**Security and observability.** Recreated state is selected by canonical
channel identity and re-authorized on later mutations. Boot/load and
persistence failures are explicit; unauthorized visibility queries cannot use
the durable registry to disclose private channel state.

**Evidence.** Proven by core registered-channel recreation tests and
PostgreSQL boot-load/persistence tests.

## Manage IRC credentials

**Actor and goal.** An account holder wants separate, revocable credentials for
clients and BNC attachment.

**Preconditions.** The caller has an authenticated browser/API session and
PostgreSQL is ready. Primary-password rotation additionally requires the
current primary password unless the account has none.

**Flow.**

- View secret-free credential posture: kind, label, created/last-used state.
- Add or rotate the one primary password.
- Create a bounded number of app passwords; the plaintext is shown once.
- Revoke an exact app-password credential.
- Use either primary or app password through SASL PLAIN.

**Visible failures and recovery.** Passwords are never listable after creation. The generic
delete path cannot delete the primary password. Partial credential input,
wrong current password, duplicate/cap exhaustion, and storage errors are
visible.

**Security and observability.** Plaintext is accepted only on bounded
credential forms, hashed before storage, rendered once for app passwords, and
excluded from logs, audit details, and metrics. Forms use session CSRF and
every list/revoke operation is owner-scoped.

**Evidence.** Proven by credential DB tests, real-socket SASL tests, HTTP API,
and `account_console_manages_credentials_tokens_and_identities`.

## Manage personal access tokens and read state

**Actor and goal.** A user wants API/OAUTHBEARER access and an inspectable
multi-device read position.

**Preconditions.** The account has an authenticated browser/API session,
PostgreSQL is ready, and marker targets refer to a conversation the account may
access.

**Flow.**

- Create a personal access token, copy its plaintext once, list metadata, and
  revoke by ID.
- Present it as HTTP bearer authentication or IRC SASL OAUTHBEARER.
- Read the account’s target/position map through **Account & access** or
  `/api/v1/me/read-markers`.
- Update positions over IRC MARKREAD.

**Visible failures and recovery.** Token caps are enforced transactionally. Revoked tokens
fail authentication. Token strings never appear in listings, HTML, audit
details, or metrics.

**Security and observability.** Tokens are random, shown once, hashed at rest,
and owner-scoped on list/revoke. Marker queries cannot enumerate another
account’s conversations; message bodies and target names are excluded from
metric labels.

**Evidence.** Proven by token cap/list/revoke, bearer authentication,
OAUTHBEARER socket, marker persistence/restart, API, and console tests.

## Inspect and terminate sessions

**Actor and goal.** A user wants to see where the account is active and end an
exact session.

**Preconditions.** The caller has a valid browser session. Live IRC entries
exist only for authenticated registered connections, while browser-session
inventory requires PostgreSQL.

**Flow.**

1. **Your sessions** lists browser sessions and the caller’s live IRC
   connections separately.
2. Browser rows expose bounded posture such as creation/last-seen and current
   session state, not the cookie/token.
3. Live rows expose exact connection ID and safe network/client metadata.
4. Revoke one browser session, all other browser sessions, or disconnect one
   live connection.
5. A revoked browser session loses HTTP and WebSocket access; a disconnected
   IRC session receives the normal close path.

**Visible failures and recovery.** IDs are owner-scoped; another account’s resources remain
invisible. The “other sessions” action preserves the current session by
identity rather than timestamp guesswork.

**Security and observability.** Resource identifiers are unpredictable and
serialized without JavaScript precision loss. Exact-resource mutation repeats
ownership checks, forms are CSRF-protected, and the inventory exposes bounded
posture but never cookies, token hashes, or credentials.

**Evidence.** Proven by HTTP/PostgreSQL owner-scoping tests and real core
connection-directory/disconnect tests.
