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

## Manage a private account profile

**Actor and goal.** An account holder wants to inspect, add, replace, or remove
the private contact email associated with the account.

**Preconditions.** The caller has an authenticated browser or API session and
PostgreSQL is ready. A newly registered account may already have contact data
when registration policy requested it.

**Flow.**

1. Open **Account & access** or read `/api/v1/me/profile`.
2. View the account name and current contact email; the response is private and
   non-cacheable.
3. Submit a replacement email or an empty value to remove it.
4. The server parses the mailbox once, canonicalizes its DNS domain, stores the
   typed value, and returns the updated private profile.

**Visible failures and recovery.** Empty local/domain parts, non-ASCII or
control characters, malformed DNS labels, and over-limit input are rejected
without changing storage. A suspended or missing account and a database
failure are explicit; the form preserves a safe value for correction.

**Security and observability.** The email is private account data: it is absent
from public and administrator account directories, metric labels, logs, and
audit details. Audit records state only whether contact data was replaced or
removed. Browser form mutation is session-authenticated and CSRF-protected;
API reads and writes are owner-scoped, and a cookie-authenticated API write
requires the session-bound CSRF header.

**Evidence.** Contact parsing is covered by typed-value unit tests; real
PostgreSQL tests prove normalized registration, private directory behavior,
replace/remove, and redacted audit details. The server-rendered account journey
proves the browser workflow.

## Manage personal access tokens and read state

**Actor and goal.** A user wants API/OAUTHBEARER access and an inspectable
multi-device read position.

**Preconditions.** The account has an authenticated browser session for token
issuance, PostgreSQL is ready, and marker targets refer to a conversation the
account may access.

**Flow.**

- Choose a 1–365-day lifetime and a non-empty subset of `read`, `write`,
  `administrator`, and `irc`; create the token through a session-bound
  CSRF-protected request, copy its plaintext once, list its exact grants and
  expiry, and revoke by ID.
- Present it as HTTP bearer authentication for methods its read/write/admin
  grants permit, or as IRC SASL OAUTHBEARER when it carries `irc`.
- Read the account’s target/position map through **Account & access** or
  `/api/v1/me/read-markers`.
- Update positions over IRC MARKREAD.

**Visible failures and recovery.** Empty/unknown grants, an out-of-range
lifetime, missing browser CSRF, token-cap exhaustion, expiry, revocation, or an
insufficient grant returns an explicit error. A bearer token cannot use the
issuance route to expand its own authority. Token strings never appear in
listings, HTML, audit details, or metrics.

**Security and observability.** Tokens are random, shown once, hashed at rest,
owner-scoped on list/revoke, and bounded by mandatory expiry. Browser sessions
and bearer tokens for one account share the same bounded API admission budget;
administrator calls have their own smaller budget. Marker queries cannot
enumerate another account’s conversations; message bodies and target names are
excluded from metric labels.

**Evidence.** Proven by token cap/list/revoke, bearer authentication,
scope/lifetime/expiry enforcement, no-escalation and shared-account-rate HTTP
tests, OAUTHBEARER socket, marker persistence/restart, API, and console tests.

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

## Review security activity and export account data

**Actor and goal.** An account holder wants to understand recent access and
take a portable copy of all retained account data without exposing reusable
secrets.

**Preconditions.** The caller is authenticated and PostgreSQL is ready.

**Flow.**

1. **Account & access** shows the 50 newest retained events where the exact
   folded account is actor or target.
2. `/api/v1/me/security-activity` pages older entries by immutable audit ID.
3. **Download my data** requests `/api/v1/me/export` and receives a
   non-cacheable, versioned JSON attachment.
4. The export includes profile, non-secret credential and token metadata,
   login identities, browser-session provenance, network configuration,
   read markers, founded-channel policy/access, retained messages, owned BNC
   buffer, and security activity from one PostgreSQL statement snapshot.

**Visible failures and recovery.** Invalid limits/cursors, an account removed
concurrently, and database failure return explicit non-success responses. An
empty retained collection is represented as an empty JSON array, not omitted
or substituted with another account's data.

**Security and observability.** Password hashes, bearer/session/invitation
digests, plaintext token values, OpenID Connect identity tokens/session IDs,
device codes, and sealed upstream credentials are absent. Network entries
report only whether a password exists. Exact actor/target predicates prevent
similarly named accounts from observing one another's activity. Login,
logout, password, app-password, token, identity, browser-session, invitation,
account-state, and provider-logout transitions write redacted events.

**Evidence.** PostgreSQL test
`account_export_and_security_activity_are_owner_scoped_and_secret_free`, the
real-socket lifecycle HTTP journey, and the Chromium invitation recipient
prove attachment headers, JSON shape, secret exclusion, owner isolation, and
visible activity.

## Permanently delete an account

**Actor and goal.** An account holder or administrator wants to erase an
account and its account-owned private data without allowing old credentials or
identity assumptions to bind to a future person.

**Preconditions.** The actor has a current browser session for self-service or
administrator authority for another account. Every registered channel founded
by the target has been explicitly transferred or dropped, and another active
effective administrator exists when the target has durable or configured
administrator authority.

**Flow.**

1. The actor enters the exact display-cased account name and confirms the
   irreversible action in **Account & access** or **Account directory**.
2. e6irc acquires the shared account/network mutation lane, validates channel
   succession and administrator recovery, and installs a folded live
   authentication deny key in the ordered core.
3. One database transaction repeats the invariants, reserves the folded name
   in `retired_account_names`, purges account invitations, device grants,
   account-owned BNC buffer, sent/direct-message history, and the account row
   with all cascading credentials, sessions, identities, networks, markers,
   and channel access.
4. A redacted deletion audit event commits with the retirement. The registry
   stops owned drivers and removes live administrator authority.
5. Self-service clears the browser cookie and returns to sign-in. The retired
   name can never be registered, invited, administrator-created, or
   auto-provisioned again.

**Visible failures and recovery.** A mismatched confirmation, missing account,
founded channel, last effective administrator, unavailable live core/registry,
or database failure is explicit. If the transaction fails after the live deny
key is installed, e6irc removes that key before reporting failure; if rollback
reconciliation itself fails, the response says so rather than claiming the
account remained fully active.

**Security and observability.** The account-name advisory lock serializes
creation, invitation, OpenID Connect provisioning, and deletion. A PostgreSQL
`BEFORE INSERT` trigger independently rejects retired names, making a future
unwrapped insertion fail closed. Audit retains only actor/action/folded-target
provenance, while account-owned private content is removed.

**Evidence.** PostgreSQL test
`permanent_account_deletion_requires_succession_purges_and_retires`, the
real-socket HTTP lifecycle test, and the Chromium self-deletion journey prove
succession refusal, durable/configured administrator recovery, live
revocation, child-data purge, cookie clearing, storage-trigger enforcement,
and permanent name retirement.
