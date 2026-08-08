# Identity and access journeys

These journeys distinguish an **account** (the stable e6irc identity) from a
credential, an OpenID Connect identity, a browser session, an IRC connection,
and an upstream-network credential. Revoking one must not silently revoke or
preserve another.

## Sign in with a local password

**Actor and goal.** An account holder wants a browser session for the web
client and console.

**Preconditions.** PostgreSQL is configured and ready, local login is enabled,
the account has a primary password, and the browser can retain the configured
session cookie.

**Flow.**

1. `GET /login` renders the available local and OpenID Connect choices.
2. The user submits the account and primary password to `POST /login`.
3. The server applies the shared authentication rate limit, verifies the
   primary-password credential, enforces the per-account active-browser-session
   cap transactionally, and creates an opaque server-side session.
4. The browser receives a `Secure`/`HttpOnly`/`SameSite` cookie according to
   managed configuration and is redirected into the application.
5. Subsequent console, API, and `/ws/ui` requests resolve the same account from
   the session.

**Visible failures and recovery.** A missing database, disabled local login,
bad credential, rate limit, session-cap conflict, or database error produces a
non-success response and no authenticated cookie. An app password is not
accepted as the primary browser password. The user can revoke old browser
sessions from **Your sessions** before retrying if the cap is reached. A
suspended account is indistinguishable from an invalid credential and cannot
mint a new session.

**Security and observability.** Passwords are Argon2 hashes in the credential
store. Login failures do not disclose whether an account exists. Authentication
metrics use fixed categories, not account names.

**Evidence.** Proven at HTTP/PostgreSQL level by
`local_login_is_browser_bound_and_accepts_only_the_primary_password`,
`concurrent_browser_session_issuance_enforces_the_active_cap`, and the browser
session inventory tests. `tools/test-oidc-browser.mjs` adds a primary password
to an OpenID Connect-provisioned account, signs out, and completes the real
local-login form in Chromium.

## Sign in with OpenID Connect

**Actor and goal.** A user wants to authenticate through a configured identity
provider and obtain or resume an e6irc account.

**Preconditions.** The provider is enabled in the managed configuration, its
issuer metadata/JWKS are reachable and valid, the public URL matches callback
registration, PostgreSQL is ready, and cookies are correctly configured.

**Flow.**

1. The user chooses a provider from `/login` or uses the provider-specific
   direct/silent-single-sign-on entry point.
2. `/api/v1/auth/oidc/{provider}/start` creates bounded, expiring state and a
   PKCE verifier, then redirects to the provider.
3. The callback validates state, issuer, signature, audience, nonce, and code
   exchange before trusting the subject.
4. When the provider has an allowed-domain policy, the callback additionally
   requires a provider-verified, syntactically valid email whose canonical
   domain exactly matches one configured domain.
5. `(issuer, subject)` resolves a linked e6irc account. First login provisions
   one according to registration policy; later logins reuse it.
6. The server creates a bounded browser session, retains the provider logout
   hint when supplied, and enters the application.

**Visible failures and recovery.** Unknown/disabled provider, stale or replayed
state, callback mismatch, invalid claims, missing/unverified/malformed or
non-matching email under an allowed-domain policy, registration denial,
identity conflict, session-cap conflict, and provider/network/database
failures all fail closed. Parent and subdomains do not match by implication.
No local session is created from partially validated claims. The validation
and signed-out pages remain reload-safe. A valid provider result for a
suspended account ends with an explicit account-unavailable response and no
browser session.

**Security and observability.** State is one-time and expiring; PKCE binds the
authorization code; identities are globally unique. Email-domain admission is
a typed exact-match policy over a verified provider claim, not suffix matching.
Front-channel and back-channel logout use correlation rather than trusting
browser-supplied account data.

**Evidence.** Proven against a real e6ircd, PostgreSQL, Dex, and Chromium by
`full_oidc_login_provisions_account_and_session`,
`oidc_silent_sso_reuses_provider_session`, and
`tools/test-oidc-browser.mjs`. Exact Shauth launch and coordinated logout are
also exercised by the `shauth-sso` CI job.

## Link or unlink an OpenID Connect identity

**Actor and goal.** A signed-in account holder wants another provider identity
to authenticate the same account, or wants to remove an existing link.

**Preconditions.** The account has a valid browser session, the target provider
is enabled and reachable, and at least one credential or identity will remain
after an unlink.

**Flow.**

1. **Account & access** lists linked identities without provider secrets.
2. **Link** starts a fresh provider flow marked as a link operation.
3. The callback applies the provider's verified exact-email-domain policy,
   then attaches the validated `(issuer, subject)` to the initiating account
   only if no other account owns it.
4. Unlink requires an authenticated, CSRF-protected console form or the
   owner-scoped `DELETE /api/v1/me/identities/{id}`.
5. The account remains usable through its remaining credentials/identities.

**Visible failures and recovery.** Linking an identity owned by another account
is a conflict, never a move. Missing/unverified or non-matching email under a
provider domain policy is rejected before linking. Unlinking an identity
outside the caller’s account is indistinguishable from absence. The server
refuses a mutation that would violate the account’s access invariants.

**Security and observability.** Link state and PKCE are bound to the initiating
session. The callback trusts only validated issuer/subject identity, unlink is
CSRF-protected and owner-scoped, and neither provider tokens nor claims are
written to audit details.

**Evidence.** Proven at real Dex/PostgreSQL level by
`oidc_identity_link_flow_and_conflict` and
`oidc_identity_link_list_and_conflict`; console rendering/mutation is covered
by `account_console_manages_credentials_tokens_and_identities`.

## Join through an administrator invitation

**Actor and goal.** An administrator wants to onboard a named local account
without choosing or learning the recipient's password; the recipient wants to
claim that account through the UI.

**Preconditions.** PostgreSQL and HTTP are ready, the administrator has an
active browser session or administrator-capable personal access token, and the
requested account name neither exists nor has been retired.

**Flow.**

1. The administrator opens **Account directory** or posts to
   `/api/v1/admin/invitations`, chooses the account name, optional private
   contact email, 1–30-day lifetime, and optional durable administrator grant.
2. e6irc stores only a SHA-256 digest and displays the single-use bearer link
   once. The secret is sent to the recipient through a trusted channel.
3. The recipient opens `/invite/{token}`. A short-lived
   `HttpOnly; SameSite=Strict` cookie binds the acceptance form to that browser.
4. The recipient chooses and confirms a primary password.
5. Password hashing, account/contact/authority creation, invitation
   consumption, and the audit event commit atomically. e6irc creates a bounded
   browser session and enters the console.
6. The administrator directory lists only live invitation metadata and can
   revoke an exact invitation without retrieving its bearer value.

**Visible failures and recovery.** Invalid or retired names, duplicate pending
invitations, malformed private contact data, out-of-range lifetime, per-admin
cap exhaustion, stale browser state, expired/revoked/consumed tokens, password
mismatch, and storage failure are explicit. Public lookup deliberately gives
the same unavailable result for every unusable bearer. A failed account
transaction does not consume the invitation.

**Security and observability.** Tokens carry 256 random bits, are hashed at
rest, expire, and are single-use. Invitation/contact secrets never enter audit
details, directories, metrics, or logs. Issuance/revocation/acceptance is
audited with folded account provenance, and administrator authority becomes
live only after its durable creation commits.

**Evidence.** PostgreSQL test
`account_invitations_are_single_use_expiring_and_digest_only`, real-socket HTTP
test `invitation_creation_export_and_permanent_deletion_work_end_to_end`, and
the two-context Chromium journey in `tools/test-oidc-browser.mjs` cross
issuance, browser binding, acceptance, login, one-use rejection, and
revocation-safe metadata.

## Sign out locally and across an identity provider

**Actor and goal.** A signed-in user wants the current e6irc browser session
ended and, when applicable, the upstream single-sign-on session coordinated
without being logged straight back in.

**Preconditions.** The browser has a valid session. Coordinated logout
additionally requires retained provider/session metadata and a valid configured
end-session endpoint, front-channel callback, or back-channel signing keys.

**Flow.**

1. Local/API sign-out revokes the exact server-side session and clears its
   cookie.
2. Browser sign-out for an OpenID Connect session validates the session-bound
   CSRF value, retains local state until the provider redirect is constructible,
   and starts relying-party-initiated logout with the required hints.
3. The provider may revoke correlated sessions through signed back-channel or
   issuer/session-bound front-channel logout.
4. The provider returns to `/auth/signed-out`, a public non-cacheable page that
   does not immediately start silent authentication again.
5. The user deliberately chooses the route back to authentication.

**Visible failures and recovery.** Missing/invalid CSRF, provider metadata,
end-session endpoint, logout-token signature/claims, replayed token, or
database failure fails closed. A local session is not silently discarded when
the requested coordinated flow could not start; the user can retry or revoke
the exact session from **Your sessions**.

**Security and observability.** Cookies are cleared only with matching
server-side revocation. Back-channel tokens require signature, issuer,
audience, event, time, session/subject, and replay checks; front-channel
requests correlate only opaque provider session identifiers. Tokens, cookies,
subjects, and logout hints are excluded from logs, audit text, and metric
labels.

**Evidence.** `rp_initiated_logout_redirects_to_provider`,
`oidc_logout_without_end_session_configuration_fails_closed`, front/back
channel claim/replay tests, and browser session revocation tests prove the
generic paths. `tools/test-shauth-sso.mjs` drives exact Shauth login, relying-
party logout, global session revocation, signed-out landing, and deliberate
re-entry in Chromium.

## Authorize an input-constrained device

**Actor and goal.** A client that cannot complete browser login wants a bearer
token through the OAuth 2.0 device authorization grant.

**Preconditions.** The HTTP public URL is correct, PostgreSQL is ready, the
device can make HTTPS requests, and the approving user can open an
authenticated browser session.

**Flow.**

1. The client posts to `/api/v1/auth/device/start` and receives a device code,
   human user code, verification URI, expiry, and polling interval.
2. It displays the verification URI and code; the server’s advertised
   `/device` page exists and is usable.
3. The user signs in in a browser, reviews the code, and approves it through a
   CSRF-protected form/API.
4. The client polls `/api/v1/auth/device/token`, respecting the interval.
5. An approved code is atomically consumed while the personal access token is
   minted; replay cannot create a second token.

**Visible failures and recovery.** Unknown, expired, malformed, already
consumed, or unapproved codes receive their specified error. Polling and start
are rate-limited; live grants are bounded and stale grants are pruned.

**Security and observability.** Device and user codes are random, bounded,
short-lived, and stored separately from the resulting token. Approval is
session-authenticated and CSRF-protected; polling metrics use fixed outcomes
without codes, tokens, or account names.

**Evidence.** Proven at HTTP/PostgreSQL level by
`device_authorization_grant_flow`,
`approved_device_grant_polls_to_a_working_token_then_is_consumed`, and the
device-page HTTP coverage. `e6irc login` drives the real start, polling,
approval/consume, private-cache, and authenticated API path in
`crates/e6irc-cli/tests/e2e.rs`.

## Authenticate an IRC or BNC client

**Actor and goal.** A client wants an authenticated IRC session or wants to
attach to an owned BNC network.

**Preconditions.** The selected listener is reachable, the account has a
primary password, app password, or personal access token accepted by that
listener, and a BNC network exists when using `account/network`.

**Flow.**

1. The client negotiates `sasl` through CAP.
2. SASL PLAIN accepts the primary password or an app password; OAUTHBEARER
   accepts a valid personal access token.
3. A normal IRC listener registers the account on the local e6irc network.
4. The BNC listener requires SASL PLAIN and interprets the account field as
   `account/network`, then selects only that account’s network (or a configured
   shared network where allowed).
5. Successful credential use updates its last-used posture without exposing
   the secret.

**Visible failures and recovery.** Missing, partial, oversized, invalid, or
revoked credentials produce SASL failure and no registered/attached session.
Network-name matching is IRC-case-insensitive; another account’s network
remains invisible.

**Security and observability.** Credentials are length-bounded before hashing,
never logged, and checked before owner-scoped network selection. Authentication
and attachment counters use fixed result categories, while exact live
connections remain visible only to their owner or an administrator.

**Evidence.** Proven over real sockets/PostgreSQL by `sasl_over_real_socket`,
`sasl_oauthbearer_with_api_token`,
`bnc_listener_authenticates_and_routes_client_to_network`,
`bnc_listener_rejects_unauthenticated_and_wrong_password`, and the chunked
SASL test.

## Rotate and revoke access

**Actor and goal.** An account holder wants to reduce or terminate access
without deleting the account.

**Preconditions.** The account holder has a current browser session and, for
primary-password rotation, the current primary credential unless no primary
credential exists yet.

**Flow.**

- Change/add the primary password from **Account & access**.
- Create an app password for IRC/BNC, copy the one-time plaintext, then revoke
  it independently.
- Create a time-bounded personal access token with only the API/IRC grants it
  needs, copy it once, list its secret-free posture, then revoke it
  independently.
- List browser sessions, revoke one, or revoke all other browser sessions.
- List live IRC connections and disconnect an exact connection ID.
- Sign out locally; when provider metadata supports it, coordinated logout also
  redirects through the provider and correlates provider-initiated logout.

**Visible failures and recovery.** Credential/session caps are hard conflicts.
An app password cannot rotate the primary password. The primary credential
cannot be deleted through generic revocation. Expired or under-scoped personal
access tokens are rejected, and a bearer cannot mint broader credentials.
Account and credential request objects reject unknown fields instead of ignoring them.
Device-grant request objects use the same closed contract.
Exact-resource deletes are owner-scoped and idempotent only where the API
contract says so. A failed Account & access API read remains an announced,
in-place retryable state rather than appearing as empty profile, credential,
token, identity, read-marker, or security-activity data.
A syntactically successful response with a malformed required collection is
the same explicit retryable contract failure, never an empty directory.

**Security and observability.** New app passwords and tokens are rendered once;
only hashes and secret-free posture remain. Rotation and revocation are
CSRF-protected, owner-scoped, and audited where privileged; secret material is
excluded from pages, logs, metrics, and audit records.

**Evidence.** Proven through the database, HTTP API, and server-rendered console
by the credential, token, password-rotation, browser-session, live-connection,
and OpenID Connect logout integration suites. The real OpenID Connect browser
journey injects a token-directory API failure and proves the rendered retry
loads the canonical resource exactly once.
