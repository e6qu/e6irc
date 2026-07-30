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
sessions from **Your sessions** before retrying if the cap is reached.

**Security and observability.** Passwords are Argon2 hashes in the credential
store. Login failures do not disclose whether an account exists. Authentication
metrics use fixed categories, not account names.

**Evidence.** Proven at HTTP/PostgreSQL level by
`local_login_is_browser_bound_and_accepts_only_the_primary_password`,
`concurrent_browser_session_issuance_enforces_the_active_cap`, and the browser
session inventory tests. Browser-driven local login is not part of the current
Playwright suite.

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
4. `(issuer, subject)` resolves a linked e6irc account. First login provisions
   one according to registration policy; later logins reuse it.
5. The server creates a bounded browser session, retains the provider logout
   hint when supplied, and enters the application.

**Visible failures and recovery.** Unknown/disabled provider, stale or replayed
state, callback mismatch, invalid claims, registration denial, identity
conflict, session-cap conflict, and provider/network/database failures all fail
closed. No local session is created from partially validated claims. The
validation and signed-out pages remain reload-safe.

**Security and observability.** State is one-time and expiring; PKCE binds the
authorization code; identities are globally unique. Front-channel and
back-channel logout use correlation rather than trusting browser-supplied
account data.

**Evidence.** Proven against a real e6ircd, PostgreSQL, Dex, and Chromium by
`full_oidc_login_provisions_account_and_session`,
`oidc_silent_sso_reuses_provider_session`, and
`tools/test-oidc-browser.mjs`. Exact Shauth launch and coordinated logout are
also exercised by the `shauth-sso` CI job.

## Link or unlink an OpenID Connect identity

**Actor and goal.** A signed-in account holder wants another provider identity
to authenticate the same account, or wants to remove an existing link.

**Flow.**

1. **Account & access** lists linked identities without provider secrets.
2. **Link** starts a fresh provider flow marked as a link operation.
3. The callback attaches the validated `(issuer, subject)` to the initiating
   account only if no other account owns it.
4. Unlink requires an authenticated, CSRF-protected console form or the
   owner-scoped `DELETE /api/v1/me/identities/{id}`.
5. The account remains usable through its remaining credentials/identities.

**Visible failures and recovery.** Linking an identity owned by another account
is a conflict, never a move. Unlinking an identity outside the caller’s account
is indistinguishable from absence. The server refuses a mutation that would
violate the account’s access invariants.

**Evidence.** Proven at real Dex/PostgreSQL level by
`oidc_identity_link_flow_and_conflict` and
`oidc_identity_link_list_and_conflict`; console rendering/mutation is covered
by `account_console_manages_credentials_tokens_and_identities`.

## Authorize an input-constrained device

**Actor and goal.** A client that cannot complete browser login wants a bearer
token through the OAuth 2.0 device authorization grant.

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

**Evidence.** Proven at HTTP/PostgreSQL level by
`device_authorization_grant_flow`,
`approved_device_grant_polls_to_a_working_token_then_is_consumed`, and the
device-page HTTP coverage. No shipped CLI currently orchestrates this flow; it
is a server/API capability.

## Authenticate an IRC or BNC client

**Actor and goal.** A client wants an authenticated IRC session or wants to
attach to an owned BNC network.

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

**Evidence.** Proven over real sockets/PostgreSQL by `sasl_over_real_socket`,
`sasl_oauthbearer_with_api_token`,
`bnc_listener_authenticates_and_routes_client_to_network`,
`bnc_listener_rejects_unauthenticated_and_wrong_password`, and the chunked
SASL test.

## Rotate and revoke access

**Actor and goal.** An account holder wants to reduce or terminate access
without deleting the account.

**Flow.**

- Change/add the primary password from **Account & access**.
- Create an app password for IRC/BNC, copy the one-time plaintext, then revoke
  it independently.
- Create a personal access token for API/OAUTHBEARER, copy it once, list its
  secret-free posture, then revoke it independently.
- List browser sessions, revoke one, or revoke all other browser sessions.
- List live IRC connections and disconnect an exact connection ID.
- Sign out locally; when provider metadata supports it, coordinated logout also
  redirects through the provider and correlates provider-initiated logout.

**Visible failures and recovery.** Credential/session caps are hard conflicts.
An app password cannot rotate the primary password. The primary credential
cannot be deleted through generic revocation. Exact-resource deletes are
owner-scoped and idempotent only where the API contract says so.

**Evidence.** Proven through the database, HTTP API, and server-rendered console
by the credential, token, password-rotation, browser-session, live-connection,
and OpenID Connect logout integration suites.
