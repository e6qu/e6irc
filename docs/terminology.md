# Terminology

A reference for the vocabulary that appears across e6irc — the IRC daemon,
its authentication and single sign-on surface, the bouncer and bridges, and
the deployment. It spans several domains (IRC, OpenID Connect, AWS), so this
page is the one place to look up an unfamiliar term.

**On abbreviations.** Prefer the spelled-out term in prose, comments, and
identifiers. This project keeps abbreviations to the unavoidable ones —
protocol and industry acronyms (IRC, OpenID Connect, JSON Web Token) and a
small set of IRC command names that are effectively their own words (WHOIS,
CHATHISTORY). Do not invent new abbreviations; if a term below is not here,
write it out. Every acronym in the codebase should be defined on this page.

See also: [`DESIGN.md`](../DESIGN.md) for the architecture and the
engineering laws, [`AGENTS.md`](../AGENTS.md) for working conventions, and
[`PLAN.md`](../PLAN.md) for build status.

---

## IRC and IRCv3

**IRC** — Internet Relay Chat, the text chat protocol e6irc speaks. A line
protocol of `command param... :trailing`, one TCP connection per client.

**IRCv3** — the modern extension set layered on classic IRC:
[capabilities](#irc-and-ircv3), message tags, `server-time`,
[SASL](#authentication-accounts-and-single-sign-on), CHATHISTORY, and more.
e6irc targets IRCv3, not just RFC 1459/2812.

**Nick** (nickname) — a client's display name on the network; unique while
in use. A registered [account](#services-nickserv-chanserv-oper) can own a
nick.

**Channel** — a named room (e.g. `#dev`); channel names start with `#`.

**Registration** (client) — the IRC handshake: a client sends `NICK` and
`USER` (optionally negotiating [capabilities](#irc-and-ircv3) first) before
it is a full user. "Registered" here means *handshake complete*, distinct
from a [registered account](#services-nickserv-chanserv-oper).

**Capability / CAP** — an opt-in protocol feature. Client and server
negotiate the set with the `CAP` command (`LS`/`REQ`/`END`). e6irc gates
registration until `CAP END`.

**Numeric** — a three-digit server reply code (e.g. `001` welcome, `401`
no-such-nick, `433` nick-in-use). Defined in `e6irc-proto`.

**ISUPPORT** — the `005` numeric advertising server limits and features
(`NICKLEN`, `CHANMODES`, `CHATHISTORY`, …) so clients configure themselves.

**Prefix** — a message source in `nick!user@host` form. Building one
requires a *registered* session (it has a `user`); resolving a nick to a
prefix goes through a registered-only lookup so a half-registered nick
cannot be prefix-built.

**Casemapping / casefold** — the rule (here `rfc1459`) for treating nicks
and channels case-insensitively. A *casefolded* key is the canonical form
used for lookups, so display casing never indexes a table.

**MOTD** — Message of the Day, the banner sent after a client registers.

**WHOIS / WHOWAS / WHO / WHOX** — user-information queries. WHOIS is a live
lookup; WHOWAS reports a departed nick; WHO/WHOX list users matching a mask
(WHOX is the extended, field-selectable form).

**MONITOR** — a client's watch list: the server notifies it when a watched
nick comes online or goes offline.

**CTCP** — Client-To-Client Protocol: messages wrapped in `\x01` (e.g.
`ACTION`, `VERSION`) carried inside `PRIVMSG`/`NOTICE`. Channel mode `+C`
blocks CTCP except `ACTION`.

**STATUSMSG** — a message addressed to a status-prefixed target
(`@#chan` = ops only, `+#chan` = ops and voiced). It is delivered only to
those members and is *not* stored in history.

**TAGMSG** — a message that carries only [message tags](#irc-and-ircv3), no
text body (e.g. typing indicators, reactions).

**Message tags / `server-time`** — IRCv3 key-value metadata prefixed to a
line with `@`. `server-time` stamps a message with its origin time so
history and bouncer playback are ordered.

**SendQ** — the per-connection outbound send queue. A client too slow to
drain its SendQ past the configured cap is disconnected ("SendQ exceeded")
so one slow client cannot stall the server.

---

## Services (NickServ, ChanServ, oper)

**Services** — the account and channel-ownership layer (the Atheme-style
`NickServ`/`ChanServ` pseudo-users), backed by PostgreSQL and served from
hot in-memory maps.

**Account** — a registered identity with credentials, separate from a
transient [nick](#irc-and-ircv3). A client authenticates to an account via
[SASL](#authentication-accounts-and-single-sign-on) or NickServ.

**NickServ** — the service for account registration and identification;
`GHOST` disconnects a stale session holding a nick you own.

**ChanServ** — the service for channel ownership. A channel's **founder**
owns it; **access flags** grant per-account privileges (auto-op `o`,
auto-voice `v`).

**SET options** — founder-set channel options via `ChanServ SET`:
**FOUNDER** (transfer ownership), **KEEPTOPIC** (retain the topic across
empty periods), **MLOCK** (mode lock).

**MLOCK** (mode lock) — a locked set of channel modes (e.g. `+nt-i`)
enforced on a registered channel: a mode change the wrong way is refused,
and the lock is re-applied when the channel is re-created.

**Oper** (IRC operator) — a privileged operator identity (user mode `+o`),
obtained via the `OPER` command against configured credentials.

**Server ban** — an operator ban refused at registration, one code path
with a `kind`: **K-line** (`user@host`), **D-line** (host/IP), **X-line**
(realname/gecos). `KILL` forcibly disconnects a client; `WALLOPS` messages
opers.

**SETHOST / chghost** — an oper command that changes a user's displayed host
(a cloak), announced to peers via the `chghost` capability.

---

## Authentication, accounts, and single sign-on

**SASL** — Simple Authentication and Security Layer: the in-band mechanism a
client uses to authenticate during the IRC handshake. e6irc supports
`PLAIN` (account + password) and `OAUTHBEARER` (a token).

**App password** — a long, random per-use password minted for an account
(argon2id-hashed at rest); usable immediately for SASL.

**Personal access token / PAT** — a bearer token for the REST API and for
`OAUTHBEARER` SASL. Shown once at creation; only its hash is stored.

**Web session** — a browser login session: an opaque cookie
(`e6irc_session`), stored only as its SHA-256 hash, `HttpOnly` +
`SameSite=Lax`.

**OAuth** — OAuth 2.0, the authorization framework OpenID Connect builds on.

**OpenID Connect / OIDC** — the identity layer over OAuth 2.0 that e6irc
uses for browser login. e6irc is a *client* of an external provider.

**Identity provider / IdP** (a.k.a. OpenID Provider) — the service that
authenticates users and issues tokens. For the e6qu deployment this is
[Shauth](#deployment-and-infrastructure).

**Relying party / RP** — an application that delegates login to an
[identity provider](#authentication-accounts-and-single-sign-on). e6irc is a
relying party of Shauth.

**Single sign-on / SSO** — one identity-provider session logging a user into
many relying parties without re-entering credentials.

**Discovery** — the provider's `/.well-known/openid-configuration` document
listing its endpoints and signing keys, fetched to configure a client.

**PKCE** — Proof Key for Code Exchange: a one-time secret (`code_verifier` /
`code_challenge`) binding an authorization request to its token exchange, so
a stolen authorization code is useless.

**Authorization code flow** — the OIDC login exchange: redirect to the
provider, receive a short-lived `code`, exchange it (with PKCE) for tokens.

**JSON Web Token / JWT** — a signed, base64url token of three
dot-separated segments (header, claims, signature).

**JSON Web Key Set / JWKS** — the provider's public signing keys (at its
`jwks_uri`), used to verify a JWT's signature.

**ID token** — the JWT proving who logged in. e6irc validates its signature
against [JWKS](#authentication-accounts-and-single-sign-on) and its claims.

**Claims** — the fields inside a token:
- `iss` (issuer) — who issued the token.
- `sub` (subject) — the stable user identifier at the provider.
- `aud` (audience) — the client(s) the token is for.
- `azp` (authorized party) — when `aud` has more than one value, the single
  client the token was issued for; if present it must equal our client id.
- `iat` / `exp` — issued-at / expiry times.
- `jti` (JWT ID) — a unique token identifier, used to reject replays.
- `sid` (session id) — the provider-side login-session identifier, used to
  target [logout](#logout).
- `nonce` — a login-request value bound into the ID token to prevent replay
  (and forbidden in a logout token).
- `preferred_username`, `email`, `role` — profile claims Shauth issues.

**`prompt=none` / silent authentication** — an authorization request that
must not show any UI. If the browser already has an
[SSO](#authentication-accounts-and-single-sign-on) session the provider
returns a code with no prompt; otherwise it returns `login_required`. e6irc
uses this to recognize an existing Shauth session without a second login.

**OAUTHBEARER** — the SASL mechanism (RFC 7628) that authenticates an IRC
client with an OAuth token instead of a password.

**Device authorization grant** (device flow, RFC 8628) — login for an input-
constrained client: it shows a short user code the user approves in a
browser, then polls for the token.

**CSRF** — Cross-Site Request Forgery: tricking a logged-in user's browser
into an unwanted request. The OIDC `state` parameter and same-origin cookie
rules defend the login and logout flows.

### Logout

**RP-initiated logout** — the relying party starts logout: e6irc clears its
own session, then redirects the browser to the provider's *end-session
endpoint* with an `id_token_hint` and `post_logout_redirect_uri`, ending the
provider's [SSO](#authentication-accounts-and-single-sign-on) session too.

**End-session endpoint** — the provider URL that terminates the SSO session
(`/oauth2/sessions/logout` on Shauth/Hydra).

**`post_logout_redirect_uri`** — where the provider returns the browser after
logout; must be pre-registered on the client.

**Front-channel logout** — the provider logs a relying party out by loading
its front-channel URL (a browser redirect/iframe carrying `iss` and `sid`);
there is no signed token, so it relies on `sid` entropy.

**Back-channel logout** — the provider POSTs a signed **logout token**
(a JWT with the backchannel-logout `events` claim, `sid`/`sub`, and a `jti`)
directly to a relying party's back-channel URL, server-to-server. e6irc
verifies the signature and claims, dedupes on `jti`, and revokes the matching
sessions.

**Coordinated logout** — the umbrella term for keeping every relying party's
session in step with the provider via the front- and back-channel
mechanisms above.

---

## Bouncer and bridges

**Bouncer / BNC** — an always-on proxy that stays connected to upstream
networks while the user's client is away, buffering traffic for replay. A
client **attaches** to a network by name and **detaches** when it leaves.

**Network** (BNC) — one configured upstream connection (an IRC server, or a
bridged Matrix/Discord/Slack workspace), each run by an always-on **driver**.

**Bridge** — a driver that presents a non-IRC service as a BNC network:
**Matrix**, **Discord**, or **Slack** (each behind a build feature flag).

**Gateway** — the persistent WebSocket a Discord or Slack bridge holds to its
platform for real-time events.

**IRC-over-WebSocket** — the browser transport (`/ws`) that carries the IRC
protocol over a WebSocket, so a web client speaks IRC without a raw TCP port.

---

## History and persistence

**CHATHISTORY** — the IRCv3 batch replay of past messages
(`LATEST`/`BEFORE`/`AFTER`/`AROUND`/`BETWEEN`/`TARGETS`), served from the hot
ring and paged from PostgreSQL beyond it.

**Hot ring / history ring** — the in-memory bounded ring of recent messages
per active channel; older history lives only in PostgreSQL. Least-recently-
active channels evict their ring.

**msgid** — a unique message identifier (IRCv3 `msgid` tag) used to address a
message in CHATHISTORY.

**PostgreSQL / PG** — the durable store for accounts, channel registration,
history, sessions, and server bans. Accessed only by the database worker.

**Migration** — a numbered, checksum-pinned SQL schema change under
`migrations/`, run at startup.

**Read marker** (`draft/read-marker`) — a per-account, per-target timestamp
of how far a user has read, set via `MARKREAD` and synced across clients.

---

## Internal architecture

**Core worker** — the single share-nothing task that owns all chat state and
processes every client event serially (the degenerate N=1 of a sharded
design). It never touches the database directly.

**Database worker** — the task that owns the PostgreSQL pool and answers the
core worker's requests, keeping slow I/O off the core.

**`e6irc-queue`** — the custom bounded MPSC queue connecting the workers,
with backpressure so a full core queue pauses socket reads.

**`e6irc-proto`** — the protocol crate: message model, parser/serializer,
casemapping, numerics, and time formatting.

**CLI / TUI** — the command-line client (`e6irc-cli`) and the terminal user
interface client (`e6irc-tui`).

**REST** — the HTTP JSON API under `/api/v1` (accounts, tokens, networks,
admin, OpenAPI spec).

**embed-web** — the build feature that bakes the built web client
(`web/dist`, a Vite + htmx bundle) into the binary and serves it at `/`;
off by default so assets can be hosted separately.

---

## Deployment and infrastructure

**e6qu** — the organization that owns e6irc and the shared development
environment it deploys into.

**Shauth** — e6qu's identity service and the [identity
provider](#authentication-accounts-and-single-sign-on) for its apps. It
brokers GitHub login and issues OpenID Connect tokens via **Ory Hydra**.

**Hydra** (Ory Hydra) — the OAuth 2.0 / OpenID Connect engine behind Shauth;
Shauth exposes Hydra's public endpoints at its own hostname.

**AWS** — Amazon Web Services, where the environment runs (region
`eu-west-1`).

**ECS** — Elastic Container Service, which runs the containers.
**Fargate** is the serverless ECS launch type (no host to manage). Tasks run
on **Graviton** (**ARM64**) CPUs.

**RDS** — Relational Database Service (managed databases). **fck-rds** is the
shared PostgreSQL the environment provisions a per-tenant database on.

**VPC** — Virtual Private Cloud, the isolated network. **ALB** / **NLB** are
the Application / Network Load Balancers; **API Gateway** is the HTTP entry
point used by scale-to-zero services.

**ACM** — AWS Certificate Manager (TLS certificates). **Route 53** is DNS;
the environment owns the `dev.e6qu.dev` zone.

**Secrets Manager** — AWS's store for secrets (database URLs, OIDC client
secrets), injected into a task at runtime by ARN rather than committed.

**GHCR** — GitHub Container Registry (`ghcr.io`), where the e6irc image is
published.

**Image digest / manifest / multi-arch** — an image is pinned by its
immutable content **digest** (`@sha256:…`), not a mutable tag. A **multi-arch
manifest** is an index listing per-architecture images (amd64 + arm64) under
one reference, so the right one is pulled per host.

**Terraform** — the infrastructure-as-code tool. **Terragrunt** is the
thin wrapper the environment uses to compose Terraform with shared state and
providers. **HCL** is HashiCorp Configuration Language, the syntax both use.

**app-contract** — an entry in the environment's `app-contracts.json`
registering an application's Shauth OpenID Connect client (redirect and
logout URIs, health URL), reconciled into Shauth at startup.
