# Terminology

This glossary defines e6irc terms.

Prefer spelled-out terms. Define each new abbreviation here.

See [DESIGN.md](../DESIGN.md), [AGENTS.md](../AGENTS.md), [PLAN.md](../PLAN.md),
and [journeys](journeys/README.md).

---

## Product and evidence

**User journey** — an end-to-end outcome sought by a person or calling
system. A journey can cross browser, REST, WebSocket, IRC, driver, and
PostgreSQL boundaries; a page or endpoint is only one step. Journey documents
state prerequisites, success, visible failure/recovery, security and
observability contracts, and the automated evidence for the complete outcome.

**Qualification boundary** — a boundary that current automated evidence does
not cross, such as replacing a real WebSocket with a browser mock or requiring
live commercial credentials. It distinguishes “components have tests” from
“the user outcome is proven.”

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

**User name** (ident) — the first parameter of `USER`, shown before the `@` in
a client's address (`nick!username@host`). It is not the
[nick](#irc-and-ircv3), not the real name, and not an
[account](#services-nickserv-chanserv-oper). A server that dislikes it closes
the link rather than sending a numeric, so e6irc requires one to be configured
(`username`, at most 10 ASCII letters, digits, `_` or `-`, starting with a
letter or digit) and never derives or rewrites it.

**Real name** — the trailing parameter of `USER`; free text shown in WHOIS.

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
used for lookups, so display casing never indexes a table. The clients use the
upstream network's own rule from its `005 CASEMAPPING` (and its channel
prefixes from `CHANTYPES`), through `e6irc_client::NetworkNames`.

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
those members and is *not* stored in history. Only a member holding op or
voice in the channel may send one (Solanum); anyone else gets `482`.

**Ban mask / extban / CIDR mask** — the argument of a channel list mode
(`+b` ban, `+q` quiet, `+e` ban exception, `+I` invite exception). A
**hostmask** is a `nick!user@host` glob; a **CIDR mask** (Classless
Inter-Domain Routing) has an address range as its host (`*!*@203.0.113.0/24`)
and matches the address the user connected from, whatever host it shows. An
**extban** (extended ban) is a `$`-prefixed mask of another kind: `$a` (any
logged-in user), `$a:<account mask>`, and their negations `$~a…`
(advertised as `EXTBAN=$,a`).

**KNOCK** — a request to be let into a channel closed to the requester
(`+i`, keyed, or full), delivered to its operators; throttled per user and
per channel.

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
`GHOST` disconnects a stale session holding a nick you own, `REGAIN` renames
that session to a [Guest nick](#services-nickserv-chanserv-oper) and gives you
the nick, and `DROP` permanently deletes your account (after a confirmation
key, through the same deletion the account console performs).

**Grouped nick** — a nick added to an account with NickServ `GROUP` (removed
with `UNGROUP`). An account owns the nick spelled like its name and its
grouped nicks, at most five in all; a nick is registered to at most one
account. Any of them identifies to the account.

**Nick protection** (NickServ `SET ENFORCE`) — an account's choice to have
its nicks enforced: a user who takes one without identifying to the account
is warned, and after the enforcement delay (30 seconds) renamed to a
**Guest nick** — `Guest` and a number, unique on the network.

**ChanServ** — the service for channel ownership. A channel's **founder**
owns it; **access flags** grant per-account privileges (auto-op `o`,
auto-voice `v`). `ACCESS` edits the same entries by **role**: **AOP**
(auto-op) or **VOP** (auto-voice).

**Successor** — the account a registered channel passes to when its
founder's account is deleted (`ChanServ SET <#channel> SUCCESSOR`). A founder
with a channel that has no successor cannot be deleted.

**SET options** — founder-set channel options via `ChanServ SET`:
**FOUNDER** (transfer ownership), **SUCCESSOR** (who inherits the channel),
**KEEPTOPIC** (retain the topic across empty periods), **MLOCK** (mode lock).

**MLOCK** (mode lock) — a locked set of channel modes (e.g. `+nt-i`)
enforced on a registered channel: a mode change the wrong way is refused,
and the lock is re-applied when the channel is re-created.

**Oper** (IRC operator) — a privileged operator identity (user mode `+o`),
obtained via the `OPER` command against configured credentials.

**Server ban** — an operator ban refused at registration, one code path
with a `kind`: **K-line** (`user@host`, the host a glob, an address or a
CIDR range), **D-line** (an IP address, CIDR range or address glob, matched
against the address the user connected from), **X-line** (realname/gecos).
A reason `public|private` shows the banned user only the part before `|`. `KILL` forcibly disconnects a client; `WALLOPS` messages
opers.

**SETHOST / chghost** — an oper command that changes a user's displayed host
(a cloak), announced to peers via the `chghost` capability.

---

## Authentication, accounts, and single sign-on

**SASL** — Simple Authentication and Security Layer: the in-band mechanism a
client uses to authenticate during the IRC handshake. e6ircd accepts `PLAIN`
(account + password) and `OAUTHBEARER` (a token). As a client — the bouncer
towards an upstream network, and the native clients — e6irc chooses the
strongest password mechanism the server offers: `SCRAM-SHA-512`,
`SCRAM-SHA-256`, then `PLAIN`.

**SCRAM** — Salted Challenge Response Authentication Mechanism (RFC 5802;
`SCRAM-SHA-256` in RFC 7677): a SASL password mechanism in which the password
never crosses the wire and the server proves it holds the account's verifier.
It uses **SASLprep** (RFC 4013), the normalization applied to the account name
and password first, and **PBKDF2**, the iterated key derivation that salts the
password.

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

**Qualification evidence** — immutable JSON from a credential-gated external
probe. It identifies the source, executable, host, target, workload, budgets,
phases, timestamps, and closed outcome without credential values.

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

**IRC-over-WebSocket** — the browser transport (`/ws/irc`) that carries the IRC
protocol over a WebSocket, so a web client speaks IRC without a raw TCP port.

**Preset** — one entry of the curated catalog of public IRC networks
(`IRC_NETWORK_PRESETS`: Libera Chat, OFTC, Snoonet), served at
`GET /api/v1/network-presets`. Every preset is a TLS endpoint on port 6697. A
preset only fills the add-network form; the request carries the resulting
fields, never a preset identifier.

**Preflight** — the optional **Test connection** diagnostic
(`POST /api/v1/me/network-preflight`, `preflight_irc`). It resolves, connects,
and registers exactly as the always-on IRC driver would, reports each stage's
timing, sends `QUIT`, and stores nothing: it joins no channel (the requested
ones are only validated), no network is created and no driver is started.
Saving a network never depends on it.

**Server password (PASS)** — a network's connection password: the argument of
the `PASS` line a private IRC server requires before `CAP LS`, `NICK` and
`USER`, answered with `464` when it is wrong or missing. It admits the
connection, not a user — distinct from the SASL or NickServ password, which
identifies an account. e6irc sends it first when one is configured, stores it
sealed like the SASL password, reports only whether one is stored
(`has_server_password`), and tells a missing one (`server_password_required`)
from a rejected one (`server_password_rejected`); both wait on the refusal
schedule. IRC networks only; a bridge has no such line.

**Channel key** — the key of a keyed (`+k`) IRC channel: the second `JOIN`
parameter, without which the server answers `475`. An account network's
autojoin entry may carry one after its channel (`#staff key`); e6irc stores it
sealed like the SASL password, reports only which channels have one
(`autojoin_keyed`), and changes it on a replace only as `autojoin_keys` says.
Keys the driver learns at runtime (a client's `JOIN`, a `+k`) are kept in
memory only. IRC networks only; a bridge's rooms have no key.

**Refusal schedule** — the delays before a driver re-dials an upstream that
refused its registration: 30 seconds, then 1, 2, and 4 minutes, long enough for
a ghost of the driver's own session to time out upstream. An ordinary
connection loss uses the shorter reconnect backoff instead.

**Parked** — a driver that has stopped re-dialing and stays stopped until its
network is reconfigured. Rejected credentials park on the first rejection,
because every further attempt counts against the account upstream, and so does
a welcome under another nickname. A refusal that may be a configuration fault
(a held nickname, one the network will not take, a server password) parks on
the fifth of its kind in a row, after the refusal schedule is exhausted. A
capacity or policy answer (a throttle, a ban, "SASL access only") never parks:
it is retried every four minutes for as long as it lasts. DESIGN §10.3 is the
full statement. A parked network shows why and what repairs it.

**Supersede** and **ensure-running** — the two ways the registry starts a
driver for a network that may already have one (`bouncer/serve.rs`).
*Supersede* (`Registry::replace`) stops the running driver, waits for it to
disconnect, and starts the new one; saving changed settings uses it.
*Ensure-running* (`Registry::ensure_running`) starts a driver when none is
registered, supersedes a parked one, and leaves a connecting, connected, or
reconnecting one alone, so enabling an already-enabled network never drops a
healthy upstream session. A plain `Registry::add` refuses a network that
already has a live driver, so two upstream sessions can never race for one
network.

**Server log** — the chat client's wire log: a conversation beside the
channels that shows every IRC line received for the open network, verbatim
except that sensitive commands are redacted. The console's per-network
**Network log** is a different, persisted view of driver lifecycle and
failures.

**Relay-desk** — the visual system shared by the identity pages, the console,
the chat client, and the terminal client: dark routing chrome, compact
monospaced provenance labels, high-contrast state colors, and one amber route
trace joining network context to the active conversation.

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

**Core worker** — one share-nothing task that owns its chat-state shard and
processes its events serially. The configured count defaults to one. It never
touches the database directly.

**Database worker** — the task that owns the PostgreSQL pool and answers the
core worker's requests, keeping slow I/O off the core.

**`e6irc-queue`** — the custom bounded MPSC queue connecting the workers,
with backpressure so a full core queue pauses socket reads.

**`e6irc-proto`** — the protocol crate: message model, parser, tag escaping,
casemapping, numerics, and time formatting.

**CLI / TUI** — the command-line client (`e6irc-cli`) and the terminal user
interface client (`e6irc-tui`).

**REST** — the HTTP JSON API under `/api/v1` (accounts, tokens, networks,
admin, OpenAPI spec).

**Read-copy-update (RCU)** — a sharing pattern in which a writer publishes a
new immutable snapshot and readers keep using the one they already hold, so
readers never lock. e6irc's channel recipient lists work this way; its managed
configuration does not (it sits behind a read–write lock off the hot path).

**Link-time optimization (LTO)** — compiler optimization across crate
boundaries at link time. Release builds use the "fat" whole-program form with
one code-generation unit.

**Authenticated encryption with associated data (AEAD)** — encryption that
also proves the ciphertext, and the context it was bound to, were not altered.
Stored credentials are sealed with the ChaCha20-Poly1305 AEAD cipher.

**Web Content Accessibility Guidelines (WCAG)** — the W3C accessibility
standard. The browser suites hold the chat, console, and identity pages to its
level AA, including contrast.

**embed-web** — the build feature that bakes the built web client
(`web/dist`, a vanilla JavaScript bundle produced by Vite) into the binary and
serves it at `/`;
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

**Open Container Initiative (OCI)** — the standard for container image and
registry formats. An **OCI referrer** is an artifact a registry stores as
attached to an image digest; e6irc's signed attestations are published that
way, so they add no tag and do not change the image manifest.

**Software bill of materials (SBOM)** — a machine-readable inventory of what
an image contains. **SPDX** (Software Package Data Exchange) is the Linux
Foundation format e6irc's is written in (SPDX 2.3 JSON); one is generated and
attested for each architecture image.

**Terraform** — the infrastructure-as-code tool. **Terragrunt** is the
thin wrapper the environment uses to compose Terraform with shared state and
providers. **HCL** is HashiCorp Configuration Language, the syntax both use.

**app-contract** — an entry in the environment's `app-contracts.json`
registering an application's Shauth OpenID Connect client (redirect and
logout URIs, health URL), reconciled into Shauth at startup.
