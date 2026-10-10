# Terminology

This glossary defines e6irc terms.

Prefer spelled-out terms. Define each new abbreviation here: every
abbreviation the prose uses — Markdown, and code comments — is written in
bold in an entry below, alone or as one of its spellings (`**TLS**`,
`**Transport Layer Security (TLS)**`, `**Bouncer / BNC**`), or spelled out
where it is used. `tools/check-terminology.py` enforces it.

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
drain its SendQ past the configured cap (`sendq_bytes`, in bytes, as
Solanum's class `sendq`) is disconnected ("SendQ exceeded") so one slow client
cannot stall the server.

**ELIST / SAFELIST** — the `005` tokens describing `LIST`. `ELIST` (extended
LIST) names the conditions it takes, one letter each: `C` creation time, `M`
channel-name mask, `N` negated mask, `T` topic time, `U` user count.
`SAFELIST` says the reply is paced to the client's SendQ, so listing every
channel cannot get the client disconnected.

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
A reason `public|private` shows the banned user only the part before `|`. A
**temporary** ban (`KLINE <minutes> <mask>`) lapses on its own. `KILL`
forcibly disconnects a client; `WALLOPS` messages opers.

**`+R` / `+Z`** — user modes. `+R` (registered-only messages): only users
logged in to an account, and operators, may message or invite you. `+Z`
(secure): set by the server on a TLS connection; WHOIS shows it as 671.

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

**Client certificate / CertFP** — a TLS certificate the client presents in
the handshake, here the bouncer towards an upstream network. Services
recognise it by its **fingerprint** (the SHA-256 or SHA-512 digest of the
certificate) once the account owner has registered it with NickServ
`CERT ADD`: **CertFP** ("certificate fingerprint") identifies the account on
every connection with no password, which is how OFTC authenticates. A network
that offers **SASL EXTERNAL** logs the certificate in during the handshake
instead ("external" because the credential is the one the transport already
carried). A generated one is self-signed: services compare fingerprints, not a
chain.

**ECDSA / Ed25519** — the signature algorithms a generated client certificate
uses: **ECDSA** is the Elliptic Curve Digital Signature Algorithm (here on the
P-256 curve), **Ed25519** the Edwards-curve signature scheme on Curve25519. An
uploaded key may also be RSA. It is read in PEM form as **PKCS** #8 or #1
(Public-Key Cryptography Standards) or **SEC** 1 (Standards for Efficient
Cryptography).

**GS2** — the Generic Security Service Application Program Interface
bridge for SASL (RFC 5801): the header (`n,a=<authzid>,`) that opens an
`OAUTHBEARER` response (RFC 7628) and a SCRAM one, naming channel binding and
the authorization identity. e6ircd parses it and refuses an authorization
identity that is not the token's account.

**NIST** — the United States National Institute of Standards and
Technology. Its **SP** (Special Publication) 800-63B, *Digital Identity
Guidelines: Authentication and Lifecycle Management*, is the source of the
8-character floor for a new password (`NewPassword`).

**App password** — a long, random per-use password minted for an account
(argon2id-hashed at rest); usable immediately for SASL.

**Personal access token / PAT** — a bearer token for the REST API and for
`OAUTHBEARER` SASL. Shown once at creation; only its hash is stored.

**Web session** — a browser login session: an opaque cookie, stored only as
its SHA-256 hash, `HttpOnly` + `SameSite=Lax`. With secure cookies (the
default, `[http] secure_cookies`) it is `__Host-e6irc_session`, also `Secure`
and pinned to the exact host; plain-HTTP development, which turns secure
cookies off, gets `e6irc_session`, since the `__Host-` prefix requires
`Secure`.

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
**wss** (the connection directory's transport name) is one a trusted proxy
reports its client reached over HTTPS; `websocket` is any other.

**Preset** — one entry of the curated catalog of public IRC networks
(`IRC_NETWORK_PRESETS`: Libera Chat, OFTC, Snoonet), served at
`GET /api/v1/network-presets`. Every preset is a TLS endpoint on port 6697. A
preset only fills the add-network form; the request carries the resulting
fields, never a preset identifier. Each says how the network authenticates an
account (`sasl`, or `client_certificate` for OFTC) and how to set it up.

**Remembered channel** — a channel a stored IRC network's session was
confirmed in (the upstream echoed our own `JOIN`), kept in PostgreSQL with its
key sealed, and rejoined beside the configured autojoin after a process
restart or an edit of the network. A `PART`, a `KICK` of the session, a rejoin
the upstream refuses, or its removal from the console forgets it.

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

**Console** (chat client) — the first entry in the chat client's
conversations, where the server buffer used to be: it shows every IRC line
received for the open network, verbatim except that sensitive commands are
redacted, beside e6irc's own notices, and sends what is typed there as the IRC
line itself (a `/command` still means the command). It replaced a separate
Server log panel (DESIGN §13.2). Not the administration console at `/console`,
whose per-network page has a different, persisted view: the **IRC
transcript**, the newest stored IRC lines of that network, including NickServ
replies and connection errors.

**Relay-desk** — the visual system shared by the identity pages, the console,
the chat client, and the terminal client: dark routing chrome, compact
monospaced provenance labels, high-contrast state colors, and one amber route
trace joining network context to the active conversation.

---

## History and persistence

**Direct message (DM)** — a private conversation between two users (a
`PRIVMSG` to a nick, a query), stored and replayed like a channel's history
under the pair of participants.

**CHATHISTORY** — the IRCv3 batch replay of past messages
(`LATEST`/`BEFORE`/`AFTER`/`AROUND`/`BETWEEN`/`TARGETS`), served from the hot
ring and paged from PostgreSQL beyond it.

**Hot ring / history ring** — the in-memory bounded ring of recent messages
per active channel; older history lives only in PostgreSQL. Least-recently-
active channels evict their ring: a **least recently used (LRU)** order.

**msgid** — a unique message identifier (IRCv3 `msgid` tag) used to address a
message in CHATHISTORY.

**PostgreSQL / PG** — the durable store for accounts, channel registration,
history, sessions, and server bans. Accessed only by the database worker.

**Database / DB** — in e6irc, always PostgreSQL; the **DB worker** is the
[database worker](#internal-architecture).

**Structured Query Language (SQL)** — PostgreSQL's query language. Every
query binds its parameters; migrations are SQL files.

**Create, read, update, delete (CRUD)** — the four operations on a managed
resource (an app password, a network, a server ban), each an `/api/v1`
route.

**Block range index (BRIN)** and **generalized inverted index (GIN)** —
PostgreSQL index kinds. A BRIN stores a summary per range of table blocks and
suits an append-ordered column such as a message timestamp; a GIN indexes
each element of an array, which is how a direct message is found by either
of its participants (`dm_peers`).

**Migration** — a numbered, checksum-pinned SQL schema change under
`migrations/`, run at startup by the process that holds the serving lease.

**Serving lease** — the one row (`serving_lease`, migration 0098) that names
the one process serving a database. Its holder renews it every few seconds;
another process may take it once it is released or its **time to live
(TTL)** — how long it stands after the last renewal — has passed.

**Standby** — an e6ircd process started against a database another process
serves: it binds only its HTTP health answers and takes the lease over when
the holder stops or dies. **Active/standby** is this arrangement; active/active
(several processes serving one database) is not supported.

**Fence** — what keeps a process that may have lost the lease from acting as
if it held it: a holder that cannot confirm a renewal in time reports its
lease unconfirmed and is not ready, keeping its clients until a renewal says
whether the lease is still its own (it resumes) or another's (it stops
serving); PostgreSQL refuses a non-holder's new connections and ends the
previous holder's open ones at a takeover.

**Universally unique identifier (UUID)** — a 128-bit random identifier; a
process names itself as a lease holder by one.

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

**`e6irc-edge`** — the crate that holds client connections: accept, TLS and
certificate reload, client addresses and per-address limits, line and
WebSocket framing, and every write to a client. It has no database
dependency, which `tools/check-edge-isolation.sh` holds (see "Edge tier").

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
That context is the **additional authenticated data (AAD)**: authenticated
but not encrypted, so a value sealed for one purpose cannot be opened as
another's.
Stored credentials are sealed with the ChaCha20-Poly1305 AEAD cipher.

**Web Content Accessibility Guidelines (WCAG)** — the World Wide Web
Consortium's accessibility standard. The browser suites hold the chat,
console, and identity pages to its level **AA** (the middle of its three
conformance levels), including contrast.

**embed-web** — the build feature that bakes the built web client
(`web/dist`, a vanilla JavaScript bundle produced by Vite) into the binary and
serves it at `/`;
off by default so assets can be hosted separately.

---

## Networking, formats, and systems

**Transmission Control Protocol (TCP)** — the reliable byte-stream transport
under IRC, HTTP and PostgreSQL connections. A **RST** (reset) aborts a
connection at once and discards what the peer had not read, which is why
e6irc's closing paths drain before they close.

**Internet Protocol (IP)** — the network layer. An **IP address** is IPv4 or
IPv6; per-address limits key on an IPv4 address or an IPv6 `/64`.

**Classless Inter-Domain Routing (CIDR)** — the `address/prefix` notation for
an address range (`203.0.113.0/24`), used by bans, `trusted_proxies`, and
`require_sasl_from`.

**Network address translation (NAT)** — rewriting addresses at a router so
many hosts share one public address. **Carrier-grade NAT** (`100.64.0.0/10`)
and **NAT64** (an IPv6 host reaching IPv4 through `64:ff9b::/96`) ranges are
internal addresses to the bouncer's upstream-address check.

**Domain Name System (DNS)** — resolves a hostname to addresses; the bouncer
vets every result again at dial time.

**Network Time Protocol (NTP)** — clock synchronization. An NTP step can jump
wall-clock time, so timeouts and reapers use a monotonic clock.

**Transport Layer Security (TLS)** — encrypted, authenticated transport, from
rustls for listeners, upstream dials, PostgreSQL, and HTTP clients. A
**certificate authority (CA)** issues the certificates a TLS client trusts.
**Distinguished Encoding Rules (DER)** is a certificate's binary form;
**Privacy-Enhanced Mail (PEM)** is its base64 text wrapping
(`-----BEGIN CERTIFICATE-----`), the form certificate and key files are read
in.

**Hypertext Transfer Protocol (HTTP) / HTTPS** — the web protocol of the
REST API, the console, and the WebSocket upgrade; HTTPS is HTTP over TLS.

**WebSocket / WS** — a full-duplex message channel upgraded from an HTTP
request; the browser's IRC transport ([IRC-over-WebSocket](#bouncer-and-bridges)).

**Uniform Resource Identifier (URI) / Uniform Resource Locator (URL)** — a
URI names a resource; a URL is a URI that also says where to fetch it (the
public URL, an OpenID Connect redirect URI).

**Application programming interface (API)** — a programmatic interface; here
usually the [REST](#internal-architecture) API under `/api/v1`.

**Service provider interface (SPI)** — an interface a plug-in implements for
its host to call. The bouncer's `NetworkDriver` trait is the driver SPI the IRC
driver and the bridges implement.

**Application binary interface (ABI)** — the calling convention a function is
compiled to (`extern "C"`).

**JavaScript Object Notation (JSON)** — the text data format of the REST API,
reports, and evidence files.

**Tom's Obvious, Minimal Language (TOML)** — the configuration file format
(`e6ircd.toml`).

**HyperText Markup Language (HTML)**, **Cascading Style Sheets (CSS)**, and
the **Document Object Model (DOM)** — a page's markup, its styling, and the
browser's in-memory tree of it. The console and chat scripts build rows as DOM
nodes, never by assembling markup strings.

**Single-page application (SPA)** — a browser application that renders every
view in one page with client-side routing. e6irc uses no SPA framework: the
chat shell is one page of plain JavaScript, and the management pages are
server-rendered.

**User interface (UI)** — what a person sees and operates: the web pages, the
terminal client, the console.

**American Standard Code for Information Interchange (ASCII)** — the 7-bit
character set; IRC's syntax characters and user names are ASCII.

**Unicode Transformation Format (UTF) / UTF-8** — UTF-8 is the
variable-width Unicode encoding e6irc requires of every line and stores.

**ISO 8601** — the International Organization for Standardization's (**ISO**)
date and time format; `server-time` and stored read-marker timestamps are its
UTC form (`2026-09-27T12:00:00.000Z`), which sorts as text.

**CRLF** — carriage return and line feed (`\r\n`), the IRC line terminator.

**Control Sequence Introducer (CSI)** — the `ESC [` pair (or the single C1
byte `0x9B`) that starts a terminal control sequence; untrusted text reaches
a terminal only as `TerminalSafe`, which neutralizes it.

**Coordinated Universal Time (UTC)** — the time zone of every stored and
`server-time` timestamp.

**Request for Comments (RFC)** — a numbered Internet standards document, such
as RFC 1459/2812 (IRC) or RFC 5802 (SCRAM).

**Secure Hash Algorithm (SHA)** — the hash family; SHA-256 digests identify
stored tokens, container images, and certificate files. A git **commit SHA**
is a commit's hash.

**Hash-based message authentication code (HMAC)** — a keyed hash: SCRAM
computes them, and a session's CSRF token is one.

**HMAC-based key derivation function (HKDF)** — RFC 5869's way to derive
independent keys from one secret: the CSRF token's key and the key sealing an
OpenID Connect sign-in's state cookie are each derived from the master secret
key with an info string of their own, so every process holding that key
issues and accepts the same values.

**Random number generator (RNG)** — keys, tokens, and nonces come from the
operating system's cryptographically secure one; the reconnect backoff
deliberately uses none, spreading drivers by a seed instead.

**Identifier (ID)** — a stable, machine-readable name: an account ID, a
session ID, a message ID (`msgid`).

**Operating system (OS)**, **central processing unit (CPU)**, and
**random-access memory (RAM)** — the host the daemon runs on.

**Process identifier (PID)** and **resident set size (RSS)** — a process's
number, and the memory it holds resident. The load harness reads e6ircd's RSS
through its PID and reports it per connection.

**First in, first out (FIFO) / last in, first out (LIFO)** — queue orders.
`e6irc-queue` is FIFO, and a queue that opts in serves LIFO (freshest first)
while it is overloaded.

**Multi-producer single-consumer (MPSC)** — a queue many tasks send into and
one task receives from, as `e6irc-queue` is.

---

## Edge tier

The connection-holding tier that lets the serving process be replaced without
closing a client connection (DESIGN §19).

**Edge** — a process (`e6ircd edge`, or the same code in process) that holds
client sockets and speaks the core link. It interprets nothing past framing,
holds no chat state of its own, and stores what the core writes to it. Not
the older sense of "boundary": DESIGN says boundary for that.

**Core** — the serving process (the [serving lease](#history-and-persistence)
holder) seen from the edges: everything that interprets a line.

**Core port** — `CorePort`, the edge's only way to reach the core: open a
session and receive the edge's end of its session link, hand over framed
lines, report the end. In the single process e6ircd implements it over the
core's own ingress; the core link takes its place across processes.

**Session link** — one session's two ends of the core link, as one process
carries it (`e6irc_edge::link`): the core's end (`SessionLink`), its remote
send queue and the frames the core sends the edge, and the edge's end
(`EdgeSession`), the send-queue buffer its writer drains and the reports of
what it wrote. Dropping the core's end ends the session. A **waiting
session** (bouncer attach, `/ws/ui`) is one whose core end waits for room
instead of refusing a line over the bound: backpressure, as a socket written
directly gave, never "SendQ exceeded".

**Session kind** — what a core-link session carries and where it goes: `Irc`
(IRC lines, to a core shard), `Attach` (IRC lines, to the bouncer's attach
logic), `Ui` (WebSocket messages, to the web client's live socket), and the
later `Upstream` and `Local`.

**Edge mode** and **single-process mode** — edges as separate processes
(opt-in), or the default one process with the edge in it over an in-memory
link. Both run the same code.

**Core link** — the authenticated stream between an edge and the core: TCP
carrying TLS 1.3 with mutual certificates, one stream per core shard, framed
by the `e6irc-link` codec. It carries many client sessions, never one link
per client.

**Mutual TLS** — TLS in which both ends present a certificate. Every core link
uses it, loopback included; `e6ircd edge-credentials` issues the certificates
from a deployment-private certificate authority.

**Link version** — the number of the core link's frame vocabulary a release
speaks (`e6irc_link::LINK_VERSION`). An edge offers a range in `Hello`; a
core accepts its own version and the one before it, and refuses any other
edge by naming both, so a core release never forces an edge restart but an
edge more than one release behind must be upgraded first.

**Observer role** — the `Hello` role of a read-only link from an edge to a
warm standby (below), reserved in the first link version; a core that serves
none refuses it by name rather than taking it as a serving link.

**Epoch fence** — the edge's rule that it speaks to at most one core: the one
presenting the highest serving-lease epoch the edge has accepted. A lower
epoch is refused and a higher one replaces the current link, so a core that
lost the lease cannot write to a client (the edge-side counterpart of the
database [fence](#history-and-persistence)).

**Session record** — the core-written, edge-stored, versioned description of
one client session (registration, login, capabilities, modes, paced replies
in progress and the rest the core needs to resume it). Opaque to the edge
past a small header.

**Channel replica** — the core-written copy of one channel's state (name,
creation time, topic, modes, lists, the edge's own members and their ranks),
held by every edge that hosts a member of that channel. A channel's state
therefore lives with its members.

**Upstream record** — the session record of an edge-held bouncer upstream:
the upstream nick, confirmed channels, naming rules, the reply router's
pending queue and the rest the `irc` driver needs to resume without
registering again.

**Revision** — the counter every session record and channel replica carries;
at a rebuild the highest revision of a channel's replicas wins.

**Cut** — the marker a stopping core sends every edge once it has quiesced:
"everything up to here is final". It carries the **cut state**, the small
global state no session owns (WHOWAS, the LUSERS maximum). A crash leaves no
cut.

**Rebuild** — a new core reconstructing live state from the edges' records and
replicas and from PostgreSQL, gracefully (after a cut) or after a crash; the
two are one recovery path.

**Roster** — the `core_edges` table naming every edge a core has linked, with
its slot and last epoch and cut; a new core waits for the edges it names.

**Edge slot** — the number (1 to 16,383) the core assigns an edge, forming the high
bits of every connection identifier that edge allocates, so edges allocate
identifiers without asking a core.

**Gap** — the pause between one core stopping and the next resuming its
sessions. Clients see no disconnect; their lines are buffered at the edge.

**Core-absence limit** — how long an edge holds paused clients without any
core (`edge.core_absence_limit`, 10 minutes by default) before closing them
with an explicit `ERROR`.

**Credit** — the core's grant of shard-queue room to a link stream; an edge
out of credits stops reading client sockets, which is the client's
backpressure. In one process a credit is the room a line's push awaits in the
shard's queue itself.

**Remote send queue** — the core's byte-accurate account of a session's
output that the edge has not yet written to the client socket. It holds the
"SendQ exceeded" bound and the paced replies' half-full rule across the
process boundary.

**Acknowledge after effect** — the rule for the core's input
acknowledgement: a line is acknowledged only once its effect is emitted,
recorded, or refused. A line that only accumulates core memory (an open
multiline batch, SASL chunks) is marked **retained for replay** instead, and
is replayed to the next core.

**Input of unknown fate** — lines past the acknowledgement when a core
crashes: their effect may or may not have been emitted. They are not replayed
(at most once), and the client is told how many with
`NOTE * INPUT_UNCONFIRMED`.

**Catch-up lines** — after a crash, the MODE, TOPIC or list changes a
rebuilding core sends to the members on edges whose replica lagged the highest
revision. The only server-originated output of a rebuild; a correction, never
a reset.

**Handover** (edge) — passing live sockets and their session state from an
edge to its successor on the same host, by descriptor passing or an in-place
re-execution. **Handover stop** (core) — a core stop in edge mode that
quiesces, sends the cut and releases the lease without closing a client; the
**final stop** (`e6ircd stop --final`) is the one that closes clients.

**Overlap drain** — an edge upgrade in which the old edge keeps serving its
existing connections while the new one takes new ones; the old edge exits
when its last session closes or at an operator-chosen deadline.

**Kernel TLS** — the operating-system kernel encrypting and decrypting TLS
records on a socket after userspace completed the handshake (Linux's `tls`
upper-layer protocol). A kernel-TLS socket is plaintext to userspace, so an
edge can hand it over.

**Warm standby** — a standby core holding read-only **observer links** to the
edges, receiving every record and replica as it is written, so a takeover
uploads only what changed. Edges find standbys through the **standby
registry**: a row per standby beside the serving lease, naming its
observer-link address, heartbeated and expiring as the lease is; the holder
pushes the current list to its edges.

**Directory key** — the monotonic number the core allocates each session at
`Open`, which the connection directory pages by, so a walk never misses a
connection opened on another edge. The slot-prefixed connection identifier
stays the session's wire identity and carries no order across edges.

**PROXY protocol / PROXY** — the header a TCP load balancer prepends to a
connection to pass on the client's address (version 2 is binary). An edge
listener may accept it, as the typed counterpart of X-Forwarded-For.

**Service Control Manager** — the Windows component that starts and stops
services. A service process cannot hand itself to a successor under it, so an
edge run there upgrades by overlap drain.

---

## Web security

**Content Security Policy (CSP)** — a response header naming where a page may
load scripts, styles, and connections from. Every response carries one,
limited to its own origin and the few other targets a page needs.

**HTTP Strict Transport Security (HSTS)** — a response header telling the
browser to reach the site over HTTPS only; sent whenever the public origin is
HTTPS.

**Cross-site scripting (XSS)** — injecting script into a page another user
loads. Pages escape every value, and scripts build nodes rather than markup.

**Server-side request forgery (SSRF)** — making a server send a request to an
address of the attacker's choosing, such as an internal service. The bouncer
vets every upstream address, at ingress and at dial time.

**Insecure direct object reference (IDOR)** — reaching another account's
object by naming its identifier. Every owner-scoped query carries its owner.

**Open Worldwide Application Security Project (OWASP)** — publishes the
password-storage minimums e6irc's argon2id parameters meet.

---

## Development process

**Continuous integration (CI)** — the GitHub Actions workflows
(`.github/workflows/`) that build, test, and run every guard on each push and
pull request.

**Pull request (PR)** — a proposed change on GitHub. AGENTS.md allows at most
one open at a time.

**GNU Affero General Public License (AGPL)** — e6irc's licence (version 3 or later):
anyone who runs a modified e6irc as a network service must offer its users
the modified source.

**Large language model (LLM)** — the kind of model an agent working in this
repository is; AGENTS.md's rules are written with its limits in mind.

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

**Simple Storage Service (S3)** — AWS object storage; a deployment can serve
the web client's static assets from it (behind a CDN) instead of embedding
them.

**Content delivery network (CDN)** — edge caches that serve static files
close to the browser.

**RDS** — Relational Database Service (managed databases).

**VPC** — Virtual Private Cloud, the isolated network. **ALB** / **NLB** are
the Application / Network Load Balancers; **API Gateway** is the HTTP entry
point used by scale-to-zero services.

**ACM** — AWS Certificate Manager (TLS certificates). **Route 53** is DNS;
a deployment owns the zone that names its hosts.

**Secrets Manager** — AWS's store for secrets (database URLs, OIDC client
secrets), injected into a task at runtime by its Amazon Resource Name rather
than committed.

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
