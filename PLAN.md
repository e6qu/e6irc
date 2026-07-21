# e6irc — Plan

Phases are sequential PRs/PR-groups; each phase ends with DESIGN.md/PLAN.md/
BUGS.md updated in the same PR. Details in DESIGN.md (section refs below);
term definitions in [`docs/terminology.md`](docs/terminology.md).

Status (2026-07-19): Phases 0–10 ✅ complete. Phases 11–12 (Discord/Slack
bridges) 🔶 code-complete behind feature flags with offline-unit-tested
mapping logic; live verification is gated on real credentials (neither
platform is self-hostable, so the gateway path can only be checked against
the live API). Phase 13 (scale) — the load harness is complete with real
multi-channel baselines; the 100k run is environment-blocked (needs a tuned
Linux host). The **Known remaining scope** audit below (fuller services,
admin/self REST API, CHATHISTORY subcommands, oper server-bans, ChanServ
SET options) is now fully built and tested — the only open work is the two
environment-blocked verifications above. Legend: ✅ done · 🔶 partial ·
⛔ blocked (reason).

Hardening sweep (2026-07-20): closed several bug classes across the tree —
client-triggerable memory-growth DoS on the single core worker (unbounded
`+b/+q/+e/+I` lists → MAXLIST/478, unbounded channel joins → CHANLIMIT/405,
unbounded read markers → per-account cap), secret-channel (`+s`) membership
and `+k` key disclosure via WHOIS/NAMES/WHO/MODE, `JOIN 0` and multi-target
PRIVMSG/NOTICE (TARGMAX) fidelity gaps, SASL 400-byte continuation for long
OAUTHBEARER tokens, an OIDC login-CSRF/session-fixation hole (state now
browser-bound) and a credential-verify timing oracle, and a set of silent
no-op/fallback violations in the bouncer (non-UTF-8 relay drop, slow-client
and persistence lag, feature-absent network config, DB-error masking). CR/LF
injection from bridge content is neutralized at the emit choke point, and the
three bridges now reconnect with backoff instead of dying on the first
disconnect (compile-verified; runtime still gated on live credentials).

Second hardening sweep (2026-07-20): a deeper pass closed more of the same
classes — an unbounded per-session INVITE set and unbounded per-account BNC
networks (both now capped), a `/api/v1/history` IDOR (any account could read
any channel's persisted history; now authorized against founder/channel
access), a `LIST <channels>` silent no-op (it ignored its argument), a TAGMSG
path that skipped ban/quiet enforcement, and a credential-hardening doc/code
gap (argon2 params now stated accurately behind a single `hasher()` choke
point). Fidelity: RPL_USERHOST oper `*`, RPL_MYINFO mode set, LUSERS
invisible/oper/unknown counts, casefolded multi-target dedup. Bouncer: HTTP
timeouts on all bridge/OIDC clients (a hung request no longer defeats the
reconnect design), reconnect backoff now resets after a working session, and
unmappable bridge commands are surfaced instead of silently dropped. Deferred
(surfaced, not yet done): full OIDC discovery/JWKS caching, auth-endpoint rate
limiting, `__Host-` cookie prefix, `/ws/ui` Origin check, and IRC-driver
message-tag propagation for bouncer backlog.

Third hardening sweep (2026-07-20): a pass over the less-trodden surface
(services, CHATHISTORY, config, client crates, load harness). CHATHISTORY now
FAILs INVALID_MSGREFTYPE / INVALID_PARAMS instead of returning empty batches
or silently defaulting the limit; TOPICLEN/KICKLEN/AWAYLEN and WHOX/KICK:1 are
advertised and the length limits enforced. A labeled-response `label` is now
re-escaped before echo (it could inject a newline into the client's own
stream); OIDC-provisioned account names are sanitized; config rejects
`command_burst=0` / `max_hot_channels=0`. Implemented two of the deferred
items: an OIDC discovery/JWKS TTL cache and a `/ws/ui` Origin check. Bouncer/
clients: the BNC listener gained the per-IP cap + handshake timeout the IRC
listener has, the IRC driver gained the connect/register timeout its Matrix
sibling had, the load harness no longer deadlocks on a pre-barrier client
failure, and the CLI/TUI surface JOIN-refusal / disconnected-send instead of
hanging or silently dropping. Boy-scout: `route_command` collapsed to one
`route_privmsg` choke point across all three bridges. Still deferred:
auth-endpoint rate limiting (needs trusted-proxy config), `__Host-` cookie
prefix, `logout_sso` GET-CSRF, and IRC-driver message-tag propagation.

Fourth hardening sweep (2026-07-20): aimed at the least-audited surface (the
web client, migrations, the persistence layer). Persistence: three tables
grew without bound — `device_grants` (unauthenticated `/device/start` floods),
`bnc_buffer` (per upstream line, also orphaned on network delete), and
`web_sessions` (expired rows) — all now pruned/capped, with a supporting
index migration. Fidelity: `MAXLIST=bqeI:100` is now enforced as a *combined*
total (was per-list ≈400); a labeled-response wrapping a CHATHISTORY batch no
longer emits a double `batch` tag; MONITOR reports the subset accepted before
the cap. Web/HTTP: the clickjacking/MIME/referrer headers the auth pages set
are now also on the app and account pages; OpenAPI documents the OIDC
`/start` and `/callback` routes; the status fragment takes an enum; and
`logout_sso` (GET) now requires the session CSRF token — clearing that
deferred item. Still deferred: auth-endpoint rate limiting (trusted-proxy
config), `__Host-` cookie prefix, IRC-driver message-tag propagation (a
3-part change touching the shared client), and the CHATHISTORY whole-second
pagination gap (needs millisecond ts). The XSS/injection surface of the web
client and the SQL/index/constraint layer were audited and found sound.

Fifth hardening sweep (2026-07-20): closed every remaining deferred item from
the four prior sweeps, plus a fresh pass. (1) IRC-driver message-tag
propagation: the `irc` driver renders upstream tags into buffered/live lines,
and `attach` filters each tag family against the attaching client's negotiated
caps (`server-time`/`message-tags`/`account-tag`) so no un-negotiated tag
reaches a client; the shared client crate requests those caps. (2) CHATHISTORY
same-second pagination: rather than widen the clock, the DB fallback now pages
on the composite `(ts, id)` key relative to the pivot row, so messages sharing
a whole second are ordered definitively by the unique id (new `*Msgid`
`HistoryQuery` variants + query arms). (3) `__Host-` cookie prefix: session and
OIDC-state cookies use `__Host-` when secure, threaded through every read/set/
clear site so the name is consistent (a mismatch would silently fail to clear).
(4) Auth-endpoint rate limiting: a token-bucket per client IP on
`create_app_password`/`oidc_start`/`oidc_sso_start`, with a `trusted_proxies`
CIDR list + rightmost-untrusted `X-Forwarded-For` resolution so a direct client
cannot spoof its IP (off unless `auth_rate_burst` is set). Fresh findings:
WHOIS `RPL_WHOISIDLE` (317) and WHOX `l` now report real idle/signon times
(tracked per session); ban/quiet/except/invite masks are canonicalized to
`nick!user@host` before storage so `+b nick` and `+b nick!*@*` can't desync;
several bridge state mutations were reordered to try_push before mutating hot
state; and the Matrix/Discord own-echo suppression now fails loud on a missing
self-id instead of silently looping our own posts back. Docs: DESIGN §8 storage
schema was corrected to the real migrations (no `tags` column, `bnc_buffer`
shape, `read_markers`, partitions marked as planned), and stale "once X lands"
comments were removed now that OIDC and the `local` driver have landed.

Sixth hardening sweep (2026-07-21): added dead-code and copy-paste detection
to CI and the local checklist, then a fresh fidelity/bug pass. Tooling:
`tools/check-dead-code.sh` compiles only the shipped artifacts (`--lib --bins`,
no `--all-targets`) with `-D warnings`, so code kept alive solely by tests is
caught as dead — test coverage can no longer mask it; `tools/check-duplication.sh`
runs jscpd over the crate sources with a ratchet threshold. Both are wired into
the `lint` job. Boy-scout de-duplication reduced production copy-paste from
3.75% to 2.3%: the client's three SASL registration paths now share `recv`/
`negotiate_sasl_cap`/`await_authenticate_challenge`/`finish_sasl_then_welcome`
helpers, and every always-on bridge driver's reconnect backoff is one shared
`Backoff` type. Bug fixes: (HIGH) a re-created channel (dropped when it emptied)
was marked history-complete, hiding all PostgreSQL-persisted history from
CHATHISTORY — a fresh ring is now complete only when no database backs it;
(HIGH) channel MODE applied earlier modes then `return`ed on a later arg-less
mode, silently mutating state without a broadcast — it now `break`s so the
applied modes are announced; (MEDIUM) the read-marker mirror is seeded from
PostgreSQL at boot (it started empty after a restart, so MARKREAD reported `*`
and a stale set could move a marker backwards); (MEDIUM) a labeled CHATHISTORY
that falls back to PostgreSQL now carries the label onto its deferred batch and
no longer ACKs the command as empty; (MEDIUM) the `/ws/ui` render socket now
subscribes before snapshotting the buffer (it dropped live lines in the gap)
and surfaces a lagged gap instead of swallowing it; IRC-over-WebSocket now
enforces the same per-IP connection cap as the raw listeners; the web composer
path is framed like every other client→upstream path (no CRLF injection);
CHATHISTORY replays a canonical uppercase verb from both ring and DB; and
RPL_WHOISCHANNELS is split across 512-byte lines like RPL_NAMREPLY.

Seventh hardening sweep (2026-07-21): strengthened dead-code detection to the
one case the compiler cannot see, then a fresh fidelity/bug pass. Tooling:
`tools/check-dead-code.sh` (compiler-based) catches private and `pub(crate)`
items only tests keep alive, but rustc treats a lib's fully-`pub` items as
reachable API, so a `pub` item referenced only by an integration test (a
separate crate) was still invisible. `tools/check-dead-pub.sh` closes that:
it flags any `pub` fn/type/const/… in shipped source referenced nowhere else in
shipped source, with an explicit `// dead-pub-allow:` escape hatch; wired into
CI and the checklist. It immediately found three dead protocol-limit constants
(`MAX_LINE_LEN`/`MAX_SERVER_TAGS_LEN`/`MAX_CLIENT_TAGS_LEN`), now wired live as
the single source of truth for the framing caps that were duplicated as the
magic `4096 + 510` across five sites — which also fixed a latent gap where the
client rejected valid large server-tag lines. Bug fixes from an adversarial
re-audit: (MEDIUM) SASL registration hung forever on a post-auth
registration-refusal numeric (e.g. `433` when the requested nick is taken) —
the shared welcome path now treats those as terminal in both loops; (MEDIUM)
a labeled `CHATHISTORY TARGETS` that resolved via PostgreSQL lost its label and
double-responded (empty ACK + unlabeled batch) — the label is threaded through
`QueryTargets`/`TargetsPage` exactly as the earlier `HistoryPage` fix; a
`network_name` containing a space (which would split the ISUPPORT `NETWORK=`
token) is now rejected at config load; a banned or quieted external sender can
no longer speak to a `-n` channel (bans/quiets/moderation are checked for
non-members too, PRIVMSG and TAGMSG); `MODE +k` on an already-keyed channel
replies `467 ERR_KEYSET` instead of silently overwriting; the `/ws/ui` socket
sends the current connection status on attach (the sticky flag was unused); the
`hot_channels` LRU no longer keeps stale keys for destroyed channels (a shared
`remove_channel` drops both maps together); and the ws-irc inbound loop breaks
the connection directly when the core is gone.

Eighth hardening sweep (2026-07-21): an adversarial pass over the surfaces the
prior sweeps under-examined — the client binaries, less-common IRC commands,
and the queue. The `e6irc-queue` MPSC and the ISUPPORT-vs-enforcement mapping
audited clean. Fixes: (HIGH) the CLI silently registered *unauthenticated* when
only one of `--account`/`--password` was given — now a loud error; (MEDIUM) the
CLI `history` subcommand hung forever if the server NAK'd the required caps — it
now fails loudly on NAK, answers PINGs while waiting, and errors on a
mid-negotiation close; (MEDIUM) CLI `tail` on a refused JOIN hung silently — now
reported like `send`/`history`; (MEDIUM) a `TOPIC` query on a `+s` channel
leaked the topic (and the channel's existence) to non-members — it now returns
`ERR_NOTONCHANNEL` like every other query surface; (MEDIUM) NICK and QUIT were
the only membership broadcasts hand-rolling a raw byte loop, so they omitted the
`server-time` tag for capable clients — both now route through `send_timed`;
(LOW) the services pseudo-client nicks (`nickserv`/`chanserv`) were not
reserved, so a user could seize one and intercept its PRIVMSGs — one
`SERVICE_NICKS` list now backs both the intercept and the NICK reservation;
`MONITOR +` at the list cap reported only the first over-limit nick and silently
dropped the rest of the batch — it now reports them all; and `set_read_marker`
was a silent no-op when the account name didn't resolve — it now surfaces an
`UnknownAccount` error the worker logs. Not changed, with reasons: the
`bnc_buffer` orphan-on-account-deletion is unreachable (no account-deletion path
exists, and `owner` is `TEXT` for the `*` shared-network sentinel, so a FK
doesn't fit); signal handling / task supervision remains an explicit, logged
deferral.

Ninth sweep — adversarial security (2026-07-21): two adversarial security
audits (auth/session/crypto and injection/access/DoS/isolation). Structurally
the daemon held up well — no SQL injection, stored XSS, IDOR, cross-account BNC
leak, open redirect, or TLS weakness; secrets (ChaCha20-Poly1305 sealing),
sessions (`__Host-`/HttpOnly/SHA-256-hashed tokens), CSRF (HMAC, constant-time),
OIDC (PKCE + constant-time state, single-key back-channel-logout verification
with replay protection), and admin authz were all found sound. Fixes: (HIGH,
H2) the event-driven core had no timer, so a slowloris (open a socket, send
nothing) held a Session forever and dead sockets were never reaped — added an
`Input::Tick` reaper: unregistered connections are closed after a 30s
registration deadline, and idle registered clients are PINGed (120s) then closed
if they don't PONG (60s), with any client line counting as liveness. (HIGH, H1)
the bridge drivers built an IRC source prefix straight from hostile-upstream
sender names, so a malicious homeserver/username could forge a NOTICE/PRIVMSG
from any nick on the attached client's stream — a shared `nick_token` now
reduces the sender to a safe nick token (no space/`!@:`/control) at each bridge
boundary. (MEDIUM) SASL verification is now capped at 8 attempts per connection
(always on) so a single socket can't drive unbounded argon2 work (online
brute-force / CPU DoS). (MEDIUM) MODE now hides a `+s` channel from non-members
(its mode string, creation time, and `+b`/`+q` mask lists were disclosed —
the same secret-channel gate the other query surfaces already apply, extended
after the sweep-8 TOPIC fix). (MEDIUM) a quieted/banned member can no longer set
the channel TOPIC (topic-defacement quiet-evasion). (LOW) the oper-password and
`+k` channel-key comparisons are now length-safe constant-time (digest-then-
compare); `verify_credentials` no longer short-circuits its multi-credential
check (match-position timing); a quieted member's PART reason is suppressed; and
every HTTP response (including the JSON/problem+json paths) now carries
`X-Content-Type-Options: nosniff`.

## Phase 0 — Scaffolding ✅ (2026-07-18)
- Cargo workspace, crate skeletons, LICENSE (AGPL-3.0-or-later), CI
  (fmt, clippy, test, cargo-deny licenses/advisories, binary-size report,
  full build/test matrix: Linux, macOS, Windows × amd64, arm64).
- `e6irc-proto`: message model, zero-copy parser/serializer, rfc1459
  casemapping, numerics/ISUPPORT tables, fuzz targets. (DESIGN §7.1)
- `e6irc-queue`: custom bounded MPSC queue — seq-numbered envelopes,
  try_push/async pop, adaptive FIFO/LIFO, loom verification. (DESIGN §7.3)
- Release publishing completed with native amd64/arm64 container builds,
  immutable 12-character commit-SHA tags, direct architecture manifests, an
  exact two-platform generic manifest, and retention of the newest 20 release
  groups. CAP/SASL state machines landed in Phase 2. Queue step-scheduler and
  trace hooks remained planned for the deterministic simulation work that used
  them.

## Phase 1 — Core ircd ✅ (2026-07-18)
- Listeners (plain+TLS via rustls), connection lifecycle, bounded SendQ
  with slow-client kill, async-backpressure core queue, registration
  burst, NICK/USER/PING/QUIT/JOIN/PART/PRIVMSG/NOTICE/TOPIC/NAMES/WHO/
  WHOIS/MODE(imnstkl+bov) core, single core worker (degenerate N=1 of
  the sharded design), serialize-once fan-out via Bytes, TOML config
  with unknown-key rejection, e2e socket tests incl. TLS handshake.
  (DESIGN §7.2–7.3)
- Deferred: WHOX (Phase 3 with the compat harness), queue
  step-scheduler/trace hooks (first deterministic-sim phase that needs
  them), rDNS/ident (decide with oper tooling). (The PING liveness reaper +
  registration deadline landed in the ninth, security, sweep; the
  per-session flood throttle landed with CAP.)

## Phase 2 — IRCv3 + persistence + accounts ✅ (2026-07-18)
- CAP 302 (LS/LIST/REQ/END, registration gating), server-time,
  echo-message, message-tags + TAGMSG, cap-notify, SASL PLAIN
  (DB-decoupled core machinery; sasl advertised only when a database is
  configured).
- Postgres via sqlx (runtime queries, embedded migrations 0001/0002),
  accounts + argon2id credentials, DB worker on the queue architecture,
  NickServ REGISTER/IDENTIFY/HELP, ChanServ REGISTER (founder
  ownership), WHOIS 330. PG integration tests in CI service container.
  (DESIGN §7.6, §8, §9.1, §9.3)
- Deferred: remaining §7.5 caps (account-tag/account-notify/away-notify/
  extended-join/batch/labeled-response/monitor → Phase 3 with the compat
  harness), app passwords + PATs (Phase 4 with the web UI that manages
  them), fuller ChanServ (FLAGS/OP/topic retention → Phase 5 with
  persistence of channel state), enforced nick ownership (SASL-required
  mode / nick protection policy decision).

## Phase 3 — Libera compat contract ✅ (2026-07-19)
Done:
- Vendored Libera greeting snapshot (CAP LS 302 + 005, provenance +
  checksum, in vendor/tests/libera-snapshot/) with an offline
  differential ISUPPORT test — shared tokens must match, whitelist
  requires written reasons (currently: CHANMODES). Read from the source
  tree at test time (never embedded in a shipped binary).
- Light-touch LIVE interop tests (crates/e6ircd/tests/live_compat.rs,
  opt-in/#[ignore]): our client connects over TLS to Libera, OFTC, and
  Ergo, registers, and parses their greeting — verified passing against
  all three. Independent implementation; no reference ircd is a build or
  CI dependency.
- Hostmask matcher; +q/+e/+I lists; JOIN admission enforcement
  (+i/+b/+k/+l with invex/exceptions) and quiet/ban speech blocking;
  WHOX; UTF8ONLY; NAMES secret symbol; LUSERS high-water mark;
  FAIL source prefixes; empty-realname rejection.
- irctest wired: controller (vendor/tests/irctest/), pinned commit,
  green list in CI with the standard marker filter.
- Optional Solanum differential oracle (vendor/tests/external-oracles/):
  builds from a pinned commit in Docker + a diff_sessions.py runner — a
  developer cross-check tool, not a build/CI dependency.
- MONITOR, batch, WHOWAS, TIME, INFO, WHOIS target-server form,
  channel-key validation all landed with irctest coverage (24 files
  green in CI).
- Oper subsystem (OPER + config [[oper]] + constant-time auth), umodes
  +o/+i, WHO mask/star matching + oper/away flags — oper/info/who/whois
  irctest green (~30 files total in CI).
- labeled-response cap landed (13/13 irctest); command parser relaxed
  for lenient 421 handling.
Out of scope (compatibility achieved; exact per-network parity is not the
goal):
- Exact CHANMODES-token parity with Libera (their `f`/`j` and full type-D
  set) is deliberately not pursued — the differential ISUPPORT test
  whitelists CHANMODES with a written reason because it encodes one
  network's policy, not the interop contract. Our common channel modes
  (+i/+m/+n/+s/+t/+C/+k/+l/+b/+q/+e/+I) are irctest-green and
  live-verified against Libera/OFTC/Ergo.
- chghost cap: ✅ now advertised. The oper SETHOST command (§5 below) is
  the host-change trigger it needed — changing a user's host broadcasts
  CHGHOST to chghost-capable peers. (DESIGN §7.7, §17)

## Phase 4 — HTTP layer: OIDC + REST API ✅ (2026-07-19)
Done:
- axum in-process on optional [http] listener; problem+json errors;
  /healthz, /api/v1/server; app-password issuance (password exchange,
  argon2id at rest, works for SASL immediately).
- OIDC code+PKCE multi-provider login: discovery, CSRF state + nonce,
  ID-token validation, account auto-provisioning on (issuer, subject),
  hashed opaque web sessions, cookie auth, /api/v1/me, idempotent
  logout. Integration-tested against dockerized dex (mock connector)
  in CI.
- PATs (single-choke-point auth), /api/v1/history, ws-irc endpoint
  (IRCv3-over-WebSocket, e2e-tested).
- OAUTHBEARER SASL: clients authenticate with an API token (RFC 7628
  payload) via the same DB-verified path as PLAIN; advertised in CAP LS
  and RPL_SASLMECHS. Client lib `register_oauthbearer`; PG-gated e2e
  (valid token -> 330, bogus token refused).
- OAUTHBEARER device flow: RFC 8628 device grant brokered by e6ircd —
  start/approve/token endpoints, PG-gated e2e; the minted token drives
  SASL OAUTHBEARER.
- Credential-management endpoints (app-password list/revoke), login page
  (askama). Admin API: config [http].admin_accounts gate + GET
  /api/v1/admin/accounts, 401/403/200 tested. Composer slash-commands:
  /me //join //part //nick //topic //msg //raw on /ws/ui. OpenAPI:
  hand-authored 3.1 spec at GET /api/v1/openapi.json covering every route
  + bearer security.
- Rate limiting: per-IP concurrent-connection cap
  ([limits].max_connections_per_ip, refused at accept) and per-session
  command-flood token bucket ([limits].command_burst, PING/PONG + oper
  exempt, closes on Excess Flood) — both opt-in/off by default.
  (DESIGN §9, §12, §15)
- **Brokered SSO (Shauth/Ory Hydra)**: any configured OIDC provider works
  as an external SSO source. Beyond code+PKCE login, e6irc now does
  **silent `prompt=none`** re-auth (`GET …/oidc/{provider}/sso`) so an
  existing provider SSO session logs the user in with no prompt — and
  `login_required` bounces to `/?sso=none` with no redirect loop — and
  **RP-initiated logout** (`GET /api/v1/auth/logout`) that clears the local
  session then redirects to the provider's `end_session_endpoint` with
  `id_token_hint` + `post_logout_redirect_uri`, ending the upstream SSO
  session too (the id token + provider are stored per session, migration
  0019). Provider config gains optional `scopes` + `end_session_endpoint`.
  Migration 0020 retained issuer/subject/session-ID correlation and consumed
  logout token IDs. Signed OpenID Connect back-channel logout at
  `POST /api/v1/auth/oidc/backchannel-logout` and front-channel logout at
  `GET /api/v1/auth/oidc/frontchannel-logout?iss=…&sid=…` revoked the matching
  durable sessions, including sessions on other devices, while rejecting
  signature, claim, audience, issuer, time-window, and replay failures.
  The application root itself became fail-closed: unauthenticated direct and
  catalog entry used a silent Shauth probe, a valid upstream session entered
  without another prompt, and a negative probe reached interactive login
  without looping. User-facing logout used top-level RP-initiated navigation,
  returned through the e6irc public URL, and refused incomplete provider or
  storage state without deleting the local session.
  Verified end-to-end against dockerized dex + PostgreSQL.

## Phase 5 — History + multiplexer + local always-on ✅ (2026-07-19)
Multiplexer core: network drivers are **always-on** (broadcast events,
run with zero clients attached), support **multi-client attach**
(`bouncer::attach` replays the detached buffer then bidirectionally
relays), over any AsyncRead+AsyncWrite. Per-user network registry +
`user/network` routing done (Phase 6). The **`local` driver** (kind=local
in [[network]]) is an in-process client of this e6ircd's own core via the
CoreHandles + queue — gives a BNC user always-on presence + backlog on
the local network with no external socket. PG-gated e2e: attaching to a
local network relays the core's in-process channel traffic.

### Earlier Phase 5 work
Done:
- messages store (single BRIN-indexed table; monthly partitions
  explicitly deferred to Phase 13), per-message msgids, batched
  UNNEST write pipeline in the DB worker (flush on queue drain),
  channel PRIVMSG/NOTICE persisted; PG-gated e2e coverage.
- msgid on live delivery incl. TAGMSG + client-tag relay + tag length
  budgets.
- Per-channel hot ring (500) + CHATHISTORY LATEST/BEFORE/AFTER with
  batch framing; async PostgreSQL paging past the ring through the DB
  worker (full fidelity). MONITOR with online/offline notifications.
Done (this phase's remaining, now landed):
- REST /api/v1/history endpoint (same query layer), session multiplexer,
  `local` driver, multi-client attach, playback, and read-marker
  (draft/read-marker cap + MARKREAD, persisted to the `read_markers`
  table with a GREATEST upsert).
Deliberately deferred:
- PM (user-to-user) history logging. Only channel PRIVMSG/NOTICE is
  persisted; direct messages are delivered but not written to server-side
  history. This is a privacy policy decision, not a missing mechanism —
  it stays off until there is an explicit opt-in policy. (DESIGN §10.1–
  10.2, §11)

## Phase 6 — BNC external networks ✅ (2026-07-19)
Done:
- `irc` driver (`bouncer::IrcNetwork`): persistent upstream IRCv3
  connection reusing e6irc-client (plain/TLS), auto-join, transparent
  PING, event/command channels, bounded detached buffer, exponential-
  backoff reconnect. e2e-tested against e6ircd-as-upstream
  (register/relay/buffer/command, reconnect-after-drop).
- Scale: hot history rings made lazy + LRU-evictable (max_hot_channels,
  default 8192) so RAM is bounded by activity at the ~100k-channel /
  ~1k-BNC-session target (user-confirmed 2026-07-19).
- Registry + [bnc] listener + `user/network` routing: bnc_serve does
  the client registration handshake (incl. full CAP negotiation),
  selects the network, and attaches. e2e-tested (client on the BNC port
  exchanges messages both ways with a peer on the real upstream).
- BNC client authentication: attaching clients must authenticate with
  SASL PLAIN against the account store (reusing db::verify_credentials —
  account or app password) before any attach; unauthenticated or
  wrong-password attempts are refused (904 / connection close, no silent
  pass-through). `[bnc]` now requires `[database]` (enforced in
  validate). PG-gated e2e: authenticated route + rejection cases.
- Upstream SASL: the driver authenticates to a SASL-requiring upstream
  (NetworkConfig.sasl); e2e-tested (driver logs into a Postgres-backed
  e6ircd, observer WHOIS confirms 330). Found+fixed a real
  register_sasl bug (completed on 001 before the async SASL verdict).
- Encrypted credential store: config secrets may be sealed
  (`enc:v1:<base64>`, ChaCha20-Poly1305 via in-tree aws-lc-rs) and
  decrypted at load with a key kept outside the config
  (`[secrets].key_file` or `E6IRC_SECRET_KEY`). `e6ircd genkey` /
  `e6ircd seal` are the operator tools; a sealed value with no/wrong key
  is a hard startup error (no silent fallback). Unit + CLI e2e tests.
  Upstream sasl_password is the first adopter; oper/oidc secrets can
  reuse open_secret next.
- Per-account network ownership: each [[network]] may set an `owner`
  account (absent = shared). The registry keys drivers by (owner, name)
  and resolves an attach to the authenticated account's own network of
  that name, else a shared one — a network owned by a different account
  is invisible (PG-gated cross-account denial test). Config validation
  rejects ambiguous names (dup (owner,name); a name both shared and
  owned). This is the ownership/isolation invariant; DB-backed
  self-service creation reuses the same (owner, name) registry.
- Per-user networks (self-service): the bnc_networks table stores each
  account's networks (upstream password sealed); the registry is mutable
  at runtime and boot-loads all persisted networks as always-on drivers.
  REST manages them — POST/GET/DELETE /api/v1/me/networks (authenticated,
  owner-scoped); creating with an upstream password seals it (409 if no
  master key — never stored in the clear) and starts the driver
  immediately. `[bnc]` no longer needs a config [[network]]. PG-gated
  e2e: create-via-REST → attach-via-BNC → delete lifecycle, plus the
  no-key refusal.
- Per-network buffer PG spill: upstream lines are persisted (bnc_buffer
  table, keyed (owner, network)); each driver restores its recent backlog
  (preload_front, capacity-bounded, oldest-first) on start via a
  persistence task that subscribes then persists new lines. A client
  attaching after a restart replays pre-restart backlog. PG-gated e2e:
  persist a peer's line, restart with a dead upstream, confirm replay.
Done (this phase's remaining, now landed / superseded):
- The `local` in-process driver landed (see Phase 5, kind=local).
- The "integration tests vs. dockerized Solanum" item is obsolete: per
  the independent-implementation directive, no reference ircd is a build
  or CI dependency. Cross-server compatibility is covered instead by the
  light-touch live-interop tests (Libera/OFTC/Ergo, opt-in) and the
  optional developer-only Solanum oracle under vendor/tests/. (DESIGN
  §10.3–10.4, §15)

## Phase 7 — Web client ✅ (2026-07-19)
Done:
- Serving foundation (DESIGN §13.3): `embed-web` cargo feature (now via
  rust-embed over web/dist) bakes the built client into the binary,
  serving `/` + `/assets/*` (hashed assets → immutable cache; index →
  no-cache); without it only the API + WebSocket paths serve (assets on
  S3/CDN). Oppositely-gated e2e (index + hashed asset served with feature,
  404 without).
Done (this phase's remaining, now landed):
- `/ws/ui` live path (DESIGN §13.2): cookie/bearer WebSocket attaching
  over the multiplexer path; pushes upstream lines as `hx-swap-oob` HTML
  fragments and relays composer input. The htmx composer JSON
  ({target, message}) becomes PRIVMSG (`/raw ` sends literally); raw
  frames pass through. Buffer snapshot replayed on attach; connected/
  disconnected status fragments. e2e (crates/e6ircd/tests/ws_ui.rs:
  authed attach + relay both ways, unauthenticated refused) + composer
  unit tests.
- Vite frontend (`web/`): htmx 2.0.10 + htmx-ext-ws 2.0.4 (both 0BSD,
  provenance in web/VENDOR.md + pnpm-lock), chat shell (index.html +
  main.js + style.css, theme-aware) that connects `/ws/ui`, applies the
  server's OOB fragments, and sends the composer form. `pnpm build` →
  web/dist, embedded by rust-embed under `embed-web`.
- The production container built the pinned pnpm/Vite frontend and compiled
  e6ircd with `embed-web`, so the deployable image contained the complete UI
  and performed no build work at startup. The chat shell exposed the signed-in
  account, account section, and global Sign out navigation in both themes.
- Coordinated and local browser logout returned to the public, reload-safe
  `/auth/signed-out` page instead of the application root. The branded,
  accessible light/dark page exposed the explicit Shauth OIDC starter, and
  real-browser coverage exercised catalog launch, direct silent SSO, logout
  landing reload, and application-local sign-in recovery.
- askama server-rendered pages (DESIGN §13.1): `/login` (OIDC provider
  buttons) and `/account` (cookie-authed user section listing the
  account's networks + credentials; redirects to /login when
  unauthenticated). Read-only for now; DB errors fail loudly.
- Account-page mutations: htmx add-network form + per-row delete
  buttons hit /account/networks (fragment endpoints returning the
  refreshed table), guarded by an HMAC(csrf_key, session) CSRF token
  (X-CSRF-Token header; constant-time verify; missing/bad -> 403). The
  JSON create path was refactored to a shared create_network_core. htmx
  served standalone at /htmx.min.js (copied into dist by the build) for
  the askama pages. Composer slash-commands DONE (see Phase 4). (DESIGN
  §13)

## Phase 8 — Native clients ✅ (2026-07-19)
Done:
- `e6irc-client` lib (tokio connection, proto framing, owned messages,
  PING-answering register + SASL PLAIN); `e6irc-cli` with
  send/tail/raw subcommands and --account/--password SASL, e2e-tested
  against a real e6ircd (plain + SASL); `e6irc-tui` (ratatui,
  terminal-independent App state unit-tested).
- OAUTHBEARER device-flow login (server broker, Phase 4). TUI
  multi-buffer: one buffer per channel/query, Alt-←/→ switch,
  `/join`/`/win`, per-buffer scrollback (PgUp/PgDn), message routing
  (channel/PM), buffer bar. (True multi-*server* is the BNC's job — a
  client attaches to one network; cross-server-in-one-TUI would need a
  multi-connection loop + config.)
- Client TLS, `e6irc history`, SASL PLAIN, SASL OAUTHBEARER, and the
  `e6irc api` subcommand — one authenticated REST request over plain
  HTTP, bearer token or E6IRC_API_TOKEN — all landed. (DESIGN §14)

## Phase 9 — Bridge SPI ✅ (2026-07-19)
- `NetworkDriver` trait (kind + `start(self: Box<Self>) -> NetworkHandle`)
  is the pluggable driver SPI; the `irc` driver is now `IrcDriver`
  implementing it, and the Registry stores `Box<dyn NetworkDriver>` so
  bridges drop in behind feature flags. `NetworkHandle::channels()` +
  `DriverEnds` (emit_line / emit / next_command) are the shared plumbing
  a driver author uses — the irc driver was refactored onto them, so
  there is one way to build a handle.
- `LoopbackDriver` reference driver (echoes commands as lines) + an SPI
  conformance test kit exercising the contract and the shared `attach`
  path with no external service. Matrix/Discord/Slack (Phases 10-12)
  implement this trait, each behind its own feature flag. (DESIGN §10.5)

## Phase 10 — Matrix bridge ✅ (2026-07-19)
- `matrix` NetworkDriver (behind the `matrix` feature; reqwest confined to
  it): logs into a homeserver (C-S API password login), joins configured
  rooms, and bridges `m.room.message`(m.text) ⇄ IRC PRIVMSG both ways
  (room alias `#name:server` ⇄ channel `#name`; sender `@u:server` ⇄ nick
  `u`; own echoes + non-text dropped). Config: `kind=matrix` [[network]]
  (addr=homeserver, nick=user, sasl_password=password, autojoin=rooms).
  Live integration test vs. a pinned Conduit homeserver
  (vendor/tests/external-oracles/conduit/): both directions verified.
  Unit tests for the mapping/urlencode.
## Phase 11 — Discord bridge 🔶 code-complete; live-verification-gated (2026-07-19)
`discord` NetworkDriver (behind the `discord` feature): connects to the
Discord gateway (WebSocket), IDENTIFYs with a bot token, keeps the
heartbeat, and bridges `MESSAGE_CREATE` events ⇄ IRC PRIVMSG (each
configured channel id → `#name` via a one-time REST lookup; author
username ⇄ nick; the bot's own messages dropped). The reverse direction
posts via the REST API. Config: `kind=discord` [[network]]
(`sasl_password` = bot token, `autojoin` = channel ids, `addr` = optional
API base). The pure parse/map/route logic is unit-tested offline.

**Not verified against live Discord.** There is no self-hostable Discord
server (Spacebar, the only reimplementation, SIGSEGVs on its current
image — tested 2026-07-19), so the gateway/REST path can only be verified
against the live API, which needs a real bot token + a guild. That live
integration test is the remaining step; it is gated on credentials, not
run in CI. (DESIGN §10.5)

## Phase 12 — Slack bridge 🔶 code-complete; live-verification-gated (2026-07-19)
`slack` NetworkDriver (behind the `slack` feature): opens a Socket Mode
WebSocket with the app-level token, ACKs each event envelope, and bridges
channel `message` events ⇄ IRC PRIVMSG (channel id → `#name` via
`conversations.info`; `user` ⇄ nick; bot messages dropped to avoid echo
loops). The reverse direction posts via `chat.postMessage`. Config:
`kind=slack` [[network]] (`sasl_account` = bot token, `sasl_password` =
app-level token, `autojoin` = channel ids). Parse/map/route unit-tested
offline.

**Not verified against live Slack.** Slack is not self-hostable; the
faithful oracle is the live Web/Socket-Mode API, needing a real workspace
+ app. That live integration test is the remaining step, gated on
credentials. (DESIGN §10.5)

## Phase 13 — Scale hardening 🔶 harness complete; 100k run environment-blocked (2026-07-19)
Done:
- Load-test harness (`crates/e6irc-load`, `e6irc-load` binary): opens N
  concurrent clients over the real e6irc-client, times connect+register+
  join throughput, measures channel fan-out (one sender bursts, every
  other client counts deliveries), and reports true end-to-end delivery
  **latency percentiles** (p50/p90/p99/max, per-message send-stamped).
  `--tls` supported. `tools/load/` has a README (methodology + OS tuning
  for the 100k target) and `sweep.sh` (walks client counts). Verified
  across 50-2000 clients with correct fan-out accounting.
- `--channels C` spreads clients across many channels. A single giant
  channel makes the join phase O(N²) (each join broadcasts a NAMES list
  of all members), which is a measurement artifact, not the server's real
  behaviour — a real deployment has many channels. Same 2000 clients,
  release, macOS: 1 channel gave 290 connects/s + 59k msg/s at 131 ms
  p50; 200 channels gave 6042 connects/s + 122k msg/s at 37 ms p50.
  Numbers recorded in tools/load/README.md.
Remaining (environment-blocked, not code-blocked):
- The 100k-connection run itself needs a tuned Linux host (fd limits,
  ephemeral-port range, socket buffers — macOS caps loopback hard). The
  harness is the instrument; the run is a hosting task.
- Fan-out/latency **target** numbers, timer wheels, and the per-connection
  memory budget follow from that run. The residual latency the harness
  already shows at scale is the single core worker (N=1 of the sharded
  design) serializing every channel's fan-out — core sharding is the open
  hardening item. (DESIGN §7.3, §17)

## Known remaining scope (audit 2026-07-19)

A completeness audit against DESIGN.md surfaced documented-but-unbuilt
surface that the ✅ phase markers above do **not** cover. Recorded here
honestly rather than left implied. All of it fails loudly today (returns
an error / 404 / `FAIL`), so none of it is a silent no-op — it is simply
not built yet. Ranked by value:

1. **ChanServ founder ownership + topic retention** — ✅ DONE
   (2026-07-19). The core keeps a hot channel-ownership map
   (`registered_founders`) and a retained-topic map (`registered_topics`),
   both boot-loaded from the `channels` table (`list_registered_channels`
   / `list_channel_topics`, migration 0010 adds the topic columns).
   `join_one` re-ops the registered founder even when not first to arrive,
   and restores a registered channel's topic when it is recreated after
   going empty; TOPIC on a registered channel persists the change
   (`SetChannelTopic`). Covered by four core tests + PG-gated
   `channel_topic_persist_and_load`.
2. **Fuller NickServ/ChanServ command surface** (DESIGN §7.6) — partial.
   Implemented: NickServ REGISTER/IDENTIFY/**GHOST**/HELP; ChanServ
   REGISTER/**DROP**/**FLAGS**/HELP. GHOST disconnects a stale session on a
   nick you own; DROP unregisters a founded channel (clearing the hot
   founder/topic/access maps + row); FLAGS lists and (founder-only) sets
   per-account access flags in the `channel_access` table (migration 0011),
   boot-loaded into a hot map, driving **auto-op/auto-voice on join**.
   ChanServ **OP** (op yourself or a
   member you have op access over) is also implemented. ChanServ **SET** now
   covers **FOUNDER** (ownership transfer, verified against the DB),
   **KEEPTOPIC** (on/off toggle of topic retention, migration 0017; off drops
   the retained topic so it is no longer persisted or restored), and
   **MLOCK** (boolean mode lock `+nt-i`, migration 0018; boot-loaded into a
   hot map, applied when a registered channel is (re)created, and enforced
   on MODE so a locked mode can't be changed the wrong way). **GUARD** is
   answered explicitly as unnecessary — a registered channel already retains
   its founder, access, topic, and mode lock across empty periods in
   persistent state, so ChanServ need not hold it open; it is declined with
   that reason, never silently accepted. This completes the ChanServ SET
   surface; unknown options are still rejected loudly.
3. **CHATHISTORY subcommands** — ✅ DONE (2026-07-19). The full draft
   surface is now implemented (DESIGN §11.2): `LATEST`/`BEFORE`/`AFTER`,
   plus `TARGETS` (buffer enumeration, `draft/chathistory-targets` batch),
   `AROUND` (up to `limit` messages centred on a selector, ~half each
   side), and `BETWEEN` (messages strictly between two selectors). All page
   the hot ring first and fall through to PostgreSQL
   (`db::query_history`/`query_targets`) past the ring. Covered by core
   ring tests (AROUND, BETWEEN, TARGETS) and PG-gated tests
   (`query_history_around_and_between`, `query_targets`).
4. **REST `/api/v1` surface vs DESIGN §12** — done. `admin` now has
   `GET /accounts`, `/channels` (registered channels + founders),
   `/bans` (K/D/X-lines with kind), `/audit` (oper audit log, `?limit`),
   and `/stats` (account/channel/ban counts) — all admin-gated (401/403/200
   tested) and in the OpenAPI spec. `GET /me/networks` reports a live
   `connected` tri-state per network (true/false from the always-on
   driver's handle, or null when no handle is live) and an `enabled` flag;
   **`PATCH /me/networks/{name}` `{enabled}`** pauses/resumes a network —
   persisting the flag (migration 0016), stopping or rebuilding its driver
   (skipped at boot while disabled), rolling the flag back if a stored
   secret can't be opened. Fixing this surfaced and repaired a latent bug:
   the buffer-persistence task held a strong driver handle, so `remove`
   never actually stopped a driver (delete leaked it too) — the registry
   now aborts that task on remove/replace. `me/tokens` list/delete are
   implemented (migration 0014 gives PATs an id).
   `GET /me/networks/{name}/buffer?limit=N` serves a network's persisted
   backlog (oldest-first, owner-scoped), working even while the network is
   paused, and `GET /me/read-markers` lists the account's per-target
   `draft/read-marker` positions (ISO-8601 UTC, millisecond precision).
   **OIDC identity linking** closes the item: `GET /auth/oidc/{provider}/link`
   (authenticated) runs the OIDC flow through the shared callback and
   attaches the resulting `(issuer, subject)` to the caller's account —
   globally unique, so an identity owned elsewhere is a hard 409, never a
   silent move — and `GET /me/identities` lists linked identities. Verified
   end-to-end against dockerized dex (link → listed → second account's
   conflict). Remaining endpoints 404 via the loud fallback.
5. **Oper network protections + audit logging** (DESIGN §7.6, §12, §15,
   §8) — done. Oper commands are OPER/KILL/WALLOPS plus the full server-ban
   surface **KLINE/DLINE/XLINE** and their removals. One `server_bans` table
   (migrations 0012+0015, boot-loaded into a hot list) carries a `kind`
   discriminant; the kind selects which session field the glob is tested
   against — kline=`user@host`, dline=host/IP, xline=realname (gecos) — so
   the three bans are one code path differing only by data, not three
   copies. A match is refused at registration (465 + closing ERROR) and
   disconnects matching online sessions; each command lists/adds, each
   UN* removes (scoped to its kind). The **audit_log** table (migration
   0013) records every OPER/KILL/K·D·X-LINE/UN* action (actor, action,
   target, detail, time); db::list_audit_log exposes it and the admin API
   serves it. **SETHOST** (oper host-cloak driving the chghost cap) is
   implemented and, like every oper action, audit-logged. The admin API's
   `GET /api/v1/admin/bans` lists all kinds with their `kind` field.

All five audit items (1–5) are now fully addressed in code: fuller
services, the CHATHISTORY subcommands, the REST admin/self surface, the
oper server-ban + audit surface, and the ChanServ SET options (FOUNDER,
KEEPTOPIC, MLOCK, with GUARD declined for a documented reason). What
remains is not code but two **environment-blocked** verifications: the
Discord/Slack bridges' live check (needs real credentials — neither
platform is self-hostable, so the gateway path can only be exercised
against the live API) and the 100k-connection load run (needs a tuned
Linux host). Both are outside what can be closed from this repository
alone.
