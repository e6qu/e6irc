# e6irc — Plan

Phases are sequential PRs/PR-groups; each phase ends with DESIGN.md/PLAN.md/
BUGS.md updated in the same PR. Details in DESIGN.md (section refs below).

Status (2026-07-19): Phases 0–10 ✅ complete. Phases 11–12 (Discord/Slack
bridges) 🔶 code-complete behind feature flags with offline-unit-tested
mapping logic; live verification is gated on real credentials (neither
platform is self-hostable, so the gateway path can only be checked against
the live API). Phase 13 (scale) — the load harness is complete with real
multi-channel baselines; the 100k run is environment-blocked (needs a tuned
Linux host). See **Known remaining scope** below for documented-but-unbuilt
surface (fuller services, admin API, CHATHISTORY subcommands) that the
completed-phase markers do not cover. Legend: ✅ done · 🔶 partial ·
⛔ blocked (reason).

## Phase 0 — Scaffolding ✅ (2026-07-18)
- Cargo workspace, crate skeletons, LICENSE (AGPL-3.0-or-later), CI
  (fmt, clippy, test, cargo-deny licenses/advisories, binary-size report,
  full build/test matrix: Linux, macOS, Windows × amd64, arm64).
- `e6irc-proto`: message model, zero-copy parser/serializer, rfc1459
  casemapping, numerics/ISUPPORT tables, fuzz targets. (DESIGN §7.1)
- `e6irc-queue`: custom bounded MPSC queue — seq-numbered envelopes,
  try_push/async pop, adaptive FIFO/LIFO, loom verification. (DESIGN §7.3)
- Deferred into later phases: release-artifact publishing workflow (with
  Phase 13's benchmarks once binaries do something), CAP/SASL state
  machines (Phase 2, where SASL lands), queue step-scheduler/trace hooks
  (Phase 1, with the first real workers that need stepping).

## Phase 1 — Core ircd ✅ (2026-07-18)
- Listeners (plain+TLS via rustls), connection lifecycle, bounded SendQ
  with slow-client kill, async-backpressure core queue, registration
  burst, NICK/USER/PING/QUIT/JOIN/PART/PRIVMSG/NOTICE/TOPIC/NAMES/WHO/
  WHOIS/MODE(imnstkl+bov) core, single core worker (degenerate N=1 of
  the sharded design), serialize-once fan-out via Bytes, TOML config
  with unknown-key rejection, e2e socket tests incl. TLS handshake.
  (DESIGN §7.2–7.3)
- Deferred: WHOX (Phase 3 with the compat harness), PING liveness reaper
  + registration/flood throttles (Phase 2 alongside CAP), queue
  step-scheduler/trace hooks (first deterministic-sim phase that needs
  them), rDNS/ident (decide with oper tooling).

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
   member you have op access over) is also implemented. ChanServ **SET FOUNDER**
   (ownership transfer, verified against the DB) and **SET KEEPTOPIC**
   (on/off toggle of topic retention, migration 0017; off drops the
   retained topic so it is no longer persisted or restored) are implemented.
   **Still absent:** SET's remaining channel-option flags (mlock, guard) —
   the last lower-value Atheme-equivalent surface. Unknown SET options are
   rejected loudly, never accepted-and-ignored.
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

Items 1, 3, 4, and 5 are fully done; item 2 is all but complete — only
SET's two remaining lower-value channel-option flags (mlock, guard) are
left, the last outstanding code surface in the audit. Beyond that, the
two external blockers remain: the bridges' live verification (real
Discord/Slack credentials — no self-hostable oracle) and the 100k load
run (a tuned Linux host).
