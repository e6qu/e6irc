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

Tenth sweep — fidelity + reaper follow-up (2026-07-21): two adversarial audits
of the I/O layer and numerics. The concurrency audit found no bug — ConnId-reuse
misdelivery, close() desync, and session/task leaks are structurally
unrepresentable (monotonic `AtomicU64` ids, `close()` removes every ConnId-keyed
reference, the reaper's close == a socket close). Fixes: (MEDIUM, self-inflicted
by the sweep-9 reaper) an idle-but-alive client was re-PINGed on every 15s tick
instead of every 120s, because `last_active` was serving as both the WHOIS-idle
clock and the ping-cadence trigger — the ping cadence now keys on
`last_active.max(last_ping_sent)` so the idle clock stays pure. Fidelity: five
standard commands that fell through to 421 are now implemented — `VERSION`
(351, followed by the ISUPPORT tokens), `ADMIN` (256–259 from real config),
`ISON` (303, and only *registered* nicks, with 461 on empty), `USERIP` (340,
sharing USERHOST's entry-builder), and `LINKS` (364/365, single-server). The two
ISUPPORT (005) lines were factored into one `send_isupport` choke point reused
by registration and VERSION. `deliver`'s writer-first-close comment was
corrected to note the reaper is what bounds that drop window. Left as honest 421
(surfaced, not silently faked): `REHASH` (would be a no-op — we have no live
config reload), and `STATS`/`KNOCK` (larger oper-tooling / invite-request
features for a later pass). Not fixed (architectural, bounded): the reaper frees
the Session but can't abort the parked socket read-task or its per-IP ConnGuard
without a core→net abort signal — the memory is reclaimed and the OS TCP timeout
frees the rest.

Eleventh sweep — reaper completion + last commands (2026-07-21): closed the two
items sweep 10 explicitly deferred. (1) `serve_conn` now `select!`s the read
loop against the write task instead of awaiting the read loop alone — so a
core-side close (the reaper, KILL, SASL-cap) drops the session's `Sender`,
`write_loop` returns, and the read future is cancelled immediately, freeing a
dead/partitioned peer's read task and its per-IP `ConnGuard` now rather than at
the OS TCP timeout. Verified with a deterministic unit test (a mock peer whose
read never completes: dropping the sendq sender must make `serve_conn` return).
(2) The last two missing standard commands are implemented: `STATS` (`u` →
`RPL_STATSUPTIME` 242 from a new `started_at`, every query terminated by
`RPL_ENDOFSTATS` 219 — an unexposed letter yields the conforming empty report)
and `KNOCK` (`RPL_KNOCK` 710 to the invite-only channel's ops + `RPL_KNOCKDLVR`
711 to the knocker; `713`/`714`/`403` for open/on-channel/secret). Only `REHASH`
remains 421 — implementing it would be a silent no-op (no live config reload).

Twelfth sweep — irctest differential fidelity (2026-07-21): ran the external
irctest conformance suite locally against the newly-landed command surface and
grew the CI green list by seven modules (`buffering`, `cap`, `channel`, `help`,
`isupport`, `readq`, `regressions`) after confirming they pass. Differential
testing found one real bug: a `NICK` to the client's *exact* current nick
(identical bytes, not merely the same casefold) broadcast a spurious `NICK`
line instead of being a silent no-op — `regressions::testCaseChanges` caught it;
now an exact-same NICK returns early with no rename, reply, or broadcast, while a
case change (`alice`→`Alice`) still broadcasts. The other modules that don't run
(metadata/multiline/redact/relaymsg/roleplay/account-registration/chathistory/
sasl/read_marker) need unimplemented drafts, services, or a database irctest
doesn't provide, so they stay out of the list.

Thirteenth sweep — draft/read-marker conformance (2026-07-21): irctest's
`read_marker` module (which connects without authenticating) exposed five real
draft/read-marker gaps; all fixed, and the module joined the CI green list.
(1) MARKREAD now works for a client that isn't logged in — per-connection,
session-local markers (`Session::anon_read_markers`), lost on disconnect; a
logged-in client still uses the account-keyed, persisted, cross-connection map.
(2) Markers keep **millisecond** precision — a new `parse_server_time_millis`
preserves the `.mmm` fraction the seconds parser was truncating; the DB and the
formatter already round-trip ms. (3) MARKREAD errors are IRCv3 `FAIL`
(`NEED_MORE_PARAMS`), not the legacy `461` numeric. (4) User (direct-message)
targets are valid, not only channels. (5) On JOIN, a read-marker-capable client
is sent the channel's current marker before RPL_ENDOFNAMES (a shared
`send_current_markread` backs both the query form and the replay). Two internal
tests that encoded the old, stricter-than-spec behavior (account-required,
channel-only) were updated to the conformant behavior.

Fourteenth sweep — millisecond server-time + CHATHISTORY conformance
(2026-07-21): stood up a persistence-backed irctest controller (set
`E6IRC_IRCTEST_DB` and the controller embeds a `[database]` section, advertises
SASL, registers accounts through the integrated NickServ, and truncates between
servers), which unlocked the `sasl` and `chathistory` modules and immediately
found five real bugs.

(1) **The wall clock was whole seconds.** `server-time` is specified to
millisecond precision, so every message in the same second carried an identical
`time=` tag and CHATHISTORY — which pages by timestamp — could not order them.
`CoreConfig::clock` now returns Unix **milliseconds** end to end: the reaper
deadlines became `_MS` constants, the flood bucket credits whole elapsed seconds
and carries the sub-second remainder instead of discarding it, and the values
that are genuinely coarse are named for it (`Topic::set_at_secs`,
`Channel::created_at_secs`) while WHOIS idle/signon, WHOX `l` and STATS uptime
divide at the point of display. Message timestamps are milliseconds in the ring,
across the `messages` SQL, and in the HTTP history API. No migration was needed —
`messages.ts` was already `TIMESTAMPTZ`; only the Rust conversion truncated. The
now-unused `parse_server_time_seconds` was deleted (its round-trip coverage moved
to the millisecond parser, where the round trip is exact).

(2) **A message was stamped twice.** Delivery read the clock for `time=` and the
history write read it again, so once the clock had millisecond resolution the two
could disagree and CHATHISTORY replayed a message with a different `time=` than
the client saw live. `ServerState::stamp` now performs one read yielding both the
timestamp and the msgid derived from it, and `Delivery` carries that value —
`deliver_message` no longer has a clock to disagree with. The regression test uses
a deliberately *advancing* test clock, because a fixed one cannot detect a double
read at all.

(3) **`CHATHISTORY LATEST` ignored its selector.** Only `*` is unbounded; with a
`msgid=`/`timestamp=` selector the reply must contain just the messages newer than
it, and e6ircd returned the whole ring. Fixed in the ring path and via new
`LatestAfter`/`LatestAfterMsgid` queries, which keep the *newest* `limit` in the
bound (deliberately distinct from `After`, which keeps the oldest).

(4) **`CHATHISTORY BETWEEN` ignored its direction.** The window is walked from
the first selector toward the second, so a reversed request with a short limit
must keep the newest messages in the span. e6ircd normalized the bounds and always
returned the oldest; worse, a reversed msgid pair reached SQL unnormalized and
produced an empty range. Bounds are now normalized with the direction carried
alongside as `newest_first`.

(5) **Two protocol-reply defects.** `FAIL CHATHISTORY` omitted the spec's
positional context, so a client could not attribute a failure to the request it
made — the subcommand (and the target, for target errors) is now included. And an
AUTHENTICATE payload that outgrew the accumulated buffer answered
ERR_SASLTOOLONG, which the spec reserves for a single over-long line; an
overflowing accumulation is now the generic ERR_SASLFAIL.

A second CI job (`irctest-services`) runs the two modules against a real
PostgreSQL. Every deselect names its reason in the workflow. **Direct-message
history is not implemented** — only channel messages are persisted, so
CHATHISTORY against a nick has no record to serve and TARGETS cannot enumerate
correspondents; that accounts for seven of the eight deselected tests and is the
obvious next piece of work. The eighth (`testChathistoryNoEventPlayback`) is not
a defect: a limit wider than the hot ring defers to PostgreSQL, and that reply can
land after the PING the test synchronizes on. `testPlainLarge800` is deselected
because irctest registers accounts over a normal PRIVMSG, so a 592-byte password
cannot fit the 512-byte line limit — e6ircd correctly answers ERR_INPUTTOOLONG.
The controller now fails loudly when registration is not confirmed, rather than
proceeding and surfacing an inscrutable SASL failure later.

Both CI database jobs moved from `postgres:16` to **`postgres:18`** (current
stable) in the same pass, and every database-backed suite — the `db`, `http` and
CLI `e2e` tests plus the new services conformance run — was re-verified against a
local PostgreSQL 18.4. Legacy majors are not a support target, so DESIGN §8 now
says 18 rather than "≥ 15": the project should test the version it claims.

Fifteenth sweep — direct-message history (2026-07-21): implemented the feature
sweep 14 surfaced as missing, taking `chathistory` conformance from 7/16 to
**16/16** and emptying that green list's deselects.

A conversation is stored **once**, under a key built from both participants'
identities sorted and joined by `!`. Sorting makes the key symmetric, so both
sides read the same thread from one copy; replay re-addresses each message to
its original recipient rather than to the conversation, so a replayed line is
identical to the one delivered live, and the batch still echoes the target as
the client spelled it.

The identity is the participant's **account**, not their nick — and irctest has
a regression test that explains why. A nick is released on disconnect and anyone
may take it, so a nick-keyed conversation would mean *registering a nick handed
you the previous holder's private messages*. An unauthenticated participant gets
a `~`-prefixed identity instead; `~` is legal in neither a nick nor an account
name, so it can never be claimed by an account of the same name. Two successive
unauthenticated holders of a nick do still share one identity — there is nothing
stronger to key on, and scoping to the connection would cut the other side off
from their own conversation the moment the peer left. The account boundary is
the one that carries privilege, and it is the one enforced.

Four real bugs surfaced on the way, none of them specific to direct messages:

(1) **Reads overtook their own writes.** The database worker buffers
`LogMessage` rows to batch them, but ran any *other* request — including a
CHATHISTORY query — before flushing that buffer. A client that sent a message
and immediately asked for history queried a database that did not contain it
yet. A read now flushes the pending batch first; consecutive messages still
batch.

(2) **Replies could arrive out of order.** A CHATHISTORY page that reaches
Postgres is answered asynchronously, so anything produced meanwhile — including
the PONG to a PING the client pipelined behind it — overtook the batch. A client
treating that PONG as a sync point concluded the history was empty, which is
indistinguishable from the server having none. A connection with a deferred
reply in flight now holds its later output behind it. This also fixed the one
non-DM test sweep 14 had deselected (`testChathistoryNoEventPlayback`).

(3) **CHATHISTORY TARGETS was ordered backwards** (newest-first) and its window
bounds were inclusive; both are the opposite of what draft/chathistory
specifies. Targets are now oldest-activity-first with exclusive bounds, so a
limit keeps the oldest buffers.

(4) **TARGETS matched a buffer on any message in the window** rather than on its
*latest* message falling there. A buffer whose newest activity is outside the
window has already been read past, and reporting it hands a reconnecting client
backlog it does not need.

Boy-scout: the per-channel ring moved out of `Channel` into one history store
shared by channels and conversations — one ring, one LRU, one cap, one
overflow/eviction rule — rather than growing a second parallel copy for direct
messages. `Topic`/`Channel` timestamps and the message path went with it. The
one remaining deselect in the persistence-backed list is `testPlainLarge800`,
unchanged from sweep 14 (irctest registers accounts over a normal PRIVMSG, so a
592-byte password cannot fit the 512-byte line limit; e6ircd correctly answers
ERR_INPUTTOOLONG).

Sixteenth sweep — LINKS fidelity + hardening the deferred-reply path
(2026-07-21): a differential pass over the irctest modules neither green list
covers found `links` failing, and an adversarial re-read of the machinery sweep
15 had just landed found a denial-of-service vector in it.

**RPL_LINKS reported the network name where the spec asks for `<server info>`**
— this server's own description. Those are different things, and e6ircd had no
description to report, so it substituted the network's name. A `description`
config field now exists (default `"e6irc server"`) and RPL_LINKS uses it;
`links` joins both green lists. Its services case stays deselected with a
written reason: e6ircd's services are integrated, not a linked second server, so
there is no `My.Little.Services` entry to report — the same reason the test
records for Ergo.

**Held output was unbounded.** Sweep 15 made a connection's output wait behind
an in-flight database reply so replies stay in command order. That held output
had not yet entered the send queue, so it escaped the queue's capacity — and
with it the SendQ kill. A connection that deferred a reply and then drew traffic
could grow a buffer without limit, which is a memory-exhaustion vector the
sweep introduced. Held output now carries exactly the bound of the queue it is
waiting to enter, and overrunning it is a SendQ kill like any other. The
regression test was checked against the unfixed code first: it buffers 202 lines
without the bound and is capped with it. (The first version of that test passed
either way — a held PONG is indistinguishable from a closed connection — which
is why it is now written to release the hold and count what comes out.)

**Account names can no longer contain `!`** (migration 0023). Conversations are
keyed by their participants' identities joined with `!`, so an account named
`a!b` could collide with the conversation between `a` and `b` and read it.
Both paths that create accounts already exclude it — NickServ registers a
validated nick, OIDC provisioning filters to `[A-Za-z0-9-_]` — but that was an
invariant held by callers, and the next caller can forget it. A CHECK constraint
enforces it where the name is stored, so the bug class cannot return.

Seventeenth sweep — draft/account-registration (2026-07-21): implemented the
`REGISTER` command, taking `account_registration` from 8 skipped to **8 passing**
and adding it to the persistence-backed green list.

`REGISTER <account|*> <email|*> <password>` creates the same account NickServ
and OIDC first-login create, so the three entry points cannot diverge. The
capability's advertised value states the policy — `before-connect`,
`email-required` — so a client knows the rules before it tries.
`custom-account-name` is deliberately absent: an account always takes the
registering nick's name, which keeps "the account you registered is the nick you
were holding" true, and that is exactly what lets direct-message conversations
be keyed by account (sweep 15). Registration before the connection completes is
off by default; a half-open connection creating accounts is a spam vector unless
the operator opts in.

Two design points worth recording. **The origin travels with the request.**
NickServ and `REGISTER` both create accounts but must answer in different
languages — notices versus `REGISTER`/`FAIL` — so `DbRequest::CreateAccount`
carries an `AccountOrigin` that the reply echoes. Tracking it on the session
would go wrong the moment one client used both.

**The reply is deferred like any other database-backed answer.** The first
implementation looked correct and failed the tests anyway: the round trip landed
after the client's sync point, so the reply appeared to be missing entirely — the
same ordering problem sweep 15 fixed for CHATHISTORY. `REGISTER` now holds the
connection's later output behind its reply, and the two existing deferred
emitters were refactored onto a shared `ServerState::emit_deferred` rather than
repeating the bypass-then-release dance a third time.

Eighteenth sweep — draft/multiline (2026-07-21): the last capability DESIGN
§7.5 listed and e6ircd did not implement. All **7** of irctest's multiline tests
pass, including the three limit/validation cases the marker filter deselects,
and the module joins the green list.

This needed client-initiated `BATCH`, which e6ircd had none of: a client opens
`BATCH +<ref> draft/multiline <target>`, tags its lines `@batch=<ref>`, and
closes with `BATCH -<ref>`. The lines are buffered rather than delivered as they
arrive, because a multiline message is **one message** — it takes one msgid and
one timestamp, and both delivered forms carry that same pair, so a client seeing
the batch and one seeing the flattened lines are looking at the same event.

Recipients with the capability get the batch as sent, blank lines and concat
tags intact, because those are what the sender wrote. Everyone else gets one
message per non-blank line: a PRIVMSG cannot carry a line break, and a blank
line would be an empty message. A batch that is abandoned or fails validation
delivers nothing at all rather than a truncated version of what the sender
meant, and says why with `FAIL BATCH`. Limits (32 lines, 4096 bytes) are
advertised as the capability's value so a client can see them before starting a
batch it cannot finish.

Boy-scout: rather than reimplementing target resolution for the second delivery
path, the checks came *out* of `deliver_one_message` into a shared
`resolve_message_target`. Both paths now resolve identically, which is not
tidiness but correctness — otherwise `+m`, `+n`, `+C`, bans and quiets could be
evaded by splitting the same text across a batch. Permission checks also see the
joined message rather than each fragment, so a CTCP cannot be smuggled past `+C`
a piece at a time. A Rust test pins that equivalence directly.

Two details the tests pinned down. The labeled-response **label belongs to the
batch**, not to an empty ACK at the time the batch was opened: the response to
`@label=xyz BATCH +123 …` is the batch that arrives later, so the label rides
the echoed BATCH open and the framer is told not to ACK. And `FAIL BATCH
MULTILINE_INVALID` carries no batch reference — only the limit failures take a
parameter, the limit itself.

Nineteenth sweep — adversarial pass over multiline (2026-07-21): sweep 18 added
a new client-driven surface (a client now opens batches and the server buffers
them), so this sweep attacked it before moving on. Three defects, all found by
probing a running server rather than re-reading the code.

(1) **A NOTICE inside a batch was relayed as a PRIVMSG.** The batch took its
kind from its first line and silently applied it to the rest, so `NOTICE` sent
inside a PRIVMSG batch reached recipients as a PRIVMSG. That is not cosmetic:
NOTICE exists to say "never reply to this automatically", and rewriting it hands
recipients a message the sender never wrote. A batch is one message, so it
cannot be half notice — mixing them is now `FAIL BATCH MULTILINE_INVALID` and
the batch delivers nothing.

(2) **A TAGMSG could claim membership of a batch and escape it.** `TAGMSG`
never went through the batch collector, so `@batch=<ref> TAGMSG #chan` was
delivered immediately — *before* the batch it claimed to be part of, with its
own msgid. A multiline batch carries PRIVMSG and NOTICE only, so a batch-tagged
TAGMSG is now refused rather than quietly re-routed.

(3) **A labeled BATCH that later failed never got its labeled response.**
Opening a batch deliberately suppresses the empty ACK, because the batch *is*
the response owed to that command. But if the batch was then abandoned, the
resulting FAIL carried no label and the original labeled command was answered by
nothing at all — a client tracking labels waits forever. Abandoning a batch now
inherits its label, and the failure is emitted outside the current command's
capture, since it answers the BATCH rather than whatever line tripped it.

Probes that came back clean, recorded so the next sweep need not redo them:
relayed lines stay inside the 512-byte limit even with large client tags on the
opening BATCH (the input line limit bounds them); a second concurrent open is
refused; and a batch whose target became unreachable before it closed is
refused at close with nothing relayed.

Twentieth sweep — REST history audit (2026-07-22): the recent sweeps all worked
through irctest, which never exercises the REST surface, so this one audited the
history endpoint against the storage changes made underneath it.

**A timestamp regression I introduced in sweep 14 and never noticed.** That
sweep made `HistoryRow::ts` milliseconds; the IRC render site was updated, the
REST one still multiplied by a thousand. Every timestamp the REST history API
returned was a thousand-fold into the future. It survived six sweeps because the
test asserted message bodies and msgids but never the time — so the assertion is
now there, checked against the unfixed code first (it fails, as it should have
all along).

**Direct-message history was unreachable over REST.** DESIGN §11.2 claimed the
web and IRC hit one history, but the endpoint authorized every target as a
channel, so a conversation could only ever be refused. It now serves them.

The authorization difference between the two target kinds is worth stating
plainly, because it looks like an inconsistency and is not: a channel read over
REST has no view of live membership, so it fails closed to a registered
relationship; a conversation read needs no check *because none could be
bypassed* — the key is built from the authenticated account, so a caller can
only ever name a conversation it is part of. That includes a caller who passes a
raw conversation key: it becomes one component of a key derived from their own
account, which matches nothing. The test probes exactly that, with a third
account trying `web`, `other`, `other!web` and `web!other`.

Both surfaces now derive the conversation key from a single
`dm_conversation_key`, rather than each spelling out the sort-and-join. Two
implementations that must agree is how a privacy boundary drifts.

Twenty-first sweep — msgid pivots scoped to their buffer (2026-07-22): two
audits, one clean and one not.

**Clean:** sweep 14's seconds-to-milliseconds change bit twice (CHATHISTORY,
then the REST endpoint in sweep 20), so every remaining timestamp site was
checked — the SQL round trip, read markers, and every consumer of
`HistoryRow::ts`. There is no third instance; the only render sites are the IRC
path and the REST one, and both now agree. Recorded so it need not be redone.

**Not clean:** CHATHISTORY's msgid pivots resolved the pivot across the *whole*
`messages` table rather than within the target being paged. The comment above
those queries already stated the intent — "an unknown msgid makes the subquery
NULL, yielding an empty result" — but a msgid belonging to another buffer is not
unknown globally, so `CHATHISTORY AFTER #public msgid=<a private message>`
silently positioned the query and returned the public messages that followed it.

No message content crossed a buffer (the outer query stays scoped to the
target), and e6ircd's msgids embed their own timestamp, so today this discloses
nothing a holder of the msgid could not already compute. That is the wrong thing
to rely on: the safety came from an unrelated detail of the msgid format rather
than from the query, and it would become a real oracle the moment msgids became
opaque. It was also a silent fallback — a request to page from a position that
does not exist in a buffer was answered with a plausible result instead of an
empty one. All nine pivot subqueries are now scoped to the target, and the
regression test checks all four pivoted variants against the unscoped code
first.

The Shauth relying-party surface that landed alongside these sweeps was audited
too and held up: every `web_sessions` lookup filters on expiry, back-channel
logout deletes the correlated rows, the new `oidc_role` is displayed rather than
used for authorization (admin is still gated on the configured account list),
and the validation endpoint requires a session and renders only its own
caller's identity.

Twenty-second sweep — bouncer audit (2026-07-22): the BNC surface is the largest
area these sweeps had never examined, and it holds upstream credentials and
replays stored lines to attaching clients, so it was audited end to end.

**One fix.** `NetworkHandle` has two ways into the detached buffer:
`emit_line`, which neutralizes embedded CR/LF/NUL so a bridge building a line
from free-form remote text cannot inject a second IRC line into an attached
client's stream, and `preload_front`, which restores persisted backlog and did
not. Every row in `bnc_buffer` was written through the sanitizing path, so
nothing was exploitable today — but the buffer is a replay boundary and storage
outlives the code that wrote it. A row left by an older build, a restore, or
anything else with database access would have been replayed verbatim. Both
entry points now sanitize, so no reader has to know which one a line arrived
through. The test was checked against the unfixed code, where the restored line
still carries its break.

**What held up, recorded so it need not be re-derived.** Network ownership is
enforced by `account_id` with `UNIQUE (account_id, name)`, and the buffer
endpoint verifies ownership before reading, both keyed on the same
display-cased account name that the registry and the persistence task use —
`verify_credentials`, `api_token_account` and the session lookup all return
`a.name`, so the IRC and HTTP paths cannot disagree about who owns a buffer.
`Registry::get` resolves the caller's own network first and falls back only to
an ownerless (operator-configured) one, so another account's network is not
reachable. The networks API returns `has_sasl_password` rather than the sealed
credential. Disable and delete both stop the driver rather than leaving it
running behind a flag, and a failed enable rolls the flag back so it cannot
claim a state the server is not in.

Twenty-third sweep — driver SPI and registry key made unmistakable
(2026-07-22): sweep 22 hardened the buffer's *restore* path and closed by noting
that the registry key was correct only because every producer happened to spell
the account the same way. This sweep removed both kinds of "correct by
coincidence".

**A line could bypass sanitization entirely.** `DriverEnds::emit` is public,
took a `DriverEvent`, and that enum carries `Line(String)` — with an arm that
did nothing for it. A driver calling `emit(DriverEvent::Line(..))` would have
broadcast straight past `emit_line`, skipping both the CR/LF/NUL neutralization
*and* the detached buffer: injection into attached clients, and a gap for
detached ones. No in-tree driver did this, but `NetworkDriver` is a public SPI
and the loopback driver is documented as a template for real bridges, so the
wrong call was as easy to write as the right one. `emit` now takes a
`ConnectionEvent` that cannot carry a line at all; the bypass is a type error,
confirmed by writing it and watching it fail to compile.

**The registry key is now casefolded at construction.** A miss there does not
error — `get` falls through to the shared network — so an owner spelled
differently than it was registered would have silently attached a client to the
operator's network instead of its own. `NetworkKey::new` is the only way to
build a key, so no caller can reintroduce the raw form. `bnc_buffer.owner`
follows the same rule, and migration 0025 folds rows written under the old
spelling rather than orphaning that backlog under a key nothing looks up.

Both changes are the same shape: the previous code was not wrong, it was
*relying on every future caller to keep it right*.

Twenty-fourth sweep — fuzzing the stateful core (2026-07-22): five sweeps of
reading code had reached diminishing returns, so this one changed technique. The
three existing fuzz targets all cover pure parsing — well-formed in, well-formed
out. The part with *state* was unfuzzed: registration, capability negotiation,
channels, and the multiline BATCH machine, where a line's effect depends on
every line before it, and where the core is full of `expect("checked")`
invariants that hold for the sequences a normal client produces.

A new `core_dispatch` target drives the core worker with an arbitrary command
stream from one connection. There is no oracle beyond "the worker survives
whatever a client sends", which is the contract a server owes a hostile peer.

**It found a remotely-triggerable panic in seconds.** `normalize_ban_mask`
decided a mask's shape from `mask.contains('!')` and `mask.contains('@')`, then
split on the strength of that answer. Those two questions say nothing about
*order*: `@!x` contains both, yet has no `@` after the `!`, so the second
`split_once(...).unwrap()` unwrapped `None`. `MODE #chan +b @!x` therefore
killed the core worker — and since creating a channel makes you its operator,
any connected user could do it. The process stayed up while serving nobody,
which is the worst shape of failure: alive to a supervisor, dead to every
client. Confirmed against a running server before and after the fix.

The mask is now parsed positionally, one separator at a time, so ordering cannot
be assumed. The unit test covers the ordinary shapes, the fuzzer's exact input,
and a property over adversarial masks: whatever goes in, the result has both
separators once and in order, because a mask that cannot be matched against a
prefix is a silently ineffective ban.

**Then it found a second one, in code from six sweeps ago.** `cmd_batch` split
the batch reference with `split_at(1)` to take its leading `+`/`-`. That is one
*byte*, not one character, so a reference beginning with a multi-byte character
— `BATCH \u{61c}CH1` — split inside it and panicked. Any registered client could
send it, and the whole worker died, not just that connection. The sign is now
taken with `chars().next()`, which cannot land mid-character. Worth recording
how it surfaced: a short fuzz run had already come back clean, and only a longer
one reached it. "The fuzzer found nothing" is a statement about how long it ran.

Both fixes carry regression tests checked against the unfixed code first, and
`core_dispatch` joins the CI fuzz loop so the stateful surface keeps getting
exercised as it grows.

Twenty-fifth sweep — fuzzing between connections (2026-07-22): sweep 24's
target drives a single connection, which cannot reach the invariants that only
exist *between* them — nick collisions, kicks and invites, a conversation
needing two participants, a multiline batch relayed to somebody else — nor the
events no client sends: the liveness `Tick`, which closes connections part-way
through another's command stream, and the deferred database pages whose whole
job is to be ordered against a connection's other output.

`core_multi` drives three connections interleaved and feeds `Tick`,
`OverlongLine`, `Closed`, `HistoryPage` and `TargetsPage` alongside client
lines, each action chosen by the leading byte so a corpus of plain IRC still
works and the fuzzer discovers the rest by mutation. It reaches ~200 more edges
than the single-connection target, which is the measure of what the older one
could not see.

The daemon came through it. The one bug found was in the harness: `&raw[1..]`
sliced the action byte off by *byte*, so a line starting with a multi-byte
character panicked the fuzzer itself — the same mistake `cmd_batch` made and
sweep 24 fixed. Worth recording rather than quietly correcting: a panic in the
harness is indistinguishable from a finding until the backtrace is read, and
writing the identical bug days after fixing it says the shape is easy to reach
for, not that the earlier one was careless.

Both core targets now run in CI.

Twenty-sixth sweep — split the command handler, and find the guard that was
not looking (2026-07-22): `core/handler.rs` had grown to 6,417 lines, the file
every sweep touched. It is now `core/handler/` with eleven modules, one per
command family, `mod.rs` keeping dispatch and shared helpers. The code moved
verbatim; what changed is that a command's module now follows from what the
command does. The multiline batch machinery moved from the capability section
to `message.rs` on the way, where it belonged.

**The split exposed that `check-duplication.sh` had never opened the four
biggest files.** jscpd skips any file over 1000 lines *by default and
silently*, so `handler.rs`, `http.rs`, `db.rs` and `state.rs` — 60% of the
source — were never scanned. The guard reported a comfortable 1.46% describing
the other 40%. Splitting one file into pieces under the limit made the numbers
jump to 3.49%, which looked like the refactor introducing duplication; measured
with the limit raised, main and the split are identical (4.25% vs 4.26%), so
the refactor introduced none. The 3.49% was the instrument, not the code.

The guard now raises `--max-lines`/`--max-size` and, more importantly, asserts
that jscpd scanned every source file it was given, failing loudly when it did
not. That check was verified by re-imposing the old limit and watching it fail
with "scanned 40 of 44".

The threshold moves 3% → 4.3%, which the guard's own comment forbids. It is
recorded there in full: 3% was calibrated against a scan that ignored most of
the code, so it never described this codebase, and re-baselining a
mis-calibrated instrument is not the same as loosening a standard to hide a
regression. The largest clone was extracted on the way — the channel and
direct-message paths each spelled out deliver-then-echo, now one
`deliver_and_echo` — taking it to 4.2%. The remaining clusters are named in the
guard for the next ratchet: the HTTP handlers' authenticate/lookup/problem
prologues, ChanServ's per-subcommand permission preamble, and the bridge
drivers' connect-retry loops.

Twenty-seventh sweep — paying back the threshold, and checking the guards
themselves (2026-07-22): sweep 26 raised the duplication threshold to 4.3% on
the argument that the old 3% had been measured against a partial scan. That is
only defensible if the number then comes back down, so this sweep did that
first: **4.2% → 3.54%**, and the ratchet is set to 3.6%.

Two clusters went. The HTTP handlers each opened with the same eight lines —
authenticate, return its rejection, re-derive the pool it had already proved
existed — and four more repeated a ten-line `JsonRejection` match. Both are now
axum extractors (`Authenticated`, `JsonBody`), so a route is authenticated
because its *signature* says so, which is also where a reader looks. ChanServ's
identify → registered → founder preamble became one `chanserv_founder_gate`;
that one matters beyond tidiness, because a permission check written three
times can drift, and the copy that drifts is the one that stops refusing.

Two things were deliberately *not* unified. Two routes answer "Invalid request
body" where the rest say "Invalid JSON", and ChanServ DROP reports "you are not
the founder" where its siblings would say "not registered". Both are
user-visible strings; collapsing them would have been a silent behaviour change
smuggled inside a refactor, so they keep their exact wording and the
duplication that comes with it.

**The guards were then tested rather than trusted**, prompted by sweep 26's
finding that jscpd had never opened the four largest files. Three probes:
a private function used only by an inline `#[cfg(test)]` module (caught), a
`pub` item reachable only from an integration test (caught by
`check-dead-pub`, invisible to the compiler as expected), and no benches exist
to form a third blind spot. The third probe found one: `check-dead-pub` counted
a name appearing in a *doc comment* as a use, so an item that was never called
passed as long as something mentioned it in prose. It now strips comments and
string literals before counting. Both directions were re-verified — the
`dead-pub-allow` exemption still works (the marker lives in a comment, so
stripping naively would have broken it), and the real tree is still clean.

Twenty-eighth sweep — split the HTTP surface (2026-07-22): `http.rs` was the
last file over a thousand lines, at 3,965. It is now `http/` with seven modules
— oidc, device, openapi, history, ws, credentials, networks — and `mod.rs`
keeping the router, `AppState`, the extractors and the shared response helpers.
No file in the crate is now larger than `oidc.rs` at 1,042 lines, down from
6,417 two sweeps ago.

The first attempt cut three items in half. Section-marker comments sit between
items and are safe boundaries, but the sub-splits inside a section (pulling the
OpenAPI document out of the device-grant section, the test modules out of the
networks section) were chosen by line number and landed mid-item. The failure
mode is worth recording: a half-item means the file does not parse, so *none* of
its items exist, which surfaced as ~25 "cannot find value `list_networks`"
errors in the router — that reads like a visibility problem and sends you
looking in the wrong place entirely. Redone with every boundary snapped to an
item start: the line where its doc comment or attributes begin, not where its
`fn` does.

Two things needed fixing that a pure move would not suggest: `include_str!`
paths are relative to the *file*, so moving a directory deeper broke the
embedded stylesheet (loudly, at compile time — but only because the asset is
embedded rather than read at runtime), and structs whose fields are read from a
sibling module needed those fields visible, not just the type.

Twenty-ninth sweep — one reconnect policy, not four (2026-07-22): the
duplication guard's own comment records the bridge drivers' reconnect loop as a
copy-paste class an earlier sweep removed. It had grown back — four copies,
matrix/slack/discord/irc — which is exactly what a ratchet exists to notice.

They are now one `run_with_backoff`. The saving is small (about fifteen lines
each) but the point is not line count: reconnect pacing is a *policy*, and four
copies meant a change to it reached whichever bridge was being edited and
quietly left the other three on the old behaviour. `irc_driver` also carried its
own `ConnectionOutcome`, identical in shape and meaning to the other three
drivers' `SessionOutcome`; there is now one type for "a driver session ended,
either stopped or dropped".

The shared loop takes a function returning a boxed future rather than an async
closure. The closure form cannot prove `Send` for a higher-ranked borrow of the
driver's ends, and the spawned task needs it; one allocation per *reconnect* is
not worth contorting the signature to avoid. That trade is written at the
signature so the next reader does not try to "simplify" it back.

Duplication 3.54% → 3.48%, ratchet to 3.5%.

`db.rs` was examined and deliberately left. Most of its clones are sqlx builder
chains — `.bind().execute().await.map_err()` — which are plumbing, and
abstracting them would read worse than the repetition. The one real target
there is the CHATHISTORY column list, repeated across eleven query variants: a
contract between those queries and one row type, and the thing that drifted
when timestamps moved from seconds to milliseconds. It wants a compile-time
`concat!` rather than a runtime `format!` that would cost the SQL its
greppability, and it wants doing at the start of a sweep rather than the end of
a long one — so it is recorded in the guard as the next target instead.

Thirtieth sweep — one CHATHISTORY column contract (2026-07-22): the target
sweep 29 recorded rather than rushed. The column list every history query
selects was written out fifteen times across eleven variants — a contract
between those queries and one row type, and the thing that drifted when
timestamps moved from seconds to milliseconds: each copy was edited by hand,
and the one that was missed stayed wrong for six sweeps until sweep 20 found
it.

It is now one `history_select!` (and `history_window!` for the two `UNION`
forms). `concat!` rather than `format!`, because `sqlx::query_as` borrows its
`&str`: this keeps every statement a single `&'static str` with no runtime work
and no temporary to outlive the query, and the SQL stays greppable, which an
interpolated string would not.

The expansion is pinned by a test that spells the expected statement out in
full rather than rebuilding it from the macro — a test that used the macro
would assert nothing. That is also why the column list still appears once more
in the file than strictly necessary. Verified beyond the unit test by the 32
PostgreSQL query tests and irctest's 16 CHATHISTORY tests, since a column-order
mistake here is a runtime failure on every history read, not a compile error.

Duplication 3.48% → 3.23%, ratchet to 3.3%.

What remains is mostly sqlx builder chains and per-route response shaping.
Those are plumbing rather than a shared concept, so the guard now records that
the number is expected to sit here — and that it should be lowered when a real
abstraction is found, not by wrapping boilerplate to move a metric.

Thirty-first sweep — the client bounds nothing (2026-07-22): every previous
sweep audited what a hostile *client* can do to the server. The clients ship
from this repository too, and they face the opposite direction: a client's
entire state is derived from lines a remote server chose to send, and that
server is not necessarily this one — it may be hostile, buggy, or a bridge
relaying somebody else's text.

Reading them against the daemon's own rules found the daemon's care simply
absent. The daemon bounds everything — SendQ, history rings, held output — and
its own client bounded nothing:

- `Buffer::push` grew the scrollback forever. Now capped at `SCROLLBACK_LINES`,
  oldest first.
- `App::open_buffer` allocated a buffer per distinct target, so a server
  sending `PRIVMSG #a1`, `#a2`, … forever allocated forever. Capped at
  `MAX_BUFFERS`, and the cap is *reported* — once, since the condition that
  triggers it is exactly the one that would flood the notice. A silent cap
  would read as the network going quiet.
- The TUI's network event channel was unbounded, filled by the server and
  drained only between draws. Now bounded, so a full queue stops the reader
  task and TCP applies the backpressure — the SendQ shape, in the other
  direction.
- `e6irc api` read the HTTP response with `read_to_end`. Bounded, and over the
  cap is an error rather than a truncation: half a JSON document on a script's
  stdin is worse than a failure.

Worth recording how the scrollback fix went wrong first. `scroll` is an offset
from the *end* of the log, so draining the front does not move the view — but
the first version decremented `scroll` by the drained count, which slid the
viewport forward one line per arrival. The test that caught it was the one
written to compare the *visible lines* before and after, not the one that
checked `scroll` stayed in range; the latter passes either way. A bound is not
correct because it is a bound.

`e6irc api` also built its request head from `method`/`path`/`token` verbatim.
This is a scripting CLI — a path is routinely built from a shell variable — so
a CR or LF there let that variable append headers or a second request. Rejected
before the socket opens, which is also what makes it testable.

A new `client_messages` fuzz target feeds the TUI arbitrary server output
through the real parse-and-convert path and exercises the render slice at
degenerate heights, where an off-by-one becomes a panic rather than a wrong
pixel. Clean over 7.6M executions; it joins the CI fuzz loop.

Writing it turned up a third copy of the borrowed→owned message conversion (the
connection's, the TUI test helper's, the fuzz target's). `OwnedMessage` is
`pub` but its constructor was not, so a caller holding a parsed `Message` had no
way to build one and each site hand-wrote the mapping — free to drift. It is now
the `From` impl the type should have had, and all three sites use it.

The sweep's boy-scout find was in the test suite, not the code. Running the
PostgreSQL-gated suites turned three bouncer tests red; they passed under
`--test-threads=1`. Every one of the 58 database tests ran against the single
database in `E6IRC_TEST_DATABASE_URL` and began by truncating it — so any two
running at once were mutually destructive, and `cargo test` runs the tests
within a binary in parallel. Nothing about that was new; it had simply been
winning the race.

Scheduling around it (a mutex, `--test-threads=1`) would have kept the tests
mutually destructive and only hidden it — and only within one process, which
`cargo nextest` would undo. Instead `E6IRC_TEST_DATABASE_URL` is now the
*administrative* connection, and `tests/support` hands each test a database
named after it, dropped and recreated on first ask. The 57 `TRUNCATE`s are
gone; there is nothing left to truncate.

The migration to it made the mistake it was meant to prevent: the rewrite named
each database after the enclosing function, and `bnc_account_db` is a helper
four tests share — so those four shared a database again. Which is why
`test_db` now records the thread that claimed each name and panics if a second
one asks: libtest runs each test on its own thread, so that is exactly the
signature of two tests sharing a database, and it says so instead of failing
somewhere else later.

Also removed: a `sed 's/127.0.0.1:15556/127.0.0.1:15556/'` in the CI dex setup,
which substituted a string with itself.

Thirty-second sweep — the bouncer as somebody else's client (2026-07-22):
sweep 31 audited the shipped clients against hostile servers. The daemon is a
client too: the BNC driver holds a persistent connection to an upstream network
this project does not run, and everything that arrives on it is stored and
replayed to real users.

**A retention trim that reached almost no network.** `persist_bnc_line` kept the
`bnc_buffer` table bounded by trimming on an amortized schedule — `if id % 1000
== 0`, where `id` is the table's own sequence. But that sequence is shared by
every network, so *which* network gets trimmed depends on how their inserts
interleave. Two networks alternating is enough: one takes the even ids, the
other the odd, and multiples of 1000 are always even. A test with two networks
each appending 7,000 lines found one of them holding all 7,000 — never trimmed
once, growing until the disk is full, at a rate an upstream chooses.

The count now lives in the per-network persistence task, which is the only
writer for its network. That is not just a fix but the shape that makes the bug
unrepresentable: there is no longer an interleaving for the trigger to depend
on. `trim_bnc_buffer` is its own function and the caller decides when it is due.

The end-to-end test for it needed two tries. The first waited for the row count
to fall inside the retention window — and passed with the trim disabled,
because an untrimmed buffer *passes through* that window on its way past it. It
now waits for the count to stop moving and asserts where it came to rest.

**The buffer held a re-serialization, not what arrived.** The driver parsed
each upstream line and rebuilt a wire line from the parse, with a hand-written
serializer that skipped every check `Message::to_line` performs — no command,
tag-key, source or parameter validation, and no rejection of a non-final
parameter containing a space. It was a second implementation of the wire format,
and the unsafe one.

It is also unnecessary: the client had the original bytes and discarded them.
`Connection::next_message_with_line` now hands them back, the driver buffers
those, and the serializer is deleted. Higher fidelity, not just less code — a
single-word trailing parameter came back without its `:`, because a
re-serializer only adds one when it must. That is what the new test pins, and
it fails against the deleted code.

**Boy-scout: five orphaned doc comments.** Refactors that moved or merged
functions left the old doc paragraph stacked on top of the new one — including
one where a function's doc had migrated onto the *next* item, leaving
`me_tokens_list` undocumented. Found by reading, then generalized into a scan
for doc blocks with two item-introducing openings, which turned up the two I had
missed. The scan is clean now.

Thirty-third sweep — a bridged message must not vanish for being long
(2026-07-22): the Discord/Slack/Matrix bridges turn free-form remote text into
IRC lines delivered to real users. Sweep 32 fixed what the IRC driver did with
an upstream's bytes; these three synthesize their own.

**Long messages were silently lost.** Each bridge built one
`:{nick}!{nick}@{host} PRIVMSG {channel} :{body}` line, and the body is
whatever the platform allows — 4,000 characters on Discord, 40,000 on Slack —
against an IRC line limit of 512. That is not a protocol nicety: the receiving
client's framing discards an over-long line *whole* (`LineEvent::TooLong`), so
the message arrives as nothing at all, with nothing said about it. The body is
now split across as many PRIVMSGs as it needs.

Embedded newlines split too. They are line breaks in the source medium, and
`sanitize_upstream_line` flattens them to spaces further down, so a multi-line
message used to arrive as one run-on line.

The split is by bytes against a byte budget, so it lands on character
boundaries — a test with 2-, 3- and 4-byte characters confirms it, and fails
with a panic (`byte index is not a char boundary`) if the boundary walk is
removed. That is the third time this repo has met that exact bug; here it was
written correctly the first time *because* it is the third time.

**The notice that exists to prevent a silent drop was silently dropped.** When
a client sends to an unbridged target, the bridge answers `:*bnc* NOTICE
{target} :not delivered: no bridged … for {target}`. `target` comes from the
client's own line, bounded only by the frame limit — several times 512 — and it
is interpolated twice. A long enough target produced a notice the client's own
framing discarded, and the silence the notice exists to prevent came back. It
is truncated to fit, on a character boundary.

**One renderer, not three.** The three `render_privmsg` copies differed only by
the `@host` suffix; Matrix additionally reduced `@user:server` to its localpart
first. Collapsing them nearly dropped that step — which would have renamed
every bridged Matrix nick — so it survives as `matrix_localpart`, named for what
it does and applied at the call site.

**Boy-scout: CI never compiled a bridge on its own.** `--all-features` is the
union, so `cfg(feature = "discord")` code that leans on something `matrix`
pulls in builds in CI and breaks for the deployment that enables one bridge.
The lint job now checks each of the three separately. This sweep proved the gap
was real from the other side: a four-config local check missed two bridge test
modules that `--all-features` caught immediately.

Thirty-fourth sweep — one char-boundary primitive, not four (2026-07-23):
"slice a string at a byte index that lands inside a multi-byte character" is a
panic, and it is reachable from remote input anywhere a length budget meets
non-ASCII text. This repo has met it three times — `normalize_ban_mask` and
`cmd_batch` (sweep 24), the client fuzz harness (sweep 31), the bridge splitter
(sweep 33) — and each site that caps a string was carrying its own hand-rolled
boundary walk: `truncate_chars` (topics, kicks, aways), the bouncer's
`truncate_on_char_boundary` (undelivered-target notice), the inline walk in
`render_bridged_privmsg`, and `sanitize_composer_line`. Four copies of the same
three lines is four places to get it wrong, and the history says it does get
gotten wrong.

They now share one primitive in `e6irc-proto`: `floor_char_boundary(s, index)`
— the largest boundary `≤ index`, clamped to the length — with
`truncate_on_char_boundary` on top. It mirrors the signature of the unstable
`str::floor_char_boundary`, so it becomes a one-line delegation if that method
stabilizes. The four sites are one call each; the bug class has one home to be
correct in.

`truncate_boundary` joins the CI fuzz loop: arbitrary string, arbitrary budget,
assert the returned index is on a boundary and the slice is a lossless prefix —
124M runs clean. The unit test walks every cut of one string exhaustively; the
fuzz target walks one cut of every string. A property this load-bearing should
be pinned from both directions.

Thirty-fifth sweep — MONITOR replies that vanished for being long
(2026-07-23): the same silent-discard class as the last two sweeps, this time
in a core numeric. A client may `MONITOR` up to 100 nicks, and all 100 can be
online; the reply put every `nick!user@host` prefix on one `RPL_MONONLINE`
line — thousands of bytes — which the receiving client's framing discards
whole. The client would then never learn any of them are online: MONITOR's
entire purpose, defeated at exactly the scale it is meant for. `RPL_MONOFFLINE`
and `RPL_MONLIST` had the same shape.

NAMES (353) and WHOIS (319) already split their lists to fit — the intent was
clearly there, just not applied to MONITOR. Rather than add a fourth hand-rolled
budget calculation (each with its own magic-number overhead: `1 + server.len()
+ 5 + …`, easy to get subtly wrong), the packing is now one method,
`ServerState::numeric_list`, which measures the fixed framing exactly as
`numeric` emits it and splits on that. MONITOR is fixed by it; NAMES and WHOIS
fold onto it and lose their bespoke arithmetic. Verified the shared overhead
reproduces both old hand-computed budgets to the byte.

The regression test monitors 100 online peers and asserts the reply spans more
than one line, every line fits the wire limit, and no nick is lost in the split
— it reports all 100 on a single line against the unfixed code.

USERHOST/USERIP (bounded to five targets) and ISON (a single reply by RFC 2812,
where splitting would be non-conformant) are deliberately left as one line;
MONITOR is the case that is both unbounded and explicitly allowed to span lines.

Thirty-sixth sweep — one speak-gate, and the one place it must not reach
(2026-07-23): the channel "may this sender speak?" decision — op/voice bypass,
otherwise subject to +m, bans, quiets, and (off-channel) +n — was copied
verbatim, thirteen lines, into both `resolve_message_target` (PRIVMSG/NOTICE)
and `cmd_tagmsg`. The TAGMSG copy's own comment said it had to be "the same gate
as PRIVMSG", which is the tell: two copies that must agree are one waiting to
disagree, and a disagreement here lets a banned or quieted user relay
typing/reaction tags it cannot send as text. It is now one method,
`Channel::may_speak`, and both paths call it.

The interesting part was the place that looked like it should join them but must
not. TOPIC on a `-t` channel checks ban/quiet — a quieted member setting the
topic would deface the channel around the quiet — and its comment also said
"same speak-gate as PRIVMSG/TAGMSG". But it deliberately omits +m: a moderated
channel silences *messages*, not topic changes, so a regular member of a +m, -t
channel may still set the topic. With `may_speak` now a named thing, that
comment was an invitation to "consolidate" TOPIC into it and quietly make +m
block topics. The comment now states the exclusion and why, and a new test pins
it: bob is blocked from PRIVMSG under +m (404) but still sets the topic —
routing TOPIC through `may_speak` fails it. Verified it fails against that wrong
change.

No behavior change to the message paths: the extracted gate is byte-for-byte
what both copies computed. This is the bug *class* removed (the gates can no
longer drift) plus the one deliberate difference made explicit and enforced.

Thirty-seventh sweep — MODE changes applied but never seen (2026-07-23): the
same silent-discard class, reached through a different door. A single MODE
command may set many bans (`MODE #c +bbbbbb mask1 … mask6`), and the echoed
broadcast — `:{op-prefix} MODE #c +bbbbbb mask1 … mask6` — carries every mask
plus the op's own hostmask. Six ~80-byte masks already run it to 546 bytes; a
recipient's framing discards the over-long line whole. The bans are in force
server-side, but the other members never see them announced: channel state and
what members observe diverge silently, which for bans is exactly the wrong
direction to be quiet about.

The broadcast is now split across as many MODE lines as the 512-byte limit
needs, each a self-contained `+`/`-` announcement, none dropped. The mode loop
was refactored to collect applied changes as `(adding, char, arg)` tuples rather
than format them inline, so the split can pack them; the single-line common case
is byte-for-byte what it was (the 164 existing mode tests are unchanged and
pass). A new test sets six long bans and asserts every broadcast line fits the
wire limit and every ban appears across them — it fails at 546 bytes against the
unsplit code.

USER MODE (`+iwB`, `-o`) needs no such split: those modes are few and carry no
arguments, so its announcement cannot approach the limit.

Thirty-eighth sweep — the message that overflows on relay (2026-07-23): the
same silent-discard class as the last five sweeps, now in the most-travelled
path of all. A client may send a PRIVMSG whose whole line is within the 510-byte
traditional limit — but the server relays it with a source prefix the sender
never wrote (`:nick!user@host `), and that pushes the relayed line past 512. A
max-length message relays at 537 bytes; a strict client discards or truncates
the tail. Unlike a numeric reply this cannot be split — one PRIVMSG is one
message — so the fix is to trim the text to fit.

The trim happens once, in `deliver_one_message`, upstream of both delivery and
history: live recipients, the sender's own echo, and CHATHISTORY all carry the
byte-identical (possibly trimmed) message. Because the *stored* body is the
trimmed one, CHATHISTORY replay of a single message fits automatically — the
overhead on replay is the same prefix, and the body it reads was already cut to
leave room for it. `fit_relayed_text` computes the budget from the sender's
prefix, the kind and the target, then trims on a UTF-8 char boundary via the
shared `truncate_on_char_boundary` (sweep 34) — so a multi-byte character
straddling the limit is never cut through. Permission and CTCP checks still see
the message as sent (their markers sit at the front, which the trim never
reaches). Three tests: the relay fits the limit, echo and relay are identical,
and a body of snowmen trims on a boundary.

Deliberately *not* covered in sweep 38, closed in sweep 39: the `draft/multiline`
egress points. Its constituent lines legitimately exceed 512 for a recipient that
negotiated the capability and larger frames (that is the point of multiline), so
the live batch form stays full — but the flattened delivery to a non-capable
recipient and the CHATHISTORY replay of multiline lines still overflowed.

Thirty-ninth sweep — the multiline egress overflow (2026-07-23): closing the
follow-up sweep 38 scoped. A `draft/multiline` line the sender sent within the
input limit still overflows 512 at two egresses that reduce it back to a plain
PRIVMSG: the flattened delivery to a client without the capability, and the
CHATHISTORY replay of the stored line (which is replayed per-line, to a requester
that need not have multiline). Both now trim with the same `fit_relayed_text`
(sweep 38): flattened delivery trims at the wire, and the stored body is trimmed
so replay fits.

The live batch form is deliberately left full — its recipient negotiated the
capability and the larger frame, which is the whole point of multiline. So a
capable client sees the full line live and a fitted line on replay; that
divergence is inherent to CHATHISTORY replaying multiline as individual PRIVMSGs
rather than reconstructing the batch, and it is the safe direction (a
within-limit line, never a dropped one). Two tests, each verified failing with
its egress's trim removed: the batch form keeps a >512 non-tag body while the
flattened copy fits, and a CHATHISTORY replay of a multiline line fits.

That closes the outbound-line-length class opened in sweep 33: bridges, MONITOR,
MODE, single-message relay, and now multiline — every path that turns internal
state into a wire line now keeps that line inside the limit, by splitting where
the content is a list and trimming where it is one message.

Forty-first sweep — two more bug classes made unrepresentable (2026-07-23):
answering "what else can the design make impossible?" by turning two
stringly/bytely-typed values into types, and writing the technique down.

`MessageKind` replaces the `&'static str` that carried a message's kind. It was
literally two casings of the same fact: the hot ring stored `"PRIVMSG"`/
`"NOTICE"`, the database stored `"privmsg"`/`"notice"`, and each was
re-uppercased on replay — a comment on the replay path admitted it existed "so
the same message never replays with a different verb case depending on where it
came from." That coincidence is now structural: one enum with `wire()` (the
uppercase verb), `db()` (the lowercase column token), and `is_loud()` (PRIVMSG
auto-replies, NOTICE never does). A stored kind that is neither is a corrupt row
surfaced by `from_db`, not a silent default.

`StatusSigil` replaces the `u8` STATUSMSG sigil (`0`/`b'@'`/`b'+'`). "Is this a
STATUSMSG" was a `!= 0` test and the audience a byte match; it is now
`Option<StatusSigil>` with `is_none()` (enters history / full audience) and an
`admits` method. Eight sites in one file, no behavior change.

The systematic half is in `DESIGN.md` §2: the "make bug classes unrepresentable"
principle now carries the catalogue of invariants it has actually installed,
each tagged with the class it closes, plus the one still-open class (epoch time
as a bare `u64` in two units) recorded and scoped rather than left implicit.

Forty-second sweep — epoch time is a type now (`Millis`), the last open
unrepresentable class (2026-07-23): sweep 41 catalogued the invariants that
close bug classes and recorded one still open — epoch time carried as a bare
`u64` in two units, milliseconds (the clock, message `ts`, `server-time`) and
seconds (the coarse `*_secs` display fields), guarded only by the `_secs`
naming. It had shipped two bugs: a whole-second clock that made same-second
messages unpageable by CHATHISTORY, and a `server_time(ts * 1000)` on an
already-millisecond value that put every REST timestamp a thousandfold into the
future for six sweeps.

`e6irc_proto::time::Millis` is now that type. `server_time` and
`parse_server_time_millis` take/return it, the clock is `fn() -> Millis`, and
every millisecond-bearing field — message `ts`, `HistoryEntry`/`HistoryRow`/
`Delivery` timestamps, `signon`/`last_active`/`started_at`/`opened_at`/
`last_ping_sent`, the flood watermark, both read-marker maps, and every
`*_ts` bound in the CHATHISTORY `DbRequest`s — is `Millis`. The two conversions
survive only where they belong: `as_secs()` for the coarse display fields, and
`as_millis() as i64` at the SQL edge, both named and greppable. `server_time(ts
* 1000)` no longer compiles.

The compiler drove it: change the four boundary signatures and chase ~90 type
errors across proto, `db.rs`, the handlers, `net.rs`, and the tests to zero.
No behavior change — the same milliseconds flow, now wearing their unit — so
the whole suite (including the millisecond-sensitive CHATHISTORY ordering and
the advancing-clock double-read test) passes unchanged. The fuzz targets, a
separate workspace, were updated in the same pass (the lesson from sweep 41's
CI miss).

`DESIGN.md` §2's invariant catalogue gains `Millis` and loses its "not yet
closed" note: every bug class that has bitten this codebase and admits a type
is now closed by one.

Forty-third sweep — fuzzing the surfaces the core fuzzers can't reach
(2026-07-23): with every type-closable class closed (sweep 42), the work shifts
from closing known classes to discovering unknown ones — and the highest-value
unfuzzed public surfaces are the two that sit *before* the core: the byte-stream
framer and the base64 decoder on the SASL path.

`LineBuffer::feed` splits a TCP stream into IRC lines and enforces the inbound
length limit — the first thing to touch every byte from every connection, and
the inbound counterpart to the outbound wire-limit class sweeps 33–40 closed.
The new `framing` target asserts two properties over arbitrary bytes fed in
arbitrary chunks: every emitted line fits the limit, and — the property a unit
test cannot reach — the line sequence is *independent of chunk boundaries*, so
the framing never shifts with however the kernel split the stream. 14.5M runs
clean.

Writing it, the fuzzer immediately flagged an assertion I had gotten wrong: it
claimed no framed line could end in CR. It can — the framer strips only the
single CR of the CRLF terminator and leaves an *embedded* CR for
`Message::parse` to reject, exactly as its doc comment says. The framer was
right and my test was wrong; the contract is now pinned by a unit test
(`strips_only_the_terminator_cr_not_embedded_ones`) so it is documented in code,
not just a comment. A good reminder that a fuzzer checks the oracle as much as
the code.

`base64::decode` parses the SASL `AUTHENTICATE` payload — untrusted bytes
decoded before any credential check. The new `base64_roundtrip` target asserts
decode never panics on arbitrary text and that encode/decode round-trips
byte-for-byte (what SASL relies on to recover the exact credential). 35M runs
clean.

Both join the CI fuzz-smoke loop. Neither found a defect — the surfaces were
already correct — but they were the two reachable public entry points with no
coverage, and both now lock invariants a future refactor could otherwise break
silently.

Forty-fourth sweep — admin-gating is a type now, not a convention
(2026-07-23): an audit of the OIDC device-grant and admin HTTP surface found it
sound — 256-bit device codes, atomic one-time consume (`DELETE … RETURNING`),
one-time approve, and every one of the five `admin_*` endpoints correctly gated.
But "correctly gated" meant every admin handler *opened with* `if let Err(r) =
require_admin(...) { return r; }` — a convention a sixth handler could silently
omit, the same fragile-discipline shape as the sweep-36 speak-gate.

The codebase already had the fix pattern for authentication: the `Authenticated`
extractor makes a route authenticated by *asking for it in the signature*. This
sweep adds the admin rung, `AdminAccount`: an axum extractor whose
`FromRequestParts` runs `require_admin`, so an admin handler takes `_admin:
AdminAccount` as a parameter and an ungated admin handler fails to compile for
want of the argument. The five handlers shed their `require_admin` prologue; the
gate now lives in the type system. It is a marker struct — the admin's name is
discarded, because no admin *read* endpoint needs the actor (a future audited
admin action can carry it then).

Behaviour is unchanged (401 unauthenticated, 403 non-admin, 200 admin), and the
existing gating test — extended to cover `/admin/stats`, the one endpoint it had
missed — confirms all five across both the extractor and the router wiring.

The device-flow audit's one real finding was minor and left recorded rather than
churned: `user_code` is generated with `ALPHABET[byte % 30]`, a modulo bias
(256 % 30 = 16, so the first sixteen letters are slightly likelier). In this
flow the user code's entropy is nearly security-irrelevant — approval binds the
grant to the approver's own account, so guessing another user's code gains
nothing — and every other token (device code, API tokens, app passwords) is
already unbiased base64 of raw `OsRng` bytes. Noted here, not fixed, to keep the
sweep to one change.

`DESIGN.md` §2's invariant catalogue gains `Authenticated`/`AdminAccount`: HTTP
authorization joins the set of preconditions the type system enforces rather
than the reviewer.

Forty-fifth sweep — fuzzing the bouncer, and one small hardening it found
(2026-07-23): after auditing the OIDC callback (textbook-correct: one-time
state, cookie binding, PKCE, nonce, `(issuer, subject)` provisioning that never
takes over an existing account) and the config validation (thorough; secure
cookies fail-safe to on) and finding both sound, the remaining gap in the
*discovery* machinery was the bouncer's upstream line-processing — the code that
turns hostile *upstream* bytes into what an attached client sees, which the
core fuzzers (they drive the server side) never reach.

`sanitize_upstream_line` and `filter_tags` are `pub(crate)`/private, and the
repo's rule is that a fuzz target must not widen a crate's public surface. The
`#[cfg(fuzzing)]` idiom threads that needle: a wrapper module compiled *only*
under cargo-fuzz's `--cfg fuzzing`, invisible to every normal build, `cargo
test`, and the shipped binary — so the real public surface is unchanged. (The
cfg is declared in `Cargo.toml`'s `[lints.rust] check-cfg` so the denied
`unexpected_cfgs` lint knows it is expected.)

The `bouncer_lines` target asserts the security invariant: for arbitrary bytes,
the pipeline `sanitize` → `filter_tags` never yields a line carrying CR/LF/NUL —
the bytes that would let one upstream line become two on the client's wire.
6.4M runs clean.

It also flagged a genuine, if benign, contract gap: `filter_tags` on a leading
`@` with no following space (a tag section with no message body) returned it
unchanged, so a no-tags client could receive a `@`-prefixed line. No well-formed
upstream produces that and the IRC driver parse-validates before storing, so it
is not reachable in production — but it is a cheap defense-in-depth to close, and
the malformed tag-only line is now dropped. Pinned by a unit test.

A second thing the fuzzer surfaced was *my test*, not the code: an assertion that
a filtered line never starts with `@` is false for a body that itself begins with
`@` (reachable only by feeding filter_tags malformed lines the real pipeline
never stores). Relaxed to the invariant that actually holds and matters —
injection-prevention — with the reasoning recorded in the target.

Forty-sixth sweep — a real ban-matching bug, found by differential fuzzing
(2026-07-23): `mask::matches` is the hostmask glob behind every ban, quiet and
exception — run against masks any channel operator sets. Its shipped form is the
iterative single-`*`-backtracking matcher, whose correctness for multiple stars
is subtle enough to prove rather than trust. The new `mask_matching` target is a
*differential* fuzz: it compares the shipped matcher against a textbook glob
dynamic program (the specification) on arbitrary `(mask, subject)`, and any
disagreement is a finding.

It found one on the second input: `*?` vs a subject containing a literal `*`.
The matcher tested `pattern[p] == text[t]` *before* recognizing `pattern[p] ==
b'*'`, so a `*` **wildcard** in the pattern matched a literal `*` byte (0x2A) in
the subject one-to-one, as if it were an ordinary character. The wildcard check
now comes first.

This is reachable and security-relevant: a username is length-bounded at intake
but not character-filtered, so a client connecting as `USER a*b …` has prefix
`nick!a*b@host`, and a ban mask that should match them could silently fail to —
ban evasion. Fixed, pinned by a regression unit test (`*?` vs `*` and friends),
and the differential fuzz is clean over 29.7M runs post-fix; the `chmodes/ban`
and full channel-mode conformance suites still pass.

Worth recording how the reference was chosen. A naive recursive glob spec is
exponential on an all-`*` pattern, and the fuzzer correctly flagged that as a
*slow unit* — the reference's cost, not the code's. The specification is now the
O(n·m) glob DP, which is both unambiguously correct and fast, so the fuzzer
tests the matcher rather than the oracle's pathologies.

Forty-seventh sweep — the CHATHISTORY window arithmetic, extracted and pinned
against a spec (2026-07-23): sweep 46 showed differential testing against an
independent specification is the sharpest remaining tool. The highest-value
target for it is the CHATHISTORY ring-window resolution — the most intricate
pure arithmetic in the codebase and the part with the longest bug history
(paging direction, off-by-one at the bounds, the same-second ordering that
forced the millisecond clock).

It was inlined in `cmd_chathistory`, entangled with the ring lookup and the
error path. This sweep extracts it whole into a pure `resolve_ring_window(history,
complete, sub, selector, selector2, limit)` — the same arithmetic, now callable
without a database or a live ring, and with the unknown-subcommand case as a
plain `None` the caller turns into its FAIL. The refactor is behaviour-preserving
(the CHATHISTORY unit tests and the 32 PostgreSQL query tests pass unchanged).

Then it is pinned by an *exhaustive* differential test: for every ring size 0–5,
every subcommand, every selector that resolves to each index (by msgid and by
timestamp, on and between entries) plus each kind of miss, every limit 1–8, both
`complete` states, and BETWEEN's full selector×selector matrix, the extracted
function is compared against a reference formulated with direct index ranges
rather than the shipped `skip`/`take` chains. The space is small enough to walk
exhaustively — stronger than fuzzing here — and a divergence names the exact
case. They agree everywhere: the arithmetic is correct. (Verified the test
discriminates by reintroducing a one-index shift in the AFTER arm and watching
it fail.)

No bug this time — but the logic most likely to *grow* one is now both isolated
and locked to a specification, so a future edit that shifts a bound fails a test
rather than silently mispaging a client's history. Worth noting the reference,
too, had to be right: its first form panicked on an empty range where BETWEEN's
two selectors resolve to one index — a reminder the oracle needs the same care
as the code, which the shipped iterator-based form handles without a special
case.

Forty-eighth sweep — the other half of the ban-evasion finding: an
unsanitized username (2026-07-23): sweep 46 fixed the glob bug that made a `*`
in a username evade a ban, and noted the root — usernames were length-truncated
but never *character*-filtered. That leaves a second, independent problem the
glob fix does not touch: `@` and `!` in a username make the `nick!user@host`
source prefix ambiguous. A client sending `USER a@evil.com …` gets the prefix
`nick!a@evil.com@host`, which every other client parses as host
`evil.com@host` — a user spoofing part of their own apparent host. RFC 2812
forbids `@` and space in a username; e6ircd allowed them.

`sanitize_username` now drops `!`, `@`, space, and control bytes at intake
(then byte-bounds to USERLEN, with a fallback so an all-`@` username cannot
collapse to the malformed `nick!@host`). The relayed prefix always has exactly
one `!` and one `@`. A regression test connects as `USER a@evil.com!x` and
checks the delivered prefix carries the sanitized `aevil.comx`; WHO, WHOIS, and
connection-registration conformance and the full irctest green list are
unchanged (real clients send plain usernames).

This closes the class the sweep-46 finding pointed at from both sides: the
matcher no longer mishandles a metacharacter in the subject, and the subject
(the prefix) can no longer carry a prefix-breaking one in the first place.

Forty-ninth sweep — the `account=` tag was emitted unescaped (input-sanitization
session, 1/N) (2026-07-23): opening a session dedicated to user-input
sanitization by mapping every client-derived string to where it lands on the
wire. The length-only fields (realname, away, topic, kick/part/quit reasons)
all flow into *trailing* parameters, where any byte but CR/LF/NUL — already
rejected at parse — is legal; those are fine. The exposure is in *middle*
parameters, the source prefix, and *tag values*, which have stricter grammars.

The account name is the field with the widest such exposure — it rides in the
`account=` message tag, the `ACCOUNT`/WHOISACCOUNT/extended-join middle params,
and SASL numerics. Account names come from a validated nick (NickServ REGISTER)
or `sanitize_account_name` (OIDC), and *both* permit `\` — a legal nick
character. In the middle-parameter positions a backslash is harmless, but in the
`account=` **tag** a raw `\` is an escape introducer: a client decodes
`account=a\b` as `ab`, and `account=a\sadmin` as `a admin`, attributing the
message to a different account than the one that spoke — an identity that bots
and clients make trust decisions on. `account=` is now escaped with
`escape_tag_value`, like every other tag value; the label tag was already
escaped at capture, and the remaining tags (`time`/`msgid`/`batch`) are
server-generated.

A regression test identifies to an account named `a\b`, then checks the relayed
tag is `@account=a\\b` and that re-parsing recovers `a\b`. account-tag,
message-tags and labeled-response conformance are unchanged.

Fiftieth sweep — malformed client tag keys were relayed to the channel
(input-sanitization session, 2/N) (2026-07-23): the audit continued through the
last client-controllable field that reaches *other* users unfiltered. Client
input can carry no CR/LF/NUL past the parser, so the only remaining risks are
space in a middle parameter and unescaped specials in a tag value — and the tag
*value* is already escaped (`client_tag_string`, sweep-49's `account=`). The gap
was the tag *key*.

The parser accepts any non-delimiter byte in a tag key — a control character, an
emoji, anything but `;`/`=`/space/CR/LF/NUL — but the message-tags spec restricts
a client-only key to `+` followed by an optional `vendor/` and a `[A-Za-z0-9-]`
name. `client_tag_string` relayed the key verbatim, so a client could push a tag
whose key held a `\x02` or non-ASCII bytes to everyone in the channel (and into
each recipient's parser). Such keys are now dropped; a well-formed
`+example.com/reply` still rides through. Not an injection — a key structurally
cannot hold a delimiter — but the propagation of malformed keys is exactly the
"don't relay unsanitized input" the spec forbids.

A unit test sends one valid and one control-char-keyed client tag and checks
only the valid one is relayed; message-tags, account-tag, and echo-message
conformance and the full irctest green list are unchanged (real client tags are
`[A-Za-z0-9-./]`).

With this the client-input map is complete: every field is validated at intake
(nick, channel, user, host), escaped for its tag position (account, label,
client-tag values), key-filtered (client-tag keys), or trailing-only (realname,
away, topic, reasons — where any surviving byte is legal). The remaining
sanitization frontier is the bridge identities, already covered by `nick_token`
and `sanitize_upstream_line`.

Fifty-first sweep — one sanitization module, and a flaky CI step fixed
(input-sanitization session, 3/N) (2026-07-23): two things, one PR.

**The flaky step.** The "Exercise OIDC in a real browser" CI step hung ~13
minutes and was canceled by the job timeout — a transient wedged chromium.
Playwright's per-action timeouts are 30s, but nothing bounded the *whole*
script, and `browser.close()` in the teardown had no timeout at all, so a hung
close sat until the job died. Both browser harnesses (`test-oidc-browser.mjs`,
`test-shauth-sso.mjs`) now carry a 180s watchdog that force-exits and a bounded
`browser.close()`, so a hang becomes a fast, clear failure instead of a 13-minute
red run; the three CI steps that install/launch chromium also gained
`timeout-minutes` so even a wedged apt/download can't eat the job budget.

**The consolidation.** Three sanitization sweeps had scattered the vocabulary —
`sanitize_username` in registration, `sanitize_account_name` in http/oidc,
`nick_token`/`sanitize_upstream_line` in the bouncer, `valid_client_tag_key` in
message, `valid_nick`/`valid_channel_name` in their handlers. They are now one
`crate::sanitize` module whose header states the rule each wire position imposes
(prefix: no `!`/`@`/space; middle: no space; tag: escaped/charset-limited;
trailing: length only) and each function names the position it protects. Callers
reference `crate::sanitize::*`; behaviour is byte-identical (the moved bodies are
unchanged, verified by the unchanged suites, including per-bridge-feature builds
and the message-tags / account / who / whois conformance). A field added later
gets the correct rule by reaching for the module rather than inventing a filter.

Length-fitting stays separate (it is a wire-*length* concern, already centered on
`e6irc_proto::message::truncate_on_char_boundary` with the `fit_*`/`clip_*`
wrappers at the delivery sites); the module documents that split so the two
concerns are not conflated.

Fifty-second sweep — the sanitize contracts are machine-checked now
(input-sanitization session, 4/N) (2026-07-23): sweep 51 consolidated the
sanitizers into `crate::sanitize` and wrote each field's wire-position contract
in prose. This sweep turns that prose into a test. Every sanitizer is a
per-character filter, so its contract is provable *exhaustively* rather than
sampled: over an adversarial twelve-character alphabet (a nick-legal letter, the
`!`/`@` prefix separators, space, the three injection bytes CR/LF/NUL, a
backslash, a bracket, a digit, a control char, and a multi-byte `é`), every
string of length 0..=3 is run through each function and its output checked
against the documented rule.

`username` never emits `!`/`@`/space/control and stays within its byte budget;
`account_name` emits only nick-charset characters; `nick_token` emits only
nick-legal characters and never a prefix-breaker; `upstream_line` never leaves a
CR/LF/NUL; `valid_client_tag_key` accepts only `+[vendor/]name` over the spec
charset. Small enough to be exhaustive, wide enough to exercise every branch and
its boundary — stronger than fuzzing for functions this shape, and deterministic.
Verified the tests bite by relaxing `username` to permit `@` and watching the
property fail on the input `"@"`.

The sanitization session now has, in one module: the consolidated sanitizers,
their contracts in prose, and those contracts machine-checked — so a future edit
that lets an unsafe character through fails a test rather than shipping.

Fifty-third sweep — five-front bug hunt: DoS panic, injection, auth
atomicity (2026-07-23): four parallel adversarial passes (core handlers, proto
parsing, bridge gateways, DB/HTTP/OIDC) turned up five concrete defects, all
fixed here in one PR.

1. **`STATS <multibyte>` panicked the shared worker** (`chanops.rs`). The query
   letter was taken with `&letter[..letter.len().min(1)]` — a byte slice at index
   1, which is mid-char for any non-ASCII first character (`STATS é`). Since one
   worker serves every connection, that panic was an unauthenticated remote DoS
   (registration is the only prerequisite). Now takes the first *char* on a
   boundary. Regression test added.
2. **Bridge channel names reached a PRIVMSG middle parameter unsanitized**
   (`discord.rs`, `slack.rs`). Every other gateway-derived field is sanitized
   (sender via `nick_token`, body via `upstream_line`), but the REST-fetched
   channel name was formatted straight into `PRIVMSG #name` — a self-hosted /
   API-compatible endpoint could return `evil PRIVMSG all :spoofed` and forge
   extra params. Both drivers now validate with `sanitize::valid_channel_name`
   and refuse the network loudly rather than putting an unsafe target on the wire.
3. **`Message::to_line` emitted a raw NUL in a tag value** (`e6irc-proto`). The
   key/source/param paths all reject illegal bytes; the tag *value* went through
   `escape_tag_value`, which escapes `; SPACE \ CR LF` but has no escape for NUL,
   so a value carrying one serialized silently. Not reachable through `parse`
   (inbound NUL is rejected up front), but a latent no-silent-fallout violation.
   New `SerializeError::BadTagValue` makes it symmetric and unrepresentable.
4. **`/auth/device/start` had no rate limit** (`http/device.rs`). Every sibling
   unauthenticated endpoint gates on `auth_rate_ok`; this one didn't, so an
   anonymous flood accumulated live `device_grants` rows that pruning can't touch
   for ten minutes. Now gated per client IP like the others.
5. **Device-grant consume/mint was non-atomic** (`db.rs`, `http/device.rs`).
   `poll_device_grant` did `DELETE ... RETURNING account` and *then* minted the
   token in a separate call; a transient error on the mint destroyed the approved
   grant and forced the user to restart the whole flow. Consume and mint now run
   in one transaction (token-insert extracted to an executor-generic
   `insert_api_token`), so they commit or roll back together. New PG-gated test
   proves the approved grant yields a working token, is single-use, and mints
   exactly once.

The four passes also *cleared* large areas: the proto parse/serialize surface is
pinned by round-trip + differential fuzzers, OIDC provisioning can't duplicate
accounts (unique constraint + rollback), no auth path logs-and-continues, and the
CHATHISTORY windows are exhaustively differential-tested.

Seventy-first sweep — four-front hunt: a lost FLAGS revocation, labeled
multiline hangs, and terminal escape injection in the CLI (2026-07-25): four
parallel audits on the DB worker/persistence, MODE handling, IRCv3 response
framing (labeled-response/batch/echo), and the client-side crates. Eight bugs
fixed:

1. **`db_reply` dropped global-state DB confirmations when the requester's
   connection had closed** (sasl.rs, MEDIUM-HIGH) — the client-vanished guard
   also swallowed `ChannelRegistered`, `FounderChanged`, and `ChannelAccessSet`,
   whose payloads update *global* hot state (the founder map, channel access).
   Worst case: a FLAGS revocation whose requester disconnected during the DB
   round-trip — the DB says revoked while the hot map keeps auto-opping the
   revoked account until restart. Those three replies now bypass the guard (the
   notices inside degrade safely on a dead conn).
2. **A DB fault during a FLAGS change was reported as "account is not
   registered"** (db.rs/sasl.rs, MEDIUM) — `applied: false` conflated the
   definitive negative with a store failure, the exact lie the founder-transfer
   path documents against. New `ChannelAccessUnavailable` reply mirrors
   `FounderChangeUnavailable`.
3. **A labeled draft/multiline batch closed empty never answered its label**
   (message.rs, MEDIUM) — the empty-batch early return emitted zero bytes, so a
   label-tracking client waited forever (the framer had been told not to ACK the
   deferred open).
4. **A labeled multiline batch refused at close (+m, ban, vanished channel)
   never answered its label** (message.rs, MEDIUM) — the refusal numeric went
   out unlabeled and the label dangled. Both paths now resolve through a shared
   `ack_multiline_label`, the same guarantee `multiline_fail` gives
   collection-time failures.
5. **echo-message was not honored for messages to services pseudo-clients**
   (message.rs) — `PRIVMSG NickServ :HELP` from an echo-message client produced
   no echo (the services intercept returned first), so the client's own line
   never rendered in its NickServ buffer. Echo now precedes the service reply,
   with the usual msgid/time/account tags, captured for labeled framing.
6. **List-mode masks (+b/+q/+e/+I) accepted embedded spaces** (channel.rs,
   MEDIUM) — `MODE #c +b :a b` (trailing form) stored a mask that splits into
   two tokens in both the MODE broadcast and the RPL_BANLIST middle — a
   malformed line for every state-tracking client, and an entry the displayed
   form can never remove (only the first token is consumed on `-b`), breaking
   the documented BANMASKLEN invariant. Adds are now rejected with
   ERR_INVALIDMODEPARAM, like the `+k` arm rejects space-containing keys;
   removals pass through so a legacy stored mask stays removable.
7. **The `e6irc` CLI printed server-controlled text verbatim to the terminal**
   (e6irc-cli, MEDIUM-HIGH) — `tail`/`history` wrote nick and message bytes
   straight to stdout; the wire parser rejects only CR/LF/NUL, so any channel
   peer could inject ESC/CSI sequences (retitle the window, clear the screen,
   spoof output). Control characters are now replaced with a visible U+FFFD
   (the TUI was already safe — ratatui filters control chars). Also: `tail`'s
   target match was case-sensitive, silently missing messages sent to a
   differently-cased channel name; it now folds under rfc1459.
8. **The app-password cap was a TOCTOU** (db.rs, LOW) — the COUNT and INSERT ran
   as separate pool statements on the concurrent REST layer, so parallel
   requests could overshoot `MAX_APP_PASSWORDS_PER_ACCOUNT`. The check and
   insert now run in one transaction with the account row locked FOR UPDATE
   (argon2 hashing kept outside the lock).

Surfaced, not changed: a labeled REGISTER/IDENTIFY answers the label with an
immediate empty ACK and the deferred SUCCESS/FAIL arrives unlabeled (only
CHATHISTORY threads labels through the deferred path — a design-level change);
a client labeling both the multiline open and close with echo-message gets a
duplicate-key tag line (pathological input); CAP LS 302's version isn't stored
(harmless: the cap set is static, so CAP NEW/DEL never fire); no `MODES=`
ISUPPORT token (clients assume the conservative default 3; the 512-byte frame
bounds the real count); and `e6irc raw`/`api` output stays unfiltered
(pipe-oriented by design). Clean bills: all eleven CHATHISTORY pagination
variants against the ring differential, DbReply routing/ordering and the
worker's flush-before-read, mode sign/param ordering and no-op suppression,
label isolation and echo tag parity (msgid/time byte-identical across delivery,
echo, ring, replay), proto tag escaping round-trips, client framing, and the
TUI's bounded scrollback. Verified beyond the gate: irctest main list **258**
(up from 255 — the labeled-multiline fixes turned three greens on) and PG
services list (49); the dex-backed `tests/oidc.rs` (4) and embed-web
`tests/http.rs` (12); the full PG db suite (40); the bridges under
`--features matrix,discord,slack`; the fuzz crate under `--cfg fuzzing` (a
`DbReply` variant was added).

Seventieth sweep — four-front hunt: a bridge OOM, an unbounded
rate-limiter map, and a channel-name that could forge a param (2026-07-25):
four parallel audits on the chat bridges (matrix/discord/slack), the
sanitization primitives, the reaper/timers/limiters, and the registration
burst/numerics/ISUPPORT. Seven bugs fixed:

1. **`valid_channel_name` didn't reject CR/LF/NUL** (sanitize.rs, MEDIUM) — its
   docstring promised a name "free of the bytes that would split it or the line,"
   but the reject set was only space/comma/BEL/`:`. Client names are pre-screened
   by `Message::parse`, but a *bridge* channel name comes from a remote API and
   never passes the parser, so a `#foo\nEVIL` would flatten (via `upstream_line`)
   to the multi-param forge `#foo EVIL` the space-check exists to prevent. CR/LF/
   NUL are now rejected.
2. **A bridge could be OOM'd by an oversized upstream response** (bouncer, MEDIUM)
   — every `reqwest` `.json()` in the matrix/discord/slack drivers buffers the
   whole body first, so a hostile or compromised upstream (the Matrix example
   even permits plaintext `http://…`, MITM-able) could return a multi-GB body and
   OOM the shared daemon — a cross-tenant DoS. All eight call sites now go through
   a `BoundedJson` extension that reads chunk-by-chunk under a 16 MiB cap.
3. **The auth-rate limiter map was not actually bounded** (oidc.rs, MEDIUM) — the
   prune only removed *fully-refilled* entries, so a flood from many distinct IPs
   (trivial with an IPv6 /64) kept every entry below full and retained them all,
   growing the map to ~request-rate × 60s. It now hard-caps at `MAX_AUTH_BUCKETS`,
   evicting the least-recently-seen entry (whose bucket simply resets) to make
   room — mirroring `pending_auth`'s hard cap.
4. **Two bridged rooms/channels deriving the same IRC name silently collapsed the
   mapping** (matrix/discord/slack, MEDIUM) — outbound reached only one, inbound
   from both merged under one channel, with no warning (unlike an *unsafe* name,
   which is refused loudly). A name collision is now refused loudly too.
5. **`valid_client_tag_key` was over-permissive and unbounded** (sanitize.rs) —
   it accepted `.` anywhere, a leading/duplicated `/`, and any length, so a
   malformed or multi-KB client-only tag key was relayed verbatim to every
   recipient. It now enforces the spec `+[vendor/]name` structure and a length
   cap.
6. **KNOCK was implemented but never advertised in ISUPPORT** (query.rs) — a
   client that gates its `/knock` UI on the `KNOCK` 005 token believed the server
   couldn't do it, though `KNOCK #invite-only` works. Now advertised.
7. **The command-flood bucket stalled on a backward wall-clock step** (handler,
   LOW) — an NTP correction left the refill watermark in the future, so
   `saturating_sub` yielded 0 and the bucket never refilled, flood-killing an
   actively-talking client through no fault of its own. It now re-anchors the
   watermark to `now` when time goes backward.

Surfaced, not changed: several LOW bridge items — `route_privmsg` doesn't split
comma-target lists or strip a STATUSMSG prefix (a delivery restructure), routing
is case-sensitive rather than casemap-folded, a fatal auth rejection reconnects
forever (the "always-on" policy treats it as transient), and an attachment-only
Discord message renders nothing; the reaper/flood timers run on the wall clock
rather than a monotonic source (the flood backstep is fixed above; the reaper's
forward-step exposure is bounded by its ping re-anchor) and the reaper `Tick`
stamps its `now` from `wall_clock` directly rather than the injected
`config.clock` (benign while they are the same function); the `RPL_MYINFO` 5th
field carries prefix modes rather than the param-taking channel modes (MYINFO is
deprecated, essentially unparsed); and the OIDC-provisioned `account_name`
charset diverges from `valid_nick` (account ≠ nick, no wire hazard). Clean bills:
the whole bridge line-injection defense (`upstream_line`/`nick_token`, notices
wire-limited, no remote-input panic), the flood-bucket refill arithmetic and
reaper cadence at every boundary, `ConnLimiter`/credential-budget/SendQ/`doomed`
accounting, the registration burst ordering (001→005→LUSERS→MOTD, ban-checked,
no double-burst), the numerics table (all codes unique/in-range), and the
ISUPPORT advertise-vs-enforce matrix (every other token matches). Verified beyond
the gate: full irctest main list (255) and PG services list (49); the dex-backed
`tests/oidc.rs` (4) and embed-web `tests/http.rs` (12); the bridges built under
`--features matrix,discord,slack`; the fuzz crate under `--cfg fuzzing`.

Sixty-ninth sweep — the CHATHISTORY rename fix + four-front hunt:
TAGMSG missing tags, an OIDC first-login race (2026-07-24): landed the
CHATHISTORY DM requester-rename mis-address surfaced in sweep 68, plus four
parallel audits (OIDC/session lifecycle, admin API + WS UI, casefold/typed-key
discipline, and TAGMSG/tags/STATUSMSG). Seven bugs fixed:

1. **CHATHISTORY re-addressed a replayed DM by the sender's historical *nick*,
   not their identity** (MEDIUM, the sweep-68 follow-up). A requester who
   renamed mid-conversation saw their own sent lines re-addressed to themselves
   instead of the correspondent. `HistoryRow`/`HistoryEntry` now carry the
   sender's `sender_account` (the DB already stored it — the two history SQL
   macros, `HistoryDbRow`, its pinned SQL-assertion test, and the fuzz crate
   were threaded through), and `history_page` compares each row's *identity*
   (`account` or `~nick`) to `conn_identity` — stable across a rename.
2. **TAGMSG omitted the `account` and `bot` tags** (MEDIUM) that PRIVMSG/NOTICE
   attach — the account-tag and bot-mode specs list TAGMSG among the messages
   that bear them, so identity/anti-spam tooling silently lost attribution for
   typing/reaction traffic. Three delivery paths; two attached the tags, one
   forgot. Now attached (per-recipient `account-tag`, `bot` for a bot sender).
3. **TAGMSG relayed duplicate client-only tag keys verbatim** (`+x=a;+x=b`),
   a technically-malformed tag section clients could disagree about. Client
   tags are now de-duplicated last-wins (matching the parser's own accessor).
4. **The OIDC first-login race returned a spurious 503** — the identity `INSERT`
   had no `ON CONFLICT`, so two concurrent first-logins for one `(issuer,
   subject)` had the loser's insert fail the unique constraint and roll back to
   an error. Now `ON CONFLICT (issuer, subject) DO NOTHING`; on a conflict it
   returns the winner's account and rolls back its own spurious account — the
   user is provisioned exactly once, retry-free.
5. **The OIDC state-binding cookie was never cleared after callback** — it
   lingered up to its `Max-Age`. Now expired alongside the session cookie via
   `axum::response::AppendHeaders` (a plain header array *inserts*, so a second
   `Set-Cookie` would have clobbered the session cookie — the mistake that first
   broke the dex/shauth login tests before the append fix).
6. **`oidc_link_start` was not rate-limited** unlike `oidc_start`/`oidc_sso_start`;
   gated on `auth_rate_ok` for parity.
7. **The REST history endpoint's docstring overstated DM parity with IRC** — it
   keys a DM by the casefolded target name, which matches the IRC path only when
   that equals the correspondent's stored identity (account, or offline `~nick`).
   The HTTP layer has no live session state to resolve a nick→account, so the
   docstring now documents the scope limit honestly rather than claiming full
   parity (same `~nick`-vs-nick class as sweep 68, unfixable without core state).

Investigated and *rejected as a non-bug*: the OIDC audit flagged that
RP-initiated logout "leaves the local session alive" when the provider can't be
coordinated (no `end_session_endpoint`). That is a **deliberate, tested**
fail-closed design — `oidc_logout_without_end_session_configuration_fails_closed`
pins it (a failed logout keeps `/me` at 200), and it fails *loudly* (503) so the
user knows the upstream SSO is still active rather than being misled into
thinking they are fully logged out. Reversing it to best-effort local logout
would trade a documented design decision for a different one, so it was reverted.

Surfaced, not changed: **TAGMSG ignores comma-separated target lists** (takes
only the first token — a delivery-loop restructure with STATUSMSG/cap/may_speak
regression risk, deferred as a focused follow-up); the OIDC **discovery cache
can serve stale JWKS across a key rotation** (bounded 15-min availability
tradeoff, never accepts a forged token); `create_web_session`'s non-OIDC wrapper
has no production caller (a password web-login path is intended, or it collapses
to the test helper); and the DB layer's hardcoded `Rfc1459` fold is coupled to
the core's fixed casemap (latent — would diverge only if the casemap became
configurable to Ascii). Clean bills: the admin API (authZ fail-closed extractor,
no data exposure, no IDOR), the WS `/ws/irc` bridge (same per-IP cap + framing
as raw TCP) and `/ws/ui` composer (CR/LF sanitization, XSS-escaped rendering,
same-origin + CSRF), the OIDC session/cookie/back-channel-logout core (14-day
TTL, `__Host-` attributes, jti replay guard, no fixation), and the entire
typed-key/casefold discipline across every state map and folded DB column (only
the one REST DM-parity scope limit found). Verified beyond the gate: full
irctest main list (255) and PG services list (49); the 40-test PG db suite (the
`sender_account` history column and the OIDC race fix on real PostgreSQL); the
fuzz crate under `--cfg fuzzing`.

Sixty-eighth sweep — four-front hunt: a config that bricks the
server, a credential that deletes the account password, and a doubled
per-IP cap (2026-07-24): four parallel audits on config/boot/shutdown, the
CHATHISTORY command surface, account-registration + the REST self-service API,
and the channel MODE internals. Eleven confirmed bugs fixed:

1. **`max_connections_per_ip = 0` was accepted and bricked the server**
   (config.rs) — `try_acquire` refuses once `count >= max`, so a max of 0
   refuses *every* connection; the server booted, reported "listening", and
   silently rejected all traffic. Rejected at load like its command_burst /
   auth_rate_burst siblings.
2. **The BNC listener used a *separate* per-IP limiter** (net.rs), so one IP
   could hold `max_connections_per_ip` IRC/WS connections *and* that many BNC
   connections — doubling the documented cap. It now shares the one counter.
3. **A sealed Slack bot token in `sasl_account` was never decrypted**
   (config.rs) — `resolve_secrets` unsealed `sasl_password` but not
   `sasl_account`, so a sealed `enc:v1:…` value was handed to Slack verbatim as
   the token (silent auth failure). Now unsealed too.
4. **`[registration]` without `[database]` was a silent no-op** — accepted but
   unable to do anything (no account store). Rejected loudly like [[oidc]]/[bnc].
5. **`nicklen` had no upper bound** — the advertised NICKLEN rides every relayed
   line's prefix, so an unbounded value could push a line past 512. Capped at 64
   like server_name/network_name.
6. **`DELETE /me/credentials/{id}` could delete the account's primary
   `local_password`** (db.rs) — the delete didn't filter `kind`, and
   `list_credentials` exposes the primary's id, so a caller could remove their
   own password login (self-lockout). Scoped to `kind = 'app_password'`.
7. **App-password / PAT labels were unbounded and control-char-unchecked**
   (http) — inconsistent with the network fields (bounded 64/128/255,
   CR/LF/NUL-rejected). Now validated (≤64, no control chars) via a shared
   `validate_label`.
8. **No per-account cap on app passwords / PATs** — networks and read-markers
   are capped, these weren't; an authenticated account could flood the
   credential tables. Both capped at 32 (the app-password cap enforced in the DB
   choke point, the PAT cap at the handler so the device-grant login path isn't
   gated).
9. **A `MODE` param mode that ran out of arguments `break`ed the whole string,
   dropping a later param-less mode** (channel.rs) — `+ki` with no key silently
   lost the `+i`, an order-dependent divergence from `+ik`. Now it skips the
   arg-less mode and continues, so a later `+i`/`+m`/… still applies.
10. **`+o`/`+v` echoed the raw input nick, not the target's canonical nick**, and
    **`+l` echoed the raw token, not the parsed value** (`+l 007` broadcast
    `+l 007` while enforcing `7`). Both now broadcast the canonical/parsed value
    for state-tracking fidelity.
11. A stale `targets_page` doc comment (said "newest-first" while emitting
    oldest-first) was corrected.

Surfaced, not changed: **no graceful shutdown / signal handling** — a SIGTERM
under load drops DB writes still queued in the worker (already acknowledged
in-code as the planned signal-handling work; a coordinated drain-on-signal is a
dedicated change, not a rush alongside eleven fixes); **CHATHISTORY DM replay is
mis-addressed after the *requester* renames** (MEDIUM) — the re-addressing
compares the row's historical sender *nick* to the requester's *current* nick,
so an authenticated user who renames mid-conversation sees their own sent lines
re-addressed to themselves. The class fix (carry the sender's stable identity on
`HistoryRow`/`HistoryEntry` — the DB already stores `sender_account` — and
compare it to `conn_identity` in `history_page`) touches the pinned history SQL
macros, `HistoryDbRow`, its SQL-assertion test, and the fuzz crate; it is a
coherent dedicated follow-up, deliberately not rushed into the hardened
CHATHISTORY path (as that arc itself was done incrementally in sweeps 60–62).
Also surfaced: unauthenticated DM history becomes unreadable once the
correspondent goes offline (a `~nick`-vs-`nick` identity-key asymmetry, a
consequence of the identity model); `REGISTER` isn't gated on the
`draft/account-registration` cap (a spec nicety — the account name is still
forced to the held nick and the credential budget still applies); and the
unauthenticated `POST /auth/app-passwords` has no hard credential budget when
`auth_rate_burst` is unset (operator-configurable). Clean bills: the entire
CHATHISTORY selector/ring/DB-routing/authorization/framing surface (only the
requester-rename re-addressing is off), boot ordering (preloads before the
worker, migrations before preloads), TLS loading (no plaintext fallback), the
whole /me/* authZ surface (no IDOR), the REGISTER state machine (no nick
hijack), and the MODE parameter-consumption model for every mixed +/- string.
Verified beyond the gate: full irctest main list (255 passed) and PG-backed
services list (49 passed); new PG db tests for the credential fixes; the fuzz
crate builds under `--cfg fuzzing`.

Sixty-seventh sweep — four-front hunt: a client-triggerable CAP
panic, an unremovable server ban, and a SASL abort cross-wire (2026-07-24):
four parallel audits on the query surface (WHO/WHOIS/WHOWAS/ISON/USERHOST),
CAP+SASL negotiation, the oper/server-ban machinery, and MONITOR/read-markers.
Eight confirmed bugs fixed:

1. **CAP ACK/NAK echoed the client's cap list verbatim** (registration.rs) —
   a ~490-byte REQ (fits the input frame) reflected into
   `:{server} CAP {target} {verb} :{request}` overflowed 512, which the
   recipient's framing discards whole and, under debug assertions (as cargo-fuzz
   runs), the wire check *panics* — a client-triggerable, unauthenticated,
   pre-registration full-server DoS. The reply is now bounded: an un-echoable
   REQ is NAKed (nothing applied) and only the fitting prefix is echoed.
2. **Server-ban dedup/removal compared masks case-sensitively while enforcement
   folds them** (oper.rs) — `KLINE Baddie@Host` then `UNKLINE baddie@host` failed
   to remove and reported "no such ban" while the ban kept enforcing (an
   *unremovable* ban), and two case-variants double-stored. The mask is now
   folded at storage (via the casemap, like enforcement), with `mask::eq`
   comparisons — the hot list, the DB `ON CONFLICT`/`DELETE` keys, and matching
   all agree. Migration 0029 folds existing rows (dropping folded-twin
   duplicates first).
3. **An XLINE gecos mask with spaces was silently split** (oper.rs) —
   `XLINE *Evil Corp* :spam` banned `*Evil` with reason `Corp*`, a different and
   broader ban than typed. Since a middle param can never contain a space, the
   reason (when given) is the final param and the mask is the rest rejoined;
   removal rejoins the whole argument. KLINE/DLINE (spaceless) keep the simple
   split.
4. **A SASL abort-then-reauth cross-wired a stale verify reply** (sasl.rs) —
   `AUTHENTICATE *` cleared the state machine but couldn't un-send the in-flight
   verify, so its reply completed a *new* attempt (logging in under the aborted
   attempt's account, or dropping a valid login). A new `sasl_verify_pending`
   marker survives the abort and blocks a new SASL verify (and an IDENTIFY)
   until the stale reply drains, so a reply is never attributed to a different
   attempt. Replaces the sweep-66 `sasl == Verifying` IDENTIFY guard, which the
   abort path slipped past.
5. **MARKREAD sibling-sync ignored the `draft/read-marker` cap** (read_marker.rs)
   — a logged-in device on an older client received an unsolicited MARKREAD line
   it never negotiated. The fan-out now filters on the sibling's cap and
   registration, like every other MARKREAD emission.
6. **USERHOST/USERIP truncated the last entry** (chanops.rs) — the entries were
   joined into a single unsplittable reply with no fit logic, so `numeric`'s
   trailing truncation chopped the last entry mid-token into a corrupt string
   (`nick*=+user@2001:db8:`). A shared `pack_trailing_list` helper now packs
   whole entries and drops the overflow (a polling client re-queries) — ISON was
   refactored onto the same helper, which also fixed its over-counted overhead.
7. **Oper ban reasons were unbounded on the wire** (oper.rs) — an over-long
   reason rode the victim's closing ERROR and the ban-list NOTICE past 512.
   Clamped to 300 chars.

Surfaced, not changed: the WHOX 354 row bounds only its trailing, not the
summed middles (an overflow needs a pathologically long — >100 char —
`server_name`; the fix would touch the central `numeric` funnel, so it's
deferred over a config-pathological latent gap); and CAP LS/LIST has no `*`
multiline continuation (the fixed server-controlled cap set fits 512 today, so
latent until the set grows). Clean bills: the whole visibility surface
(+s/+p/+i correctly hidden across WHO/WHOIS/WHOWAS/NAMES/LIST, casefold-safe),
WHOX field parse/order, numeric codes and terminators, WHOWAS records; the
all-or-nothing CAP REQ, the SASL chunking/buffer bounds and 900-series
numerics, mechanism parsing; OPER constant-time auth, KILL teardown, DLINE-IP
non-evasion, the registration ban choke point, audit-log attribution; and the
MONITOR notification paths (nick-change/quit/kill/register), read-marker
monotonicity, and `account_connections` (no stale-ConnId leak). Verified beyond
the gate: full irctest main list (255 passed) and PG-backed services list (49
passed); migration 0029 applies cleanly across the 38-test PG db suite; the
fuzz crate builds under `--cfg fuzzing`.

Sixty-sixth sweep — four-front hunt: a bouncer that couldn't be
severed, proto round-trip corruption, and a concurrent-verify cross-wire
(2026-07-24): four parallel audits on the `e6irc-proto` wire crate, the
bouncer/BNC subsystem, the NickServ/ChanServ services surface, and the
concurrency/queue/worker plumbing. Eight confirmed bugs fixed:

1. **Removing a network did not stop its driver while a client was attached**
   (bouncer). The driver stopped only when every command sender dropped, but
   an attached client holds one — so an operator revoking a compromised
   network left its upstream TCP connection *and its decrypted SASL password*
   live until the last client detached. The registry now holds an authoritative
   `watch` shutdown the driver observes via `next_command`/`run_with_backoff`
   (attach never clones it), so removal severs the network regardless of
   attached clients; `attach` observes it too and detaches the client. Unit
   test drives shutdown with a command sender outstanding.
2. **`to_line()` could serialize a source that re-parsed to a different one**
   (proto). A `!`/`@` in the source name (or `@` in the user) placed a
   structural delimiter where `parse` splits, so `name:"a!b"` round-tripped to
   `name:"a", user:"b"` — silent structural corruption. The serializer now
   rejects it (`BadSource`), mirroring the anti-ambiguity checks the params
   already get; `!`/`@` in the host stay legal (they round-trip).
3. **`base64::decode` accepted non-canonical padding** (proto). The bits a
   padded group discards weren't checked for zero, so `"AB=="` and `"AA=="`
   both decoded to `[0]` — credential malleability on the SASL path. Now the
   discarded bits must be zero.
4. **`parse_server_time_millis` accepted impossible dates/times** (proto): the
   day was checked only `1..=31` regardless of month (`2026-02-31` rolled into
   March), `:60` seconds were accepted, and a signed year (`+526-…`) parsed. Now
   the day is validated against the real month length (leap years included),
   `:60` is rejected, and the year must be unsigned digits.
5. **The irc bouncer driver buffered its own keepalive PONG** (bouncer): the
   reply to its idle `PING :e6bnc-keepalive` fell through to the backlog, so a
   quiet network wrote ~720 junk lines/day, evicting real messages and showing
   keepalive noise on replay. Now dropped, mirroring the local driver.
6. **SET KEEPTOPIC ON did not re-capture the live topic** (services): turning
   retention back on left `registered_topics` empty (OFF had cleared it and the
   TOPIC path persists only on change), so the live topic was silently lost on
   the next empty→recreate cycle. Now recaptured on ON, mirroring registration.
7. **A SASL verify and a NickServ IDENTIFY verify could be in flight at once**
   (concurrency): both are offloaded (the only concurrent DB replies) and routed
   by ambient session flags, so an IDENTIFY reply landing mid-SASL was taken for
   the SASL result — logging the client in as the wrong (but self-owned)
   account. The two flows are now mutually exclusive: IDENTIFY refuses while
   SASL is verifying and the SASL verify-start refuses while an IDENTIFY is
   pending, so at most one credential check is outstanding and the reply is
   unambiguous. (Two overlapping IDENTIFYs stay allowed — each names an account
   the client proved it owns — bounded by the credential budget.)
8. **Stale `LineEvent::Line` doc** (proto): claimed "NUL-free" while the framer
   deliberately passes NUL through for `Message::parse` to reject. Comment fixed.

Surfaced, not changed: a *disabled* account network silently falls through to a
shared network of the same name on attach (resolving it needs a DB lookup in the
hot attach path; low-value, agent rated acceptable); the ChanServ SET
MLOCK/KEEPTOPIC and DROP hot-map updates use the same fire-and-forget-on-enqueue
pattern as the accepted TOPIC path (a rare DB-write failure diverges hot/DB
until restart — the high-value authoritative-answer cases were converted to the
reply-confirmed round-trip in sweeps 63/65; converting these three is a coherent
follow-up, not a rush alongside eight other fixes); and the deferred-reply hold
can reorder unrelated earlier output behind a later batch (both messages still
delivered — a minor ordering nit). Clean bills: proto mask/glob, casemapping,
tag escape symmetry, isupport, framing length/chunk logic, truncation
boundaries; the queue's waker protocol and no-lost-wakeup under the flagged
schedules; ConnId monotonicity; deferred-reply accounting (no double-release);
the verify semaphore (no permit leak); log-batch flush-before-read ordering; and
the bouncer's backlog ordering, buffer bounding, casefold keys, injection
sanitization, and attach authz. Verified beyond the gate: full irctest main list
(255 passed) and PG-backed services list (49 passed).

Sixty-fifth sweep — four-front hunt: silent DB-error fallbacks, a +C
multiline bypass, and a hot-map/DB divergence (2026-07-24): four parallel
audits on the persistence layer, the net/framing/reaper stack, the HTTP/OIDC
surface, and message routing/tags. Thirteen confirmed bugs, all fixed in one
pass. The dominant theme (three audits converged on it) was **DB errors folded
into plausible-but-wrong success answers** — the exact silent-fallback the
design laws forbid:

1. **CHATHISTORY / TARGETS / REST history answered an empty result on a store
   fault**, indistinguishable from a buffer with no history — a bouncer-style
   client caches "nothing here" for a window that exists. `query_history` and
   `query_targets` now return `Result`; the IRC path answers `FAIL CHATHISTORY
   MESSAGE_ERROR` (the same failure its enqueue-failure sibling already sent)
   and `/api/v1/history` answers 503, both instead of a misleading empty page.
2. **NickServ / ChanServ REGISTER silently vanished on a DB failure** — the
   `Unavailable` reply carried no origin, so it fell through every handler arm
   and the user's command got no response at all (a literal silent hang). The
   account and channel registration failures now carry their origin
   (`AccountRegisterUnavailable{origin}` / `ChannelRegisterUnavailable`) and
   each answers with a loud "temporarily unavailable".
3. **A founder transfer whose DB write *errored* was reported as the definitive
   "no such account"** — a lie the founder might act on (re-registering an
   account they were told doesn't exist). `set_channel_founder` now returns
   `Result<bool>`, and a store fault becomes `FounderChangeUnavailable` (say so)
   distinct from `FounderChangeFailed` (a real missing account).
4. **Channel-registration seeded the hot founder map from the live session, not
   the account the DB row was written with** — a LOGOUT/IDENTIFY racing the
   round-trip recorded the wrong founder (or none), diverging the hot map from
   the DB until restart. The reply now echoes `founder_account`; the handler
   uses it unconditionally.
5. **+C (no-CTCP) was bypassable via a multiline batch**: the check inspected
   only the first byte of the `\n`-joined blob, so a CTCP on line 2+ passed and
   re-emerged as its own PRIVMSG when the batch was flattened for non-multiline
   recipients. Now every line is checked (a single-line body has no `\n`, so
   it's unchanged there).
6. **The in-process `local` bouncer session was reaped every ~3 minutes**: it
   registers like a real session so the liveness reaper PINGs it, but it had no
   PONG logic and no network peer to answer — so it timed out, dropped, and
   reconnected, churning the "always-on" network. The local driver now answers
   the reaper's PING (and keeps it out of the user's buffer).
7. **`delete_bnc_network` was two standalone DELETEs** — a failure between them
   orphaned buffer rows that a later same-named network would replay as stale
   backlog. Now one transaction.
8. **`account_credentials.last_used_at` was exposed but never written** — every
   app password reported `null` forever, defeating a "is this credential still
   used?" audit. A successful verify now stamps the matched credential.
9. **The device-flow `user_code` had modulo bias** (31-char alphabet over 256):
   A–H were 12.5% likelier. Now rejection-sampled to uniform (RFC 8628 §6.1).
10. **A dead `VerifyPassword` arm in `handle_request`** duplicated the verify
    logic *without* the concurrency semaphore; unreachable today, it would
    silently lose the bound if a refactor routed through it. Now `unreachable!`,
    matching the `LogMessage` precedent.
11. **`audit_log_created_idx` served no query** (the reader orders by `id`) —
    pure write-time overhead on every audited action. Dropped (migration 0028).
12. **The OIDC callback error-path consumed the pending-auth entry before the
    state-cookie binding check** — an attacker who learned a victim's in-flight
    `state` could race `?error=…&state=<victim>` to burn the victim's login (a
    login-DoS), the exact guard the success path applies. The error path now
    binds-then-consumes too.

Also a channel registered *with a topic already set* never persisted it (the
TOPIC path persists only on change), silently breaking KEEPTOPIC for the
founder's initial topic — now seeded on `ChannelRegistered`.

Surfaced, not changed: the message-tags budget is not enforced on relay (our
own framer tolerates over-budget tag sections and a strict recipient is rare —
a low-value conformance gap that would touch every delivery path, deferred
rather than rushed); and the writer-first-close ghost-session window (already
documented in-code as a reaper-bounded tradeoff). Clean bills: ON CONFLICT ↔
constraint pairing, casefold discipline across every `name_folded` pair,
boot-load completeness, timestamp round-trips, transaction atomicity of the
account/OIDC/device paths, the framer's overflow contract, TLS handshake
timeouts, the queue waker protocol, SendQ accounting, reaper time arithmetic,
and the entire authZ/IDOR surface of the REST API (every `/me/*` scoped to the
caller, every `/admin/*` gated by a fail-closed extractor). Verified beyond the
gate: full irctest main list (255 passed) and PG-backed services list (49
passed) both green.

Sixty-fourth sweep — four-front hunt: a +i bypass, client exit-code
lies, and teardown/notify gaps (2026-07-24): four parallel audits on fronts
without a recent deep pass — IRCv3 capability machinery, channel
membership/modes, the client-side crates, and session/identity lifecycle.
Thirteen confirmed bugs, all fixed in one pass:

1. **Stale INVITE bypassed +i on a recreated channel** (found independently by
   two audits — the security finding of the sweep). Invites were stored on the
   *invitee's session* keyed by channel name, and channel teardown never
   cleared them: invite yourself via a throwaway channel, drop it, and the
   lingering entry admitted you through +i on any later channel reusing the
   name. Invites now live on the `Channel` (`invited: HashSet<ConnId>`,
   bounded per channel), so teardown revokes them by construction — the
   session-side leak is unrepresentable. Regression test drives the full
   invite → teardown → recreate+i → refused sequence.
2. **Unbounded list-mode masks broke the wire limit** — a ~490-byte `+b` mask
   produced a >512-byte MODE broadcast (discarded whole by recipients'
   framing while the ban was enforced — state desync; and an abort under the
   debug wire check), and RPL_BANLIST's 100-byte middle clip displayed a
   truncated mask that `-b` could never match (an unremovable ban). New
   `BANMASKLEN = 100` clips at store time (Solanum `clean_ban_mask`
   precedent), aligned exactly with `NUMERIC_MIDDLE_MAX`: stored = displayed
   = broadcast = removable.
3. **Post-registration SASL never broadcast `ACCOUNT`** to account-notify
   peers (the IDENTIFY and AccountCreated paths did — same state change,
   different door). `notify_account_change` now fires on the Verifying
   success branch; its `!registered` guard keeps connect-time SASL a no-op.
4. **A teardown from inside a labeled command swallowed the final ERROR** —
   the terminal `ERROR :Closing Link` was diverted into the labeled-response
   capture, and the wrapper only tried to deliver it after `close()` removed
   the session. `close()` now flushes a capture addressed to the dying
   connection before removal, so `@label=x QUIT` (and flood/credential
   kills inside labeled commands) close loudly again.
5. **Self-KILL audited with an empty actor** — `record_audit` ran after
   `close()` had removed the oper's own session. Audit now records first.
6. **`e6irc send` exited 0 on non-delivery** — post-PRIVMSG error numerics
   (401/404/…) were drained and discarded, and a connection close during the
   join-wait fell through to a PRIVMSG into a dead socket. The drain now
   fails on delivery-error numerics and the join-wait treats EOF as an error
   (same fix in `history`); `tail --count N` errors when the stream ends
   early. E2E test pins the non-zero exit.
7. **`e6irc raw` blocked the runtime on stdin** — a slow-fed pipe left server
   PINGs unanswered until the ping-timeout killed the session and the late
   lines went into a dead socket, exiting 0. Now async stdin `select!`ed
   against the socket, answering PINGs, erroring on unexpected close.
8. **TUI network task swallowed all outbound write failures** — typed
   messages were echoed into the buffer as sent and silently dropped forever
   on a half-broken socket. Write failures (including PONG) now surface
   `Disconnected` and end the task.
9. **The client library silently skipped malformed/over-long server lines**
   (including the framing layer's explicit `TooLong` signal, against that
   module's own contract). They are now loud `InvalidData` errors — framing
   already guarantees non-empty NUL-free lines, so anything unparseable
   means the peer is not speaking IRC.
10. **Load-harness setup could wedge forever with zero output** — the
    connect/register/join phase had no timeout, so a server that accepted
    TCP but stalled before 001 (the exact at-capacity condition the harness
    measures) hung every client behind the barrier. Setup is now bounded at
    30s, timing out into the counted-failure path.
11. **TUI attributed QUIT notices to every buffer** including queries with
    unrelated users; now scoped to channel buffers and the quitter's query.

Also surfaced, not changed: synchronous service NOTICEs are captured into a
labeled response while DB-deferred ones arrive later unlabeled — each label
still gets exactly one framed response, so this is a consistency observation
against ambiguous spec, not a violation. PASS remains deliberately
unimplemented (the irctest controller declares it). Clean bills: MONITOR
lifecycle, cap-gated broadcast filters, ISUPPORT-vs-enforcement, casefold
discipline (no raw-string bypasses), MODE param consumption, ban/quiet/invex
precedence, teardown parity across QUIT/KILL/GHOST/k-line/reaper, ConnId
monotonicity (no reuse hazards), the queue crate's waker protocol, and the
proto crate's escape/truncate symmetry. Verified locally beyond the gate:
the full irctest main green list (255 passed) and the PG-backed services
list (49 passed) both green.

Sixty-third sweep — ChanServ FLAGS phantom-grant divergence (2026-07-24):
closes the last item the sweep-60 ChanServ audit surfaced. `FLAGS <account>
+flags` updated the hot `channel_access` map **optimistically** — right after the
persist request was queued — while the DB write was a `SELECT`-guarded
`INSERT ... WHERE a.name_folded = $2` that writes *nothing* when the account
isn't registered. Granting flags to a name with no account therefore created a
hot entry the DB never held; if that name later registered and joined, it would
be **auto-opped from access it was never actually granted** (the hot map is what
auto-op consults on JOIN).

The fix mirrors the founder-transfer round-trip (sweep 60): `set_channel_access`
now folds channel+account internally and returns `Result<bool, DbError>` — the
`bool` is `rows_affected() > 0` on the ADD path (false when no account matched),
always true on the REMOVE path. The DB worker replies
`DbReply::ChannelAccessSet { channel, account, flags, applied }`, and *only* the
reply handler touches the hot map or notifies the founder: it inserts/removes the
entry and confirms "are now +X" / "Cleared flags" when `applied`, and when
`!applied` sends "is not registered; no flags set" and leaves the hot map
untouched. No path can now diverge the running server from storage. Regression
tests at both layers: a core test drives the full request→reply round-trip and
proves a grant to an unregistered "ghost" leaves no phantom entry and does not
auto-op ghost when it later registers; a PG-gated db test asserts the `applied`
bool (true for a registered account, false for a phantom) and that the phantom
grant leaks no row. With this every item from the sweep-60 audit is closed.

Sixty-second sweep — CHATHISTORY BETWEEN pivot resolution (2026-07-24):
the finale of the CHATHISTORY hardening arc begun in sweep 60. Sweeps 60–61
fixed the missing-msgid pagination dead-end (Bug 1) and the ring↔DB boundary
disagreement (Bug 2); this fixes the last two, both in the DB-path BETWEEN
dispatch.

**`BETWEEN` derived its span bounds and paging direction from a *ring-only*
lookup** (`selector_ts`), so when a `msgid=` pivot had scrolled out of the ring:
- a mixed `msgid=`+`timestamp=` BETWEEN **lost the msgid bound** (`selector_ts`
  returned `None` → the code substituted a degenerate `0` / `u64::MAX`),
  returning a wildly-wrong window; and
- a two-`msgid` BETWEEN given newest-first **collapsed the direction to
  oldest-first** and mis-oriented the `(after, before)` bounds into an inverted,
  always-empty SQL range — a silent data loss on a legitimate reverse page.

The two selectors now travel to the DB unresolved as a new
`HistoryQuery::BetweenSelectors { first, second, limit }` (a `SelectorBound` is a
`Msgid` or a `Timestamp`), and `query_between_selectors` resolves each pivot's
`(ts, id)` position **in PostgreSQL** — a msgid via a scoped lookup, a timestamp
via `id` sentinels (`MAX`/`MIN`) that make its bound `ts`-only. It orders the two
pivots by their real `(ts, id)`, derives the direction from the argument order,
and runs one composite-`(ts, id)`-bounded query, so the span and the `limit` cut
are correct regardless of whether either pivot is still in the ring. This
replaces the old `Between` and `BetweenMsgid` variants with the one unified path
(the DB layer no longer duplicates a timestamp and a msgid form). A new PG-gated
test pins the reversed-order, mixed, and unknown-pivot cases; the existing
BETWEEN tests were rewritten onto `BetweenSelectors`; the `chathistory` services
irctest stays green.

With this the CHATHISTORY arc is complete: all four bugs the sweep-60 audit found
(pagination dead-end, ring↔DB boundary, mixed-BETWEEN bound loss, reversed-BETWEEN
inversion) are fixed, each with tests, across three focused sweeps rather than one
rushed rewrite. The one remaining item from that audit — the `FLAGS
<unknown-account>` hot/DB divergence — was closed in sweep 63.

Sixty-first sweep — CHATHISTORY ring↔DB boundary unification (2026-07-24):
the continuation of sweep 60's scoped CHATHISTORY work. Sweep 60 fixed the
missing-msgid pagination dead-end (Bug 1); this sweep fixes the ring-vs-DB
boundary disagreement (Bug 2), the largest remaining piece.

**The ring answered AFTER / bounded-LATEST / BETWEEN with different boundary
semantics than the PostgreSQL fallback** (`history.rs`), so the two paths could
return *different rows for the same request* — violating the design invariant
that CHATHISTORY must not answer differently by source. The ring resolved a
`timestamp=T` pivot to "first entry with `ts >= T`" and then did `skip(pos+1)`,
while the DB uses strict `ts > T`:
- `AFTER timestamp=T` where `T` fell *between* two messages dropped the first
  message after `T` (the ring skipped it; the DB included it).
- `AFTER`/bounded-`LATEST` with a pivot *older than the ring's oldest* not only
  hit that off-by-one but also reported `covered = true`, so the DB was never
  consulted and evicted messages between `T` and the ring were silently missed.
- The `BETWEEN` lower bound had the same `skip(pos+1)` off-by-one for a
  timestamp between messages.

`resolve_ring_window` was rewritten around explicit *lower-exclusive* (`ts > T`
/ after-the-msgid) and *upper-exclusive* (`ts < T` / before-the-msgid) boundary
helpers that match the DB exactly, with `covered` computed correctly for the
pivot-older-than-ring case (AFTER/LATEST/BETWEEN now defer to the DB when the
oldest row they'd return could be evicted). The BETWEEN direction and bounds are
derived by ordering the two pivots by how many entries precede each, not by a
ring-only timestamp compare. The exhaustive differential test's reference impl
was independently rewritten to the DB-strict spec (so ring == reference == DB),
its adversarial alphabet already exercises timestamps that land between messages
and past the ring, and focused tests pin the specific boundary cases. The
`chathistory` services irctest (ring + DB together) stays green.

Still deferred — the two BETWEEN DB-path bugs sweep 60 named (c/d), which are
independent of the ring and need DB-side pivot resolution: a mixed
`msgid=`+`timestamp=` BETWEEN whose msgid has scrolled out of the ring loses the
msgid bound (`selector_ts` is ring-only), and a newest-first two-`msgid` BETWEEN
past the ring mis-derives direction and returns an inverted empty range. Both
require resolving a `msgid=` pivot's `(ts, id)` in SQL (a preliminary lookup or
a self-orienting query) rather than depending on the ring — a distinct, contained
piece with its own DB integration tests, kept separate from this
ring-semantics rewrite rather than rushed alongside it. Also still open: the
`FLAGS <unknown-account>` hot/DB divergence (needs the founder-transfer
round-trip).

Sixtieth sweep — CHATHISTORY pagination dead-end, a ChanServ DROP
divergence, and DB-worker head-of-line blocking (2026-07-24): two deep audits
(the CHATHISTORY PostgreSQL query path, and the ChanServ/mlock/founder
subsystem) plus a scoped robustness fix.

1. **Backward CHATHISTORY pagination silently dead-ended one page past the ring
   edge** (`history.rs`) — `needs_db_for_missing_ref` only routed a `timestamp=`
   pivot to the DB, so a `msgid=` pivot that had scrolled out of an incomplete
   ring was treated as "no such/older history" and the DB was never queried,
   even though `BeforeMsgid`/`AfterMsgid`/`AroundMsgid` pivot on it in SQL. A
   client paging backward with successive msgid pivots hit an empty batch and
   believed history had ended. Now a missing `msgid=` (like `timestamp=`) on an
   incomplete ring routes to the DB. The exhaustive differential test's
   reference was updated to match, and a focused test pins it.
2. **ChanServ DROP orphaned the mode lock and keeptopic override in hot state**
   (`services.rs`) — DROP cleared `registered_founders`/`registered_topics`/
   `channel_access` but not `channel_mlock` or `keeptopic_off`, while
   `drop_channel` deletes the whole `channels` row (both are columns on it). A
   dropped-then-recreated channel reapplied a stale `+mlock` the DB no longer
   held (and a member couldn't remove it, since `mlock_conflict` has no
   `is_registered` gate), then a restart silently flipped the behavior back. Now
   DROP clears all five registration-scoped maps. Regression test.
3. **The DB worker serialized argon2 verifies head-of-line** (`db.rs`) — every
   `AUTHENTICATE` awaited its ~tens-of-ms argon2 verify inline, so a burst of
   logins queued CHATHISTORY reads and account lookups behind one verify at a
   time (a latency cliff and a cheap DoS amplifier). Password verification is a
   pure read with no ordering dependency, so it now runs off the worker loop
   bounded by a 4-permit semaphore — decoupling auth latency from history reads
   without turning it into a memory DoS (each argon2 is ~19 MiB, so an unbounded
   spawn would be worse). Account creation (a rare write) stays inline.

Investigated and *surfaced, not fixed* — three further CHATHISTORY DB-path bugs
found by the audit that are entangled and need a coordinated ring/DB/reference
rewrite (a botched CHATHISTORY-semantics change would be worse than the narrow
existing bugs, so they get a dedicated pass rather than a rushed one alongside
the DB-worker refactor): (a) ring vs DB disagree on AFTER / bounded-LATEST at a
`timestamp=` pivot that falls *between* messages — the ring uses `ts >= T` +
`skip(pos+1)` while the DB uses strict `ts > T`, and the "pivot older than the
ring" case additionally drops the ring's oldest row and misses evicted rows;
(b) a mixed `msgid=`+`timestamp=` BETWEEN silently loses the msgid bound when the
msgid has scrolled out of the ring (`selector_ts` is ring-only → substitutes a
degenerate `0`/`u64::MAX`); (c) a newest-first BETWEEN on two msgid pivots past
the ring collapses `newest_first` to false (ring-only direction detection) and
returns an inverted empty range. The shared root cause is that msgid→position
resolution is done only against the in-memory ring; the durable fix is to let
the DB resolve any `msgid=` pivot's `(ts, id)`. Also surfaced: a `FLAGS
<unknown-account> +flags` creates a hot/DB divergence (hot map updated
optimistically, DB `SELECT`-guarded INSERT writes nothing) — needs the
founder-transfer round-trip pattern.

Fifty-ninth sweep — hardening + fidelity: OIDC config-safety, a CSRF
cache leak, and query fidelity (2026-07-24): four deep audits (OIDC/Shauth
token validation, async cancellation/task-lifecycle, the web frontend, and the
load harness + low-traffic command fidelity) found the *core* sound —
ID-token/nonce/PKCE/state validation is correct and `alg:none`-safe; the
concurrency design has no cancellation-unsafe select, lock-across-await, or task
leak; the web client keeps the session token out of JS and escapes all DOM
sinks. The actionable output is six defense-in-depth / config-safety / fidelity
fixes, all landed here in one PR.

1. **Require an HTTPS OIDC issuer in production** (`config.rs`) — discovery and
   JWKS are fetched from `issuer_url`, so a plaintext issuer lets an on-path
   attacker inject signing keys and forge ID tokens. `Config::validate` now
   rejects an `http` issuer when `secure_cookies` is set (a dev setup with
   `secure_cookies = false` may still use http locally).
2. **Reject duplicate OIDC issuers** (`config.rs`) — two providers sharing an
   `issuer_url` would collide on the `(issuer, subject)` account key, resolving
   one provider's subject to the other's account. Rejected at load.
3. **Rate-limit the front-channel logout endpoint** (`http/oidc.rs`) — unlike the
   signed back-channel path it has no token to verify and revokes a session by a
   guessable `sid`, so it is now per-IP `auth_rate_ok`-gated like the other
   unauthenticated OIDC endpoints, blunting `sid` brute-forcing.
4. **`/api/v1/me` is now `no-store`** (`http/device.rs`) — its body carries the
   session-bound CSRF token, so it must not sit in a shared/proxy cache (a
   sibling handler already did this; `me` was missed).
5. **ISON echoes the canonical nick casing** (`query.rs`) — `ISON AlIcE` for
   online `alice` now replies `alice` (Solanum behaviour) instead of the caller's
   input casing; the lookup was already casefolded, only the echoed label was raw.
6. **WHOWAS reports a last-seen time** (`state.rs`, `query.rs`) — `RPL_WHOISSERVER`
   carried a `(unknown)` placeholder; `WhowasEntry` now records a `signoff`
   timestamp (from the clock) and the 312 shows it, matching Solanum/Ergo.

Investigated and *not* changed (surfaced, not swallowed): the app ships only a
`frame-ancestors 'none'` CSP, so HTML escaping is the sole XSS barrier — a real
`script-src` needs per-response nonces for the two inline blocks (deferred rather
than risk breaking them). The DB worker serializes argon2 verifies head-of-line,
delaying history reads — but making them concurrent would trade that latency for
a *memory* DoS (each argon2 is 19 MiB) without a concurrency bound, so it needs a
bounded-parallelism design, not a naive spawn. The core queue wakes all parked
producers per pop (a thundering herd under sustained overload) — an efficiency
issue in the loom-verified queue primitive, left alone rather than risk a subtle
lost-wakeup. Graceful shutdown (last DB batch dropped on kill), the OIDC
link-flow Shauth gate / optional `typ` / unchecked `iat`/`nbf`, and the load
harness's fan-out duplicate-delivery blind spot are all noted for later.

Fifty-eighth sweep — four-front hunt: a client SASL hang, an AccountKey
invariant, and SQL-index/robustness fixes (2026-07-24): four parallel passes
(client crates, the `AccountKey` typed-key invariant, SQL migrations/schema, and
a whole-binary panic audit) produced one systematic invariant + four concrete
fixes. The panic audit found no new reachable panic in the core — the prior
sweeps plus the fuzz harness have closed that class (a documented negative).

1. **The IRC client hung forever on a SASL-reject numeric** (`e6irc-client`) —
   `await_authenticate_challenge` treated only EOF or `AUTHENTICATE` as terminal,
   so a server that answered `AUTHENTICATE PLAIN` with `904`/`905`/`906`/`908`
   (or a `433`-class registration refusal) and held the socket open span the loop
   forever with no timeout. Its sibling wait loops already fail loudly on those
   numerics; this one was missed. Now terminal, and both SASL sub-loops answer
   PING (a strict server no longer ping-timeouts a login mid-CAP/-auth) and treat
   an `ERROR` line as terminal. Regression test drives a hostile mock server over
   an in-memory duplex pipe.
2. **`AccountKey` makes the account casefold-mismatch bug class unrepresentable**
   (`state.rs`, `read_marker.rs`, `services.rs`). Accounts were the one identity
   with no typed key (`ChanKey`/`NickKey` already exist): `read_markers` keyed on
   the *display*-cased account while `registered_founders`/`channel_access` keyed
   on the *folded* one. No live bug today (every login canonicalizes the account
   casing), but the disagreement was latent-fragile. A new `AccountKey(String)`
   newtype, built only via `ServerState::account_key`, now types all three
   in-core maps — folding `read_markers` into line with the others. The DB stays
   invariant-safe at the `name_folded` edge, so no SQL churn.
3. **`oidc_logout_tokens` had no `expires_at` index** (`migrations/0026`) — it is
   pruned on every back-channel logout (`DELETE … WHERE expires_at <= now()`),
   the same prune-on-write pattern migration 0021 indexed for the other tables,
   but this one was left out, so each logout did a full seq scan on a growing
   table. New index.
4. **The `messages` history index didn't cover `(ts, id)`** (`migrations/0027`) —
   CHATHISTORY orders and pivots on the composite `(ts, id)`, but the index was
   only `(target, ts)`, forcing a sort on equal-millisecond ties. Replaced with a
   covering `(target, ts, id)` index (the old one was a prefix, so nothing
   regresses).
5. **One duplicate msgid could drop a whole history batch** (`db.rs`) — the
   batched `INSERT INTO messages` had no conflict handling, so a single
   `UNIQUE(msgid)` violation aborted the statement and lost up to N unrelated
   messages. Added `ON CONFLICT (msgid) DO NOTHING` so a stray duplicate only
   drops itself.

Investigated and *not* changed (surfaced): `bnc_buffer` rows orphan on account
deletion (no FK) — but there is no runtime account-deletion path, and an FK would
break shared ownerless (`*`) networks, so it stays latent; the client silently
drops an over-long server line and does not neutralize BiDi/zero-width display
spoofing (display-only, ratatui already filters control chars).

Fifty-seventh sweep — four-front bug hunt: silent driver death, a
read-marker sentinel collision, and SSRF/keepalive hardening (2026-07-24): four
parallel adversarial passes (read-marker/CHATHISTORY, BNC irc/local drivers,
HTTP REST/pages, casemapping/keys/identity) surfaced five concrete defects, all
fixed here in one PR.

1. **The `local` BNC driver had no reconnect and died silently** (`local_driver.rs`)
   — unlike every other driver, it ran outside `run_with_backoff`, so a core-side
   close (an operator KILLs the BNC user, or the core drops the in-process conn)
   exited the task forever: no `Disconnected` event, no reconnect, and the sticky
   `is_connected()` flag stuck `true`. It now reconnects with a fresh `ConnId` and
   emits `Disconnected` like the others.
2. **A read-marker first-set to the Unix epoch was silently not persisted**
   (`read_marker.rs`) — the account path used `Millis(0)` as an "unset" sentinel,
   but `0` is a legitimate marker value (`1970-01-01T00:00:00.000Z`), so a
   first-ever set to it (`0 > 0` is false) updated the in-core mirror but skipped
   the DB write, diverging the two (and, repeated, filling the account's marker
   quota with un-persisted phantoms). Persistence now keys off marker *presence*,
   not the sentinel — a first set always persists, whatever its value.
3. **An authenticated user could make the server dial an internal address**
   (`http/networks.rs`) — the network `addr` was validated only for emptiness, so
   any tenant could point a network at `169.254.169.254` (cloud metadata) etc.,
   which the server then dials on a reconnect loop. Create-time validation now
   refuses the link-local metadata range, unspecified, multicast, broadcast and
   documentation IP literals. Loopback and RFC-1918 / unique-local private ranges
   stay allowed, because a self-hosted or LAN IRC upstream (including
   `127.0.0.1`) is a first-class e6irc use case — the sharp, zero-false-positive
   vector is the metadata endpoint.
4. **The `irc` upstream driver could wedge on a half-open peer** (`irc_driver.rs`)
   — `connect_once` bounds connect + registration, but the steady-state read
   blocked forever if the upstream half-opened (firewall drop, peer vanishes),
   starving the reconnect loop with `is_connected()` stuck true. It now sends a
   keepalive PING on an idle gap and drops if the next gap passes unanswered.
5. **`account_connections` compared accounts with raw `==`** (`state.rs`) — the
   one account comparison in the core that bypassed the casemap, a latent
   silent-no-op (a MARKREAD sibling-sync miss) if a session ever held a
   non-canonical account label. It now folds both sides like every other account
   comparison. Boy-scout hardening of the "make casefold bugs unrepresentable"
   invariant; also validated network `nick`/`realname`/`autojoin` against CR/LF/NUL
   injection and bounded their lengths.

Investigated and *not* changed (surfaced, not swallowed): accounts still lack a
typed `AccountKey` wrapper and the DB/HTTP layers fold with a hardcoded
`Rfc1459` literal in ~25 sites rather than sourcing `state.casemap` — both are
latent invariant-bypasses that hold today (rfc1459 is the only mapping and every
login canonicalizes the account casing), but would become live bugs if casemap
became configurable; a full `AccountKey` refactor is deferred rather than
ballooned into this PR. The draft/read-marker `services` irctest cases
(persist-across-reconnect, cross-session propagation) are not in e6irc's green
list and fail on `main` independently of this sweep — noted for a future look.

Fifty-sixth sweep — four-front bug hunt: TLS slow-loris, an argon2 DoS,
a WHOX overflow, and bridge/proxy hardening (2026-07-23): four parallel
adversarial passes (Matrix bridge, numerics/ISUPPORT, rate-limiting/flood, and
TLS/net/proxy) surfaced eight concrete defects, all fixed here in one PR.

1. **The TLS handshake had no timeout** (`net.rs`) — a peer that finished the TCP
   connect but never sent (or dribbled) a ClientHello held a task, an fd, and its
   per-IP slot indefinitely, *invisible to the reaper*: `Input::Open` only
   reaches the core (and thus the liveness deadline) after the handshake. A
   plaintext peer has no such window. The handshake is now bounded (30s, matching
   the registration budget) and dropped loudly on elapse.
2. **NickServ IDENTIFY / REGISTER (and the IRCv3 `REGISTER` command) drove
   *uncapped* argon2 work** (`services.rs`, `registration.rs`) — SASL caps
   credential verifications at 8/connection, but these three argon2-driving paths
   spent from no budget, so a single connection could loop them for unbounded CPU
   + memory (a global stall on the one core worker) and an online-brute-force
   bypass. All now spend from one shared per-connection budget
   (`credential_attempt_ok`, renamed from `sasl_attempt_ok`), closing the class:
   any command that can trigger an argon2 op charges the same counter.
3. **WHOX `RPL_WHOSPCRPL` (354) could exceed the 512-byte wire limit** — it packs
   up to 12 middles plus a client-influenced realname trailing, and on a server
   with a long name or large `nicklen` their sum overflowed, so the recipient's
   framing discarded the whole row silently. The `numeric` funnel now fits the
   *trailing* against the accumulated head, bounding every numeric at one place
   (a `numeric_list` page is already built to fit, so it's a no-op there).
4. **The Matrix "not delivered" NOTICE interpolated a raw, unbounded
   homeserver room id** (`matrix.rs`), reintroducing the silent-drop class the
   `unmapped_target_notice` path already fixed: an over-long notice is discarded
   whole and the failure goes silent. A shared, length-bounded `undelivered_notice`
   helper now backs the Matrix, Discord, and Slack failure notices alike.
5. **The Matrix room-alias channel name was never validated** (`matrix.rs`),
   unlike Slack/Discord — a misconfigured alias could put a space/`:` into a
   PRIVMSG middle parameter. It now validates with `sanitize::valid_channel_name`
   and refuses the network loudly.
6. **`client_ip` silently skipped `ip:port` / bracketed-IPv6 `X-Forwarded-For`
   entries** (`http`), so a proxy that annotates ports made the resolver skip the
   real client and fall back to a spoofable left-hand entry or the proxy's own IP
   — collapsing per-IP rate limits and bans onto one key. XFF parsing now
   tolerates those forms.
7. **`CASEMAPPING` was hardcoded in 005** (`query.rs`) instead of derived from the
   active mapping — correct today, but it would silently lie the moment casemap
   became configurable. Now `state.casemap.isupport_token()`.
8. **`server_name` / `network_name` had no length bound** (`config.rs`); an
   over-long `server_name` inflates every numeric's overhead (feeding #3) and an
   over-long `NETWORK=` was silently clipped. Both are now bounded (≤ 64) at load.

Investigated and *not* changed: the per-IP connection cap is opt-in by design
(no global accept ceiling) — noted as a hardening candidate rather than a bug;
the `auth_buckets` map can grow past its soft 4096 bound under a many-source
attack (memory-only, throughput-throttled); and the Matrix reconnect re-syncs
rather than resuming (a documented durability tradeoff, not a defect).

Fifty-fifth sweep — four-front bug hunt: info-disclosure, a ban-evasion
transport, and delivery/history fidelity (2026-07-23): four parallel adversarial
passes (WHO/WHOIS/NAMES/LIST visibility, message routing/echo, history/DB
persistence, config/oper/admin) surfaced eleven concrete defects, all fixed here
in one PR. (A twelfth candidate — a self-directed message "delivered twice" with
echo-message — was investigated and found *correct*: the recipient copy plus the
labeled echo are both required by the labeled-response spec, and irctest
`testLabeledPrivmsgResponsesToSelf` / `testMessagesToSelf` assert exactly two
messages with one label. No change made.)

*Information disclosure.* (1) **`+i` invisible members leaked through channel
`WHO` and `NAMES`** to a non-member of a public channel — the invisible filter
existed only on the wildcard branch of WHO. Both now apply the shared rule
(hidden from an outsider who shares no channel; fellow members still see each
other). (2) **A literal, wildcard-free host `WHO 10.0.0.5` bypassed the `+i`
gate**, since the mask matched host as well as nick; "named exactly" now means a
wildcard-free *nick* match specifically.

*A whole transport that evaded server bans.* (3) **Every IRC-over-WebSocket
session was opened with the literal host `"websocket"`**, so KLINE/DLINE never
matched and a banned user reconnected freely through `/ws/irc` (and every WS user
shared one hostmask). It now uses the real client IP (X-Forwarded-For only via a
trusted proxy), exactly as the raw-TCP path does.

*Operator surface.* (4) **`OPER` leaked operator-name existence by timing** —
an unknown name skipped the SHA-256 compares that a wrong password performs; the
compare now always runs against a dummy secret. (5) **Config accepted an empty
oper name/password or duplicate names silently**; `validate()` now rejects them
loudly like every other subsystem.

*Message delivery.* (6) **The `+C` (no-CTCP) ACTION exemption was a prefix
match**, so `\x01ACTIONX\x01` / `\x01ACTIONVERSION\x01` slipped through; it now
requires the exact `ACTION` tag (bare, space-delimited, or `\x01`-closed).
(7) **A labeled multiline batch hung a client that lacked echo-message** — the
label rode only the echo copy, so no response and no ACK ever arrived; a labeled
`ACK` is now emitted on the success path (mirroring the failure path). (8)
**`TAGMSG @#chan` ignored the STATUSMSG sigil** and answered `ERR_NOSUCHNICK`; it
now routes to the op/voice subset like PRIVMSG.

*History / DB.* (9) **CHATHISTORY TARGETS over the PostgreSQL path emitted DM
correspondents as raw identities** (`~nick` / folded account) instead of display
nicks — the no-DB path converted, the DB path did not. `targets_page` is now the
single conversion site for both. (10) **Deleting a BNC network orphaned its
`bnc_buffer` rows** — the delete matched the raw account while the buffer is
keyed by the *folded* owner, so backlog leaked and a same-named network replayed
it; the delete now binds the folded owner. (11) **A malformed `timestamp=`
CHATHISTORY selector silently defaulted the window bound** (latest-N, or an empty
window) instead of `FAIL … INVALID_PARAMS`; it is now rejected up front.

The passes also cleared: admin-API authz (unforgeable `AdminAccount` extractor,
fail-closed on empty admin set), TLS/startup (loud errors, no silent
TLS-disable), the composite `(ts,id)` msgid-pivot paging, read/write casefold
symmetry for the `messages` table, and the WHOX field parsing/order.

Fifty-fourth sweep — four-front bug hunt: a silent-hang liveness leak,
case-inconsistent bans, phantom mode broadcasts, spec gaps (2026-07-23): four
parallel adversarial passes (connection lifecycle, byte-level I/O, IRCv3 state
machines, channel modes/permissions) surfaced six concrete defects, all fixed
here in one PR.

1. **A deferred `REGISTER` reply leaked on transient DB failure** — a live-client
   silent hang. `DbReply::Unavailable`/`PasswordRejected` carry no origin, so the
   `db_reply` arm handled SASL-verify and NickServ-identify but never a deferred
   `REGISTER`: its hold on the connection's output was never released, and the
   client — receiving neither its `FAIL` nor even the liveness `PING` (also held)
   — was eventually ping-timeout-reaped. A new `Session::pending_register` flag
   routes the origin-less reply back to REGISTER, emits the owed
   `FAIL … TEMPORARILY_UNAVAILABLE`, and releases the defer. Regression test
   proves the hold lifts (a pipelined PING gets its PONG).
2. **List-mode removal/dedup was case-sensitive while matching is case-
   insensitive** (`channel.rs`). `+b/+q/+e/+I` match subjects under the
   casemapping, but add-dedup and removal compared masks with raw `==`, so
   `-b FOO!*@*` failed to remove a ban stored as `foo!*@*` (leaving it enforced)
   *while broadcasting the removal as success*, and cross-case adds double-stored
   one logical ban against `MAXLIST`. New `mask::eq` folds comparisons the same
   way the matcher folds subjects.
3. **No-op mode changes were broadcast as real transitions** (`channel.rs`).
   Re-setting an already-set boolean mode, re-op-ing an existing op, re-adding a
   present ban, or clearing an unset key/limit all emitted a phantom `MODE` that
   desyncs state-tracking clients. Every arm now announces only a change that
   actually happened (Solanum semantics).
4. **`CAP LIST` omitted `draft/multiline` and `draft/account-registration`**
   (`registration.rs`). Both are fully enabled by `CAP REQ` but tracked outside
   `CAP_NAMES`, and only `sasl` was special-cased in LIST — so a client
   re-syncing its negotiated set was told an enabled cap was off. Now enumerated
   symmetrically.
5. **CHATHISTORY accepted `*` for non-LATEST subcommands** (`history.rs`). `*` is
   the open bound, valid only for LATEST; for BEFORE/AFTER/AROUND it silently
   returned an empty batch, and for BETWEEN it degenerated to an unbounded full
   scan (`0 .. u64::MAX`). Now a hard `FAIL CHATHISTORY INVALID_PARAMS`.
6. **The WebSocket outbound path silently mutated content** (`http/ws.rs`).
   `String::from_utf8_lossy(&bytes).trim_end()` stripped *all* trailing
   whitespace — dropping significant trailing spaces in a `:`-prefixed trailing
   parameter — and corrupted non-UTF-8 message bytes into U+FFFD. Now strips only
   the exact `\r\n` terminator and sends a binary frame for non-UTF-8 rather than
   lossily replacing it. Boy-scout: `bouncer/serve.rs` now references
   `MAX_CLIENT_FRAME_LEN` instead of the hand-computed `4096 + 510`.

The passes also cleared: `LineBuffer::feed` is provably chunk-independent and
bounds its buffer at `limit + 1`; the send queue's backpressure/SendQ-kill is
exact and deadlock-free; nick/account/membership/monitor indices are all cleaned
up on close; SASL chunk reassembly, MONITOR lifecycle, and the CHATHISTORY ring
arithmetic (exhaustive differential test) are sound.

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
  without looping. A silent probe answered `consent_required` — the browser
  holds a provider session but has never authorized this client, which is what
  a relying party sees on its first visit — took one ordinary authorization
  request instead, so a first-party application joins an established single
  sign-on session with no interaction; probing alone can never record the
  missing consent, so treating it as "not signed in" stranded a signed-in user
  on the sign-in page. Token-endpoint client authentication became an explicit
  `token_endpoint_auth_method` on each provider, because the method is a
  property of the client *registration* that discovery cannot report; Shauth
  registers managed applications with `client_secret_post`.
  The account and validation pages published the signed-in user as
  `data-shauth-user` and the real sign-out control as `data-shauth-sign-out`,
  so post-deployment qualification exercises the interface a person uses.
  User-facing logout used top-level RP-initiated navigation,
  returned through the e6irc public URL, and refused incomplete provider or
  storage state without deleting the local session.
  Verified end-to-end against dockerized dex + PostgreSQL, and against a real
  Shauth, Ory Hydra, PostgreSQL, two-relying-party, and Chromium stack
  (`tools/test-shauth-sso.sh`) covering direct entry, catalog entry, single
  sign-on into a second application, application-initiated and
  provider-initiated logout, and fail-closed re-entry.

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
