# e6irc plan

The product has IRC, PostgreSQL, accounts, `/api/v1`, OpenID Connect, BNC, web
chat, native clients, Matrix, and an API-first console. CI tests all supported
platforms, browsers, PostgreSQL, recovery, containers, fuzzing, and load smoke.

## Completion

Complete means: one API contract; usable browser chat and console; API and
browser evidence for shipped workflows; and measured release, recovery, scale,
and integration claims.

## Current state

The console reads and writes only through `/api/v1`. Browser chat and console
load the served OpenAPI contract, parse each successful API response into a
closed immutable projection, and serialize each JSON mutation from its closed
request shape before a view uses or sends it. Browser chat does the same for UI
WebSocket events and composer requests. Immutable console mutation operations
are checked against the router. Successful mutations refresh their API-backed
view without a document reload. Bridge provider frames and REST bodies cross
typed contracts. Server routes emit closed response models, including one
current-schema observability snapshot/history contract and a bearer-protected
deployment-neutral application observation derived from the same real counters;
URL queries and forms reject unknown fields. Owner, administrator, and static
network creation use
the same explicit driver, transport, and identity fields; kind-specific
requests reject incompatible fields.
Container startup validates rendered TOML through the daemon parser. Managed
configuration schema changes migrate persisted rows with their historic explicit
behavior; new configuration never receives an implicit decode default.
History accepts one typed cursor window and a bounded page size.
Chat, console, and identity pages share the relay-desk visual system and
accessible light, dark, and forced-colors palettes. Both network forms read one
server-side preset catalog (`GET /api/v1/network-presets`), use one vocabulary,
ask first for what a known network cannot supply, and keep the rest under an
Advanced disclosure. The chat client opens an account's sole runnable network
by itself (with several, the person chooses), opens a network it has just added, and has one control for each thing: one network
list, one Server log switch, one command reference. The console navigation
leads with the account holder's own pages and groups the administrator's. Browser snapshots cover all
three shells; interaction tests cover WCAG AA contrast, keyboard focus, Escape
dismissal, reduced motion, responsive controls, and non-interactive unavailable
network routes. On phones, the console brings its active route into the
horizontal navigation viewport. Confirmations repeat the initiating action,
preserve its submitted name and value, and reset cancellation state on every
opening. API-backed forms expose the exact initiating action as in progress and
share one per-form guard that disables every submit route until the mutation and
view refresh finish, preventing duplicate keyboard, pointer, or scripted
submissions. Dynamically rendered console tables and logs use shared constructors
for named keyboard-focusable regions. The terminal UI carries the same
relay-desk hierarchy through an explicit route/status strip, active-first
conversation rail, scrollback and unread state, and a visible
horizontally-following composer.
Its closed slash-command grammar retains malformed input, supports direct and
raw messages, and advances read markers only when the user reaches the live
edge.
External qualification has one manual GitHub workflow. It selects one closed
campaign, refuses local provider oracles, and uploads only evidence accepted by
the runner verifier. Its Discord, Slack, and OpenID Connect boundaries use
closed request, response, and WebSocket-frame contracts.
The qualification runner recorded live public IRC campaign evidence for
Libera.Chat, OFTC, and Ergo on 2026-08-13; that evidence qualifies the runner's
egress, not an arbitrary deployment. A 2026-08-23 qualification from the
Scaleway production container proved registration and configured-channel joins
against OFTC and Ergo Testnet. The same deployed IPv4 egress was explicitly
rejected by Libera until it supplies an existing email-verified NickServ
account through SASL, and the container has no routable IPv6 fallback. Libera
therefore remains disabled there rather than being misreported as fixed.
A 2026-09-20 run from a residential egress proved the whole product path against
Libera without SASL: browser dialog, creation, driver registration, configured
channel join, attach, and send. The same run found why supplying an existing
account never worked from the chat client, and what a rejected account then did:

- The chat client sent its network create and edit requests without the
  session's `X-E6IRC-CSRF` value, so every save was refused with 403 and
  credentials could never be stored from the dialog built for them. The shared
  API contract module now owns that header and `Content-Type` and refuses an
  unsafe method without the token before it reaches the network.
- Rejected credentials were re-sent after 200ms, 400ms, 800ms, and 1.6s. They
  now park on the first rejection. Other registration refusals retry after 30s,
  1m, 2m, and 4m, keep the upstream's reason visible while they wait, and park
  on the fifth in a row.
- A server `ERROR` during capability discovery or SASL — Libera's throttle and
  ban answer — was an untyped transient drop whose text was discarded, and any
  transient drop reset the park count, so a refusing upstream's own throttle
  kept the driver re-dialing forever. `ERROR` is now one typed refusal at every
  pre-welcome stage, and only a session that registered resets the count.
- `PATCH {"enabled": true}` on an enabled network panicked the handler on a
  registry assertion. The registry now refuses an occupied key before a second
  driver starts; create and edit supersede, enable means ensure-running.
- The chat client read the network list once, rendered it in three places, and
  let them contradict each other and the server: a network parked on rejected
  credentials kept reading "connected". There is one list, re-read every ten
  seconds, that quotes the upstream's own reason beside the settings control.

The driver no longer answers a taken nickname by silently registering as
`nick_` (and only when SASL was off). It offers the configured nickname only,
reports the refusal with the upstream's text, retries on the refusal schedule
so a ghost of its own session can time out, and parks if the nickname stays
taken.

Neither browser surface gates saving on a connection test: **Test connection**
is an optional diagnostic that says `QUIT` when it is done. The console has a bounded,
owner-scoped component-log view for IRC and every bridge driver. Its API reads
the live buffer while active and persisted history after stop; typed lifecycle
and operational failures are safe notices, and storage-failure notices cannot
retry through the failed writer. Administrators also have a bounded live server
log for fixed operational error classes. It excludes request data, IRC traffic,
and secrets; the durable audit log remains the source for privileged actions.
The BNC and browser attach paths now reconcile a typed authoritative IRC
session snapshot after bounded replay. Their subscription and buffer snapshot
form one atomic replay/live boundary, and a client that overruns bounded live
delivery is visibly detached instead of retaining stale session state. Browser
attach status uses monotonic driver revisions, so a sticky current state cannot
be overwritten by an older queued transition, and a recovered connection does
not serialize its historical failure into an invalid connected event. Browser
startup consumes that socket replay once; later history merges only stable
message identifiers and exact ordered wire overlap, and retains the requested
page ahead of a full live window under an expanded finite bound. Raw attach
registration uses the actual upstream nick, malformed downstream/browser
composer lines fail loudly, and SASL PLAIN cannot request a different
authorization identity. CHATHISTORY works with or without negotiated batching;
every replay tag remains independently capability-gated. Synthesized echoes preserve validated client-only tags
but mint their own timestamp provenance and fit the added identity prefix into
the traditional IRC wire allowance. The shared driver-command boundary rejects
malformed, injected, and over-budget lines regardless of which attach frontend
called it. IRC server and BNC attach SASL share 400-byte chunk and bounded
payload constants; overlong chunks reset cleanly for retry, exact chunks require
the terminating `+`, and malformed completed exchanges spend the same permanent
per-connection authentication budget as valid-shaped attempts. A successful
exchange fixes the connection's account; a second receives 907 rather than
replacing it. Database-unavailable verification is reported as retryable rather
than as bad credentials. External-network history stores
both direct-message directions under one RFC1459-folded peer, validates its
metadata, and implements the complete LATEST/BEFORE/AFTER/AROUND/BETWEEN plus
two-bound TARGETS surface through one tested window resolver. Raw snapshot
reconciliation completes synthetic JOINs with NAMES and places a negotiated
read marker before end-of-NAMES. The browser marks stale snapshot channels as
past while retaining their transcript, and routes server notices to the server
buffer rather than creating phantom direct messages.
The BNC marker schema retains the account table's full BIGINT identity width,
and capacity checks serialize on the durable account row.
One live/history routing policy maps STATUSMSG `@#channel` and `+#channel`
traffic to the underlying channel. Composer commands with missing targets or
required operands fail as correlated, retryable errors instead of becoming a
different raw IRC command.
Its IRC state applies the protocol's last-duplicate-tag rule and handles every
comma-separated JOIN/PART and paired or single-channel KICK target; incomplete
topic numerics remain visible without crashing the socket handler. IRC wire
limits now share one independent tag/body predicate across the server, BNC,
WebSocket, TUI, and shared client. Valid long server tags survive live replay
and persistence, oversized bodies fail loudly, and IRC-over-WebSocket enforces
one unterminated IRC line per message instead of executing embedded CRLF as a
second command.
Bridge-backed networks now refuse every unsupported or malformed downstream
command with a bounded notice instead of accepting it into a quiet no-op.
The browser network rail now distinguishes the driver's parked lifecycle from
its latest failure code, so rejected Libera credentials and verified-account
registration policy produce the promised Server log and settings recovery
guidance instead of a bare failed-state label.

## Remaining qualification

- Run the shipped credential-gated campaigns for Discord, Slack, and each
  required OpenID Connect issuer.
- Run the tuned-host scale campaign. It remains required for production scale
  claims.

## Rules

- One open pull request.
- Fix discovered defects in the active change or ask for a decision.
- Keep this file current; detailed contracts belong in code and journeys.
