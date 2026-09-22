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
WebSocket events and composer requests. Each console operation is matched
against that served contract before it is sent, and the repository gate matches
every method/URL pair, URL literal, and form action in the console against the
router's route table, refusing to pass when it extracts none; it also forbids
POST routes under `/console`, document reloads, and console forms that bypass
`/api/v1`. Successful mutations refresh their API-backed
view without a document reload. Bridge provider frames and REST bodies cross
typed contracts. Server routes emit closed response models, including one
current-schema observability snapshot/history contract and a bearer-protected
deployment-neutral application observation derived from the same real counters;
URL queries and forms reject unknown fields. Owner, administrator, and static
network creation use
the same explicit driver, transport, and identity fields; kind-specific
requests reject incompatible fields.
The container starts with `e6ircd --config-from-environment`; the environment
goes through the same parser and validation as a configuration file. Managed
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
three shells; interaction tests cover Web Content Accessibility Guidelines level AA
contrast, keyboard focus, Escape
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
owner-scoped **Network log** view for IRC and every bridge driver. Its API reads
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
For external networks one routing policy (`conversation_target`) maps
STATUSMSG `@#channel` and `+#channel` traffic to the underlying channel for live
delivery, bridge routing, and backlog filing alike; the backlog used to file
such a line under its sender as a direct message. The core's own STATUSMSG
handling is separate by design: its channel types are its own, and it needs
the sigil to choose the audience. Composer commands with missing targets or
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

A 2026-09-20 review of the whole tree after #333 found, and this change fixes:

- **Privilege.** A write-scoped bearer token could install a password on a
  single-sign-on-only account and unlink its identity, taking the account over;
  a read-only token could send on the owner's upstream through `/ws/ui`; a
  bearer token beside any cookie could revoke every browser session; POST
  logout skipped the session token; a suspended owner's network could be
  enabled by an administrator and came back at every boot. Password, identity
  and session changes need a browser session; sending needs `write`; startable
  networks exclude suspended owners at one source.
- **The shared egress.** The connection test had no bound of its own, so one
  account could run hundreds of registrations a minute against a public network
  from the address every tenant shares. It is limited per account and per
  process, answers 429, has one budget below the request deadline so its typed
  timeouts are what the caller reads, and says `QUIT` on every exit. Its verb
  moved out of the network name space (`POST /api/v1/me/network-preflight`): a
  network named `preflight` was unreachable, and a startup check now refuses any
  two route patterns one URL could satisfy.
- **The bouncer.** An attached client's `QUIT` and `PING` were forwarded
  upstream, so every client exit ended the always-on session; upstream-confirmed
  channels were tracked without bound; a long outage evicted the real backlog
  with identical reconnect notices; a missing SASL mechanism parked at once as
  "rejected credentials"; downstream traffic hid a dead upstream from the
  keepalive. The identity put on the wire is parsed, not checked.
- **The core.** A refused ChanServ REGISTER deferred a reply that no verdict
  would ever release, silencing the caller's connection for good; FLAGS, SET
  FOUNDER, a labeled LIST, a server-ban verdict for an operator, and a
  cross-shard CHATHISTORY with nothing to send were the same class. The worker
  awaited pushes into its own bounded queue and could park forever; it now
  handles its own effects inline. QUIT and NICK reached a peer once per shared
  channel. OPER had no attempt budget. Two session lookups could panic the
  worker. Deleting an account that had ever sent a bouncer MARKREAD failed on a
  foreign key, and deletion and export missed the account's own messages by
  matching the folded name against a column that stores the display name. Two
  administrators demoting each other could both commit. An invitation recorded
  while a channel was open later passed `+i`; TOPIC, KICK and INVITE told a
  non-member whether a secret channel exists; a CTCP hidden in a multiline
  continuation passed `+C`.
- **The native clients.** The terminal client dropped every error numeric, KICK
  and server ERROR while echoing the refused message as sent, and retried
  rejected credentials every two seconds forever; no client wait had a deadline.
- **The browser.** Credential fields invited the browser to autofill the e6irc
  login into a third-party network's form; two quick settings clicks could save
  one network under another's name; background refreshes took focus, reset logs
  to their top, and detached a confirmation's form so confirming did nothing.
- **Operations.** The backup and restore scripts could not reach a database
  given as a URL (libpq does not expand one from `PGDATABASE`) and leaked the
  password trying; a configuration parse error printed the offending line,
  which can be a secret; a trailing comma in the administrator list crash-looped
  the container silently; CI syntax-checked only the first of its shell scripts;
  the journey guard never resolved the tests a journey cites; the console
  operation check compared an empty set.

The owner decisions that review raised were all taken as "fix it", in the same
change:

- **Several core workers.** `core_workers > 1` answered differently from one
  worker: a message, WHOIS, ISON, USERHOST, MONITOR, KILL or GHOST aimed at a
  nick on another shard did not find it, LUSERS and WHOWAS counted one shard,
  a labeled command answered in pieces lost the pieces, a join could outlive
  its session, and two workers with full queues deadlocked on each other. Every
  shard — a lone one included — now answers from the same process-wide
  directories, publication is tracked rather than remembered, a worker never
  waits on another's queue, shutdown is a drain, readiness needs every shard's
  heartbeat, and irctest passes unchanged at two workers.
- **Conversations with unauthenticated users** are never stored or read from
  the database (migration 0058 purges the old ones): a stranger taking a
  released nick used to inherit the previous holder's direct messages.
- **CHATHISTORY** with a msgid the store does not hold answers `FAIL … :unknown
  msgid` from the core, the bouncer and the REST API instead of an empty page,
  and a session's database history requests are capped.
- **The IRC user name is configured, never derived** (`username`, migration
  0057, required for `irc` and `local` networks on every ingress). The forms
  and native clients share one stated default — blank means the nickname, only
  when the nickname is a legal user name — and never rewrite one to fit.
- **The bouncer.** A services outage no longer parks a SASL network; a welcome
  under another nickname is a refusal; the `local` driver waits for its 001; a
  half-open attached client is pinged and detached; the failure and its retry
  time are one transition. Matrix: permanent refusals park, one login per
  driver with a stable device and a logout, and a filtered sync.
- **Native clients.** Secrets come from a file or the environment as well as a
  flag, and neither client — nor `e6irc api`/`login` — sends a credential over
  a connection that is neither TLS nor loopback without an explicit override.
- **Accounts and the API.** Every personal access token is minted under one
  per-account cap, the device grant included. A login attempt costs two Argon2
  computations whatever the account holds (app passwords are found by lookup,
  migration 0059) instead of up to 33. `/ws/ui` is capped per account and pings
  a silent browser. A configuration whose listeners collide or whose sizes are
  absurd is refused. `e6ircd recover-administrator` is the explicit, local,
  audited way back in for an operator who lost every administrator login. A
  bouncer upstream inside the server's own network (loopback, RFC 1918,
  carrier-grade NAT, unique-local) is refused by default at every ingress and
  at dial time; `internal_upstreams = "allow"` is the operator-level exception
  the test harnesses use. Six
  unaudited test-only side doors in the database layer are gone, and shutdown
  flushes held output before the closing `ERROR`.
- **Delivery.** One `ci-ok` job gates every other; a release is published only
  from a commit whose CI run succeeded; every action and base image is pinned
  to a digest; the runtime image is distroless — the daemon states its own
  configuration from the environment (`--config-from-environment`), in memory,
  so the shell entrypoint, its temporary secrets file and its TOML quoting are
  gone; the container has a `HEALTHCHECK` backed by `e6ircd healthcheck`; the systemd unit is hardened; the fuzz lockfile is checked for
  drift; the dead-public guard sees `pub async fn`.

A 2026-09-21 review after #334 (five read-only reviewers over the core, the
bouncer and clients, the HTTP layer, the browser code, and operations) found,
and this change fixes:

- **The bouncer.** The egress rule could be passed with a non-canonical
  spelling of an internal address (`http://2130706433/`, `0x7f.1`, `127.1`):
  the URL parser canonicalised it and the HTTP client short-circuited DNS for
  an IP-literal host, so the vetting resolver never ran. Every bridge request
  now goes through one client that judges the parsed host first, and a 3xx is a
  failed request. Matrix transaction ids restarted at zero per session while
  the login was reused, so messages after a reconnect were silently swallowed as
  duplicates; a stopped or replaced IRC driver never said QUIT and its
  successor met its own ghost; the gateway dialer tried one address; a
  services-outage streak made the next parking refusal park at once; a tarpit
  kept the backoff at 200 ms; upstream writes were unbounded and one stuck
  socket could hold every account's network mutation; `ws://` gateways were
  accepted; the Slack name cache was unbounded; the terminal client had no read
  liveness.
- **The core.** A session that logged in mid-session (SASL, IDENTIFY, REGISTER)
  never released the `~nick` conversation rings it had as a stranger, so the
  next holder of the nick could read them; `Session.account` is now
  write-private and the one setter releases. The channel limit was not counted
  for channels owned by another shard; operators received a server-ban notice
  once per shard, and a removal that found nothing announced a removal; a dead
  second reply path for topic persistence is gone.
- **The browser.** The console network editors sent `null` for blank
  credential and real-name fields and were refused by their own contract
  check, so a network with a stored NickServ account could not be edited
  without retyping the password and no bridge could be saved at all; the
  reconnect replay doubled transcripts; a deduplicated alert kept a stale
  Restore action; text typed into a channel the session no longer holds was
  echoed as delivered; an expired session kept the socket retrying forever;
  credential edits under Remove were discarded or kept silently; channel
  modes ignored the network's `005`; the add-network dialog typed over the
  person; the sign-out link was live before its CSRF URL; the member list was
  unreachable on phones; "Save and reconnect" silently enabled a disabled
  network.
- **Accounts and the API.** `recover-administrator` revoked only the local
  password and browser sessions, leaving an intruder's tokens and app
  passwords alive on an account it then made administrative; it now revokes
  everything, as suspension does, and needs no restart because administrator
  authority is read from the account row on every request. A password change
  revoked nothing; it now ends every other browser session. A first OpenID
  Connect login invented `alice-2` on a name clash; it is a loud 409. The
  OpenAPI document disagreed with the handlers in nine places the browser's
  validator would trip on, and a router-walking check now refuses an
  authenticated operation missing its standard responses. Both secret-key
  sources set at once were resolved by precedence; content rules ran on
  ciphertext; `admin_accounts` entries were never syntax-checked; an `https`
  public URL accepted insecure cookies; console pages authenticated bearers
  through a second, weaker path. Every UI-socket attach replayed the whole
  ring: lines now carry an opaque replay cursor and a reconnect resumes
  exactly, or is told to reload.
- **Operations.** The deployment guide and journey still described the
  pre-distroless image, a retired variable and the old egress rule; the
  migration-integrity guard passed on an unresolvable base and compared paths
  rather than version numbers; the systemd stop budget equalled, rather than
  exceeded, the daemon's drain-plus-flush; the image accepted a missing build
  revision as "unknown"; the test matrix's 15-minute job timeout cancelled the
  merge commit's cold Intel build; CI service images were tag-pinned.

A 2026-09-21 second review (an adversarial protocol reviewer, a real-networks
bouncer reviewer, an operability reviewer) and a live run of the owner's story
against Libera through the real browser and the real daemon found, and this
change fixes:

- **The bouncer against real networks.** A shared egress and any simultaneous
  drop turned Libera's per-address throttle into a permanent park of every
  network past the first few: all drivers re-dialled the same server in
  lockstep (jitter under 0.1 s, no address rotation, no boot stagger) and a
  pre-welcome `ERROR` parked after five. Capacity and policy answers from a
  network never park now; jitter is proportional, addresses rotate by seed,
  boot dials stagger. An upstream `ERROR :Closing Link` was forwarded to
  attached clients (which reconnected themselves) and persisted; it is a
  bouncer notice and a diagnostic. 437/436 were not refusals (30 s burned per
  attempt); a welcome under a truncated nick dropped the session without QUIT
  and re-registered five times; a hundred-channel rejoin was a hundred JOIN
  lines; a forced rename to `Guest12345` was adopted silently; the connection
  test joined every channel it said it did not join and could not test a
  running network; 451 to `CAP LS` parked; 906 counted toward parking; the
  synthesized self-echo carried the nickname as its user part; the EFnet preset
  could never connect over TLS (no member of the round robin presents a
  certificate for `irc.efnet.org`) and is gone; and SIGTERM never told the
  drivers to stop, so every restart met its own ghost.
- **The core, adversarially.** A comma list naming an already-joined 10k-member
  channel a hundred times cloned its member list a hundred times and replayed
  TOPIC and NAMES each time; a list mode named a hundred times dumped the list
  a hundred times; flood control was off by default with a refill no real
  client could live under when turned on. Target lists are deduplicated and
  bounded by the advertised TARGMAX, a rejoin is a no-op, a list is dumped
  once, and flood control is on by default with Solanum's shape. An over-long
  PING token produced a 548-byte PONG that panicked debug builds; `TOPIC :#c`
  cleared the topic; MARKREAD scanned every account's markers and every
  session per command; a labeled echo whose body read `BATCH +z` escaped its
  batch; three `draft/multiline` rules were unenforced.
- **Operations.** The systemd unit could crash-loop into a permanently failed
  unit when PostgreSQL came up later than e6irc, and the daemon gave up on its
  first database connection in milliseconds (reporting the pool's "timed out"
  instead of the refusal); it now retries for a bounded, loud window. `/healthz`
  was a constant, so a stalled core shard stayed "healthy" behind the container
  health check; it now requires every shard's heartbeat. HTTP requests that hit
  the deadline or waited on the concurrency permit were neither counted nor
  timed. Self-registration and OpenID Connect provisioning wrote no audit row,
  and network/configuration audit details named no fields. Bouncer history had
  no time-based retention, a saturated maintenance tick could never catch up,
  samples were pruned only while sampling was on, a listener rollback failure
  was swallowed, and refused connections logged one line each without bound.
  The stop budget now covers the drivers' goodbye; a restore into an empty
  database is proven by the recovery script.

A 2026-09-21 fourth review (native clients, the database layer with EXPLAIN,
the bridges against the providers' current contracts, transport security and
supply chain) found, and this change fixes:

- **The server password.** A private network that requires `PASS` could not be
  configured; it can now, end to end (client library, CLI/TUI, sealed storage
  in migration 0061, an explicit keep/set/remove action on replace, both
  browser forms), and a 464 tells a missing password from a rejected one.
  e6ircd answered a client's `PASS` with 451, which stalled clients; the
  replace endpoint silently dropped a password typed beside `keep`.
- **The bridges.** An IRC user could page a whole Discord guild or Slack
  workspace; remote text could deliver a CTCP request to every attached IRC
  client; Discord sat "connected" and deaf after an invalid session and
  re-identified on every drop; Matrix joined encrypted rooms and relayed
  nothing, dropped every msgtype but text, and lost an outage's messages;
  Slack treated routine refreshes as failures and relayed retried envelopes
  twice; no driver honoured a rate limit; bridge REST bases accepted `http://`.
- **The native clients.** The terminal client marked unloaded messages read on
  every device; `e6irc send` and `raw` exited 0 on refusals; a cached API
  token went to any IRC server; the cleartext check trusted a `*.localhost`
  name and `HTTP_PROXY`; `tail` never gave up on a silent server; quitting
  dropped queued lines and never sent QUIT; long lines were clipped, pastes
  sent line by line, and `/raw` replies shown nowhere.
- **Transport and supply chain.** The bouncer's attach listener took account
  passwords in cleartext; the HTTP listener had no header or idle timeout and
  no per-address limit, so one client could starve every page and the health
  check; the bouncer sent upstream SASL and server passwords over plaintext
  networks; IPv4-mapped peers escaped bans and trusted-proxy matching; the TLS
  certificate was never reloaded; the attested SBOM named no Rust crate and no
  build was `--locked`; core dumps could carry keys; responses lacked a header
  baseline and the console needed inline styles; HSTS forced
  `includeSubDomains`; browser tokens used a non-injective alphabet; SASL
  passwords were silently trimmed. The bouncer now relays the upstream's own
  echo, so a refused line is never echoed as sent.
- **The database.** A suspended, demoted or recovered administrator's
  invitations still opened accounts; deleting a busy network or account left
  backlog written behind the deletion (migration 0062 ties each line to its
  network); a slow migration was cancelled by the pool's statement timeout;
  account deletion and export scanned `messages` whole (0063; export now
  streams from a snapshot); password changes ran Argon2 under a row lock;
  one refused maintenance delete rolled back the others; a restart could leave a
  backlog over its 5,000-line cap, and attach history loaded every row of a
  target; CHATHISTORY TARGETS and maintenance deletes scanned tables; audit
  rows were written outside the change they record, and OPER/KILL/SETHOST not
  at all under the operator's name; the pool was a fixed 10 connections; the
  read-marker cap was per core shard; the replay of a quiet buffer walked every
  other buffer's lines. Unused indexes were dropped (0064), device grants
  reference accounts by id (0065), and `cargo` now rebuilds when a migration is
  added.

Deploying c51261725b5d to Scaleway (2026-09-21) found, and 0067 plus this
change fix:

- **A stored `null` stopped the daemon.** The live settings row, written by an
  older release, held `limits.command_burst: null`; #336 had made the field
  required, and the daemon crash-looped for about 45 minutes until migration
  0067 (#338) removed the `null`. Released settings rows are now fixtures that
  every change must still load (`tests/fixtures/server_settings/`).
- **Idle upstream connections logged as refusals.** A reverse proxy's idle
  kept-alive connections, closed at the header bound, were each logged as a
  refused peer; only a connection that never completed a request is now.

- **Libera from a cloud host.** Libera answered `CAP LS` only after its ident
  check timed out (6.9 s from Scaleway, whose firewall dropped ident), past the
  client's 5 s bound, so every SASL attempt failed as "SASL unavailable" — and
  Libera requires SASL from cloud addresses, so the network could not connect
  at all. The bound is 20 s, silence is a retried timeout rather than a missing
  capability, and an upstream's reason is no longer cut at 160 characters (it
  hid the end of Libera's "SASL … required to connect from your current IP").

## Remaining qualification

- Run the shipped credential-gated campaigns for Discord, Slack, and each
  required OpenID Connect issuer.
- Run the tuned-host scale campaign. It remains required for production scale
  claims.

## Rules

- One open pull request.
- Fix discovered defects in the active change or ask for a decision.
- Keep this file current; detailed contracts belong in code and journeys.
