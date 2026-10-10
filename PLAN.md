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
behavior; new configuration never receives an implicit decode default. After
the first import the console owns the operational settings: a start whose file
or environment states one with a value other than the stored one is refused,
naming each such setting and printing no value.
History accepts one typed cursor window and a bounded page size.
Chat, console, and identity pages share the relay-desk visual system and
accessible light, dark, and forced-colors palettes. The one network form, the
chat client's dialog, reads the server-side preset catalog
(`GET /api/v1/network-presets`), asks first for what a known network cannot
supply, and keeps the rest under an Advanced disclosure. The chat client opens an account's sole runnable network
by itself (with several, the person chooses), opens a network it has just added, and has one control for each thing: one network
list, one console (the first conversation, which shows every IRC line the
network sends and takes raw lines), one command reference. The console navigation
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
egress, not an arbitrary deployment. A 2026-08-23 qualification from a
production container on a cloud host proved registration and configured-channel joins
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

The driver no longer answers a taken nickname by silently running as `nick_`
(and only when SASL was off). A taken nickname is treated as a possible ghost
of the network's own session (a crash, a standby's takeover, a link that died
without `QUIT`): the driver registers under one alternative, is
`regaining_nickname` ("connected as bncbot_, regaining bncbot") rather than
connected, joins and sends nothing, and takes the configured nickname back —
NickServ `REGAIN` with SASL, and `MONITOR` or `ISON` otherwise. A definite
services refusal parks it at once; a holder that outlasts five minutes, or an
alternative that is taken too, is the `nickname_in_use` refusal on its
schedule. The CSRF token's key and the OpenID Connect flow cookie's key are
derived from the master secret key, so open pages keep posting and sign-ins in
progress complete across a restart and a standby's takeover; a flow is still
answered once, because its code exchange first records it as spent in
PostgreSQL (migration 0099), which every process shares.

The chat client's network dialog does not gate saving on a connection test:
**Test connection** is an optional diagnostic that says `QUIT` when it is done.
A network's console page has a bounded, owner-scoped **IRC transcript** of its
stored lines, for IRC and every bridge driver. Its API reads
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
For external networks one routing policy (`NetworkNames::conversation`) maps
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
registration policy produce the promised console lines and settings recovery
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

Deploying c51261725b5d (2026-09-21) found, and 0067 plus this
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
  check timed out (6.9 s from a cloud host whose firewall dropped ident), past the
  client's 5 s bound, so every SASL attempt failed as "SASL unavailable" — and
  Libera requires SASL from cloud addresses, so the network could not connect
  at all. The bound is 20 s, silence is a retried timeout rather than a missing
  capability, and an upstream's reason is no longer cut at 160 characters (it
  hid the end of Libera's "SASL … required to connect from your current IP").

- **SASL mechanisms.** The bouncer and native clients spoke only PLAIN. They
  now choose the strongest password mechanism a network offers — SCRAM-SHA-512,
  SCRAM-SHA-256, then PLAIN — verify a SCRAM server's signature, never fall
  back from a failed SCRAM to PLAIN, and say which mechanism logged in (tested
  against RFC 7677's vector, an in-test SCRAM server, and a real Ergo server).

- **One editor for a network, and a console to type in.** Setting a NickServ
  account and password behaved differently on each screen that offered it: the
  console editor discarded typed credentials when Remove was ticked (and said
  "Updated."), the network page trimmed the password, made "leave blank to
  keep" impossible and replayed a `null` real name the API refuses. Those
  duplicate forms are gone: the chat client's settings dialog is the one
  editor, opened from the console by link, and the `/console/networks/{name}`
  `edit` and `logs` pages with them. The chat client gained a **console**
  conversation (the old server buffer) that shows every line in both
  directions and sends what is typed as the IRC line itself, replacing the
  separate Server log panel and its switch; a network is enabled or disabled
  from the list where it appears.

Sweeping after #342 found, and this change fixes:

- **The same `null` two fields over.** Reviewing every persisted field whose
  type had changed found `limits.api_rate_burst` and
  `limits.administrator_api_rate_burst`: `Option<usize>` until API rate limits
  were made explicit, required since, and stored as `null` by any row written
  before that release — the crash-loop of 0067 waiting to happen again.
  Migration 0068 removes both, and the released-settings fixture for that
  release (`0052-b0084a00a04a.json`, captured by building that release) is now
  part of the suite that every settings change must still load.
- **A short CHATHISTORY page read as the end of the buffer.** The attach
  listener cut its page with a SQL `LIMIT`, then dropped every stored `TAGMSG`
  for a client that had not negotiated `message-tags` — a request for 100 came
  back with 87 and no way to tell that from "there is no more". The client's
  scope is now part of the query (`BncHistoryScope`, built from the one
  capability that decides it), so the `LIMIT` counts only lines that will be
  sent; `CHATHISTORY TARGETS` answers in the same scope, so it cannot name a
  conversation that pages back empty. The command is a generated column
  (migration 0069) rather than a flag the insert path writes, so it cannot
  disagree with the line it describes, and it reads the frame rather than the
  body: a message *about* `TAGMSG` is still delivered.
- **Read markers were the one collection with no bound.** Capped at 256 per
  account but unbounded in accounts, and absent from the storage sweep, so the
  table only grew — and every row of it is read at boot and mirrored into each
  core shard, making its size the daemon's start-up cost too. Both marker
  tables are now swept against the history retention (0070): a marker older
  than that names a position no stored message can be read from.
- **A storage failure announced itself to the future.** A `BacklogStorage`
  failure notice was retained in the bouncer's ring, so every client that
  attached later replayed a failure that was over; it is live-only now, like
  the other transient notices, and the per-network status dedup keys on the
  lifecycle rather than the message. The persist-failure log is rate-limited to
  the transition, and a log batch is bounded at 1,024 rows so a flood cannot
  hold the writer in one drain.
- **The UI says things once.** A connection can be tested from the add dialog
  before anything is stored, and the result is reported in the dialog — it used
  to be written to the console buffer, which does not exist until a network is
  open, so the first test of a first network reported nowhere. The storage
  warning that sat inside the Preferences menu (invisible unless the menu was
  open) and again as an alert is now only the alert; the sidebar's "no networks
  yet" is gone, because the picker filling the pane beside it says the same
  sentence and carries the button that acts on it. Dead rules for three
  removed screens (`.side-link`, `#raw-output-*`, `.raw-wire`) went with them.

Sweeping after #343 found, and this change fixes:

- **A network could be added in the editor but not removed there.** Removing
  one existed only in the console, so a person who added a network in the chat
  client had to go to another application to delete it. The settings dialog --
  the one editor -- now removes it: asked once, naming what goes with it, the
  second press being the answer. Removing the network that is open returns the
  client to the picker in this document rather than leaving it on conversations
  it can no longer send to. The console keeps the control on a network's own
  page, where a bridge is removed too, and loses the duplicate on each row of
  the list. The real-browser journey now crosses removal end to end; it never
  did, so the destructive path had no coverage outside unit tests.
- **The same failure said twice, in two wordings.** A message that did not
  enter the socket, unconfirmed sends at a disconnect, the in-flight cap,
  backlog that would not load and a member list that could not be refreshed
  were written into the console buffer *and* raised as an alert -- with
  different sentences -- while a failed join was written only to the console,
  which is rarely the conversation being read. Every one of them is an alert
  now; the console keeps the connection's own record.
- **A message with no text in it could be stored.** A `draft/multiline` batch
  whose lines are all blank delivers nothing to a client without the capability
  (a blank line is a line break, not text), so stored it became a history row
  that replays as no line at all -- a CHATHISTORY page of N rows reaching such
  a client as fewer than N messages, the same false "end of the buffer" that
  #343 fixed for `TAGMSG`. It is refused at the sender with `ERR_NOTEXTTOSEND`,
  exactly as an empty PRIVMSG is, so every stored message is one its recipients
  can receive.

- **Tests that failed for being slow.** Around seventy integration-test waits
  were bounded at a handful of seconds each. The bound is there to turn a hang
  into a readable failure, but written that short it also asserts latency: the
  attach suite failed on a CI runner, and five database tests failed locally,
  purely for running beside a browser suite. They share one generous deadline
  now (`tests/support/deadline.rs`), so a hang still fails with its own
  sentence and a busy machine does not. The short `from_millis` windows that
  assert *nothing* arrived are deliberately untouched.

Sweeping after #344 found, and this change fixes:

- **The SCRAM client accepted an iteration count RFC 7677 forbids.** The
  constant's own comment cited the 4096 minimum, but only the upper bound was
  enforced: a server could ask for `i=1` and this client would derive a key
  from it. The iteration count is what makes a captured transcript expensive to
  attack, so a server asking for fewer is weakening our credential; the
  exchange now stops and says so, rather than obeying.
- **Nothing held the settings row the deployed release writes.** Fixtures
  existed for the two shape changes already found, but not for
  `b532432c5894` -- the revision production is actually running, whose row the
  next deploy has to load. Captured by that release's own code and added to the
  suite: it loads cleanly after migrating through 0068-0070, so the deploy that
  is pending does not repeat the crash-loop, and the row is guarded from here
  on.
- **A verified token whose claims could not be read said nothing.** The OpenID
  Connect login parsed the id_token's claims for `sid` and dropped a failure on
  the floor; without `sid` a back-channel logout can only match by subject,
  which revokes more than the provider asked for. It is reported now.

Also checked and found sound, so recorded rather than re-derived next time: the
chat client reads no response field the served contract does not declare
(the fault behind #343's preflight); the irctest green list omits only files
whose tests skip entirely on this server; eight minutes of fuzzing across
`core_multi`, `core_dispatch` and `bouncer_lines` found nothing.

Sweeping after #345 found, and this change fixes:

- **The configuration API could be read but not written back.** `GET
  /api/v1/admin/configuration` returns settings including the OIDC, operator
  and server-network collections; `PATCH` refused exactly those fields, so the
  obvious loop -- read the resource, change one setting, send it back, which is
  the only shape a script has -- failed with a 400. It was found by doing it:
  turning on the BNC attach listener from the command line. The write now
  accepts those collections when they are echoed as read (the read redacts
  every secret and the write compares against that same redaction) and refuses
  a *changed* one by name, with the endpoint that does change it.

Checked against the real world rather than a mock, and sound: a local daemon
connected to Libera on the first poll, stored its backlog, and served a client
attaching over the BNC listener -- SASL, welcome, the `*bnc*` lifecycle notices
and the replay with `server-time` tags -- and held the connection open. Libera
answers `e=other-error` as its SCRAM server-first for an unknown account, the
case the client has handled since #342.

Sweeping after #346 found, and this change fixes:

- **The documented way to attach a client to your own bouncer did not work.**
  The TUI's own `--help`, the README, `DESIGN.md` and three journey documents
  all say a BNC network is selected with `account/network` as the SASL user
  name -- soju's convention. The attach listener only ever read the selector
  from the *nickname*, ZNC's convention, so following the instructions gave
  `904 SASL authentication failed`. Running the TUI exactly as its help says
  is how it was found. The listener now accepts either, because neither alone
  is enough: every client can set a SASL user name, while `<nick>/<network>`
  asks for a nickname containing `/`, which is not a legal nickname and which
  many clients will not send. A client that sends both must agree, or it is
  refused naming both networks.

Exercised rather than inspected, and sound: the `e6irc` CLI against both the
core listener and the attach listener -- `send`, `history`, `raw` (including
its nonzero exit on a refused line) and `api` -- and the TUI over a pty.

A sweep of the bouncer found, and this change fixes:

- **Bridges echoed nothing a client sent.** Discord, Slack and Matrix drop the
  provider's copy of their own posts and emitted no echo in its place, so a
  message sent through a bridge reached neither the other attached clients nor
  the backlog. Each target the provider accepted is now echoed once, under the
  bridge account's IRC identity; a refused one still gets only its notice.
- **One unreadable Matrix event stalled the bridge.** A redacted or malformed
  `m.room.message` failed the whole sync, whose position then never advanced.
  Events are decoded one at a time; such an event is one "not relayed" notice.
- **CHATHISTORY batches whose lines did not say so.** Lines inside a `BATCH`
  on the attach listener lacked their `batch=` tag.
- **A nick change the owner asked for was reported as forced.** The upstream's
  confirmation of a client's own `NICK` counted as `renamed_by_upstream`.
- **The local driver.** A stop during registration left the half-registered
  core session to the reaper, and its synthesized echo showed `~nick` where
  the core shows the `USER` name. It also negotiated no capabilities with the
  core, so the local network stripped client-only tags (`CLIENTTAGDENY=*`):
  no typing indicators, no reactions, and an echo without the core's `msgid`.
  It now asks the core for `message-tags`, `server-time`, `echo-message` and
  `account-tag`, and relays the core's own echo.
- **Lines sent with `CAP END` were refused.** The attach handshake answered
  lines arriving in the same read as `CAP END` with 421, and dropped the half
  of a line it had framed; both now reach the attached session.
- **A bridge's echo named someone the client was not.** A client attached to
  a bridge was welcomed under the nick it asked for, while its echo named the
  provider account, so echo-message clients did not recognise their own lines
  and `e6irc send` waited for an echo that never came. A bridge now begins
  its session under the account's nick, in its mapped channels, before it
  reports connected; the attach layer answers `NICK` (447) and `JOIN`
  (re-stated, or 403) on a bridge itself, and the web composer refuses
  `NICK`, `JOIN` and `PART` there. The web client marks the bridge's channels
  joined from the session (it had refused to send into them), offers no Leave
  for them, and no longer takes a bridge's empty configured nick for a nick
  that every trailing punctuation mark mentioned.
- **Matrix dropped the account's other devices.** Every event from the
  logged-in account was dropped as the bridge's own; now only events carrying
  a transaction id (which the homeserver shows only to the sending device)
  are, and posts from the account's other devices are relayed.

A 2026-09-24 security review found, and this change fixes:

- **Per-address limits counted each IPv6 address alone.** One subscriber holds
  a whole `/64`, so every per-address limit handed a client 2^64 budgets. All
  of them — connections, in-flight HTTP requests, the HTTP authentication
  bucket, IRC account creation — are keyed by one type that folds IPv6 to its
  `/64`, and a core session is charged to the address it connected from even
  after SETHOST.
- **Password guessing against one account was bounded only per address.**
  Every password check (web login, app-password exchange, password change,
  SASL PLAIN and NickServ IDENTIFY, the attach listener) reserves one of ten
  attempts per account name per 15 minutes before checking (migration 0074),
  and a refusal is `429` + `Retry-After` over HTTP and a `904` or NickServ
  notice over IRC.
- **A configured administrator's name could be registered by anyone.** NickServ
  and IRCv3 `REGISTER`, administrator account creation and invitations refuse
  it; only OIDC provisioning and the bootstrap/recovery flows create it, and
  startup names each configured administrator that has no account yet.
- **Bridged senders could pass as the owner or each other.** Senders were shown
  by a name (a Matrix localpart, a Slack display name, a Discord or webhook
  username); they are now keyed by the provider's account id, shown at their
  homeserver or under their id, and never given the owner's nick or another
  shown sender's.
- **A re-created channel served the previous occupants' history.** CHATHISTORY
  reads of a channel start at its current incarnation; the founder and access
  list of a registered channel keep the whole record, as over REST.
- **NickServ `SETPASS` and `RESETPASS` (and `Q`/`X`/`AuthServ` `AUTH`/`LOGIN`)
  reached the backlog unredacted.** One list of sensitive services commands
  now serves the bouncer's echoes and the core's echo-message.
- **Front-channel logout signed out any visitor.** It cleared the session
  cookie of whoever loaded it; it now clears it only when that cookie named a
  session the logout revoked.

A sweep of startup, shutdown and operations found, and this change fixes:

- **A graceful shutdown lost the bouncer's last backlog lines.** Every
  network's persistence task was aborted the moment its driver released the
  upstream, so lines still queued — the goodbye among them — never reached
  PostgreSQL. They are now written within the shared driver-stop deadline; only
  a write still running at the deadline is abandoned, and reported.
- **`SIGHUP` during the database wait killed the daemon.** The reload handler
  was installed only after PostgreSQL was reached and migrated, and systemd does
  not restart a unit that died of `SIGHUP`. It is now installed first.
- **`/readyz` let one client exhaust the database pool.** The unauthenticated
  probe bypasses admission and took a pool connection per request; concurrent
  requests now share one probe, reused for a second.
- **`check-config` passed configurations that start refused.** It now runs the
  start's own checks for the monitoring token and every TLS certificate/key
  pair.
- **A failed certificate reload could be skipped forever.** The file stamp was
  the modification time alone and a failure was recorded as settled; a fix that
  kept the time was never read. Stamps now include length, inode and
  status-change time, and a failing read is retried at every check (reported
  once per distinct failure).
- **`E6IRC_SECRET_KEY=` meant a key to one reader and "unset" to the rest.** The
  master-key variables go through the environment's one rule, and a source test
  refuses any other environment read in the daemon.
- **The container health check's start period (60 s) was shorter than the
  startup it waits for.** It is 420 s, above the 300 s database wait plus the
  migration lock retries; a unit test holds it there.
- **The deployment guide pointed at a `/metrics` route that does not exist.**
  It is `/api/v1/admin/metrics`, which needs administrator authentication.

The integrated services now carry the whole NickServ/ChanServ surface DESIGN
§7.6 names: NickServ GROUP/UNGROUP, REGAIN, INFO, SET ENFORCE (nick protection
with a cross-shard Guest rename) and DROP (the console's deletion procedure,
now shared); ChanServ ACCESS, DEOP/VOICE/DEVOICE and SET SUCCESSOR, with
account deletion passing founded channels to their successors in storage and
in every shard's mirror. Operators read the server bans, private reasons
included, with STATS k/d/x.

A review of that surface fixed, each with a test that failed before:

- **GROUP claimed names REGISTER refuses.** Any identified user could group a
  configured administrator's name and so block that administrator's account
  from ever being created. Every claim path now asks one predicate
  (`ReservedAccountNames::claimable`), and storage refuses a services nick to
  every creation path, OpenID Connect included; the administrator set is
  computed once and shared.
- **Founder-only ChanServ changes trusted the core's founder check.** A
  pipelined `SET FOUNDER` let the former founder still name the successor,
  change access, set KEEPTOPIC/MLOCK or `DROP` the channel. Storage now
  re-checks the founder with the row locked for all of them.
- **The successor was invisible.** FLAGS, ACCESS LIST and both consoles show
  it; the core mirrors it, and a transfer clears it.
- **STATS k/d/x split an X-line mask with spaces and blanked an IPv6 mask**
  to `*`; masks, and a session's host, are spelled as Solanum spells them.
- **The nick mirror could drift and a late verdict revived a deleted
  account's nicks**; storage's idempotent answers now repair it and a deleted
  account gains nothing back.
- **Nick protection renamed a session whose IDENTIFY was still being
  verified**; it waits for the verdict.
- **ChanServ refused grouped nicks where it takes an account**, ACCESS ADD on
  an existing entry claimed it was added, and the OP/DEOP/VOICE/DEVOICE MODE
  line echoed the nick as typed. The owner console resolves grouped nicks the
  same way.

Maintainer decisions implemented on top: a founder transfer always clears the
successor; the nick-protection clock never restarts (leaving and returning
keeps the deadline, and a return after it renames at once); and GHOST, REGAIN,
the enforcement rename and ChanServ OP/DEOP/VOICE/DEVOICE are audited.

A review of the bouncer as a client of its upstream and a server to its
attached clients found, and this change fixes:

- **One client's replies went to every client and into the history.** A
  `/LIST` reached every attached client, overran their shared broadcast and
  detached them, and evicted the stored conversation; a `WHO` on join filled
  the backlog. Replies are routed to the attachment whose command they answer —
  by `labeled-response` when the upstream has it, by reply order otherwise —
  live, on a bounded route of its own, and never retained or stored.
- **Client-only tags and `TAGMSG` reached upstreams that cannot carry them**,
  answered by a 421 in front of every client (or, on a server that does not
  parse tags, losing the message behind a fake echo). They are stripped, with
  `CLIENTTAGDENY=*` advertised, and a `TAGMSG` is answered to its sender alone.
- **Names were compared under RFC 1459 whatever the network said.** Another
  user's `NICK` or `JOIN` could be taken for ours on an `ascii` network, and
  two channels shared one history. The session, rejoin set, echo matching and
  history filing read the network's `CASEMAPPING`, `CHANTYPES` and
  `STATUSMSG`; stored conversations keep their spelling and are keyed and
  re-keyed under the network's mapping (migration 0076), and TARGETS names them
  as spelled. Read markers keep their spelling and mapping too and are re-keyed
  the same way (migration 0086).
- **A keyed channel could not be autojoined.** Only a key a client joined with
  or a `+k` the driver saw was remembered, in memory, so a restart lost it and
  the channel was answered with 475. An account network's autojoin entry now
  takes a key (`#staff key`), stored sealed (migration 0087), write-only over
  the API with an explicit keep action, never carried to a new destination,
  and edited in the network dialog.
- **Replay and CHATHISTORY disagreed on time** on networks without
  `server-time`: every line is stamped when it is taken in.
- **Echoes**: a message to several targets is echoed per target, an echo the
  upstream truncated still matches, and a labelled echo is routed by its label.
- **The upstream's registration burst** (its own ISUPPORT, the MOTD) was replayed
  over the bouncer's welcome; it is read, not relayed or retained.
- **Rejoin**: a refused rejoin is dropped instead of retried forever, a client's
  `PART` removes a channel the session is not in, and keyed channels are
  rejoined with their keys.
- **Reconnects** left no mark in the ring (a replay showed two JOINs without the
  PART between); `CAP NEW`/`CAP DEL` mid-session were ignored; bouncer-made
  lines could exceed the line limit.
- **Attach**: a synthesized JOIN is followed by the channel's real topic and
  member list, asked of the upstream for that client alone, and a raw client's
  replay starts each conversation at its account's read marker.

A 2026-09-25 review of the HTTP, WebSocket and console surface found, and this
change fixes:

- **A live chat socket outlived its credential.** `/ws/ui` kept streaming and
  sending after logout, session revocation, a password change, provider logout,
  the session cap, token revocation or expiry. The credential tables announce
  every change themselves (migration 0077); a listener closes the sockets a
  change ends (1008), and expiry closes them too.
- **A stored network secret followed an edited address.** Keeping a password
  while pointing a network (or a bridge base) somewhere else sent it there; the
  one function that applies credentials refuses it (409).
- **Account activity showed other principals' rows.** Audit rows record the
  kind of each name (migration 0078); an account's activity and export show
  only rows naming it as an account, and an IRC ban's row names the operator.
- **OpenID Connect.** A rotated key is followed at once (one throttled refresh);
  a failed discovery is remembered for 30 s; the callback is rate-limited and a
  flow is answered once; provider calls obey the egress rule within the
  configured issuer's trust domain; an email names a new account only when
  verified under a domain policy.
- **Step-up re-authentication** guards the self-service changes that mint or
  redirect lasting access (migration 0079), with a console confirm-and-retry.
- **The session's CSRF value left URLs** (sign-out is a form post, linking a
  POST); revoking one browser session refuses a bearer as the bulk revocation
  does; administrator pages spend the administrator budget; the configuration
  view is an allowlist.
- **The contract.** Pre-handler statuses (429 for rate-limited handlers, 408,
  413, the re-authentication 403) are derived from handler signatures; the body
  limit's and the monitoring endpoint's refusals are problem documents; `/ws/ui`
  is described; a REST topic is stored whole or refused.

A review of the database layer found, and this change (migration 0080) fixes,
each with a test that failed before:

- **CHATHISTORY TARGETS read every stored direct message of the requester** on
  the serial database worker, so one account with a large DM history could
  stall every other client's history. A `dm_conversations` summary kept by
  triggers on `messages` (backfilled by the migration) answers the
  conversation half in at most the request's limit of rows.
- **The 200-channel founder cap was per core shard, and transfers bypassed
  it.** Registration, ChanServ `SET FOUNDER`, the owner console's transfer and
  deletion succession count the receiving account's channels under its row
  lock; a transfer past the cap is refused, and so is a deletion whose
  succession would take a successor past it, naming the channels.
- **Expired personal access tokens held cap slots** until maintenance swept
  them; only unexpired tokens are counted, as the account directory counts.
- **The two password checks treated a failed "last used" write oppositely**;
  one helper records it for both, and its failure fails the check.
- **Storage did not hold the forms the code relies on**: BNC network names are
  constrained to the token language on which `lower()` equals the RFC 1459
  fold, and bouncer line and read-marker timestamps to the canonical
  millisecond form their lexical comparisons need.
- `account_invitations.accepted_account_id` (written, never read) and the
  redundant `bnc_networks_account_idx` are dropped; DESIGN §8 now matches the
  schema (the `messages` index, canonical `sent_at`, `login_attempts`).

An IRCv3 conformance review, extension by extension, found, and this change
fixes:

- **A labeled NickServ IDENTIFY dropped its echo**: a second "deferred" flag
  was set without counting the answer. A capture now has one count, and every
  asynchronous answer is gathered into the one labeled response.
- **900/901 only came from SASL**, and 901 never; they come from the one login
  and logout path. A labeled `AUTHENTICATE` was ACKed before its verdict, and a
  line sent mid-verify produced 904 followed by the real verdict.
- **`REGISTER` stored an empty password** no login could ever use; one parser
  (`NewPassword`) serves IRC, NickServ and the web. It answers `NEED_NICK` when
  there is no nick to register.
- **invite-notify reached every member**, not those who may invite; **WHOIS
  ignored multi-prefix**; **multiline lines exceeded 512 bytes** inside the
  batch (now split with `draft/multiline-concat`); **SETNAME cut** an over-long
  realname (now refused; `NAMELEN` advertised); **`MODES` was not advertised**
  (now `MODES=4`, enforced); pre-parse refusals lost their **label**; an **empty
  multiline batch** was answered with silence; MONITOR's 421 had an extra
  parameter; the attach listener took `AUTHENTICATE *` for a mechanism.

Maintainer decision implemented on top: history keeps client-only tags and
`TAGMSG` reactions (migration 0081), replayed to `message-tags` readers; typing
indicators are never stored, on the server or the bouncer. CHATHISTORY TARGETS
answers in the reader's scope, as the bouncer's does: for a reader without
`message-tags` a buffer is dated by its newest text and one with only
`TAGMSG`s in the window is not listed (ring times per scope, a second
`dm_conversations` time, migration 0085).

Maintainer decision implemented: `LIST` takes Libera's conditions and
advertises them (`ELIST=CMNTU`, `SAFELIST`), as Solanum's `m_list` parses
them — member counts, creation and topic times in minutes, name masks and
their negations, comma-separated, all of which must hold; each shard applies
them to the channels it owns. The reply, which could overrun the client's
SendQ and disconnect it on a network with more channels than that holds, is
now paced to half of it (DESIGN §7.2, §7.7). irctest's `testListMask`,
`testListNotMask` and `testListUsers` run and pass; the creation- and
topic-time cases still need a controller that can move the clock.

Maintainer decision implemented: `WHO` is paced like `LIST`. A `WHO *`, or a
`WHO` of a channel with more members than half the asker's SendQ, used to
queue every row at once and disconnect the asker ("SendQ exceeded"); its rows
now go out as the client reads, a remote channel's on the asker's shard, a
labeled one as one batch, and later WHOs follow it in order within one SendQ
— past that, `263 RPL_TRYAGAIN` (DESIGN §7.2).

Maintainer decisions implemented: history, SendQ and backlog are bounded in
bytes, and the authentication throttle is on by default. A resource-bounds
review found every memory cap counted items, not bytes. Each hot history ring
now also holds at most `max_history_ring_bytes` (500 KiB) and all of them
`max_hot_history_bytes` (512 MiB), shedding a ring's oldest entries and then
the least recently active rings; a multiline message's text is held once and
its plain line derived where it is stored. The SendQ is `sendq_bytes` (512
KiB, the 1,024 lines it held at a full line each; migration 0088 converts the
stored count), held output and paced LIST/WHO counted in the same bytes. A
network's backlog holds `buffer_cap` lines of at most 512 bytes' worth each,
in memory and in storage (5,000 rows, 2.5 megabytes), trimmed oldest first.
`limits.auth_rate_burst` defaults to twenty a minute per address and is turned
off only by `"off"`; a stored unset is migrated to the default (0088). The
bouncer-shutdown test's upstream now closes the link on `QUIT` as a server
does, where it had waited for the driver to close first and raced the end of
the shutdown (DESIGN §7.2, §7.3, §11, §18).

Cross-shard history and message fixes, with the maintainer's decisions
implemented (DESIGN §2, §7.7, §8, §11):

- **A multiline batch of only blank lines was delivered and stored** when
  another shard owned the channel: the check lived in the sender's own
  delivery only. Closing a batch now yields a `CompletedMultiline`, which a
  batch with no text cannot become, and both deliveries take only that.
- **Hot rings are sorted by `(ts, arrival)`.** A conversation line from the
  peer's shard or a stepped-back clock left rings out of time order, so
  BEFORE missed a message AFTER included, LATEST came out of order and ring and
  database pages disagreed at their edge. The ring now inserts in order, never
  takes in an entry older than one it shed (which would sit before a hole),
  and BETWEEN orders its pivots by that same place, which it had got wrong for
  a timestamp older than the ring. The new `chathistory_window` fuzz target
  (named in the code before it existed) checks every covered window against a
  model of the database.
- **TARGETS named another shard's channel by its folded key** (`#foo{x}` for
  `#Foo[x]`) when the database answered; it is named from the published
  channel directory.
- **Relayed messages name their target canonically** (Solanum parity): `#foo`
  for `PRIVMSG #FOO`, `Bob` for `PRIVMSG BOB`, on both shards' paths, so
  CHATHISTORY replay is the live line byte for byte.
- **One parser for CHATHISTORY and MARKREAD** in the core and the bouncer: the
  bouncer refused `BETWEEN #c timestamp=bad foo=1 10` with the wrong code and
  the core accepted a MARKREAD with a stray parameter.
- **A conversation's read marker is kept under the peer's identity**, as the
  conversation is, so it survives their nick change; an away grouped nick
  resolves to its account for both.
- **History retention covers memory**: the core's rings and the bouncer's
  backlogs no longer serve what storage maintenance deleted, and a console
  change applies at once.

A review of whether the docs, tests, CI and guards tell the truth found, and
this change fixes:

- **SASL-required mode** was promised by DESIGN §7.2 and did not exist.
  `limits.require_sasl` and `limits.require_sasl_from` (CIDRs) now refuse an
  anonymous client at the end of registration as Libera refuses its SASL-only
  ranges (465, `SASL access only`); both are console-owned and validated.
- **OIDC provider endpoints are HTTPS under `secure_cookies`**: the
  end-session endpoint in configuration, and every endpoint a discovery
  document advertises.
- **Guards that could be walked around.** The dead-public guard let a
  same-named definition keep a dead item alive (two were deleted) and never
  saw `pub mod`/`pub use`; the no-deferral guard missed ordinary rewordings
  and read PLAN.md alone; the `--locked` guard missed `cargo check`/`run`,
  toolchain-prefixed commands and most documents, and the fuzz build ran
  unlocked; two scripts ran service images by tag; irctest skips were never
  counted; the no-op guard read only Rust and took `panic!("")` as a message;
  the journey guard took any function as evidence. Each has a contract test.
- **Tests that could not fail**: a buffer-trim test settled by timing, a
  secret test that passed when a key was set, an assertion-free test, two
  `#[should_panic]` tests that took any panic, a contrast test of copied hex
  values, and an unchecked snapshot checksum.
- **Docs that disagreed with the code**: when a refused network parks (three
  documents), DESIGN §5's dependency policy, the default flood limits, the
  client's SASL mechanisms, and CI's PostgreSQL setup.

A review of the operator commands and channel modes against Solanum found,
and this change fixes, each with a test that failed before:

- **`KLINE 60 *@host` banned `*@60`**, and **`KLINE <nick>` banned
  `*@<nick>`**, a host nobody has. A leading duration is now minutes (below),
  and a bare nick bans that user's host or is refused with 401.
- **Unknown channel modes answered 472 once per letter**; now once per
  command, as Solanum does.
- **Ban, quiet, exception and invite-exception rows** carried no setter or
  time; each entry now records both and 367/728/348/346 report them.
- **A second OPER announced `+o` again and switched the audited operator
  identity**; it is answered 381 and changes nothing.
- **KNOCK on a `+g` channel reached only its operators, and RPL_KNOCK named
  the recipient**; every member of a `+g` channel hears it, in Solanum's
  `710 #c #c nick!user@host` shape.
- **SETHOST accepted globs and commas**; it takes Solanum's `clean_host`
  alphabet.
- **A KILL victim never saw the KILL line**; it is sent before the `ERROR`.
- **ChanServ spoke as three sources** (bare `ChanServ` for a mode lock, the
  server name for OP/VOICE and access on join, `ChanServ!ChanServ@services.*`
  for notices); one helper now names it for all of them.
- **DESIGN §7.6 promised user modes `+R` and `+Z` that did not exist**; both
  are implemented (below).

Maintainer decisions implemented: temporary K/D/X-lines (`KLINE <minutes>
<mask>`, at most 52 weeks) stored with their expiry (migration 0089), audited
with their length, shown in STATS with the lowercase letter and the time left,
lapsed on every shard on its tick with one notice per operator, never loaded or
listed once lapsed, and swept by storage maintenance; the administrator API
takes `duration_minutes` and lists `expires_at`, and the console has both.
`+R` refuses messages, notices, TAGMSG and INVITE from users not logged in
(486; operators pass); `+Z` is set on TLS connections, a trusted proxy's HTTPS
WebSocket included (transport `wss`), and WHOIS shows 671; both are in the
published user record and in RPL_MYINFO. TOPIC needs `can_send`, so an
unvoiced member of a `+m -t` channel cannot set it; `-i` (and `-l` without
`+i`) revokes recorded invites; `MODE me +i foo` applies `+i` only; `MODE #c`
from a non-member shows `+k`/`+l` without their arguments. `+l 10abc` and
`+l 0` stay refused with 696, a documented difference from Solanum.

A review of the web client and the console script found, and this change
fixes, each with a test that failed before:

- **The ban directory failed on "All kinds".** The filter form submits
  `kind=`, and the console forwarded its page query verbatim, so the
  contract's enum refused the read before it was sent; the accounts page sent
  its invitation cursor and the reauthentication flag to an operation that
  declares neither. Every directory's API query and pager link now come from
  one allow-list helper, `directoryQuery`, and a test pins that the console
  reads its page query nowhere else.
- **STATUSMSG sigils were hard-coded `@+`.** The chat client now reads
  `005 STATUSMSG` and takes off only advertised sigils, as the server's
  `NetworkNames::conversation` does, with its test cases (`%#dev`, `&#dev`).
- **A reconnect cleared "messages were not confirmed".** The socket's open
  handler cleared the key that alert shared with "Not connected"; the two
  have separate keys and only connection-down alerts clear on open.
- **PART, KICK and QUIT reasons kept their colour codes.** One helper renders
  every such reason.
- **Channel and nick names were drawn with bidi controls** in the
  conversation list, header, member list and alerts; they are stripped where
  drawn and each name is a bidi isolate.
- **An auto-join key beginning with `#`, `&`, `+` or `!` was saved as a
  channel.** The settings box separates entries by commas, and the word after
  a channel is its key, as the server's entry grammar reads it.

A review of wire safety found, and this change fixes (DESIGN §7.1, limits and
decoding):

- **A channel message of high bytes was replaced by a rejection notice.** Two
  hundred Latin-1 bytes fit the frame but decode to six hundred bytes of
  U+FFFD, and the bouncer replaced the whole line with an `:e6irc` "upstream
  input rejected" NOTICE. Decoding now fits the text again, so a line that fits
  as bytes is always relayed, and the notice speaks as `*bnc*`; the
  `bouncer_lines` fuzz target asserts it.
- **Echoed client tokens could split a bouncer reply** (`NICK :a b` answered
  `432 * a b :…`; `CAP :a b`, `JOIN :#a b` and `JOIN ::x` on a bridge alike).
  The core's echo rule is now `MiddleParam` in `e6irc-proto`, the only type the
  bouncer's attach numerics take.
- **Over-long lines that aborted the debug worker**: a `FAIL REGISTER` echoing
  a 480-byte account, and operator NOTICEs echoing an unbounded K/D/X-line mask
  or SETHOST host. `fail_line` clips and fits, every server NOTICE goes through
  one fitted `server_notice`, and server-ban masks are bounded. The bouncer's
  own notices carrying upstream text (a closing reason, SASL notes, bridge
  targets) go through a fitted `bnc_notice`, where a multi-byte reason used to
  turn them into the rejection notice. `core_dispatch` now also fuzzes with
  accounts enabled.
- **The core's numerics still took their middles as strings**, and let a space
  through for the one pre-joined mode string, so every call site echoing a
  client token had to remember to render it — and three did not: an invalid
  `+l` limit (`MODE #c +l :a b` answered `696 … l a b :…`), a WHOX query token
  (`WHO #c :%nt,a b` shifted every field of each 354 row), and the STATS letter
  (`STATS : u` sent an empty parameter). The refused target of a JOIN past the
  channel limit was echoed unclipped. The funnel now takes `core::Middle`
  values — `Middle::echo` for client or upstream text, `Middle::own` for the
  server's, `From` an integer — each written as exactly one parameter, and
  `RPL_CHANNELMODEIS` passes each mode argument as its own; `clip_echo` is
  gone. The remaining `FAIL TOPIC`/`SETNAME`/`INVALID_MESSAGE` lines built by
  hand now go through `fail_line`, and USERHOST, ISON and the HELP index
  measure their packed trailing against the line the funnel frames rather
  than a head rebuilt beside it.

A review of the client library, the TUI and the CLI found, and this change
fixes, each with a test that failed before:

- **A server could grow the connection's capability state without end.**
  Every name in every `CAP ACK` was enabled, requested or not, each by a
  linear scan: a peer streaming acknowledgements (an upstream network the
  bouncer connects to included) cost unbounded memory and quadratic time. A
  verdict now counts only for a name awaiting one, and the enabled set holds
  the program's own names, so the server cannot add one.
- **One Latin-1 line in the welcome burst failed the TUI's connect and
  `e6irc history`**, and the TUI never saw the MOTD or the 005 read while its
  capabilities were requested. That request now reads the burst as the
  steady-state stream does and hands every line back; the TUI shows it and
  takes the connection's naming rules (CASEMAPPING, CHANTYPES, STATUSMSG) on
  every connect, and its second copy of the STATUSMSG sigils is gone.
- **What a server said while a client connected was gathered in a list the
  server sized** — the TUI's whole connect, `tail`'s welcome burst — and a
  bouncer's playback there is thousands of lines. The waits now hand each
  line on as it is read (`e6irc_client::LineSink`): the TUI's state or its
  bounded queue, `tail`'s output.
- **`--history-lines` above the server's limit broke every connect**, and a
  server that cut pages to its own limit made the client mark unread lines
  read everywhere. Pages fit the 005 `CHATHISTORY` limit, a refused history
  request costs only that channel's history, and `history --count` is cut to
  the limit with a warning.
- **`--no-read-markers` still sent `MARKREAD`**: markers now follow whether
  the connection has `draft/read-marker` enabled.
- **A server that dropped the TUI right after welcoming it was reconnected to
  every two seconds forever**: the backoff starts afresh only after a session
  stays up for one liveness window.
- **The SCRAM-to-PLAIN step after a refusal before any credential was said
  only by the bouncer**; the TUI and the CLI now say it too.

A review of the sharded core found, and this change fixes, each with
a test that failed before:

- **A remote WHO answered after its asker closed aborted the worker.** The
  reply was queued to be paced to a connection that no longer existed, and the
  pacer's "only an open connection is paced" expectation killed the daemon.
  Paced LIST and WHO replies now live on the session itself, so none can be
  queued for, or paced to, a closed connection (DESIGN §7.2).
- **A second JOIN in flight to one channel lost member updates.** The session
  kept the channels with a JOIN in flight as a set, so the first answer (a
  refused key) ended the window of the JOIN behind it: a NICK sent between
  them never reached the owner that then admitted the user, a `JOIN 0` sent
  after both was spent on the refusal and left the user in the channel, and
  the channel limit undercounted. Both are counted per channel now.
- **A labeled MODE or KICK of a channel on another shard broke its labeled
  response**: the actor's own echo came after an empty `ACK`, untagged, where
  one worker sends it as the labeled answer. The owner now returns the actor's
  copy in the result; a ChanServ OP/VOICE of a remote channel had the same
  split, and a mode lock enforced by the JOIN that recreated its channel was
  told before that JOIN on one worker and after its labeled response on two —
  it now follows the JOIN inside it, alike on both.

Maintainer decisions implemented from a review of resource bounds (DESIGN
§7.2):

- **LIST keeps a cursor, not a copy.** A LIST used to clone the name and topic
  of every channel it admitted into one sorted list held on the session until
  it was paced out — some 65 megabytes per LIST at 100k channels, rebuilt by every
  `LIST`/`LIST` abort. It now holds its conditions and one resume key per
  shard, and each turn asks the shards for the next page after it, no larger
  than the room the client's send queue has; rows come out in casemapped name
  order across all shards, and an abort drops the cursor.
- **Every line is metered, and reads are paced.** PING and PONG were exempt
  from the command allowance and unregistered connections were never metered,
  so one client streaming PONGs (or churning NICK) could fill its shard's
  queue. Every line now spends a token where it enters the core — over TCP,
  `/ws/irc` and from the bouncer's in-process session — and an empty bucket
  stops the connection's reader until one is back instead of closing it with
  Excess Flood. The allowance keeps Solanum's shape (40, then 20 a second) and
  its operator exemption.

A further review found, and this change fixes, each with a test that failed
before:

- **`server-time` parsing accepted many spellings of one instant**:
  `2026-7-18T12:0:0Z`, `02026-…`, an empty fraction (`.Z`), trailing garbage
  after the fraction (`.000garbageZ`), and a fourth fraction digit, silently
  truncated. Fields are now fixed-width, and the fraction is absent or one to
  three digits up to the `Z` (the server emits three; one or two still come
  from third-party upstreams the bouncer ingests).
- **An empty secret or account passed through from the command line** of the
  CLI and TUI (`--password ''`, `--oauth-token ''`, `--account ''`), where an
  empty environment variable or file was refused; one check now covers every
  source.
- **The bounded queue judged room by count on a weighted queue**: `room()`
  resolved while the pending event did not fit (a busy spin), and a pop woke
  exactly one parked producer whatever weight it freed. Room is now asked for
  an event (`room_for`), and a pop wakes, in line order, every producer whose
  event fits; three new loom models cover the drop handoff, a receiver dropped
  under parked producers, and the last sender dropped under a parked pop
  (DESIGN §7.3).
- **An over-long line the framer dropped was answered without its label**,
  though a line refused later for the same reason was labeled; the framer now
  recovers the label from the prefix it held, over TCP and WebSocket alike
  (DESIGN §7.1).
- **The SCRAM client accepted an empty salt**; it is a malformed server-first
  message now.
- **An IPv4-mapped CIDR ban (`*!*@::ffff:203.0.113.0/120`) was stored but
  could never match**, subjects' addresses being canonical IPv4; the same held
  for `limits.trusted_proxies` and `limits.require_sasl_from`. A mapped range
  is now read as its IPv4 range everywhere, and one shorter than `/96` is
  refused.
- **An attachment was counted as attached before it subscribed** to the
  network's live events, so `attached_clients` could report a client that
  would only see what was published in between through the ring's replay;
  `lagged_attach_is_not_left_open_with_stale_session_state` waits on that count
  and hung under load (its burst went into the 8-line ring instead of lagging
  the live feed). The count is now taken by the subscription itself
  (`AttachSnapshot::attachment`), for raw-IRC and web attachments alike.
- **DESIGN §7.1 described CAP and SASL state machines in `e6irc-proto`** that
  are not there, and the message module claimed a serializer; both now say
  what the crate holds.

A review of how connections end found, and this change fixes (DESIGN §7.2,
§13.4, §15, §18):

- **Shutdown did not wait for clients to receive their closing `ERROR`.** It
  was queued, and the runtime's end cancelled its write. Every connection task
  (IRC plaintext and TLS, `/ws/irc`, attach) now holds a `ConnectionTask`, and
  shutdown waits for them for at most 8 s once the core has stopped; the unit's
  stop budget is 65 s.
- **The shutdown request itself was unbounded**: a shard with a full queue it
  no longer took from held it before the core's stop budget began. It is now
  made within that budget.
- **A session the core had closed kept its socket, task and per-IP slot** for
  as long as its client trickled out the backlog, while its reader kept
  pushing (and counting) lines. A SendQ kill now discards the backlog and sends
  only the closing `ERROR`, as Solanum does; every ended session has 5 s in
  all to receive what it is owed, and its reader stops at once.
- **The closing `ERROR` could be destroyed by a reset.** IRC sockets and
  `/ws/irc` now close lingering, as HTTP refusals do.
- **`X-Forwarded-For` skipped an unparsable entry** and walked on into entries
  the client wrote. Such an entry before the client's address now refuses the
  request (`400`), with a rate-limited log line naming the proxy.
- **`/ws/irc` ended sessions by dropping the socket** and reported every end
  as "WebSocket closed"; a message over the frame limit closed the connection.
  It now sends a Close frame (1000), reports the transport's reason, answers an
  over-long message `417` and closes (1009) only past a 64 KiB ceiling.
- The attach listener showed a mapped IPv4 client in its IPv6 spelling; an
  unloadable attach certificate was counted as a TLS handshake failure (now
  `configuration`); `/ws/ui` sent a pong of its own beside the WebSocket
  layer's (which the layer's replacement of its queued pong kept to one on the
  wire; the redundant arm is gone and a test holds one ping to one pong).

A review of the bridges found, and this change fixes, each with a test that
failed before (DESIGN §10.5):

- **One remote message could detach every attached client.** A message was
  one IRC line per newline, unbounded, published in a tight loop into a
  broadcast of 1024: two thousand newlines overflowed it, every attached
  client was detached as too slow, the backlog writer recorded a gap, and
  blank lines went out as empty `PRIVMSG`s. A message is now at most 16 lines
  and a counted notice, blank lines are left out, and a burst (a resumed
  Matrix sync, a Discord RESUME's replay) waits for the subscribers.
- **One unreadable Discord dispatch ended every session.** A `MESSAGE_CREATE`
  that did not decode ended the session before its sequence number was
  counted, so each RESUME replayed it into the same failure; a bad READY spent
  an IDENTIFY on every attempt. The envelope is read first, each dispatch on
  its own, and an unreadable one is a "malformed" notice in its channel.
- **A lost position was never announced.** A Matrix kick forgot the whole sync
  position, and a refused Discord RESUME started afresh, so what every other
  channel said meanwhile was skipped without a word. Every bridge now says so
  in each channel, once, when a session cannot resume; a Matrix kick drops
  only that room from the position and rejoins it.
- **Slack configuration errors were retried forever.** Only the token codes
  parked; `missing_scope`, `not_allowed_token_type`, `invalid_arguments` and
  the like reconnected on the transient schedule. Slack errors are a typed
  classification now, and what only the owner can fix parks at once. A
  Discord channel id is parsed as a snowflake with the configuration.
- **Slack skipped the shared status check.** Its Web API calls decoded the body
  of a 3xx or 5xx as the answer and ignored a 429's wait, so failed name
  lookups hammered a rate-limited Slack. Every bridge request is a
  `BridgeRequest` whose only send reads the status.
- **A Slack bot was renamed by its own edits**, to its id and back, and a bot's
  message could look up nine mentions where eight were meant.

Maintainer decisions implemented for the bridges:

- **Discord text reads literally.** Outbound text is escaped for Discord's
  Markdown, so IRC text is not rendered as headings, quotes, lists, spoilers
  or masked links, and a `/me` stays italic whatever underscores it holds.
- **One policy for threads and edits.** A thread reply is a line in its
  parent's bridged channel and an edit is `* <new text>` on every bridge;
  Discord dropped thread messages and ignored edits, and Matrix read an edit
  only from its fallback body.
- **Matrix keeps its long poll.** A client's line is delivered while `/sync`
  waits, instead of cancelling and reissuing it per line.

A review of the administrator and network API found, and this change fixes:

- **A managed server network could be saved that stopped the next start.** Its
  validator checked nick, real name and autojoin only for blankness while the
  start parses them strictly and exits on a configured network it cannot
  build; validation now is that parse (`UpstreamIdentity`), and the `400`
  carries the validator's reason, naming the field, instead of "missing or
  invalid required fields".
- **The OpenAPI create schema had no bounds** on a network's name, address,
  nick, real name or SASL fields, and `autojoin_keys.keep` had none on its
  length. Create, replace and the connection test now share one field
  description built from the handlers' constants, held to them by a test; the
  handler refuses a `keep` longer than autojoin can be.
- **A SASL login was trimmed on edit and stored verbatim on create.** All three
  requests parse it into `UpstreamSaslAccount`, which refuses surrounding
  whitespace.
- **The accounts page said "Showing an older page." on the first page** of a
  directory with more, reading a next cursor as the current position. Every
  console pager now takes its status from its own query through one renderer.
- **A stale configuration revision was a `503` on the scalar PATCH** and a
  `409` everywhere else and in the contract; one save-result mapper serves
  both.
- **"Bouncer not enabled" branches answered a state no server can be in** (a
  database but no registry). The HTTP state now holds the two as one `Backing`
  value, and the branches, the empty-list fallback, the template banner and
  the contract's `404` descriptions are gone.

Maintainer decisions implemented from the same review:

- **A network the server configuration defines for an account is the
  operator's.** An account's create under its name, and PUT, PATCH and DELETE
  of it (the administrator's per-owner toggle too), are `409`s that leave it
  running; the registry refuses to replace or stop a configured slot, and a
  stored row is never shown with its runtime. `/me/networks` and
  `/admin/networks` list it with `configured: true`, read-only in both clients.
- **`/admin/networks` pages by a bounded, stable cursor** (`limit`, `after`,
  `next_after`), like the other administrator directories.
- **Exact filters are one rule:** a blank value is a `400`, not "no filter";
  bounds count characters, as the contract's `maxLength` does; the audit
  `actor` and `target` filters fold against account principals.

Maintainer decisions implemented from a review of configuration, storage and
qualification (DESIGN §8, §17, §18):

- **A settings revision another process commits reaches the serving one.**
  `rotate-secrets` writes the stored settings from a process of its own; the
  table's announcement brings the revision to the serving process, and a save
  that still finds its revision stale reloads it, so the console never wedges
  on a revision it cannot see. (Several processes *serving* one database is
  not supported: one serves, the others stand by — below.)
- **The load harness measures fan-out, not the flood limiter.** A burst past
  the server's command burst is refused unless the senders oper up, and
  `qualify-linux.sh` passes the operator or refuses; the claimed core-shard
  count is checked against the server's own.
- **The authentication throttle stays on for upgrades (0088)**, with an
  upgrade note on `trusted_proxies` and a start-up warning when a loopback-only
  HTTP listener without trusted proxies makes every user share one budget.

Maintainer decisions implemented from the last sweep (DESIGN §8, §11, §18):

- **History has one total order, `(ts, msgid)`**, byte-compared in the ring
  and `COLLATE "C"` in the database (index built concurrently, 0093), so a
  millisecond's lines persisted by different shards page identically from
  both; msgid counters are fixed-width so one shard's ids ascend as stamped.
  An interrupted concurrent index build is dropped and rebuilt on the next
  attempt.
- **Read markers stored under a nick follow the identity key (0094):** a
  grouped nick's to its account, an unregistered nick's to `~nick`, the newer
  of two kept.
- **The MOTD is bounded in bytes as sent** (`MAX_MOTD_BYTES`, half the
  smallest SendQ, counted at the longest server name and nickname) as well as
  per line. Migration clamps of stored values (0091's `buffer_cap`, 0094's
  MOTD) are revisions of their own with a `CONFIG` audit entry carrying the
  previous value in full.
- **`E6IRC_PUBLIC_URL` may be unset**, like a database-backed file's omitted
  `[http].public_url`: the stored value applies, and a first start with none
  stored refuses naming `http.public_url`.
- **A settings save that moved the BNC listener and found its revision stale
  binds straight to the reloaded revision** (`follow_bnc_listener`, shared with
  the settings watcher).

Maintainer decisions implemented from a review of Solanum and Libera parity
(DESIGN §7.2, §7.6, §7.7):

- **NickServ and ChanServ are present to presence queries** — WHOIS, WHO,
  ISON, USERHOST, MONITOR and INVITE — from one record per service.
- **Nick changes are throttled** at Solanum's `anti_nick_flood` values as
  Libera runs them (five per twenty seconds, 438), operators exempt; and one
  nick keeps at most twenty WHOWAS records.
- **A bare NAMES lists every visible channel**, then the users in no channel,
  paced as a LIST is and across every shard.
- **A young connection's QUIT comment is `Client Quit`** (Solanum's
  `anti_spam_exit_message_time`, five minutes, as Libera). It is the
  console-owned `limits.anti_spam_exit_message_time_seconds` (0 to 3600,
  applied without a restart); irctest runs e6ircd with it at 0, as Solanum's
  controller runs Solanum, so its `testQuit` runs in the green list.

The same review found, and this change fixes, each with a test that failed
before:

- **A channel name could hide a formatting control**: `JOIN #lib\x0fera`
  created a channel shown as `#libera`. Channel names are parsed once
  (`ChannelName`) and a look-alike or over-long one is 479, as Solanum's
  `disable_fake_channels` refuses one.
- **Any command reset WHOIS idle time**; only a PRIVMSG does now, and the
  reaper keeps its own liveness clock.
- **INVITE named the invitee as the inviter typed it** and never said they
  were away; it uses their own nick and follows 341 with 301.
- **Empty, listed and server targets**: `WHOIS :`, `WHOWAS :` and `PING :`
  were answered as a missing nick or not at all, `WHOIS a,b` looked up
  `a,b`, and a server argument to WHOIS, VERSION, TIME, MOTD, ADMIN or LINKS
  was ignored; they are 431, 409, the first nick, and 402 or answered here.
- **WHO** matched a mask against nick and host only, and showed `*` for a
  nick's channel; it matches username, server and realname too and shows a
  channel the asker may see. Its `o` flag and WHOX selector parse as
  Solanum's do, and the help says so.
- **MONITOR stored targets that could never be nicks**, including a spaced one
  that broke its 731/732 lists.
- **Closing lines had four shapes**, and a long stored ban reason made an
  over-long one at registration; one function builds and fits them all.
- WHOIS 312 carried the network name where Solanum puts the server's
  description; MODE's help left out `+R`; `MAXLIST`'s comment said per list.

A review of the bouncer's drivers, registry and attach path found, and this
change fixes, each with a test that failed before (DESIGN §10):

- **The local driver relayed the core's `ERROR :Closing Link`** (a KILL, a
  GHOST or REGAIN, a K- or D-line) to every attached client and into the
  backlog. Both drivers now read every line through one control-line function
  (`PING`, `CAP`, keepalive `PONG`, `ERROR`); `ERROR` is a notice and the
  drop's diagnostic. The local driver also rejoins the channels joined at
  runtime after such a drop, sharing the `irc` driver's `JoinedChannels`.
- **Attach reconciliation flooded the upstream and the shared queue**: two
  questions per channel whose JOIN had aged out. Every line the `irc` driver
  writes is now paced (5 at once, then 2 a second, Solanum's allowance); the
  session follows each channel's topic and members, so an attach and a
  browser's `NAMES` are answered from them, and at most two channels' lists
  are asked for per attach; a full command queue is told live, never retained.
- **Replay misattributed**: it started at the current nick. The ring keeps the
  session state at its oldest entry, and an attach is reconciled to it before
  the replay and to the current state after (maintainer decision); the attach
  layer's numerics follow the client's current nick. A backlog restored from
  storage after a restart still started at the current nick; each stored line
  now records the own nick it was said under (migration 0096), and the
  restored ring's head starts from it.
- **A client attached before the registration burst never learned the
  network's ISUPPORT**: the welcome is built from the attach snapshot, and the
  burst's end is told to each attachment as a `005` of what changed.
- **Shutdown raced an in-flight replace**, which then started a driver into
  the emptied registry; shutdown now takes the mutation lane and closes the
  registry. Drivers are prepared, then launched after persistence subscribes.
- **Echoes around a `CAP NEW`/`DEL echo-message` were doubled or lost**, and a
  refused capability was re-requested on every `CAP` line.
- **Status**: the up-front attach status says why a network is down, a new
  failure reason within one outage is retained once, and an owned network
  without a driver says whether it is disabled, being reconfigured, or failed
  to start and why. The persistence task files a line under the nick it was
  said under.

A review of account authority found, and this change fixes:

- **A suspended or deleted account stayed attached** through the attach
  listener to a shared or configured network, and a password checked just
  before the suspension could attach after the sweep. `attach` now takes an
  `AccountLease` the account lifecycle revokes on the mutation lane; the
  listener spends a ticket taken before the credential check on it, so the
  race is refused. The core's sweep also closes a session that authenticated
  but had not registered, which it used to skip.
- **An OIDC link finished from any browser** within ten minutes of its start:
  link and re-authentication flows now seal a `BoundSession`, and the link is
  checked live, the account's and recent in the transaction that inserts it.
- **A grouped nick's app-password exchange** answered 401 after a successful
  verify: verification yields a `VerifiedAccount`, which minting takes.
- **OAUTHBEARER ignored its GS2 authorization identity**; a token can no
  longer act as another account.
- **Device codes were stored in plaintext**; 0095 keeps their SHA-256.

Maintainer decisions implemented from the same review:

- **Suspension holds the account's configured networks** stopped
  (`owner_suspended` in the inventory) and reactivation restarts them;
  deletion holds them for good (`owner_deleted`), across restarts too.
- **A password change ends every live IRC session and bouncer attachment** of
  the account, and a verdict for a check queued before it is refused.
- **The serving process applies an account's authority whoever changed it**:
  a suspension, deletion or primary password change committed by another
  process (`recover-administrator`, a hand-written row) ends the account's IRC
  sessions and attachments there, applied once from the store's announcement
  (0095's `authority_generation`, `AuthorityLedger`).
- **Revoking an app password or a personal access token ends what it signed
  in**, and only that: IRC sessions and bouncer attachments keep the
  credential that opened them (`CredentialId`), migration 0097 announces each
  revocation by id, whichever process deletes it, and the server closes that
  credential's sessions (`App password revoked`) and attachments; a check of
  it in flight is refused. Before, they stayed open for as long as they lived.
  A session a token signed in ends at the token's expiry, as `/ws/ui` does,
  not when maintenance prunes it.
- **A verdict read while the revocation listener was disconnected** could
  open a session for a credential revoked meanwhile, after the re-connected
  listener's re-read. The re-connection now first refuses every check in
  flight on every core shard and at the attach listener (the client retries),
  for account authority and issued credentials alike.
- **The design's SASL OAUTHBEARER row described OIDC JWT validation** the
  server does not do; it names the personal access token it verifies.
- **New passwords are at least 8 characters** (NIST SP 800-63B) unless the
  console-owned `registration.minimum_password_length` (1–128, applied live)
  says otherwise; existing passwords still verify. irctest runs at 1, so its
  services suite's short passwords register unmodified.
- **Device authorization speaks RFC 8628 as written**: form bodies with a
  bound `client_id`, per-code polling pace with `slow_down`, and RFC 6749
  error and token responses; `e6irc login` speaks it.

Maintainer decisions implemented for high availability (DESIGN §1, §7.3, §8,
§18; `deploy/README.md`, High availability):

- **Active/standby, never active/active.** One process serves a database — the
  core, the bouncer registry and every driver, the database worker, storage
  maintenance, the sampler, read-marker expiry, and the IRC, attach and HTTP
  listeners. Several serving processes are IRC linking by another name and
  stay a non-goal.
- **A second process stands by automatically**, loudly (a stderr line,
  `/readyz` 503 naming the holder, `/healthz` 200, nothing else served), and
  takes over when the lease is released (graceful stop) or expires (crash).
- **Lease timing is fixed**: a 15-second TTL, a renewal every 3 seconds, a
  fence 10 seconds after the last confirmed renewal on the monotonic clock,
  every lease comparison on the database's `now()` (migration 0098).
- **Fencing is enforced by PostgreSQL too**: every pool connection passes
  `serving_lease_register_backend`, and a takeover ends the previous holder's
  recorded connections, so its queued writes fail and none lands.
- **A fenced holder holds on through an outage unless actually taken over**:
  past the fence it keeps its clients and hot state, answers `/readyz` 503
  (`lease: unconfirmed`) and keeps renewing; a renewal that finds the lease
  still its own resumes it, one that finds another holder drains and exits.
- **Only the holder migrates**; a standby older than the schema refuses at
  boot; `rotate-secrets` and `recover-administrator` never migrate under a
  serving process and refuse an older schema with "upgrade the serving process
  first".
- **PostgreSQL's own high availability must replicate synchronously**, or a
  failover can roll the lease row back; the first upgrade to this release
  stops every process.

## Edge tier

Goal: e6irc deploys and redeploys without dropping a client connection
(DESIGN §1, §19). A connection-holding edge (`e6ircd edge`) holds client
sockets and the core's records of them; the core, the serving-lease holder,
can then be replaced gracefully or after a crash while every socket stays
open. The phases run in order, each on the one open pull request of its
time, and each lands green on its own: it builds in every feature
configuration, tests, clippy, `tools/gate.sh`, the dead-code guard and the
fuzz type-check all pass, and DESIGN §19.9's rewrites for that phase land
with it.

Status: phases 0, 1, 2 and 3 done; phase 4 is the next to build; every other
phase is scheduled in the order below.

- **Phase 0 — design (done).** DESIGN §1 (goal and non-goals), §2 (the edge
  tier's invariants), §19 (the design and its settled decisions), a §18
  cross-reference, and the glossary's "Edge tier" terms. *Green because*
  documentation only; the terminology, no-deferral and journey guards pass.
- **Phase 1 — extract `e6irc-edge` (done).** Move accept, the TLS acceptor and
  certificate reload, client-address resolution (`ClientIp`, `PeerLimitKey`,
  `ConnLimiter`), `peer_write`, `lingering_close`, the framing read and write
  loops and the WebSocket framing helpers into an `e6irc-edge` crate with no
  sqlx; a `tools/gate.sh` guard over `cargo tree` holds "no sqlx in
  `e6irc-edge`". DESIGN §4 and §7.2. *Green because* a pure move: the single
  process is unchanged and every existing test passes as is.
  As built (DESIGN §19.1, "Phase 1 as built"): the moved code reaches the core
  only through `CorePort`, which e6ircd implements over `CoreIngress` with the
  same `Input` events, and counts through `TransportTelemetry`; the session
  identity the accept assigns (`ConnId`, `ConnectionIdAllocator`,
  `ConnectionTransport`, `Output`) moved with it. The guard is
  `tools/check-edge-isolation.sh`: no sqlx or other PostgreSQL client, no
  `e6ircd` and no `reqwest` in any dependency kind, feature or target, with
  its contract test run against a scratch workspace.
- **Phase 2 — in-process link (done).** The core reaches connections only
  through link frames: the remote send queue with `Drained` accounting,
  credits, `Kill` and `End`, pacing woken by `Drained`; bouncer attach and
  `/ws/ui` become link session kinds; the flood meter moves to the edge.
  DESIGN §7.2. *Green because* every existing test, irctest included, runs
  through the in-process edge with "SendQ exceeded", pacing and the closing
  drain unchanged.
  As built (DESIGN §19.1, "Phase 2 as built"): `e6irc_edge::link` gives each
  session's link two ends — the core's `SessionLink`, the remote send queue
  counting every byte until the edge reports it written, and the edge's
  `EdgeSession`, the bounded buffer its writer drains — and every session that
  reaches a core shard (TCP, TLS, `/ws/irc`, the `local` driver's) opens and
  speaks through them and `CorePort`; `Drained` travels through the
  loom-verified `e6irc_queue::Progress`, wakes a paced reply's turn, and
  replaces the 20 ms pacing reminder; a credit in process is room in the
  shard's queue, granted first come first served; the meter
  (`e6irc_edge::meter`) is the edge's, with each session's exemption set on
  its link; the `/ws/irc` connection loop is the edge's. The one visible
  change is the one DESIGN §2 prescribes: a client that stops reading is cut
  at `sendq_bytes` unwritten, not up to twice that. Bouncer attach and
  `/ws/ui` are link session kinds (`Attach`, `Ui`) whose output keeps exactly
  the backpressure their sockets gave — the core's end waits for room and
  for what it wrote to be on the socket, bounded by the 30 s write deadline,
  and never kills for "SendQ exceeded" — settled by the maintainer. The
  attach listener accepts and serves through the edge's own loops over an
  `AttachPort`, each session's lines on a per-session inbound queue that is
  their credit; `/ws/ui`'s connection loop and its Ping liveness are the
  edge's, with DESIGN §19.2 defining its frames: a text message as `Output`,
  the client's messages as `Message`, and a close frame on `End`. The
  `/ws/irc` and `/ws/ui` upgrade handlers stay in e6ircd until upgrade
  authorization (phase 3).
- **Phase 3 — process boundary (done).** The `e6irc-link` codec and its
  `link_frames` fuzz target; `e6ircd edge`; the mutual-TLS link and
  `e6ircd edge-credentials`; the epoch fence; `/readyz`-based discovery; HTTP
  proxying and upgrade authorization; edge configuration from `Welcome`; the
  `core_edges` roster; the PROXY protocol version 2 on edge listeners; the
  `Hello` role field, with the observer role refused loudly by name; the
  connection directory paged by a monotonic directory key the core allocates
  at `Open` (re-allocated in the records' original order at a rebuild), with
  `ConnectionIdAllocator` and `LiveConnectionQuery` documented as promising a
  unique, never reused, unpredictable wire identity and no order. A core
  restart still closes sessions, loudly (`ERROR … (server restarting)`), and
  so does a link reset. DESIGN §4, §8, §9.4, §17. *Green because* behaviour is
  identical except for the process boundary, and the first process-level
  tests run on Linux, macOS and Windows.
  As built (DESIGN §19.1, "Phase 3 as built"): `e6ircd edge` runs the edge's
  own accept, framing and write code against `RemoteCorePort`, which feeds
  each session's in-process link pair from the core link's frames; the core
  serves links on `[edge_link]` (`edge_link.rs`), one TLS stream per shard,
  and has no listeners of its own in edge mode. The `/ws/irc` and `/ws/ui`
  upgrades are authorized by the core's own handlers over the HTTP link pool
  (grant headers, not an `HttpRequest` frame) and completed at the edge;
  HTTP serving moved to `e6irc_edge::http`. Slots are 14 bits, keeping
  identifiers inside the HTTP boundary's signed 64-bit range, and an
  edge-mode core counts its own sessions in slot 0. `Open` carries the kind,
  address and transport; the TLS facts and the cut identifier join it with
  the phase that reads them, under a new link version. The zero-drop suite's
  first scenarios need no PostgreSQL and run in the `test` job on all six
  cells; the roster and the `/ws/ui` and attach scenarios run in `db-tests`,
  and irctest's green list runs a second time through an edge, in its own
  `irctest-edge` job. Settled by the maintainer at review: the edge serves
  its own metrics now (`[metrics]`, the monitoring token, the core's format)
  rather than in phase 9, since edge mode is usable from this release; the
  console in edge mode renders no listener field and shows each edge's
  listeners and certificates as reported; the link's headers are one
  namespace a client can neither send nor read; request admission stays the
  core's.
- **Phase 4 — graceful rebuild.** PostgreSQL 18 installed natively on the
  macOS and Windows runners (D15), since this is the first phase whose
  zero-drop scenarios need it; `Open` gains the connection's TLS facts and
  `Hello` the cut identifier, with the roster's last cut, under link
  version 2 (the core then accepts 1 and 2, exercising the N−1 path).
  Session records, channel replicas,
  acknowledge after effect with retained lines, the graceful cut and
  rebuild, re-authorization, durable ring epochs and `ReplayCursor`s, paced
  replies resumed, `local` driver sessions homed on an edge, the handover and
  final stops (`e6ircd stop --handover|--final`); the deterministic
  restart-at-every-step test; the zero-drop suite's graceful scenarios. DESIGN
  §7.3, §8, §10, §11.2. *Green because* a graceful core restart becomes
  drop-free and exact, and a crash still closes sessions loudly.
- **Phase 5 — crash takeover.** The rebuild without a cut, catch-up lines,
  `NOTE INPUT_UNCONFIRMED`, the roster wait and late edges, the core-absence
  limit, resending after a link reset, and the interplay with the
  database-outage hold. *Green because* a crash becomes drop-free, with the
  zero-drop suite's crash scenarios asserting losses equal the reported
  counts.
- **Phase 5b — warm standby.** A standby registry beside the lease: each
  standby records its observer-link address in a row heartbeated and expiring
  as the lease is, announced on change. The holder pushes the current standby
  list to its edges over the core link (`Welcome` and on each change), and
  edges dial observers from it, with no operator configuration naming a
  standby under systemd, containers or Kubernetes. Standbys receive every
  record and replica as written; at `Hello{cut}` the new core fetches only
  the revisions that differ, so the upload leaves the gap. DESIGN §8, §18. *Green because*
  the observer role is additive (a standby without it still takes over by
  full upload, the phase 5 path), and the zero-drop suite runs its graceful
  and crash scenarios both with and without a warm standby, recording the
  gap of each.
- **Phase 6 — edge-held IRC upstreams.** `UpstreamPort` with its edge and
  in-process implementations, upstream records, gap PONG and the bounded gap
  buffer, the egress verdict pushed to the edge. DESIGN §10. *Green because*
  core-held stays the default until the zero-drop upstream test (no `QUIT`,
  no second registration, the nick unchanged) passes on all three operating
  systems.
- **Phase 7 — edge handover.** Listener and plaintext socket handover:
  `SCM_RIGHTS` and in-place re-execution under systemd on Linux and macOS,
  `WSADuplicateSocketW` on Windows outside the Service Control Manager; the
  overlap drain with its operator deadline. *Green because* it is a new,
  opt-in operation, proven by the zero-drop suite's handover and drain
  scenarios.
- **Phase 8 — kernel TLS on Linux.** The unbuffered handshake,
  `dangerous_into_kernel_connection`, record counting against the
  confidentiality limit, and the loud end of a connection on a key update
  after handover. *Green because* it is opt-in (`tls_handover = "kernel"`),
  refuses to start when the module is unavailable, and has its own Linux
  zero-drop scenario.
- **Phase 9 — deployment and qualification.** systemd units, Compose,
  Kubernetes manifests and `deploy/README.md`; DESIGN §18's edge mode; the
  stop-budget guard gains the handover budget; the chaos soak; the 100k
  scale qualification with its gap measurement; the journey that proves the
  outcome (`docs/journeys/`). *Green because* documentation, guards and
  measurement.

Maintainer decisions for the edge tier (DESIGN §19.10), every recommendation
of the design adopted:

- **D1** `e6ircd edge` subcommand over a database-free `e6irc-edge` crate.
- **D2** Single process stays the default, as an in-process edge.
- **D3** Client TLS terminates at the edge (kernel TLS on Linux, primary) or
  at a load balancer; both supported.
- **D4** Edge upgrade is live handover plus the overlap drain; no in-repo TLS
  record layer.
- **D5** Input of unknown fate after a crash: at most once, with
  `NOTE INPUT_UNCONFIRMED`.
- **D6** Unauthenticated conversations' rings live in the participants'
  records; WHOWAS and the LUSERS maximum travel in the cut state and are lost
  at a crash, declared.
- **D7** Edge-held IRC upstreams are built (phase 6).
- **D8** Mutual TLS on every link, loopback included.
- **D9** In edge mode listeners belong to the edge's bootstrap configuration,
  shown read-only in the console.
- **D10** Per-address limits are core-authoritative, with an edge pre-filter.
- **D11** Record bodies: read N and N−1; advance the written version with
  `e6ircd records advance`.
- **D12** A 10-minute core-absence limit and a 30-second roster wait.
- **D13** `local` driver sessions are homed on an edge.
- **D14** Windows under the Service Control Manager upgrades by overlap
  drain; live handover under any other supervisor.
- **D15** PostgreSQL 18 is installed natively on the macOS and Windows
  runners for the zero-drop suite.
- **D16** In edge mode SIGTERM is a handover; `e6ircd stop --final` closes
  clients.
- **D17** The edge proxies all HTTP.
- **D18** The warm standby is phase 5b, right after crash takeover, with the
  observer role reserved in `Hello` in phase 3; standbys are found through a
  standby registry beside the lease that the holder pushes to its edges.

Maintainer answers to the phase 0 review:

- **Replay marking.** The core marks accumulating lines *retained for replay*
  in the acknowledgement; the edge replays exactly those and never reads a
  payload (DESIGN §2, §19.2).
- **Standby discovery** is the standby registry, not operator configuration
  (DESIGN §19.8, phase 5b).
- **Connection-directory order.** A directory walk that can miss a live
  connection is a bug: the directory pages by a core-allocated monotonic
  directory key, and the slot-prefixed identifier is only the wire identity
  (DESIGN §2, §19.2, phase 3).
- **PROXY protocol version 2** lands in phase 3; **`e6ircd stop
  --handover|--final`** lands in phase 4.

## Remaining qualification

- Run the shipped credential-gated campaigns for Discord, Slack, and each
  required OpenID Connect issuer.
- Run the tuned-host scale campaign. It remains required for production scale
  claims.

## Rules

- One open pull request.
- Fix discovered defects in the active change or ask for a decision.
- Keep this file current; detailed contracts belong in code and journeys.
