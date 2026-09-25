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
  the core shows the `USER` name.
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
  as spelled.
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

## Remaining qualification

- Run the shipped credential-gated campaigns for Discord, Slack, and each
  required OpenID Connect issuer.
- Run the tuned-host scale campaign. It remains required for production scale
  claims.

## Rules

- One open pull request.
- Fix discovered defects in the active change or ask for a decision.
- Keep this file current; detailed contracts belong in code and journeys.
