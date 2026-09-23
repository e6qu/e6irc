# e6irc — Design

A monolithic Rust IRC daemon with a built-in REST API, web backend (OIDC login),
and per-user BNC hosting — plus a CLI client, a TUI client, and a vanilla
JavaScript web client bundled with Vite.

License: **AGPL-3.0-or-later**. All compiled-in dependencies must be
AGPL-compatible (permissive licenses are fine; license compliance is enforced
in CI with `cargo-deny`).

Unfamiliar term? See [`docs/terminology.md`](docs/terminology.md) — the
glossary of IRC, OpenID Connect, and deployment vocabulary used here. The
product outcomes and their automated evidence are mapped in
[`docs/journeys/`](docs/journeys/README.md).

---

## 1. Goals

- **One binary** (`e6ircd`) that is simultaneously:
  - a modern IRCv3 server (single server = the whole network, no S2S linking),
  - an HTTP server exposing a versioned REST API,
  - the web backend for the browser chat client and server-rendered console,
  - an OIDC relying party (web users log in via registered OIDC providers),
  - a BNC host: always-on sessions on the local server, ZNC/soju-style
    bouncer connections to **external IRC networks**, and (via the same
    abstraction) bridges to non-IRC services (Matrix, Discord, Slack).
- **Libera.Chat compatibility** as an explicit target (§7.7): e6ircd matches
  the shared Libera protocol surface, and the BNC connector targets Libera as
  its primary external network. The client matrix records qualification limits.
- Designed for **~100k+ concurrent connections** on one machine.
- **Small binary, high performance**: no needless dependencies, one TLS stack,
  one async runtime, compile-time templates, feature flags for optional
  subsystems.
- Frontend static assets are **deployable two ways** from the same Vite build:
  served from static storage (e.g. S3/CDN) or embedded into the server binary
  behind a compile-time feature.
- **Cross-platform release binaries**: all binaries (`e6ircd`,
  `e6irc-cli`, `e6irc-tui`) build for **Linux, macOS, and Windows**, each
  on **amd64 (x86_64) and arm64 (aarch64)**. Linux is the primary server
  deployment target, but no OS/arch in the matrix is a second-class port;
  CI builds and tests all of them. OS-specific behavior (signals, keyring,
  file permissions) always has an explicit per-OS implementation, never a
  silently missing feature.

### Non-goals

- Server-to-server federation (IRC linking). Single-server only; the internal
  state model is not required to keep seams for later linking.
- Dynamic plugin loading (`dlopen`). Bridges are compiled in behind feature
  flags; the monolith stays statically linked.
- Supporting non-vanilla Postgres or other SQL backends. PostgreSQL is the
  one persistence backend.

---

## 2. Engineering principles

These are project-wide rules, enforced in review and (where possible) CI:

- **No silent no-ops.** Every client-observable command either works or fails
  loudly (`ERR_UNKNOWNCOMMAND`, IRCv3 `FAIL`, HTTP 4xx/5xx). Accepting and
  ignoring input is banned. Unimplemented-but-planned surface returns an
  explicit error, never a fake success.
- **No silent fallbacks.** No empty catches, no "log and continue" in logic
  paths, no defaults that mask configuration errors. Network retry/backoff
  (BNC reconnects, OIDC JWKS refresh) is legitimate unreliability handling
  and is not covered by this rule.
- **Provenance required.** Vendored test corpora and protocol reference data
  (numerics tables, ISUPPORT strings captured from Libera, irctest) carry
  source URL, license, pinned commit/date, and checksum, and are excluded
  from the build.
- Code never references plan phases or bug IDs; the "why" goes in commit
  messages.
- **Make bug classes unrepresentable; fix classes, not instances.**
  When a bug is found (by a test, a harness, or review), the first
  question is "what is the *class* of this bug, and can the design make
  it impossible?" — a type, an API shape, or a single choke point beats
  a spot patch. Concretely in this codebase:
  - *Parse, don't validate*: raw input crosses into typed values once,
    at the boundary (proto parser, config deserializer); interior code
    never re-checks strings.
  - *Newtypes for meaning*: values with different invariants get
    different types even when representation matches — casefolded map
    keys vs display names, session tokens vs their hashes, wire lines
    vs unescaped text.
  - *States as types*: invariants like "registered sessions have a
    nick" are encoded so the invalid combination cannot be constructed,
    not `expect()`ed at each use.
  - *One choke point per concern*: message delivery variants, numeric
    formatting, credential verification each have exactly one
    implementation; a second call path is a review flag.
  - Process-wide singletons (crypto provider, runtime) are pinned once
    at startup, never resolved ambiently.
  - *A paragraph justifying a line, or a comment excusing a shortcut,
    means the code is probably wrong*: multi-sentence comments defending
    one statement — or explaining why a corner was cut — are refactor
    signals. Make the invariant real, or just do the thing properly,
    until the defense is unnecessary.

  The invariants this principle has actually installed, each closing a
  class that had bitten (a spot patch would have left the class open):
  - `ChanKey`/`NickKey`/`HistoryKey`/`AccountKey` — casefolded map keys are a
    distinct type from display names, constructible only via
    `chan_key`/`nick_key`/`account_key`, so "index the channel/account table with
    un-casefolded input" cannot be written. `AccountKey` types every in-core
    account map (read markers, registered founders, channel access) onto the
    folded convention; the DB enforces the same at the `name_folded` edge.
  - `MaskKey` — the casefold-key discipline extended from map keys to *list*
    elements: a channel's ban/quiet/exception `Vec`s and the **server-ban list**
    hold `MaskKey`, which folds once in its constructor and carries the display
    form alongside, so a `push`/`contains`/`retain` cannot compare an un-folded
    mask and let a ban silently fail to match, while STATS still shows the
    operator's original casing. The one place map keys couldn't reach — a folded
    comparison over a `Vec` — is now closed the same way, and the by-hand
    `mask::eq` it replaced is gone.
  - `BncBufferKey` — every database operation on a persisted bouncer buffer
    constructs the same casefolded `(owner, network)` composite key used by the
    live registry. A URL/delete spelling such as `Libera` therefore cannot
    resolve the case-insensitive network row but miss (or orphan) backlog stored
    under `libera`. The storage API accepts display spellings only at this one
    constructor boundary; callers cannot issue an un-folded buffer query.
  - Stored BNC driver kinds are a closed set at both edges: PostgreSQL constrains
    `bnc_networks.kind` to the compiled model's `irc`/bridge variants, and row
    decoding returns `InvalidNetworkKind` instead of defaulting an unknown value
    to `irc`. Corrupt or future-schema data fails startup/read loudly rather than
    reinterpreting bridge configuration and credentials as an IRC upstream.
  - `WireLine` — the injection class (an embedded CR/LF/NUL in a line's content,
    which would split it into a second forged line on the wire) is
    unrepresentable *at the delivery funnel*, in every build: `deliver` takes
    only a `WireLine`, whose sole constructor `sanitized` neutralizes those bytes
    (leaving the one trailing CRLF terminator). Before, the funnel checked only
    line *length*, and injection was prevented solely upstream by parse-rejection
    plus per-position sanitizers — a line carrying an injection byte from an
    untrusted *data* source the core relays (a history body, a bridged line) had
    no funnel backstop. Unlike an over-long line (a *code* bug the debug
    assertion panics on), an injection byte is data the core must handle rather
    than abort the shared worker on, so it is neutralized in all builds, not
    asserted against.
  - `ComposerResult` — a web-composer response is either `Sent` or `Rejected`;
    success cannot carry an error and rejection always has one.
  - `CredentialAttemptBudget` — IRC registration, services, OPER, and BNC attach
    consume the same closed per-connection authentication budget. Valid and
    malformed completed SASL payloads spend a slot, exhaustion is permanent,
    and no ninth attempt can reach password verification. An authenticated
    session cannot replace its account through a second SASL exchange; it gets
    the protocol's 907 refusal.
  - `SendOutcome::Rejected(ClientLineError)` — the BNC's public driver queue
    boundary admits only one syntactically valid IRC client frame within the
    independent tag/body budgets. Raw attach and browser validation improve
    their own error reporting, but cannot bypass this final admission rule.
  - `PendingServiceReply` — a deferred NickServ reply is a value, so no pending
    request cannot be confused with an unlabeled one.
  - `CredentialRow` / `OidcIdentityRow` / `WebSessionIdentity` — named SQL
    projections prevent same-typed columns from being transposed at a caller.
  - `LockedAccountState` / `HistoryMarker` / `WhoRowData` / invitation rows —
    named rows preserve account, history, WHO, and invitation field meanings.
  - `AccountDeletionTargetRow` / `HistoryTargetRow` / `ChannelMutationOwnerRow`
    — named rows preserve deletion, history-target, and channel-control fields.
  - `CredentialHash` / `CredentialVerificationRow` / `PasswordMutation` /
    `SessionLogoutHint` — credential, transaction, and logout fields have names.
  - `CredentialOrigin` — a credential-verify verdict (`PasswordVerified` /
    `PasswordRejected` / `Unavailable`) answers *either* a SASL `AUTHENTICATE`
    or a NickServ `IDENTIFY`; the request carries which, echoed onto the reply,
    so `db_reply` routes on the origin the request *was* rather than inferring
    it from `sasl == Verifying` / `pending_identify` session flags. The old
    inference conflated "which command asked" with "is the attempt still live";
    a verdict routed under the wrong flag logged the client in as the wrong
    account. The flag now gates only liveness (drop a superseded verdict).
  - `ReadMarkerStored` / `ReadMarkerUnavailable` — an authenticated MARKREAD
    update is a database-confirmed state transition: only the stored verdict
    may enter the hot mirror or fan out to sibling clients, while a queue/store
    failure produces an explicit `FAIL`. Pending targets reserve their
    per-account cap slots until the verdict, so waiting for durability cannot
    reopen an unbounded-growth race.
  - Registered-channel and server-ban mutations are database-confirmed state
    transitions. Channel registration stores its initial topic in the INSERT;
    retained TOPIC, KEEPTOPIC, MLOCK, and DROP carry typed
    stored/missing/unavailable verdicts, and only a stored verdict changes
    their hot mirrors or confirms the command. A revisioned pending-topic
    overlay orders pipelined TOPIC and KEEPTOPIC without reading stale
    committed state, while pending channel
    registrations reserve both the channel name and the founder's cap slot.
    K/D/X-line storage is constrained to that closed set; a corrupt row aborts
    startup. Add/remove writes the ban row and audit row in one transaction;
    enforcement, disconnects, operator notices, and HTTP admin responses happen
    only after it commits. The IRC and HTTP origins are typed requesters, so a
    global committed result does not depend on a still-live `ConnId`, and no
    sentinel connection can accidentally stand in for an admin request. A
    committed change is announced to operators once, by the shard that
    committed it; the other shards reconcile from the `ServerBanApplied`
    broadcast without announcing, and a removal the database could not find
    reconciles silently (the requester alone is told nothing was stored).
  - `PersistedChannelMutation` — the founder web console and REST API do not
    write channel rows beside the live core. They submit one typed mutation to
    the core, which validates and canonicalizes it, while the serial database
    worker locks and re-checks founder ownership, writes the mutation and audit
    row in one transaction, and returns a typed verdict. Only an applied verdict
    changes the hot founder/topic/KEEPTOPIC/MLOCK/access maps.
    Registration from ChanServ and the owner control plane shares one audited
    insert; the HTTP origin is admitted only when an identified session for the
    actor currently operates the live channel, and its typed verdict seeds the
    same founder/topic mirrors.
    The API and ChanServ therefore cannot write independently committed
    versions of one setting, and restart preload reads the same rows that
    produced the live verdict. MLOCK parsing
    orders modes by the closed lockable-mode set, so equivalent policies have
    one stored and returned spelling; migration 0038 normalizes historical
    rows and constrains future storage. A corrupt/non-canonical preload is a
    startup error, never a silently missing lock.
  - `ConnectionEvent` — the bouncer SPI's connection-state event *cannot
    carry a line*, so a driver can't route text past the line sanitizer and
    detached-buffer append; the bypass is a compile error, not a lint.
  - `IrcSessionSnapshot` — a BNC's current nick and confirmed channel set live
    outside its bounded replay ring. Raw IRC and browser attaches reconcile
    that authoritative snapshot after playback, so an aged-out JOIN, a stale
    PART, or a reconnect cannot manufacture current membership from history.
    The IRC driver also derives reconnect-intent deltas from this one tracker;
    attach state and the next rejoin set cannot parse the same upstream line
    with two subtly different membership rules.
  - `subscribe_with_replay_snapshot` — buffered emitters retain the IRC-session
    and buffer locks through broadcast publication, while each raw/browser
    attach subscribes and snapshots both under those same locks. The
    replay/live boundary therefore places every buffered line and its resulting
    nick/membership state on exactly one side: no timing window can lose it or
    deliver it twice. A client that overruns the bounded live broadcast is
    detached after a visible gap notice, because continuing could preserve
    stale nick or membership state.
  - `AttachCapability` — BNC attach capability names, state changes, `CAP LS`,
    and `CAP LIST` derive from one closed set. An attach cannot use SASL without
    negotiating it, and a new capability cannot be accepted but omitted from
    discovery or state reporting.
  - `MessageKind` (PRIVMSG/NOTICE) — one type with `wire()`, `db()` and
    `is_loud()`, so the uppercase verb, the lowercase storage token, and the
    "does it auto-reply" rule cannot drift; before, the ring and the database
    stored different casings of the same message.
  - `StatusSigil` — the STATUSMSG `@`/`+` target sigil is `Option<enum>`, so
    "does this enter history / narrow the audience" is `is_none()` and a
    method, not a byte compared against `0`.
  - `crate::sanitize` — one module holds every "turn untrusted text into a
    field safe for its wire position" function (username, account name, bridge
    nick token, upstream line sanitizing and bounding, client-tag-key validation,
    nick/channel validators), each documented with the position it protects
    (prefix / middle / tag / trailing). A new field gets the right rule by
    reaching for the module rather than re-deriving a one-off filter.
  - `Authenticated`/`AdminAccount`/`AdminPageActor` — an HTTP handler is
    authenticated (or admin-gated) because it *asks for* the extractor in its
    signature, which runs the check as a precondition of being called. JSON
    routes use API rejection semantics; server-rendered administrator pages use
    the login redirect plus session-bound CSRF derivation. An admin route or
    page cannot forget the gate: the ungated handler fails to compile for want
    of the argument, rather than relying on every handler to open with the same
    line.
  - `SessionUserAgent` and owner-scoped browser-session queries — login
    provenance is bounded and neutralized exactly once before storage, while
    inventory and revocation always bind both the folded account and the
    resource id. A guessed id cannot disclose or revoke another account's
    session, and the opaque authentication token and its hash never enter an
    inventory row.
  - `ConnectionIdAllocator`/`LiveConnectionPageSize` — every production
    ingress transport draws from one randomly boot-seeded, non-wrapping ID
    source, and live-state queries can retain only a typed bounded page plus
    one cursor sentinel. Disconnect mutations carry the selected ID to the
    shared teardown path and owner mutations recheck its authenticated account;
    mutable nick reuse cannot redirect a stale control to another client.
  - `AuditLogRow`/`AuditLogPageSize` — the audit read binds named columns into
    a typed row instead of returning five transposition-prone strings, and an
    invalid zero/oversized page cannot reach SQL or cursor arithmetic. Stable
    `id < before_id` pagination excludes concurrent appends by construction.
  - `AccountDirectoryRow`/`AccountDirectoryPageSize` — the administrator
    account read has a typed, secret-free posture projection and a bounded
    page size. Stable `id < before_id` pagination replaces the former
    unbounded name dump, while an exact lookup enters storage only through the
    same RFC1459-folded key used by authentication.
  - `RegisteredChannelDirectoryRow`/`ServerBanDirectoryRow` and their bounded
    page-size types — persistent administrator policy inventories are typed
    projections with stable `id < before_id` pagination. Exact channel,
    founder, and mask lookup reuses the RFC1459-folded storage keys; ban kind
    enters the query only after validation against its closed K/D/X-line set.
  - `WhoxRow` — WHOX reply fields are a struct, not a row of same-typed
    `&str`, so two fields cannot be transposed at a call site.
  - `HistoryDbRow` — the history read binds columns by **name**
    (`#[derive(sqlx::FromRow)]`), not by position. As a 7-tuple with four
    same-typed `String` columns, transposing any two compiled cleanly and
    silently mis-mapped (a replayed message showing its body as the source
    prefix); the computed `ts_millis` column is aliased so it has a name to bind
    to. Same class as `WhoxRow`, closed at the SQL edge.
  - `DbRequest::QueryHistory.target` — a database history read names one exact
    stored buffer: a channel, or the conversation key of two accounts. There is
    no fallback to guess between, because a conversation with an
    unauthenticated party is never stored (§11.1.1).
  - `Hidden` — a `+s` (secret) channel is invisible to non-members on *every*
    surface, including the ones that change the channel. The predicate lives
    once in `Channel::hidden_from`, and the deny surfaces
    (MODE/KNOCK/TOPIC/KICK/INVITE) carry the returned `Hidden` token — across
    the channel-owner hop when there is one — to the one `deny_hidden` helper,
    which answers `ERR_NOSUCHCHANNEL`. No surface can hand-pick a different
    numeric (`TOPIC`, `KICK` and `INVITE` once returned 442, confirming the
    channel exists — an existence oracle); the token has no other consumer.
  - A deferred reply is matched by exactly one release on every path. A
    command that may answer synchronously (a refusal, a full queue) answers
    under the dispatch capture and defers nothing; only a request that was
    actually queued defers, and a capture records that it was deferred rather
    than having it inferred from "nothing was sent". A defer no verdict would
    release held every later line for that connection until the send-queue
    kill — which a refused ChanServ REGISTER did to its caller.
  - A core worker never awaits a push into its own bounded queue: it is the
    only task that can pop it, so a full queue meant parking forever, with
    ticks and shutdown (and the database flush) parked behind it. Effects for
    this shard are handled inline by `Core::handle`, so the worker, the tests,
    and the fuzzers share one semantics; only other shards' effects are routed.
  - Nor does it await another worker's queue, which is the same deadlock with
    two participants. It `try_push`es; what does not fit waits in a bounded
    per-destination backlog (65,536, in order) while the worker keeps reading
    its own queue, woken by `Sender::room()` — a future that holds no payload
    and is therefore cancel-safe. Exceeding the backlog stops the worker with
    the typed `CoreWorkerExit::Backlogged`, which supervision treats as the
    critical failure it is.
  - One worker and N workers give the same answers by construction. The
    session's shard counts the JOINs it has routed to another shard
    (`Session::pending_joins`) from the moment they are sent, so a pipelined
    burst meets the channel limit exactly as on one worker. What a
    command needs to know about a user or channel on another shard (WHOIS,
    ISON, USERHOST, MONITOR, WHOWAS, LUSERS, a labeled away reply) is read
    from process-wide directories that every shard — including a lone one —
    answers from; the same-shard lookups were deleted, so the mistake cannot be
    re-made. `SessionStore::get_mut` and the channel directory's mutable
    accessors record what was touched and `Core::handle` republishes what
    changed after every event, so "forgot to publish" is unrepresentable. What
    *acts* on a session (KILL, GHOST, SETHOST, a delivery) is routed to its
    shard as a typed input. A user's AWAY/SETNAME/CHGHOST/NICK/QUIT reaches
    each peer exactly once however many channel owners report it: the
    recipient's session shard deduplicates, so there is no election to lose.
  - The registered-session count is maintained at the transitions, in the one
    function that can register a session, and debug-asserted against a full
    scan; it used to be recounted over every session after every event.
  - `require_form_actor` — the one precondition shared by every
    server-rendered mutation: resolve the cookie account and verify the
    submitted session-bound CSRF token before returning an actor. Forms carry
    the token in their body, so standard browser submissions work without a
    feature-gated client runtime.
  - `FormBody<T>` — URL-encoded form rejection is an extractor contract, not
    handler boilerplate. A server-rendered mutation that asks for a form gets
    the same problem response for malformed input before its body runs, so a
    new handler cannot forget or invent a different parse-failure path.
  - `RateLimited` — a request that has spent one token from the per-IP
    auth-rate budget, as a `FromRequestParts` extractor. Every unauthenticated,
    work-inducing route declares the throttle by asking for `_: RateLimited`
    instead of opening with the `client_ip` + `auth_rate_ok` prologue (and
    pulling in `ConnectInfo` + `HeaderMap`) by hand — so the gate lives in one
    place and an ungated route is a conspicuous omission rather than a forgotten
    first line, which is how `device_token` came to lack it. Same shape as the
    other extractors, for the throttle rather than the auth check.
  - `escape_tag_value` — the tag-value escaper's output is wire-safe *by
    construction*: `;`/space/`\`/CR/LF get their escapes and a NUL (which has no
    tag escape and cannot ride a wire line) is dropped, so a caller that reaches
    the escaper directly — bypassing `Message::to_line`, which also rejects NUL —
    cannot put a raw NUL on the wire and truncate the line. The single choke
    point for tag-value wire safety, rather than a guard one call path can skip.
  - *No argon2 on the serial DB-worker loop* — both credential-verifying and
    account-creating requests are intercepted in `run_worker` and spawned under
    the `verify_sem` bound; their inline `handle_request` arms are `unreachable!`.
    So the ~100ms hash never runs on the one serial worker, where a cheap
    one-line REGISTER/AUTHENTICATE could otherwise head-of-line-block every
    queued CHATHISTORY read and login behind it. The structural guard (offload +
    `unreachable!`) makes "an argon2 op on the serial loop" unwritable.
  - `TerminalSafe` — untrusted server text that reaches the user's terminal
    (in `e6irc-cli` and `e6irc-tui`) as *text for a person* can only take this
    form. The two machine-readable outputs keep exact values instead, and are
    safe for stated reasons: `tail --json` always writes DEL and C1 as `\uXXXX`
    (inside a JSON string that is the same value, so a pipe loses nothing and a
    terminal sees nothing), and `e6irc api` neutralizes the response body only
    when standard output is a terminal, giving a program the exact bytes. Its sole
    constructor `from_untrusted` neutralizes every terminal control byte (the
    C0/C1/DEL/CSI escapes the wire parser lets through, since it rejects only
    CR/LF/NUL). The TUI's `LogLine` fields are typed `TerminalSafe`, so a render
    path cannot be handed a raw escape sequence — the client's terminal safety
    is a project invariant rather than a reliance on the TUI framework's internal
    control-char filtering. One shared definition across both client crates.
  - *Monotonic watermarks are seeded, never a zero sentinel* — a session's
    `flood_refilled_to_ms`/`last_active`/`last_ping_sent` are all initialized
    from the open-time `MonoMillis`, never `MonoMillis(0)`. Because the mono
    clock's epoch is process start, a zero is indistinguishable from a real early
    reading, so a `now − 0 = uptime` computation misbehaves in the first moments
    of uptime. Seeding from the open time removes the sentinel so the class
    cannot recur on a new watermark field.
  - `bridge_send` — every reverse-direction (IRC→upstream) bridge HTTP send
    whose failure is an HTTP status funnels through one checked helper that
    rejects a non-2xx. The raw `reqwest::Response` from a bare `.send()` never
    reaches delivery-outcome logic, so "send, ignore the status, report
    delivered" — a silent drop — is unwritable (the Matrix bridge had exactly
    that against a 403/429/5xx). The same choke-point shape as the inbound
    `BoundedJson` body cap.
  - *Bridge protocol payloads are parsed into typed envelopes at ingress.*
    Unknown Discord dispatches, Matrix event kinds, and Slack envelope/event
    kinds remain intentionally ignorable protocol extension points. A malformed
    known HELLO/READY/message, `m.text`, or `events_api` payload is instead an
    error that drops into the driver's reconnect policy. Required provider data
    therefore cannot become a made-up heartbeat interval, empty identifier,
    `"?"` sender, or silently absent message through JSON-index defaults.
  - Transport-owning modules deny Clippy's `let_underscore_must_use`: a
    fallible socket write, flush, queue push, or task join cannot be discarded
    with the project's former `let _ = ...` idiom. Active-session writes are
    checked and terminate or reconnect on failure; the few terminal/broadcast
    notifications with no possible observer use an explicit discard. This
    closes the class where a failed PONG or status notice left a driver/socket
    running as if delivery had succeeded.
  - `stamp()` returns the `(ts, msgid)` pair from one clock read, so a
    message's server-time tag and its history copy cannot disagree.
  - `Millis` — epoch time is a newtype, not a bare `u64`, so a seconds value
    cannot be passed where milliseconds are meant and `server_time(ts * 1000)`
    does not compile. Both historical unit bugs (a whole-second clock that made
    same-second messages unpageable, and a `* 1000` that put REST timestamps a
    thousandfold into the future for six sweeps) are now type errors; the two
    conversions live behind `as_secs()` and the SQL edge, named and greppable.
    The SQL boundary rejects pre-epoch and precision-losing values, so corrupt
    signed storage cannot wrap into a future protocol time or become epoch.
  - `logRegion` — every dynamically rendered console backlog or live log gets
    its bounded-scroll container, log role, accessible name, and keyboard focus
    in one constructor. A new Safari-inaccessible overflow region cannot be
    produced by copying only the visual `backlog` class.
  - `scrollRegion` — every dynamically rendered console table gets its region
    role, purpose-specific accessible name, and keyboard focus in one
    constructor. Refresh code cannot overwrite a neighboring table's identity
    after rendering.
  - The wire-length **runtime** invariant (§7.1): where a *type* is
    impractical (every outbound line is a `String`), a debug-build assertion
    at the one send funnel makes the class machine-checked by the test and
    fuzz suites instead. The technique generalizes: when the value can't be
    typed, put one check at the one choke point and let the fuzzers find
    regressions.

- **The boy-scout rule (hard).** Leave the code cleaner than you found
  it; if you see something broken, fix it — even when it looks unrelated.
  Everything here is one system, so nothing is truly unrelated; a defect
  only *looks* unrelated because no one observer holds the whole in view
  at once. Fixing what you find (or loudly surfacing what you must not
  silently change) is always in scope. See `AGENTS.md` for the full
  statement and the pre-stop checklist.

---

## 3. Architecture overview

**Module layout.** The HTTP surface lives in `http/`, one module per concern —
oidc, device, openapi, history, ws, credentials, networks — with `mod.rs`
holding the router, `AppState`, the extractors and the shared response helpers.
The core worker's command handling lives in
`core/handler/`, one module per command family — registration, sasl, services,
channel, message, chanops, query, history, monitor, read_marker, oper — with
`mod.rs` holding dispatch and the helpers they share. The split is by *what a
command does*, so the module a change belongs in follows from the command being
changed. Submodules reach
shared helpers through `use super::*`, and items crossing a module boundary are
`pub(super)`, which keeps the dead-code guard able to see unused ones.

```
                        ┌────────────────────────── e6ircd (one process) ─────────────────────────┐
                        │                                                                          │
 IRC clients ──6697────▶│  IRC listener (TLS/plain)          ┌───────────────┐                     │
 (irssi, weechat,       │        │                           │  IRC core     │                     │
  e6irc-cli/tui)        │        ▼                           │  (channels,   │                     │
                        │  Session multiplexer ◀────────────▶│   users,      │                     │
Browsers ──443────────▶│  (attach/detach, playback)         │   modes,      │                     │
  (chat + console)      │        │                           │   services)   │                     │
                        │        │ network drivers           └───────┬───────┘                     │
                        │        ├─ local     (in-process)           │                             │
                        │        ├─ irc       (Libera, OFTC, …) ─────┼──────▶ outbound TLS         │
                        │        ├─ matrix    (feature flag)         │                             │
                        │        ├─ discord   (feature flag)         │                             │
                        │        └─ slack     (feature flag)         │                             │
                        │                                            │                             │
                        │  HTTP (axum): REST /api/v1 · OIDC · askama pages · WS · [static]        │
                        │                                            │                             │
                        │  History/write pipeline ── batched ────────┴──▶ PostgreSQL              │
                        └──────────────────────────────────────────────────────────────────────────┘
```

The **session multiplexer** is the architectural centerpiece (§10): every
user-facing "network" — the local server itself, an external IRC network, or
a bridged service — is a **network driver** behind one trait. Always-on
presence, detached buffering, multi-client attach, and history playback are
implemented once, above the drivers.

---

## 4. Repository & workspace layout

```
e6irc/
├── Cargo.toml                # workspace
├── crates/
│   ├── e6irc-proto/          # IRC message model, parser/serializer, casemapping,
│   │                         #   numerics, ISUPPORT, CAP/SASL state machines (no I/O)
│   ├── e6irc-queue/          # custom bounded queue: the core↔DB and SendQ
│   │                         #   communication primitive (§7.3); loom-verified,
│   │                         #   step-schedulable for deterministic tests
│   ├── e6ircd/               # the monolithic server binary
│   ├── e6irc-client/         # client library: connection, TLS, SASL (PLAIN +
│   │                         #   OAUTHBEARER), chathistory helpers
│   ├── e6irc-cli/            # scripting-oriented CLI client binary
│   ├── e6irc-tui/            # ratatui TUI client binary
│   ├── e6irc-load/           # load generator binary: many concurrent clients,
│   │                         #   connect rate and exact fan-out measurement
│   └── e6irc-qualification/  # runs credential-gated external qualifications
│                             #   and writes and verifies their evidence files
├── fuzz/                     # cargo-fuzz targets and corpus; its own package,
│                             #   outside the workspace, built by CI's fuzz-smoke
├── web/                      # Vite project (vanilla JavaScript chat client)
├── migrations/               # sqlx migrations (embedded in binary)
├── deploy/                   # systemd unit and the
│                             #   deployment guide
├── docs/                     # glossary, user journeys and their coverage,
│                             #   client capabilities, API-first inventory
├── tools/                    # CI guards and their tests, backup/restore,
│                             #   release packaging, browser and recovery
│                             #   journeys, load sweep and qualification scripts
├── test/                     # Compose override for the Shauth single-sign-on
│                             #   journey
├── vendor/                   # third-party test material (irctest, reference
│                             #   servers, a Libera snapshot); never compiled in
├── Dockerfile · deny.toml
├── AGENTS.md (CLAUDE.md is a symlink to it) · DESIGN.md · PLAN.md · BUGS.md
└── LICENSE                   # AGPL-3.0-or-later
```

`e6irc-proto` is I/O-free and shared by server, BNC upstream connector, and
both native clients — one parser to fuzz, one behavior everywhere.

---

## 5. Technology choices

| Concern | Choice | Rationale |
|---|---|---|
| Async runtime | **tokio** (multi-thread) | The ecosystem standard; everything below assumes it. |
| Queues | **custom `e6irc-queue`** | The core↔DB and per-connection SendQ primitive; built in-repo so it can be step-scheduled, traced, and loom-verified (§7.3). The always-on driver/attach layer (§10) additionally uses tokio `broadcast`/`mpsc` for event fan-out and command delivery. |
| TLS | **rustls** (default `aws-lc-rs` provider) | No OpenSSL anywhere in the tree (enforced by `cargo-deny`); one TLS stack for listeners, upstream BNC connections, Postgres, and HTTP clients. |
| HTTP | **axum** + tower | Thin over hyper, tower middleware for auth/rate limits; no needless layers. |
| Database | **sqlx** (postgres + rustls features only) | Async, compile-time-checked queries, embedded migrations. |
| Templates | **askama** | Compile-time templates → fast, no runtime template engine in the binary. |
| Web client | **askama + standard forms** for server-rendered management; a small first-party runtime for confirmation/copy/refresh; vanilla-JS live chat bundled by **Vite** | No SPA framework or production package dependency; server-rendered where state is the server's, client-parsed where it is the client's (chat buffers/nick lists). |
| TUI | **ratatui** + crossterm | Standard, portable. |
| Passwords | **argon2** (argon2id) | For local passwords and hashed app passwords. |
| OIDC | **openidconnect** crate | Certified-flow implementation of code+PKCE, discovery, JWKS. |
| Config | **toml** + serde, `E6IRC_*` env overrides | No config-framework dependency. |
| Logging | Line-oriented operational messages on stderr | Human-readable process diagnostics; machine consumers use the typed JSON/Prometheus observability surfaces in §16. |
| Metrics | Fixed-cardinality in-process atomics + bounded histograms | One typed snapshot feeds the console, JSON API, Prometheus exposition, readiness, and PostgreSQL history (§16). |

**Dependency policy — minimal, only what's really needed:**

- The table above is the *approved* dependency set; adding any crate beyond
  it requires a written justification in the PR: what it does that stdlib /
  tokio / an already-present dependency cannot, and why hand-rolling it
  in-repo is worse. Small utilities (a left-pad, a tiny format helper, a
  simple backoff) are written in-repo, never imported.
- `default-features = false` on every dependency; features are enabled
  individually and each enabled feature must be used.
- Every dependency must build and pass tests on the full target matrix
  (Linux, macOS, Windows × amd64, arm64); arch- or OS-specific code paths
  (SIMD, intrinsics, platform APIs) need an equivalent path on the other
  targets — no x86-only or Unix-only crates without a gated alternative.
- The transitive tree is part of the review surface: CI posts a
  `cargo tree` diff on PRs that change `Cargo.lock`, and `cargo-deny` gates
  licenses (AGPL-compat), duplicate major versions, and known advisories.
- Periodic pruning: a dependency whose justification no longer holds is
  removed, not kept out of inertia.
- **Up-to-date, with a 24-hour cooldown**: dependencies are kept current,
  but a version is only adopted once it has been published on crates.io
  (or npm, for `web/`) for **at least 24 hours** — a supply-chain guard
  against compromised fresh releases. Publish timestamps are checked via
  the registry API when pinning or bumping; automated update PRs follow
  the same rule.
- **GitHub Actions follow the same rule**: the latest release of each
  action is looked up via the GitHub API (never guessed), adopted only
  if published ≥ 24 hours ago, and pinned to the exact release tag —
  except where an action's documented interface is a rolling tag (e.g.
  `dtolnay/rust-toolchain@stable`).

---

## 6. Feature flags & build profiles

Server (`e6ircd`) features:

| Feature | Default | Contents |
|---|---|---|
| `embed-web` | off | Embed `web/dist` via `rust-embed`; serve at `/`. Off → API-only, assets live on S3/CDN. |
| `matrix` / `discord` / `slack` | off | Each bridge driver and its HTTP/WS client code (`dep:reqwest`, and for Discord/Slack `dep:tokio-tungstenite`, `dep:futures-util`). |

The hand-authored OpenAPI 3.1 document at `/api/v1/openapi.json` and the
native IRC-over-WebSocket endpoint (§13.4, for third-party web IRC clients
such as gamja) are always compiled in — neither is feature-gated.
Observability is also always compiled in, so the console and automation read
the same process state (see §16).

Release profile (workspace):

```toml
[profile.release]
lto = "fat"
codegen-units = 1
opt-level = 3
strip = "symbols"
```

- **Server keeps `panic = "unwind"`**: a panic in one connection task must be
  caught at the task boundary (logged loudly, connection dropped) without
  taking down 100k other connections. Clients (`e6irc-cli`, `e6irc-tui`) use
  `panic = "abort"` for size.
- No fixed binary-size target. Size is kept small structurally (dependency
  policy, feature flags, one TLS stack, compile-time templates); CI reports
  the stripped size per-PR purely for visibility, with no threshold.

---

## 7. IRC server core

### 7.1 Protocol crate (`e6irc-proto`)

- Message model per RFC 1459/2812 as amended by the living "Modern IRC"
  specification (https://modern.ircdocs.horse) and IRCv3 message-tags.
- Zero-copy parse: a received line is kept as one `Bytes` buffer; the parsed
  `Message` borrows slices into it. Tag escaping/unescaping per the
  message-tags spec (https://ircv3.net/specs/extensions/message-tags).
  Serialization (`to_line`) fails loudly rather than emitting a byte it cannot
  represent: keys, source parts, and params reject any illegal byte, and a tag
  value is rejected (`SerializeError::BadTagValue`) if it holds a NUL — the one
  byte the value escaping has no encoding for. The four field positions share
  one contract so the "silently emit a raw control byte" class is closed
  symmetrically instead of per-field.
- Limits: 512-byte traditional message body; tags budget per spec (8191
  bytes total for tags on server→client, 4096 client→server as advertised
  by us); oversized input is rejected with `FAIL`/`ERR_INPUTTOOLONG`, never
  truncated silently. One shared predicate checks the tag and traditional
  budgets independently at server, BNC, WebSocket, and shared-client ingress;
  checking only their combined maximum would let an untagged line borrow the
  entire tag allowance. On *output*, a relayed PRIVMSG/NOTICE carries a source
  prefix the sender did not, so a within-limit message can overflow 512 once
  relayed; the text is trimmed to fit at delivery — once, so live delivery, the
  echo and CHATHISTORY agree — since a single message cannot be split the way a
  list-bearing numeric can. A debug-build assertion at the single send funnel
  (`wire_line_violation`) rejects any outbound line whose traditional part
  exceeds the limit, so the whole class is machine-checked by the test and fuzz
  suites rather than guarded site by site; it is compiled out of release, where
  a panic on the shared worker would be worse than the over-long line.
  Numerics fit at their own funnel: `ServerState::numeric` clips each middle and
  truncates the trailing against the accumulated head, so a numeric that packs
  many middles *and* a client-influenced trailing (WHOX's `RPL_WHOSPCRPL`, a
  realname) can't sum past 512 and be discarded whole. `server_name`/
  `network_name` are length-bounded at config load so the fixed head they sit in
  can't inflate that budget.
- Casemapping: **`rfc1459`** (what Libera/Solanum advertises), implemented
  once here and used for every nick/channel comparison in the entire system.
- Includes the numerics table, ISUPPORT token model, and the CAP and SASL
  client/server state machines (pure, I/O-free, unit-tested).
- Fuzz coverage also pins the byte-stream framer (`LineBuffer::feed`: every
  emitted line fits the inbound limit, and the line sequence is independent of
  how the stream is chunked into reads), `base64` (decode never panics on
  arbitrary text; encode/decode round-trips, which SASL relies on to recover the
  exact credential), and the bouncer's upstream line-processing (`sanitize` +
  `filter_tags`: whatever a hostile upstream sends, the line an attached client
  receives never carries a CR/LF/NUL that would split it into two). The hostmask
  glob (`mask::matches`, run against untrusted ban masks) is checked
  *differentially* against a textbook glob DP: the optimized single-`*`-backtrack
  matcher must agree with the spec on every input. The CHATHISTORY ring-window
  arithmetic is extracted as a pure `resolve_ring_window` and pinned by an
  exhaustive differential test (every ring size, subcommand, selector position
  and limit) against an independent index-range specification. The bouncer
  functions are reached through a `#[cfg(fuzzing)]`-only wrapper module, so the
  fuzz coverage does not widen the crate's real public surface.
- `floor_char_boundary`/`truncate_on_char_boundary`: the single primitive
  under every length-cap (topic, kick, away, composer line, bridged message).
  Slicing a `str` at a byte index inside a multi-byte character panics, and that
  is reachable from remote input wherever a budget meets non-ASCII text — so it
  lives once, tested and fuzzed, rather than hand-rolled per site.
- Fuzz targets (cargo-fuzz) for parser and tag unescaping, and for the
  stateful core: `core_dispatch` drives one connection, `core_multi` drives
  several interleaved and adds the events no client sends (the liveness tick,
  deferred database pages). A panic there takes the single worker down for
  every client, so "survives whatever a client sends" is the whole oracle.
  `client_messages` runs the other direction — it feeds the shipped TUI
  arbitrary *server* output, because a client's state is derived from lines a
  remote server chose and that server need not be this one.

### 7.2 Connection lifecycle

- Listeners: plaintext (default 6667) and TLS (6697, rustls); optional
  PROXY-protocol v2 support for LB deployments (config-gated).
- One tokio task per connection owning the socket; outbound traffic goes
  through a **bounded** per-connection queue of `Bytes` (SendQ). Queue-full →
  the classic ircd answer: kill the slow client with a "SendQ exceeded" quit.
  No unbounded buffering, no silent drops.
- RecvQ/flood control: a token bucket per connection, on by default with
  Solanum's shape (`limits.command_burst = 40` tokens, `limits.command_rate =
  20` per second; a registered non-oper session spends one per command, PING
  and PONG exempt, and is closed with Excess Flood when the bucket is empty),
  plus per-IP connection throttle and registration throttle. It used to be off
  by default with a fixed one-token-per-second refill, which left every
  output-amplifying command class — repeated JOIN/NAMES targets, repeated list
  modes — unbounded for anyone who never turned it on, and made any burst that
  was turned on flood-kill an ordinary autojoin storm.
- JOIN, PART and NAMES target lists are casefold-deduplicated and bounded by
  the advertised `TARGMAX` (`JOIN:250`, `PART:250` — the channel limit — and
  `NAMES:1`, as on Libera); the first target past the bound is refused with
  ERR_TOOMANYTARGETS. A JOIN of a channel already joined is a no-op (no echo,
  TOPIC or NAMES; a comma list naming a 10k-member channel a hundred times used
  to clone its member list a hundred times). A list mode named more than once
  in one MODE is dumped once. `TOPIC <channel>` with one parameter is a query
  however it is framed (`TOPIC :#c` used to clear the topic). Every echo of
  client text, PONG included, is fitted to the 512-byte wire limit.
- Registration pipeline: `CAP LS 302` → (SASL) → NICK/USER → welcome burst
  (001–005 with ISUPPORT, LUSERS, MOTD). SASL-required mode configurable
  globally and per-IP-range.

### 7.3 Queue-based core: state model at 100k+ connections

**Current implementation and qualification boundary.** The daemon starts a
configured nonzero number of single-threaded core workers (default one).
Workers own their shard state; shared directories and typed queue events route
session work and broadcast global commits. Connection tasks and the database
writer communicate through bounded queues. Runtime N=2/N=3 coverage proves
the lifecycle, routing, delivery, and shutdown. Tuned-host scale qualification
remains required before a performance claim.

**Target architecture rule.** The server is a set of **single-threaded event
loops ("workers") that own their state exclusively**; the *only*
communication between workers — and between I/O tasks and workers — is
our custom queue (`e6irc-queue`). No shared mutable state, no cross-worker
locks. Every state mutation is an event consumed from exactly one queue,
which gives:

- **Single-writer correctness**: each piece of state has exactly one
  owner; per-queue total order makes "who mutated what, when" a linear,
  replayable log rather than an interleaving of lock acquisitions.
- **Step-by-step debuggability**: in test/sim builds a `Stepper` freezes
  the world and advances one event at a time across chosen queues;
  event traces can be recorded and replayed deterministically.
- **Deterministic simulation testing**: the whole core (workers + queues,
  I/O mocked at the edges) runs single-threaded under a seeded scheduler —
  interleaving bugs become reproducible test failures, not heisenbugs.

**`e6irc-queue` (custom, in-repo — for the core↔DB and SendQ paths; the
driver/attach layer of §10 uses tokio `broadcast`/`mpsc`):**

- Bounded MPSC ring buffer; accepted envelopes carry a per-queue monotonic
  sequence number. The bound is an admission limit, not an eager allocation:
  storage grows only with admitted envelopes, which prevents every empty
  per-connection SendQ from reserving its maximum capacity.
- **No silent loss**: `try_push` returns `Err(Full(event))` — the
  producer decides (kill the slow consumer's connection, exert
  backpressure, or shed *with accounting*). Delivered-or-returned is an
  invariant, not a best effort.
- Consumer API: `async pop()` in runtime mode (custom waker, no tokio
  channel underneath); `try_pop()` as the nonblocking/manual-step primitive.
- Async producers wait in FIFO order. One freed slot wakes one live producer,
  and dropping a pending push removes its waiter registration; cancellation
  cannot consume a future wakeup and a single pop cannot create a
  thundering-herd repoll.
- Instrumentation built in: depth, current FIFO/LIFO mode, and mode-switch
  count.
- **Adaptive degraded mode (FIFO→LIFO)**: per-queue opt-in policy. When
  depth crosses a high watermark the queue flips to LIFO dequeue — under
  overload the *freshest* events are served first and stale work is what
  waits — flipping back to FIFO at a low watermark (hysteresis). Mode
  changes are observable through the mode-switch counter. Only wired for
  queues whose consumers tolerate reordering (envelopes carry seq
  numbers, so downstream can restore order or detect staleness); queues
  whose ordering is semantic — e.g. a shard's command stream — stay
  strict FIFO. Fixed runtime queues export their depth, capacity, mode, and
  mode-switch counter through the process telemetry contract.
- **Verified**: loom model-checks the concurrency core (push/pop/wake
  under all interleavings); property tests pin FIFO-per-producer,
  bounded-memory, and delivered-or-returned invariants.

**Worker topology:**

- **Core shards** (configured N): each owns its sessions and channel
  partition. Shared directories reserve nicks and durable channel metadata.
  A channel command is routed to `shard(#chan)`; a session command is routed
  to its connection owner.
- **Connection I/O tasks** (per socket): parse inbound lines → enqueue to
  the right shard; drain their **SendQ** (also an `e6irc-queue`, bounded)
  → socket. SendQ full = classic slow-client kill.
- **Fan-out, serialize-once**: a channel message is serialized per
  *capability variant* (tags on/off, server-time, account-tag, …), each
  variant a `Bytes`; delivery = clone (refcount bump) + push into each
  member's SendQ. Cross-shard channel membership works because SendQ
  producer handles are shareable; state stays single-owner.
- **Pipeline workers**: history writer (batches to Postgres), multiplexer,
  each network driver — all the same pattern: one loop, one queue in.
- Timers (PING, idle, throttle decay) are events too: a timer-wheel worker
  enqueues ticks, so even time-driven mutations flow through queues (and
  are injectable in simulation).

### 7.4 Performance engineering (cross-cutting)

The following is the performance target and review checklist, not a claim that
every mechanism is present. Shipped foundations include borrowed IRC parsing,
`Cow` tag/ISUPPORT unescaping, bounded queues, capability-variant
serialize-once fan-out in shared `Bytes`, partial-write-correct vectored SendQ
draining capped below platform scatter/gather limits, release link-time
optimization (LTO), copy-on-write recipient snapshots, dense generation-safe session IDs, batched accepts, a
timer-wheel reaper, reusable outbound write batches, and reproducible load
tracking. Lock-free configuration reload and microbenchmarks are not present:
no benchmark crate is a dependency, and managed configuration does not reach a
hot path at all. It is one revisioned snapshot behind an
`Arc<tokio::sync::RwLock<…>>` shared by the HTTP handlers, the observability
sampler, and storage maintenance. `PATCH /api/v1/admin/configuration` holds the
write lock across the revision check, the live BNC-listener change, and the
PostgreSQL write; the sampler and maintenance workers read their settings from
the same snapshot each cycle. A managed value the core, an IRC listener, or
sign-in consumes is stored and reported as restart-required, because those take
their configuration once, at start (§18). Any nontrivial optimization lands with evidence that proves it:

- **Zero-copy end-to-end**: parsing borrows from the receive buffer
  (§7.1); a routed message is serialized once per capability variant and
  shared as `Bytes` — delivery to N recipients is N refcount bumps, zero
  memcpy; SendQs drain via vectored writes (`writev`), never
  concatenation.
- **Copy-on-write where sharing beats copying**: tag values unescape to
  `Cow` (allocate only when an escape exists); channel recipient
  snapshots are Arc'd copy-on-write lists so fan-out iterates outside any
  lock. If a reloadable value ever has to be read on the routing path, it
  becomes an atomically swapped `Arc` snapshot (the read-copy-update pattern)
  so those readers never lock; today none is, and the read–write lock above is
  taken only by control-plane requests and two periodic workers.
- **Cache-conscious layout**: hot structs ordered and sized against
  cache lines; `#[repr(align(64))]` separation between producer- and
  consumer-owned fields to prevent false sharing (queue internals as
  they evolve to atomics); dense slab/index addressing (`SessionId` =
  slab index + generation) instead of pointer chasing; shard loops
  iterate dense arrays.
- **Allocation discipline**: inbound line buffers come from reuse pools;
  the routing path performs no per-message allocation beyond the shared
  serialization.
- **Syscall economy**: `TCP_NODELAY` plus explicit flush coalescing,
  batched accepts, timer wheels instead of per-connection timers.
- **Queue internals may evolve, the contract may not**: the mutex ring
  is the loom-verified baseline; a padded-atomic ring (SPSC fast paths,
  seqlock reads) may replace it *if* benchmarks demand — the loom suite
  and public API are the gate any such change must pass unchanged.
- **Build-level**: fat LTO, `codegen-units = 1` (§6). Benchmark evidence
  decides PGO, BOLT, and any allocator change.
- **Measured, always**: a microbenchmark, when one is added, lives beside its
  hot module; the `e6irc-load` crate and the `tools/load` scripts are the
  macrobenchmark, tracking connect rate, exact fan-out sequence membership, and
  p50/p90/p99/max latency under a controlled environment. The harness accepts
  explicit minimum-rate/maximum-P99 thresholds and treats missing, duplicate,
  out-of-range, and malformed deliveries as failures. Every pull request runs
  a deliberately generous 64-client regression gate, including Linux daemon
  resident-memory sampling and a 1 MiB incremental RSS/connection ceiling;
  manual baselines reach 2,000 clients. The harness accepts a stricter
  host-specific RSS ceiling alongside throughput and latency thresholds.
  A controlled run writes a versioned result plus the host and server-binary
  provenance, so a published number stays bound to its workload and budgets.
  Production-host budgets and the 100k qualification remain a target boundary,
  not a shipped performance claim.

### 7.5 IRCv3 capabilities

Target set (all specs at https://ircv3.net/irc/):

`cap-notify` (implied by CAP LS 302), `sasl` (PLAIN, OAUTHBEARER; §9),
`server-time`, `message-tags`, `message-ids` (msgid tag), `echo-message`,
`batch`, `labeled-response`, `standard-replies`, `account-tag`,
`account-notify`, `away-notify`, `extended-join`, `multi-prefix`,
`userhost-in-names`, `chghost`, `setname`, `invite-notify`, `monitor`
(MONITOR command + extended-monitor), `chathistory` (draft; §11.3),
`draft/multiline` (§7.5.1), `read-marker` (draft) for multi-device read sync,
`draft/account-registration` (§9.1).

#### 7.5.1 Multiline

A `draft/multiline` batch is **one message**: it takes one msgid and one
timestamp, and both delivered forms carry that same pair, so a client seeing the
batch and one seeing the flattened lines are looking at the same event. A batch
that is abandoned or fails validation delivers *nothing* — a truncated version
of what the sender wrote would be worse than silence, and the sender is told why
with `FAIL BATCH`. A batch may not mix PRIVMSG and NOTICE (it is one message,
and NOTICE's "never auto-reply" meaning cannot be applied to half of it), and
TAGMSG may not join one at all. A line inside a batch must address the batch's
target (`FAIL BATCH MULTILINE_INVALID_TARGET`), the concat tag may not open a
batch, and a `@batch` tag with no reference — or naming a batch this connection
never opened — is refused, never delivered as a plain message; a batch
reference is non-empty by construction. If the opening BATCH was labeled, the
failure carries that label: the batch was the response owed to that command,
so without it a client tracking labels would wait forever. Whether a captured
labeled response is already one batch (CHATHISTORY) is decided by parsing its
first and last lines as `BATCH +ref` / `BATCH -ref` commands, never by
searching message text, so an echo whose body reads `BATCH +z` cannot escape
its labeled batch.

Recipients that negotiated the capability receive the batch as sent, blank lines
and `draft/multiline-concat` tags intact, because those are what the sender
wrote. Everyone else receives one message per non-blank line: a PRIVMSG has no
way to carry a line break, and a blank line would be an empty message. A batch
whose lines are *all* blank therefore has no text in it, and is refused with
`ERR_NOTEXTTOSEND` exactly as an empty PRIVMSG is -- delivered, it would reach
those recipients as nothing at all, and stored it would be a history row that
replays as no line, so a page of N rows would arrive as fewer than N messages
and read as the end of the buffer (§11.2). Refusing it at the sender keeps
every stored message one that its recipients can actually receive. The
limits (`max-bytes`, `max-lines`) are advertised as the capability's value, so a
client can see them before starting a batch it cannot finish.

The one-message property holds through **history** too. A multiline message is
stored as a single entry under its single msgid — its lines and their concat
flags encoded together — not one row per line, because the CHATHISTORY spec
requires a replayed msgid to be the one originally sent, and per-line ids would
be ids no client ever saw. CHATHISTORY reconstructs it on replay exactly as live
delivery would send it now: a nested `draft/multiline` batch (blank lines and
concat tags intact) for a requester that negotiated the capability, or the
flattened non-blank lines (msgid on the first only) for one that did not —
reusing the stored msgid in both. So the batch a client saw live and the one it
pages back are the same event, with the same id.

Every message — single-line or batched — resolves its target through one place,
so `+m`, `+n`, `+C`, bans and quiets cannot be evaded by splitting text across a
batch, and permission checks see the whole message rather than each fragment.

This is a **superset of Libera's advertised set** (Libera does not offer
chathistory/multiline); the Libera-compat contract (§7.7) governs the shared
subset's exact behavior.

### 7.6 Channel/user modes, services

- Channel modes: Solanum's set as deployed on Libera — list modes
  `+b +q +e +I` (quiet is a list mode, not an owner prefix), key `+k`, limit
  `+l`, forward `+f`, join-throttle `+j`, and the Solanum flag set
  (`+i +m +n +s +t +c +C +g +z +L +P +Q +r +F …`). Membership prefixes: `@`
  (+o) and `+` (+v) only — **no halfop**, matching Libera. The authoritative
  mode-by-mode behavior list is pinned from Solanum's documentation/help
  files (with provenance) as a vendored compat reference, and verified by
  the differential harness (§7.7).
- User modes: Solanum-compatible core (`+i +w +Z +R …`) plus oper modes.
- Oper system: config-defined opers, privileges (kline/dline/xline-style
  bans, SETHOST, global notices), all actions audit-logged.
- **Integrated services** (no separate Atheme process): `NickServ` and
  `ChanServ` pseudo-clients whose command surfaces
  (`REGISTER`, `IDENTIFY`, `GHOST`, `ACCESS`/`FLAGS`, `OP`, topic retention,
  founder/successor, etc.) follow Atheme's semantics as deployed on Libera —
  this is what users' muscle memory and client scripts expect. Accounts
  created via NickServ and via web/OIDC are the same account rows (§9.1).
  `SASL` and `IDENTIFY` set the same account state; `account-notify`/WHOIS
  reflect it identically to Libera.

### 7.7 Libera.Chat compatibility contract

Explicit target: **a client, bot, or script written for Libera.Chat works
unmodified against e6ircd** for the protocol surface both sides implement.

Concretely:

- `CASEMAPPING=rfc1459`; ISUPPORT tokens mirror Libera's (CHANMODES,
  PREFIX=(ov)@+, EXCEPTS, INVEX, MONITOR, TARGMAX, WHOX, …). A snapshot of
  Libera's actual 005 burst and CAP LS output is vendored (dated, with
  provenance) as the reference.
- Numerics and reply text shapes follow Solanum where clients are known to
  parse them (WHOIS replies, ban list replies, `RPL_ISUPPORT`, error
  numerics).
- **WHOX** (`WHO #chan %tnfhuar`) — heavily used by clients/bots on Libera.
- NickServ/ChanServ surface per §7.6.
- **Compatibility verification** — complementary checks, none of them a
  build dependency (e6irc is an independent implementation; a reference
  ircd is only ever a cross-check):
  1. **irctest** conformance suite (https://github.com/progval/irctest),
     vendored hookup in `vendor/tests/irctest/`, run in CI.
  2. Offline **ISUPPORT differential** against a vendored snapshot of
     Libera's actual 005 burst (`vendor/tests/libera-snapshot/`): every
     shared token must match, exceptions whitelisted with a reason.
  3. Opt-in, **light-touch live interop** tests
     (`crates/e6ircd/tests/live_compat.rs`): our client makes one brief
     TLS connection to Libera, OFTC, and Ergo and reads their greeting —
     `#[ignore]`d so they never run in normal CI or load public services.
  4. Optional differential **oracle**: a pinned Solanum built in Docker
     under `vendor/tests/external-oracles/` for deeper scripted-session
     cross-checks (divergences fixed or whitelisted). Never built or run
     by the default build/CI.
- The BNC `irc` driver (§10.3) treats Libera as its primary interop target:
  SASL to Atheme, Solanum cap set, its throttles/quirks are all exercised in
  integration tests against the same dockerized stack.

Where "modern IRC" (chathistory, multiline, …) goes beyond Libera, we extend;
we never *diverge* on surface Libera defines.

---

## 8. Persistence (PostgreSQL)

Vanilla PostgreSQL 18 (current stable) via sqlx; migrations embedded and run
on startup (refusing to start on drift, loudly). CI provisions `postgres:18`
for every database-backed suite — legacy majors are deliberately not a
support target, so "it happens to work on an older server" is not a claim
this project makes or tests. The shared application pool is sized by
`[database] max_connections` (2–200; default 1 + 4 + 2 × CPU threads) and has a
two-second acquisition deadline, a 15-second PostgreSQL statement deadline, and a
five-second lock-acquisition deadline and a 60-second
`idle_in_transaction_session_timeout` on every pooled connection. Migrations
run on a dedicated connection with no statement deadline and a ten-second lock
deadline, retried up to six times with a stderr line per attempt, so a long
migration is not cancelled by the pool's bound. Dependency
loss, pool exhaustion, a wedged query, or a contended lock therefore becomes a
typed database failure instead of parking an HTTP or worker caller indefinitely.

Principal tables (columns abridged):

- `accounts` (id, name/casefolded, private contact email, created_at, flags).
  The closed flag bits are durable administrator authority and suspension; a
  database constraint rejects every other value. At least one effective
  durable-or-configured administrator remains active across HTTP deletion.
- `retired_account_names` (casefolded name, deletion time) permanently reserves
  deleted identities. The account-name transaction lock serializes create and
  delete, while a storage trigger makes a future unwrapped account insert reject
  a retired name independently of application routing.
- `account_invitations` (opaque token digest, proposed account/contact/
  authority, issuer, creation/expiry, consumption/accepted-account metadata).
  A partial unique index admits at most one live invitation per folded name;
  bearer plaintext is returned once and never stored.
- `account_credentials` (account_id, kind: local_password | app_password,
  argon2id hash, label, last_used_at) — app passwords are per-client,
  revocable, shown once at creation
- `oidc_identities` (issuer, subject) → account_id, UNIQUE(issuer, subject)
- `web_sessions` (owner-scoped resource id, opaque token hash, account_id,
  creation/expiry, bounded user agent, optional OIDC identity/session metadata)
- `api_tokens` (hashed PATs, scopes, expiry)
- `channels` (registered channels: founder, flags, topic retention, mlock)
- `channel_access` (channel_id, account_id, flags) — Atheme-style FLAGS
- `messages` — append-only history log; columns (id, msgid, target,
  sender_prefix, sender_account, kind, body, ts), indexed `(target, ts)`
  and `(ts, id)`; `messages_sender_account_idx` (migration 0063) together with
  the direct-message peers index makes the account-message predicate (account
  deletion and export) a BitmapOr of two index scans. Migration 0064 dropped the
  unused BRIN on `ts`. The live storage policy retains 1–3650 days
  (30 by default) and removes expired rows in bounded 10,000-row batches.
  Native monthly range partitions remain the target representation at the
  scale qualification boundary; retention semantics do not depend on that
  representation. Server-time and account-tag are reconstructed from `ts`
  and `sender_account`, so no separate tags column is stored.
- `bnc_networks` (account_id, name, addr, tls, nick, realname, autojoin,
  sasl_account, `sasl_password_sealed` — **sealed** (`enc:v1:`) with the
  server master key (§15), `server_password_sealed` (IRC only, a table CHECK;
  sealed like the SASL password), enabled)
- `bnc_buffer` (id, owner, network, network_id, line, created_at, target,
  msgid, sent_at) — persisted
  detached-buffer lines replayed on attach after a restart; `owner` is `*`
  for a shared/server-level network; `owner` is the RFC1459-casefolded account,
  matching the registry key. The `/network` selector is likewise folded for
  matching (registry key + a `UNIQUE (account_id, lower(name))` index on
  `bnc_networks`, migration 0034), so selection is case-insensitive like every
  other IRC identifier and a case-mismatched attach cannot fall through to an
  operator's shared network of the same name (§2); display casing is preserved.
  `target` is the conversation the line belongs to, `msgid` the upstream
  `msgid=` tag when present, and `sent_at` the effective ISO-8601 instant
  (the `time=` tag verbatim, else bouncer arrival time) — the three columns
  the attach listener's CHATHISTORY paging and TARGETS scan over.
  Both ways into a network's buffer — a live line
  from a driver and restored backlog from this table — remove CR/LF/NUL and
  cap one entry to the IRC wire limit. A replay cannot inject a second line or
  make the bounded buffer retain an unbounded entry.
  Retention is per (owner, network): the persistence task counts its own
  appends and trims to the newest `BNC_BUFFER_CAP` at every
  `BNC_TRIM_INTERVAL`, and rows older than `storage.history_retention_days`
  are deleted by storage maintenance in bounded batches (index
  `bnc_buffer_created_at_idx`, migration 0060) — "history retention" means
  bouncer history, direct messages included, not only the server's own. Read
  markers (`read_markers` and `bnc_read_markers`) are swept against that same
  retention (migration 0070): a marker is a position in history, so once no
  message that old is kept, it points where nothing can be read from. They are
  capped per account but unbounded in accounts, and `read_markers` is read
  whole at boot and mirrored into every core shard, so the sweep bounds the
  daemon's start-up cost as well as the table. The count belongs to that task, not to the table's `id`
  sequence — one sequence is shared by every network, so triggering off it
  makes retention depend on the interleaving between them. Each persistence
  task also trims once when it starts (after restoring the backlog), in batches
  of at most 10,000 rows, and maintenance sweeps any buffer still over the cap,
  64 per tick. `network_id` (nullable foreign key to `bnc_networks` ON DELETE
  CASCADE, migration 0062) is resolved once when a database network's
  persistence task starts and written on every line, so a line for a deleted
  network fails loudly and a re-created network never inherits backlog.
  Server-level (`*`) lines never carry one (a CHECK); configuration-file
  networks carry none, including account-owned ones, which have no
  `bnc_networks` row. Migration 0064 dropped `bnc_buffer_target_idx` and
  `bnc_buffer_msgid_idx` as unused: `bnc_buffer_sent_at_idx` serves every
  per-target read and `bnc_buffer_lookup_idx` the replay.
- `device_grants` — device-authorization approvals; `account_id` references
  `accounts(id)` ON DELETE CASCADE (migration 0065).
- `bnc_read_markers` (BIGINT account_id, network, target, timestamp) —
  per-account, per-BNC-network read position, the source for
  `draft/read-marker` on the attach listener. Distinct from `read_markers`
  below, which tracks the core's local-server targets. Writes lock the durable
  account row in their transaction, increase monotonically, and admit at most
  256 targets per account even under concurrent inserts; the core keeps a
  per-account count of distinct marker targets (confirmed or with a write in
  flight), maintained at every write to the marker maps — which are private to
  the state module for exactly that reason — so the cap costs a lookup per
  MARKREAD rather than a scan of every account's markers, and sibling-connection
  sync uses an account → connections index kept at login, logout and close. The
  committed value
  is acknowledged and fanned out only to other read-marker-capable attachments
  of the same account. Deleting a BNC network deletes its markers, so
  recreating the same name cannot inherit stale read state.
- `read_markers` (account_id, target, marker_ts) — per-account read
  position, the source for `draft/read-marker`. The 256-target cap is enforced
  in PostgreSQL under an account-row lock, so several core shards cannot exceed
  it together; a refusal is `FAIL MARKREAD INVALID_PARAMS`. Updates are monotonic
  (`GREATEST`) and the returned committed value drives the core mirror and
  client acknowledgement; an enqueue or PostgreSQL failure is never reported
  as success. Anonymous connections use explicitly session-local markers.
- `audit_log` (stable id, actor, action, target, detail, creation time for
  privileged oper/control-plane actions). Exact actor/action/target queries use
  `(filter, id DESC)` indexes and paginate with `id < before_id`; a concurrently
  appended action is therefore never duplicated into an older page.

Administrator account-directory reads project account age and aggregate login/
resource counts only. Correlated reads use the child tables' account-owner
indexes (including `oidc_identities.account_id` and
`channels.founder_account_id`) and paginate accounts by immutable id. Expired
browser sessions and personal access tokens are not counted; credential
hashes, bearer/session hashes, OpenID Connect subjects, and sealed upstream
secrets are not selected at all.

A supervised five-minute storage-maintenance worker applies the live
UI-managed `[storage]` policy independently of monitoring. Each collection —
expired message-history rows, audit events, browser sessions, personal access
tokens, device grants, consumed OpenID Connect logout tokens, and
expired/revoked/consumed account invitations — is its own statement and
transaction, deleting at most 10,000 rows named by primary key
(`= ANY(ARRAY(… ORDER BY … LIMIT))`). A failing collection is reported by table
after the others commit, so one refused delete cannot roll back another.
Time-order indexes and the global acquisition/statement/lock deadlines bound
both the selection and the transaction. Filling any batch is logged with per-collection provenance and
the next fixed cycle continues draining it; database failure is counted and
logged. The worker's unexpected return or panic is a critical runtime failure,
not an invisible loss of retention.

Administrator registered-channel and server-ban reads are independent of the
unbounded boot preload required by the live core. They project newest-first
policy pages with immutable IDs, exact folded filters, and one extra row for
cursor detection. Channel posture includes the founder, registration time,
KEEP policy, retained-topic presence, canonical mode lock, and access-grant
count. `(founder_account_id, id DESC)` supports founder-filtered channel pages.
Ban posture preserves display casing while filtering by the enforcement key;
`(kind, id DESC)` supports kind-filtered pages. The overview asks each directory
for only its newest ten rows.

Write path for messages: producers push to an in-process MPSC; a writer pool
batches into multi-row `INSERT ... UNNEST` (or COPY for bulk) with group
commit — one connection cannot stall the chat path on Postgres latency. The
in-memory hot ring buffer (§11.3) serves recent history without touching PG.

---

## 9. Identity & authentication

### 9.1 Account model

One `accounts` row per user regardless of origin. An account may have zero or
one local password, N app passwords, and N OIDC identities. A partial unique
index makes a second primary password unrepresentable in storage. The web
"user section" manages all of them. NickServ `REGISTER` creates the same kind
of account the OIDC first-login path creates.

An empty database can expose a one-time browser bootstrap only when
`[bootstrap].token`, PostgreSQL, and HTTP are all configured. `GET /bootstrap`
binds the form to an expiring `HttpOnly; SameSite=Strict` browser state cookie;
the POST is authentication-rate-limited and compares only a SHA-256 digest of
the supplied token in constant time. The transaction locks the account table,
creates the first account, its primary password, durable administrator flag,
and audit row atomically. Any existing account permanently closes the route,
including an account concurrently created through IRC registration. The
plaintext bootstrap token is not retained in HTTP state.

The browser bootstrap is never re-opened. An operator who has lost every
administrator login (a forgotten password, a broken identity provider) recovers
on the host, where the configuration and the database already are: `e6ircd
recover-administrator --account NAME [<configuration>]`. In one transaction it
gives one *existing, active* account a new 32-random-byte password printed
once, durable administrator authority, and no remaining browser sessions, and
writes an `ADMINISTRATOR_RECOVERY` audit row (every creation path writes
`ACCOUNT_CREATE` too — IRC self-registration with the account as actor, OpenID
Connect provisioning with `oidc:<issuer>`; `NETWORK_CREATE`/`NETWORK_UPDATE`
details name the fields present or changed, `CONFIG` detail ends with the
changed dotted field names, and values never appear) whose actor is
`host:recover-administrator`. An unknown or suspended account is refused and
nothing is changed. It needs no restart: the running daemon honours the
granted authority and the revoked credentials on its next request, and the
operator signs in with the printed password and changes it. It is explicit,
local, one-shot and audited; nothing about it is reachable from the network.

Suspension is a durable account state, not a credential rewrite. One
transaction sets the flag, revokes every browser session, personal access
token, and approved device grant, and records the actor/target audit event.
Primary and app-password hashes, OpenID Connect links, channel ownership, and
network definitions remain so reactivation can restore the identity without
resurrecting any revoked bearer. Every credential lookup and bearer-issuance
choke point rejects suspended accounts.

Durable administrator authority is independently grantable/revocable by
immutable account ID. The acting administrator cannot demote itself, and the
last active effective durable-or-configured administrator cannot be suspended
or removed. Configured administrator grants remain a distinct restart-scoped
authority source; the directory shows both sources, and revoking a durable
grant cannot falsely remove a still-active configuration grant. Every durable
authority transition is audited and updates the live HTTP authorization
registry immediately.

Administrators can also provision a local account immediately or issue a
1–30-day single-use invitation. Invitation issuance validates the same account
name and typed private contact email as direct creation, takes the shared
  per-name advisory lock, enforces a per-administrator pending cap (counting
  only unexpired invitations), and stores only the SHA-256 digest of a 256-bit
  bearer. Suspension, demotion (unless configuration still grants authority)
  and host recovery revoke the issuer's live invitations in the same
  transaction, one `ACCOUNT_INVITATION_REVOKE` row each, and accepting an
  administrator invitation re-checks that its issuer is still an active durable
  or configured administrator. The administrator directory is
  a bounded, stable newest-first cursor page. Acceptance is rate-limited and
bound to a short-lived `HttpOnly; SameSite=Strict` browser cookie; password
hashing, account/contact/authority creation, invitation consumption, and audit
commit in one transaction before the browser session is issued. Expired,
revoked, consumed, and unknown bearers deliberately share one public
unavailable response.

Permanent deletion is a succession operation rather than a cascading accident.
The target must found no registered channel and cannot be the last active
effective administrator, including authority supplied by deployment
configuration. The shared account/network mutation lane first installs a
folded authentication deny key in the ordered core, then stops the account's
drivers, so no persistence task can write backlog behind the deletion (they
are restarted only if the database refuses). The final transaction
rechecks every invariant, reserves the name permanently, purges pending/
consumed invitation contact data, device grants, owned BNC buffer, sent and
direct-message history (in batches of 5,000, in the fixed order messages →
bnc_buffer → device_grants → invitations → account), and then deletes the account so credentials, sessions,
identity links, networks, markers (the bouncer's `bnc_read_markers` included,
which lacked the cascade until migration 0056 and made deletion fail for anyone
who had sent one MARKREAD), and access rows cascade. An account's own messages
are matched by both spellings of its name, because `messages.sender_account`
stores the display name. Administrator, suspension, and deletion changes take
one transaction-scoped advisory lock first, so two administrators demoting each
other cannot both commit and leave none. The redacted audit
event and retirement commit together. On database failure the HTTP boundary
removes the live deny key before returning the error; success stops owned
drivers and clears live administrator authority. No shipped creation path—or
the account-table trigger—can assign a retired name to somebody else.

The `draft/account-registration` `REGISTER` command creates that same account,
so the two entry points cannot diverge; the capability's advertised value states
the policy (`before-connect`, `email-required`) so a client knows the rules
before it tries. `custom-account-name` is deliberately **not** advertised: an
account always takes the registering nick's name, which keeps "the account you
registered is the nick you were holding" true — and that in turn is what lets
direct-message conversations be keyed by account (§11.1.1). Registration before
the connection completes is off by default: a half-open connection creating
accounts is a spam vector unless the operator opts in. A registration email is
parsed once into a bounded ASCII mailbox with a canonical lowercase DNS domain,
then stored as private account profile data; it is never exposed by the account
directory. e6ircd does not claim to have verified locally supplied mail because
it does not send verification messages. `email-required` therefore requires
valid contact data, while OpenID Connect domain admission separately requires a
provider-verified email claim.

### 9.2 Web login

- **OIDC** authorization-code + PKCE against one or more providers
  registered in config (issuer URL, client id/secret, allowed email domains
  option). A non-empty domain policy admits only a syntactically valid,
  provider-verified email whose canonical domain exactly matches an entry;
  parent/subdomain relationships never become implicit wildcards. Discovery +
  JWKS cached with proper refresh. First login
  auto-provisions an account (nick derived from `preferred_username`,
  conflict → user picks). Subsequent logins match on (issuer, subject),
  never on email.
- Local-account login form (argon2id verify) for accounts without OIDC. It
  accepts only the primary password, not an IRC app password, is covered by the
  per-IP authentication rate limit, bounds every credential field before
  Argon2, and binds each form to a short-lived `HttpOnly; SameSite=Strict`
  browser cookie to prevent login CSRF/session planting.
- Session: opaque random token, hash stored server-side (`web_sessions`),
  `HttpOnly; Secure; SameSite=Lax` cookie. CSRF: state-changing
  server-rendered forms carry a per-session HMAC token in the request body and
  reject a missing or invalid token before mutation. Each login records a
  bounded, display-safe user agent and a separate stable resource id; neither
  the opaque token nor its hash is exposed by session inventory.
- Local and OpenID Connect login cannot issue a session for a suspended
  account. OpenID Connect returns an explicit account-unavailable response
  after validating the provider result; it never turns suspension into a
  dependency failure or creates a partially authenticated browser session.
- The embedded application entry point was an authentication boundary. A
  valid local session rendered the client; otherwise a single configured
  provider's ordinary authorization flow began immediately. An existing
  Shauth session completed that flow without another prompt, while a browser
  without one stopped at Shauth's credential page rather than falling back to
  a local login page. The application shell exposed the authenticated account
  and a top-level logout navigation.
- Coordinated logout: the session retained its OIDC issuer, subject, session
  ID, provider, and ID token. `GET /api/v1/auth/logout` performed
  RP-initiated logout through the provider `end_session_endpoint` with the ID
  token, client ID, and registered post-logout URI. The provider called
  `POST /api/v1/auth/oidc/backchannel-logout` with a signed logout token, or
  loaded `GET /api/v1/auth/oidc/frontchannel-logout?iss=…&sid=…`; both paths
  revoked the correlated durable sessions. Back-channel token signatures,
  issuer, audience, event object, nonce absence, time, `sid`/`sub`, and `jti` were verified, and
  consumed token IDs were retained until expiry to reject replay. The
  recommended `logout+jwt` type, the generic `JWT` type emitted by existing
  providers, and an omitted type were accepted; a token explicitly typed for
  another protocol was rejected.
  RP-initiated logout returned through the application's registered
  `/auth/signed-out` URL. That public, non-cacheable page remained local on
  reload and offered an explicit application-local OIDC starter instead of
  immediately probing SSO again. Missing provider metadata, a malformed
  end-session endpoint, or a storage failure preserved the local session and
  failed loudly rather than producing a partial logout.

### 9.3 IRC client authentication

| Mechanism | For | Notes |
|---|---|---|
| SASL **PLAIN** | every existing IRC client | password = local password **or** an app password generated in the web UI. |
| SASL **OAUTHBEARER** (RFC 7628) | e6irc-cli/tui and OAuth-capable clients | client obtains a token via the provider's **device authorization grant**; server validates signature/claims via cached JWKS (or introspection if configured) and maps (iss, sub) → account. |
| NickServ `IDENTIFY` | legacy clients without SASL | same credential check as PLAIN. |

CERTFP is explicitly out of scope for v1 (not selected).

### 9.4 REST API authentication

Personal access tokens are hashed at rest, expire after a caller-selected
1–365 days (30 by default), and carry a non-empty closed grant set:
`read`, `write`, `administrator`, and `irc`. `Authorization: Bearer` requires
`read` for safe API methods and `write` for mutations; administrator routes
also require both the `administrator` grant and the account's current durable
or configured administrator authority. IRC SASL OAUTHBEARER independently
requires `irc`. Device authorization issues `read`/`write`/`irc`, never
administrator authority. Token issuance and device approval require the
browser session plus its `X-E6IRC-CSRF` value, so an existing bearer cannot
mint a broader replacement. Every unsafe cookie-authenticated REST method
requires that same header at the shared authentication boundary. The web
session cookie remains the browser credential, with the CSRF rules above.

Authenticated API requests share a per-account token bucket across browser
sessions and personal access tokens (240 requests per minute by default).
Administrator operations use a separate, smaller per-account bucket (60 per
minute by default). Both are UI-managed, bounded in memory, and fail closed
when the bucket registry cannot admit another active account. The HTTP service
also enforces a 1 MiB request-body limit, 1,024-request aggregate concurrency
limit, and 30-second request deadline before work can consume unbounded
process resources. The concurrency bound is one semaphore for the whole
service, not one per route, and a request abandoned at the deadline answers a
`408` problem document. Connections are served with a timer: a request's
headers must arrive within 10 s, and the same bound closes an idle kept-alive
connection (axum's default server has no timer, which silently drops hyper's
header timeout). Only a connection that never completed a request is logged as
a refused peer; an idle kept-alive connection closed at the bound is ordinary,
and a reverse proxy's idle upstream connections used to log a "refused" line
every ten seconds. One address may hold 128 connections (trusted proxies
exempt) and 32 requests in flight (429 beyond); `/healthz` and `/readyz`
bypass the admission bounds, so one client cannot starve the health check. A connection test dials a host the caller chose from
the address every tenant shares, so it has its own admission: one running test
per account, six started per account per minute, and eight running in the
process; a refusal is a `429` with `Retry-After` and costs the account nothing.
The test registers and says `QUIT :connection test complete`; it joins no
channel (registration is the qualification, and a join would be visible
noise on the owner's public channels), so its answer names the confirmed nick
and the timings only. While the network being tested is running, the test is
refused with a `409` ("network is running; disable it to test its settings"):
the running driver holds the nick, so the test could only answer
`nickname_in_use`, and the server never probes under an invented nick.
The verb lives at `/api/v1/me/network-preflight`, outside the positions a
network name occupies — the contract check refuses any two route patterns one
URL could satisfy, so no resource name is unreachable.
The same admin-gated data is also served as a
server-rendered management **console** at `/console` (accounts, registered
channels, server bans, audit preview), with a dedicated filterable,
cursor-paginated security-operations view at `/console/audit`; it shares the
`pages` module, `render_private`, and the exact admin gate the
`/api/v1/admin/*` JSON endpoints use, so it can never surface server-wide data
to a non-admin. Beyond the read
views, the console can **act**: add/remove a K/D/X-line, unregister a registered
channel, and disconnect an exact live connection from the bounded,
cursor-paginated directory at `/console/sessions`. The directory projects only
registered clients and supports exact RFC1459-folded nick/account filters plus
closed transport and operator filters. It retains at most one requested page
and its cursor sentinel while scanning hot state, so response allocation is
independent of total connections.

Every ingress path shares one non-wrapping connection-ID allocator seeded from
the operating system's cryptographically secure random number generator at
boot. Disconnect requests carry the immutable ID
resolved by the directory instead of a mutable nick, closing both nick-reuse
and predictable post-restart stale-form targeting. JSON renders IDs and cursors
as decimal strings so JavaScript cannot round a 64-bit resource identifier.
The core owns the disconnect choke point: IRC `KILL`, console forms, and REST
mutations share the same audit, operator-notice, terminal `ERROR`, and close
path. Actions are admin-gated + CSRF-protected; success redirects (PRG), failure
re-renders with an error banner. The equivalent administrator REST surface is
`GET /api/v1/admin/connections` and
`DELETE /api/v1/admin/connections/{id}`.

A non-admin counterpart at `/console/my-sessions` lets any signed-in user see
and disconnect *their own* authenticated clients. The core forces the account
filter and rechecks ownership of the immutable ID at mutation time, so a stale
or guessed identifier cannot touch another account. The matching REST surface
is `GET /api/v1/me/connections` and
`DELETE /api/v1/me/connections/{id}`. The same console page lists durable
browser logins with creation/expiry, sign-in method, provider, bounded
user-agent provenance, and a current-session marker. Issuance is serialized on
the account row and capped at 32 active browser sessions; a new login
atomically revokes the oldest instead of exceeding the cap or locking the
account out. Individual and bulk other-session revocation remain owner-scoped
in PostgreSQL, and deleting the current session also clears its browser cookie.
Their REST surface is `GET /api/v1/me/sessions` and
`DELETE /api/v1/me/sessions/{id}`.
An account may hold 32 live chat sockets (`/ws/ui`, one per browser tab). The
33rd is upgraded and at once closed with WebSocket code 1008 and a reason — a
browser can read a close frame but not a refused upgrade — which the chat
client shows once and does not retry by itself. A silent peer is sent a
WebSocket Ping after `ATTACH_LIVENESS_INTERVAL` (120 s) and detached after a
second silent interval, the same rule as an attached IRC client (§10.1).
The account directory also projects effective administrator authority, its
durable/configuration sources, and suspension posture.
`PATCH /api/v1/admin/accounts/{id}` and matching CSRF-protected console forms
change exactly one durable authority or suspension state by immutable account
ID. Self-suspension, self-demotion, and suspending/demoting the last active
durable administrator are conflicts. Account-state
and network CRUD share one mutation guard. After the durable transaction,
suspension installs a case-folded deny key on the ordered core thread before
disconnecting every authenticated IRC session, then stops every active network
owned by that account. A password verdict already in flight is therefore
converted to denial instead of recreating a session after the sweep.
Reactivation removes the core deny key and rebuilds every enabled owned
network; invalid persisted network configuration fails before changing the
durable state. A runtime reconciliation failure reports the exact committed
partial state instead of claiming success.
The console shell (`console_base.html`) is
also home to `/console/account`, the complete self-service surface for creating
or rotating the primary password, creating and revoking app passwords and
personal access tokens, linking and safely unlinking login identities, and
inspecting persisted read markers. An OIDC-provisioned account can add its
first local password without presenting a nonexistent current password;
subsequent rotations require the current primary and never accept an app
password. App
passwords and tokens are displayed exactly once; only hashes are retained.
The same page reads and updates the private contact email used by registration
policy and account recovery contact. The typed email value is canonicalized at
the HTTP/IRC boundary, changes are audited without recording the address or its
domain, and public account posture never includes it.
Identity unlink is transactional: the account row serializes concurrent
requests, the last login method cannot be removed, and sessions asserted by
the removed identity are revoked in the same transaction. A final OIDC
identity is removable when a primary password remains. The old `/account`
URL is an authenticated redirect to this canonical page.

The same page presents the account's newest security activity, with stable
cursor pagination at `/api/v1/me/security-activity`, and downloads a versioned
non-cacheable JSON attachment at `/api/v1/me/export`. The export is built from
one PostgreSQL statement snapshot and includes retained personal content and
secret-free configuration/posture; password hashes, bearer/session/invitation
digests, plaintext bearer values, provider identity tokens/session IDs, device
codes, and sealed upstream credentials are absent. Credential, token, identity,
browser-session, login/logout, provider-logout, invitation, account-state, and
deletion transitions emit redacted account-visible audit events.

`/console/accounts` additionally owns immediate local account creation,
single-use invitation issuance/revocation, and permanent deletion with exact
display-name confirmation. The matching REST resources are
`POST /api/v1/admin/accounts`, `DELETE /api/v1/admin/accounts/{id}`,
`GET|POST /api/v1/admin/invitations`, and
`DELETE /api/v1/admin/invitations/{id}`. Self-deletion is
`DELETE /api/v1/me/account` and requires a cookie session plus its CSRF value;
a personal access token cannot delete the identity that issued it.

The shell also contains `/console/configuration`, the database-backed operational control
plane. Its singleton `server_settings` row is a typed JSON document with an
optimistic-concurrency revision, actor, and timestamp; every committed revision
also writes a redacted `CONFIG` audit entry in the same transaction. The
database URL, master-key source, HTTP bind, configured administrator grants,
and optional one-time first-administrator token remain bootstrap values
because they are prerequisites for reaching the console.
Identity, MOTD, IRC listeners, public URL/cookie policy, administrator grants,
OIDC providers, operators, registration policy, resource limits, trusted
proxies, server-level networks, and the BNC attach address are UI-managed.
Credential-bearing values are sealed before entering PostgreSQL and are never
rendered back. Existing
plaintext bootstrap credentials remain authoritative until a master key is
supplied; that next start atomically seals and imports them rather than either
persisting plaintext or replacing them with redacted placeholders.

Server-rendered data tables carry screen-reader captions, and navigation
landmarks carry accessible names. `tools/check-template-accessibility.py`
checks those structural contracts across the complete Askama template
directory in CI so a newly added operational table cannot silently regress to
an unnamed grid.

The console is also the home of `/console/networks` — a per-user BNC network
manager with add (with a connection test) / remove / enable-disable. An IRC
network's settings have exactly **one** editor, the chat client's dialog
(`/?network=<name>&settings=1`, which the console links to): connection and
identity fields (addr, tls, nick, username, realname, autojoin) and write-only
SASL and server credentials — keep the encrypted password while changing its
account, replace it, or remove both halves, with typed values under a ticked
Remove refused rather than silently dropped. The password is never rendered
back to the browser. The console carried a second editor and a third
credential form whose rules disagreed with it (one trimmed the password, one
made "keep the stored one" impossible, one discarded what was typed); they are
gone, and with them the `/console/networks/{name}/edit` and
`/console/networks/{name}/logs` pages — the stored log is read in the network
page's own transcript, which loads all of it on request. A bridge is
configured on the Integrations page. The manager is available to any
authenticated user for their own networks. The create form defaults to a
Libera Chat preset and offers a small, provenance-dated catalog of published
TLS endpoints (Libera, OFTC, Snoonet — each verified as a TLS registration
through the driver, with a certificate valid for the preset hostname; EFnet is
absent because no member of its round robin presents one for `irc.efnet.org`)
plus Custom. A preset's human label
is never its client/URL identifier: `Libera Chat` maps to the safe stable id
`libera`. Presets are applied server-side so they work without JavaScript;
the script only mirrors their fields for editing. A preset is endpoint
provenance, not a compatibility claim for the deployment's current egress.
The same catalog is served at `GET /api/v1/network-presets`, which the chat
client's network dialog reads, so both surfaces offer one list and an endpoint
is corrected in one place. Both forms ask first for what a known network cannot
supply — the network, a nickname, an optional NickServ account and password,
and channels to join — and keep what a preset already determines (name, server,
TLS, real name) under an Advanced disclosure that opens itself for a custom
server or an invalid field. **Test connection** runs the production preflight
on request; it is a diagnostic, never a condition for saving: the API has never
required it, and each forced test cost a second full registration and a
join/part flap in every configured channel on a public network. The preflight
says `QUIT` when it is done instead of dropping the socket. Invalid submissions re-render
the page with the precise shared validation problem and preserve non-secret
input, including the resolved preset values. IRC addresses must be a syntactic
`host:port` with a nonzero numeric port (and bracketed IPv6); configuration,
REST, and console creation share that invariant so an invalid endpoint cannot
be persisted into an endless reconnect loop. The identity a driver puts on the
wire is parsed, not checked: `UpstreamNick`, `UpstreamRealname`, and
`UpstreamChannel` are built only by `FromStr` at the one driver factory, so the
configuration file, a stored row, and the API admit exactly the same values and
a driver cannot be handed an unchecked one. The grammar is structural — what no
server could read as one nickname or one channel (`al ice` is a two-parameter
`NICK`; an autojoin entry of `0` means "leave every channel"; `#a key` supplies
a key nobody configured) — not a network's nickname policy, which still comes
back as a loud 432. A refusal names the request field it belongs to in the
problem body (`field`), and both network forms mark, reveal, and focus that
input. A blank real name means the nickname, on edit exactly as on create,
because the form says so and an IRC network always has one. If no master key is configured,
credential inputs are visibly
unavailable rather than accepting a password the server must refuse to store.

Console pages that refresh themselves do so through one scheduler, because
replacing rows under the person using them is a defect, not a cosmetic one: a
tick is skipped while the page is hidden, while a confirmation dialog is open
(replacing the rows detached the form it was about to submit, and confirming
then did nothing, silently), and while keyboard focus or a text selection is
inside the region. Logs are updated in place — lines that scrolled off are
dropped, new ones appended — so the reader keeps their place, and a log opens
at its newest line. The refresh status line is a live region, so it speaks for
the first load, a pressed Refresh, and the start or end of a failure, never for
a routine tick. A Refresh button whose target has no refresher throws instead of
doing nothing. Removing a shared network, an IRC operator, or an identity
provider asks first, like every other destructive control.

Each network has an owner-scoped
operations page refreshed every ten seconds: lifecycle and state-transition
time, connection age and latency, attempts and errors, attached raw/web
clients, per-network line/byte traffic, in-memory buffer use, stored backlog
bounds, and the newest 100 stored lines. `/api/v1/me/networks/{name}` exposes
the same counters and timestamps plus the last error as a closed,
credential-safe code and summary. An IRC registration rejection may
additionally carry the parser's bounded sanitized upstream diagnostic so an
owner can act on provider requirements; arbitrary transport errors and
credentials never enter that field. The
runtime snapshot is held once on `NetworkHandle`, so IRC and every bridge
driver enter the same measurement path; both raw-IRC and web attachments use
the counted `send` funnel. A reconnecting session must return a
`SessionOutcome::Dropped(NetworkFailure)`, making an unclassified transient
failure a type error across IRC, local, Matrix, Discord, and Slack. Its public
connection event enters a typed runtime phase: only `Connected` carries a
connection time, only `Reconnecting` can carry a retry time, and a parked
network cannot be scheduled to retry. The latest error is one timestamped
record, so monitoring cannot pair a failure with another failure's time.
Live driver status events carry the same closed failure classification, so raw
IRC attachments and WebSocket clients do not re-read mutable state to explain
a disconnect.
Recoverable
message-delivery and detached-backlog storage failures use the same closed
classification-and-accounting choke point, so an error counter or timestamp
cannot advance without a safe reason. Backlog restore failures are loud and
observable rather than silently starting with missing history.

`/console/integrations` (admin) manages the chat-platform bridges:
per-platform build availability, the complete stored inventory (including
disabled bridges and bridges whose feature is absent), status, inspect,
Disable/Enable, add/Remove, and a platform-shaped edit form. The form replaces
endpoints, Matrix identity, and channel selection while treating credential
inputs as write-only: blank preserves the encrypted value, Matrix/Discord can
replace their password/token, and Slack can independently replace either
token. Provider bases are empty only when the driver has a defined default;
otherwise they are absolute HTTP(S) URLs without embedded credentials, query,
or fragment. This validation lives in the shared driver factory as well as the
HTTP boundary, so configuration, stored rows, REST, and console cannot construct
different notions of a valid bridge. A network's `kind`
(`irc`/`matrix`/`discord`/`slack`) is a column on
`bnc_networks`, so bridges are runtime-managed just like IRC upstreams — created
via the console or REST, persisted, and started by the one feature-gated
`bouncer::build_driver` factory that every construction site (config-network
startup, DB-network boot, runtime create, re-enable) shares. Per-kind secrecy:
the password is always sealed; a kind whose *account* field is a secret (Slack's
bot token) seals that too, while an IRC `sasl_account` login name stays plaintext.
Create, edit, and enable construct the prospective driver before mutating
PostgreSQL, so a missing key or factory rejection cannot leave durable state
claiming a driver configuration that never entered the live registry.
Create, edit, enable/disable, and delete also hold one asynchronous registry
mutation gate across their database and live-registry transitions. Concurrent
control-plane requests therefore have a single order and cannot resurrect a
deleted driver, publish an older edit after a newer one, or leave storage and
the running registry representing different operations.
The registry refuses to register over a live driver *before* the second driver
starts, so two upstream sessions can never race for one network, and each
caller states what it means: create and edit **supersede** (stop the
predecessor, then start), while enable and account reactivation **ensure
running** (start when absent, supersede a driver the upstream parked, and
leave a working or still-retrying one alone). Enabling an already-enabled
network is therefore an idempotent success that never drops a healthy upstream
session.

---

## 10. Session multiplexer & BNC subsystem

### 10.1 The unifying abstraction

```rust
trait NetworkDriver {          // one impl per kind: local, irc, matrix, discord, slack
    async fn start(...) -> DriverHandle;   // connect / open session
    // DriverHandle: send events up (messages, joins, state),
    // accept commands down (send message, join, set away, ...)
}
```

A user's **network** = one driver instance. The multiplexer, written once
above the trait, provides for every network kind:

- **Always-on presence**: driver stays up while zero clients are attached.
- **Multi-client attach/detach**: any number of the user's IRC connections
  (native clients, web client, TUI) attach to a network; joins/parts/msgs
  are mirrored to all attached clients. A sender's own messages reach the
  stream exactly once. When the upstream offers `echo-message`, the driver
  requests it and relays the upstream's echo, which arrives only for a line the
  upstream accepted — a refused line (404, 486) is answered by the refusal
  alone, so a client that waits for its echo (as `e6irc send` does) learns the
  truth; the echo is routed to the attachment that sent the line by matching
  command, target and text against the lines awaiting one (at most 256; a
  refused line's entry ages out). An upstream without `echo-message` gets the
  echo synthesized when the line is written. Either way the originator
  receives its echo only when it negotiated `echo-message` on attach, the same
  contract a real server has, and a NickServ command that can carry a secret
  is redacted in the upstream's echo exactly as in a synthesized one.
  Synthesized echoes retain only
  validated client-only tags and mint their own `time` provenance; a downstream
  cannot forge or duplicate server `time`/`msgid` tags in persisted history.
  What belongs to the attachment itself never reaches the upstream: a client's
  `PING` is answered locally (so lag checks work while the upstream is
  reconnecting or parked, and its `PONG`s do not fill the backlog), a `PONG` is
  consumed, and `QUIT` ends that attachment only — every IRC client sends one
  on exit, and forwarding it would end the always-on session the bouncer
  exists to keep. The browser composer refuses the same commands, judged on the
  final line after slash translation so `/raw` cannot smuggle them. The
  reverse holds too: the upstream's own `CAP` lines end at the driver, because
  an attached client negotiated its capabilities with the bouncer and would act
  on the upstream's against the wrong hop.
- **Attachment liveness**: a quiet or parked network writes nothing to its
  clients, so a half-open one (a laptop that slept, a NAT that forgot the
  flow) would never be written to, never error, and hold its task, socket and
  attached-client count forever. A client silent for
  `ATTACH_LIVENESS_INTERVAL` (120 s) is sent `PING`; one silent for a second
  interval is detached as unresponsive. `attach` returns a typed `AttachEnd`
  (client closed, quit, too slow, unresponsive; network removed; driver
  stopped), and the listener logs that reason for every detachment.
- **Detached buffering**: events accumulate in a per-network ring persisted
  to PostgreSQL. A lifecycle notice is buffered and persisted once per
  *transition* (lifecycle plus failure code); repeats are delivered live only.
  An upstream that is down all weekend would otherwise fill the ring, and then
  the stored backlog, with identical "reconnecting" lines and evict the very
  history the bouncer exists to keep. The BNC attach listener also keeps per-account, per-target
  read markers (`bnc_read_markers`, served over `MARKREAD`); they are
  separate from the ircd core's per-account markers (§11) because a BNC
  target lives on an external network the core knows nothing about.
- **Playback**: attaching clients receive the full detached ring,
  tag-filtered by their negotiated caps. Subscription plus buffer snapshot is
  one mutex-ordered boundary with publication, so a line is replayed or live,
  never both. A retained-event overrun is visible and terminal; reconnecting
  establishes a new authoritative boundary instead of continuing with possibly
  stale IRC state. `CHATHISTORY` paging is served by
  the ircd core (§11) for the local network; on the BNC attach listener it
  pages the persisted `bnc_buffer` ring directly (LATEST/BEFORE/AFTER/AROUND/
  BETWEEN by `msgid=` or `timestamp=` selector, plus the two-timestamp TARGETS
  window), intercepted on attach and never forwarded upstream. Each window is
  resolved in PostgreSQL under its LIMIT over `bnc_buffer_sent_at_idx`
  (`db::bnc_history_window`), never by loading a target's rows; an unknown
  msgid is `MESSAGE_ERROR`. Bounded LATEST keeps
  the newest rows *after* its selector; reverse BETWEEN limits from its first
  endpoint; TARGETS uses the dedicated `draft/chathistory-targets` batch.
  Stored timestamps are validated and canonicalized before they become sort
  keys, and replay emits that same canonical `time=` value. `batch` is optional:
  a client that negotiated it receives the applicable batch envelope and tags;
  otherwise the same bounded page is emitted directly. `message-tags`,
  `server-time`, and `account-tag` independently gate their own replay metadata,
  and `message-tags` also scopes *which rows the page is cut from* (§11.2).
- **A notice is retained only if it will still be true.** A `*bnc*` notice
  about the network's own lifecycle belongs in the ring, so a client attaching
  later learns the state it is joining; a transient failure — backlog storage
  refusing a write — does not, because replaying it announces a fault that is
  over. Transient notices go to the live broadcast only, and the per-network
  status dedup keys on the lifecycle rather than on the message text, so a
  reworded diagnostic is not a new transition.
- **Authoritative attach state**: replay is followed by an
  `IrcSessionSnapshot` containing the current upstream nick and confirmed
  memberships. Raw clients receive the NICK/JOIN/PART reconciliation needed to
  reach it. A synthesized JOIN includes a minimal NAMES reply, with the
  account's MARKREAD position before end-of-NAMES when negotiated. `/ws/ui`
  sends the typed snapshot before its replay boundary; the browser separates
  current membership from transcript retention, so reconnect reconciliation
  marks a past channel instead of erasing its visible messages.
- **Operations**: `NetworkHandle` owns a typed lifecycle snapshot plus
  connection attempts/errors, connect latency, attached-client count,
  line/byte traffic, last-activity times, and buffer occupancy. Driver endpoints
  can change lifecycle and record inbound lines only through that shared state;
  downstream traffic crosses the handle's counted bounded-send funnel. The
  Operations API returns this runtime shape without display strings; the browser
  formats it and combines it with typed persisted backlog metadata.

### 10.2 `local` driver — always-on on our own server

The user's presence on e6ircd itself is a network like any other, but the
driver is a direct in-process handle into the IRC core (no TCP, no parse).
This means always-on local sessions, multi-device attach, and playback cost
one implementation shared with the external-network path. "Direct" does not
mean "assumed": the driver waits for the core's 001 (bounded by a 30 s
`WELCOME_DEADLINE`, so a wedged core is a reported failure rather than a silent
wait) and treats a refusal — the nickname is held by another session, or the
welcome names a different one — exactly as the `irc` driver treats an
upstream's.

### 10.3 `irc` driver — external networks (ZNC/soju-style)

- Full IRCv3 *client* implementation reusing `e6irc-proto` + the same SASL
  machinery; requests `server-time`, `message-tags`, and `account-tag`
  from upstream when available (Libera: yes), and `echo-message`, in a
  capability request of its own, when the upstream offers it (§10.1). An
  upstream's SASL password or server password crosses only TLS, or a plaintext
  connection to a loopback address *literal* under
  `internal_upstreams = "allow"` (the test harness): every ingress refuses
  anything else by field (create, replace, connection test, static and managed
  configuration, driver construction), and `e6irc_client::Connection` writes no
  credential to a plaintext peer off loopback — the peer is judged by the
  address actually connected, and only the CLI's explicit
  `--allow-cleartext-credentials` lifts it.
  Synthesized message echoes carry the prefix the upstream shows for this
  session — `nick!user@host`, with the configured user name (tilde included
  when the upstream adds one) and the server's name until the first self-echo
  or `396` reveals the real user and host — and rebuild their traditional body
  within the 512-byte wire allowance, preserving valid client-only tags and cutting
  trailing UTF-8 only at a character boundary; malformed message commands do
  not manufacture an echo the upstream would never send. NickServ commands
  that can contain a password, email address, verification code, recovery
  token, or replacement credential synthesize only a redacted trailing field,
  while the exact command is still sent upstream.
- Auto-reconnect has two schedules, because a lost packet and a refusal are
  different events. A transient drop retries with exponential backoff from
  200ms to a 30s cap, with jitter of 0–25% of the delay drawn per driver from
  its seed; the same seed rotates the vetted address list and advances the
  start per attempt, and stored networks started at boot stagger their first
  dial over 0–5 s — so a daemon restart with many networks, or a network-wide
  drop, does not have every driver re-dial the same server in the same
  instant. A refusal is the upstream's answer and never takes that schedule.
  `RegistrationRefusal::retry_policy` decides, per kind and in the client
  crate so no caller can re-type it, one of three policies. **Park now**:
  rejected credentials (a retry re-sends the same password, can only fail the
  same way, and every failure counts against the owner's account) and a
  welcome under another nickname (`WelcomedAsAnotherNickname`; the owner must
  change the nick). **Schedule, then park**: a refusal the owner may be able
  to outwait but that may also be a configuration fault — 433/436/437 on the
  nick, 432, 468, 464, a SASL exchange that ended without a verdict — retries
  after 30s, 1m, 2m, and 4m and parks on the fifth **of one kind** in a row; a
  refusal of another kind starts the count over, so the 433 that follows a
  services outage (the driver's own ghost) is owed the whole schedule. **Until
  it clears, never park**: a capacity or policy answer from the network — a
  pre-welcome `ERROR` (a connection throttle, "too many host connections", a
  K-line, "SASL access only"), a 465 ban, `sasl_unavailable`, a 906 abort —
  takes the same first steps and then stays at 4m for as long as it lasts,
  with the upstream's sanitized reason in the runtime snapshot the whole time.
  Parking waits for the owner to change something; a throttle, a services
  outage and even a ban give them nothing to change, and a ban that is
  retried every four minutes costs the network one refused dial while keeping
  its reason visible, where a parked network costs the owner a re-save of every
  network the moment a shared throttle lifts. The failure and the time of the next attempt are published as one
  transition (`FailureDisposition::Retry { next_attempt_in }`), so no observer
  can see a network waiting to retry with its reason but no next-attempt time
  (the time is cleared again when the attempt begins). Only a session that
  actually registered resets that count: a dial
  that dies before registration neither counts as a refusal nor forgives the
  ones already counted, so a refusing upstream's own throttle cannot keep the
  driver from parking. The transient backoff likewise resets only after a
  session that reached `Connected` and stayed up for ten seconds: a tarpit that
  completes the handshake and says nothing until the registration deadline
  keeps the schedule growing. A stopped driver — removed, replaced, or stopped
  by process shutdown (§18) — says `QUIT :e6irc bouncer stopping` within 2 s
  before its socket closes, so its successor never meets its own ghost; every upstream write is bounded (10 s, then
  `upstream_write_failed`), the auto-join burst is raced against the stop
  signal, and the registry waits at most 15 s for a stopped driver before a
  replace or remove proceeds, loudly. A server `ERROR` is classified by the one pre-welcome
  refusal predicate at every stage — capability discovery, capability
  requests, SASL, and the welcome — so its reason (`Trying to reconnect too
  fast`, `SASL access only`) is typed and kept wherever it arrives.
  Authentication and registration rejection have distinct terminal lifecycle
  states. The driver only ever offers the nickname the owner configured. A
  433 is a refusal like any other: it is reported with the upstream's text,
  retried on the refusal schedule — which outlasts the usual cause, a ghost of
  our own previous session awaiting its ping timeout — and parks if the
  nickname stays taken. It never substitutes `nick_` or any other invented
  nickname: ZNC and soju do, and the result is an identity the owner did not
  choose, holding channel access and a NickServ relationship they did not
  expect; HexChat, which tries only the alternates its user typed and then
  stops, is the model (§2, no silent fallbacks). The same holds when the
  upstream does the substituting: a welcome addressed to any other nickname
  than the configured one (a server truncating to its NICKLEN, a services
  rename on connect) is a registration refusal that names both, not a
  connection: the driver says `QUIT` first and parks on the first occurrence,
  because nothing but the configured nick can clear it; a difference of case
  alone (RFC1459 folding) is not a refusal. A rename the upstream forces
  *after* the welcome (Atheme's ENFORCE moving an unidentified nick to
  `Guest12345`) is tracked, as it must be, and announced: `renamed_by_upstream`
  in the runtime snapshot with the diagnostic "upstream renamed this session
  from X to Y", and one `*bnc*` notice into the backlog. The `USER`
  name is configured, never derived. It used to be the first ten bytes of the
  nickname, so a legal nickname such as `_bot` registered as `USER _bot`, which
  Solanum-family servers answer by closing the link. `UpstreamUsername` admits
  1–10 bytes, an ASCII letter or digit first, then letters, digits, `_` and
  `-`: the strictest common grammar rather than a merely structural one,
  because a bad user name is answered with a closed link, not a numeric; `.`
  is excluded because whether and how many dots are accepted is per-server
  configuration. It is required for `irc` and `local` networks on every
  ingress (API create/replace/connection test, static and managed
  configuration) and refused for bridges; migration 0057 wrote into existing
  rows and managed entries exactly what each had been sending, repaired only
  where the grammar no longer admits it (`e6irc` when nothing usable
  remains). An upstream that still refuses the user name is a registration
  refusal (`invalid_username`). The browser forms and the native clients state
  one default — a blank user name means the nickname — and apply it only when
  the nickname is itself a legal user name; otherwise they ask for one. Nothing
  is ever rewritten to fit. On reconnect the driver
  re-registers under the configured nick and re-joins the *configured*
  autojoin channels plus every channel the upstream confirmed membership in
  before the drop — comma-joined within the 510-byte line, so a heavy user's
  hundred channels are a handful of lines rather than a burst Solanum's flood
  limit answers with "Excess Flood" (runtime JOIN/PART/KICK are tracked as they
  are acknowledged upstream). Tracked membership is bounded at 512 channels, per session and in
  the reconnect intent: the names come from the upstream, which a tenant may
  point at a server of their own, so an unbounded set was a memory and
  reconnect-flood lever on the shared daemon. Past the bound the session ends
  as `channel_limit_exceeded`; a confirmed name e6irc cannot track is announced
  live and not rejoined. A process restart falls back to the configured
  autojoin, which is the operator-declared floor. Upstream SASL uses
  credentials stored encrypted (§15) with the strongest password mechanism the
  network offers — SCRAM-SHA-512, then SCRAM-SHA-256 (RFC 5802/7677, the
  server's signature verified in constant time, and the iteration count held to
  RFC 7677's 4096 floor as well as a ceiling: the count is what makes a captured
  transcript expensive to attack, so a server asking for less is weakening our
  credential and is refused, not obeyed), then PLAIN — and says which one
  logged in (a `:*bnc*` notice after connecting; `sasl_mechanism` in the
  connection-test result). A server that names no mechanisms is offered PLAIN;
  when its 908 then names a stronger one this client speaks, that one is
  offered once on the same connection. A failed SCRAM (a 904 on the proof, a
  forged or malformed server message, a credential SASLprep cannot carry) is
  never retried as PLAIN: that would hand the password to the server that just
  failed to prove itself. SCRAM's iteration count is bounded at 1,000,000. A network may also carry a server
  password — the `PASS` a private server requires before `CAP LS`, `NICK` and
  `USER`; the driver and the connection test send it as the first line
  through the one `register()`. It is a `ServerPassword` (at most 504 bytes,
  no CR, LF or NUL) refused before a byte leaves, stored sealed, and resealed
  by `rotate-secrets`. A 464 after a `PASS` is `server_password_rejected`; one
  with no `PASS` configured is `server_password_required`; both are
  configuration faults that take the refusal schedule and park, never
  hammering the network. e6ircd itself has no connection password: it accepts
  a `PASS` before registration without reply and answers 462 after it, so a
  client's `PASS` is never answered with a 451 that would read as a refusal
  of `CAP LS`. The client records what the server
  advertises and requests only that, the metadata capabilities in one
  `CAP REQ`. Only a verdict on the credentials themselves — a 904 for a
  mechanism the server offers — is an authentication failure, which parks at
  once. A server that does not offer the mechanism or the capability
  (`sasl_unavailable`), or that ends the exchange without a verdict
  (`sasl_failed`: nick locked, too long; a 906 abort is `sasl_aborted` and is
  retried until it clears), is a registration refusal carrying the server's own
  words. Treating those as "rejected credentials" parked a network instantly
  and left its owner retyping a correct password. A server with no capability
  negotiation at all — a 421 or 451 to `CAP LS`, or twenty seconds of silence —
  registers plainly (NICK/USER and then `CAP END`, harmless to a server that
  merely answered slowly) — unless SASL is configured, where registering
  unauthenticated would be a silent downgrade, so it fails loudly as a
  `registration_timed_out`, retried, never as `sasl_unavailable`. The bound is
  twenty seconds because servers read nothing a client sends until their ident
  and DNS checks end: Libera answered after 6.9 s from a host that drops ident,
  and the old five-second bound made every SASL attempt from there fail as
  "SASL unavailable". An upstream's reason is carried up to 300 characters,
  which holds Libera's cloud-address refusal whole. A
  post-registration `ERROR :Closing Link …` from the upstream (a ping timeout,
  a rolling restart, a services GHOST, an operator KILL) never reaches an
  attached client or the backlog as `ERROR` — several clients treat that as
  the end of *their* connection and reconnect themselves, which is exactly what
  a bouncer exists to hide; it becomes `:*bnc* NOTICE * :upstream closed the
  link: …` and the `connection_lost` diagnostic. The idle
  window that detects a half-open upstream is measured from the last line the
  upstream sent; downstream traffic does not restart it (it used to, so a dead
  link was never noticed while anyone was typing), and the Discord and Slack
  gateways share the same deadline type.
  Once authentication or registration failure parks the driver, its command
  boundary returns terminal unavailability instead of accepting lines into a
  queue that has no consumer.
- Every registration, auto-join, command, heartbeat, and protocol PONG emission
  is part of the session outcome: a failed upstream transport write drops and
  reconnects, while a closed in-process core queue stops the `local` driver
  instead of retrying a permanently gone core. `Connected` is emitted only
  after the upstream — or, for the `local` network, the in-process core — has
  welcomed the registration under the configured nickname and every configured
  auto-join has been written to its transport. A registration the upstream
  refuses is never reported as a connection.
- The dialer vets every DNS answer at connect time, alternates IPv6 and IPv4
  results while preserving each family's resolver order, bounds each concrete
  TCP/TLS attempt, and tries the remaining vetted addresses. TLS still validates
  the certificate against the configured hostname rather than the pinned IP.
  What may be dialled is one rule for every driver (`egress`): addresses that
  are never a network — link-local with the cloud metadata endpoint, broadcast,
  documentation, multicast, unspecified — are refused always, and loopback, RFC
  1918, carrier-grade NAT and unique-local addresses are refused **by
  default**: an account holder types the upstream address, so allowing them
  would let any account make the server connect to internal infrastructure and
  learn what answers. The rule is applied to the literal at every API ingress
  (create, replace, connection test; the refusal names the rule, never the
  address), read as the URL parser reads it — `2130706433`, `0x7f.1`, `127.1`,
  `0177.0.0.1`, percent-encoded octets, `user@host` — so no spelling of an
  internal address passes as a hostname, and to every *resolved* address at dial time, so a hostname that
  resolves — or later rebinds — to an internal address is refused there. The
  one exception is operator-level: `internal_upstreams = "allow"` in the server
  configuration, which the test harnesses set because their upstreams are
  in-process listeners on loopback. It is not exposed through the container's
  environment.
- Primary interop target: Libera (tested against the §7.7 docker stack).
- Account registration remains ordinary IRC services traffic. The console's
  guided email round trip emits `PRIVMSG NickServ :REGISTER password email`
  and `PRIVMSG NickServ :VERIFY REGISTER nick code` only while the upstream is
  connected, then stores the verified account/password through the existing
  sealed write-only credential path. Owners may send the same commands from
  any attached IRC client. A provider that blocks registration from the
  deployment's address must be registered through an accepted connection;
  e6irc cannot convert that provider policy into a successful local preflight.

### 10.4 Attach addressing

Downstream clients select a network with the ZNC/soju username convention:
`alice/libera` (default network configurable; bare `alice` = `local`).
The selector's nick and network components are independently validated; the
slash-bearing selector is routing input, never the downstream IRC identity.
Registration and later session reconciliation use the actual upstream nick (or
the validated nick component while no upstream session exists). Off loopback
the attach listener requires `[bnc].tls` (console: `bnc_tls`), because
attaching clients send their account password; the configuration file and
every console save refuse a cleartext non-loopback bind. Attach SASL
PLAIN accepts an empty authorization identity or the same RFC1459-folded
identity as its authentication identity; it cannot authenticate one account
while requesting authorization as another. The web client and REST API address
networks explicitly by id.

### 10.5 Bridges: `matrix` / `discord` / `slack` drivers

Bridges are **network drivers** behind feature flags — a Discord guild or
Slack workspace appears to the user as another network with channels;
Matrix rooms likewise. v1 ships the **SPI + a loopback reference driver** (used in tests) and
the **`matrix` driver** (Matrix client-server API, behind the `matrix`
feature, integration-tested against a pinned Conduit homeserver in
`vendor/tests/external-oracles/`), plus Discord and Slack drivers with local
HTTP/WebSocket contract oracles. Shipped credential-gated campaigns perform
provider authentication, two sessions, delivery, read-back, and cleanup; a
commercial-provider claim still requires retained passed evidence.

External qualification parses provider-discovered HTTP and WebSocket endpoints
before it sends credentials. HTTP endpoints use HTTPS unless the issuer is a
loopback test oracle; WebSockets use WSS under the same rule, and the bridge
gateway dialer enforces it: a `ws://` gateway URL from the upstream is refused
unless the configured API base is itself a loopback `http://` under
`internal_upstreams = "allow"`. Every bridge HTTP request is built through
`BridgeHttp`, which judges the parsed URL host against the egress rule before
the HTTP client sees it (IP-literal hosts never reach the vetting resolver),
and any 3xx answer is a failed request, never a delivery. Bridge REST bases are
HTTPS too: `validate_bridge_base` and `BridgeHttp::request` admit `http://`
only for a loopback test oracle under `internal_upstreams = "allow"`, where
Matrix passwords, access tokens and bot tokens used to be able to travel in
cleartext while the gateway already required `wss://`. OIDC metadata
cannot cross between the external and loopback trust domains. Signed provider
WebSocket query parameters stay inside the typed endpoint and never enter
evidence.

Qualification verification binds evidence to an explicit source revision,
target, and freshness limit. Scale evidence also binds the retained raw load
result and host provenance by digest and verifies their target, budgets,
workload, host digest, and outcome before acceptance.

Design constraints recorded now:

- Per-user ("personal bouncer", Bitlbee-style) mode is the primary mode and
  fits the multiplexer natively.
- Server-level **relay mode** (mirroring a remote channel into a public local
  channel with synthetic identities) is outside the bridge contract. Bridges
  are attached networks, either account-owned or explicitly shared, and do not
  inject remote identities into the local IRC namespace.
- Driver-specific transports: Matrix client-server API (long-poll /sync),
  Discord gateway WebSocket + REST, Slack Socket Mode. Each stays inside its
  feature flag including its HTTP client code.
- A bridge separates what retrying can fix from what it cannot. A transport
  failure reconnects on the transient schedule (a 403 on Matrix `/sync`
  included); an answer about the configuration itself (Matrix: a 403 on a room
  join, which is "not invited"; any bridge: a room or channel name that is not
  a safe IRC channel name, or two that fold to one channel) is a
  `ConfigurationRejected` outcome whose policy is decided in one place,
  `ConfigurationRefusal::retry_policy`, by the same rule as a registration
  refusal: what only the owner can clear parks at once (a Discord gateway
  configuration close 4010–4014, Slack `link_disabled`, an encrypted Matrix
  room); what the upstream may clear on its own takes the refusal schedule and
  then parks (a room join refused before an invitation arrives, a channel name
  the provider side can rename). The diagnostic is e6irc's own sentence naming
  the room or channel; provider response text is deliberately never carried.
  A 401/403 on Discord's channel lookup is about the token, so it is
  `AuthRejected` and parks at once.
- A Matrix password login creates a device on the homeserver that only
  `/logout` removes, so the login belongs to the driver, not to the session:
  made once, reused by every reconnect, replaced only when the homeserver
  answers 401 to the token, and logged out when the driver stops. `/sync` is
  filtered to the bridged rooms (no presence, account data or ephemeral events,
  lazily loaded members, a bounded timeline) — unfiltered, the first sync is
  the whole account, which on a populated one exceeds the bridge response cap
  so the bridge could never come up. The first sync only establishes a
  position; a timeline the homeserver cut short is announced as a gap. Every
  login names the same device, `e6irc/<owner>/<network>` (`*` for a
  server-level network), so a process that crashed before it could log out
  re-uses its device instead of leaving one behind. Transaction ids are minted
  per driver (a counter prefixed with the driver's start time), never per
  session: the device, and so the id scope, outlives sessions and processes,
  and a repeated id is silently deduplicated by the homeserver. The sync
  position is kept beside the login too: `since` and the joined rooms survive
  a reconnect (cleared with the login, on a configuration refusal, or when the
  homeserver refuses a resumed sync), so an outage's messages are delivered or
  a `limited` timeline announces the gap; a 429 on `/sync` waits the requested
  time and re-asks from the same position instead of reconnecting. A bridged
  room with `m.room.encryption` state (checked after each join) or an
  encrypted event mid-session is `ConfigurationRejected(room_encrypted)`: the
  bridge holds no device keys and would otherwise relay nothing, silently.
  `m.emote` becomes a CTCP ACTION, `m.notice` a NOTICE, media its body plus the
  spec's `/_matrix/media/v3/download` link (homeservers that enforce
  authenticated media will not open it), `m.location` its body plus a geo URI;
  any other msgtype produces one bounded "not relayed" notice.
- Discord keeps its gateway session per driver and RESUMEs on
  `resume_gateway_url` after a drop, so the gap is replayed and the daily
  IDENTIFY budget is not spent; op 9 (invalid session) ends the session — it
  used to be ignored while the gateway kept ACKing heartbeats, leaving the
  network "connected" and deaf — and op 9 `d:false` and close codes
  4004/4007/4009/4010–4014 forget the session. A heartbeat that finds the
  previous one unacknowledged drops the zombie connection; op 7 reconnects
  without recording a failure. 4004 is `AuthRejected`; 4010–4014 are
  configuration refusals that park at once with a code-specific diagnostic
  (4014 names the Message Content intent). Posts send
  `allowed_mentions: {parse: []}`, so an IRC line can never page a guild.
- Slack reads `disconnect.reason`: `warning` and `refresh_requested` open the
  next socket inside the session while the retiring one is still read and
  acked (no failure recorded); `link_disabled` is a configuration refusal.
  Envelopes are acked before any HTTP work, deliveries and name lookups run in
  bounded serial queues beside the socket, a re-delivered envelope id is acked
  and not relayed twice, and the socket is pinged every 30 s. Outbound text
  escapes `& < >` (which also neutralises `<!channel>`); inbound entities and
  markup are decoded (`<@U…>` to `@name`, `<#C…|n>` to `#n`, links to
  `label (url)`). Message subtypes are a whitelist (file shares, thread
  broadcasts, `/me`, edits as `* text`, other bots); housekeeping subtypes and
  deletions (IRC has no deletion) are dropped by name, and an unknown subtype
  produces a bounded notice. A failed name lookup is not cached. The
  display-name cache is bounded at 4096 upstream ids; overflow clears it,
  counted and logged.
- Reverse bridge delivery accepts `PRIVMSG` only. A CTCP ACTION becomes the
  provider's emote (Matrix `m.emote`, Discord/Slack italics) and any other CTCP
  is refused; IRC formatting is stripped outbound; inbound provider text loses
  every C0 control but tab and newline, so remote text can never reach an IRC
  client as a CTCP request (`\x01VERSION\x01` used to be delivered as one).
  One shared `BridgeText` does both directions for all three drivers. A 429 is
  waited out once (at most 10 s) before the undelivered notice names the rate
  limit. Unmapped targets, malformed messages, unsupported commands, and
  per-target provider failures each emit a bounded `*bnc*` refusal notice;
  queue admission can never become a silent bridge no-op.
- The Discord qualification campaign identifies with the driver's own intents
  (`e6irc_proto::provider::DISCORD_GATEWAY_INTENTS`), so a pass proves the
  application may receive them; the Slack campaign proves delivery by acking
  the marker's own `events_api` envelope before cleanup.

---

## 11. History & CHATHISTORY

- **11.1 What is logged**: channel messages on the local server (per-channel
  opt-out honoring, e.g., `+P`-style policy decisions), direct messages between
  two accounts, and all BNC network buffers. Every stored message has a stable `msgid` (also sent live
  via `message-ids`) and a Unix-**millisecond** timestamp, stamped once and
  shared by live delivery, the hot ring and the `messages` row — `server-time`
  is specified to milliseconds and CHATHISTORY pages by timestamp, so a coarser
  or twice-read clock makes messages unorderable or replays them bearing a
  different time than they were delivered with.
- **11.1.1 Conversations**: a direct message is stored **once**, under a key
  built from both participants' *identities* sorted and joined by `!`. Sorting
  makes the key symmetric, so both sides read the same thread from the single
  copy; replay re-addresses each message to its original recipient rather than
  to the conversation, so a replayed line matches the one delivered live.
  An identity is the participant's **account**, or a `~`-prefixed nick when they
  have not authenticated. A database CHECK constraint keeps `!` out of account
  names, so the key stays unambiguous no matter what future code creates an
  account — an account called `a!b` would otherwise collide with the
  conversation between `a` and `b`. This distinction is load-bearing, not cosmetic: a nick
  is released on disconnect and anyone may take it, so keying by nick would mean
  registering a nick handed you the previous holder's private messages. `~`
  cannot occur in a nick or an account name, so an unauthenticated identity can
  never be claimed by an account of the same name. Two successive
  *unauthenticated* holders of a nick derive the same `~nick` — there is
  nothing stronger to key on. A conversation with an unauthenticated party is
  therefore never written to the database and never read from it: it lives
  only in the in-memory ring, on the shard of each party, and every shard frees
  it the moment that identity is let go, whether by disconnecting, by
  changing nick, or by logging in (SASL, NickServ IDENTIFY, or account
  registration): the connection is then its account, and `~nick` belongs to
  the next holder. `ServerState::set_account` is the one path by which a
  session gains an account — the field is write-private — and it performs the
  release. An authenticated participant keeps such a conversation for
  exactly as long as the other party holds the nick; CHATHISTORY TARGETS finds
  each channel's newest message with one backward index probe (LATERAL
  `max(ts)`), and lists
  it from the ring alongside what the database returns. Only a conversation
  between two accounts is stored, and a stored conversation is always addressed
  by one exact key. Migration 0058 deleted the `~` conversations stored before
  this rule.
  The BNC persistence path applies the same symmetry to raw external-network
  lines: an inbound direct message is keyed by its source and a synthesized
  outbound echo by its recipient, both RFC1459-folded. TARGETS and paging
  therefore expose one peer buffer containing both directions, including after
  restart or a nick change between emission and persistence.
- **11.2 Query surface**: IRCv3 `CHATHISTORY` (BEFORE/AFTER/AROUND/BETWEEN/
  LATEST/TARGETS) for IRC clients; `GET /api/v1/history/...` for the web
  client and API consumers — both hit the same query layer, including direct
  messages. The two surfaces authorize differently because they see different
  things: a channel read over REST has no view of live membership, so it fails
  closed to a registered relationship (founder or access), while a conversation
  read needs no check at all — its key is derived from the *authenticated
  account*, so a caller can only ever address a conversation it is part of and
  there is nothing to bypass. Both derive that key from one function, since two
  implementations that must agree is how a privacy boundary drifts. A REST
  conversation is addressed by account name, so conversations with an
  unauthenticated party are not reachable there. The REST API pages by time
  only — a message id is not an accepted position, so the unknown-msgid case of
  §11.3 cannot arise there — and every refusal names the parameter at fault
  (`field`: `target`, `limit`, `before` or `after`).
- **11.3 Hot path**: per-target in-memory ring (last 500 events) answers
  the common "LATEST *" without Postgres; misses fall through to the
  `messages` table. Channels and conversations share one ring store, one LRU
  and one cap, so the overflow and eviction rules cannot drift apart between
  them. A msgid used as a paging pivot is resolved **within the target being
  paged**: a msgid belonging to some other buffer names a position that does not
  exist here, so it is unknown here. A msgid the authoritative store does not
  hold for the target — the ring when it is the whole record, otherwise the
  database — answers `FAIL CHATHISTORY MESSAGE_ERROR <SUBCOMMAND> <target>
  :unknown msgid`, never an empty page: a client resuming from a vanished msgid
  would read "nothing newer" as "up to date". A timestamp that matches nothing
  is a real position and stays an empty page. The bouncer's CHATHISTORY emits
  the same line. A page is cut by the database in the *client's* scope: a
  stored `TAGMSG` is nothing but tags, so a client that did not negotiate
  `message-tags` cannot receive one at all, and excluding those rows after the
  `LIMIT` returned fewer lines than asked for — indistinguishable from the end
  of the buffer. `BncHistoryScope` is built from that one capability and rides
  into the query, so the `LIMIT` counts only deliverable lines, and TARGETS
  answers in the same scope rather than naming a conversation whose page comes
  back empty. What decides it is `bnc_buffer.command`, a column generated from
  the line (migration 0069) rather than written beside it: it cannot disagree
  with the line it describes, it covers rows stored before it existed, and it
  reads the frame — a message whose *body* mentions `TAGMSG` still arrives. A session may have at most 8 history requests waiting on the
  database; beyond that it is answered `FAIL CHATHISTORY MESSAGE_ERROR …
  :Too many history requests in flight`, so one client cannot fill the database
  queue that logins and message logging share.
  With no database the rings are the whole record. A channel's ring lives on
  the shard that owns the channel; that shard publishes when the ring last saw
  a message, and CHATHISTORY TARGETS is answered from the published value on
  every shard, so the answer does not depend on which worker owns a channel.
  A reply that has to reach Postgres is *deferred*, and the connection's
  later output is held behind it — replies must reach a client in the order it
  issued the commands, or a client that pipelines CHATHISTORY and PING sees the
  PONG first and concludes the history was empty. Held output carries the same
  bound as the send queue it is waiting to enter, so a connection blocked on the
  database is still killed for SendQ overrun rather than buffering without limit.
  **Rings are lazy and LRU-evicted** so hot-history RAM
  is bounded by *activity*, not target count: only the
  `max_hot_channels` (default 8192) most-recently-active targets hold a
  ring; a channel that overflows its ring or is evicted is marked
  history-incomplete and serves CHATHISTORY from Postgres. Target scale
  (2026-07-19, user-confirmed): ~100k channels, ~1k concurrent BNC
  upstream sessions — at 100k channels an always-on 500-entry ring per
  channel would be tens of GB, so eviction is load-bearing, not an
  optimization.

---

## 12. REST API (`/api/v1`)

Versioned under `/api/v1`; JSON; errors use RFC 9457 problem+json shape.
Every URL query and form is closed: unknown fields are rejected before a
handler runs. OIDC callback issuers, when returned, must exactly match the
configured provider.
Surface (initial):

- `auth`: OIDC start/callback, device-flow bootstrap, logout
- `me`: profile, credentials (app passwords CRUD — secret shown once),
  API tokens CRUD, OIDC identity link/list/unlink
- `networks`: BNC network CRUD (+ enable/disable, status), buffers list,
  read-marker get/set. Full IRC updates use `PUT /me/networks/{name}` with a
  required credential action (`keep`, `set`, or `remove`), so a write-only
  secret is never changed through an ambiguous omitted-field convention. The
  server password has its own required action beside it (`keep`, `set` with
  `password`, or `remove`; only an IRC network accepts `set` or `remove`);
  create and the connection test take an optional `server_password`, a value
  that cannot travel in one `PASS` line is a 400 naming `server_password`, and
  responses report `has_server_password`, never the value. The tagged actions
  refuse stray fields, so a password typed beside `keep` is refused rather than
  silently dropped. Both browser clients omit a blank credential field rather
  than sending null; an
  account box emptied against a stored account, or a value typed under a
  ticked Remove, is refused at the box rather than resolved one way or the
  other.
- A first OpenID Connect login provisions an account named exactly by the
  provider's configured claim; a name already in use or retired is a
  `409 Account name already taken` naming the claim — the server never
  suffixes or invents a name for a person. The callback query is a closed set:
  `session_state` (Keycloak, Microsoft Entra) is admitted and ignored, and any
  other unknown parameter is a problem-document 400, as is every other
  handler's query (`QueryParams`). Linking an identity requires an active
  account.
- `channels`: owner-scoped registered-channel inventory and management at
  `/me/channels` (live-operator registration, retained topic, KEEPTOPIC,
  canonical MLOCK, access flags, founder transfer, unregister)
- `history`: paged queries per §11.2
- `admin`: bounded, exact-filtered/stable-cursor account posture, registered
  channel policy, global K/D/X-line policy, and audit log; server stats;
  account suspension/reactivation; live/historical observability; Prometheus
  exposition. Personalized
  administrator JSON and metrics responses carry `Cache-Control: no-store`.
- `healthz` (liveness; no auth): the process answers and every core shard's
  heartbeat is within 45 s; database-free, so a database outage shows on
  `readyz` and never restart-loops the container, while a stalled shard is a
  503 the health check acts on. It used to be a constant.
- `readyz` (the same core check plus configured-PostgreSQL readiness; no auth)

The OpenAPI 3.1 document at `/api/v1/openapi.json` is hand-authored for
request/response semantics and always served (no feature gate, no utoipa
dependency). Its method/path inventory and path/query parameter declarations
are checked against the Axum API router; a mismatch is a unit-test failure and
the endpoint refuses to serve a plausible but incomplete contract.

---

## 13. Web client (askama + vanilla JavaScript + Vite)

### 13.1 Model

Two surfaces, both without an SPA framework. The **management** pages —
login, the user account section, and the `/console` admin/BNC/integrations
console — are server-rendered Askama document shells. Their authenticated
reads and mutations use `/api/v1`; no `/console` mutation route exists. The
always-served, same-origin `/console.js` hydrates those API-backed controls,
including explicit confirmation, retry, and failure states. The shared
confirmation dialog repeats the initiating action label and severity, preserves
the submitter's name/value semantics, and resets its return state before every
opening so Escape can never inherit an earlier confirmation. Every API-backed
form also crosses one shared in-flight submission guard: the initiating action
gains a visible and accessible progress state, every submit control in that form
is disabled, and keyboard, pointer, or synthetic resubmission cannot issue a
second mutation until the first operation and its view refresh finish. On phone layouts,
the active route is brought into the horizontal console-navigation viewport on
load. The console works
in the default build and `embed-web`; its private pages permit only that
same-origin script. The shared browser contract parser validates each path,
query, JSON request, and JSON response before a request or view uses it.
`/console/channels` lets an identified live channel operator register it, then
manage the retained topic, KEEPTOPIC, canonical mode lock,
auto-op/auto-voice grants, ownership transfer, and unregister lifecycle
through storage-confirmed core mutations. Empty and unauthorized inventories
remain distinct from storage failures, and every form is session-CSRF
protected. `/console/accounts` gives administrators a newest-first,
case-insensitive exact-search directory of account age, login-method posture,
effective administrator/suspension state, active access, networks, and founded
channels. It can suspend/reactivate every non-current account and explains the
credential/session/network consequences before submission. It deliberately
shares the
secret-free projection and stable cursor with `GET /api/v1/admin/accounts`;
the overview requests only its newest ten rows. `/console/admin/channels` and
`/console/bans` likewise own bounded exact-search policy directories and their
destructive controls; channel unregister and ban add/remove still cross the
live core and redirect back to the page that owns the mutation. The overview
contains only ten-row previews instead of unbounded policy tables. The **live chat
client** is a small hand-written vanilla-JS IRC client (`web/src`,
bundled by Vite): it parses IRC lines client-side into buffers and a member
list rather than swapping server HTML, since per-channel routing and nick-list
state are naturally client state. Its embedded HTML and hashed assets carry a
deny-by-default CSP permitting only same-origin scripts, styles, fonts, forms,
images, and HTTP/WebSocket connections. The socket reconnects with backoff so a
transient drop self-heals. Networks appear in exactly one place: the sidebar
list, which opens a network, shows its state, and carries its settings control.
It is re-read every ten seconds while the page is visible, because state
changes on the server (a reconnect, a rejected password) and a list read once
went stale and contradicted its own copies. A row whose network is not
connected quotes the upstream's own sanitized reason beside the control that
repairs it. Opening the page without a `?network=` selector opens the account's
sole runnable network and rewrites the address to say so, because opening the
only one is not a choice. With several, the client does not pick "the first"
on the person's behalf: the landing panel asks them to choose from the list
(and, on a phone, offers the control that shows it rather than opening it
unasked). An account with nothing runnable sees the same panel, whose action
adds a network in place. Adding a network opens it. A refresh that changes
nothing leaves the list alone, and one that changes it hands keyboard focus
back to the same control of the same network; an expired session offers Sign
in once and stops asking. Each opening of the settings dialog is numbered, so a
slow answer for an earlier opening can neither fill in nor throw inside a later
one, and settings that failed to load cannot be saved as blanks over the stored
ones. The dialog also *removes* the network, because it is the one editor and a
person who added a network here had otherwise to go to the console to delete
it: the button asks once, naming what goes with the network (its stored
backlog, read positions, and credentials), and the second press is the answer
-- no browser dialog, which cannot be styled, translated, or driven by the
tests that have to prove a destructive path. Removing the network that is open
returns the client to the picker in this document, because its socket and its
conversations are state about something that no longer exists. The console
lists networks and keeps the same control on the network's own page (where a
bridge, which the dialog does not edit, is also removed); it carries no Remove
on each row of the list, where a destructive button repeated per row is the
easiest to hit by mistake. Only a join asked for in this client moves the view: the bouncer
rejoining every channel after an upstream reconnect does not. Replay therefore
no longer decides where a network opens (it used to leave whichever channel it
mentioned last): once the attach replay ends, the client reopens the
conversation that was open on that network last time, else a network's only
conversation, else it stays put for the person to choose. A bridge
network's settings control leads to its own per-type form rather than the IRC
dialog. No field that takes a third-party credential is marked `username` or
`current-password`: the only credential a browser holds for this origin is the
e6irc login, and those tokens invite it to be filled in and sent to another
network (a test scans the chat shell and every template for it). A failure of something the person just asked for -- a message that
did not enter the socket, a join that was not sent, backlog that would not
load, a refused notification permission -- is reported once, as an alert above
the chat, which is read whatever conversation is open and is deduplicated by
key. The console conversation keeps the connection's own record (what it sent
and received, what was enabled, why a socket was not opened); it is not a
second place for failures, which used to be written there as well, in wording
that had drifted from the alert's. The
preferences menu owns validated theme/notification settings, stored one key at
a time so the chat and the console — which share the record — cannot undo each
other's change, and responsive conversation navigation
preserves the full chat pane on phones. Every mutation the chat client sends
carries the session's `X-E6IRC-CSRF` value read from `/api/v1/me`; the shared
API contract module owns that header and `Content-Type`, refusing an unsafe
method without the token before it reaches the network, so neither client can
set — or therefore forget — them by hand. The identity, console, and
chat surfaces share the relay-desk visual system: dark routing chrome, compact
monospaced provenance labels, high-contrast state colors, and one amber route
trace joining network context to the active conversation. A disabled network
still opens: its page says why chat is unavailable and links to where it can be
enabled. Identity, network-list,
history, storage, notification, and socket-protocol failures have visible,
actionable states; an API failure is never rendered as an empty account. The
member list is rank-ordered with sigils kept live from channel `MODE`, reading
membership sigils and which modes take a parameter from the network's own
`005 PREFIX` and `CHANMODES` (RFC-style defaults until they arrive), and the
client offers a join-channel input and click-to-query on nicks. On phone widths
the member list is a header-toggled panel mirroring the conversation rail. The
sign-out link exists only once `/me` has supplied its CSRF-bearing URL.

### 13.2 Live chat over WebSocket

The chat page opens one WS (`/ws/ui`, cookie-authenticated). The server pushes
typed line, status, authoritative `session` (nick + joined channels), and
`{"t":"snapshot","v":"complete"}` replay-boundary events. Raw line events preserve IRCv3 `time` and `msgid` tags so live and
persisted timelines use the same clock and have stable overlap identity. The
client applies the protocol parser's last-duplicate-tag rule, parses each line,
routes it to the right buffer (channel / DM / server), with STATUSMSG targets
such as `@#ops` routed to the underlying channel,
maintains the per-channel member list, reconciles stale replay buffers against
the session event, and renders the active buffer (all via
DOM APIs, never `innerHTML` on server text, so a hostile upstream line can't
inject markup). Startup uses this atomic socket replay as its single initial
backlog source rather than racing it against a duplicate REST snapshot. The
replay boundary precedes live traffic; only after it does
the client request authoritative NAMES snapshots, preventing stale detached
replay from overwriting current membership. Every `line` event and the
`snapshot` boundary carry an opaque replay cursor (`<epoch>:<seq>`: the
ring's lifetime and the line's position); a reconnecting socket presents it as
`?after=` and is replayed exactly the lines after it. A cursor the ring cannot
honour — another lifetime after a restart or a replaced driver, an evicted
position, or text that is not a cursor — is answered with
`{"t":"replay","v":"full"}` followed by the whole ring, and the client resets
its transcripts with one "history reloaded" note. The client keeps no
de-duplication heuristic. Before each transport retry the
client checks the session; a 401 ends the retry loop and offers sign-in once.
A message typed into a channel the session no longer holds is refused with a
one-click rejoin; only slash commands pass. The composer sends
`{id, target, message}` (with slash-commands) up the same socket, which the
server validates as one complete IRC line and maps to the driver. CR/LF/NUL
injection and an over-limit derived line reject the whole request; they are
never cleaned or truncated into a different message. At most 64 sends await a
result. The browser appends local echo and sent-history only after the server
returns the matching `sent` event; `send-error`, queue refusal, replacement,
and socket closure retain retryable text and cannot produce a false successful
echo. This keeps the web client on the exact same multiplexer attach path as an
IRC client — the web client *is* an attached client of the user's networks.
Fetching persisted history prepends it without replacing live lines or local
echoes that arrived while the request was in flight. Matching non-empty
`msgid` values and the exact ordered wire overlap at the history/live boundary
are deduplicated; content equality elsewhere is not identity because distinct
IRC messages can have identical bodies. Explicit history expands the buffer's
bounded capacity by one API page, so loading older context remains effective
even when the normal live window is full. Live and persisted PRIVMSG/NOTICE
rows use the same routing function, so a status-target or server notice cannot
change buffer class when older history is loaded. Self PART/KICK closes the
channel buffer, direct-message buffers have an explicit local Close action,
and channel buffers have a Leave action whose confirmed self PART closes them.
Comma-separated JOIN/PART targets and the supported multi-target KICK forms
update every affected buffer using the same pairing rules as the BNC session
tracker. Malformed membership commands and incomplete topic numerics are shown
in the server buffer rather than ignored or allowed to throw in the socket
handler.
The browser's **console** — the first entry in the conversations, where the
server buffer used to be — shows every exact safe inbound IRC wire line,
including state-changing lines, numerics and NickServ replies, beside e6irc's
own notices, and sends what is typed there as the IRC line itself (a `/command`
still means the command). It replaced a separate Server log panel with a
switch of its own. The command
reference exists once, in the help dialog, and `/help` prints that same list; `/query`, `/msg`, `/notice`, `/join`, `/part`, `/nick`, `/me`, `/raw`,
and `/quote` preserve normal IRC workflows instead of requiring a
configuration-only UI.
Status values are the closed set `connected`, `disconnected`, and
`unavailable`. The first two describe a live driver's upstream lifecycle;
each driver transition has a monotonic revision, so an initial sticky status
suppresses every older status already queued at the attach boundary. A
connected sticky event never carries a historical failure reason.
`unavailable` is terminal for that socket because the network was removed,
disabled, or replaced. The client reconciles the REST inventory and attaches a
live replacement under the same name; if none exists, it stops its transport
reconnect loop and offers the network console instead of retrying forever.

### 13.3 Build & deployment duality

Vite builds `web/` → `web/dist` (hashed assets). Two deployments of the
same artifact:

1. **Embedded** (`embed-web` feature): `rust-embed` serves `dist/` from the
   binary at `/`, immutable cache headers keyed on the content hashes.
2. **Static storage (S3/CDN)**: `dist/` is uploaded as-is and served through a
   same-origin CDN topology (`/assets/*` → static storage, application/API/
   WebSocket/console paths → e6ircd). The browser session cookie and WebSocket
   Origin check deliberately share that one origin; a cross-origin application
   shell is not a supported deployment and no build-time variable pretends to
   weaken that security boundary.

### 13.4 IRC-over-WebSocket (always compiled)

Alongside the application-specific `/ws/ui` socket, expose the IRCv3 WebSocket text
encoding at `/ws/irc` so existing web IRC clients (e.g. gamja) can connect
directly. Cheap to provide (same parser, same session path as TCP).

The endpoint negotiates the IRCv3 WebSocket subprotocol: a client offering
`binary.ircv3.net` and/or `text.ircv3.net` gets its **first choice** echoed,
which fixes the outbound frame type for the connection (binary → raw bytes;
text → text frames, non-UTF-8 lossily replaced with U+FFFD as a text frame
requires valid UTF-8). A client offering neither gets per-line auto framing
(text when valid UTF-8, else binary) — the original behavior.
Each WebSocket message is exactly one IRC line without a CR/LF terminator, as
required by IRCv3. An embedded delimiter rejects that whole message as
malformed and can never be interpreted as a second command; the transport cap
is the complete client tag-plus-body allowance.

A dedicated **WS-IRC listener** is also available: a `[[listeners]]` entry
with `websocket = true` serves this same endpoint at the root path
(`ws://addr/`) on its own port, with no HTTP UI surface — for deployments
that want a bare WS-IRC port (and the shape upstream irctest's websocket
suite drives). TLS is terminated at a front proxy, so `websocket = true`
with a `tls` section is refused at config load.

---

## 14. Native clients

### 14.1 `e6irc-cli` — scripting client

Non-interactive, pipe-friendly: `e6irc send '#chan' 'msg'`,
`e6irc tail '#chan'`, `e6irc raw`, `e6irc history …`, and
`e6irc api <method> <path>` (bounded authenticated HTTP/HTTPS passthrough).
IRC commands support plaintext or public-CA TLS and anonymous, paired SASL
PLAIN, or SASL OAUTHBEARER registration. `tail --json` emits one complete JSON
object per message, including structured tags, for safe automation. An
unbounded `tail` that loses its server — closed, or silent through two
three-minute liveness windows, the first ending in `PING :e6irc-keepalive`
(the shared `e6irc_client::liveness` the TUI also uses) — exits nonzero, and a
reader that goes away (a broken pipe) ends `tail`/`history` output cleanly.
`&` channels are joined like `#` ones. Every wait on the server — connecting
and registering, a capability request, a join with its history, and every
wait after `QUIT` — is bounded by `--response-timeout` (30 s by default), so
a peer that holds the socket open with irrelevant lines cannot hang a script.
`send` confirms delivery: it requires `echo-message` and, without it, fails
with "delivery cannot be confirmed" before sending anything; it gets past the
registration burst with a PING round trip and exits 0 only on its own echo,
while a refusal (`e6irc_client::is_refusal`: a 400–599 numeric or `FAIL`,
shared with the TUI) or no verdict within the timeout is a nonzero exit. `raw`
prints every server line to stdout and each refusal to stderr, and exits
nonzero if any line was refused. `--tls-name` requires `--tls`.
Every authentication mode requests the same optional server-time,
message-tags, and account-tag metadata capabilities, so changing credentials
cannot silently reduce the information delivered to the caller.

Both native clients take `--username`, the `USER` name. When it is absent the
nickname is used, and only if it is itself a portable user name
(`e6irc_client::is_portable_username`, the grammar of §10.3); a nickname that is
not stops the command with a request for `--username` and is never shortened or
rewritten to fit.

A secret never has to be typed where the process list and the shell history
can see it. Each one — the SASL password, the SASL OAUTHBEARER token, the
`api` bearer token — comes from exactly one of a file (`--password-file`,
`--oauth-token-file`, `api --bearer-token-file`), the environment
(`E6IRC_PASSWORD`, `E6IRC_OAUTH_TOKEN`, `E6IRC_API_TOKEN`), or the command-line
flag, whose `--help` says what it costs. The flag and the file together are a
usage error, not a precedence rule; the environment is consulted only when
neither was given, and a variable that is set but empty is an error rather than
"absent". Flags always win over the environment: the password variable is
consulted only when `--account` is given, and `E6IRC_OAUTH_TOKEN` selects
bearer authentication only when no authentication flag is present. A secret file is held to the token cache's standard (refused when
group- or other-readable, bounded, UTF-8), loses one trailing line break, and
must not be empty or missing. `e6irc-client::credentials` is the one resolver
the CLI and the TUI share, so the two cannot disagree.

Neither client sends a credential over a connection that is neither TLS nor
loopback — decided by address, not by name: every address the host resolves
to must be loopback, and exactly those addresses are dialled
(`e6irc_client::loopback_addresses`), so a `*.localhost` name that DNS answers
with a public address is refused. The request is refused before the socket is
opened, naming
`--allow-cleartext-credentials` as the explicit override. The refusal lives in
`e6irc-client` (`CleartextCredentials::{Refuse, Allow}` on
`ConnectionOptions`), not in each binary's argument handling, so a new caller
cannot forget it. The same holds for the HTTP commands: `e6irc login` (which
exists to obtain a token) and an `e6irc api` call that carries one are refused
over `http://` to any host but this machine before a request is made, with the
same override and the same definition of loopback; they pin their HTTP client
to the vetted addresses and ignore proxy environment variables (an
`HTTP_PROXY` would otherwise receive the bearer token in cleartext), and the
CLI runs one TLS stack (aws-lc-rs; reqwest is built without its `ring`
provider). An `api` call that carries no token is not refused.
`--oauth-from-cache` sends the cached token only to an IRC server on the host
of the origin that issued it; `--allow-oauth-token-for-other-server` is the
explicit override. Both native clients take a server password from
`--server-password-file`, `E6IRC_SERVER_PASSWORD`, or `--server-password`
(visible in the process list), through the same resolver and precedence as the
SASL secrets; it is sent as the first line, falls under the same cleartext
refusal, and a 464 tells a missing password from a rejected one. A server
that refuses and closes can make the client's next registration write fail
first; the client then reads what the server sent before it left (for at most
two seconds) and reports that refusal, not the broken pipe.

`e6irc login` implements the RFC 8628 device flow: it prints the verification
URI and user code, honors the server's polling interval/slow-down/expiry
contract, and atomically stores the issued bearer token without printing it.
The shared cache includes the issuing API origin so `api` cannot silently send
it to a different `--base`; an explicit token or `E6IRC_API_TOKEN` wins without
requiring a cache path. Unix storage is created with private directory/file
modes and refused when group/other-readable. Windows uses the current user's
local application-data directory and atomic replacement. Both native clients
can use the same cache for SASL OAUTHBEARER with `--oauth-from-cache`.

### 14.2 `e6irc-tui`

The shipped ratatui client uses one owned `e6irc-client::ConnectionOptions`
request for plaintext/public-CA TLS and anonymous, SASL password (the
strongest of SCRAM-SHA-512, SCRAM-SHA-256 and PLAIN the server offers), or SASL
OAUTHBEARER registration. An `account/network` SASL account selects an owned
BNC network. It has bounded channel/query buffers, Alt-Left/Right, Alt-b/f
(macOS Option-arrows arrive as ESC b/f) and Ctrl-P/N switching (other Alt/Ctrl
letters are ignored rather than typed),
bounded scrollback, a relay/status strip, an active-first conversation rail,
a visible horizontally-following composer caret, `/help`, `/join`, `/msg`,
`/win`, `/raw`, literal-slash escape with `//`, `/quit`, Ctrl-End return to the
latest message, Ctrl-C exit (Esc clears the composer; it does not quit), automatic reconnect with the same explicit
request, and loud disconnect/write/drop state. The steady-state read is
bounded by a three-minute liveness window measured from the server's last
line: one silent window sends `PING :e6irc-keepalive`, a second ends the session
with "server stopped responding" and runs the reconnect path; the answer to
its own probe stays out of the log. Reconnection is not a fixed
two-second loop: rejected credentials, a rejected server password, and a ban
are never retried (the client stops with a final status, as the bouncer's
driver parks), and any other failure backs off exponentially from
`--reconnect-delay` to five minutes. A refused channel is dropped from the
session with a status line instead of failing the whole connect. The client
adopts the nickname the server confirmed — a BNC's welcome carries the real
upstream nick, which may differ from `--nick` — and follows its own NICK
changes, so direct messages and its own JOIN/PART are recognised. Every error
numeric, FAIL/WARN/NOTE, ERROR, and KICK is rendered: a message refused by a
moderated channel is said in the buffer it was sent from instead of standing
there as a delivered-looking local echo. The slash-command grammar is
closed: malformed
or unknown commands remain in the composer with an explanation instead of
silently doing nothing or leaking into a conversation. On initial
connect and reconnect it requires the history/read-marker capabilities it
uses, rejoins every channel confirmed for the client, pages `CHATHISTORY AFTER`
the server's marker forward (by msgid, else time) until a short page — at most
ten pages and never more than the scrollback — or loads the latest bounded
window, and coalesces shared read-marker writes as buffer focus advances. A
channel with unread lines beyond what was loaded says "more unread lines were
not loaded", and its read marker is held at the last contiguously loaded line
until a later session loads every unread line: loading the oldest page and
then marking "now" as read used to mark the unloaded middle read on every
device. Other numerics and unmodelled commands are shown beside the
conversation they name or in a `*server*` buffer that refuses message text;
INVITE, TOPIC and MODE are rendered; `/me` renders as `* nick …` and mIRC
formatting is stripped; long lines wrap by display width; a resize redraws at
once. A multi-line bracketed paste is refused whole rather than sent line by
line. Quitting sends the queued lines and the last read marker, then `QUIT`,
within five seconds, and says so if it could not. A read marker is never
flushed while disconnected, so one that meets a disconnect is sent after
reconnecting rather than reported as a lost message. Startup failures print
`e6irc-tui: <message>` and exit 1. While the current
buffer is in scrollback, new messages increase its unread count and cannot
advance its marker; returning to the live edge clears that count and queues the
latest marker. Unread counts are visible and history/live overlap is
deduplicated by stable message ID.
The composer and socket-writer queue are both bounded. A message is locally
echoed only after bounded-queue admission; a full queue, disconnected socket,
or over-limit complete IRC line leaves the input available and reports the
refusal. A read-marker update that meets a full writer queue remains pending
instead of being lost.
Capability refusal fails visibly rather than degrading into a different
experience. A pseudo-terminal journey drives the real full-screen binary
against e6ircd and proves inbound rendering, outbound delivery, clean exit,
and terminal restoration. “Multi-buffer” means several channels/queries inside
one connection, not several simultaneous networks; the BNC is the
cross-network multiplexer.

### 14.3 A client's input is untrusted too

`TerminalSafe` also neutralises the invisible Unicode format characters
(U+061C, U+200B–200F, U+202A–202E, U+2060–2069, U+FEFF), so a nick
`alice\u{200B}` cannot pass for `alice` and bidi overrides cannot reorder a
line; human-readable output strips IRC formatting first
(`TerminalSafe::from_irc_text`).

Every clause of §7.2's bounded-buffer rule applies here in reverse. A client's
state — buffers, scrollback, the queue between the socket and the renderer — is
derived from lines a *remote server* chose, and a general IRCv3 client connects
to servers this project does not run. So the same rule holds: scrollback and
buffer count are capped, the socket→render queue is bounded (a full queue stops
the reader and lets TCP push back, exactly as SendQ does outbound), and the
`e6irc api` response read is bounded with an error rather than a truncation.
Hitting a cap is reported to the user, once — a silent cap reads as the network
going quiet, which is the client-side form of a silent no-op (§2). The shared
client's steady-state read therefore returns typed message/relay/rejected-line
events: malformed or over-limit remote input can keep the connection alive,
but the CLI, TUI, and BNC must surface the rejection.

---

## 15. Security

- Passwords/app passwords: argon2id via a single `hasher()` choke point
  (argon2 0.5.3 defaults — v19, m≈19 MiB, t=2, p=1 — meeting the OWASP
  minimum), constant-time verification; app passwords are 32 random bytes,
  base64-shown once. Every Argon2 computation takes one of four process-wide
  permits. A login attempt costs exactly two computations, whatever the
  account holds and whether or not it exists: the primary password, plus the
  one app password the presented secret names by its SHA-256 lookup
  (`account_credentials.secret_lookup`, migration 0059) — each replaced by a
  dummy when absent. Trying every stored hash made one guess cost up to 33
  computations under one permit and let the duration count an account's
  credentials. A CHECK constraint makes the lookup present on exactly the app
  passwords, so none can exist that would have to be tried blind; the ones
  minted before 0059, whose secrets were never stored, were revoked by it with
  an audit record each. A password change verifies and hashes before opening
  any transaction and commits with a compare-and-swap on the verified hash, so
  no Argon2 computation runs while a row lock is held; account- and
  channel-row locks taken only to serialize a cap are `FOR NO KEY UPDATE`.
- Audit rows are written inside the mutation's own transaction for network
  create/update/toggle/delete, ChanServ DROP/SET FOUNDER/FLAGS/KEEPTOPIC/MLOCK
  and server bans; an upstream account command is recorded before it is sent,
  and a 503 answers when it cannot be. OPER, KILL and SETHOST are recorded under
  the operator name and refused with a NOTICE when the audit row cannot be
  queued; an HTTP disconnect whose audit cannot be written is a 503. A
  suspension's disconnect is not refusable, because `ACCOUNT_SUSPEND` has
  already committed.
- Administrator authority is read from the account row on every request
  (`is_effective_admin`: the durable flag or a configured grant); no process
  holds a registry, so `e6ircd recover-administrator` and any out-of-process
  grant take effect on the next request. Recovery revokes every credential the
  account held (local and app passwords, personal access tokens, device
  grants, browser sessions) exactly as suspension does, through one shared
  revocation. A primary password change or addition ends every other browser
  session in the same transaction; app passwords and personal access tokens
  are separately managed and left unchanged, and the response says so.
  Console pages authenticate by browser session only: a bearer — whatever its
  scopes — gets 401, and suspension or an unavailable database surface as
  their problem documents, not a login redirect.
- Every personal access token is minted by one capped path
  (`mint_api_token_under_cap`, 32 per account, checked under the account-row
  lock), the device grant included. Approval at the cap is refused in the
  approving browser and the grant stays pending; a grant that loses its slot
  between approval and poll — or whose account was suspended or deleted — is
  consumed, audited, and answered with RFC 8628 `access_denied` once.
- Upstreams inside the server's own network are refused by default (§10.3,
  `egress`): a BNC network is an outbound connection an account holder aims,
  and internal infrastructure is not a target it may aim at.
- Upstream BNC secrets (SASL passwords, bridge tokens) sealable at rest
  under a **server master keyring** provided via `[secrets].key_file` plus
  optional `previous_key_files`, or the `E6IRC_SECRET_KEY` plus optional
  comma-separated `E6IRC_PREVIOUS_SECRET_KEYS` environment variables (each
  key is 32 bytes, base64). Sealed values are written as
  `enc:v2:<base64(nonce‖ciphertext‖tag)>`, with authenticated context binding;
  legacy context-free `enc:v1:` remains read-only compatible. A sealed value
  with no/wrong key is a hard startup error, and plaintext bootstrap values
  pass through until the managed control plane imports them sealed.
  The authenticated encryption with associated data (AEAD) cipher is
  **ChaCha20-Poly1305** via the in-tree aws-lc-rs (already pulled
  by rustls) — chosen over XChaCha20-Poly1305 to avoid a new crypto
  dependency; the fresh-random 96-bit nonce per value makes reuse
  negligible at config-secret volumes. `e6ircd genkey` mints a key and
  `e6ircd seal` encrypts stdin. Rotation first installs a new primary while
  retaining the old key as a read-only fallback; `e6ircd rotate-secrets`
  locks and re-seals managed configuration plus every account-network secret
  in one PostgreSQL transaction, with a redacted audit record. The old key is
  removed only after that command commits. A corrupt, plaintext, or unreadable
  value rolls the entire operation back.
- TLS ≥ 1.2 everywhere (rustls). Server certificates are reloaded on SIGHUP
  and when their files change; a failed reload keeps the served certificate
  and logs an error once per broken file state, and a key that does not match
  its certificate is refused. Responses carry HSTS (`max-age=31536000`)
  whenever the validated public origin is HTTPS (never on an explicitly plain
  development origin); `includeSubDomains` only with
  `[http].hsts_include_subdomains`, which forces every sibling host of the
  domain onto HTTPS for a year; never `preload`. `/ws/ui` upgrades check
  Origin; `/ws/irc` does not — IRCv3 WebSocket permits cross-origin clients and
  the endpoint carries no cookie authority (it authenticates in-band with
  SASL).
- Every response carries `nosniff`, a deny-all `Permissions-Policy`,
  `Cross-Origin-Resource-Policy: same-origin` and a default
  `Cache-Control: no-store`; pages add `Cross-Origin-Opener-Policy:
  same-origin`; JSON, problem documents and `/api/` responses add
  `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`. Each is
  added by one baseline layer only where the handler set none. The one
  frameable answer is OpenID Connect front-channel logout, which the provider
  loads in an iframe: it sets `frame-ancestors` to that issuer's origin alone
  (`tools/test-shauth-sso.mjs` proves the provider's iframes reach it). The console's
  CSP admits no inline style (`style-src 'self'`, stylesheet at
  `/console.css`).
- A client address is canonicalised once (`ClientIp`): IPv4-mapped IPv6
  becomes IPv4 for limiter keys, ban hosts, trusted-proxy matching and each
  forwarded entry, so a D-line on an IPv4 address matches a `/ws/irc` user on a
  dual-stack listener and a proxy in a trusted IPv4 range is trusted.
- The master key is zeroized when dropped, and key text read from files or
  the environment is wiped; the process is non-dumpable on Linux
  (`PR_SET_DUMPABLE`) and the systemd unit sets `LimitCORE=0`, so an abort
  cannot write keys or passwords to a core file.
- Not provided, stated rather than implied: TLS client certificates, ALPN and
  multiple certificates by SNI on IRC listeners (one certificate per
  listener); OCSP or CRL checks on outbound TLS, whose roots are the
  compiled-in webpki set; hiding the server version (`/api/v1/server` exposes
  it, as IRC `VERSION` does). Concurrent password verification is bounded
  process-wide by the Argon2 permits, which is what bounds a distributed login
  flood's CPU cost; the per-address auth buckets bound a single source.
- Rate limits: per-IP connection/registration throttle, per-session command
  token bucket, per-account API limits (tower middleware), SASL attempt
  limits with backoff.
- IRC network protections: kline/dline/xline equivalents managed by opers
  and via admin API, all audit-logged.
- Every HTTP response receives a fresh server-generated 128-bit correlation
  identifier. No client-supplied identifier is trusted as provenance.
- No secrets in logs; `tracing` field redaction for credentials.
- CSRF per §9.2; cookies HttpOnly/Secure; session fixation avoided by
  rotating session id at login.
- One-time first-administrator bootstrap uses a separate Strict browser-state
  cookie, the shared authentication rate limit, a 32–512-byte deployment
  secret, constant-time digest comparison, and an atomic empty-store check.
  Account suspension revokes bearer material transactionally and is enforced
  again by the ordered core so in-flight verification cannot race the action.

---

## 16. Observability

Operational events remain loud WARN-level stderr lines; fixed-cardinality
telemetry records the machine-readable side of the same failures without
putting untrusted values or secrets in labels. One process-wide snapshot
contains connection state and lifecycle totals, IRC and BNC line/byte traffic,
HTTP and database operation totals, SendQ kills, fixed error categories, BNC
driver up/down state, authenticated raw-IRC and web attachment gauges,
core/database queue depth, capacity, FIFO/LIFO mode and mode-switch totals, and
cumulative core/database/HTTP latency histograms. The attachment guard belongs
to the resolved network handle, so both client transports enter and leave the
same counter only after authentication; accepted but unauthenticated sockets
cannot inflate it. This semantic correction is snapshot schema version 2; the
console does not plot version-1 raw-socket gauges as authenticated attachment
history, while unaffected version-1 counters remain usable.
Queue pressure is snapshot schema version 3. Schema-v2 samples deserialize
with an empty queue map, so an upgrade preserves the rest of their history.
Schema version 4 adds `database_pool` (size, idle, max, acquire timeouts); the
same values are exported as `e6irc_database_pool_connections{state}`,
`e6irc_database_pool_max_connections` and
`e6irc_database_pool_acquire_timeouts_total`, the last counted wherever a
query error is mapped.
Only the statically registered `core` and `db` queues become Prometheus labels;
per-connection SendQs remain aggregated through bounded kill/error counters.
Each running BNC handle additionally keeps owner-scoped per-network counters
and lifecycle timing. Those values are deliberately not process-wide metric
labels: account and network names are unbounded label cardinality. They are
served only through the authenticated network API and console operations page.
A separate bounded server event feed records only fixed error component and
severity values with a fixed safe message. It cannot contain request data, IRC
traffic, external error text, or secrets.

The snapshot is the sole source for:

- `/console/monitoring`, an administrator-only server-rendered view refreshed
  every ten seconds by `/console.js`, with selectable 1-hour, 6-hour, 24-hour,
  and 7-day windows across IRC/BNC traffic, live IRC/BNC connections, upstream
  availability, core/database queue pressure, new errors, and P95
  core/database/HTTP latency; current queue/percentile tables and the error
  ledger remain alongside the trends, and
  refresh failures remain visibly actionable;
- `/api/v1/admin/observability`, authenticated JSON with the current snapshot
  and at most 1,000 bounded historical points over an explicit 1-minute to
  7-day range; invalid ranges fail with HTTP 400 rather than being clamped;
- `/api/v1/admin/metrics`, authenticated Prometheus text exposition with only
  fixed `state`/`kind`/`queue`/`mode` labels;
- `/api/v1/monitoring/observation`, a read-only `e6qu.monitoring/v2`
  application observation protected by a deployment-owned
  `E6IRC_MONITORING_TOKEN`. The process retains only its SHA-256 digest, checks
  the bearer in constant time, and publishes the same real fixed-cardinality
  IRC, BNC, queue, error, and uptime counters. It omits `cost_estimate` because
  the application is not itself a priced resource; inventing one would violate
  provenance;
- `/console/logs` and `/api/v1/admin/logs`, administrator-only live views of
  at most 1,000 redacted server events; the durable audit log remains the
  source for privileged actions; and
- `/readyz`, which fails when the heartbeat of *any* core shard is stale
  (`core_heartbeat_age_ms` is the stalest shard's age, so a silent shard is not
  masked by a healthy one) or
  configured PostgreSQL cannot answer `SELECT 1` within a separate two-second
  query deadline.

The production image carries no HTTP client, so a container `HEALTHCHECK`
cannot be a `curl`. `e6ircd healthcheck [--ready]
[--addr ip:port]` is the daemon probing itself — `/healthz`, or `/readyz` with
`--ready` — at `--addr`, else the `E6IRC_HTTP_ADDR` the server binds, else
that variable's default (`environment_config::DEFAULT_HTTP_ADDR`); an unspecified listener address is probed on loopback of the
same family. It exits 0 only on a `200` within three seconds, 1 with the reason
otherwise, and 2 on a usage error, and the image's `HEALTHCHECK` is that
command.

When PostgreSQL is configured, a sampler stores the typed JSON snapshot in
`observability_samples`. The UI-managed `[observability]` interval (5–300
seconds), enable switch, and retention (1–2160 hours) apply live. Expired
samples are pruned by the storage-maintenance worker under
`observability.retention_hours` whether or not sampling is on (pruning on
insert left the table frozen the moment sampling was switched off). That
worker runs every five minutes in bounded batches; a tick whose batch fills
runs up to 21 batches 250 ms apart and logs once with totals, so a large
backlog — or a retention cut from a year to a month — drains instead of
saturating forever. It also reports its database latency and failures through
this telemetry even when historical sampling is disabled. `/healthz` remains a
dependency-free liveness probe. HTTP observation (`x-request-id`, HSTS,
request count and latency) is the outermost layer, outside the body limit,
the concurrency semaphore and the request deadline, so a `408` or a permit
wait is counted and timed like any other request. Per-peer connection
refusals (per-IP limit, connection-id exhaustion, socket setup, TLS handshake
failure or timeout) are summarised by `PeerRefusalLog`: the first occurrence
at once, then one line per 60 s window carrying the suppressed count, bounded
to 4,096 (peer, class) entries; the counters are unaffected.

Logging continues to use loud stderr lines; metrics do not depend on a
third-party metrics stack.

---

## 17. Testing strategy

**Methodology.** Development is **TDD**: tests are written first (red),
implementation follows (green), then refactor; no feature lands without
tests at the appropriate level. The **testing pyramid** shapes the suite —
many fast unit/property tests, fewer integration tests, a small set of
acceptance/UI/e2e tests at the top. User-visible behavior and its evidence are
cataloged in `docs/journeys/`. Acceptance is currently expressed as direct
Rust integration tests and targeted browser/shell scripts; there is no shared
Given/When/Then scenario DSL.

Layers, bottom to top:

1. **Unit/property**: proto crate (parser round-trips, casemapping,
   CAP/SASL state machines), multiplexer buffer logic; **loom
   model-checking** of `e6irc-queue`'s concurrency core.
2. **Fuzzing**: CI smoke runs every declared cargo-fuzz target, including
   parser/tag input, serialization, single- and multi-client stateful core
   command streams, and arbitrary server output into the TUI model.
   `e6irc-queue::Receiver::try_pop` supplies a manual-step primitive; fixed
   multi-queue schedules record and replay their shard/sequence steps. A seeded
   whole-core multi-worker simulation remains part of the N>1 evidence.
   A separate all-feature coverage job combines the portable workspace suite
   with the real PostgreSQL database and HTTP lifecycle suites, then rejects
   line coverage below 80%; the floor is a regression ratchet. Provider/browser
   jobs supply their environment-dependent acceptance evidence outside that
   percentage.
3. **irctest** (progval/irctest) run in CI against `e6ircd` — the same
   suite Solanum/Ergo use.
4. **Compatibility** (§7.7): the vendored Libera-snapshot ISUPPORT
   differential (offline, in CI); opt-in light-touch live interop tests
   against Libera/OFTC/Ergo; and an optional pinned-Solanum differential
   oracle under `vendor/tests/external-oracles/` (developer tool, not CI). A
   second opt-in probe drives the actual BNC path through DNS vetting,
   pinned-address TLS, registration, and lifecycle reporting against Libera.
5. **Integration**: BNC `irc` driver against an e6ircd upstream
   (reconnect, SASL, playback); OIDC flows against dockerized Dex; the Matrix
   bridge against pinned Conduit. The PostgreSQL job explicitly runs the
   ignored database, HTTP, OIDC, BNC, `/ws/ui`, and CLI suites with their
   required environment. The URL supplied to Rust suites is administrative:
   each test owns an empty database, including the CLI journey that follows the
   browser's intentional persisted configuration, so suite order cannot leak
   accounts or sealed secrets into another server bootstrap. A separate
   actual-daemon journey owns an isolated empty PostgreSQL container so it can
   prove first-boot migrations/import and stop/start recovery under simultaneous
   readiness, database-backed HTTP, and hot IRC traffic.
6. **Journey acceptance**: the scenarios in `docs/journeys/` map outcomes to
   direct real-server integration tests. The matrix identifies partial
   journeys where adjacent layers are proven separately.
7. **e2e (API & network)**: REST `/api/v1` exercised over HTTP against a
   running `e6ircd` + Postgres (docker-composed in CI); IRC flows exercised
   over real sockets, including TLS.
8. **Released settings rows**: `tests/fixtures/server_settings/` holds the
   managed configuration each release stored, captured by that release's own
   code and named `<its last migration>-<release>.json`; a PostgreSQL test
   loads every one through today's migrations. A change to the stored shape
   adds the previous release's fixture. The deploy of `c51261725b5d`
   crash-looped on a `null` that no fresh-row test could hold (migration 0067).
9. **UI tests**: Playwright drives real OIDC and local-password authentication
   through Chromium, Firefox, and WebKit; exact Shauth qualification uses
   Chromium. Firefox runs with `browser.tabs.remote.useCrossOriginOpenerPolicy`
   off: pages send `Cross-Origin-Opener-Policy: same-origin`, and the context
   swap it causes makes Playwright's Firefox driver lose a page's events
   (microsoft/playwright#42731), so a reload hung about one run in five. Focused replay/race/membership cases use
   browser-side network/history/WebSocket doubles. A separate full-stack case
   edits every managed-configuration subsection and credential collection,
   proves persisted themes and the desktop-notification boundary, creates a
   network through the console, crosses real PostgreSQL, registry, IRC-driver,
   local TCP-upstream, and `/ws/ui` paths in both directions, inspects
   operations data, visits every administrator directory, mutates and audits a
   server ban, verifies queue monitoring in HTML and JSON, then gracefully
   restarts the daemon and proves session/network/backlog recovery.
10. **Load**: `e6irc-load` and `tools/load/sweep.sh` measure connection rate,
   duplicate-proof exact fan-out sequence delivery, and latency percentiles;
   any client, socket, malformed sequence, missing/duplicate delivery, or
   supplied-threshold failure is a nonzero process exit. CI exercises 64
   clients across eight channels against a real daemon with generous
   catastrophic-regression floors (10 connects/s, 100 deliveries/s, P99 below
   five seconds). The Linux smoke also samples the daemon's pre-run and peak
   resident set and rejects incremental growth above 1 MiB per requested
   connection; controlled hosts can supply a stricter bytes/connection
   ceiling. Recorded manual baselines reach 2,000 clients; production
   performance thresholds and the 100k run are not qualified.

---

## 18. Configuration & operations

- Startup retries the first PostgreSQL connection for
  `[database] startup_wait_seconds` (default 300; 1 s doubling to 30 s; one
  stderr line per attempt; connection errors only — a migration error is
  immediate) and then exits non-zero, so a host whose database comes up later
  than the daemon is a loud wait rather than a crash loop; the first probe is
  one plain connection, so the reason (refused, authentication, "starting up")
  is reported instead of the pool's "timed out".
- `[database] max_connections` / `E6IRC_DATABASE_MAX_CONNECTIONS` sizes the
  shared pool (2–200; default 1 serial worker + 4 Argon2 permits + 2 × CPU
  threads) and is logged at startup. Database settings are bootstrap-only; the
  console does not edit them.
- A minimal `e6irc.toml`/environment bootstrap supplies the PostgreSQL URL,
  secrets-key source, HTTP bind, immutable release revision, and either
  existing administrator authority or a one-time first-administrator token.
  Unknown keys are a **startup error**. The token is accepted only with
  PostgreSQL and HTTP configured, is 32–512 control-free bytes, and is
  permanently unusable after the first account exists.
- Operational configuration is a typed, revisioned PostgreSQL snapshot managed
  at `/console/configuration`. On first start after migration, validated
  bootstrap values are imported once with provenance. Later starts load the
  persisted revision before constructing the core or listeners, so the UI is
  authoritative. Writes use compare-and-swap revisions and a same-transaction
  redacted audit entry; stale writers fail visibly. The write takes the scalar
  settings only: the collections that hold secrets (OIDC providers, operators,
  server-level networks) are kept from the current revision and changed through
  their own endpoints. They may nevertheless be *sent back exactly as read* --
  the read redacts every secret, and the write compares against that same
  redaction -- so reading the resource, changing one field and sending it back
  works, which is the only shape a script has. Sending a collection that
  differs is refused by name, with the endpoint that does change it; it is
  never quietly dropped.
- `[secrets].key_file` and `E6IRC_SECRET_KEY` are alternatives; a configuration
  stating both is refused naming both sources, never resolved by precedence.
  Rules about a secret's *content* (bootstrap token length, a non-empty OIDC
  client secret and oper password) run in `validate_secrets()` after sealed
  values are opened, so they judge the secret, never its `enc:v2:` ciphertext.
  Every `http.admin_accounts` entry must be a valid account name (an IRC
  nickname of at most 64 bytes; `"alice, bob"` is refused naming `" bob"`), and
  `secure_cookies` and the `public_url` scheme must agree in both directions.
- `internal_upstreams` (`refuse` by default, `allow`) is the server's policy on
  bouncer upstreams inside its own network (§10.3). It is bootstrap
  configuration, not a console setting, and the environment-stated
  configuration has no variable for it.
- A configuration that parses but cannot work is refused at load and at every
  console save. Two listening sockets that cannot both bind — the same nonzero
  port on the same address, or on a wildcard of the same family — are refused
  naming both sections (`[[listeners]] #n`, `[http]`, `[bnc]`). Every listener
  binds `[::]` dual-stack on every platform (Linux defaults a v6 socket to
  dual-stack, Windows and several BSDs to v6-only), so `[::]` also collides
  with any IPv4 address on its port. Sizes have upper bounds as well as lower ones: `core_workers`
  ≤ 64, `core_queue` ≤ 1,048,576, `sendq` ≤ 65,536, `max_hot_channels` ≤
  1,048,576, a network's `buffer_cap` ≤ 100,000. `usize::MAX` workers used to
  validate.
- The BNC registry exists whenever PostgreSQL does, independently of the raw
  attach listener. Its listener is runtime-managed: enabling or rebinding first
  binds the replacement socket, swaps only after success, and retains the
  working listener on failure. Disabling the attach socket does not stop
  always-on networks or the web client.
- Graceful shutdown is four bounded steps in this order: the listeners stop
  accepting; every bouncer driver is stopped concurrently and says goodbye to
  its upstream (`QUIT`, or the Matrix logout; at most 15 s for all of them, a
  laggard is logged and the stop stands), so a restart never meets its own
  ghost; the core drains; the bounded PostgreSQL write paths flush. Stopping the
  core is a drain: a shard that has seen the shutdown stops taking outside
  input but keeps serving the other shards until every shard has seen it and
  nothing is passing between them. Every shard is then joined; a shard that
  panicked or will not stop is ended and reported *after* the database flush,
  never instead of it. A client's closing `ERROR` is the last line it is
  sent: the output handle of a session that has been told goodbye discards
  everything after it, including deliveries that arrive from other shards
  while they drain. Durable
  network/history state is continuously persisted; there is no separate
  driver-checkpoint format.
- Main owns and supervises the core and PostgreSQL worker join handles while
  serving; listener join handles have explicit supervisors. Any unexpected
  completion or panic names the failed task, initiates the same bounded drain,
  and makes the process exit non-zero. HTTP-to-core control requests have a
  five-second reply deadline, so even a live but wedged core cannot hold an
  API request forever.
- BNC listener and observability-sampling changes apply live. Core
  identity/limits, IRC listeners, OIDC,
  operator, and access-policy changes are stored immediately and explicitly
  reported as restart-required; no response claims those values were applied
  to the running core.
- CI builds and tests source on Linux, macOS, and Windows for amd64 and arm64.
  Each `main` commit whose CI run succeeded publishes a **multi-architecture container image**
  (linux/amd64 and linux/arm64) whose runtime base is the distroless
  `gcr.io/distroless/cc-debian12` — glibc, libgcc and CA certificates, with no
  shell, package manager or script — pinned by digest like every other base. Each architecture digest has signed build-provenance
  and SPDX software-bill-of-materials attestations — the binary is built with
  `cargo auditable`, so the SBOM names its Rust crates and CI requires
  `rustls` in it; generating it downloads syft, so one failed attempt is
  retried once and the requirement still fails a job with no SBOM — and every
  shipped build passes `--locked`
  (`tools/check-locked-builds.sh`); native releases build with the image's
  pinned Rust (`tools/check-release-toolchain.sh`) and no restored cache. The
  assembled manifest has signed provenance,
  and the release workflow verifies them after publication. A hardened,
  CI-validated systemd unit is shipped for native Linux installation.
  The container daemon is built with every bridge plus the embedded web
  client. Its command is `e6ircd --config-from-environment`: the bootstrap
  configuration is built from the environment by the daemon itself
  (`environment_config`), in memory, and goes through exactly the parser and
  validation a file does, so the two ingresses cannot disagree and no
  secrets-bearing file exists. A shell entrypoint used to render a TOML file,
  which kept a shell in the image and made TOML quoting a bug class of its
  own. Every refusal names the variable and never a value; a variable that
  entrypoint honoured and nothing reads any more (`E6IRC_CONFIG_PATH`,
  `E6IRC_BINARY`) is refused rather than ignored. Every subcommand that needs
  the configuration (`check-config`, `rotate-secrets`,
  `recover-administrator`) takes the same flag, so it runs by `docker exec` in
  a container that has no file to point at.
  The systemd stop budget mechanically exceeds the daemon's bounded shutdown
  — the core drain followed by the PostgreSQL flush; the guard sums both
  constants. The unit sets `StartLimitIntervalSec=0` (asserted by the same
  guard): a refused first database connection fails the daemon in
  milliseconds, and systemd's default limit of five starts in ten seconds
  would otherwise leave the unit permanently failed after a reboot where
  PostgreSQL comes up later than e6irc; restarts stay `RestartSec` apart and
  each attempt is a journal line, loud rather than final.
  A version tag equal to `v` plus the workspace version publishes deterministic
  archives containing `e6ircd`, `e6irc`, and `e6irc-tui` for Linux, macOS, and
  Windows on x86-64 and ARM64. Each archive has a GitHub build-provenance
  attestation and the release includes sorted SHA-256 checksums. The packager's
  exact members, modes, and reproducibility run in ordinary CI so tag-only
  code cannot rot. Musl artifacts and a `scratch` image are not shipped: a
  static musl build costs a threaded server more in its allocator than the
  few megabytes of glibc it would save over distroless.
- The production container built and embedded the Vite client before the Rust
  release build; no build step ran at startup. Each `main` commit whose CI succeeded published
  one immutable 12-character commit-SHA manifest plus direct `-amd64` and
  `-arm64` image manifests to GitHub Container Registry. Mutable `latest` and
  branch tags were not published, the manifest shape was verified after push,
  and only the newest 20 release groups were retained.
  Untagged Open Container Initiative (OCI) attestation referrers are retained and pruned by the same
  oldest-kept-release boundary rather than accumulating outside those groups.

---

## 19. Scope boundaries

- Bridges are account-owned or explicitly shared attached networks, not
  synthetic-user relay bots in public local channels (§10.5).
- IRCv3 capabilities whose standardized wire names include `draft/` retain
  those names. Their implemented behavior is pinned and exercised through the
  repository's irctest revision (§17).
- Process diagnostics are human-readable stderr lines. Structured operational
  consumers use the typed JSON and Prometheus telemetry contract (§16).

## 20. References

- Modern IRC: https://modern.ircdocs.horse · RFC 1459 · RFC 2812
- IRCv3 specs: https://ircv3.net/irc/
- Solanum ircd: https://github.com/solanum-ircd/solanum · Atheme:
  https://github.com/atheme/atheme
- Libera.Chat guides (modes, services): https://libera.chat/guides/
- irctest: https://github.com/progval/irctest
- soju (BNC prior art): https://soju.im · ZNC: https://znc.in
- SASL OAUTHBEARER: RFC 7628 · OAuth device grant: RFC 8628
- Terminology glossary: [`docs/terminology.md`](docs/terminology.md)
