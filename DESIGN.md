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
  - `CredentialAttemptBudget` — IRC registration, services, and BNC attach
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
    sentinel connection can accidentally stand in for an admin request.
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
  - `HistoryTargets` — a database history read is either one exact target or an
    offline direct-message choice with a primary and fallback. The fallback
    cannot accidentally be applied to channels or online peers, and the two
    candidate keys cannot be passed as unrelated request fields.
  - `Hidden` — a `+s` (secret) channel is invisible to non-members on *every*
    query surface. The predicate lives once in `Channel::hidden_from`, and the
    deny surfaces (MODE/KNOCK/TOPIC) take the returned `Hidden` token to the one
    `deny_hidden` helper, which answers `ERR_NOSUCHCHANNEL`. No surface can
    hand-pick a different numeric (a `TOPIC` query once returned 442, confirming
    the channel exists — an existence oracle); the token has no other consumer.
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
    (in `e6irc-cli` and `e6irc-tui`) can only take this form, and its sole
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
│   └── e6irc-tui/            # ratatui TUI client binary
├── web/                      # Vite project (vanilla JavaScript chat client)
├── migrations/               # sqlx migrations (embedded in binary)
├── tools/                    # dev/CI scripts (compat harness, load generator)
├── DESIGN.md · PLAN.md · BUGS.md
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
- RecvQ/flood control: token-bucket per connection (configurable burst/rate),
  plus per-IP connection throttle and registration throttle.
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
draining capped below platform scatter/gather limits, release LTO, CoW
recipient snapshots, dense generation-safe session IDs, batched accepts, a
timer-wheel reaper, reusable outbound write batches, and reproducible load
tracking. Arc-swapped configuration and Criterion microbenchmarks are not yet
present. Any nontrivial optimization lands with evidence that proves it:

- **Zero-copy end-to-end**: parsing borrows from the receive buffer
  (§7.1); a routed message is serialized once per capability variant and
  shared as `Bytes` — delivery to N recipients is N refcount bumps, zero
  memcpy; SendQs drain via vectored writes (`writev`), never
  concatenation.
- **Copy-on-write where sharing beats copying**: tag values unescape to
  `Cow` (allocate only when an escape exists); channel recipient
  snapshots are Arc'd CoW lists so fan-out iterates outside any lock;
  reloadable config is an Arc-swapped snapshot (RCU pattern) — readers
  never lock.
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
- **Measured, always**: microbenchmarks live beside hot modules; `tools/load`
  macrobenchmarks track connect rate, exact fan-out sequence membership, and
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
TAGMSG may not join one at all. If the opening BATCH was labeled, the failure
carries that label: the batch was the response owed to that command, so without
it a client tracking labels would wait forever.

Recipients that negotiated the capability receive the batch as sent, blank lines
and `draft/multiline-concat` tags intact, because those are what the sender
wrote. Everyone else receives one message per non-blank line: a PRIVMSG has no
way to carry a line break, and a blank line would be an empty message. The
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
this project makes or tests. The shared application pool has a two-second
acquisition deadline, a 15-second PostgreSQL statement deadline, and a
five-second lock-acquisition deadline on every pooled connection. Dependency
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
  btree + BRIN on `ts`. The live storage policy retains 1–3650 days
  (30 by default) and removes expired rows in bounded 10,000-row batches.
  Native monthly range partitions remain the target representation at the
  scale qualification boundary; retention semantics do not depend on that
  representation. Server-time and account-tag are reconstructed from `ts`
  and `sender_account`, so no separate tags column is stored.
- `bnc_networks` (account_id, name, addr, tls, nick, realname, autojoin,
  sasl_account, `sasl_password_sealed` — **sealed** (`enc:v1:`) with the
  server master key (§15), enabled)
- `bnc_buffer` (id, owner, network, line, created_at, target, msgid,
  sent_at) — persisted
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
  `BNC_TRIM_INTERVAL`. The count belongs to that task, not to the table's `id`
  sequence — one sequence is shared by every network, so triggering off it
  makes retention depend on the interleaving between them
- `bnc_read_markers` (BIGINT account_id, network, target, timestamp) —
  per-account, per-BNC-network read position, the source for
  `draft/read-marker` on the attach listener. Distinct from `read_markers`
  below, which tracks the core's local-server targets. Writes lock the durable
  account row in their transaction, increase monotonically, and admit at most
  256 targets per account even under concurrent inserts. The committed value
  is acknowledged and fanned out only to other read-marker-capable attachments
  of the same account. Deleting a BNC network deletes its markers, so
  recreating the same name cannot inherit stale read state.
- `read_markers` (account_id, target, marker_ts) — per-account read
  position, the source for `draft/read-marker`. Updates are monotonic
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
UI-managed `[storage]` policy independently of monitoring. Each transaction
removes at most 10,000 expired message-history rows, audit events, browser
sessions, personal access tokens, device grants, and consumed OpenID Connect
logout tokens, plus expired/revoked/consumed account invitations, from each
collection. Time-order indexes and the global
acquisition/statement/lock deadlines bound both the selection and the
transaction. Filling any batch is logged with per-collection provenance and
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
  per-name advisory lock, enforces a per-administrator pending cap, and stores
  only the SHA-256 digest of a 256-bit bearer. The administrator directory is
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
folded authentication deny key in the ordered core. The final transaction
rechecks every invariant, reserves the name permanently, purges pending/
consumed invitation contact data, device grants, owned BNC buffer, sent and
direct-message history, and then deletes the account so credentials, sessions,
identity links, networks, markers, and access rows cascade. The redacted audit
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
process resources.
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
manager with add/remove/enable-disable, and **edit** of an IRC
network's connection/identity fields (addr, tls, nick, realname, autojoin) and
write-only SASL credentials (keep the encrypted password while changing its
account, replace it, or remove both halves). The password is never rendered
back to the browser. A bridge is configured on the Integrations page, so the
IRC edit form refuses non-IRC kinds. The manager is available to any
authenticated user for their own networks. The create form defaults to a
Libera Chat preset and offers a small, provenance-dated catalog of published
TLS endpoints (Libera, OFTC, EFnet, Snoonet) plus Custom. A preset's human label
is never its client/URL identifier: `Libera Chat` maps to the safe stable id
`libera`. Presets are applied server-side so they work without JavaScript;
the script only mirrors their fields for editing. A preset is endpoint
provenance, not a compatibility claim for the deployment's current egress.
The console disables creation until the exact endpoint, TLS choice, identity,
channels, and optional credentials have passed the production preflight; any
change to those fields invalidates the qualification. Invalid submissions re-render
the page with the precise shared validation problem and preserve non-secret
input, including the resolved preset values. IRC addresses must be a syntactic
`host:port` with a nonzero numeric port (and bracketed IPv6); configuration,
REST, and console creation share that invariant so an invalid endpoint cannot
be persisted into an endless reconnect loop. If no master key is configured,
credential inputs are visibly
unavailable rather than accepting a password the server must refuse to store.

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
pause/resume, add/remove, and a platform-shaped edit form. The form replaces
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
  are mirrored to all attached clients. A sender's own messages are
  synthesized into the stream by the driver (the upstream is never asked
  for `echo-message`, so there is exactly one echo, never two); the
  originator receives its echo only when it negotiated `echo-message` on
  attach, the same contract a real server has. Synthesized echoes retain only
  validated client-only tags and mint their own `time` provenance; a downstream
  cannot forge or duplicate server `time`/`msgid` tags in persisted history.
- **Detached buffering**: events accumulate in a per-network ring persisted
  to PostgreSQL. The BNC attach listener also keeps per-account, per-target
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
  window), intercepted on attach and never forwarded upstream. One pure
  oldest-first resolver owns every boundary and direction. Bounded LATEST keeps
  the newest rows *after* its selector; reverse BETWEEN limits from its first
  endpoint; TARGETS uses the dedicated `draft/chathistory-targets` batch.
  Stored timestamps are validated and canonicalized before they become sort
  keys, and replay emits that same canonical `time=` value. `batch` is optional:
  a client that negotiated it receives the applicable batch envelope and tags;
  otherwise the same bounded page is emitted directly. `message-tags`,
  `server-time`, and `account-tag` independently gate their own replay metadata.
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
one implementation shared with the external-network path.

### 10.3 `irc` driver — external networks (ZNC/soju-style)

- Full IRCv3 *client* implementation reusing `e6irc-proto` + the same SASL
  machinery; requests `server-time`, `message-tags`, and `account-tag`
  from upstream when available (Libera: yes). It deliberately does not
  request `echo-message`: the driver synthesizes self-echoes itself
  (§10.1), and requesting it would produce every echo twice.
  Synthesized message echoes rebuild their prefixed traditional body within
  the 512-byte wire allowance, preserving valid client-only tags and cutting
  trailing UTF-8 only at a character boundary; malformed message commands do
  not manufacture an echo the upstream would never send. NickServ commands
  that can contain a password, email address, verification code, recovery
  token, or replacement credential synthesize only a redacted trailing field,
  while the exact command is still sent upstream.
- Auto-reconnect with exponential backoff + jitter, bounded so repeatedly
  rejected credentials or IRC registration settings stop re-dialing rather
  than hammering the upstream forever; authentication and registration
  rejection have distinct terminal lifecycle states. On reconnect the driver
  re-registers under the configured nick — a 433 without SASL earns one
  replacement-nick retry (`nick_`), since the common cause is a lingering
  ghost of our own previous session — and re-joins the *configured*
  autojoin channels plus every channel the upstream confirmed membership in
  before the drop (runtime JOIN/PART/KICK are tracked as they are
  acknowledged upstream; a forced upstream NICK renames the tracked
  identity). A process restart falls back to the configured autojoin, which
  is the operator-declared floor. Upstream SASL PLAIN uses credentials
  stored encrypted (§15).
  Once authentication or registration failure parks the driver, its command
  boundary returns terminal unavailability instead of accepting lines into a
  queue that has no consumer.
- Every registration, auto-join, command, heartbeat, and protocol PONG emission
  is part of the session outcome: a failed upstream transport write drops and
  reconnects, while a closed in-process core queue stops the `local` driver
  instead of retrying a permanently gone core. `Connected` is emitted only
  after registration and configured auto-joins have all reached their
  transport.
- The dialer vets every DNS answer at connect time, alternates IPv6 and IPv4
  results while preserving each family's resolver order, bounds each concrete
  TCP/TLS attempt, and tries the remaining vetted addresses. TLS still validates
  the certificate against the configured hostname rather than the pinned IP.
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
the validated nick component while no upstream session exists). Attach SASL
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
loopback test oracle; WebSockets use WSS under the same rule. OIDC metadata
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
- Reverse bridge delivery accepts `PRIVMSG` only. Unmapped targets, malformed
  messages, unsupported commands, and per-target provider failures each emit a
  bounded `*bnc*` refusal notice; queue admission can never become a silent
  bridge no-op.

---

## 11. History & CHATHISTORY

- **11.1 What is logged**: channel messages on the local server (per-channel
  opt-out honoring, e.g., `+P`-style policy decisions), direct messages, and all
  BNC network buffers. Every stored message has a stable `msgid` (also sent live
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
  never be claimed by an account of the same name. (Two successive
  *unauthenticated* holders of a nick do share an identity — there is nothing
  stronger to key on, and scoping to the connection would cut the other
  participant off from their own conversation the moment the peer left. The
  account boundary is the one that carries privilege.) When the correspondent
  is offline, the core cannot distinguish an account name from a formerly
  unauthenticated nick. The PostgreSQL read therefore prefers the account-form
  conversation when it exists and otherwise tries the `~nick` form; online
  peers and channels always resolve to one exact target.
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
  unauthenticated party are not reachable there.
- **11.3 Hot path**: per-target in-memory ring (last 500 events) answers
  the common "LATEST *" without Postgres; misses fall through to the
  `messages` table. Channels and conversations share one ring store, one LRU
  and one cap, so the overflow and eviction rules cannot drift apart between
  them. A msgid used as a paging pivot is resolved **within the target being
  paged**: a msgid belonging to some other buffer names a position that does not
  exist here, so it yields an empty result rather than silently positioning the
  query from a message the caller may never have been able to see.
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
  secret is never changed through an ambiguous omitted-field convention.
- `channels`: owner-scoped registered-channel inventory and management at
  `/me/channels` (live-operator registration, retained topic, KEEPTOPIC,
  canonical MLOCK, access flags, founder transfer, unregister)
- `history`: paged queries per §11.2
- `admin`: bounded, exact-filtered/stable-cursor account posture, registered
  channel policy, global K/D/X-line policy, and audit log; server stats;
  account suspension/reactivation; live/historical observability; Prometheus
  exposition. Personalized
  administrator JSON and metrics responses carry `Cache-Control: no-store`.
- `healthz` (liveness; no auth)
- `readyz` (core-heartbeat and configured-PostgreSQL readiness; no auth)

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
transient drop self-heals; opening the page without a `?network=` selector
shows a picker of the caller's networks (its entry point). The persistent
top-bar selector changes networks from every chat view, the preferences menu
owns validated theme/notification settings, and responsive conversation
navigation preserves the full chat pane on phones. The identity, console, and
chat surfaces share the relay-desk visual system: dark routing chrome, compact
monospaced provenance labels, high-contrast state colors, and one amber route
trace joining network context to the active conversation. The network catalog
links only enabled networks with a running driver; disabled or unbuilt entries
remain visible status rows and point recovery toward management instead of
offering a dead-end chat action. Identity, network-list,
history, storage, notification, and socket-protocol failures have visible,
actionable states; an API failure is never rendered as an empty account. The
member list is rank-ordered with sigils kept live from channel `MODE`, and the
client offers a join-channel input and click-to-query on nicks.

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
replay from overwriting current membership. The composer sends
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
The browser has an optional raw-output receiver tape that retains and renders
every exact safe inbound IRC wire line, including state-changing lines,
numerics, and NickServ replies. `/help` documents the available composer
grammar; `/query`, `/msg`, `/notice`, `/join`, `/part`, `/nick`, `/me`, `/raw`,
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
object per message, including structured tags, for safe automation.
Every authentication mode requests the same optional server-time,
message-tags, and account-tag metadata capabilities, so changing credentials
cannot silently reduce the information delivered to the caller.

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
request for plaintext/public-CA TLS and anonymous, SASL PLAIN, or SASL
OAUTHBEARER registration. An `account/network` SASL account selects an owned
BNC network. It has bounded channel/query buffers, Alt-Left/Right switching,
bounded scrollback, a relay/status strip, an active-first conversation rail,
a visible horizontally-following composer caret, `/help`, `/join`, `/msg`,
`/win`, `/raw`, literal-slash escape with `//`, `/quit`, Ctrl-End return to the
latest message, Ctrl-C exit, automatic reconnect with the same explicit
request, and loud disconnect/write/drop state. The slash-command grammar is
closed: malformed
or unknown commands remain in the composer with an explanation instead of
silently doing nothing or leaking into a conversation. On initial
connect and reconnect it requires the history/read-marker capabilities it
uses, rejoins every channel confirmed for the client, loads bounded
CHATHISTORY after the server's marker (or the latest bounded window), and
coalesces shared read-marker writes as buffer focus advances. While the current
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
  base64-shown once.
- Upstream BNC secrets (SASL passwords, bridge tokens) sealable at rest
  under a **server master keyring** provided via `[secrets].key_file` plus
  optional `previous_key_files`, or the `E6IRC_SECRET_KEY` plus optional
  comma-separated `E6IRC_PREVIOUS_SECRET_KEYS` environment variables (each
  key is 32 bytes, base64). Sealed values are written as
  `enc:v2:<base64(nonce‖ciphertext‖tag)>`, with authenticated context binding;
  legacy context-free `enc:v1:` remains read-only compatible. A sealed value
  with no/wrong key is a hard startup error, and plaintext bootstrap values
  pass through until the managed control plane imports them sealed.
  AEAD is **ChaCha20-Poly1305** via the in-tree aws-lc-rs (already pulled
  by rustls) — chosen over XChaCha20-Poly1305 to avoid a new crypto
  dependency; the fresh-random 96-bit nonce per value makes reuse
  negligible at config-secret volumes. `e6ircd genkey` mints a key and
  `e6ircd seal` encrypts stdin. Rotation first installs a new primary while
  retaining the old key as a read-only fallback; `e6ircd rotate-secrets`
  locks and re-seals managed configuration plus every account-network secret
  in one PostgreSQL transaction, with a redacted audit record. The old key is
  removed only after that command commits. A corrupt, plaintext, or unreadable
  value rolls the entire operation back.
- TLS ≥ 1.2 everywhere (rustls); responses carry HSTS whenever the validated
  public origin is HTTPS (and never on an explicitly plain development
  origin); WS upgrades check Origin.
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
- `/readyz`, which fails when a core heartbeat is stale or
  configured PostgreSQL cannot answer `SELECT 1` within a separate two-second
  query deadline.

When PostgreSQL is configured, a sampler stores the typed JSON snapshot in
`observability_samples`. The UI-managed `[observability]` interval (5–300
seconds), enable switch, and retention (1–2160 hours) apply live. Every insert
deletes rows older than the configured retention in the same transaction, so
the history is bounded by construction rather than a separate best-effort
cleanup job. The independently supervised storage-maintenance worker also
reports its database latency and failures through this telemetry even when
historical sampling is disabled. `/healthz` remains a dependency-free
liveness probe.

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
8. **UI tests**: Playwright drives real OIDC and local-password authentication
   through Chromium, Firefox, and WebKit; exact Shauth qualification uses
   Chromium. Focused replay/race/membership cases use
   browser-side network/history/WebSocket doubles. A separate full-stack case
   edits every managed-configuration subsection and credential collection,
   proves persisted themes and the desktop-notification boundary, creates a
   network through the console, crosses real PostgreSQL, registry, IRC-driver,
   local TCP-upstream, and `/ws/ui` paths in both directions, inspects
   operations data, visits every administrator directory, mutates and audits a
   server ban, verifies queue monitoring in HTML and JSON, then gracefully
   restarts the daemon and proves session/network/backlog recovery.
9. **Load**: `e6irc-load` and `tools/load/sweep.sh` measure connection rate,
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
  redacted audit entry; stale writers fail visibly.
- The BNC registry exists whenever PostgreSQL does, independently of the raw
  attach listener. Its listener is runtime-managed: enabling or rebinding first
  binds the replacement socket, swaps only after success, and retains the
  working listener on failure. Disabling the attach socket does not stop
  always-on networks or the web client.
- Graceful shutdown: stop accepting, notify clients, stop drivers, and flush
  the bounded PostgreSQL write paths within the shutdown budget. Durable
  network/history state is continuously persisted; there is no separate
  driver-checkpoint format.
- Main owns and supervises the core and PostgreSQL worker join handles while
  serving; listener join handles have explicit supervisors. Any unexpected
  completion or panic names the failed task, initiates the same bounded drain,
  and makes the process exit non-zero. HTTP-to-core control requests have a
  five-second reply deadline, so even a live but wedged core cannot hold an
  API request forever.
- BNC listener changes apply live. Core identity/limits, IRC listeners, OIDC,
  operator, and access-policy changes are stored immediately and explicitly
  reported as restart-required; no response claims those values were applied
  to the running core.
- CI builds and tests source on Linux, macOS, and Windows for amd64 and arm64.
  Each merge to `main` publishes a **multi-architecture container image**
  (linux/amd64 and linux/arm64) whose runtime base is
  `debian:bookworm-slim`. Each architecture digest has signed build-provenance
  and SPDX-SBOM attestations; the assembled manifest has signed provenance,
  and the release workflow verifies them after publication. A hardened,
  CI-validated systemd unit is shipped for native Linux installation.
  The container daemon is built with every bridge plus the embedded web
  client, and its environment-rendered bootstrap file is mode `0600` at an
  unpredictable temporary path unless the operator explicitly chooses one.
  The systemd stop budget mechanically exceeds the daemon's bounded
  PostgreSQL flush budget.
  A version tag equal to `v` plus the workspace version publishes deterministic
  archives containing `e6ircd`, `e6irc`, and `e6irc-tui` for Linux, macOS, and
  Windows on x86-64 and ARM64. Each archive has a GitHub build-provenance
  attestation and the release includes sorted SHA-256 checksums. The packager's
  exact members, modes, and reproducibility run in ordinary CI so tag-only
  code cannot rot. Musl artifacts and scratch/distroless images are not
  shipped.
- The production container built and embedded the Vite client before the Rust
  release build; no build step ran at startup. Each merge to `main` published
  one immutable 12-character commit-SHA manifest plus direct `-amd64` and
  `-arm64` image manifests to GitHub Container Registry. Mutable `latest` and
  branch tags were not published, the manifest shape was verified after push,
  and only the newest 20 release groups were retained.
  Untagged OCI attestation referrers are retained and pruned by the same
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
