# e6irc — Design

A monolithic Rust IRC daemon with a built-in REST API, web backend (OIDC login),
and per-user BNC hosting — plus a CLI client, a TUI client, and a vanilla
JavaScript web client bundled with Vite.

License: **AGPL-3.0-or-later**. All compiled-in dependencies must be
AGPL-compatible (permissive licenses are fine; license compliance is enforced
in CI with `cargo-deny`).

Unfamiliar term? See [`docs/terminology.md`](docs/terminology.md) — the
glossary of IRC, OpenID Connect, and deployment vocabulary used here.

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
- **Libera.Chat compatibility** as an explicit target (§7.7): clients and
  scripts written against Libera (Solanum ircd + Atheme services) must work
  against e6ircd, and the BNC upstream connector must interoperate cleanly
  with Libera as the primary external network.
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
    K/D/X-line add/remove writes the ban row and audit row in one transaction;
    enforcement, disconnects, operator notices, and HTTP admin responses happen
    only after it commits. The IRC and HTTP origins are typed requesters, so a
    global committed result does not depend on a still-live `ConnId`, and no
    sentinel connection can accidentally stand in for an admin request.
  - `ConnectionEvent` — the bouncer SPI's connection-state event *cannot
    carry a line*, so a driver can't route text past the CR/LF sanitizer and
    the detached-buffer append; the bypass is a compile error, not a lint.
  - `MessageKind` (PRIVMSG/NOTICE) — one type with `wire()`, `db()` and
    `is_loud()`, so the uppercase verb, the lowercase storage token, and the
    "does it auto-reply" rule cannot drift; before, the ring and the database
    stored different casings of the same message.
  - `StatusSigil` — the STATUSMSG `@`/`+` target sigil is `Option<enum>`, so
    "does this enter history / narrow the audience" is `is_none()` and a
    method, not a byte compared against `0`.
  - `crate::sanitize` — one module holds every "turn untrusted text into a
    field safe for its wire position" function (username, account name, bridge
    nick token, upstream CR/LF/NUL neutralization, client-tag-key validation,
    nick/channel validators), each documented with the position it protects
    (prefix / middle / tag / trailing). A new field gets the right rule by
    reaching for the module rather than re-deriving a one-off filter.
  - `Authenticated`/`AdminAccount` — an HTTP handler is authenticated (or
    admin-gated) because it *asks for* the extractor in its signature, which
    runs the check as a precondition of being called. An admin route cannot
    forget the gate: the ungated handler fails to compile for want of the
    argument, rather than relying on every handler to open with the same line.
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
    of uptime — the class that flood-killed fresh clients (sweep 79). Seeding
    from the open time removes the sentinel so the class cannot recur on a new
    watermark field.
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
`mod.rs` holding dispatch and the helpers they share. It was a single 6,400-line
file until sweep 26; the split is by *what a command does*, so the module a
change belongs in follows from the command being changed. Submodules reach
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
│   │                         #   OAUTHBEARER device flow), chathistory (shared by CLI/TUI)
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
  truncated silently. On *output*, a relayed PRIVMSG/NOTICE carries a source
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

**Architecture rule.** The server is a set of **single-threaded event
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

- Bounded MPSC ring buffer; envelopes carry a per-queue monotonic
  sequence number and source id (trace/replay identity).
- **No silent loss**: `try_push` returns `Err(Full(event))` — the
  producer decides (kill the slow consumer's connection, exert
  backpressure, or shed *with accounting*). Delivered-or-returned is an
  invariant, not a best effort.
- Consumer API: `async pop()` in runtime mode (custom waker, no tokio
  channel underneath); `step()` under the manual scheduler.
- Instrumentation built in: depth gauge, enqueue/dequeue trace hooks.
- **Adaptive degraded mode (FIFO→LIFO)**: per-queue opt-in policy. When
  depth crosses a high watermark the queue flips to LIFO dequeue — under
  overload the *freshest* events are served first and stale work is what
  waits — flipping back to FIFO at a low watermark (hysteresis). Mode
  changes are never silent: counter + trace hook + metrics. Only wired
  for queues whose consumers tolerate reordering (envelopes carry seq
  numbers, so downstream can restore order or detect staleness); queues
  whose ordering is semantic — e.g. a shard's command stream — stay
  strict FIFO.
- **Verified**: loom model-checks the concurrency core (push/pop/wake
  under all interleavings); property tests pin FIFO-per-producer,
  bounded-memory, and delivered-or-returned invariants.

**Worker topology:**

- **Core shards** (N ≈ cores): each owns the sessions, nick table
  partition, and channel table partition for its hash range
  (casefolded-name hash). A command touching `#chan` is routed to
  `shard(#chan)`'s queue; nick-scoped commands to `shard(nick)`.
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

State-of-the-art throughput and latency practices are the default coding
discipline on hot paths — with the rule that any nontrivial optimization
lands together with the benchmark that proves it:

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
- **Build-level**: fat LTO, `codegen-units = 1` (§6); PGO and BOLT
  evaluated in the scale-hardening phase; allocator swap
  (mimalloc/jemalloc) decided by benchmark behind a feature flag, not by
  fashion.
- **Measured, always**: criterion microbenches live beside hot modules;
  `tools/load` macrobenchmarks track p50/p99/p999 fan-out latency and
  throughput per-PR so regressions are visible immediately.

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
this project makes or tests.

Principal tables (columns abridged):

- `accounts` (id, name/casefolded, created_at, flags)
- `account_credentials` (account_id, kind: local_password | app_password,
  argon2id hash, label, last_used_at) — app passwords are per-client,
  revocable, shown once at creation
- `oidc_identities` (issuer, subject) → account_id, UNIQUE(issuer, subject)
- `web_sessions` (opaque id hash, account_id, expiry, ua)
- `api_tokens` (hashed PATs, scopes, expiry)
- `channels` (registered channels: founder, flags, topic retention, mlock)
- `channel_access` (channel_id, account_id, flags) — Atheme-style FLAGS
- `messages` — append-only history log; columns (id, msgid, target,
  sender_prefix, sender_account, kind, body, ts), indexed `(target, ts)`
  btree + BRIN on `ts`. Native monthly range partitions and
  partition-drop retention are a planned scale-hardening step — the write
  path and queries are already partition-shaped (append-only, time-bounded
  scans). Server-time and account-tag are reconstructed from `ts` and
  `sender_account`, so no separate tags column is stored.
- `bnc_networks` (account_id, name, addr, tls, nick, realname, autojoin,
  sasl_account, `sasl_password_sealed` — **sealed** (`enc:v1:`) with the
  server master key (§15), enabled)
- `bnc_buffer` (id, owner, network, line, created_at) — persisted
  detached-buffer lines replayed on attach after a restart; `owner` is `*`
  for a shared/server-level network; `owner` is the RFC1459-casefolded account,
  matching the registry key. The `/network` selector is likewise folded for
  matching (registry key + a `UNIQUE (account_id, lower(name))` index on
  `bnc_networks`, migration 0034), so selection is case-insensitive like every
  other IRC identifier and a case-mismatched attach cannot fall through to an
  operator's shared network of the same name (§2); display casing is preserved.
  Both ways into a network's buffer — a live line
  from a driver and restored backlog from this table — neutralize embedded
  CR/LF/NUL, so a line replayed to an attaching client cannot become two
  regardless of which path it arrived through or which build wrote it, and a
  bridge-synthesized line is split to fit `MAX_LINE_LEN` — an over-long line is
  discarded whole by the receiving client's framing, so emitting one loses the
  message silently.
  Retention is per (owner, network): the persistence task counts its own
  appends and trims to the newest `BNC_BUFFER_CAP` at every
  `BNC_TRIM_INTERVAL`. The count belongs to that task, not to the table's `id`
  sequence — one sequence is shared by every network, so triggering off it
  makes retention depend on the interleaving between them
- `read_markers` (account_id, target, marker_ts) — per-account read
  position, the source for `draft/read-marker`. Updates are monotonic
  (`GREATEST`) and the returned committed value drives the core mirror and
  client acknowledgement; an enqueue or PostgreSQL failure is never reported
  as success. Anonymous connections use explicitly session-local markers.
- `audit_log` (oper/admin actions, API mutations)

Write path for messages: producers push to an in-process MPSC; a writer pool
batches into multi-row `INSERT ... UNNEST` (or COPY for bulk) with group
commit — one connection cannot stall the chat path on Postgres latency. The
in-memory hot ring buffer (§11.3) serves recent history without touching PG.

---

## 9. Identity & authentication

### 9.1 Account model

One `accounts` row per user regardless of origin. An account may have any
combination of: local password, N app passwords, N OIDC identities. Web
"user section" manages all of them. NickServ `REGISTER` creates the same
kind of account the OIDC first-login path creates.

The `draft/account-registration` `REGISTER` command creates that same account,
so the two entry points cannot diverge; the capability's advertised value states
the policy (`before-connect`, `email-required`) so a client knows the rules
before it tries. `custom-account-name` is deliberately **not** advertised: an
account always takes the registering nick's name, which keeps "the account you
registered is the nick you were holding" true — and that in turn is what lets
direct-message conversations be keyed by account (§11.1.1). Registration before
the connection completes is off by default: a half-open connection creating
accounts is a spam vector unless the operator opts in. e6ircd cannot send
verification mail, so `email-required` only enforces that an address was
supplied.

### 9.2 Web login

- **OIDC** authorization-code + PKCE against one or more providers
  registered in config (issuer URL, client id/secret, allowed domains
  option). Discovery + JWKS cached with proper refresh. First login
  auto-provisions an account (nick derived from `preferred_username`,
  conflict → user picks). Subsequent logins match on (issuer, subject),
  never on email.
- Local-account login form (argon2id verify) for accounts without OIDC.
- Session: opaque random token, hash stored server-side (`web_sessions`),
  `HttpOnly; Secure; SameSite=Lax` cookie. CSRF: state-changing
  server-rendered forms carry a per-session HMAC token in the request body and
  reject a missing or invalid token before mutation.
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
  issuer, audience, event, time, `sid`/`sub`, and `jti` were verified, and
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

Personal access tokens (hashed at rest, scoped, expiring) via
`Authorization: Bearer`, or the web session cookie (for the browser clients,
with the CSRF rules above). Admin endpoints additionally require the
account's admin flag. The same admin-gated data is also served as a
server-rendered management **console** at `/console` (accounts, registered
channels, server bans, audit log); it shares the `pages` module,
`render_private`, and the exact admin gate the `/api/v1/admin/*` JSON endpoints
use, so it can never surface server-wide data to a non-admin. Beyond the read
views, the console can **act**: add/remove a K/D/X-line, unregister a registered
channel, and — from a live client-sessions view at `/console/sessions` — KILL a
session by nick. These run on the core worker via `Input::Admin { req, reply }`
(a oneshot-reply), reusing the exact live-state + persistence path of the
equivalent oper/services command — a console ban updates the hot ban list,
persists, disconnects matching sessions, and audit-logs identically to oper
KLINE; a console KILL is the same teardown as oper KILL; the sessions view is a
live snapshot of the core's session table (the shared logic is extracted so
there is one implementation, not two). Actions are admin-gated + CSRF-protected;
success redirects (PRG), failure re-renders with an error banner. A non-admin
counterpart at `/console/my-sessions` lets any signed-in user see and disconnect
*their own* connected clients: the core scopes the snapshot to the caller's
account and refuses a self-service kill of a session not authenticated as the
caller, so it can never touch anyone else's. The console shell (`console_base.html`) is
also home to `/console/account`, the complete self-service surface for creating
and revoking app passwords and personal access tokens, linking and safely
unlinking login identities, and inspecting persisted read markers. App
passwords and tokens are displayed exactly once; only hashes are retained.
Identity unlink is transactional: the account row serializes concurrent
requests, the last login identity cannot be removed, and sessions asserted by
the removed identity are revoked in the same transaction. The old `/account`
URL is an authenticated redirect to this canonical page.

The shell also contains `/console/configuration`, the database-backed operational control
plane. Its singleton `server_settings` row is a typed JSON document with an
optimistic-concurrency revision, actor, and timestamp; every committed revision
also writes a redacted `CONFIG` audit entry in the same transaction. The
database URL, master-key source, HTTP bind, and initial administrator remain
bootstrap values because they are prerequisites for reaching the console.
Identity, MOTD, IRC listeners, public URL/cookie policy, administrator grants,
OIDC providers, operators, registration policy, resource limits, trusted
proxies, server-level networks, and the BNC attach address are UI-managed.
Credential-bearing values are sealed before entering PostgreSQL and are never
rendered back. Existing
plaintext bootstrap credentials remain authoritative until a master key is
supplied; that next start atomically seals and imports them rather than either
persisting plaintext or replacing them with redacted placeholders.

The console is also the home of `/console/networks` — a per-user BNC network manager with
add/remove/enable-disable, and **edit** of an IRC
network's connection/identity fields (addr, tls, nick, realname, autojoin; SASL
credentials change via delete+recreate; a bridge is edited on the Integrations
page, so the IRC edit form refuses non-IRC kinds), available to any
authenticated user for their own networks. Each network has an owner-scoped
operations page refreshed every ten seconds: lifecycle and state-transition
time, connection age and latency, attempts and errors, attached raw/web
clients, per-network line/byte traffic, in-memory buffer use, stored backlog
bounds, and the newest 100 stored lines. `/api/v1/me/networks/{name}` exposes
the same counters and timestamps without raw errors or credentials. The
runtime snapshot is held once on `NetworkHandle`, so IRC and every bridge
driver enter the same measurement path; both raw-IRC and web attachments use
the counted `send` funnel.

`/console/integrations` (admin) manages the chat-platform bridges:
per-platform build availability, the complete stored inventory (including
disabled bridges and bridges whose feature is absent), status, inspect,
pause/resume, and add/remove. A network's `kind`
(`irc`/`matrix`/`discord`/`slack`) is a column on
`bnc_networks`, so bridges are runtime-managed just like IRC upstreams — created
via the console or REST, persisted, and started by the one feature-gated
`bouncer::build_driver` factory that every construction site (config-network
startup, DB-network boot, runtime create, re-enable) shares. Per-kind secrecy:
the password is always sealed; a kind whose *account* field is a secret (Slack's
bot token) seals that too, while an IRC `sasl_account` login name stays plaintext.

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
  are mirrored to all attached clients (self-echo via `echo-message`).
- **Detached buffering**: events accumulate per buffer with per-client read
  markers (`read-marker` cap ↔ web client ↔ TUI all share position).
- **Playback**: modern clients pull via `CHATHISTORY`; legacy clients get
  timestamp-prefixed backlog replay on attach (soju-style, configurable
  per client).
- **Operations**: `NetworkHandle` owns a typed lifecycle snapshot plus
  connection attempts/errors, connect latency, attached-client count,
  line/byte traffic, last-activity times, and buffer occupancy. Driver endpoints
  can change lifecycle and record inbound lines only through that shared state;
  downstream traffic crosses the handle's counted bounded-send funnel.

### 10.2 `local` driver — always-on on our own server

The user's presence on e6ircd itself is a network like any other, but the
driver is a direct in-process handle into the IRC core (no TCP, no parse).
This means always-on local sessions, multi-device attach, and playback cost
one implementation shared with the external-network path.

### 10.3 `irc` driver — external networks (ZNC/soju-style)

- Full IRCv3 *client* implementation reusing `e6irc-proto` + the same SASL
  machinery; requests `server-time`, `message-tags`, `away-notify`, etc.
  from upstream when available (Libera: yes).
- Auto-reconnect with exponential backoff + jitter, bounded so a repeatedly
  rejected upstream credential stops re-dialing rather than hammering the
  upstream forever. On reconnect the driver re-registers and re-joins the
  *configured* autojoin channels under the configured nick. A JOIN or NICK
  issued by an attached client changes only the current upstream session;
  persistent reconnect behavior is edited explicitly in the network's stored
  configuration. Upstream SASL PLAIN uses credentials stored encrypted (§15).
- Every registration, auto-join, command, heartbeat, and protocol PONG emission
  is part of the session outcome: a failed upstream transport write drops and
  reconnects, while a closed in-process core queue stops the `local` driver
  instead of retrying a permanently gone core. `Connected` is emitted only
  after registration and configured auto-joins have all reached their
  transport.
- Primary interop target: Libera (tested against the §7.7 docker stack).

### 10.4 Attach addressing

Downstream clients select a network with the ZNC/soju username convention:
`alice/libera` (default network configurable; bare `alice` = `local`).
The web client and REST API address networks explicitly by id.

### 10.5 Bridges: `matrix` / `discord` / `slack` drivers

Bridges are **network drivers** behind feature flags — a Discord guild or
Slack workspace appears to the user as another network with channels;
Matrix rooms likewise. v1 ships the **SPI + a loopback reference driver** (used in tests) and
the **`matrix` driver** (Matrix client-server API, behind the `matrix`
feature, integration-tested against a pinned Conduit homeserver in
`vendor/tests/external-oracles/`); Discord then Slack follow as separate
phases (each needs real service credentials to test).

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
Surface (initial):

- `auth`: OIDC start/callback, device-flow bootstrap, logout
- `me`: profile, credentials (app passwords CRUD — secret shown once),
  API tokens CRUD, OIDC identity link/list/unlink
- `networks`: BNC network CRUD (+ enable/disable, status), buffers list,
  read-marker get/set
- `channels`: registered-channel management (access flags, topic, mlock)
- `history`: paged queries per §11.2
- `admin`: accounts, global bans (kline-equivalents), server stats,
  audit-log query, live/historical observability, Prometheus exposition
- `healthz` (liveness; no auth)
- `readyz` (core-heartbeat and configured-PostgreSQL readiness; no auth)

The OpenAPI 3.1 document at `/api/v1/openapi.json` is hand-authored and
always served (no feature gate, no utoipa dependency).

---

## 13. Web client (askama + vanilla JavaScript + Vite)

### 13.1 Model

Two surfaces, both without an SPA framework. The **management** pages —
login, the user account section, and the `/console` admin/BNC/integrations
console — are server-rendered askama pages using standard form submissions and
Post/Redirect/Get. An always-served, same-origin `/console.js` handles only
progressive enhancements: destructive-action confirmation, one-time-secret
copying, and monitoring refresh with explicit failure state. The console
therefore works in the default build as well as `embed-web`, and its private
pages use a CSP that permits only that same-origin script. The **live chat
client** is a small hand-written vanilla-JS IRC client (`web/src`,
bundled by Vite): it parses IRC lines client-side into buffers and a member
list rather than swapping server HTML, since per-channel routing and nick-list
state are naturally client state. The socket reconnects with backoff so a
transient drop self-heals; opening the page without a `?network=` selector
shows a picker of the caller's networks (its entry point). The persistent
top-bar selector changes networks from every chat view, the preferences menu
owns validated theme/notification settings, and responsive conversation
navigation preserves the full chat pane on phones. Identity, network-list,
history, storage, notification, and socket-protocol failures have visible,
actionable states; an API failure is never rendered as an empty account. The
member list is rank-ordered with sigils kept live from channel `MODE`, and the
client offers a join-channel input and click-to-query on nicks.

### 13.2 Live chat over WebSocket

The chat page opens one WS (`/ws/ui`, cookie-authenticated). The server pushes
JSON events — `{"t":"line","v":"<raw IRC line>"}` and `{"t":"status",...}` —
and the client parses each line, routes it to the right buffer (channel / DM /
server), maintains the per-channel member list, and renders the active buffer
(all via DOM APIs, never `innerHTML` on server text, so a hostile upstream line
can't inject markup). The composer sends `{target, message}` (with
slash-commands) up the same socket, which the server maps to an IRC line. This
keeps the web client on the exact same multiplexer attach path as an IRC client
— the web client *is* an attached client of the user's networks.
Status values are the closed set `connected`, `disconnected`, and
`unavailable`. The first two describe a live driver's upstream lifecycle;
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
`e6irc tail '#chan'` (follow, `--json` line output), `e6irc history …`,
`e6irc api <method> <path>` (authenticated REST passthrough). Auth via app
password or the OAUTHBEARER device flow (`e6irc login`), token cached in
the OS keyring where available, plain file fallback with 0600 perms —
chosen explicitly by flag, never silently.

### 14.2 `e6irc-tui`

ratatui client using `e6irc-client`: multi-network (via BNC username
addressing), buffer sidebar with unread/read-marker state shared with the
web client, chathistory infinite scroll, SASL PLAIN + device-flow login.
It is a *general* IRCv3 client (works against Libera directly too) — which
doubles as a continuous test of our client library against the compat
target.

### 14.3 A client's input is untrusted too

Every clause of §7.2's bounded-buffer rule applies here in reverse. A client's
state — buffers, scrollback, the queue between the socket and the renderer — is
derived from lines a *remote server* chose, and a general IRCv3 client connects
to servers this project does not run. So the same rule holds: scrollback and
buffer count are capped, the socket→render queue is bounded (a full queue stops
the reader and lets TCP push back, exactly as SendQ does outbound), and the
`e6irc api` response read is bounded with an error rather than a truncation.
Hitting a cap is reported to the user, once — a silent cap reads as the network
going quiet, which is the client-side form of a silent no-op (§2).

---

## 15. Security

- Passwords/app passwords: argon2id via a single `hasher()` choke point
  (argon2 0.5.3 defaults — v19, m≈19 MiB, t=2, p=1 — meeting the OWASP
  minimum), constant-time verification; app passwords are 32 random bytes,
  base64-shown once.
- Upstream BNC secrets (SASL passwords, bridge tokens) sealable at rest
  under a **server master key** provided via `[secrets].key_file` or the
  `E6IRC_SECRET_KEY` env var (32 bytes, base64). Sealed values are
  written in config as `enc:v1:<base64(nonce‖ciphertext‖tag)>`, decrypted
  at load; a sealed value with no/wrong key is a hard startup error, and
  plaintext values pass through (file-protected, like oper passwords).
  AEAD is **ChaCha20-Poly1305** via the in-tree aws-lc-rs (already pulled
  by rustls) — chosen over XChaCha20-Poly1305 to avoid a new crypto
  dependency; the fresh-random 96-bit nonce per value makes reuse
  negligible at config-secret volumes. `e6ircd genkey` mints a key;
  `e6ircd seal` encrypts stdin. (Key rotation re-seals values with a new
  key; a versioned `enc:vN:` prefix leaves room for an XChaCha upgrade.)
- TLS ≥ 1.2 everywhere (rustls); HSTS on the web origin; WS upgrades check
  Origin.
- Rate limits: per-IP connection/registration throttle, per-session command
  token bucket, per-account API limits (tower middleware), SASL attempt
  limits with backoff.
- IRC network protections: kline/dline/xline equivalents managed by opers
  and via admin API, all audit-logged.
- No secrets in logs; `tracing` field redaction for credentials.
- CSRF per §9.2; cookies HttpOnly/Secure; session fixation avoided by
  rotating session id at login.

---

## 16. Observability

Operational events remain loud WARN-level stderr lines; fixed-cardinality
telemetry records the machine-readable side of the same failures without
putting untrusted values or secrets in labels. One process-wide snapshot
contains connection state and lifecycle totals, IRC and BNC line/byte traffic,
HTTP and database operation totals, SendQ kills, fixed error categories, BNC
driver up/down state, authenticated raw-IRC and web attachment gauges, and
cumulative core/database/HTTP latency histograms. The attachment guard belongs
to the resolved network handle, so both client transports enter and leave the
same counter only after authentication; accepted but unauthenticated sockets
cannot inflate it. This semantic correction is snapshot schema version 2; the
console does not plot version-1 raw-socket gauges as authenticated attachment
history, while unaffected version-1 counters remain usable.
Each running BNC handle additionally keeps owner-scoped per-network counters
and lifecycle timing. Those values are deliberately not process-wide metric
labels: account and network names are unbounded label cardinality. They are
served only through the authenticated network API and console operations page.

The snapshot is the sole source for:

- `/console/monitoring`, an administrator-only server-rendered view refreshed
  every ten seconds by `/console.js`, with selectable 1-hour, 6-hour, 24-hour,
  and 7-day windows across IRC/BNC traffic, live IRC/BNC connections, upstream
  availability, new errors, and P95 core/database/HTTP latency; current
  percentile tables and the error ledger remain alongside the trends, and
  refresh failures remain visibly actionable;
- `/api/v1/admin/observability`, authenticated JSON with the current snapshot
  and at most 1,000 bounded historical points over an explicit 1-minute to
  7-day range; invalid ranges fail with HTTP 400 rather than being clamped;
- `/api/v1/admin/metrics`, authenticated Prometheus text exposition with only
  fixed `state`/`kind` labels;
- `/readyz`, which fails when the single core worker's heartbeat is stale or
  configured PostgreSQL cannot answer `SELECT 1`.

When PostgreSQL is configured, a sampler stores the typed JSON snapshot in
`observability_samples`. The UI-managed `[observability]` interval (5–300
seconds), enable switch, and retention (1–2160 hours) apply live. Every insert
deletes rows older than the configured retention in the same transaction, so
the history is bounded by construction rather than a separate best-effort
cleanup job. `/healthz` remains a dependency-free liveness probe.

Logging continues to use loud stderr lines; metrics do not depend on a
third-party metrics stack.

---

## 17. Testing strategy

**Methodology.** Development is **TDD**: tests are written first (red),
implementation follows (green), then refactor; no feature lands without
tests at the appropriate level. The **testing pyramid** shapes the suite —
many fast unit/property tests, fewer integration tests, a small set of
acceptance/UI/e2e tests at the top. User-visible behavior is additionally
specified as **BDD-style acceptance tests**: Given/When/Then scenarios
written against a running server, using a small in-repo scenario DSL
(dev-only code; no runtime dependency and no BDD-framework crate). UI
behavior is tested through a real browser; API and network behavior is
tested end-to-end against a real `e6ircd` + PostgreSQL.

Layers, bottom to top:

1. **Unit/property**: proto crate (parser round-trips, casemapping,
   CAP/SASL state machines), multiplexer buffer logic; **loom
   model-checking** of `e6irc-queue`'s concurrency core.
2. **Fuzzing**: cargo-fuzz on parser + tag unescape (CI smoke; longer runs
   scheduled).
2b. **Deterministic simulation**: the queue-based core (§7.3) under a
   seeded single-threaded scheduler with mocked I/O — randomized event
   interleavings, reproducible by seed; step-debugger doubles as the
   failure-investigation tool.
3. **irctest** (progval/irctest) run in CI against `e6ircd` — the same
   suite Solanum/Ergo use.
4. **Compatibility** (§7.7): the vendored Libera-snapshot ISUPPORT
   differential (offline, in CI); opt-in light-touch live interop tests
   against Libera/OFTC/Ergo; and an optional pinned-Solanum differential
   oracle under `vendor/tests/external-oracles/` (developer tool, not CI).
5. **Integration**: BNC `irc` driver against an e6ircd upstream
   (reconnect, SASL, playback); OIDC flows against a dockerized Keycloak
   (or dex).
6. **BDD acceptance**: Given/When/Then scenarios for user journeys
   (register → identify → join → message; OIDC first login provisions an
   account; attach second client → playback; app-password revocation cuts
   access; …) executed against a real server instance.
7. **e2e (API & network)**: REST `/api/v1` exercised over HTTP against a
   running `e6ircd` + Postgres (docker-composed in CI); IRC flows exercised
   over real sockets, including TLS.
8. **UI tests**: Playwright (dev tooling inside `web/`) drives the browser
   client in headless Chromium against a running server — login, live
   message receive over `/ws/ui`, and self-service CRUD.
9. **Load**: `tools/load/` tokio flood-client; CI perf job at reduced scale,
   manual 100k-connection benchmark procedure documented with target
   numbers (connect rate, fan-out p99, RSS/connection).

---

## 18. Configuration & operations

- A minimal `e6irc.toml`/environment bootstrap supplies the PostgreSQL URL,
  secrets-key source, HTTP bind, immutable release revision, and initial
  administrator. Unknown keys are a **startup error**.
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
- Graceful shutdown: stop accepting, notify clients, flush PG write queue,
  checkpoint driver state.
- BNC listener changes apply live. Core identity/limits, IRC listeners, OIDC,
  operator, and access-policy changes are stored immediately and explicitly
  reported as restart-required; no response claims those values were applied
  to the running core.
- Ships as: prebuilt release binaries for **Linux, macOS, and Windows
  (amd64 + arm64 each)**, a systemd unit example, and a **multi-arch
  docker image** (linux/amd64 and linux/arm64 manifest; scratch/distroless
  — the binary is static-friendly apart from libc, musl target evaluated
  in CI on both architectures).
- The production container built and embedded the Vite client before the Rust
  release build; no build step ran at startup. Each merge to `main` published
  one immutable 12-character commit-SHA manifest plus direct `-amd64` and
  `-arm64` image manifests to GitHub Container Registry. Mutable `latest` and
  branch tags were not published, the manifest shape was verified after push,
  and only the newest 20 release groups were retained.

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
