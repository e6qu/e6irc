# Journey coverage and product boundaries

This is the traceability view of the journey corpus. It separates strong
component coverage from proof of the whole outcome and records when a claim is
a design target rather than current behavior.

## Coverage matrix

| Journey | State | Strongest automated evidence | Boundary not crossed by CI |
|---|---|---|---|
| Local browser login | Proven | Chromium adds a password, signs out, and submits the local-login form against real e6ircd/PostgreSQL | — |
| OpenID Connect login/logout | Proven | Real e6ircd + PostgreSQL + Dex + Chromium; separate Shauth job | Provider diversity beyond Dex/Shauth |
| Identity link/unlink | Proven | Real Dex + PostgreSQL plus console/API | — |
| Device authorization grant | Proven at API/browser-page level | HTTP + PostgreSQL one-time consume and verification page | No shipped native client orchestrates it |
| SASL PLAIN/OAUTHBEARER local IRC | Proven | Real sockets + PostgreSQL + CLI; native clients share one typed connection request | TUI argument/auth wiring is not a pseudo-terminal e2e |
| IRC registration/channel messaging | Proven | Core/e2e, irctest, fuzz, six-platform matrix | Live third-party server interop is opt-in |
| Direct messages and durable history | Proven | Core + PostgreSQL authorization/pagination/restart | — |
| Channel governance/services | Proven | Core + PostgreSQL + API/console + irctest services | — |
| IRC operator/ban/audit | Proven | Core + PostgreSQL atomic mutation/audit + console/API | — |
| WebSocket IRC | Proven | Real WebSocket protocol integration | Browser third-party client not driven |
| Web chat state machine | Proven in browser with mocked transport | Chromium replay/race/NAMES/leave/query tests | Focused edge-state cases replace `/ws/ui` and upstream |
| `/ws/ui` relay | Proven at protocol level | Real HTTP/WebSocket + upstream test | Chromium not on this path |
| Full browser chat | Proven | Chromium → console/API → PostgreSQL → registry → IRC driver → local TCP peer → `/ws/ui`, both directions | Public-network interop remains opt-in |
| Network preset creation | Proven through UI/storage/runtime | Chromium verifies the Libera preset; custom creation crosses console/PostgreSQL/driver | Public Libera endpoint is opt-in |
| BNC attach/auth/route | Proven | Real listener + upstream + PostgreSQL | Newly included in database CI |
| BNC persistence/restart | Proven | Real PostgreSQL restart/trim/wire-form tests | — |
| Per-network operations UI | Proven | Chromium inspects connected state and persisted live traffic from the real upstream | — |
| Managed configuration | Proven by component/integration | Validation, CAS/audit, listener runtime, HTTP | No browser sweep of every subsection |
| Directories/policy/sessions | Proven | PostgreSQL cursor/filter + HTTP role/scoping | — |
| Monitoring/history/metrics | Proven by component/integration | Telemetry + PostgreSQL retention + HTTP/console | No external scrape/alert stack |
| Local bridge | Proven | In-process driver and common attach path | — |
| IRC driver | Proven locally | Local upstream SASL/relay/reconnect/lifecycle | Live Libera is opt-in |
| Matrix bridge | Proven | Real pinned Conduit, both directions | Other homeserver implementations |
| Discord bridge | Externally qualified | Offline protocol/mapping/backoff tests | Live gateway/REST needs bot and guild |
| Slack bridge | Externally qualified | Offline protocol/mapping/backoff tests | Live Socket Mode/Web API needs app/workspace |
| CLI shipped commands | Proven | Real server/API/TLS/SASL e2e | No device login, token cache, or JSON tail exists |
| TUI shipped behavior | Partially proven | Unit tests + server-message fuzz + shared TLS/SASL/OAuth transport | No history/read-sync or pseudo-terminal e2e |
| REST resource families | Proven at route and family level | Exact router/OpenAPI method-path catalog + extensive real HTTP/PostgreSQL tests | Schema semantics remain hand-authored and directly tested |
| First boot/migrations | Proven by component/integration | Config + migrations + database suites + production image | No fresh external-host acceptance script |
| Graceful restart/durable reload | Proven | Chromium journey gracefully restarts the real daemon and recovers session, network, connection, and backlog; domain tests cover the rest | — |
| Cross-platform source portability | Proven | Linux/macOS/Windows × x86-64/ARM64 all-feature CI | Distribution archives are not published |
| Multi-architecture container | Proven on every `main` merge | Native amd64/arm64 builds, shape verification, signed provenance, and SPDX SBOM attestations | — |
| 100k single-host target | Unproven | Exact-delivery 64-client CI smoke plus manual baselines through 2,000 clients | Target architecture, budgets, thresholds, and tuned-host qualification are incomplete |

“—” means the defined journey boundary is crossed by current CI; it does not
mean every possible environment or fault has been tested.

## What the suite is strong at

- Protocol behavior has unusually deep direct-core, real-socket, irctest,
  property, fuzz, and loom coverage.
- PostgreSQL invariants are exercised against a real database: authorization,
  transaction boundaries, caps, stable pagination, restart, retention, and
  owner isolation.
- HTTP handler tests cover authentication/role/CSRF/no-store behavior and
  complete mutation lifecycles rather than template snapshots alone.
- OIDC crosses a real provider and browser; Matrix crosses a real homeserver.
- CI builds all features together and each bridge independently, then tests
  every supported operating-system/architecture cell.
- The production container is built and inspected as a deployable artifact.

## Material qualification boundaries

### Browser-to-network acceptance

The Chromium suite contains both layers: deterministic browser-side
REST/history/WebSocket replacements for replay races and membership edge
states, and one complete local acceptance path through real console forms,
PostgreSQL, the registry, an IRC driver, a TCP upstream, `/ws/ui`, persistence,
operations diagnostics, graceful daemon restart, and session recovery.

### Target-scale architecture

The current core runs one worker. The sharded ownership/routing model,
deterministic whole-core scheduler/replay, timer-wheel work, and several
zero-copy/performance mechanisms described as target architecture in DESIGN
are not present. The load harness is useful, but there are no numeric
acceptance thresholds, per-connection RSS budget, CI performance regression,
or 100k qualification result.

### Native-client product parity

The CLI is a robust one-shot tool for its shipped commands, but it does not
provide device-login/keyring/JSON-tail workflows. The TUI accepts plaintext or
public-CA TLS, SASL PLAIN or OAUTHBEARER, `account/network` BNC selection, and
automatic reconnect with explicit dropped-send status. Its remaining product
boundary is history/read-marker synchronization and a pseudo-terminal
acceptance test.

### External bridges and public networks

Matrix has a self-hosted CI oracle. Discord and Slack require real commercial
credentials; public-network probes must be respectful and opt-in. Their
transport journeys therefore remain externally qualified while their pure
protocol/state logic remains in normal CI.

### Distribution and operations

Source portability and multi-architecture containers are proven. The
repository ships a validated hardened systemd unit; every published
architecture image has signed build provenance and an SPDX SBOM attestation,
and the assembled manifest has signed provenance. Native binary archives,
musl/static images, and an external alerting stack are outside the shipped
distribution.

### Specification and journey traceability

One macro generates the Axum API method routers and the operation inventory
that the OpenAPI document must match exactly; drift fails a unit test and makes
the endpoint return an explicit contract error. These documents are the stable
journey inventory. Acceptance remains idiomatic Rust integration tests and
targeted browser/shell journeys rather than a second scenario-language stack.

## CI mapping

| CI job | Product risk addressed |
|---|---|
| `lint` | formatting, warnings, all-feature and per-bridge compilation, frontend unit tests/build, no-op/dead-public/duplication/no-deferral guards |
| `deny` | licenses, advisories, bans, and dependency-source policy |
| `test` | all-feature workspace behavior on six OS/architecture cells |
| `db-tests` | real PostgreSQL storage/HTTP/OIDC/browser/BNC/`ws_ui`/CLI journeys |
| `production-container` | deployable image and embedded web-client shape |
| `load-smoke` | real daemon with 64 clients, eight channels, exact fan-out, and graceful shutdown |
| `shauth-sso` | exact external single-sign-on/logout integration |
| `irctest`, `irctest-services` | IRC and services conformance |
| `matrix-bridge` | bidirectional live bridge behavior |
| `loom` | queue concurrency interleavings |
| `fuzz-smoke` | parser, serializer, stateful core, multi-client core, and hostile TUI server output |
| `size-report` | informational release binary-size visibility |

The `Release image` workflow separately publishes direct amd64/arm64 images,
verifies the assembled manifest, emits signed build/SBOM attestations, verifies
those attestations as a consumer, and prunes complete old release groups.

The PostgreSQL BNC and `/ws/ui` ignored integration suites belong in
`db-tests`; the workflow invokes them explicitly. “Ignored” in their source
means they need the supplied database environment, not that CI may omit them.
