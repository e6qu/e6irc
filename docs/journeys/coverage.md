# Journey coverage and product boundaries

This is the traceability view of the journey corpus. It separates strong
component coverage from proof of the whole outcome and records when a claim is
a design target rather than current behavior.

## Coverage matrix

| Journey | State | Strongest automated evidence | Boundary not crossed by CI |
|---|---|---|---|
| Local browser login | Partially proven | Real HTTP + PostgreSQL credential/session tests | Chromium does not submit local login |
| OpenID Connect login/logout | Proven | Real e6ircd + PostgreSQL + Dex + Chromium; separate Shauth job | Provider diversity beyond Dex/Shauth |
| Identity link/unlink | Proven | Real Dex + PostgreSQL plus console/API | — |
| Device authorization grant | Proven at API/browser-page level | HTTP + PostgreSQL one-time consume and verification page | No shipped native client orchestrates it |
| SASL PLAIN/OAUTHBEARER local IRC | Proven | Real sockets + PostgreSQL + CLI | TUI does not expose either |
| IRC registration/channel messaging | Proven | Core/e2e, irctest, fuzz, six-platform matrix | Live third-party server interop is opt-in |
| Direct messages and durable history | Proven | Core + PostgreSQL authorization/pagination/restart | — |
| Channel governance/services | Proven | Core + PostgreSQL + API/console + irctest services | — |
| IRC operator/ban/audit | Proven | Core + PostgreSQL atomic mutation/audit + console/API | — |
| WebSocket IRC | Proven | Real WebSocket protocol integration | Browser third-party client not driven |
| Web chat state machine | Proven in browser with mocked transport | Chromium replay/race/NAMES/leave/query tests | Real `/ws/ui` and upstream are replaced |
| `/ws/ui` relay | Proven at protocol level | Real HTTP/WebSocket + upstream test | Chromium not on this path |
| Full browser chat | Partially proven | The two rows above prove each side independently | No browser → server → driver → peer test |
| Network preset creation | Proven through storage/runtime | Server-side preset unit + console/API/PostgreSQL lifecycle | Public Libera endpoint is opt-in |
| BNC attach/auth/route | Proven | Real listener + upstream + PostgreSQL | Newly included in database CI |
| BNC persistence/restart | Proven | Real PostgreSQL restart/trim/wire-form tests | — |
| Per-network operations UI | Proven at HTTP/runtime level | Snapshot/accounting unit + console rendering | No browser interaction test |
| Managed configuration | Proven by component/integration | Validation, CAS/audit, listener runtime, HTTP | No browser sweep of every subsection |
| Directories/policy/sessions | Proven | PostgreSQL cursor/filter + HTTP role/scoping | — |
| Monitoring/history/metrics | Proven by component/integration | Telemetry + PostgreSQL retention + HTTP/console | No external scrape/alert stack |
| Local bridge | Proven | In-process driver and common attach path | — |
| IRC driver | Proven locally | Local upstream SASL/relay/reconnect/lifecycle | Live Libera is opt-in |
| Matrix bridge | Proven | Real pinned Conduit, both directions | Other homeserver implementations |
| Discord bridge | Externally qualified | Offline protocol/mapping/backoff tests | Live gateway/REST needs bot and guild |
| Slack bridge | Externally qualified | Offline protocol/mapping/backoff tests | Live Socket Mode/Web API needs app/workspace |
| CLI shipped commands | Proven | Real server/API/TLS/SASL e2e | No device login, token cache, or JSON tail exists |
| TUI shipped behavior | Partially proven | Unit tests + server-message fuzz | No TLS/auth/history/read-sync/reconnect or PTY e2e |
| REST resource families | Partially proven | Extensive real HTTP/PostgreSQL tests | OpenAPI/router parity is representative, not mechanical |
| First boot/migrations | Proven by component/integration | Config + migrations + database suites + production image | No fresh external-host acceptance script |
| Graceful restart/durable reload | Proven by component/integration | Shutdown/flush plus restart tests per durable domain | No mixed-traffic process-level restart scenario |
| Cross-platform source portability | Proven | Linux/macOS/Windows × x86-64/ARM64 all-feature CI | Distribution archives are not published |
| Multi-architecture container | Proven on tag path | Native amd64/arm64 builds and shape verification | No provenance/SBOM output |
| 100k single-host target | Unproven | Harness and manual baselines through 2,000 clients | Target architecture and qualification run are incomplete |

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

The Chromium chat tests install browser-side replacements for network REST,
history, and WebSocket. Separate Rust integration tests drive the real
`/ws/ui` relay and PostgreSQL-backed network lifecycle. This catches rich
client-state bugs and server protocol bugs, but not wiring/configuration drift
between them. The absent proof is a real browser sending to and receiving from
a local upstream through the complete multiplexer path.

### Target-scale architecture

The current core runs one worker. The sharded ownership/routing model,
deterministic whole-core scheduler/replay, timer-wheel work, and several
zero-copy/performance mechanisms described as target architecture in DESIGN
are not present. The load harness is useful, but there are no numeric
acceptance thresholds, per-connection RSS budget, CI performance regression,
or 100k qualification result.

### Native-client product parity

The CLI is a robust one-shot tool for its shipped commands, but it lacks the
documented device-login/keyring/JSON-tail experience. The TUI is a minimal
single plaintext connection with bounded multi-buffer state; it lacks the
authentication, TLS, history, read-sync, reconnect, and BNC-selection journey
expected of the described general client.

### External bridges and public networks

Matrix has a self-hosted CI oracle. Discord and Slack require real commercial
credentials; public-network probes must be respectful and opt-in. Their
transport journeys therefore remain externally qualified while their pure
protocol/state logic remains in normal CI.

### Distribution and operations

Source portability and multi-architecture containers are proven. Native binary
archives, systemd packaging, musl/static images, release provenance/SBOM, a
process-level restart/chaos scenario, and an alerting stack are not shipped.

### Specification and journey traceability

The OpenAPI test checks representative paths rather than deriving all method/
path pairs from the axum router. Before this corpus, there was no stable
journey inventory or Given/When/Then scenario layer despite DESIGN describing
one. These documents provide the inventory; CI still expresses acceptance as
Rust integration tests and targeted browser scripts rather than a shared
scenario DSL.

## CI mapping

| CI job | Product risk addressed |
|---|---|
| `lint` | formatting, warnings, all-feature and per-bridge compilation, frontend unit tests/build, no-op/dead-public/duplication/no-deferral guards |
| `deny` | licenses, advisories, bans, and dependency-source policy |
| `test` | all-feature workspace behavior on six OS/architecture cells |
| `db-tests` | real PostgreSQL storage/HTTP/OIDC/browser/BNC/`ws_ui`/CLI journeys |
| `production-container` | deployable image and embedded web-client shape |
| `shauth-sso` | exact external single-sign-on/logout integration |
| `irctest`, `irctest-services` | IRC and services conformance |
| `matrix-bridge` | bidirectional live bridge behavior |
| `loom` | queue concurrency interleavings |
| `fuzz-smoke` | parser, serializer, stateful core, multi-client core, and hostile TUI server output |
| `size-report` | informational release binary-size visibility |

The PostgreSQL BNC and `/ws/ui` ignored integration suites belong in
`db-tests`; the workflow invokes them explicitly. “Ignored” in their source
means they need the supplied database environment, not that CI may omit them.
