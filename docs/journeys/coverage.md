# Journey coverage and product boundaries

This is the traceability view of the journey corpus. It separates strong
component coverage from proof of the whole outcome and records when a claim is
a design target rather than current behavior.

## Coverage matrix

| Journey | State | Strongest automated evidence | Boundary not crossed by CI |
|---|---|---|---|
| [Bootstrap and manage the server through the UI](administration-and-monitoring.md#bootstrap-and-manage-the-server-through-the-ui) | Proven | Real HTTP/PostgreSQL one-time first-administrator creation and closure plus Chromium managed-configuration coverage across audit/revision and live BNC state | — |
| [Explore accounts, channels, policy, and audit](administration-and-monitoring.md#explore-accounts-channels-policy-and-audit) | Proven | PostgreSQL/core/BNC/HTTP account authority and suspend-reactivate journey, directory/filter/action tests, and Chromium K-Line add/remove/audit proof | — |
| [Inspect and terminate live connections](administration-and-monitoring.md#inspect-and-terminate-live-connections) | Proven | Real core directory plus owner/admin exact-disconnect HTTP journeys | — |
| [Operate the network fleet](administration-and-monitoring.md#operate-the-network-fleet) | Proven | PostgreSQL admin fleet integration test (gating, inventory, CSRF toggle, persisted flip, audit row) | — |
| [Monitor traffic, connections, queue pressure, latency, availability, and errors](administration-and-monitoring.md#monitor-traffic-connections-queue-pressure-latency-availability-and-errors) | Proven | Queue/runtime telemetry, schema compatibility, PostgreSQL monitoring/history/audit/expired-bearer retention, console/JSON/Prometheus tests, and live Chromium inspection | External alerting is not part of e6irc |
| [Audit privileged changes](administration-and-monitoring.md#audit-privileged-changes) | Proven | Core audit events and atomic PostgreSQL mutation/audit tests | — |
| [Add and operate a bridge](bridges-clients-and-automation.md#add-and-operate-a-bridge) | Partially proven | All-feature management journey, live pinned Matrix oracle, and real-socket Discord/Slack HTTP+WebSocket protocol oracles in both directions | Live Discord/Slack provider qualification requires commercial credentials |
| [Use the scripting CLI](bridges-clients-and-automation.md#use-the-scripting-cli) | Proven | Real server/API/TLS/PLAIN/OAuth/device-cache/JSON executable journeys | — |
| [Use the terminal UI](bridges-clients-and-automation.md#use-the-terminal-ui) | Proven | Real pseudo-terminal/e6ircd journey plus duplex protocol, model, and fuzz tests | — |
| [Build another native client](bridges-clients-and-automation.md#build-another-native-client) | Proven | Shared-client tests plus CLI, TUI, load, TLS, and live-server consumers | — |
| [Automate the REST API](bridges-clients-and-automation.md#automate-the-rest-api) | Proven | Exact router/OpenAPI catalog and real HTTP/PostgreSQL resource-family tests | OpenAPI schemas remain hand-authored and directly tested |
| [Register and configure a channel](channels-and-account.md#register-and-configure-a-channel) | Proven | Core, PostgreSQL, services, console, and REST lifecycle tests | — |
| [Recreate a registered channel](channels-and-account.md#recreate-a-registered-channel) | Proven | Core recreation plus PostgreSQL boot-load tests | — |
| [Manage IRC credentials](channels-and-account.md#manage-irc-credentials) | Proven | Credential storage, console/API, and real-socket SASL tests | — |
| [Manage a private account profile](channels-and-account.md#manage-a-private-account-profile) | Proven | Typed email parser plus real PostgreSQL registration/privacy/audit and console mutation tests | — |
| [Manage personal access tokens and read state](channels-and-account.md#manage-personal-access-tokens-and-read-state) | Proven | Scoped/expiring token lifecycle, no-escalation/shared-rate HTTP, bearer/OAUTHBEARER, marker persistence, API, and console tests | — |
| [Inspect and terminate sessions](channels-and-account.md#inspect-and-terminate-sessions) | Proven | Owner-scoped browser/live-session inventory and exact-revocation tests | — |
| [Review security activity and export account data](channels-and-account.md#review-security-activity-and-export-account-data) | Proven | Owner-isolated PostgreSQL export/activity, real HTTP attachment, and Chromium recipient journey | — |
| [Permanently delete an account](channels-and-account.md#permanently-delete-an-account) | Proven | PostgreSQL succession/purge/retirement invariants plus real HTTP/core/BNC and Chromium self-deletion | — |
| [Discover service identity and readiness before sign-in](deployment-and-recovery.md#discover-service-identity-and-readiness-before-sign-in) | Proven | Real public server/liveness/readiness/login/OpenAPI HTTP tests | — |
| [First production boot](deployment-and-recovery.md#first-production-boot) | Proven | Actual daemon against an isolated empty PostgreSQL container proves migrations, import, readiness, and IRC traffic; CI also inspects the production image | — |
| [Deploy a release](deployment-and-recovery.md#deploy-a-release) | Proven | Six-platform builds, deterministic package test, image shape, and publication contract | Tag publication itself runs only for a matching release tag |
| [Restart without losing durable state](deployment-and-recovery.md#restart-without-losing-durable-state) | Proven | Chromium gracefully restarts the real daemon and proves session/network/runtime/backlog recovery | — |
| [Recover from PostgreSQL interruption](deployment-and-recovery.md#recover-from-postgresql-interruption) | Proven | Named PostgreSQL stop/start under real daemon, probe, database-backed HTTP, and hot IRC traffic proves bounded failure and recovery | — |
| [Back up and restore PostgreSQL](deployment-and-recovery.md#back-up-and-restore-postgresql) | Proven | Guarded shell contract plus real custom-format PostgreSQL archive, destructive proof mutation, transactional restore, and daemon reboot journey | External master-key/config backup storage remains the operator’s responsibility |
| [Recover from secret-key loss or rotation](deployment-and-recovery.md#recover-from-secret-key-loss-or-rotation) | Proven | Keyring/open/seal/wrong-key startup and CLI tests plus atomic PostgreSQL all-secret rotation/rollback/audit proof | Irrecoverable key loss still requires a key backup or explicit credential replacement |
| [Qualify high scale](deployment-and-recovery.md#qualify-high-scale) | Unproven | Exact-delivery 64-client CI gate, daemon RSS/connection threshold, lazy SendQ allocation, runtime N=2/N=3 routing, and recorded 2,000-client baselines | 100,000-client tuned-host result and production thresholds are absent |
| [Sign in with a local password](identity-and-access.md#sign-in-with-a-local-password) | Proven | Chromium adds a password, signs out, and completes real local login against e6ircd/PostgreSQL | — |
| [Sign in with OpenID Connect](identity-and-access.md#sign-in-with-openid-connect) | Proven | Real e6ircd, PostgreSQL, Dex, and Chromium plus exact Shauth journey | Provider diversity beyond Dex/Shauth |
| [Link or unlink an OpenID Connect identity](identity-and-access.md#link-or-unlink-an-openid-connect-identity) | Proven | Real Dex/PostgreSQL conflict and console/API lifecycle tests | — |
| [Join through an administrator invitation](identity-and-access.md#join-through-an-administrator-invitation) | Proven | Digest-only PostgreSQL lifecycle, real HTTP browser binding, and two-context Chromium acceptance | — |
| [Sign out locally and across an identity provider](identity-and-access.md#sign-out-locally-and-across-an-identity-provider) | Proven | Generic session/front/back-channel tests plus exact Shauth coordinated browser logout | Provider diversity beyond Dex/Shauth |
| [Authorize an input-constrained device](identity-and-access.md#authorize-an-input-constrained-device) | Proven | Real CLI through HTTP/PostgreSQL approval/consume to private cache and authenticated API | — |
| [Authenticate an IRC or BNC client](identity-and-access.md#authenticate-an-irc-or-bnc-client) | Proven | Real socket PLAIN/OAUTHBEARER/BNC routing tests plus CLI and terminal client paths | — |
| [Rotate and revoke access](identity-and-access.md#rotate-and-revoke-access) | Proven | Credential, token, session, exact connection, and coordinated-logout journeys | — |
| [Connect and register](irc-and-services.md#connect-and-register) | Proven | Real sockets, TLS, core/e2e, database, irctest, property, and fuzz tests | Public third-party server interop is separately opt-in |
| [Join and participate in a channel](irc-and-services.md#join-and-participate-in-a-channel) | Proven | Core integration and both irctest suites | — |
| [Send a direct message](irc-and-services.md#send-a-direct-message) | Proven | Core delivery and PostgreSQL participant authorization/pagination tests | — |
| [Resume history and synchronize read state](irc-and-services.md#resume-history-and-synchronize-read-state) | Proven | Core/PostgreSQL selector, restart, REST, native-client, and marker tests | — |
| [Register an account or channel through services](irc-and-services.md#register-an-account-or-channel-through-services) | Proven | Core services, persistence-backed irctest, PostgreSQL, and console/API tests | — |
| [Operate and protect the network through IRC](irc-and-services.md#operate-and-protect-the-network-through-irc) | Proven | Core operator/ban tests and atomic PostgreSQL policy/audit tests | — |
| [Connect through IRC-over-WebSocket](irc-and-services.md#connect-through-irc-over-websocket) | Proven | Real WebSocket protocol integration across supported framing modes | A third-party browser client is not driven |
| [Make network management available](networks-and-bouncer.md#make-network-management-available) | Proven | Configuration validation and live runtime listener management tests | — |
| [Add Libera Chat, OFTC, EFnet, Snoonet, or a custom IRC network](networks-and-bouncer.md#add-libera-chat-oftc-efnet-snoonet-or-a-custom-irc-network) | Partially proven | Chromium, Firefox, and WebKit verify exact preflight-before-create, PostgreSQL creation, and a local live driver; the Scaleway container registered and joined channels on OFTC and Ergo Testnet on 2026-08-23 | EFnet and Snoonet did not complete a deployed registration probe; Libera rejected the deployed IPv4 path without an existing verified SASL account |
| [Register and verify an upstream IRC account](networks-and-bouncer.md#register-and-verify-an-upstream-irc-account) | Proven | Closed API/unit contracts plus real-driver Chromium REGISTER/VERIFY, visible replies, secret redaction, sealed credential save, re-enable, SASL PLAIN, and rejoin | A third-party provider's actual email delivery and address policy remain provider-controlled |
| [Read the raw IRC protocol while it happens](networks-and-bouncer.md#read-the-raw-irc-protocol-while-it-happens) | Partially proven | The sidebar entry and its states are covered by the Chromium/Firefox/WebKit visual and axe accessibility suites; the parked-state guidance and the sensitive-command redaction classifier both have unit tests | No test drives a live upstream NickServ exchange and then reads it back off the tape; the closest real-driver evidence is the registration journey above |
| [Diagnose an upstream connection](networks-and-bouncer.md#diagnose-an-upstream-connection) | Proven | Runtime snapshot/error-ledger tests, bounded upstream registration diagnostics, terminal-send refusal, and Chromium transcript inspection | — |
| [Attach any IRC client to an owned network](networks-and-bouncer.md#attach-any-irc-client-to-an-owned-network) | Proven | Real listener/upstream/PostgreSQL authentication, routing, and refusal tests | — |
| [Persist and replay while detached or across restart](networks-and-bouncer.md#persist-and-replay-while-detached-or-across-restart) | Proven | Real PostgreSQL restart, trim, deletion, and wire-form tests | — |
| [Edit, pause, resume, or delete a network](networks-and-bouncer.md#edit-pause-resume-or-delete-a-network) | Proven | Console/API lifecycle, registry, race, and WebSocket detachment tests | — |
| [Enter chat and choose a network](web-chat.md#enter-chat-and-choose-a-network) | Proven | Chromium, Firefox, and WebKit cross authentication, inventory, PostgreSQL, registry, driver, and `/ws/ui` | Public-network interop remains opt-in |
| [Receive replay and live messages without gaps or duplicates](web-chat.md#receive-replay-and-live-messages-without-gaps-or-duplicates) | Proven | Deterministic three-engine edge cases plus real upstream/persistence/restart path | — |
| [Join, converse, and leave](web-chat.md#join-converse-and-leave) | Proven | Three-engine acknowledgement/refusal/lifecycle cases and real bidirectional upstream journey | — |
| [Personalize web chat and desktop notifications](web-chat.md#personalize-web-chat-and-desktop-notifications) | Proven | Client edge-case tests plus three-engine theme reload, explicit granted-permission boundary, exact notification, and opt-out over real upstream traffic | Operating-system presentation after the browser API is the platform’s responsibility |
| [Navigate account and operational surfaces](web-chat.md#navigate-account-and-operational-surfaces) | Proven | Three engines visit every administrator directory, run axe checks, verify reduced-motion monitoring, and perform configuration, credential, network, policy, monitoring, audit, and sign-out workflows; focused HTTP covers remaining mutations | — |

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
- CI builds all features together and each bridge independently, tests every
  supported operating-system/architecture cell, and runs bridge-management HTTP
  journeys against PostgreSQL with all features.
- The production container is built and inspected as a deployable artifact.

## Material qualification boundaries

### Browser-to-network acceptance

The Playwright suite contains both layers: deterministic browser-side
REST/history/WebSocket replacements for replay races and membership edge
states, and one complete local acceptance path through real console forms,
administrator directories and policy/audit actions, queue monitoring,
PostgreSQL, the registry, an IRC driver, a TCP upstream, `/ws/ui`, persistence,
operations diagnostics, graceful daemon restart, and session recovery.
Chromium, Firefox, and WebKit each run that complete path in isolated
PostgreSQL/Dex jobs; engine-specific request-cancellation text is normalized
without suppressing other console, page, or transport failures.

### Target-scale architecture

The daemon runs a configured nonzero number of core workers. Typed shard
ownership and runtime N=2/N=3 routing are proven, but production qualification
is not. The reduced CI run has numeric
catastrophic-regression thresholds, but there are no production-host acceptance
thresholds, production-qualified per-connection RSS budget, or 100k result.
The Linux smoke enforces a deliberately generous incremental RSS/connection
ceiling. The controlled harness records source, executable, host, workload,
budget, phase, and closed-outcome evidence for stricter tuned-host campaigns.

### Native-client product parity

The CLI implements device login, a private origin-bound token cache, bounded
HTTP/HTTPS, structured tail output, TLS, PLAIN/OAUTHBEARER, history, and
failure-sensitive one-shot commands. The TUI consumes the shared cache, loads
marker-relative history, maintains scrollback-aware shared read
positions/unread state, exposes route and connection state, retains refused
commands for correction, and rejoins confirmed channels. The real
pseudo-terminal journey protects both the terminal boundary and the shipped
relay-desk framing. One TUI process intentionally presents buffers for one
attached network; the BNC is the cross-network multiplexer.

### External bridges and public networks

Matrix has a self-hosted CI oracle. Discord and Slack have strict local
provider oracles that exercise their production HTTP/WebSocket clients in both
directions, but qualification against the commercial services still requires
real credentials. Public-network probes are respectful, opt-in, and record
their evidence. Local oracle success is not provider qualification.

### Distribution and operations

Source portability and multi-architecture containers are proven. The
repository ships a validated hardened systemd unit; every published
architecture image has signed build provenance and an SPDX SBOM attestation,
and the assembled manifest has signed provenance. Matching version tags publish
the daemon, CLI, and TUI for the same six native targets in deterministic
archives with per-archive build provenance and SHA-256 checksums. Musl/static
images and an external alerting stack are outside the shipped distribution.

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
| `coverage` | all-feature workspace line-coverage regression floor |
| `db-tests` | real PostgreSQL storage/all-feature HTTP bridge management/OIDC/browser/BNC/`ws_ui`/CLI journeys |
| `postgres-recovery` | isolated empty PostgreSQL first boot plus live stop/start degradation and recovery under HTTP and IRC traffic |
| `production-container` | deployable image and embedded web-client shape |
| `load-smoke` | real daemon with 64 clients, eight channels, duplicate-proof exact fan-out, generous numeric thresholds, and graceful shutdown |
| `native-client-journeys` | deterministic archive contract plus real PTY render/message/terminal-restore journey |
| `shauth-sso` | exact external single-sign-on/logout integration |
| `irctest`, `irctest-services` | IRC and services conformance |
| `matrix-bridge` | bidirectional live bridge behavior |
| `loom` | queue concurrency interleavings |
| `fuzz-smoke` | parser, serializer, stateful core, multi-client core, and hostile TUI server output |
| `size-report` | informational release binary-size visibility |

The `Release image and native archives` workflow publishes direct amd64/arm64
images, verifies the assembled manifest, emits signed build/SBOM attestations,
verifies those attestations as a consumer, and prunes complete old image
groups. On a matching version tag it also builds all six native targets,
attests each deterministic archive, checks that the complete six-file set
arrived, writes sorted SHA-256 checksums, and creates the GitHub release.

The PostgreSQL BNC and `/ws/ui` ignored integration suites belong in
`db-tests`; the workflow invokes them explicitly. “Ignored” in their source
means they need the supplied database environment, not that CI may omit them.
