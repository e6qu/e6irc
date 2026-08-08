# e6irc plan

Terms are defined in [docs/terminology.md](docs/terminology.md). Product
contracts and evidence live in [docs/journeys](docs/journeys/README.md);
architecture and invariants live in [DESIGN.md](DESIGN.md).

## Status

Core IRC, persistence, accounts, REST, OpenID Connect, BNC, web chat, native
clients, Matrix, and API-first console migration are implemented and covered by
CI. Discord and Slack have deterministic transport coverage but require real
provider credentials for qualification. The 100k single-host target is not
qualified: the harness exists, but production hardware budgets and a tuned-host
campaign do not.

## Completion standard

The product is complete only when:

- `/api/v1` is the sole dynamic client contract, with shared authorization,
  validation, error, audit, and durable/core paths.
- Browser chat and console are responsive, keyboard and screen-reader usable,
  and intentionally designed across roles and viewports.
- Each shipped workflow has API evidence plus browser evidence where browser
  behavior matters.
- Release, recovery, scale, and advertised third-party integration claims have
  measured qualification evidence.

## Active program

### A. API-first boundary

The mutable-console inventory is complete in
[docs/api-first-inventory.md](docs/api-first-inventory.md). All console reads
and mutations use canonical resources; rendered mutation handlers are removed.
Required browser collections are parsed at the boundary, so malformed successful
responses are retryable contract failures, never empty state.

Remaining work:

1. Keep OpenAPI, route inventory, fixtures, and compatibility tests in lockstep.
2. Replace any newly discovered UI-only validation or state with typed API/core
   boundaries.
3. Keep browser request, CSRF, problem, retry, and committed-result behavior in
   one client path.

### B. Console product quality

Console shells hydrate from API data and retain explicit loading, empty,
permission-denied, retryable-failure, and success states. Navigation, themes,
focus, reduced motion, forced colors, and narrow layouts have baseline browser
coverage.

Remaining work:

1. Establish reusable semantic design tokens and component patterns.
2. Make dense operator directories searchable, filterable, responsive, and
   safe for destructive actions without overwriting in-progress edits.
3. Test desktop, tablet, phone, high-zoom, reduced-motion, and forced-colors
   behavior for every essential task.

### C. Browser and API evidence

API contracts are the primary proof of domain behavior. Chromium, Firefox, and
WebKit journeys cover authentication, browser-only state, WebSocket attachment,
and durable effects.

Remaining work:

1. Add deterministic component/state tests for navigation, focus, offline, and
   recovery paths.
2. Add reviewed visual baselines and automated accessibility checks for shared
   components and critical pages.
3. Retain traces, screenshots, console logs, and network logs for failed
   browser runs.

### D. Client and protocol parity

Browser, CLI, TUI, and IRC capability boundaries must be explicit and tested.

Remaining work:

1. Publish and test a client capability matrix.
2. Complete or explicitly narrow NickServ/ChanServ compatibility.
3. Qualify durable direct-message history and controlled public-network/client
   interoperability.

### E. Operational and scale qualification

The load harness, recovery tests, metrics, and container artifacts exist; they
are not a production-scale qualification.

Remaining work:

1. Define hardware profiles and budgets for throughput, latency, memory,
   descriptors, queue pressure, recovery, and shutdown.
2. Run reproducible tuned-Linux campaigns, publishing inputs and results.
3. Add sharding, timer, replay, and queue changes only when measurements show
   they are required.
4. Exercise failure, backup, restore, upgrade, rollback, and incident runbooks.

### F. External integration and release qualification

Matrix has a self-hosted oracle. Discord and Slack require controlled live
tenants; OpenID Connect needs a maintained provider matrix.

Remaining work:

1. Qualify Discord and Slack with dedicated credentials, lifecycle controls,
   rate-limit/reconnect evidence, and safe diagnostics.
2. Qualify identity providers beyond Dex and Shauth, including logout and JWKS
   rotation.
3. Verify upgrade/rollback compatibility and release gates across artifacts,
   API compatibility, accessibility, recovery, and operator documentation.

## Governance

- One open pull request; each PR is a coherent vertical slice with tests and
  documentation.
- Fix discovered defects in the active change or ask the human for a decision.
- Update this plan only for current status and active work. Code, tests,
  `DESIGN.md`, and journey documents are the authoritative detailed record.
