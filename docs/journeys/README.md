# User journeys

This directory is the product-level map of e6irc. `DESIGN.md` defines the
system contracts and architecture; these documents describe what a person or
calling system is trying to accomplish, every component crossed on the way,
the visible failure behavior, and the automated evidence that protects the
journey.

The unit of documentation is an outcome, not a page or endpoint. A journey can
therefore cross browser pages, REST, WebSocket, IRC, the multiplexer, an
external network, PostgreSQL, and a restart. That is deliberate: testing each
piece in isolation does not prove the outcome a user experiences.

## Actors and entry points

| Actor | Primary entry points | Authentication |
|---|---|---|
| Visitor | `/login`, `/healthz`, `/readyz`, `/api/v1/server` | None |
| Account holder | Web client, self-service console, IRC, BNC listener | Browser session, SASL PLAIN/OAUTHBEARER, app password, or personal access token |
| Channel founder | IRC services, registered-channel console/API | Account authentication plus founder/access checks |
| IRC operator | IRC operator commands | `OPER` against managed operator configuration |
| Administrator | Operational console and `/api/v1/admin/*`, including exact live-connection control | Account in the configured administrator set |
| Native-client user | `e6irc`, `e6irc-tui`, or another client using `e6irc-client` | The capabilities exposed by that binary; these differ today |
| Automation/device client | REST API and RFC 8628 device authorization endpoints | Personal access token or an approved device token |
| Bridge operator | Integrations console and managed network configuration | Administrator session |
| Deployer/operator | `e6ircd`, migrations, container, probes, logs, metrics | Host/container and database access |

## Journey catalog

| Area | Journeys |
|---|---|
| [Identity and access](identity-and-access.md) | local login, OpenID Connect login and linking, device authorization, logout, password/token/session lifecycle |
| [IRC and services](irc-and-services.md) | registration, capability negotiation, channel and direct chat, history, read markers, services, operator actions, WebSocket IRC |
| [Web chat](web-chat.md) | enter the application, choose a network, live chat, replay/history, membership state, disconnect and recovery |
| [Networks and BNC](networks-and-bnc.md) | enable the registry/listener, add a preset or custom network, connect and diagnose, attach an IRC client, persist/replay, edit/pause/delete |
| [Channels and account self-service](channels-and-account.md) | register and govern a channel, manage credentials/identities, inspect and terminate sessions |
| [Administration and monitoring](administration-and-monitoring.md) | bootstrap and managed configuration, directories and policy, traffic/latency/error monitoring, audit, readiness |
| [Bridges, clients, and automation](bridges-clients-and-automation.md) | local/Matrix/Discord/Slack networks, CLI, TUI, client library, REST automation |
| [Deployment and recovery](deployment-and-recovery.md) | first boot, migration, container release, restart, shutdown, secret loss, dependency failure |
| [Coverage and product boundaries](coverage.md) | journey-to-test traceability, test layers, external qualification, and claims that are targets rather than shipped behavior |

## Status vocabulary

Every journey uses one of four evidence states:

- **Proven** — CI drives the complete outcome across the relevant process or
  protocol boundary. Supporting unit tests may exist, but they are not the
  reason for this label.
- **Partially proven** — CI proves important components, but a user-visible
  boundary is replaced by a mock or tested separately.
- **Externally qualified** — the repository contains an opt-in procedure or
  probe whose faithful environment or credentials cannot be supplied by normal
  CI.
- **Unproven** — the implementation exists, but no automated test establishes
  the full user outcome.

“Proven” is intentionally stricter than “has tests.” For example, browser
tests that replace `/ws/ui` and network APIs with browser-side mocks prove the
chat state machine and rendering, but do not prove browser → server → BNC
driver → upstream delivery.

## Contract common to every journey

All journeys inherit the engineering laws in `DESIGN.md` §2:

1. A requested action either succeeds or produces a visible, specific failure.
   It must not silently become a different action.
2. Authentication and authorization are checked at the boundary and again
   where owner-scoped state is selected.
3. User-controlled text, identifiers, endpoints, and secrets remain untrusted
   at every boundary.
4. Collections, queues, history, request bodies, and directory queries are
   bounded.
5. Mutations that cross storage and runtime state preserve atomicity or expose
   the exact partial failure; they never report success for a configuration
   the runtime did not adopt.
6. Secrets do not appear in list responses, rendered pages, logs, audit
   details, metric labels, or persisted plaintext.
7. Each failure has operational evidence: a response/problem, IRC numeric or
   `FAIL`, a bounded error category/counter, and where appropriate an audit
   record.

## Maintaining this corpus

When behavior changes, update the corresponding journey and its row in
`coverage.md` in the same change. A new public route, console workflow, IRC
command family, client command, bridge kind, or deployment mode is incomplete
until its actor, success result, failure contract, and test evidence are
represented here.

Historical implementation detail remains in `PLAN.md`; it is not a substitute
for this current-state map.
