# e6irc plan

The product has IRC, PostgreSQL, accounts, `/api/v1`, OpenID Connect, BNC, web
chat, native clients, Matrix, and an API-first console. CI tests all supported
platforms, browsers, PostgreSQL, recovery, containers, fuzzing, and load smoke.

## Completion

Complete means: one API contract; usable browser chat and console; API and
browser evidence for shipped workflows; and measured release, recovery, scale,
and integration claims.

## Current work

### Stage F — Scale architecture and qualification

- The daemon runs one core worker. Deterministic two-worker tests prove typed
  ownership/routing, ordering, backpressure, persistence verdicts, disconnected
  requesters, and owner API controls.
- Controlled Linux campaigns record source, executable, host, workload,
  budgets, and a closed passed/rejected/failed outcome. Runtime N>1 startup and
  tuned-host campaigns remain required before scale claims or enablement.

## Remaining qualification

- Run controlled external qualification for Discord, Slack, additional identity
  providers, and public IRC networks.

## Rules

- One open pull request.
- Fix discovered defects in the active change or ask for a decision.
- Keep this file current; detailed contracts belong in code and journeys.
