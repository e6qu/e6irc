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

- The daemon runs a configured nonzero number of core workers (default 1).
  Runtime N=2/N=3 tests cover ownership, routing, delivery, and shutdown.
- Controlled Linux campaigns record source, executable, host, workload,
  configured worker count, budgets, and a closed passed/rejected/failed outcome.
  Tuned-host campaigns remain required before scale claims.

## Remaining qualification

- Run credential-gated external campaigns and retain their evidence for
  Discord, Slack, additional identity providers, public IRC networks, and a
  tuned host. Local contracts are not external qualification.

## Rules

- One open pull request.
- Fix discovered defects in the active change or ask for a decision.
- Keep this file current; detailed contracts belong in code and journeys.
