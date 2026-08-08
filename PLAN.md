# e6irc plan

The product has IRC, PostgreSQL, accounts, `/api/v1`, OpenID Connect, BNC, web
chat, native clients, Matrix, and an API-first console. CI tests all supported
platforms, browsers, PostgreSQL, recovery, containers, fuzzing, and load smoke.

## Completion

Complete means: one API contract; usable browser chat and console; API and
browser evidence for shipped workflows; and measured release, recovery, scale,
and integration claims.

## Remaining qualification

- Publish and test a client capability matrix; finish or narrow service and
  public-network interoperability claims.
- Define hardware budgets and run reproducible tuned-Linux scale campaigns.
- Qualify Discord, Slack, more identity providers, upgrade/rollback, backup,
  restore, and release artifacts with controlled environments.

## Rules

- One open pull request.
- Fix discovered defects in the active change or ask for a decision.
- Keep this file current; detailed contracts belong in code and journeys.
