# e6irc plan

The product has IRC, PostgreSQL, accounts, `/api/v1`, OpenID Connect, BNC, web
chat, native clients, Matrix, and an API-first console. CI tests all supported
platforms, browsers, PostgreSQL, recovery, containers, fuzzing, and load smoke.

## Completion

Complete means: one API contract; usable browser chat and console; API and
browser evidence for shipped workflows; and measured release, recovery, scale,
and integration claims.

## Current work

### Console and browser evidence

- Keep shared tokens, responsive layouts, focus, reduced motion, forced colors,
  loading, empty, denied, retry, and committed states consistent.
- Make destructive actions explicit and reversible until confirmation. Never
  discard edited input on cancellation or request failure.
- Add deterministic tests for navigation, focus, recovery, and offline states.
- Add accessibility checks, visual review, and failed-run diagnostics for
  shared components and essential workflows.

### API boundary

Keep OpenAPI, [API-first inventory](docs/api-first-inventory.md), fixtures,
and compatibility tests synchronized. Put new validation and durable mutations
behind typed API/core boundaries.

### Product qualification

- Publish and test a client capability matrix; finish or narrow service and
  public-network interoperability claims.
- Define hardware budgets and run reproducible tuned-Linux scale campaigns.
- Qualify Discord, Slack, more identity providers, upgrade/rollback, backup,
  restore, and release artifacts with controlled environments.

## Rules

- One open pull request.
- Fix discovered defects in the active change or ask for a decision.
- Keep this file current; detailed contracts belong in code and journeys.
