# e6irc plan

The product has IRC, PostgreSQL, accounts, `/api/v1`, OpenID Connect, BNC, web
chat, native clients, Matrix, and an API-first console. CI tests all supported
platforms, browsers, PostgreSQL, recovery, containers, fuzzing, and load smoke.

## Completion

Complete means: one API contract; usable browser chat and console; API and
browser evidence for shipped workflows; and measured release, recovery, scale,
and integration claims.

## Current work

### Stage E — Compatibility qualification

- Publish a checked client capability matrix and keep public-network claims
  within their evidence.
- Qualify or narrow service, identity-provider, and public-network claims.

## Remaining qualification

- Define hardware budgets and run reproducible tuned-Linux scale campaigns.
- Run controlled external qualification for Discord, Slack, additional identity
  providers, and public IRC networks.

## Rules

- One open pull request.
- Fix discovered defects in the active change or ask for a decision.
- Keep this file current; detailed contracts belong in code and journeys.
