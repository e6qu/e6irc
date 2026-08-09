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

- Complete typed cross-shard channel ownership. JOIN, PART, QUIT, KICK, TOPIC,
  single-line messages, TAGMSG, batches/multiline, KNOCK, and INVITE route to
  the channel owner. Nick reservations are process-wide and atomically claimed.
  MODE reads and list queries route to the owner; MODE mutations, remaining
  channel queries, services, history, persistence callbacks, and HTTP controls
  still need the same boundary.
- Prove multi-worker ordering, failure, backpressure, persistence, API, and
  load behavior before enabling production N>1 workers.
- Run reproducible tuned-Linux scale campaigns before making scale claims.

## Remaining qualification

- Run controlled external qualification for Discord, Slack, additional identity
  providers, and public IRC networks.

## Rules

- One open pull request.
- Fix discovered defects in the active change or ask for a decision.
- Keep this file current; detailed contracts belong in code and journeys.
