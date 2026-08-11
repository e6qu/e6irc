# e6irc plan

The product has IRC, PostgreSQL, accounts, `/api/v1`, OpenID Connect, BNC, web
chat, native clients, Matrix, and an API-first console. CI tests all supported
platforms, browsers, PostgreSQL, recovery, containers, fuzzing, and load smoke.

## Completion

Complete means: one API contract; usable browser chat and console; API and
browser evidence for shipped workflows; and measured release, recovery, scale,
and integration claims.

## Current state

The console reads and writes only through `/api/v1`. Browser chat and console
load the served OpenAPI contract and parse each successful API response into a
closed immutable projection before a view uses it. Browser chat parses each UI
WebSocket event into its closed
shape before handling it and serializes each composer request from its closed
shape before sending it. Immutable console mutation operations are checked
against the router. Successful mutations refresh their API-backed view without
a document reload.
External qualification has one manual GitHub workflow. It selects one closed
campaign, refuses local provider oracles, and uploads only evidence accepted by
the runner verifier.

## Remaining qualification

- Run the shipped credential-gated campaigns for Discord, Slack, each required
  OpenID Connect issuer, and public IRC networks.
- Run the tuned-host scale campaign. It remains required for production scale
  claims.

## Rules

- One open pull request.
- Fix discovered defects in the active change or ask for a decision.
- Keep this file current; detailed contracts belong in code and journeys.
