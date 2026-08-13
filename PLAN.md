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
load the served OpenAPI contract, parse each successful API response into a
closed immutable projection, and serialize each JSON mutation from its closed
request shape before a view uses or sends it. Browser chat parses each UI
WebSocket event into its closed
shape before handling it and serializes each composer request from its closed
shape before sending it. Immutable console mutation operations are checked
against the router. Successful mutations refresh their API-backed view without
a document reload.
Chat, console, and identity pages share accessible light and dark palettes.
Browser tests cover WCAG AA contrast, keyboard focus, Escape dismissal,
reduced motion, forced colors, and responsive chat controls.
External qualification has one manual GitHub workflow. It selects one closed
campaign, refuses local provider oracles, and uploads only evidence accepted by
the runner verifier.
The current qualification runner passed live public IRC campaigns for
Libera.Chat, OFTC, and Ergo on 2026-08-13. The console has a bounded,
owner-scoped component-log view backed by the same API buffer for IRC and every
bridge driver.

## Remaining qualification

- Run the shipped credential-gated campaigns for Discord, Slack, and each
  required OpenID Connect issuer.
- Run the tuned-host scale campaign. It remains required for production scale
  claims.

## Rules

- One open pull request.
- Fix discovered defects in the active change or ask for a decision.
- Keep this file current; detailed contracts belong in code and journeys.
