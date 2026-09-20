# API-first inventory

The public contract is `/api/v1/openapi.json`.

## Boundary

`/login`, `/bootstrap`, invitations, sign-out, and static asset delivery are
document/navigation boundaries. They may render HTML or redirect because they
establish or end browser state. Every authenticated product read and mutation
belongs to `/api/v1`; HTML shells must use those API contracts rather than a
parallel console handler.

The console is a document shell. Authenticated reads and mutations use
`/api/v1`; it has no mutation routes. A console operation is a method and a URL
built where it is sent, and each one is matched against the served
`/api/v1/openapi.json` — operation, path, query, and request body — before the
request leaves the browser.

`tools/check-api-first-inventory.py` checks the same thing statically, against
the router's route table, and fails CI when:

- `console.js` states a method and URL together — `apiMutation("METHOD", URL)`,
  `apiRead(URL)`, or a `mutate…(form, URL, "METHOD", …)` wrapper call — that
  the route table does not document. A template-literal URL is compared with
  each `${…}` segment standing for a route parameter;
- any `/api/v1` URL literal in `console.js` is not a documented route;
- an API-marked console form's `action` is not a route with a documented
  mutation, is outside `/api/v1`, or names a handler `console.js` does not have;
- an `apiMutation`/`apiOperation` call whose method or URL is a variable is
  not in the script's counted allow-list, which gives the reason each such
  site is covered elsewhere — so a new unresolvable site fails the gate;
- no operation at all is extracted, so the check can never pass by seeing
  nothing;
- the router gains a POST route under `/console`, `console.js` calls
  `window.location.reload`, or it sends an API request that is not a declared
  operation value.

Browser chat and console load `/api/v1/openapi.json` once and parse each
documented success response into a closed immutable projection before rendering.
The OpenAPI tests require a closed JSON schema for each browser read and console
JSON mutation.
