# API-first inventory

The public contract is `/api/v1/openapi.json`.

## Boundary

`/login`, `/bootstrap`, invitations, sign-out, and static asset delivery are
document/navigation boundaries. They may render HTML or redirect because they
establish or end browser state. Every authenticated product read and mutation
belongs to `/api/v1`; HTML shells must use those API contracts rather than a
parallel console handler.

The console is a document shell. Authenticated reads and mutations use
`/api/v1`; it has no mutation routes. `tools/check-api-first-inventory.py`
fails CI if one is added. Console mutations are immutable, declared
method/path operations. The gate checks each operation against the router.

Console reads load `/api/v1/openapi.json` once and parse the documented success
response into a closed immutable projection before rendering. The OpenAPI test
requires a closed JSON schema for each console read.
