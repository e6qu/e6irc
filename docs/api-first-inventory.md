# API-first inventory

This is the Stage A inventory for the API-first product-completion program in
[`PLAN.md`](../PLAN.md). It is a migration control, not API documentation:
the public contract remains `/api/v1/openapi.json`.

## Boundary

`/login`, `/bootstrap`, invitations, sign-out, and static asset delivery are
document/navigation boundaries. They may render HTML or redirect because they
establish or end browser state. Every authenticated product read and mutation
belongs to `/api/v1`; HTML shells must use those API contracts rather than a
parallel console handler.

The table below covers every router entry that invokes a `console_*` mutation
handler. `Mapped` means an API operation already represents the same product
transition, although the console still reaches its own handler today. `Gap`
means that the canonical API operation must be introduced before that handler
can be removed. `Composite` means an API client can compose existing resources,
but an explicit atomic/bulk API contract is needed to preserve the console
operation's semantics.

## Account and identity

| Console mutation | Canonical API operation | State | Migration requirement |
|---|---|---|---|

## Registered channels

| Console mutation | Canonical API operation | State | Migration requirement |
|---|---|---|---|
| `/console/admin/channels/drop` | `DELETE /api/v1/admin/channels/{name}` | Mapped | Use the administrator-scoped audited unregister resource. |

## Owner networks and bridges

| Console mutation | Canonical API operation | State | Migration requirement |
|---|---|---|---|

## Administrator accounts, policy, and live controls

| Console mutation | Canonical API operation | State | Migration requirement |
|---|---|---|---|

## Managed configuration

The Configuration document is a read-only shell: it hydrates all managed
settings, credential metadata, revision/provenance, and secret-free runtime
status from `GET /api/v1/admin/configuration`. Its scalar settings, operators,
OpenID Connect providers, and server networks all mutate only via administrator
API routes; the former `/console/configuration/*` mutation routes no longer
exist.

## Read-only console views

The following console views already have a principal API data source and move
with their owning domain: overview (the bounded administrator stats and
directory resources), account and policy
directories, audit (`/api/v1/admin/audit`), monitoring
(`/api/v1/admin/observability`, `/api/v1/admin/monitoring`, and
`/api/v1/admin/metrics`), owner networks and per-network Operations,
network buffers, owner sessions/connections, administrator connections, and
managed configuration.

## Mechanical coverage

`tools/check-api-first-inventory.py` extracts every `/console` route with a
`console_*` mutation handler from the router and requires one table row here.
Adding, removing, or renaming a console mutation therefore requires updating
this migration inventory in the same change.
