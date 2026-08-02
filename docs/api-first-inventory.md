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
| `/console/account/profile` | `PATCH /api/v1/me/profile` | Mapped | Render and submit the profile editor through this resource. |
| `/console/account/delete` | `DELETE /api/v1/me/account` | Mapped | Preserve exact-name confirmation and post-delete session handling. |
| `/console/account/app-passwords` | `POST /api/v1/auth/app-passwords` | Mapped | Return the one-time secret only through the API response. |
| `/console/account/password` | `PUT /api/v1/me/password` | Mapped | Preserve current-password and confirmation validation. |
| `/console/account/app-passwords/{id}/delete` | `DELETE /api/v1/me/credentials/{id}` | Mapped | Keep primary-password refusal explicit. |
| `/console/account/tokens` | `POST /api/v1/me/tokens` | Mapped | Preserve closed scopes and one-time bearer display. |
| `/console/account/tokens/{id}/delete` | `DELETE /api/v1/me/tokens/{id}` | Mapped | Refresh only after committed revocation. |
| `/console/account/identities/{id}/delete` | `DELETE /api/v1/me/identities/{id}` | Mapped | Preserve linked-session revocation behavior. |
| `/console/my-sessions/browser/{id}/delete` | `DELETE /api/v1/me/sessions/{id}` | Mapped | Clear the current cookie when its own session is revoked. |
| `/console/my-sessions/browser/others/delete` | `DELETE /api/v1/me/sessions?except=current` | Mapped | Use the atomic selector; do not emulate it with a racy client loop. |
| `/console/my-sessions/{id}/disconnect` | `DELETE /api/v1/me/connections/{id}` | Mapped | Keep owner scope and immutable connection ID. |

## Registered channels

| Console mutation | Canonical API operation | State | Migration requirement |
|---|---|---|---|
| `/console/channels/register` | `POST /api/v1/me/channels` | Mapped | Use the API's live-core admission verdict. |
| `/console/channels/topic` | `PATCH /api/v1/me/channels/{name}` | Mapped | Represent topic as an explicit typed patch field. |
| `/console/channels/keeptopic` | `PATCH /api/v1/me/channels/{name}` | Mapped | Represent the policy toggle as an explicit typed patch field. |
| `/console/channels/mlock` | `PATCH /api/v1/me/channels/{name}` | Mapped | Return canonical mode-lock spelling. |
| `/console/channels/access` | `PUT /api/v1/me/channels/{name}/access/{account}` | Mapped | Preserve owner/founder authorization and closed flags. |
| `/console/channels/access/delete` | `DELETE /api/v1/me/channels/{name}/access/{account}` | Mapped | Refresh from committed access state. |
| `/console/channels/founder` | `PATCH /api/v1/me/channels/{name}` | Mapped | Preserve irreversible founder-transfer confirmation. |
| `/console/channels/drop` | `DELETE /api/v1/me/channels/{name}` | Mapped | Preserve explicit destructive confirmation. |
| `/console/admin/channels/drop` | `DELETE /api/v1/admin/channels/{name}` | Gap | Add an administrator-scoped audited unregister resource. |

## Owner networks and bridges

| Console mutation | Canonical API operation | State | Migration requirement |
|---|---|---|---|
| `/console/networks` | `POST /api/v1/me/networks` | Mapped | Use one typed network/bridge creation schema. |
| `/console/networks/preflight` | `POST /api/v1/me/networks/preflight` | Mapped | Keep preflight non-persistent and distinguish it from creation. |
| `/console/networks/{name}/edit` | `PUT /api/v1/me/networks/{name}` | Mapped | Preserve typed secret `keep`/`set`/`remove` behavior. |
| `/console/networks/{name}/delete` | `DELETE /api/v1/me/networks/{name}` | Mapped | Surface durable/runtime teardown outcomes. |
| `/console/networks/{name}/toggle` | `PATCH /api/v1/me/networks/{name}` | Mapped | Use an explicit enabled-state patch. |
| `/console/integrations` | `POST /api/v1/me/networks` | Mapped | Bridge creation uses the generic typed network resource. |
| `/console/integrations/{name}/edit` | `PUT /api/v1/me/networks/{name}` | Mapped | Keep platform-specific fields inside the closed network-kind schema. |
| `/console/integrations/delete` | `DELETE /api/v1/me/networks/{name}` | Mapped | Preserve bridge teardown and buffer handling. |
| `/console/integrations/toggle` | `PATCH /api/v1/me/networks/{name}` | Mapped | Use the same lifecycle transition as IRC networks. |

## Administrator accounts, policy, and live controls

| Console mutation | Canonical API operation | State | Migration requirement |
|---|---|---|---|
| `/console/accounts/create` | `POST /api/v1/admin/accounts` | Mapped | Preserve local-password and authority validation. |
| `/console/accounts/invitations` | `POST /api/v1/admin/invitations` | Mapped | Return invitation bearer material once. |
| `/console/accounts/invitations/{id}/delete` | `DELETE /api/v1/admin/invitations/{id}` | Mapped | Preserve immutable invitation scope. |
| `/console/accounts/{id}/delete` | `DELETE /api/v1/admin/accounts/{id}` | Mapped | Preserve succession and last-administrator protection. |
| `/console/accounts/{id}/suspension` | `PATCH /api/v1/admin/accounts/{id}` | Mapped | Return the committed suspension posture. |
| `/console/accounts/{id}/administrator` | `PATCH /api/v1/admin/accounts/{id}` | Mapped | Return durable/effective authority distinctly. |
| `/console/admin/networks/{owner}/{name}/toggle` | `PATCH /api/v1/admin/networks/{owner}/{name}` | Gap | Add an administrator-scoped audited lifecycle patch. |
| `/console/bans` | `POST /api/v1/admin/bans` | Gap | Add typed audited K/D/X-line creation. |
| `/console/bans/delete` | `DELETE /api/v1/admin/bans/{id-or-key}` | Gap | Choose one immutable identifier and preserve casefolded removal semantics. |
| `/console/sessions/{id}/disconnect` | `DELETE /api/v1/admin/connections/{id}` | Mapped | Keep exact immutable-ID disconnect semantics. |

## Managed configuration

| Console mutation | Canonical API operation | State | Migration requirement |
|---|---|---|---|
| `/console/configuration` | `GET/PATCH /api/v1/admin/configuration` | Gap | Add revisioned configuration read and compare-and-swap write. |
| `/console/configuration/opers` | `POST /api/v1/admin/configuration/opers` | Gap | Add typed operator creation inside the revisioned configuration contract. |
| `/console/configuration/opers/delete` | `DELETE /api/v1/admin/configuration/opers/{name}` | Gap | Preserve configuration revision/audit provenance. |
| `/console/configuration/oidc` | `POST /api/v1/admin/configuration/oidc-providers` | Gap | Keep provider secret fields write-only. |
| `/console/configuration/oidc/delete` | `DELETE /api/v1/admin/configuration/oidc-providers/{name}` | Gap | Preserve revision/audit provenance. |
| `/console/configuration/shared-networks` | `POST /api/v1/admin/configuration/networks` | Gap | Use the same closed network-kind schema as owner resources. |
| `/console/configuration/shared-networks/delete` | `DELETE /api/v1/admin/configuration/networks/{name}` | Gap | Preserve revision/audit provenance. |

## Read-only console views

The following console views already have a principal API data source and move
with their owning domain: overview (`/api/v1/admin/stats`), account and policy
directories, audit (`/api/v1/admin/audit`), monitoring
(`/api/v1/admin/observability` and `/api/v1/admin/metrics`), owner networks,
network buffers, owner sessions/connections, and administrator connections.
Configuration and per-network operations require their read contracts to land
with the gaps above before their rendered views can retire.

## Mechanical coverage

`tools/check-api-first-inventory.py` extracts every `/console` route with a
`console_*` mutation handler from the router and requires one table row here.
Adding, removing, or renaming a console mutation therefore requires updating
this migration inventory in the same change.
