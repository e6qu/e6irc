# Administration and monitoring journeys

## Bootstrap and manage the server through the UI

**Actor and goal.** A deployer supplies only secrets/boot-critical values; an
administrator then configures the service through **Configuration**.

**Preconditions.** PostgreSQL and the HTTP listener can start from bootstrap
configuration. Either administrator authority already exists, or the empty
account store is paired with a 32–512-byte one-time bootstrap token. The
deployment supplies a stable master key before importing credentials.

**Flow.**

1. Bootstrap TOML/environment supplies PostgreSQL, secret-key source, initial
   HTTP bind/public URL/revision, and either static administrator grants or a
   one-time first-administrator token.
2. On an empty account store, `/login` links to `/bootstrap`. The deployer
   submits the token, account name, and confirmed primary password through an
   expiring browser-state-bound form. One transaction creates the account,
   durable administrator flag, credential, and audit row, then signs the new
   administrator in.
3. Any existing account closes `/bootstrap` permanently and removes its login
   link. The deployment removes the bootstrap token after initialization.
4. Migrations run; the first successful boot validates and imports a managed
   configuration snapshot with provenance.
5. Later starts load the persisted revision before constructing the core and
   listeners.
6. The administrator edits identity, IRC listeners, BNC attach listener,
   public URL/cookie/admin access, capacity, monitoring retention, durable
   history/audit retention, registration, server/shared networks, IRC
   operators, and OpenID Connect providers.
7. A compare-and-swap revision prevents two browser tabs from overwriting each
   other. The response distinguishes live-applied values from
   restart-required values.

**Visible failures and recovery.** Unknown bootstrap keys, invalid values,
missing/invalid bootstrap token, mismatched password confirmation, a consumed
bootstrap, stale revisions, listener bind errors, provider validation errors,
and database errors fail explicitly. A failed bootstrap creates no partial
account or authority. A failed stale write creates no audit row. A failed BNC
rebind preserves the working listener.

**Security and observability.** Bootstrap is per-IP rate-limited, binds an
expiring `HttpOnly; SameSite=Strict` browser state, compares only a retained
token digest in constant time, and atomically audits the first administrator.
The configuration page is administrator-only and every form is session-CSRF
protected. Credential fields are sealed and write-only, revisions record
provenance, and successful writes create a redacted audit row in the same
transaction.

**Evidence.** The real HTTP/PostgreSQL bootstrap journey proves invalid-token
rejection, atomic first-administrator creation, immediate administrator access,
and permanent route closure; database concurrency tests prove only one first
account can win. Configuration validation and import/revision behavior are
covered by unit/PostgreSQL tests, and BNC listener management is
HTTP/runtime-tested.
The real Chromium/PostgreSQL journey signs in as the configured administrator,
edits representative values in every scalar subsection, checks the live BNC
listener and retained revision, then creates and removes a server network, IRC
operator, and OpenID Connect provider. It verifies exact revision increments
and that write-only credentials never reappear as rendered plaintext.
The managed-configuration and PostgreSQL maintenance tests additionally prove
closed 1–3650-day retention bounds, independent message/audit cutoffs, removal
of every expired browser/API/device/logout bearer family, and preservation of
current rows.

## Explore accounts, channels, policy, and audit

**Actor and goal.** An administrator wants bounded, searchable operational
directories rather than database access.

**Preconditions.** The caller is a configured administrator with a valid
session or bearer token, and PostgreSQL is available for durable directory and
audit state.

**Flow.**

- **Accounts** shows secret-free account posture with exact filters and stable
  cursor pagination, including effective administrator and suspension state.
- **Accounts** can suspend or reactivate a non-current account by immutable ID.
  Suspension atomically revokes browser sessions, personal access tokens, and
  approved device grants; denies primary/app-password and OpenID Connect
  authentication; disconnects every live IRC session; and stops every owned
  network while retaining identity, channel, and network definitions.
  Reactivation restores credential eligibility and validated enabled networks,
  but never resurrects a revoked bearer.
- **Accounts** can grant or revoke durable administrator authority. The page
  distinguishes durable and restart-scoped configuration grants so removing
  one source never claims the other disappeared.
- **Channel registry** shows durable founder/topic/mode/access posture and
  allows an authorized administrative drop.
- **Server bans** lists/adds/removes KLINE, DLINE, and XLINE policy.
- **Audit log** filters immutable privileged/configuration actions by stable
  fields.
- Overview presents bounded newest/recent slices and links to the full
  explorers.

**Visible failures and recovery.** Non-administrators are rejected at every
handler/API. Filter sizes, page sizes, and cursor shapes are bounded and
validated. User strings are escaped in HTML and never become metric labels.
Database failure is an error state, not an empty directory. Self-suspension,
self-demotion, and suspending or demoting the last active durable administrator
are explicit conflicts.
Invalid stored network configuration prevents reactivation before the durable
state changes. A post-commit core/runtime reconciliation failure reports the
exact safe partial state so retry can reconcile it.

**Security and observability.** Administrator extraction is part of every
handler signature; state-changing forms additionally require CSRF. Directory
projections omit secrets, escape user strings, bound filters/pages, and emit
redacted audit records for mutations. Account lifecycle and network CRUD share
one mutation lane. The core suspension event installs its deny key before
disconnecting sessions, so an already-running password verification cannot
authenticate after the administrative sweep.

**Evidence.** Proven by PostgreSQL cursor/filter/posture and atomic bearer
revocation tests; ordered-core late-verdict/disconnect tests; exact-owner
registry-stop tests; and a real HTTP suspend/reactivate journey covering
durable administrator discovery, self-protection, authorization, revoked
cookies/tokens, retained credentials, non-resurrection, live authority
grant/revoke, and authority-source projection. Administrator-only
API/console integration tests also cover escaping and mutation actions. The
real Chromium/PostgreSQL journey visits every full
administrator directory, adds and removes a K-Line through the rendered
policy controls, and confirms both actions in the audit explorer.

## Inspect and terminate live connections

**Actor and goal.** An administrator wants to investigate load or abuse and
disconnect the exact connection involved.

**Preconditions.** The caller is an administrator and the target is a currently
registered live connection represented by the core’s opaque identifier.

**Flow.**

1. **Live connections** queries the bounded in-process directory.
2. Exact filters and stable pagination locate a connection without exposing
   credentials.
3. The page/API distinguishes account, nick, peer/proxied address, listener,
   connected time, and safe connection posture.
4. An authorized disconnect addresses the opaque connection ID, not a
   mutable nickname.
5. The core closes that session and updates monitoring/account directories.

**Visible failures and recovery.** Role checks are repeated on mutation; self-service
connection endpoints separately enforce account ownership.
Stale/unknown IDs report absence. Directory capacity is bounded; saturation is
observable rather than silently dropping arbitrary live entries.

**Security and observability.** Opaque random identifiers prevent nickname
reuse and restart collisions from targeting a different session. Disconnect
uses the shared audited core close path; list output contains safe posture, not
credentials or raw authentication material.

**Evidence.** Proven by admin/owner and self-scoped connection integration
tests.

## Monitor traffic, connections, queue pressure, latency, availability, and errors

**Actor and goal.** An administrator wants to answer “is the service healthy,
what is busy, and where is time/failure accumulating?” from e6irc itself.

**Preconditions.** The process is running; historical views additionally
require PostgreSQL and enabled sampling, while administrator JSON/metrics and
console views require an administrator session.

**Flow.**

1. `/healthz` reports process liveness without requiring dependencies.
2. `/readyz` reports core readiness and, when configured, a real PostgreSQL
   `SELECT 1`.
3. Fixed process counters/gauges/histograms track IRC traffic, upstream
   traffic, current IRC clients/BNC attachments, network availability, core/
   PostgreSQL/HTTP latency, categorized errors, and the depth, capacity,
   FIFO/LIFO mode, and mode-switch count of the fixed core and database
   queues.
4. A configured sampler stores typed, bounded snapshots in
   `observability_samples` and prunes outside the retention window in the same
   transaction.
5. Independently of sampling, a supervised maintenance worker applies the
   live storage policy to bounded batches of history, audit, and expired
   credential rows every five minutes.
6. **Monitoring** renders selectable time windows, deltas/trends, queue
   capacity pressure, current queue state, cumulative latency histograms, and
   an error ledger.
7. `/api/v1/admin/observability` returns JSON history;
   `/api/v1/admin/metrics` returns Prometheus text.
8. Network **Operations** provides owner-scoped per-network detail that global
   aggregates intentionally omit.
9. Every HTTP response carries a fresh server-generated correlation identifier;
   HTTPS public origins also carry HSTS.

**Visible failures and recovery.** Invalid windows are rejected/bounded.
Sampling/storage failure is logged and counted without making liveness depend
on the metrics database. A maintenance batch that reaches its fixed cap names
each deletion count and resumes on the next cycle; an unexpected sampler or
maintenance-task exit is a critical process failure. Metric dimensions are
fixed: only the statically
registered `core` and `db` queues become process-wide queue labels.
Per-connection SendQ names, account/network/channel names, and secrets cannot
create unbounded cardinality or disclosure. Historical schema-v2 samples
remain readable and simply have no queue series.

**Security and observability.** Liveness/readiness disclose only dependency
state; detailed JSON, metrics, and console history are administrator-only and
non-cacheable. Series and error reasons use closed dimensions, and historical
retention is bounded and pruned transactionally.

**Evidence.** Telemetry arithmetic/formatting, runtime network accounting,
queue monitor transitions, bounded Prometheus labels, and schema-v2 history
compatibility are unit-tested. Readiness, metrics/observability authorization,
correlation IDs, HTTPS-only HSTS, queue JSON/Prometheus/UI rendering,
persistence, monitoring retention, durable storage/credential retention,
monitoring
page/panel, and per-network operations are covered by HTTP/PostgreSQL tests.
The real Chromium/PostgreSQL journey opens Monitoring, verifies both runtime
queues in the rendered page, proves a restart-required core-capacity edit does
not misrepresent the still-active queue, then checks the configured capacity
appears in schema-v3 JSON after restart.
There is no alerting or external dashboard shipped; Prometheus is an export
surface.

## Audit privileged changes

**Actor and goal.** An administrator wants to attribute security- and
configuration-sensitive actions.

**Preconditions.** PostgreSQL is ready and the initiating actor has the
operator, founder, owner, or administrator authority required by the mutation.

**Flow.**

- IRC operator actions record the operator/account provenance.
- Server-ban mutations persist policy and audit in one transaction.
- Managed configuration writes include actor, revision, and redacted change
  detail.
- Administrator console actions record exact targets.
- The audit explorer/API supports bounded filters and cursor pagination.

**Visible failures and recovery.** Secret material is redacted before storage. A mutation
whose contract requires audit does not commit without its audit record.
Failed/stale configuration writes do not claim an action occurred.

**Security and observability.** Audit reads are administrator-only, bounded,
filterable, and non-cacheable. Actor/action/target/time are retained while
passwords, tokens, cookies, sealed ciphertext, and raw provider payloads are
excluded before persistence.

**Evidence.** Proven by core audit events, PostgreSQL transaction tests, and
the audit explorer/API tests.
