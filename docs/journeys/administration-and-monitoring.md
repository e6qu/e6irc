# Administration and monitoring journeys

## Bootstrap and manage the server through the UI

**Actor and goal.** A deployer supplies only secrets/boot-critical values; an
administrator then configures the service through **Configuration**.

**Preconditions.** PostgreSQL and the HTTP listener can start from bootstrap
configuration, the initial administrator account exists or can be created, and
the deployment supplies a stable master key before importing credentials.

**Flow.**

1. Bootstrap TOML/environment supplies PostgreSQL, secret-key source, initial
   HTTP bind/public URL/revision, and initial administrator as required by the
   deployment.
2. Migrations run; the first successful boot validates and imports a managed
   configuration snapshot with provenance.
3. Later starts load the persisted revision before constructing the core and
   listeners.
4. The administrator edits identity, IRC listeners, BNC attach listener,
   public URL/cookie/admin access, capacity, monitoring retention, registration,
   server/shared networks, IRC operators, and OpenID Connect providers.
5. A compare-and-swap revision prevents two browser tabs from overwriting each
   other. The response distinguishes live-applied values from
   restart-required values.

**Visible failures and recovery.** Unknown bootstrap keys, invalid values,
missing secrets, stale revisions, listener bind errors, provider validation
errors, and database errors fail explicitly. A failed stale write creates no
audit row. A failed BNC rebind preserves the working listener.

**Security and observability.** The page is administrator-only and every form
is session-CSRF protected. Credential fields are sealed and write-only,
revisions record provenance, and successful writes create a redacted audit row
in the same transaction.

**Evidence.** Configuration validation and import/revision behavior are covered
by unit/PostgreSQL tests, and BNC listener management is HTTP/runtime-tested.
The real Chromium/PostgreSQL journey signs in as the configured administrator,
edits representative values in every scalar subsection, checks the live BNC
listener and retained revision, then creates and removes a server network, IRC
operator, and OpenID Connect provider. It verifies exact revision increments
and that write-only credentials never reappear as rendered plaintext.

## Explore accounts, channels, policy, and audit

**Actor and goal.** An administrator wants bounded, searchable operational
directories rather than database access.

**Preconditions.** The caller is a configured administrator with a valid
session or bearer token, and PostgreSQL is available for durable directory and
audit state.

**Flow.**

- **Accounts** shows secret-free account posture with exact filters and stable
  cursor pagination.
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
Database failure is an error state, not an empty directory.

**Security and observability.** Administrator extraction is part of every
handler signature; state-changing forms additionally require CSRF. Directory
projections omit secrets, escape user strings, bound filters/pages, and emit
redacted audit records for mutations.

**Evidence.** Proven by PostgreSQL cursor/filter/posture tests and
administrator-only API/console integration tests, including escaping and
mutation actions.

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

## Monitor traffic, connections, latency, availability, and errors

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
   PostgreSQL/HTTP latency, and categorized errors.
4. A configured sampler stores typed, bounded snapshots in
   `observability_samples` and prunes outside the retention window in the same
   transaction.
5. **Monitoring** renders selectable time windows, deltas/trends, cumulative
   latency histograms, and an error ledger.
6. `/api/v1/admin/observability` returns JSON history;
   `/api/v1/admin/metrics` returns Prometheus text.
7. Network **Operations** provides owner-scoped per-network detail that global
   aggregates intentionally omit.

**Visible failures and recovery.** Invalid windows are rejected/bounded.
Sampling/storage failure is logged and counted without making liveness depend
on the metrics database. Metric dimensions are fixed; account/network/channel
names and secrets cannot create unbounded cardinality or disclosure.

**Security and observability.** Liveness/readiness disclose only dependency
state; detailed JSON, metrics, and console history are administrator-only and
non-cacheable. Series and error reasons use closed dimensions, and historical
retention is bounded and pruned transactionally.

**Evidence.** Telemetry arithmetic/formatting and runtime network accounting
are unit-tested. Readiness, metrics/observability authorization, persistence,
retention, monitoring page/panel, and per-network operations are covered by
HTTP/PostgreSQL tests. There is no alerting or external dashboard shipped;
Prometheus is an export surface.

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
