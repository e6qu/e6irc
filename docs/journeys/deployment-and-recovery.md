# Deployment and recovery journeys

## First production boot

**Actor and goal.** A deployer wants one server process with migrations,
embedded web assets, a database-backed control plane, and explicit readiness.

**Flow.**

1. Provide the PostgreSQL URL, stable secret-key source, immutable release
   revision, public URL/cookie policy, initial administrator, and listener
   bootstrap required by the chosen mode.
2. Build/install `e6ircd` or run the production container. The container builds
   the Vite client and embeds it at image-build time; startup does not compile
   assets.
3. Validate the complete bootstrap configuration. Unknown keys and invalid
   cross-field combinations stop startup.
4. Connect to PostgreSQL, apply ordered migrations, and import the first
   managed configuration snapshot with provenance.
5. Load persisted accounts, registered-channel policy, bans, configuration,
   networks, and recent network backlog before exposing the corresponding
   behavior.
6. Bind listeners and report `/healthz`; report `/readyz` only with the
   configured dependencies actually ready.
7. Continue configuration from `/console/configuration`.

**Visible failures and recovery.** Missing/invalid configuration, migration
failure, unavailable PostgreSQL, unreadable/wrong secret key, persisted
configuration incompatibility, and bind failure terminate startup with a
specific error. There is no in-memory fallback for a configured database.

**Evidence.** Config/migration/import/boot-load behavior is covered by
unit/PostgreSQL tests. CI builds and inspects the production image and runs a
real server in the database, browser, protocol, bridge, and CLI jobs.

## Deploy a release

**Shipped release path.**

- Every pull request builds/tests all workspace features on Linux, macOS, and
  Windows for x86-64 and ARM64.
- Every merge to `main` builds the production image natively on Linux amd64
  and arm64, verifies each image’s runtime shape, and publishes one immutable
  12-character commit-SHA multi-architecture GHCR manifest.
- Each architecture digest receives signed build-provenance and SPDX SBOM
  attestations as OCI referrers. The assembled multi-architecture digest
  receives signed provenance, and the workflow verifies each attestation
  through the same public consumer command operators use.
- The runtime image is `debian:bookworm-slim`; the server runs as an
  unprivileged user and contains the embedded web client.
- `deploy/` supplies the Terraform/ECS example, its deployment contract, and a
  hardened systemd service for native Linux installation.
- A tag exactly equal to `v` plus the workspace version builds `e6ircd`,
  `e6irc`, and `e6irc-tui` natively for Linux, macOS, and Windows on x86-64
  and ARM64. The six deterministic archives include documentation/license and
  the systemd unit, receive build-provenance attestations, and ship with sorted
  SHA-256 checksums.

**Product boundary.** Native archives use each platform's ordinary dynamic
runtime. Musl/static artifacts and scratch/distroless container images are not
part of this release shape.

**Evidence.** The production-container CI job builds and inspects the image.
The release workflow verifies per-architecture images before manifest
publication, generates and verifies the attestations, and validates the final
manifest shape. Ordinary pull-request CI proves the native packager's exact
members, executable/document modes, and byte-for-byte reproducibility; the
tag workflow uses that packager on all six native runners and refuses an
incomplete archive set. `systemd-analyze verify` checks the service in CI.

## Restart without losing durable state

**Actor and goal.** An operator wants a normal restart to preserve control
plane and history state.

**Flow.**

1. Stop accepting new connections.
2. Notify/close live clients through the normal shutdown path.
3. Stop drivers and allow the bounded PostgreSQL history/network-buffer write
   paths to flush within the shutdown budget.
4. Exit; ephemeral live connections and runtime timestamps are expected to
   disappear.
5. On restart, load managed configuration, registered-channel state, bans,
   network definitions, recent BNC backlog, read markers, history, and browser
   sessions from PostgreSQL.
6. Start enabled networks and listeners from the loaded revision.

**Visible failures and recovery.** Shutdown timeouts and write failures are
logged; the process does not wait forever. A new process does not claim old
runtime connection duration. Durable rows remain bounded by their retention/
cap contracts.

**Evidence.** Graceful shutdown and worker flush behavior are unit/integration
tested; BNC backlog, read markers, channels, bans, browser sessions, and
history each have restart/boot-load PostgreSQL tests. The Chromium acceptance
journey additionally sends real upstream traffic, stops the daemon with
SIGTERM and requires exit zero, starts a new process on the same database, and
proves the session, network, reconnected runtime, and backlog together.

## Recover from PostgreSQL interruption

**Actor and goal.** An operator wants an honest failure signal and bounded
degradation when the configured database is unavailable.

**Behavior.**

- `/healthz` remains a process liveness signal.
- `/readyz` becomes non-ready when its real database query fails.
- Database-dependent authentication, history, managed configuration, network
  mutation, and directory operations fail visibly.
- Existing hot IRC state continues only where the operation does not require a
  persistence guarantee; no requested durable mutation is acknowledged as
  durable without its write.
- Error counters/logs identify the fixed database failure category.

**Evidence.** Readiness and database error propagation are covered at HTTP and
worker levels. CI does not run a long-lived chaos test that kills and restores
PostgreSQL under mixed traffic.

## Recover from secret-key loss or rotation

**Actor and goal.** An operator wants to understand the consequence of the key
that seals upstream credentials.

**Behavior.**

- A sealed `enc:v1:` credential requires the configured external key.
- Missing or wrong key is a startup/load error for data that must be opened;
  the server never treats ciphertext as plaintext or silently drops SASL.
- The console disables new password storage when no key is available.
- `e6ircd genkey` and `e6ircd seal` create keys/ciphertext; secrets remain
  outside the managed configuration and audit output.

**Recovery contract.** Restore the original key from the deployment’s secret
backup, or explicitly replace/remove each affected upstream credential. There
is no automatic key rotation/re-encryption workflow.

**Evidence.** Secret open/seal, missing/wrong-key startup, CLI tooling, and
console/API password refusal are tested.

## Qualify high scale

**Actor and goal.** A performance operator wants evidence toward the design
target of approximately 100,000 concurrent connections on one machine.

**Shipped flow.**

1. Build release binaries and tune a Linux host’s file descriptors, ephemeral
   ports, and socket buffers as documented in `tools/load/README.md`.
2. Run `e6irc-load` or `tools/load/sweep.sh` across client/channel counts.
3. Measure connect/register/join rate, exact fan-out delivery, and
   end-to-end latency percentiles.
4. Correlate results with process monitoring and host RSS/CPU.

**Current qualification boundary.** The harness has results through 2,000
local clients. CI runs a real-daemon 64-client/eight-channel smoke and requires
every unique expected sequence exactly once, at least 10 connections/second,
at least 100 fan-out deliveries/second, P99 below five seconds, and graceful
process shutdown. The harness exits nonzero on client/socket loss, malformed,
missing, duplicate, or out-of-range deliveries, or a supplied threshold
violation. The shared-runner thresholds catch catastrophic regressions without
claiming production-host performance. The runtime has one core worker (the N=1
form of the target topology); core sharding, timer-wheel scheduling,
per-connection memory budget, production performance targets, and a tuned-host
100k run are not implemented or qualified.

**Evidence.** Harness correctness has unit/integration coverage and recorded
manual baselines. The 100k design target is not a shipped performance claim.
