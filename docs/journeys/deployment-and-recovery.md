# Deployment and recovery journeys

## Discover service identity and readiness before sign-in

**Actor and goal.** A visitor, client, load balancer, or deployer wants to find
the service identity and distinguish a live process from one ready to serve
dependency-backed work.

**Preconditions.** The HTTP listener is reachable; no e6irc account or
credential is required for these deliberately public endpoints.

**Flow.**

1. `GET /api/v1/server` returns the bounded public server/network identity and
   supported entry-point information used by clients.
2. `GET /healthz` reports that the process and HTTP loop are alive.
3. `GET /readyz` checks the core heartbeat and performs a real,
   deadline-bounded PostgreSQL query when a database is configured.
4. A human opens `/login` to discover enabled local and OpenID Connect sign-in
   choices; automation can read `/api/v1/openapi.json` before obtaining a
   token.

**Visible failures and recovery.** An unready dependency returns a non-success
readiness response with safe component state while liveness can remain
successful. Invalid configuration prevents the listener from starting rather
than serving a misleading healthy response; callers retry readiness after the
dependency recovers.

**Security and observability.** Public responses expose no account inventory,
credentials, database address, provider secret, or internal error payload.
Probe latency/status use fixed telemetry dimensions, and authentication is
still mandatory on every private resource regardless of service discovery.

**Evidence.** `server_info_endpoint`, `healthz_is_public_and_ok`,
`readyz_reports_core_and_optional_database_state`, `login_page_renders`, and
the exact router/OpenAPI catalog test exercise these unauthenticated boundaries
over real HTTP.

## First production boot

**Actor and goal.** A deployer wants one server process with migrations,
embedded web assets, a database-backed control plane, and explicit readiness.

**Preconditions.** The deployer has a supported binary/image, a reachable
PostgreSQL database, durable secret storage, the required listener addresses,
and either existing administrator authority or a one-time random token for
creating the first durable administrator.

**Flow.**

1. Provide the PostgreSQL URL, stable secret-key source, immutable release
   revision, public URL/cookie policy, listener bootstrap, and either static
   administrator grants or a 32–512-byte first-administrator token.
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
7. If the account store is empty, open `/bootstrap`, create the first durable
   administrator, verify the route has closed, and remove the deployment token.
8. Continue configuration from `/console/configuration`.

**Visible failures and recovery.** Missing/invalid configuration, migration
failure, unavailable PostgreSQL, unreadable/wrong secret key, persisted
configuration incompatibility, bind failure, invalid bootstrap token, and an
already-consumed bootstrap produce specific errors. First-account creation is
atomic, and there is no in-memory fallback for a configured database.

**Security and observability.** Secrets enter through files/environment or the
external key source, never the image or managed configuration plaintext. Logs
identify the failing startup stage without printing secrets; liveness and
readiness distinguish process state from dependency readiness.

**Evidence.** Config/migration/import/boot-load behavior is covered by
unit/PostgreSQL tests. A process-level CI journey starts an isolated empty
PostgreSQL container and the actual `e6ircd` binary, then proves every ordered
migration, the initial managed configuration import, readiness, and real IRC
registration/channel traffic. CI also builds and inspects the production image
and runs the real server in browser, protocol, bridge, and CLI jobs.

## Deploy a release

**Actor and goal.** A release operator wants one verified server image and
matching native clients with source/build provenance for every supported
platform.

**Preconditions.** The source revision is green, registry/release permissions
are available, and a native release tag exactly matches the workspace version
when archives are requested.

**Flow.**

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
  unprivileged user and contains the embedded web client and every compiled
  bridge driver.
- Environment bootstrap renders to an unpredictable mode-`0600` file unless
  an operator explicitly supplies the path.
- `deploy/` documents the environment-variable deployment contract and ships
  a hardened systemd service for native Linux installation. The Terraform/ECS
  example lives in the separate `e6qu/infra` repository, not in this one.
- A tag exactly equal to `v` plus the workspace version builds `e6ircd`,
  `e6irc`, and `e6irc-tui` natively for Linux, macOS, and Windows on x86-64
  and ARM64. The six deterministic archives include documentation/license and
  the systemd unit, receive build-provenance attestations, and ship with sorted
  SHA-256 checksums.

**Visible failures and recovery.** Any missing architecture, malformed archive,
shape mismatch, checksum difference, attestation failure, or nonmatching tag
fails publication. Immutable commit tags allow retry without replacing a
different revision; incomplete native archive sets never become a release.

**Security and observability.** Builds use pinned actions/tooling, unprivileged
runtime images, deterministic archive contents, checksums, and signed
provenance/software-bill-of-materials attestations. Registry pruning retains
complete release groups and their referrers rather than orphaning evidence.

**Evidence.** The production-container CI job builds and inspects the image.
The release workflow verifies per-architecture images before manifest
publication, generates and verifies the attestations, and validates the final
manifest shape. Ordinary pull-request CI proves the native packager's exact
members, executable/document modes, and byte-for-byte reproducibility; the
tag workflow uses that packager on all six native runners and refuses an
incomplete archive set. `systemd-analyze verify` checks the service in CI,
the same gate compares its stop budget to the daemon flush budget, and the
portable entrypoint test executes both generated-path and operator-path modes.

## Restart without losing durable state

**Actor and goal.** An operator wants a normal restart to preserve control
plane and history state.

**Preconditions.** PostgreSQL and the same master key remain available, the
new process reads a compatible managed revision, and shutdown receives enough
time for bounded flush paths.

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

While serving, main supervises the core, PostgreSQL worker, protocol listeners,
connection reaper, observability sampler, and storage-maintenance worker. An
unexpected task return or panic enters this same shutdown flow and results in
a non-zero process exit.

**Visible failures and recovery.** Shutdown timeouts and write failures are
logged; the process does not wait forever. A new process does not claim old
runtime connection duration. Durable rows remain bounded by their
retention/cap contracts. History and audit expiry use the live console policy;
expired browser/API/device/logout bearers are removed by the same bounded
maintenance transaction.

**Security and observability.** The process reloads sealed credentials only
with the configured external key and never logs them. Shutdown and boot stages,
flush failures, driver reconnects, readiness, and new runtime timestamps make
the transition visible without pretending ephemeral sessions survived.

**Evidence.** Graceful shutdown, critical-task outcome provenance, worker
flush behavior, managed retention validation, and exact PostgreSQL maintenance
deletions are unit/integration tested; BNC backlog, read markers, channels,
bans, browser sessions, and history each have restart/boot-load PostgreSQL
tests. The Chromium acceptance
journey additionally sends real upstream traffic, stops the daemon with
SIGTERM and requires exit zero, starts a new process on the same database, and
proves the session, network, reconnected runtime, and backlog together.

## Recover from PostgreSQL interruption

**Actor and goal.** An operator wants an honest failure signal and bounded
degradation when the configured database is unavailable.

**Preconditions.** The deployment has PostgreSQL configured and can observe
HTTP probes, server logs, and metrics while the dependency is interrupted and
restored.

**Flow.**

- `/healthz` remains a process liveness signal.
- `/readyz` becomes non-ready within its fixed database-query deadline when
  the dependency cannot answer.
- Database-dependent authentication, history, managed configuration, network
  mutation, and directory operations fail visibly.
- Existing hot IRC state continues only where the operation does not require a
  persistence guarantee; no requested durable mutation is acknowledged as
  durable without its write.
- Error counters/logs identify the fixed database failure category.

**Visible failures and recovery.** Requests that require PostgreSQL return
dependency errors and readiness remains false until a real query succeeds
again. The readiness query and shared pool acquisition each have explicit
two-second application deadlines. Every pooled connection also carries a
15-second statement deadline and five-second lock deadline, so an interrupted,
wedged, or contended database cannot leave a database-backed request hanging
indefinitely.
Retrying after recovery re-enters the normal database worker path; the server
never reports an unwritten mutation as durable.

**Security and observability.** Database errors are sanitized before reaching
clients and fixed-category telemetry; connection strings and query data are
not exposed. Liveness, readiness, and database latency/error counters remain
separate signals.

**Evidence.** HTTP and worker tests cover readiness and database error
propagation. A process-level CI journey additionally starts `e6ircd` against
its own named PostgreSQL container, registers two real IRC clients, stops the
database, and proves bounded non-readiness, continuing liveness and hot IRC
traffic, plus a bounded, explicit database-dependent device-grant failure. It
restarts the same database, proves readiness and device grants recover,
exchanges more IRC traffic, and requires a clean daemon shutdown without
logging the database password.

## Back up and restore PostgreSQL

**Actor and goal.** An operator wants a verifiable recovery copy of every
durable e6irc row and a guarded way to replace a damaged database from it.

**Preconditions.** PostgreSQL client tools compatible with the server are on
`PATH`; `E6IRC_DATABASE_URL` reaches the intended database; the external
master-key files are backed up separately. e6ircd must be stopped before a
restore so no process can write post-backup state into the replacement.

**Flow.**

1. Run `tools/backup-postgres.sh /var/backups/e6irc.dump`. It uses a
   custom-format `pg_dump`, excludes ownership/privilege coupling, validates
   the archive with `pg_restore --list`, and atomically publishes a private
   dump plus a SHA-256 sidecar without overwriting an existing backup.
2. Store the dump, sidecar, deployment configuration, and external secret
   keyring in the backup system. Database ciphertext is intentionally useless
   without that separately protected key material.
3. Stop e6ircd and select the restore target. Read the connected database name
   rather than inferring it from a URL.
4. Set `E6IRC_RESTORE_CONFIRM` to that exact name and run
   `tools/restore-postgres.sh e6irc.dump DATABASE`. The tool checks the sidecar
   filename and digest, validates the archive, verifies the live database name,
   then performs a clean, fail-fast, ownership-neutral restore in one
   PostgreSQL transaction.
5. Start e6ircd. Normal migration checksum checks, managed-configuration load,
   sealed-secret opening, readiness, and durable-state journeys qualify the
   restored store before traffic resumes.

**Visible failures and recovery.** Existing backup paths, a missing sidecar,
checksum mismatch, invalid archive, wrong explicit confirmation, different
connected database name, or any `pg_dump`/`pg_restore` failure exits nonzero.
Restore uses one transaction, so a failed archive application does not leave a
half-restored schema. Keep the source database and backup unchanged, correct
the named failure, and retry while e6ircd remains stopped.

**Security and observability.** The database URL is passed through the
`PGDATABASE` environment rather than command arguments; scripts use a private
umask and never print the URL. Backups contain sealed credentials and personal
data and therefore require the same access controls as the database. The
restore requires two matching pieces of operator intent—the expected database
argument and confirmation environment value—before issuing `--clean`.

**Evidence.** A portable shell contract test proves no-overwrite, checksum,
confirmation, live-name, archive-validation, and single-transaction command
construction. The process-level PostgreSQL recovery journey creates a real
custom archive after traffic and migrations, destroys durable proof rows,
restores the archive, and boots the daemon against the recovered store.

## Recover from secret-key loss or rotation

**Actor and goal.** An operator wants to understand the consequence of the key
that seals upstream credentials.

**Preconditions.** Credential-bearing network/operator/provider configuration
exists and the operator still has the current external primary key. Key loss
without a backup is recoverable only by explicitly replacing each affected
credential.

**Flow.**

- New context-bound credentials use `enc:v2:`; legacy `enc:v1:` values remain
  readable so the same rotation upgrades them.
- Missing or wrong key is a startup/load error for data that must be opened;
  the server never treats ciphertext as plaintext or silently drops SASL.
- The console disables new password storage when no key is available.
- `e6ircd genkey` and `e6ircd seal` create keys/ciphertext; secrets remain
  outside the managed configuration and audit output.
- To rotate, generate a new key, make it the primary `key_file`, move the old
  path into `previous_key_files`, and restart. Both ciphertext generations are
  then readable while every new write uses the new primary.
- Run `e6ircd rotate-secrets --config /path/to/e6ircd.toml`. One PostgreSQL
  transaction locks the managed settings and account-network rows, proves
  every non-empty credential decryptable, re-seals all of them with the
  primary, increments the managed revision, and writes one redacted audit
  event. After it succeeds, remove the old fallback and restart.

**Visible failures and recovery.** A missing fallback, wrong key, malformed
ciphertext, unexpected plaintext database value, missing database/control
plane, or concurrent storage failure makes the command nonzero and rolls back
the entire transaction. The pre-rotation keyring continues to open the
unchanged rows. Restore a lost original key from the deployment’s secret
backup, or explicitly replace/remove each affected upstream credential.

**Security and observability.** Authenticated encryption rejects wrong or
modified ciphertext. Key bytes, plaintext credentials, and ciphertext are
excluded from rendered configuration, audit details, logs, and metrics;
startup names only the affected configuration boundary.

**Evidence.** Secret open/seal/context/tamper behavior, primary/fallback
selection, missing/wrong-key startup, CLI tooling, and console/API password
refusal are tested. Real PostgreSQL tests prove all managed and account-network
secret classes are re-sealed, the old key stops opening them, audit data is
redacted, and one corrupt later row rolls the earlier settings update back.

## Qualify high scale

**Actor and goal.** A performance operator wants evidence toward the design
target of approximately 100,000 concurrent connections on one machine.

**Preconditions.** A release build runs on a dedicated tuned Linux host with
file-descriptor, port, and socket budgets sized for the requested client count,
and host process/memory/CPU telemetry is available.

**Flow.**

1. Build release binaries and tune a Linux host’s file descriptors, ephemeral
   ports, and socket buffers as documented in `tools/load/README.md`.
2. Run `e6irc-load` or `tools/load/sweep.sh` across client/channel counts.
3. Measure connect/register/join rate, exact fan-out delivery, and
   end-to-end latency percentiles.
4. Pass the e6ircd process ID and a maximum incremental RSS-per-connection
   budget so the harness samples and enforces daemon memory rather than relying
   on an operator to transcribe it.
5. Correlate results with broader host CPU and socket telemetry.

**Visible failures and recovery.** The harness has results through 2,000
local clients. CI runs a real-daemon 64-client/eight-channel smoke and requires
every unique expected sequence exactly once, at least 10 connections/second,
at least 100 fan-out deliveries/second, P99 below five seconds, and graceful
process shutdown. The harness exits nonzero on client/socket loss, malformed,
missing, duplicate, or out-of-range deliveries, or a supplied threshold
violation. Linux CI also rejects incremental server RSS above 1 MiB per
requested connection, and the queue contract proves an empty SendQ does not
preallocate its maximum envelope count. The shared-runner thresholds catch
catastrophic regressions without claiming production-host performance. The
runtime has one core worker (the N=1 form of the target topology); core
sharding, timer-wheel scheduling, production performance targets, and a
tuned-host 100k run are not implemented or qualified.

**Security and observability.** The harness uses synthetic bounded payloads and
reports aggregate rates/latency rather than credentials or user content. Exact
sequence accounting detects missing, duplicate, malformed, or cross-channel
delivery, while host telemetry supplies resource provenance for any published
result.

**Evidence.** Harness correctness has unit/integration coverage, Linux
daemon-RSS parsing and threshold coverage, lazy queue-allocation regression
coverage, and recorded manual baselines. The 100k design target is not a
shipped performance claim.
