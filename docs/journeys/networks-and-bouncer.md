# Networks and BNC journeys

A **network** is an always-on driver owned by an account (or explicitly shared
by the server). The BNC attach listener is optional: web chat can use the
network registry even when raw IRC attachment is disabled.

## Make network management available

**Actor and goal.** An administrator wants users to create always-on networks
through the UI.

**Preconditions and flow.**

1. Configure PostgreSQL and a stable secret key. PostgreSQL owns the network
   registry; the key is required only when storing an upstream password.
2. Start the server and import bootstrap configuration on first boot.
3. In **Configuration**, enable/rebind the BNC attach listener if raw IRC
   clients should attach. The replacement socket is bound before the live
   listener is swapped.
4. Save the managed configuration revision. The UI reports which values
   applied live and which require restart.

**Visible failures and recovery.** Without PostgreSQL, the registry is
unavailable and network creation is disabled visibly. Without a master key,
passwordless networks may still be created, but password fields are disabled
and plaintext storage is refused. A failed listener rebind leaves the old
working listener active and reports the error.

**Evidence.** Proven by configuration validation/runtime-listener unit tests
and `console_configuration_enables_and_persists_bnc_listener`.

## Add Libera Chat, OFTC, EFnet, Snoonet, or a custom IRC network

**Actor and goal.** An account holder wants an always-on upstream configured
entirely through **BNC networks**.

**Flow.**

1. Open `/console/networks`. The form defaults to the Libera Chat preset and
   also offers OFTC, EFnet, Snoonet, and Custom server.
2. Selecting a preset fills the stable network ID, published TLS endpoint, and
   TLS checkbox. Server-side preset resolution repeats this step on submit, so
   the safety defaults do not depend on JavaScript or client-supplied hidden
   values.
3. Supply nickname, optional real name and comma-separated autojoin channels,
   and optional upstream SASL account/password.
4. Submit the CSRF-protected form. The server validates all sizes and syntax,
   blocks prohibited IP literals, seals any password, constructs the driver,
   inserts the owner-scoped row, and starts the driver immediately. Each DNS
   result is vetted again at dial time.
5. The result redirects to the network list. Status comes from the live
   runtime snapshot, including connected state, attempts, timestamps,
   latency, traffic, attachments, and fixed-category errors.

**Visible failures and recovery.**

- An unknown/tampered preset is rejected, not treated as Custom.
- Invalid network ID, endpoint, nickname, channel list, TLS policy, or
  credential pair re-renders the form with the specific error and non-secret
  values preserved.
- Missing secret key refuses a supplied password before persistence.
- Duplicate owner/network names conflict under IRC casemapping.
- DNS rebinding/address policy, TLS verification, upstream SASL rejection,
  nickname collision, and connection loss happen asynchronously after a valid
  configuration is stored. They appear in live operations and leave the
  network configured for retry/edit; a stored row is not misreported as
  connected.
- A synchronous driver-construction failure happens before insertion. Once
  storage succeeds, registry insertion owns the running/retrying driver.

**Evidence.** Preset integrity and server-side application have unit tests.
`console_add_and_delete_network_via_the_console` proves console creation and
deletion with PostgreSQL; `bnc_network_management_lifecycle` proves API
mutation, live driver start, BNC attach, update/toggle/delete, and secret
handling. The live public-network probe in `irc_driver.rs` is opt-in, so real
Libera DNS/TLS/SASL behavior is externally qualified rather than CI-proven.

## Diagnose an upstream connection

**Actor and goal.** An account holder wants to understand whether a network is
working and why it is not.

**Flow.**

1. The network list shows enabled/paused, connecting/connected/disconnected,
   driver kind, upstream, attached clients, and error count.
2. **Inspect** shows configuration without returning the stored secret.
3. **Operations** refreshes the live snapshot: attempt/success/disconnect
   timestamps, connection duration, latest connect latency, bytes/lines in and
   out, attached clients, backlog length, and the bounded error ledger.
4. Recent persisted detached backlog is shown oldest-first and remains
   available while the network is paused.
5. Global **Monitoring** aggregates upstream traffic, availability, error
   deltas, and latency across networks.

**Visible failures and recovery.** Runtime snapshots say when a driver is
absent, disabled, connecting, or failed. Runtime timestamps reset on a
restart/reconfiguration and are labeled as such. Stored credentials are shown
only as presence/posture.

**Evidence.** Snapshot/accounting/error-ledger behavior is unit-tested; network
detail/operations rendering and owner scoping are HTTP-tested; monitoring
aggregation/history is tested at HTTP/DB level.

## Attach any IRC client to an owned network

**Actor and goal.** A user wants a normal IRC client to resume an always-on
network.

**Flow.**

1. Read the attach address from **BNC networks**.
2. Connect to the BNC listener and negotiate SASL PLAIN.
3. Authenticate with account `account/network` and the primary or app
   password.
4. The listener resolves the account first, then selects only that account’s
   case-insensitive network name (or an eligible shared network).
5. The client receives buffered lines and live driver output; commands are
   relayed back to the same driver.
6. Disconnecting the client decrements attachments but leaves the driver and
   upstream session running.

**Visible failures and recovery.** Missing SASL, malformed/chunked payload
errors, bad credentials, absent/disabled network, registry failure, and
cross-account selection are refused before attachment. An unavailable
upstream may still allow stored backlog replay, but it is not described as a
live connection.

**Evidence.** Proven end-to-end over real sockets and PostgreSQL by the BNC
authentication/routing/rejection/chunking tests and network-management
lifecycle test. These tests now run in the database CI job.

## Persist and replay while detached or across restart

**Actor and goal.** A user wants messages received with no clients attached to
survive reconnection and process restart.

**Flow.**

1. Every driver emits upstream lines into a bounded in-memory buffer.
2. With PostgreSQL, a persistence task stores wire-preserving lines under the
   owner/network key and trims the network’s history to its cap.
3. On driver start, recent rows preload oldest-first into the bounded buffer.
4. A later BNC or web attachment replays that stream before following live
   output.
5. Deleting a network purges its casefolded buffer; another network’s history
   is untouched.

**Visible failures and recovery.** Persistence errors are counted/logged and
do not fabricate durable success. Removing/replacing a network aborts the old
persistence task so it cannot retain a ghost driver.

**Evidence.** Proven by restart-spanning replay, trim isolation, deletion
purge, wire-form, and detached buffer API tests against PostgreSQL.

## Edit, pause, resume, or delete a network

**Actor and goal.** An owner wants lifecycle control without editing files or
restarting the daemon.

**Flow.**

- **Edit** validates a complete replacement and swaps the live driver only
  after storage/runtime checks. Blank password retains the sealed secret;
  **Remove stored SASL credentials** is explicit.
- **Pause** stores disabled state and stops the driver while retaining
  configuration/backlog.
- **Resume** starts a fresh driver from the stored configuration.
- **Delete** removes owner-scoped configuration, runtime driver, persistence
  task, and buffer.
- Equivalent GET/POST/PUT/PATCH/DELETE API operations use the same mutation
  core as console forms.

**Visible failures and recovery.** Every transition reports conflict,
validation, storage, or runtime failure. A stale runtime handle, leaked task,
or partial rename is not an accepted state.

**Evidence.** Proven by console edit/create/delete tests, API full-replacement
and patch lifecycle tests, registry unit tests, and WebSocket detachment on
network removal.
